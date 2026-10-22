"""win11_windows.py —— L2 材料窗口任务组调度器（Win11 快系统，C-136 §二
+ C-137 §1/§3 + C-138 §1/§2）。

规格：docs/context/L2L3L4-接口冻结-C136.md §二（材料窗口调度，Agent A）、
docs/context/C137-接口冻结.md §1/§3 与 docs/context/C138-接口冻结.md
§1/§2（window_key/branch_key、窗口状态机 producing→sealed→settled 与
三层账目；冲突处以 C-138 为准——窗口状态机载体在 runtime 的
_open_windows，本模块提供 release/mark_branch_done/mark_window_settled
三层账目原语，语义与其一致）。

- 每相机独立双窗：**处理中冻结窗口**（已租约包集合，推理期间输入不变
  ——acquire 交出的 WindowHandle 在窗口存续期间冻结，不因新素材改写）+
  **有界待处理窗**（max_pending；推理期间新摘的包进入待处理窗）。
- `acquire() -> WindowHandle | None`：WindowHandle 即**窗口任务组**（同
  窗全部包一起，分支随窗不散落）；一次 acquire 服务一个窗口组，跨相机
  轮转不变（公平，忙相机不长期占用）。一轮 acquire：1) 为全部逻辑占用
  相机收割 store.take_ready 可消费包进各自待处理窗；2) 从上次服务位置
  之后按轮转顺序服务第一台空闲相机（逻辑占用窗数 < l2_in_flight）——
  有待处理窗则整窗提升为冻结窗（出队时复核年龄），否则新摘一批
  （≤ max_pending）为冻结窗。安静且无新信息返回 None（不产生理解动作，
  不把轮询当理解）。
- **三层账目分列（C-137 §3，任一解除不影响其余两层，互不挪账）**：
  1) 逻辑窗口占用（本模块）：WindowHandle.release() **不再**立即解除
     占用——L2 处理后 L3 仍在异步执行同窗任务，窗口保持逻辑冻结
     （frozen_windows），直到调用方在窗内全部分支终态后调
     mark_window_settled()，或超窗龄上限 max_window_hold_s（可覆盖，
     缺省跟随 max_age_s）被 sweep 解除；占用未解除的相机不出新窗
     （L2 完成≠窗口完成），同相机新材料只进待处理窗；
  2) 材料租约（store）：release() 照旧立即整窗归还 store 租约与消费
     资格（不等 L3）；
  3) 实际存活字节（store finalize 口径）：跟随真实数组回收，本模块
     不挪账、不为显示"释放"提前减掉仍被消费者持有的图像账。
- 分支登记（C-137 §1）：mark_branch_done(branch_key) 登记分支终态
  （幂等）；同窗分支被预算截断时由调用方经
  note_omission(branch_key, reason, count) 登记——handle 记录缺失
  （进 handle.omissions 与 snapshot 汇总），不悄悄拆散窗口。
- 待处理满：按 merge_policy 收敛——默认 keep_start_turning_latest：
  **确定性转折选取（C-137，零模型）**——按包入窗时记录的
  change_original_boxes 面积序列选角色：起点（最早）+ 转折（面积序列
  严格局部极值；等值游程取首个极值）+ 最新，去重后按时间序保留；容量
  不足按 [起点, 距起点时间最远的转折, 最新] 优先保角色裁剪（容量 1
  退化保留最新——C-136 冻结语义）。全部舍弃/保留（含角色标签与面积）
  记入合并记录，合并动作计 merged；drop_oldest：丢弃最旧（释放租约，
  计数 dropped，记录原因与时间）。分支随窗不散落：同窗所有包一起进出
  （整窗提升、整窗释放），不跨相机、不相干材料不混合（窗口只含本相机
  包）。
- 身份/时效/取消（A3）：入待处理窗与出队（进入冻结窗）时复核包
  created_mono_ms 年龄（max_age_s 可覆盖，默认跟随 store.max_age_s；
  单调钟，严格大于）——超龄包如实释放租约，计 cancelled（原因
  "expired"，带时间记录）。逻辑占用有独立窗龄上限（max_window_hold_s，
  严格大于）——超限解除占用（计 settled，记录原因 age_cap），不动租
  约。close() 清理全部未处理（待处理）窗：逐包 release + cancelled
  计数（原因 "closing"）；在途/冻结窗是调用方仍持有的租约与逻辑占用，
  本模块不假装释放；handle.release()/mark_window_settled() 在 close
  后仍有效、如实归还。
- **C154 车道 Q F1：释放前的观察通知（可选注入，缺省零行为）**。
  折叠/丢弃/取消/关闭这四条路径都会把包的租约**如实归还**，此前的材
  料在归还后就再也没有任何消费者能看到（诊断 M1：14/14 带检出包在进
  池前被折叠）。构造参数 `on_packages_released` 是一个**可选**回调：
  恰在这四条路径调用 `store.release()` **之前**，以"本批次即将释放的
  包元组（原始包对象，不是副本）"调用一次。
  契约（调用方必须遵守，本模块的回调点也据此设计）：
  1. 回调在**窗口调度锁内**同步执行——只允许 O(1) 记身份/入自有有界
     缓冲，**不得**复制像素、查库、调模型、做磁盘 I/O 或等待；
  2. 回调抛出的任何异常都被本模块吞并（释放与账目照常），绝不打断
     窗口收敛；
  3. 回调**不得**回调本调度器的公开方法（嵌套取锁会自锁）；
  4. 回调若需要异步观察，必须自行做**有界**移交并在满时显式拒绝计数
     ——本模块不提供无界积压。
  未注入（缺省 `None`）时这四条路径与本参数出现前**逐字段等价**：只多
  一次 `is not None` 判断，零账目、零记录、零行为差异。

零模型加载、零 I/O、纯内存；所有公开方法非阻塞，内部锁保护（调度器
锁→store 锁单向，无重入死锁）。接口合同见
docs/context/L2L3L4-接口冻结-C136.md §二 与 docs/context/C137-接口冻
结.md §3（本地）。零 SQL、零文件写。
"""

import collections
import threading
import time

__all__ = ["WindowScheduler", "WindowHandle"]

_MAX_RECORDS = 256   # 丢弃/合并/取消/登记诊断记录上界（防无界增长）

_MERGE_POLICIES = ("keep_start_turning_latest", "drop_oldest")


class WindowHandle:
    """一扇冻结窗口＝一个窗口任务组：同相机 1..N 个已租约包。

    packages 在窗口存在期间不变（冻结窗语义）；三层账目接口分列：
    - release()：整窗归还 store 租约并结束本窗 L2 在途（幂等，重复调用
      如实返回 False）；**不解除逻辑占用**——L3 异步期间窗口保持冻结；
    - mark_branch_done(branch_key)：登记一个分支终态（幂等；重复同键
      返回 False），计 branch_done；
    - mark_window_settled()：窗内全部分支终态后由调用方调用，解除逻辑
      占用（幂等），计 settled；
    - note_omission(branch_key, reason, count)：登记预算截断缺失（同键
      同因合并计数），进 omissions 与 snapshot 汇总。
    window_id 为调度器存续期单调序号。release/settled 后 store 侧字节
    随消费者弃引经 finalize 口径真实返还（计费语义归材料仓，本模块不
    挪账）。
    """

    __slots__ = ("window_id", "camera_id", "packages", "_scheduler",
                 "_released", "_settled", "_branches_done", "omissions")

    def __init__(self, window_id, camera_id, packages, scheduler):
        self.window_id = window_id
        self.camera_id = camera_id
        self.packages = tuple(packages)
        self._scheduler = scheduler
        self._released = False
        self._settled = False
        self._branches_done = set()
        self.omissions = ()      # ({branch_key, reason, count}, ...) 只增

    def release(self):
        """租约层整窗释放：结束 L2 在途 + 逐包归还 store 租约（幂等）。

        返回是否首次释放。**不解除逻辑占用**（C-137 §3：L2 完成≠窗口
        完成）——占用由 mark_window_settled() 或窗龄上限解除。先在本模
        块锁内结束在途，再逐包 store.release（非阻塞）。close 后仍可有
        效释放（调用方仍持租约，如实归还，不假装消失）。
        """
        scheduler = self._scheduler
        with scheduler._lock:
            if self._released:
                return False
            self._released = True
            cam = scheduler._cams.get(self.camera_id)
            if cam is not None and self in cam["in_flight"]:
                cam["in_flight"].remove(self)
        for pkg in self.packages:
            scheduler.store.release(pkg)
        return True

    def mark_branch_done(self, branch_key):
        """登记分支终态（branch_key = window_key + (kind, crop/region)）。

        幂等：同键首次 True 并计 branch_done；重复 False。占用/租约均
        不动（分支终态≠窗口终结：调用方在全部终态后另调 settled）。
        """
        scheduler = self._scheduler
        with scheduler._lock:
            if branch_key in self._branches_done:
                return False
            self._branches_done.add(branch_key)
            cam = scheduler._cams.get(self.camera_id)
            if cam is not None:
                cam["branch_done"] += 1
            return True

    def mark_window_settled(self):
        """解除逻辑占用（窗内全部分支终态后由调用方调用；幂等）。

        返回是否首次解除。只动逻辑占用层：租约（若调用方尚未 release）
        与字节账不受影响。被窗龄上限 sweep 先行解除的窗口（_settled 已
        置位）如实返回 False，不重复计数。
        """
        scheduler = self._scheduler
        with scheduler._lock:
            if self._settled:
                return False
            self._settled = True
            cam = scheduler._cams.get(self.camera_id)
            if cam is not None:
                cam["frozen"] = [entry for entry in cam["frozen"]
                                 if entry["handle"] is not self]
                cam["settled"] += 1
            return True

    def note_omission(self, branch_key, reason, count=1):
        """登记窗口任务组内被预算截断的分支缺失（调用方处理中发现）。

        同 (branch_key, reason) 合并累加 count（不悄悄拆散窗口）；记录
        进 handle.omissions、snapshot 汇总（omissions/omitted_branches）
        与相机诊断记录。返回该键该因的累计缺失分支数。count 必须 ≥ 1。
        release/settled 后仍可登记（L3 迟到发现的缺失照常入账）。
        """
        count = int(count)
        if count < 1:
            raise ValueError("omission count 必须 ≥ 1")
        scheduler = self._scheduler
        with scheduler._lock:
            entries = [dict(entry) for entry in self.omissions]
            total = count
            for entry in entries:
                if (entry["branch_key"] == branch_key
                        and entry["reason"] == reason):
                    entry["count"] += count
                    total = entry["count"]
                    break
            else:
                entries.append({"branch_key": branch_key,
                                "reason": str(reason), "count": count})
            self.omissions = tuple(entries)
            cam = scheduler._cams.get(self.camera_id)
            scheduler._omissions += 1
            scheduler._omitted_branches += count
            if cam is not None:
                cam["records"].append({
                    "t_mono_ms": scheduler._clock() * 1000.0,
                    "kind": "omission", "reason": str(reason),
                    "packages": count, "branches": count,
                    "branch_key": branch_key})
            return total


class WindowScheduler:
    """多相机材料窗口任务组调度器（线程安全；全部方法非阻塞）。

    每相机独立维护：处理中冻结窗（逻辑占用 ≤ l2_in_flight 扇，默认
    1——推理与 L3 异步期间输入不变）+ 有界待处理窗（≤ max_pending 包，
    合并/丢弃计数如实）。不跨相机混合；丢弃/合并/取消/窗龄解除/缺失
    登记记录（时间、原因、涉及包数与遗漏分支数、角色标签）保留有界内
    部账（_MAX_RECORDS），计数进 snapshot()。
    """

    def __init__(self, camera_ids, store, *, l2_in_flight=1, max_pending=2,
                 poll_timeout_s=0.2,
                 merge_policy="keep_start_turning_latest", max_age_s=None,
                 max_window_hold_s=None, clock=time.monotonic,
                 on_packages_released=None):
        if int(l2_in_flight) < 1:
            raise ValueError("l2_in_flight 必须 ≥ 1")
        if int(max_pending) < 1:
            raise ValueError("max_pending 必须 ≥ 1")
        if merge_policy not in _MERGE_POLICIES:
            raise ValueError("未知 merge_policy: %r" % (merge_policy,))
        if on_packages_released is not None \
                and not callable(on_packages_released):
            raise ValueError("on_packages_released 必须可调用或 None")
        self.camera_ids = tuple(camera_ids)
        self.store = store
        self.l2_in_flight = int(l2_in_flight)
        self.max_pending = int(max_pending)
        # C154 Q F1：释放前观察通知（缺省 None=零行为，见模块头契约）。
        self.on_packages_released = on_packages_released
        # 轮询节奏提示：acquire 恒非阻塞，安静返回 None；调用方循环在
        # None 后按 poll_timeout_s 间歇重试（安静不空转）。
        self.poll_timeout_s = float(poll_timeout_s)
        self.merge_policy = merge_policy
        # A3：出队年龄上限可覆盖；缺省跟随 store.max_age_s（同源口径）
        self.max_age_s = (float(max_age_s) if max_age_s is not None
                          else float(getattr(store, "max_age_s", 60.0)))
        # C-137 A1：逻辑占用窗龄上限（可覆盖）；缺省跟随 max_age_s（同
        # 源口径）——占用有界，L3 挂死不永久饿死相机。
        self.max_window_hold_s = (
            float(max_window_hold_s) if max_window_hold_s is not None
            else self.max_age_s)
        if self.max_window_hold_s <= 0:
            raise ValueError("max_window_hold_s 必须 > 0")
        self._clock = clock
        self._lock = threading.Lock()
        self._order = list(self.camera_ids)   # 轮转顺序（构造序，确定公平）
        self._cams = {cam: self._new_cam() for cam in self._order}
        self._cursor = -1                     # 上次服务位置（轮转公平）
        self._window_seq = 0                  # window_id：存续期单调递增
        self._omissions = 0                   # 缺失登记调用次数（全局）
        self._omitted_branches = 0            # 缺失分支累计数（全局）
        self._closed = False

    # ---- 消费者接口（L2 循环调用，非阻塞） --------------------------------

    def acquire(self):
        """跨相机公平轮转取一个窗口任务组；安静且无新信息返回 None。

        1) 窗龄 sweep：逻辑占用超 max_window_hold_s 的窗解除占用（计
           settled，原因 age_cap；不动租约）；
        2) 逻辑占用相机收割：推理/L3 期间新摘的包只进待处理窗（有界；
           满按 merge_policy 合并/丢最旧，计数+记录），冻结窗不被改写；
        3) 从上次服务位置之后轮转找第一台空闲相机（逻辑占用窗数 <
           l2_in_flight——占用相机不长期霸占）：待处理窗整窗提升为冻结
           窗（出队时复核年龄），或新摘一批（≤ max_pending）。无空闲
           相机/无新信息 → None（不产生理解动作）。
        """
        with self._lock:
            if self._closed or not self._order:
                return None
            now_mono_ms = self._clock() * 1000.0
            for cam_id in self._order:       # 1)+2) sweep 与占用相机收割
                cam = self._cams[cam_id]
                if cam["frozen"]:
                    self._sweep_frozen_locked(cam, now_mono_ms)
                if cam["frozen"]:
                    self._harvest_locked(cam, cam_id, now_mono_ms)
            n = len(self._order)
            for step in range(n):            # 3) 轮转服务空闲相机
                idx = (self._cursor + 1 + step) % n
                cam_id = self._order[idx]
                cam = self._cams[cam_id]
                if len(cam["frozen"]) >= self.l2_in_flight:
                    continue                 # 逻辑占用：不长期霸占
                if cam["pending"]:
                    handle = self._promote_locked(cam, cam_id, now_mono_ms)
                else:
                    handle = self._fresh_window_locked(cam, cam_id,
                                                       now_mono_ms)
                if handle is None:
                    continue                 # 该相机无新信息
                self._cursor = idx
                return handle
            return None

    # ---- 观测与生命周期 -----------------------------------------------------

    def snapshot(self):
        """合同冻结结构的线程安全只读快照（不含路径/凭据/帧数据）。

        每相机九字段：frozen_windows（逻辑占用中窗数）/in_flight（L2 在
        途未 release 窗数）/pending（待处理包数）/merged（合并动作数）/
        dropped（满窗丢弃最旧包数）/cancelled（取消包数：超龄 expired +
        关闭 closing）/windows_total（累计开窗数）/branch_done（分支终
        态登记数）/settled（占用解除数：显式 settled + 窗龄 age_cap）；
        全局键为各相机之和，另加 omissions（缺失登记调用次数）与
        omitted_branches（缺失分支累计数）。快照点顺带做窗龄 sweep
        （解除超限占用，账目如实）。
        """
        with self._lock:
            now_mono_ms = self._clock() * 1000.0
            for cam in self._cams.values():
                if cam["frozen"]:
                    self._sweep_frozen_locked(cam, now_mono_ms)
            cameras = {}
            totals = {"frozen_windows": 0, "in_flight": 0, "pending": 0,
                      "merged": 0, "dropped": 0, "cancelled": 0,
                      "windows_total": 0, "branch_done": 0, "settled": 0}
            for cam_id in self._order:
                cam = self._cams[cam_id]
                entry = {
                    "frozen_windows": len(cam["frozen"]),
                    "in_flight": len(cam["in_flight"]),
                    "pending": len(cam["pending"]),
                    "merged": cam["merged"],
                    "dropped": cam["dropped"],
                    "cancelled": cam["cancelled"],
                    "windows_total": cam["windows_total"],
                    "branch_done": cam["branch_done"],
                    "settled": cam["settled"],
                }
                cameras[cam_id] = entry
                for key in totals:
                    totals[key] += entry[key]
            return {"cameras": cameras, "omissions": self._omissions,
                    "omitted_branches": self._omitted_branches, **totals}

    def close(self):
        """停止（幂等）：清理全部未处理（待处理）窗——逐包 release +
        cancelled 计数（reason="closing"，带时间记录）；此后 acquire 恒
        返回 None。

        在途/逻辑冻结窗是调用方仍持有的租约与占用：本模块不假装释放
        （A3——在途不可中止调用由 backend diagnostic 承载报告）；
        handle.release() 与 handle.mark_window_settled() 在 close 后仍
        有效，如实归还租约/解除占用。
        """
        with self._lock:
            self._closed = True
            now_mono_ms = self._clock() * 1000.0
            for cam_id in self._order:
                cam = self._cams[cam_id]
                while cam["pending"]:
                    pkg = cam["pending"].pop()
                    self._cancel_locked(cam, cam_id, pkg, "closing",
                                        now_mono_ms)

    # ---- 内部 ---------------------------------------------------------------

    def _new_cam(self):
        return {"in_flight": [],       # L2 在途窗（release 前）
                "frozen": [],          # 逻辑占用窗（settled/窗龄前）
                "pending": [],         # 有界待处理窗（≤ max_pending 包）
                "merged": 0, "dropped": 0, "cancelled": 0,
                "windows_total": 0, "branch_done": 0, "settled": 0,
                "records": collections.deque(maxlen=_MAX_RECORDS)}

    def _harvest_locked(self, cam, cam_id, now_mono_ms):
        """占用相机收割：新摘包逐个入待处理窗（有界，满按策略收敛）。"""
        while True:
            pkg = self.store.take_ready(cam_id)
            if pkg is None:
                return
            if self._too_old(pkg, now_mono_ms):
                self._cancel_locked(cam, cam_id, pkg, "expired", now_mono_ms)
                continue
            self._absorb_pending_locked(cam, cam_id, pkg, now_mono_ms)

    def _fresh_window_locked(self, cam, cam_id, now_mono_ms):
        """空闲相机新摘一批（≤ max_pending）为冻结窗；无新信息 → None。

        开窗即一次角色选取（确定性：起点+转折+最新），包记录 role 与
        area_at_entry（窗口任务组身份可由帧 ID/面积证明）。
        """
        packages = []
        while len(packages) < self.max_pending:
            pkg = self.store.take_ready(cam_id)
            if pkg is None:
                break
            if self._too_old(pkg, now_mono_ms):
                self._cancel_locked(cam, cam_id, pkg, "expired", now_mono_ms)
                continue
            pkg.area_at_entry = self._package_area(pkg)
            packages.append(pkg)
        if not packages:
            return None
        roles = self._role_map([p.area_at_entry for p in packages])
        for i, pkg in enumerate(packages):
            pkg.role = roles.get(i)
        return self._make_window_locked(cam, cam_id, packages, now_mono_ms)

    def _promote_locked(self, cam, cam_id, now_mono_ms):
        """待处理窗整窗提升为冻结窗（出队时复核年龄；分支随窗不散落）。

        未参与过选取的包补齐角色（已标记者不动——合并/新窗选取的标签
        是选择期事实，不因提升改写）。
        """
        pending = cam["pending"]
        kept = []
        for pkg in pending:
            if self._too_old(pkg, now_mono_ms):
                self._cancel_locked(cam, cam_id, pkg, "expired", now_mono_ms)
            else:
                kept.append(pkg)
        cam["pending"] = kept
        if not kept:
            return None
        self._fill_roles_locked(kept)
        handle = self._make_window_locked(cam, cam_id, kept, now_mono_ms)
        cam["pending"] = []
        return handle

    def _notify_released_locked(self, packages):
        """C154 Q F1：**释放之前**把本批即将 release 的包如实通知观察者。

        调用方持调度器锁；回调同步执行（只允许记身份/入自有有界缓冲），
        任何异常都被吞并——观察失败绝不打断窗口收敛与租约归还。未注入
        回调时零行为（只多一次 None 判断）。
        """
        sink = self.on_packages_released
        if sink is None:
            return
        try:
            sink(tuple(packages))
        except Exception:
            pass

    def _absorb_pending_locked(self, cam, cam_id, pkg, now_mono_ms):
        """新摘包进入待处理窗（记录入窗面积）；满（=max_pending）按
        merge_policy 收敛。

        keep_start_turning_latest（默认，C-137 确定性转折选取，零模型）：
        以入窗面积序列选角色——起点（最早）+ 转折（严格局部极值，等值
        游程取首个）+ 最新，去重后按时间序保留；容量不足按 [起点, 距起
        点时间最远的转折, 最新] 优先保角色裁剪（容量 1 退化保留最新，
        C-136 冻结语义）。被裁/折叠包租约如实归还；保留与舍弃明细（含
        角色标签与面积）记入合并记录；merged 计合并动作。
        drop_oldest：释放最旧包（计 dropped，记录原因 pending_full 与
        时间）后追加。遗漏分支（折叠/丢弃包的 change_boxes 数）进记录，
        计数进 snapshot。
        """
        pkg.area_at_entry = self._package_area(pkg)
        pending = cam["pending"]
        if len(pending) < self.max_pending:
            pending.append(pkg)
            return
        if self.merge_policy == "drop_oldest":
            old = pending.pop(0)
            self._notify_released_locked((old,))   # C154 Q F1：release 前观察
            self.store.release(old)
            cam["dropped"] += 1
            self._record_locked(cam, "dropped", "pending_full", 1, old,
                                now_mono_ms)
            pending.append(pkg)
            return
        seq = list(pending) + [pkg]
        roles = self._role_map([p.area_at_entry for p in seq])
        keep = self._select_keep(len(seq), roles, self.max_pending)
        keep_set = set(keep)
        for i, member in enumerate(seq):     # 角色同账：保留者与被裁者
            member.role = roles.get(i)
        kept = [seq[i] for i in keep]
        folded = [member for i, member in enumerate(seq)
                  if i not in keep_set]
        self._notify_released_locked(folded)   # C154 Q F1：release 前观察
        for old in folded:
            self.store.release(old)          # 折叠/裁剪：租约如实归还
        cam["merged"] += 1                   # 合并动作计数
        self._record_locked(cam, "merged", "pending_full", len(folded),
                            folded, now_mono_ms,
                            kept=self._pkg_details(kept),
                            folded=self._pkg_details(folded))
        cam["pending"] = kept

    def _make_window_locked(self, cam, cam_id, packages, now_mono_ms):
        """开一扇冻结窗（window_id 单调；占用相机在途槽与逻辑占用槽）。"""
        self._window_seq += 1
        handle = WindowHandle(self._window_seq, cam_id, tuple(packages),
                              self)
        cam["in_flight"].append(handle)
        cam["frozen"].append({"handle": handle, "born": now_mono_ms})
        cam["windows_total"] += 1
        return handle

    def _sweep_frozen_locked(self, cam, now_mono_ms):
        """C-137 A1：逻辑占用超 max_window_hold_s（单调钟，严格大于）→
        解除占用（计 settled，记录原因 age_cap）；不动租约与字节账——
        调用方仍持的租约由 store TTL/显式 release 口径承载，本模块不假
        装释放。"""
        limit_ms = self.max_window_hold_s * 1000.0
        keep = []
        for entry in cam["frozen"]:
            if now_mono_ms - entry["born"] > limit_ms:
                handle = entry["handle"]
                handle._settled = True       # 先行解除：显式 settled 不重复计
                cam["settled"] += 1
                cam["records"].append({
                    "t_mono_ms": now_mono_ms, "kind": "settled",
                    "reason": "age_cap", "packages": len(handle.packages),
                    "branches": 0, "window_id": handle.window_id})
            else:
                keep.append(entry)
        cam["frozen"] = keep

    def _too_old(self, pkg, now_mono_ms):
        """A3 时效复核：created_mono_ms 年龄严格大于上限（单调钟）。"""
        return (now_mono_ms - pkg.created_mono_ms) > self.max_age_s * 1000.0

    def _cancel_locked(self, cam, cam_id, pkg, reason, now_mono_ms):
        """取消单包：如实释放租约 + cancelled 计数 + 带时间记录。

        C154 Q F1：`store.release()` **之前**先通知观察者（超龄/关闭两条
        取消路径共用本方法，因此两条都在"材料仍有效"时被看到）。
        """
        self._notify_released_locked((pkg,))
        self.store.release(pkg)
        cam["cancelled"] += 1
        self._record_locked(cam, "cancelled", reason, 1, pkg, now_mono_ms)

    # ---- 确定性转折选取（C-137，零模型） -------------------------------------

    @staticmethod
    def _package_area(pkg):
        """入窗面积：change_original_boxes 面积和（原图像素²）。

        无门控标定或无框 = 0.0（如实，不猜测比例）。
        """
        return float(sum(box["w"] * box["h"]
                         for box in pkg.change_original_boxes()))

    @staticmethod
    def _role_map(areas):
        """面积序列 → 角色表（索引→start/turning/latest）。

        起点最早、最新最新；转折=严格局部极值（比前后两个**不同值**邻
        居都大或都小；等值游程整体作一个候选，取游程**首个**元素——等
        宽窗口取首个极值）。单包窗口退化记 latest（唯一且信息最全）。
        """
        n = len(areas)
        if n == 0:
            return {}
        if n == 1:
            return {0: "latest"}
        roles = {0: "start", n - 1: "latest"}
        runs = []                            # (首索引, 值) 等值游程压缩
        for i, area in enumerate(areas):
            if not runs or runs[-1][1] != area:
                runs.append((i, area))
        for j in range(1, len(runs) - 1):
            idx, value = runs[j]
            if ((value > runs[j - 1][1] and value > runs[j + 1][1])
                    or (value < runs[j - 1][1] and value < runs[j + 1][1])):
                roles[idx] = "turning"
        return roles

    @staticmethod
    def _select_keep(n, roles, capacity):
        """容量不足时的保留集合（C-137：按 [起点, 距起点时间最远的转折,
        最新] 优先保角色；容量 1 退化保留最新——C-136 冻结语义）。

        候选（起点+转折+最新）不超容量则全保（中间非候选如实折叠）；
        超出时起点与最新保底，其余槽位按距起点时间从远到近依次给转折。
        返回升序索引表。
        """
        candidates = sorted(roles)
        if n <= capacity or len(candidates) <= capacity:
            return candidates
        if capacity == 1:
            return [n - 1]
        keep = {0, n - 1}
        turnings = [i for i in candidates if roles[i] == "turning"]
        for idx in reversed(turnings):       # 时间序 → 距起点最远优先
            if len(keep) >= capacity:
                break
            keep.add(idx)
        return sorted(keep)

    @classmethod
    def _fill_roles_locked(cls, packages):
        """提升补角色：只为未参与过选取（role=None）的包按当前序列规则
        补标签；已标记者不动（选择期事实不改写）。"""
        roles = cls._role_map([p.area_at_entry for p in packages])
        for i, pkg in enumerate(packages):
            if pkg.role is None and roles.get(i) is not None:
                pkg.role = roles[i]

    @staticmethod
    def _pkg_details(packages):
        """合并记录明细：帧 ID + 角色标签 + 入窗面积（可由内容证明）。"""
        return [{"frame_id": p.cur.frame_id, "role": p.role,
                 "area": p.area_at_entry} for p in packages]

    @staticmethod
    def _record_locked(cam, kind, reason, packages, pkgs_or_pkg, now_mono_ms,
                       **extra):
        """丢弃/合并/取消诊断记录（有界）：时间、原因、数量、遗漏分支；
        合并记录附保留/舍弃明细（kept/folded：帧 ID、角色、面积）。"""
        if isinstance(pkgs_or_pkg, (list, tuple)):
            pkgs = pkgs_or_pkg
        else:
            pkgs = (pkgs_or_pkg,)
        branches = sum(len(getattr(p, "change_boxes", None) or ())
                       for p in pkgs)
        record = {"t_mono_ms": now_mono_ms, "kind": kind, "reason": reason,
                  "packages": packages, "branches": branches}
        record.update(extra)
        cam["records"].append(record)
