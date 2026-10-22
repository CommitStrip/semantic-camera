"""win11_materials.py —— 有界时序材料包存取（Win11 快系统→未来 L2—L4 交接）。

C-133 材料合同（docs/context/L1-时间-材料-结果合同-C133.md §二 M1—M6）与
C-135 接口冻结（docs/context/L2L3-接口冻结-C135.md §一/§二）并存；冲突处
以 C-135 为准。C-136 A1（docs/context/L2L3L4-接口冻结-C136.md）在其上
修订：take_ready 的 finalize 注册属准备段——全部注册完成才原子提交消费，
任一注册失败完整回滚（detach 已注册回调+精确回退已入账字节），不产生
幽灵槽/幽灵账本。C-137（docs/context/C137-接口冻结.md）在其上新增窗口
生命周期接口：MaterialPackage.role / area_at_entry 由窗口调度器写入、
随租约副本透传（本模块不解释、不伪造，未登记显式 None）。

- M1 完整身份：材料与结果绑定 (camera_id, run_id, config_version, frame_id)；
  prev/nxt 回填与 attach_result 四元全匹配，只匹配 camera+frame 一律视为
  缺陷（跨运行/跨配置串线修复）。
- M2 前后帧边界：回填仅当同 run_id、同 config_version 且
  `0 < t_gap ≤ MAX_ADJACENT_GAP_MS(10000)`；包内记录实际
  prev_gap_ms/nxt_gap_ms（缺失=None 显式）。跨 run/跨配置/过旧材料不得
  冒充紧邻帧。
- M3 真实字节计费（仓内原图池，store_bytes 口径）：uid 引用计数账本——
  每个独立图像对象（ingest 时 copy 入仓，MaterialFrame.key 由 store 分配
  存续期单调 uid，不用 id() 以规避对象回收后的 id 复用串账）只要有任何
  在仓引用（prev/cur/nxt 任意槽位）就持续计费；逐出一个包只释放其独占
  引用，最后引用消失才真正减费。全局预算按全库真实存活字节判定：超限
  跨相机按 created_mono 逐出最旧包（公平，不饿死既有相机），计
  dropped_pressure（其中因全库预算压力被逐出的计入 global_drops）；每
  相机包数上限并存。单帧超全库预算的必拒材料直接拒收，不逐出任何在存
  材料。快照 store_bytes 与实际可达图像对象账实相符（测试双验）。
- M4 消费者租约与污染隔离（C-135 §二"真实存活字节"修订口径）：take_ready
  输出隔离副本（图像 .copy() + 框与检测逐字段深拷贝）——消费者怎么改都
  不影响仓内原图与框。在途租约单独记账：每相机 max_leases=8、全库
  LEASE_MAX_BYTES（64MB）、LEASE_MAX_S=120。finalize 注册属 take_ready
  准备段（C-136 A1）：全部图像数组的 finalize 注册完成后才原子提交消
  费，任一注册异常完整回滚（detach+字节回退），不留半提交幽灵槽。**计费跟随实际存活对象**：
  take_ready 为副本的每个图像数组注册 weakref.finalize(数组, 回调)——
  **数组真被回收才**从 consumer_alive_bytes 减除；finalize 回调只做线程
  安全入队（无锁、无重入），账目在下一个仓调用点排空——规避 GC 在持锁
  路径触发回收时的回调重入死锁。release 只解除 store 强引用与任务资格
  （released_leases 计数），**不等于内存返还**：消费者仍持图片（含视图/
  别名——finalize 绑定基对象即副本数组本身，视图存活即基对象存活）→
  字节持续计费 → 租约预算饱和 → 新 take 被拒（背压，诚实有界）。TTL
  到期只做状态标记（leased→expired）与计数（lease_expired），不动字节
  账。**模块边界（归属清晰）**：本模块只对本模块交出的图片数组计费与
  保证；第三方（消费者）对交出图片自行额外 copy 出的新数组不归本模块
  保证与计费；第三方加工产生的派生输出（L2 裁图、增强图等）归生产运
  行面（L2Runtime）自计并上报健康面，不入材料仓账本；本模块交出的图片
  与生产派生输出归属清晰、互不挪账。
- M4b 双池预算：仓内原图预算（store_bytes 口径）与消费者副本存活预算
  （consumer_alive_bytes 口径）是两个池，全链路合计上限 = 两池之和
  （默认各 64MB → 合计 128MB），不得宣传成单池；租约预算检查对象=
  consumer_alive_bytes。
- M5 关闭语义：close() 后 ingest/attach 恒拒（内部计 closed，与显式清空
  区分），不重新积存；租约如实显示（活跃/过期未释放租约的存活字节跟随
  真实存活对象，直到数组真被回收）；幂等。
- R1 配合：attach_result 接受 accepted/reject_reason，包与快照记录
  last_l1_accepted/last_reject_reason——被拒结果只作诊断，绝不写成有效
  受理（状态面以 last_l1_accepted 闸门）；确定性 fallback 定案后迟到
  attach 只作诊断拒绝，已拒收证据不得重新激活。

C-135 §一 材料状态机（字段名冻结）：ingest → 包进入 waiting_l1（对 L2
不可见——take_ready/租约消费只摘 consumable 与 fallback_terminal 包，
FIFO 跳过等待头部不阻塞；waiting_l1 材料持续入仓不受限）。attach_result
依据 (status, accepted) 驱动迁移：accepted ok → consumable；accepted
empty/失败 → fallback_terminal(reason="empty"/"model_unavailable"/
"infer_failed"/…其余非 ok status 原样)；rejected → fallback_terminal(
reason="rejected:<原因>")；attach 等待超 L1_WAIT_S（默认 3.0，构造
l1_wait_s 可覆盖，单调钟）→ sweep 转 fallback_terminal(
reason="l1_wait_timeout")。sweep 挂在 ingest/take_ready/attach_result/
snapshot 调用点（无新线程），不阻塞。确定规则（冻结）：超时 fallback
后同一材料身份的有效接受结果（accepted ok）迟到且包未消费 → 一次性
晋升 consumable（包记 late_promotion=True，计 late_promotions）；已
消费 → 只作诊断拒绝（rejected_attach）。晋升随机性为零（由状态机判定，
不取决于线程先后）。摘走的包带 l1_terminal_reason（None=consumable，
其余为原因串）与 late_promotion 标记。

快照字段（C-134 冻结 + C-135 新增冻结）：每相机 ready（=可摘包数，
consumable+fallback）/waiting_l1/consumable/fallback/late_promotions/
l1_timeouts/consumed/expired/dropped_pressure/global_drops/
rejected_attach/attach_missed/dup_rejected/leased（=active_leases 活跃
租约数）/active_leases/lease_expired（=expired_leases 过期未释放租约
数）/expired_leases/released_leases（已释放任务数，累计）/lease_bytes
（=consumer_alive_bytes 兼容别名）/consumer_alive_bytes（消费者侧实际
存活图片字节，finalize 口径）/total_bytes（=store_bytes 仓内原图字节）/
store_bytes/oldest_age_s/ready_with_prev/ready_with_next/
last_l1_status/last_l1_accepted/last_reject_reason；全局 total_bytes/
store_bytes/lease_bytes/consumer_alive_bytes/active_leases/
released_leases/expired_leases/total_packages。
其余拒收细分（单帧超预算 oversize / 关闭后受理 closed / 租约超限
lease_slots、lease_bytes）不进冻结快照，仅入 store._rejects 内部账。
clock 参数仅供测试注入（默认 time.monotonic，生产无感知）。

零模型加载、零 I/O、纯内存；所有公开方法非阻塞，内部锁保护。
接口合同见 docs/context/L1-时间-材料-结果合同-C133.md 与
docs/context/L2L3-接口冻结-C135.md（本地）。零 SQL、零文件写。
"""

import collections
import threading
import time
import weakref

MAX_ADJACENT_GAP_MS = 10000.0       # 合同 M2：prev/nxt 紧邻帧最大时间间隔
LEASE_MAX_BYTES = 64 * 1024 * 1024  # 合同 M4：全库消费者存活字节预算
LEASE_MAX_S = 120.0                 # 合同 M4：租约最长持有秒数
L1_WAIT_S = 3.0                     # C-135 §一：attach 等待上限默认值（单调钟）

_CONSUMED_ID_CAP = 256              # 已消费身份诊断记录上界（防无界增长）

__all__ = ["MaterialFrame", "MaterialPackage", "MaterialsStore",
           "MAX_ADJACENT_GAP_MS", "LEASE_MAX_BYTES", "LEASE_MAX_S",
           "L1_WAIT_S"]


def _copy_fields(mapping):
    """逐字段拷贝一个扁平结构：新 dict、新嵌套 list、新嵌套 dict。

    用于 change_boxes 与 detections 的深拷贝（A2 框深拷贝 / A3 检测逐
    检测深拷贝）：标量字段原样，track_id 等字段原样透传不伪造（缺失就是
    缺失）；list 元素中的 dict 递归拷贝，其余元素按标量原样收集（bbox 等
    扁平数值列表）。
    """
    copy = {}
    for key, value in mapping.items():
        if isinstance(value, list):
            copy[key] = [_copy_fields(item) if isinstance(item, dict)
                         else item for item in value]
        elif isinstance(value, dict):
            copy[key] = _copy_fields(value)
        else:
            copy[key] = value
    return copy


def _l1_verdict(status, accepted, reject_reason):
    """C-135 §一：由 (status, accepted) 判定 attach 结果的迁移裁决。

    返回 (verdict_ok, terminal_reason)：accepted ok → (True, None)；
    accepted 非 ok（empty/model_unavailable/infer_failed 等，status 原样
    透传为原因）→ (False, status)；rejected（accepted=False）→
    (False, "rejected:<原因>")。
    """
    if not accepted:
        return False, "rejected:" + str(reject_reason)
    if status == "ok":
        return True, None
    return False, str(status)


class MaterialFrame:
    """一帧材料的所有者对象：帧字节由 store 在 ingest 时 copy 独占。

    key 由 store 分配（存续期单调递增、永不复用），作为引用计数账本的稳定
    uid——不用 id()，规避对象回收后 id 复用造成的串账。key=None 表示该帧
    不归 store 计费（take_ready 输出的隔离副本）。
    """

    __slots__ = ("key", "frame_id", "frame_bgr", "t_capture_ms",
                 "timestamp_kind", "width", "height", "material_reason")

    def __init__(self, frame_id, frame_bgr, t_capture_ms, timestamp_kind,
                 key=None, material_reason=None):
        self.key = key
        self.frame_id = frame_id
        self.frame_bgr = frame_bgr
        self.t_capture_ms = t_capture_ms
        self.timestamp_kind = timestamp_kind
        self.width = int(frame_bgr.shape[1])
        self.height = int(frame_bgr.shape[0])
        # C-144：快系统材料触发原因（change_start|latest|patrol）随帧
        # 贯穿——L1 巡检与深度理解准入的判别依据（冻结 §1 唯一命名）。
        self.material_reason = material_reason


class MaterialPackage:
    """单份时序材料包：cur 必有；prev/nxt 为 None 即显式缺失（不伪造）。

    C-135 §一 状态机：state ∈ {waiting_l1, consumable, fallback_terminal,
    consumed}。waiting_l1 对 L2 不可见（take_ready 不摘）；摘走的包
    state="consumed"。l1_terminal_reason 仅 fallback_terminal 包非 None
    （"empty"/"model_unavailable"/"infer_failed"/"rejected:<原因>"/
    "l1_wait_timeout"）；consumable 包为 None。late_promotion 标记超时
    fallback 后有效结果迟到的一次性晋升（冻结规则）。

    C-137 窗口生命周期接口：role（"start"/"turning"/"latest" 或 None）
    与 area_at_entry（入窗时 change_original_boxes 面积和或 None）由窗
    口调度器在包入窗/角色选取时写入（本模块只承载与随租约副本透传，
    不解释；未登记包显式 None，不伪造角色）。
    """

    __slots__ = ("camera_id", "run_id", "config_version", "material_id",
                 "created_mono_ms", "cur", "prev", "nxt", "change_boxes",
                 "gate_w", "gate_h", "l1_status", "l1_error_code",
                 "detections", "state", "prev_gap_ms", "nxt_gap_ms",
                 "last_l1_accepted", "last_reject_reason",
                 "l1_terminal_reason", "late_promotion",
                 "role", "area_at_entry", "material_reason")

    def __init__(self, camera_id, run_id, config_version, material_id,
                 created_mono_ms, cur, change_boxes, gate_w, gate_h):
        self.camera_id = camera_id
        self.run_id = run_id
        self.config_version = config_version
        self.material_id = material_id
        self.created_mono_ms = created_mono_ms
        self.cur = cur
        self.prev = None
        self.nxt = None
        self.prev_gap_ms = None
        # C-144：包级材料触发原因（取 cur 帧的 material_reason；聚合包
        # 以 cur 为准——深度准入判别的唯一依据，冻结 §1 命名）。
        self.material_reason = (getattr(cur, "material_reason", None)
                                if cur is not None else None)
        self.nxt_gap_ms = None
        self.change_boxes = change_boxes
        self.gate_w = gate_w
        self.gate_h = gate_h
        self.l1_status = None
        self.l1_error_code = None
        self.detections = None
        self.last_l1_accepted = None
        self.last_reject_reason = None
        self.l1_terminal_reason = None
        self.late_promotion = False
        self.state = "waiting_l1"   # waiting_l1|consumable|fallback_terminal|consumed
        self.role = None            # C-137：start|turning|latest|None（调度器写）
        self.area_at_entry = None   # C-137：入窗面积（调度器写）

    def change_original_boxes(self):
        """门控坐标框 → 原图像素框（按 cur 尺寸 / gate 尺寸比例）。

        gate_w/gate_h 缺失或为零（无门控标定）返回 []——不猜测比例，
        不伪造坐标。
        """
        if self.cur is None:
            return []
        gate_w = self.gate_w
        gate_h = self.gate_h
        if not gate_w or not gate_h:
            return []
        scale_x = self.cur.width / gate_w
        scale_y = self.cur.height / gate_h
        boxes = []
        for box in self.change_boxes or []:
            boxes.append({
                "x": box["x"] * scale_x,
                "y": box["y"] * scale_y,
                "w": box["w"] * scale_x,
                "h": box["h"] * scale_y,
            })
        return boxes


class MaterialsStore:
    """多相机有界材料包存取（线程安全；全部方法非阻塞）。

    仓内原图按 uid 引用计数账本计（M3）：账本 key → {nbytes, refs, cam}；
    store_bytes = Σ nbytes(refs>0)，即 store 仍持有的每一个独立图像对象；
    全库预算检查用该真实存活字节，快照与实际可达对象账实相符（测试双
    验）。消费者侧按"真实存活字节"计（C-135 §二）：take_ready 为租约副
    本的每个图像数组注册 weakref.finalize——数组真被回收才入队、在下一
    个仓调用点从 consumer_alive_bytes 减除（finalize 回调只做线程安全
    deque.append，不取锁，规避 GC 在持锁路径触发回收时的重入死锁）；
    release 只解除 store 强引用与任务资格，不动 finalize 账。租约预算
    检查对象=consumer_alive_bytes（M4b 双池独立，互不挪用）。**模块边
    界**：本模块只对本模块交出的图片数组计费与保证；第三方（消费者）
    对交出图片自行额外 copy 出的新数组不归本模块保证与计费；生产派生
    输出（L2 裁图、增强图等）归生产运行面自计并上报健康面，不入材料
    仓账本——本模块交出的图片与派生输出归属清晰。
    """

    _REJECT_KINDS = ("dup", "oversize", "closed", "lease_slots", "lease_bytes")

    def __init__(self, *, max_packages_per_camera=8,
                 max_total_bytes=LEASE_MAX_BYTES, max_age_s=60.0,
                 max_adjacent_gap_ms=MAX_ADJACENT_GAP_MS, max_leases=8,
                 max_lease_bytes=LEASE_MAX_BYTES, max_lease_s=LEASE_MAX_S,
                 l1_wait_s=L1_WAIT_S, clock=time.monotonic):
        self.max_packages_per_camera = int(max_packages_per_camera)
        self.max_total_bytes = int(max_total_bytes)
        self.max_age_s = float(max_age_s)
        self.max_adjacent_gap_ms = float(max_adjacent_gap_ms)
        self.max_leases = int(max_leases)
        self.max_lease_bytes = int(max_lease_bytes)
        self.max_lease_s = float(max_lease_s)
        self.l1_wait_s = float(l1_wait_s)   # C-135 §一：构造可覆盖
        self._clock = clock
        self._lock = threading.Lock()
        # camera_id -> 计数器 dict（见 _new_cam_locked）
        self._cams = {}
        # uid -> {"nbytes": int, "refs": int, "cam": camera_id}
        self._ledger = {}
        self._total_bytes = 0          # 全库仓内原图存活字节（store_bytes 口径）
        self._consumer_alive_bytes = 0  # 全库消费者侧实际存活图片字节（finalize 口径）
        self._pending_dead = collections.deque()  # finalize 入队的真实回收记录
        self._material_seq = 0         # material_id：store 存续期单调递增
        self._frame_seq = 0            # MaterialFrame.key：存续期单调 uid
        self._state = "running"        # running | closing | stopped
        self._rejects = {}             # camera_id -> {kind: n}（内部账）

    # ---- 提交方接口（相机线程调用，非阻塞） ------------------------------

    @property
    def state(self):
        """running | closing | stopped（M5 生命周期，幂等只进不退）。"""
        with self._lock:
            return self._state

    def ingest(self, camera_id, run_id, config_version, frame_id, frame_bgr,
               t_capture_ms, timestamp_kind, change_boxes, gate_w, gate_h,
               material_reason=None):
        """受理一帧材料（非阻塞）；返回 False=未受理。

        内部对 frame_bgr.copy() 独占（调用方缓冲区后续改写不影响包内帧）。
        C-135 §一：新包进入 waiting_l1（对 L2 不可见，等待 L1 结果；材料
        持续入仓不受限）。新包 cur=新帧；对上一包按 M2 边界回填 prev/nxt
        （同 run、同 config、`0 < t_gap ≤ max_adjacent_gap_ms`，记录 gap，
        缺失显式 None，每包只回填一次）。维护 sweep 挂在本调用点（无新
        线程）：超龄逐出（计 expired）、租约 TTL 标记、L1 等待超时迁移。
        容量：按每相机包数上限与全库真实存活字节压力逐出——本相机超包数
        上限逐本相机最旧包；全库超字节预算跨相机按 created_mono 逐最旧包
        （公平，计 dropped_pressure + global_drops），逐出后按引用计数
        重算直到达标。单帧超全库预算的必拒材料直接拒收，不逐出任何在存
        材料。同相机同 (run, config, frame_id) 在存重复 → 拒收
        （dup_rejected）。close 后恒拒（closed）。
        """
        try:
            frame = MaterialFrame(frame_id, frame_bgr.copy(), t_capture_ms,
                                  timestamp_kind,
                                  material_reason=material_reason)
            nbytes = int(frame.frame_bgr.nbytes)
            boxes = [_copy_fields(box) for box in (change_boxes or [])]
        except Exception:
            return False
        with self._lock:
            if self._state != "running":        # M5：close 后恒拒
                self._count_reject_locked(camera_id, "closed")
                return False
            now_s = self._clock()
            now_mono_ms = now_s * 1000.0
            self._drain_dead_locked()
            self._sweep_expired_locked(now_mono_ms)
            self._sweep_leases_locked(now_s)
            self._sweep_l1_wait_locked(now_mono_ms)
            cam = self._cams.get(camera_id)
            if cam is None:
                cam = self._new_cam_locked(camera_id)
            ring = cam["ring"]
            for held in ring:               # M1：身份四元判定重复
                if (held.cur.frame_id == frame_id
                        and held.run_id == run_id
                        and held.config_version == config_version):
                    cam["dup_rejected"] += 1
                    self._count_reject_locked(camera_id, "dup")
                    return False
            if nbytes > self.max_total_bytes:
                # 单帧必拒：逐出无济于事，不破坏任何在存材料
                self._count_reject_locked(camera_id, "oversize")
                return False
            if not self._make_room_locked(cam, nbytes):
                self._count_reject_locked(camera_id, "oversize")
                return False
            self._material_seq += 1
            frame.key = self._frame_seq     # 入仓帧获得计费 uid
            self._frame_seq += 1
            self._ledger[frame.key] = {"nbytes": nbytes, "refs": 0,
                                       "cam": camera_id}
            pkg = MaterialPackage(camera_id, run_id, config_version,
                                  self._material_seq, now_mono_ms, frame,
                                  boxes, gate_w, gate_h)
            if ring:
                prev_pkg = ring[-1]
                gap = t_capture_ms - prev_pkg.cur.t_capture_ms
                if (prev_pkg.run_id == run_id
                        and prev_pkg.config_version == config_version
                        and 0.0 < gap <= self.max_adjacent_gap_ms):
                    pkg.prev = prev_pkg.cur     # 共享同一所有者对象
                    pkg.prev_gap_ms = gap
                    self._ref_locked(prev_pkg.cur)
                    if prev_pkg.nxt is None:    # 有界回填：每包只回填一次
                        prev_pkg.nxt = frame
                        prev_pkg.nxt_gap_ms = gap
                        self._ref_locked(frame)
            self._ref_locked(frame)             # cur 槽位引用
            ring.append(pkg)
            return True

    def attach_result(self, camera_id, run_id, config_version, frame_id,
                      status, error_code, detections, accepted=True,
                      reject_reason=None):
        """按 M1 四元全匹配写 L1 结果并驱动 C-135 §一状态机（非阻塞）。

        (run_id, config_version, frame_id) 必须与在存包完全一致；frame_id
        命中但 run/config 不符 → 身份越权，计 rejected_attach 拒绝（旧
        run/旧配置结果不得污染新材料）；frame_id 命中已消费（take_ready
        摘走）包的身份 → 只作诊断拒绝（rejected_attach，C-135 冻结规则
        "已消费→只作诊断拒绝"）；完全不存在（从未存在/已逐出）→ 计
        attach_missed。

        状态迁移由 (status, accepted) 驱动（waiting_l1 期间多次 attach=
        以最新为准，结果槽替换语义延续）：
        - waiting_l1 / consumable：accepted ok → consumable；accepted
          非 ok → fallback_terminal(reason=status)；rejected →
          fallback_terminal(reason="rejected:<原因>")（最新裁决替换）。
        - fallback_terminal("l1_wait_timeout")：有效接受结果（accepted
          ok）迟到且未消费 → 一次性晋升 consumable（包记
          late_promotion=True，计 late_promotions）；其余迟到结果只更新
          诊断槽位，超时 fallback 判定不变（晋升随机性为零，由状态机
          判定）。
        - 其余 fallback_terminal（empty/失败/拒绝等确定性判定）：定案后
          迟到 attach 只作诊断拒绝（rejected_attach），不改状态不改槽
          ——已拒收证据不得重新激活（R1），fallback 分支路由稳定。
        accepted=False 的被拒结果照常记录 last_l1_accepted/
        last_reject_reason（状态面以 last_l1_accepted 闸门，R1 配合）。
        """
        with self._lock:
            if self._state != "running":        # M5：close 后恒拒
                self._count_reject_locked(camera_id, "closed")
                return False
            now_s = self._clock()
            now_mono_ms = now_s * 1000.0
            self._drain_dead_locked()
            self._sweep_expired_locked(now_mono_ms)
            self._sweep_l1_wait_locked(now_mono_ms)
            cam = self._cams.get(camera_id)
            if cam is None:
                cam = self._new_cam_locked(camera_id)
            match = None
            identity_conflict = False
            for pkg in cam["ring"]:
                if pkg.cur.frame_id != frame_id:
                    continue
                if (pkg.run_id == run_id
                        and pkg.config_version == config_version):
                    match = pkg
                    break
                identity_conflict = True
            if match is None:
                if (run_id, config_version, frame_id) in cam["consumed_set"]:
                    cam["rejected_attach"] += 1     # 已消费：诊断拒绝（冻结）
                elif identity_conflict:
                    cam["rejected_attach"] += 1
                else:
                    cam["attach_missed"] += 1
                return False
            verdict_ok, verdict_reason = _l1_verdict(status, accepted,
                                                     reject_reason)
            if (match.state == "fallback_terminal"
                    and match.l1_terminal_reason != "l1_wait_timeout"):
                # 确定性 fallback 已定案：迟到结果只作诊断拒绝（R1 不
                # 重新激活），不改状态不改结果槽
                cam["rejected_attach"] += 1
                return False
            # 写结果槽（以最新为准；waiting_l1 期间替换语义延续）
            match.l1_status = status
            match.l1_error_code = error_code
            match.detections = detections
            match.last_l1_accepted = bool(accepted)
            match.last_reject_reason = reject_reason
            cam["last_l1_status"] = status
            cam["last_l1_accepted"] = bool(accepted)
            cam["last_reject_reason"] = reject_reason
            if verdict_ok:
                if match.state == "fallback_terminal":
                    # l1_wait_timeout 后有效结果迟到：一次性晋升（冻结）
                    if not match.late_promotion:
                        match.late_promotion = True
                        cam["late_promotions"] += 1
                match.state = "consumable"
                match.l1_terminal_reason = None
            elif match.state in ("waiting_l1", "consumable"):
                match.state = "fallback_terminal"
                match.l1_terminal_reason = verdict_reason
            # else：l1_wait_timeout fallback 收到非 ok 迟到结果——超时
            # fallback 判定不变（reason 仍 l1_wait_timeout），上方槽位
            # 已按最新诊断更新
            return True

    def take_ready(self, camera_id):
        """非阻塞取最旧**可摘**包（consumable / fallback_terminal）的隔
        离副本；无则 None。

        C-135 §一 状态机：waiting_l1 包对 L2 不可见——take_ready 跳过
        它们摘最旧可摘包（FIFO 不被等待头部阻塞）；摘走的包带
        l1_terminal_reason（None=consumable，其余为 fallback 原因串）与
        late_promotion 标记。

        A2/A3 复制原子性 + C-136 A1 finalizer 原子性：先**完成全部必要
        分配/登记准备**——完整构建全部副本（prev/cur/nxt 图像 .copy() +
        框/检测逐字段深拷贝 + 字段复制）并注册全部 finalize 计费回调，
        全部成功后才原子提交消费（摘包/计数/租约一气呵成）——复制或任
        一 finalize 注册失败：不提交消费、不创建半租约、不产生幽灵槽/
        幽灵账本（注册失败额外 detach 已注册回调+精确回退已入账字节；
        TTL/维护 sweep 作为独立维护动作可先期发生）。

        C-135 §二 真实存活字节：副本每个图像数组注册 weakref.finalize——
        **数组真被回收才**从 consumer_alive_bytes 减除（回调仅入队，账目
        在仓调用点排空）；release 只解除 store 强引用与任务资格，不动
        finalize 账（release ≠ 内存返还）。租约预算检查对象=
        consumer_alive_bytes：消费者不弃引用 → 字节持续计费 → 新 take
        被拒（背压，诚实有界）；活跃与过期未释放租约都占每相机
        max_leases 槽位——take 不能成为绕过总预算的出口。
        """
        with self._lock:
            now_s = self._clock()
            now_mono_ms = now_s * 1000.0
            self._drain_dead_locked()
            self._sweep_expired_locked(now_mono_ms)
            self._sweep_leases_locked(now_s)
            self._sweep_l1_wait_locked(now_mono_ms)
            cam = self._cams.get(camera_id)
            if not cam or not cam["ring"]:
                return None
            ring = cam["ring"]
            idx = None
            for i, pkg in enumerate(ring):
                if pkg.state in ("consumable", "fallback_terminal"):
                    idx = i
                    break
            if idx is None:
                return None             # 只有 waiting_l1：对 L2 不可见
            pkg = ring[idx]
            alive_bytes = self._package_bytes(pkg)
            if len(cam["leases"]) >= self.max_leases:
                self._count_reject_locked(camera_id, "lease_slots")
                return None
            if (self._consumer_alive_bytes + alive_bytes
                    > self.max_lease_bytes):
                self._count_reject_locked(camera_id, "lease_bytes")
                return None
            copy = self._copy_package_locked(pkg)   # 纯构建：不改仓状态
            # ---- 准备段：finalize 注册全部完成（任一注册异常→完整回滚，
            # 不碰仓状态：摘包/计数/租约全部未动，无幽灵槽——C-136 A1）----
            self._register_alive_bills_locked(cam, camera_id, copy)
            # ---- 提交段：全部准备成功后原子变更仓状态 ----
            ring.pop(idx)
            for frame in (pkg.prev, pkg.cur, pkg.nxt):
                if frame is not None:
                    self._unref_locked(frame)   # 只减仓内引用；副本独立
            cam["consumed"] += 1
            cam["leased"] += 1
            cam["leases"].append({"pkg": copy, "bytes": alive_bytes,
                                  "born": now_s, "state": "leased"})
            ident = (pkg.run_id, pkg.config_version, pkg.cur.frame_id)
            if ident not in cam["consumed_set"]:
                cam["consumed_ids"].append(ident)
                cam["consumed_set"].add(ident)
                if len(cam["consumed_ids"]) > _CONSUMED_ID_CAP:
                    cam["consumed_set"].discard(cam["consumed_ids"].popleft())
            return copy

    def release(self, pkg):
        """显式释放 take_ready 建立的在途租约；返回是否确实释放。

        C-135 §二：release 只解除 store 强引用与任务资格（released_leases
        计数），**不动 finalize 账**——消费者仍持副本（或其视图/别名）时
        consumer_alive_bytes 持续计费，数组真被回收才经 finalize 返还。
        活跃或已过期未释放的租约都可 release（到期≠释放：到期只标记，
        字节仍计费）。重复 release / 未知包 → False（幂等友好）。close
        后仍可 release。
        """
        if pkg is None:
            return False
        with self._lock:
            self._drain_dead_locked()
            self._sweep_leases_locked(self._clock())
            cam = self._cams.get(pkg.camera_id)
            if cam is None:
                return False
            leases = cam["leases"]
            for i, lease in enumerate(leases):
                if lease["pkg"] is pkg:
                    leases.pop(i)
                    if lease["state"] == "leased":
                        cam["leased"] -= 1
                    else:               # 过期未释放租约离账：不再仍计费
                        cam["lease_expired"] -= 1
                    cam["released_leases"] += 1
                    return True
            return False

    # ---- 观测与生命周期 ---------------------------------------------------

    def snapshot(self):
        """合同冻结结构的线程安全只读快照（不含路径/凭据/帧数据）。

        C-134 冻结字段全保留；C-135 新增：每相机 waiting_l1/consumable/
        fallback/late_promotions/l1_timeouts（§一）与 active_leases/
        released_leases/expired_leases/consumer_alive_bytes/store_bytes
        （§二，lease_bytes=consumer_alive_bytes、total_bytes=store_bytes
        兼容别名）。维护 sweep 挂在本调用点。
        """
        with self._lock:
            now_s = self._clock()
            now_mono_ms = now_s * 1000.0
            self._drain_dead_locked()
            self._sweep_expired_locked(now_mono_ms)
            self._sweep_leases_locked(now_s)
            self._sweep_l1_wait_locked(now_mono_ms)
            cameras = {}
            total_packages = 0
            active_leases = 0
            released_leases = 0
            expired_leases = 0
            for camera_id in sorted(self._cams):
                cam = self._cams[camera_id]
                ring = cam["ring"]
                total_packages += len(ring)
                active_leases += cam["leased"]
                released_leases += cam["released_leases"]
                expired_leases += cam["lease_expired"]
                oldest_age_s = None
                if ring:
                    oldest_age_s = max(
                        0.0,
                        (now_mono_ms - ring[0].created_mono_ms) / 1000.0)
                waiting = consumable = fallback = 0
                for pkg in ring:
                    if pkg.state == "waiting_l1":
                        waiting += 1
                    elif pkg.state == "consumable":
                        consumable += 1
                    elif pkg.state == "fallback_terminal":
                        fallback += 1
                cameras[camera_id] = {
                    "ready": consumable + fallback,
                    "waiting_l1": waiting,
                    "consumable": consumable,
                    "fallback": fallback,
                    "late_promotions": cam["late_promotions"],
                    "l1_timeouts": cam["l1_timeouts"],
                    "consumed": cam["consumed"],
                    "expired": cam["expired"],
                    "dropped_pressure": cam["dropped_pressure"],
                    "global_drops": cam["global_drops"],
                    "rejected_attach": cam["rejected_attach"],
                    "attach_missed": cam["attach_missed"],
                    "dup_rejected": cam["dup_rejected"],
                    "leased": cam["leased"],
                    "active_leases": cam["leased"],
                    "lease_expired": cam["lease_expired"],
                    "expired_leases": cam["lease_expired"],
                    "released_leases": cam["released_leases"],
                    "lease_bytes": cam["consumer_alive_bytes"],
                    "consumer_alive_bytes": cam["consumer_alive_bytes"],
                    "total_bytes": cam["total_bytes"],
                    "store_bytes": cam["total_bytes"],
                    "oldest_age_s": oldest_age_s,
                    "ready_with_prev": sum(1 for p in ring
                                           if p.prev is not None),
                    "ready_with_next": sum(1 for p in ring
                                           if p.nxt is not None),
                    "last_l1_status": cam["last_l1_status"],
                    "last_l1_accepted": cam["last_l1_accepted"],
                    "last_reject_reason": cam["last_reject_reason"],
                    # C-144：最近包的触发原因（供界面状态映射与准入诊断）
                    "last_material_reason": (ring[-1].material_reason
                                             if ring else None),
                }
            return {"cameras": cameras,
                    "total_bytes": self._total_bytes,
                    "store_bytes": self._total_bytes,
                    "lease_bytes": self._consumer_alive_bytes,
                    "consumer_alive_bytes": self._consumer_alive_bytes,
                    "active_leases": active_leases,
                    "released_leases": released_leases,
                    "expired_leases": expired_leases,
                    "total_packages": total_packages}

    def close(self):
        """M5：进入 closing→stopped（幂等）。

        释放全部未取走包的帧引用与字节预算；此后 ingest/attach 恒拒（内部
        计 closed，与显式清空区分），不重新积存。在途租约如实保留（活跃/
        过期未释放的租约槽位与真实存活字节保留：到期只标记；显式 release
        解除任务资格，数组真被回收才经 finalize 返还字节）；已 take_ready
        取走的隔离副本不受影响。快照随包清零但相机计数器与租约账面保留。
        """
        with self._lock:
            self._state = "closing"
            self._drain_dead_locked()
            if self._cams or self._ledger:
                self._sweep_leases_locked(self._clock())
                for cam in self._cams.values():
                    ring = cam["ring"]
                    while ring:
                        old = ring.pop()
                        for frame in (old.prev, old.cur, old.nxt):
                            if frame is not None:
                                self._unref_locked(frame)
            self._state = "stopped"

    # ---- 内部 --------------------------------------------------------------

    def _new_cam_locked(self, camera_id):
        cam = {"ring": [], "consumed": 0, "expired": 0, "dropped_pressure": 0,
               "global_drops": 0, "rejected_attach": 0, "attach_missed": 0,
               "dup_rejected": 0, "leased": 0, "lease_expired": 0,
               "released_leases": 0, "consumer_alive_bytes": 0,
               "late_promotions": 0, "l1_timeouts": 0, "total_bytes": 0,
               "last_l1_status": None, "last_l1_accepted": None,
               "last_reject_reason": None, "leases": [],
               "consumed_ids": collections.deque(),
               "consumed_set": set()}
        self._cams[camera_id] = cam
        self._rejects[camera_id] = {kind: 0 for kind in self._REJECT_KINDS}
        return cam

    def _count_reject_locked(self, camera_id, kind):
        counters = self._rejects.setdefault(
            camera_id, {kind_: 0 for kind_ in self._REJECT_KINDS})
        counters[kind] = counters.get(kind, 0) + 1

    def _ref_locked(self, frame):
        """记账一个在仓槽位引用；0→>0 时该独立图像对象开始计费。"""
        entry = self._ledger.get(frame.key)
        if entry is None:
            return
        if entry["refs"] == 0:
            self._total_bytes += entry["nbytes"]
            self._cams[entry["cam"]]["total_bytes"] += entry["nbytes"]
        entry["refs"] += 1

    def _unref_locked(self, frame):
        """释放一个在仓槽位引用；最后引用消失才真正减费（M3）。"""
        entry = self._ledger.get(frame.key)
        if entry is None:
            return
        entry["refs"] -= 1
        if entry["refs"] <= 0:
            del self._ledger[frame.key]
            self._total_bytes -= entry["nbytes"]
            self._cams[entry["cam"]]["total_bytes"] -= entry["nbytes"]

    def _register_alive_bills_locked(self, cam, camera_id, copy):
        """C-135 §二 + C-136 A1：对租约副本的每个图像数组注册
        weakref.finalize 并即时入账——**准备段**，在原子提交消费（摘包/
        计数/租约）之前完成全部注册。任一注册异常 → detach 已注册
        finalize（回调永不触发，防幽灵回收记录）+ 精确回退已入账字节
        （全局与每相机同步）+ 异常原样上抛——仓状态一个比特都没动，不
        产生半提交（幽灵槽）。

        finalize 绑定基对象（副本数组本身）：消费者持有的视图/别名引用
        基对象——视图存活即基对象存活，计费正确；消费者自行额外 copy 出
        的新数组不注册、不归本模块计费。回调只做线程安全的 deque.append
        （无锁、无重入），账目由 _drain_dead_locked 在仓调用点排空——
        规避 GC 在持锁路径触发回收时的回调重入死锁。注册全程持仓锁且副
        本数组被局部变量持有（不可回收），回滚窗口内无 finalize 触发，
        detach+回退精确无损。
        """
        pending = self._pending_dead
        registered = []
        billed = 0
        try:
            for frame in (copy.prev, copy.cur, copy.nxt):
                if frame is None:
                    continue
                nbytes = int(frame.frame_bgr.nbytes)
                registered.append(weakref.finalize(
                    frame.frame_bgr, pending.append, (camera_id, nbytes)))
                billed += nbytes
                self._consumer_alive_bytes += nbytes
                cam["consumer_alive_bytes"] += nbytes
        except BaseException:
            for fin in registered:
                fin.detach()            # 回调永不触发：防幽灵回收记录
            self._consumer_alive_bytes -= billed
            cam["consumer_alive_bytes"] -= billed
            raise

    def _drain_dead_locked(self):
        """排空 finalize 入队的真实回收记录：consumer_alive_bytes 随数组
        真回收如实回落（全局与每相机分账同步减除）。"""
        pending = self._pending_dead
        while pending:
            camera_id, nbytes = pending.popleft()
            self._consumer_alive_bytes -= nbytes
            cam = self._cams.get(camera_id)
            if cam is not None:
                cam["consumer_alive_bytes"] -= nbytes

    def _sweep_l1_wait_locked(self, now_mono_ms):
        """C-135 §一：waiting_l1 包等待超 l1_wait_s（单调钟，严格大于）→
        fallback_terminal(reason="l1_wait_timeout")，计 l1_timeouts。
        sweep 挂在 ingest/take_ready/attach_result/snapshot 调用点，无新
        线程，不阻塞。TTL/预算逐出照旧（expired/dropped_pressure 口径），
        与本迁移分账。"""
        limit_ms = self.l1_wait_s * 1000.0
        for cam in self._cams.values():
            for pkg in cam["ring"]:
                if pkg.state != "waiting_l1":
                    continue
                if now_mono_ms - pkg.created_mono_ms > limit_ms:
                    pkg.state = "fallback_terminal"
                    pkg.l1_terminal_reason = "l1_wait_timeout"
                    cam["l1_timeouts"] += 1

    def _evict_head_locked(self, cam, *, global_pressure):
        """逐出相机最旧包（创建序即最旧在前），只减其独占槽位引用。"""
        old = cam["ring"].pop(0)
        for frame in (old.prev, old.cur, old.nxt):
            if frame is not None:
                self._unref_locked(frame)
        cam["dropped_pressure"] += 1
        if global_pressure:
            cam["global_drops"] += 1
        return old

    def _make_room_locked(self, cam, nbytes):
        """为 nbytes 腾容量：本相机包数超限逐本相机最旧包（本地压力）；
        全库真实存活字节超限跨相机按 created_mono 逐最旧包（M3 公平，
        计 global_drops）。逐出后引用计数即时重算。返回 False=放不下。
        """
        ring = cam["ring"]
        while True:
            over_local = len(ring) >= self.max_packages_per_camera
            over_global = self._total_bytes + nbytes > self.max_total_bytes
            if not over_local and not over_global:
                return True
            if over_local and ring:
                self._evict_head_locked(cam, global_pressure=False)
                continue
            victim_cam = None
            victim_head = None
            for other in self._cams.values():
                other_ring = other["ring"]
                if other_ring:
                    head = other_ring[0]
                    if (victim_head is None
                            or head.created_mono_ms < victim_head.created_mono_ms):
                        victim_cam, victim_head = other, head
            if victim_cam is None:
                return False
            self._evict_head_locked(victim_cam, global_pressure=True)

    def _sweep_expired_locked(self, now_mono_ms):
        """逐出全部相机超龄包（创建序即最旧在前）；计 expired 回落预算。"""
        max_age_ms = self.max_age_s * 1000.0
        for cam in self._cams.values():
            ring = cam["ring"]
            while ring:
                if now_mono_ms - ring[0].created_mono_ms <= max_age_ms:
                    break                   # 按创建序排列，后面只会更新
                old = ring.pop(0)
                for frame in (old.prev, old.cur, old.nxt):
                    if frame is not None:
                        self._unref_locked(frame)
                cam["expired"] += 1

    def _sweep_leases_locked(self, now_s):
        """A1：租约 TTL 到期只做状态标记与计数——state leased→expired、
        leased→lease_expired 迁移；**不动字节账**（consumer_alive_bytes
        跟随真实存活对象，由 finalize 口径决定）；显式 release(pkg) 只
        解除 store 强引用与任务资格，数组真被回收才真实返还字节。"""
        for cam in self._cams.values():
            for lease in cam["leases"]:
                if (lease["state"] == "leased"
                        and now_s - lease["born"] > self.max_lease_s):
                    lease["state"] = "expired"
                    cam["leased"] -= 1
                    cam["lease_expired"] += 1

    @staticmethod
    def _package_bytes(pkg):
        """租约计费字节 = 副本实际持有的全部图像字节（prev/cur/nxt）。"""
        total = 0
        for frame in (pkg.prev, pkg.cur, pkg.nxt):
            if frame is not None:
                total += int(frame.frame_bgr.nbytes)
        return total

    def _copy_frame_locked(self, frame):
        if frame is None:
            return None
        # 副本 key=None：不进引用计数账本，与仓内原图彻底脱钩（M4）
        return MaterialFrame(frame.frame_id, frame.frame_bgr.copy(),
                             frame.t_capture_ms, frame.timestamp_kind,
                             material_reason=getattr(frame,
                                                     "material_reason",
                                                     None))

    @staticmethod
    def _copy_detections(detections):
        """A3：检测结果逐检测深拷贝（新 list + 新 dict + 新 bbox list +
        逐字段）——外部改原结构或改取走副本的嵌套框互不污染。None 显式
        透传；track_id 等字段原样透传不伪造（缺就是缺）。"""
        if detections is None:
            return None
        if isinstance(detections, list):
            return [_copy_fields(det) if isinstance(det, dict) else det
                    for det in detections]
        return detections

    def _copy_package_locked(self, pkg):
        """A2：**纯构建**隔离副本，不改任何仓状态（调用方在全部构建成功
        后才原子提交）：prev/cur/nxt 图像 .copy()、框与检测逐字段深拷贝
        （A2 框深拷贝 / A3 检测深拷贝）、字段复制（含 l1_terminal_reason
        与 late_promotion 标记）。"""
        cur = self._copy_frame_locked(pkg.cur)
        prev = self._copy_frame_locked(pkg.prev)
        nxt = self._copy_frame_locked(pkg.nxt)
        copy = MaterialPackage(
            pkg.camera_id, pkg.run_id, pkg.config_version, pkg.material_id,
            pkg.created_mono_ms, cur,
            [_copy_fields(box) for box in (pkg.change_boxes or [])],
            pkg.gate_w, pkg.gate_h)
        copy.prev = prev
        copy.nxt = nxt
        copy.prev_gap_ms = pkg.prev_gap_ms
        copy.nxt_gap_ms = pkg.nxt_gap_ms
        copy.l1_status = pkg.l1_status
        copy.l1_error_code = pkg.l1_error_code
        copy.detections = self._copy_detections(pkg.detections)
        copy.last_l1_accepted = pkg.last_l1_accepted
        copy.last_reject_reason = pkg.last_reject_reason
        copy.l1_terminal_reason = pkg.l1_terminal_reason
        copy.late_promotion = pkg.late_promotion
        copy.role = pkg.role                   # C-137：生命周期标签随副本透传
        copy.area_at_entry = pkg.area_at_entry
        copy.material_reason = pkg.material_reason   # C-144：原因随副本透传
        copy.state = "consumed"
        return copy
