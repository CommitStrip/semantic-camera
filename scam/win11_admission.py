# -*- coding: utf-8 -*-
"""C-144-R2 深度理解准入与重复抑制（冻结 §1；纯内存纯函数风格）。

decide() 是 L2/L3 深度理解任务的唯一准入判别点：patrol 材料默认无
深度理解资格（L1 巡检=对象连续性/健康，不是理解资格）；真实变化才
准入。状态由调用方持有（本模块无全局可变状态），阈值常量冻结在模块头。

坐标单位（冻结 §0）：
- 门控变化框 = 像素坐标 → 像素阈值（MIN_MOVE_PX）只用于该维度；
- L1 检测框 bbox = 归一化坐标 → 归一化比例阈值（DET_MOVE_RATIO），
  绝不与像素阈值混算。

C-144-R2 语义（取代 R1）：
- **统一配对**：一次最近邻贪心配对产生同一映射，中心位移与尺寸比较
  都读该映射——排序交换/邻近抖动不产生伪变化，尺寸排序不参与配对。
- **边沿驱动**：变化框"有→无"=回稳（cleared），"无→有"=静→动新
  边沿（即时准入）——删除 60s 时间再武装（巡检刷新时间使其失效，
  且会把同位置新动作强制延迟）；持续供框几何相同=同一持续变化，抑制。
- **离开与原位返回**：L1 状态三态（detected/confirmed_empty/
  unavailable）；连续 LEAVE_CONFIRM_COUNT 次有效空 → 一次离开变化
  （之后持续空不再产生离开任务）；失败/超时重置连续计数（不累计）；
  离开后同一对象原位返回 → 重新获得变化资格。
- **时间四分**：last_seen_s（每次观察推进）/last_change_s（仅真实
  变化推进，巡检不重置）/last_admit_s（仅准入推进）/retry_count
  （任务未接纳的重试计数，调用方维护）。超窗（SCENE_REF_WINDOW_S）
  仅作 reason 标注——**不自动触发重模型调用**（静止 30 分钟零调用）。
"""
import math

# —— 冻结阈值（模块常量；改动即语义变化须升版） ——
# 门控变化框（像素坐标）：中心位移比例（相对门控对角线）与绝对下限
MOVE_RATIO = 0.03
MIN_MOVE_PX = 1.0
# L1 检测框（归一化坐标）：中心/尺寸变化比例阈值（无像素下限——归一
# 化坐标没有"像素"概念，不与像素阈值混算）
DET_MOVE_RATIO = 0.03
# 框尺寸变化比例：同一配对内宽/高变化超此值 = 缩放变化（moved）
SIZE_CHANGE_RATIO = 0.25
# 场景参考观察复用窗（秒）：仅用于 reason 标注（scene_ref_expired）；
# 超窗**不清参考、不自动 admit**（静止 30 分钟零调用）
SCENE_REF_WINDOW_S = 300.0
# 连续有效确认空次数：达到后产生**一次**离开变化；失败/超时重置计数
LEAVE_CONFIRM_COUNT = 3
# 任务未接纳（队列拒收/材料过期）后的重试准入上限（调用方维护计数）
ADMIT_RETRY_MAX = 2

DECISIONS = ("admit_initial", "admit_change", "admit_recovery",
             "suppress_no_new_info", "suppress_duplicate")

DET_STATUSES = ("detected", "confirmed_empty", "unavailable")


def _finite(value):
    return (isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value))


def _center_and_size_of(box):
    """单框中心+尺寸：兼容生产 dict 形态（monitor 合同 {"x","y","w","h"}）
    与测试数组形态 [x, y, w, h]；坏框/缺键/非有限值 → None（跳过不抛）。"""
    try:
        if isinstance(box, dict):
            x, y = box.get("x"), box.get("y")
            w, h = box.get("w"), box.get("h")
        else:
            x, y, w, h = box[0], box[1], box[2], box[3]
        cx = float(x) + float(w) / 2.0
        cy = float(y) + float(h) / 2.0
        bw = float(w)
        bh = float(h)
    except (TypeError, ValueError, IndexError, KeyError, AttributeError):
        return None
    if not (_finite(cx) and _finite(cy) and _finite(bw) and _finite(bh)):
        return None
    return (cx, cy, bw, bh)


def change_signature(change_boxes):
    """门控变化框签名（**像素坐标原样**，不归一化）。

    返回 (count, items) 或 None（空/无有效框）；items=[(cx,cy,w,h),…]
    按 (cx,cy) 稳定排序（顺序抖动不改变签名）。"""
    items = []
    for box in change_boxes or ():
        cs = _center_and_size_of(box)
        if cs is not None:
            items.append(cs)
    if not items:
        return None
    items.sort(key=lambda c: (round(c[0], 3), round(c[1], 3)))
    return (len(items), tuple(items))


def det_signature(detections):
    """L1 检测框签名（归一化坐标）：中心+尺寸点集。

    detections 为 L1 输出列表（dict 含归一化 bbox=[x,y,w,h]）；坏项跳过。
    空列表/无有效框 → None（是否=确认空由 det_status 判定，见 decide）。"""
    items = []
    for det in detections or ():
        try:
            bbox = det["bbox"]
            cs = _center_and_size_of((bbox[0], bbox[1], bbox[2], bbox[3]))
        except (TypeError, ValueError, IndexError, KeyError, AttributeError):
            continue
        if cs is None:
            continue
        items.append((round(cs[0], 4), round(cs[1], 4),
                      round(cs[2], 4), round(cs[3], 4)))
    if not items:
        return None
    items.sort()
    return (len(items), tuple(items))


def _pair_objects(items_a, items_b):
    """统一最近邻贪心配对（冻结 §1.4）：返回 (pairs, unmatched_a)。

    pairs=[(ia, ib, dist),…]；配对代价=中心欧氏距离，不按数组序/尺寸序。
    中心位移与尺寸比较都使用这一个映射。"""
    pairs = []
    used_b = set()
    for ia, a in enumerate(items_a):
        best = None
        for ib, b in enumerate(items_b):
            if ib in used_b:
                continue
            d = math.hypot(a[0] - b[0], a[1] - b[1])
            if best is None or d < best[0]:
                best = (d, ib)
        if best is not None:
            pairs.append((ia, best[1], best[0]))
            used_b.add(best[1])
    paired_a = {p[0] for p in pairs}
    unmatched_a = [ia for ia in range(len(items_a)) if ia not in paired_a]
    return pairs, unmatched_a


def _both_present_moved(last_sig, cur_sig, threshold):
    """两侧签名均非空：经同一配对判变化——出现/消失对象（映射外）、
    配对中心位移超阈值、配对尺寸变化超 SIZE_CHANGE_RATIO，任一即 moved。"""
    items_a = last_sig[1]
    items_b = cur_sig[1]
    if len(items_a) != len(items_b):
        return True
    pairs, unmatched_a = _pair_objects(items_a, items_b)
    if unmatched_a:
        return True
    for ia, ib, dist in pairs:
        if dist > threshold:
            return True
        aw, ah = items_a[ia][2], items_a[ia][3]
        bw, bh = items_b[ib][2], items_b[ib][3]
        if aw > 0 and abs(bw - aw) / aw > SIZE_CHANGE_RATIO:
            return True
        if ah > 0 and abs(bh - ah) / ah > SIZE_CHANGE_RATIO:
            return True
    return False


def _change_threshold(sig_a, sig_b):
    """门控变化框维度阈值：像素位移比例（相对双侧点集对角线）+绝对下限。"""
    xs = [c[0] for c in sig_a[1] + sig_b[1]]
    ys = [c[1] for c in sig_a[1] + sig_b[1]]
    diag = max(1.0, math.hypot(max(xs) - min(xs), max(ys) - min(ys)))
    return max(MOVE_RATIO * diag, MIN_MOVE_PX)


def _det_threshold():
    """检测框维度阈值：归一化坐标，相对单位正方形对角线。"""
    return DET_MOVE_RATIO * math.hypot(1.0, 1.0)


def resolve_det_status(det_status=None, detections=None,
                       detections_present=None, confirmed_leave=False,
                       cur_det=None):
    """L1 检测状态三态推导（冻结 §1.1；旧参数兼容）。

    显式 det_status 优先；否则由旧参数推导：
    - detections 非空有效 → detected；
    - detections 空列表 + detections_present=False（或 confirmed_leave）
      → confirmed_empty（有效确认空）；
    - 其余（present=None / detections=None）→ unavailable
      （失败/超时/缺失——**不等于离开**）。"""
    if det_status in DET_STATUSES:
        return det_status
    if detections is not None:
        if cur_det is not None:
            return "detected"
        if detections_present is False or confirmed_leave:
            return "confirmed_empty"
        return "unavailable"
    return "unavailable"


def decide(*, material_reason, change_boxes, gate_w=None, gate_h=None,
           identity, scene_ref=None, recovery=False, now_s=None,
           detections=None, detections_present=None, confirmed_leave=False,
           det_status=None):
    """深度理解准入判别（C-144-R2 冻结 §1；唯一入口）。

    参数
    ----
    material_reason:
        材料触发原因（change_start|latest|patrol；其他值按 patrol 保守
        处理——不冒充变化）。
    change_boxes:
        该材料的门控变化框（像素坐标；patrol 恒空）。
    gate_w / gate_h:
        门控尺寸（签名用像素原样；保留参数位以兼容调用方）。
    identity:
        完整身份 dict（camera_id/run_id/config_version）——任一变化使
        场景参考失效。
    scene_ref:
        **场景参考状态** dict 或 None（结构见模块 docstring/冻结 §1.2）；
        调用方必须保存并在下次 decide 传入每次返回的 new_scene_ref。
    recovery:
        显式人工重分析（单次判定即消耗；不因巡检反复触发）。
    now_s:
        当前单调秒（调用方注入；时间四分与超窗标注用）。
    det_status / detections / detections_present / confirmed_leave:
        L1 检测状态（三态优先；旧参数经 resolve_det_status 兼容推导）。

    返回 (decision, reason_code, new_scene_ref)。
    """
    cur_change = change_signature(change_boxes)
    cur_det = det_signature(detections)
    det_status = resolve_det_status(det_status=det_status,
                                    detections=detections,
                                    detections_present=detections_present,
                                    confirmed_leave=confirmed_leave,
                                    cur_det=cur_det)
    prev_retry = 0
    if isinstance(scene_ref, dict):
        prev_retry = scene_ref.get("retry_count", 0) or 0

    def _ref(*, change_sig, det_sig, ref_det_status, leave_count, left,
             cleared, last_change_s, last_admit_s):
        return {"identity": dict(identity or {}),
                "change_sig": change_sig, "det_sig": det_sig,
                "det_status": ref_det_status, "leave_count": leave_count,
                "left": left, "cleared": cleared,
                "last_seen_s": now_s, "last_change_s": last_change_s,
                "last_admit_s": last_admit_s, "retry_count": prev_retry}

    if recovery:
        return ("admit_recovery", "recovery_requested",
                _ref(change_sig=cur_change, det_sig=cur_det,
                     ref_det_status=det_status, leave_count=0, left=False,
                     cleared=False, last_change_s=now_s, last_admit_s=now_s))

    # 场景参考有效性：身份逐键等值（camera/run/config 任一变化即失效）。
    # 超窗**不**失效（reusable 仍 True）——恒抑制直到真实变化（静止
    # 30 分钟零调用的关键）。
    reusable = False
    if isinstance(scene_ref, dict):
        ref_ident = scene_ref.get("identity") or {}
        keys = ("camera_id", "run_id", "config_version")
        reusable = all(ref_ident.get(k) == (identity or {}).get(k)
                       for k in keys)
    if not reusable:
        if det_status == "unavailable" and cur_change is None:
            # A failure/timeout carries no scene observation to initialize.
            return ("suppress_no_new_info", "observation_unavailable", scene_ref)
        return ("admit_initial", "no_prior_scene_ref",
                _ref(change_sig=cur_change, det_sig=cur_det,
                     ref_det_status=det_status, leave_count=0, left=False,
                     cleared=False, last_change_s=now_s, last_admit_s=now_s))

    last_change_sig = scene_ref.get("change_sig")
    last_det_sig = scene_ref.get("det_sig")
    last_det_status = scene_ref.get("det_status", "unavailable")
    last_change_s = scene_ref.get("last_change_s")
    last_admit_s = scene_ref.get("last_admit_s")
    leave_count = scene_ref.get("leave_count", 0) or 0
    left = bool(scene_ref.get("left"))
    cleared = bool(scene_ref.get("cleared"))

    ref_stale = (_finite(now_s)
                 and _finite(scene_ref.get("last_seen_s"))
                 and now_s - scene_ref["last_seen_s"] > SCENE_REF_WINDOW_S)

    # ---- det 维度（离开/返回/位移/缩放；失败≠离开） ----
    det_moved = False
    det_reason = None
    new_leave_count = leave_count
    new_left = left
    # unavailable：保留旧签名与旧状态（恢复后同位对象不误报出现）；
    # 其余状态用本次观察。
    ref_det_status = (last_det_status if det_status == "unavailable"
                      or (det_status == "confirmed_empty" and last_det_sig is not None)
                      else det_status)
    if det_status == "detected":
        new_leave_count = 0
        if left:
            det_moved = True                  # 原位返回：重新获得资格
            det_reason = "change_return"
            new_left = False
        elif last_det_sig is None or last_det_status != "detected":
            det_moved = cur_det is not None   # 空/失败后重现：出现边沿
            if det_moved:
                det_reason = "signature_changed"
        elif cur_det is not None:
            if _both_present_moved(last_det_sig, cur_det, _det_threshold()):
                det_moved = True
                det_reason = "signature_changed"
    elif det_status == "confirmed_empty":
        if not left and last_det_sig is not None:
            if confirmed_leave:
                new_leave_count = LEAVE_CONFIRM_COUNT
            else:
                new_leave_count = leave_count + 1
            if new_leave_count >= LEAVE_CONFIRM_COUNT:
                det_moved = True              # 一次离开变化
                det_reason = "change_leave"
                new_left = True
                new_leave_count = 0
                ref_det_status = "confirmed_empty"
        elif last_det_sig is None:
            new_leave_count = 0
    else:
        # unavailable：失败/超时**重置**连续空计数（只有连续有效 empty
        # 才可判离开）；不判离开、不推进 det 参考。
        new_leave_count = 0

    # ---- change 维度（边沿驱动；无时间再武装） ----
    change_moved = False
    settled = False
    if last_change_sig is None:
        change_moved = cur_change is not None   # 静→动新边沿（即时）
    elif cur_change is None:
        settled = True                          # 回稳（cleared）
    else:
        change_moved = _both_present_moved(
            last_change_sig, cur_change, _change_threshold(last_change_sig,
                                                           cur_change))
    new_cleared = True if settled else (False if change_moved else cleared)

    # 参考推进规则（累计变化语义——小幅抑制不丢累计量）：
    # admit：参考推进到本次观察；
    # 抑制：**保留**参考（det 累计相对上次准入点测量；change 保留原
    # 几何直到回稳）；例外=离开确认完成后记 det_sig=None、
    # 回稳记 change_sig=None（静→动新边沿依据）。
    if det_status == "confirmed_empty" and new_left:
        sup_det_sig = None
    else:
        sup_det_sig = last_det_sig
    sup_change_sig = None if settled else last_change_sig

    if det_moved or change_moved:
        admit_det_sig = (cur_det if det_status == "detected"
                         else (None if det_status == "confirmed_empty"
                               else last_det_sig))
        return ("admit_change", det_reason or "signature_changed",
                _ref(change_sig=cur_change, det_sig=admit_det_sig,
                     ref_det_status=ref_det_status,
                     leave_count=new_leave_count, left=new_left,
                     cleared=new_cleared, last_change_s=now_s,
                     last_admit_s=now_s))

    # ---- 双维度均无实质变化：抑制（时间四分——last_change_s /
    #      last_admit_s 不被巡检重置；超窗仅改 reason 标注） ----
    if cur_change is not None or cur_det is not None:
        return ("suppress_duplicate", "same_signature",
                _ref(change_sig=sup_change_sig, det_sig=sup_det_sig,
                     ref_det_status=ref_det_status,
                     leave_count=new_leave_count, left=new_left,
                     cleared=new_cleared, last_change_s=last_change_s,
                     last_admit_s=last_admit_s))
    return ("suppress_no_new_info",
            "patrol_no_change" if not ref_stale else "scene_ref_expired",
            _ref(change_sig=sup_change_sig, det_sig=sup_det_sig,
                 ref_det_status=ref_det_status,
                 leave_count=new_leave_count, left=new_left,
                 cleared=new_cleared, last_change_s=last_change_s,
                 last_admit_s=last_admit_s))
