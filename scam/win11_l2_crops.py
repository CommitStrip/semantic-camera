"""win11_l2_crops.py —— L2 纯裁图引擎（C-134 §0 + C-135 §六；规则源自
C-133 §3）。

从候选双方框生成联合区域/外扩/夹取/去重/预算，加上全景与变化区域支路的
纯构建，输出 CropRecord + 图像裁剪（numpy 切片 .copy()，消费者改写不污染
任务帧）。不调用任何模型、零 I/O（JPEG 编码仅为内存内计量，不落盘）。

规则（全部保守占位，待实测调整）：
- 联合框外扩：每侧 margin = k × max(union_w, union_h)，建议 k=0.2；下限
  保底 margin ≥ 0.02（归一化，避免贴脸零上下文）。
- 面积上限（外扩行为，C-133 延续）：外扩后联合框面积超帧面积上限
  （UNION_AREA_CAP=0.5）不再外扩并标注 context_capped；原始联合框本身超
  上限→改用整帧并标注 whole_frame_fallback + 省略理由（与全景分支重叠，
  如实记录）。整帧替代不受单张预算约束（"整帧兜底除外"）。
- 夹取：裁框夹取到帧边界 [0,1]；夹取事实记入 clamped（请求框任一边抵达
  或越出帧边界即记——贴边意味着最终裁框坐标由帧边界截定，上下文在边界外
  被截断）；像素框经 floor/ceil（带 1e-9 容差吸收浮点尘埃，避免坐标恰在
  整数时多算一像素列/行）并夹取到实际帧尺寸；归一化→像素按分量语义换算
  （x/y 分量夹到 [0,1]、宽高换算保持不变——负坐标平移不改变 w/h 的像素
  换算）；裁图必完整包含双方（夹取后的）参与者框——不用孤立人像替代
  互动区域。
- 非法框拒收：NaN/Inf/负宽高/零面积/完全越界的参与者框→拒该候选，计入
  omitted（invalid_participant_box）；退化框永不参与配对产出（C-133 T4）。
- 单张预算三判据（C-135 §六，取消 C-134"按帧面积同比放大"单判据）：
  max_crop_area_ratio（最终裁框占帧面积比例上限）+ max_crop_pixels_fixed
  （绝对像素上限）+ max_crop_bytes（JPEG 编码后字节上限，编码仅用于内存
  内计量不落盘，固定质量 JPEG_MEASURE_QUALITY 保证确定性）——三者独立
  验证取最严，超限显式记账（crop_area_ratio_cap / crop_pixels_cap /
  crop_bytes_cap）不静默丢弃；整帧替代豁免。cv2 不可用导致字节无法计量
  时如实记 bytes_budget_unmeasurable 并放行（绝不用估算值冒充实测）。
- 参与者覆盖不变式（C-135 §六 B2）：IoU≥0.8 的确定性去重合并附加守卫——
  被合并候选的双方参与者框必须与保留裁框相交 ≥ 其可见面积
  PARTICIPANT_MIN_COVERAGE（0.5），否则独立成图（记录与实际裁图一致，
  不能只追加候选来源却裁掉新增参与者）；coverage_ratio 分母=参与者框与
  帧的交集（可见部分，出帧部分物理不可覆盖不计入）。构建后可用
  verify_participant_coverage 对成品记录整体核验，返回违规清单。
- 确定性去重：裁框 IoU ≥ 0.8 视为重复区域→合并为一张裁图；被合并的全部
  候选与理由保留在 reason_candidates（merged_count 记数）；spatial/semantic
  双图对同一对对象产生的候选按同一规则去重。排序键 (-score, 出现序) 保证
  同分确定性。
- 归一化框 IoU 与像素分辨率无关（尺度不变），去重与外扩在归一化空间判定
  （C-133 T5）；像素绝对预算按 C-135 新判据在高分辨率如实触发（不再随帧
  面积放大——同归一化框在高清下可因绝对上限被拒，这是预算的真实语义）。
"""

import math

from scam.win11_l2_contract import (
    CropRecord,
    CropTransform,
)

MARGIN_RATIO = 0.2        # C-133 §3.1 建议值 k（整体约 ×1.4 覆盖），待实测
MIN_MARGIN_NORM = 0.02    # 外扩下限保底（归一化），避免贴脸零上下文
UNION_AREA_CAP = 0.5      # 联合框/外扩后面积上限（帧面积占比，外扩行为），
#                          待实测；单张预算另由 L2Budget.max_crop_area_ratio
#                          独立裁决（C-135 §六）
DEDUP_IOU = 0.8           # 重复区域合并阈值，待实测
_PX_EPS = 1e-9            # 像素换算容差：吸收浮点尘埃，不放大裁框
JPEG_MEASURE_QUALITY = 85  # 字节预算计量用 JPEG 质量（固定值保证确定性；
#                            与 scam/environment.py 证据编码同档）
PARTICIPANT_MIN_COVERAGE = 0.5  # 参与者覆盖不变式下限（可见面积占比）

__all__ = [
    "CropRequest",
    "DEDUP_IOU",
    "JPEG_MEASURE_QUALITY",
    "MARGIN_RATIO",
    "MIN_MARGIN_NORM",
    "PARTICIPANT_MIN_COVERAGE",
    "UNION_AREA_CAP",
    "box_iou",
    "build_candidate_crops",
    "build_change_region_crops",
    "build_whole_frame_crop",
    "clamp_box",
    "coverage_ratio",
    "expand_box",
    "is_valid_box",
    "jpeg_encoded_bytes",
    "norm_box_to_px",
    "slice_region",
    "union_box",
    "verify_participant_coverage",
]


class CropRequest:
    """单候选裁图请求：候选三元组 + 参与双方归一化框（由 stage 配对给出，
    引擎不做身份反查）。"""

    __slots__ = ("candidate", "subject_box_norm", "object_box_norm")

    def __init__(self, candidate, subject_box_norm, object_box_norm):
        self.candidate = candidate
        self.subject_box_norm = subject_box_norm
        self.object_box_norm = object_box_norm


# ---- 纯几何助手（归一化 [x,y,w,h]） ----------------------------------------

def is_valid_box(box):
    """合法参与框：有限值、正宽高、与帧有正面积交集（完全越界=非法）。

    部分出帧的框合法（后续夹取）；NaN/Inf/负宽高/零面积/完全出帧非法。
    """
    x, y, w, h = (float(v) for v in box)
    if not all(math.isfinite(v) for v in (x, y, w, h)):
        return False
    if w <= 0.0 or h <= 0.0:
        return False
    if x >= 1.0 or y >= 1.0 or x + w <= 0.0 or y + h <= 0.0:
        return False                      # 完全在帧外
    return True


def union_box(a, b):
    """双方框联合框（归一化）。"""
    ax, ay, aw, ah = (float(v) for v in a)
    bx, by, bw, bh = (float(v) for v in b)
    x1, y1 = min(ax, bx), min(ay, by)
    x2 = max(ax + aw, bx + bw)
    y2 = max(ay + ah, by + bh)
    return (x1, y1, x2 - x1, y2 - y1)


def expand_box(box, margin):
    """每侧外扩 margin（归一化）。"""
    x, y, w, h = (float(v) for v in box)
    return (x - margin, y - margin, w + 2.0 * margin, h + 2.0 * margin)


def clamp_box(box):
    """夹取到帧边界 [0,1]；返回 ((x,y,w,h), clamped) 或 None（夹取后退化）。

    clamped 语义（本批裁决 #3）：请求框任一边抵达或越出帧边界（≤0/≥1）即
    True——贴边意味着最终裁框坐标由帧边界截定（所求上下文在边界处被截断）；
    严格"越出才记"会把恰好落在边界上的裁框误报为未夹取，且对浮点尘埃方向
    敏感（1.0 与 1.0+ε 两位分）。
    """
    x, y, w, h = (float(v) for v in box)
    x2, y2 = x + w, y + h
    clamped = x <= 0.0 or y <= 0.0 or x2 >= 1.0 or y2 >= 1.0
    nx1 = min(max(x, 0.0), 1.0)
    ny1 = min(max(y, 0.0), 1.0)
    nx2 = min(max(x2, 0.0), 1.0)
    ny2 = min(max(y2, 0.0), 1.0)
    if nx2 <= nx1 or ny2 <= ny1:
        return None
    return (nx1, ny1, nx2 - nx1, ny2 - ny1), clamped


def box_iou(a, b):
    """归一化框 IoU（尺度不变：归一化空间与像素空间同值）。"""
    ax, ay, aw, ah = (float(v) for v in a)
    bx, by, bw, bh = (float(v) for v in b)
    ix1, iy1 = max(ax, bx), max(ay, by)
    ix2 = min(ax + aw, bx + bw)
    iy2 = min(ay + ah, by + bh)
    iw = max(0.0, ix2 - ix1)
    ih = max(0.0, iy2 - iy1)
    inter = iw * ih
    union = aw * ah + bw * bh - inter
    if union <= 0.0:
        return 0.0
    return inter / union


def coverage_ratio(participant_norm, crop_norm):
    """参与者可见面积被裁框覆盖的比例（参与者覆盖不变式的度量）。

    分母=参与者框与帧的交集面积（可见部分）——出帧部分物理不可覆盖，
    不计入分母（整帧裁框对部分出帧参与者恒覆盖其可见全部）；分母为 0
    （完全出帧/退化框）返回 1.0（无可见面积即无未覆盖物，不判违规）。
    """
    px, py, pw, ph = (float(v) for v in participant_norm)
    cx, cy, cw, ch = (float(v) for v in crop_norm)
    ix1, iy1 = max(px, cx), max(py, cy)
    ix2 = min(px + pw, cx + cw)
    iy2 = min(py + ph, cy + ch)
    inter = max(0.0, ix2 - ix1) * max(0.0, iy2 - iy1)
    vx1, vy1 = max(px, 0.0), max(py, 0.0)
    vx2 = min(px + pw, 1.0)
    vy2 = min(py + ph, 1.0)
    visible = max(0.0, vx2 - vx1) * max(0.0, vy2 - vy1)
    if visible <= 0.0:
        return 1.0
    return inter / visible


def jpeg_encoded_bytes(image_bgr):
    """JPEG 编码后的字节数（仅内存内计量：不落盘、不缓存、不外发）。

    编码器懒加载 cv2（生产既有依赖，与 evidence/environment 同款接口），
    固定 JPEG_MEASURE_QUALITY 质量保证同图同字节数（预算判定确定性）。
    cv2 不可用或编码失败返回 None——调用方如实记账（bytes_budget_
    unmeasurable）并放行，绝不用估算值冒充实测。
    """
    try:
        import cv2
    except Exception:                     # 依赖缺失：无法计量，如实上报
        return None
    try:
        ok, buf = cv2.imencode(
            ".jpg", image_bgr,
            [int(cv2.IMWRITE_JPEG_QUALITY), int(JPEG_MEASURE_QUALITY)])
    except Exception:                     # 编码器异常：同样不冒充
        return None
    if not ok:
        return None
    return int(buf.nbytes)


def norm_box_to_px(box, width, height):
    """归一化 [x,y,w,h] → 像素 [x1,y1,x2,y2]（int，夹取到帧尺寸）。

    分量语义（冻结文件 §1 bbox_norm 分量 + 本批裁决 #1）：x/y 分量夹取到
    [0,1]，宽高的像素换算保持不变（负坐标平移不改变 w/h 换算），远边
    x+w/y+h 按需夹到 ≤ 帧边界——部分出帧框换算后仍保有完整宽高。
    floor/ceil 带 _PX_EPS 容差——坐标换算恰好落在整数像素（浮点尘埃
    +1e-13 量级）时不多算一像素列/行。NaN/Inf 或夹取后退化返回 None。
    """
    x, y, w, h = (float(v) for v in box)
    if not all(math.isfinite(v) for v in (x, y, w, h)):
        return None
    iw, ih = int(width), int(height)
    x1n = min(max(x, 0.0), 1.0)             # x 分量夹到 [0,1]
    y1n = min(max(y, 0.0), 1.0)             # y 分量夹到 [0,1]
    x2n = min(x1n + w, 1.0)                 # 保持 w 换算；远边按需夹 ≤1
    y2n = min(y1n + h, 1.0)
    x1 = min(max(math.floor(x1n * iw + _PX_EPS), 0), iw)
    y1 = min(max(math.floor(y1n * ih + _PX_EPS), 0), ih)
    x2 = min(max(math.ceil(x2n * iw - _PX_EPS), 0), iw)
    y2 = min(max(math.ceil(y2n * ih - _PX_EPS), 0), ih)
    if x2 <= x1 or y2 <= y1:
        return None
    return (x1, y1, x2, y2)


def slice_region(frame_bgr, bbox_px):
    """按像素框切图（numpy 切片 + .copy()：改写裁图不污染任务帧）。"""
    x1, y1, x2, y2 = (int(v) for v in bbox_px)
    h = int(frame_bgr.shape[0])
    w = int(frame_bgr.shape[1])
    x1, x2 = max(0, min(x1, w)), max(0, min(x2, w))
    y1, y2 = max(0, min(y1, h)), max(0, min(y2, h))
    if x2 <= x1 or y2 <= y1:
        return None
    return frame_bgr[y1:y2, x1:x2, :].copy()


# ---- 候选裁图主路 -----------------------------------------------------------

def _participants_covered(participant_boxes, crop_norm):
    """合并守卫：全部参与者框被裁框覆盖 ≥ PARTICIPANT_MIN_COVERAGE。"""
    for box in participant_boxes:
        if coverage_ratio(box, crop_norm) < PARTICIPANT_MIN_COVERAGE:
            return False
    return True


def build_candidate_crops(frame_bgr, width, height, identity, requests,
                          budget, max_records=None):
    """候选请求 → (records, images, dropped, notes)。

    每条候选：双方框联合 → 外扩（k=0.2 建议，下限 0.02）→ 面积上限判定
    （超限不外扩 context_capped；原始联合框超限整帧替代）→ 夹取 → 像素框
    → 单张三判据预算（area_ratio / pixels_fixed / bytes，独立验证取最严，
    整帧替代豁免）→ 切图 → 分数降序 → IoU≥0.8 确定性去重合并（附参与者
    覆盖守卫）→ 槽位上限。非法参与者框/预算舍弃显式记账（notes），不静默
    丢弃。

    max_records：本路可用槽位数（stage 按全景占位后传入，C-135 §六 优先级
    全景 > 关系裁图 > 变化区域）；None → budget.max_crops_total（直接驱动
    引擎、不经 stage 装配的调用方自担全景占位）。
    """
    if max_records is None:
        cap = max(0, int(budget.max_crops_total))
    else:
        cap = max(0, int(max_records))
    entries = []
    dropped = 0
    notes = []
    for order, request in enumerate(requests):
        cand = request.candidate
        subj = tuple(float(v) for v in request.subject_box_norm)
        obj = tuple(float(v) for v in request.object_box_norm)
        if not is_valid_box(subj) or not is_valid_box(obj):
            dropped += 1
            notes.append("invalid_participant_box")
            continue
        u = union_box(subj, obj)
        if u[2] * u[3] > UNION_AREA_CAP:
            # 原始联合框超帧面积上限→整帧替代（与全景分支重叠，记录省略
            # 理由；整帧替代豁免单张三判据预算）
            entries.append({
                "order": order, "cand": cand, "norm": (0.0, 0.0, 1.0, 1.0),
                "margin": 0.0, "clamped": False, "capped": False,
                "px": (0, 0, int(width), int(height)), "whole": True,
                "union": u, "subj": subj, "obj": obj,
                "img": slice_region(frame_bgr, (0, 0, int(width), int(height))),
            })
            continue
        margin = max(MARGIN_RATIO * max(u[2], u[3]), MIN_MARGIN_NORM)
        expanded = expand_box(u, margin)
        if expanded[2] * expanded[3] > UNION_AREA_CAP:
            final_raw, eff_margin, capped = u, 0.0, True     # 不再外扩
        else:
            final_raw, eff_margin, capped = expanded, margin, False
        clamped_pair = clamp_box(final_raw)
        if clamped_pair is None:
            dropped += 1
            notes.append("degenerate_after_clamp")
            continue
        norm, clamped = clamped_pair
        px = norm_box_to_px(norm, width, height)
        if px is None:
            dropped += 1
            notes.append("degenerate_px_box")
            continue
        # 单张预算三判据（C-135 §六：独立验证取最严；绝对像素上限不随帧
        # 面积同比放大——高分辨率下如实触发，这是预算的真实语义）
        if (budget.max_crop_area_ratio is not None
                and norm[2] * norm[3] > budget.max_crop_area_ratio):
            dropped += 1
            notes.append("crop_area_ratio_cap")
            continue
        if (budget.max_crop_pixels_fixed is not None
                and (px[2] - px[0]) * (px[3] - px[1])
                > budget.max_crop_pixels_fixed):
            dropped += 1
            notes.append("crop_pixels_cap")
            continue
        image = slice_region(frame_bgr, px)
        if image is None:                    # 防御：声明尺寸与帧不符
            dropped += 1
            notes.append("degenerate_px_box")
            continue
        if budget.max_crop_bytes is not None:
            measured = jpeg_encoded_bytes(image)
            if measured is None:
                notes.append("bytes_budget_unmeasurable")
            elif measured > budget.max_crop_bytes:
                dropped += 1
                notes.append("crop_bytes_cap")
                continue
        entries.append({
            "order": order, "cand": cand, "norm": norm, "margin": eff_margin,
            "clamped": clamped, "capped": capped, "px": px, "whole": False,
            "union": u, "subj": subj, "obj": obj, "img": image,
        })

    # 分数降序（同分按出现序，确定性）；IoU≥DEDUP_IOU 且参与者确被保留
    # 裁框覆盖（≥50% 可见面积）才合并——否则独立成图，记录与实际裁图一致
    entries.sort(key=lambda e: (-e["cand"].score_raw, e["order"]))
    groups = []
    for entry in entries:
        for group in groups:
            if box_iou(entry["norm"], group["norm"]) >= DEDUP_IOU \
                    and _participants_covered((entry["subj"], entry["obj"]),
                                              group["norm"]):
                group["reasons"].append(entry["cand"])
                break
        else:
            groups.append({"entry": entry, "norm": entry["norm"],
                           "reasons": []})

    if len(groups) > cap:
        excess = len(groups) - cap
        dropped += excess
        notes.extend(["budget_cap"] * excess)
        groups = groups[:cap]

    records = []
    images = []
    for i, group in enumerate(groups):
        entry = group["entry"]
        omitted = ()
        if entry["whole"]:
            omitted = ("union_over_area_cap:whole_frame_substituted",)
        transform = CropTransform(
            union_norm=entry["union"], margin_ratio=entry["margin"],
            bbox_norm=entry["norm"], bbox_px=entry["px"],
            clamped=entry["clamped"], whole_frame_fallback=entry["whole"],
            context_capped=entry["capped"])
        image = entry["img"]
        if image is None:                    # 防御：声明尺寸与帧不符
            dropped += 1
            notes.append("degenerate_px_box")
            continue
        records.append(CropRecord(
            crop_id=(f"{identity.camera_id}:{identity.run_id}"
                     f":frame:{identity.frame_id}:crop:{i}"),
            identity=identity, transform=transform,
            participants=(entry["cand"].subject, entry["cand"].obj),
            reason_candidates=tuple([entry["cand"]] + group["reasons"]),
            merged_count=len(group["reasons"]), omitted=omitted,
            same_region_as=None))
        images.append(image)
    return tuple(records), tuple(images), dropped, tuple(notes)


# ---- 全景与变化区域支路（构建纯函数；装配优先级归 stage） -------------------

def build_whole_frame_crop(frame_bgr, identity, participants=()):
    """全景帧裁图（whole_frame_fallback=True；不受单张三判据预算约束——
    全景恒保留，C-135 §六）。

    participants：全景参与者（全部可用对象的 ObjectRef；零对象显式为空）。
    """
    h = int(frame_bgr.shape[0])
    w = int(frame_bgr.shape[1])
    transform = CropTransform(
        union_norm=(0.0, 0.0, 1.0, 1.0), margin_ratio=0.0,
        bbox_norm=(0.0, 0.0, 1.0, 1.0), bbox_px=(0, 0, w, h),
        clamped=False, whole_frame_fallback=True, context_capped=False)
    record = CropRecord(
        crop_id=(f"{identity.camera_id}:{identity.run_id}"
                 f":frame:{identity.frame_id}:crop:whole"),
        identity=identity, transform=transform,
        participants=tuple(participants),
        reason_candidates=(), merged_count=0, omitted=(), same_region_as=None)
    return record, slice_region(frame_bgr, (0, 0, w, h))


def build_change_region_crops(frame_bgr, width, height, identity,
                              regions_norm, max_crops):
    """变化区域裁图：逐区域夹取+像素换算；非法/退化区域跳过（非预算舍弃，
    不计入）；max_crops 限数（产出到上限即停）。

    返回 (records, images, budget_dropped)——budget_dropped=合法但因
    max_crops 上限未能产出的区域数（显式记账不静默，C-135 §六）。
    """
    cap = max(0, int(max_crops))
    prepared = []
    for region in regions_norm:
        box = (float(region[0]), float(region[1]),
               float(region[2]), float(region[3]))
        if not is_valid_box(box):
            continue
        clamped_pair = clamp_box(box)
        if clamped_pair is None:
            continue
        norm, clamped = clamped_pair
        px = norm_box_to_px(norm, width, height)
        if px is None:
            continue
        prepared.append((norm, clamped, px))
    records = []
    images = []
    for norm, clamped, px in prepared[:cap]:
        image = slice_region(frame_bgr, px)
        if image is None:
            continue
        transform = CropTransform(
            union_norm=norm, margin_ratio=0.0, bbox_norm=norm, bbox_px=px,
            clamped=clamped, whole_frame_fallback=False, context_capped=False)
        records.append(CropRecord(
            crop_id=(f"{identity.camera_id}:{identity.run_id}"
                     f":frame:{identity.frame_id}:chg:{len(records)}"),
            identity=identity, transform=transform, participants=(),
            reason_candidates=(), merged_count=0, omitted=(),
            same_region_as=None))
        images.append(image)
    budget_dropped = max(0, len(prepared) - cap)
    return tuple(records), tuple(images), budget_dropped


# ---- 构建后核验（参与者覆盖不变式，C-135 §六 B2） ---------------------------

def verify_participant_coverage(records, requests,
                                min_ratio=PARTICIPANT_MIN_COVERAGE):
    """成品 CropRecord 的参与者覆盖核验：记录中全部来源候选的参与对象框
    必须与实际裁框（transform.bbox_norm，整帧归一化）相交 ≥ 其可见面积的
    min_ratio（默认 0.5）——记录与实际裁图一致。

    返回违规元组 (crop_id, object_id, ratio)；空元组=不变式成立。不在
    requests 中的候选（调用方直接构造记录）跳过核验（无框可查，不臆测）。
    """
    request_by_candidate = {}
    for request in requests:
        request_by_candidate[request.candidate] = request
    violations = []
    for record in records:
        crop_norm = record.transform.bbox_norm
        for cand in record.reason_candidates:
            request = request_by_candidate.get(cand)
            if request is None:
                continue
            for ref, box in ((cand.subject, request.subject_box_norm),
                             (cand.obj, request.object_box_norm)):
                ratio = coverage_ratio(tuple(box), crop_norm)
                if ratio < min_ratio:
                    violations.append((record.crop_id, ref.object_id, ratio))
    return tuple(violations)
