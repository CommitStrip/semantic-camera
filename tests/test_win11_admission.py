# -*- coding: utf-8 -*-
"""C-144-R2 win11_admission 单测：统一配对/边沿驱动/离开与原位返回/
失败重置离开计数/时间四分/累计位移/身份隔离。

R1 保留（语义未变处）：坐标单位分离、缩放签名、累计位移、删 300s 重
初始、身份隔离、顺序抖动、无对象变化维度。
R2 新契约：静→动新边沿即时准入（删 60s 时间再武装）；连续有效 empty
→一次离开；失败/超时重置离开计数；离开后原位返回重获资格。"""
from scam.win11_admission import decide

IDENT = {"camera_id": "cam", "run_id": "r1", "config_version": 0}


def test_initial_empty_has_no_departure():
    _, _, ref = _feed("patrol", [], detections=[], det_status="confirmed_empty")
    for tick in range(1, 8):
        decision, reason, ref = _feed(
            "patrol", [], detections=[], det_status="confirmed_empty",
            scene_ref=ref, now_s=100 + tick)
        assert decision.startswith("suppress"), reason
        assert not ref["left"] and ref["leave_count"] == 0


def test_initial_unavailable_is_not_an_initial_observation():
    ref = None
    for tick in range(5):
        decision, reason, ref = _feed(
            "patrol", [], detections=None, det_status="unavailable",
            scene_ref=ref, now_s=100 + tick)
        assert decision == "suppress_no_new_info" and ref is None
    decision, _, _ = _feed("change_start", [[20, 20, 10, 10]],
                          det_status="unavailable", scene_ref=ref)
    assert decision == "admit_initial"


def test_short_empty_gap_then_same_object_is_not_new_arrival():
    _, _, ref = _feed("patrol", [], detections=_person())
    _, _, ref = _feed("patrol", [], detections=[], det_status="confirmed_empty",
                      scene_ref=ref, now_s=101)
    decision, _, _ = _feed("patrol", [], detections=_person(),
                          scene_ref=ref, now_s=102)
    assert decision.startswith("suppress")


def _person(cx_norm=0.45):
    # bbox 归一化 [x, y, w, h]：中心 cx_norm
    return [{"cls": "person", "conf": 0.9,
             "bbox": [cx_norm - 0.05, 0.4, 0.10, 0.20]}]


def _feed(material_reason, change_boxes, detections=None, scene_ref=None,
          now_s=100.0, **kw):
    return decide(material_reason=material_reason,
                  change_boxes=change_boxes, gate_w=96, gate_h=48,
                  identity=IDENT, scene_ref=scene_ref, now_s=now_s,
                  detections=detections, **kw)


def test_cross_half_frame_admitted():
    """同一对象横跨半幅画面：必须准入。"""
    d, _, ref = _feed("latest", [[10, 20, 10, 10]], detections=_person(0.4))
    assert d == "admit_initial"
    d, rc, ref = _feed("change_start", [[180, 20, 10, 10]],
                       detections=_person(0.9), scene_ref=ref, now_s=110.0)
    assert d == "admit_change", rc


def test_slow_cumulative_move_admitted():
    """多次小位移累计达到阈值：必须准入（基准随观察推进，累计比较）。"""
    ref = None
    admits = 0
    cx = 0.40
    for step in range(24):
        cx += 0.01                      # 每步 1% 归一化位移
        d, rc, ref = _feed("patrol", [], detections=_person(cx),
                           scene_ref=ref, now_s=100.0 + step)
        if d == "admit_change":
            admits += 1
    # 累计位移 0.24：每越过 DET_MOVE_RATIO 就应重新准入——而非全部抑制
    assert admits >= 2, f"累计位移应多次触发准入，实得 {admits}"


def test_scale_change_admitted_same_center():
    """中心不变但明显变大：不能仍当作完全相同。"""
    d, _, ref = _feed("latest", [], detections=_person(0.45))
    assert d == "admit_initial"
    grown = [{"cls": "person", "conf": 0.9, "bbox": [0.40, 0.30, 0.20, 0.40]}]
    d, rc, _ = _feed("change_start", [], detections=grown, scene_ref=ref,
                     now_s=110.0)
    assert d == "admit_change", rc


def test_static_301s_10min_30min_never_reinit():
    """完全静止：跨 301 秒、10 分钟和 30 分钟——不因时间到期新调用。"""
    d, _, ref = _feed("latest", [[10, 20, 10, 10]], detections=_person(0.45))
    assert d == "admit_initial"
    for now in (401.0, 700.0, 1900.0):
        d, rc, ref = _feed("patrol", [], detections=_person(0.45),
                           scene_ref=ref, now_s=now)
        assert d.startswith("suppress"), \
            f"now={now}: 静止画面不得重新准入（{d}/{rc}）"


def test_same_region_new_action_edge_immediate():
    """同区域静→动新边沿：回稳后同几何变化框再现——**即时**准入，
    不等任何再武装间隔；持续供框几何相同则抑制（同一持续变化）。"""
    boxes = [[10, 20, 10, 10]]
    d, _, ref = _feed("change_start", boxes, detections=_person(0.45))
    assert d == "admit_initial"
    # 持续供框、几何相同：抑制（61s 后也一样——没有时间再武装）
    d, rc, ref = _feed("change_start", boxes, detections=_person(0.45),
                       scene_ref=ref, now_s=161.0)
    assert d.startswith("suppress"), rc
    # 回稳（变化框消失）
    d, rc, ref = _feed("patrol", [], detections=_person(0.45),
                       scene_ref=ref, now_s=165.0)
    assert d.startswith("suppress"), rc
    # 同区域同几何再次出现：静→动新边沿——即时准入（绝不延迟 60s）
    d, rc, _ = _feed("change_start", boxes, detections=_person(0.45),
                     scene_ref=ref, now_s=166.0)
    assert d == "admit_change", rc


def test_patrol_does_not_reset_change_time():
    """巡检推进 last_seen 但不重置 last_change_s（同区域新动作判别
    所依赖的变化时间只由真实变化推进）。"""
    d, _, ref = _feed("change_start", [[10, 20, 10, 10]],
                      detections=_person(0.45))
    assert d == "admit_initial"
    t_change = ref["last_change_s"]
    for step in range(6):
        d, rc, ref = _feed("patrol", [], detections=_person(0.45),
                           scene_ref=ref, now_s=100.0 + 5.0 * (step + 1))
        assert d.startswith("suppress"), rc
    assert ref["last_change_s"] == t_change, "巡检不得重置最近真实变化时间"
    assert ref["last_seen_s"] == 130.0, "巡检应推进最近观察时间"


def test_identity_isolation():
    d, _, ref = _feed("latest", [[10, 20, 10, 10]], detections=_person(0.45))
    from scam.win11_admission import decide
    d, _, _ = decide(material_reason="latest",
                     change_boxes=[[10, 20, 10, 10]],
                     gate_w=96, gate_h=48,
                     identity=dict(IDENT, run_id="r2"), scene_ref=ref,
                     now_s=110.0, detections=_person(0.45))
    assert d == "admit_initial"


def test_confirmed_empty_leave_then_return():
    """连续 3 次有效确认空 → 一次离开变化；之后持续空不再产生离开任务；
    原位返回 → 重新获得变化资格。"""
    d, _, ref = _feed("latest", [], detections=_person(0.45))
    assert d == "admit_initial"
    # 第 1、2 次有效空：计数未满，抑制
    d, rc, ref = _feed("patrol", [], detections=[],
                       detections_present=False, scene_ref=ref, now_s=101.0)
    assert d.startswith("suppress"), rc
    d, rc, ref = _feed("patrol", [], detections=[],
                       detections_present=False, scene_ref=ref, now_s=102.0)
    assert d.startswith("suppress"), rc
    # 第 3 次有效空：一次离开变化
    d, rc, ref = _feed("patrol", [], detections=[],
                       detections_present=False, scene_ref=ref, now_s=103.0)
    assert d == "admit_change" and rc == "change_leave", (d, rc)
    assert ref["left"] is True
    # 离开后持续空：静止无人不持续生成离开任务
    d, rc, ref = _feed("patrol", [], detections=[],
                       detections_present=False, scene_ref=ref, now_s=104.0)
    assert d.startswith("suppress"), rc
    # 原位返回：重新获得变化资格
    d, rc, ref = _feed("change_start", [], detections=_person(0.45),
                       scene_ref=ref, now_s=110.0)
    assert d == "admit_change" and rc == "change_return", (d, rc)
    assert ref["left"] is False


def test_failures_reset_leave_count():
    """empty 与 infer_failed/timeout 混合：失败/超时重置连续空计数，
    不得累计成离开。"""
    d, _, ref = _feed("latest", [], detections=_person(0.45))
    assert d == "admit_initial"
    seq = [("empty", dict(detections=[], detections_present=False)),
           ("fail", dict(detections=None, detections_present=None)),
           ("empty", dict(detections=[], detections_present=False)),
           ("timeout", dict(detections=None, detections_present=None)),
           ("empty", dict(detections=[], detections_present=False)),
           ("fail", dict(detections=None, detections_present=None))]
    for i, (label, kw) in enumerate(seq):
        d, rc, ref = _feed("patrol", [], scene_ref=ref,
                           now_s=101.0 + i, **kw)
        assert d.startswith("suppress"), \
            f"step{i}({label}): 不得离开（{d}/{rc}）"
        assert rc != "change_leave" and rc != "confirmed_leave", rc


def test_size_swap_jitter_no_false_change():
    """邻近对象 1px 抖动 + 中心排序交叉：中心与尺寸用同一最近邻配对，
    不得产生伪变化（R1 缺陷=尺寸按排序位次 zip 比较）。"""
    small = [130, 90, 20, 20]             # 中心 (140,100)
    big = [111, 90, 60, 60]               # 中心 (141,120)
    d, _, ref = _feed("change_start", [small, big], detections=_person(0.45))
    assert d == "admit_initial"
    small_j = [131, 90, 20, 20]           # 中心 (141,100) 1px 抖动
    big_j = [110, 90, 60, 60]             # 中心 (140,120) 1px 抖动
    d, rc, _ = _feed("change_start", [big_j, small_j],
                     detections=_person(0.45), scene_ref=ref, now_s=102.0)
    assert d.startswith("suppress"), (d, rc)


def test_order_shuffle_no_false_change():
    """检测顺序变化不产生伪变化（多框交换顺序签名稳定）。"""
    boxes_a = [[20, 20, 10, 10], [60, 20, 10, 10]]
    d, _, ref = _feed("latest", boxes_a, detections=_person(0.45))
    assert d == "admit_initial"
    boxes_b = [[60, 20, 10, 10], [20, 20, 10, 10]]   # 顺序交换
    d, rc, _ = _feed("latest", boxes_b, detections=_person(0.45),
                     scene_ref=ref, now_s=110.0)
    assert d == "suppress_duplicate", rc


def test_no_object_but_change_admitted_via_change_dim():
    """无对象但画面变化（门控框出现）：change 维度准入（det 空不拦）。"""
    d, _, ref = _feed("latest", [], detections=[], det_status="confirmed_empty")
    assert d == "admit_initial"
    d, _, _ = _feed("change_start", [[30, 30, 20, 20]], detections=[],
                    scene_ref=ref, now_s=110.0)
    assert d == "admit_change"


def test_real_change_after_long_suppression_not_blocked():
    """长时间抑制后真实新变化照常准入（超窗不清参考但也不阻断变化）。"""
    d, _, ref = _feed("latest", [], detections=_person(0.45))
    assert d == "admit_initial"
    d, rc, ref = _feed("patrol", [], detections=_person(0.45),
                       scene_ref=ref, now_s=100.0 + 1800.0)
    assert d.startswith("suppress"), rc
    d, rc, _ = _feed("change_start", [[90, 30, 24, 24]],
                     detections=_person(0.75), scene_ref=ref,
                     now_s=100.0 + 1810.0)
    assert d == "admit_change", rc
