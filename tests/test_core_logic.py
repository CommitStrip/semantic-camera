"""zones/gate/track/verdict 纯逻辑测试（移植自 JS 套件的已验证断言）。"""

from scam.config import validate_venue
from scam.gate import MotionGate
from scam.track import Tracker
from scam.verdict import ZoneRuntime, rule_fires
from scam.zones import Grid, bbox_center_cell


def det(x, y, w, h, cls="person", conf=0.9):
    return {"cls": cls, "conf": conf, "bbox": [x, y, w, h],
            "cx": x + w / 2, "cy": y + h / 2}


# ==================== 网格（海康式圈选） ====================

def test_grid_cell_mapping_and_bounds():
    g = Grid(rows=18, cols=22)
    assert g.cell_of(0.0, 0.0) == 0
    assert g.cell_of(0.999, 0.999) == 18 * 22 - 1, "右下角收拢到最后一个格"
    assert g.cell_of(-0.5, -0.5) == 0, "越界收拢不越界"
    assert g.cell_of(0.5, 0.5) == 9 * 22 + 11


def test_bbox_center_cell():
    g = Grid(rows=18, cols=22)
    assert bbox_center_cell(g, [0.0, 0.0, 0.04, 0.04]) == 0, "中心 (0.02,0.02) 在首格"
    assert bbox_center_cell(g, [0.98, 0.98, 0.02, 0.02]) == 18 * 22 - 1, "中心 (0.99,0.99) 在末格"


# ==================== T0 帧差门控（VUS 移植） ====================

def flat(size, value):
    return [value] * size


def test_gate_first_frame_warms_up_only():
    g = MotionGate()
    assert g.detect(flat(96 * 54, 100), 96, 54) == []
    assert g.last_ratio == 0.0


def test_gate_still_frame_no_trigger():
    g = MotionGate()
    g.detect(flat(96 * 54, 100), 96, 54)
    assert g.detect(flat(96 * 54, 100), 96, 54) == []


def test_gate_single_pixel_noise_below_area_no_trigger():
    g = MotionGate()
    g.detect(flat(96 * 54, 100), 96, 54)
    f = flat(96 * 54, 100)
    f[0] = 126
    assert g.detect(f, 96, 54) == [], "单像素差 26 越阈值但面积不足"


def test_gate_block_above_area_triggers_with_box():
    g = MotionGate()
    base = flat(96 * 54, 100)
    g.detect(base, 96, 54)
    f = list(base)
    for r in range(10, 14):
        for c in range(40, 56):
            f[r * 96 + c] = 200
    boxes = g.detect(f, 96, 54)
    assert len(boxes) == 1
    b = boxes[0]
    assert b["x"] <= 40 and b["y"] <= 10
    assert b["x"] + b["w"] >= 55 and b["y"] + b["h"] >= 13  # 框宽=max-min（同 vus）
    assert 0 < g.last_ratio <= 1


def test_gate_reset_background_suppresses_burst():
    g = MotionGate()
    g.detect(flat(96 * 54, 100), 96, 54)
    g.reset_background(flat(96 * 54, 200))
    assert g.detect(flat(96 * 54, 200), 96, 54) == [], "重置后同帧不再误报"


# ==================== Tracker（VUS 移植 + QA 修复语义） ====================

def test_tracker_confirms_after_two_detections():
    tr = Tracker()
    tr.update([det(0.4, 0.4, 0.12, 0.35)], 0)
    tr.update([det(0.4, 0.4, 0.12, 0.35)], 500)
    assert len(tr.get_confirmed()) == 1


def test_tracker_cls_guard_and_distance_gate():
    tr = Tracker()
    tr.update([det(0.4, 0.4, 0.12, 0.35, "person")], 0)
    tr.update([det(0.4, 0.4, 0.12, 0.35, "person")], 500)
    tid = tr.get_confirmed()[0]["id"]
    tr.update([det(0.4, 0.4, 0.12, 0.35, "car")], 1000)
    assert tr.tracks[tid]["cls"] == "person", "异类不改写身份"
    before = len(tr.tracks)
    tr.update([det(0.78, 0.4, 0.12, 0.35, "person")], 1500)
    assert len(tr.tracks) > before, "中心距超阈判新目标"


# ==================== 报警判定（模板比对） ====================

def test_rule_enter_dwell():
    rule = {"cls": "person", "template": "enter-dwell", "dwell_s": 5}
    assert rule_fires(rule, "person", True, 5.0)
    assert not rule_fires(rule, "person", True, 4.9)
    assert not rule_fires(rule, "person", False, 100)


def test_rule_immediate_and_loiter():
    imm = {"cls": "person", "template": "immediate"}
    assert rule_fires(imm, "person", True, 0)
    loi = {"cls": "person", "template": "loiter", "dwell_s": 30}
    assert not rule_fires(loi, "person", True, 10)
    assert rule_fires(loi, "person", True, 31)


def test_zone_runtime_dwell_accumulates_and_clears():
    zr = ZoneRuntime()
    assert zr.update(7, "z1", True, 0) == 0.0
    assert zr.update(7, "z1", True, 2000) == 2.0
    zr.update(7, "z1", False, 3000)
    assert zr.update(7, "z1", True, 9000) == 0.0, "离开后重新计时"


def test_tracker_derives_center_from_bbox():
    """检测源不带 cx/cy 时从框推导（生产 NanoDet 曾漏中心点→入口即崩）。"""
    tr = Tracker()
    tr.update([{"cls": "person", "conf": 0.9,
                "bbox": [0.4, 0.4, 0.1, 0.2]}], 0)
    t = tr.tracks[1]
    assert abs(t["cx"] - 0.45) < 1e-9
    assert abs(t["cy"] - 0.5) < 1e-9


def test_validate_venue_type_hardening():
    """校验器类型不设防会崩溃而非报错（grid/zones/相机条目传错类型）。"""
    bad = {"cameras": [
        {"id": "a", "source": "x", "detector": {"engine": "none"},
         "grid": "not-a-dict", "zones": "not-a-list"},
        "not-a-dict-camera",
        {"id": "b", "source": "x", "detector": {"engine": "none"},
         "schedule": "not-a-list"},
    ]}
    errs = validate_venue(bad)
    assert any("grid" in e for e in errs)
    assert any("zones 必须为数组" in e for e in errs)
    assert any("相机条目必须为对象" in e for e in errs)
    assert any("schedule 必须为数组" in e for e in errs)
