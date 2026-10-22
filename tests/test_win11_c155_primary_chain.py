"""C155 主帧链生产接线回归。

防回归点：real-p3 断点＝计划期未传主帧 id(`primary_frame_id_missing`)
⇒ 主帧事件键恒 null ⇒ 事件页不可达。生产接线后必须：
①计划调用显式传主帧 id；②主帧取自**本包 cur 帧**（不用 latest/首条/邻近）。
"""

import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_plan_passes_current_frame_as_primary():
    """源级防回归：生产计划调用必须显式传主帧 id，且取自本包 cur 帧。"""
    src = (ROOT / "scam" / "win11_l2_runtime.py").read_text(encoding="utf-8")
    start = src.index("def _plan_event_materials")
    nxt = src.find("\n    def ", start + 10)
    body = src[start:nxt if nxt > 0 else len(src)]
    assert "self.event_materials.plan_frames(" in body, "必须存在生产计划调用"
    assert "primary_frame_id=" in body, "计划期必须显式传主帧 id（P0-3(a) 接线）"
    assert '"cur"' in body, "主帧必须取自本包 cur 帧（不用 latest/首条/邻近）"


def test_plan_forwards_cur_frame_id_behaviourally():
    """行为级：`_plan_event_materials` 实收 primary_frame_id == pkg.cur.frame_id。"""
    from scam.win11_l2_runtime import L2Runtime

    seen = {}

    class _Pool:
        def window_event_id(self, window_key):
            return None

        def plan_frames(self, **kwargs):
            seen.update(kwargs)
            return "PLAN"

        def snapshot(self):
            return {}

    class _Ledger:
        budget = types.SimpleNamespace(max_frames_per_task=3)

    fake_self = types.SimpleNamespace(
        event_materials=_Pool(),
        l3_window_budget_ledger=_Ledger(),
        _count=lambda *a, **k: None,
    )
    pkg = types.SimpleNamespace(
        material_id=42, material_reason="change_start", change_boxes=None,
        cur=types.SimpleNamespace(frame_id=777, camera_id="cam", run_id="run"),
    )
    plan = L2Runtime._plan_event_materials(
        fake_self, "cam", pkg, ("cam", "run", 0, 5))
    assert plan == "PLAN"
    assert seen.get("primary_frame_id") == 777, seen
    assert seen.get("material_id") == 42
    assert seen.get("window_id") == 5

