"""固定离线语义评估集（v1）一致性验证：schema、类别 taxonomy、计数对账。"""

import json
from pathlib import Path

_EVAL = Path(__file__).resolve().parent.parent / "tests" / "data" \
    / "semantic_eval_set.v1.json"


def test_eval_set_schema_and_taxonomy():
    data = json.loads(_EVAL.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert set(data["taxonomy"]) == {
        "scene_misidentification", "number_time_fabrication",
        "overconfidence", "danger_underreporting"}
    assert "单评审员" in data["status_note"], \
        "单评审员结果只能叫风险样本，不得称准确率"
    assert data["reviewed_count"] + data["unjudged_count"] == len(
        data["samples"])


def test_eval_set_reviewed_entries_and_counts_consistent():
    data = json.loads(_EVAL.read_text(encoding="utf-8"))
    counts = {}
    reviewed = 0
    for entry in data["samples"]:
        assert entry["id"] and isinstance(entry["model_raw"], str)
        if entry["human"] is None:
            continue
        reviewed += 1
        cats = entry["human"]["categories"]
        for c in cats:
            assert c in data["taxonomy"], f"未知类别 {c}"
            counts[c] = counts.get(c, 0) + 1
        assert entry["human"]["judgment"], "已评审条目必须有人工判定与理由"
    assert reviewed == data["reviewed_count"]
    assert counts == data["category_counts_reviewed"], \
        "类别计数必须与汇总一致（回归起点不可漂移）"
    # 回归起点（C-124 人工抽样的已知风险计数）
    assert counts["number_time_fabrication"] == 4
    assert counts["overconfidence"] == 3
