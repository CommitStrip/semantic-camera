"""patterns + naming 双车道测试（P2 验收：同签名第二段零 VLM 自命名）。"""

import pytest

from scam.patterns import (PatternLibrary, embedding_similarity,
                           segment_similarity, segment_similarity_joint)
from scam.naming import NamingLanes


def sig(cls=("person",), count="1", zones=("z1",), lines=(), modality="DAY-COLOR",
        tod="夜", dur="短", dwell="无"):
    return {"cls": sorted(cls), "count": count, "zones": sorted(zones),
            "lines": sorted(lines), "modality": modality, "tod": tod,
            "dur": dur, "dwell": dwell}


def make_vlm(counter):
    def vlm(seg, frames):
        counter["n"] += 1
        return {"short_name": "可疑人员翻墙入院",
                "detail": "凌晨一名穿深色连帽衫者自围墙东侧翻入，电表箱前停留三分钟后原路返回",
                "rationale": "围栏上方人体越过", "conf": 0.9}
    return vlm


def test_embedding_similarity_basics():
    assert embedding_similarity([1, 0], [1, 0]) == 1.0
    assert embedding_similarity([1, 0], [0, 1]) == 0.0
    assert embedding_similarity([1], [1, 2]) is None


def test_segment_similarity_joint_degrades_to_structure():
    a = sig()
    b = sig(tod="昼", dur="中")
    s = segment_similarity(a, b)
    j = segment_similarity_joint(a, b, None, None)
    assert j == s, "缺嵌入=纯结构"
    assert j < 1.0


def test_second_segment_zero_vlm_self_named():
    """P2 验收：同签名第二段——嵌入比对命中 → 自命名，零 VLM 调用。"""
    lib = PatternLibrary(sim_threshold=0.82)
    calls = {"n": 0}

    def vlm(seg, frames):
        calls["n"] += 1
        return {"short_name": "可疑人员翻墙入院",
                "detail": "凌晨一名穿深色连帽衫者自围墙东侧翻入，电表箱前停留三分钟后原路返回",
                "rationale": "围栏上方人体越过", "conf": 0.9}

    lanes = NamingLanes(lib, vlm=vlm)
    seg1 = {"segment_id": "s1", "signature": sig(), "tod": "夜"}
    emb1 = [1.0, 0.1, 0.0, 0.0]
    r1 = lanes.on_segment(seg1, emb=emb1, modality="DAY-COLOR")
    assert r1["vlm_used"] is True and r1["source"] == "t2b-vlm"
    assert calls["n"] == 1

    seg2 = {"segment_id": "s2", "signature": sig(), "tod": "夜"}
    emb2 = [0.99, 0.11, 0.01, 0.0]          # 同模式相近嵌入
    r2 = lanes.on_segment(seg2, emb=emb2, modality="DAY-COLOR")
    assert r2["vlm_used"] is False, "第二段必须零 VLM 自命名"
    assert r2["source"] == "t2a-self"
    assert r2["short_name"] == r1["short_name"]
    assert calls["n"] == 1, "第二段不得再调 VLM"


def test_dual_modality_archives_and_dimension_guard():
    lib = PatternLibrary()
    p = lib.match_or_record(sig())["pattern"]
    lib.attach_embedding(p["id"], [1.0, 0.0], "DAY-COLOR")
    lib.attach_embedding(p["id"], [0.0, 1.0], "DAY-COLOR")
    assert lib.embedding_match(p, [0.7071, 0.7071], "DAY-COLOR") > 0.99
    lib.attach_embedding(p["id"], [1.0, 0.0, 0.0, 0.0], "DAY-COLOR")
    embs = lib.patterns[p["id"]]["embs"]["DAY-COLOR"]
    assert len(embs["c"]) == 4 and embs["n"] == 1, "维度不一致=重置档案（防 NaN）"
    lib.attach_embedding(p["id"], [1.0, 0.0], "NIGHT-BW")
    assert "NIGHT-BW" in lib.patterns[p["id"]]["embs"], "跨模态分档案"


def test_pattern_prune_evicts_drafts_keeps_verified():
    lib = PatternLibrary(sim_threshold=0.82, max_patterns=2)
    for i, state in enumerate(["model-verified", "human-verified", "draft", "draft"]):
        lib.patterns[f"pat-{i}"] = {
            "id": f"pat-{i}",
            "signature": {"cls": [], "count": "0", "zones": [], "lines": [],
                          "modality": "M", "tod": "夜", "dur": "短", "dwell": "无"},
            "name": f"n{i}", "state": state, "count": i, "embs": {}}
    lib._prune()
    assert "pat-0" in lib.patterns and "pat-1" in lib.patterns, "已验证模式受保护"
    assert "pat-2" not in lib.patterns and "pat-3" not in lib.patterns, "draft 先逐出"
