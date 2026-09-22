"""patterns + naming 双车道测试（P2 验收：同签名第二段零 VLM 自命名）。

后半部分为 LC-046 S1 的模式库持久化验收：固定版本化快照、校验先于变更、
拒绝坏类型/重复 ID/非法状态/畸形嵌入记录、序号防碰撞与既有维度重置守卫。
S1-R1 另验收：质心只有一种 float32 存储精度——内存值、快照文本与既有 BLOB 列
同值，`save`→`load` 得到逐字节稳定的规范快照。
"""

import json
import struct

import pytest

from scam.db import connect, init_schema
from scam.patterns import (PATTERN_LIBRARY_FIELDS, PATTERN_RECORD_FIELDS,
                           PatternLibrary, PatternPersistenceError,
                           embedding_similarity, float32_value, load_library,
                           save_library, segment_similarity,
                           segment_similarity_joint)
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


# ---------- LC-046 S1：固定版本化快照 + 校验先于变更 + 序号防碰撞 ----------

NAMED_DETAIL = "凌晨一名穿深色连帽衫者自围墙东侧翻入，电表箱前停留三分钟后原路返回"


def make_library(*, sim_threshold=0.82, max_patterns=500):
    """两模式小库：pat-1 已命名并带双模态质心，pat-2 为仅累积窗口的 draft。"""
    lib = PatternLibrary(sim_threshold=sim_threshold,
                         max_patterns=max_patterns)
    named = lib.match_or_record(sig(), [1.0, 0.0], "DAY-COLOR")["pattern"]
    lib.record_hit(named, "夜", "DAY-COLOR")
    lib.record_name(named["id"], "可疑人员翻墙入院", NAMED_DETAIL, consistent=True)
    lib.attach_embedding(named["id"], [1.0, 0.0], "DAY-COLOR")
    lib.attach_embedding(named["id"], [0.9, 0.1], "DAY-COLOR")
    lib.attach_embedding(named["id"], [0.0, 1.0], "NIGHT-BW")
    other = lib.match_or_record(
        sig(cls=("car",), zones=("z9",), tod="昼", dur="中"))["pattern"]
    lib.record_hit(other, "昼", "DAY-COLOR")
    return lib


def state_of(lib):
    return json.dumps(lib.to_document(), ensure_ascii=False, sort_keys=True)


def memory_db():
    conn = connect(":memory:")
    init_schema(conn)
    return conn


def corrupt_library_db():
    """已写入完整两模式、可供篡改的连接。"""
    conn = memory_db()
    save_library(conn, make_library())
    conn.commit()
    return conn


def assert_load_rejected(conn):
    with pytest.raises(PatternPersistenceError):
        load_library(conn)
    conn.close()


def test_snapshot_has_a_fixed_versioned_structure():
    lib = make_library()
    document = lib.to_document()
    assert set(document) == set(PATTERN_LIBRARY_FIELDS)
    assert document["schema"] == "scam.pattern-library/v1"
    assert document["kind"] == "pattern_library"
    assert document["version"] == 1
    assert document["seq"] == lib.seq
    assert [record["id"] for record in document["patterns"]] == \
        ["pat-1", "pat-2"]
    for record in document["patterns"]:
        assert set(record) == set(PATTERN_RECORD_FIELDS)
    named = document["patterns"][0]
    assert named["signature"]["cls"] == ["person"]
    assert named["name"] == "可疑人员翻墙入院"
    assert named["detail"] == NAMED_DETAIL, "细节不截断"
    assert named["state"] == "draft"
    assert named["count"] == 1 and named["llm_agree"] == 1
    assert named["human_samples"] == 0 and named["version"] == 1
    assert named["expected_window"] == {"tod": ["夜"],
                                        "modality": ["DAY-COLOR"]}
    assert named["last_audit"] is None
    day_color = named["embs"]["DAY-COLOR"]
    assert (day_color["dim"], day_color["n"]) == (2, 2)
    assert set(named["embs"]["NIGHT-BW"]) == {"c", "n", "dim"}


def test_snapshot_is_deterministic_and_round_trips_byte_for_byte():
    lib = make_library()
    text = lib.snapshot()
    assert lib.snapshot() == text, "同库快照字节稳定"
    restored = PatternLibrary()
    restored.restore(text)
    assert restored.snapshot() == text, "快照可跨库逐字节往返"
    assert restored.seq == lib.seq
    assert set(restored.patterns) == set(lib.patterns)
    original = lib.patterns["pat-1"]
    copy = restored.patterns["pat-1"]
    assert copy["name"] == original["name"]
    assert copy["detail"] == original["detail"]
    assert copy["count"] == original["count"]
    assert copy["llm_agree"] == original["llm_agree"]
    assert copy["human_samples"] == original["human_samples"]
    assert copy["expected_window"] == original["expected_window"]
    assert copy["embs"]["DAY-COLOR"]["c"] == original["embs"]["DAY-COLOR"]["c"]


def test_restore_advances_the_sequence_past_restored_ids():
    document = make_library().to_document()
    document["seq"] = 1                     # 人为落后于已恢复的 pat-2
    fresh = PatternLibrary()
    fresh.restore(document)
    assert fresh.seq == 3, "序号必须推进到已恢复 pat-N 之后"
    created = fresh.match_or_record(
        sig(cls=("train",), count="4+", zones=("z9",), tod="昼", dur="长")
    )["pattern"]
    assert created["id"] == "pat-3"
    assert created["id"] not in ("pat-1", "pat-2")


def test_restore_rejects_malformed_input_sources():
    lib = PatternLibrary()
    for source in ("{not json", "[1, 2, 3]", "null", None, 7, 3.5):
        with pytest.raises(PatternPersistenceError):
            lib.restore(source)
    assert lib.patterns == {} and lib.seq == 1


def _document_mutations():
    """(名称, 变体)：每个变体都是 restore 必须拒绝的坏文档。"""
    def drop_root_field(document):
        document.pop("seq")

    def unknown_root_field(document):
        document["extra"] = 1

    def bad_schema(document):
        document["schema"] = "scam.pattern-library/v2"

    def bad_kind(document):
        document["kind"] = "pattern_library_v2"

    def bad_version(document):
        document["version"] = 2

    def bad_seq(document):
        document["seq"] = -1

    def bad_patterns_type(document):
        document["patterns"] = {}

    def bad_pattern_type(document):
        document["patterns"][0] = "pat-1"

    def unknown_record_field(document):
        document["patterns"][0]["extra"] = True

    def missing_record_field(document):
        document["patterns"][0].pop("state")

    def duplicate_ids(document):
        document["patterns"][1]["id"] = document["patterns"][0]["id"]

    def unsupported_state(document):
        document["patterns"][0]["state"] = "pending"

    def bad_count(document):
        document["patterns"][0]["count"] = -1

    def bad_bool_count(document):
        document["patterns"][0]["count"] = True

    def bad_name(document):
        document["patterns"][0]["name"] = 7

    def bad_signature_type(document):
        document["patterns"][0]["signature"] = ["cls"]

    def bad_signature_keys(document):
        document["patterns"][0]["signature"].pop("tod")

    def bad_signature_values(document):
        document["patterns"][0]["signature"]["count"] = 1

    def bad_window_shape(document):
        document["patterns"][0]["expected_window"] = {"tod": [], "lines": []}

    def bad_window_item(document):
        document["patterns"][0]["expected_window"]["tod"] = [7]

    def bad_audit(document):
        document["patterns"][0]["last_audit"] = {"agree": "yes"}

    def bad_embedding_type(document):
        document["patterns"][0]["embs"]["DAY-COLOR"] = [1.0, 0.0]

    def bad_embedding_keys(document):
        document["patterns"][0]["embs"]["DAY-COLOR"]["extra"] = 1

    def bad_embedding_dim(document):
        document["patterns"][0]["embs"]["DAY-COLOR"]["dim"] = 3

    def bad_embedding_samples(document):
        document["patterns"][0]["embs"]["DAY-COLOR"]["n"] = 0

    def bad_embedding_nan(document):
        document["patterns"][0]["embs"]["DAY-COLOR"]["c"] = [1.0, float("nan")]

    def bad_embedding_range(document):
        document["patterns"][0]["embs"]["DAY-COLOR"]["c"] = [1.0, 1e300]

    def bad_modality_name(document):
        document["patterns"][0]["embs"][""] = {"c": [1.0], "n": 1, "dim": 1}

    return (
        ("root-missing", drop_root_field),
        ("root-unknown", unknown_root_field),
        ("schema", bad_schema),
        ("kind", bad_kind),
        ("version", bad_version),
        ("seq", bad_seq),
        ("patterns-type", bad_patterns_type),
        ("pattern-type", bad_pattern_type),
        ("record-unknown", unknown_record_field),
        ("record-missing", missing_record_field),
        ("duplicate-ids", duplicate_ids),
        ("state", unsupported_state),
        ("count", bad_count),
        ("count-bool", bad_bool_count),
        ("name", bad_name),
        ("signature-type", bad_signature_type),
        ("signature-keys", bad_signature_keys),
        ("signature-values", bad_signature_values),
        ("window-shape", bad_window_shape),
        ("window-item", bad_window_item),
        ("audit", bad_audit),
        ("embedding-type", bad_embedding_type),
        ("embedding-keys", bad_embedding_keys),
        ("embedding-dim", bad_embedding_dim),
        ("embedding-samples", bad_embedding_samples),
        ("embedding-nan", bad_embedding_nan),
        ("embedding-range", bad_embedding_range),
        ("embedding-modality", bad_modality_name),
    )


DOCUMENT_MUTATIONS = _document_mutations()


@pytest.mark.parametrize("mutate", [item[1] for item in DOCUMENT_MUTATIONS],
                         ids=[item[0] for item in DOCUMENT_MUTATIONS])
def test_restore_rejects_bad_documents_without_mutating_any_state(mutate):
    document = make_library().to_document()
    mutate(document)
    lib = PatternLibrary()
    lib.patterns["pat-9"] = {"id": "pat-9", "signature": sig(),
                             "state": "draft", "embs": {}}
    lib.seq = 42
    before = state_of(lib)
    with pytest.raises(PatternPersistenceError):
        lib.restore(document)
    assert state_of(lib) == before, "校验失败不得改变任何自身状态"


def test_library_round_trips_through_the_existing_tables():
    conn = memory_db()
    lib = make_library()
    save_library(conn, lib)
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0] == 2
    assert conn.execute(
        "SELECT COUNT(*) FROM pattern_embeddings").fetchone()[0] == 2
    restored = load_library(conn)
    assert restored.snapshot() == lib.snapshot(), "重建 worker 后逐字节一致"
    assert restored.seq == lib.seq
    conn.close()


def test_centroids_use_one_deterministic_float32_storage_precision():
    """内存质心、快照文本与既有 BLOB 列同精度：不假装 float64 能存活于列格式。"""
    conn = memory_db()
    lib = PatternLibrary()
    pattern = lib.match_or_record(sig())["pattern"]
    lib.attach_embedding(pattern["id"], [0.9, 0.1], "DAY-COLOR")
    first = lib.patterns[pattern["id"]]["embs"]["DAY-COLOR"]["c"]
    assert first == [float32_value(0.9), float32_value(0.1)], \
        "入档即归一 float32 存储精度"
    assert first != [0.9, 0.1], "float64 输入值不得原样留在内存库里"

    lib.attach_embedding(pattern["id"], [0.3, 0.7], "DAY-COLOR")
    entry = lib.patterns[pattern["id"]]["embs"]["DAY-COLOR"]
    assert (entry["dim"], entry["n"]) == (2, 2)
    assert [float32_value(value) for value in entry["c"]] == entry["c"], \
        "加权质心同样是 float32 精度（归一幂等）"
    assert entry["c"] != [(0.9 + 0.3) / 2, (0.1 + 0.7) / 2], \
        "加权中间值不得以 float64 形态入档"

    save_library(conn, lib)
    conn.commit()
    blob = conn.execute(
        "SELECT centroid, dim FROM pattern_embeddings").fetchone()
    assert len(blob["centroid"]) == 4 * blob["dim"]
    assert struct.unpack("<2f", blob["centroid"]) == tuple(entry["c"]), \
        "BLOB 与内存值同一 float32 精度"
    restored = load_library(conn)
    assert restored.patterns[pattern["id"]]["embs"]["DAY-COLOR"]["c"] == \
        entry["c"], "落库前后质心同值"
    assert restored.snapshot() == lib.snapshot(), "save→load 快照逐字节稳定"
    conn.close()


def test_float32_value_is_idempotent_and_rejects_out_of_range():
    value = float32_value(0.1)
    assert float32_value(value) == value, "归一幂等"
    assert float32_value(1.0) == 1.0 and float32_value(0) == 0.0
    with pytest.raises(OverflowError):
        float32_value(1e300)


def test_save_helpers_never_commit_on_their_own():
    conn = memory_db()
    save_library(conn, make_library())
    assert conn.in_transaction is True, "写面不自行提交，事务由调用方收口"
    conn.rollback()
    assert conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0] == 0
    conn.close()


def test_save_library_removes_patterns_dropped_from_the_library():
    conn = memory_db()
    lib = make_library()
    save_library(conn, lib)
    conn.commit()
    lib.patterns.pop("pat-2")               # 模拟 draft 被逐出
    save_library(conn, lib)
    conn.commit()
    assert {row[0] for row in conn.execute(
        "SELECT pattern_id FROM patterns")} == {"pat-1"}
    assert {row[0] for row in conn.execute(
        "SELECT pattern_id FROM pattern_embeddings")} == {"pat-1"}
    conn.close()


def test_load_library_rejects_unsupported_state():
    conn = corrupt_library_db()
    conn.execute(
        "UPDATE patterns SET state='pending' WHERE pattern_id='pat-1'")
    conn.commit()
    assert_load_rejected(conn)


def test_load_library_rejects_bad_signature_text():
    conn = corrupt_library_db()
    conn.execute(
        "UPDATE patterns SET signature='{oops' WHERE pattern_id='pat-1'")
    conn.commit()
    assert_load_rejected(conn)

    conn = corrupt_library_db()
    conn.execute("UPDATE patterns SET signature=NULL WHERE pattern_id='pat-1'")
    conn.commit()
    assert_load_rejected(conn)


def test_load_library_rejects_bad_payload_text():
    conn = corrupt_library_db()
    conn.execute(
        "UPDATE patterns SET payload='{oops' WHERE pattern_id='pat-1'")
    conn.commit()
    assert_load_rejected(conn)

    conn = corrupt_library_db()
    conn.execute(
        "UPDATE patterns SET payload='{\"llm_agree\": 1}'"
        " WHERE pattern_id='pat-1'")
    conn.commit()
    assert_load_rejected(conn)


def test_load_library_rejects_bad_centroid_rows():
    conn = corrupt_library_db()
    conn.execute("UPDATE pattern_embeddings SET centroid=? WHERE dim=2",
                 (b"\x00\x00\x80?",))
    conn.commit()
    assert_load_rejected(conn)

    conn = corrupt_library_db()
    conn.execute("UPDATE pattern_embeddings SET dim=3 WHERE dim=2")
    conn.commit()
    assert_load_rejected(conn)


def test_load_library_rejects_orphan_embedding_rows():
    conn = corrupt_library_db()
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute(
        "INSERT INTO pattern_embeddings"
        " (pattern_id, modality, centroid, dim, n) VALUES (?,?,?,?,?)",
        ("pat-ghost", "DAY-COLOR", b"\x00\x00\x80?", 1, 1))
    conn.commit()
    assert_load_rejected(conn)


def test_embedding_dimension_guard_holds_across_persistence():
    conn = memory_db()
    lib = PatternLibrary()
    pattern = lib.match_or_record(sig())["pattern"]
    lib.attach_embedding(pattern["id"], [1.0, 0.0], "DAY-COLOR")
    lib.attach_embedding(pattern["id"], [0.0, 1.0], "DAY-COLOR")
    lib.attach_embedding(pattern["id"], [1.0, 0.0, 0.0, 0.0], "DAY-COLOR")
    entry = lib.patterns[pattern["id"]]["embs"]["DAY-COLOR"]
    assert (entry["dim"], entry["n"]) == (4, 1), "维度不一致=重置档案（防 NaN）"
    save_library(conn, lib)
    conn.commit()
    stored = conn.execute(
        "SELECT modality, dim, n, LENGTH(centroid) FROM pattern_embeddings"
    ).fetchone()
    assert tuple(stored) == ("DAY-COLOR", 4, 1, 16), "float32 质心 4 维 = 16 字节"
    restored = load_library(conn)
    copy = restored.patterns[pattern["id"]]["embs"]["DAY-COLOR"]
    assert (copy["dim"], copy["n"]) == (4, 1)
    conn.close()
