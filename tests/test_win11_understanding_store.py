"""UnderstandingStore（C-138 §3 + C-139 §4）测试：有界存储 / 原子落盘 /
诊断计数 / 真实父子校验 / 并发 append / 冻结摘要形状 / append 深拷贝隔离 /
流式加载四类预算 / 非有限数与旧格式校验 / 未知相机 LRU 有界 /
C-140 §2 关键嵌套字段浅校验。"""

import hashlib
import json
import threading
from pathlib import Path

import pytest

from scam.win11_understanding_store import (
    DEFAULT_MAX_KNOWN_CAMERAS,
    DEFAULT_MAX_LOAD_FILE_BYTES,
    KINDS,
    UnderstandingStore,
    _resolve_within,
    branch_category,
    branch_counts,
    build_summary,
    latest_source_fields,
)

# C-139-R2 + C-140 §2 后的 snapshot 冻结字段集（原八字段 + 各批新增计数）。
SNAPSHOT_FIELDS = {
    "appended", "rotated", "record_too_large", "non_finite_rejected",
    "bad_lines", "bad_structure", "load_bad_lines", "load_oversized_lines",
    "load_non_finite", "load_parsed_records",
    "load_file_too_large", "load_truncated_oldest", "persist_failed",
    "cameras_evicted", "memory_only", "cameras",
}


def _branch_entry(branch="panorama", status="ok", text="一个人站在门口",
                  crop_id=None, key_tail=("w-1",)):
    return {
        "window_key": ["front", "run-1", "v1", *key_tail],
        "branch_key": ["front", "run-1", "v1", *key_tail, branch, crop_id],
        "branch": branch,
        "crop_id": crop_id,
        "status": status,
        "model_ref": "l3-local-model",
        "observation": ({"text": text, "unstructured": True,
                         "certainty": "model_inferred"}
                        if text else None),
        "inference": None,
        "reason": None if text else "error_code=E_MODEL",
        "sources": [{"position": "cur", "frame_id": "f9", "present": True,
                     "t_capture_ms": 12.0, "timestamp_kind": "source_capture"}],
        "missing": {"frames_dropped": 0, "omission_reason": None,
                    "frames": []},
    }


def _l3_rec(entries, window="w-1", status="ok"):
    return {"window": window, "branch": entries[0]["branch"],
            "status": status, "results": entries, "at": 1.0}


def _key(camera):
    """与实现一致的摘要目录键（测试自行推导，不依赖实现内部）。"""
    return hashlib.sha256(camera.encode("utf-8")).hexdigest()[:16]


def _write_lines(path, records):
    """按落盘布局写一个 kind 文件（测试直接构造磁盘状态）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records),
        encoding="utf-8")


# ---------- 基本读写与内存模式 ----------------------------------------------

def test_memory_mode_roundtrip_and_snapshot_frozen_fields():
    store = UnderstandingStore()
    assert store.append("front", "l2", {"status": "ok"}) is True
    assert store.append("front", "l3", {"window": "w", "branch": "panorama",
                                        "status": "ok"}) is True
    assert store.append("front", "l4", {"version_id": "v1",
                                        "status": "ok"}) is True
    assert store.history("front", "l2") == [{"status": "ok"}]
    assert len(store.history("front", "l3")) == 1
    snap = store.snapshot()
    # C-139：字段集扩展为 14 个（C-138 八字段 + 六个新预算/校验计数）
    assert set(snap) == SNAPSHOT_FIELDS
    assert snap["memory_only"] is True
    assert snap["appended"] == 3
    assert snap["cameras"]["front"]["appended"] == 3
    # 内存模式不产生任何文件
    assert store.summary("front")["camera"] == "front"


def test_append_validates_inputs():
    store = UnderstandingStore()
    with pytest.raises(ValueError):
        store.append(123, "l2", {})
    with pytest.raises(ValueError):
        store.append("", "l2", {})
    with pytest.raises(ValueError):
        store.append("front", "l5", {})
    with pytest.raises(ValueError):
        store.append("front", "l2", ["not", "a", "dict"])
    with pytest.raises(ValueError):
        store.append("front", "l2", {"x": object()})
    with pytest.raises(ValueError):
        store.history("front", "nope")


def test_disk_roundtrip_and_lazy_reload(tmp_path):
    root = tmp_path / "ustore"
    store = UnderstandingStore(root)
    store.append("front", "l2", {"status": "ok", "calibrated": False})
    store.append("front", "l3", _l3_rec([_branch_entry()]))
    store.append("back", "l4", {"version_id": "v9", "status": "partial"})
    # 摘要目录键：sha256(camera)[:16]，用户输入不进入文件路径
    key = hashlib.sha256("front".encode()).hexdigest()[:16]
    assert (root / key / "l2.jsonl").exists()

    reloaded = UnderstandingStore(root)
    assert reloaded.history("front", "l2") == [
        {"status": "ok", "calibrated": False}]
    assert len(reloaded.history("front", "l3")) == 1
    assert reloaded.history("back", "l4")[0]["version_id"] == "v9"
    assert reloaded.snapshot()["memory_only"] is False
    summary = reloaded.summary("front")
    assert summary["branches"][0]["text"] == "一个人站在门口"


# ---------- C1：append 深拷贝隔离 --------------------------------------------

def test_append_isolates_caller_nested_mutation(tmp_path):
    root = tmp_path / "ustore"
    store = UnderstandingStore(root)
    record = {
        "status": "ok",
        "bbox": [1, 2, 3, 4],
        "sources": [{"frame_id": "f1", "bbox": [5, 6]}],
        "results": [{"branch": "panorama", "missing": {"frames": []}}],
    }
    assert store.append("front", "l2", record) is True
    target = root / _key("front") / "l2.jsonl"
    before_disk = target.read_bytes()
    before_history = store.history("front", "l2")
    # 调用方事后改原对象：嵌套 list/dict 全部改到
    record["sources"].append({"frame_id": "intruder"})
    record["bbox"][0] = 999
    record["results"][0]["missing"]["frames"].append("x")
    record["status"] = "hacked"
    # 历史与已存文件都不被污染
    history = store.history("front", "l2")
    assert history == before_history
    assert history[0]["status"] == "ok"
    assert history[0]["bbox"] == [1, 2, 3, 4]
    assert history[0]["sources"] == [{"frame_id": "f1", "bbox": [5, 6]}]
    assert history[0]["results"][0]["missing"]["frames"] == []
    assert target.read_bytes() == before_disk
    # 全新实例重读磁盘也无污染
    assert UnderstandingStore(root).history("front", "l2") == before_history


def test_history_and_summary_returns_are_deep_copies():
    store = UnderstandingStore()
    items = [{"kind": "observation", "text": "一人", "certainty": "observed"}]
    assert store.append("front", "l2",
                        {"status": "ok", "sources": [{"frame_id": "f1"}]}
                        ) is True
    assert store.append("front", "l4", {"version_id": "v1", "status": "ok",
                                        "items": items}) is True
    # 改 history() 返回值（含嵌套）→ 内部不变
    leaked = store.history("front", "l2")
    leaked.append({"status": "intruder"})
    leaked[0]["sources"].append({"frame_id": "intruder"})
    assert store.history("front", "l2") == [
        {"status": "ok", "sources": [{"frame_id": "f1"}]}]
    # 改 summary() 返回值（branches/fusion 嵌套）→ 内部不变
    summary = store.summary("front")
    summary["fusion"]["items"][0]["text"] = "hacked"
    summary["branches"].append({"kind": "intruder"})
    fresh = store.summary("front")
    assert fresh["fusion"]["items"][0]["text"] == "一人"
    assert fresh["branches"] == []
    # 共享同一 items 对象的原记录后续被改，也不影响已接受历史
    items[0]["text"] = "later-mutated"
    assert store.history("front", "l4")[0]["items"][0]["text"] == "一人"


# ---------- C2：加载预算（流式 + 分项） --------------------------------------

def test_load_file_too_large_rejects_and_keeps_memory(tmp_path):
    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    _write_lines(target, [{"status": "old", "seq": i} for i in range(20)])
    # 场景一：只读访问——超限文件整体拒载 + 计数，磁盘文件一字节不动
    store = UnderstandingStore(root, max_load_file_bytes=100)
    assert store.history("front", "l2") == []
    snap = store.snapshot()
    assert snap["load_file_too_large"] == 1
    assert snap["cameras"]["front"]["load_file_too_large"] == 1
    assert len(target.read_text(encoding="utf-8").splitlines()) == 20
    # 场景二：先 append（内存已有）再遇超限文件——内存内容保留可查看
    store2 = UnderstandingStore(root, max_load_file_bytes=100)
    assert store2.append("front", "l2", {"status": "new"}) is True
    assert [r["status"] for r in store2.history("front", "l2")] == ["new"]
    assert store2.snapshot()["load_file_too_large"] == 1


def test_oversized_line_skipped_and_counted(tmp_path):
    root = tmp_path / "ustore"
    target = root / _key("front") / "l3.jsonl"
    huge = {"status": "ok", "blob": "x" * 500}
    _write_lines(target, [{"status": "ok", "seq": 1}, huge,
                          {"status": "ok", "seq": 2}])
    store = UnderstandingStore(root, max_record_bytes=64)
    history = store.history("front", "l3")
    assert [r.get("seq") for r in history] == [1, 2]
    snap = store.snapshot()
    assert snap["load_oversized_lines"] == 1
    assert snap["cameras"]["front"]["load_oversized_lines"] == 1
    assert snap["bad_lines"] == 0


def test_giant_line_skipped_without_full_line_buffer(tmp_path, monkeypatch):
    """R2：巨行（> max_record_bytes×2）绝不整行读入内存——分块倒读中
    拼行缓冲超硬上限即判定巨行、跳到行起点边界，且同行只计一次数。"""
    import scam.win11_understanding_store as store_mod

    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    giant = '{"status": "ok", "blob": "' + "x" * 5000 + '"}'
    _write_lines(target, [
        {"status": "ok", "seq": 0},
        json.loads(giant),          # 唯一的一行巨行（~5020 字节，无内嵌 \n）
        {"status": "ok", "seq": 2},
    ])
    # 32 字节小块读取：巨行必然横跨多个读取块，触发拼行超硬上限路径
    monkeypatch.setattr(store_mod, "_SCAN_CHUNK_BYTES", 32)
    store = UnderstandingStore(root, max_record_bytes=64)   # 硬上限=128
    history = store.history("front", "l2")
    assert [r.get("seq") for r in history] == [0, 2]
    snap = store.snapshot()
    # 巨行横跨多块也只计一次——绝不按块重复计数
    assert snap["load_oversized_lines"] == 1
    assert snap["cameras"]["front"]["load_oversized_lines"] == 1
    assert snap["load_parsed_records"] == 2
    assert snap["bad_lines"] == 0


def test_default_chunk_giant_line_also_counted_once(tmp_path):
    """默认 64KB 块下，单条 70KB 巨行（跨块、无内嵌 \\n）同样只跳过+计一次。"""
    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    lines = [json.dumps({"status": "ok", "seq": 1}, ensure_ascii=False),
             json.dumps({"status": "ok", "blob": "y" * 70_000},
                        ensure_ascii=False),
             json.dumps({"status": "ok", "seq": 3}, ensure_ascii=False)]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    store = UnderstandingStore(root, max_record_bytes=1024)   # 硬上限=2048
    assert [r.get("seq") for r in store.history("front", "l2")] == [1, 3]
    snap = store.snapshot()
    assert snap["load_oversized_lines"] == 1
    assert snap["load_parsed_records"] == 2


# ---------- C-140-R1：巨行 skipping 退出边界（倒序扫描吞行缺陷回归） ----------

def _bline(record):
    """单条记录 → 含结尾 \\n 的 bytes 行（测试直接构造磁盘字节）。"""
    return (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")


def _write_blines(path, lines):
    """按字节精确写 kind 文件（lines 各自带 \\n；末行可无 \\n）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(lines))


def test_giant_line_skipping_exit_keeps_legal_lines_before_it(
        tmp_path, monkeypatch):
    """Codex 复现实锤：seq1→seq2→巨行→seq3 倒序加载必须三条全回。

    巨行内容无换行，其起点是缓冲中**最后一个** \\n（rfind）；skipping
    退出若取**第一个** \\n（find），同块内巨行之前的完整合法行（seq2）
    会被当成巨行内容一起丢弃 → 只返回 seq1、seq3。工程化对齐：让最后
    读取的一块恰好完整覆盖 seq1、seq2 与巨行头部（退出块含两个 \\n）。
    """
    import scam.win11_understanding_store as store_mod

    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    chunk = 64
    giant = _bline({"status": "ok", "blob": "x" * 398})   # 427 字节 > 硬上限 128
    _write_blines(target, [_bline({"status": "ok", "seq": 1}),
                           _bline({"status": "ok", "seq": 2}),
                           giant,
                           _bline({"status": "ok", "seq": 3})])
    raw = target.read_bytes()
    nl2 = raw.index(b"\n", raw.index(b"\n") + 1)   # 第二个 \n（巨行起点边界）
    tail = len(raw) % chunk or chunk               # 最后读取一块的长度
    # 布局预置条件：巨行起点（nl2+1）落在末读块内，且 seq1、seq2 完整在块内
    assert nl2 + 1 < tail
    assert len(giant) > 2 * 64 + chunk             # 巨行必然触发 skipping 路径

    monkeypatch.setattr(store_mod, "_SCAN_CHUNK_BYTES", chunk)
    store = UnderstandingStore(root, max_record_bytes=64)   # 硬上限=128
    assert [r.get("seq") for r in store.history("front", "l2")] == [1, 2, 3]
    snap = store.snapshot()
    assert snap["load_oversized_lines"] == 1       # 巨行恰计一次
    assert snap["load_parsed_records"] == 3        # 三条合法行全部入池
    assert snap["bad_lines"] == 0
    assert snap["load_bad_lines"] == 0


@pytest.mark.parametrize("chunk", [7, 8, 11, 13, 16, 17, 23, 24, 31, 32,
                                   33, 41, 47, 48, 49, 64, 65, 96, 128,
                                   137, 205, 206, 411, 412])
def test_giant_line_scan_result_invariant_across_chunk_sizes(
        tmp_path, monkeypatch, chunk):
    """任意读取块大小下扫描可见结果必须完全一致（跨块与边界对齐全切法）。

    同一文件（seq1→seq2→巨行→seq3）在每种块大小下都应：三条合法行全
    回、巨行恰计一次 oversized、零误计——不因块边界切在哪而丢行。
    """
    import scam.win11_understanding_store as store_mod

    root = tmp_path / ("ustore-%d" % chunk)
    target = root / _key("front") / "l2.jsonl"
    _write_blines(target, [_bline({"status": "ok", "seq": 1}),
                           _bline({"status": "ok", "seq": 2}),
                           _bline({"status": "ok", "blob": "x" * 350}),
                           _bline({"status": "ok", "seq": 3})])
    monkeypatch.setattr(store_mod, "_SCAN_CHUNK_BYTES", chunk)
    store = UnderstandingStore(root, max_record_bytes=64)   # 硬上限=128
    assert [r.get("seq") for r in store.history("front", "l2")] == [1, 2, 3]
    snap = store.snapshot()
    assert snap["load_oversized_lines"] == 1
    assert snap["load_parsed_records"] == 3
    assert snap["bad_lines"] == 0


def test_giant_line_spanning_many_chunks_keeps_both_neighbors(
        tmp_path, monkeypatch):
    """巨行横跨大量读取块时，其前后的合法行都必须保留（C-139-R2 不回归）。"""
    import scam.win11_understanding_store as store_mod

    root = tmp_path / "ustore"
    target = root / _key("front") / "l4.jsonl"
    giant = _bline({"version_id": "v-giant", "blob": "y" * 600})
    _write_blines(target, [_bline({"version_id": "v1", "seq": 0}),
                           _bline({"version_id": "v2", "seq": 1}),
                           giant,
                           _bline({"version_id": "v3", "seq": 2})])
    assert len(giant) > 8 * 16          # 巨行横跨至少 8 个 16 字节块
    monkeypatch.setattr(store_mod, "_SCAN_CHUNK_BYTES", 16)
    store = UnderstandingStore(root, max_record_bytes=64)
    history = store.history("front", "l4")
    assert [r["version_id"] for r in history] == ["v1", "v2", "v3"]
    assert [r.get("seq") for r in history] == [0, 1, 2]
    snap = store.snapshot()
    assert snap["load_oversized_lines"] == 1
    assert snap["load_parsed_records"] == 3
    assert snap["bad_lines"] == 0


def test_multiple_and_consecutive_giant_lines_each_counted_once(
        tmp_path, monkeypatch):
    """多条巨行（含首尾连续两条）每条恰计一次；中间合法行全部保留。"""
    import scam.win11_understanding_store as store_mod

    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"

    def giant(n):
        return _bline({"status": "ok", "blob": "g" * (200 + 30 * n)})

    _write_blines(target, [giant(1), giant(2),        # 文件开头连续两条巨行
                           _bline({"status": "ok", "seq": 1}),
                           giant(3),
                           _bline({"status": "ok", "seq": 2}),
                           _bline({"status": "ok", "seq": 3}),
                           giant(4), giant(5),        # 尾部连续两条巨行
                           _bline({"status": "ok", "seq": 4})])
    monkeypatch.setattr(store_mod, "_SCAN_CHUNK_BYTES", 13)
    store = UnderstandingStore(root, max_record_bytes=64)
    assert [r.get("seq") for r in store.history("front", "l2")] == [1, 2, 3, 4]
    snap = store.snapshot()
    assert snap["load_oversized_lines"] == 5          # 每条巨行恰一次
    assert snap["load_parsed_records"] == 4
    assert snap["bad_lines"] == 0


@pytest.mark.parametrize("trailing_newline", [True, False])
@pytest.mark.parametrize("giant_first", [True, False])
def test_trailing_newline_and_giant_position_variants(
        tmp_path, monkeypatch, giant_first, trailing_newline):
    """文件末尾有/无换行 × 巨行在最旧/最新侧：可见结果一致且无吞行。"""
    import scam.win11_understanding_store as store_mod

    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    giant = _bline({"status": "ok", "blob": "z" * 300})
    if giant_first:
        lines = [giant, _bline({"status": "ok", "seq": 1}),
                 _bline({"status": "ok", "seq": 9})]
    else:
        lines = [_bline({"status": "ok", "seq": 1}),
                 _bline({"status": "ok", "seq": 9}), giant]
    if not trailing_newline:
        lines[-1] = lines[-1][:-1]        # 末行去掉换行符
    _write_blines(target, lines)
    monkeypatch.setattr(store_mod, "_SCAN_CHUNK_BYTES", 17)
    store = UnderstandingStore(root, max_record_bytes=64)
    assert [r.get("seq") for r in store.history("front", "l2")] == [1, 9]
    snap = store.snapshot()
    assert snap["load_oversized_lines"] == 1
    assert snap["load_parsed_records"] == 2
    assert snap["bad_lines"] == 0


@pytest.mark.parametrize("pad", range(0, 18))
def test_legal_lines_exact_at_chunk_boundaries(tmp_path, monkeypatch, pad):
    """填充把巨行起点相对块边界移动到每一种对齐（含边界恰切在换行符前后）。

    合法行都必须完整保留——无论块边界切在行内容中间、\\n 之前还是 \\n
    之后，倒序扫描结果不得有任何差别。
    """
    import scam.win11_understanding_store as store_mod

    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    chunk = 16
    lines = [_bline({"status": "ok", "seq": 1, "pad": "p" * pad}),
             _bline({"status": "ok", "seq": 2}),
             _bline({"status": "ok", "blob": "w" * 300}),
             _bline({"status": "ok", "seq": 3})]
    assert len(lines[0]) < 64             # 填充行仍是合法大小（不误入 oversized）
    _write_blines(target, lines)
    monkeypatch.setattr(store_mod, "_SCAN_CHUNK_BYTES", chunk)
    store = UnderstandingStore(root, max_record_bytes=64)
    assert [r.get("seq") for r in store.history("front", "l2")] == [1, 2, 3]
    snap = store.snapshot()
    assert snap["load_oversized_lines"] == 1
    assert snap["load_parsed_records"] == 3
    assert snap["bad_lines"] == 0


def test_budgets_and_limits_unchanged_with_giant_lines(tmp_path, monkeypatch):
    """记录预算 / 文件字节预算 / max_per_camera 在含巨行文件上不回归。"""
    import scam.win11_understanding_store as store_mod

    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    giant = _bline({"status": "ok", "blob": "b" * 300})
    _write_blines(target, [_bline({"status": "ok", "seq": i})
                           for i in range(1, 9)] + [giant] +
                  [_bline({"status": "ok", "seq": 9}),
                   _bline({"status": "ok", "seq": 10})])
    monkeypatch.setattr(store_mod, "_SCAN_CHUNK_BYTES", 19)
    # 场景一：预算 1 → 倒序取最新 1 条；预算+1 即停，巨行根本不会被走到
    store = UnderstandingStore(root, max_record_bytes=64,
                               load_budget_records=1)
    assert [r.get("seq") for r in store.history("front", "l2")] == [10]
    snap = store.snapshot()
    assert snap["load_parsed_records"] == 2       # 预算+1 的截断确认
    assert snap["load_truncated_oldest"] == 1
    assert snap["load_oversized_lines"] == 0      # 提前停：未触及巨行
    # 场景二：skipping 退出后保留行照常入预算池，预算+1 即停
    # （预算 1：退出后第一条 L2 入池即达 预算+1，L1 不再解析——过程断言看
    # parsed 计数；实际载入按共享预算只保留最新 1 条）
    root2 = tmp_path / "ustore2"
    target2 = root2 / _key("front") / "l2.jsonl"
    _write_blines(target2, [_bline({"status": "ok", "seq": 1}),
                            _bline({"status": "ok", "seq": 2}),
                            giant,
                            _bline({"status": "ok", "seq": 3})])
    store2 = UnderstandingStore(root2, max_record_bytes=64,
                                load_budget_records=1)
    assert [r.get("seq") for r in store2.history("front", "l2")] == [3]
    snap2 = store2.snapshot()
    assert snap2["load_oversized_lines"] == 1
    assert snap2["load_parsed_records"] == 2     # L3 + 退出后首条 L2 即停
    assert snap2["load_truncated_oldest"] == 1
    # 场景二补：预算 2 → 退出后保留的 L2 完整可用（未被巨行误吞/污染），
    # 扫描继续到 L1 达 预算+1 停；实际载入保留最新 2 条
    store2b = UnderstandingStore(root2, max_record_bytes=64,
                                 load_budget_records=2)
    assert [r.get("seq") for r in store2b.history("front", "l2")] == [2, 3]
    snap2b = store2b.snapshot()
    assert snap2b["load_oversized_lines"] == 1
    assert snap2b["load_parsed_records"] == 3
    assert snap2b["load_truncated_oldest"] == 1
    # 场景三：文件字节预算（stat 即拒载）对含巨行文件依旧生效
    store3 = UnderstandingStore(root, max_record_bytes=64,
                                max_load_file_bytes=64)
    assert store3.history("front", "l2") == []
    assert store3.snapshot()["load_file_too_large"] == 1
    # 场景四：max_per_camera 收敛（加载 3 条、驻留最新 2 条；不计 rotated）
    root4 = tmp_path / "ustore4"
    target4 = root4 / _key("front") / "l2.jsonl"
    _write_blines(target4, [_bline({"status": "ok", "seq": i})
                            for i in (1, 2, 3)])
    store4 = UnderstandingStore(root4, max_per_camera=2)
    assert [r.get("seq") for r in store4.history("front", "l2")] == [2, 3]
    snap4 = store4.snapshot()
    assert snap4["rotated"] == 0
    # 冻结语义：max_per_camera 收敛不计截断（磁盘未动，append 重写时自然收敛）
    assert snap4["load_truncated_oldest"] == 0


def test_counter_consistency_and_legacy_through_skipping_exit(
        tmp_path, monkeypatch):
    """计数与实际处理一致：巨行恰计一次 oversized、合法行计 parsed；经
    skipping 退出路径恢复的旧格式行仍如实标 legacy；全局与逐相机一致。"""
    import scam.win11_understanding_store as store_mod

    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    _write_blines(target, [
        _bline({"seq": 1}),                            # 旧格式 → legacy
        _bline({"status": "ok", "seq": 2}),
        _bline({"status": "ok", "blob": "q" * 300}),   # 巨行
        _bline({"status": "ok", "seq": 3}),
    ])
    monkeypatch.setattr(store_mod, "_SCAN_CHUNK_BYTES", 23)
    store = UnderstandingStore(root, max_record_bytes=64)
    history = store.history("front", "l2")
    assert [r.get("seq") for r in history] == [1, 2, 3]
    assert history[0].get("legacy") is True
    assert all("legacy" not in r for r in history[1:])
    snap = store.snapshot()
    assert snap["load_oversized_lines"] == 1
    assert snap["load_parsed_records"] == 3
    assert snap["bad_lines"] == 0
    assert snap["load_bad_lines"] == 0
    assert snap["bad_structure"] == 0
    cam = snap["cameras"]["front"]
    assert cam["load_oversized_lines"] == 1
    assert cam["load_parsed_records"] == 3


def test_file_growth_after_stat_reads_only_snapshot_size(
        tmp_path, monkeypatch):
    """R2：stat 之后文件被追加 → 只读 stat 时的快照大小，绝不无界读取。"""
    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    _write_lines(target, [{"status": "ok", "seq": i} for i in range(3)])
    snapshot_size = target.stat().st_size
    resolved_target = str(target.resolve())   # monkeypatch 前先解析（resolve 内部会 stat）
    # stat 之后才发生的追加（快照外的第 4 条）
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"status": "ok", "seq": 3}) + "\n")
    assert target.stat().st_size > snapshot_size

    real_stat = type(target).stat

    class _FakeStat:
        def __init__(self, size):
            self.st_size = size

    def fake_stat(self, **kwargs):
        if str(self) == resolved_target:
            return _FakeStat(snapshot_size)   # 模拟 TOCTOU：stat 早于追加
        return real_stat(self, **kwargs)

    monkeypatch.setattr(type(target), "stat", fake_stat)
    store = UnderstandingStore(root)
    # 追加的 seq=3 位于快照末尾之外：本轮加载不可见，也不出错
    assert [r.get("seq") for r in store.history("front", "l2")] == [0, 1, 2]
    snap = store.snapshot()
    assert snap["load_parsed_records"] == 3
    assert snap["bad_lines"] == 0


def test_load_shallow_type_validation_skips_and_counts(tmp_path):
    """R2 浅结构校验：status 必须是 str、kind 必须在 {l2,l3,l4}（存在才
    校验）——不符跳过 + load_bad_lines；缺字段的 legacy 记录如实放行。"""
    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join([
        json.dumps({"status": 42, "seq": 1}),            # status 非 str
        json.dumps({"status": "ok", "kind": "l9"}),      # kind 越值域
        json.dumps({"status": "ok", "kind": 7}),         # kind 非 str
        json.dumps({"status": "ok", "seq": 4}),          # 合规 → 载入
        json.dumps({"seq": 5}),                          # 缺字段 → legacy
    ]) + "\n", encoding="utf-8")
    store = UnderstandingStore(root)
    history = store.history("front", "l2")
    # 合规记录与缺字段 legacy 记录都放行（各自如实标注）；history 旧→新
    assert [r.get("seq") for r in history] == [4, 5]
    assert "legacy" not in history[0]            # 当前格式绝不误标
    assert history[1]["legacy"] is True          # 缺 status 锚点 → legacy
    snap = store.snapshot()
    assert snap["load_bad_lines"] == 3
    assert snap["load_parsed_records"] == 2
    assert snap["bad_lines"] == 0


def test_load_budget_round_robin_keeps_all_kinds_alive(tmp_path):
    root = tmp_path / "ustore"
    for kind, count in (("l2", 20), ("l3", 10)):
        _write_lines(root / _key("front") / (kind + ".jsonl"),
                     [{"status": "ok", "seq": i} for i in range(count)])
    store = UnderstandingStore(root, load_budget_records=9)
    l2 = store.history("front", "l2")
    l3 = store.history("front", "l3")
    # 冻结语义：共享总预算 + 每轮按 l2→l3→l4 各取一条最新。
    # 9 条预算轮转分配 → l2 取最新 5 条，l3 取最新 4 条；
    # l2 记录泛滥（20 条）绝不能让 l3 一条都读不到。
    assert [r["seq"] for r in l2] == [15, 16, 17, 18, 19]
    assert [r["seq"] for r in l3] == [6, 7, 8, 9]
    # R2：扫描期预算——每个 kind 解析到 预算+1 条即停（l2 池=10 条最新，
    # l3 文件只有 10 条全入池），截断计数=已解析-实际载入=20-9=11。
    snap = store.snapshot()
    assert snap["load_truncated_oldest"] == 20 - 9
    assert snap["load_parsed_records"] == 10 + 10
    # 预算 0：一条不载；扫描仍解析 1 条（预算+1=截断确认），按截断计数
    root2 = tmp_path / "ustore2"
    _write_lines(root2 / _key("back") / "l2.jsonl",
                 [{"status": "ok", "seq": i} for i in range(3)])
    zero = UnderstandingStore(root2, load_budget_records=0)
    assert zero.history("back", "l2") == []
    assert zero.snapshot()["load_truncated_oldest"] == 1
    assert zero.snapshot()["load_parsed_records"] == 1


def test_load_budget_stops_parsing_early_process_evidence(tmp_path):
    """R2 核心缺口：预算提前停止扫描——过程断言看解析计数而非历史长度。"""
    root = tmp_path / "ustore"
    _write_lines(root / _key("front") / "l2.jsonl",
                 [{"status": "ok", "seq": i} for i in range(8)])
    store = UnderstandingStore(root, load_budget_records=1)
    history = store.history("front", "l2")
    # 只保留最新 1 条
    assert [r["seq"] for r in history] == [7]
    # 过程断言：解析计数 = 预算+1（第 2 条仅确认截断发生），绝非全部 8 条
    snap = store.snapshot()
    assert snap["load_parsed_records"] == 1 + 1
    assert snap["cameras"]["front"]["load_parsed_records"] == 2
    assert snap["load_truncated_oldest"] == 1


def test_load_budget_takes_most_recent_lines(tmp_path):
    root = tmp_path / "ustore"
    key = hashlib.sha256("front".encode()).hexdigest()[:16]
    target = root / key / "l2.jsonl"
    target.parent.mkdir(parents=True)
    lines = [json.dumps({"seq": i}, ensure_ascii=False) for i in range(10)]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    store = UnderstandingStore(root, load_budget_records=5,
                               max_per_camera=50)
    assert [r["seq"] for r in store.history("front", "l2")] == [5, 6, 7, 8, 9]


def test_bad_json_and_bad_structure_skipped_not_fatal(tmp_path):
    root = tmp_path / "ustore"
    key = hashlib.sha256("front".encode()).hexdigest()[:16]
    target = root / key / "l3.jsonl"
    target.parent.mkdir(parents=True)
    good = json.dumps({"window": "w", "branch": "panorama",
                       "status": "ok"}, ensure_ascii=False)
    target.write_text("\n".join([
        good,
        "{这不是合法 JSON",
        "[1, 2, 3]",            # 合法 JSON 但顶层不是 dict → 坏结构
        '"just a string"',
        good,
    ]) + "\n", encoding="utf-8")
    store = UnderstandingStore(root)
    history = store.history("front", "l3")
    assert len(history) == 2
    snap = store.snapshot()
    assert snap["bad_lines"] == 1
    assert snap["load_bad_lines"] == 2
    # 坏行不拖垮写入：加载后继续 append 正常
    assert store.append("front", "l3", {"window": "w2"}) is True
    assert len(store.history("front", "l3")) == 3


def test_persist_failure_keeps_memory_view(tmp_path):
    root = tmp_path / "blocked"
    root.write_text("i am a file, not a dir", encoding="utf-8")
    store = UnderstandingStore(root)
    assert store.append("front", "l2", {"status": "ok"}) is False
    # 查看能力不因落盘失败消失
    assert store.history("front", "l2") == [{"status": "ok"}]
    snap = store.snapshot()
    assert snap["persist_failed"] == 1
    assert snap["appended"] == 1


# ---------- C3：数值与结构校验 -----------------------------------------------

def test_append_rejects_non_finite_numbers():
    store = UnderstandingStore()
    assert store.append("front", "l2", {"score": float("nan")}) is False
    assert store.append("front", "l2", {"score": float("inf")}) is False
    assert store.append("front", "l2",
                        {"sources": [{"score": 1e400}]}) is False
    assert store.history("front", "l2") == []
    snap = store.snapshot()
    assert snap["non_finite_rejected"] == 3
    assert snap["cameras"]["front"]["non_finite_rejected"] == 3
    assert snap["appended"] == 0


def test_load_skips_non_finite_records(tmp_path):
    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    target.parent.mkdir(parents=True)
    target.write_text("\n".join([
        json.dumps({"status": "ok", "seq": 1}),
        '{"status": "ok", "seq": 2, "score": NaN}',
        '{"status": "ok", "seq": 3, "score": Infinity}',
        '{"status": "ok", "seq": 4, "score": 1e400}',
        json.dumps({"status": "ok", "seq": 5}),
    ]) + "\n", encoding="utf-8")
    store = UnderstandingStore(root)
    assert [r["seq"] for r in store.history("front", "l2")] == [1, 5]
    snap = store.snapshot()
    assert snap["load_non_finite"] == 3
    assert snap["bad_lines"] == 0


def test_illegal_top_level_rejected_on_append_and_load(tmp_path):
    store = UnderstandingStore()
    for bad in ([1, 2], "a string", 42, None):
        with pytest.raises(ValueError):
            store.append("front", "l2", bad)
    assert store.history("front", "l2") == []
    # 加载侧：顶层非 dict 跳过 + 计数，好行照常读入
    root = tmp_path / "ustore"
    target = root / _key("front") / "l2.jsonl"
    target.parent.mkdir(parents=True)
    target.write_text("[1, 2, 3]\n" + json.dumps({"status": "ok"}) + "\n",
                      encoding="utf-8")
    disk_store = UnderstandingStore(root)
    assert disk_store.history("front", "l2") == [{"status": "ok"}]
    assert disk_store.snapshot()["load_bad_lines"] == 1


def test_legacy_records_marked_on_load(tmp_path):
    root = tmp_path / "ustore"
    key = _key("front")
    _write_lines(root / key / "l2.jsonl", [{"seq": 1}])       # 缺 status 锚点
    _write_lines(root / key / "l4.jsonl", [{"items": []}])    # 缺 version_id
    store = UnderstandingStore(root)
    assert store.history("front", "l2") == [{"seq": 1, "legacy": True}]
    assert store.history("front", "l4") == [{"items": [], "legacy": True}]
    # 当前格式（含锚点字段）绝不误标
    _write_lines(root / key / "l3.jsonl", [{"status": "ok"}])
    store2 = UnderstandingStore(root)
    assert store2.history("front", "l3") == [{"status": "ok"}]
    assert "legacy" not in store2.history("front", "l3")[0]


# ---------- C5：关键嵌套字段浅校验（C-140 §2） --------------------------------

def test_l4_items_wrong_type_skipped_and_counted(tmp_path):
    """C-140 断点修复：items 为字符串的 L4 记录不再被当有效记录加载
    （整条跳过 + bad_structure；显式 null 视同缺字段照常兼容）。"""
    root = tmp_path / "ustore"
    _write_lines(root / _key("front") / "l4.jsonl", [
        {"version_id": "v-bad", "status": "ok", "items": "不是列表"},
        {"version_id": "v-null", "status": "ok", "items": None},
        {"version_id": "v-good", "status": "ok",
         "items": [{"kind": "observation", "text": "一人"}]},
    ])
    store = UnderstandingStore(root)
    history = store.history("front", "l4")
    assert [r["version_id"] for r in history] == ["v-null", "v-good"]
    assert all("legacy" not in r for r in history)   # 有锚点=当前格式
    snap = store.snapshot()
    assert snap["bad_structure"] == 1
    assert snap["cameras"]["front"]["bad_structure"] == 1
    assert snap["load_parsed_records"] == 2
    assert snap["bad_lines"] == 0
    assert snap["load_bad_lines"] == 0


def test_l4_items_non_dict_entries_dropped_record_kept(tmp_path):
    """items 为 list 但混入非 dict 条目 → 就地剔除坏条目（逐条计数），
    记录本身保留——只剔除坏条目，不整条丢弃历史。"""
    root = tmp_path / "ustore"
    _write_lines(root / _key("front") / "l4.jsonl", [
        {"version_id": "v1", "status": "ok",
         "items": [{"t": 1}, "stray", 42, None, {"t": 2}]},
    ])
    store = UnderstandingStore(root)
    history = store.history("front", "l4")
    assert len(history) == 1
    assert history[0]["items"] == [{"t": 1}, {"t": 2}]
    assert store.summary("front")["fusion"]["items"] == [{"t": 1}, {"t": 2}]
    snap = store.snapshot()
    assert snap["bad_structure"] == 3          # 每个被剔除条目各计一次
    assert snap["load_parsed_records"] == 1


def test_l3_results_wrong_type_skipped_and_entries_filtered(tmp_path):
    """results 为 str 的 L3 记录整条跳过 + 计数；list 内非 dict 条目剔除。"""
    root = tmp_path / "ustore"
    _write_lines(root / _key("front") / "l3.jsonl", [
        {"window": "w", "branch": "panorama", "status": "ok",
         "results": "oops"},
        {"window": "w", "branch": "panorama", "status": "ok",
         "results": [{"status": "ok",
                      "observation": {"text": "一人"}}, "bad-entry"]},
    ])
    store = UnderstandingStore(root)
    history = store.history("front", "l3")
    assert len(history) == 1
    assert history[0]["results"] == [
        {"status": "ok", "observation": {"text": "一人"}}]
    snap = store.snapshot()
    assert snap["bad_structure"] == 2          # 1 整条 + 1 坏条目
    assert snap["load_parsed_records"] == 1


def test_version_id_and_window_fields_type_enforced(tmp_path):
    """version_id 必须 str；window 四元字段必须 str/int（bool/float/list/
    dict 均拒）。不符整条跳过 + bad_structure，其余记录照常加载。"""
    root = tmp_path / "ustore"
    _write_lines(root / _key("front") / "l4.jsonl", [
        {"version_id": 7, "status": "ok"},                     # int → 拒
        {"version_id": "v2", "window_id": 3, "status": "ok"},  # int 允许
        {"version_id": "v3", "camera_id": {"cam": 1}},         # dict → 拒
        {"version_id": "v4", "run_id": ["run-1"]},             # list → 拒
        {"version_id": "v5", "config_version": 1.5},           # float → 拒
        {"version_id": "v6", "window_id": True},               # bool → 拒
        {"version_id": "v7", "status": "ok", "camera_id": "front",
         "run_id": "run-1", "config_version": 2,
         "window_id": "w-1"},                                  # 合规
    ])
    store = UnderstandingStore(root)
    history = store.history("front", "l4")
    assert [r["version_id"] for r in history] == ["v2", "v7"]
    snap = store.snapshot()
    assert snap["bad_structure"] == 5
    assert snap["load_parsed_records"] == 2


def test_frame_refs_and_sources_must_be_lists(tmp_path):
    """frame_refs（l4）与 sources（任意 kind）存在时必须是 list。"""
    root = tmp_path / "ustore"
    _write_lines(root / _key("front") / "l4.jsonl", [
        {"version_id": "v1", "frame_refs": "f1"},              # 拒
        {"version_id": "v2", "frame_refs": ["f1", "f2"]},      # 合规
    ])
    _write_lines(root / _key("front") / "l2.jsonl", [
        {"status": "ok", "sources": "not-a-list"},             # 拒
        {"status": "ok", "sources": [{"frame_id": "f1"}]},     # 合规
    ])
    store = UnderstandingStore(root)
    assert [r["version_id"] for r in store.history("front", "l4")] == ["v2"]
    assert [r["status"] for r in store.history("front", "l2")] == ["ok"]
    assert store.snapshot()["bad_structure"] == 2


def test_legacy_missing_nested_fields_and_nulls_stay_compatible(tmp_path):
    """旧格式缺 items/results/frame_refs 照常兼容（不因缺字段拒绝）；
    显式 null 视同缺字段；坏记录不拖垮同文件合法记录（含失败态）。"""
    root = tmp_path / "ustore"
    _write_lines(root / _key("front") / "l3.jsonl", [
        {"status": "model_unavailable", "branch": "panorama",
         "reason": "error_code=E_MODEL"},              # 旧格式：无 results
        {"status": "ok", "branch": "panorama", "results": None},
    ])
    _write_lines(root / _key("front") / "l4.jsonl", [
        {"version_id": "v1"},                          # 无 items/frame_refs
    ])
    store = UnderstandingStore(root)
    assert len(store.history("front", "l3")) == 2
    assert len(store.history("front", "l4")) == 1
    snap = store.snapshot()
    assert snap["bad_structure"] == 0
    assert snap["load_bad_lines"] == 0
    assert snap["bad_lines"] == 0


# ---------- C4：未知相机 LRU 有界 --------------------------------------------

def test_unknown_camera_lru_bounded_on_disk(tmp_path):
    root = tmp_path / "ustore"
    store = UnderstandingStore(root)   # 默认 max_known_cameras=32
    store.append("cam-000", "l2", {"status": "ok", "cam": "cam-000"})
    for i in range(1, 33):
        store.append("cam-{:03d}".format(i), "l2", {"status": "ok"})
    snap = store.snapshot()
    assert snap["cameras_evicted"] == 1
    assert len(snap["cameras"]) == 32
    assert "cam-000" not in snap["cameras"]
    # 最旧相机内存历史被淘汰；磁盘文件不动——再次访问按哈希键懒加载恢复
    target = root / _key("cam-000") / "l2.jsonl"
    lines = target.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["cam"] == "cam-000"
    assert store.history("cam-000", "l2") == [
        {"status": "ok", "cam": "cam-000"}]
    assert store.snapshot()["cameras_evicted"] == 1  # 懒加载恢复不计淘汰


def test_memory_mode_camera_lru_bounded():
    store = UnderstandingStore()       # 默认 max_known_cameras=32
    for i in range(100):
        store.append("cam-{:03d}".format(i), "l2", {"seq": i})
    snap = store.snapshot()
    assert len(snap["cameras"]) == 32
    assert snap["cameras_evicted"] == 100 - 32
    # 无界增长不可能：任何时刻驻留相机数 ≤ 上限
    assert store.history("cam-000", "l2") == []      # 最旧已被淘汰
    assert [r["seq"] for r in store.history("cam-099", "l2")] == [99]


def test_constructor_budgets_validated_and_frozen_defaults():
    with pytest.raises(ValueError):
        UnderstandingStore(max_known_cameras=0)
    with pytest.raises(ValueError):
        UnderstandingStore(max_load_file_bytes=0)
    store = UnderstandingStore()
    assert store._max_load_file_bytes == DEFAULT_MAX_LOAD_FILE_BYTES
    assert store._max_load_file_bytes == 8 * 1024 * 1024
    assert store._max_known_cameras == DEFAULT_MAX_KNOWN_CAMERAS
    assert store._max_known_cameras == 32


# ---------- 路径安全：真实父子校验 -------------------------------------------

def test_path_escape_rejected_by_real_parent_child(tmp_path):
    root = tmp_path / "store-a"
    root.mkdir()
    with pytest.raises(ValueError):
        _resolve_within(root, "..", "escape.jsonl")
    # startswith 会误放行的前缀同名兄弟目录（store-ab 以 store-a 开头）
    sibling = tmp_path / "store-ab"
    sibling.mkdir()
    with pytest.raises(ValueError):
        _resolve_within(root, "..", "store-ab", "f.jsonl")
    # 落到 root 本身也不算合法文件路径
    with pytest.raises(ValueError):
        _resolve_within(root, "..")
    # root 内部路径正常
    ok = _resolve_within(root, "abc123", "l2.jsonl")
    assert ok.is_relative_to(root.resolve())


def test_store_paths_never_escape_root_for_any_camera(tmp_path):
    root = tmp_path / "ustore"
    store = UnderstandingStore(root)
    for camera in ("../../evil", "front", "a/b", "..", "nul"):
        with pytest.raises(ValueError):
            store.append(camera, "not-a-kind", {})
    # 即便相机名含路径字符，落盘键也是哈希，不产生越权目录
    assert store.append("../../evil", "l2", {"status": "ok"}) is True
    assert list(root.iterdir())[0].name == hashlib.sha256(
        "../../evil".encode()).hexdigest()[:16]


# ---------- 并发 ------------------------------------------------------------

def test_concurrent_append_no_loss_no_dup():
    store = UnderstandingStore(max_per_camera=500)
    barrier = threading.Barrier(2)

    def worker(tag):
        barrier.wait()
        for i in range(50):
            assert store.append("front", "l2", {"tag": tag, "seq": i}) is True

    threads = [threading.Thread(target=worker, args=(t,)) for t in "ab"]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    history = store.history("front", "l2")
    assert len(history) == 100
    keys = [(r["tag"], r["seq"]) for r in history]
    assert len(set(keys)) == 100, "并发 append 不得丢条或重复"
    assert store.snapshot()["appended"] == 100


# ---------- 摘要组装（冻结形状） ---------------------------------------------

def test_summary_empty_keeps_frozen_shape():
    summary = build_summary("front", [], [], [])
    assert set(summary) == {"camera", "summary", "window_state",
                            "branches", "fusion"}
    assert summary["branches"] == []
    assert summary["fusion"] is None
    assert summary["window_state"] is None
    assert "暂无" in summary["summary"]
    store = UnderstandingStore()
    assert store.summary("ghost") == {**summary, "camera": "ghost"}


def test_summary_branch_rows_have_exactly_frozen_fields():
    l3 = [_l3_rec([_branch_entry(), _branch_entry(
        branch="relation_crop", crop_id="c1", text="该人员手持包裹")])]
    l4 = [{"version_id": "abcdef1234567890", "status": "ok",
           "window_id": "w-1",
           "items": [{"kind": "observation", "text": "一人",
                      "certainty": "observed"}], "at": 2.0}]
    l2 = [{"status": "ok", "calibrated": False, "window_state": "producing"}]
    summary = build_summary("front", l2, l3, l4)
    assert summary["window_state"] == "producing"
    assert [row["kind"] for row in summary["branches"]] == \
        ["panorama", "relation_crop"]
    for row in summary["branches"]:
        assert set(row) == {"branch_key", "kind", "status", "text",
                            "sources", "missing"}
    assert summary["branches"][0]["text"] == "一个人站在门口"
    assert summary["branches"][1]["text"] == "该人员手持包裹"
    assert summary["branches"][0]["branch_key"] == \
        "front|run-1|v1|w-1|panorama|"
    assert summary["branches"][0]["sources"][0]["frame_id"] == "f9"
    assert summary["fusion"] == {"version_id": "abcdef1234567890",
                                 "status": "ok",
                                 "items": [{"kind": "observation",
                                            "text": "一人",
                                            "certainty": "observed"}]}
    counts = branch_counts(summary["branches"])
    assert counts == {"pending": 0, "done": 2, "failed": 0, "evicted": 0,
                      "other": 0}
    assert "完成 2" in summary["summary"]
    assert "融合版本 abcdef123456" in summary["summary"]


def test_summary_dedupes_by_branch_key_last_wins():
    old = _branch_entry(text="旧描述")
    new = _branch_entry(text="重试后的新描述")
    l3 = [_l3_rec([old]), _l3_rec([new])]
    summary = build_summary("front", [], l3, [])
    assert len(summary["branches"]) == 1
    assert summary["branches"][0]["text"] == "重试后的新描述"


def test_summary_failure_entry_text_comes_from_reason():
    entry = _branch_entry(status="model_unavailable", text=None)
    summary = build_summary("front", [], [_l3_rec([entry])], [])
    row = summary["branches"][0]
    assert row["status"] == "model_unavailable"
    assert row["text"] == "error_code=E_MODEL"
    assert branch_counts(summary["branches"])["failed"] == 1


def test_summary_evicted_and_pending_categories():
    assert branch_category("ok") == "done"
    assert branch_category("partial") == "done"
    assert branch_category("infer_failed") == "failed"
    assert branch_category("queue_evicted") == "evicted"
    assert branch_category("expired") == "evicted"
    assert branch_category("stale_identity") == "evicted"
    assert branch_category("identity_rejected") == "evicted"
    assert branch_category("stop_cancelled") == "evicted"
    assert branch_category("producing") == "pending"
    assert branch_category("mystery") == "other"
    l3 = [_l3_rec([_branch_entry(status="expired", text=None)]),
          _l3_rec([_branch_entry(key_tail=("w-2",))], window="w-2")]
    counts = branch_counts(build_summary("front", [], l3, [])["branches"])
    assert counts["evicted"] == 1 and counts["done"] == 1


def test_summary_gate_reason_and_no_branches():
    l2 = [{"status": "model_unavailable", "gate_reason": "model_unavailable",
           "calibrated": False}]
    summary = build_summary("front", l2, [], [])
    assert summary["branches"] == []
    assert "关系识别不可用（model_unavailable）" in summary["summary"]
    assert "分支" not in summary["summary"]


def test_store_summary_matches_build_summary():
    store = UnderstandingStore()
    store.append("front", "l2", {"status": "ok", "calibrated": False})
    store.append("front", "l3", _l3_rec([_branch_entry()]))
    store.append("front", "l4", {"version_id": "v1", "status": "ok",
                                 "items": []})
    assert store.summary("front") == build_summary(
        "front", store.history("front", "l2"),
        store.history("front", "l3"), store.history("front", "l4"))


def test_latest_source_fields_prefers_l3_then_l2():
    l3 = [_l3_rec([_branch_entry()])]
    l2 = [{"status": "ok", "model_ref": "l2-model", "calibrated": False}]
    fields = latest_source_fields(l2, l3)
    assert fields == {"model_ref": "l3-local-model", "calibrated": False}
    assert latest_source_fields(l2, [])["model_ref"] == "l2-model"
    assert latest_source_fields([], []) == {"model_ref": "", "calibrated": None}
    # calibrated 取最近一条带字段的 L2 记录；缺失如实 None
    assert latest_source_fields([{"status": "ok"}], [])["calibrated"] is None


def test_kinds_are_frozen_triple():
    assert KINDS == ("l2", "l3", "l4")
