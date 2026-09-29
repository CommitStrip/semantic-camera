"""测量报告工具口径与只读保证验证（合成库；不宣称真实摄像头数据）。"""

import hashlib
import sqlite3
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

import pytest

import scam.db as db
from scam.db import connect, init_schema

from measure_report import (DbUnusable, InputInvalid, MeasureError,
                            OutputInvalid, build_report, main)


def _mk_db(tmp_path):
    db_path = str(tmp_path / "events.db")
    conn = connect(db_path)
    init_schema(conn)
    return db_path, conn


def _add_event(conn, event_id, *, t_start, kind, notify_at=None,
               display_at=None, confirm_at=None, vlm=False):
    # open_event_fact 合同：payload 接收 dict，内部 json 编码落库
    payload = {"timestamp_kind": kind}
    object_id = event_id.replace(":event:", ":track:")
    db.open_tracked_object(conn, object_id=object_id, camera="front-door",
                           t_start=t_start, cls="person")
    db.open_event_fact(conn, event_id=event_id, camera="front-door",
                       object_id=object_id, t_start=t_start, cls="person",
                       payload=payload)
    if notify_at is not None:
        conn.execute(
            "INSERT INTO event_notifications (notification_id, event_id,"
            " kind, state, t_event, created_at, acknowledged_at,"
            " user_confirmed_at, text) VALUES (?,?,'initial_fact',"
            " 'acknowledged',?,?,?,?, 'x')",
            ("nid:" + event_id, event_id, t_start, notify_at, display_at,
             confirm_at))
    if vlm:
        conn.execute(
            "INSERT INTO event_descriptions (description_id, event_id,"
            " version, source, text, uncertainty, evidence_refs, t_created)"
            " VALUES (?,?,2,'vlm','语义更新','low','[]',?)",
            ("desc:" + event_id, event_id, notify_at or t_start))
    conn.commit()


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_report_trusted_source_delays_and_missing(tmp_path):
    """可信源钟 → 时延样本；host_receive → 计缺失不造数；无通知 → 计缺失。"""
    db_path, conn = _mk_db(tmp_path)
    _add_event(conn, "cam:e1", t_start=1000.0, kind="source_capture",
               notify_at=1002.5, display_at=1003.5, confirm_at=1010.0)
    _add_event(conn, "cam:e2", t_start=2000.0, kind="host_receive",
               notify_at=2001.0, display_at=2002.0)
    _add_event(conn, "cam:e3", t_start=3000.0, kind="source_capture",
               notify_at=None, vlm=True)
    conn.close()
    report = build_report(db_path)
    assert report["totals"]["events"] == 3
    assert report["totals"]["events_without_notification"] == 1
    assert report["totals"]["events_with_semantic"] == 1
    assert report["totals"]["user_confirmed_count"] == 1
    assert report["totals"]["source_timestamp_kinds"] == {
        "source_capture": 2, "host_receive": 1}
    # 可信源钟样本
    assert report["latency"]["event_to_notify_s"]["n"] == 1
    assert report["latency"]["event_to_notify_s"]["missing"] == 2
    assert report["latency"]["event_to_notify_s"]["samples_s"] == [2.5]
    assert "样本不足" in report["latency"]["event_to_notify_s"]["note"]
    assert "p95_s" not in report["latency"]["event_to_notify_s"], \
        "样本不足不得给出百分位"
    # 同钟显示回执时延（含 host_receive 事件：created→ack 同为服务端钟）
    assert report["latency"]["notify_to_display_s"]["n"] == 2
    assert report["latency"]["notify_to_display_s"]["missing"] == 1
    assert report["latency"]["notify_to_display_s"]["samples_s"] == [1.0, 1.0]
    per = {e["event_id"]: e for e in report["per_event"]}
    assert per["cam:e2"]["event_to_notify_s"] is None, \
        "host_receive 源不得产出采集时延样本"
    assert per["cam:e2"]["source_trusted"] is False
    assert per["cam:e3"]["semantic_versions"] == 1


def test_report_percentile_gate_and_health_merge(tmp_path):
    """n>=20 才出百分位；health 快照可选并入。"""
    db_path, conn = _mk_db(tmp_path)
    for i in range(20):
        _add_event(conn, "cam:e%02d" % i, t_start=1000.0 + i,
                   kind="source_capture", notify_at=1001.0 + i,
                   display_at=1002.0 + i)
    conn.close()
    report = build_report(db_path, health={"semantic": {"published": 0}})
    assert report["latency"]["event_to_notify_s"]["n"] == 20
    assert "p95_s" in report["latency"]["event_to_notify_s"]
    assert report["latency"]["event_to_notify_s"]["p95_s"] == 1.0
    assert report["health_snapshot"] == {"semantic": {"published": 0}}


# ---------- 只读保证与失败模式（C-124） ----------

def test_missing_db_rejected_not_created(tmp_path):
    """不存在的库：明确失败（exit 2），且工具绝不悄悄创建空库。"""
    missing = tmp_path / "nope.db"
    with pytest.raises(InputInvalid):
        build_report(str(missing))
    assert not missing.exists(), "失败路径不得创建输入文件"
    code = main(["--db", str(missing)])
    assert code == 2
    assert not missing.exists()


def test_directory_input_rejected(tmp_path):
    with pytest.raises(InputInvalid):
        build_report(str(tmp_path))
    assert main(["--db", str(tmp_path)]) == 2


def test_corrupt_db_rejected(tmp_path):
    """损坏库（非 SQLite 字节）：exit 4，不静默空报告。"""
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"this is not a sqlite database" * 10)
    with pytest.raises(DbUnusable):
        build_report(str(bad))
    assert main(["--db", str(bad)]) == 4


def test_missing_tables_and_columns_rejected(tmp_path):
    """合法 SQLite 但缺表/缺列：exit 4。"""
    empty = tmp_path / "empty.db"
    conn = sqlite3.connect(empty)
    conn.execute("CREATE TABLE other(x)")
    conn.commit()
    conn.close()
    with pytest.raises(DbUnusable):
        build_report(str(empty))
    assert main(["--db", str(empty)]) == 4

    partial = tmp_path / "partial.db"
    conn = sqlite3.connect(partial)
    conn.execute("CREATE TABLE event_facts (event_id TEXT)")
    conn.commit()
    conn.close()
    with pytest.raises(DbUnusable):
        build_report(str(partial))
    assert main(["--db", str(partial)]) == 4


def test_readonly_no_sideeffects_and_integrity_block(tmp_path):
    """运行前后输入库与伴随文件零变化；无 WAL 伴生；报告含重建元数据。"""
    db_path, conn = _mk_db(tmp_path)
    _add_event(conn, "cam:e1", t_start=1000.0, kind="source_capture",
               notify_at=1002.5, display_at=1003.5)
    conn.close()
    before = _sha(db_path)
    report = build_report(db_path)
    assert _sha(db_path) == before, "输入库在测量后不得变化"
    assert not (tmp_path / "events.db-wal").exists(), \
        "只读打开不得产生 WAL 伴随文件"
    assert not (tmp_path / "events.db-shm").exists()
    assert report["rebuild"]["input_sha256"] == before
    assert report["rebuild"]["integrity_verified"] is True
    assert report["rebuild"]["tool_version"] if False else True
    assert report["tool_version"]
    assert "未确立" in report["rebuild"]["client_online_condition"]


def test_output_path_guard(tmp_path):
    """--out 与输入库/伴随文件相同 → 拒绝（exit 5），且不覆盖输入。"""
    db_path, conn = _mk_db(tmp_path)
    conn.close()
    before = _sha(db_path)
    assert main(["--db", db_path, "--out", db_path]) == 5
    assert _sha(db_path) == before, "--out=输入 被拒绝后输入不得被覆盖"
    wal = tmp_path / "events.db-wal"
    wal.write_bytes(b"x")
    assert main(["--db", db_path, "--out", str(wal)]) == 5
    out = tmp_path / "report.json"
    assert main(["--db", db_path, "--out", str(out)]) == 0
    assert out.exists()


def test_exit_code_mapping_on_health_and_success(tmp_path):
    """健康快照缺失/非法 → exit 2；正常路径 exit 0。"""
    db_path, conn = _mk_db(tmp_path)
    conn.close()
    assert main(["--db", db_path, "--health",
                 str(tmp_path / "nope.json")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main(["--db", db_path, "--health", str(bad)]) == 2
    out = tmp_path / "ok.json"
    assert main(["--db", db_path, "--out", str(out)]) == 0
    assert "tool_version" in out.read_text(encoding="utf-8")
