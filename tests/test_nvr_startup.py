"""共享运行时的启动恢复测试（由 Win11 发布要求驱动）。"""

import scam.db as db
from scam.nvr import _recover_event_truth


def test_startup_reports_recovered_event_truth(tmp_path, capsys):
    conn = db.connect(str(tmp_path / "startup.db"))
    db.init_schema(conn)
    db.open_tracked_object(
        conn, object_id="obj-1", camera="front", t_start=1.0, cls="person")

    counts = _recover_event_truth(conn, now=100.0, stale_after_s=30.0)

    assert counts["tracked_objects"] == 1
    output = capsys.readouterr().out
    assert "对象 1" in output
    assert "审查段 0" in output
    assert "语义事件 0" in output


def test_startup_stays_quiet_when_no_recovery_is_needed(tmp_path, capsys):
    conn = db.connect(str(tmp_path / "startup.db"))
    db.init_schema(conn)

    counts = _recover_event_truth(conn, now=100.0, stale_after_s=30.0)

    assert sum(counts.values()) == 0
    assert capsys.readouterr().out == ""
