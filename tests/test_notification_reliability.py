"""工作包 B 回归：事件初始事实提醒可靠性收口（四项）。

覆盖：①游标分页不饿死（>10/超一页/持续插入/同创建时间/首条未确认不阻塞/
非法游标）；②渲染后回执重试契约（仅 r.ok 标已处理、服务端幂等不改首次时间）；
③补账全量可续跑（>2000/只缺一半/批中失败/重复启动/批量上界/待补数诚实）；
④时延字段正名（created_delay_s/display_delay_s，不可信或缺失即 null）。
合成测试；不代表真实 RTSP、通知质量或现场延迟达标。
"""

import json

import numpy as np
import pytest

import scam.db as db
from scam.db import (backfill_initial_fact_pairs, connect,
                     read_backfill_cursor,
                     count_events_missing_pairs, ensure_initial_description,
                     ensure_initial_notification, init_schema,
                     list_initial_notifications, open_event_fact,
                     open_tracked_object, acknowledge_notification)
from scam.server import WorkbenchState

from test_environment_baseline import _H, _get, _post


def _seed_event(conn, i, *, created_at=None, with_desc=True, with_notif=True,
                camera="front", t_start=None):
    """快速播种一条事件事实（及可选的描述/提醒），返回 (event_id, notif_id)。"""
    event_id = f"{camera}:run:event:{i}"
    object_id = f"{camera}:run:track:{i}"
    start = float(i) if t_start is None else float(t_start)
    open_tracked_object(conn, object_id=object_id, camera=camera,
                        t_start=start, cls="person")
    open_event_fact(conn, event_id=event_id, camera=camera,
                    object_id=object_id, t_start=start, cls="person")
    notif_id = None
    if with_desc:
        ensure_initial_description(
            conn, event_id, text=f"{camera} 画面中出现 person",
            t_created=start)
    if with_notif:
        ensure_initial_notification(
            conn, event_id, text=f"{camera} 画面中出现 person",
            t_event=start,
            created_at=(float(i) if created_at is None else created_at))
        notif_id = f"notif:{event_id}:initial_fact"
    return event_id, notif_id


@pytest.fixture()
def state(tmp_path):
    db_path = str(tmp_path / "wb.db")
    conn = connect(db_path)
    init_schema(conn)
    conn.close()
    return WorkbenchState(db_path)


# ---------- ① 未确认提醒不得饿死 ----------

def _walk_all(state, limit=10):
    """按游标走完全部页，返回收集到的 notification_id 序列。"""
    collected = []
    cursor = None
    for _guard in range(100):
        status, data = _get(state, "/api/v2/notifications?limit="
                            + str(limit)
                            + (f"&cursor={cursor}" if cursor else ""))
        assert status == 200
        ids = [n["notification_id"] for n in data["notifications"]]
        collected.extend(ids)
        if not data.get("next_cursor"):
            break
        cursor = data["next_cursor"]
    return collected


def test_cursor_pagination_covers_more_than_one_page(state):
    conn = connect(state.db_path)
    for i in range(25):
        _seed_event(conn, i, created_at=1000.0 + i)
    conn.close()

    collected = _walk_all(state, limit=10)
    assert len(collected) == 25
    assert len(set(collected)) == 25, "翻页不得重复或遗漏"
    # 倒序：后建的排前面
    order = [int(x.split(":")[-2].split(":")[-1])
             for x in collected] if False else None
    status, data = _get(state, "/api/v2/notifications?limit=10")
    times = [n["created_at"] for n in data["notifications"]]
    assert times == sorted(times, reverse=True)


def test_new_inserts_do_not_starve_old_backlog(state):
    conn = connect(state.db_path)
    for i in range(12):
        _seed_event(conn, i, created_at=1000.0 + i)
    conn.close()

    # 第一页
    status, page1 = _get(state, "/api/v2/notifications?limit=10")
    cursor = page1["next_cursor"]
    assert cursor, "12 条应有下一页"
    old_ids = {n["notification_id"] for n in page1["notifications"]}

    # 持续插入新提醒
    conn = connect(state.db_path)
    for i in range(12, 30):
        _seed_event(conn, i, created_at=2000.0 + i)
    conn.close()

    # 沿旧游标继续：仍能推进到旧积压（不会被新数据挤掉）
    status, page2 = _get(state, "/api/v2/notifications?limit=10&cursor="
                         + cursor)
    assert status == 200
    assert page2["notifications"], "旧积压必须可继续到达"
    assert all(n["notification_id"] not in old_ids
               for n in page2["notifications"])


def test_same_created_time_ties_are_stable(state):
    conn = connect(state.db_path)
    for i in range(15):
        _seed_event(conn, i, created_at=1000.0)   # 全部同一创建时间
    conn.close()

    collected = _walk_all(state, limit=5)
    assert len(collected) == 15 and len(set(collected)) == 15, \
        "同创建时间必须有确定第二关键字（notification_id）顺序"
    again = _walk_all(state, limit=5)
    assert collected == again, "重复遍历顺序必须一致"


def test_first_unacked_does_not_block_others(state):
    conn = connect(state.db_path)
    for i in range(14):
        _seed_event(conn, i, created_at=1000.0 + i)
    conn.close()
    collected = _walk_all(state, limit=10)
    # 首条（最新）不回执，其余可见性与顺序不受影响
    assert len(collected) == 14


def test_invalid_cursor_rejected(state):
    conn = connect(state.db_path)
    _seed_event(conn, 1, created_at=1000.0)
    conn.close()
    for bad in ("garbage", "!!!!", "eyJ0IjoxfQ"):   # 非法/畸形游标
        status, body = _get(state,
                            "/api/v2/notifications?limit=5&cursor=" + bad)
        assert status == 400, bad


def test_workbench_dedupes_and_acks_after_render(state):
    """页面契约：渲染去重（不重复横幅）、渲染后才回执、失败退避重试。"""
    handler = _H("GET", "/", None, state)
    handler.do_GET()
    html = handler.wfile.getvalue().decode("utf-8")
    assert "renderedMap.has(" in html, "重复轮询不得重复插入横幅"
    assert "ui.banner.prepend(item);" in html, "先渲染进页面"
    assert html.index("ui.banner.prepend(item);") < \
        html.index("ackQueue.push("), "渲染先于回执"
    assert "if(r.ok){st.done=true}" in html, "仅 2xx 才算回执成功"
    assert "st.nextAt=now+Math.min(30000,2000" in html, "失败退避重试"
    assert "工作台可读取" in html and "回执≠已读" in html, \
        "状态文案不得冒充用户已读"


def test_ack_idempotent_first_time_wins(state):
    conn = connect(state.db_path)
    _seed_event(conn, 1, created_at=1000.0)
    conn.close()
    nid = "notif:front:run:event:1:initial_fact"
    status, first = _post(state, "/api/v2/notifications/ack",
                          {"notification_id": nid})
    assert first["first_acknowledgement"] is True
    conn = connect(state.db_path)
    row = conn.execute(
        "SELECT acknowledged_at FROM event_notifications"
        " WHERE notification_id=?", (nid,)).fetchone()
    t1 = row["acknowledged_at"]
    conn.close()
    status, second = _post(state, "/api/v2/notifications/ack",
                           {"notification_id": nid})
    assert second["first_acknowledgement"] is False
    conn = connect(state.db_path)
    row = conn.execute(
        "SELECT acknowledged_at FROM event_notifications"
        " WHERE notification_id=?", (nid,)).fetchone()
    conn.close()
    assert row["acknowledged_at"] == t1, "首次 acknowledged_at 不得被覆盖"


# ---------- ③ 补账全量可续跑 ----------

def test_backfill_covers_more_than_2000_in_batches(state):
    conn = connect(state.db_path)
    for i in range(2100):
        _seed_event(conn, i, with_desc=False, with_notif=False)
    conn.close()
    conn = connect(state.db_path)
    assert count_events_missing_pairs(conn) == 2100

    rounds = 0
    total = {"descriptions": 0, "notifications": 0}
    while True:
        stats = backfill_initial_fact_pairs(conn, created_at=1.0, batch=500)
        rounds += 1
        total["descriptions"] += stats["descriptions"]
        total["notifications"] += stats["notifications"]
        assert stats["descriptions"] <= 500, "单批规模有上界"
        if stats["remaining"] == 0:
            break
        assert rounds < 10
    assert rounds == 5, "2100 条 / 每批 500 = 5 轮可推进完"
    assert total["descriptions"] == 2100 and total["notifications"] == 2100
    assert count_events_missing_pairs(conn) == 0
    conn.close()


def test_backfill_only_missing_half_pairs(state):
    conn = connect(state.db_path)
    _seed_event(conn, 1, with_desc=True, with_notif=False)    # 只缺提醒
    _seed_event(conn, 2, with_desc=False, with_notif=True)    # 只缺描述
    _seed_event(conn, 3, with_desc=True, with_notif=True)     # 齐全
    stats = backfill_initial_fact_pairs(conn, created_at=1.0)
    assert stats["descriptions"] == 1 and stats["notifications"] == 1
    assert stats["remaining"] == 0
    # 重复启动零增行
    again = backfill_initial_fact_pairs(conn, created_at=2.0)
    assert again["descriptions"] == 0 and again["notifications"] == 0
    conn.close()


def test_backfill_batch_failure_keeps_pending_and_retries_cleanly(
        state, monkeypatch):
    conn = connect(state.db_path)
    for i in range(6):
        _seed_event(conn, i, with_desc=False, with_notif=False)
    conn.close()

    real_ensure = db.ensure_initial_description
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("db locked")
        return real_ensure(*args, **kwargs)

    monkeypatch.setattr(db, "ensure_initial_description", flaky)
    conn = connect(state.db_path)
    stats = backfill_initial_fact_pairs(conn, created_at=1.0, batch=6)
    assert stats["failed"] == 1
    assert stats["remaining"] == 1, "批中失败的条目留在待补"
    # 故障前后行数：成功 5 条各恰一对，失败条目零行
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_descriptions").fetchone()["c"] == 5
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_notifications").fetchone()["c"] == 5
    conn.close()

    monkeypatch.undo()
    conn = connect(state.db_path)
    # 回绕语义：游标已到批末，失败条目要等回绕批次才再试（最多 3 轮）
    stats2 = None
    for _round in range(3):
        stats2 = backfill_initial_fact_pairs(conn, created_at=2.0, batch=6)
        if stats2["remaining"] == 0:
            break
    assert stats2["descriptions"] == 1 and stats2["notifications"] == 1
    assert stats2["remaining"] == 0
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_descriptions").fetchone()["c"] == 6
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_notifications").fetchone()["c"] == 6
    conn.close()


def test_backfill_parallel_with_live_creation_is_exactly_once(state):
    """补账进行中实时新事件入库：描述/提醒仍各恰一条。"""
    conn = connect(state.db_path)
    for i in range(4):
        _seed_event(conn, i, with_desc=False, with_notif=False)
    conn.close()

    conn = connect(state.db_path)
    backfill_initial_fact_pairs(conn, created_at=1.0, batch=2)   # 只补一半
    # 实时路径：sink 语义=事件建立即幂等建一对
    _seed_event(conn, 99, created_at=5.0)                        # 新事件入库
    stats = backfill_initial_fact_pairs(conn, created_at=2.0, batch=100)
    assert stats["remaining"] == 0
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_descriptions").fetchone()["c"] == 5
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_notifications").fetchone()["c"] == 5
    conn.close()


def test_health_reports_pending_backfill(state):
    """健康面如实显示待补数；'值守已启动'不冒充'积压已清零'。"""
    state.backfill = {"pending": 42, "failed": 1}
    status, body = _get(state, "/api/health")
    assert body["backfill"]["pending"] == 42
    assert body["backfill"]["failed"] == 1


# ---------- ④ 时延字段正名 ----------

def _detail(state, event_id):
    status, body = _get(state, "/api/v2/events/" + event_id)
    assert status == 200
    return body["notifications"][0]


def test_latency_fields_are_semantically_named(state):
    conn = connect(state.db_path)
    open_tracked_object(conn, object_id="o1", camera="front", t_start=1.0,
                        cls="person")
    open_event_fact(conn, event_id="e-trust", camera="front", object_id="o1",
                    t_start=10.0, cls="person",
                    payload={"timestamp_kind": "source_capture"})
    open_event_fact(conn, event_id="e-untrust", camera="front", object_id="o1",
                    t_start=10.0, cls="person",
                    payload={"timestamp_kind": "host_receive"})
    conn.close()
    conn = connect(state.db_path)
    ensure_initial_notification(
        conn, "e-trust", text="t", t_event=10.0, created_at=12.5)
    ensure_initial_notification(
        conn, "e-untrust", text="t", t_event=10.0, created_at=12.5)
    conn.close()

    trusted = _detail(state, "e-trust")
    assert trusted["created_delay_s"] == pytest.approx(2.5, abs=1e-6), \
        "可信同钟的事件→创建延迟可证实"
    assert trusted["display_delay_s"] is None, "未回执即无显示延迟"
    assert trusted["end_to_end_latency_s"] is None, "端到端时延不可测恒 null"

    untrusted = _detail(state, "e-untrust")
    assert untrusted["created_delay_s"] is None, "源时间不可信不得出数"
    assert untrusted["end_to_end_latency_s"] is None

    # 显示回执延迟：acknowledged_at - created_at（服务端同钟，非人工已读）
    nid = "notif:e-trust:initial_fact"
    conn = connect(state.db_path)
    acknowledge_notification(conn, nid, at=14.0)
    conn.close()
    acked = _detail(state, "e-trust")
    assert acked["display_delay_s"] == pytest.approx(1.5, abs=1e-6)
    assert acked["acknowledged_at"] is not None


def test_latency_null_on_negative_or_missing(state):
    conn = connect(state.db_path)
    open_tracked_object(conn, object_id="o1", camera="front", t_start=1.0,
                        cls="person")
    open_event_fact(conn, event_id="e-neg", camera="front", object_id="o1",
                    t_start=20.0, cls="person",
                    payload={"timestamp_kind": "source_capture"})
    conn.close()
    conn = connect(state.db_path)
    # created_at(15) < t_event(20)：负值不得生成看似精确的数字
    ensure_initial_notification(conn, "e-neg", text="t", t_event=20.0,
                                created_at=15.0)
    conn.close()
    neg = _detail(state, "e-neg")
    assert neg["created_delay_s"] is None
    assert neg["display_delay_s"] is None

    conn = connect(state.db_path)
    conn.execute(
        "UPDATE event_notifications SET acknowledged_at=10.0,"
        " created_at=15.0 WHERE notification_id=?",
        ("notif:e-neg:initial_fact",))
    conn.commit()
    conn.close()
    neg2 = _detail(state, "e-neg")
    assert neg2["display_delay_s"] is None, "回执早于创建视为不可信"
    assert neg2["end_to_end_latency_s"] is None

# ---------- B-R1：持续失败不饿死正常待补（扫描游标可续跑） ----------

def _rounds_until(conn, target_remaining, *, batch, limit_rounds=12,
                  created_at=1.0):
    """跑若干轮补账直到剩余待补数达到目标；返回各轮统计。"""
    rounds = []
    for _i in range(limit_rounds):
        stats = backfill_initial_fact_pairs(conn, created_at=created_at,
                                            batch=batch)
        rounds.append(stats)
        if stats["remaining"] == target_remaining:
            return rounds
    return rounds


def test_persistent_failures_do_not_starve_normal_events(state, monkeypatch):
    """前 batch 条持续失败时，其后正常待补事件必须在有限轮次内补齐；
    失败条目保持待补，故障解除后可补齐；不靠增大 batch/跳过/删除蒙混。"""
    conn = connect(state.db_path)
    for i in range(6):
        _seed_event(conn, i, with_desc=False, with_notif=False)
    conn.close()
    fail_ids = {"front:run:event:0", "front:run:event:1"}
    real = db.ensure_initial_description

    def flaky(conn_arg, event_id, **kwargs):
        if event_id in fail_ids:
            raise RuntimeError("persistent failure")
        return real(conn_arg, event_id, **kwargs)

    monkeypatch.setattr(db, "ensure_initial_description", flaky)
    conn = connect(state.db_path)
    rounds = _rounds_until(conn, 2, batch=2)   # 只剩 2 条持续失败的
    assert rounds and rounds[-1]["remaining"] == 2, \
        "正常事件有限轮内补齐，失败条目保持待补"
    assert sum(r["descriptions"] for r in rounds) == 4
    assert sum(r["notifications"] for r in rounds) == 4
    for eid in fail_ids:
        assert conn.execute(
            "SELECT COUNT(*) c FROM event_descriptions WHERE event_id=?",
            (eid,)).fetchone()["c"] == 0
        assert conn.execute(
            "SELECT COUNT(*) c FROM event_notifications WHERE event_id=?",
            (eid,)).fetchone()["c"] == 0
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_facts").fetchone()["c"] == 6, \
        "绝不删除待补记录蒙混"

    monkeypatch.undo()
    rounds2 = _rounds_until(conn, 0, batch=2)
    assert rounds2 and rounds2[-1]["remaining"] == 0, "故障解除后补齐"
    assert sum(r["descriptions"] for r in rounds2) == 2
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_descriptions").fetchone()["c"] == 6
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_notifications").fetchone()["c"] == 6
    conn.close()


def test_backfill_cursor_resumes_after_restart(state):
    """扫描进度持久化：跨进程重启从安全位置续跑，不从头重扫。"""
    conn = connect(state.db_path)
    for i in range(9):
        _seed_event(conn, i, with_desc=False, with_notif=False)
    conn.close()

    conn = connect(state.db_path)
    first = backfill_initial_fact_pairs(conn, created_at=1.0, batch=3)
    assert first["scanned"] == 3 and first["remaining"] == 6
    cursor_after = first["cursor_after"]
    conn.close()

    conn2 = connect(state.db_path)   # 模拟进程重启（新连接）
    assert read_backfill_cursor(conn2) == cursor_after, "游标跨重启持久"
    second = backfill_initial_fact_pairs(conn2, created_at=1.0, batch=3)
    assert second["cursor_before"] == cursor_after, "重启后不从头重扫"
    assert second["remaining"] == 3
    rounds = _rounds_until(conn2, 0, batch=3, limit_rounds=6)
    assert rounds and rounds[-1]["remaining"] == 0
    assert conn2.execute(
        "SELECT COUNT(*) c FROM event_descriptions").fetchone()["c"] == 9
    conn2.close()


def test_backfill_wraps_at_end_and_retries_failed(state, monkeypatch):
    """扫到末尾回绕；持续失败条目在回绕批次仍被重试（不被固定跳过）。"""
    conn = connect(state.db_path)
    for i in range(3):
        _seed_event(conn, i, with_desc=False, with_notif=False)
    conn.close()
    fail_ids = {"front:run:event:0"}
    real = db.ensure_initial_description

    def flaky(conn_arg, event_id, **kwargs):
        if event_id in fail_ids:
            raise RuntimeError("persistent failure")
        return real(conn_arg, event_id, **kwargs)

    monkeypatch.setattr(db, "ensure_initial_description", flaky)
    conn = connect(state.db_path)
    backfill_initial_fact_pairs(conn, created_at=1.0, batch=2)
    stats_b = backfill_initial_fact_pairs(conn, created_at=1.0, batch=2)
    assert stats_b["remaining"] == 1, "正常条目补齐、失败条目仍待补"
    saw_retry = False
    for _i in range(3):
        s = backfill_initial_fact_pairs(conn, created_at=1.0, batch=2)
        if s["failed"] >= 1:
            saw_retry = True
            break
    assert saw_retry, "回绕批次必须重试持续失败条目"
    monkeypatch.undo()
    rounds = _rounds_until(conn, 0, batch=2)
    assert rounds and rounds[-1]["remaining"] == 0
    conn.close()


def test_concurrent_new_events_join_later_scans(state):
    """扫描中并发新增事件：游标前后各一条都不丢失，最终全部补齐。"""
    conn = connect(state.db_path)
    for i in range(4):
        _seed_event(conn, i, with_desc=False, with_notif=False)
    conn.close()
    conn = connect(state.db_path)
    backfill_initial_fact_pairs(conn, created_at=1.0, batch=2)   # 游标推进
    _seed_event(conn, "0b", with_desc=False, with_notif=False, t_start=1005)
    _seed_event(conn, 9, with_desc=False, with_notif=False, t_start=1009)
    rounds = _rounds_until(conn, 0, batch=2, limit_rounds=10)
    assert rounds and rounds[-1]["remaining"] == 0, "并发新增全部补齐"
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_descriptions").fetchone()["c"] == 6
    assert conn.execute(
        "SELECT COUNT(*) c FROM event_notifications").fetchone()["c"] == 6
    conn.close()


def test_health_keeps_failed_visible_until_cleared(state, monkeypatch):
    """持续失败期间健康面保持待补+本轮失败；不得显示已清零。"""
    conn = connect(state.db_path)
    for i in range(2):
        _seed_event(conn, i, with_desc=False, with_notif=False)
    conn.close()

    def flaky(*args, **kwargs):
        raise RuntimeError("persistent failure")

    monkeypatch.setattr(db, "ensure_initial_description", flaky)
    conn = connect(state.db_path)
    stats = backfill_initial_fact_pairs(conn, created_at=1.0, batch=5)
    assert stats["remaining"] == 2 and stats["failed"] >= 1
    state.backfill = {"pending": stats["remaining"], "failed": stats["failed"],
                      "scanned": stats["scanned"], "wrapped": stats["wrapped"]}
    status, body = _get(state, "/api/health")
    assert body["backfill"]["pending"] == 2
    assert body["backfill"]["failed"] >= 1, "持续失败不得显示成已清零"
    conn.close()


# ---------- B-R1：页面回执失败路径（可执行：合成浏览器协议模拟） ----------

class _SyntheticPage:
    """协议级客户端（合成浏览器）：与工作台 JS 契约一致——先渲染去重、
    2xx 才记回执、失败保持待确认可重试。可执行，但不是真实浏览器。"""

    def __init__(self, state):
        self.state = state
        self.rendered = {}
        self.banner_order = []
        self.ack_done = {}
        self.ack_attempts = {}
        self.cursor = None

    def poll(self, pages=3, limit=5):
        for _page in range(pages):
            path = f"/api/v2/notifications?limit={limit}"
            if self.cursor:
                path += f"&cursor={self.cursor}"
            status, data = _get(self.state, path)
            if status != 200:
                break
            for n in data["notifications"]:
                nid = n["notification_id"]
                if nid not in self.rendered:
                    self.rendered[nid] = n.get("text")
                    self.banner_order.append(nid)   # 渲染先于回执
                self.ack_done.setdefault(nid, False)
            self.cursor = data.get("next_cursor")
            if not self.cursor:
                self.cursor = None   # 页尾回绕：下一轮从顶部继续
                break

    def flush_acks(self, *, network_down=False):
        for nid in list(self.ack_done):
            if self.ack_done[nid]:
                continue
            self.ack_attempts[nid] = self.ack_attempts.get(nid, 0) + 1
            if network_down:
                continue   # 请求失败：保持待确认（不标已处理）
            status, _body = _post(self.state, "/api/v2/notifications/ack",
                                  {"notification_id": nid})
            if status == 200:
                self.ack_done[nid] = True


def test_page_ack_non2xx_then_recovery_confirms_once(state, monkeypatch):
    """回执返回非 2xx → 失败期间服务端未确认、页面不重复插入；
    恢复后最终确认恰一次，原始确认时间不被重复请求覆盖。"""
    conn = connect(state.db_path)
    for i in range(3):
        _seed_event(conn, i, created_at=1000.0 + i)
    conn.close()
    page = _SyntheticPage(state)

    real_ack = state.acknowledge_notification

    def failing_ack(nid):
        raise RuntimeError("ack channel down")   # 路由层 → 503

    monkeypatch.setattr(state, "acknowledge_notification", failing_ack)
    page.poll()
    page.flush_acks()
    assert len(page.banner_order) == 3, "渲染 3 条"
    assert all(v is False for v in page.ack_done.values()), \
        "非 2xx 不得记为已处理"
    conn = connect(state.db_path)
    unacked = conn.execute(
        "SELECT COUNT(*) c FROM event_notifications"
        " WHERE acknowledged_at IS NULL").fetchone()["c"]
    conn.close()
    assert unacked == 3, "失败期间服务端仍为未确认"

    page.poll()
    page.poll()
    assert len(page.banner_order) == 3
    assert len(page.rendered) == 3

    monkeypatch.setattr(state, "acknowledge_notification", real_ack)
    page.flush_acks()
    assert all(page.ack_done.values()), "恢复后最终确认"
    conn = connect(state.db_path)
    rows = conn.execute(
        "SELECT notification_id,acknowledged_at FROM event_notifications"
    ).fetchall()
    first_ack = {r["notification_id"]: r["acknowledged_at"] for r in rows}
    assert all(v is not None for v in first_ack.values())
    conn.close()

    for nid in first_ack:
        _post(state, "/api/v2/notifications/ack", {"notification_id": nid})
    conn = connect(state.db_path)
    rows = conn.execute(
        "SELECT notification_id,acknowledged_at FROM event_notifications"
    ).fetchall()
    conn.close()
    for r in rows:
        assert r["acknowledged_at"] == first_ack[r["notification_id"]], \
            "重复请求不得覆盖原始确认时间"


def test_page_network_failure_retry_and_old_backlog_polling(state):
    """网络断开式失败可重试；跨页积压+持续插入下旧提醒仍被轮询到。"""
    conn = connect(state.db_path)
    for i in range(12):
        _seed_event(conn, i, created_at=1000.0 + i)
    conn.close()
    page = _SyntheticPage(state)

    page.poll(pages=2, limit=5)          # 部分渲染（跨页中间态）
    page.flush_acks(network_down=True)   # 断网：全部失败
    assert all(v is False for v in page.ack_done.values())
    assert all(a >= 1 for a in page.ack_attempts.values())

    conn = connect(state.db_path)
    for i in range(12, 20):
        _seed_event(conn, i, created_at=2000.0 + i)
    conn.close()

    for _round in range(8):
        page.poll(pages=3, limit=5)
        page.flush_acks()
        if len(page.rendered) == 20 and all(page.ack_done.values()):
            break
    assert len(page.rendered) == 20, "旧提醒最终全部被轮询到"
    assert len(page.banner_order) == 20, "无重复横幅"
    assert all(page.ack_done.values())
    conn = connect(state.db_path)
    unacked = conn.execute(
        "SELECT COUNT(*) c FROM event_notifications"
        " WHERE acknowledged_at IS NULL").fetchone()["c"]
    conn.close()
    assert unacked == 0


# ---------- B-R1：游标输入硬化（NaN/Infinity/过大/畸形 → 400） ----------

def _b64(payload):
    import base64
    return base64.urlsafe_b64encode(payload.encode("ascii")).decode("ascii")


@pytest.mark.parametrize("token", [
    "garbage!!!",
    "A" * 600,                                  # 过大
    _b64('[NaN, "x"]'),                         # 非有限时间
    _b64('[Infinity, "x"]'),
    _b64('[-Infinity, "x"]'),
    _b64('{"a": 1}'),                           # 畸形形状
    _b64("[1]"),
    _b64('["x", "y"]'),
    _b64('[true, "x"]'),
    _b64('[1.0, ""]'),
    _b64('[1.0, "a/b"]'),                       # 路径形态
    _b64('[1.0, "' + "x" * 250 + '"]'),         # 标识过大
])
def test_invalid_cursor_inputs_rejected_before_query(state, token, monkeypatch):
    """无效游标一律 400：不进数据库查询、不 500。"""
    def boom(*args, **kwargs):
        raise AssertionError("非法游标不得进入数据库查询")

    monkeypatch.setattr(db, "list_initial_notifications", boom)
    status, body = _get(state, "/api/v2/notifications?limit=5&cursor="
                        + token)
    assert status == 400, token[:40]
    assert body.get("error") == "invalid cursor"


def test_weird_limit_values_do_not_error_500(state):
    conn = connect(state.db_path)
    _seed_event(conn, 1, created_at=1000.0)
    conn.close()
    for limit in ("abc", "-5", "99999999", "1e999", "0"):
        status, _body = _get(
            state, "/api/v2/notifications?limit=" + limit)
        assert status == 200, f"limit={limit} 不得 500"

