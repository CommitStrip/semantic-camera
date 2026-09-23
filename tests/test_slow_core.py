"""S1 慢系统持久化核心测试（LC-046 冻结合同测试矩阵）。

覆盖：命中复用零新档、新异建档、幂等水位、跨重启模式复用、失败有界重试
终态、快路径真值逐字节不变、provider 缺席零调用、provider 命名回写、
同段唯一慢结果、签名聚合正确性。
"""

import json
import os
import time

import pytest

import scam.db as db
from scam.slow_core import MODALITY_DAY, SlowCore


def _conn(tmp_path):
    conn = db.connect(str(tmp_path / "slow.db"))
    db.init_schema(conn)
    return conn


def _seed_segment(conn, *, rid="rev-1", camera="front", t0=1000.0,
                  t1=1120.0, cls="person", zone="z1"):
    """闭合审查段 + 段内一个对象与一条语义事件（三层真值）。"""
    db.open_review_segment(conn, review_id=rid, camera=camera, t_start=t0)
    db.close_review_segment(conn, rid, t_end=t1, reason="quiet")
    db.open_tracked_object(
        conn, object_id=f"{rid}:obj", camera=camera,
        t_start=t0 + 10, cls=cls, zones=[zone])
    db.close_tracked_object(conn, f"{rid}:obj", t_end=t1 - 10, reason="gone")
    db.open_semantic_event(
        conn, semantic_event_id=f"{rid}:sem", camera=camera, review_id=rid,
        object_id=f"{rid}:obj", t_start=t0 + 20, template="enter-dwell",
        zone_id=zone, cls=cls)
    db.close_semantic_event(conn, f"{rid}:sem", t_end=t1 - 5, reason="left")
    conn.commit()


_TRUTH_TABLES = (("tracked_objects", "object_id"),
                 ("review_segments", "review_id"),
                 ("semantic_events", "semantic_event_id"))
# SC-B 允许慢系统补充的 semantic_events 空文本列（其余字段/表逐字节不变）
_ENRICHABLE = ("short_name", "detail")


def _snapshot_truth(conn):
    """快路径三层真值快照（逐字段值，供基线感知比较）。"""
    snapshot = {}
    for table, order in _TRUTH_TABLES:
        rows = conn.execute(
            f"SELECT * FROM {table} ORDER BY {order}").fetchall()
        snapshot[table] = {row[order]: dict(row) for row in rows}
    return snapshot


def _assert_truth_preserved(before, after):
    """基线感知比较：允许字段'原空→被补充'；原有文本与其余字段逐字节不变。"""
    for table, order in _TRUTH_TABLES:
        assert set(before[table]) == set(after[table]), table
        for key, row_before in before[table].items():
            row_after = after[table][key]
            for column, value_before in row_before.items():
                value_after = row_after[column]
                if table == "semantic_events" and                         column in _ENRICHABLE and not value_before:
                    continue      # 原为空：允许被慢系统空文本补充
                assert value_after == value_before,                     f"{table}.{key}.{column}: {value_before!r} -> "                     f"{value_after!r}"


class CountingProvider:
    def __init__(self, reply):
        self.reply = reply
        self.calls = 0

    def understand(self, prompt, frames, context=None):
        self.calls += 1
        return self.reply


# ---------- 1. 新异建档 → 2. 命中复用（零新档、计数递增） ----------

def test_first_record_then_hit_reuses_pattern(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-a")
    _seed_segment(conn, rid="rev-b")          # 同构活动：同签名
    core = SlowCore(conn, camera="front")

    # 同一批内顺序处理：rev-a 建档，rev-b 即刻命中该 draft（库内即时复用）
    first = core.process_pending()
    assert first["recorded"] == 1 and first["matched"] == 1
    assert core.process_pending()["processed"] == 0   # 第三轮无待办

    rows = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
    assert rows == 1, "同签名第二段必须复用模式，不得新建"
    count = conn.execute("SELECT count FROM patterns").fetchone()[0]
    assert count >= 1, "命中计数递增"
    conn.close()


# ---------- 3. 幂等水位：同段只产生一份慢结果 ----------

def test_idempotent_watermark_single_result_per_review(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-1")
    core = SlowCore(conn, camera="front")

    core.process_pending()
    core.process_pending()                    # 第二轮：无待办

    seg_rows = conn.execute(
        "SELECT COUNT(*) FROM segments").fetchone()[0]
    assert seg_rows == 1, "segments 档案即水位，同段只一份慢结果"
    assert core.process_pending()["processed"] == 0
    assert core.waterlevel()["pending"] == 0
    conn.close()


# ---------- 4. 跨重启模式复用（新实例从 patterns 表加载） ----------

def test_pattern_survives_restart(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-1")
    SlowCore(conn, camera="front").process_pending()

    fresh = SlowCore(conn, camera="front")    # 新实例=跨进程等价
    assert fresh.load_library() >= 1
    _seed_segment(conn, rid="rev-2")
    stats = fresh.process_pending()
    assert stats["matched"] == 1, "重启后同签名段仍命中既有模式"
    total = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
    assert total == 1
    conn.close()


# ---------- 5. 失败有界重试 → 终态 failed → 不再重扫 ----------

def test_bounded_retry_then_failed_terminal(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-x")
    core = SlowCore(conn, camera="front", max_retries=3)

    def broken(self, review, **kwargs):
        raise RuntimeError("注入失败")

    monkeypatch.setattr(SlowCore, "process_one", broken)
    for _ in range(2):                        # 两次批处理 → 重试 2 次
        stats = core.process_pending()
    assert stats["retried"] >= 1
    # LZ-065 新契约：重试期间允许恰一行认领占位（claiming=CAS 锁），
    # 但绝不允许出现终态结果档
    rows = conn.execute(
        "SELECT json_extract(payload,'$.status') FROM segments").fetchall()
    assert [r[0] for r in rows] == ["claiming"], rows

    monkeypatch.undo()
    stats = core.process_pending()            # 第 3 次重试（未超限）成功路径
    # 此轮 process_one 已恢复但重试计数=2 < 3：正常处理并落档案
    assert stats["processed"] == 1
    conn.close()


def test_retry_exhaustion_finalizes_failed(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-y")
    core = SlowCore(conn, camera="front", max_retries=2)

    def broken(self, review, **kwargs):
        raise RuntimeError("持续失败")

    monkeypatch.setattr(SlowCore, "process_one", broken)
    for _ in range(3):
        core.process_pending()

    payload = conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-y'").fetchone()
    assert json.loads(payload[0])["status"] == "claiming",         "SC-B：尝试用尽但认领新鲜时必须保持 claiming（活跃最后尝试保护）"
    # 认领过陈旧阈值后才允许终态化
    conn.execute(
        "UPDATE segments SET payload=json_set(payload,'$.t_claim',?)"
        " WHERE segment_id='rev-y'",
        (int((time.time() - 1200) * 1e6),))
    conn.commit()
    stats = core.process_pending()
    payload = conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-y'").fetchone()
    assert json.loads(payload[0])["status"] == "failed",         "陈旧且耗尽后必须落 failed 终态档"
    assert stats["failed"] == 1
    assert core.waterlevel()["pending"] == 0, "终态段不再重扫"
    assert core.waterlevel()["failed_final"] == 1
    conn.close()


# ---------- 6. 快路径真值逐字节不变 ----------

def test_fast_path_truth_is_read_only(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-ro")
    before = _snapshot_truth(conn)

    SlowCore(conn, camera="front").process_pending()

    _assert_truth_preserved(before, _snapshot_truth(conn))


# ---------- 7. provider 缺席：新异段 pending_naming、零调用 ----------

def test_missing_provider_degrades_to_pending_naming(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-np")
    core = SlowCore(conn, camera="front")

    stats = core.process_pending(provider=None)

    assert stats["vlm_calls"] == 0
    payload = json.loads(conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-np'"
    ).fetchone()[0])
    assert payload["naming"] == "pending_naming"
    conn.close()


# ---------- 8. provider 命名回写（一致性计数、不越级晋升） ----------

def test_provider_names_new_pattern(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-name")
    core = SlowCore(conn, camera="front")
    provider = CountingProvider("人员在大门口短暂停留")

    stats = core.process_pending(provider=provider)

    assert stats["vlm_calls"] == 1
    name, state = conn.execute(
        "SELECT name,state FROM patterns").fetchone()
    assert name == "人员在大门口短暂停留"
    assert state == "draft", "单次一致命名只计数，不越级 model-verified"
    detail = conn.execute(
        "SELECT detail FROM segments WHERE segment_id='rev-name'"
    ).fetchone()[0]
    assert detail == "人员在大门口短暂停留"
    conn.close()


# ---------- 9. 签名聚合正确性（来自三层真值的确定性） ----------

def test_signature_aggregation_from_truth(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-sig", t0=1780000000.0, t1=1780000120.0)
    core = SlowCore(conn, camera="front")
    review = {"review_id": "rev-sig", "camera": "front",
              "t_start": 1780000000.0, "t_end": 1780000120.0}

    sig = core.signature_for(review)

    assert sig["cls"] == ["person"]
    assert sig["zones"] == ["z1"]
    assert sig["count"] == "1"
    assert sig["dur"] == "长"                    # 120s 整落在"长"桶边界
    assert sig["dwell"] == "无"
    assert sig["modality"] in ("DAY-COLOR", "NIGHT-BW")
    assert sig["tod"] in ("晨", "昼", "暮", "夜")
    conn.close()


# ---------- 水位/统计可观测 ----------

def test_waterlevel_reports_pending_and_patterns(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-w")
    core = SlowCore(conn, camera="front")

    assert core.waterlevel()["pending"] == 1
    core.process_pending()
    level = core.waterlevel()
    assert level["pending"] == 0 and level["patterns"] == 1
    conn.close()


# ---------- 多相机 pattern_id 命名空间（主键互撞事故回归锁） ----------

def test_multi_camera_pattern_ids_never_collide(tmp_path):
    """不同相机各自的 pat-1 落库后必须互不覆盖（曾因裸 pat-N 主键互撞，
    ON CONFLICT 把 front 行 payload 覆盖成 back 的——数据污染）。"""
    conn = _conn(tmp_path)
    for camera, rid in (("front", "rev-f"), ("back", "rev-b")):
        _seed_segment(conn, rid=rid, camera=camera)

    front = SlowCore(conn, camera="front")
    back = SlowCore(conn, camera="back")
    front.process_pending()
    back.process_pending()

    rows = conn.execute(
        "SELECT pattern_id, camera FROM patterns ORDER BY pattern_id"
    ).fetchall()
    assert len(rows) == 2, "两相机各一档，绝不允许覆盖成一档"
    cameras = {r["camera"] for r in rows}
    assert cameras == {"front", "back"}
    ids = [r["pattern_id"] for r in rows]
    assert ids[0] != ids[1], "持久化主键必须带相机命名空间"

    # 各自加载后仍能命中自己的档
    for core, camera in ((front, "front"), (back, "back")):
        _seed_segment(conn, rid=f"rev-{camera}-2", camera=camera)
    fresh = SlowCore(conn, camera="front")
    fresh.load_library()
    assert len(fresh.library.patterns) == 1,         "front 只看到自己的档，不被 back 污染"
    conn.close()


# ---------- LZ-065 P0-1：失败段内存库污染不落库、重试不膨胀 ----------

def test_failed_write_does_not_inflate_hit_count(tmp_path, monkeypatch):
    """落档失败（磁盘满）→ 内存库丢弃重载 → 重试后 hit 计数恰为一次。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-a")
    core = SlowCore(conn, camera="front")
    core.process_pending()
    pid = next(iter(core.library.patterns))
    assert core.library.patterns[pid]["count"] == 0

    _seed_segment(conn, rid="rev-b")
    calls = {"n": 0}
    orig = SlowCore._persist_terminal

    def flaky(self, review, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("disk full simulation")
        return orig(self, review, **kw)

    monkeypatch.setattr(SlowCore, "_persist_terminal", flaky)
    core.process_pending()          # rev-b：命中→hit+1（内存）→落档失败
    monkeypatch.undo()

    core.process_pending()          # 重试成功
    assert core.library.patterns[pid]["count"] == 1,         "同一逻辑事件的 hit 计数必须恰好一次（失败重试不得膨胀）"
    rows = conn.execute(
        "SELECT COUNT(*) FROM segments").fetchone()[0]
    assert rows == 2
    conn.close()


# ---------- LZ-065 P0-3：认领 CAS——双实例互斥/活跃不误伤/陈旧可接管 ----------

def test_claim_cas_single_winner_between_instances(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-cas")
    a = SlowCore(conn, camera="front")
    b = SlowCore(conn, camera="front")
    assert a.instance_id != b.instance_id

    claimed_a = a.pending_reviews()
    claimed_b = b.pending_reviews()
    ids_a = [r["review_id"] for r in claimed_a]
    ids_b = [r["review_id"] for r in claimed_b]
    assert "rev-cas" in ids_a and "rev-cas" not in ids_b,         "同一闭合段只能被一个实例认领（CAS 互斥）"
    conn.close()


def test_active_claim_not_stolen_before_stale_threshold(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-live")
    owner = SlowCore(conn, camera="front")
    assert owner.pending_reviews()          # owner 认领（claiming，新鲜）

    other = SlowCore(conn, camera="front")
    assert other.pending_reviews() == [],         "活跃认领（未过陈旧阈值）不得被另一实例接管或终态化"
    conn.close()


def test_stale_claim_can_be_taken_over(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-stale")
    owner = SlowCore(conn, camera="front")
    owner.pending_reviews()
    # 人工把认领时间拨回 20 分钟前（模拟 worker 崩溃残留）；t_claim 为微秒整数
    conn.execute(
        "UPDATE segments SET payload=json_set(payload,"
        " '$.t_claim', ?) WHERE segment_id='rev-stale'",
        (int((time.time() - 1200) * 1e6),))
    conn.commit()

    other = SlowCore(conn, camera="front")
    assert other.pending_reviews() == [],         "默认 recover_stale=False：不得接管异实例陈旧认领"
    claimed = other.pending_reviews(recover_stale=True)
    assert [r["review_id"] for r in claimed] == ["rev-stale"],         "显式 recover_stale=True 时，过陈旧阈值的崩溃认领必须可被接管续跑"
    conn.close()


# ---------- LZ-065 P1-4：金标单行写 + worker 代数重载不覆盖 ----------

def test_golden_label_survives_worker_generation_reload(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-g1")
    worker_core = SlowCore(conn, camera="front")
    worker_core.process_pending()
    pid = next(iter(worker_core.library.patterns))
    gen_before = SlowCore.library_generation(conn)

    # HTTP 线程金标改名（独立实例，单行写+代数递增）
    http_core = SlowCore(conn, camera="front")
    http_core.confirm_pattern(pid, name="门口送快递")
    assert SlowCore.library_generation(conn) == gen_before + 1

    # worker 内存库仍是旧名——但轮首发现代数变化即失效重载
    assert worker_core.library.patterns[pid].get("name") != "门口送快递"
    worker_core._library = None               # 模拟 worker 轮首重载
    assert worker_core.library.patterns[pid]["name"] == "门口送快递",         "重载必须吸收金标；worker 继续累积不再覆盖管理员改名"
    conn.close()


# ============ SC-A-R1 P0-1：单事务原子提交 ============

from scam.slow_core import (SlowPersistenceBusy,  # noqa: E402
                            SlowPersistenceConflict)


def test_segment_and_pattern_commit_atomically(tmp_path):
    """成功慢处理：segment 终态与 pattern 同时可见（独立连接复核一致性）。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-atom")
    core = SlowCore(conn, camera="front")
    stats = core.process_pending()
    assert stats["processed"] == 1

    seg = conn.execute(
        "SELECT json_extract(payload,'$.status') AS st,"
        " json_extract(payload,'$.pattern_id') AS pid"
        " FROM segments WHERE segment_id='rev-atom'").fetchone()
    assert seg["st"] in ("recorded", "matched")
    assert seg["pid"], "segment 终态必须携带 pattern_id（同事务写入）"

    fresh = db.connect(str(tmp_path / "slow.db"))
    pat = fresh.execute(
        "SELECT COUNT(*) FROM patterns").fetchone()[0]
    assert pat == 1, "独立连接必须同时看到 pattern（无段/模式分裂窗口）"
    fresh.close()
    conn.close()


def test_pattern_save_failure_keeps_claim_retryable(tmp_path, monkeypatch):
    """pattern 保存阶段失败：claiming 保持、无半写、retry 恰 +1、下轮成功。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-f0")
    core = SlowCore(conn, camera="front")
    core.process_pending()                       # rev-f0 建档（count 源）
    pid = next(iter(core.library.patterns))
    base_count = core.library.patterns[pid]["count"]
    _seed_segment(conn, rid="rev-f1", t0=5000.0, t1=5120.0)

    calls = {"n": 0}
    orig = SlowCore._save_library_sql

    def flaky(self):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("pattern save failure (simulated)")
        return orig(self)

    monkeypatch.setattr(SlowCore, "_save_library_sql", flaky)
    stats = core.process_pending()               # rev-f1：保存失败
    monkeypatch.undo()

    assert stats["retried"] == 1 and stats["processed"] == 0
    seg = conn.execute(
        "SELECT json_extract(payload,'$.status') AS st FROM segments"
        " WHERE segment_id='rev-f1'").fetchone()
    assert seg["st"] == "claiming", "失败后 segment 必须保持 claiming"
    retry = conn.execute(
        "SELECT value FROM meta WHERE key='slow:retry:rev-f1'").fetchone()
    assert int(retry[0]) == 1, "retry 恰好 +1（独立小事务）"
    stats2 = core.process_pending()              # 下一轮成功
    assert stats2["processed"] == 1
    assert core.library.patterns[pid]["count"] == base_count + 1, \
        "失败重试后 hit 计数恰 +1"
    conn.close()


def test_embedding_failure_rolls_back_pattern_and_segment(tmp_path):
    """pattern 已写后 embedding 写入失败（触发器）→ 整事务回滚、可重试。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-emb")
    conn.execute(
        "CREATE TRIGGER block_emb BEFORE INSERT ON pattern_embeddings"
        " BEGIN SELECT RAISE(ABORT, 'embedding write blocked'); END")
    conn.commit()

    core = SlowCore(conn, camera="front")
    emb = [0.1, 0.2, 0.3, 0.4]
    stats = core.process_pending(
        emb_fn=lambda review: (emb, "DAY-COLOR"))

    assert stats["processed"] == 0 and stats["retried"] == 1
    seg = conn.execute(
        "SELECT json_extract(payload,'$.status') AS st FROM segments"
        " WHERE segment_id='rev-emb'").fetchone()
    assert seg["st"] == "claiming", "embedding 失败必须整事务回滚（段不终态）"
    pat = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
    assert pat == 0, "pattern 不得半写（与 embedding/segment 同事务）"
    emb_rows = conn.execute(
        "SELECT COUNT(*) FROM pattern_embeddings").fetchone()[0]
    assert emb_rows == 0

    conn.execute("DROP TRIGGER block_emb")
    conn.commit()
    stats2 = core.process_pending(emb_fn=lambda review: (emb, "DAY-COLOR"))
    assert stats2["processed"] == 1, "故障移除后下一轮可重试成功"
    conn.close()


def test_terminal_segment_update_requires_owned_claim(tmp_path):
    """持久化前认领被他人接管：终态 CAS rowcount=0 → 全回滚、不覆盖。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-cas2")
    core = SlowCore(conn, camera="front")
    claimed = core.pending_reviews()
    assert [r["review_id"] for r in claimed] == ["rev-cas2"]

    other = db.connect(str(tmp_path / "slow.db"))
    other.execute(
        "UPDATE segments SET payload=json_set(payload,"
        " '$.owner', 'intruder', '$.t_claim', ?) WHERE segment_id='rev-cas2'",
        (int(time.time() * 1e6),))
    other.commit()
    row = other.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-cas2'").fetchone()
    other.close()

    with pytest.raises(SlowPersistenceConflict):
        core.process_one(claimed[0])

    after = conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-cas2'").fetchone()
    assert after[0] == row[0], "竞输者不得覆盖他人认领（payload 逐字节不变）"
    pat = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
    assert pat == 0, "CAS rowcount=0 时 patterns 不得提交"
    conn.close()


def test_existing_caller_transaction_is_not_committed(tmp_path):
    """调用方未提交事务：内部持久化 fail-closed，绝不被静默提交。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-busy")
    core = SlowCore(conn, camera="front")
    claimed = core.pending_reviews()

    conn.execute("INSERT INTO meta (key,value) VALUES ('caller:row','1')")
    assert conn.in_transaction, "调用方已有未提交事务"

    with pytest.raises(SlowPersistenceBusy):
        core.process_one(claimed[0])

    assert conn.in_transaction, "外部事务仍由调用方控制"
    other = db.connect(str(tmp_path / "slow.db"))
    seen = other.execute(
        "SELECT COUNT(*) FROM meta WHERE key='caller:row'").fetchone()[0]
    other.close()
    assert seen == 0, "调用方写入不得被内部逻辑提交（其他连接不可见）"
    conn.rollback()
    conn.close()


# ============ SC-A-R1 P0-2：陈旧接管快照 CAS ============

def _age_claim(conn, rid, owner=None, t_claim_us=None, seconds_old=1200):
    if t_claim_us is None:
        t_claim_us = int((time.time() - seconds_old) * 1e6)
    conn.execute(
        "UPDATE segments SET payload=json_set("
        "payload, '$.t_claim', ?"
        + (", '$.owner', ?" if owner else "") +
        ") WHERE segment_id=?", (
            (t_claim_us, owner, rid) if owner
            else (t_claim_us, rid)))
    conn.commit()
    row = conn.execute(
        "SELECT payload FROM segments WHERE segment_id=?", (rid,)).fetchone()
    return row[0]


def test_stale_takeover_uses_owner_and_t_claim_snapshot_cas(tmp_path):
    """B、C 持同一旧快照：B 先接管成功；C 的旧快照 CAS 必须 rowcount=0。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-snap")
    a = SlowCore(conn, camera="front")
    a.pending_reviews()
    old_payload = _age_claim(conn, "rev-snap")     # A 的陈旧认领（快照）
    old = json.loads(old_payload)

    conn_b = db.connect(str(tmp_path / "slow.db"))
    conn_c = db.connect(str(tmp_path / "slow.db"))
    b = SlowCore(conn_b, camera="front")
    c = SlowCore(conn_c, camera="front")

    claimed_b = b.pending_reviews(recover_stale=True)
    assert [r["review_id"] for r in claimed_b] == ["rev-snap"], \
        "B 持旧快照先接管必须成功（显式 recover_stale=True）"

    assert c.pending_reviews(recover_stale=True) == [], \
        "B 接管后的新鲜认领不得被 C 抢走（不得刷新快照放行）"

    cur = conn_c.execute(
        "UPDATE segments SET payload=? WHERE segment_id=?"
        " AND json_extract(payload,'$.status')='claiming'"
        " AND json_extract(payload,'$.owner')=?"
        " AND json_extract(payload,'$.t_claim')=?",
        ('{"status":"claiming","owner":"c","t_claim":1}', "rev-snap",
         old["owner"], old["t_claim"]))
    conn_c.commit()
    assert cur.rowcount == 0, "持旧快照的第二接管者必须竞输（CAS 绑定快照）"
    row = conn_c.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-snap'"
    ).fetchone()
    assert json.loads(row[0])["owner"] == b.instance_id, \
        "不得覆盖 B 的新认领"
    conn_b.close()
    conn_c.close()
    conn.close()


def test_stale_takeover_cannot_overwrite_refreshed_claim(tmp_path):
    """计划后原 owner 刷新 t_claim（心跳）：旧计划接管者不得接管。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-refresh")
    a = SlowCore(conn, camera="front")
    a.pending_reviews()
    _age_claim(conn, "rev-refresh")                 # 先陈旧
    _age_claim(conn, "rev-refresh", seconds_old=1)  # 原 owner 刷新为新鲜

    before = conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-refresh'"
    ).fetchone()[0]
    c = SlowCore(conn, camera="front")
    assert c.pending_reviews() == [], "刷新后的活跃认领不得被接管"
    after = conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-refresh'"
    ).fetchone()[0]
    assert after == before, "claim 行必须逐字段不变"
    conn.close()


def test_stale_takeover_cannot_overwrite_new_owner(tmp_path):
    """owner 已改变：旧计划快照（旧 owner）CAS 必须 rowcount=0。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-owner")
    a = SlowCore(conn, camera="front")
    a.pending_reviews()
    old_payload = _age_claim(conn, "rev-owner", owner="old-owner")
    old = json.loads(old_payload)

    _age_claim(conn, "rev-owner", owner="new-owner")
    new_payload = conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-owner'"
    ).fetchone()[0]

    cur = conn.execute(
        "UPDATE segments SET payload=? WHERE segment_id=?"
        " AND json_extract(payload,'$.status')='claiming'"
        " AND json_extract(payload,'$.owner')=?"
        " AND json_extract(payload,'$.t_claim')=?",
        ('{"status":"claiming","owner":"stale-planner","t_claim":1}',
         "rev-owner", old["owner"], old["t_claim"]))
    conn.commit()
    assert cur.rowcount == 0, "旧 owner 快照不得覆盖新 owner"
    after = conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-owner'"
    ).fetchone()[0]
    assert after == new_payload
    conn.close()


# ============ SC-A-R2 P0-A：外层事务必须在认领前 fail-closed ============

def test_process_pending_rejects_preexisting_caller_transaction_before_claim(
        tmp_path):
    """外层事务早于 process_pending：认领/昂贵调用/统计之前即拒绝。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-pre")
    core = SlowCore(conn, camera="front")

    conn.execute("INSERT INTO meta (key,value) VALUES ('caller:pre','1')")
    assert conn.in_transaction

    called = {"n": 0}

    def counting_emb(review):
        called["n"] += 1
        return None, None

    with pytest.raises(SlowPersistenceBusy):
        core.process_pending(emb_fn=counting_emb)

    assert conn.in_transaction, "调用后外层事务仍存在"
    assert called["n"] == 0, "emb_fn 调用次数必须为 0"
    other = db.connect(str(tmp_path / "slow.db"))
    seen = other.execute(
        "SELECT COUNT(*) FROM meta WHERE key='caller:pre'").fetchone()[0]
    claims = other.execute(
        "SELECT COUNT(*) FROM segments WHERE segment_id='rev-pre'"
    ).fetchone()[0]
    pats = other.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
    other.close()
    assert seen == 0, "第二连接看不到调用方未提交行"
    assert claims == 0, "不得产生 segment claim"
    assert pats == 0
    retry = conn.execute(
        "SELECT COUNT(*) FROM meta WHERE key='slow:retry:rev-pre'"
    ).fetchone()[0]
    assert retry == 0, "retry 不得变化"

    conn.rollback()
    gone = conn.execute(
        "SELECT COUNT(*) FROM meta WHERE key='caller:pre'").fetchone()[0]
    assert gone == 0, "调用方 rollback 后无关行消失"
    conn.close()


def test_pending_reviews_rejects_preexisting_caller_transaction(tmp_path):
    """pending_reviews 单调用入口：认领写入前拒绝，不产生 claim。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-pre2")
    core = SlowCore(conn, camera="front")

    conn.execute("INSERT INTO meta (key,value) VALUES ('caller:pre2','1')")
    assert conn.in_transaction

    with pytest.raises(SlowPersistenceBusy):
        core.pending_reviews()

    assert conn.in_transaction
    other = db.connect(str(tmp_path / "slow.db"))
    seen = other.execute(
        "SELECT COUNT(*) FROM meta WHERE key='caller:pre2'").fetchone()[0]
    claims = other.execute(
        "SELECT COUNT(*) FROM segments WHERE segment_id='rev-pre2'"
    ).fetchone()[0]
    other.close()
    assert seen == 0, "外层写入不得被 commit"
    assert claims == 0, "不得产生 segment claim"
    conn.rollback()
    conn.close()


def test_save_library_does_not_commit_caller_transaction(tmp_path):
    """save_library 兼容入口：外层事务时 fail-closed，不写不提交。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-sl")
    core = SlowCore(conn, camera="front")
    core.process_pending()                    # 造一个已持久 pattern
    conn.execute("INSERT INTO meta (key,value) VALUES ('caller:sl','1')")
    assert conn.in_transaction

    with pytest.raises(SlowPersistenceBusy):
        core.save_library()

    assert conn.in_transaction
    other = db.connect(str(tmp_path / "slow.db"))
    seen = other.execute(
        "SELECT COUNT(*) FROM meta WHERE key='caller:sl'").fetchone()[0]
    other.close()
    assert seen == 0, "外层数据对第二连接不可见"
    conn.rollback()
    conn.close()


def test_confirm_pattern_rejects_before_mutating_memory_when_caller_transaction_exists(
        tmp_path):
    """confirm_pattern 生产入口：外层事务时在改内存前拒绝，逐字段不变。"""
    import copy
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-cf")
    core = SlowCore(conn, camera="front")
    core.process_pending()
    pid = next(iter(core.library.patterns))
    before_mem = copy.deepcopy(core.library.patterns[pid])
    before_row = conn.execute(
        "SELECT * FROM patterns").fetchall()
    before_row = [tuple(r) for r in before_row]
    gen_before = SlowCore.library_generation(conn)

    conn.execute("INSERT INTO meta (key,value) VALUES ('caller:cf','1')")
    assert conn.in_transaction

    with pytest.raises(SlowPersistenceBusy):
        core.confirm_pattern(pid, name="不应写入")

    assert conn.in_transaction, "外层事务仍由调用方控制"
    assert core.library.patterns[pid] == before_mem, \
        "内存 pattern 必须逐字段一致"
    after_row = [tuple(r) for r in conn.execute("SELECT * FROM patterns")]
    assert after_row == before_row, "patterns 表逐字段一致"
    assert SlowCore.library_generation(conn) == gen_before, \
        "library generation 不变"
    conn.rollback()
    conn.close()


# ============ SC-A-R3 P0-A：金标与库代数的原子提交 ============


def _block_meta_generation(conn):
    conn.execute(
        "CREATE TRIGGER blk_gen_ins BEFORE INSERT ON meta"
        " WHEN NEW.key='slow:lib:gen'"
        " BEGIN SELECT RAISE(ABORT, 'blocked by fault injection'); END")
    conn.execute(
        "CREATE TRIGGER blk_gen_upd BEFORE UPDATE ON meta"
        " WHEN NEW.key='slow:lib:gen'"
        " BEGIN SELECT RAISE(ABORT, 'blocked by fault injection'); END")
    conn.commit()


def _unblock_meta_generation(conn):
    conn.execute("DROP TRIGGER IF EXISTS blk_gen_ins")
    conn.execute("DROP TRIGGER IF EXISTS blk_gen_upd")
    conn.commit()


def _block_patterns_writes(conn):
    conn.execute(
        "CREATE TRIGGER blk_pat_ins BEFORE INSERT ON patterns"
        " WHEN 1"
        " BEGIN SELECT RAISE(ABORT, 'blocked by fault injection'); END")
    conn.execute(
        "CREATE TRIGGER blk_pat_upd BEFORE UPDATE ON patterns"
        " WHEN 1"
        " BEGIN SELECT RAISE(ABORT, 'blocked by fault injection'); END")
    conn.commit()


def _unblock_patterns_writes(conn):
    conn.execute("DROP TRIGGER IF EXISTS blk_pat_ins")
    conn.execute("DROP TRIGGER IF EXISTS blk_pat_upd")
    conn.commit()


def _block_embeddings_writes(conn):
    conn.execute(
        "CREATE TRIGGER blk_emb_ins BEFORE INSERT ON pattern_embeddings"
        " WHEN 1"
        " BEGIN SELECT RAISE(ABORT, 'blocked by fault injection'); END")
    conn.execute(
        "CREATE TRIGGER blk_emb_upd BEFORE UPDATE ON pattern_embeddings"
        " WHEN 1"
        " BEGIN SELECT RAISE(ABORT, 'blocked by fault injection'); END")
    conn.commit()


def _unblock_embeddings_writes(conn):
    conn.execute("DROP TRIGGER IF EXISTS blk_emb_ins")
    conn.execute("DROP TRIGGER IF EXISTS blk_emb_upd")
    conn.commit()


def _prepared_core(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-g")
    core = SlowCore(conn, camera="front")
    core.process_pending()
    pid = next(iter(core.library.patterns))
    return conn, core, pid


def test_confirm_generation_failure_rolls_back_everything(tmp_path):
    """A. generation 写入失败：pattern 行/代数/内存全部不变，连接无残留事务。"""
    import copy
    conn, core, pid = _prepared_core(tmp_path)
    row_before = [tuple(r) for r in conn.execute(
        "SELECT * FROM patterns ORDER BY pattern_id")]
    gen_before = SlowCore.library_generation(conn)
    mem_before = copy.deepcopy(core.library.patterns)
    seq_before = core.library.seq

    _block_meta_generation(conn)
    raised = None
    try:
        core.confirm_pattern(pid, name="金标不应生效")
    except Exception as exc:                       # noqa: BLE001
        raised = type(exc).__name__
    finally:
        _unblock_meta_generation(conn)

    assert raised is not None, "generation 失败必须向上抛"
    assert conn.in_transaction is False, "失败后连接不得残留事务"
    other = db.connect(str(tmp_path / "slow.db"))
    assert [tuple(r) for r in other.execute(
        "SELECT * FROM patterns ORDER BY pattern_id")] == row_before, \
        "第二连接必须看到 pattern 行逐字段不变"
    assert SlowCore.library_generation(other) == gen_before, \
        "第二连接必须看到 generation 不变"
    other.close()
    assert core.library.patterns == mem_before, "内存必须逐字节恢复"
    assert core.library.seq == seq_before
    conn.close()


def test_confirm_pattern_write_failure_rolls_back_everything(tmp_path):
    """B. pattern 写入失败：pattern/代数/内存全部不变，连接无残留事务。"""
    import copy
    conn, core, pid = _prepared_core(tmp_path)
    row_before = [tuple(r) for r in conn.execute(
        "SELECT * FROM patterns ORDER BY pattern_id")]
    gen_before = SlowCore.library_generation(conn)
    mem_before = copy.deepcopy(core.library.patterns)

    _block_patterns_writes(conn)
    raised = None
    try:
        core.confirm_pattern(pid, name="金标不应生效")
    except Exception as exc:                       # noqa: BLE001
        raised = type(exc).__name__
    finally:
        _unblock_patterns_writes(conn)

    assert raised is not None
    assert conn.in_transaction is False
    other = db.connect(str(tmp_path / "slow.db"))
    assert [tuple(r) for r in other.execute(
        "SELECT * FROM patterns ORDER BY pattern_id")] == row_before
    assert SlowCore.library_generation(other) == gen_before
    other.close()
    assert core.library.patterns == mem_before
    conn.close()


def test_confirm_success_is_atomic_visible(tmp_path):
    """C. 成功路径：第二连接同时看到新金标与 generation+1（无半提交窗口）。"""
    conn, core, pid = _prepared_core(tmp_path)
    gen_before = SlowCore.library_generation(conn)

    summary = core.confirm_pattern(pid, name="门口送快递")
    assert summary["name"] == "门口送快递"
    assert conn.in_transaction is False

    other = db.connect(str(tmp_path / "slow.db"))
    row = other.execute(
        "SELECT name FROM patterns WHERE pattern_id=?",
        (core._row_id(pid),)).fetchone()
    gen_after = SlowCore.library_generation(other)
    other.close()
    assert row["name"] == "门口送快递", "金标必须可见"
    assert gen_after == gen_before + 1, "代数必须恰 +1（同事务）"
    conn.close()


def test_confirm_misreport_failure_restores_memory_and_db(tmp_path):
    """D. misreport 路径 + generation 失败：state/审计/痕迹/代数/内存全恢复。"""
    import copy
    conn, core, pid = _prepared_core(tmp_path)
    core.confirm_pattern(pid, name="已有名字")
    row_before = [tuple(r) for r in conn.execute(
        "SELECT * FROM patterns ORDER BY pattern_id")]
    gen_before = SlowCore.library_generation(conn)
    mem_before = copy.deepcopy(core.library.patterns)

    _block_meta_generation(conn)
    raised = None
    try:
        core.confirm_pattern(pid, misreport=True)
    except Exception as exc:                       # noqa: BLE001
        raised = type(exc).__name__
    finally:
        _unblock_meta_generation(conn)

    assert raised is not None
    assert conn.in_transaction is False
    other = db.connect(str(tmp_path / "slow.db"))
    assert [tuple(r) for r in other.execute(
        "SELECT * FROM patterns ORDER BY pattern_id")] == row_before, \
        "state/审计字段不得半写"
    assert SlowCore.library_generation(other) == gen_before
    other.close()
    assert core.library.patterns == mem_before, \
        "last_human_feedback/last_audit 等必须逐字节恢复"
    conn.close()


def test_save_library_midway_failure_commits_nothing(tmp_path):
    """E. save_library 中途失败（embeddings 阶段）：patterns 也不得提交。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-s1")
    core = SlowCore(conn, camera="front")
    core.process_pending()
    _seed_segment(conn, rid="rev-s2", t0=9000.0, t1=9120.0,
                  cls="car")
    core.process_pending()
    assert len(core.library.patterns) == 2

    emb = [0.5] * 4
    rows = sorted(core.library.patterns)
    for pid in rows:
        core.library.attach_embedding(pid, emb, "DAY-COLOR")
        core.library.patterns[pid]["detail"] = "批量新细节"
    first_row_id = core._row_id(rows[0])
    before_first = conn.execute(
        "SELECT detail FROM patterns WHERE pattern_id=?",
        (first_row_id,)).fetchone()[0]

    _block_embeddings_writes(conn)
    raised = None
    try:
        core.save_library()
    except Exception as exc:                       # noqa: BLE001
        raised = type(exc).__name__
    finally:
        _unblock_embeddings_writes(conn)

    assert raised is not None
    assert conn.in_transaction is False, "失败后不得残留半写事务"
    other = db.connect(str(tmp_path / "slow.db"))
    after_first = other.execute(
        "SELECT detail FROM patterns WHERE pattern_id=?",
        (first_row_id,)).fetchone()[0]
    emb_count = other.execute(
        "SELECT COUNT(*) FROM pattern_embeddings").fetchone()[0]
    other.close()
    assert after_first == before_first, \
        "embeddings 阶段失败时 patterns 也不得被提交（单事务原子）"
    assert emb_count == 0, "不得有半写 embedding"
    conn.close()


# ============ SC-A-R4 P0-A/P0-B：BEGIN 恢复与 generation CAS ============

from scam.slow_core import SlowGenerationConflict  # noqa: E402


def _two_cores(tmp_path):
    """同库两个独立实例与连接（admin/worker 或 A/B 竞争的标准夹具）。"""
    conn_a = _conn(tmp_path)
    conn_b = db.connect(str(tmp_path / "slow.db"))
    return conn_a, conn_b


def _seed_initial_pattern(conn):
    _seed_segment(conn, rid="rev-1")
    core = SlowCore(conn, camera="front")
    core.process_pending()
    pid = next(iter(core.library.patterns))
    return core, pid


def test_begin_failure_restores_memory_without_mutation(tmp_path):
    """1. BEGIN 自身失败（外部持写锁）：内存/行/代数全不变，无残留事务。"""
    import copy
    conn, _ = _two_cores(tmp_path)
    core, pid = _seed_initial_pattern(conn)
    row_before = [tuple(r) for r in conn.execute(
        "SELECT * FROM patterns ORDER BY pattern_id")]
    gen_before = SlowCore.library_generation(conn)
    mem_before = copy.deepcopy(core.library.patterns)
    seq_before = core.library.seq

    holder = db.connect(str(tmp_path / "slow.db"))
    holder.execute("BEGIN EXCLUSIVE")      # 外部持写锁
    try:
        conn.execute("PRAGMA busy_timeout=0")
        raised = None
        try:
            core.confirm_pattern(pid, name="锁失败不应残留")
        except Exception as exc:               # noqa: BLE001
            raised = type(exc).__name__
        assert raised is not None, "BEGIN 失败必须向上抛（不得转成成功）"
        assert "OperationalError" in raised or "locked" in str(raised)
    finally:
        conn.execute("PRAGMA busy_timeout=5000")
        holder.rollback()
        holder.close()

    assert conn.in_transaction is False, "失败后不得残留事务"
    assert core.library.patterns == mem_before, \
        "BEGIN 失败时内存必须逐字节不变（含 last_human_feedback）"
    assert core.library.seq == seq_before
    check = db.connect(str(tmp_path / "slow.db"))
    assert [tuple(r) for r in check.execute(
        "SELECT * FROM patterns ORDER BY pattern_id")] == row_before
    assert SlowCore.library_generation(check) == gen_before
    check.close()
    conn.close()


def test_stale_worker_cannot_overwrite_admin_label(tmp_path):
    """2. 旧 worker 不得覆盖管理员金标：CAS 冲突 → 重载重算后成功。"""
    conn_a, conn_b = _two_cores(tmp_path)
    admin_core, pid = _seed_initial_pattern(conn_a)
    # worker 实例基于 generation=0 加载内存库
    worker_core = SlowCore(conn_b, camera="front")
    assert worker_core.library is not None
    assert worker_core._library_generation_seen == 0

    _seed_segment(conn_a, rid="rev-2", t0=5000.0, t1=5120.0)
    conn_a.commit()
    claimed = worker_core.pending_reviews()
    assert [r["review_id"] for r in claimed] == ["rev-2"]
    outcome = worker_core._compute(claimed[0])   # 完成昂贵阶段，未持久化

    admin_summary = admin_core.confirm_pattern(pid, name="管理员名字")
    assert admin_summary["name"] == "管理员名字"
    gen_after_admin = SlowCore.library_generation(conn_a)
    assert gen_after_admin == 1

    row_id = worker_core._row_id(pid)
    name_in_db = conn_a.execute(
        "SELECT name,count,version FROM patterns WHERE pattern_id=?",
        (row_id,)).fetchone()
    gen_before_conflict = gen_after_admin
    retry_before = conn_a.execute(
        "SELECT COUNT(*) FROM meta WHERE key='slow:retry:rev-2'"
    ).fetchone()[0]

    raised = None
    try:
        worker_core._persist_terminal(
            claimed[0], status=outcome["status"], detail=outcome["detail"],
            payload=outcome["payload"], signature=outcome["signature"])
    except SlowGenerationConflict as exc:
        raised = type(exc).__name__
    except Exception as exc:                       # noqa: BLE001
        raised = "OTHER:" + type(exc).__name__

    assert raised == "SlowGenerationConflict", \
        f"旧 worker 必须固定冲突失败（实测 {raised}）"
    assert conn_b.in_transaction is False
    after = conn_a.execute(
        "SELECT name,count,version FROM patterns WHERE pattern_id=?",
        (row_id,)).fetchone()
    assert tuple(after) == tuple(name_in_db), "管理员金标行不得被改写"
    assert SlowCore.library_generation(conn_a) == gen_before_conflict, \
        "generation 不得变化"
    seg = conn_a.execute(
        "SELECT json_extract(payload,'$.status') FROM segments"
        " WHERE segment_id='rev-2'").fetchone()[0]
    assert seg == "claiming", "冲突后 segment 必须保持 claiming"
    retry_after = conn_a.execute(
        "SELECT COUNT(*) FROM meta WHERE key='slow:retry:rev-2'"
    ).fetchone()[0]
    assert retry_after == retry_before, "generation 冲突不得消耗 retry"
    assert worker_core._library is None, "worker 缓存必须失效"

    # 下一轮：重载 → 重算 → 成功；管理员名字仍在
    stats = worker_core.process_pending()
    assert stats["processed"] == 1 and stats["conflict"] == 0
    final_name = conn_a.execute(
        "SELECT name FROM patterns WHERE pattern_id=?",
        (row_id,)).fetchone()[0]
    assert final_name == "管理员名字", "重试成功后管理员名字必须仍在"
    seg = conn_a.execute(
        "SELECT json_extract(payload,'$.status') FROM segments"
        " WHERE segment_id='rev-2'").fetchone()[0]
    assert seg in ("recorded", "matched")
    conn_a.close()
    conn_b.close()


def test_two_admin_connections_generation_cas(tmp_path):
    """3. 双管理员竞争：后者固定冲突（非 last-write-wins），重载后可续。"""
    conn_a, conn_b = _two_cores(tmp_path)
    core_a, pid = _seed_initial_pattern(conn_a)
    core_b = SlowCore(conn_b, camera="front")
    core_b.library                       # 触发加载（绑定 generation 快照）
    assert core_b._library_generation_seen == 0

    summary_a = core_a.confirm_pattern(pid, name="名字A")
    assert summary_a["name"] == "名字A"
    assert SlowCore.library_generation(conn_a) == 1

    raised = None
    try:
        core_b.confirm_pattern(pid, name="名字B")
    except SlowGenerationConflict:
        raised = "SlowGenerationConflict"
    except Exception as exc:                       # noqa: BLE001
        raised = "OTHER:" + type(exc).__name__

    assert raised == "SlowGenerationConflict", "B 必须冲突失败"
    assert conn_b.in_transaction is False
    row_id = core_b._row_id(pid)
    name_db = conn_a.execute(
        "SELECT name FROM patterns WHERE pattern_id=?",
        (row_id,)).fetchone()[0]
    assert name_db == "名字A", "数据库必须保留 A 的名字"
    assert SlowCore.library_generation(conn_a) == 1, "generation 恰为 1"
    assert core_b._library is None, "B 旧内存不得被当作有效缓存"

    summary_c = core_b.confirm_pattern(pid, name="名字C")   # 重载后重试
    assert summary_c["name"] == "名字C"
    assert SlowCore.library_generation(conn_a) == 2
    conn_a.close()
    conn_b.close()


def test_save_library_stale_snapshot_conflict(tmp_path):
    """4. save_library 旧快照竞争：冲突失败、不覆盖、无残留事务。"""
    conn_a, conn_b = _two_cores(tmp_path)
    core_a, pid = _seed_initial_pattern(conn_a)
    core_b = SlowCore(conn_b, camera="front")
    core_b.library                       # 触发加载（绑定 generation 快照）
    assert core_b._library_generation_seen == 0

    core_a.confirm_pattern(pid, name="A的整库前状态")
    assert SlowCore.library_generation(conn_a) == 1

    core_b.library.patterns[pid]["detail"] = "B 的旧快照整库覆盖尝试"
    raised = None
    try:
        core_b.save_library()
    except SlowGenerationConflict:
        raised = "SlowGenerationConflict"
    except Exception as exc:                       # noqa: BLE001
        raised = "OTHER:" + type(exc).__name__

    assert raised == "SlowGenerationConflict"
    assert conn_b.in_transaction is False
    row = conn_a.execute(
        "SELECT name,detail FROM patterns WHERE pattern_id=?",
        (core_b._row_id(pid),)).fetchone()
    assert row["name"] == "A的整库前状态", "A 内容不得被覆盖"
    assert row["detail"] != "B 的旧快照整库覆盖尝试"
    assert SlowCore.library_generation(conn_a) == 1, "generation 不变"
    assert core_b._library is None, "B 缓存失效"
    conn_a.close()
    conn_b.close()


def test_worker_commit_with_unchanged_generation(tmp_path):
    """5. generation 一致时 worker 正常提交，且不得无意义递增代数。"""
    conn = _conn(tmp_path)
    core = SlowCore(conn, camera="front")
    _seed_segment(conn, rid="rev-w")
    gen_before = SlowCore.library_generation(conn)
    assert core.library is not None

    stats = core.process_pending()

    assert stats["processed"] == 1
    seg = conn.execute(
        "SELECT json_extract(payload,'$.status') FROM segments"
        " WHERE segment_id='rev-w'").fetchone()[0]
    assert seg in ("recorded", "matched")
    pid = next(iter(core.library.patterns))
    assert core.library.patterns[pid]["count"] == 0
    assert SlowCore.library_generation(conn) == gen_before, \
        "worker 派生写入不得递增库代数"
    conn.close()


def test_cross_camera_conservative_reload(tmp_path):
    """6. 跨相机：front 金标使 back worker 保守冲突；不覆盖不损坏可续跑。"""
    conn_a, conn_b = _two_cores(tmp_path)
    front_core, pid = _seed_initial_pattern(conn_a)

    back_core = SlowCore(conn_b, camera="back")
    back_core.library                    # 触发加载（绑定 generation 快照）
    assert back_core._library_generation_seen == 0
    _seed_segment(conn_a, rid="rev-back", camera="back", t0=7000.0,
                  t1=7120.0)
    conn_a.commit()
    claimed = back_core.pending_reviews()
    assert [r["review_id"] for r in claimed] == ["rev-back"]
    outcome = back_core._compute(claimed[0])

    front_core.confirm_pattern(pid, name="front金标")
    assert SlowCore.library_generation(conn_a) == 1

    raised = None
    try:
        back_core._persist_terminal(
            claimed[0], status=outcome["status"], detail=outcome["detail"],
            payload=outcome["payload"], signature=outcome["signature"])
    except SlowGenerationConflict:
        raised = "SlowGenerationConflict"
    except Exception as exc:                       # noqa: BLE001
        raised = "OTHER:" + type(exc).__name__
    assert raised == "SlowGenerationConflict"

    front_name = conn_a.execute(
        "SELECT name FROM patterns WHERE pattern_id=?",
        (front_core._row_id(pid),)).fetchone()[0]
    assert front_name == "front金标", "front 金标不得被 back 覆盖"
    seg = conn_a.execute(
        "SELECT json_extract(payload,'$.status') FROM segments"
        " WHERE segment_id='rev-back'").fetchone()[0]
    assert seg == "claiming"

    stats = back_core.process_pending()          # 重载后可续
    assert stats["processed"] == 1
    seg = conn_a.execute(
        "SELECT json_extract(payload,'$.status') FROM segments"
        " WHERE segment_id='rev-back'").fetchone()[0]
    assert seg in ("recorded", "matched"), "不得形成永久 claiming"
    front_name = conn_a.execute(
        "SELECT name FROM patterns WHERE pattern_id=?",
        (front_core._row_id(pid),)).fetchone()[0]
    assert front_name == "front金标", "back 续跑不得损坏 front"
    conn_a.close()
    conn_b.close()


# ============ SC-B：迁入 SlowCore 的严格合同 ============


def _with_evidence(tmp_path, conn, rid, frames=3, evil=False, corrupt=False):
    """给段内对象造 clean_best_frame 证据资产（真实 JPEG 文件 + 索引行）。"""
    import cv2
    import numpy as np
    frame = np.zeros((16, 16, 3), dtype=np.uint8)
    frame[:, :, 1] = 128
    ok, encoded = cv2.imencode(".jpg", frame)
    assert ok
    content = encoded.tobytes()
    # UNIQUE(owner_type, owner_id, kind) 约束下每帧挂独立对象
    refs = []
    for index in range(frames):
        object_id = f"{rid}:fo{index}"
        db.open_tracked_object(conn, object_id=object_id, camera="front",
                               t_start=1040.0 + index, cls="person",
                               zones=["z1"])
        db.close_tracked_object(conn, object_id, t_end=1100.0,
                                reason="gone")
        if evil and index == 0:
            rel = "../escape.jpg"          # 越栏引用：绝不进入 loader
        else:
            rel = f"front/{rid}-{index}.jpg"
            target = tmp_path / "evidence" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if corrupt:
                target.write_bytes(b"not-a-jpeg")
            else:
                target.write_bytes(content)
        refs.append(rel)
        conn.execute(
            "INSERT INTO evidence_assets"
            " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
            "  t_start,t_end,score,size_bytes,sha256,created_at,updated_at,"
            "  metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"best:{rid}:{index}", "tracked_object", object_id, "front",
             "clean_best_frame", rel, "available", "image/jpeg",
             1050.0 + index, None, 1.0, len(content), "0" * 64,
             1000.0, 1000.0, "{}"))
    conn.commit()
    return refs


class RecordingProvider:
    name = "recording"

    def __init__(self, reply="门口有人"):
        self.reply = reply
        self.calls = 0
        self.frames_seen = []

    def understand(self, prompt, frames_b64, context=None):
        self.calls += 1
        self.frames_seen.append(len(frames_b64))
        return self.reply


def test_provider_receives_at_most_three_frames(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-3f")
    _with_evidence(tmp_path, conn, rid="rev-3f", frames=5)
    core = SlowCore(conn, camera="front")
    provider = RecordingProvider()
    core.process_pending(provider=provider)
    assert provider.calls == 1
    assert provider.frames_seen == [3], "provider 每段最多三帧"
    conn.close()


def test_unsafe_evidence_refs_never_reach_loader(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-evil")
    refs = _with_evidence(tmp_path, conn, rid="rev-evil", frames=3,
                          evil=True)
    seen = {"refs": None}

    def loader(safe_refs, context):
        seen["refs"] = list(safe_refs)
        import cv2
        return [cv2.imread(str(tmp_path / "evidence" / r))
                for r in safe_refs]

    core = SlowCore(conn, camera="front", frame_loader=loader)
    core.process_pending(provider=RecordingProvider())
    assert seen["refs"] is not None
    assert all(".." not in r for r in seen["refs"]), \
        "越栏引用必须被过滤，绝不进入 loader"
    assert len(seen["refs"]) <= 3
    conn.close()


def test_frame_loader_error_degrades_without_blocking(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-lx")
    _seed_segment(conn, rid="rev-ly", t0=5000.0, t1=5120.0, cls="car")
    _with_evidence(tmp_path, conn, rid="rev-lx", frames=1)
    _with_evidence(tmp_path, conn, rid="rev-ly", frames=1)

    def boom(refs, context):
        raise RuntimeError("loader 故障")

    core = SlowCore(conn, camera="front", frame_loader=boom)
    stats = core.process_pending(provider=RecordingProvider())
    assert stats["processed"] == 2, "loader 故障不得阻塞后续段"
    payload = json.loads(conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-lx'"
    ).fetchone()[0])
    assert payload.get("frames") == "frames:RuntimeError", \
        "固定错误类型必须记录在档案"
    conn.close()


def test_naming_discipline_t2a_zero_t2b_single(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-t2a")
    core = SlowCore(conn, camera="front")
    provider = RecordingProvider("夜间门口行人")
    core.process_pending(provider=provider)
    assert provider.calls == 1, "T2b 新异一次调用"
    _seed_segment(conn, rid="rev-t2b", t0=5000.0, t1=5120.0)
    stats = core.process_pending(provider=provider)
    assert stats["matched"] == 1
    assert provider.calls == 1, "T2a 命中零 VLM 调用"
    conn.close()


def test_provider_undecidable_and_exception_fallbacks(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-und")
    core = SlowCore(conn, camera="front")
    stats = core.process_pending(
        provider=RecordingProvider("undecidable"))
    payload = json.loads(conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-und'"
    ).fetchone()[0])
    assert payload.get("naming") == "undecidable"
    assert stats["fallbacks"] == 1
    # 事件文本仍拿到 fallback 占位名（可读），不冒充模型命名
    name = conn.execute(
        "SELECT short_name FROM semantic_events"
        " WHERE semantic_event_id='rev-und:sem'").fetchone()[0]
    assert name and "未命名事件" in name

    _seed_segment(conn, rid="rev-err", t0=9000.0, t1=9120.0, cls="car")

    class BoomProvider:
        name = "boom"

        def understand(self, *a, **k):
            raise TimeoutError("模型超时")

    stats2 = core.process_pending(provider=BoomProvider())
    payload2 = json.loads(conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-err'"
    ).fetchone()[0])
    assert payload2.get("naming") == "provider_error:TimeoutError"
    assert stats2["processed"] == 1, "provider 异常不得阻塞结构化慢处理"
    assert stats2["fallbacks"] == 1
    conn.close()


def test_embedding_rejects_non_finite_and_oversize(tmp_path):
    from scam.patterns import PATTERN_EMBEDDING_DIM_MAX
    conn = _conn(tmp_path)
    core = SlowCore(conn, camera="front")
    cases = [float("nan"), float("inf"), float("-inf"), True,
             "x" * 3, [1.0] * (PATTERN_EMBEDDING_DIM_MAX + 1)]
    for index, bad in enumerate(cases):
        rid = f"rev-emb-bad-{index}"
        _seed_segment(conn, rid=rid, t0=1000.0 + index * 1000,
                      t1=1120.0 + index * 1000)
        core.process_pending(emb_fn=lambda r, b=bad: (b, "DAY-COLOR"))
        payload = json.loads(conn.execute(
            "SELECT payload FROM segments WHERE segment_id=?",
            (rid,)).fetchone()[0])
        assert payload.get("embedding") == "rejected", (index, payload)
    assert conn.execute(
        "SELECT COUNT(*) FROM pattern_embeddings").fetchone()[0] == 0, \
        "非法嵌入绝不部分写"
    conn.close()


def test_event_text_only_fills_empty_never_overwrites(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-txt")
    # 预置管理员已有文本：不得被覆盖
    conn.execute(
        "UPDATE semantic_events SET short_name='管理员已命名',"
        " detail='管理员细节' WHERE semantic_event_id='rev-txt:sem'")
    conn.commit()

    core = SlowCore(conn, camera="front")
    core.process_pending(provider=RecordingProvider("模型新名字"))

    row = conn.execute(
        "SELECT short_name, detail FROM semantic_events"
        " WHERE semantic_event_id='rev-txt:sem'").fetchone()
    assert row["short_name"] == "管理员已命名", "管理员文本逐字节保留"
    assert row["detail"] == "管理员细节"
    conn.close()


def test_event_text_rolls_back_with_generation_conflict(tmp_path):
    conn_a = _conn(tmp_path)
    _seed_segment(conn_a, rid="rev-gc")
    admin_core = SlowCore(conn_a, camera="front")
    admin_core.process_pending()               # 建 pattern（gen 仍 0）

    conn_b = db.connect(str(tmp_path / "slow.db"))
    worker = SlowCore(conn_b, camera="front")
    worker.library                             # 绑定 gen=0
    _seed_segment(conn_a, rid="rev-gc2", t0=5000.0, t1=5120.0)
    claimed = worker.pending_reviews()
    outcome = worker._compute(claimed[0])
    pid = next(iter(admin_core.library.patterns))
    admin_core.confirm_pattern(pid, name="管理员金标")   # gen → 1

    before_text = conn_a.execute(
        "SELECT short_name FROM semantic_events"
        " WHERE semantic_event_id='rev-gc2:sem'").fetchone()[0]
    raised = None
    try:
        worker._persist_terminal(
            claimed[0], status=outcome["status"], detail=outcome["detail"],
            payload=outcome["payload"], signature=outcome["signature"],
            short_name=outcome["payload"].get("named")
            or outcome.get("fallback_name"))
    except Exception as exc:                       # noqa: BLE001
        raised = type(exc).__name__
    assert raised == "SlowGenerationConflict"
    after_text = conn_a.execute(
        "SELECT short_name FROM semantic_events"
        " WHERE semantic_event_id='rev-gc2:sem'").fetchone()[0]
    assert after_text == before_text, "generation 冲突时文本也不得写入"
    conn_a.close()
    conn_b.close()


def test_event_text_trigger_failure_rolls_back_everything(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-trig")
    conn.execute(
        "CREATE TRIGGER blk_evt_upd BEFORE UPDATE ON semantic_events"
        " WHEN 1"
        " BEGIN SELECT RAISE(ABORT, 'blocked event text'); END")
    conn.commit()

    core = SlowCore(conn, camera="front")
    stats = core.process_pending()

    assert stats["retried"] == 1 and stats["processed"] == 0
    seg = conn.execute(
        "SELECT json_extract(payload,'$.status') AS st FROM segments"
        " WHERE segment_id='rev-trig'").fetchone()
    assert seg["st"] == "claiming", "文本失败必须整事务回滚（段不终态）"
    assert conn.execute(
        "SELECT COUNT(*) FROM patterns").fetchone()[0] == 0, \
        "pattern 不得半写"
    conn.execute("DROP TRIGGER blk_evt_upd")
    conn.commit()
    conn.close()


def test_active_last_attempt_is_not_terminalized(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-last")
    core = SlowCore(conn, camera="front", max_retries=1)

    def boom(self, review, **kwargs):
        raise RuntimeError("持久化失败")

    import pytest as _pytest
    with _pytest.MonkeyPatch.context() as mp:
        mp.setattr(SlowCore, "_persist_terminal", boom)
        first = core.process_pending()
        assert first["retried"] == 1
        second = core.process_pending()          # 达上限但认领新鲜
    assert second["failed"] == 0, "活跃的最后一次尝试不得被立即终态化"
    seg = conn.execute(
        "SELECT json_extract(payload,'$.status') AS st FROM segments"
        " WHERE segment_id='rev-last'").fetchone()
    assert seg["st"] == "claiming", "活跃最后尝试必须保持 claiming"
    conn.close()


def test_exhausted_terminalized_only_after_stale(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-exh")
    core = SlowCore(conn, camera="front", max_retries=1)

    def boom(self, review, **kwargs):
        raise RuntimeError("持久化失败")

    import pytest as _pytest
    with _pytest.MonkeyPatch.context() as mp:
        mp.setattr(SlowCore, "_persist_terminal", boom)
        core.process_pending()                   # retry=1（达上限）
        core.process_pending()                   # 新鲜：不终态化
    # 把认领时间拨回 20 分钟前（模拟长期停滞）→ 过期后才允许终态化
    conn.execute(
        "UPDATE segments SET payload=json_set(payload, '$.t_claim', ?)"
        " WHERE segment_id='rev-exh'",
        (int((time.time() - 1200) * 1e6),))
    conn.commit()
    stats = core.process_pending()
    assert stats["failed"] == 1, "陈旧且耗尽才可终态化"
    seg = conn.execute(
        "SELECT json_extract(payload,'$.status') AS st FROM segments"
        " WHERE segment_id='rev-exh'").fetchone()
    assert seg["st"] == "failed"
    conn.close()


# ============ SC-B-R1：loader 降级 / 证据索引围栏 / 阈值核心 ============


class _RecordingProvider:
    name = "recording-br1"

    def __init__(self):
        self.calls = 0
        self.frames_seen = []

    def understand(self, prompt, frames_b64, context=None):
        self.calls += 1
        self.frames_seen.append(list(frames_b64))
        return "命名"


def _assert_segment_finished_without_retry(conn, rid):
    seg = conn.execute(
        "SELECT json_extract(payload,'$.status') AS st FROM segments"
        " WHERE segment_id=?", (rid,)).fetchone()
    assert seg["st"] in ("recorded", "matched"), f"段必须完成终态: {seg['st']}"
    retry = conn.execute(
        "SELECT COUNT(*) FROM meta WHERE key=?",
        (f"slow:retry:{rid}",)).fetchone()[0]
    assert retry == 0, "loader 故障不得进入 retry"


def test_loader_immediate_exception_degrades(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-imm")
    _with_evidence(tmp_path, conn, rid="rev-imm", frames=1)

    def boom(refs, context):
        raise RuntimeError("立即异常")

    core = SlowCore(conn, camera="front", frame_loader=boom)
    provider = _RecordingProvider()
    stats = core.process_pending(provider=provider)

    assert stats["processed"] == 1 and stats["retried"] == 0
    payload = json.loads(conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-imm'"
    ).fetchone()[0])
    assert payload.get("frames") == "frames:RuntimeError"
    assert provider.calls == 1, "provider 最多一次（可收空帧）"
    _assert_segment_finished_without_retry(conn, "rev-imm")
    conn.close()


def test_loader_generator_late_exception_degrades(tmp_path):
    """P0-B：生成器先 yield 一帧后抛异常——部分帧丢弃、固定降级、零 retry。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-gen")
    _with_evidence(tmp_path, conn, rid="rev-gen", frames=2)
    import numpy as np

    def gen_loader(refs, context):
        yield np.zeros((8, 8, 3), dtype=np.uint8)   # 先给一帧
        raise ValueError("延迟异常")

    core = SlowCore(conn, camera="front", frame_loader=gen_loader)
    provider = _RecordingProvider()
    stats = core.process_pending(provider=provider)

    assert stats["processed"] == 1 and stats["retried"] == 0
    payload = json.loads(conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-gen'"
    ).fetchone()[0])
    assert payload.get("frames") == "frames:ValueError"
    assert provider.frames_seen == [[]], \
        "部分取得的帧必须丢弃（不得'部分命名又隐瞒失败'）"
    _assert_segment_finished_without_retry(conn, "rev-gen")
    conn.close()


def test_loader_non_iterable_output_degrades(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-int")
    _with_evidence(tmp_path, conn, rid="rev-int", frames=1)

    def bad_loader(refs, context):
        return 42

    core = SlowCore(conn, camera="front", frame_loader=bad_loader)
    provider = _RecordingProvider()
    stats = core.process_pending(provider=provider)
    assert stats["processed"] == 1 and stats["retried"] == 0
    payload = json.loads(conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-int'"
    ).fetchone()[0])
    assert payload.get("frames") == "frames:TypeError"
    _assert_segment_finished_without_retry(conn, "rev-int")
    conn.close()


def test_loader_more_than_three_frames_capped(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-five")
    _with_evidence(tmp_path, conn, rid="rev-five", frames=5)
    import numpy as np

    def five_loader(refs, context):
        return [np.zeros((8, 8, 3), dtype=np.uint8) for _ in range(5)]

    core = SlowCore(conn, camera="front", frame_loader=five_loader)
    provider = _RecordingProvider()
    stats = core.process_pending(provider=provider)
    assert stats["processed"] == 1
    assert len(provider.frames_seen[0]) <= 3, "provider 最多三帧"
    conn.close()


# ---------- P1-C：证据索引/围栏 ----------

def _evidence_loader_spy(seen):
    def loader(refs, context):
        seen.extend(refs)
        return []
    return loader


def test_available_jpeg_reaches_loader(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-ok")
    _with_evidence(tmp_path, conn, rid="rev-ok", frames=1)
    seen = []
    core = SlowCore(conn, camera="front",
                    frame_loader=_evidence_loader_spy(seen))
    core.process_pending(provider=_RecordingProvider())
    assert seen and seen[0].endswith(".jpg"), "available+JPEG 必须到达 loader"
    conn.close()


def test_missing_or_corrupt_state_not_reaching_loader(tmp_path):
    conn = _conn(tmp_path)
    for state in ("missing", "corrupt"):
        rid = f"rev-{state}"
        _seed_segment(conn, rid=rid, t0=1000.0 + len(state) * 500,
                      t1=1120.0 + len(state) * 500)
        refs = _with_evidence(tmp_path, conn, rid=rid, frames=1)
        conn.execute(
            "UPDATE evidence_assets SET state=? WHERE path=?",
            (state, refs[0]))
        conn.commit()
    seen = []
    core = SlowCore(conn, camera="front",
                    frame_loader=_evidence_loader_spy(seen))
    core.process_pending(provider=_RecordingProvider())
    assert seen == [], f"missing/corrupt 不得到达 loader: {seen}"
    conn.close()


def test_non_jpeg_mime_not_reaching_loader(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-png")
    refs = _with_evidence(tmp_path, conn, rid="rev-png", frames=1)
    conn.execute(
        "UPDATE evidence_assets SET mime='image/png' WHERE path=?",
        (refs[0],))
    conn.commit()
    seen = []
    core = SlowCore(conn, camera="front",
                    frame_loader=_evidence_loader_spy(seen))
    core.process_pending(provider=_RecordingProvider())
    assert seen == [], "非 JPEG MIME 不得到达 loader"
    conn.close()


def test_absolute_and_dotdot_paths_not_reaching_loader(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-abs")
    refs = _with_evidence(tmp_path, conn, rid="rev-abs", frames=1)
    conn.execute(
        "UPDATE evidence_assets SET path=? WHERE path=?",
        ("C:/Windows/win.ini", refs[0]))
    conn.commit()
    seen = []
    core = SlowCore(conn, camera="front",
                    frame_loader=_evidence_loader_spy(seen))
    core.process_pending(provider=_RecordingProvider())
    assert seen == [], "绝对路径不得到达 loader"
    conn.close()


def test_symlink_escape_not_reaching_loader(tmp_path, monkeypatch):
    """根内引用经真身复核发现指向根外（符号链接/联接）→ 拒绝（可注入验证）。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-link")
    refs = _with_evidence(tmp_path, conn, rid="rev-link", frames=1)
    real_root = os.path.realpath(str(tmp_path / "evidence"))
    outside = os.path.realpath(str(tmp_path / "outside"))

    original_realpath = os.path.realpath

    def fake_realpath(path):
        resolved = original_realpath(path)
        if os.path.normcase(resolved).startswith(
                os.path.normcase(real_root) + os.sep):
            return os.path.join(outside, "escape.jpg")   # 模拟越栏链接
        return resolved

    monkeypatch.setattr(os.path, "realpath", fake_realpath)
    seen = []
    core = SlowCore(conn, camera="front",
                    frame_loader=_evidence_loader_spy(seen))
    core.process_pending(provider=_RecordingProvider())
    monkeypatch.undo()
    assert seen == [], "指向根外的符号链接引用不得到达 loader"
    conn.close()


def test_rejections_do_not_retry_or_touch_truth(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-rej")
    refs = _with_evidence(tmp_path, conn, rid="rev-rej", frames=1)
    conn.execute(
        "UPDATE evidence_assets SET state='missing' WHERE path=?",
        (refs[0],))
    conn.commit()
    before = _snapshot_truth(conn)
    core = SlowCore(conn, camera="front")
    stats = core.process_pending(provider=_RecordingProvider())
    assert stats["processed"] == 1 and stats["retried"] == 0
    _assert_truth_preserved(before, _snapshot_truth(conn))
    conn.close()


# ---------- P1-B 核心侧：阈值传入 ----------

def test_core_stale_threshold_controls_takeover(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-core1", t0=9000.0, t1=9120.0)
    conn.execute(
        "INSERT INTO segments (segment_id,camera,t_start,t_end,signature,"
        "detail,payload) VALUES ('rev-core1','front',9000.0,9120.0,NULL,"
        "NULL,?)",
        (json.dumps({"status": "claiming", "owner": "dead",
                     "t_claim": int((time.time() - 2) * 1e6)}),))
    conn.commit()
    other = SlowCore(conn, camera="front")
    assert other.pending_reviews(recover_stale=True,
                                 stale_after_s=10) == [], \
        "未超传入阈值不得接管"
    claimed = other.pending_reviews(recover_stale=True, stale_after_s=1)
    assert [r["review_id"] for r in claimed] == ["rev-core1"], \
        "超过传入阈值必须允许接管"
    conn.close()


def test_core_exhaustion_respects_passed_threshold(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-core2")
    core = SlowCore(conn, camera="front", max_retries=1)

    def boom(self, review, **kwargs):
        raise RuntimeError("持久化失败")

    import pytest as _pytest
    with _pytest.MonkeyPatch.context() as mp:
        mp.setattr(SlowCore, "_persist_terminal", boom)
        core.process_pending()                    # retry=1（达上限）
    conn.execute(
        "UPDATE segments SET payload=json_set(payload,'$.t_claim',?)"
        " WHERE segment_id='rev-core2'",
        (int((time.time() - 2) * 1e6),))
    conn.commit()
    # 阈值 10s：认领仅 2 秒旧 → 不得终态化
    stats_high = core.process_pending(stale_after_s=10)
    assert stats_high["failed"] == 0
    seg = conn.execute(
        "SELECT json_extract(payload,'$.status') AS st FROM segments"
        " WHERE segment_id='rev-core2'").fetchone()
    assert seg["st"] == "claiming"
    # 阈值 1s：已超 → 允许固定终态
    stats_low = core.process_pending(stale_after_s=1)
    assert stats_low["failed"] == 1
    seg = conn.execute(
        "SELECT json_extract(payload,'$.status') AS st FROM segments"
        " WHERE segment_id='rev-core2'").fetchone()
    assert seg["st"] == "failed"
    conn.close()


def test_core_stale_validation_before_write(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-core3")
    core = SlowCore(conn, camera="front")
    before = conn.execute(
        "SELECT COUNT(*) FROM segments").fetchone()[0]
    for bad in (float("nan"), float("inf"), float("-inf"), True, 0, -1,
                "1"):
        with pytest.raises(ValueError):
            core.process_pending(stale_after_s=bad)
        with pytest.raises(ValueError):
            core.pending_reviews(stale_after_s=bad)
    after = conn.execute(
        "SELECT COUNT(*) FROM segments").fetchone()[0]
    assert after == before, "非法阈值必须在任何数据库写入前拒绝"
    conn.close()


# ============ SC-B-R2：耗尽陈旧认领按计划快照原子收官 ============

import hashlib as _hashlib  # noqa: E402


def _seed_claim(conn, rid, payload_text, *, t0=1000.0, t1=1120.0,
                retries=None, max_retries=None):
    """造一个任意 payload 的 claiming 占位行（可选预置 retry 计数）。"""
    _seed_segment(conn, rid=rid, t0=t0, t1=t1)
    conn.execute(
        "INSERT INTO segments (segment_id,camera,t_start,t_end,signature,"
        "detail,payload) VALUES (?,?,?,?,NULL,NULL,?)",
        (rid, "front", t0, t1, payload_text))
    if retries is not None:
        conn.execute(
            "INSERT INTO meta (key,value) VALUES (?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (f"slow:retry:{rid}", str(retries)))
    conn.commit()


def _claim_payload_text(owner="dead-worker", seconds_old=1200):
    return json.dumps({"status": "claiming", "owner": owner,
                       "t_claim": int((time.time() - seconds_old) * 1e6)})


def _claim_payload_json(conn, rid):
    row = conn.execute(
        "SELECT payload FROM segments WHERE segment_id=?", (rid,)).fetchone()
    return row[0]


def test_foreign_stale_exhausted_finalizes_in_same_round(tmp_path):
    """1. 异实例·陈旧·耗尽·recover_stale=True：本轮直接固定失败终态。"""
    conn = _conn(tmp_path)
    _seed_claim(conn, "rev-ex1", _claim_payload_text(seconds_old=1200),
                retries=1)
    core = SlowCore(conn, camera="front", max_retries=1)

    stats = core.process_pending(recover_stale=True)

    assert stats["failed"] == 1
    assert stats["processed"] == 0
    assert stats["retried"] == 0 and stats["conflict"] == 0
    payload = json.loads(_claim_payload_json(conn, "rev-ex1"))
    assert payload["status"] == "failed"
    assert payload["error"] == "retries_exhausted"
    assert payload["final"] is True
    assert core.waterlevel()["pending"] == 0, "backlog 必须同步减少"
    # 同一轮完成——不需第二个陈旧周期
    assert stats["failed"] == 1
    conn.close()


def test_foreign_fresh_exhausted_is_not_finalized(tmp_path):
    """2. 异实例·耗尽·未过阈值：保持 claiming，本轮 failed=0。"""
    conn = _conn(tmp_path)
    _seed_claim(conn, "rev-ex2", _claim_payload_text(seconds_old=1),
                retries=1)
    before = _claim_payload_json(conn, "rev-ex2")
    core = SlowCore(conn, camera="front", max_retries=1)

    stats = core.process_pending(recover_stale=True)

    assert stats["failed"] == 0
    assert _claim_payload_json(conn, "rev-ex2") == before, \
        "owner/t_claim 必须逐字节不变"
    assert core.waterlevel()["pending"] == 1
    conn.close()


def test_foreign_stale_exhausted_not_touched_when_recovery_disabled(
        tmp_path):
    """3. recover_stale=False：陈旧耗尽认领不接管、不终态化。"""
    conn = _conn(tmp_path)
    _seed_claim(conn, "rev-ex3", _claim_payload_text(seconds_old=1200),
                retries=1)
    before = _claim_payload_json(conn, "rev-ex3")
    core = SlowCore(conn, camera="front", max_retries=1)

    stats = core.process_pending()          # 默认 False

    assert stats["failed"] == 0 and stats["processed"] == 0
    assert _claim_payload_json(conn, "rev-ex3") == before
    conn.close()


def test_same_owner_fresh_exhausted_is_not_finalized(tmp_path):
    """4. 同实例·耗尽·未过阈值：活跃最后尝试保护。"""
    conn = _conn(tmp_path)
    core = SlowCore(conn, camera="front", max_retries=1)
    _seed_claim(conn, "rev-ex4",
                _claim_payload_text(owner=core.instance_id, seconds_old=1),
                retries=1)
    before = _claim_payload_json(conn, "rev-ex4")

    stats = core.process_pending()

    assert stats["failed"] == 0
    assert _claim_payload_json(conn, "rev-ex4") == before
    conn.close()


def test_same_owner_stale_exhausted_finalizes(tmp_path):
    """5. 同实例·耗尽·已过阈值：本轮直接收官。"""
    conn = _conn(tmp_path)
    core = SlowCore(conn, camera="front", max_retries=1)
    _seed_claim(conn, "rev-ex5",
                _claim_payload_text(owner=core.instance_id, seconds_old=1200),
                retries=1)

    stats = core.process_pending()

    assert stats["failed"] == 1
    payload = json.loads(_claim_payload_json(conn, "rev-ex5"))
    assert payload["status"] == "failed" and payload["final"] is True
    conn.close()


def test_malformed_claim_time_never_proves_stale(tmp_path):
    """6. 缺失/null/字符串/bool 时间：一律不接管、不终态、retry 不增。"""
    cases = {
        "null-time": json.dumps({"status": "claiming",
                                 "owner": "dead", "t_claim": None}),
        "omit-time": json.dumps({"status": "claiming", "owner": "dead"}),
        "string-time": json.dumps({"status": "claiming", "owner": "dead",
                                   "t_claim": "1234567890"}),
        "omit-owner": json.dumps({"status": "claiming",
                                  "t_claim": 1}),
    }
    conn = _conn(tmp_path)
    core = SlowCore(conn, camera="front", max_retries=1)
    for index, (tag, text) in enumerate(cases.items()):
        rid = f"rev-mal-{tag}"
        _seed_claim(conn, rid, text, t0=1000.0 + index * 500,
                    t1=1120.0 + index * 500, retries=1)
        before = _claim_payload_json(conn, rid)
        stats = core.process_pending(recover_stale=True)
        assert stats["failed"] == 0 and stats["processed"] == 0, tag
        assert _claim_payload_json(conn, rid) == before, tag
        retry = conn.execute(
            "SELECT value FROM meta WHERE key=?", (f"slow:retry:{rid}",)
        ).fetchone()[0]
        assert retry == "1", f"{tag}: retry 不得变化"
    # backlog 诚实可见（claiming 计入）
    assert core.waterlevel()["pending"] == len(cases)
    # 函数级 bool/非有限契约（SQLite 会把 JSON true 归一为数字——存储层
    # 语义边界，故 bool 以直接参数验证 failure-closed 证明函数）
    assert core._claim_is_provably_stale("o", True, 600.0) is False
    assert core._claim_is_provably_stale("o", float("nan"), 600.0) is False
    assert core._claim_is_provably_stale("o", float("inf"), 600.0) is False
    assert core._claim_is_provably_stale(None, 1, 600.0) is False
    assert core._claim_is_provably_stale("o", None, 600.0) is False
    assert core._claim_is_provably_stale("o", "x", 600.0) is False
    conn.close()


def test_exhausted_finalize_cas_single_winner(tmp_path):
    """7. 双连接同快照：只允许一方收官，最终恰一条 failed。"""
    conn_a = _conn(tmp_path)
    _seed_claim(conn_a, "rev-cas1", _claim_payload_text(seconds_old=1200),
                retries=1)
    conn_b = db.connect(str(tmp_path / "slow.db"))
    core_a = SlowCore(conn_a, camera="front", max_retries=1)
    core_b = SlowCore(conn_b, camera="front", max_retries=1)

    stats_a = core_a.process_pending(recover_stale=True)
    stats_b = core_b.process_pending(recover_stale=True)

    assert stats_a["failed"] + stats_b["failed"] == 1, \
        f"合计 failed 必须为 1（实测 {stats_a['failed']}+{stats_b['failed']}）"
    failed_rows = conn_a.execute(
        "SELECT COUNT(*) FROM segments WHERE json_extract(payload,"
        "'$.status')='failed'").fetchone()[0]
    assert failed_rows == 1, "数据库恰一条 failed 终态"
    payload = json.loads(_claim_payload_json(conn_a, "rev-cas1"))
    assert payload["final"] is True
    conn_a.close()
    conn_b.close()


def test_exhausted_finalize_snapshot_change_loses_cas(tmp_path):
    """8. 计划后 owner/t_claim 被改：原快照收官必竞输（不覆盖新认领）。"""
    conn_a = _conn(tmp_path)
    _seed_claim(conn_a, "rev-cas2", _claim_payload_text(seconds_old=1200),
                retries=1)
    old_text = _claim_payload_json(conn_a, "rev-cas2")
    core = SlowCore(conn_a, camera="front", max_retries=1)

    # 另一连接改写认领（新 owner+t_claim）
    conn_b = db.connect(str(tmp_path / "slow.db"))
    conn_b.execute(
        "UPDATE segments SET payload=? WHERE segment_id='rev-cas2'",
        (_claim_payload_text(owner="new-owner", seconds_old=1),))
    conn_b.commit()
    new_text = _claim_payload_json(conn_b, "rev-cas2")

    # SC-B-R3：CAS 依据是**整份原始 payload 文本快照**
    finalized = core._finalize_exhausted_claim("rev-cas2", old_text)
    assert finalized is False, "旧快照收官必须竞输"
    assert _claim_payload_json(conn_b, "rev-cas2") == new_text, \
        "数据库必须保留新 owner/t_claim"
    conn_a.close()
    conn_b.close()


def test_exhausted_finalize_has_no_slow_dependencies(tmp_path):
    """9. provider/embedder/frame_loader 注入即抛：收官仍成功且三者零调用。"""
    conn = _conn(tmp_path)
    _seed_claim(conn, "rev-dep", _claim_payload_text(seconds_old=1200),
                retries=1)
    calls = {"provider": 0, "embedder": 0, "loader": 0}

    class BoomProvider:
        name = "boom"

        def understand(self, *a, **k):
            calls["provider"] += 1
            raise RuntimeError("provider 不应被调用")

    def boom_loader(refs, context):
        calls["loader"] += 1
        raise RuntimeError("loader 不应被调用")

    def boom_embedder(frames):
        calls["embedder"] += 1
        raise RuntimeError("embedder 不应被调用")

    core = SlowCore(conn, camera="front", max_retries=1,
                    frame_loader=boom_loader)
    stats = core.process_pending(provider=BoomProvider(),
                                 emb_fn=lambda review: (boom_embedder([]),
                                                        "DAY-COLOR"),
                                 recover_stale=True)

    assert stats["failed"] == 1
    assert calls == {"provider": 0, "embedder": 0, "loader": 0}, calls
    payload = json.loads(_claim_payload_json(conn, "rev-dep"))
    assert payload["status"] == "failed"
    conn.close()


def test_exhausted_finalize_changes_only_segment(tmp_path):
    """10. 收官前后：patterns/embeddings/events/generation/retry 逐字节不变。"""
    conn = _conn(tmp_path)
    # 先建一个模式与事件文本，作为"不允许被碰"的旁证
    _seed_segment(conn, rid="rev-base")
    SlowCore(conn, camera="front").process_pending()
    _seed_claim(conn, "rev-only", _claim_payload_text(seconds_old=1200),
                t0=5000.0, t1=5120.0, retries=1)

    def digest():
        parts = []
        for table in ("patterns", "pattern_embeddings"):
            rows = conn.execute(
                f"SELECT * FROM {table}").fetchall()
            parts.append(_hashlib.sha256(json.dumps(
                [tuple(r) for r in rows], ensure_ascii=False,
                default=str, sort_keys=True).encode()).hexdigest())
        parts.append(_hashlib.sha256(json.dumps(
            [tuple(r) for r in conn.execute("SELECT * FROM semantic_events")],
            ensure_ascii=False, default=str, sort_keys=True).encode()
        ).hexdigest())
        parts.append(str(SlowCore.library_generation(conn)))
        parts.append(str(conn.execute(
            "SELECT value FROM meta WHERE key='slow:retry:rev-only'"
        ).fetchone()[0]))
        return parts

    before = digest()
    core = SlowCore(conn, camera="front", max_retries=1)
    stats = core.process_pending(recover_stale=True)
    assert stats["failed"] == 1
    # digest 中 retry 部分属于目标 review——排除后比较其余
    after = digest()
    assert before[:4] == after[:4], \
        "patterns/embeddings/events/generation 必须逐字节不变"
    assert after[4] == "1", "retry 值不得增加"
    conn.close()


# ---------- LZ-083 SC-B-R3：认领文档保真解析与整份 payload 快照 CAS ----------

def _retry_value(conn, rid):
    row = conn.execute("SELECT value FROM meta WHERE key=?",
                       (f"slow:retry:{rid}",)).fetchone()
    return row[0] if row else None


def _dep_spy():
    """三个昂贵依赖的调用计数；注入即抛，证明 fail-closed 路径零调用。"""
    calls = {"provider": 0, "embedder": 0, "loader": 0}

    class _BoomProvider:
        name = "boom"

        def understand(self, *args, **kwargs):
            calls["provider"] += 1
            raise RuntimeError("provider 不得被调用")

    def boom_loader(refs, context):
        calls["loader"] += 1
        raise RuntimeError("frame_loader 不得被调用")

    def boom_emb_fn(review):
        calls["embedder"] += 1
        raise RuntimeError("embedder 不得被调用")

    return calls, _BoomProvider(), boom_loader, boom_emb_fn


def _run_failclosed_round(tmp_path, rid, payload_text):
    """数据库真实入口跑一轮 recover_stale=True / stale_after_s=1。"""
    conn = _conn(tmp_path)
    _seed_claim(conn, rid, payload_text, retries=1)
    before = _claim_payload_json(conn, rid)
    retry_before = _retry_value(conn, rid)
    calls, provider, loader, emb_fn = _dep_spy()
    core = SlowCore(conn, camera="front", max_retries=1, frame_loader=loader)
    stats = core.process_pending(recover_stale=True, stale_after_s=1,
                                 provider=provider, emb_fn=emb_fn)
    after = _claim_payload_json(conn, rid)
    retry_after = _retry_value(conn, rid)
    return conn, before, after, retry_before, retry_after, stats, calls, core


def _assert_failclosed(conn, before, after, retry_before, retry_after,
                       stats, calls, core):
    """fail-closed 全量断言：不接管/不终态化/不增 retry/不减 backlog/零依赖。"""
    assert stats["failed"] == 0, "不得制造 failed 事实"
    assert stats["processed"] == 0
    assert stats["retried"] == 0
    assert stats["conflict"] == 0
    assert after == before, "payload 必须逐字节不变"
    assert retry_after == retry_before, "retry 必须不变"
    assert core.waterlevel()["pending"] == 1, "backlog 必须保持 1"
    assert calls == {"provider": 0, "embedder": 0, "loader": 0}, calls
    conn.close()


def test_db_bool_true_t_claim_fails_closed(tmp_path):
    """1. 数据库真实入口：`t_claim:true` 必须 fail-closed（LZ-082 P0 回归）。"""
    conn = _conn(tmp_path)
    _seed_claim(conn, "rev-r3-true",
                json.dumps({"status": "claiming", "owner": "dead",
                            "t_claim": True}), retries=1)
    # 钉住 P0 前提：SQL 层确实把 JSON true 归一成整数 1（原始类型已丢失）
    probe = conn.execute(
        "SELECT json_extract(payload,'$.t_claim') AS v,"
        " json_type(payload,'$.t_claim') AS t FROM segments"
        " WHERE segment_id='rev-r3-true'").fetchone()
    assert probe["v"] == 1 and probe["t"] == "true", \
        "P0 前提：json_extract 把 true 归一成整数 1"
    before = _claim_payload_json(conn, "rev-r3-true")
    retry_before = _retry_value(conn, "rev-r3-true")
    calls, provider, loader, emb_fn = _dep_spy()
    core = SlowCore(conn, camera="front", max_retries=1, frame_loader=loader)

    stats = core.process_pending(recover_stale=True, stale_after_s=1,
                                 provider=provider, emb_fn=emb_fn)

    _assert_failclosed(conn, before, _claim_payload_json(conn, "rev-r3-true"),
                       retry_before, _retry_value(conn, "rev-r3-true"),
                       stats, calls, core)


def test_db_bool_false_t_claim_fails_closed(tmp_path):
    """2. `t_claim:false` 同样必须完全不改写。"""
    conn, before, after, rb, ra, stats, calls, core = _run_failclosed_round(
        tmp_path, "rev-r3-false",
        json.dumps({"status": "claiming", "owner": "dead",
                    "t_claim": False}))
    _assert_failclosed(conn, before, after, rb, ra, stats, calls, core)


_BAD_T_CLAIM_CASES = [
    ("null", {"t_claim": None}),
    ("missing", {}),
    ("string-1", {"t_claim": "1"}),
    ("float-1.0", {"t_claim": 1.0}),
    ("array", {"t_claim": [1, 2]}),
    ("object", {"t_claim": {"us": 1}}),
    ("nan", {"t_claim": float("nan")}),
    ("inf", {"t_claim": float("inf")}),
    ("neg-inf", {"t_claim": float("-inf")}),
]


@pytest.mark.parametrize("tag,extra", _BAD_T_CLAIM_CASES,
                         ids=[case[0] for case in _BAD_T_CLAIM_CASES])
def test_db_unprovable_t_claim_types_fail_closed(tmp_path, tag, extra):
    """3. 参数化：缺失/null/字符串/浮点/数组/对象/NaN/±Inf 一律 fail-closed。"""
    doc = {"status": "claiming", "owner": "dead"}
    doc.update(extra)
    conn, before, after, rb, ra, stats, calls, core = _run_failclosed_round(
        tmp_path, f"rev-r3-{tag}", json.dumps(doc))
    _assert_failclosed(conn, before, after, rb, ra, stats, calls, core)


_OWNER_CASES = [
    ("bool-true", True),
    ("bool-false", False),
    ("number", 1),
    ("empty", ""),
    ("null", None),
    ("array", [1]),
    ("object", {"a": 1}),
]


@pytest.mark.parametrize("tag,owner_value", _OWNER_CASES,
                         ids=[case[0] for case in _OWNER_CASES])
def test_db_owner_type_errors_fail_closed(tmp_path, tag, owner_value):
    """4. owner 类型错误：即使 t_claim 看似足够陈旧也不得接管或收官。"""
    stale_us = int((time.time() - 1200) * 1e6)
    conn, before, after, rb, ra, stats, calls, core = _run_failclosed_round(
        tmp_path, f"rev-r3-owner-{tag}",
        json.dumps({"status": "claiming", "owner": owner_value,
                    "t_claim": stale_us}))
    _assert_failclosed(conn, before, after, rb, ra, stats, calls, core)


def test_db_owner_missing_fails_closed(tmp_path):
    """4b. owner 缺失：同样不得接管或收官。"""
    stale_us = int((time.time() - 1200) * 1e6)
    conn, before, after, rb, ra, stats, calls, core = _run_failclosed_round(
        tmp_path, "rev-r3-owner-missing",
        json.dumps({"status": "claiming", "t_claim": stale_us}))
    _assert_failclosed(conn, before, after, rb, ra, stats, calls, core)


def test_db_malformed_json_does_not_poison_the_batch(tmp_path):
    """5. 非法 JSON 不毒死整批：前一条损坏，后一条合法陈旧耗尽仍正常收官。"""
    conn = _conn(tmp_path)
    _seed_claim(conn, "rev-r3-bad", "{not json at all",
                t0=1000.0, t1=1120.0)
    _seed_claim(conn, "rev-r3-good", _claim_payload_text(seconds_old=1200),
                t0=2000.0, t1=2120.0, retries=1)
    bad_before = _claim_payload_json(conn, "rev-r3-bad")
    core = SlowCore(conn, camera="front", max_retries=1)

    stats = core.process_pending(recover_stale=True, stale_after_s=1)

    assert stats["failed"] == 1, "failed 只计合法那一条"
    assert stats["processed"] == 0
    assert stats["retried"] == 0 and stats["conflict"] == 0
    assert _claim_payload_json(conn, "rev-r3-bad") == bad_before, \
        "损坏 payload 必须逐字节不变"
    payload = json.loads(_claim_payload_json(conn, "rev-r3-good"))
    assert payload["status"] == "failed"
    assert payload["error"] == "retries_exhausted"
    assert payload["final"] is True
    conn.close()


def test_db_non_object_and_terminal_rows_are_untouched(tmp_path):
    """5b. 根非 object / status 非 claiming / 终态行：一律不触碰且不抛异常。"""
    conn = _conn(tmp_path)
    rows = {
        "rev-r3-arr": "[1, 2, 3]",
        "rev-r3-num": "12345",
        "rev-r3-stat": json.dumps({"status": 1, "owner": "dead",
                                   "t_claim": 1}),
        "rev-r3-done": json.dumps({"status": "recorded"}),
    }
    for index, (rid, text) in enumerate(rows.items()):
        _seed_claim(conn, rid, text, t0=1000.0 + index * 500,
                    t1=1120.0 + index * 500)
    before = {rid: _claim_payload_json(conn, rid) for rid in rows}
    core = SlowCore(conn, camera="front", max_retries=1)

    stats = core.process_pending(recover_stale=True, stale_after_s=1)

    assert stats["failed"] == 0 and stats["processed"] == 0
    for rid, text in before.items():
        assert _claim_payload_json(conn, rid) == text, rid
    conn.close()


def test_db_terminal_rows_do_not_starve_pending_window(tmp_path):
    """5c. 大量终态行排在前面也不得挤占 LIMIT 窗口、饿死真正待办。"""
    conn = _conn(tmp_path)
    for index in range(40):
        _seed_claim(conn, f"rev-r3-done-{index:02d}",
                    json.dumps({"status": "recorded", "n": index}),
                    t0=float(index), t1=float(index) + 120)
    _seed_claim(conn, "rev-r3-starve", _claim_payload_text(seconds_old=1200),
                t0=100.0, t1=220.0, retries=1)
    core = SlowCore(conn, camera="front", max_retries=1)

    # limit=1 是最窄窗口：若终态行参与 LIMIT 截断，真待办必然拿不到名额
    assert core.pending_reviews(1, recover_stale=True,
                                stale_after_s=1) == []

    payload = json.loads(_claim_payload_json(conn, "rev-r3-starve"))
    assert payload["status"] == "failed", "终态行不得挤占 LIMIT 窗口"
    assert payload["error"] == "retries_exhausted"
    assert core.waterlevel()["pending"] == 0
    conn.close()


def test_db_extra_field_change_loses_snapshot_cas(tmp_path):
    """6a. owner/t_claim 未变、只改额外字段：原快照收官必竞输。"""
    conn_a = _conn(tmp_path)
    _seed_claim(conn_a, "rev-r3-epoch", _claim_payload_text(seconds_old=1200),
                retries=1)
    old_text = _claim_payload_json(conn_a, "rev-r3-epoch")
    core = SlowCore(conn_a, camera="front", max_retries=1)

    conn_b = db.connect(str(tmp_path / "slow.db"))
    doc = json.loads(old_text)
    doc["lease_epoch"] = 2
    new_text = json.dumps(doc)
    conn_b.execute(
        "UPDATE segments SET payload=? WHERE segment_id='rev-r3-epoch'",
        (new_text,))
    conn_b.commit()

    finalized = core._finalize_exhausted_claim("rev-r3-epoch", old_text)

    assert finalized is False, "owner/t_claim 未变也必须竞输（整份快照 CAS）"
    assert _claim_payload_json(conn_b, "rev-r3-epoch") == new_text, \
        "新 payload 必须保留"
    assert json.loads(new_text)["status"] == "claiming", "不得出现 failed 终态"
    assert _retry_value(conn_a, "rev-r3-epoch") == "1", "retry 不得增加"
    conn_a.close()
    conn_b.close()


def test_db_takeover_loses_cas_when_payload_changes(tmp_path, monkeypatch):
    """6b. 接管路径：计划已读、CAS 未写的窗口里 payload 被改 → 竞输。"""
    conn = _conn(tmp_path)
    _seed_claim(conn, "rev-r3-take", _claim_payload_text(seconds_old=1200))
    conn_b = db.connect(str(tmp_path / "slow.db"))
    calls, provider, loader, emb_fn = _dep_spy()
    core = SlowCore(conn, camera="front", max_retries=3, frame_loader=loader)

    real_claim_payload = SlowCore._claim_payload

    def racing_claim_payload(self, t_claim_us=None):
        text = real_claim_payload(self, t_claim_us)
        row = conn_b.execute(
            "SELECT payload FROM segments WHERE segment_id='rev-r3-take'"
        ).fetchone()
        doc = json.loads(row[0])
        doc["lease_epoch"] = 2          # owner/t_claim 保持不变
        conn_b.execute(
            "UPDATE segments SET payload=? WHERE segment_id='rev-r3-take'",
            (json.dumps(doc),))
        conn_b.commit()
        return text

    monkeypatch.setattr(SlowCore, "_claim_payload", racing_claim_payload)

    claimed = core.pending_reviews(recover_stale=True, stale_after_s=1)

    assert claimed == [], "旧快照接管必须竞输（不得进入本轮执行）"
    doc = json.loads(_claim_payload_json(conn, "rev-r3-take"))
    assert doc["lease_epoch"] == 2 and doc["status"] == "claiming"
    assert calls == {"provider": 0, "embedder": 0, "loader": 0}, calls
    conn.close()
    conn_b.close()


def test_valid_canonical_stale_exhausted_still_finalizes(tmp_path):
    """7. 有效 canonical 整数微秒：异实例+耗尽+过阈值 仍单轮收官。"""
    conn = _conn(tmp_path)
    _seed_claim(conn, "rev-r3-valid", _claim_payload_text(seconds_old=1200),
                retries=1)
    core = SlowCore(conn, camera="front", max_retries=1)

    stats = core.process_pending(recover_stale=True, stale_after_s=1)

    assert stats["failed"] == 1
    assert core.waterlevel()["pending"] == 0, "backlog 必须由 1 变 0"
    payload = json.loads(_claim_payload_json(conn, "rev-r3-valid"))
    assert payload["status"] == "failed"
    assert payload["error"] == "retries_exhausted"
    assert payload["final"] is True
    conn.close()


def test_valid_canonical_fresh_claim_is_protected(tmp_path):
    """8. 有效 canonical 整数微秒但未过阈值：保持 claiming、payload 不变。"""
    conn = _conn(tmp_path)
    _seed_claim(conn, "rev-r3-fresh", _claim_payload_text(seconds_old=1),
                retries=1)
    before = _claim_payload_json(conn, "rev-r3-fresh")
    core = SlowCore(conn, camera="front", max_retries=1)

    stats = core.process_pending(recover_stale=True, stale_after_s=600)

    assert stats["failed"] == 0
    assert _claim_payload_json(conn, "rev-r3-fresh") == before
    assert core.waterlevel()["pending"] == 1
    conn.close()


def test_terminal_cas_snapshot_correct_on_all_three_claim_paths(tmp_path):
    """9a. 新建认领/同实例续跑/陈旧接管：三条路径终态 CAS 快照都必须正确。"""
    conn = _conn(tmp_path)
    core = SlowCore(conn, camera="front")

    # ① 新建认领（INSERT 路径）
    _seed_segment(conn, rid="rev-r3-p1")
    stats = core.process_pending()
    assert stats["processed"] == 1 and stats["conflict"] == 0
    assert json.loads(_claim_payload_json(conn, "rev-r3-p1"))["status"] \
        in ("matched", "recorded")

    # ② 同实例续跑（快照=数据库读到的原始文本）
    _seed_claim(conn, "rev-r3-p2",
                _claim_payload_text(owner=core.instance_id, seconds_old=1),
                t0=3000.0, t1=3120.0)
    stats = core.process_pending()
    assert stats["processed"] == 1 and stats["conflict"] == 0
    assert json.loads(_claim_payload_json(conn, "rev-r3-p2"))["status"] \
        in ("matched", "recorded")

    # ③ 异实例陈旧接管（快照=接管后写入的新文本）
    _seed_claim(conn, "rev-r3-p3", _claim_payload_text(seconds_old=1200),
                t0=4000.0, t1=4120.0)
    stats = core.process_pending(recover_stale=True, stale_after_s=1)
    assert stats["processed"] == 1 and stats["conflict"] == 0
    assert json.loads(_claim_payload_json(conn, "rev-r3-p3"))["status"] \
        in ("matched", "recorded")
    conn.close()


def test_terminal_cas_conflict_rolls_back_all_tables(tmp_path, monkeypatch):
    """9b. 认领后被另一连接改动：终态 CAS 冲突，patterns/嵌入/事件文本全回滚。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, rid="rev-r3-rollback")
    conn_b = db.connect(str(tmp_path / "slow.db"))
    core = SlowCore(conn, camera="front")

    real_compute = SlowCore._compute

    def racing_compute(self, review, **kwargs):
        outcome = real_compute(self, review, **kwargs)
        row = conn_b.execute(
            "SELECT payload FROM segments WHERE segment_id=?",
            (review["review_id"],)).fetchone()
        doc = json.loads(row[0])
        doc["lease_epoch"] = 7          # 只改额外字段，owner/t_claim 不变
        conn_b.execute(
            "UPDATE segments SET payload=? WHERE segment_id=?",
            (json.dumps(doc), review["review_id"]))
        conn_b.commit()
        return outcome

    monkeypatch.setattr(SlowCore, "_compute", racing_compute)

    stats = core.process_pending()

    assert stats["conflict"] == 1, "终态 CAS 必须冲突"
    assert stats["processed"] == 0 and stats["failed"] == 0
    assert stats["retried"] == 0
    assert conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0] == 0, \
        "patterns 必须随事务回滚"
    assert conn.execute(
        "SELECT COUNT(*) FROM pattern_embeddings").fetchone()[0] == 0
    doc = json.loads(_claim_payload_json(conn, "rev-r3-rollback"))
    assert doc["lease_epoch"] == 7 and doc["status"] == "claiming"
    text = conn.execute(
        "SELECT short_name, detail FROM semantic_events"
        " WHERE semantic_event_id='rev-r3-rollback:sem'").fetchone()
    assert text["short_name"] is None and text["detail"] is None, \
        "事件文本不得在冲突事务中落库"
    conn.close()
    conn_b.close()


def test_decode_claim_snapshot_strict_type_contract():
    """补充：解析器本身的精确类型契约（bool 不是 int）。"""
    ok = SlowCore._decode_claim_snapshot(
        json.dumps({"status": "claiming", "owner": "o", "t_claim": 123}))
    assert ok == {"owner": "o", "t_claim": 123,
                  "payload": json.dumps({"status": "claiming", "owner": "o",
                                         "t_claim": 123})}
    for bad in (True, False, 1.0, "1", None, [1], {"a": 1}):
        text = json.dumps({"status": "claiming", "owner": "o",
                           "t_claim": bad})
        assert SlowCore._decode_claim_snapshot(text) is None, bad
    assert SlowCore._decode_claim_snapshot("{bad json") is None
    assert SlowCore._decode_claim_snapshot("NaN") is None
    assert SlowCore._decode_claim_snapshot(
        '{"status":"claiming","owner":"o","t_claim":NaN}') is None
    assert SlowCore._decode_claim_snapshot(None) is None
    assert SlowCore._decode_claim_snapshot("") is None


# ============ SC-B-R4：唯一 backlog 真值与坏认领可观测性 ============

_R4_CORRUPT_PAYLOADS = [
    ("bad-json", "{not json at all"),
    ("root-array", "[1, 2, 3]"),
    ("root-string", '"claiming"'),
    ("root-number", "12345"),
    ("root-bool", "true"),
    ("root-null", "null"),
    ("no-status", json.dumps({"owner": "dead"})),
    ("status-int", json.dumps({"status": 1})),
    ("status-null", json.dumps({"status": None})),
    ("status-array", json.dumps({"status": ["claiming"]})),
    ("status-object", json.dumps({"status": {"name": "claiming"}})),
    ("unknown-status", json.dumps({"status": "mystery"})),
    ("case-typo", json.dumps({"status": "Claiming"})),
    ("broken-claim", json.dumps({"status": "claiming", "owner": True,
                                 "t_claim": "1"})),
]


def _seed_r4(conn, rid, payload_text, *, camera="front", t0=1000.0,
             t1=1120.0, retries=None, with_row=True):
    """R4 播种：任意相机 + 任意 payload（含 SQL NULL / 无 segments 行）。"""
    db.open_review_segment(conn, review_id=rid, camera=camera, t_start=t0)
    db.close_review_segment(conn, rid, t_end=t1, reason="quiet")
    if with_row:
        conn.execute(
            "INSERT INTO segments (segment_id,camera,t_start,t_end,signature,"
            "detail,payload) VALUES (?,?,?,?,NULL,NULL,?)",
            (rid, camera, str(t0), str(t1), payload_text))
    if retries is not None:
        conn.execute(
            "INSERT INTO meta (key,value) VALUES (?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (f"slow:retry:{rid}", str(retries)))
    conn.commit()


def test_core_pending_covers_corrupt_payload_matrix(tmp_path):
    """1. 损坏矩阵：全部不被改写、零昂贵调用、pending 等于损坏行总数。

    未知不是完成、损坏不是清零——这些行不进入本轮执行（fail-closed），
    但必须继续暴露为 backlog（诚实可观测）。
    """
    conn = _conn(tmp_path)
    before = {}
    for index, (tag, text) in enumerate(_R4_CORRUPT_PAYLOADS):
        rid = f"rev-r4-{tag}"
        _seed_r4(conn, rid, text, t0=1000.0 + index * 500,
                 t1=1120.0 + index * 500, retries=1)
        before[rid] = _claim_payload_json(conn, rid)

    calls, provider, loader, emb_fn = _dep_spy()
    core = SlowCore(conn, camera="front", max_retries=1, frame_loader=loader)
    stats = core.process_pending(recover_stale=True, stale_after_s=1,
                                 provider=provider, emb_fn=emb_fn)

    assert stats["failed"] == 0 and stats["processed"] == 0
    assert stats["retried"] == 0 and stats["conflict"] == 0
    for rid, text in before.items():
        assert _claim_payload_json(conn, rid) == text, rid
    level = core.waterlevel()
    assert level["pending"] == len(_R4_CORRUPT_PAYLOADS)
    assert level["failed_final"] == 0
    assert calls == {"provider": 0, "embedder": 0, "loader": 0}, calls
    conn.close()


def test_core_known_terminals_exit_backlog(tmp_path):
    """2. 只有 matched/recorded/failed 三个合法终态退出 backlog。"""
    conn = _conn(tmp_path)
    for index, status in enumerate(("matched", "recorded", "failed")):
        _seed_r4(conn, f"rev-r4-term-{status}", json.dumps({"status": status}),
                 t0=1000.0 + index * 500, t1=1120.0 + index * 500)
    core = SlowCore(conn, camera="front")

    level = core.waterlevel()

    assert level["pending"] == 0
    assert level["failed_final"] == 1, "failed_final 只计合法 failed"
    conn.close()


def test_core_pending_mixed_exact_counts(tmp_path):
    """3. 混合精确计数：2 无档案 + 3 合法 claiming + 4 损坏 + 3 终态 = 9。"""
    conn = _conn(tmp_path)
    for index in range(2):
        _seed_r4(conn, f"rev-r4-norow-{index}", None,
                 t0=1000.0 + index * 10, t1=1100.0 + index * 10,
                 with_row=False)
    for index in range(3):
        _seed_r4(conn, f"rev-r4-claim-{index}",
                 _claim_payload_text(seconds_old=1),
                 t0=2000.0 + index * 10, t1=2100.0 + index * 10)
    for index, (_, text) in enumerate(_R4_CORRUPT_PAYLOADS[:4]):
        _seed_r4(conn, f"rev-r4-bad-{index}", text,
                 t0=3000.0 + index * 10, t1=3100.0 + index * 10)
    for index, status in enumerate(("matched", "recorded", "failed")):
        _seed_r4(conn, f"rev-r4-done-{index}", json.dumps({"status": status}),
                 t0=4000.0 + index * 10, t1=4100.0 + index * 10)
    core = SlowCore(conn, camera="front")

    level = core.waterlevel()

    assert level["pending"] == 2 + 3 + 4 == 9
    assert level["failed_final"] == 1
    assert SlowCore.count_pending_reviews(conn, camera=None) == 9
    conn.close()


def test_count_pending_reviews_camera_filter(tmp_path):
    """4. 相机过滤：front/back 各自精确，None 为全局之和。"""
    conn = _conn(tmp_path)
    for index in range(2):
        _seed_r4(conn, f"rev-r4-fp-{index}", "{not json",
                 t0=1000.0 + index * 10, t1=1100.0 + index * 10)
    _seed_r4(conn, "rev-r4-ft", json.dumps({"status": "matched"}),
             t0=1200.0, t1=1300.0)
    for index in range(3):
        _seed_r4(conn, f"rev-r4-bp-{index}", json.dumps({"status": "mystery"}),
                 camera="back", t0=2000.0 + index * 10, t1=2100.0 + index * 10)
    for index in range(2):
        _seed_r4(conn, f"rev-r4-bt-{index}", json.dumps({"status": "recorded"}),
                 camera="back", t0=2200.0 + index * 10, t1=2300.0 + index * 10)

    assert SlowCore.count_pending_reviews(conn, camera="front") == 2
    assert SlowCore.count_pending_reviews(conn, camera="back") == 3
    assert SlowCore.count_pending_reviews(conn, camera=None) == 5
    assert SlowCore(conn, camera="front").waterlevel()["pending"] == 2
    assert SlowCore(conn, camera="back").waterlevel()["pending"] == 3
    conn.close()


def test_pending_window_and_backlog_are_separate(tmp_path):
    """9. 处理窗口与 backlog 分离：坏认领不占 LIMIT，但仍计入 backlog。

    "是否进入本轮执行"与"是否仍计入 backlog"是两件事：坏认领不进入执行
    （fail-closed），但绝不能被抹出 backlog（那等于谎报清零）。
    """
    conn = _conn(tmp_path)
    for index in range(30):
        _seed_r4(conn, f"rev-r4-badlim-{index}", "{not json",
                 t0=1000.0 + index, t1=1005.0 + index, retries=1)
    for index in range(20):
        _seed_r4(conn, f"rev-r4-termlim-{index}",
                 json.dumps({"status": "recorded"}),
                 t0=1100.0 + index, t1=1105.0 + index)
    _seed_r4(conn, "rev-r4-live", None, t0=2000.0, t1=2120.0, with_row=False)

    core = SlowCore(conn, camera="front", max_retries=1)
    stats = core.process_pending(limit=1)

    assert stats["processed"] == 1, "唯一合法待办必须在 limit=1 窗口内拿到名额"
    assert core.waterlevel()["pending"] == 30, "30 条坏认领仍计入 backlog"
    assert json.loads(_claim_payload_json(conn, "rev-r4-live"))["status"] \
        in ("matched", "recorded")
    conn.close()


def test_count_pending_reviews_is_read_only(tmp_path):
    """10. 只读与事务边界：不开事务、不 commit、不改任何表、不接慢依赖。"""
    conn = _conn(tmp_path)
    _seed_r4(conn, "rev-r4-ro-claim", _claim_payload_text(seconds_old=1),
             t0=1000.0, t1=1120.0)
    _seed_r4(conn, "rev-r4-ro-bad", "{not json", t0=2000.0, t1=2120.0)
    calls, provider, loader, emb_fn = _dep_spy()

    def digest():
        return (
            conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(COALESCE(payload,''))),0)"
                " FROM segments").fetchone()[:],
            conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(COALESCE(payload,''))),0)"
                " FROM review_segments").fetchone()[:],
            conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(COALESCE(value,''))),0)"
                " FROM meta").fetchone()[:],
            conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0],
            conn.execute(
                "SELECT COUNT(*) FROM pattern_embeddings").fetchone()[0],
        )

    before = digest()
    changes_before = conn.total_changes
    assert conn.in_transaction is False

    # 类方法可直接用裸连接调用——不需要 SlowCore 实例，也就无从接慢依赖
    assert SlowCore.count_pending_reviews(conn) == 2
    assert SlowCore.count_pending_reviews(conn, camera="front") == 2
    assert SlowCore.count_pending_reviews(conn, camera="back") == 0
    assert SlowCore.count_pending_reviews(conn, camera=None) == 2

    assert conn.in_transaction is False, "统一统计不得开启事务"
    assert conn.total_changes == changes_before, "统一统计不得修改任何行"
    assert digest() == before
    assert calls == {"provider": 0, "embedder": 0, "loader": 0}, calls
    conn.close()
