"""SC-B：linux_slow_path 薄适配器测试。

本文件只测试兼容适配器——canonical 慢处理合同由 test_slow_core /
test_slow_worker / test_slow_embed / test_slow_feedback 覆盖。
"""

import json
import time

import pytest

import scam.db as db
from scam import linux_slow_path


def _conn(tmp_path):
    conn = db.connect(str(tmp_path / "slow.db"))
    db.init_schema(conn)
    return conn


def _seed_segment(conn, rid, camera="front", t0=1000.0, t1=1120.0,
                  cls="person", zone="z1"):
    db.open_review_segment(conn, review_id=rid, camera=camera, t_start=t0)
    db.close_review_segment(conn, rid, t_end=t1, reason="quiet")
    db.open_tracked_object(conn, object_id=f"{rid}:obj", camera=camera,
                           t_start=t0 + 10, cls=cls, zones=[zone])
    db.close_tracked_object(conn, f"{rid}:obj", t_end=t1 - 10, reason="gone")
    db.open_semantic_event(
        conn, semantic_event_id=f"{rid}:sem", camera=camera, review_id=rid,
        object_id=f"{rid}:obj", t_start=t0 + 20, template="enter-dwell",
        zone_id=zone, cls=cls)
    db.close_semantic_event(conn, f"{rid}:sem", t_end=t1 - 5, reason="left")
    conn.commit()


# ---------- 端到端：适配器 → SlowCore → canonical 数据库结果 ----------

def test_adapter_reaches_canonical_end_state(tmp_path):
    """真实 SQLite 端到端：run_once 落 canonical 终态（段档案+模式+空文本）。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-a")

    stats = linux_slow_path.run_once(conn)

    assert stats["processed"] == 1
    seg = conn.execute(
        "SELECT json_extract(payload,'$.status') AS st FROM segments"
        " WHERE segment_id='rev-a'").fetchone()
    assert seg["st"] in ("recorded", "matched"), "canonical 终态必须落 segment"
    assert conn.execute(
        "SELECT COUNT(*) FROM patterns").fetchone()[0] == 1
    enriched = conn.execute(
        "SELECT short_name, detail FROM semantic_events"
        " WHERE semantic_event_id='rev-a:sem'").fetchone()
    assert enriched["short_name"], "canonical 空文本补充必须生效"
    conn.close()


def test_adapter_stat_fields_are_fixed_and_non_negative(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-s")
    stats = linux_slow_path.run_once(conn)
    assert tuple(stats.keys()) == linux_slow_path.STAT_FIELDS
    for key, value in stats.items():
        assert isinstance(value, int) and value >= 0, key
    assert stats["new_patterns"] == 1
    assert stats["backlog"] == 0
    conn.close()


def test_adapter_is_idempotent_single_canonical_execution(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-i")
    first = linux_slow_path.run_once(conn)
    second = linux_slow_path.run_once(conn)
    assert first["processed"] == 1
    assert second["processed"] == 0, "第二次不得重复 canonical 执行"
    assert conn.execute(
        "SELECT COUNT(*) FROM segments").fetchone()[0] == 1
    conn.close()


# ---------- 参数翻译与校验 ----------

def test_adapter_parameter_validation(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-v")
    with pytest.raises(ValueError):
        linux_slow_path.run_once(conn, limit=0)
    with pytest.raises(ValueError):
        linux_slow_path.run_once(conn, limit=linux_slow_path.MAX_LIMIT + 1)
    with pytest.raises(ValueError):
        linux_slow_path.run_once(conn, max_attempts=0)
    with pytest.raises(ValueError):
        linux_slow_path.run_once(conn, stale_after_s=-1)
    with pytest.raises(ValueError):
        linux_slow_path.run_once(conn, environment="不是字典")
    conn.close()


def test_adapter_connection_lifecycle_and_transaction_guard(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-c")
    linux_slow_path.run_once(conn)
    # 连接由调用方持有：适配器不关闭
    assert conn.execute("SELECT 1").fetchone()[0] == 1
    # 外层事务 fail-closed
    conn.execute("INSERT INTO meta (key,value) VALUES ('caller:a','1')")
    with pytest.raises(ValueError):
        linux_slow_path.run_once(conn)
    conn.rollback()
    conn.close()


def test_adapter_recover_stale_passes_through(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-r")
    owner = linux_slow_path.run_once(conn)
    assert owner["processed"] == 1

    # 造一个异实例陈旧认领：直接写 claiming 行（模拟崩溃残留）
    _seed_segment(conn, "rev-r2", t0=5000.0, t1=5120.0)
    conn.execute(
        "INSERT INTO segments (segment_id,camera,t_start,t_end,signature,"
        "detail,payload) VALUES ('rev-r2','front',5000.0,5120.0,NULL,NULL,?)",
        (json.dumps({"status": "claiming", "owner": "dead-worker",
                     "t_claim": int((time.time() - 1200) * 1e6)}),))
    conn.commit()
    conservative = linux_slow_path.run_once(conn)          # 默认不接管
    assert conservative["processed"] == 0
    recovered = linux_slow_path.run_once(conn, recover_stale=True)
    assert recovered["processed"] == 1, "显式 recover_stale 必须接管陈旧认领"
    conn.close()


def test_adapter_vlm_bridge_calls_once(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-n")
    calls = {"n": 0}

    def fake_vlm(seg, keyframes):
        calls["n"] += 1
        return {"short_name": "适配器命名"}

    stats = linux_slow_path.run_once(conn, vlm=fake_vlm)
    assert calls["n"] == 1, "桥接至多一次调用"
    assert stats["vlm_calls"] == 1
    row = conn.execute("SELECT name FROM patterns").fetchone()
    assert row[0] == "适配器命名"
    # 第二轮：T2a 命中，零新调用
    _seed_segment(conn, "rev-n2", t0=9000.0, t1=9120.0)
    second = linux_slow_path.run_once(conn, vlm=fake_vlm)
    assert calls["n"] == 1, "T2a 命中不得再次调用 VLM"
    assert second["pattern_hits"] == 1
    conn.close()


def test_adapter_embedder_bridge_calls_once(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-e")
    # 造证据帧（bridge 仅在存在安全证据帧时被调用）
    import cv2
    import numpy as np
    frame = np.zeros((16, 16, 3), dtype=np.uint8)
    ok, encoded = cv2.imencode(".jpg", frame)
    assert ok
    rel = "front/rev-e.jpg"
    evidence_dir = tmp_path / "evidence" / "front"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (tmp_path / "evidence" / rel).write_bytes(encoded.tobytes())
    conn.execute(
        "INSERT INTO evidence_assets"
        " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
        "  t_start,t_end,score,size_bytes,sha256,created_at,updated_at,"
        "  metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("best:rev-e", "tracked_object", "rev-e:obj", "front",
         "clean_best_frame", rel, "available", "image/jpeg",
         1050.0, None, 1.0, len(encoded.tobytes()), "0" * 64,
         1000.0, 1000.0, "{}"))
    conn.commit()
    calls = {"n": 0}

    def fake_embedder(frames):
        calls["n"] += 1
        return [0.1, 0.2, 0.3, 0.4]

    linux_slow_path.run_once(conn, embedder=fake_embedder)
    assert calls["n"] == 1, "桥接至多一次调用"
    conn.close()


def test_adapter_core_failure_is_honest(tmp_path, monkeypatch):
    """SlowCore 失败时适配器如实失败：不吞、不重试、不另起第二实现。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-f")

    from scam.slow_core import SlowCore
    calls = {"n": 0}

    def boom(self, **kwargs):
        calls["n"] += 1
        raise RuntimeError("canonical failure")

    monkeypatch.setattr(SlowCore, "process_pending", boom)
    with pytest.raises(RuntimeError):
        linux_slow_path.run_once(conn)
    assert calls["n"] == 1, "失败必须原样上抛（不重试）"
    conn.close()


# ---------- 静态边界：无独立写状态机 ----------

def test_adapter_source_has_no_write_state_machine():
    import inspect
    source = inspect.getsource(linux_slow_path)
    for forbidden in ("INSERT INTO", "UPDATE segments", "UPDATE semantic",
                      "DELETE FROM", "BEGIN IMMEDIATE", "save_pattern",
                      "delete_pattern", "def _transaction", "def _plan_items",
                      "def _claim_item", "def _finalize_exhausted",
                      "def _record_failure", "def _write_segment",
                      "def _enrich_event_text"):
        assert forbidden not in source, forbidden
    # 允许的 SQL 只有两处只读 SELECT（相机列表 + backlog 汇总）
    assert source.count(".execute(") == 2
    assert "SELECT DISTINCT camera" in source
    assert "SELECT COUNT(*)" in source


def test_adapter_has_no_network_or_subprocess_side_effects():
    import inspect
    source = inspect.getsource(linux_slow_path)
    for forbidden in ("urllib", "requests", "subprocess", "socket",
                      "http.client"):
        assert forbidden not in source, forbidden


# ============ SC-B-R1：适配器全局预算 / 帧桥接 / 阈值翻译 ============


def _seed_two_cameras(conn):
    _seed_segment(conn, "rev-f", camera="front")
    _seed_segment(conn, "rev-b", camera="back", t0=5000.0, t1=5120.0)


def _finalized_count(conn):
    return conn.execute(
        "SELECT COUNT(*) FROM segments"
        " WHERE json_extract(payload,'$.status') IN"
        " ('recorded','matched','failed')").fetchone()[0]


def test_global_limit_across_two_cameras(tmp_path):
    """P0-A：limit=1 全局预算——两相机合计至多一项进入 canonical 处理。"""
    conn = _conn(tmp_path)
    _seed_two_cameras(conn)

    stats = linux_slow_path.run_once(conn, limit=1)

    consumed = (stats["processed"] + stats["retried"]
                + stats["failed"] + stats["claimed"] * 0)
    assert stats["processed"] <= 1, stats
    assert _finalized_count(conn) == 1, "数据库最多一条段进入终态"
    assert stats["backlog"] == 1, "另一条必须仍在 backlog（全相机汇总）"
    conn.close()


def test_limit_two_processes_both_cameras(tmp_path):
    conn = _conn(tmp_path)
    _seed_two_cameras(conn)
    stats = linux_slow_path.run_once(conn, limit=2)
    assert stats["processed"] == 2
    assert _finalized_count(conn) == 2
    assert stats["backlog"] == 0
    conn.close()


def test_budget_flows_when_first_camera_empty(tmp_path):
    """第一台相机无可执行项时，预算可流向第二台。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-b", camera="back", t0=5000.0, t1=5120.0)
    stats = linux_slow_path.run_once(conn, limit=1)
    assert stats["processed"] == 1, "预算必须流向有工作的相机"
    conn.close()


def test_retry_consumes_global_budget(tmp_path, monkeypatch):
    """第一台相机产生 retry 时同样消耗预算：后续相机不得突破上限。"""
    conn = _conn(tmp_path)
    _seed_two_cameras(conn)

    from scam.slow_core import SlowCore
    orig = SlowCore._persist_terminal

    # 相机按字母序处理：back 先于 front —— 让第一台（back）失败
    def flaky(self, review, **kw):
        if review["camera"] == "back":
            raise OSError("back 持久化失败")
        return orig(self, review, **kw)

    monkeypatch.setattr(SlowCore, "_persist_terminal", flaky)
    stats = linux_slow_path.run_once(conn, limit=1)
    monkeypatch.undo()

    assert stats["retried"] == 1
    assert stats["processed"] == 0, "预算已被第一台的 retry 消耗"
    front = conn.execute(
        "SELECT COUNT(*) FROM segments WHERE camera='front'").fetchone()[0]
    assert front == 0, "后续相机不得突破全局上限"
    conn.close()


def _seed_segment_with_frame(tmp_path, conn, rid):
    import cv2
    import numpy as np
    _seed_segment(conn, rid)
    frame = np.zeros((16, 16, 3), dtype=np.uint8)
    frame[:, :, 1] = 200
    ok, encoded = cv2.imencode(".jpg", frame)
    assert ok
    rel = f"front/{rid}.jpg"
    target = tmp_path / "evidence" / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(encoded.tobytes())
    conn.execute(
        "INSERT INTO evidence_assets"
        " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
        "  t_start,t_end,score,size_bytes,sha256,created_at,updated_at,"
        "  metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (f"best:{rid}", "tracked_object", f"{rid}:obj", "front",
         "clean_best_frame", rel, "available", "image/jpeg",
         1050.0, None, 1.0, len(encoded.tobytes()), "0" * 64,
         1000.0, 1000.0, "{}"))
    conn.commit()


def test_legacy_vlm_receives_real_frames(tmp_path):
    """P1-A：旧 vlm 收到实际 BGR 帧（不是 base64 字符串、不是空表）。"""
    import numpy as np
    conn = _conn(tmp_path)
    _seed_segment_with_frame(tmp_path, conn, "rev-kf")
    seen = {}

    def fake_vlm(seg, keyframes):
        seen["frames"] = keyframes
        seen["seg"] = seg
        return {"short_name": "带帧命名"}

    stats = linux_slow_path.run_once(conn, vlm=fake_vlm)

    assert stats["vlm_calls"] == 1
    frames = seen["frames"]
    assert len(frames) == 1, f"旧 VLM 必须收到一张实际帧，收到 {len(frames)}"
    assert isinstance(frames[0], np.ndarray), "元素必须是图像数组"
    assert seen["seg"].get("segment_id") == "rev-kf"
    conn.close()


def test_legacy_vlm_frames_capped_at_three(tmp_path):
    import cv2
    import numpy as np
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-cap")
    for index in range(5):
        oid = f"rev-cap:o{index}"
        db.open_tracked_object(conn, object_id=oid, camera="front",
                               t_start=1040.0 + index, cls="person",
                               zones=["z1"])
        db.close_tracked_object(conn, oid, t_end=1100.0, reason="gone")
        frame = np.zeros((8, 8, 3), dtype=np.uint8)
        ok, encoded = cv2.imencode(".jpg", frame)
        assert ok
        rel = f"front/rev-cap-{index}.jpg"
        target = tmp_path / "evidence" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(encoded.tobytes())
        conn.execute(
            "INSERT INTO evidence_assets"
            " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
            "  t_start,t_end,score,size_bytes,sha256,created_at,updated_at,"
            "  metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"best:rev-cap:{index}", "tracked_object", oid, "front",
             "clean_best_frame", rel, "available", "image/jpeg",
             1050.0 + index, None, 1.0, len(encoded.tobytes()), "0" * 64,
             1000.0, 1000.0, "{}"))
    conn.commit()
    seen = {}

    def fake_vlm(seg, keyframes):
        seen["n"] = len(keyframes)
        return {"short_name": "翻页"}

    linux_slow_path.run_once(conn, vlm=fake_vlm)
    assert seen["n"] <= 3, "旧 VLM 最多收到三帧"
    conn.close()


def test_legacy_vlm_decode_failure_degrades_without_retry(tmp_path, monkeypatch):
    """帧编码/解码失败：不重读路径、不重复调用 VLM、不阻塞终态。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-bad")
    # 安全 loader 返回一个不可编码对象（模拟帧损坏）——编码阶段失败 →
    # frames_b64 为空 → 旧 VLM 收到空列表并继续诚实降级
    from scam.slow_core import SlowCore

    def bad_loader(refs, context):
        return [object()]

    calls = {"n": 0, "frames": None}

    def fake_vlm(seg, keyframes):
        calls["n"] += 1
        calls["frames"] = keyframes
        return {"short_name": "降级名"}

    # 直接经 SlowCore 注入 loader（适配器 run_once 的 frame_loader 透传）
    stats = linux_slow_path.run_once(conn, vlm=fake_vlm,
                                     frame_loader=bad_loader)
    # 无证据资产时 loader 不被调用——本用例经 slow_core 直接验证：
    core = SlowCore(conn, camera="front", frame_loader=bad_loader)
    _seed_segment_with_frame(tmp_path, conn, "rev-bad2")

    class _Provider:
        name = "rec"

        def understand(self, prompt, frames_b64, context=None):
            calls["n"] += 1
            calls["frames"] = frames_b64
            return "命名"

    stats2 = core.process_pending(provider=_Provider())
    assert stats2["processed"] == 1
    assert stats2["retried"] == 0, "帧故障不得进入 retry"
    assert calls["n"] == 1, "VLM 至多一次（空帧仍调用一次）"
    conn.close()


def test_t2a_hit_has_zero_new_vlm_calls(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment_with_frame(tmp_path, conn, "rev-t2a")
    calls = {"n": 0}

    def fake_vlm(seg, keyframes):
        calls["n"] += 1
        return {"short_name": "第一段名"}

    linux_slow_path.run_once(conn, vlm=fake_vlm)
    assert calls["n"] == 1
    _seed_segment_with_frame(tmp_path, conn, "rev-t2b")
    # rev-t2b 是新段但同签名——需要独立证据资产路径
    stats = linux_slow_path.run_once(conn, vlm=fake_vlm)
    assert stats["pattern_hits"] == 1
    assert calls["n"] == 1, "T2a 命中后 VLM 零新增调用"
    conn.close()


# ---------- P1-B：阈值翻译 ----------

def _seed_stale_foreign_claim(conn, rid, seconds_old=2.0):
    _seed_segment(conn, rid, t0=9000.0, t1=9120.0)
    conn.execute(
        "INSERT INTO segments (segment_id,camera,t_start,t_end,signature,"
        "detail,payload) VALUES (?,?,?,?,NULL,NULL,?)",
        (rid, "front", 9000.0, 9120.0,
         json.dumps({"status": "claiming", "owner": "dead-worker",
                     "t_claim": int((time.time() - seconds_old) * 1e6)})))
    conn.commit()


def test_stale_threshold_forwarded_allows_takeover(tmp_path):
    """stale_after_s=1 且 2 秒前认领：允许接管并处理。"""
    conn = _conn(tmp_path)
    _seed_stale_foreign_claim(conn, "rev-st1", seconds_old=2.0)
    stats = linux_slow_path.run_once(conn, recover_stale=True,
                                     stale_after_s=1)
    assert stats["processed"] == 1, "超过传入阈值必须允许接管"
    conn.close()


def test_stale_threshold_forwarded_blocks_takeover(tmp_path):
    """stale_after_s=10 且仅 2 秒前：不得接管。"""
    conn = _conn(tmp_path)
    _seed_stale_foreign_claim(conn, "rev-st2", seconds_old=2.0)
    stats = linux_slow_path.run_once(conn, recover_stale=True,
                                     stale_after_s=10)
    assert stats["processed"] == 0, "未超阈值不得接管"
    conn.close()


def test_recover_stale_false_never_takes_over_small_threshold(tmp_path):
    conn = _conn(tmp_path)
    _seed_stale_foreign_claim(conn, "rev-st3", seconds_old=2.0)
    stats = linux_slow_path.run_once(conn, recover_stale=False,
                                     stale_after_s=0.1)
    assert stats["processed"] == 0, "recover_stale=False 无论阈值多小都不得接管"
    conn.close()


def test_stale_argument_validation_before_any_write(tmp_path):
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-val")
    before = conn.execute(
        "SELECT COUNT(*) FROM segments").fetchone()[0]
    for bad in (float("nan"), float("inf"), float("-inf"), True, 0, -1,
                "1"):
        with pytest.raises(ValueError):
            linux_slow_path.run_once(conn, stale_after_s=bad)
    after = conn.execute(
        "SELECT COUNT(*) FROM segments").fetchone()[0]
    assert after == before, "非法阈值必须在任何数据库写入前拒绝"
    conn.close()


# ---------- SC-B-R2：适配器入口的耗尽收官 ----------

def test_adapter_stale_exhausted_finalizes_in_one_round(tmp_path):
    """旧异实例耗尽认领超传入阈值：run_once 单轮直接 failed，backlog 归零。"""
    conn = _conn(tmp_path)
    _seed_segment(conn, "rev-adx", t0=9000.0, t1=9120.0)
    conn.execute(
        "INSERT INTO segments (segment_id,camera,t_start,t_end,signature,"
        "detail,payload) VALUES ('rev-adx','front',9000.0,9120.0,NULL,"
        "NULL,?)",
        (json.dumps({"status": "claiming", "owner": "dead-worker",
                     "t_claim": int((time.time() - 1200) * 1e6)}),))
    conn.execute(
        "INSERT INTO meta (key,value) VALUES ('slow:retry:rev-adx','3')")
    conn.commit()

    stats = linux_slow_path.run_once(conn, recover_stale=True,
                                     stale_after_s=1, max_attempts=3)

    assert stats["failed"] == 1, f"单轮必须直接收官: {stats}"
    assert stats["backlog"] == 0, "backlog 必须归零（不得再等一个陈旧周期）"
    payload = json.loads(conn.execute(
        "SELECT payload FROM segments WHERE segment_id='rev-adx'"
    ).fetchone()[0])
    assert payload["status"] == "failed"
    assert payload["error"] == "retries_exhausted"
    conn.close()
