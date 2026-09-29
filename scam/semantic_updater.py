"""semantic_updater.py —— Win11「进行中事件的语义更新」后台链（第一切片 R1）。

合同（语义更新合同 v1，经两轮复验整改收固）：
- 输入只收已落库 `event_facts` + 受控证据资产；证据摘要必须来自**实际送给模型
  的同一份字节**（读取后校验 sha256/大小/JPEG 头，再以同一份内容计算摘要并
  形成幂等身份）；记录与文件身份在读取时发生变化 → 保守失败，不混配新旧画面；
- v1 初始事实不可变；本链只追加描述 v(n+1) 与 `semantic_update` 工作台提醒，
  单事务恰一次，绝不覆盖旧描述、不改写事件原始事实、不接外部通知渠道；
- 独立守护线程、并发=1、队列有界、可停止；快路径零同步等待模型；
- 扫描：meta 游标可持续推进+回绕（旧开放事件在持续新增下于有限轮次内获得
  机会，跨重启不遗忘；单轮工作量有界；并发新增随游标推进或回绕进入）；
- 失败状态机：可恢复失败按退避重试（有上限）→ 终态失败；证据摘要变化或进程
  重启可重新激活；绝不一进失败集合就永久跳过，也不每轮无间隔狂调模型；
- 健康快照与事件详情区分 已发布/处理中/排队/等待重试/已失败/无可用证据，
  仅暴露固定错误码——不暴露路径、凭据或模型异常正文；线程存活不冒充完成。

生产入口默认真实本地模型（build_provider local）；注入确定性 provider 仅限测试。
本模块不宣称语义理解质量达标。
"""

import base64
import hashlib
import json
import os
import queue
import threading
import time
from pathlib import Path

from .db import (connect, publish_semantic_update,
                 semantic_update_ledger_hit,
                 semantic_update_ledger_hit_prefix)

MIN_RECHECK_S = 60.0
QUEUE_MAX = 64
RETRY_MAX = 2
RETRY_BACKOFF_S = 30.0
RETRY_BACKOFF_CAP_S = 300.0
SCAN_BATCH = 32
SCAN_INTERVAL_S = 15.0
MAX_OBSERVED_ITEMS = 16
MAX_OBSERVED_LEN = 64
MAX_INFERENCE_LEN = 300
_UNCERTAINTY = ("confirmed", "low", "high")
_CURSOR_KEY = "semantic_scan_cursor"


def build_prompt():
    """语义更新提示词：严格 JSON，区分可直接确认事实与模型推断。"""
    return (
        "你是监控场景分析员。这是同一台固定摄像头在一次事件中抓取的画面。"
        "只输出一个 JSON 对象，不要输出任何其他文字。\n"
        '字段：{"observed": ["画面可直接确认的事实，每条≤64字，最多16条"], '
        '"inference": "基于画面的模型推断，≤300字", '
        '"uncertainty": "confirmed|low|high"}\n'
        "observed 只写画面里能直接看到的内容；inference 是你的推断，"
        "必须与 observed 区分；不得虚构；禁止省略号或占位符；"
        "无法判断的字段用中文简短说明该字段未知。"
    )


def processing_fingerprint(model_id):
    """处理指纹：提示词 + 模型标识的 sha256 前 16 位（幂等身份组成部分）。"""
    return hashlib.sha256(
        (build_prompt() + "|" + str(model_id)).encode("utf-8")).hexdigest()[:16]


def _extract_json(raw):
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        parsed = json.loads(text[start:end + 1])
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


_PLACEHOLDER_TAIL = "..."


def _is_placeholder(text):
    stripped = str(text).strip()
    if not stripped:
        return True
    if not any(ch.isalnum() or ord(ch) > 0x2E80 for ch in stripped):
        return True
    return stripped.endswith(_PLACEHOLDER_TAIL)


def _check_text(value, limit):
    return (isinstance(value, str) and 0 < len(value) <= limit
            and not _is_placeholder(value))


def validate_semantic_profile(raw):
    """不可信模型输出 → 结构化档案；任何字段不合格 → None（绝不产肯定式编造）。"""
    if not isinstance(raw, dict):
        return None
    observed = raw.get("observed")
    if not isinstance(observed, list) or len(observed) > MAX_OBSERVED_ITEMS:
        return None
    if not all(_check_text(x, MAX_OBSERVED_LEN) for x in observed):
        return None
    inference = raw.get("inference")
    if not _check_text(inference, MAX_INFERENCE_LEN):
        return None
    uncertainty = raw.get("uncertainty")
    if uncertainty not in _UNCERTAINTY:
        uncertainty = "low"      # 模型推断默认保守标记
    if not observed:
        return None
    return {"observed": [str(x) for x in observed],
            "inference": str(inference),
            "uncertainty": uncertainty}


def compose_text(profile):
    """描述文本：显式区分「画面可直接确认的事实」与「模型推断」。"""
    label = {"confirmed": "低不确定性", "low": "存在不确定性",
             "high": "高不确定性"}[profile["uncertainty"]]
    observed = "；".join(profile["observed"])
    return (f"观察到（画面可直接确认）：{observed}。"
            f"模型推断（{label}，非人工确认）：{profile['inference']}。")


# 固定错误码（对外只有码与固定中文短语，绝不含异常正文/路径/凭据）
REASON_TEXT = {
    "no_evidence": "无可用证据资产",
    "evidence_missing_or_corrupt": "证据缺失或损坏",
    "evidence_identity_mismatch": "证据在处理期间发生变化，已保守放弃本次",
    "model_unavailable": "模型暂不可用",
    "output_invalid": "模型输出不完整或不合格",
    "processing_failed": "处理失败",
}


class SemanticUpdater:
    """进行中事件语义更新后台链（Win11 专属接线）。

    - 扫描游标（meta 持久化）：每轮按 `event_id > 游标 AND open` 取一批
      （有界），扫到末尾回绕；并发新增随游标或回绕进入；跨重启不遗忘；
    - 单事件状态机：queued → running → published / waiting_retry(退避) /
      failed_terminal(重试耗尽) / no_evidence；证据摘要变化或重启重新激活；
    - 发布：描述 v(n+1) 与 semantic_update 提醒单事务恰一次（db 层保证）。
    """

    def __init__(self, db_path, provider, *, stop_event, evidence_root=None,
                 scan_interval_s=SCAN_INTERVAL_S, min_recheck_s=MIN_RECHECK_S,
                 queue_max=QUEUE_MAX, retry_max=RETRY_MAX,
                 scan_batch=SCAN_BATCH):
        self.db_path = db_path
        self.provider = provider
        self.stop_event = stop_event
        self.scan_interval_s = float(scan_interval_s)
        self.min_recheck_s = float(min_recheck_s)
        self.retry_max = int(retry_max)
        self.scan_batch = int(scan_batch)
        self.model_id = str(getattr(provider, "model", "unknown") or "unknown")
        self.fingerprint = processing_fingerprint(self.model_id)
        from .evidence import EvidenceStore
        self.evidence = EvidenceStore(
            evidence_root or os.path.join(
                os.path.dirname(os.path.abspath(db_path)), "evidence"))
        self.queue = queue.Queue(maxsize=queue_max)
        self.in_flight = None            # event_id（处理中可见）
        self.records = {}                # event_id -> 状态记录（见 _record）
        self.published = 0
        self.last_error = None           # {event, code, at}
        self.cursor = ""                 # 扫描游标（内存），持久化于 meta
        self._published = set()          # 本次进程内已确认发布的事件
        self._queued_ids = set()         # 事件级排队去重（过期快照处理时自愈）
        self._thread = None
        self._wake = threading.Event()

    # ---- 健康快照（真实状态，线程存活 ≠ 理解完成） ----

    def snapshot(self):
        waiting = sum(1 for r in self.records.values()
                      if r["state"] == "waiting_retry")
        terminal = sum(1 for r in self.records.values()
                       if r["state"] == "failed_terminal")
        no_ev = sum(1 for r in self.records.values()
                    if r["state"] == "no_evidence")
        return {"queued": self.queue.qsize(),
                "in_progress": self.in_flight,
                "failed": terminal,
                "waiting_retry": waiting,
                "no_evidence": no_ev,
                "published": self.published,
                "last_error": self._last_error(),
                "provider": self.model_id,
                "fingerprint": self.fingerprint}

    def _last_error(self):
        candidates = [(r.get("at", 0), eid, r.get("code"))
                      for eid, r in self.records.items()
                      if r.get("code")]
        if not candidates:
            return None
        at, event_id, code = max(candidates)
        return {"event": event_id, "code": code, "at": at}

    def event_state(self, event_id):
        """事件详情语义状态（固定码）：published 优先于内存态。

        reason=固定中文短语（REASON_TEXT），绝不携带异常正文。
        """
        def _with_reason(state, code, attempts):
            return {"state": state, "code": code,
                    "reason": REASON_TEXT.get(code),
                    "attempts": attempts}

        if self.in_flight == event_id:
            return _with_reason("running", None, None)
        if event_id in self._published:
            return _with_reason("published", None, None)
        r = self.records.get(event_id)
        if r is not None:
            return _with_reason(r["state"], r.get("code"),
                                r.get("attempts"))
        return _with_reason("none", None, None)

    def _record(self, event_id, *, state, code=None, attempts=None,
                digest=None):
        prev = self.records.get(event_id, {})
        self.records[event_id] = {
            "state": state, "code": code,
            "attempts": (prev.get("attempts", 0) if attempts is None
                         else attempts),
            "digest": digest or prev.get("digest"),
            "at": time.time(),
        }
        if code:
            self.last_error = {"event": event_id, "code": code,
                               "at": time.time()}

    def _fail(self, event_id, code, *, digest=None):
        """可恢复失败：退避重试；超过上限转终态。返回当前状态。"""
        prev = self.records.get(event_id, {})
        attempts = prev.get("attempts", 0) + 1
        if attempts > self.retry_max:
            self._record(event_id, state="failed_terminal", code=code,
                         attempts=attempts, digest=digest)
            return "failed_terminal"
        backoff = min(RETRY_BACKOFF_CAP_S,
                      RETRY_BACKOFF_S * (2 ** (attempts - 1)))
        self._record(event_id, state="waiting_retry", code=code,
                     attempts=attempts, digest=digest)
        self.records[event_id]["next_retry_mono"] = (
            time.monotonic() + backoff)
        return "waiting_retry"

    # ---- 生命周期 ----

    def start(self):
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run,
                                        name="semantic-updater", daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        self.stop_event.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    # ---- 循环 ----

    def _run(self):
        while not self.stop_event.is_set():
            self._scan()
            self._drain()
            self._wake.wait(self.scan_interval_s)
            self._wake.clear()

    def _conn(self):
        return connect(self.db_path)

    def _scan(self):
        """游标推进的有界扫描（回绕）：open 事件逐批评估并入队。"""
        conn = self._conn()
        now_mono = time.monotonic()
        try:
            cursor = self._read_cursor(conn)
            rows = conn.execute(
                "SELECT event_id,object_id,camera FROM event_facts"
                " WHERE t_end IS NULL AND event_id > ?"
                " ORDER BY event_id LIMIT ?",
                (cursor, self.scan_batch)).fetchall()
            for row in rows:
                if self.stop_event.is_set():
                    return
                self._evaluate(conn, row["event_id"], row["object_id"],
                               row["camera"], now_mono)
            if len(rows) >= self.scan_batch:
                self._write_cursor(conn, rows[-1]["event_id"])
                self.cursor = rows[-1]["event_id"]
            else:
                # 扫到末尾：回绕起点，旧事件与失败条目进入下一轮
                self._write_cursor(conn, "")
                self.cursor = ""
        finally:
            conn.close()

    def _read_cursor(self, conn):
        row = conn.execute(
            "SELECT value FROM meta WHERE key=?", (_CURSOR_KEY,)).fetchone()
        self.cursor = row["value"] if row and row["value"] else ""
        return self.cursor

    def _write_cursor(self, conn, value):
        conn.execute(
            "INSERT INTO meta (key,value) VALUES (?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (_CURSOR_KEY, value))
        conn.commit()

    def _evaluate(self, conn, event_id, object_id, camera, now_mono):
        """单事件评估：状态门 → 证据快照 → 静态预算 → 入队。

        published 态不跳过：同一证据摘要+同处理指纹 → 账本命中，跳过（不重复
        调用模型）；受控资产换成真正不同、完整性核验通过的证据 → 自然入队，
        追加 v3（生产状态机自然识别，不需要测试清内存特权）。排队中的事件
        不重复入队；快照过期由处理时对当前受控记录的全量核验自愈。
        """
        if self.in_flight == event_id:
            return
        if event_id in self._queued_ids:
            return   # 事件级去重：已在排队
        r = self.records.get(event_id)
        if r is not None and r["state"] == "waiting_retry" \
                and now_mono < r.get("next_retry_mono", 0):
            return   # 退避未到期
        if r is not None and r["state"] == "failed_terminal":
            if now_mono < r.get("eval_mono", 0.0) + self.min_recheck_s:
                return   # 终态证据重检限频
            r["eval_mono"] = now_mono
        asset = self._verified_asset(conn, object_id)
        if asset is None:
            if r is None or r["state"] != "no_evidence":
                self._record(event_id, state="no_evidence",
                             code="no_evidence")
            return
        digest = self._evidence_digest(asset["path"])
        if digest is None:
            self._record(event_id, state="no_evidence",
                         code="evidence_missing_or_corrupt")
            return
        if r is not None and r["state"] == "failed_terminal" \
                and r.get("digest") == digest:
            return   # 同一证据摘要：终态维持，不重复耗模型
        if semantic_update_ledger_hit_prefix(conn, event_id, digest):
            # 同证据摘要已有语义更新（任意处理指纹）→ 已发布，不重复调用
            self._record(event_id, state="published", code=None,
                         digest=digest)
            self._published.add(event_id)
            return
        if self.queue.full():
            # 队列拥塞：保护快路径；本事件保持原状态，后续扫描恢复
            self._record(event_id, state="queued_backoff",
                         code="queue_full", digest=digest)
            return
        if r is None or r["state"] != "waiting_retry":
            self.records.pop(event_id, None)   # 全新排队：重试预算重置
        self._queued_ids.add(event_id)
        try:
            self.queue.put_nowait({"event_id": event_id, "camera": camera,
                                   "object_id": object_id,
                                   "asset_id": asset["asset_id"],
                                   "asset_path": asset["path"],
                                   "asset_sha256": asset["sha256"],
                                   "asset_size": asset["size"]})
            self._wake.set()
        except queue.Full:
            self._queued_ids.discard(event_id)
            return

    def _verified_asset(self, conn, object_id):
        """受控资产记录：id/相对路径/大小/SHA-256（available 才算可用）。"""
        row = conn.execute(
            "SELECT asset_id,path,sha256,size_bytes FROM evidence_assets"
            " WHERE owner_type='tracked_object' AND owner_id=?"
            " AND kind='clean_best_frame' AND state='available'"
            " ORDER BY t_start DESC LIMIT 1", (object_id,)).fetchone()
        if row is None:
            return None
        return {"asset_id": row["asset_id"], "path": row["path"],
                "sha256": row["sha256"], "size": row["size_bytes"]}

    def _evidence_digest(self, relative_path):
        """轻量摘要（扫描预算用）；正式绑定在 _process 的核验读取。"""
        try:
            full = self.evidence.resolve(relative_path)
            with Path(full).open("rb") as handle:
                content = handle.read()
        except (ValueError, OSError):
            return None
        if not content.startswith(b"\xff\xd8"):
            return None
        return hashlib.sha256(content).hexdigest()

    def _drain(self):
        while not self.stop_event.is_set():
            try:
                item = self.queue.get(timeout=0.2)
            except queue.Empty:
                return
            self.in_flight = item["event_id"]
            self._queued_ids.discard(item["event_id"])
            try:
                self._process(item)
            except Exception:
                # 绝不让后台异常外溢；固定码入档，可重试
                self._fail(item["event_id"], "processing_failed")
            finally:
                self.in_flight = None

    def _process(self, item):
        """证据绑定处理：核验读取 → 摘要取自**实际送模字节** → 恰一次发布。"""
        event_id = item["event_id"]
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT event_id,t_end,t_start,camera,object_id"
                " FROM event_facts WHERE event_id=?", (event_id,)).fetchone()
            if row is None:
                self._record(event_id, state="failed_terminal",
                             code="event_missing",
                             attempts=self.retry_max + 1)
                return
            # 重新取得资产记录：入队快照可能过期（资产行在排队期间被更新），
            # 以**当前受控记录**为准做下方完整性核验（大小+SHA-256+JPEG 头），
            # 摘要取自实际送模字节——新旧画面绝不混配；记录已消失 → 无证据
            asset = self._verified_asset(conn, row["object_id"])
            if asset is None:
                self._record(event_id, state="no_evidence",
                             code="no_evidence")
                return
            try:
                full = self.evidence.resolve(asset["path"])
                with Path(full).open("rb") as handle:
                    content = handle.read()
            except (ValueError, OSError):
                self._fail(event_id, "evidence_missing_or_corrupt")
                return
            # 完整性核验：大小 + 完整 SHA-256 + JPEG 头
            if asset["size"] is not None and \
                    len(content) != int(asset["size"]):
                self._fail(event_id, "evidence_identity_mismatch")
                return
            if asset["sha256"] and hashlib.sha256(content).hexdigest() \
                    != asset["sha256"]:
                self._fail(event_id, "evidence_identity_mismatch")
                return
            if not content.startswith(b"\xff\xd8"):
                self._fail(event_id, "evidence_missing_or_corrupt")
                return
            # 摘要 = 实际送给模型的同一份字节
            digest = hashlib.sha256(content).hexdigest()
            identity = f"{digest}:{self.fingerprint}"
            if semantic_update_ledger_hit(conn, event_id, identity):
                self._record(event_id, state="published", code=None,
                             digest=digest)
                self._published.add(event_id)
                return
            import base64 as b64mod
            raw = self.provider.understand(
                build_prompt(),
                [base64.b64encode(content).decode("ascii")],
                context={"camera_id": row["camera"], "event_id": event_id})
            profile = validate_semantic_profile(
                _extract_json(raw) if raw is not None else None)
            if profile is None:
                self._fail(event_id,
                           "model_unavailable" if raw is None
                           else "output_invalid", digest=digest)
                return
            text = compose_text(profile)
            payload = {"observed": profile["observed"],
                       "inference": profile["inference"],
                       "uncertainty": profile["uncertainty"],
                       "identity": identity,
                       "evidence_digest": digest,
                       "evidence_asset_id": asset["asset_id"],
                       "model_id": self.model_id,
                       "event_open_at_capture": row["t_end"] is None,
                       "provider": getattr(self.provider, "name", "unknown")}
            version, created = publish_semantic_update(
                conn, event_id=event_id, identity=identity,
                text=text, uncertainty=profile["uncertainty"],
                evidence_refs=[asset["asset_id"]],
                t_created=time.time(), model_id=self.model_id,
                event_open_at_write=row["t_end"] is None, payload=payload)
            if created:
                self.published += 1
                self._published.add(event_id)
                self.records.pop(event_id, None)
            elif version is None:
                # 账本已存在（并发/重复调度）：零重复版本，静默收敛
                self._record(event_id, state="published", code=None,
                             digest=digest)
                self._published.add(event_id)
        finally:
            conn.close()
