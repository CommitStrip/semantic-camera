"""Explicit Monitor evidence -> append-only event understanding.

The camera thread records metadata only. One bounded worker owns its SQLite
connection; neither tracking nor the L4 publisher waits for database writes.
Unassociated results stay in the existing L4 understanding history. This bridge
never creates events, changes their lifecycle, or copies a scene to many objects.

One thing, start to finish (INTERFACE-B): many technical windows append versions
to the *same* ``event_id`` that the fact chain opened, so the user reads one
progression instead of many duplicate events.

- Association stays on explicit production identity only: camera/run/config plus
  the tracker-mutated ``object_id``/``track_id``/``time_kind`` and the persisted
  event interval. No text similarity, no latest-event guess, no time proximity.
- Versions are appended (``MAX(version)+1``) with the initial observation v1 left
  untouched; a late window after close appends history and never reopens the fact.
- An appended version never occupies the v1 slot: if the fact chain has not yet
  persisted ``initial_observation``, the write is refused and the observation
  stays unassociated instead of replacing the user-visible start of the event.
- Every refusal is retained and queryable: the durable full record stays in the
  existing L4 understanding history, and this bridge additionally keeps a bounded
  index (``unassociated()``) of the association decision and its exact reason.
"""

from collections import Counter, OrderedDict, deque
import hashlib
import json
import math
import os
import queue
import threading
import time
import uuid

from . import db


def _identity(value):
    if not isinstance(value, dict):
        raise ValueError("identity_missing")
    camera, run, config = (value.get(k) for k in
                           ("camera_id", "run_id", "config_version"))
    if not isinstance(camera, str) or not camera or not isinstance(run, str) or not run:
        raise ValueError("identity_missing")
    if isinstance(config, bool) or not isinstance(config, (str, int)) or config == "":
        raise ValueError("identity_missing")
    return camera, run, str(config)


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _trace_event(trace, stage, **fields):
    # The bridge injects a nonblocking queue writer, never the user callback.
    if trace is not None:
        try:
            trace(stage, **fields)
        except Exception:
            pass  # Measurement cannot change the database transaction's truth.


def attach_understanding(conn, *, event_id, identity, text, uncertainty,
                         evidence_refs, t_created, model_id,
                         event_open_at_write=None, binding=None, payload=None,
                         trace=None):
    """Worker-side frozen entry. Requires a frame-bound Monitor snapshot.

    Return structured status: appended / duplicate / unassociated / rejected.
    The optional trace argument is an internal nonblocking emitter; configure
    user observers on EventProgress, not on this transaction function.
    The supplied open flag is not trusted; the current database fact determines
    it. Closed events may receive versions but are never reopened.

    Appends one version to the event the fact chain owns. The version payload
    records where this window sits in the event's progression (``progress``:
    first_update / continuing / after_close plus the persisted interval and the
    verified evidence time span) so start -> progress -> end stays one readable
    story. Every value there is read from the persisted fact inside this
    transaction; wall time and window order are never used to infer progress.
    """
    try:
        key = _identity(identity)
        if not binding or not event_id:
            return {"status": "unassociated", "reason": "binding_missing"}
        if _identity(binding) != key or binding.get("event_id") != event_id:
            return {"status": "unassociated", "reason": "identity_mismatch"}
        if uncertainty not in ("low", "high"):
            return {"status": "rejected", "reason": "uncertainty_invalid"}
        if (not isinstance(text, str) or not text.strip()
                or not isinstance(model_id, str) or not model_id):
            raise ValueError("understanding_invalid")
        if isinstance(t_created, bool) or not math.isfinite(float(t_created)):
            raise ValueError("time_invalid")
        row = conn.execute("SELECT camera,object_id,state,t_start,t_last,t_end,"
                           "end_reason,payload FROM event_facts WHERE event_id=?",
                           (event_id,)).fetchone()
        if row is None:
            return {"status": "unassociated", "reason": "event_missing"}
        fact_payload = json.loads(row["payload"] or "{}")
        if not isinstance(fact_payload, dict):
            return {"status": "unassociated", "reason": "fact_payload_invalid"}
        bound_times = []
        for bound in [binding] + list((payload or {}).get("bindings", ())):
            observed = float(bound["t_ms"]) / 1000.0
            if (_identity(bound) != key or bound.get("event_id") != event_id
                    or row["camera"] != key[0] or row["object_id"] != bound.get("object_id")
                    or not row["object_id"].startswith(f"{key[0]}:{key[1]}:track:")
                    or fact_payload.get("track_id") != bound.get("track_id")
                    or fact_payload.get("timestamp_kind") != bound.get("time_kind")
                    or not math.isfinite(observed)
                    or not row["t_start"] <= observed <= row["t_last"]):
                return {"status": "unassociated", "reason": "fact_binding_mismatch"}
            if not any(isinstance(ref, dict)
                       and str(ref.get("frame_id")) == bound["frame_id"]
                       and ref.get("t_ms") == bound["t_ms"]
                       and ref.get("time_kind") == bound["time_kind"]
                       for ref in evidence_refs):
                return {"status": "unassociated", "reason": "binding_evidence_missing"}
            bound_times.append(observed)
        # The start of an event belongs to the fact chain. An appended
        # understanding must never take the v1 slot: the initial observation is
        # written with INSERT OR IGNORE on version 1, so a model version sitting
        # there would permanently hide the confirmed start. Refuse and keep this
        # observation unassociated (retryable) instead.
        if conn.execute("SELECT 1 FROM event_descriptions WHERE event_id=?"
                        " AND version=1", (event_id,)).fetchone() is None:
            return {"status": "unassociated",
                    "reason": "initial_description_missing"}
        prior = conn.execute(
            "SELECT COUNT(*) AS n FROM event_descriptions"
            " WHERE event_id=? AND source='vlm'", (event_id,)).fetchone()["n"]
        open_at_write = row["state"] == "open"
        progress = {
            "phase": ("continuing" if open_at_write and prior else
                      "first_update" if open_at_write else "after_close"),
            "phase_basis": "persisted_fact_at_write",
            "prior_understanding_versions": int(prior),
            "event_state_at_write": row["state"],
            "event_end_reason": row["end_reason"],
            "event_t_start": row["t_start"],
            "event_t_last": row["t_last"],
            "event_t_end": row["t_end"],
            "evidence_ref_count": len(evidence_refs),
            "bound_frame_count": len(bound_times),
            "evidence_t_min": min(bound_times),
            "evidence_t_max": max(bound_times),
        }
        provenance = dict(payload or {})
        provenance.update(source="l4", identity=dict(identity), binding=dict(binding),
                          model_id=model_id, progress=progress,
                          event_open_at_write=open_at_write)
        # Wall time and window ordinal are not evidence: the same content and
        # processing fingerprint replayed in another window is still duplicate.
        dedupe = hashlib.sha256(_json({
            "identity": key, "evidence_refs": sorted({_json(r) for r in evidence_refs}), "text": text,
            "uncertainty": uncertainty, "model_id": model_id,
            "processing_fingerprint": provenance.get("processing_fingerprint")
        }).encode("utf-8")).hexdigest()
        _trace_event(trace, "write_start", event_id=event_id,
                     event_occurrence=binding.get("event_occurrence"))
        version, created = db.publish_semantic_update(
            conn, event_id=event_id, identity="l4:" + dedupe, text=text,
            uncertainty=uncertainty, evidence_refs=evidence_refs,
            t_created=float(t_created), model_id=model_id,
            event_open_at_write=open_at_write, payload=provenance)
        if created:
            _trace_event(trace, "commit_success", event_id=event_id,
                         description_version=version, status="appended")
            return {"status": "appended", "event_id": event_id, "version": version}
        # CHECK failures and ledger hits share db's False return; distinguish
        # them explicitly, including a concurrent duplicate inserted by a peer.
        duplicate = db.semantic_update_ledger_hit(conn, event_id, "l4:" + dedupe)
        _trace_event(trace, "write_skipped" if duplicate else "commit_failed",
                     event_id=event_id, status="duplicate" if duplicate else "rejected",
                     reason="ledger_hit" if duplicate else "publish_rejected")
        return {"status": "duplicate" if duplicate else "rejected",
                "reason": "ledger_hit" if duplicate else "publish_rejected",
                "event_id": event_id}
    except (ValueError, TypeError, KeyError) as exc:
        return {"status": "rejected", "reason": str(exc)}


def _bounded(value, limit=128):
    """JSON-safe, size-bounded echo of an unvalidated identity field."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, int):
        return value
    return value if math.isfinite(value) else None


# ---------------------------------------------------------------------------
# C155-A：逐帧只读归属分类（P0-1 / P0-2）
#
# 与整包 `resolve_material_binding` **并存**：原方法的签名、输出形状、状态/原因码
# 与计数（`material_binding_*`）逐字不变。本接口只做**加法**，并使用独立计数
# 命名空间（`material_frame_*`）——两套口径**不可直接横比**：历史报告里的
# `material_binding_*` 仍是整包口径，逐帧口径只在本命名空间内自比。
#
# 逐帧判定只读该帧**自己**的事实链快照（`self._frames[identity + (frame_id,)]`）：
# 不取包的并集、不借邻帧、不看 latest/时间接近/文本相似/后续 L4 结果。
FRAME_BINDING_MODE = "frame_level"

#: 包级主导原因：0 个合格帧时，按此优先级取第一条命中的**帧级**原因码
#: （逐帧词表不含 `object_ids_missing`：未声明对象时以**该帧自身**唯一对象为
#: 对象守卫，多对象帧仍 `multi_object`，绝不代调用方挑一个对象）
FRAME_REASON_PRIORITY = (
    "multi_object",
    "object_mismatch",
    "event_binding_ambiguous",
    "identity_mismatch",
    "time_kind_mismatch",
    "no_event_binding",
    "no_object",
    "frame_binding_missing",
    "frames_invalid",
)

#: 逐帧三分类词表（`ambiguous` / `rejected` 同列一组）
FRAME_BINDING_CLASSES = ("bound", "context", "ambiguous", "rejected")


def frame_event_key(row):
    """逐帧行 → **完整事件键**（P0-3(a) 的入口键）；不合格时返回 `None`。

    只在该帧**自己**成立唯一合法绑定时给出；绝不从同一次请求的别的帧补全、
    不按多数/latest/文本择一、不编造缺失身份。键的槽位与材料池事件页一致：
    `(camera_id, run_id, config_version, event_id, object_id)` + 完整可追溯段
    （`track_id` / `event_occurrence` / `time_kind` / 持久区间 / 绑定帧）。
    """
    if not isinstance(row, dict) or row.get("classification") != "bound" \
            or not row.get("bound"):
        return None
    key = row.get("event_key")
    if not isinstance(key, dict) or not key.get("event_id") \
            or not key.get("object_id"):
        return None
    return dict(key)


class EventProgress:
    """Bounded evidence registry and nonblocking single-writer queue."""

    def __init__(self, db_path, *, max_frames=2048, max_queue=64,
                 max_payload_bytes=262144, binding_retention_s=600.0,
                 max_unassociated=256, mono_clock=time.monotonic,
                 trace_observer=None, trace_clock=None,
                 trace_clock_domain=None, trace_clock_kind="real"):
        if min(max_frames, max_queue, max_payload_bytes, max_unassociated) < 1:
            raise ValueError("positive budgets required")
        self.db_path = db_path
        self.max_frames = max_frames
        self.max_payload_bytes = max_payload_bytes
        if not math.isfinite(binding_retention_s) or binding_retention_s <= 0:
            raise ValueError("positive finite binding retention required")
        self.binding_retention_s = binding_retention_s
        self._clock = mono_clock
        self._frames = OrderedDict()
        self._events = OrderedDict()
        self._frame_times = {}
        self._event_times = {}
        self._unassociated = deque(maxlen=max_unassociated)
        self._unassociated_reasons = Counter()
        self._unassociated_dropped = 0
        self._queue = queue.Queue(maxsize=max_queue)
        self._lock = threading.Lock()
        self._counts = Counter()
        self._closed = False
        self._thread = None
        self._last = None
        self._in_flight = 0
        self._trace_observer = None
        self._trace_thread = None
        if trace_observer is not None:
            self.set_trace_observer(trace_observer, clock=trace_clock,
                                    clock_domain=trace_clock_domain,
                                    clock_kind=trace_clock_kind)

    def set_trace_observer(self, observer, *, clock_domain, clock=None,
                           clock_kind="real"):
        """Configure once before start/submit; runtime may share its clock domain."""
        if observer is None:
            return
        if not callable(observer) or not isinstance(clock_domain, str) or not clock_domain:
            raise ValueError("trace observer and explicit clock domain required")
        if clock_kind not in ("real", "simulated") or (clock is not None and not callable(clock)):
            raise ValueError("trace clock invalid")
        with self._lock:
            if self._thread is not None or not self._queue.empty() or self._trace_observer is not None:
                raise RuntimeError("trace configuration must precede use")
            self._trace_lock = threading.Lock()
            self._trace_queue = queue.Queue(maxsize=128)
            self._trace_counts = Counter()
            self._trace_clock = clock or time.monotonic
            self._trace_domain = clock_domain
            self._trace_clock_kind = clock_kind
            self._trace_instance = uuid.uuid4().hex
            self._trace_process_id = os.getpid()
            self._trace_sequence = 0
            self._trace_closed = False
            self._trace_in_flight = False
            self._trace_observer = observer

    def _trace_base(self, fusion):
        if self._trace_observer is None:
            return None
        data = fusion if isinstance(fusion, dict) else {}
        with self._trace_lock:
            self._trace_sequence += 1
            attempt = self._trace_sequence
        sources = data.get("frame_refs") or ()
        identity = {k: data.get(k) for k in
                    ("camera_id", "run_id", "config_version", "window_id")}
        if (not isinstance(sources, (list, tuple)) or len(sources) > 512
                or any(v is not None and not isinstance(v, (str, int)) for v in identity.values())
                or any(isinstance(v, str) and len(v) > 1024 for v in identity.values())):
            with self._trace_lock:
                self._trace_counts["clock_or_record_errors"] += 1
            return None
        return {"schema": "scam.trace/v1", "component": "event_progress",
                "trace_id": f"{self._trace_instance}:{attempt}",
                "time_unit": "ms", "clock_kind": "host_monotonic", "clock": self._trace_clock_kind,
                "clock_domain": self._trace_domain,
                "process_id": self._trace_process_id,
                **identity,
                "source_version_id": data.get("version_id"),
                "source_frame_ids": tuple(str(r["frame_id"]) for r in sources
                                          if isinstance(r, dict) and r.get("frame_id") is not None),
                "event_id": None, "description_version": None}

    def _emit_trace(self, base, stage, **fields):
        if base is None:
            return
        try:
            stamp = float(self._trace_clock()) * 1000.0
            if not math.isfinite(stamp):
                raise ValueError("non-finite trace clock")
            record = dict(base, stage=stage, t_mono_ms=stamp, **fields)
            with self._trace_lock:
                if self._trace_closed:
                    self._trace_counts["after_close_dropped"] += 1
                    return
                self._trace_queue.put_nowait(record)
                self._trace_counts["queued"] += 1
        except queue.Full:
            with self._trace_lock:
                self._trace_counts["dropped"] += 1
        except Exception:
            with self._trace_lock:
                self._trace_counts["clock_or_record_errors"] += 1

    def _run_trace(self):
        while True:
            try:
                record = self._trace_queue.get(timeout=0.05)
            except queue.Empty:
                with self._trace_lock:
                    if self._trace_closed:
                        return
                continue
            with self._trace_lock:
                self._trace_in_flight = True
            try:
                self._trace_observer(record)
                with self._trace_lock:
                    self._trace_counts["delivered"] += 1
            except Exception:
                with self._trace_lock:
                    self._trace_counts["callback_errors"] += 1
            finally:
                self._trace_queue.task_done()
                with self._trace_lock:
                    self._trace_in_flight = False

    def record_conclusion(self, monitor, conclusion):
        """Same camera thread, after Monitor.step and BEFORE attach_result.

        Actual Tracker-mutated detections and Monitor event map are authoritative.
        Unconfirmed objects remain in observed_refs to prevent scene fan-out.
        Failures/rejected results are not treated as absence or fresh bindings.
        """
        accepted = self._record_conclusion(monitor, conclusion)
        with self._lock:
            self._counts["binding_recorded" if accepted else "binding_rejected"] += 1
        return accepted

    def _record_conclusion(self, monitor, conclusion):
        if not conclusion.get("accepted") or conclusion.get("status") not in ("ok", "empty"):
            return False
        try:
            key = _identity(conclusion)
            if key != (monitor.camera_id, monitor.run_id, str(monitor.zone_revision)):
                return False
            frame = str(conclusion["frame_id"])
            if conclusion["frame_id"] is None:
                return False
            t_ms = monitor._last_result_ms
            if t_ms is None or not math.isfinite(float(t_ms)):
                return False
            refs, bindings = [], {}
            if len(conclusion.get("detections") or ()) > 256:
                return False
            for detection in conclusion.get("detections") or ():
                tid = detection.get("trackId")
                if tid is None:
                    return False
                object_id = monitor._object_id(tid)
                refs.append(object_id)
                event = monitor._event_facts.get(tid)
                if event and event.get("state") == "open":
                    bindings[object_id] = {
                        "camera_id": key[0], "run_id": key[1],
                        "config_version": conclusion["config_version"],
                        "frame_id": frame, "object_id": object_id,
                        "track_id": tid, "event_id": event["event_id"],
                        "t_ms": float(t_ms), "time_kind": monitor.timestamp_kind,
                        "event_t_start": event["t_start"],
                        "event_t_last": event["last"]["t_last"],
                        "event_occurrence": event["occurrence"],
                        "association_frame_id": frame,
                        "binding_reason": "at_consumption"}
            snapshot = {"refs": tuple(refs), "bindings": bindings,
                        "t_ms": float(t_ms), "time_kind": monitor.timestamp_kind}
            with self._lock:
                if self._closed:
                    return False
                self._prune_bindings_locked()
                frame_key = key + (frame,)
                # A duplicate key cannot silently replace an earlier truth.
                if frame_key in self._frames:
                    return self._frames[frame_key] == snapshot
                self._frames[frame_key] = snapshot
                self._frame_times[frame_key] = self._clock()
                for object_id, binding in bindings.items():
                    event_key = key + (object_id, binding["event_id"])
                    self._events[event_key] = binding
                    self._event_times[event_key] = self._clock()
                    self._events.move_to_end(event_key)
                while len(self._events) > self.max_frames:
                    removed, _ = self._events.popitem(last=False)
                    self._event_times.pop(removed, None)
                    self._counts["event_binding_evicted"] += 1
                while len(self._frames) > self.max_frames:
                    removed, _ = self._frames.popitem(last=False)
                    self._frame_times.pop(removed, None)
                    self._counts["frame_evicted"] += 1
            return True
        except (AttributeError, ValueError, TypeError, KeyError):
            return False

    @staticmethod
    def _bounded(value, limit=128):
        """JSON-safe, size-bounded echo of an unvalidated identity field."""
        return _bounded(value, limit)

    def _index_unassociated_locked(self, fusion, result):
        """Keep a bounded, queryable index of association refusals.

        The durable full record is the existing L4 understanding history entry
        (same camera/run/config/window/version); this index only adds the exact
        reason and the claimed identity so an operator can re-check why a window
        was not merged. Admitted/duplicate windows are not listed. Nothing here
        is ever written to the event database.
        """
        status = str(result.get("status"))
        if status in ("appended", "duplicate"):
            return
        reason = str(result.get("reason") or status)
        refs = fusion.get("frame_refs") or ()
        frames = []
        for ref in list(refs)[:16]:
            if not isinstance(ref, dict):
                continue
            frames.append({"frame_id": self._bounded(ref.get("frame_id")),
                           "t_ms": self._bounded(ref.get("t_ms")),
                           "time_kind": self._bounded(ref.get("time_kind"), 32)})
        if len(self._unassociated) == self._unassociated.maxlen:
            self._unassociated_dropped += 1
        self._unassociated.append({
            "status": status, "reason": reason,
            "camera_id": self._bounded(fusion.get("camera_id")),
            "run_id": self._bounded(fusion.get("run_id")),
            "config_version": self._bounded(fusion.get("config_version"), 32),
            "window_id": self._bounded(fusion.get("window_id")),
            "version_id": self._bounded(fusion.get("version_id")),
            "at": self._bounded(fusion.get("at")),
            "evidence_frames": frames,
            "evidence_ref_total": len(refs) if isinstance(refs, (list, tuple)) else 0,
            "recorded_mono_ms": float(self._clock()) * 1000.0,
        })
        self._unassociated_reasons[reason] += 1

    def unassociated(self, *, limit=50, camera=None, reason=None):
        """Newest-first view of retained non-associations (bounded, in memory).

        Filters match the claimed identity/reason exactly. `version_id` locates
        the durable L4 understanding record; this index itself does not survive
        a restart and is not a second event store.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("positive limit required")
        with self._lock:
            retained = list(self._unassociated)
        found = []
        for entry in reversed(retained):
            if camera is not None and entry["camera_id"] != camera:
                continue
            if reason is not None and entry["reason"] != reason:
                continue
            found.append(dict(entry))
            if len(found) >= limit:
                break
        return found

    def resolve_material_binding(self, *, camera_id, run_id, config_version,
                                 object_ids=(), frames=(),
                                 frame_time_kind=None):
        """C154: read-only pre-task binding query over the existing snapshot.

        Returns the *unique* fact-chain event key for the given material
        identity, or an explicit "not aggregatable" status with a controlled
        reason. It copies under the registry lock, reuses the existing pruning
        and persistence guards, never writes the database and never mutates
        business state. No `latest`/time-neighbour/text-similarity/未来 L4
        inference: only the bindings already recorded for these exact frames.

        `object_ids` are the exact `{camera}:{run}:track:{id}` refs under
        consideration; they must match the recorded frame refs exactly —
        a frame whose refs carry more or fewer objects is `multi_object`
        (or `object_mismatch`), never silently narrowed to one object.
        """
        identity = (camera_id, run_id, str(config_version))
        if not camera_id or not run_id or config_version is None \
                or isinstance(config_version, bool):
            return self._binding_result("unbound", "identity_incomplete")
        requested = []
        for value in object_ids or ():
            if not isinstance(value, str) or not value:
                return self._binding_result("unbound", "object_ids_invalid")
            requested.append(value)
        if not requested:
            # 不声明对象 = 帧内对象身份不明：绝不代调用方"挑一个对象"
            return self._binding_result("not_aggregatable",
                                        "object_ids_missing")
        frame_rows = []
        for row in frames or ():
            if not isinstance(row, dict) or row.get("frame_id") is None:
                return self._binding_result("unbound", "frames_invalid")
            row_kind = row.get("timestamp_kind", frame_time_kind)
            if frame_time_kind is not None and row_kind is not None \
                    and row_kind != frame_time_kind:
                return self._binding_result("unbound", "time_kind_mismatch")
            frame_rows.append((str(row["frame_id"]), row_kind))
        if not frame_rows:
            return self._binding_result("unbound", "frames_invalid")
        with self._lock:
            if self._closed:
                return self._binding_result("unbound", "closed")
            self._prune_bindings_locked()
            snapshots = {}
            for frame_id, requested_kind in frame_rows:
                snapshot = self._frames.get(identity + (frame_id,))
                if snapshot is None:
                    return self._binding_result("unbound",
                                                "frame_binding_missing")
                recorded_kind = snapshot.get("time_kind")
                if frame_time_kind is not None and requested_kind is not None \
                        and requested_kind != frame_time_kind:
                    # 调用方请求的时间域与事实链记录的时间域不同：不可比 →
                    # 不借关联（绝不用相邻时间/别的时基猜同一事件）
                    return self._binding_result("not_aggregatable",
                                                "time_kind_mismatch")
                if requested_kind is not None and recorded_kind is not None \
                        and requested_kind != recorded_kind:
                    return self._binding_result("not_aggregatable",
                                                "time_kind_mismatch")
                snapshots[frame_id] = snapshot
            refs = set()
            for snapshot in snapshots.values():
                refs.update(snapshot.get("refs") or ())
            if len(refs) != 1:
                return self._binding_result("not_aggregatable", "multi_object")
            for snapshot in snapshots.values():
                if set(snapshot.get("refs") or ()) != refs:
                    return self._binding_result("not_aggregatable",
                                                "multi_object")
            object_id = next(iter(refs))
            if requested:
                if set(requested) != refs:
                    return self._binding_result("not_aggregatable",
                                                "object_mismatch")
            event_ids = set()
            for snapshot in snapshots.values():
                binding = (snapshot.get("bindings") or {}).get(object_id)
                if binding is None:
                    return self._binding_result("not_aggregatable",
                                                "no_event_binding")
                event_ids.add(binding.get("event_id"))
            if len(event_ids) != 1:
                return self._binding_result("not_aggregatable",
                                            "conflicting_events")
            binding = dict((snapshots[frame_rows[0][0]].get("bindings")
                            or {})[object_id])
            if binding.get("event_id") in (None, ""):
                return self._binding_result("not_aggregatable",
                                            "no_event_binding")
            if binding.get("camera_id") != camera_id \
                    or binding.get("run_id") != run_id \
                    or str(binding.get("config_version")) != str(
                        config_version):
                return self._binding_result("not_aggregatable",
                                            "identity_mismatch")
            kinds = {snapshot.get("time_kind") for snapshot in
                     snapshots.values()}
            if len(kinds) != 1:
                return self._binding_result("not_aggregatable",
                                            "time_kind_mismatch")
            kind = next(iter(kinds))
            if frame_time_kind is not None and kind is not None \
                    and kind != frame_time_kind:
                return self._binding_result("not_aggregatable",
                                            "time_kind_mismatch")
            for frame_id, _kind in frame_rows:
                snapshot = snapshots[frame_id]
                bound = (snapshot.get("bindings") or {}).get(object_id)
                if bound is None or bound.get("event_id") \
                        != binding.get("event_id"):
                    return self._binding_result("not_aggregatable",
                                                "conflicting_events")
            rows = tuple({
                "frame_id": frame_id,
                "t_ms": _bounded(snapshots[frame_id].get("t_ms")),
                "time_kind": _bounded(snapshots[frame_id].get("time_kind"), 32),
            } for frame_id, _kind in frame_rows)
        self._counts["material_binding_resolved"] += 1
        return {
            "status": "unique",
            "reason": None,
            "binding": {
                "camera_id": camera_id,
                "run_id": run_id,
                "config_version": config_version,
                "object_id": object_id,
                "track_id": _bounded(binding.get("track_id")),
                "event_id": binding.get("event_id"),
                "event_occurrence": _bounded(binding.get("event_occurrence")),
                "event_t_start": _bounded(binding.get("event_t_start")),
                "event_t_last": _bounded(binding.get("event_t_last")),
                "time_kind": _bounded(binding.get("time_kind"), 32),
                "t_ms": _bounded(binding.get("t_ms")),
                "association_frame_id": _bounded(
                    binding.get("association_frame_id")),
                "frame_id": _bounded(binding.get("frame_id")),
                "binding_reason": _bounded(binding.get("binding_reason"), 32),
            },
            "frames": rows,
        }

    # -- C155-A：逐帧只读归属（P0-1 / P0-2 / P0-3(a)） ----------------------

    def resolve_frame_bindings(self, *, camera_id, run_id, config_version,
                               frames=(), object_ids=(),
                               frame_time_kind=None, primary_frame_id=None):
        """C155-A: 逐帧只读归属分类；原整包 resolver 与本方法**并存**。

        判定粒度是**帧**：每帧只能凭**该帧自己**的事实链快照成为事件证据；
        未知邻帧（无快照、无 L1 结论、缺序位）**不再**使有效帧整包失去准入
        资格。与整包 resolver 共用**同一把锁、同一次清理、同一批快照**，
        并复用其只读身份/对象/时基与**持久区间**守卫；绝不新增第二套更宽松的
        绑定真相（不读数据库、不读 L4 结果、不事后回填 F2′）。

        三分类词表（`FRAME_BINDING_CLASSES`，逐帧行 `classification`）：

        - ``bound``：该帧自己已成立唯一合法绑定（唯一对象 + 已落库 open 事件的
          完整事件键，且观测点落在该帧自己记录的持久区间内）→ 可作事件证据。
        - ``context``：该帧有自己的权威快照，但**明确未归属**任何事件
          （``no_event_binding``：单对象、无 open 事件；``no_object``：帧内
          无对象）→ 只可作画面参考，**绝不是**事件证据。
        - ``ambiguous``：该帧自己的事实**不足以唯一归属**（``multi_object`` /
          ``object_mismatch`` / ``time_kind_mismatch`` /
          ``event_binding_ambiguous``，或该帧根本没有自己的权威事实
          ``frame_binding_missing``）。
        - ``rejected``：该帧行不可用（``frames_invalid``：非行/无可用
          `frame_id`）、身份守卫失败（``identity_mismatch``）或事实链已关闭
          （``closed``）。

        `object_ids` 两种模式（行级 `object_declaration` 如实标注，包级同名字段）：

        - **声明**（非空）：帧自身对象集合必须与声明全等，否则
          ``object_mismatch``（多对象仍 ``multi_object``）。
        - **未声明**（空；例如 runtime 只问"主帧自己是否已成立绑定"）：该帧自身
          **唯一**对象即它的对象身份守卫；多对象帧仍 ``multi_object``，
          **绝不代调用方在帧内挑一个对象**。原整包 resolver 在未声明对象时
          仍按原样拒绝（``object_ids_missing``，零改动）。

        包级 `status` **只有** ``ok`` / ``unbound`` / ``rejected`` 三个取值，
        **没有** ``unique``：**部分成功不得伪装成整包唯一**。``ok`` 表示
        "至少一帧合格、且合格帧同属**一个**事件键（同对象、同时基）"，
        未归属帧仍如实分列在 `context_frames` / `ambiguous_or_rejected` 里；
        包内出现多于一个事件键、多个对象或混合时基时 `status="rejected"`
        （``conflicting_events`` / ``multi_object`` / ``time_kind_mismatch``），
        **最小一期拒绝聚合、绝不混合**。

        P0-3(a)：`primary_frame_id` 指定当前任务主序位帧（`cur`），返回
        `result["primary"]`——只回答"**该帧**是否已成立唯一合法绑定"及其
        **完整事件键**（`event_key` / `event_key_tuple`）。主帧不合格时
        `qualified=false`、`event_key=null`、`borrowed_from_other_frame=false`：
        即使同请求里别的帧已绑定，也**不借邻帧**挑事件键（继续原未关联路径）。
        未显式指定时，仅当请求里**只有一个**可识别帧才用它（`selection=
        "sole_identified_frame"`），否则 `qualified=false`。

        只读保证：持锁复制、沿用 `_prune_bindings_locked()`、不写数据库、
        不改业务状态；`frames` 与请求逐行同序，新增字段全部**加法兼容**
        （新键只出现在本方法的输出里，旧字段含义不变）。计数落在
        `material_frame_*` 独立命名空间（`mode="frame_level"`，
        `historical_counts_comparable=false`），**不写** `material_binding_*`。
        """
        identity = (camera_id, run_id, str(config_version))
        request_reason = None
        if not camera_id or not run_id or config_version is None \
                or isinstance(config_version, bool):
            request_reason = "identity_incomplete"
        requested = []
        if request_reason is None:
            for value in object_ids or ():
                if not isinstance(value, str) or not value:
                    request_reason = "object_ids_invalid"
                    break
                requested.append(value)
        if request_reason is not None:
            return self._frame_binding_result(
                "rejected", request_reason, classified=(), identity=identity,
                requested=(), frame_time_kind=frame_time_kind,
                primary_frame_id=primary_frame_id)
        try:
            raw_rows = list(frames or ())
        except TypeError:
            raw_rows = None
        if not raw_rows:
            return self._frame_binding_result(
                "rejected", "frames_invalid", classified=(),
                identity=identity, requested=requested,
                frame_time_kind=frame_time_kind,
                primary_frame_id=primary_frame_id)
        classified = []
        with self._lock:
            closed = self._closed
            if not closed:
                # 与整包 resolver 同一把锁、同一次清理、同一批快照
                self._prune_bindings_locked()
                for row in raw_rows:
                    classified.append(self._classify_frame_row_locked(
                        identity, row, requested, frame_time_kind))
        if closed:
            # 事实链已关闭：请求级拒绝（逐帧 rejected/closed，不读快照、不借任何帧）
            closed_base = dict(self._frame_identity(identity),
                               object_declaration=("declared" if requested
                                                   else "absent"))
            return self._frame_binding_result(
                "rejected", "closed",
                classified=[self._frame_row(self._frame_row_id(row),
                                            "rejected", "closed",
                                            **closed_base)
                            for row in raw_rows],
                identity=identity, requested=requested,
                frame_time_kind=frame_time_kind,
                primary_frame_id=primary_frame_id)
        return self._frame_binding_result(
            None, None, classified=classified, identity=identity,
            requested=requested, frame_time_kind=frame_time_kind,
            primary_frame_id=primary_frame_id)

    @staticmethod
    def _frame_row(frame_id, classification, reason, **fields):
        """逐帧行骨架（加法字段；**不编造缺失身份**：不可用即 `None`+原因）。"""
        row = {"frame_id": frame_id, "classification": classification,
               "reason": reason, "snapshot_present": False,
               "t_ms": None, "time_kind": None, "row_time_kind": None,
               "refs": [], "refs_source": "frame_snapshot", "bound": False,
               "object_id": None, "track_id": None, "event_id": None,
               "event_occurrence": None, "event_t_start": None,
               "event_t_last": None, "event_key": None,
               "event_key_tuple": None, "binding_reason": None,
               "association_frame_id": None, "camera_id": None,
               "run_id": None, "config_version": None,
               "object_declaration": None}
        row.update(fields)
        return row

    @staticmethod
    def _frame_identity(identity):
        """帧身份三元（加法字段；调用方可用它复核该行属于哪个身份）。"""
        return {"camera_id": _bounded(identity[0]),
                "run_id": _bounded(identity[1]),
                "config_version": _bounded(identity[2], 32)}

    @staticmethod
    def _frame_row_id(row):
        """行内可用 `frame_id` → `str`；缺失/非法 → `None`（**不编造身份**）。"""
        if not isinstance(row, dict):
            return None
        raw_id = row.get("frame_id")
        if raw_id is None or isinstance(raw_id, bool) \
                or not isinstance(raw_id, (str, int)):
            return None
        return str(raw_id)

    def _classify_frame_row_locked(self, identity, row, requested,
                                   frame_time_kind):
        """持锁：只用该帧**自己**的快照分类（绝不用包的并集/别的帧快照）。

        `requested` 非空 = 调用方**声明**了对象集合 → 帧自身对象必须与声明全等；
        为空 = **未声明**（例如 runtime 只查主帧自身是否已成立绑定）→ 该帧自身
        唯一对象即它的对象身份，但多对象帧仍 `ambiguous/multi_object`：
        绝不代调用方"挑一个对象"。
        """
        frame_id = self._frame_row_id(row)
        base = dict(self._frame_identity(identity),
                    object_declaration=("declared" if requested else "absent"))
        if frame_id is None:
            # 缺序位/非法身份：本行不可用，但**不牵连**同请求的其它帧
            return self._frame_row(None, "rejected", "frames_invalid", **base)
        row_kind = _bounded(row.get("timestamp_kind", frame_time_kind), 32)
        if frame_time_kind is not None and row_kind is not None \
                and row_kind != frame_time_kind:
            # 请求时基与该行来源时基不同：跨 clock 不可比 → 不借关联
            return self._frame_row(frame_id, "ambiguous", "time_kind_mismatch",
                                   row_time_kind=row_kind, **base)
        snapshot = self._frames.get(identity + (frame_id,))
        if snapshot is None:
            # 该帧没有自己的权威事实（无 L1 结论/已过期/身份不符的未知帧）：
            # 不得整包拒绝，也不得借别的帧的绑定 → ambiguous + 受控原因
            return self._frame_row(frame_id, "ambiguous",
                                   "frame_binding_missing",
                                   row_time_kind=row_kind, **base)
        recorded_kind = _bounded(snapshot.get("time_kind"), 32)
        t_ms = _bounded(snapshot.get("t_ms"))
        refs = []
        for value in snapshot.get("refs") or ():
            if isinstance(value, str) and value and value not in refs:
                refs.append(value)
        common = dict(base, snapshot_present=True, t_ms=t_ms,
                      time_kind=recorded_kind, row_time_kind=row_kind,
                      refs=refs)
        if frame_time_kind is not None and recorded_kind is not None \
                and recorded_kind != frame_time_kind:
            return self._frame_row(frame_id, "ambiguous",
                                   "time_kind_mismatch", **common)
        if not refs:
            # 该帧自己的事实是"无对象"：明确未归属，可作画面参考
            return self._frame_row(frame_id, "context", "no_object", **common)
        if len(refs) != 1:
            # 该帧自身多对象：绝不把包的并集/别的帧当成本帧的对象真值
            return self._frame_row(frame_id, "ambiguous", "multi_object",
                                   **common)
        object_id = refs[0]
        if requested and set(requested) != {object_id}:
            # 调用方**声明**的对象集合与帧自身对象不符：不把帧归到没被请求的对象上
            return self._frame_row(frame_id, "ambiguous", "object_mismatch",
                                   **common)
        binding = (snapshot.get("bindings") or {}).get(object_id)
        if not isinstance(binding, dict) or not binding.get("event_id"):
            # 有快照、单对象，但该对象没有已落库的 open 事件：明确未归属
            return self._frame_row(frame_id, "context", "no_event_binding",
                                   **common)
        if binding.get("camera_id") != identity[0] \
                or binding.get("run_id") != identity[1] \
                or str(binding.get("config_version")) != identity[2]:
            # 该帧自己的绑定属于别的 camera/run/config：不借"同名 id"
            return self._frame_row(frame_id, "rejected", "identity_mismatch",
                                   **common)
        if binding.get("time_kind") is not None and recorded_kind is not None \
                and binding.get("time_kind") != recorded_kind:
            return self._frame_row(frame_id, "ambiguous",
                                   "time_kind_mismatch", **common)
        if not self._frame_binding_selfconsistent(snapshot, binding, frame_id):
            # 该帧自己的持久区间/绑定帧无法自我印证：归属不唯一确定
            return self._frame_row(frame_id, "ambiguous",
                                   "event_binding_ambiguous", **common)
        event_key = {
            "camera_id": _bounded(identity[0]), "run_id": _bounded(identity[1]),
            "config_version": _bounded(identity[2], 32),
            "event_id": binding.get("event_id"), "object_id": object_id,
            "track_id": _bounded(binding.get("track_id")),
            "event_occurrence": _bounded(binding.get("event_occurrence")),
            "time_kind": _bounded(binding.get("time_kind"), 32),
            "event_t_start": _bounded(binding.get("event_t_start")),
            "event_t_last": _bounded(binding.get("event_t_last")),
            "frame_id": frame_id, "t_ms": t_ms,
            "association_frame_id": _bounded(
                binding.get("association_frame_id")),
            "binding_reason": _bounded(binding.get("binding_reason"), 32),
        }
        return self._frame_row(
            frame_id, "bound", None, bound=True, object_id=object_id,
            track_id=_bounded(binding.get("track_id")),
            event_id=binding.get("event_id"),
            event_occurrence=_bounded(binding.get("event_occurrence")),
            event_t_start=_bounded(binding.get("event_t_start")),
            event_t_last=_bounded(binding.get("event_t_last")),
            event_key=event_key,
            event_key_tuple=[_bounded(identity[0]), _bounded(identity[1]),
                             _bounded(identity[2], 32),
                             str(binding.get("event_id")), object_id],
            binding_reason=_bounded(binding.get("binding_reason"), 32),
            association_frame_id=_bounded(
                binding.get("association_frame_id")), **common)

    @staticmethod
    def _frame_binding_selfconsistent(snapshot, binding, frame_id):
        """该帧自己的绑定必须**自我印证**：绑定帧=本帧、观测点在自己的区间内。"""
        if str(binding.get("frame_id")) != frame_id:
            return False
        values = (snapshot.get("t_ms"), binding.get("t_ms"),
                  binding.get("event_t_start"), binding.get("event_t_last"))
        if any(isinstance(value, bool)
               or not isinstance(value, (int, float)) for value in values):
            return False
        t_ms, bound_ms, first, last = (float(value) for value in values)
        if not all(math.isfinite(value) for value in
                   (t_ms, bound_ms, first, last)):
            return False
        if abs(t_ms - bound_ms) > 1e-9:
            return False
        return first <= t_ms / 1000.0 <= last

    @staticmethod
    def _dominant_frame_reason(reason_counts):
        """0 个合格帧时的包级主导原因（词表内按优先级，词表外按字典序，绝不静默）。"""
        for code in FRAME_REASON_PRIORITY:
            if reason_counts.get(code):
                return code
        remaining = sorted(reason_counts)
        return remaining[0] if remaining else None

    @staticmethod
    def _frame_id_list(rows, classes):
        """三分类列表：**去重**（首次出现序）的帧 id；无 id 的行只进 `frames`。"""
        found = []
        for row in rows:
            frame_id = row.get("frame_id")
            if frame_id is None or row.get("classification") not in classes:
                continue
            if frame_id not in found:
                found.append(frame_id)
        return found

    @staticmethod
    def _frame_binding_primary(rows, primary_frame_id):
        """P0-3(a)：**主序位帧自身**的绑定答案；绝不借邻帧/多数/latest/文本。"""
        identified = [row for row in rows if row.get("frame_id")]
        if primary_frame_id is None:
            selection = "sole_identified_frame" if len(identified) == 1 else None
            target = identified[0]["frame_id"] if len(identified) == 1 else None
        elif isinstance(primary_frame_id, bool) or not isinstance(
                primary_frame_id, (str, int)):
            selection, target = None, None
        else:
            selection, target = "explicit", str(primary_frame_id)
        answer = {"requested_frame_id": _bounded(primary_frame_id),
                  "selection": selection, "frame_id": target, "found": False,
                  "classification": None, "snapshot_present": False,
                  "bound": False, "qualified": False, "reason": None,
                  "event_key": None, "event_key_tuple": None,
                  "binding_frame_id": None,
                  "borrowed_from_other_frame": False,
                  "source": "own_frame_snapshot", "other_bound_frames": []}
        if selection is None:
            answer["reason"] = ("primary_frame_id_invalid"
                                if primary_frame_id is not None
                                else "primary_frame_id_missing")
            return answer
        match = next((row for row in rows
                      if row.get("frame_id") == target), None)
        if match is None:
            # 主帧不在本次请求里：只回答"未核验"，不替调用方去查别的帧
            answer["reason"] = "primary_frame_not_in_request"
            return answer
        answer.update(
            found=True, frame_id=match["frame_id"],
            classification=match["classification"],
            snapshot_present=bool(match["snapshot_present"]),
            bound=bool(match["bound"]), qualified=bool(match["bound"]),
            reason=match.get("reason"),
            event_key=(dict(match["event_key"])
                       if match.get("event_key") else None),
            event_key_tuple=(list(match["event_key_tuple"])
                             if match.get("event_key_tuple") else None),
            binding_frame_id=(match["frame_id"] if match["bound"] else None),
            other_bound_frames=[row["frame_id"] for row in rows
                                if row.get("classification") == "bound"
                                and row["frame_id"] != match["frame_id"]])
        return answer

    def _count_frame_bindings(self, result):
        """逐帧口径的**独立**计数（加法）；绝不写 `material_binding_*`。"""
        counts = result["counts"]
        self._counts["material_frame_binding_calls"] += 1
        self._counts["material_frame_binding_frames"] += counts["rows"]
        for name in FRAME_BINDING_CLASSES:
            self._counts["material_frame_binding_frames_" + name] += counts[name]
        self._counts["material_frame_binding_frames_unidentified"] += counts[
            "unidentified_rows"]
        self._counts["material_frame_binding_duplicate_rows"] += counts[
            "duplicate_rows"]
        self._counts["material_frame_binding_packages_" + (
            "resolved" if result["status"] == "ok" else "refused")] += 1
        for reason, number in result["reason_counts"].items():
            self._counts["material_frame_reason_" + str(reason)] += number
        if result["status"] != "ok":
            self._counts["material_frame_package_reason_" + str(
                result["reason"])] += 1

    def _frame_binding_result(self, status, reason, *, classified, identity,
                              requested, frame_time_kind, primary_frame_id):
        """逐帧行 → 包级结果（`ok`/`unbound`/`rejected`，**无** `unique`）。"""
        rows = list(classified)
        identified = [row for row in rows if row.get("frame_id")]
        distinct = {row["frame_id"] for row in identified}
        counts = Counter(row["classification"] for row in rows)
        reason_counts = Counter(row["reason"] for row in rows
                                if row.get("reason"))
        bound_rows = [row for row in rows
                      if row["classification"] == "bound"]
        event_ids, event_keys, seen = [], [], set()
        for row in bound_rows:
            event_id = row.get("event_id")
            if event_id and event_id not in event_ids:
                event_ids.append(event_id)
            key = row.get("event_key_tuple")
            if key and tuple(key) not in seen:
                seen.add(tuple(key))
                event_keys.append(list(key))
        if status is None:
            if not bound_rows:
                status = "unbound"
                reason = self._dominant_frame_reason(reason_counts)
            elif len(event_ids) != 1:
                # 同包两个事件键：最小一期拒绝聚合，绝不混合
                status, reason = "rejected", "conflicting_events"
            elif len({row.get("object_id") for row in bound_rows}) != 1:
                status, reason = "rejected", "multi_object"
            elif len({row.get("time_kind") for row in bound_rows}) != 1:
                status, reason = "rejected", "time_kind_mismatch"
            else:
                status, reason = "ok", None
        result = {
            "status": status,
            "mode": FRAME_BINDING_MODE,
            "reason": reason,
            "historical_counts_comparable": False,
            "object_declaration": ("declared" if requested
                                   else ("absent" if rows else None)),
            "identity": {"camera_id": _bounded(identity[0]),
                         "run_id": _bounded(identity[1]),
                         "config_version": _bounded(identity[2], 32)},
            "frame_time_kind": _bounded(frame_time_kind, 32),
            "object_ids": list(requested),
            "frames": rows,
            "bound_frames": self._frame_id_list(rows, ("bound",)),
            "context_frames": self._frame_id_list(rows, ("context",)),
            "ambiguous_or_rejected": self._frame_id_list(
                rows, ("ambiguous", "rejected")),
            "event_ids": event_ids,
            "event_keys": event_keys,
            "counts": {"rows": len(rows), "distinct_frames": len(distinct),
                       "duplicate_rows": len(identified) - len(distinct),
                       "unidentified_rows": len(rows) - len(identified),
                       "bound": counts["bound"], "context": counts["context"],
                       "ambiguous": counts["ambiguous"],
                       "rejected": counts["rejected"]},
            "reason_counts": dict(sorted(reason_counts.items())),
            "primary": self._frame_binding_primary(rows, primary_frame_id),
        }
        if not rows and status != "ok":
            # 请求级拒绝：主帧答案如实指向该请求级原因，绝不冒充"主帧不在请求里"
            result["primary"]["reason"] = reason
        self._count_frame_bindings(result)
        return result

    def _binding_result(self, status, reason):
        """Controlled refusal shape (no business state written)."""
        self._counts["material_binding_refused"] += 1
        self._counts["material_binding_" + str(reason)] += 1
        return {"status": status, "reason": str(reason), "binding": None,
                "frames": ()}

    def submit(self, fusion):
        """Serialize bounded metadata, enqueue only; no database/queue waiting."""
        trace_base = self._trace_base(fusion)
        self._emit_trace(trace_base, "l4_received")
        try:
            key = _identity(fusion)
            encoded = _json(fusion)
            if len(encoded.encode("utf-8")) > self.max_payload_bytes:
                raise ValueError("payload_budget")
            copied = json.loads(encoded)
            with self._lock:
                if self._closed:
                    self._counts["closed_rejected"] += 1
                    self._emit_trace(trace_base, "submit_rejected", reason="closed")
                    return False
                # Freeze frame bindings at acceptance, so later cache eviction
                # or a camera/config change cannot reinterpret queued evidence.
                frames = self._snapshot_frames(key, copied.get("frame_refs", ()))
                self._queue.put_nowait((copied, frames, trace_base))
                self._counts["queued"] += 1
                self._emit_trace(trace_base, "progress_queued")
            return True
        except queue.Full:
            with self._lock:
                self._counts["queue_full"] += 1
            self._emit_trace(trace_base, "submit_rejected", reason="queue_full")
            return False
        except (ValueError, TypeError, KeyError):
            with self._lock:
                self._counts["invalid"] += 1
            self._emit_trace(trace_base, "submit_rejected", reason="invalid")
            return False

    def _prune_bindings_locked(self):
        cutoff = self._clock() - self.binding_retention_s
        for cache, times, counter in (
                (self._frames, self._frame_times, "frame_expired"),
                (self._events, self._event_times, "event_binding_expired")):
            while cache:
                first = next(iter(cache))
                if times.get(first, cutoff) >= cutoff:
                    break
                cache.pop(first)
                times.pop(first, None)
                self._counts[counter] += 1

    def _snapshot_frames(self, key, frame_refs):
        """Caller holds registry lock. Never mutate an earlier frame snapshot.

        A pre-confirmation source frame may acquire the *actual* subsequently
        confirmed event through its exact Tracker object ref and persisted
        Monitor interval. Multiple occurrences/range mismatch remain unknown;
        the confirmation frame is recorded separately, never forged as source.
        """
        self._prune_bindings_locked()
        frames = {}
        for ref in frame_refs:
            fid = str(ref["frame_id"])
            snap = self._frames.get(key + (fid,))
            if snap is None:
                frames[fid] = None
                continue
            frozen = dict(snap, bindings=dict(snap["bindings"]), binding_rejections={})
            for object_id in snap["refs"]:
                if object_id in frozen["bindings"]:
                    continue
                matches = [b for event_key, b in self._events.items()
                           if event_key[:4] == key + (object_id,)
                           and b["time_kind"] == snap["time_kind"]
                           and b["event_t_start"] <= snap["t_ms"] / 1000.0 <= b["event_t_last"]]
                if len(matches) == 1:
                    frozen["bindings"][object_id] = dict(
                        matches[0], frame_id=fid, t_ms=snap["t_ms"],
                        binding_reason="confirmed_after_source_frame")
                elif len(matches) > 1:
                    frozen["binding_rejections"][object_id] = "event_binding_ambiguous"
            frames[fid] = frozen
        return frames

    @staticmethod
    def _associate(conn, fusion, snapshots, trace=None):
        refs = {s["ref"] for item in fusion.get("items", ())
                for s in item.get("sources", ()) if s.get("kind") == "l1_object"}
        if len(refs) != 1:
            return {"status": "unassociated", "reason": "no_object" if not refs else "multi_object"}
        target = next(iter(refs))
        bindings = []
        for frame in fusion.get("frame_refs", ()):
            snap = snapshots.get(str(frame["frame_id"]))
            if snap is None:
                return {"status": "unassociated", "reason": "frame_binding_missing"}
            if (frame.get("time_kind") != snap["time_kind"]
                    or frame.get("t_ms") != snap["t_ms"]):
                return {"status": "unassociated", "reason": "frame_time_mismatch"}
            if any(ref != target for ref in snap["refs"]):
                return {"status": "unassociated", "reason": "multi_object_frame"}
            if target in snap["refs"]:
                binding = snap["bindings"].get(target)
                if binding is None:
                    return {"status": "unassociated", "reason": snap.get(
                        "binding_rejections", {}).get(target, "event_unpersisted")}
                bindings.append(binding)
        if not bindings or len({b["event_id"] for b in bindings}) != 1:
            return {"status": "unassociated", "reason": "event_binding_ambiguous"}
        # No model conclusion is promoted to confirmed fact. Keep all structured
        # sources/gaps in the version payload; text is an observation/explanation.
        texts = sorted({i["text"] for i in fusion.get("items", ())
                 if i.get("text") and any(s.get("kind") == "l3_branch"
                                          for s in i.get("sources", ()))})
        if not texts:
            return {"status": "unassociated", "reason": "explanation_missing"}
        identity = {k: fusion[k] for k in ("camera_id", "run_id", "config_version")}
        return attach_understanding(
            conn, event_id=bindings[0]["event_id"], identity=identity,
            text="\n".join(dict.fromkeys(texts)), uncertainty="high",
            evidence_refs=fusion["frame_refs"], t_created=fusion["at"],
            model_id="l4-fusion", binding=bindings[0],
            payload={"window_id": fusion.get("window_id"),
                     "fusion_version_id": fusion.get("version_id"),
                     "processing_fingerprint": hashlib.sha256(_json({
                         "rule": "l4-event-progress/v1",
                         "items": sorted({_json(dict(i, sources=sorted(
                             i.get("sources", ()), key=_json)))
                             for i in fusion.get("items", ())})
                     }).encode("utf-8")).hexdigest(),
                     "items": fusion.get("items", ()), "bindings": bindings},
            trace=trace)

    def start(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("event progress closed")
            if self._thread is None:
                if self._trace_observer is not None:
                    self._trace_thread = threading.Thread(target=self._run_trace, daemon=True,
                                                          name="win11-progress-observer")
                    self._trace_thread.start()
                self._thread = threading.Thread(target=self._run, daemon=True,
                                                name="win11-event-progress")
                self._thread.start()

    def _run(self):
        conn = None
        try:
            while True:
                try:
                    fusion, snapshots, trace_base = self._queue.get(timeout=0.05)
                except queue.Empty:
                    with self._lock:
                        if self._closed:
                            return
                    continue
                with self._lock:
                    self._in_flight = 1
                trace_state = None
                if trace_base is not None:
                    trace_state = {"ended": False, "write_started": False,
                                   "event_id": None, "event_occurrence": None}

                    def trace(stage, **fields):
                        if stage == "write_start":
                            trace_state.update(write_started=True, event_id=fields.get("event_id"),
                                               event_occurrence=fields.get("event_occurrence"))
                        elif stage in ("commit_success", "commit_failed", "write_skipped"):
                            trace_state["ended"] = True
                        if trace_state["event_occurrence"] is not None:
                            fields.setdefault("event_occurrence", trace_state["event_occurrence"])
                        self._emit_trace(trace_base, stage, **fields)

                try:
                    if conn is None:
                        conn = db.connect(self.db_path)
                    if trace_base is None:
                        result = self._associate(conn, fusion, snapshots)
                    else:
                        result = self._associate(conn, fusion, snapshots, trace)
                except Exception as exc:
                    result = {"status": "failed", "reason": type(exc).__name__}
                    if trace_state is not None:
                        self._emit_trace(trace_base, "commit_failed", status="failed",
                                         reason=type(exc).__name__, event_id=trace_state["event_id"],
                                         write_attempted=trace_state["write_started"],
                                         publication_outcome="unconfirmed" if trace_state["write_started"] else "not_attempted")
                        trace_state["ended"] = True
                    if conn is not None:
                        try:
                            conn.rollback()
                        except Exception:
                            try:
                                conn.close()
                            finally:
                                conn = None
                finally:
                    self._queue.task_done()
                if trace_base is not None and not trace_state["ended"]:
                    self._emit_trace(trace_base, "write_skipped", status=result["status"],
                                     reason=result.get("reason"), event_id=result.get("event_id"))
                with self._lock:
                    self._in_flight = 0
                    self._counts[result["status"]] += 1
                    self._last = result
                    self._index_unassociated_locked(fusion, result)
        finally:
            if conn is not None:
                conn.close()

    def close(self, timeout=5.0):
        deadline = time.monotonic() + max(0.0, timeout) if self._trace_observer is not None else None
        with self._lock:
            self._closed = True
            thread = self._thread
        if thread is not None:
            thread.join(timeout=max(0.0, timeout))
        core_done = not (thread and thread.is_alive()) and self._queue.empty()
        if self._trace_observer is None:
            return core_done
        if core_done:
            with self._trace_lock:
                self._trace_closed = True
        if self._trace_thread is not None:
            self._trace_thread.join(timeout=max(0.0, deadline - time.monotonic()))
        return core_done and not (self._trace_thread and self._trace_thread.is_alive()) and self._trace_queue.empty()

    def snapshot(self):
        with self._lock:
            self._prune_bindings_locked()
            result = {"counts": dict(self._counts),
                    "last": None if self._last is None else dict(self._last),
                    "closed": self._closed, "pending": self._queue.qsize(),
                    "in_flight": self._in_flight,
                    "frames": len(self._frames), "event_bindings": len(self._events),
                    "unassociated": {
                        "retained": len(self._unassociated),
                        "capacity": self._unassociated.maxlen,
                        "dropped": self._unassociated_dropped,
                        "by_reason": dict(self._unassociated_reasons)}}
        if self._trace_observer is not None:
            with self._trace_lock:
                result["trace"] = {"counts": dict(self._trace_counts),
                                   "pending": self._trace_queue.qsize(),
                                   "in_flight": self._trace_in_flight,
                                   "closed": self._trace_closed,
                                   "clock_domain": self._trace_domain,
                                   "delivery_complete": bool(
                                       self._trace_closed and self._trace_queue.empty()
                                       and not self._trace_in_flight
                                       and self._trace_counts["delivered"] == self._trace_counts["queued"]
                                       and not any(self._trace_counts[k] for k in (
                                           "dropped", "callback_errors", "clock_or_record_errors",
                                           "after_close_dropped")))}
        return result
