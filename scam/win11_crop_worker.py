"""Bounded asynchronous evidence worker on top of CropEvidenceStore (C-141 §2/§3,
C141-R1 interface freeze §1-§3, C141-R2 interface freeze §1-§3).

One daemon=False worker thread drains a bounded queue of (image copy,
provenance) tasks; each task ends in exactly one terminal state:
``pending → saved | failed | dropped | commit_uncertain``. ``saved`` requires
BOTH a successful ``store.save`` and a successful persistent-index append —
an index failure is reported honestly and never faked into ``saved``.

Budgets are explicit, constructor-configured caps: queue 64, pending TTL 300s
(monotonic clock), close wait 5s, task history 1024 terminal records, image
pixel/byte caps, per-task metadata byte cap, index line cap, and per-find scan
budgets (bytes / parses / records). Non-terminal tasks are separately bounded
(≤ queue_max+1) at admission, terminal records are bounded by history_max at
eviction, so ``_tasks``/``_order`` have a hard total bound; terminal eviction
never stalls behind the oldest pending ref.

Admission reservation (C141-R2 §1, frozen): a submit claims its capacity slot
ATOMICALLY under one short state lock — the unified hard bound is
``reserved + pending + inflight ≤ queue_max + 1`` (``pending`` counts created
non-terminal tasks: queued plus the at most one inside ``store.save``;
``reserved`` counts submissions holding an unconverted reservation) — and
only then measures inputs and copies strictly outside every lock, so a slow
copy never blocks status/close/fast paths and concurrent submissions cannot
overshoot the bound while copying. The reservation is converted into a queued
task or released EXACTLY ONCE (one-shot guard): stopped, oversize input,
copy failure and enqueue failure all release it. Rejections stay zero-copy.

Durable commit (C141-R2 §2, frozen): an index append failing BEFORE its first
byte (record build/serialization, fences, ``open``) is a certain
``failed(index_failed)``. A failure of ``write``/``flush``/``fsync`` — or a
post-fsync fence showing the appended path no longer names the very file that
was fsynced — raises ``commit_uncertain``: the line may already be durable and
reachable, so memory claims NEITHER failed NOR saved; ``status(ref)`` reports
the visible ``commit_uncertain`` state (with the real asset id — the archive
exists) and it is never rewritten, never retried, never deleted. The
authoritative truth is the index file itself: find/restart read actual lines —
a present line reads as saved, an absent line stays unattributed. The index
file never stores uncertainty: its lines are only ``saved``/``failed``.

Commit-status query (C141-R3 §1, frozen): ``commit_status(camera_id,
identity)`` answers the CURRENT in-memory commit fact for one complete
nine-key identity — ``commit_uncertain`` (with the real asset id), an
explicit "no uncertainty" (``{"status": None}``), or ``None`` when no live
task matches (unobserved / the writing process's memory state is lost; after
a restart the empty table answers ``None`` and uncertainty is NEVER
fabricated). It is read-only, zero disk, zero side effects, iterating the
already-bounded task table under the short state lock; ``find`` remains the
PERSISTENT index truth and still never returns the uncertain state — the
server composes both honestly ("index line readable, durability unproven").

The persistent index is an append-only JSONL file per camera under
``<store root>/index/<sha256(camera)[:16]>.jsonl``. ``find`` reads only that
camera's own file through an asset-grade fence (regular file, no
symlink/reparse at the root, index dir and file levels, lstat → O_NOFOLLOW
open → fstat samestat → post-read recheck of the file AND the index directory
AND the store root identity), validates structure/schema/full identity
(``saved`` entries must carry a real 64-hex asset id) and enforces strict
camera equality: a record whose camera differs from the file's owner is a
poison row — skipped and counted, never returned. Giant lines are skipped
whole (never parsed in fragments); scan-budget stops are disclosed as
truncation diagnostics. Orphan assets (on disk, absent from the index) are
never attributed to any branch. Writes verify the opened handle is a regular
file matching the pre-open identity and re-verify the path after fsync. Only
the boundary of a controlled local directory is promised — this is integrity
hardening, not a defense against an arbitrary malicious host process.

The worker owns its own locks and touches no fast-system / L1 / L2 lock;
inside the worker only ``store.save`` and the index append perform I/O — no
user callbacks ever run on the worker thread.
"""
import collections
import hashlib
import json
import math
import os
import queue
import re
import stat
import threading
import time
from copy import deepcopy
from pathlib import Path

from scam.win11_crop_evidence import CropEvidenceError

_INDEX_DIR = "index"
_SCAN_CHUNK_BYTES = 65536
_INDEX_SCHEMA = "sc.cropindex/v1"
# Registry fields exposed to filters (camera_id is fixed by the per-camera
# file; the rest is the frozen identity plus the asset/status linkage).
_FILTER_FIELDS = frozenset({
    "crop_id", "branch", "slot", "window_id", "material_id", "run_id",
    "config_version", "asset_id", "status", "frame_id", "frame_seq"})
_RECORD_IDENTITY_KEYS = (
    "camera_id", "run_id", "config_version", "material_id", "crop_id",
    "frame_id", "t_capture_ms", "timestamp_kind",
    "window_id", "branch", "slot", "frame_seq")
# sc.crop/v1 core identity: the store refuses to archive a payload without
# these, so an index line missing any of them is not a line we ever wrote.
_REQUIRED_IDENTITY_KEYS = _RECORD_IDENTITY_KEYS[:8]
# C141-R3 §1 (frozen): the complete nine-key identity a commit-status query
# must carry in full. commit_status refuses incomplete queries instead of
# guessing; every key of every admitted task is snapshotted against exactly
# this tuple (bounded: nine scalars per task, hard-bounded task table).
_COMMIT_IDENTITY_KEYS = ("camera_id", "run_id", "config_version",
                         "material_id", "window_id", "branch", "crop_id",
                         "frame_id", "slot")
_MAX_FIND_LIMIT = 1000


def _camera_index_path(root, camera_id):
    """Fenced per-camera index path: hashed key, resolved inside the root."""
    key = hashlib.sha256(camera_id.encode("utf-8")).hexdigest()[:16]
    root_resolved = Path(root).resolve()
    resolved = root_resolved.joinpath(_INDEX_DIR, key + ".jsonl")
    if resolved == root_resolved or not resolved.is_relative_to(root_resolved):
        raise ValueError("index path escaped store root")
    return resolved


def _is_reparse(info):
    """True when a lstat result carries a Windows reparse point attribute."""
    return bool(getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024))


def _same_identity(left, right):
    """File identity (device + inode) without mtime: the index is append-only,
    so a legitimate concurrent append must not read as an identity change."""
    return left.st_ino == right.st_ino and left.st_dev == right.st_dev


def _index_record(payload, ref, asset_id, status, reason, submitted_ms, finished_ms):
    """Registry line for one terminal task; None when not attributable.

    camera_id must be a well-formed string for the per-camera file; other
    identity fields are copied as-is (store-validated values are JSON-safe,
    and the write path serializes with allow_nan=False as a final gate).
    """
    if not isinstance(payload, dict):
        return None
    camera = payload.get("camera_id")
    if not isinstance(camera, str) or not 0 < len(camera) <= 256:
        return None
    record = {"schema": _INDEX_SCHEMA, "ref": ref, "asset_id": asset_id,
              "status": status, "reason": reason,
              "submitted_ms": submitted_ms, "finished_ms": finished_ms}
    for key in _RECORD_IDENTITY_KEYS:
        if key in payload:
            record[key] = payload[key]
    return record


def _canonical(value):
    """Canonical form of an identity scalar: int/str → str, anything else
    (bool, float, None, containers) → None, i.e. never comparable."""
    if type(value) is int:
        return str(value)
    if type(value) is str:
        return value
    return None


def _filter_matches(record_value, filter_value):
    """Normalized equality for identity filters (C-141 integration fix).

    Identity keys legally come in either shape across producers — B's
    provenance carries ints (window_id=11, material_id=610) while the server
    derives strings ("11"/"610") — so int/str scalars compare in canonical
    string form. bool keeps its own type: True/False never match 1/0 or
    "1"/"0", in either position.
    """
    want = _canonical(filter_value)
    return want is not None and want == _canonical(record_value)


def _admit_record(obj, owner_camera, counters):
    """Validate one parsed index line against the frozen contract.

    Rejections are counted honestly: malformed lines as ``bad_lines``; a
    well-formed line whose camera differs from the index file's owner camera
    as ``cross_camera`` (poison row — skipped, never returned). A ``saved``
    record must carry a real 64-hex asset id and the full v1 identity keys.
    """
    if not isinstance(obj, dict) or type(obj.get("ref")) is not int \
            or obj.get("schema") != _INDEX_SCHEMA \
            or obj.get("status") not in ("saved", "failed") \
            or not (obj.get("reason") is None
                    or isinstance(obj.get("reason"), str)):
        counters["bad_lines"] += 1
        return None
    asset = obj.get("asset_id")
    valid_asset = isinstance(asset, str) \
        and re.fullmatch(r"[0-9a-f]{64}", asset)
    if obj["status"] == "saved":
        if not valid_asset:              # saved without a real asset id
            counters["bad_lines"] += 1
            return None
    elif asset is not None and not valid_asset:
        counters["bad_lines"] += 1
        return None
    camera = obj.get("camera_id")
    if not isinstance(camera, str) or not 0 < len(camera) <= 256:
        counters["bad_lines"] += 1
        return None
    if camera != owner_camera:           # strict per-camera equality
        counters["cross_camera"] += 1
        return None
    if any(key not in obj for key in _REQUIRED_IDENTITY_KEYS):
        counters["bad_lines"] += 1       # incomplete identity: unusable
        return None
    return obj


def _scan_backwards(handle, size, camera_id, *, line_bytes_cap, record_budget,
                    scan_bytes_budget, parse_budget, records, counters):
    """Reverse chunked scan with correct giant-line boundaries.

    ``buf`` holds unprocessed bytes ending at the last confirmed ``\\n``
    boundary. When an over-cap mid-line tail is discarded, ``partial`` marks
    buf's right edge as mid-line: the fragment up to the next ``\\n`` is then
    dropped WITHOUT parsing, so a giant line is never parsed in pieces and a
    crafted suffix inside it cannot be admitted as a record. Total scan
    effort is bounded by bytes (scan_bytes_budget), parse attempts
    (parse_budget) and admitted records (record_budget); every stop before
    the file's beginning is disclosed as ``truncated``.
    """
    handle.seek(0, os.SEEK_END)
    pos = min(handle.tell(), max(0, size))
    remaining = scan_bytes_budget
    parses = 0
    buf = b""
    partial = False
    while pos > 0 and len(records) < record_budget and remaining > 0:
        step = min(_SCAN_CHUNK_BYTES, pos, remaining)
        pos -= step
        remaining -= step
        handle.seek(pos)
        chunk = handle.read(step)
        if not chunk:
            break
        buf = chunk + buf
        while buf and len(records) < record_budget:
            nl = buf.rfind(b"\n")
            if nl == -1:
                if len(buf) > line_bytes_cap:
                    if not partial:
                        counters["oversized_lines"] += 1
                    partial = True
                    buf = b""
                break
            line, buf = buf[nl + 1:], buf[:nl]
            if partial:
                partial = False         # head of a discarded giant line: skip
                continue                # never parse mid-line fragments
            if not line.strip():
                continue
            if len(line) > line_bytes_cap:
                counters["oversized_lines"] += 1
                continue
            if parses >= parse_budget:
                counters["truncated"] += 1
                return                  # remaining lines left unexamined
            parses += 1
            try:
                obj = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                counters["bad_lines"] += 1
                continue
            record = _admit_record(obj, camera_id, counters)
            if record is not None:
                records.append(record)
    truncated = pos > 0                 # stopped before the file's beginning
    if len(records) < record_budget and buf.strip():
        if partial:
            pass                        # tail of an already-counted giant line
        elif pos > 0:
            truncated = True            # left boundary never scanned: no parse
        elif len(buf) > line_bytes_cap:
            counters["oversized_lines"] += 1
        elif parses >= parse_budget:
            truncated = True
        else:
            parses += 1
            try:
                obj = json.loads(buf)
            except (ValueError, UnicodeDecodeError):
                counters["bad_lines"] += 1
            else:
                record = _admit_record(obj, camera_id, counters)
                if record is not None:
                    records.append(record)
    if truncated:
        counters["truncated"] += 1


def _read_camera_records(path, *, camera_id, line_bytes_cap, record_budget,
                         scan_bytes_budget, parse_budget):
    """Fenced reverse scan of one camera's JSONL → (newest-first, counters).

    Read fence at three levels (store root, index directory, file): real
    directory / regular file only, no symlink, no Windows reparse point,
    lstat → O_NOFOLLOW open → fstat identity → post-read recheck that the
    path STILL names the exact same regular file (device + inode;
    append-only growth is legitimate and never reads as an identity change,
    a shrink does) and — C141-R2 §3 — that the index directory AND the
    store root were not swapped while we read: their pre-read identities
    are re-compared after the scan and any mismatch discards everything
    read and counts ``unsafe``. Never reads the whole file, never buffers
    an over-cap line, stops at any budget with an honest ``truncated``
    count. Read-only: no lock, no disk write. Only the boundary of a
    controlled local directory is promised; not a defense against an
    arbitrary malicious host process.
    """
    counters = {"bad_lines": 0, "oversized_lines": 0, "cross_camera": 0,
                "unsafe": 0, "truncated": 0}
    records = []
    try:
        root_stat = path.parent.parent.lstat()
    except FileNotFoundError:
        return records, counters             # nothing indexed yet
    except OSError:
        counters["unsafe"] += 1
        return records, counters
    if not stat.S_ISDIR(root_stat.st_mode) or _is_reparse(root_stat):
        counters["unsafe"] += 1
        return records, counters
    try:
        dir_stat = path.parent.lstat()
    except FileNotFoundError:
        return records, counters             # nothing indexed yet
    except OSError:
        counters["unsafe"] += 1
        return records, counters
    if not stat.S_ISDIR(dir_stat.st_mode) or _is_reparse(dir_stat):
        counters["unsafe"] += 1
        return records, counters
    try:
        before = path.lstat()
    except FileNotFoundError:
        return records, counters
    except OSError:
        counters["unsafe"] += 1
        return records, counters
    if not stat.S_ISREG(before.st_mode) or _is_reparse(before):
        counters["unsafe"] += 1
        return records, counters
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags)
    except OSError:
        counters["unsafe"] += 1
        return records, counters
    opened = None
    try:
        with os.fdopen(fd, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) \
                    or not _same_identity(before, opened):
                counters["unsafe"] += 1
                return records, counters
            _scan_backwards(handle, opened.st_size, camera_id,
                            line_bytes_cap=line_bytes_cap,
                            record_budget=record_budget,
                            scan_bytes_budget=scan_bytes_budget,
                            parse_budget=parse_budget,
                            records=records, counters=counters)
    except OSError:
        counters["truncated"] += 1           # read died mid-scan: honest
    if opened is None:
        counters["unsafe"] += 1
        return [], counters
    try:
        current = path.lstat()
    except OSError:
        counters["unsafe"] += 1
        return [], counters
    if not stat.S_ISREG(current.st_mode) or not _same_identity(opened, current) \
            or current.st_size < opened.st_size:
        counters["unsafe"] += 1
        return [], counters          # swapped or truncated under us: trust
    try:
        dir_after = path.parent.lstat()
    except OSError:
        counters["unsafe"] += 1
        return [], counters          # index dir swapped under us: trust
    if (not stat.S_ISDIR(dir_after.st_mode) or _is_reparse(dir_after)
            or not _same_identity(dir_stat, dir_after)):
        counters["unsafe"] += 1
        return [], counters          # nothing read is attributable anymore
    try:
        root_after = path.parent.parent.lstat()
    except OSError:
        counters["unsafe"] += 1
        return [], counters
    if (not stat.S_ISDIR(root_after.st_mode) or _is_reparse(root_after)
            or not _same_identity(root_stat, root_after)):
        counters["unsafe"] += 1
        return [], counters          # store root swapped under us: trust nothing
    return records, counters         # nothing; append-only growth is fine


class CropWorker:
    """Bounded single-thread async saver; submit/status/find never block.

    Every admitted frame is copied exactly once; the copy has exactly one
    owner (its task) and is released exactly once, at the task's single
    pending → terminal transition. Rejected submissions (stopped, queue
    full, oversize input) are refused before any copy is made. Concurrent
    submissions claim their capacity slot atomically under the state lock
    (admission reservation, C141-R2 §1) so the bound cannot be overshot
    while copies run outside every lock.
    """

    def __init__(self, store, *, queue_max=64, ttl_s=300, close_timeout_s=5.0,
                 find_limit=200, index_scan_budget=2048, index_line_bytes=65536,
                 index_scan_bytes=4 * 1024 * 1024, index_parse_budget=4096,
                 history_max=1024, max_image_pixels=4_000_000,
                 max_image_bytes=8 * 1024 * 1024, max_meta_bytes=16384,
                 clock=time.monotonic):
        if not (hasattr(store, "save") and hasattr(store, "read")
                and hasattr(store, "root")):
            raise ValueError("store must expose save/read/root")
        checks = (type(queue_max) is not int or queue_max <= 0,
                  type(ttl_s) not in (int, float) or type(ttl_s) is bool
                  or not math.isfinite(ttl_s) or ttl_s <= 0,
                  type(close_timeout_s) not in (int, float)
                  or type(close_timeout_s) is bool
                  or not math.isfinite(close_timeout_s) or close_timeout_s < 0,
                  type(find_limit) is not int or find_limit <= 0
                  or find_limit > _MAX_FIND_LIMIT,
                  type(index_scan_budget) is not int or index_scan_budget <= 0,
                  type(index_line_bytes) is not int or index_line_bytes < 1024,
                  type(index_scan_bytes) is not int or index_scan_bytes <= 0,
                  type(index_parse_budget) is not int or index_parse_budget <= 0,
                  type(history_max) is not int or history_max <= 0,
                  type(max_image_pixels) is not int or max_image_pixels <= 0,
                  type(max_image_bytes) is not int or max_image_bytes <= 0,
                  type(max_meta_bytes) is not int or max_meta_bytes <= 0,
                  not callable(clock))
        if any(checks):
            raise ValueError("invalid worker budget")
        self._store = store
        self._root = Path(store.root)
        self._queue_max = queue_max
        self._ttl_s = float(ttl_s)
        self._close_timeout_s = float(close_timeout_s)
        self._find_limit = find_limit
        self._index_scan_budget = index_scan_budget
        self._index_line_bytes = index_line_bytes
        self._index_scan_bytes = index_scan_bytes
        self._index_parse_budget = index_parse_budget
        self._history_max = history_max
        self._max_image_pixels = max_image_pixels
        self._max_image_bytes = max_image_bytes
        self._max_meta_bytes = max_meta_bytes
        self._clock = clock
        self._lock = threading.Lock()
        self._commit_lock = threading.Lock()  # commit authorization only
        self._queue = queue.Queue(maxsize=queue_max)
        self._tasks = {}                     # ref → task dict (hard bounded)
        self._order = collections.deque()    # terminal refs, oldest first
        self._pending = 0                    # pending+inflight task count
        self._reserved = 0                   # unconverted admission slots
        self._next_ref = 1
        self._thread = None
        self._inflight = None                # ref currently inside store.save
        self._closing = False
        self._closed = False
        self._close_deadline = None
        self._bad_index_lines = 0
        self._oversized_index_lines = 0
        self._index_write_failures = 0
        self._commit_uncertain_appends = 0
        self._queue_full_rejections = 0
        self._oversize_image_rejections = 0
        self._oversize_meta_rejections = 0
        self._history_evictions = 0
        self._cross_camera_index_lines = 0
        self._unsafe_index_reads = 0
        self._index_scan_truncations = 0

    # ------------------------------------------------------------- lifecycle

    def start(self):
        """Spawn the single worker thread; idempotent while not closed."""
        with self._lock:
            if self._closing or self._closed:
                return
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._run,
                                            name="crop-evidence-worker")
            self._thread.start()

    def close(self, timeout_s=None):
        """Bounded stop: drain within the window, then drop the leftovers.

        Idempotent. Pending tasks that had not yet taken their commit
        authorization when the bounded join ends become
        ``dropped(stop_timeout)``; a task whose index append already started
        is never dropped — it finishes honestly as ``saved``,
        ``failed(index_failed)`` or ``commit_uncertain`` once its
        uncancellable append settles, so memory and the persistent index
        never disagree and an uncertain task is never rewritten to dropped.
        Returns an honest summary: how many were dropped here, which refs
        were still committing, how many sit in the ``commit_uncertain``
        terminal state, and whether the thread is still alive.
        """
        if timeout_s is None:
            timeout_s = self._close_timeout_s
        if type(timeout_s) not in (int, float) or type(timeout_s) is bool \
                or not math.isfinite(timeout_s) or timeout_s < 0:
            raise ValueError("invalid close timeout")
        with self._lock:
            if self._closing or self._closed:
                self._closed = True
                return self._close_summary_locked(0)
            self._closing = True
            self._close_deadline = self._clock() + timeout_s
            thread = self._thread
        if thread is not None:
            thread.join(timeout_s)
        with self._lock:
            self._closed = True
            dropped = 0
            # list(): _finish_locked may evict entries from _tasks.
            for task in list(self._tasks.values()):
                if task["status"] != "pending" or task["authorized"]:
                    continue
                if self._finish_locked(task, "dropped", "stop_timeout"):
                    dropped += 1
            return self._close_summary_locked(dropped)

    def _close_summary_locked(self, dropped):
        thread = self._thread
        return {"dropped": dropped,
                "committing": sorted(t["ref"] for t in self._tasks.values()
                                     if t["status"] == "pending"
                                     and t["authorized"]),
                "commit_uncertain": sum(1 for t in self._tasks.values()
                                        if t["status"] == "commit_uncertain"),
                "thread_alive": thread is not None and thread.is_alive()}

    def join(self, timeout_s=5.0):
        """Bounded join for lifecycle owners/tests; True when thread ended."""
        if type(timeout_s) not in (int, float) or type(timeout_s) is bool \
                or not math.isfinite(timeout_s) or timeout_s < 0:
            raise ValueError("invalid join timeout")
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout_s)
        return not thread.is_alive()

    # ------------------------------------------------------------- interface

    def submit(self, image_bgr, provenance):
        """Non-blocking enqueue of an owned image copy; never touches disk.

        Admission reservation protocol (C141-R2 §1, frozen): under one short
        state lock the worker decides stopped/queue-capacity and atomically
        reserves the slot. The unified hard bound is
        ``reserved + pending + inflight ≤ queue_max + 1`` — ``pending``
        counts created non-terminal tasks (queued plus the at most one
        inside ``store.save``), ``reserved`` counts submissions holding an
        unconverted reservation. True acceptance capacity is therefore
        unchanged (at most ``queue_max + 1`` non-terminal tasks can ever
        exist); the reservation only makes the slot claim atomic, so
        concurrent submissions cannot overshoot the bound while copying.
        After the claim the caller releases the lock: oversize inputs are
        measured and the image copied / provenance deepcopied strictly
        OUTSIDE every lock (a slow copy never blocks status/close/fast
        paths). Reacquiring the lock, the reservation is converted into a
        queued task or released — and every release path (stopped, oversize,
        copy failure, enqueue failure, unexpected exception) fires the
        one-shot guard exactly once, so reservations never leak. Rejected
        submissions copy nothing (R1 semantics kept).
        """
        copy_method = getattr(image_bgr, "copy", None)
        if not callable(copy_method):
            raise ValueError("image_bgr must support copy()")
        reserved = False                     # one-shot reservation guard
        try:
            with self._lock:
                self._sweep_expired_locked()
                thread = self._thread
                if self._closing or self._closed or thread is None \
                        or not thread.is_alive():
                    return {"status": "dropped", "reason": "worker_stopped"}
                if self._reserved + self._pending >= self._queue_max + 1:
                    self._queue_full_rejections += 1
                    return {"status": "dropped", "reason": "queue_full"}
                self._reserved += 1          # atomic capacity claim
                reserved = True
            shape = getattr(image_bgr, "shape", None)
            if (isinstance(shape, tuple) and len(shape) >= 2
                    and type(shape[0]) is int and type(shape[1]) is int
                    and shape[0] * shape[1] > self._max_image_pixels):
                with self._lock:
                    self._oversize_image_rejections += 1
                    self._reserved -= 1
                    reserved = False
                return {"status": "dropped", "reason": "image_oversize"}
            img_bytes = getattr(image_bgr, "nbytes", None)
            if type(img_bytes) is int and img_bytes > self._max_image_bytes:
                with self._lock:
                    self._oversize_image_rejections += 1
                    self._reserved -= 1
                    reserved = False
                return {"status": "dropped", "reason": "image_oversize"}
            try:
                meta_probe = json.dumps(provenance, ensure_ascii=False,
                                        separators=(",", ":")).encode("utf-8")
            except Exception:
                meta_probe = None            # not JSON-shaped: the store will judge
            if meta_probe is not None and len(meta_probe) > self._max_meta_bytes:
                with self._lock:
                    self._oversize_meta_rejections += 1
                    self._reserved -= 1
                    reserved = False
                return {"status": "dropped", "reason": "provenance_oversize"}
            try:
                image = copy_method()
            except Exception:
                raise ValueError("image_bgr must support copy()") from None
            try:
                payload = deepcopy(provenance)
            except Exception:
                raise ValueError("provenance must be copyable") from None
            with self._lock:                 # reservation conversion
                thread = self._thread
                if self._closing or self._closed or thread is None \
                        or not thread.is_alive():
                    self._reserved -= 1
                    reserved = False
                    return {"status": "dropped", "reason": "worker_stopped"}
                ref = self._next_ref
                self._next_ref += 1
                now_ms = int(self._clock() * 1000)
                task = {"ref": ref, "status": "pending", "reason": None,
                        "asset_id": None, "submitted_ms": now_ms,
                        "finished_ms": None, "image": image,
                        "provenance": payload, "authorized": False,
                        # Frozen nine-key snapshot (C141-R3 §1): stays after
                        # the terminal provenance release so terminal tasks
                        # (incl. commit_uncertain) remain identity-matchable
                        # with zero disk I/O and no unbounded registry.
                        "identity": {key: payload.get(key)
                                     for key in _COMMIT_IDENTITY_KEYS}}
                self._tasks[ref] = task
                self._pending += 1
                self._reserved -= 1          # the slot moved with the task
                reserved = False
                try:
                    self._queue.put_nowait(ref)
                except queue.Full:           # lost race vs the consumer's
                    self._queue_full_rejections += 1   # transient get window
                    self._finish_locked(task, "dropped", "queue_full")
                    return {"status": "dropped", "reason": "queue_full"}
            return {"ref": ref, "status": "pending"}
        except BaseException:
            if reserved:                     # exactly-once release: the guard
                reserved = False             # is already false on every
                with self._lock:             # explicit path above, so this
                    self._reserved -= 1      # backstop covers only unexpected
            raise                            # exception paths

    def status(self, ref):
        """Zero-blocking, zero-disk-write state of one ref (unknown if absent).

        Terminal states are ``saved``, ``failed``, ``dropped`` and the
        honest uncertainty state ``commit_uncertain`` (C141-R2 §2: the
        index line may or may not be durable/reachable — memory claims
        neither failed nor saved; the real asset id is reported because the
        archive itself exists). A ``commit_uncertain`` state is never
        rewritten to anything else.
        """
        with self._lock:
            self._sweep_expired_locked()
            task = self._tasks.get(ref) if type(ref) is int else None
            if task is None:
                return {"ref": ref, "status": "unknown", "reason": None,
                        "asset_id": None, "submitted_ms": None,
                        "finished_ms": None}
            return {"ref": task["ref"], "status": task["status"],
                    "reason": task["reason"], "asset_id": task["asset_id"],
                    "submitted_ms": task["submitted_ms"],
                    "finished_ms": task["finished_ms"]}

    def commit_status(self, camera_id, identity):
        """In-memory commit state of the current task under a full identity.

        Authoritative contract (C141-R3 interface freeze §1). ``find``
        reports the PERSISTENT index facts only (durable ``saved``/``failed``
        lines — it never returns ``commit_uncertain``); THIS method reports
        the complementary CURRENT in-memory fact for the live task table, so
        the server can honestly compose "the index line is already readable
        while durability is unproven" at its layer. Read-only: zero disk
        access, zero side effects (no TTL sweep, no counters, nothing
        created, rewritten or deleted) — one short iteration of the already
        bounded task table (non-terminal ≤ queue_max+1, terminal history ≤
        history_max; there is NO unbounded registry).

        * ``identity``: the complete nine-key identity (camera_id/run_id/
          config_version/material_id/window_id/branch/crop_id/frame_id/
          slot). Every key is required — absent or None raises
          ``ValueError("incomplete identity")``; the server gates
          completeness before calling.
        * Matching: full nine-key equality against the task's frozen
          identity snapshot with the R1 normalized int/str comparison
          (``_filter_matches``); the ``camera_id`` argument must agree with
          the identity's own camera key too. A different ``run_id`` never
          matches — state is never borrowed across runs (or workers).
        * Returns: a matched task in ``commit_uncertain`` →
          ``{"status": "commit_uncertain", "reason":
          "index_commit_uncertain", "asset_id": <real 64-hex id or None>}``;
          matched tasks with no uncertainty (pending/saved/failed/dropped)
          → ``{"status": None}`` (explicit "no uncertainty right now");
          no matching task → ``None`` (= unobserved / the writing process's
          memory state is lost — after a restart the empty table answers
          ``None`` and uncertainty is NEVER fabricated).
        """
        if not isinstance(camera_id, str) or not 0 < len(camera_id) <= 200:
            raise ValueError(
                "camera_id must be a non-empty string of at most 200 chars")
        if not isinstance(identity, dict) or any(
                identity.get(key) is None for key in _COMMIT_IDENTITY_KEYS):
            raise ValueError("incomplete identity")
        with self._lock:
            matched = False
            for task in self._tasks.values():
                snapshot = task["identity"]
                if not all(_filter_matches(snapshot.get(key), identity[key])
                           for key in _COMMIT_IDENTITY_KEYS):
                    continue
                if not _filter_matches(snapshot.get("camera_id"), camera_id):
                    continue        # param/identity camera disagreement:
                matched = True      # never answer across cameras
                if task["status"] == "commit_uncertain":
                    return {"status": "commit_uncertain",
                            "reason": "index_commit_uncertain",
                            "asset_id": task["asset_id"]}
        if not matched:
            return None
        return {"status": None}

    def find(self, camera_id, filters=None, limit=None):
        """Indexed registry for one camera; newest first, bounded; read-only.

        Reads only this camera's own index file through the fenced reader;
        records whose camera differs from the file's owner are poison rows —
        skipped and counted, never returned. Orphan assets (on disk without
        an index record) are never reported. The index file is the
        authoritative truth (C141-R2 §2): a durable line reads as ``saved``
        even when the writing task ended ``commit_uncertain`` in memory, and
        an absent line is never invented; ``find`` therefore never returns
        the uncertain state itself — ``status(ref)`` does. Identity filters
        compare int/str scalars in normalized string form; bool filter
        values never match numbers or their string forms.
        """
        if not isinstance(camera_id, str) or not 0 < len(camera_id) <= 200:
            raise ValueError("camera_id must be a non-empty string of at most 200 chars")
        if limit is None:
            limit = self._find_limit
        if type(limit) is not int or not 0 < limit <= _MAX_FIND_LIMIT:
            raise ValueError("limit must be a positive integer")
        if filters is None:
            filters = {}
        if not isinstance(filters, dict) or set(filters) - _FILTER_FIELDS:
            raise ValueError("unsupported filter fields")
        try:
            path = _camera_index_path(self._root, camera_id)
        except ValueError:
            return []
        records, counters = _read_camera_records(
            path, camera_id=camera_id,
            line_bytes_cap=self._index_line_bytes,
            record_budget=self._index_scan_budget,
            scan_bytes_budget=self._index_scan_bytes,
            parse_budget=self._index_parse_budget)
        with self._lock:
            self._bad_index_lines += counters["bad_lines"]
            self._oversized_index_lines += counters["oversized_lines"]
            self._cross_camera_index_lines += counters["cross_camera"]
            self._unsafe_index_reads += counters["unsafe"]
            self._index_scan_truncations += counters["truncated"]
        matched = []
        for record in records:
            if all(_filter_matches(record.get(field), value)
                   for field, value in filters.items()):
                matched.append(record)
                if len(matched) >= limit:
                    break
        return matched

    def read(self, asset_id):
        """Verified archive read; unchanged store validation (fixed codes)."""
        return self._store.read(asset_id)

    def diagnostics(self):
        """Honest counters for budget, fence and index anomalies (no paths).

        ``commit_uncertain_appends`` counts index appends whose durability
        is unproven (C141-R2 §2) — separate from ``index_write_failures``,
        which counts certain pre-write failures.
        """
        with self._lock:
            return {"bad_index_lines": self._bad_index_lines,
                    "oversized_index_lines": self._oversized_index_lines,
                    "index_write_failures": self._index_write_failures,
                    "commit_uncertain_appends": self._commit_uncertain_appends,
                    "queue_full_rejections": self._queue_full_rejections,
                    "oversize_image_rejections":
                        self._oversize_image_rejections,
                    "oversize_meta_rejections":
                        self._oversize_meta_rejections,
                    "history_evictions": self._history_evictions,
                    "cross_camera_index_lines":
                        self._cross_camera_index_lines,
                    "unsafe_index_reads": self._unsafe_index_reads,
                    "index_scan_truncations": self._index_scan_truncations}

    # ------------------------------------------------------------ internals

    def _run(self):
        while True:
            with self._lock:
                closing = self._closing
                deadline = self._close_deadline
            if closing and (self._queue.empty()
                            or self._clock() >= deadline):
                break
            if not closing:
                self._sweep_expired()
            try:
                ref = self._queue.get(timeout=0.02)
            except queue.Empty:
                continue
            self._process(ref)

    def _sweep_expired(self):
        with self._lock:
            self._sweep_expired_locked()

    def _sweep_expired_locked(self):
        """TTL tick (memory only): expired still-pending refs → dropped."""
        now = self._clock()
        # list(): _finish_locked may evict entries from _tasks.
        for task in list(self._tasks.values()):
            if task["status"] == "pending" and task["ref"] != self._inflight \
                    and now - task["submitted_ms"] / 1000.0 > self._ttl_s:
                self._finish_locked(task, "dropped", "ttl_exceeded")

    def _process(self, ref):
        with self._lock:
            task = self._tasks.get(ref)
            if task is None or task["status"] != "pending":
                return                      # swept or dropped before execution
            image = task["image"]
            payload = task["provenance"]
            submitted_ms = task["submitted_ms"]
            self._inflight = ref
        try:
            try:
                asset_id = self._store.save(image, payload)
            except CropEvidenceError as error:
                self._finish_failed(task, payload, ref, submitted_ms, error.code)
                return
            except Exception:
                self._finish_failed(task, payload, ref, submitted_ms, "write_failed")
                return
            if not self._authorize_commit_locked(task):
                return                      # dropped before authorization: the
                # asset stays an orphan on disk — never indexed, never
                # attributed, and never dressed up as saved or dropped twice.
            try:
                self._append_index(payload, ref, asset_id, "saved", None,
                                   submitted_ms)
            except CropEvidenceError as error:
                with self._lock:
                    if error.code == "commit_uncertain":
                        # C141-R2 §2: the line may already be durable and
                        # reachable — honest uncertainty, never dressed up
                        # as failed or saved; terminal + authorized, so the
                        # closer's sweep can never rewrite it to dropped.
                        self._commit_uncertain_appends += 1
                        self._finish_locked(task, "commit_uncertain",
                                            "index_commit_uncertain", asset_id)
                    else:
                        self._index_write_failures += 1
                        self._finish_locked(task, "failed", "index_failed")
                return
            except Exception:
                with self._lock:
                    self._index_write_failures += 1
                    self._finish_locked(task, "failed", "index_failed")
                return
            with self._lock:
                self._finish_locked(task, "saved", None, asset_id)
        finally:
            with self._lock:
                if self._inflight == ref:
                    self._inflight = None

    def _authorize_commit_locked(self, task):
        """Short in-memory commit authorization BEFORE the index append.

        Takes the dedicated commit lock and then the state lock; a pure
        memory decision with zero disk I/O inside either. Exactly one of the
        closer's leftover sweep and this grant wins per task: the sweep
        never drops an authorized task and this grant never revives a
        dropped one. Authorization strictly precedes the append and cannot
        be reversed by a later stop, so one ref can never end up ``dropped``
        in memory while ``saved`` in the persistent index (or vice versa).
        """
        with self._commit_lock:
            with self._lock:
                if task["status"] != "pending":
                    return False
                task["authorized"] = True
                return True

    def _finish_failed(self, task, payload, ref, submitted_ms, code):
        # Best-effort registry line for attributable failures; a registry gap
        # here is honest and never changes the task's own failure code. The
        # same commit authorization gates the failure line: a task the closer
        # already dropped gets no contradicting "failed" index line. The
        # task's failure itself is CERTAIN (store.save raised), so even an
        # uncertain registry append (C141-R2 §2) only moves the uncertainty
        # counter — the terminal state stays the honest ``failed(code)``.
        if not self._authorize_commit_locked(task):
            return
        try:
            self._append_index(payload, ref, None, "failed", code, submitted_ms)
        except CropEvidenceError as error:
            with self._lock:
                if error.code == "commit_uncertain":
                    self._commit_uncertain_appends += 1  # counted, never retried
                else:
                    self._index_write_failures += 1
        except Exception:
            with self._lock:
                self._index_write_failures += 1
        with self._lock:
            self._finish_locked(task, "failed", code)

    def _append_index(self, payload, ref, asset_id, status, reason, submitted_ms):
        """One durable registry append; raises on any failure (caller maps).

        Frozen two-phase durability protocol (C141-R2 §2):

        * Pre-write failure — record build/serialization, directory/file
          fences, the ``open`` itself, the opened-handle identity check —
          raises ``index_failed``: not one byte of the line was written, so
          a certain ``failed(index_failed)`` is honest.
        * Any failure of ``write``/``flush``/``fsync`` (or of the handle
          close) raises ``commit_uncertain``: the line — or part of it —
          may already be durable and reachable, so the honest state is
          NEITHER ``failed`` NOR ``saved``. Uncertainty is never retried,
          never deleted, never swallowed: the fsync error propagates as the
          task's ``commit_uncertain`` terminal state.
        * Post-fsync final fence (C141-R2 §3): if the path no longer names
          the very regular file this handle just fsynced, or it shrank, the
          appended line's reachability is unknown → ``commit_uncertain``.

        The authoritative truth is the index file itself: ``find``/restart
        read actual lines — a present line reads as saved, an absent line
        stays unattributed. The index file never stores uncertainty: its
        lines are only ``saved``/``failed``.
        """
        record = _index_record(payload, ref, asset_id, status, reason,
                               submitted_ms, int(self._clock() * 1000))
        if record is None:
            raise CropEvidenceError("index_failed")       # pre-write
        line = json.dumps(record, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"),
                          allow_nan=False).encode("utf-8") + b"\n"
        if len(line) > self._index_line_bytes:
            raise CropEvidenceError("index_failed")       # pre-write
        index_dir = self._root / _INDEX_DIR
        try:
            dir_stat = index_dir.lstat()
        except FileNotFoundError:
            index_dir.mkdir(parents=True, exist_ok=True)
            dir_stat = index_dir.lstat()
        if not stat.S_ISDIR(dir_stat.st_mode) or _is_reparse(dir_stat):
            raise CropEvidenceError("index_failed")       # pre-write
        path = _camera_index_path(self._root, record["camera_id"])
        before = None
        try:
            file_stat = path.lstat()
            if not stat.S_ISREG(file_stat.st_mode) or _is_reparse(file_stat):
                raise CropEvidenceError("index_failed")   # pre-write
            before = file_stat
        except FileNotFoundError:
            pass
        flags = (os.O_WRONLY | os.O_CREAT | os.O_APPEND
                 | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            fd = os.open(path, flags, 0o600)
        except OSError:
            raise CropEvidenceError("index_failed") from None   # pre-write
        try:
            opened = os.fstat(fd)
            # C141-R2 §3: the opened handle must be a regular file and —
            # when the path pre-existed — the very file the pre-check saw.
            if not stat.S_ISREG(opened.st_mode) or (
                    before is not None
                    and not _same_identity(opened, before)):
                raise CropEvidenceError("index_failed")   # pre-write
        except OSError:
            os.close(fd)
            raise CropEvidenceError("index_failed") from None
        except CropEvidenceError:
            os.close(fd)
            raise
        try:
            stream = os.fdopen(fd, "ab")
        except Exception:
            os.close(fd)
            raise CropEvidenceError("index_failed") from None   # pre-write
        try:
            with stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:                                 # write/flush/fsync:
            raise CropEvidenceError("commit_uncertain") from None   # may be
        # durable and reachable — honest uncertainty (C141-R2 §2).
        try:
            after = path.lstat()
        except OSError:
            raise CropEvidenceError("commit_uncertain") from None
        if (not stat.S_ISREG(after.st_mode) or _is_reparse(after)
                or not _same_identity(after, opened)
                or after.st_size < opened.st_size):
            # Final fence: the durable line is only honest while the path
            # still names the file we just fsynced and still holds our
            # bytes (append-only growth is legitimate; a shrink is not).
            raise CropEvidenceError("commit_uncertain")

    def _finish_locked(self, task, status, reason=None, asset_id=None):
        """Single pending → terminal transition; releases the copy once.

        Terminal states: saved | failed | dropped | commit_uncertain. The
        asset id is reported for ``saved`` and for ``commit_uncertain``
        (the archive exists; only its registry line is uncertain).
        """
        if task["status"] != "pending":
            return False
        task["status"] = status
        task["reason"] = reason
        task["asset_id"] = (asset_id if status in ("saved", "commit_uncertain")
                            else None)
        task["finished_ms"] = int(self._clock() * 1000)
        task["image"] = None
        task["provenance"] = None
        self._pending -= 1
        self._order.append(task["ref"])
        self._evict_locked()
        return True

    def _evict_locked(self):
        """Bounded task history: oldest terminal records only.

        Non-terminal refs are bounded at admission (reservations join the
        same ``queue_max+1`` hard bound, C141-R2 §1, so ``_tasks`` never
        holds more than ``queue_max+1`` pending entries) and terminal
        records are bounded here (≤ history_max); eviction walks the
        terminal deque only, so the oldest pending ref can never stall
        terminal reclamation.
        """
        evicted = 0
        while len(self._tasks) > self._history_max and self._order:
            ref = self._order.popleft()
            task = self._tasks.get(ref)
            if task is None or task["status"] == "pending":
                continue                    # stale guard; pending never enters
            del self._tasks[ref]
            evicted += 1
        if evicted:
            self._history_evictions += evicted
