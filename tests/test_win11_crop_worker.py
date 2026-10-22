"""C-141 A3: CropWorker determinism tests.

Every test is deterministic: injected fake clocks, event-ordered gates, no
long sleeps, no subprocess. All worker threads are joined/reclaimed before a
test ends (teardown closes every created worker after gates are released).
"""
import hashlib
import json
import os
import queue
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import cv2
import numpy as np
import pytest

import scam.win11_crop_worker as crop_worker_module
from scam.win11_crop_evidence import CropEvidenceError, CropEvidenceStore
from scam.win11_crop_worker import CropWorker


def provenance(camera="验收相机", frame=2, **extra):
    meta = dict(camera_id=camera, run_id="run1", config_version=1,
                material_id="material1", frame_id=frame, crop_id="crop1",
                t_capture_ms=1000, timestamp_kind="host_receive",
                source_size=[40, 30], bbox_px=[5, 4, 25, 14])
    meta.update(extra)
    return meta


def pixels(seed=0):
    return ((np.arange(600, dtype=np.uint8).reshape(10, 20, 3)
             + np.uint8(seed % 256))).astype(np.uint8)


class FakeClock:
    def __init__(self, start=10_000.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class GateStore:
    """Real store behind an event gate: deterministic in-flight blocking."""

    def __init__(self, inner):
        self.inner = inner
        self.gate = threading.Event()
        self.gate.set()
        self.entered = threading.Event()

    @property
    def root(self):
        return self.inner.root

    def read(self, asset_id):
        return self.inner.read(asset_id)

    def save(self, frame, prov):
        self.entered.set()
        if not self.gate.wait(timeout=10):
            raise CropEvidenceError("write_failed")
        return self.inner.save(frame, prov)


def wait_until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.002)
    return bool(predicate())


class CopyCountingImage:
    """Probe image: counts copy() calls, delegates shape/nbytes like an array."""

    def __init__(self, array):
        self._array = array
        self.copies = 0

    @property
    def shape(self):
        return self._array.shape

    @property
    def nbytes(self):
        return self._array.nbytes

    def copy(self):
        self.copies += 1
        return self._array.copy()


class CountingProv(dict):
    """Probe provenance: counts deepcopy attempts (zero-copy assertions)."""

    def __init__(self, meta):
        super().__init__(meta)
        self.deepcopies = 0

    def __deepcopy__(self, memo):
        self.deepcopies += 1
        clone = CountingProv(self)
        clone.deepcopies = self.deepcopies
        return clone


class GatedIndexWorker(CropWorker):
    """Worker whose index append blocks on an event: deterministic gate."""

    def __init__(self, store, **kwargs):
        super().__init__(store, **kwargs)
        self.index_gate = threading.Event()
        self.index_gate.set()
        self.index_entered = threading.Event()

    def _append_index(self, *args, **kwargs):
        self.index_entered.set()
        if not self.index_gate.wait(timeout=10):
            raise CropEvidenceError("index_failed")
        return super()._append_index(*args, **kwargs)


def poison_record(cam, *, ref=999, frame=42, asset="f" * 64):
    """A fully well-formed registry line, for planting into foreign files."""
    return {"schema": "sc.cropindex/v1", "ref": ref, "asset_id": asset,
            "status": "saved", "reason": None, "submitted_ms": 1,
            "finished_ms": 1, "camera_id": cam, "run_id": "run1",
            "config_version": 1, "material_id": "material1",
            "crop_id": "crop1", "frame_id": frame, "t_capture_ms": 1000,
            "timestamp_kind": "host_receive"}


def index_line(record):
    return json.dumps(record, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8") + b"\n"


@pytest.fixture
def factory(tmp_path):
    created = []

    def make(**kwargs):
        store = kwargs.pop("store", None)
        if store is None:
            store = CropEvidenceStore(tmp_path / ("root%d" % len(created)))
        worker = CropWorker(store, **kwargs)
        worker.start()
        created.append(worker)
        return worker, store

    yield make
    for worker in created:
        worker.close(timeout_s=2.0)


# ---------------------------------------------------------------- 1 saved


def test_submit_saved_pixels_identity_and_content_address(factory):
    worker, store = factory()
    frame = pixels()
    pristine = frame.copy()
    meta = provenance(branch="local", slot="current", window_id=3)
    ref = worker.submit(frame, meta)["ref"]
    assert wait_until(lambda: worker.status(ref)["status"] == "saved")
    frame[:] = 0                       # submit owned a copy: archive unchanged
    status = worker.status(ref)
    asset = status["asset_id"]
    assert len(asset) == 64 and status["reason"] is None
    assert status["finished_ms"] >= status["submitted_ms"]
    # asset_id is the sha256 of the archived bytes, not the crop logic id
    assert hashlib.sha256(
        (Path(store.root) / (asset + ".crop")).read_bytes()).hexdigest() == asset
    read = worker.read(asset)
    assert read["metadata"]["schema"] == "sc.crop/v2"
    assert read["metadata"]["provenance"] == meta
    image = cv2.imdecode(np.frombuffer(read["png"], np.uint8), cv2.IMREAD_COLOR)
    assert np.array_equal(image, pristine)
    assert hashlib.sha256(read["png"]).hexdigest() == read["metadata"]["png_sha256"]
    records = worker.find(meta["camera_id"])
    assert len(records) == 1
    assert records[0]["asset_id"] == asset and records[0]["status"] == "saved"


# ------------------------------------------------------------ 2 queue full


def test_queue_full_drops_immediately_without_blocking(tmp_path):
    gate = GateStore(CropEvidenceStore(tmp_path))
    gate.gate.clear()
    worker = CropWorker(gate, queue_max=1)
    worker.start()
    try:
        first = worker.submit(pixels(), provenance(frame=1))
        assert first["status"] == "pending"
        assert gate.entered.wait(5)          # deterministic: save in flight
        second = worker.submit(pixels(), provenance(frame=2))
        assert second["status"] == "pending"  # fills the single queue slot
        third = worker.submit(pixels(), provenance(frame=3))
        assert third == {"status": "dropped", "reason": "queue_full"}
    finally:
        gate.gate.set()
    assert wait_until(lambda: worker.status(first["ref"])["status"] == "saved"
                      and worker.status(second["ref"])["status"] == "saved")
    records = worker.find(provenance()["camera_id"])
    assert len(records) == 2
    assert all(r["status"] == "saved" for r in records)
    assert worker.status(third.get("ref", -1))["status"] == "unknown"
    worker.close()


# ------------------------------------------------------------------- 3 TTL


def test_ttl_sweeps_pending_only_not_inflight(tmp_path):
    clock = FakeClock()
    gate = GateStore(CropEvidenceStore(tmp_path))
    gate.gate.clear()
    worker = CropWorker(gate, ttl_s=50, clock=clock)
    worker.start()
    try:
        first = worker.submit(pixels(), provenance(frame=1))["ref"]
        assert gate.entered.wait(5)
        second = worker.submit(pixels(), provenance(frame=2))["ref"]
        clock.advance(100)
        state = worker.status(second)      # status() is a sweep tick
        assert state["status"] == "dropped" and state["reason"] == "ttl_exceeded"
        assert state["asset_id"] is None
        assert worker.status(first)["status"] == "pending"  # in-flight kept
    finally:
        gate.gate.set()
    assert wait_until(lambda: worker.status(first)["status"] == "saved")
    worker.close()


# --------------------------------------------------- 4 same content racing


def test_concurrent_same_content_single_asset_no_clobber(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store)
    worker.start()
    try:
        meta = provenance()
        with ThreadPoolExecutor(max_workers=4) as pool:
            refs = [r["ref"] for r in pool.map(
                lambda _: worker.submit(pixels(), meta), range(6))]
        assert wait_until(lambda: all(
            worker.status(r)["status"] == "saved" for r in refs))
        assets = {worker.status(r)["asset_id"] for r in refs}
        assert len(assets) == 1            # content addressing, one asset
        asset_id = assets.pop()
        assert len(list(Path(store.root).glob("*.crop"))) == 1  # no clobber
        records = worker.find(meta["camera_id"])
        assert len(records) == 6
        assert all(r["asset_id"] == asset_id for r in records)
    finally:
        worker.close()


# ------------------------------------------------------- 5 multi-camera mix


def test_multi_camera_cross_submissions_isolated(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store)
    worker.start()
    cams = ["相机-α", "camera-b"]
    try:
        def submit(i):
            meta = provenance(camera=cams[i % 2], frame=i,
                              branch="local", slot="current")
            return cams[i % 2], worker.submit(pixels(seed=i), meta)["ref"]
        with ThreadPoolExecutor(max_workers=4) as pool:
            pairs = list(pool.map(submit, range(10)))
        assert wait_until(lambda: all(
            worker.status(r)["status"] == "saved" for _, r in pairs))
        records_a = worker.find(cams[0])
        records_b = worker.find(cams[1])
        assert len(records_a) == 5 and len(records_b) == 5
        assert all(r["camera_id"] == cams[0] for r in records_a)
        assert all(r["camera_id"] == cams[1] for r in records_b)
        assert ({r["asset_id"] for r in records_a}
                == {worker.status(r)["asset_id"] for c, r in pairs if c == cams[0]})
        # identity filters: equal match inside one camera, never across
        probe = records_b[0]
        assert [x["asset_id"] for x in
                worker.find(cams[1], filters={"asset_id": probe["asset_id"]})] \
            == [probe["asset_id"]]
        assert worker.find(cams[0], filters={"asset_id": probe["asset_id"]}) == []
        assert worker.find(cams[1], filters={"branch": "local", "slot": "current"})
        assert worker.find(cams[1], filters={"slot": "previous"}) == []
        assert len(list((Path(store.root) / "index").glob("*.jsonl"))) == 2
    finally:
        worker.close()


def test_find_identity_filters_match_int_or_string_shapes(tmp_path):
    # C-141 integration regression: B's provenance carries int identity
    # scalars while the server filters with strings derived from window/branch
    # keys — find() must normalize both shapes; bool never matches 1/0.
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store)
    worker.start()
    cam = "类型相机"
    try:
        meta = provenance(camera=cam, frame=7, config_version=0,
                          material_id=610, window_id=11,
                          branch="local", slot="current")
        ref = worker.submit(pixels(), meta)["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] == "saved")
        for field, shapes in (("window_id", (11, "11")),
                              ("material_id", (610, "610")),
                              ("config_version", (0, "0")),
                              ("frame_id", (7, "7"))):
            for value in shapes:
                records = worker.find(cam, filters={field: value})
                assert len(records) == 1, (field, value)
                assert records[0]["ref"] == ref
        # bool keeps its own type: no match against 1/0 or "1"/"0" either way
        for field in ("window_id", "material_id", "config_version", "frame_id"):
            assert worker.find(cam, filters={field: True}) == []
            assert worker.find(cam, filters={field: False}) == []
        # genuine mismatches still miss in both shapes
        assert worker.find(cam, filters={"window_id": 12}) == []
        assert worker.find(cam, filters={"window_id": "12"}) == []
        assert worker.find(cam, filters={"window_id": 11,
                                         "slot": "current",
                                         "branch": "local"}) \
            == worker.find(cam, filters={"window_id": "11"})
    finally:
        worker.close()


# ---------------------------------------------------------- 6 capacity fail


def test_capacity_failure_is_honest_and_keeps_old_evidence(tmp_path):
    root = tmp_path / "cap"
    seed_store = CropEvidenceStore(root)
    seed_asset = seed_store.save(pixels(), provenance(frame=1))
    size = (root / (seed_asset + ".crop")).stat().st_size
    capped = CropEvidenceStore(root, max_total_bytes=size + 1)
    worker = CropWorker(capped)
    worker.start()
    try:
        ref = worker.submit(pixels(seed=7), provenance(frame=2))["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] == "failed")
        status = worker.status(ref)
        assert status["reason"] == "capacity" and status["asset_id"] is None
        assert capped.read(seed_asset)             # old evidence intact
        assert len(list(root.glob("*.crop"))) == 1  # nothing deleted, nothing faked
        records = worker.find(provenance()["camera_id"])
        assert any(r["status"] == "failed" and r["reason"] == "capacity"
                   and r["asset_id"] is None for r in records)
        assert not any(r["ref"] == ref and r["status"] == "saved" for r in records)
    finally:
        worker.close()


# ------------------------------------------------------- 7 index write fail


def test_index_write_failure_reports_index_failed(tmp_path):
    root = tmp_path / "poisoned"
    store = CropEvidenceStore(root)
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    (root / "index").mkdir()
    (root / "index" / (key + ".jsonl")).mkdir()   # write boundary fails for real
    worker = CropWorker(store)
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] == "failed")
        status = worker.status(ref)
        assert status["reason"] == "index_failed" and status["asset_id"] is None
        assets = list(root.glob("*.crop"))
        assert len(assets) == 1                  # asset exists: honest state
        read = worker.read(assets[0].stem)
        assert read["metadata"]["provenance"] == provenance()
        assert worker.find(cam) == []            # never attributed anywhere
    finally:
        worker.close()


# ---------------------------------------------------------- 8 read failures


def test_read_fixed_codes_through_worker(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store)
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] == "saved")
        asset = worker.status(ref)["asset_id"]
        with pytest.raises(CropEvidenceError, match="invalid_id"):
            worker.read("../escape")
        with pytest.raises(CropEvidenceError, match="invalid_id"):
            worker.read("")
        with pytest.raises(CropEvidenceError, match="missing"):
            worker.read("a" * 64)
        (Path(store.root) / (asset + ".crop")).write_bytes(b"tampered")
        with pytest.raises(CropEvidenceError, match="corrupt"):
            worker.read(asset)
    finally:
        worker.close()


# -------------------------------------------------------- 9 restart/orphans


def test_restart_finds_history_and_orphans_stay_unattributed(tmp_path):
    root = tmp_path / "restart"
    cam = "重启相机"
    w1 = CropWorker(CropEvidenceStore(root))
    w1.start()
    r1 = w1.submit(pixels(seed=1), provenance(camera=cam, frame=1,
                                              branch="local", slot="previous"))
    r2 = w1.submit(pixels(seed=2), provenance(camera=cam, frame=2,
                                              branch="local", slot="current"))
    assert wait_until(lambda: all(w1.status(r["ref"])["status"] == "saved"
                                  for r in (r1, r2)))
    saved_assets = {w1.status(r1["ref"])["asset_id"], w1.status(r2["ref"])["asset_id"]}
    w1.close()
    # a genuine orphan: byte-valid archive on disk with no index record
    stranger_asset = CropEvidenceStore(tmp_path / "elsewhere").save(
        pixels(seed=3), provenance(camera=cam, frame=3, slot="next"))
    (root / (stranger_asset + ".crop")).write_bytes(
        (tmp_path / "elsewhere" / (stranger_asset + ".crop")).read_bytes())
    w2 = CropWorker(CropEvidenceStore(root))   # fresh worker, same root
    w2.start()
    try:
        records = w2.find(cam)
        assert [r["frame_id"] for r in records] == [2, 1]   # newest first
        assert {r["asset_id"] for r in records} == saved_assets
        assert all(r["camera_id"] == cam for r in records)
        assert w2.find(cam, filters={"slot": "previous"})[0]["frame_id"] == 1
        # the orphan is readable as verified bytes but registered nowhere
        assert w2.read(stranger_asset)["metadata"]["provenance"]["frame_id"] == 3
        assert w2.find(cam, filters={"asset_id": stranger_asset}) == []
        assert w2.find(cam, filters={"frame_id": 3}) == []
        assert w2.status(r1["ref"])["status"] == "unknown"  # refs are per-worker
    finally:
        w2.close()


# --------------------------------------------------- 10 unsafe root via API


def test_unsafe_root_surfaces_through_worker(tmp_path):
    root = tmp_path / "unsafe"
    store = CropEvidenceStore(root)
    (root / "intruder.txt").write_bytes(b"foreign")
    worker = CropWorker(store)
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] == "failed")
        assert worker.status(ref)["reason"] == "unsafe_root"
        assert (root / "intruder.txt").read_bytes() == b"foreign"
    finally:
        worker.close()
    link = tmp_path / "linked"
    try:
        link.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        return                            # no symlink privilege on platform
    with pytest.raises(CropEvidenceError, match="unsafe_root"):
        CropEvidenceStore(link)           # symlinked root never becomes a store


# ------------------------------------------------------------ 11 close path


def test_close_bounded_stop_timeout_and_bounded_join(tmp_path):
    gate = GateStore(CropEvidenceStore(tmp_path))
    gate.gate.clear()
    worker = CropWorker(gate, close_timeout_s=0.3, clock=FakeClock())
    worker.start()
    inflight = worker.submit(pixels(), provenance(frame=1))["ref"]
    assert gate.entered.wait(5)
    queued = worker.submit(pixels(), provenance(frame=2))["ref"]
    started = time.monotonic()
    worker.close()                        # bounded stop
    assert time.monotonic() - started < 5.0
    for ref in (inflight, queued):
        state = worker.status(ref)
        assert state["status"] == "dropped" and state["reason"] == "stop_timeout"
    assert worker.submit(pixels(seed=9), provenance(frame=9)) \
        == {"status": "dropped", "reason": "worker_stopped"}
    worker.close()                        # idempotent
    gate.gate.set()                       # release the blocked save
    assert worker.join(5.0)               # bounded convergence, thread reaped
    for ref in (inflight, queued):
        state = worker.status(ref)
        assert state["status"] == "dropped"   # terminal state never overwritten
    assert worker.find(provenance()["camera_id"]) == []   # nothing faked saved
    assets = list(Path(gate.root).glob("*.crop"))
    assert len(assets) <= 1               # late save may land as an orphan only


def test_close_after_drain_saves_everything(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store)
    worker.start()
    refs = [worker.submit(pixels(seed=i), provenance(frame=i))["ref"]
            for i in range(5)]
    worker.close()
    assert all(worker.status(r)["status"] == "saved" for r in refs)
    asset = worker.status(refs[0])["asset_id"]
    # pure v1 provenance through the worker keeps the v1 label
    assert worker.read(asset)["metadata"]["schema"] == "sc.crop/v1"


# -------------------------------------------------------- 12 zero leakage


def test_errors_and_status_leak_no_paths_or_os_errors(tmp_path):
    root = tmp_path / "leak"
    store = CropEvidenceStore(root)
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    (root / "index").mkdir()
    (root / "index" / (key + ".jsonl")).mkdir()
    worker = CropWorker(store)
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] == "failed")
        observations = [json.dumps(worker.status(ref), ensure_ascii=False, default=str),
                        json.dumps(worker.find(cam), ensure_ascii=False, default=str),
                        json.dumps(worker.diagnostics())]
        assert "image" not in worker.status(ref)   # no internals exposed
        for bad in ("a" * 64, "../escape", ""):
            try:
                worker.read(bad)
            except CropEvidenceError as error:
                observations.append(str(error))
                observations.append(error.code)
        blob = "".join(observations)
        for marker in (str(tmp_path), str(root.resolve()), "WinError",
                       "OSError", "PermissionError", "IsADirectoryError", ":\\"):
            assert marker not in blob
    finally:
        worker.close()


# ------------------------------------------------- budgets & small honesty


def test_budget_and_input_validation(tmp_path):
    store = CropEvidenceStore(tmp_path)
    for kwargs in ({"queue_max": 0}, {"queue_max": True}, {"ttl_s": 0},
                   {"ttl_s": -1}, {"ttl_s": float("nan")}, {"ttl_s": True},
                   {"close_timeout_s": -1}, {"close_timeout_s": float("inf")},
                   {"find_limit": 0}, {"find_limit": 1001},
                   {"index_scan_budget": 0}, {"index_line_bytes": 512},
                   {"index_scan_bytes": 0}, {"index_parse_budget": 0},
                   {"history_max": 0}, {"max_image_pixels": 0},
                   {"max_image_bytes": 0}, {"max_meta_bytes": 0},
                   {"clock": None}):
        with pytest.raises(ValueError):
            CropWorker(store, **kwargs)
    with pytest.raises(ValueError):
        CropWorker(object())              # no save/read/root
    worker = CropWorker(store)
    with pytest.raises(ValueError):
        worker.submit(None, provenance())  # image must be copyable
    with pytest.raises(ValueError):
        worker.find("")
    with pytest.raises(ValueError):
        worker.find("x" * 201)
    with pytest.raises(ValueError):
        worker.find("cam", limit=0)
    with pytest.raises(ValueError):
        worker.find("cam", filters={"not_a_field": 1})
    with pytest.raises(ValueError):
        worker.find("cam", filters=["bad"])
    assert worker.find("never-seen") == []
    assert worker.status(1234)["status"] == "unknown"
    assert worker.submit(pixels(), provenance()) \
        == {"status": "dropped", "reason": "worker_stopped"}  # never started
    worker.close()
    worker.close()                        # idempotent even without start
    assert worker.submit(pixels(), provenance()) \
        == {"status": "dropped", "reason": "worker_stopped"}


def test_status_history_is_bounded(tmp_path):
    worker = CropWorker(CropEvidenceStore(tmp_path), history_max=4)
    worker.start()
    try:
        refs = [worker.submit(pixels(seed=i), provenance(frame=i))["ref"]
                for i in range(8)]
        assert wait_until(lambda: all(
            worker.status(r)["status"] != "pending" for r in refs))
        states = [worker.status(r)["status"] for r in refs]
        assert states[:4] == ["unknown"] * 4   # oldest evicted: bounded memory
        assert states[4:] == ["saved"] * 4     # newest registry kept
    finally:
        worker.close()


# =========================================================== C141-R1 fix 1
# Bounded memory: rejection before copy, hard total bound, terminal reclaim
# never stalled by the oldest pending ref.


def test_thousand_rejections_bounded_memory_and_zero_copy(tmp_path):
    gate = GateStore(CropEvidenceStore(tmp_path))
    gate.gate.clear()
    queue_max, history_max = 1, 4
    worker = CropWorker(gate, queue_max=queue_max, history_max=history_max)
    worker.start()
    try:
        first = worker.submit(pixels(), provenance(frame=1))
        assert first["status"] == "pending"
        assert gate.entered.wait(5)            # deterministic: save in flight
        second = worker.submit(pixels(seed=1), provenance(frame=2))
        assert second["status"] == "pending"   # fills the single queue slot
        image = CopyCountingImage(pixels(seed=2))
        meta = CountingProv(provenance(frame=3))
        rejects = [worker.submit(image, meta) for _ in range(1000)]
        assert all(r == {"status": "dropped", "reason": "queue_full"}
                   for r in rejects)
        assert image.copies == 0 and meta.deepcopies == 0   # rejected first
        hard_bound = queue_max + 1 + history_max
        assert len(worker._tasks) <= hard_bound          # hard total bound
        assert len(worker._order) <= history_max         # terminal bounded
        assert sum(1 for t in worker._tasks.values()
                   if t["status"] == "pending") <= queue_max + 1
        assert worker.diagnostics()["queue_full_rejections"] >= 1000
    finally:
        gate.gate.set()
    assert wait_until(lambda: worker.status(first["ref"])["status"] == "saved"
                      and worker.status(second["ref"])["status"] == "saved")
    # terminal reclaim is never stalled by a pending ref: churn the history
    for i in range(20):
        ref = worker.submit(pixels(seed=10 + i), provenance(frame=10 + i))["ref"]
        assert wait_until(lambda r=ref: worker.status(r)["status"] == "saved")
    assert wait_until(lambda: sum(1 for t in worker._tasks.values()
                                  if t["status"] == "pending") == 0)
    assert len(worker._tasks) <= history_max     # drained: only terminal left
    assert len(worker._order) <= history_max
    assert worker.diagnostics()["history_evictions"] >= 20 - history_max
    # probe validity: an admitted submit really does exactly one copy
    probe_image = CopyCountingImage(pixels(seed=99))
    probe_meta = CountingProv(provenance(frame=99))
    probe_ref = worker.submit(probe_image, probe_meta)["ref"]
    assert wait_until(lambda: worker.status(probe_ref)["status"] == "saved")
    assert probe_image.copies == 1 and probe_meta.deepcopies == 1
    worker.close()


def test_reject_paths_never_copy_stopped_worker(tmp_path):
    worker = CropWorker(CropEvidenceStore(tmp_path))    # never started
    image = CopyCountingImage(pixels())
    meta = CountingProv(provenance())
    assert worker.submit(image, meta) == {"status": "dropped",
                                          "reason": "worker_stopped"}
    assert image.copies == 0 and meta.deepcopies == 0
    with pytest.raises(ValueError):
        worker.submit(None, provenance())      # unusable input still raises
    worker.close()
    worker.close()                             # idempotent
    assert worker.submit(image, meta) == {"status": "dropped",
                                          "reason": "worker_stopped"}
    assert image.copies == 0 and meta.deepcopies == 0


def test_oversize_budgets_reject_before_copy(tmp_path):
    worker = CropWorker(CropEvidenceStore(tmp_path), max_image_pixels=100,
                        max_image_bytes=64, max_meta_bytes=512)
    worker.start()
    try:
        big_pixels = CopyCountingImage(
            np.zeros((20, 20, 3), dtype=np.uint8))          # 400 px > 100
        assert worker.submit(big_pixels, provenance(frame=1)) \
            == {"status": "dropped", "reason": "image_oversize"}
        assert big_pixels.copies == 0
        fat_bytes = CopyCountingImage(
            np.zeros((5, 10, 3), dtype=np.uint8))           # 50 px, 150 B > 64
        assert worker.submit(fat_bytes, provenance(
            frame=2, source_size=[10, 5], bbox_px=[0, 0, 10, 5])) \
            == {"status": "dropped", "reason": "image_oversize"}
        assert fat_bytes.copies == 0
        meta = CountingProv(provenance(frame=3, junk="x" * 2048))
        tiny = np.zeros((2, 10, 3), dtype=np.uint8)   # 20 px, 60 B: passes both
        assert worker.submit(tiny, meta) \
            == {"status": "dropped", "reason": "provenance_oversize"}
        assert meta.deepcopies == 0
        diag = worker.diagnostics()
        assert diag["oversize_image_rejections"] == 2
        assert diag["oversize_meta_rejections"] == 1
        assert worker.find(provenance()["camera_id"]) == []  # nothing archived
    finally:
        worker.close()


# =========================================================== C141-R1 fix 2
# Stop/index commit authorization: no mutually exclusive terminal states.


def test_commit_authorized_append_completes_saved_after_close(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = GatedIndexWorker(store)
    worker.index_gate.clear()
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert worker.index_entered.wait(5)    # granted, append in flight
        assert worker.status(ref)["status"] == "pending"   # no fake terminal
        summary = worker.close(timeout_s=0)
        assert summary["dropped"] == 0
        assert summary["committing"] == [ref]  # honest: not cancellable here
        assert summary["thread_alive"] is True
        assert worker.status(ref)["status"] == "pending"   # never stop_timeout
    finally:
        worker.index_gate.set()
    assert wait_until(lambda: worker.status(ref)["status"] == "saved")
    assert worker.join(5.0)
    records = worker.find(provenance()["camera_id"])
    assert len(records) == 1 and records[0]["status"] == "saved"
    assert records[0]["ref"] == ref            # memory == index: no conflict
    assert worker.status(ref)["status"] == "saved"


def test_stop_before_grant_dropped_and_never_indexed(tmp_path):
    gate = GateStore(CropEvidenceStore(tmp_path))
    gate.gate.clear()
    worker = GatedIndexWorker(gate)
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert gate.entered.wait(5)            # inside store.save, pre-grant
        summary = worker.close(timeout_s=0)
        assert summary["dropped"] == 1 and summary["committing"] == []
        assert worker.status(ref)["status"] == "dropped"
        assert worker.status(ref)["reason"] == "stop_timeout"
    finally:
        gate.gate.set()                        # the blocked save completes
    assert worker.join(5.0)
    assert not worker.index_entered.is_set()   # append never even attempted
    assert worker.find(provenance()["camera_id"]) == []   # no index line
    assert worker.status(ref)["status"] == "dropped"      # never overwritten


def test_authorized_append_failure_is_honest_index_failed(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = GatedIndexWorker(store)
    worker.index_gate.clear()
    worker.start()
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert worker.index_entered.wait(5)    # granted, append in flight
        summary = worker.close(timeout_s=0)
        assert summary["committing"] == [ref]  # must not be dropped
        (store.root / "index").mkdir(parents=True, exist_ok=True)
        (store.root / "index" / (key + ".jsonl")).mkdir()  # append will fail
    finally:
        worker.index_gate.set()
    assert wait_until(lambda: worker.status(ref)["status"] == "failed")
    state = worker.status(ref)
    assert state["reason"] == "index_failed" and state["asset_id"] is None
    assert worker.join(5.0)
    assert worker.find(cam) == []              # no line: memory matches index


# =========================================================== C141-R1 fix 3
# Index attribution (strict camera equality) and read fencing.


def test_cross_camera_poison_rows_skipped_and_counted(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store)
    worker.start()
    cam_a, cam_b = "相机甲", "相机乙"
    try:
        ref_a = worker.submit(pixels(seed=1),
                              provenance(camera=cam_a, frame=1))["ref"]
        ref_b = worker.submit(pixels(seed=2),
                              provenance(camera=cam_b, frame=2))["ref"]
        assert wait_until(lambda: worker.status(ref_a)["status"] == "saved"
                          and worker.status(ref_b)["status"] == "saved")
        key_a = hashlib.sha256(cam_a.encode("utf-8")).hexdigest()[:16]
        path_a = store.root / "index" / (key_a + ".jsonl")
        with open(path_a, "ab") as sink:       # B-camera row planted in A's file
            sink.write(index_line(poison_record(cam_b, ref=999, frame=42)))
        found_a = worker.find(cam_a)
        assert [r["ref"] for r in found_a] == [ref_a]   # poison never returned
        assert all(r["camera_id"] == cam_a for r in found_a)
        assert worker.find(cam_a, filters={"frame_id": 42}) == []
        assert worker.find(cam_a, filters={"asset_id": "f" * 64}) == []
        assert worker.diagnostics()["cross_camera_index_lines"] >= 1
        found_b = worker.find(cam_b)           # B's own file is untouched
        assert [r["ref"] for r in found_b] == [ref_b]
        assert all(r["camera_id"] == cam_b for r in found_b)
    finally:
        worker.close()


def test_index_read_fencing_rejects_non_regular_file(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store)
    worker.start()
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    index_file = store.root / "index" / (key + ".jsonl")
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] == "saved")
        assert len(worker.find(cam)) == 1      # sanity: readable while intact
        index_file.unlink()
        index_file.mkdir()                     # index file replaced by a dir
        assert worker.find(cam) == []
        assert worker.diagnostics()["unsafe_index_reads"] >= 1
        index_file.rmdir()
        (store.root / "index").rmdir()         # index dir replaced by a file
        (store.root / "index").write_bytes(b"not a dir")
        assert worker.find(cam) == []
        assert worker.diagnostics()["unsafe_index_reads"] >= 2
    finally:
        worker.close()


def test_index_read_fencing_rejects_symlink_and_reparse(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store)
    worker.start()
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    index_file = store.root / "index" / (key + ".jsonl")
    unsafe = 0
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] == "saved")
        # a symlink standing in for the index file (skipped without privilege)
        twin = tmp_path / "twin.jsonl"
        twin.write_bytes(index_file.read_bytes())
        planted = False
        try:
            index_file.unlink()
            index_file.symlink_to(twin)
            planted = True
        except OSError:
            index_file.write_bytes(twin.read_bytes())   # restore, no privilege
        if planted:
            assert worker.find(cam) == []              # fenced even to a twin
            unsafe = worker.diagnostics()["unsafe_index_reads"]
            assert unsafe >= 1
        # a junction (reparse point) standing in for the index directory
        if os.name == "nt":
            real_dir = tmp_path / "index_real"
            try:
                import _winapi
                (store.root / "index").rename(real_dir)
                _winapi.CreateJunction(str(real_dir), str(store.root / "index"))
            except (OSError, ImportError, AttributeError):
                return
            try:
                assert worker.find(cam) == []
                assert worker.diagnostics()["unsafe_index_reads"] >= unsafe + 1
            finally:
                (store.root / "index").rmdir()         # drop the junction only
    finally:
        worker.close()


def test_giant_line_skipped_whole_never_parsed_in_fragments(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store)
    worker.start()
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    index_file = store.root / "index" / (key + ".jsonl")
    try:
        ref1 = worker.submit(pixels(seed=1), provenance(frame=1))["ref"]
        assert wait_until(lambda: worker.status(ref1)["status"] == "saved")
        giant = (b"x" * (4 * 65536)
                 + index_line(poison_record(cam, ref=777, frame=777,
                                            asset="e" * 64)))
        with open(index_file, "ab") as sink:
            sink.write(giant)                  # planted JSON is its suffix
        ref2 = worker.submit(pixels(seed=2), provenance(frame=2))["ref"]
        assert wait_until(lambda: worker.status(ref2)["status"] == "saved")
        records = worker.find(cam)
        assert sorted(r["frame_id"] for r in records) == [1, 2]
        assert not any(r["ref"] == 777 for r in records)
        assert worker.diagnostics()["oversized_index_lines"] == 1  # once/scan
        assert worker.diagnostics()["bad_index_lines"] == 0
        assert worker.find(cam, filters={"frame_id": 777}) == []   # rescanned,
        # and the filtered find re-counts the same single giant line honestly:
        assert worker.diagnostics()["oversized_index_lines"] == 2
        assert worker.diagnostics()["bad_index_lines"] == 0  # never a fragment
    finally:
        worker.close()


def test_scan_budgets_truncate_honestly(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store, index_scan_bytes=600)
    worker.start()
    cam = provenance()["camera_id"]
    try:
        refs = [worker.submit(pixels(seed=i),
                              provenance(camera=cam, frame=i))["ref"]
                for i in range(1, 6)]
        assert wait_until(lambda: all(
            worker.status(r)["status"] == "saved" for r in refs))
        records = worker.find(cam)             # only the newest fit the budget
        assert records[0]["frame_id"] == 5 and len(records) < 5
        assert worker.diagnostics()["index_scan_truncations"] >= 1
    finally:
        worker.close()
    worker2 = CropWorker(CropEvidenceStore(tmp_path / "p"),
                         index_parse_budget=1)
    worker2.start()
    try:
        refs = [worker2.submit(pixels(seed=i),
                               provenance(camera=cam, frame=i))["ref"]
                for i in range(1, 4)]
        assert wait_until(lambda: all(
            worker2.status(r)["status"] == "saved" for r in refs))
        records = worker2.find(cam)            # exactly one parse attempt
        assert [r["frame_id"] for r in records] == [3]
        assert worker2.diagnostics()["index_scan_truncations"] >= 1
    finally:
        worker2.close()


def test_torn_tail_skipped_then_visible_after_growth(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store)
    worker.start()
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    index_file = store.root / "index" / (key + ".jsonl")
    planted = poison_record(cam, ref=9, frame=9, asset="d" * 64)
    full = index_line(planted)
    prefix = full[:len(full) // 2]         # genuine torn write: a strict prefix
    try:
        ref1 = worker.submit(pixels(), provenance(camera=cam, frame=1))["ref"]
        assert wait_until(lambda: worker.status(ref1)["status"] == "saved")
        with open(index_file, "ab") as sink:   # torn concurrent append
            sink.write(prefix)
        assert [r["frame_id"] for r in worker.find(cam)] == [1]
        assert worker.diagnostics()["bad_index_lines"] >= 1
        with open(index_file, "ab") as sink:   # the append completes later
            sink.write(full[len(prefix):])
        records = worker.find(cam)
        assert sorted(r["frame_id"] for r in records) == [1, 9]
    finally:
        worker.close()


# =========================================================== C141-R2 fix 1
# Concurrent admission reservation: the capacity slot is claimed atomically
# under a short lock BEFORE any image copy is made; rejections stay zero-copy
# and every reservation is released exactly once (zero leak).


def _race_submissions(worker, probes, metas):
    """Fire len(probes) concurrent submits released by one shared barrier."""
    n = len(probes)
    barrier = threading.Barrier(n + 1)
    results = [None] * n

    def race(i):
        barrier.wait()
        results[i] = worker.submit(probes[i], metas[i])

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(race, i) for i in range(n)]
        barrier.wait()                     # all racers fire between the gates
        for future in futures:
            future.result(timeout=15)
    return results


def test_concurrent_submit_copies_bounded_by_true_capacity(tmp_path):
    for n in (16, 64):
        gate = GateStore(CropEvidenceStore(tmp_path / ("race%d" % n)))
        gate.gate.clear()
        worker = CropWorker(gate, queue_max=1)
        worker.start()
        try:
            first = worker.submit(pixels(), provenance(frame=0))
            assert first["status"] == "pending"
            assert gate.entered.wait(5)    # slot 1 deterministically in save
            probes = [CopyCountingImage(pixels(seed=i)) for i in range(n)]
            metas = [CountingProv(provenance(frame=100 + i)) for i in range(n)]
            results = _race_submissions(worker, probes, metas)
            admitted = [r for r in results if r.get("status") == "pending"]
            rejected = [r for r in results if r.get("status") == "dropped"]
            # true acceptance capacity = queue_max + 1 non-terminal tasks,
            # one already taken by the gated save → exactly 1 of the n fits
            assert len(admitted) == 1
            assert len(rejected) == n - 1
            assert all(r == {"status": "dropped", "reason": "queue_full"}
                       for r in rejected)
            # reservation protocol: copy only after the atomic slot claim —
            # never one speculative copy per racing loser (old code: n copies)
            assert sum(p.copies for p in probes) <= len(admitted)
            assert sum(m.deepcopies for m in metas) <= len(admitted)
            # per-sentinel zero-copy proof on every rejection path
            for i, result in enumerate(results):
                if result.get("status") == "dropped":
                    assert probes[i].copies == 0
                    assert metas[i].deepcopies == 0
        finally:
            gate.gate.set()
            worker.close(timeout_s=5.0)    # reaped on every path (red or green)
        assert wait_until(
            lambda: worker.status(first["ref"])["status"] == "saved"
            and worker.status(admitted[0]["ref"])["status"] == "saved")
        with worker._lock:
            assert worker._reserved == 0   # no reservation left behind


def test_reservation_released_exactly_once_on_copy_failure(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store, queue_max=1)
    worker.start()

    class ExplodingCopy:
        shape = (2, 5, 3)
        nbytes = 30

        def __init__(self):
            self.attempts = 0

        def copy(self):
            self.attempts += 1
            raise RuntimeError("copy exploded")

    try:
        for round_no in range(2):          # two leaks would eat the capacity
            bad = ExplodingCopy()
            with pytest.raises(ValueError):
                worker.submit(bad, provenance(frame=50 + round_no))
            assert bad.attempts == 1       # the grant did reach the copy
        with worker._lock:
            assert worker._reserved == 0   # exactly-once release, zero leak
        # capacity intact: a good submission is still admitted and saved
        ref = worker.submit(pixels(seed=7), provenance(frame=60))["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] == "saved")
    finally:
        worker.close()


def test_reservation_released_when_worker_stops_mid_copy(tmp_path):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store, queue_max=1)
    worker.start()
    release_copy = threading.Event()
    copy_started = threading.Event()

    class GatedCopy:
        def __init__(self, array):
            self._array = array
            self.copies = 0

        @property
        def shape(self):
            return self._array.shape

        @property
        def nbytes(self):
            return self._array.nbytes

        def copy(self):
            self.copies += 1
            copy_started.set()
            if not release_copy.wait(10):
                raise RuntimeError("copy gate timeout")
            return self._array.copy()

    summary = {"dropped": None}
    try:
        blocked = GatedCopy(pixels(seed=1))
        outcome = []

        def racing_submit():
            outcome.append(worker.submit(blocked, provenance(frame=70)))

        thread = threading.Thread(target=racing_submit)
        thread.start()
        assert copy_started.wait(5)        # granted, mid-copy outside the lock
        started = time.monotonic()
        summary = worker.close(timeout_s=0.3)   # stop never blocks on the copy
        assert time.monotonic() - started < 5.0
        assert summary["dropped"] == 0
    finally:
        release_copy.set()
        thread.join(10)
        worker.close(timeout_s=5.0)        # reaped on every path (red or green)
    assert outcome == [{"status": "dropped", "reason": "worker_stopped"}]
    with worker._lock:
        assert worker._reserved == 0       # stop-interleave: released once
        assert all(t["status"] != "pending" for t in worker._tasks.values())


def test_reservation_released_on_queue_put_failure(tmp_path, monkeypatch):
    store = CropEvidenceStore(tmp_path)
    worker = CropWorker(store, queue_max=2)
    worker.start()

    class FullQueue:
        def __init__(self, inner):
            self._inner = inner
            self.put_attempts = 0

        def qsize(self):
            return self._inner.qsize()

        def empty(self):
            return self._inner.empty()

        def get(self, timeout=None):
            return self._inner.get(timeout=timeout)

        def put_nowait(self, item):
            self.put_attempts += 1
            raise queue.Full()

    patched = FullQueue(worker._queue)
    monkeypatch.setattr(worker, "_queue", patched)
    try:
        with worker._lock:
            expected_ref = worker._next_ref     # refs move monotonically
        result = worker.submit(pixels(), provenance(frame=80))
        assert result == {"status": "dropped", "reason": "queue_full"}
        assert patched.put_attempts == 1
        with worker._lock:
            assert worker._reserved == 0   # enqueue failure: released once
            assert worker._pending == 0
        state = worker.status(expected_ref)
        assert state["status"] == "dropped"
        assert state["reason"] == "queue_full"
    finally:
        monkeypatch.undo()                 # restore the real queue
        worker.close()
    worker2 = CropWorker(store, queue_max=2)
    worker2.start()
    try:
        ref = worker2.submit(pixels(seed=8), provenance(frame=81))["ref"]
        assert wait_until(lambda: worker2.status(ref)["status"] == "saved")
    finally:
        worker2.close()


# =========================================================== C141-R2 fix 2
# Durable commit protocol: write/flush/fsync uncertainty is honest
# commit_uncertain — never a certain failed while the line may be saved.


class FsyncFault:
    """Scoped deterministic fsync-path fault injection for the index file.

    mode="fail": the real fsync runs, then raises OSError — exactly the
    Codex repro (write+flush already reached the OS). mode="swap-after":
    the real fsync SUCCEEDS, and the index path is really replaced by a
    fresh empty file at the append's post-fsync fence lstat (the handle is
    closed by then, so the swap lands) — the durable line is no longer
    reachable under its path. Only the index file is ever matched; asset
    fsyncs pass through untouched.
    """

    def __init__(self, index_file, mode="fail"):
        self.index_file = index_file
        self.mode = mode
        self.fired = 0
        self._real_fsync = os.fsync
        self._real_stat = os.stat
        self._armed = True
        self._swap_now = False

    def __call__(self, fd):
        matched = False
        if self._armed:
            try:
                st = os.fstat(fd)
                target = self.index_file.lstat()
                matched = ((st.st_ino, st.st_dev)
                           == (target.st_ino, target.st_dev))
            except OSError:
                matched = False
        result = self._real_fsync(fd)
        if matched:
            self._armed = False
            self.fired += 1
            if self.mode == "fail":
                raise OSError("injected index fsync failure")
            self._swap_now = True           # swap at the post-fsync fence
        return result

    def _stat_hook(self, target, *args, follow_symlinks=True, **kwargs):
        if (self._swap_now and not isinstance(target, int)
                and Path(target) == self.index_file):
            self._swap_now = False
            self.index_file.unlink()        # handle closed: real swap lands
            self.index_file.write_bytes(b"")
        return self._real_stat(target, *args, follow_symlinks=follow_symlinks,
                               **kwargs)

    def install(self, monkeypatch):
        monkeypatch.setattr(os, "fsync", self)
        if self.mode == "swap-after":
            monkeypatch.setattr(os, "stat", self._stat_hook)


def test_fsync_failure_after_write_is_commit_uncertain(tmp_path, monkeypatch):
    root = tmp_path / "dur"
    store = CropEvidenceStore(root)
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    fault = FsyncFault(root / "index" / (key + ".jsonl"), mode="fail")
    fault.install(monkeypatch)
    worker = CropWorker(store)
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] != "pending")
        state = worker.status(ref)
        assert state["status"] == "commit_uncertain"
        assert state["reason"] == "index_commit_uncertain"
        assert len(state["asset_id"]) == 64      # the archive itself exists
        assert state["finished_ms"] is not None
        assert fault.fired == 1
        # mutual exclusion: never a certain failed while the line reads saved
        assert state["status"] != "failed"
        diag = worker.diagnostics()
        assert diag["commit_uncertain_appends"] == 1
        assert diag["index_write_failures"] == 0
        # the index file is the authority: the written line reads as saved
        records = worker.find(cam)
        assert [r["ref"] for r in records] == [ref]
        assert all(r["status"] == "saved" for r in records)
        summary = worker.close()           # close carries the uncertain count
        assert summary["commit_uncertain"] == 1
        assert summary["committing"] == []
        assert worker.status(ref)["status"] == "commit_uncertain"  # frozen
    finally:
        worker.close()
    restarted = CropWorker(CropEvidenceStore(root))
    restarted.start()
    try:
        records = restarted.find(cam)      # restart reads the same file truth
        assert [r["ref"] for r in records] == [ref]
        assert all(r["status"] == "saved" for r in records)
    finally:
        restarted.close()


def test_pre_write_failure_stays_certain_index_failed(tmp_path, monkeypatch):
    root = tmp_path / "pre"
    store = CropEvidenceStore(root)
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    poisoned = root / "index" / (key + ".jsonl")
    (root / "index").mkdir(parents=True)
    poisoned.mkdir()                       # open() will fail: pre-write zone
    fault = FsyncFault(poisoned, mode="fail")
    fault.install(monkeypatch)
    worker = CropWorker(store)
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] != "pending")
        state = worker.status(ref)
        assert state["status"] == "failed"       # certain: zero bytes written
        assert state["reason"] == "index_failed"
        assert state["asset_id"] is None
        assert fault.fired == 0                  # fsync was never reached
        assert worker.diagnostics()["commit_uncertain_appends"] == 0
        assert worker.find(cam) == []            # no line anywhere
    finally:
        worker.close()


def test_failed_line_uncertain_append_keeps_certain_failure(
        tmp_path, monkeypatch):
    root = tmp_path / "cap"
    seed_store = CropEvidenceStore(root)
    seed_asset = seed_store.save(pixels(), provenance(frame=1))
    size = (root / (seed_asset + ".crop")).stat().st_size
    capped = CropEvidenceStore(root, max_total_bytes=size + 1)
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    fault = FsyncFault(root / "index" / (key + ".jsonl"), mode="fail")
    fault.install(monkeypatch)
    worker = CropWorker(capped)
    worker.start()
    try:
        ref = worker.submit(pixels(seed=7), provenance(frame=2))["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] != "pending")
        state = worker.status(ref)
        assert state["status"] == "failed"   # certain: store.save raised
        assert state["reason"] == "capacity"
        assert fault.fired == 1              # the failure line hit fsync
        assert worker.diagnostics()["commit_uncertain_appends"] == 1
        # the written failure line is the file authority: find shows it
        records = worker.find(cam)
        assert any(r["ref"] == ref and r["status"] == "failed"
                   and r["reason"] == "capacity" for r in records)
    finally:
        worker.close()


def test_close_never_rewrites_uncertain_state(tmp_path, monkeypatch):
    store = CropEvidenceStore(tmp_path / "unc")
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    fault = FsyncFault(store.root / "index" / (key + ".jsonl"), mode="fail")
    fault.install(monkeypatch)
    worker = GatedIndexWorker(store)
    worker.index_gate.clear()
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert worker.index_entered.wait(5)  # granted, append in flight
        summary = worker.close(timeout_s=0)
        assert summary["dropped"] == 0
        assert summary["committing"] == [ref]
    finally:
        worker.index_gate.set()
    assert wait_until(lambda: worker.status(ref)["status"] == "commit_uncertain")
    assert worker.join(5.0)
    assert worker.status(ref)["reason"] == "index_commit_uncertain"
    summary = worker.close()
    assert summary["commit_uncertain"] == 1  # the sweep never rewrote it
    records = worker.find(cam)
    assert [r["ref"] for r in records] == [ref]      # line landed: saved


def test_post_write_path_swap_is_commit_uncertain(tmp_path, monkeypatch):
    root = tmp_path / "swap"
    store = CropEvidenceStore(root)
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    index_file = root / "index" / (key + ".jsonl")
    fault = FsyncFault(index_file, mode="swap-after")
    fault.install(monkeypatch)
    worker = CropWorker(store)
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] != "pending")
        state = worker.status(ref)
        assert state["status"] == "commit_uncertain"  # reachability broken
        assert fault.fired == 1
        assert worker.find(cam) == []        # path truth: no line anymore
        assert index_file.read_bytes() == b""     # the swapped-in file
        assert worker.diagnostics()["commit_uncertain_appends"] == 1
    finally:
        worker.close()


# =========================================================== C141-R2 fix 3
# Read/write fence hardening: post-read directory/root identity recheck and
# opened-handle identity verification on writes (controlled local directory
# boundary only).


def _arm_post_read_swap(monkeypatch, swap_path, perform):
    """Run perform() just before the FIRST post-scan lstat of swap_path.

    Deterministic timing hook: the replacement itself is a real filesystem
    operation observed by the real fence; only its scheduling is injected
    (armed by the scan seam — no sleeps, no call counting).
    """
    real_scan = crop_worker_module._scan_backwards
    real_stat = os.stat
    state = {"armed": False, "done": False}

    def hooked_scan(*args, **kwargs):
        try:
            return real_scan(*args, **kwargs)
        finally:
            state["armed"] = True

    def hooked_stat(target, *args, follow_symlinks=True, **kwargs):
        if (state["armed"] and not state["done"]
                and not isinstance(target, int)
                and Path(target) == swap_path):
            state["done"] = True
            perform()
        return real_stat(target, *args, follow_symlinks=follow_symlinks,
                         **kwargs)

    monkeypatch.setattr(crop_worker_module, "_scan_backwards", hooked_scan)
    monkeypatch.setattr(os, "stat", hooked_stat)
    return state


def test_read_fence_rejects_index_dir_swapped_after_read(tmp_path, monkeypatch):
    root = tmp_path / "rdir"
    store = CropEvidenceStore(root)
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    index_dir = root / "index"
    index_file = index_dir / (key + ".jsonl")
    worker = CropWorker(store)
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] == "saved")
        assert len(worker.find(cam)) == 1        # sanity: intact read first

        def perform_dir_swap():
            staged = tmp_path / "staged-index"
            index_dir.rename(staged)             # identity moves with the dir
            index_dir.mkdir()                    # fresh dir: new identity
            os.link(staged / (key + ".jsonl"),
                    index_file)                  # same-inode line replay

        _arm_post_read_swap(monkeypatch, index_dir, perform_dir_swap)
        assert worker.find(cam) == []   # post-read dir fence discards it all
        assert worker.diagnostics()["unsafe_index_reads"] >= 1
    finally:
        worker.close()


def test_read_fence_rejects_root_swapped_after_read(tmp_path, monkeypatch):
    root = tmp_path / "rroot"
    store = CropEvidenceStore(root)
    cam = provenance()["camera_id"]
    worker = CropWorker(store)
    worker.start()
    try:
        ref = worker.submit(pixels(), provenance())["ref"]
        assert wait_until(lambda: worker.status(ref)["status"] == "saved")
        assert len(worker.find(cam)) == 1        # sanity: intact read first

        def perform_root_swap():
            staged = tmp_path / "staged-root"
            root.rename(staged)                  # whole tree moved away
            root.mkdir()                         # fresh root: new identity
            os.rename(staged / "index", root / "index")  # dir identity kept

        _arm_post_read_swap(monkeypatch, root, perform_root_swap)
        assert worker.find(cam) == []            # post-read root fence fires
        assert worker.diagnostics()["unsafe_index_reads"] >= 1
    finally:
        worker.close()


def test_write_rejects_opened_file_swapped_before_write(tmp_path, monkeypatch):
    root = tmp_path / "wswap"
    store = CropEvidenceStore(root)
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    index_file = root / "index" / (key + ".jsonl")
    foreign = tmp_path / "foreign.bin"     # OUTSIDE the store root: the store
    worker = CropWorker(store)             # rightly rejects foreign entries
    worker.start()
    try:
        ref1 = worker.submit(pixels(seed=1), provenance(frame=1))["ref"]
        assert wait_until(lambda: worker.status(ref1)["status"] == "saved")
        foreign.write_bytes(b"")
        real_open = os.open

        def divert_open(path, flags, mode=None):
            # divert only writes; reads must still see the real index file
            if Path(path) == index_file and (flags & 0b11) != os.O_RDONLY:
                if mode is None:
                    return real_open(foreign, flags)
                return real_open(foreign, flags, mode)
            if mode is None:
                return real_open(path, flags)
            return real_open(path, flags, mode)

        monkeypatch.setattr(os, "open", divert_open)
        ref2 = worker.submit(pixels(seed=2), provenance(frame=2))["ref"]
        assert wait_until(lambda: worker.status(ref2)["status"] != "pending")
        state = worker.status(ref2)
        assert state["status"] == "failed"   # pre-write: opened ≠ pre-checked
        assert state["reason"] == "index_failed"
        assert state["asset_id"] is None
        assert foreign.read_bytes() == b""   # not one byte was written
        records = worker.find(cam)
        assert [r["ref"] for r in records] == [ref1]   # real index untouched
    finally:
        monkeypatch.undo()
        worker.close()


def test_write_rejects_non_regular_opened_handle(tmp_path, monkeypatch):
    root = tmp_path / "wfifo"
    store = CropEvidenceStore(root)
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    index_file = root / "index" / (key + ".jsonl")
    worker = CropWorker(store)
    worker.start()
    try:
        ref1 = worker.submit(pixels(seed=1), provenance(frame=1))["ref"]
        assert wait_until(lambda: worker.status(ref1)["status"] == "saved")
        armed = {"on": True}
        real_fstat = os.fstat

        def forged_fstat(fd):
            st = real_fstat(fd)
            if armed["on"]:
                try:
                    target = index_file.lstat()
                except OSError:
                    return st
                if (st.st_ino, st.st_dev) == (target.st_ino, target.st_dev):
                    armed["on"] = False
                    return os.stat_result((stat.S_IFIFO | 0o644,
                                           st.st_ino, st.st_dev, st.st_nlink,
                                           st.st_uid, st.st_gid, st.st_size,
                                           st.st_atime, st.st_mtime,
                                           st.st_ctime))
            return st

        monkeypatch.setattr(os, "fstat", forged_fstat)
        ref2 = worker.submit(pixels(seed=2), provenance(frame=2))["ref"]
        assert wait_until(lambda: worker.status(ref2)["status"] != "pending")
        state = worker.status(ref2)
        assert state["status"] == "failed"   # opened handle: not a regular file
        assert state["reason"] == "index_failed"
        lines = index_file.read_bytes().splitlines()
        assert len(lines) == 1               # nothing appended by the rejection
        records = worker.find(cam)
        assert [r["ref"] for r in records] == [ref1]
    finally:
        monkeypatch.undo()
        worker.close()


# =========================================================== C141-R3 fix 1
# Bounded read-only complete-identity commit status query: the server's real
# window into in-memory commit_uncertain. find stays persistent-facts-only
# (saved/failed, never uncertain), so "the index line is already readable
# while durability is unproven" is composed honestly at the server layer.

_COMMIT_IDENTITY_NINE = ("camera_id", "run_id", "config_version",
                         "material_id", "window_id", "branch", "crop_id",
                         "frame_id", "slot")


def full_identity(camera="验收相机", frame=2, **extra):
    """The frozen complete nine-key identity a commit_status query carries."""
    ident = dict(camera_id=camera, run_id="run1", config_version=1,
                 material_id="material1", window_id=3, branch="local",
                 slot="current", crop_id="crop1", frame_id=frame)
    ident.update(extra)
    return ident


def uncertain_worker(tmp_path, monkeypatch):
    """Real store + real worker under a deterministic index fsync fault."""
    root = tmp_path / "cs"
    store = CropEvidenceStore(root)
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    fault = FsyncFault(root / "index" / (key + ".jsonl"), mode="fail")
    fault.install(monkeypatch)
    worker = CropWorker(store)
    worker.start()
    return worker, fault


def test_commit_status_reports_uncertain_with_real_asset(tmp_path, monkeypatch):
    worker, fault = uncertain_worker(tmp_path, monkeypatch)
    try:
        meta = provenance(frame=2, window_id=3, branch="local", slot="current")
        ref = worker.submit(pixels(), meta)["ref"]
        assert wait_until(lambda: worker.status(ref)["status"]
                          == "commit_uncertain")
        asset = worker.status(ref)["asset_id"]
        assert fault.fired == 1 and len(asset) == 64   # real archive id
        assert worker.commit_status(meta["camera_id"], full_identity()) == {
            "status": "commit_uncertain",
            "reason": "index_commit_uncertain",
            "asset_id": asset}
    finally:
        worker.close()


def test_commit_status_never_borrows_across_runs_or_cameras(
        tmp_path, monkeypatch):
    worker, fault = uncertain_worker(tmp_path, monkeypatch)
    try:
        meta = provenance(frame=2, window_id=3, branch="local", slot="current")
        ref = worker.submit(pixels(), meta)["ref"]
        assert wait_until(lambda: worker.status(ref)["status"]
                          == "commit_uncertain")
        other_run = full_identity(run_id="run-other")
        assert other_run["run_id"] != full_identity()["run_id"]
        assert worker.commit_status(other_run["camera_id"], other_run) is None
        # the camera argument must agree with the identity's own camera
        assert worker.commit_status("别的相机", full_identity()) is None
        cross_camera = full_identity(camera="别的相机")
        assert worker.commit_status(cross_camera["camera_id"],
                                    cross_camera) is None
        # the true identity still matches: no state was borrowed away
        assert worker.commit_status(meta["camera_id"],
                                    full_identity())["status"] \
            == "commit_uncertain"
    finally:
        worker.close()


def test_commit_status_saved_and_pending_are_no_uncertainty(tmp_path):
    gate = GateStore(CropEvidenceStore(tmp_path))
    gate.gate.clear()
    worker = CropWorker(gate)
    worker.start()
    try:
        meta = provenance(frame=5, window_id=3, branch="local", slot="current")
        ref = worker.submit(pixels(), meta)["ref"]
        assert gate.entered.wait(5)          # deterministic: save in flight
        assert worker.status(ref)["status"] == "pending"
        assert worker.commit_status(meta["camera_id"],
                                    full_identity(frame=5)) == {"status": None}
        gate.gate.set()
        assert wait_until(lambda: worker.status(ref)["status"] == "saved")
        assert worker.commit_status(meta["camera_id"],
                                    full_identity(frame=5)) == {"status": None}
    finally:
        gate.gate.set()
        worker.close()


def test_commit_status_after_restart_is_none_not_fabricated(
        tmp_path, monkeypatch):
    root = tmp_path / "restart"
    store = CropEvidenceStore(root)
    cam = provenance()["camera_id"]
    key = hashlib.sha256(cam.encode("utf-8")).hexdigest()[:16]
    fault = FsyncFault(root / "index" / (key + ".jsonl"), mode="fail")
    fault.install(monkeypatch)
    first = CropWorker(store)
    first.start()
    try:
        meta = provenance(frame=2, window_id=3, branch="local", slot="current")
        ref = first.submit(pixels(), meta)["ref"]
        assert wait_until(lambda: first.status(ref)["status"]
                          == "commit_uncertain")
    finally:
        first.close()
    assert first.join(5.0)
    restarted = CropWorker(CropEvidenceStore(root))   # fresh memory, same disk
    restarted.start()
    try:
        assert restarted.commit_status(cam, full_identity()) is None
        assert restarted.commit_status(cam, full_identity(frame=9)) is None
        records = restarted.find(cam, filters={"frame_id": 2})
        assert [r["status"] for r in records] == ["saved"]  # durable fact kept
    finally:
        restarted.close()


def test_commit_status_rejects_incomplete_identity(tmp_path):
    worker = CropWorker(CropEvidenceStore(tmp_path))    # no thread needed
    try:
        camera = full_identity()["camera_id"]
        for key in _COMMIT_IDENTITY_NINE:
            broken = full_identity()
            del broken[key]
            with pytest.raises(ValueError, match="incomplete identity"):
                worker.commit_status(camera, broken)
        with pytest.raises(ValueError, match="incomplete identity"):
            worker.commit_status(camera, None)
        with pytest.raises(ValueError, match="incomplete identity"):
            worker.commit_status(camera, full_identity(window_id=None))
        with pytest.raises(ValueError):
            worker.commit_status("", full_identity())
    finally:
        worker.close()


def test_commit_status_normalizes_int_and_string_identity(
        tmp_path, monkeypatch):
    worker, fault = uncertain_worker(tmp_path, monkeypatch)
    try:
        meta = provenance(frame=7, config_version=0, material_id=610,
                          window_id=11, branch="local", slot="current")
        ref = worker.submit(pixels(), meta)["ref"]
        assert wait_until(lambda: worker.status(ref)["status"]
                          == "commit_uncertain")
        as_strings = dict(camera_id=meta["camera_id"], run_id="run1",
                          config_version="0", material_id="610",
                          window_id="11", branch="local", slot="current",
                          crop_id="crop1", frame_id="7")
        hit = worker.commit_status(meta["camera_id"], as_strings)
        assert hit["status"] == "commit_uncertain"   # int stored, str queried
        assert hit["reason"] == "index_commit_uncertain"
        assert len(hit["asset_id"]) == 64
        assert worker.commit_status(meta["camera_id"],
                                    dict(as_strings, window_id="12")) is None
        assert worker.commit_status(meta["camera_id"],
                                    dict(as_strings, frame_id="8")) is None
    finally:
        worker.close()
    # reverse shapes: string identity stored, int queried
    worker2 = CropWorker(CropEvidenceStore(tmp_path / "rev"))
    worker2.start()
    try:
        meta = provenance(frame=8, config_version="0", material_id="610",
                          window_id="11", branch="local", slot="current")
        ref = worker2.submit(pixels(seed=1), meta)["ref"]
        assert wait_until(lambda: worker2.status(ref)["status"] == "saved")
        as_ints = dict(camera_id=meta["camera_id"], run_id="run1",
                       config_version=0, material_id=610, window_id=11,
                       branch="local", slot="current", crop_id="crop1",
                       frame_id=8)
        assert worker2.commit_status(meta["camera_id"], as_ints) \
            == {"status": None}                      # str stored, int queried
        assert worker2.commit_status(
            meta["camera_id"], dict(as_ints, material_id=999)) is None
    finally:
        worker2.close()


def test_find_stays_persistent_facts_never_uncertain(tmp_path, monkeypatch):
    worker, fault = uncertain_worker(tmp_path, monkeypatch)
    try:
        meta = provenance(frame=2, window_id=3, branch="local", slot="current")
        ref = worker.submit(pixels(), meta)["ref"]
        assert wait_until(lambda: worker.status(ref)["status"]
                          == "commit_uncertain")
        records = worker.find(meta["camera_id"])
        assert [r["ref"] for r in records] == [ref]      # the line landed
        assert all(r["status"] == "saved" for r in records)
        assert not any(r["status"] == "commit_uncertain"
                       for r in records)                 # find never fakes it
        # both truths stay honest at once: index saved + memory uncertain
        assert worker.commit_status(meta["camera_id"],
                                    full_identity())["status"] \
            == "commit_uncertain"
    finally:
        worker.close()
