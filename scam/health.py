"""Linux NVR L3 health primitives.

This module contains no worker threads and performs no network I/O.  Callers
own the sampling cadence, which keeps health reporting from becoming another
failure domain in the fast alert path.
"""

from __future__ import annotations

import os
import shutil
import threading
import time


class CameraWatchdog:
    """Thread-safe per-camera liveness state with explicit degradation.

    ``now`` values are monotonic seconds. Source timestamps are retained only
    as evidence metadata and never used for liveness calculations.
    """

    def __init__(self, camera_id, *, stall_after_s=30.0):
        if not isinstance(stall_after_s, (int, float)) or isinstance(
                stall_after_s, bool) or stall_after_s <= 0:
            raise ValueError("stall_after_s must be a positive number")
        self.camera_id = str(camera_id)
        self.stall_after_s = float(stall_after_s)
        self._lock = threading.Lock()
        self._state = "starting"
        self._started_at = None
        self._last_open_at = None
        self._last_frame_at = None
        self._last_source_ts = None
        self._timestamp_kind = "unknown"
        self._last_error = None
        self._last_error_at = None
        self._open_failures = 0
        self._read_failures = 0
        self._reconnects = 0
        self._frames = 0

    def started(self, *, now=None):
        now = time.monotonic() if now is None else float(now)
        with self._lock:
            self._started_at = now
            self._state = "starting"

    def opened(self, *, now=None, reconnect=False):
        now = time.monotonic() if now is None else float(now)
        with self._lock:
            self._last_open_at = now
            if reconnect:
                self._reconnects += 1
            self._state = "online" if self._frames else "starting"

    def frame(self, *, now=None, source_ts=None, timestamp_kind="unknown"):
        now = time.monotonic() if now is None else float(now)
        with self._lock:
            self._last_frame_at = now
            self._last_source_ts = source_ts
            self._timestamp_kind = timestamp_kind or "unknown"
            self._frames += 1
            self._state = "online"
            self._last_error = None
            self._last_error_at = None

    def failure(self, kind, error, *, now=None):
        now = time.monotonic() if now is None else float(now)
        if kind not in ("open", "read"):
            raise ValueError("failure kind must be open or read")
        with self._lock:
            if kind == "open":
                self._open_failures += 1
            else:
                self._read_failures += 1
            self._last_error = str(error)
            self._last_error_at = now
            self._state = "recovering"

    def stopped(self, *, now=None):
        with self._lock:
            self._state = "stopped"

    def snapshot(self, *, now=None):
        now = time.monotonic() if now is None else float(now)
        with self._lock:
            state = self._state
            age = (None if self._last_frame_at is None
                   else max(0.0, now - self._last_frame_at))
            if state not in ("stopped", "recovering") and age is not None \
                    and age >= self.stall_after_s:
                state = "stalled"
            return {
                "camera": self.camera_id,
                "state": state,
                "stall_after_s": self.stall_after_s,
                "last_frame_age_s": age,
                "last_source_ts": self._last_source_ts,
                "timestamp_kind": self._timestamp_kind,
                "frames": self._frames,
                "open_failures": self._open_failures,
                "read_failures": self._read_failures,
                "reconnects": self._reconnects,
                "last_error": self._last_error,
                "last_error_age_s": (
                    None if self._last_error_at is None
                    else max(0.0, now - self._last_error_at)),
            }


def _parse_proc_status(text):
    """Parse the small /proc/self/status subset used by soak evidence."""
    result = {"rss_bytes": None, "threads": None}
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            fields = line.split()
            if len(fields) >= 2:
                result["rss_bytes"] = int(fields[1]) * 1024
        elif line.startswith("Threads:"):
            fields = line.split()
            if len(fields) >= 2:
                result["threads"] = int(fields[1])
    return result


class RuntimeResourceSampler:
    """Best-effort process and storage sampler for Linux soak evidence."""

    def __init__(self, storage_root):
        self.storage_root = os.path.abspath(storage_root)
        self._previous = None

    def _process_metrics(self):
        metrics = {
            "rss_bytes": None,
            "threads": threading.active_count(),
            "open_fds": None,
        }
        try:
            with open("/proc/self/status", encoding="ascii") as handle:
                metrics.update(_parse_proc_status(handle.read()))
        except (OSError, ValueError):
            pass
        try:
            metrics["open_fds"] = len(os.listdir("/proc/self/fd"))
        except OSError:
            pass
        return metrics

    def sample(self, *, now=None, process_time_s=None):
        now = time.monotonic() if now is None else float(now)
        process_time_s = (time.process_time() if process_time_s is None
                          else float(process_time_s))
        process = self._process_metrics()
        cpu_percent = None
        if self._previous is not None:
            wall_delta = now - self._previous[0]
            cpu_delta = process_time_s - self._previous[1]
            if wall_delta > 0:
                cpu_percent = max(0.0, 100.0 * cpu_delta / wall_delta)
        self._previous = (now, process_time_s)

        disk = {"total_bytes": None, "used_bytes": None,
                "free_bytes": None, "used_percent": None}
        try:
            usage = shutil.disk_usage(self.storage_root)
            disk.update({
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "used_percent": (round(100.0 * usage.used / usage.total, 3)
                                 if usage.total else None),
            })
        except OSError:
            pass
        return {
            "sampled_at": time.time(),
            "cpu_percent": (None if cpu_percent is None
                            else round(cpu_percent, 3)),
            **process,
            "disk": disk,
        }


class HealthRegistry:
    """Own camera watchdogs and produce one bounded API-ready snapshot."""

    def __init__(self, camera_ids, storage_root, *, stall_after_s=30.0):
        ids = [str(camera_id) for camera_id in camera_ids]
        if len(ids) != len(set(ids)):
            raise ValueError("camera ids must be unique")
        self._cameras = {
            camera_id: CameraWatchdog(
                camera_id, stall_after_s=stall_after_s)
            for camera_id in ids
        }
        self.resources = RuntimeResourceSampler(storage_root)

    def camera(self, camera_id):
        try:
            return self._cameras[str(camera_id)]
        except KeyError as exc:
            raise KeyError(f"unknown camera: {camera_id}") from exc

    def snapshot(self, *, now=None, include_resources=True):
        now = time.monotonic() if now is None else float(now)
        cameras = [self._cameras[camera_id].snapshot(now=now)
                   for camera_id in sorted(self._cameras)]
        return {
            "cameras": cameras,
            "count": len(cameras),
            "resources": (self.resources.sample(now=now)
                          if include_resources else None),
        }
