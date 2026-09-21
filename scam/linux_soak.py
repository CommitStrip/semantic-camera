"""Linux NVR soak evidence collector.

This tool records API observations; it never declares release gates passed.
Real Linux, RTSP and duration evidence must come from the host that produced
the output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone


SCHEMA = "scam.linux-soak/v1"
ENDPOINTS = ("/api/health", "/api/stats")


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_base_url(value, *, allow_non_loopback=False):
    """Return a normalized HTTP origin, rejecting credentials and paths."""
    parsed = urllib.parse.urlsplit(str(value))
    if parsed.scheme not in ("http", "https"):
        raise ValueError("base URL must use http or https")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("base URL must contain a host and no credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("base URL must be an origin without path/query/fragment")
    host = parsed.hostname.lower()
    loopback = host == "localhost" or host == "::1" or host.startswith("127.")
    if not loopback and not allow_non_loopback:
        raise ValueError(
            "non-loopback target requires --allow-non-loopback; prefer SSH tunnel")
    port = f":{parsed.port}" if parsed.port is not None else ""
    display_host = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{display_host}{port}"


def fetch_json(url, *, timeout_s=5.0, opener=urllib.request.urlopen):
    """Fetch one JSON endpoint and preserve honest success/failure metadata."""
    started = time.monotonic()
    try:
        request = urllib.request.Request(
            url, headers={"Accept": "application/json"}, method="GET")
        with opener(request, timeout=float(timeout_s)) as response:
            status = int(getattr(response, "status", 200))
            raw = response.read()
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("JSON root is not an object")
        return {
            "ok": 200 <= status < 300,
            "status": status,
            "latency_ms": round((time.monotonic() - started) * 1000.0, 3),
            "payload": payload,
            "error": None,
        }
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError,
            urllib.error.URLError) as exc:
        return {
            "ok": False,
            "status": getattr(exc, "code", None),
            "latency_ms": round((time.monotonic() - started) * 1000.0, 3),
            "payload": None,
            "error": f"{type(exc).__name__}: {exc}",
        }


def collect_sample(base_url, *, timeout_s=5.0, opener=urllib.request.urlopen,
                   sequence=0, elapsed_s=0.0):
    return {
        "schema": SCHEMA,
        "kind": "sample",
        "sequence": int(sequence),
        "observed_at": _utc_now(),
        "elapsed_s": round(float(elapsed_s), 3),
        "endpoints": {
            path: fetch_json(base_url + path, timeout_s=timeout_s, opener=opener)
            for path in ENDPOINTS
        },
    }


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":")).encode("utf-8")


class EvidenceWriter:
    """Append-only NDJSON writer with a rolling SHA-256 chain."""

    def __init__(self, output_dir, manifest):
        self.output_dir = os.path.abspath(output_dir)
        os.makedirs(self.output_dir, exist_ok=False)
        self.samples_path = os.path.join(self.output_dir, "samples.ndjson")
        self._handle = open(self.samples_path, "xb")
        self._previous_hash = "0" * 64
        self._count = 0
        self._write_json_atomic("manifest.json", manifest)

    def _write_json_atomic(self, name, value):
        target = os.path.join(self.output_dir, name)
        temporary = target + ".tmp"
        with open(temporary, "xb") as handle:
            handle.write(_canonical(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)

    def append(self, record):
        chained = dict(record)
        chained["previous_sha256"] = self._previous_hash
        digest = hashlib.sha256(_canonical(chained)).hexdigest()
        chained["record_sha256"] = digest
        self._handle.write(_canonical(chained) + b"\n")
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._previous_hash = digest
        self._count += 1
        return chained

    def finish(self, summary):
        result = dict(summary)
        result.update({
            "schema": SCHEMA,
            "kind": "summary",
            "sample_count": self._count,
            "last_record_sha256": self._previous_hash,
            "finished_at": _utc_now(),
        })
        self._write_json_atomic("summary.json", result)
        self._handle.close()
        return result

    def abort(self):
        if not self._handle.closed:
            self._handle.close()


def summarize(samples, *, requested_duration_s, started_monotonic,
              finished_monotonic):
    accumulator = SummaryAccumulator()
    for sample in samples:
        accumulator.observe(sample)
    return accumulator.finish(
        requested_duration_s=requested_duration_s,
        started_monotonic=started_monotonic,
        finished_monotonic=finished_monotonic)


class SummaryAccumulator:
    """Bounded-memory aggregation for long-running soak observations."""

    def __init__(self):
        self.endpoint_successes = {path: 0 for path in ENDPOINTS}
        self.endpoint_failures = {path: 0 for path in ENDPOINTS}
        self.camera_states = {}

    def observe(self, sample):
        for path, result in sample.get("endpoints", {}).items():
            bucket = (self.endpoint_successes if result.get("ok")
                      else self.endpoint_failures)
            if path in bucket:
                bucket[path] += 1
        health = sample.get("endpoints", {}).get("/api/health", {})
        payload = health.get("payload") if health.get("ok") else None
        if isinstance(payload, dict):
            # Linux L3 publishes runtime state under watchdog.cameras.  The
            # legacy top-level cameras list contains gate ratios and must not
            # be misreported as watchdog state.  Keep the fallback for older
            # collectors/servers that exposed state directly at the top level.
            watchdog = payload.get("watchdog")
            cameras = (watchdog.get("cameras", [])
                       if isinstance(watchdog, dict)
                       else payload.get("cameras", []))
            for camera in cameras:
                if not isinstance(camera, dict):
                    continue
                state = str(camera.get("state", "unknown"))
                self.camera_states[state] = self.camera_states.get(state, 0) + 1

    def finish(self, *, requested_duration_s, started_monotonic,
               finished_monotonic, termination_reason="duration_reached"):
        observed = max(0.0, finished_monotonic - started_monotonic)
        return {
            "requested_duration_s": float(requested_duration_s),
            "observed_duration_s": round(observed, 3),
            "endpoint_successes": dict(self.endpoint_successes),
            "endpoint_failures": dict(self.endpoint_failures),
            "camera_state_observations": dict(self.camera_states),
            "termination_reason": str(termination_reason),
            "completed_requested_duration": (
                termination_reason == "duration_reached"
                and observed >= float(requested_duration_s)),
            "release_gate_passed": None,
            "release_gate_note": (
                "Raw observation only; evaluate host, RTSP, duration, resource "
                "plateau and failure thresholds separately."),
        }


def build_manifest(args, base_url):
    return {
        "schema": SCHEMA,
        "kind": "manifest",
        "run_id": str(uuid.uuid4()),
        "started_at": _utc_now(),
        "base_url": base_url,
        "duration_s": float(args.duration_seconds),
        "interval_s": float(args.interval_seconds),
        "timeout_s": float(args.timeout_seconds),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
    }


def run(args, *, stop_requested=None, stop_reason=None):
    base_url = validate_base_url(
        args.base_url, allow_non_loopback=args.allow_non_loopback)
    if args.duration_seconds < 0 or args.interval_seconds <= 0 \
            or args.timeout_seconds <= 0:
        raise ValueError("duration must be >= 0; interval and timeout must be > 0")
    writer = EvidenceWriter(args.output_dir, build_manifest(args, base_url))
    started = time.monotonic()
    accumulator = SummaryAccumulator()
    sequence = 0
    stop_requested = stop_requested or (lambda: False)
    stop_reason = stop_reason or (lambda: "operator_stop")
    termination_reason = "duration_reached"
    try:
        while True:
            now = time.monotonic()
            sample = collect_sample(
                base_url, timeout_s=args.timeout_seconds,
                sequence=sequence, elapsed_s=now - started)
            writer.append(sample)
            accumulator.observe(sample)
            sequence += 1
            elapsed = time.monotonic() - started
            if elapsed >= args.duration_seconds:
                break
            if stop_requested():
                termination_reason = str(stop_reason())
                break
            # Bound signal/stop latency even when the sampling interval is
            # large.  A partial run still receives a summary and a non-zero
            # CLI exit status instead of looking like a completed 24h run.
            wait_s = min(args.interval_seconds,
                         max(0.0, args.duration_seconds - elapsed))
            deadline = time.monotonic() + wait_s
            while not stop_requested():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(1.0, remaining))
            if stop_requested():
                termination_reason = str(stop_reason())
                break
        return writer.finish(accumulator.finish(
            requested_duration_s=args.duration_seconds,
            started_monotonic=started, finished_monotonic=time.monotonic(),
            termination_reason=termination_reason))
    except BaseException:
        writer.abort()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="采集Linux NVR浸泡原始证据（不自动宣称发布门禁通过）")
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--duration-seconds", type=float, default=86400.0)
    parser.add_argument("--interval-seconds", type=float, default=30.0)
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--allow-non-loopback", action="store_true")
    args = parser.parse_args(argv)
    stop_event = threading.Event()
    stop_state = {"reason": "operator_stop"}
    previous_handlers = {}

    def _request_stop(signum, _frame):
        try:
            stop_state["reason"] = signal.Signals(signum).name.lower()
        except ValueError:
            stop_state["reason"] = f"signal_{signum}"
        stop_event.set()

    for signame in ("SIGINT", "SIGTERM"):
        signum = getattr(signal, signame, None)
        if signum is not None:
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, _request_stop)
    try:
        summary = run(
            args, stop_requested=stop_event.is_set,
            stop_reason=lambda: stop_state["reason"])
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if summary["completed_requested_duration"] else 130


if __name__ == "__main__":
    raise SystemExit(main())
