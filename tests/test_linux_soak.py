import hashlib
import json
from types import SimpleNamespace

import pytest

from scam.linux_soak import (EvidenceWriter, SummaryAccumulator,
                             collect_sample, run, summarize,
                             validate_base_url)


class _Response:
    status = 200

    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


def test_base_url_is_loopback_and_credential_safe():
    assert validate_base_url("http://127.0.0.1:8765/") == \
        "http://127.0.0.1:8765"
    assert validate_base_url("http://[::1]:8765") == "http://[::1]:8765"
    with pytest.raises(ValueError):
        validate_base_url("ftp://127.0.0.1")
    with pytest.raises(ValueError):
        validate_base_url("http://user:secret@127.0.0.1:8765")
    with pytest.raises(ValueError):
        validate_base_url("http://192.0.2.10:8765")
    assert validate_base_url(
        "http://192.0.2.10:8765", allow_non_loopback=True) == \
        "http://192.0.2.10:8765"


def test_collect_sample_preserves_success_and_failure():
    def opener(request, timeout):
        if request.full_url.endswith("/api/health"):
            return _Response({"cameras": [{"state": "online"}]})
        raise OSError("stats unavailable")

    sample = collect_sample(
        "http://127.0.0.1:8765", opener=opener,
        sequence=7, elapsed_s=12.5)
    assert sample["sequence"] == 7
    assert sample["elapsed_s"] == 12.5
    assert sample["endpoints"]["/api/health"]["ok"] is True
    assert sample["endpoints"]["/api/stats"]["ok"] is False
    assert "stats unavailable" in sample["endpoints"]["/api/stats"]["error"]


def test_evidence_writer_creates_verifiable_hash_chain(tmp_path):
    output = tmp_path / "run"
    writer = EvidenceWriter(str(output), {"kind": "manifest"})
    first = writer.append({"sequence": 0, "value": "a"})
    second = writer.append({"sequence": 1, "value": "b"})
    summary = writer.finish({"observed_duration_s": 1.0})

    lines = [json.loads(line) for line in
             (output / "samples.ndjson").read_text("utf-8").splitlines()]
    assert lines == [first, second]
    assert first["previous_sha256"] == "0" * 64
    assert second["previous_sha256"] == first["record_sha256"]
    unhashed = dict(first)
    digest = unhashed.pop("record_sha256")
    canonical = json.dumps(
        unhashed, ensure_ascii=False, sort_keys=True,
        separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == digest
    assert summary["last_record_sha256"] == second["record_sha256"]
    assert summary["sample_count"] == 2


def test_summary_is_observation_not_release_claim():
    samples = [{
        "endpoints": {
            "/api/health": {"ok": True, "payload": {
                "cameras": [{"state": "online"}, {"state": "stalled"}]}},
            "/api/stats": {"ok": False, "payload": None},
        }
    }]
    result = summarize(
        samples, requested_duration_s=10,
        started_monotonic=5, finished_monotonic=16)
    assert result["completed_requested_duration"] is True
    assert result["endpoint_successes"]["/api/health"] == 1
    assert result["endpoint_failures"]["/api/stats"] == 1
    assert result["camera_state_observations"] == {
        "online": 1, "stalled": 1}
    assert result["release_gate_passed"] is None


def test_summary_uses_linux_watchdog_states_not_gate_ratio_cameras():
    accumulator = SummaryAccumulator()
    accumulator.observe({
        "endpoints": {
            "/api/health": {"ok": True, "payload": {
                "cameras": [{"id": "front", "ratio": 0.5}],
                "watchdog": {"cameras": [
                    {"camera": "front", "state": "recovering"},
                    {"camera": "back", "state": "online"},
                ]},
            }},
            "/api/stats": {"ok": True, "payload": {"cameras": []}},
        }
    })
    result = accumulator.finish(
        requested_duration_s=60,
        started_monotonic=10,
        finished_monotonic=20)

    assert result["camera_state_observations"] == {
        "recovering": 1, "online": 1}
    assert "unknown" not in result["camera_state_observations"]
    assert result["completed_requested_duration"] is False
    assert result["release_gate_passed"] is None


def test_writer_refuses_to_mix_with_existing_output(tmp_path):
    output = tmp_path / "run"
    output.mkdir()
    with pytest.raises(FileExistsError):
        EvidenceWriter(str(output), {"kind": "manifest"})


def test_operator_stop_writes_honest_partial_summary(tmp_path, monkeypatch):
    def fake_sample(_base_url, **kwargs):
        return {
            "schema": "scam.linux-soak/v1",
            "kind": "sample",
            "sequence": kwargs["sequence"],
            "observed_at": "2026-09-20T00:00:00Z",
            "elapsed_s": kwargs["elapsed_s"],
            "endpoints": {
                "/api/health": {"ok": True, "payload": {
                    "watchdog": {"cameras": [
                        {"camera": "front", "state": "online"}]}}},
                "/api/stats": {"ok": True, "payload": {"cameras": []}},
            },
        }

    monkeypatch.setattr("scam.linux_soak.collect_sample", fake_sample)
    args = SimpleNamespace(
        base_url="http://127.0.0.1:8765",
        allow_non_loopback=False,
        output_dir=str(tmp_path / "partial"),
        duration_seconds=86400.0,
        interval_seconds=30.0,
        timeout_seconds=1.0,
    )
    summary = run(
        args, stop_requested=lambda: True,
        stop_reason=lambda: "sigterm")

    saved = json.loads(
        (tmp_path / "partial" / "summary.json").read_text("utf-8"))
    assert saved == summary
    assert summary["sample_count"] == 1
    assert summary["termination_reason"] == "sigterm"
    assert summary["completed_requested_duration"] is False
    assert summary["release_gate_passed"] is None
    assert summary["camera_state_observations"] == {"online": 1}
