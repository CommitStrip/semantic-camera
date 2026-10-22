"""Win11 picture-understanding capability switch contracts."""

import json

import pytest

from scam import nvr
from scam.db import connect, init_schema
from scam.server import WorkbenchState
from test_server import _H
from test_server_c148_compact import browser
from test_server_c150_experience import fixture_page
from test_nvr_startup import (
    _RecordingServer,
    _drive_with_captured_signals,
    _write_venue,
)


@pytest.mark.parametrize("configured", [False, True])
def test_health_exposes_only_authoritative_configured_boolean(
    tmp_path, configured
):
    path = str(tmp_path / "events.db")
    db = connect(path)
    init_schema(db)
    db.close()
    state = WorkbenchState(path)
    state.understanding_enabled = configured
    response = _H("GET", "/api/health", state=state)
    response.do_GET()
    payload = json.loads(response.wfile.getvalue())
    assert payload["understanding_capability"] == {"configured": configured}


@pytest.mark.parametrize("invalid", [None, "false", 0])
def test_health_does_not_guess_disabled_when_config_is_unknown(
    tmp_path, invalid
):
    path = str(tmp_path / "events.db")
    db = connect(path)
    init_schema(db)
    db.close()
    state = WorkbenchState(path)
    state.understanding_enabled = invalid
    response = _H("GET", "/api/health", state=state)
    response.do_GET()
    assert "understanding_capability" not in json.loads(
        response.wfile.getvalue()
    )


def test_real_win11_main_marks_disabled_from_saved_config(
    tmp_path, monkeypatch
):
    path = tmp_path / "cameras.json"
    _write_venue(path)
    saved = json.loads(path.read_text(encoding="utf-8"))
    saved["l3"] = {"enabled": False}
    path.write_text(json.dumps(saved), encoding="utf-8")
    _RecordingServer.states = []
    monkeypatch.setattr(nvr, "WorkbenchServer", _RecordingServer)
    _drive_with_captured_signals(monkeypatch, [])
    code = nvr.main(
        ["--config", str(path), "--db", str(tmp_path / "events.db")],
        edition="win11",
    )
    assert code == 0
    assert _RecordingServer.states[-1].understanding_enabled is False


@pytest.mark.parametrize("explicit_off", [True, False])
def test_explicit_off_suppresses_legacy_worker_but_old_configs_keep_it(
    tmp_path, monkeypatch, explicit_off
):
    path = tmp_path / "cameras.json"
    _write_venue(path)
    if explicit_off:
        saved = json.loads(path.read_text(encoding="utf-8"))
        saved["l3"] = {"enabled": False}
        path.write_text(json.dumps(saved), encoding="utf-8")
    calls = []
    from scam import semantic_updater

    original = semantic_updater.SemanticUpdater

    def capture(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(semantic_updater, "SemanticUpdater", capture)
    _RecordingServer.states = []
    monkeypatch.setattr(nvr, "WorkbenchServer", _RecordingServer)
    _drive_with_captured_signals(monkeypatch, [])
    assert nvr.main(
        ["--config", str(path), "--db", str(tmp_path / "events.db")],
        edition="win11",
    ) == 0
    assert len(calls) == (0 if explicit_off else 1)
    assert _RecordingServer.states[-1].understanding_enabled is (
        not explicit_off
    )


def test_real_page_disabled_state_replaces_waiting_but_keeps_saved_text(
    browser,
):
    page = browser.new_page()
    try:
        _, errors, _ = fixture_page(page)
        entry = {
            "summary": "正在分析",
            "counts": {},
            "branches": [],
            "current_identity": {"run_id": "r", "config_version": "0"},
        }
        payload = {
            "runtime": {
                "cameras": [
                    {
                        "camera": "camera-demo",
                        "state": "online",
                        "hint": "synthetic",
                    }
                ]
            },
            "understanding_capability": {"configured": False},
            "understanding": {"camera-demo": entry},
        }
        page.route(
            "**/api/health",
            lambda route: route.fulfill(
                content_type="application/json", body=json.dumps(payload)
            ),
        )
        page.evaluate("refreshHealth()")
        line = page.locator("#understanding-line").inner_text()
        details = page.locator("#understanding-detail").inner_text()
        assert "图片理解未启用" in line
        assert "等待分析" not in details
        assert "正在分析" not in line
        summary = page.evaluate(
            "eventSummary({event_id:'a',camera:'camera-demo',"
            "initial_fact_text:'事实'})"
        )
        assert "图片理解未启用" in summary["note"]
        assert "合成理解" in summary["text"]
        assert not errors
    finally:
        page.close()


def test_missing_capability_does_not_hide_real_running_state(browser):
    page = browser.new_page()
    try:
        _, _, _ = fixture_page(page)
        note = page.evaluate(
            "eventSummary({event_id:'b',camera:'camera-demo'})"
        )
        assert "图片理解未启用" not in note["note"]
        assert "分析中" in note["note"]
    finally:
        page.close()
