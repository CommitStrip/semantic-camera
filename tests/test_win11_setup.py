import io
import json
from types import SimpleNamespace

import pytest

from scam.config import load_venue, validate_venue
from scam.win11_setup import (SetupHandler, SetupState, build_initial_venue,
                              write_initial_config)


def _payload(**updates):
    data = {"camera_id": "front-door", "source_kind": "rtsp",
            "source": "rtsp://admin:secret@192.0.2.10:554/live",
            "detector_model": "C:/models/person.onnx",
            "monitor_only": False}
    data.update(updates)
    return data


class _Handler(SetupHandler):
    def __init__(self, path="/", body=None, state=None, token="token",
                 content_type="application/json"):
        raw = json.dumps(body).encode("utf-8") if body is not None else b""
        self.path = path
        self.headers = {"Content-Type": content_type,
                        "Content-Length": str(len(raw)),
                        "X-Setup-Token": token}
        self.rfile = io.BytesIO(raw)
        self.wfile = io.BytesIO()
        self.status = None
        self.response_headers = {}
        self._server = SimpleNamespace(
            state=state or SetupState("unused", token), shutdown=lambda: None)

    @property
    def server(self):
        return self._server

    def send_response(self, code, message=None):
        self.status = code

    def send_header(self, key, value):
        self.response_headers[key] = value

    def end_headers(self):
        pass

    def json_body(self):
        return json.loads(self.wfile.getvalue().decode("utf-8"))


def test_build_initial_venue_requires_honest_detection_choice():
    venue = build_initial_venue(_payload())
    assert validate_venue(venue) == []
    camera = venue["cameras"][0]
    assert camera["detector"]["engine"] == "onnx"
    assert camera["record_enabled"] is False
    assert camera["zones"] == []

    with pytest.raises(ValueError, match="仅预览不告警"):
        build_initial_venue(_payload(detector_model=""))
    preview = build_initial_venue(
        _payload(detector_model="", monitor_only=True))
    assert preview["cameras"][0]["detector"] == {"engine": "none"}


@pytest.mark.parametrize("updates", [
    {"camera_id": "../escape"},
    {"source_kind": "rtsp", "source": "http://camera/live"},
    {"source_kind": "camera", "source": "not-a-number"},
    {"source_kind": "unknown"},
])
def test_build_initial_venue_rejects_untrusted_input(updates):
    with pytest.raises(ValueError):
        build_initial_venue(_payload(**updates))


def test_write_initial_config_is_utf8_and_never_overwrites(tmp_path):
    path = tmp_path / "中文目录" / "cameras.json"
    venue = build_initial_venue(_payload())
    write_initial_config(path, venue)
    assert load_venue(path) == venue

    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        write_initial_config(path, build_initial_venue(
            _payload(camera_id="other")))
    assert path.read_bytes() == original

    tiny = tmp_path / "tiny-existing.json"
    tiny.write_text("{}", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_initial_config(tiny, venue)
    assert tiny.read_text(encoding="utf-8") == "{}"


def test_setup_page_is_local_first_and_does_not_echo_credentials():
    handler = _Handler(path="/")
    handler.do_GET()
    html = handler.wfile.getvalue().decode("utf-8")
    assert handler.status == 200
    assert "接入第一路摄像头" in html
    assert "只预览画面" in html and "不产生目标告警" in html
    assert "secret" not in html
    assert handler.response_headers["Cache-Control"] == "no-store"
    assert handler.response_headers["X-Content-Type-Options"] == "nosniff"


def test_setup_post_requires_json_and_session_token(tmp_path):
    state = SetupState(str(tmp_path / "cameras.json"), "good")
    handler = _Handler(path="/api/setup", body=_payload(), state=state,
                       token="bad")
    handler.do_POST()
    assert handler.status == 403 and not state.saved.is_set()

    handler = _Handler(path="/api/setup", body=_payload(), state=state,
                       token="good", content_type="text/plain")
    handler.do_POST()
    assert handler.status == 415 and not state.saved.is_set()


def test_setup_post_persists_once_without_returning_credentials(
        tmp_path, monkeypatch):
    state = SetupState(str(tmp_path / "cameras.json"), "good")
    started = []

    class ImmediateThread:
        def __init__(self, target, daemon):
            self.target = target

        def start(self):
            started.append(True)
            self.target()

    monkeypatch.setattr("scam.win11_setup.threading.Thread", ImmediateThread)
    handler = _Handler(path="/api/setup", body=_payload(), state=state,
                       token="good")
    handler.do_POST()
    response = handler.json_body()
    assert handler.status == 200 and response == {"ok": True}
    assert "secret" not in handler.wfile.getvalue().decode("utf-8")
    assert state.saved.is_set() and started
    assert load_venue(state.config_path)["cameras"][0]["source"].startswith(
        "rtsp://")

    again = _Handler(path="/api/setup", body=_payload(), state=state,
                     token="good")
    again.do_POST()
    assert again.status == 409
