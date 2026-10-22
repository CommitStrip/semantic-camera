import base64
import concurrent.futures
import json
from pathlib import Path
from urllib.error import HTTPError

import cv2
import numpy as np
import pytest

import os

from scam import models
import scam.win11_l3_cloud as provider_module


BASE = "https://203.0.113.10/v1"
MODEL = "cloud-vlm-test"
KEY_ENV = "C190_CLOUD_KEY_TEST"


@pytest.fixture(autouse=True)
def _cloud_key(monkeypatch):
    monkeypatch.setenv(KEY_ENV, "test-key")
    monkeypatch.setattr(models, "_resolve_ips", lambda host: {"203.0.113.10"})


def _frame(value=1):
    return np.full((4, 6, 3), value, dtype=np.uint8)


def _b64(frame):
    ok, encoded = cv2.imencode(".jpg", frame)
    assert ok is True
    return base64.b64encode(encoded.tobytes()).decode("ascii")


def _meta(frame_id):
    return {"frame_id": frame_id, "timestamp_kind": "video_pts",
            "present": True}


class _Response:
    def __init__(self, content, status=200):
        self.status = status
        self._payload = json.dumps({
            "choices": [{"message": {"content": content}}]
        }).encode("utf-8")

    def read(self, size=-1):
        if size is None or size < 0:
            return self._payload
        return self._payload[:size]

    def close(self):
        self.close_count = getattr(self, "close_count", 0) + 1


class _HTTPError(RuntimeError):
    def __init__(self, status):
        super().__init__(f"http-{status}")
        self.status = status
        self.code = status


class _Transport:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def __call__(self, request, timeout):
        self.requests.append({
            "full_url": request.full_url,
            "headers": dict(request.header_items()),
            "body": json.loads(request.data.decode("utf-8")),
            "timeout": timeout,
        })
        response = self.response
        if isinstance(response, Exception):
            raise response
        return response


def _provider(**kwargs):
    from scam.win11_l3_cloud import CloudOpenAICompatibleL3Provider
    values = {"base_url": BASE, "model": MODEL, "key_env": KEY_ENV,
              "consent": True, "transport": _Transport(_Response("{}"))}
    values.update(kwargs)
    return CloudOpenAICompatibleL3Provider(**values)


def _backend(**kwargs):
    from scam.win11_l3_cloud import CloudOpenAICompatibleL3Backend
    values = {"base_url": BASE, "model": MODEL, "key_env": KEY_ENV,
              "consent": True, "transport": _Transport(_Response("{}")),
              "infer_timeout_s": 5.0, "load_timeout_s": 5.0}
    values.update(kwargs)
    return CloudOpenAICompatibleL3Backend(**values)


def test_default_consent_is_off_and_never_constructs_network_path():
    from scam.win11_l3_cloud import CloudOpenAICompatibleL3Provider
    with pytest.raises(ValueError, match="cloud_consent_required"):
        CloudOpenAICompatibleL3Provider(
            base_url=BASE, model=MODEL, key_env=KEY_ENV,
            transport=_Transport(_Response("{}")))


@pytest.mark.parametrize("base", [
    "http://203.0.113.10/v1",
    "https://user:secret@203.0.113.10/v1",
    "https://203.0.113.10/v1?trace=secret",
    "https://203.0.113.10/v1#fragment",
])
def test_strict_endpoint_rejects_non_https_and_embedded_secrets(base):
    with pytest.raises(ValueError):
        _provider(base_url=base)


def test_dns_resolution_rejects_private_or_loopback_endpoint(monkeypatch):
    monkeypatch.setattr(models, "_resolve_ips", lambda host: {"127.0.0.1"})
    with pytest.raises(ValueError):
        _provider()


def test_missing_key_is_structured_and_transport_is_not_called(monkeypatch):
    monkeypatch.delenv(KEY_ENV)
    transport = _Transport(_Response('{"observation":"never"}'))
    provider = _provider(transport=transport)
    with pytest.raises(RuntimeError, match="cloud_key_missing"):
        provider.understand_frames("prompt", ["a"], [{"frame_id": 0}])
    assert transport.requests == []


@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_whitespace_key_is_rejected_without_transport(monkeypatch, value):
    monkeypatch.setenv(KEY_ENV, value)
    transport = _Transport(_Response("{}"))
    provider = _provider(transport=transport)
    with pytest.raises(RuntimeError, match="cloud_key_missing"):
        provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)])
    assert transport.requests == []


def test_provider_sends_ordered_frames_meta_prompt_and_budget():
    transport = _Transport(_Response(json.dumps({
        "observation": "raw observation",
        "inference": "raw inference",
        "unknown": {"reason": "not visible"},
    }, ensure_ascii=False)))
    provider = _provider(transport=transport, max_tokens=200)
    frames = [_b64(_frame(7)), None, _b64(_frame(9))]
    meta = [_meta(10), {"frame_id": 20, "present": False}, _meta(30)]
    out = provider.understand_frames("有序 prompt", frames, meta)
    assert out == {"observation": "raw observation",
                   "inference": "raw inference",
                   "unknown": {"reason": "not visible"}}
    assert len(transport.requests) == 1
    request = transport.requests[0]
    assert request["timeout"] == provider.request_timeout_s
    body = request["body"]
    assert body["model"] == MODEL
    assert body["max_tokens"] == 200
    assert body["stream"] is False
    assert body["temperature"] == 0
    content = body["messages"][0]["content"]
    assert content[0] == {"type": "text", "text": "有序 prompt"}
    assert content[1]["type"] == "text"
    assert json.loads(content[1]["text"].split("META ", 1)[1]) == _meta(10)
    assert content[2]["type"] == "image_url"
    encoded = content[2]["image_url"]["url"]
    assert encoded.startswith("data:image/jpeg;base64,")
    assert content[3]["type"] == "text"
    assert "FRAME 1 MISSING" in content[3]["text"]
    assert json.loads(content[3]["text"].split("META ", 1)[1]) == meta[1]
    assert content[4]["type"] == "text"
    assert json.loads(content[4]["text"].split("META ", 1)[1]) == _meta(30)
    assert content[5]["type"] == "image_url"
    headers = dict((k.lower(), v) for k, v in request["headers"].items())
    assert headers["authorization"] == "Bearer test-key"
    assert "secret" not in json.dumps(body)


def test_metadata_length_and_position_are_strict():
    provider = _provider()
    with pytest.raises(RuntimeError,
                       match="cloud_frame_metadata_length_mismatch"):
        provider.understand_frames("prompt", [_b64(_frame()), _b64(_frame())],
                                   [_meta(1)])
    mismatched = [_meta(0), _meta(2)]
    mismatched[1]["position"] = 2
    with pytest.raises(RuntimeError,
                       match="cloud_frame_position_mismatch"):
        provider.understand_frames("prompt", [_b64(_frame()), _b64(_frame())],
                                   mismatched)


@pytest.mark.parametrize("timeout", [True, False, float("nan"),
                                     float("inf"), 0, -1])
def test_request_timeout_rejects_invalid_numbers(timeout):
    with pytest.raises(ValueError,
                       match="cloud_request_timeout_must_be_positive"):
        _provider(request_timeout_s=timeout)


def test_transport_message_is_sanitized_and_not_retried():
    secret = "SECRET-URL-OR-HEADER-DETAIL"

    def fail_transport(request, timeout):
        raise RuntimeError(f"custom {secret}")

    provider = _provider(transport=fail_transport)
    with pytest.raises(RuntimeError,
                       match=r"cloud_transport_failed:RuntimeError") as excinfo:
        provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)])
    assert secret not in str(excinfo.value)


def test_response_size_is_bounded_before_json_parsing():
    payload = (json.dumps({"choices": [{"message": {"content": "ok"}}]})
               .encode("utf-8"))

    class LargeResponse:
        close_count = 0

        def read(self, size=-1):
            if size is None or size < 0:
                return payload
            return payload[:size]

        def close(self):
            self.close_count += 1

    provider = _provider(transport=lambda request, timeout: LargeResponse(),
                         max_response_bytes=8)
    with pytest.raises(RuntimeError,
                       match="cloud_response_too_large"):
        provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)])


@pytest.mark.parametrize("payload, expected_error", [
    ("{}", "cloud_response_choices"),
    ("{\"choices\": []}", "cloud_response_choices"),
])
def test_response_is_closed_on_bad_json_shape(payload, expected_error):
    class BadShapeResponse(_Response):
        def __init__(self):
            self.payload = payload.encode("utf-8")
            self.close_count = 0

        def read(self, size=-1):
            if size is None or size < 0:
                return self.payload
            return self.payload[:size]

    response = BadShapeResponse()
    provider = _provider(transport=lambda request, timeout: response)
    with pytest.raises(RuntimeError, match=expected_error):
        provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)])
    assert response.close_count == 1


def test_response_close_is_called_on_read_failure_and_original_error_wins():
    class ReadFailureResponse:
        close_count = 0

        def read(self, size=-1):
            raise RuntimeError("read detail must not leak")

        def close(self):
            self.close_count += 1
            raise RuntimeError("close detail must not mask read error")

    response = ReadFailureResponse()
    provider = _provider(transport=lambda request, timeout: response)
    with pytest.raises(RuntimeError,
                       match=r"cloud_response_read_failed:RuntimeError") as excinfo:
        provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)])
    assert response.close_count == 1
    assert "read detail" not in str(excinfo.value)
    assert "close detail" not in str(excinfo.value)


def test_close_failure_is_structured_only_when_no_original_error():
    class CloseFailureResponse(_Response):
        def close(self):
            raise RuntimeError("close detail must not leak")

    provider = _provider(transport=lambda request, timeout: CloseFailureResponse("{}"))
    with pytest.raises(RuntimeError,
                       match=r"cloud_response_close_failed:RuntimeError") as excinfo:
        provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)])
    assert "close detail" not in str(excinfo.value)


def test_successful_response_is_closed_exactly_once():
    response = _Response("ok")
    provider = _provider(transport=lambda request, timeout: response)
    assert provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)]) == {"text": "ok"}
    assert response.close_count == 1


def test_no_redirect_handler_refuses_redirect():
    handler = provider_module._NoRedirect()
    assert handler.redirect_request(
        None, None, 302, "Found", {}, "https://example.test/target") is None


def test_redirect_does_not_forward_authorization_header():
    captured = {}

    class Opener:
        def open(self, request, timeout):
            captured["request"] = request
            raise RuntimeError("redirect intercepted")

    monkeypatch = None
    original = provider_module.build_opener
    provider_module.build_opener = lambda handler: Opener()
    try:
        provider = _provider(transport=None)
        with pytest.raises(RuntimeError, match="cloud_transport_failed"):
            provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)])
    finally:
        provider_module.build_opener = original
    assert "Authorization" not in captured["request"].header_items()


def test_non_json_and_unknown_are_preserved_without_repair():
    exact = "  RAW non-JSON answer\n"
    response = _Response(exact)
    provider = _provider(transport=lambda request, timeout: response)
    out = provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)])
    assert out == {"text": exact}
    assert response.close_count == 1

    unknown = '{"observation":"raw","unknown":{"door":"unknown"}}'
    response = _Response(unknown)
    provider = _provider(transport=lambda request, timeout: response)
    out = provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)])
    assert out == {"observation": "raw", "unknown": {"door": "unknown"}}
    assert response.close_count == 1


def test_http_errors_are_structured_and_never_retried():
    for status, exception_type in ((429, "cloud_rate_limited"),
                                   (500, "cloud_server_error"),
                                   (400, "cloud_bad_response")):
        transport = _Transport(HTTPError(
            "https://203.0.113.10/v1", status,
                f"HTTP Error {status}", None, fp=None))
        provider = _provider(transport=transport)
        with pytest.raises(RuntimeError, match=exception_type):
            provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)])
        assert len(transport.requests) == 1


def test_bad_response_shape_is_structured():
    response = _Response({"no_choices": True})
    provider = _provider(transport=lambda request, timeout: response)
    with pytest.raises(RuntimeError, match="cloud_response_message_content"):
        provider.understand_frames("prompt", [_b64(_frame())], [_meta(1)])
    assert response.close_count == 1


def test_backend_model_ref_is_cloud_and_stage_preserves_unknown():
    from scam.win11_l3 import L3Stage
    from scam.win11_l3_contract import L3Budget
    from scam.win11_materials import MaterialFrame, MaterialPackage
    from types import SimpleNamespace
    transport = _Transport(_Response(json.dumps({
        "observation": "door area observed",
        "unknown": "entry not observable",
    })))
    backend = _backend(transport=transport)
    assert backend.model_ref == f"cloud/{MODEL}"
    assert backend.snapshot()["backend"] == "cloud-openai-compatible"
    assert backend.snapshot()["dtype"] is None
    images = [_frame(2), _frame(4), _frame(3)]
    frames = [MaterialFrame(frame_id, image, frame_id * 1000.0, "video_pts")
              for frame_id, image in zip((0, 149, 480), images)]
    package = MaterialPackage("camera", "run", 0, 1, 0.0, frames[1], [],
                              6, 4)
    package.prev, package.nxt = frames[0], frames[2]
    package.prev_gap_ms = 1000.0
    package.nxt_gap_ms = 1000.0
    branch = SimpleNamespace(branch_kind="panorama", crop_id=None,
                             identity=SimpleNamespace(camera_id="camera",
                                                      run_id="run",
                                                      config_version=0,
                                                      material_id=1))
    task, = __import__("scam.win11_l3_tasks", fromlist=["tasks_from_package"]) \
        .tasks_from_package(pkg=package, branches=[branch], window_id=1,
                            budget=L3Budget(max_frames_per_task=3))
    output = L3Stage(backend).process(task)
    assert output.status.value == "ok"
    assert output.results[0].observation == "door area observed"
    assert output.results[0].model_unknown == "entry not observable"


def test_backend_timeout_poisons_and_reports_in_flight_honestly():
    class BlockingTransport:
        def __init__(self):
            self.event = __import__("threading").Event()

        def __call__(self, request, timeout):
            self.event.wait(2.0)
            raise TimeoutError("blocked transport")

    transport = BlockingTransport()
    backend = _backend(transport=transport, infer_timeout_s=0.05)
    with pytest.raises(TimeoutError):
        backend.understand_frames("prompt", [_frame()], [_meta(1)])
    assert backend.poisoned is True
    diagnostic = backend.diagnostic()
    assert diagnostic["pending_calls"] == 1
    assert diagnostic["executor_threads_alive"] == 1
    with pytest.raises(Exception, match="backend_isolated"):
        backend.understand_frames("prompt", [_frame()], [_meta(1)])
    transport.event.set()
    with pytest.raises(Exception):
        backend._pending_future.result(timeout=5)
    assert backend.diagnostic()["pending_calls"] == 0
    close = backend.close(timeout_s=5.0)
    assert close["closed"] is True and close["close_incomplete"] is False


def test_close_and_late_call_are_structured():
    backend = _backend()
    first = backend.close(timeout_s=5.0)
    assert first == {"closed": True, "pending_calls": 0,
                     "threads_alive": 0, "close_incomplete": False}
    with pytest.raises(Exception, match=r"close\(\) was called"):
        backend.understand_frames("prompt", [_frame()], [_meta(1)])
