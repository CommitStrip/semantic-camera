"""C190 offline cloud privacy contract tests.

No live HTTP client reaches the network. Legacy-provider defects remain frozen
as strict xfails. The independent win11_l3_cloud interface is now exercised
directly with injected transports.
"""

from __future__ import annotations

import json
import os
import threading
import time
from urllib.error import HTTPError, URLError

import numpy as np
import pytest

from scam import models
import scam.win11_l3_cloud as cloud_module


def _public_dns(monkeypatch):
    monkeypatch.setattr(
        models, "_resolve_ips", lambda host: {"203.0.113.10"}
    )


def test_post_json_does_not_follow_redirect(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'{"ok": true}'

    class Opener:
        def open(self, request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return Response()

    def build(handler):
        captured["handler"] = (
            handler() if isinstance(handler, type) else handler
        )
        return Opener()

    monkeypatch.setattr(models.urllib.request, "build_opener", build)
    assert models._post_json(
        "https://api.example.test", {"x": 1}, 2,
        {"Authorization": "Bearer not-forwarded"},
    ) == {"ok": True}
    handler = captured["handler"]
    assert handler.redirect_request(
        captured["request"], None, 302, "Found", {},
        "https://evil.example.test/collect",
    ) is None


def test_cloud_http_base_rejected_without_dns(monkeypatch):
    _public_dns(monkeypatch)
    with pytest.raises(ValueError, match="https"):
        models.CloudOpenAICompat("http://api.example.test", "m")


@pytest.mark.xfail(
    strict=True,
    reason="current CloudOpenAICompat accepts an empty key instead of rejecting",
)
def test_current_cloud_missing_key_must_reject(monkeypatch):
    _public_dns(monkeypatch)
    monkeypatch.setenv("C190_KEY", "")
    with pytest.raises(ValueError):
        models.CloudOpenAICompat(
            "https://api.example.test", "m", key_env="C190_KEY"
        )


@pytest.mark.xfail(
    strict=True,
    reason="current CloudOpenAICompat calls undefined _context_text and swallows it",
)
def test_current_cloud_context_method_must_exist(monkeypatch):
    _public_dns(monkeypatch)
    monkeypatch.setenv("C190_KEY", "test-only")
    provider = models.CloudOpenAICompat(
        "https://api.example.test", "m", key_env="C190_KEY"
    )
    assert callable(getattr(provider, "_context_text", None))


@pytest.mark.xfail(
    strict=True,
    reason="current CloudOpenAICompat retains userinfo/query secrets in base",
)
def test_current_cloud_rejects_userinfo_and_query_secret(monkeypatch):
    _public_dns(monkeypatch)
    with pytest.raises(ValueError):
        models.CloudOpenAICompat(
            "https://user:pass@api.example.test/v1?token=SECRET",
            "m",
            key_env="C190_KEY",
        )


@pytest.mark.xfail(
    strict=True,
    reason="current CloudOpenAICompat swallows transport exceptions as None",
)
def test_current_cloud_transport_error_must_be_visible(monkeypatch):
    _public_dns(monkeypatch)
    monkeypatch.setenv("C190_KEY", "test-only")
    provider = models.CloudOpenAICompat(
        "https://api.example.test", "m", key_env="C190_KEY"
    )
    monkeypatch.setattr(
        models.CloudOpenAICompat,
        "_context_text",
        staticmethod(lambda context: ""),
        raising=False,
    )

    def fail_post(*args, **kwargs):
        raise RuntimeError("HTTP 503 SECRET-DETAIL")

    monkeypatch.setattr(models, "_post_json", fail_post)
    with pytest.raises(Exception, match="503"):
        provider.understand("prompt", ["base64"], {"camera": "c1"})


class _CloudResponse:
    def __init__(self, content: str, raw: bytes | None = None):
        self.raw = (
            raw
            if raw is not None
            else json.dumps(
                {"choices": [{"message": {"content": content}}]}
            ).encode("utf-8")
        )
        self.closed = 0

    def read(self, size: int = -1):
        if size < 0:
            return self.raw
        return self.raw[:size]

    def close(self):
        self.closed += 1


class _CaptureTransport:
    def __init__(self, response=None, exc=None):
        self.response = response or _CloudResponse('{"observation":"ok"}')
        self.exc = exc
        self.calls = []

    def __call__(self, request, timeout):
        self.calls.append(
            {
                "request": request,
                "url": request.full_url,
                "headers": dict(request.header_items()),
                "body": json.loads(request.data.decode("utf-8")),
                "timeout": timeout,
            }
        )
        if self.exc is not None:
            raise self.exc
        return self.response


NEW_BASE = "https://203.0.113.10/v1"
NEW_MODEL = "c190-cloud-model"
NEW_KEY_ENV = "C190_NEW_CLOUD_KEY"


@pytest.fixture
def new_cloud_env(monkeypatch):
    _public_dns(monkeypatch)
    monkeypatch.setenv(NEW_KEY_ENV, "test-key-value")


def _new_provider(*, transport=None, base_url=NEW_BASE, **kwargs):
    values = {
        "base_url": base_url,
        "model": NEW_MODEL,
        "key_env": NEW_KEY_ENV,
        "consent": True,
        "transport": transport or _CaptureTransport(),
    }
    values.update(kwargs)
    return cloud_module.CloudOpenAICompatibleL3Provider(**values)


@pytest.mark.parametrize("consent", [False, None, 0, 1, "true"])
def test_new_cloud_consent_must_be_strict_true(new_cloud_env, consent):
    transport = _CaptureTransport()
    with pytest.raises(ValueError, match="cloud_consent_required"):
        cloud_module.CloudOpenAICompatibleL3Provider(
            base_url=NEW_BASE,
            model=NEW_MODEL,
            key_env=NEW_KEY_ENV,
            consent=consent,
            transport=transport,
        )
    assert transport.calls == []


def test_new_cloud_missing_or_control_key_is_rejected_without_echo(
        new_cloud_env, monkeypatch):
    transport = _CaptureTransport()
    provider = _new_provider(transport=transport)
    monkeypatch.delenv(NEW_KEY_ENV)
    with pytest.raises(
        cloud_module.CloudKeyMissing, match="cloud_key_missing"
    ) as missing:
        provider.understand_frames("prompt", ["AAAA"], [{"position": 0}])
    assert "test-key-value" not in str(missing.value)
    assert transport.calls == []

    monkeypatch.setenv(NEW_KEY_ENV, "CONTROL-SECRET\nVALUE")
    with pytest.raises(
        cloud_module.CloudKeyMissing,
        match="cloud_key_invalid_control_characters",
    ) as control:
        provider.understand_frames("prompt", ["AAAA"], [{"position": 0}])
    assert "CONTROL-SECRET" not in str(control.value)
    assert transport.calls == []


@pytest.mark.parametrize(
    "base_url",
    [
        "http://203.0.113.10/v1",
        "https://user:URLSECRET@203.0.113.10/v1",
        "https://203.0.113.10/v1?token=URLSECRET",
        "https://203.0.113.10/v1#URLSECRET",
    ],
)
def test_new_cloud_base_url_secrets_are_rejected_without_echo(
        new_cloud_env, base_url):
    with pytest.raises(ValueError) as excinfo:
        _new_provider(base_url=base_url)
    assert "URLSECRET" not in str(excinfo.value)


def test_new_cloud_private_dns_is_rejected(new_cloud_env, monkeypatch):
    monkeypatch.setattr(models, "_resolve_ips", lambda host: {"10.0.0.7"})
    with pytest.raises(ValueError, match="本地/私网"):
        _new_provider(base_url="https://cloud-c190.example.test/v1")


def test_new_cloud_default_transport_refuses_cross_host_redirect(
        new_cloud_env, monkeypatch):
    captured = {}

    class RedirectingOpener:
        def __init__(self, handler):
            self.handler = handler
            self.requests = []

        def open(self, request, timeout):
            self.requests.append(request)
            redirected = self.handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "https://evil.example.test/collect",
            )
            assert redirected is None
            raise HTTPError(
                request.full_url,
                302,
                "Found",
                {},
                None,
            )

    def build(handler):
        instance = handler() if isinstance(handler, type) else handler
        captured["opener"] = RedirectingOpener(instance)
        return captured["opener"]

    monkeypatch.setattr(cloud_module, "build_opener", build)
    provider = _new_provider(transport=None)
    provider.transport = None
    with pytest.raises(cloud_module.CloudHTTPError) as excinfo:
        provider.understand_frames(
            "prompt", ["AAAA"], [{"position": 0}]
        )
    assert excinfo.value.status == 302
    assert len(captured["opener"].requests) == 1
    headers = dict(
        (key.lower(), value)
        for key, value in captured["opener"].requests[0].header_items()
    )
    assert headers["authorization"] == "Bearer test-key-value"


def test_new_cloud_preserves_ordered_frames_meta_and_missing_slot(new_cloud_env):
    transport = _CaptureTransport(
        _CloudResponse('{"observation":"ordered","unknown":null}')
    )
    provider = _new_provider(transport=transport)
    frames = ["FRAME-A", None, "FRAME-C"]
    meta = [
        {"position": 0, "frame_id": 10},
        {"position": 1, "frame_id": 20},
        {"position": 2, "frame_id": 30},
    ]
    assert provider.understand_frames("ordered prompt", frames, meta) == {
        "observation": "ordered",
        "unknown": None,
    }
    content = transport.calls[0]["body"]["messages"][0]["content"]
    assert content[0] == {"type": "text", "text": "ordered prompt"}
    assert "FRAME 0 PRESENT" in content[1]["text"]
    assert "FRAME 1 MISSING" in content[3]["text"]
    assert content[4]["text"].startswith("FRAME 2 PRESENT")
    assert content[5]["image_url"]["url"].endswith("FRAME-C")
    assert [item["type"] for item in content] == [
        "text", "text", "image_url", "text", "text", "image_url"
    ]


@pytest.mark.parametrize("status", [429, 500, 503])
def test_new_cloud_http_errors_are_structured_and_single_call(
        new_cloud_env, status):
    transport = _CaptureTransport(
        exc=HTTPError(
            NEW_BASE, status, "controlled", {}, None
        )
    )
    provider = _new_provider(transport=transport)
    with pytest.raises(cloud_module.CloudHTTPError) as excinfo:
        provider.understand_frames(
            "prompt", ["AAAA"], [{"position": 0}]
        )
    assert excinfo.value.status == status
    assert excinfo.value.code == (
        "cloud_rate_limited" if status == 429 else "cloud_server_error"
    )
    assert len(transport.calls) == 1


def test_new_cloud_bad_http_json_is_visible_not_success(new_cloud_env):
    transport = _CaptureTransport(_CloudResponse("", raw=b"<html>500</html>"))
    provider = _new_provider(transport=transport)
    with pytest.raises(
        cloud_module.CloudBadResponse, match="cloud_response_json"
    ):
        provider.understand_frames(
            "prompt", ["AAAA"], [{"position": 0}]
        )
    assert len(transport.calls) == 1


def test_new_cloud_response_over_limit_is_rejected_after_bounded_read(
        new_cloud_env):
    response = _CloudResponse("", raw=b"x" * 17)
    requested_sizes = []
    original_read = response.read

    def bounded_read(size=-1):
        requested_sizes.append(size)
        return original_read(size)

    response.read = bounded_read
    transport = _CaptureTransport(response)
    provider = _new_provider(
        transport=transport,
        max_response_bytes=16,
    )
    with pytest.raises(
        cloud_module.CloudResponseTooLarge,
        match="cloud_response_too_large:16",
    ):
        provider.understand_frames(
            "prompt", ["AAAA"], [{"position": 0}]
        )
    assert requested_sizes == [17]
    assert len(transport.calls) == 1


def test_new_cloud_transport_exception_cause_must_not_leak(
        new_cloud_env):
    transport = _CallableTransport(
        lambda request, timeout: (_ for _ in ()).throw(
            URLError("SECRET-CAUSE-DETAIL")
        )
    )
    provider = _new_provider(transport=transport)
    with pytest.raises(cloud_module.CloudTransportError) as excinfo:
        provider.understand_frames(
            "prompt", ["AAAA"], [{"position": 0}]
        )
    assert excinfo.value.__cause__ is None


class _CallableTransport:
    def __init__(self, func):
        self.func = func

    def __call__(self, request, timeout):
        return self.func(request, timeout)


def test_new_cloud_timeout_in_flight_and_close_are_not_faked_zero(
        new_cloud_env):
    class BlockingTransport:
        def __init__(self):
            self.started = threading.Event()
            self.release = threading.Event()
            self.calls = 0

        def __call__(self, request, timeout):
            del request, timeout
            self.calls += 1
            self.started.set()
            self.release.wait(2.0)
            return _CloudResponse('{"text":"late-result"}')

    transport = BlockingTransport()
    backend = cloud_module.CloudOpenAICompatibleL3Backend(
        base_url=NEW_BASE,
        model=NEW_MODEL,
        key_env=NEW_KEY_ENV,
        consent=True,
        transport=transport,
        infer_timeout_s=0.05,
        load_timeout_s=1.0,
    )
    frames = np.zeros((4, 6, 3), dtype=np.uint8)
    with pytest.raises(TimeoutError):
        backend.understand_frames(
            "prompt", [frames], [{"position": 0}]
        )
    assert transport.started.is_set()
    diagnostic = backend.diagnostic()
    assert diagnostic["pending_calls"] == 1
    assert diagnostic["executor_threads_alive"] == 1
    incomplete = backend.close(timeout_s=0.01)
    assert incomplete["closed"] is False
    assert incomplete["close_incomplete"] is True
    assert incomplete["pending_calls"] >= 1

    transport.release.set()
    deadline = time.monotonic() + 2.0
    while backend.diagnostic()["pending_calls"] and time.monotonic() < deadline:
        time.sleep(0.01)
    complete = backend.close(timeout_s=2.0)
    assert complete == {
        "closed": True,
        "pending_calls": 0,
        "threads_alive": 0,
        "close_incomplete": False,
    }
