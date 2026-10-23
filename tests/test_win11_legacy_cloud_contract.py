"""Independent, non-xfail regression for the legacy cloud provider."""

from __future__ import annotations

import json

import pytest

from scam import models


KEY_ENV = "PUBLIC_LEGACY_CLOUD_KEY"
BASE = "https://203.0.113.10/v1"


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    monkeypatch.setattr(
        models, "_resolve_ips", lambda host: {"203.0.113.10"}
    )
    monkeypatch.setenv(KEY_ENV, "test-only-key")


def test_legacy_cloud_is_reachable_from_existing_build_provider():
    provider = models.build_provider(
        {
            "channel": "cloud",
            "base": BASE,
            "model": "test-model",
            "key_env": KEY_ENV,
        }
    )
    assert isinstance(provider, models.CloudOpenAICompat)
    assert provider.name == "cloud"
    assert provider.base == BASE


@pytest.mark.parametrize("key", ["", "   ", "\t", "safe\nvalue", "safe\x7fvalue"])
def test_missing_blank_or_control_key_fails_closed(monkeypatch, key):
    monkeypatch.setenv(KEY_ENV, key)
    with pytest.raises(ValueError) as excinfo:
        models.CloudOpenAICompat(BASE, "test-model", key_env=KEY_ENV)
    assert "safe" not in str(excinfo.value)
    assert "value" not in str(excinfo.value)


def test_build_provider_does_not_return_an_unauthenticated_provider(monkeypatch):
    monkeypatch.delenv(KEY_ENV)
    assert models.build_provider(
        {
            "channel": "cloud",
            "base": BASE,
            "model": "test-model",
            "key_env": KEY_ENV,
        }
    ) is None


@pytest.mark.parametrize(
    "base",
    [
        "https://user:URLSECRET@203.0.113.10/v1",
        "https://203.0.113.10/v1?token=URLSECRET",
        "https://203.0.113.10/v1#URLSECRET",
    ],
)
def test_url_credentials_query_and_fragment_are_rejected_without_echo(base):
    with pytest.raises(ValueError) as excinfo:
        models.CloudOpenAICompat(base, "test-model", key_env=KEY_ENV)
    assert "URLSECRET" not in str(excinfo.value)


def test_context_rendering_is_deterministic_text():
    provider = models.CloudOpenAICompat(
        BASE, "test-model", key_env=KEY_ENV
    )
    assert callable(provider._context_text)
    assert provider._context_text(None) == ""
    assert provider._context_text("camera=c1") == "camera=c1"
    assert provider._context_text({"z": 1, "a": 2}) == '{"a": 2, "z": 1}'


def test_transport_status_is_visible_but_original_message_is_suppressed(monkeypatch):
    provider = models.CloudOpenAICompat(
        BASE, "test-model", key_env=KEY_ENV
    )

    def fail_post(*args, **kwargs):
        raise RuntimeError("HTTP 503 SECRET-DETAIL")

    monkeypatch.setattr(models, "_post_json", fail_post)
    with pytest.raises(models.CloudProviderError, match="503") as excinfo:
        provider.understand("prompt", ["AAAA"], {"camera_id": "c1"})
    assert excinfo.value.code == "cloud_http_error"
    assert excinfo.value.status == 503
    assert "SECRET-DETAIL" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__ is True


def test_generic_transport_failure_is_visible_and_sanitized(monkeypatch):
    provider = models.CloudOpenAICompat(
        BASE, "test-model", key_env=KEY_ENV
    )

    class SecretTransportFailure(RuntimeError):
        pass

    def fail_post(*args, **kwargs):
        raise SecretTransportFailure("SECRET-TRANSPORT-DETAIL")

    monkeypatch.setattr(models, "_post_json", fail_post)
    with pytest.raises(
        models.CloudProviderError, match="SecretTransportFailure"
    ) as excinfo:
        provider.understand("prompt", ["AAAA"], {"camera_id": "c1"})
    assert excinfo.value.code == "cloud_transport_failed"
    assert excinfo.value.status is None
    assert "SECRET-TRANSPORT-DETAIL" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__ is True


def test_success_keeps_existing_request_contract(monkeypatch):
    captured = {}

    def fake_post(url, body, timeout, headers=None):
        captured.update(
            url=url,
            body=body,
            timeout=timeout,
            headers=headers,
        )
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps({"scene_type": "room"})
                    }
                }
            ]
        }

    monkeypatch.setattr(models, "_post_json", fake_post)
    provider = models.CloudOpenAICompat(
        BASE, "test-model", key_env=KEY_ENV, timeout=7
    )
    assert provider.understand(
        "prompt", ["AAAA"], {"camera_id": "c1"}
    ) == {"scene_type": "room"}
    assert captured["url"] == BASE + "/v1/chat/completions"
    assert captured["timeout"] == 7
    assert captured["headers"] == {
        "Authorization": "Bearer test-only-key"
    }
    assert captured["body"]["messages"][0] == {
        "role": "system",
        "content": '{"camera_id": "c1"}',
    }
