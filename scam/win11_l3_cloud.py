"""C190 OpenAI-compatible cloud backend for ordered L3 frame tasks.

This module is independent of the local transformers path.  Network access is
disabled unless the caller passes explicit ``consent=True``.  The transport is
injectable so contracts run without contacting an external API.
"""

from __future__ import annotations

import concurrent.futures
import json
import math
import os
import sys
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, HTTPRedirectHandler, build_opener
from urllib.parse import urlsplit

from scam.models import validate_base
from scam.win11_l3_backend import LocalTransformersL3Backend


class CloudConsentRequired(ValueError):
    pass


class CloudConfigurationError(ValueError):
    pass


class CloudKeyMissing(RuntimeError):
    pass


class CloudTransportError(RuntimeError):
    pass


class CloudTimeoutError(RuntimeError):
    pass


class CloudHTTPError(RuntimeError):
    def __init__(self, status: int):
        self.status = int(status)
        kind = {
            429: "cloud_rate_limited",
        }.get(self.status, "cloud_server_error" if self.status >= 500
              else "cloud_bad_response")
        self.code = kind
        super().__init__(f"{kind}:{self.status}")


class CloudBadResponse(RuntimeError):
    pass


class CloudResponseTooLarge(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CloudOpenAICompatibleL3Provider:
    """Strict OpenAI-compatible transport preserving ordered L3 input."""

    name = "cloud"
    model_id = None
    dtype = None
    precision_mode = None
    attention_implementation = None
    vision_chunk_size = None

    def __init__(self, *, base_url: str, model: str, key_env: str,
                 consent: bool = False, transport=None, request_timeout_s: float = 60.0,
                 max_tokens: int = 200, max_frames: int = 3,
                 jpeg_budget_bytes_per_frame: Optional[int] = None,
                 max_response_bytes: int = 16 * 1024 * 1024) -> None:
        if consent is not True:
            raise ValueError(
                "cloud_consent_required: cloud inference is disabled unless "
                "consent is explicitly True")
        if not isinstance(model, str) or not model.strip():
            raise ValueError("cloud_model_required")
        if not isinstance(key_env, str) or not key_env.strip():
            raise ValueError("cloud_key_env_required")
        parsed = urlsplit(base_url)
        if parsed.scheme != "https":
            raise ValueError("cloud_base_url_requires_https")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("cloud_base_url_userinfo_forbidden")
        if parsed.query or parsed.fragment:
            raise ValueError("cloud_base_url_query_and_fragment_forbidden")
        validate_base(base_url, allow_local=False, allow_public=True)
        if type(max_tokens) is not int or max_tokens <= 0:
            raise ValueError("cloud_max_tokens_must_be_positive_integer")
        if type(max_frames) is not int or max_frames <= 0:
            raise ValueError("cloud_max_frames_must_be_positive_integer")
        if request_timeout_s is not None and (isinstance(request_timeout_s, bool)
                or not isinstance(request_timeout_s, (int, float))
                or not math.isfinite(request_timeout_s)
                or request_timeout_s <= 0):
            raise ValueError("cloud_request_timeout_must_be_positive")
        if jpeg_budget_bytes_per_frame is not None and (
                type(jpeg_budget_bytes_per_frame) is not int
                or jpeg_budget_bytes_per_frame <= 0):
            raise ValueError("cloud_jpeg_budget_must_be_positive_integer")
        if (type(max_response_bytes) is not int or max_response_bytes <= 0
                or max_response_bytes > 64 * 1024 * 1024):
            raise ValueError("cloud_max_response_bytes_invalid")

        self.base_url = base_url.rstrip("/")
        self.model = model
        self.model_id = model
        self.key_env = key_env
        self.consent = True
        self.transport = transport
        self.request_timeout_s = (float(request_timeout_s)
                                  if request_timeout_s is not None else None)
        self.max_tokens = max_tokens
        self.max_frames = max_frames
        self.jpeg_budget_bytes_per_frame = jpeg_budget_bytes_per_frame
        self.max_response_bytes = max_response_bytes

    def _key(self) -> str:
        key = os.environ.get(self.key_env)
        if not isinstance(key, str) or not key.strip():
            raise CloudKeyMissing(
                f"cloud_key_missing:{self.key_env}")
        if "\r" in key or "\n" in key:
            raise CloudKeyMissing("cloud_key_invalid_control_characters")
        return key

    @staticmethod
    def _frame_meta_text(position: int, meta: Dict[str, Any],
                         present: bool) -> str:
        marker = f"FRAME {position} MISSING" if not present else (
            f"FRAME {position} PRESENT")
        encoded = json.dumps(meta, ensure_ascii=False, sort_keys=True)
        return f"{marker}\nMETA {encoded}"

    def _content(self, prompt: str, frames_b64, frames_meta):
        frames = list(frames_b64 or [])
        meta = list(frames_meta or [])
        if len(meta) != len(frames):
            raise CloudBadResponse(
                "cloud_frame_metadata_length_mismatch:"
                f"{len(meta)}!={len(frames)}")
        if len(frames) > self.max_frames:
            raise ValueError(
                f"cloud_frame_budget_exceeded:{len(frames)}>{self.max_frames}")
        content = [{"type": "text", "text": prompt}]
        for position, frame in enumerate(frames):
            frame_meta = meta[position]
            if not isinstance(frame_meta, dict):
                raise CloudBadResponse("cloud_frame_metadata_must_be_object")
            declared_position = frame_meta.get("position")
            if (declared_position is not None
                    and (type(declared_position) is not int
                         or declared_position != position)):
                raise CloudBadResponse(
                    "cloud_frame_position_mismatch:"
                    f"{declared_position}!={position}")
            meta_text = self._frame_meta_text(position, frame_meta,
                                             frame is not None)
            content.append({"type": "text", "text": meta_text})
            if frame is None:
                continue
            if not isinstance(frame, str):
                raise CloudBadResponse("cloud_frame_must_be_base64_string")
            if self.jpeg_budget_bytes_per_frame is not None:
                approximate_jpeg_bytes = len(frame) * 3 // 4
                if approximate_jpeg_bytes > self.jpeg_budget_bytes_per_frame:
                    raise ValueError(
                        "cloud_jpeg_budget_exceeded:"
                        f"{position}:{approximate_jpeg_bytes}")
            content.append({
                "type": "image_url",
                "image_url": {"url": "data:image/jpeg;base64," + frame},
            })
        return content

    def _transport_call(self, request: Request, timeout: Optional[float]):
        if self.transport is not None:
            return self.transport(request, timeout)
        opener = build_opener(_NoRedirect)
        return opener.open(request, timeout=timeout)

    def _post_chat(self, body: Dict[str, Any]):
        key = self._key()
        request = Request(
            self.base_url + "/chat/completions",
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {key}",
            },
            method="POST")
        response = None
        try:
            try:
                response = self._transport_call(request, self.request_timeout_s)
            except HTTPError as exc:
                raise CloudHTTPError(exc.code) from None
            except TimeoutError as exc:
                raise CloudTimeoutError("cloud_request_timeout") from None
            except (URLError, OSError) as exc:
                raise CloudTransportError(
                    f"cloud_transport_failed:{type(exc).__name__}") from None
            except Exception as exc:
                # Do not echo custom transport messages, URLs, headers, or bodies.
                raise CloudTransportError(
                    f"cloud_transport_failed:{type(exc).__name__}") from None
            try:
                raw = response.read(self.max_response_bytes + 1)
            except Exception as exc:
                raise CloudTransportError(
                    f"cloud_response_read_failed:{type(exc).__name__}") from None
            if len(raw) > self.max_response_bytes:
                raise CloudResponseTooLarge(
                    f"cloud_response_too_large:{self.max_response_bytes}")
            try:
                payload = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError:
                raise CloudBadResponse("cloud_response_utf8") from None
            except json.JSONDecodeError:
                raise CloudBadResponse("cloud_response_json") from None
            if not isinstance(payload, dict):
                raise CloudBadResponse("cloud_response_not_object")
            choices = payload.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(
                    choices[0], dict):
                raise CloudBadResponse("cloud_response_choices")
            message = choices[0].get("message")
            if not isinstance(message, dict) or not isinstance(
                    message.get("content"), str):
                raise CloudBadResponse("cloud_response_message_content")
            return message["content"]
        finally:
            if response is not None:
                had_response_error = sys.exc_info()[0] is not None
                try:
                    close = getattr(response, "close", None)
                    if callable(close):
                        close()
                except Exception as exc:
                    # A close failure must never hide the original response error.
                    if not had_response_error:
                        raise CloudTransportError(
                            f"cloud_response_close_failed:{type(exc).__name__}"
                        ) from None

    def understand_frames(self, prompt, frames_b64, frames_meta=None):
        if not isinstance(prompt, str):
            raise CloudBadResponse("cloud_prompt_must_be_string")
        body = {
            "model": self.model,
            "stream": False,
            "temperature": 0,
            "max_tokens": self.max_tokens,
            "messages": [{
                "role": "user",
                "content": self._content(prompt, frames_b64, frames_meta),
            }],
        }
        content = self._post_chat(body)
        try:
            value = json.loads(content)
        except json.JSONDecodeError:
            return {"text": content}
        if not isinstance(value, dict):
            return {"text": content}
        return value


class CloudOpenAICompatibleL3Backend(LocalTransformersL3Backend):
    """Existing bounded L3 lifecycle adapted to an explicit cloud provider."""

    def __init__(self, *, base_url: str, model: str, key_env: str,
                 consent: bool, transport=None,
                 timeout_s: float = 180.0,
                 infer_timeout_s: float = 120.0,
                 load_timeout_s: float = 60.0,
                 request_timeout_s: float = 60.0,
                 max_tokens: int = 200,
                 max_frames: int = 3,
                 jpeg_budget_bytes_per_frame: Optional[int] = None,
                 max_response_bytes: int = 16 * 1024 * 1024) -> None:
        provider = CloudOpenAICompatibleL3Provider(
            base_url=base_url, model=model, key_env=key_env, consent=consent,
            transport=transport, request_timeout_s=request_timeout_s,
            max_tokens=max_tokens, max_frames=max_frames,
            jpeg_budget_bytes_per_frame=jpeg_budget_bytes_per_frame,
            max_response_bytes=max_response_bytes)
        super().__init__(
            provider=provider, timeout_s=timeout_s,
            infer_timeout_s=infer_timeout_s, load_timeout_s=load_timeout_s)
        self.model_ref = f"cloud/{model}"
        self.backend = "cloud-openai-compatible"
        self.dtype = None
        self.precision_mode = None
        self.attention_implementation = None
        self.vision_chunk_size = None

    def snapshot(self) -> Dict[str, Any]:
        snapshot = super().snapshot()
        snapshot.update({
            "model_ref": self.model_ref,
            "backend": self.backend,
            "dtype": None,
            "precision_mode": None,
            "attention_implementation": None,
            "vision_chunk_size": None,
            "last_call_dtypes": None,
            "last_call_execution": None,
        })
        return snapshot
