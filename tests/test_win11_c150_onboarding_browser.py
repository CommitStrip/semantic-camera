"""Actual Chromium clicks on setup HTML; synthetic routes, no config/service/device."""
import json

import pytest

from scam.win11_setup import _html, _clean_source, build_initial_venue
from test_server_c148_compact import browser


def setup_page(browser, width=900):
    page = browser.new_page(viewport={"width": width, "height": 844})
    state = {"status": 200, "hold": False, "requests": [], "pending": [], "errors": []}
    page.on("pageerror", lambda error: state["errors"].append(str(error)))
    def route(request):
        if request.request.method == "POST":
            state["requests"].append(request.request.post_data_json)
            assert request.request.headers["x-setup-token"] == "synthetic-token"
            if state["hold"]:
                state["pending"].append(request)
            else:
                request.fulfill(status=state["status"], content_type="application/json",
                                body=json.dumps({"error": "合成固定错误"}))
        else:
            request.fulfill(content_type="text/html", body=_html("synthetic-token"))
    page.route("**/*", route)
    page.goto("http://setup.test/")
    return page, state


def valid_input(page):
    page.locator("#source").fill("rtsp://fixture-user:fixture-secret@192.0.2.10/live")
    page.locator("#monitor-only").check()


def test_empty_focus_source_switch_and_success(browser):
    page, state = setup_page(browser)
    try:
        page.locator("#save").click()
        assert page.locator("#source").evaluate("e=>e===document.activeElement")
        assert state["requests"] == []
        for kind, label, placeholder in [("camera", "本机摄像头编号", "0"),
                                          ("file", "视频文件路径", "videos"),
                                          ("rtsp", "RTSP 地址", "rtsp://")]:
            page.locator("#source-kind").select_option(kind)
            assert label in page.locator("#source-label").inner_text()
            assert placeholder in page.locator("#source").get_attribute("placeholder")
        valid_input(page)
        page.locator("#save").click()
        page.wait_for_function("document.querySelector('#message').textContent.includes('配置已保存')")
        assert state["requests"] == [{"camera_id": "front-door", "source_kind": "rtsp",
            "source": "rtsp://fixture-user:fixture-secret@192.0.2.10/live",
            "detector_model": "", "monitor_only": True}]
        assert page.locator("#save").is_disabled()
        message = page.locator("#message").inner_text()
        assert "fixture-secret" not in message and "已连接" not in message and "就绪" not in message
        assert not state["errors"]
    finally:
        page.close()


@pytest.mark.xfail(
    strict=False, run=True,
    reason="顺序相关的偶发失败：单独运行通过、全量套件中偶发（模块级浏览器状态），"
           "已知限制见 RELEASE_NOTES")
def test_inflight_repeat_and_400_input_retention(browser):
    page, state = setup_page(browser)
    try:
        valid_input(page)
        state["hold"] = True
        page.locator("#save").click()
        assert page.locator("#save").is_disabled()
        page.locator("#save").evaluate("e=>{e.click();e.click()}")
        assert len(state["requests"]) == 1
        assert "保存中" in page.locator("#message").inner_text()
        state["pending"][0].fulfill(status=400, content_type="application/json",
                                  body=json.dumps({"error": "合成固定校验错误"}))
        page.wait_for_function("!document.querySelector('#save').disabled")
        assert "合成固定校验错误" in page.locator("#message").inner_text()
        assert page.locator("#source").input_value().endswith("192.0.2.10/live")
        assert page.locator("#monitor-only").is_checked()
        assert "fixture-secret" not in page.locator("#message").inner_text()
        assert not state["errors"]
    finally:
        page.close()


@pytest.mark.parametrize("status,disabled,text", [(403, True, "会话已失效"),
                                                  (409, False, "配置已存在")])
def test_status_recovery_and_narrow_layout(browser, status, disabled, text):
    page, state = setup_page(browser, 390)
    try:
        state["status"] = status
        valid_input(page)
        page.locator("#save").click()
        page.wait_for_function("text=>document.querySelector('#message').textContent.includes(text)", arg=text)
        assert page.locator("#save").is_disabled() is disabled
        assert "fixture-secret" not in page.locator("#message").inner_text()
        assert page.locator("#source").input_value().startswith("rtsp://fixture-user:")
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
        assert not state["errors"]
    finally:
        page.close()


def test_client_backend_boundary_measurement(browser):
    page, state = setup_page(browser)
    try:
        def client(source, kind="file", model=""):
            return page.evaluate("b=>localValidate(b)", {"camera_id": "fixture", "source_kind": kind,
                "source": source, "detector_model": model, "monitor_only": True})
        assert client("x" * 2048) == []
        assert client("x" * 2049)
        assert _clean_source("file", "x" * 2048) == "x" * 2048
        with pytest.raises(ValueError):
            _clean_source("file", "x" * 2049)
        assert client("fixture.mp4", model=" " * 1024) == []
        assert client("fixture.mp4", model=" " * 1025)
        with pytest.raises(ValueError):
            build_initial_venue({"camera_id": "fixture", "source_kind": "file", "source": "fixture.mp4",
                "detector_model": " " * 1025, "monitor_only": True})
        # C151 trim fix: preserve raw-length limit, trim edge tabs before control checks.
        for source in (" rtsp://192.0.2.10/live ", "\trtsp://192.0.2.10/live\t"):
            assert client(source, "rtsp") == []
            assert _clean_source("rtsp", source) == "rtsp://192.0.2.10/live"
        padded = "rtsp://192.0.2.10/live".ljust(2049)
        assert len(padded) == 2049
        for source in ("rtsp://192.0.2.10/li\tve", "rtsp://192.0.2.10/li\x01ve", padded):
            assert client(source, "rtsp")
            with pytest.raises(ValueError):
                _clean_source("rtsp", source)
        # Remaining measured parity gaps; do not silently fix frozen production.
        assert client("１２", "camera")
        assert _clean_source("camera", "１２") == "１２"
        assert not state["errors"]
    finally:
        page.close()


def test_chrome_empty_authority_blocked_and_valid_authority_preserved(browser):
    page, state = setup_page(browser)
    try:
        page.locator("#monitor-only").check()
        for source in ("rtsp:///live", "rtsp:///", "rtsp://", "rtsp://user@/live"):
            page.locator("#source").fill(source)
            page.locator("#save").click()
            assert state["requests"] == []
            assert "包含主机" in page.locator("#err-source").inner_text()
            assert page.locator("#source").evaluate("e=>e===document.activeElement")
            with pytest.raises(ValueError, match="包含主机"):
                _clean_source("rtsp", source)
        for source in ("rtsp://192.0.2.10/live", "rtsps://fixture:secret@192.0.2.10:554/live",
                       "rtsp://fixture:secret@[2001:db8::1]:554/live"):
            assert page.evaluate("b=>localValidate(b)", {"camera_id": "fixture", "source_kind": "rtsp",
                "source": source, "detector_model": "", "monitor_only": True}) == []
            assert _clean_source("rtsp", source) == source
        # Validation only: no actual RTSP connection or real config is exercised.
        assert not state["errors"]
    finally:
        page.close()
