"""Compact workbench contracts; browser fixtures are explicitly synthetic."""
import io
import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import pytest

from scam.server import _INDEX_HTML


def test_core_and_optional_disclosures():
    from html.parser import HTMLParser

    class Panels(HTMLParser):
        def __init__(self):
            super().__init__()
            self.panels = {}

        def handle_starttag(self, tag, attrs):
            values = dict(attrs)
            if tag == "details":
                self.panels[values.get("id")] = values

    panels = Panels()
    panels.feed(_INDEX_HTML)
    for key in ("zone-settings", "baseline-settings", "advanced-panel"):
        assert key in panels.panels
        assert "open" not in panels.panels[key]
    assert 'id="live-card"' in _INDEX_HTML
    assert 'id="observation-card"' in _INDEX_HTML
    assert 'id="zone-grid" aria-label="区域网格" hidden' in _INDEX_HTML


def test_neutral_style_and_accessibility():
    assert "radial-gradient" not in _INDEX_HTML
    assert "backdrop-filter" not in _INDEX_HTML
    assert "prefers-color-scheme:dark" in _INDEX_HTML
    assert "prefers-reduced-motion:reduce" in _INDEX_HTML
    assert ":focus-visible" in _INDEX_HTML
    assert 'class="table-scroll" role="region"' in _INDEX_HTML
    assert "function zoneEditing()" in _INDEX_HTML
    assert "if(!zoneEditing())return" in _INDEX_HTML
    assert "EXPANDED_SOURCES_CAP=128" in _INDEX_HTML
    assert "gateSkippedWrite" in _INDEX_HTML


def test_existing_page_script_harness(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node unavailable for existing page-script harness")
    script = _INDEX_HTML.split("<script>", 1)[1].split("</script>", 1)[0]
    page_script = tmp_path / "page.js"
    page_script.write_text(script, encoding="utf-8")
    syntax = subprocess.run([node, "--check", str(page_script)], capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr
    harness = Path(__file__).with_name("c144r1_page_dom.js")
    result = subprocess.run([node, str(harness), str(page_script)], capture_output=True,
                            text=True, encoding="utf-8", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def synthetic_page(page):
    """Serve actual page/script against routed fixtures, with no network access."""
    from PIL import Image, ImageDraw

    image = Image.new("RGB", (640, 360), "#ddd")
    draw = ImageDraw.Draw(image)
    draw.rectangle((85, 40, 270, 325), fill="#aaa", outline="#555", width=2)
    draw.rectangle((370, 180, 535, 310), fill="#b7b7b7", outline="#666", width=2)
    draw.text((16, 14), "SYNTHETIC CAMERA - UI TEST ONLY", fill="#333")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    state = {"connection": "online", "summary": "发现变化，正在分析", "frame": True}
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))

    def route(request):
        path = urlparse(request.request.url).path
        if path == "/":
            request.fulfill(content_type="text/html", body=_INDEX_HTML)
            return
        if path.startswith("/api/frame/"):
            request.fulfill(status=200 if state["frame"] else 503,
                            content_type="image/png", body=buffer.getvalue())
            return
        payload = {}
        if path == "/api/cameras":
            payload = {"cameras": [{"id": "camera-demo"}]}
        elif path.startswith("/api/zones/"):
            payload = {"grid": {"rows": 4, "cols": 6}, "zones": [], "runtime": "active"}
        elif path.endswith("/baselines"):
            payload = {"baselines": []}
        elif path.startswith("/api/environment/"):
            payload = {"baseline": {"state": "baseline_required", "reason": "no_pointer"}}
        elif path == "/api/health":
            payload = {"runtime": {"cameras": [{"camera": "camera-demo",
                        "state": state["connection"], "hint": "在线" if state["connection"] == "online" else "断线：检查相机连接"}]},
                       "understanding": {"camera-demo": {"summary": state["summary"], "branches": []}}}
        elif path == "/api/v2/events":
            payload = {"events": [{"event_id": "demo-event", "t_start": 1791900000,
                        "camera": "camera-demo", "cls": "对象", "state": "open",
                        "initial_fact_text": "画面发生变化，正在分析", "escalation_count": 0}]}
        elif path == "/api/v2/notifications":
            payload = {"notifications": []}
        request.fulfill(content_type="application/json", body=json.dumps(payload, ensure_ascii=False))

    page.route("**/*", route)
    page.goto("http://workbench.test/")
    page.wait_for_function("document.querySelector('#zone-frame').naturalWidth === 640")
    page.wait_for_function("document.querySelector('#event-timeline tbody').rows.length === 1")
    page.evaluate("refreshHealth()")
    return state, errors


@pytest.fixture(scope="module")
def browser():
    sync = pytest.importorskip("playwright.sync_api")
    with sync.sync_playwright() as playwright:
        candidates = list((Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright").glob("chromium-*/chrome-win64/chrome.exe"))
        options = {"executable_path": str(sorted(candidates)[-1])} if candidates else {}
        installed_chrome = Path(os.environ.get("PROGRAMFILES", "")) / "Google/Chrome/Application/chrome.exe"
        if not candidates and installed_chrome.is_file():
            options = {"executable_path": str(installed_chrome)}
        try:
            instance = playwright.chromium.launch(headless=True, **options)
        except sync.Error as error:
            pytest.skip(f"Installed Chromium unavailable: {error}")
        yield instance
        instance.close()


def capture(page, name):
    directory = os.environ.get("C148_ARTIFACT_DIR")
    if directory:
        destination = Path(directory)
        destination.mkdir(parents=True, exist_ok=True)
        page.evaluate("""() => { if(!document.querySelector('#synthetic-label')) {
          const p=document.createElement('p'); p.id='synthetic-label';
          p.textContent='合成界面验收 · 非真实摄像头/模型';
          p.style.cssText='font-size:12px;color:#777;margin:0 0 8px';
          document.body.prepend(p); }}""")
        page.screenshot(path=str(destination / name), full_page=True)


def test_browser_editing_keyboard_and_poll_preservation(browser):
    page = browser.new_page(viewport={"width": 1440, "height": 900}, color_scheme="light")
    try:
        state, errors = synthetic_page(page)
        assert not page.locator("#zone-grid").is_visible()
        assert not page.locator("#save-zone").is_visible()
        assert not page.locator("#grid-summary").is_visible()
        assert page.locator("#frame-stage").is_visible()
        assert page.locator("#camera-status").is_visible()
        live = page.locator("#live-card").bounding_box()
        records = page.locator("#observation-card").bounding_box()
        assert live and records and records["y"] >= live["y"] + live["height"]
        assert records["width"] >= 1300
        cells = page.locator("#event-timeline tbody tr").first.locator("td")
        assert "画面发生变化" in cells.nth(4).inner_text()
        assert "暂无可回看画面" in cells.nth(5).inner_text()
        assert "打开详情" in cells.nth(7).inner_text()
        assert cells.nth(1).evaluate("node => getComputedStyle(node).whiteSpace") == "nowrap"
        assert cells.nth(4).bounding_box()["width"] >= 260
        assert "持续观察不受影响" in page.locator("#gate-message").inner_text()
        assert page.locator('.workbench-nav svg[aria-hidden="true"]').count() == 4
        assert page.get_by_role("link", name="区域配置", exact=True).count() == 1
        capture(page, "desktop-light.png")
        page.locator("#open-zone-settings").focus()
        page.keyboard.press("Enter")
        assert page.locator("#zone-grid").is_visible()
        assert page.locator("#grid-summary").is_visible()
        assert page.get_by_role("button", name="新建区域", exact=True).count() == 1
        capture(page, "desktop-settings.png")
        page.locator(".grid-cell").first.click()
        assert page.locator(".grid-cell.selected").count() == 1
        page.evaluate("async () => {await refreshHealth(); await refreshTimeline();}")
        assert page.locator("#zone-settings").evaluate("node => node.open")
        assert page.locator(".grid-cell.selected").count() == 1
        page.locator("#zone-settings > summary").click()
        assert not page.locator("#zone-grid").is_visible()
        page.evaluate("paintCell(1,true)")
        assert page.locator(".grid-cell.selected").count() == 1
        state["connection"] = "degraded"
        state["summary"] = "分析失败：模型不可用；当前观察仍继续"
        page.evaluate("refreshHealth()")
        assert "断线" in page.locator("#camera-status").inner_text()
        assert "分析失败" in page.locator("#understanding-line").inner_text()
        capture(page, "desktop-degraded.png")
        assert errors == []
    finally:
        page.close()


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_browser_narrow_screen_no_document_overflow(browser, scheme):
    page = browser.new_page(viewport={"width": 390, "height": 844}, color_scheme=scheme)
    try:
        state, errors = synthetic_page(page)
        state["summary"] = "正在分析 · " + "long-identity-without-whitespace-" * 25
        page.evaluate("refreshHealth()")
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert page.locator("#understanding-line").evaluate("node => node.clientHeight <= 130 && node.scrollHeight > node.clientHeight")
        assert not page.locator("#save-zone").is_visible()
        assert page.locator(".table-scroll").evaluate("node => node.scrollWidth > node.clientWidth")
        page.locator("#gate-dismiss").click()
        page.evaluate("loadEnvironment()")
        assert not page.locator("#environment-gate").is_visible()
        capture(page, f"mobile-{scheme}.png")
        assert errors == []
    finally:
        page.close()
