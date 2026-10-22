"""C150 actual page/script, routed synthetic fixtures; no camera/model/service."""
import io
import json
import os
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest
from scam.server import _INDEX_HTML
from test_server_c148_compact import browser


def fixture_page(page):
    from PIL import Image, ImageDraw
    picture = Image.new("RGB", (640, 360), "#dddddd")
    draw = ImageDraw.Draw(picture)
    draw.text((18, 18), "SYNTHETIC UI FIXTURE - NOT A REAL CAMERA", fill="#333333")
    draw.rectangle((120, 60, 210, 300), fill="#999999")
    draw.rectangle((310, 190, 430, 300), fill="#bbbbbb")
    buffer = io.BytesIO()
    picture.save(buffer, format="PNG")
    def event(key, number):
        return {"event_id": key, "camera": "camera-demo", "cls": "person",
                "t_start": 1791923400 + number, "state": "open",
                "initial_fact_text": "系统记录：画面中出现 person",
                "best_frame": {"content_url": "/api/evidence/synthetic-image"} if key == "a" else None,
                "escalation_count": 0}
    state = {"events": [event(k, i) for i, k in enumerate("abcd")],
             "details": {}, "detail_requests": [], "list_failed": False,
             "detail_failed": False, "connection": "online",
             "understanding_capability": None}
    for i, key in enumerate("abcd"):
        state["details"][key] = dict(event(key, i), descriptions=[
            {"version": 1, "source": "initial_observation", "text": "原始事实版本一",
             "t_created": 1791923400, "uncertainty": "confirmed", "evidence_refs": []}],
            notifications=[], semantic={"state": ["published", "running", "failed_terminal", "no_evidence"][i]})
    state["details"]["a"]["descriptions"].append({"version": 2, "source": "vlm",
        "text": "合成理解：一人将物品放在门边。", "t_created": 1791923450,
        "uncertainty": "low", "evidence_refs": ["synthetic-image"]})
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    # Deterministically drive real polling functions without timer races.
    page.add_init_script("window.setInterval = () => 0;")
    def route(request):
        path = unquote(urlparse(request.request.url).path)
        if path == "/":
            request.fulfill(content_type="text/html", body=_INDEX_HTML)
            return
        if path.startswith(("/api/frame/", "/api/evidence/")):
            request.fulfill(content_type="image/png", body=buffer.getvalue())
            return
        payload, status = {}, 200
        if path == "/api/cameras":
            payload = {"cameras": [{"id": "camera-demo"}]}
        elif path.startswith("/api/zones/"):
            payload = {"grid": {"rows": 4, "cols": 6}, "zones": [], "runtime": "active"}
        elif path.endswith("/baselines"):
            payload = {"baselines": []}
        elif path.startswith("/api/environment/"):
            payload = {"baseline": {"state": "baseline_required", "reason": "no_pointer"}}
        elif path == "/api/health":
            payload = {"runtime": {"cameras": [{"camera": "camera-demo", "state": state["connection"],
                "hint": "连接已断开，现场暂不可用" if state["connection"] == "degraded" else "在线；合成验收"}]}}
            if state["understanding_capability"] is not None:
                payload["understanding_capability"] = state["understanding_capability"]
        elif path == "/api/v2/events":
            payload, status = {"events": state["events"]}, 503 if state["list_failed"] else 200
        elif path.startswith("/api/v2/events/"):
            key = path.rsplit("/", 1)[1]
            state["detail_requests"].append(key)
            payload = state["details"].get(key, {})
            status = 503 if state["detail_failed"] else 200
        elif path == "/api/v2/notifications":
            payload = {"notifications": []}
        elif path == "/api/review":
            payload = {"segments": []}
        elif path == "/api/events":
            payload = {"events": []}
        elif path == "/api/patterns":
            payload = {"patterns": []}
        request.fulfill(status=status, content_type="application/json",
                        body=json.dumps(payload, ensure_ascii=False))
    page.route("**/*", route)
    page.goto("http://workbench.test/")
    page.wait_for_function("!timelineRefreshing && timelineRows.size === 4")
    page.evaluate("refreshTimeline()")  # Load next two summaries, same bounded path.
    page.evaluate("() => {const p=document.createElement('p');p.textContent='合成界面验收 · 非真实摄像头 / 模型';p.id='synthetic-label';document.body.prepend(p)}")
    return state, errors, event


def screenshot(page, name):
    directory = os.environ.get("C150_ARTIFACT_DIR")
    if directory:
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(target / name), full_page=True)


def test_actual_latest_summary_states_and_bounded_requests(browser):
    page = browser.new_page(viewport={"width": 1440, "height": 900}, color_scheme="light")
    try:
        state, errors, _ = fixture_page(page)
        assert len(state["detail_requests"]) == 4
        assert "一人将物品" in page.locator('[data-event-id="a"] .record-summary').inner_text()
        assert "可能有误" in page.locator('[data-event-id="a"] .record-summary-note').inner_text()
        assert "分析中" in page.locator('[data-event-id="b"] .record-summary-note').inner_text()
        assert "理解失败" in page.locator('[data-event-id="c"] .record-summary-note').inner_text()
        assert "缺少可用证据" in page.locator('[data-event-id="d"] .record-summary-note').inner_text()
        assert page.get_by_role("link", name="打开记录原图 a").count() == 1
        page.evaluate("refreshTimeline()")
        assert len(state["detail_requests"]) == 4  # No N+1 request burst on every poll.
        assert errors == []
        screenshot(page, "desktop-summary-states.png")
    finally:
        page.close()


def test_focus_history_and_new_records_do_not_interrupt_reader(browser):
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    try:
        state, errors, event = fixture_page(page)
        link = page.get_by_role("link", name="打开记录详情 a", exact=True)
        link.focus()
        page.evaluate("window.readerFocus = document.activeElement")
        for _ in range(3):
            page.evaluate("refreshTimeline()")
        assert page.evaluate("document.activeElement === window.readerFocus")
        page.keyboard.press("Enter")
        page.wait_for_function("document.querySelector('#event-detail-title').textContent.includes('camera-demo')")
        history = page.locator(".description-history")
        assert not history.evaluate("node => node.open")
        assert "一人将物品" in page.locator("#event-detail-body > .desc-version").first.inner_text()
        history.locator("summary").click()
        assert "原始事实版本一" in history.inner_text()
        # Preserve the reader's viewport anchor, not an absolute document
        # offset: a new notice above the table can legitimately add height.
        before = history.locator("summary").bounding_box()["y"]
        state["events"].insert(0, event("new-one", 100))
        state["details"]["new-one"] = dict(state["events"][0], descriptions=[], semantic={"state": "none"})
        page.evaluate("refreshTimeline()")
        assert page.locator("[data-event-id='new-one']").count() == 0
        assert page.locator("#timeline-latest").is_visible()
        assert history.evaluate("node => node.open")
        assert abs(history.locator("summary").bounding_box()["y"] - before) < 2
        screenshot(page, "desktop-reading-new-records.png")
        page.locator("#close-event-detail").click()
        assert page.get_by_role("link", name="打开记录详情 a", exact=True).evaluate("node => node === document.activeElement")
        page.locator("#timeline-latest").click()
        assert page.locator("[data-event-id='new-one']").count() == 1
        assert errors == []
    finally:
        page.close()


def test_failure_stale_summary_offline_and_empty_are_honest(browser):
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    try:
        state, errors, _ = fixture_page(page)
        state["events"] = state["events"][:1]
        state["detail_failed"] = True
        page.evaluate("detailSummaryCache.get('a').at = 0")
        page.evaluate("refreshTimeline()")
        assert "非最新" in page.locator('[data-event-id="a"] .record-summary-note').inner_text()
        assert "一人将物品" in page.locator('[data-event-id="a"] .record-summary').inner_text()
        state["list_failed"] = True
        state["connection"] = "degraded"
        page.evaluate("async () => {await refreshHealth();await refreshTimeline()}")
        assert "连接中断" in page.locator("#timeline-status").inner_text()
        assert "连接已断开" in page.locator("#camera-status").inner_text()
        screenshot(page, "desktop-offline-stale.png")
        state["list_failed"] = False
        state["events"] = []
        page.evaluate("refreshTimeline()")
        assert "暂无观察记录" in page.locator("#event-timeline tbody").inner_text()
        assert errors == []
    finally:
        page.close()


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_narrow_long_text_and_wrong_identity_never_borrow_summary(browser, scheme):
    page = browser.new_page(viewport={"width": 390, "height": 844}, color_scheme=scheme)
    try:
        state, errors, _ = fixture_page(page)
        state["events"] = state["events"][:1]
        state["details"]["a"]["descriptions"][-1]["text"] = "<script>not executed</script>" + "long-identity-" * 70
        page.evaluate("detailSummaryCache.get('a').at = 0")
        page.evaluate("refreshTimeline()")
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert "<script>not executed" in page.locator('[data-event-id="a"] .record-summary').inner_text()
        assert page.locator(".table-scroll").first.evaluate("node=>node.scrollWidth>node.clientWidth")
        screenshot(page, f"mobile-{scheme}-long-summary.png")
        state["details"]["a"]["event_id"] = "other-event"
        state["details"]["a"]["descriptions"][-1]["text"] = "外来事件叙事不能显示"
        page.evaluate("detailSummaryCache.delete('a')")
        page.evaluate("refreshTimeline()")
        assert "外来事件叙事" not in page.locator("#event-timeline tbody").inner_text()
        assert "摘要读取失败" in page.locator('[data-event-id="a"] .record-summary-note').inner_text()
        assert errors == []
    finally:
        page.close()


def test_summary_cache_bound_and_one_poll_never_fans_out(browser):
    page = browser.new_page()
    try:
        state, errors, event = fixture_page(page)
        state["events"] = [event("row-" + str(i), i) for i in range(30)]
        for row in state["events"]:
            state["details"][row["event_id"]] = dict(row, descriptions=[], semantic={"state": "none"})
        before = len(state["detail_requests"])
        page.evaluate("refreshTimeline()")
        assert len(state["detail_requests"]) - before == 2
        page.evaluate("() => {for(let i=0;i<100;i++)rememberSummary('synthetic-'+i,{at:Date.now(),detail:null})}")
        assert page.evaluate("detailSummaryCache.size") == 64
        assert errors == []
    finally:
        page.close()


def test_capability_disable_repaints_existing_rows_immediately(browser):
    page = browser.new_page()
    try:
        state, errors, _ = fixture_page(page)
        state["understanding_capability"] = {"configured": False}
        page.evaluate("refreshHealth()")
        note = page.locator(
            '[data-event-id="b"] .record-summary-note').inner_text()
        assert "图片理解未启用" in note
        assert "分析中" not in note
        assert errors == []
    finally:
        page.close()


def test_capability_unknown_clears_stale_disabled_note_immediately(browser):
    page = browser.new_page()
    try:
        state, errors, _ = fixture_page(page)
        state["understanding_capability"] = {"configured": False}
        page.evaluate("refreshHealth()")
        assert "图片理解未启用" in page.locator(
            '[data-event-id="b"] .record-summary-note').inner_text()

        state["understanding_capability"] = None
        page.evaluate("refreshHealth()")
        note = page.locator(
            '[data-event-id="b"] .record-summary-note').inner_text()
        assert "图片理解未启用" not in note
        assert "分析中" in note
        assert errors == []
    finally:
        page.close()
