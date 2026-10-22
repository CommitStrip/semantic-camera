"""C-139-R2 工作台浏览器级测试（子代理 D · 用户追溯）。

真实 HTTP 服务（ThreadingHTTPServer + WorkbenchHandler，仅绑 127.0.0.1
临时端口）+ 真实 Chromium（Playwright）加载工作台页面，验证：

- D1 当前/历史分列：当前区只渲染 is_current===true 的分支行（身份来自
  runtime 注册表权威值），历史区显示旧 run/config 条目并带身份短码；
- 安全文本：模型输出含 ``<script>``/``<img>`` 片段时按 textContent 纯文本
  渲染——不执行、不进标签（dialog 监听兜底）；
- D2 来源透传：分支行常显 crop_id/模型短码/帧时间；点击「来源 ▸」展开
  sources（帧序位/帧 id/帧时间/时间类型）；融合版本条目显示 frame_refs
  （frame_id/时间/坐标体系）；
- D3 证据诚实：有磁盘证据（受控索引在场）→「打开原始裁图」链接且链接
  目标真实可取（HTTP 200 + image/jpeg）；未持久化裁图 →「原始裁图尚未
  保存」，绝不给失效链接。

依赖缺失 → skip 并如实命名（playwright 未安装 / chromium 浏览器不可用）。
主会话原生执行：``python -m pytest tests/test_win11_browser_c139r2.py -q``
"""

import hashlib
import json
import threading
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from scam.db import connect, init_schema
from scam.server import WorkbenchHandler, WorkbenchState
from scam.win11_understanding_store import UnderstandingStore

CAMERA = "front"
CURRENT_RUN = ("run-2", "v3")
EVIDENCE_CROP = "crop-evidence-1"
MISSING_CROP = "crop-not-persisted"

# 模型输出里的恶意片段：必须以纯文本出现，绝不当 HTML 执行。
SCRIPT_SNIPPET = "<script>alert(1)</script>"
IMG_SNIPPET = "<img src=x onerror=alert(2)>"

CURRENT_TEXT = "画面中一人站在大门口" + SCRIPT_SNIPPET
HISTORY_TEXT = "门口地面上有包裹" + IMG_SNIPPET

FAKE_JPEG = b"\xff\xd8" + b"fake-crop-jpeg-bytes" + b"\xff\xd9"


def _seed_store():
    """两代 run 的 l3 记录（带 sources/crop_id）+ 带 frame_refs 的 l4 版本。

    记录形状同 win11_l2_runtime.results_from_output / l4 累计发布的冻结
    字段集；当前 run 与注册表权威身份一致，旧 run 为历史。
    """
    store = UnderstandingStore()
    store.append(CAMERA, "l2", {"status": "ok", "calibrated": False,
                                "model_ref": "local-vlm-7b",
                                "window_state": "producing"})
    store.append(CAMERA, "l3", {
        "window": "w-old", "branch": "relation_crop", "status": "ok",
        "at": 1.0,
        "results": [{
            "window_key": [CAMERA, "run-1", "v1", "w-old"],
            "branch_key": [CAMERA, "run-1", "v1", "w-old", "relation_crop",
                           MISSING_CROP, "mat-1"],
            "branch": "relation_crop", "crop_id": MISSING_CROP,
            "model_ref": "local-vlm-7b", "status": "ok",
            "observation": {"text": HISTORY_TEXT, "unstructured": True,
                            "certainty": "model_inferred"},
            "sources": [{"position": "cur", "frame_id": "f-old",
                         "present": True, "t_capture_ms": 9000.0,
                         "timestamp_kind": "source_capture"}],
            "missing": {"frames_dropped": 0, "omission_reason": None,
                        "frames": []}}]})
    store.append(CAMERA, "l3", {
        "window": "w-new", "branch": "panorama", "status": "ok", "at": 2.0,
        "results": [{
            "window_key": [CAMERA, CURRENT_RUN[0], CURRENT_RUN[1], "w-new"],
            "branch_key": [CAMERA, CURRENT_RUN[0], CURRENT_RUN[1], "w-new",
                           "panorama", EVIDENCE_CROP, None],
            "branch": "panorama", "crop_id": EVIDENCE_CROP,
            "model_ref": "local-vlm-7b", "status": "ok",
            "observation": {"text": CURRENT_TEXT, "unstructured": True,
                            "certainty": "model_inferred"},
            "sources": [{"position": "cur", "frame_id": "f-new",
                         "present": True, "t_capture_ms": 17123.5,
                         "timestamp_kind": "source_capture"}],
            "missing": {"frames_dropped": 0, "omission_reason": None,
                        "frames": []}}]})
    store.append(CAMERA, "l4", {
        "version_id": "abcdef1234567890", "status": "ok",
        "window_id": "w-new", "coord_space": "normalized",
        "items": [{"kind": "observation", "text": "一人站在门口",
                   "certainty": "observed", "unstructured": False,
                   "sources": ["crop:" + EVIDENCE_CROP, "frame:f-new"]}],
        "frame_refs": [{"frame_id": "f-new", "t_ms": 17123.5,
                        "time_kind": "source_capture",
                        "coord_space": "normalized",
                        "crop_ref": EVIDENCE_CROP,
                        "stable_ref": "front:run-2:track:3",
                        "bbox_norm": [0.1, 0.2, 0.3, 0.4]}],
        "at": 3.0})
    return store


def _seed_evidence_asset(wb_state, tmp_path):
    """受控证据索引 + 磁盘 JPEG：EVIDENCE_CROP 的裁图可经 /api/evidence 取。"""
    evidence_dir = tmp_path / "evidence" / CAMERA / "crops"
    evidence_dir.mkdir(parents=True)
    target = evidence_dir / "frame.jpg"
    target.write_bytes(FAKE_JPEG)
    conn = wb_state._conn()
    try:
        conn.execute(
            "INSERT INTO evidence_assets"
            " (asset_id,owner_type,owner_id,camera,kind,path,state,mime,"
            " t_start,score,size_bytes,sha256,created_at,updated_at,metadata)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (EVIDENCE_CROP, "semantic_event", "event:c139r2", CAMERA,
             "clean_best_frame", f"{CAMERA}/crops/frame.jpg", "available",
             "image/jpeg", 2.0, 1.0, len(FAKE_JPEG),
             hashlib.sha256(FAKE_JPEG).hexdigest(), 2.0, 2.0,
             json.dumps({"bbox": [0.1, 0.2, 0.3, 0.4]})))
        conn.commit()
    finally:
        conn.close()


def _seed_baseline(wb_state):
    """经应用自身受控路径建立有效环境基线：值守门禁放行（首次使用遮罩
    不出现，页面可正常交互）。画面经 save_scene_frame 落盘并带哈希/大小。"""
    from scam.db import establish_environment_baseline
    stored = wb_state.evidence.save_scene_frame(
        camera=CAMERA, frame_bytes=FAKE_JPEG, established_at=2.0)
    conn = wb_state._conn()
    try:
        establish_environment_baseline(
            conn, camera=CAMERA, baseline_id="baseline:front:c139r2",
            established_at=2.0, established_via="first-use",
            scene_summary="测试基线", machine_state="unknown",
            profile={"scene_type": "indoor"}, model_id="test-model",
            config_fingerprint="unknown",
            evidence_path=stored["path"],
            evidence_sha256=stored["sha256"],
            evidence_size=stored["size_bytes"], payload=None)
    finally:
        conn.close()


@pytest.fixture()
def workbench_url(tmp_path):
    """真实工作台 HTTP 服务（127.0.0.1 临时端口；已注册相机与理解历史）。"""
    db_path = tmp_path / "wb-c139r2.db"
    conn = connect(str(db_path))
    init_schema(conn)
    conn.execute("INSERT INTO zones (camera, data) VALUES (?, ?)",
                 (CAMERA, "[]"))
    conn.commit()
    conn.close()
    wb_state = WorkbenchState(str(db_path))
    _seed_evidence_asset(wb_state, tmp_path)
    _seed_baseline(wb_state)
    wb_state.understanding_store = _seed_store()
    # C-139-R2 D1：当前身份权威来源 = runtime 注册表（state.l2._registry）。
    wb_state.l2 = SimpleNamespace(_registry={CAMERA: CURRENT_RUN})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), WorkbenchHandler)
    httpd.state = wb_state
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def browser_page():
    """Playwright Chromium 页面；依赖缺失 → skip 并如实命名。

    依次探测：playwright 自带 chromium → 系统 Edge（channel=msedge）→
    系统 Chrome（channel=chrome）；全部不可用才跳过，并如实列出已探测
    的后端与失败类型。
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("playwright 未安装：C-139-R2 浏览器级测试跳过")
    try:
        pw = sync_playwright().start()
    except Exception as exc:  # 驱动缺失等环境问题
        pytest.skip(f"playwright 驱动不可用：C-139-R2 浏览器级测试跳过"
                    f"（{type(exc).__name__}）")
    page = None
    try:
        failures = []
        for channel in (None, "msedge", "chrome"):
            label = channel or "chromium(bundled)"
            try:
                browser = pw.chromium.launch(headless=True, channel=channel)
            except Exception as exc:
                failures.append(f"{label}={type(exc).__name__}")
                continue
            try:
                page = browser.new_page()
                yield page
            finally:
                browser.close()
            return
        pytest.skip("playwright 浏览器不可用：C-139-R2 浏览器级测试跳过"
                    "（已探测 " + "；".join(failures) + "）")
    finally:
        pw.stop()


def _detail_section_texts(page):
    return page.locator("#understanding-detail .und-section") \
        .all_text_contents()


def test_workbench_c139r2_user_traceability_browser(workbench_url,
                                                    browser_page):
    """浏览器级验收：当前/历史分列、textContent 安全渲染、来源展开点击、
    frame_refs 与证据诚实链接（D1/D2/D3）。"""
    page = browser_page
    dialogs = []
    page.on("dialog", lambda dialog: (dialogs.append(dialog.type),
                                      dialog.dismiss()))
    page.goto(workbench_url, wait_until="domcontentloaded")
    # 等待首用门禁放行（有效基线 → 遮罩带 hidden 属性）与理解区真正渲染。
    # refreshHealth 首轮可能早于相机下拉就绪，由 5s 轮询补渲染（≤15s）。
    page.wait_for_selector("#environment-gate[hidden]", state="attached",
                           timeout=15000)
    page.wait_for_selector("#understanding-detail:not([hidden])",
                           timeout=15000)
    # 冻结轮询定时器：后续断言/点击期间 5s 重渲染不再替换 DOM（确定性）。
    page.evaluate(("const top = setTimeout(function(){}, 0);"
                   "for (let i = 0; i <= top; i++) {"
                   "clearInterval(i); clearTimeout(i); }"))

    # ---- D1：当前区与历史区分开渲染 ------------------------------------
    sections = _detail_section_texts(page)
    assert "当前窗口进展" in sections, sections
    assert "历史记录（旧 run/config）" in sections, sections
    assert sections.index("当前窗口进展") \
        < sections.index("历史记录（旧 run/config）")
    # 当前区：权威身份（注册表 run-2/v3）的行；头部标注当前身份
    head = page.locator("#understanding-detail .und-head").text_content()
    assert "（当前 run run-2 · 配置 v3）" in head
    current_row = page.locator(
        "#understanding-detail .und-branch", has_text=CURRENT_TEXT)
    assert current_row.count() == 1
    assert "（历史" not in current_row.text_content()
    # 历史区：旧 run/config 条目 + 身份短码
    history_row = page.locator(
        "#understanding-detail .und-branch", has_text=HISTORY_TEXT)
    assert history_row.count() == 1
    assert "（历史 run run-1 · 配置 v1）" in history_row.text_content()

    # ---- 安全文本：模型输出按 textContent 渲染，绝不当 HTML ------------
    detail_text = page.locator("#understanding-detail").text_content()
    assert SCRIPT_SNIPPET in detail_text and IMG_SNIPPET in detail_text
    assert page.locator(
        "#understanding-detail script, #understanding-detail img").count() == 0
    assert dialogs == []   # 恶意片段未执行（无 alert 弹窗）

    # ---- D2：分支行常显追溯速览（crop_id/模型为短码 + 帧时间）---------
    assert ("裁图 crop-evid…ce-1 · 模型 local-vlm-7b · 帧 f-new"
            " t=17123.5ms") in detail_text
    toggle = current_row.locator("button.und-toggle")
    sources_area = current_row.locator(".und-sources")
    assert sources_area.is_hidden()          # 默认收起
    toggle.click()                            # 点击展开
    assert sources_area.is_visible()
    sources_text = sources_area.text_content()
    assert "帧#cur f-new t=17123.5ms（source_capture）" in sources_text
    assert "crop_id：crop-evidence-1" in sources_text
    assert "模型：local-vlm-7b" in sources_text
    toggle.click()                            # 再点收起
    assert sources_area.is_hidden()

    # ---- D2：融合版本条目显示 frame_refs（帧 id/时间/坐标体系）---------
    assert "· 帧 f-new t=17123.5ms（normalized）" in detail_text

    # ---- D3：证据链接诚实 ----------------------------------------------
    # 有磁盘证据 → 受控链接，且目标真实可取（HTTP 200 + image/jpeg）
    evidence_link = current_row.locator("a", has_text="打开原始裁图")
    assert evidence_link.count() == 1
    href = evidence_link.get_attribute("href")
    assert href == "/api/evidence/crop-evidence-1"
    resp = page.request.get(workbench_url + href)
    assert resp.status == 200
    assert resp.headers.get("content-type") == "image/jpeg"
    assert resp.body() == FAKE_JPEG
    # 未持久化裁图 → 如实「原始裁图尚未保存」，绝不给失效链接
    assert "原始裁图尚未保存" in history_row.text_content()
    assert history_row.locator("a", has_text="打开原始裁图").count() == 0
