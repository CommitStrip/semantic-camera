# -*- coding: utf-8 -*-
"""C145 工作台布局静态合同（ZCode 主会话专属；pytest 可跑、无 subprocess）。

锁定 C145 布局实施的结构事实：
1. 现场（live-card）：相机选择 + 当前画面 + 圈选覆盖层 + 连接/理解状态行；
2. 观察记录（observation-card）：事件表 + 选中详情面板 + 理解分支解释区；
3. 高级折叠（advanced-panel，details 默认收起）：区域圈选说明/审查时间线/
   管理员规则告警（旧接口）/模式库——技术窗口不冒充用户事件；
4. 选中详情：原图（best_frame 有则给受控链接）+ 可用录像诚实行；
5. 命名纪律：主列表称「观察记录」；头部副标可选增强口径；
6. R2 契约元素原样保留（expandedStateKey/LRU/跳过/storage 安全）。

行为级验收由 tests/c145_page_dom.js（node，真实页面脚本驱动）与受控
浏览器承载；本文件防止行为绿但结构回退。
"""
import re
from pathlib import Path

_SERVER = Path(__file__).resolve().parent.parent / "scam" / "server.py"


def _html():
    src = _SERVER.read_text(encoding="utf-8")
    start = src.index("<body>") + len("<body>")
    end = src.index("<script>", start)
    return src[start:end]


def _js():
    src = _SERVER.read_text(encoding="utf-8")
    start = src.index("<script>") + len("<script>")
    end = src.index("</script>", start)
    return src[start:end]


# ---------------------------------------------------------------- 现场卡

def test_live_card_assembly():
    """现场卡：相机选择 + 画面（含圈选覆盖层）+ 状态行 + 理解摘要行。"""
    html = _html()
    m = re.search(r'<div class="card" id="live-card">(.*?)'
                  r'<div class="card" id="observation-card">', html, re.S)
    assert m, "现场卡缺失或不在观察记录卡之前"
    body = m.group(1)
    for part in ('id="camera-select"', 'id="frame-stage"', 'id="zone-frame"',
                 'id="zone-grid"', 'id="grid-summary"', 'id="runtime-state"',
                 'id="l1-status"', 'id="understanding-line"'):
        assert part in body, f"现场卡缺少 {part}"
    assert "圈选为可选增强" in body, "现场卡应标注圈选为可选增强"


# ---------------------------------------------------------------- 观察记录

def test_observation_card_naming_and_parts():
    """主列表称「观察记录」；含事件表/详情面板/理解分支解释区。"""
    html = _html()
    m = re.search(r'<div class="card" id="observation-card">(.*?)'
                  r'<div class="card" id="guard-grid-card">', html, re.S)
    assert m, "观察记录卡缺失"
    body = m.group(1)
    assert "<h2>观察记录</h2>" in body, "主列表必须称观察记录"
    for part in ('id="reminder-banner"', 'id="event-timeline"',
                 'id="event-detail-panel"', 'id="understanding-detail"'):
        assert part in body, f"观察记录卡缺少 {part}"
    assert "选中记录可看解释、时间、原图与可用录像" in body


def test_technical_windows_in_advanced_panel():
    """技术窗口（审查时间线/管理员规则告警旧接口/模式库/圈选配置表单）
    收进高级折叠 details 且默认收起（无 open 属性）。"""
    html = _html()
    m = re.search(r'<details id="advanced-panel"([^>]*)>(.*?)</details>',
                  html, re.S)
    assert m, "高级折叠缺失"
    attrs, body = m.group(1), m.group(2)
    assert "open" not in attrs, "高级折叠必须默认收起"
    for part in ('id="review"', 'id="events"', 'id="patterns"',
                 "审查时间线", "管理员规则告警", "模式库",
                 "区域与规则（可选增强）"):
        assert part in body, f"高级折叠缺少 {part}"
    # 不冒充：旧告警卡标注"旧接口"，主线指向观察记录
    assert "旧接口" in body and "观察记录" in body


def test_aside_keeps_zone_form_and_optional_baseline():
    """区域配置表单与环境基线卡仍在 aside（表单为高级能力的配置面，
    环境基线为可选增强口径）。"""
    html = _html()
    aside = html[html.index("<aside>"):html.index("</aside>")]
    for part in ('id="zone-list"', 'id="save-zone"', 'id="rule-template"',
                 "环境基线为可选增强", 'id="environment-message"',
                 'id="baseline-history"'):
        assert part in aside, f"aside 缺少 {part}"


# ---------------------------------------------------------------- 详情

def test_event_detail_original_image_and_recording_honest():
    """详情渲染：best_frame 有则给受控原图链接；录像无绑定如实说明。"""
    js = _js()
    assert "if(d.best_frame&&d.best_frame.content_url){" in js, \
        "详情缺少原图分支"
    assert "打开原始画面" in js and "aria-label" in js, \
        "原图链接需要可访问名称"
    assert "可用录像：暂无（该记录未绑定录像段）" in js, \
        "详情缺少可用录像诚实行"


# ---------------------------------------------------------------- 命名纪律

def test_header_subtitle_optional_baseline_wording():
    """头部副标与 gate 文案：可选增强口径；禁用残留文案。"""
    src = _SERVER.read_text(encoding="utf-8")
    assert "环境基线为可选增强（可跳过，随时可建）" in src
    assert "固定机位首次使用须先建立环境基线" not in src, \
        "头部副标不得再宣称基线强制"
    assert "可选识别" not in src


def test_r2_contracts_untouched():
    """R2 契约元素在布局重排后原样保留（状态键/LRU/跳过/storage）。"""
    js = _js()
    for part in ("expandedStateKey", "EXPANDED_SOURCES_CAP=128",
                 "gateSkippedRead", "gateSkippedWrite",
                 "const prevScrollTop=box.scrollTop"):
        assert part in js, f"R2 契约元素缺失: {part}"
