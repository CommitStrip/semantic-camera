# -*- coding: utf-8 -*-
"""C-144-R2 agent C 专属页面验证（workbench 内联脚本合同；无 subprocess）。

行为级验收由 DeepSeek Harness 的 node DOM harness 承载
（tests/c144r1_page_dom.js，经 work/run 手段驱动——见批次交付记录）；
本文件锁定其背后的**页面脚本静态合同**与 loadEnvironment 状态机的
Python 复刻，防止行为绿但结构回退：

1. 展开状态：状态键=完整身份（camera|run|config|window|material|
   branch|crop），与 C142 冻结显示锚分离；容器=Map 且容量常量 ≤128、
   超限淘汰最老（有界生命周期）。
2. 跳过环境基线：loadEnvironment 的无相机/读取失败/无基线/非 ready
   分支都不得把门盖回（跳过后门保持隐藏；ready 分支本就隐藏）；
   sessionStorage 访问全部 try/catch（storage 不可用页面照常）。
3. 重渲染保留阅读滚动位置（replaceChildren 后恢复 scrollTop）。
4. 「发现变化，正在分析」由近期事实驱动（det.pending），不由累计
   计数永久显示。
"""
import re
from pathlib import Path

import pytest

_SERVER = Path(__file__).resolve().parent.parent / "scam" / "server.py"


def _workbench_js():
    src = _SERVER.read_text(encoding="utf-8")
    start = src.index("<script>") + len("<script>")
    end = src.index("</script>", start)
    return src[start:end]


# ---------------------------------------------------------------- 展开状态

def test_expanded_sources_state_key_is_complete_identity():
    """状态键含 camera/window/material/branch/crop 全段（与显示锚分离）。"""
    js = _workbench_js()
    assert "expandedStateKey" in js, "缺少完整身份状态键派生"
    m = re.search(r"function expandedStateKey\(b,camId\)\{(.+?)\}", js, re.S)
    assert m, "expandedStateKey 实现缺失"
    body = m.group(1)
    for part in ("camId", "window_key", "material_id", "branch_key",
                 "crop_id"):
        assert part in body, f"状态键缺少身份段: {part}"
    # 显示锚与状态键分离：toggle 读写 stateKey，anchor 只进 DOM 属性
    toggle_block = re.search(r"const anchor=undSrcAnchor[^;]+;(.{0,900}?)"
                             r"toggle\.onclick", js, re.S)
    assert toggle_block, "来源切换钮块缺失"
    block = toggle_block.group(1)
    assert "expandedStateKey(b,camId)" in block, "切换钮未使用状态键"
    assert "expandedSources.has(stateKey)" in block
    assert "expandedSources.has(anchor)" not in js, \
        "展开状态不得再按显示锚存取（尾部编号相同会串态）"


def test_expanded_sources_lru_cap_128():
    """容器=Map、容量常量 ≤128、超限淘汰最老（有界生命周期）。"""
    js = _workbench_js()
    m = re.search(r"EXPANDED_SOURCES_CAP=(\d+)", js)
    assert m, "缺少展开集合容量常量"
    assert int(m.group(1)) <= 128, "容量必须 ≤128"
    assert "const expandedSources=new Map()" in js, "容器须为 Map（LRU 序）"
    assert re.search(r"while\(expandedSources\.size>EXPANDED_SOURCES_CAP\)"
                     r".{0,120}?\.delete\(", js, re.S), \
        "缺少超限淘汰最老的收敛循环"


# ---------------------------------------------------------------- 基线门

def test_skip_baseline_respected_in_every_non_ready_branch():
    """loadEnvironment 各分支：跳过后门保持隐藏；未跳过才显示门。"""
    js = _workbench_js()
    m = re.search(r"async function loadEnvironment\(\)\{.*?\nconst B=baseline\.state;",
                  js, re.S)
    assert m, "loadEnvironment 结构变化：请同步本合同测试"
    body = m.group(0)
    assert "const gateSkipped=gateSkippedRead()" in body, \
        "函数入口必须读取跳过状态（storage 安全）"
    # 失败/无基线分支：门跟随跳过状态（不得无条件 gate.hidden=false）
    assert body.count("ui.gate.hidden=gateSkipped") >= 2, \
        "读取失败与无基线分支都必须尊重跳过选择"
    # 非 ready 分支：先 ready 短路，再跳过收起门，最后才未跳过显示门
    tail = js[js.index("const B=baseline.state;"):]
    tail = tail[:tail.index("async function establishBaseline")]
    assert tail.index("if(B==='ready')") < tail.index("if(gateSkipped){") \
        < tail.index("ui.gate.hidden=false;ui.baselineRetry.hidden="), \
        "非 ready 分支顺序应为 ready→跳过收起→未跳过显示门"
    skip_block = re.search(r"if\(gateSkipped\)\{(.{0,400}?)\}", tail, re.S)
    assert skip_block, "跳过分支缺失"
    assert "ui.gate.hidden=false" not in skip_block.group(1), \
        "跳过分支内不得再显示门"


def test_storage_access_is_exception_safe():
    """sessionStorage 读写全部 try/catch（storage 不可用页面照常操作）。"""
    js = _workbench_js()
    assert "function gateSkippedRead(){try{return sessionStorage" in js
    assert "function gateSkippedWrite(){try{sessionStorage" in js
    # loadEnvironment 内不得再有裸 sessionStorage 访问
    m = re.search(r"async function loadEnvironment\(\)\{.*?establishBaseline",
                  js, re.S)
    assert m and "sessionStorage" not in m.group(0).replace(
        "gateSkippedRead()", "").replace("gateSkippedWrite()", ""), \
        "loadEnvironment 不得裸访问 sessionStorage"


# ---------------------------------------------------------------- 渲染

def test_rerender_preserves_scroll_position():
    """重渲染：replaceChildren 前保存 scrollTop、渲染完成后恢复。"""
    js = _workbench_js()
    m = re.search(r"function renderUnderstandingDetail\(box,camId,entry(?:,capability=null)?\)\{"
                  r"(.*?)\nbox\.hidden=false;\nbox\.scrollTop=prevScrollTop\}",
                  js, re.S)
    assert m, "渲染函数缺少滚动位置保存/恢复"
    body = m.group(1)
    assert "const prevScrollTop=box.scrollTop" in body
    assert "box.replaceChildren()" in body


def test_change_analyzing_is_near_fact_driven():
    """「发现变化，正在分析」只由在途分析包数（det.pending）驱动，
    不绑定任何累计计数（近期事实，分析完即消退）。"""
    js = _workbench_js()
    m = re.search(r"if\(\(det\.pending\|\|0\)>0\)return'发现变化，正在分析'",
                  js)
    assert m, "「发现变化，正在分析」必须由 det.pending 驱动"


# ---------------------------------------------------------------- 状态机复刻

def _load_env_state_machine(skipped, *, camera="front-door", baseline,
                            fetch_error=False):
    """loadEnvironment 分支行为的 Python 复刻（与页面脚本逐分支对齐；
    页面脚本结构变化时上面的静态合同测试会先拦住）。"""
    state = {"gate_hidden": None, "env_message": "", "gate_message": "",
             "analyze_disabled": False}
    if not camera:
        state["gate_hidden"] = skipped
        state["gate_message"] = "请先配置相机"
        state["analyze_disabled"] = True
        return state
    if fetch_error:
        state["env_message"] = ("基线状态读取失败（已跳过：观察与证据不受阻，"
                                "环境增强为可选）。" if skipped
                                else "基线状态读取失败，请稍候重试。")
        state["gate_hidden"] = skipped
        return state
    if baseline is None:
        state["env_message"] = ("环境基线尚未建立（已跳过：观察与证据不受阻；"
                                "可随时在下方建立基线以启用环境增强）。"
                                if skipped else "环境基线状态暂不可用。")
        state["gate_hidden"] = skipped
        return state
    if baseline["state"] == "ready":
        state["gate_hidden"] = True
        state["env_message"] = "环境基线已就绪。"
        return state
    if skipped:
        state["gate_hidden"] = True
        state["env_message"] = ("环境基线尚未建立（已跳过：观察与证据不受阻；"
                                "环境基线为可选增强，可随时在下方建立基线）。")
        return state
    state["gate_hidden"] = False
    state["env_message"] = "该相机还没有环境基线。"
    return state


@pytest.mark.parametrize("skipped", [False, True])
def test_gate_branch_matrix(skipped):
    """无基线/失败/非 ready/ready 四分支 × 跳过与否的门状态矩阵。

    契约：非 ready 族分支门状态=「跳过则隐藏、未跳过则显示」；
    ready 分支门恒隐藏（基线存在，无门可显示）。"""
    no_ready = {"state": "no_pointer"}
    # 未跳过：非 ready 显示门；跳过：门保持隐藏（不覆盖用户选择）
    assert _load_env_state_machine(skipped, baseline=no_ready)[
        "gate_hidden"] is skipped
    # 读取失败
    assert _load_env_state_machine(skipped, baseline=None,
                                   fetch_error=True)["gate_hidden"] is skipped
    # 无基线记录
    assert _load_env_state_machine(skipped, baseline=None)[
        "gate_hidden"] is skipped
    # ready：无论跳过与否门都隐藏（基线存在，无门可显示）
    assert _load_env_state_machine(skipped,
                                   baseline={"state": "ready"})[
        "gate_hidden"] is True
