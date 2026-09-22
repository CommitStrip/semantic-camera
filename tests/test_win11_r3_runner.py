"""ZW-012 · Win11 R3 原生两阶段操作脚本契约（deploy/run-win11-r3-acceptance.ps1）。

只读检查包装脚本，不修改产品代码、驱动、安装脚本、其它测试或 Linux 文件：
- 静态契约在任何主机上都执行（纯 ASCII/BOM 无关兼容、无进程控制、无网络、无配置/
  区域写入、无 eval、参数数组调用、覆盖拒绝先于 Python 调用、退出码透传）；
- 装有 PowerShell（powershell 与/或 pwsh，二者都装则都检查，不要求都装）时，再执行
  PowerShell AST 解析、纯函数直测（参数顺序、LOCALAPPDATA 默认目录、回环允许/拒绝
  矩阵）与真实进程行为（非法地址先拒绝且不调用 Python、LOCALAPPDATA 默认、覆盖拒绝、
  退出码透传）；
- 本文件不使用 skip：主机没有 PowerShell 时，同一批用例改为断言静态契约，绝不静默跳过。

Windows PowerShell 5.1 兼容（ZW-012-R1）：`Uri.Host` 的 IPv6 方括号先归一化再进允许清单比对，
交回驱动前重建为恰好一对方括号；证据目录改用 5.1/7 共同支持且把路径当实参的具名参数形式创建；
“拒绝先于调用”只按`# ---- 8.`主流程里的真实调用点判定，不再命中函数前的说明注释。

测试夹具（ZW-018 / `C-062`）：参数集合只解析 `New-Item` 到第一个管道之前（`| Out-Null` 的
`-Out` 不是 `New-Item` 的参数）；退出码透传与破折号目录两条真实进程用例恢复用
`sys.executable` 真实执行 `-m scam.win11_r3_acceptance`，并给子进程环境显式**前置**仓库根
`PYTHONPATH`，因此从任意临时 cwd 都能导入真实驱动、确定取到结构化前置码 2 与写 stderr 的
结构化失败文档。ZW-016 的 `.cmd`/`.sh` 假驱动已删除：Windows PowerShell 把 `.cmd` 当
`-PythonCommand` 调用时不形成与原生 Python 等价的参数边界（只记到 `-m`），记录文件还会落在
被测目录里污染断言。驱动自身的成功/失败语义仍由 tests/test_win11_r3_acceptance.py 在进程内
覆盖。

证据等级：合成/静态证据，非真实 Win11 主机端到端；真实 RTSP、真实模型质量、告警
延迟、干净安装与长稳恒为未验证。
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "deploy" / "run-win11-r3-acceptance.ps1"
SOURCE = RUNNER.read_text(encoding="utf-8-sig")
LINES = SOURCE.splitlines()

MODULE = "scam.win11_r3_acceptance"
DEFAULT_BASE_URL = "http://127.0.0.1:8600"
STATE_NAME = "win11-r3-state.json"
REPORT_NAME = "win11-r3-report.json"
REFUSAL_EXIT = 3
# 驱动自身的前置条件失败码：包装脚本只可能以 3 拒绝，取到 2 就证明子进程真的跑过
DRIVER_PRECONDITION_EXIT = 2
# 结构化失败文档的固定 schema 标识（驱动 `_report_error` 写 stderr 的 JSON）
REPORT_SCHEMA = "scam.win11-r3-report/v1"

PURE_FUNCTIONS = ("New-R3ArgumentList", "Get-R3DefaultEvidenceRoot",
                  "ConvertTo-R3LoopbackTarget", "ConvertTo-R3LoopbackHostText")

# 回环允许/拒绝矩阵：允许项是驱动自身也会接受的形状（http + 回环字面量 + 显式端口），
# 拒绝项覆盖协议、用户信息、非回环/私网/保留地址、路径/查询/片段与非法端口。
URL_MATRIX = (
    ("http://127.0.0.1:8600", True),
    ("http://127.0.0.1:8600/", True),
    ("http://127.0.0.1:80", True),
    ("http://127.0.0.1:65535", True),
    ("http://localhost:8600", True),
    ("http://[::1]:8600", True),
    ("http://[::1]:80", True),
    ("http://[::1]:8600/", True),
    ("HTTP://[::1]:8600", True),
    ("HTTP://LOCALHOST:8600", True),
    ("  http://127.0.0.1:8600  ", True),
    ("https://127.0.0.1:8600", False),
    ("ftp://127.0.0.1:8600", False),
    ("file:///C:/temp/state.json", False),
    ("http://user:secret@127.0.0.1:8600", False),
    ("http://user@127.0.0.1:8600", False),
    ("http://10.0.0.5:8600", False),
    ("http://192.168.1.10:8600", False),
    ("http://169.254.169.254:8600", False),
    ("http://0.0.0.0:8600", False),
    ("http://127.0.0.2:8600", False),
    ("http://example.com:8600", False),
    ("http://localhost.evil.example:8600", False),
    ("http://127.0.0.1:8600/api", False),
    ("http://127.0.0.1:8600/?token=1", False),
    ("http://127.0.0.1:8600/#frag", False),
    ("http://127.0.0.1", False),
    ("http://127.0.0.1:", False),
    ("http://127.0.0.1:0", False),
    ("http://127.0.0.1:99999", False),
    ("http://[::2]:8600", False),
    ("http://[::ffff:127.0.0.1]:8600", False),
    ("http://[::1]:8600/api", False),
    ("http://[::1]:8600/?token=1", False),
    ("http://[::1]", False),
    ("not-a-url", False),
    ("", False),
)

# 允许项交给驱动的必须是规范化重建的地址（不是操作者原文）：http + 回环字面量 + 显式端口，
# IPv6 恰好一对方括号。localhost 两行按不区分大小写比对（主机名大小写归一不是本契约的一部分）。
CANONICAL_ALLOWED_TEXT = {
    "http://127.0.0.1:8600": "http://127.0.0.1:8600",
    "http://127.0.0.1:8600/": "http://127.0.0.1:8600",
    "http://127.0.0.1:80": "http://127.0.0.1:80",
    "http://127.0.0.1:65535": "http://127.0.0.1:65535",
    "  http://127.0.0.1:8600  ": "http://127.0.0.1:8600",
    "http://[::1]:8600": "http://[::1]:8600",
    "http://[::1]:80": "http://[::1]:80",
    "http://[::1]:8600/": "http://[::1]:8600",
    "HTTP://[::1]:8600": "http://[::1]:8600",
}
CASE_INSENSITIVE_ALLOWED_TEXT = {
    "http://localhost:8600": "http://localhost:8600",
    "HTTP://LOCALHOST:8600": "http://localhost:8600",
}

# 主机文本归一化矩阵（纯函数直测，不经过 System.Uri）：Windows PowerShell 5.1 的
# Uri.Host 保留方括号、PowerShell 7 去掉，扩展写法也可能出现；只有真正表示回环的
# 拼写才允许归一化为规范文本，其余一律 $null（fail-closed，绝不因归一化放宽允许清单）。
HOST_TEXT_MATRIX = (
    ("::1", "::1"),
    ("[::1]", "::1"),
    ("[::1] ", "::1"),
    ("0:0:0:0:0:0:0:1", "::1"),
    ("[0:0:0:0:0:0:0:1]", "::1"),
    ("0000:0000:0000:0000:0000:0000:0000:0001", "::1"),
    ("127.0.0.1", "127.0.0.1"),
    ("127.0.0.1 ", "127.0.0.1"),
    ("localhost", "localhost"),
    ("LOCALHOST", "localhost"),
    ("::2", None),
    ("[::2]", None),
    ("::ffff:127.0.0.1", None),
    ("[::ffff:127.0.0.1]", None),
    ("[[::1]]", None),
    ("[::1", None),
    ("[localhost]", None),
    ("fe80::1%12", None),
    ("::", None),
    ("1::", None),
    ("::1:0", None),
    ("127.0.0.2", None),
    ("localhost.evil.example", None),
    ("not-a-host", None),
    ("", None),
    ("   ", None),
)

# 运行包装脚本时，真正会被执行到的非法地址子集（命令行可安全传入的形状）。
EXECUTED_REFUSAL_URLS = (
    "https://127.0.0.1:8600",
    "http://user:secret@127.0.0.1:8600",
    "http://10.0.0.5:8600",
    "http://192.168.1.10:8600",
    "http://example.com:8600",
    "http://127.0.0.1:8600/api",
    "http://127.0.0.1",
    "http://[::2]:8600",
    "http://[::1]:8600/api",
)


# ---------- 通用工具 ----------

def _powershell_interpreters():
    """返回可用的 PowerShell 解释器（powershell 与/或 pwsh），不要求两者都装。"""
    found = []
    for name in ("powershell", "pwsh"):
        executable = shutil.which(name)
        if executable:
            found.append((name, executable))
    return found


def _decode(raw):
    """按 UTF-8 / 本机 OEM 代码页解码子进程输出（PS 5.1 与 PS 7 编码不同）。"""
    for encoding in ("utf-8", "oem", "mbcs"):
        try:
            return raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", "replace")


def _run(command, cwd, env=None, timeout=180):
    completed = subprocess.run(command, cwd=str(cwd), env=env,
                               capture_output=True, timeout=timeout)
    return (completed.returncode, _decode(completed.stdout),
            _decode(completed.stderr))


def _run_runner(executable, extra_args, cwd, env=None):
    command = [executable, "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-File", str(RUNNER)]
    return _run(command + [str(arg) for arg in extra_args], cwd=cwd, env=env)


def _code_lines():
    """去掉注释行与空行后的脚本文本（注释不可能执行，另在专门的用例里单独约束）。"""
    return [line for line in LINES
            if line.strip() and not line.lstrip().startswith("#")]


MAIN_FLOW_MARKER = "# ---- 1."
INVOKE_SECTION_MARKER = "# ---- 8."


def _main_flow_source():
    """主流程（第 1 段到文件末）文本：真实调用与全部拒绝点都只在这里。

    头部说明注释里也逐字写着调用形式（`& $python @argumentList`），在整份源码上做位置
    比较会命中注释而不是真实调用；函数定义与文件头说明都被切掉，只留主流程。第 1 段
    标记是这里唯一的定位锚点。
    """
    assert SOURCE.count(MAIN_FLOW_MARKER) == 1, SOURCE.count(MAIN_FLOW_MARKER)
    return SOURCE[SOURCE.index(MAIN_FLOW_MARKER):]


def _slash(path):
    return str(path).replace("\\", "/")


def _extract_function(name):
    """按花括号配对取出 ^function <name> { ... } 的完整定义文本。

    脚本内不存在带花括号的字符串（格式化占位符成对出现），因此配对计数是可靠的；
    配对失败即断言失败，绝不静默返回半截文本。
    """
    match = re.search(r"^function\s+" + re.escape(name) + r"\s*\{",
                      SOURCE, re.MULTILINE)
    assert match is not None, "未找到函数定义: " + name
    depth = 0
    index = match.end() - 1
    while index < len(SOURCE):
        character = SOURCE[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[match.start():index + 1]
        index += 1
    raise AssertionError("函数定义未闭合: " + name)


def _no_powershell_fallback():
    """主机没有 PowerShell 时的静态兜底：每条行为契约都必须仍能被静态验证。"""
    assert "$allowedHosts = @('127.0.0.1', 'localhost', '::1')" in SOURCE
    for code in ("unsafe_workbench", "localappdata_missing", "state_exists",
                 "report_exists", "state_missing", "base_url_not_applicable",
                 "phase_invalid", "python_missing"):
        assert "Stop-R3Request -Code '" + code + "'" in SOURCE, code
    assert "$childExitCode = $LASTEXITCODE" in SOURCE
    assert "exit $childExitCode" in SOURCE
    assert "& $python @argumentList" in SOURCE
    # 5.1 兼容两项：IPv6 主机文本先归一化再比对，证据目录用具名参数形式创建
    assert "$hostText = ConvertTo-R3LoopbackHostText -HostText $uri.Host" in SOURCE
    assert "New-Item -Path $resolvedEvidenceRoot -ItemType Directory -Force" in SOURCE


# ---------- 1. 静态契约（任何主机都执行） ----------

def test_runner_source_is_ascii_only_and_bom_independent():
    raw = RUNNER.read_bytes()
    assert raw.isascii(), (
        "脚本源码必须保持纯 ASCII：Windows PowerShell 5.1 会用本机 ANSI 代码页解析"
        "无 BOM 脚本，非 ASCII 字节会被误读甚至吞掉引号；保持 ASCII 才能让 5.1 与 7 "
        "在任意区域设置下读到同一份代码与同一条消息")
    assert SOURCE.endswith("\n")
    assert LINES[0].strip() == "#Requires -Version 5.1"
    # PS 7 专属语法一律不得出现（5.1 会直接解析失败）
    for token in ("??", "&&", "||", "-Parallel", "::new(", "[ordered]@{"):
        assert token not in SOURCE, token


def test_runner_never_controls_processes_or_uses_network_or_eval():
    lowered = SOURCE.lower()
    forbidden = (
        # 进程控制/探测：本脚本绝不代劳重启，也不探测值守进程
        "start-process", "stop-process", "restart-process", "get-process",
        "wait-process", "debug-process", "taskkill", "tasklist", "wmic",
        "sc.exe", "schtasks", "stop-service", "start-service",
        "restart-service", "stop-computer", "restart-computer",
        "start-job", "stop-job", "invoke-command",
        # 网络：工作台只由 Python 驱动以只读回环方式访问
        "invoke-webrequest", "invoke-restmethod", "system.net", "webclient",
        "httpclient", "test-netconnection", "test-connection", "test-wsman",
        "resolve-dnsname", "start-bitstransfer", "bitsadmin", "curl", "wget",
        "netsh", "net use",
        # 表达式求值：只允许参数数组调用
        "invoke-expression", "iex ", "add-type", "scriptblock]::create",
    )
    for token in forbidden:
        assert token not in lowered, token


def test_runner_never_writes_config_or_zones_and_never_reads_them():
    lowered = SOURCE.lower()
    for token in ("set-content", "out-file", "add-content", "clear-content",
                  "remove-item", "move-item", "copy-item", "rename-item",
                  "set-item", "set-itemproperty", "new-itemproperty",
                  "export-clixml", "convertto-json", "convertfrom-json",
                  "[system.io.file]::write", "[system.io.file]::create",
                  "streamwriter",
                  "get-content", "import-clixml", "readalltext",
                  "streamreader", "[system.io.file]::read",
                  "read-host", "get-credential", "securestring",
                  "pscredential", "convertto-securestring"):
        assert token not in lowered, token
    # cameras.json / zones 只允许作为边界声明出现在注释里，绝不作为代码目标
    for line in LINES:
        if "cameras.json" in line or "zones" in line:
            assert line.lstrip().startswith("#"), line


def test_runner_creates_only_the_evidence_directory():
    new_items = [line for line in _code_lines() if "New-Item" in line]
    assert len(new_items) == 1, new_items
    line = new_items[0]
    # New-Item 在 Windows PowerShell 5.1 与 7 上只有这一组常用参数，且都没有 -LiteralPath：
    # 5.1 绑定 -LiteralPath 会直接失败，让合法 After 在调用 Python 前变成 internal_error。
    # 参数集合只取第一个管道之前的文本：该行以 `| Out-Null` 收尾（抑制目录对象回显），
    # 管道后的 `-Out` 不是 New-Item 的参数，扫进来会让这条断言假失败。
    arguments_text = line.split("New-Item", 1)[1].split("|", 1)[0]
    assert set(re.findall(r"-[A-Za-z]+", arguments_text)) == \
        {"-Path", "-ItemType", "-Force"}, arguments_text
    assert "-ItemType Directory" in line
    # 路径作为具名参数的实参、且是变量而不是拼出的字符串：以 '-' 开头的证据目录因此
    # 仍然是路径值，不可能被当成参数名（也不允许用 --% 之类的停止解析符号兜）
    assert re.search(r"-Path\s+\$resolvedEvidenceRoot\b", arguments_text), line
    assert "--%" not in SOURCE
    # 除证据目录外没有任何创建/写入路径
    assert "mkdir" not in SOURCE.lower()
    assert "[system.io.file]" not in SOURCE.lower()


def test_runner_reads_only_localappdata_from_the_environment():
    assert re.findall(r"GetEnvironmentVariable\('([^']*)'\)", SOURCE) == \
        ["LOCALAPPDATA"]
    assert "$env:" not in SOURCE


def test_runner_declares_explicit_phases_and_deterministic_artifacts():
    assert "$script:R3StateFileName = 'win11-r3-state.json'" in SOURCE
    assert "$script:R3ReportFileName = 'win11-r3-report.json'" in SOURCE
    assert "$script:R3DefaultBaseUrl = 'http://127.0.0.1:8600'" in SOURCE
    # 两个阶段归一化为驱动的小写子命令，且只接受 Before / After
    assert "$phaseName = $Phase.Trim().ToLowerInvariant()" in SOURCE
    assert "if ($phaseName -ne 'before' -and $phaseName -ne 'after')" in SOURCE
    # Before 与 After 共用同一套确定性产物解析（After 消费 Before 写下的那个状态文件）
    assert ("$resolvedStatePath = Join-Path $resolvedEvidenceRoot "
            "$script:R3StateFileName") in SOURCE
    assert ("$resolvedReportPath = Join-Path $resolvedEvidenceRoot "
            "$script:R3ReportFileName") in SOURCE


def test_runner_module_literal_is_scam_win11_r3_acceptance():
    assert "$ModuleName = 'scam.win11_r3_acceptance'" in SOURCE
    assert "scam.win11_r3_acceptance" in SOURCE
    # 不得误接到预检入口或其它模块
    assert "win11_acceptance" not in SOURCE.replace("win11_r3_acceptance", "")
    assert "-m scam.win11_r3_acceptance" in SOURCE


def test_runner_argument_array_boundary_and_exit_code_pass_through():
    assert "& $python @argumentList" in SOURCE
    assert "$childExitCode = $LASTEXITCODE" in SOURCE
    assert "exit $childExitCode" in SOURCE
    assert "invoke-expression" not in SOURCE.lower()
    # 脚本自身只可能退出“拒绝码”或“驱动退出码”，绝不自行编造 0/1/2
    exits = set(re.findall(r"(?m)^\s*exit\s+(.+)$", SOURCE))
    assert exits == {"$script:R3RefusalExitCode", "$childExitCode"}, exits
    for fabricated in ("exit 0", "exit 1", "exit 2", "exit 3"):
        assert fabricated not in SOURCE, fabricated


def test_runner_refuses_every_checked_input_before_invoking_python():
    # 头部说明注释里也逐字写着调用形式（"& $python @argumentList"），在整份源码上取第一个
    # 出现会命中注释而不是真实调用；这里只取主流程文本，把真实调用点钉在第 8 段，再证明
    # 每一个检查输入的 Stop-R3Request 调用点都早于它。
    main_flow = _main_flow_source()
    assert main_flow.count("& $python @argumentList") == 1, main_flow
    invoke_at = main_flow.index("& $python @argumentList")
    # 真实调用点确实在主流程第 8 段：排在解释器门禁与证据目录创建之后
    assert main_flow.index(INVOKE_SECTION_MARKER) < invoke_at
    assert main_flow.index("$python = Resolve-R3Python") < invoke_at
    assert main_flow.index("New-Item -Path $resolvedEvidenceRoot") < invoke_at
    assert main_flow.index("$argumentList = New-R3ArgumentList") < invoke_at
    for code in ("phase_invalid", "localappdata_missing", "unsafe_workbench",
                 "base_url_not_applicable", "state_exists", "state_missing",
                 "report_exists", "python_missing"):
        marker = "Stop-R3Request -Code '" + code + "'"
        assert main_flow.index(marker) < invoke_at, code
    # “每一个”调用点：主流程内除“读不到退出码”那一处外，全部调用点都早于真实调用；
    # 全文也不存在主流程之外的调用点（函数定义与注释里的文字不算调用点）。
    pattern = r"Stop-R3Request -Code '([a-z_]+)'"
    call_sites = [(match.group(1), match.start())
                  for match in re.finditer(pattern, main_flow)]
    assert call_sites, call_sites
    assert SOURCE.count("Stop-R3Request -Code '") == len(call_sites), call_sites
    for code, position in call_sites:
        if code == "internal_error":
            continue
        assert position < invoke_at, code
    # 唯一的调用后拒绝只能是读到驱动退出码之前的那一处，且它确实挂在退出码判定上
    tail = main_flow[invoke_at:]
    assert set(re.findall(pattern, tail)) == {"internal_error"}, tail
    assert "if ($null -eq $childExitCode) {" in tail
    assert "$childExitCode = $LASTEXITCODE" in tail
    # Python 驱动的 no-clobber 仍是最终边界：拒绝信息里必须写明这一点
    assert SOURCE.count("keeps its own no-clobber as the final boundary") == 2


def test_runner_prints_fixed_next_step_only_after_successful_before():
    assert ("\n    if ($childExitCode -eq 0 -and $phaseName -eq 'before') {\n"
            "        Write-R3NextStep\n    }\n") in SOURCE
    assert "restart the Win11 workstation app BY HAND now" in SOURCE
    assert "run the After phase" in SOURCE
    # 拒绝、After 与失败路径都必须打印边界声明：拒绝出口 + 正常出口 + 异常出口
    calls = re.findall(r"(?m)^\s+Write-R3BoundaryNotice$", SOURCE)
    assert len(calls) == 3, calls


def test_runner_states_the_unverified_boundary_on_every_result():
    assert "R3 native-restart candidate evidence only" in SOURCE
    for keyword in ("Real RTSP", "real model quality", "alert latency",
                    "clean installation", "soak remain unverified"):
        assert keyword in SOURCE, keyword


def test_runner_documents_exit_code_contract():
    assert "3" in SOURCE
    assert "passed through unchanged" in SOURCE
    assert "refused by this wrapper before Python was invoked" in SOURCE


def test_runner_interpreter_resolution_and_self_location():
    resolver = _extract_function("Resolve-R3Python")
    assert "if (-not [string]::IsNullOrWhiteSpace($PythonCommand))" in resolver
    assert ".venv" in resolver and "python.exe" in resolver
    assert resolver.index(".venv") < resolver.index("return 'python'")
    assert "$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path" in SOURCE


# ---------- 2. PowerShell AST 解析（装有 PowerShell 时逐解释器执行） ----------

_PARSE_PROBE = """param(
    [Parameter(Mandatory = $true)][string] $OutPath,
    [Parameter(Mandatory = $true)][string] $RunnerPath
)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($RunnerPath, [ref] $tokens, [ref] $errors)
$messages = @()
foreach ($item in @($errors)) { $messages += $item.Message }
$payload = [ordered]@{
    interpreter = $PSVersionTable.PSVersion.ToString()
    parseErrors = $messages
}
[System.IO.File]::WriteAllText($OutPath, ($payload | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
"""


@pytest.fixture(scope="module")
def parse_probes(tmp_path_factory):
    """每个可用解释器解析一次包装脚本；无解释器时返回空字典。"""
    interpreters = _powershell_interpreters()
    if not interpreters:
        return {}
    root = tmp_path_factory.mktemp("zw012-parse-probe")
    probe = root / "parse-probe.ps1"
    probe.write_text(_PARSE_PROBE, encoding="utf-8")
    results = {}
    for name, executable in interpreters:
        out = root / (name + "-parse.json")
        code, stdout, stderr = _run(
            [executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
             "Bypass", "-File", str(probe), str(out), str(RUNNER)], cwd=root)
        payload = json.loads(out.read_text(encoding="utf-8")) \
            if out.exists() else None
        results[name] = {"exit_code": code, "stdout": stdout,
                         "stderr": stderr, "payload": payload}
    return results


def test_powershell_ast_parse_reports_no_error(parse_probes):
    if not parse_probes:
        # 无 PowerShell：退化为逐函数花括号配对的结构检查（不静默跳过）
        for name in PURE_FUNCTIONS:
            text = _extract_function(name)
            assert text.startswith("function " + name)
            assert text.endswith("}")
        assert SOURCE.count("{") == SOURCE.count("}")
        return
    for name, result in parse_probes.items():
        assert result["payload"] is not None, (name, result["stderr"])
        assert result["payload"]["parseErrors"] == [], name
        assert result["payload"]["interpreter"]
        assert result["exit_code"] == 0, (name, result["stderr"])


# ---------- 3. 纯函数直测（真实执行脚本内的函数定义） ----------

_BEHAVIOR_PROBE_HEAD = """param(
    [Parameter(Mandatory = $true)][string] $OutPath
)
$ErrorActionPreference = 'Stop'

{definitions}

$result = [ordered]@{{
    interpreter = $PSVersionTable.PSVersion.ToString()
    harnessError = $null
    argumentListBefore = @()
    argumentListAfter = @()
    evidenceRootWindows = $null
    evidenceRootEmpty = $null
    evidenceRootBlank = $null
    urlMatrix = @()
    hostTextMatrix = @()
}}
try {{
    $result.argumentListBefore = @(New-R3ArgumentList -Phase 'before' -StatePath 'STATE' -BaseUrl 'http://127.0.0.1:8600')
    $result.argumentListAfter = @(New-R3ArgumentList -Phase 'after' -StatePath 'STATE' -ReportPath 'REPORT')
    $result.evidenceRootWindows = Get-R3DefaultEvidenceRoot -LocalAppData 'C:\\Users\\probe\\AppData\\Local'
    $result.evidenceRootEmpty = Get-R3DefaultEvidenceRoot -LocalAppData ''
    $result.evidenceRootBlank = Get-R3DefaultEvidenceRoot -LocalAppData '   '
    $matrix = @()
    foreach ($case in @({cases})) {{
        $target = ConvertTo-R3LoopbackTarget -Url $case
        $entry = [ordered]@{{ url = $case; allowed = ($null -ne $target); text = '' }}
        if ($null -ne $target) {{ $entry.text = $target.Text }}
        $matrix += $entry
    }}
    $result.urlMatrix = $matrix
    $hosts = @()
    foreach ($case in @({hostCases})) {{
        $canonical = ConvertTo-R3LoopbackHostText -HostText $case
        $entry = [ordered]@{{ host = $case; canonical = '' }}
        if ($null -ne $canonical) {{ $entry.canonical = $canonical }}
        $hosts += $entry
    }}
    $result.hostTextMatrix = $hosts
}} catch {{
    $result.harnessError = $_.Exception.Message
}}
[System.IO.File]::WriteAllText($OutPath, ($result | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
"""


def _quote_literals(values):
    return ", ".join("'" + value.replace("'", "''") + "'" for value in values)


def _behavior_probe_source():
    definitions = "\n\n".join(_extract_function(name)
                              for name in PURE_FUNCTIONS)
    return _BEHAVIOR_PROBE_HEAD.format(
        definitions=definitions,
        cases=_quote_literals(url for url, _allowed in URL_MATRIX),
        hostCases=_quote_literals(text for text, _canonical in HOST_TEXT_MATRIX))


@pytest.fixture(scope="module")
def probes(tmp_path_factory):
    """每个可用解释器调用一次脚本内的纯函数；无解释器时返回空字典。"""
    interpreters = _powershell_interpreters()
    if not interpreters:
        return {}
    root = tmp_path_factory.mktemp("zw012-behavior-probe")
    probe = root / "behavior-probe.ps1"
    probe.write_text(_behavior_probe_source(), encoding="utf-8")
    results = {}
    for name, executable in interpreters:
        out = root / (name + "-probe.json")
        code, stdout, stderr = _run(
            [executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
             "Bypass", "-File", str(probe), str(out)], cwd=root)
        payload = json.loads(out.read_text(encoding="utf-8")) \
            if out.exists() else None
        results[name] = {"exit_code": code, "stdout": stdout,
                         "stderr": stderr, "payload": payload}
    return results


def _payload(probes, name):
    result = probes[name]
    assert result["payload"] is not None, (name, result["stderr"])
    assert result["payload"]["harnessError"] is None, \
        (name, result["payload"]["harnessError"])
    return result["payload"]


def test_argument_order_is_exact_for_both_phases(probes):
    expected_before = ["-m", MODULE, "before", "--state", "STATE",
                       "--base-url", DEFAULT_BASE_URL]
    expected_after = ["-m", MODULE, "after", "--state", "STATE",
                      "--report", "REPORT"]
    if not probes:
        helper = _extract_function("New-R3ArgumentList")
        assert ("$arguments = @('-m', $ModuleName, $Phase, '--state', "
                "$StatePath)") in helper
        assert "$arguments += @('--report', $ReportPath)" in helper
        assert "$arguments += @('--base-url', $BaseUrl)" in helper
        return
    for name in probes:
        payload = _payload(probes, name)
        assert payload["argumentListBefore"] == expected_before, name
        assert payload["argumentListAfter"] == expected_after, name


def test_default_evidence_root_follows_localappdata(probes):
    if not probes:
        helper = _extract_function("Get-R3DefaultEvidenceRoot")
        assert ("Join-Path (Join-Path $LocalAppData.Trim() 'semantic-camera') "
                "'acceptance'") in helper
        assert "IsNullOrWhiteSpace" in helper
        return
    for name in probes:
        payload = _payload(probes, name)
        assert _slash(payload["evidenceRootWindows"]) == \
            "C:/Users/probe/AppData/Local/semantic-camera/acceptance", name
        assert payload["evidenceRootEmpty"] is None, name
        assert payload["evidenceRootBlank"] is None, name


def test_loopback_url_allow_reject_matrix(probes):
    if not probes:
        target = _extract_function("ConvertTo-R3LoopbackTarget")
        assert "$allowedHosts = @('127.0.0.1', 'localhost', '::1')" in target
        assert "$uri.Scheme -ne 'http'" in target
        assert "[string]::IsNullOrEmpty($uri.UserInfo)" in target
        assert "$uri.AbsolutePath -ne '/'" in target
        assert "[string]::IsNullOrEmpty($uri.Query)" in target
        assert "[string]::IsNullOrEmpty($uri.Fragment)" in target
        assert "$port -lt 1 -or $port -gt 65535" in target
        assert "$portText -notmatch '^[0-9]{1,5}$'" in target
        # IPv6 主机文本先归一化再进允许清单，重建时只补一对方括号
        assert "$hostText = ConvertTo-R3LoopbackHostText -HostText $uri.Host" in target
        assert "$allowedHosts -notcontains $hostText" in target
        assert "$canonicalHost = '[' + $canonicalHost + ']'" in target
        # 归一化自身只认“全零组 + 末尾 1”：其余拼写一律 $null，绝不放宽允许清单
        helper = _extract_function("ConvertTo-R3LoopbackHostText")
        assert "$text.StartsWith('[')" in helper and "$text.EndsWith(']')" in helper
        assert "$groups = $text.Split(':')" in helper
        assert "$group = $groups[$index].TrimStart('0')" in helper
        assert "if ($group -ne '1') { return $null }" in helper
        # 拒绝项不可能被静态兜底漏掉：矩阵本身必须声明为非空
        assert sum(1 for _url, allowed in URL_MATRIX if allowed) >= 5
        assert sum(1 for _url, allowed in URL_MATRIX if not allowed) >= 10
        # 允许与拒绝两侧都必须有 IPv6 样本，否则方括号归一化根本没被矩阵覆盖
        assert sum(1 for url, allowed in URL_MATRIX if allowed and "[" in url) >= 3
        assert sum(1 for url, allowed in URL_MATRIX if not allowed and "[" in url) >= 3
        return
    for name in probes:
        payload = _payload(probes, name)
        actual = {entry["url"]: entry["allowed"]
                  for entry in payload["urlMatrix"]}
        assert set(actual) == {url for url, _allowed in URL_MATRIX}
        for url, allowed in URL_MATRIX:
            assert actual[url] is allowed, (name, url)
        # 每个允许项都必须有精确的规范化文本期望，不许只靠“以 http:// 开头”
        assert set(CANONICAL_ALLOWED_TEXT) | set(CASE_INSENSITIVE_ALLOWED_TEXT) == \
            {url for url, allowed in URL_MATRIX if allowed}
        texts = {entry["url"]: entry["text"] for entry in payload["urlMatrix"]}
        for url, expected in CANONICAL_ALLOWED_TEXT.items():
            assert texts[url] == expected, (name, url, texts[url])
        for url, expected in CASE_INSENSITIVE_ALLOWED_TEXT.items():
            assert texts[url].lower() == expected, (name, url, texts[url])
        for entry in payload["urlMatrix"]:
            if entry["allowed"]:
                # 交给驱动的必须是规范化后的地址：http + 回环主机 + 显式端口
                assert entry["text"].startswith("http://"), entry
                # IPv6 恰好一对方括号（5.1 的 '[::1]' 绝不能变成 '[[::1]]'）
                assert entry["text"].count("[") == entry["text"].count("]") <= 1, entry
                assert "?token" not in entry["text"], entry
                assert "secret" not in entry["text"], entry


def test_ipv6_loopback_host_text_is_normalized_fail_closed(probes):
    """主机文本归一化：5.1 的 '[::1]' 与扩展写法都归一化为 '::1'，其余一律拒绝。"""
    if not probes:
        helper = _extract_function("ConvertTo-R3LoopbackHostText")
        assert helper.startswith("function ConvertTo-R3LoopbackHostText")
        assert "IsNullOrWhiteSpace" in helper
        assert "$text.Length -ge 2 -and $text.StartsWith('[')" in helper
        assert "$groups = $text.Split(':')" in helper
        assert "$group = $groups[$index].TrimStart('0')" in helper
        assert "if ($group -ne '1') { return $null }" in helper
        assert "return '::1'" in helper
        for canonical in ("127.0.0.1", "localhost"):
            assert "'" + canonical + "'" in helper
        # 归一化函数绝不调用任何 IP/网络 API（只按文本判定）
        assert "IPAddress" not in helper
        return
    for name in probes:
        payload = _payload(probes, name)
        actual = {entry["host"]: entry["canonical"]
                  for entry in payload["hostTextMatrix"]}
        assert set(actual) == {text for text, _canonical in HOST_TEXT_MATRIX}
        for text, canonical in HOST_TEXT_MATRIX:
            assert actual[text] == (canonical or ""), (name, text, actual[text])


# ---------- 4. 真实进程行为（装有 PowerShell 时执行，否则退化为静态契约） ----------

def _evidence_case(tmp_path, name="evidence"):
    root = tmp_path / name
    root.mkdir()
    return root


def _child_env():
    """显式交给包装脚本的子进程环境：仓库根**前置**到已有的 `PYTHONPATH`（保留原值）。

    包装脚本把这套环境原样转交给 Python 子进程。只有仓库根在 import 路径上，任意解释器
    才能在任意 cwd（用例自己的临时证据目录）下真实导入 `scam.win11_r3_acceptance`，而不必
    先把本项目装进那个解释器——这正是不用假驱动也能稳定拿到驱动自身结构化前置结果的前提。
    其余变量一律从当前进程继承（`SystemRoot`/`PATH` 等，Windows 上不可缺）。
    """
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (str(REPO) + os.pathsep + existing) if existing \
        else str(REPO)
    return env


def _expected_after_refusal():
    """`{}` 状态文件下真实驱动必然写出的结构化前置失败：``(错误码, 错误文本标记)``。

    R3 驱动的第一道门禁是**精确平台**：非 win32 主机上它必须先以 ``unsafe_platform`` 拒绝，
    固定 schema 校验在那台主机上不可达——这是驱动的既有语义，不是测试放宽。验收主机
    （win32）上，状态文件的固定 schema 校验就是真实撞上的那道门禁。标记按 `_compact` 口径
    给出（已去掉空白）。
    """
    if sys.platform == "win32":
        return "state_unreadable", "state:schema"
    return "unsafe_platform", "platform:"


def _compact(text):
    """去掉全部空白后的子进程输出，用于断言驱动的结构化失败文档。

    Windows PowerShell 5.1 会把原生 stderr 折行并加行首前缀（例如 `python.exe : `），
    PowerShell 7 则原样透传；这些都只发生在空白处。驱动写下的 JSON 只有 `", "` 与 `": "`
    两种分隔，因此比较前把两侧空白一律去掉：断言既不依赖「哪条流收到它」，也不依赖折行
    宽度，同时仍然按 JSON 的键值结构判定（不是扫描自由文本）。
    """
    return re.sub(r"\s+", "", text)


def test_runner_refuses_unsafe_urls_without_invoking_python(tmp_path):
    interpreters = _powershell_interpreters()
    if not interpreters:
        _no_powershell_fallback()
        return
    for index, url in enumerate(EXECUTED_REFUSAL_URLS):
        root = _evidence_case(tmp_path, "refuse-%d" % index)
        code, out, err = _run_runner(
            interpreters[0][1],
            ["-Phase", "Before", "-BaseUrl", url, "-EvidenceRoot", str(root),
             "-PythonCommand", str(root / "no-such-python.exe")],
            cwd=tmp_path)
        assert code == REFUSAL_EXIT, (url, code, out, err)
        assert "unsafe_workbench" in out, (url, out)
        assert "loopback-ok" not in out, (url, out)
        assert "secret" not in out, (url, out)
        assert "-BaseUrl" in out, (url, out)
        assert not (root / STATE_NAME).exists(), url


def test_runner_accepts_loopback_and_stops_at_the_interpreter_gate(tmp_path):
    interpreters = _powershell_interpreters()
    if not interpreters:
        _no_powershell_fallback()
        return
    cases = ((DEFAULT_BASE_URL, "http://127.0.0.1:8600"),
             ("http://localhost:8600", "http://localhost:8600"),
             # PS 5.1 的 Uri.Host 带方括号，交给驱动的必须是恰好一对方括号的规范地址
             ("http://[::1]:8600", "http://[::1]:8600"),
             ("HTTP://[::1]:8600/", "http://[::1]:8600"))
    for index, (url, expected) in enumerate(cases):
        root = _evidence_case(tmp_path, "accept-%d" % index)
        code, out, err = _run_runner(
            interpreters[0][1],
            ["-Phase", "Before", "-BaseUrl", url, "-EvidenceRoot", str(root),
             "-PythonCommand", str(root / "no-such-python.exe")],
            cwd=tmp_path)
        assert "unsafe_workbench" not in out, (url, out)
        # 真实进程里打印的就是规范化重建后的地址（不是操作者原文）
        assert "loopback-ok " + expected in out, (url, out)
        # 通过地址门禁后停在解释器门禁：既证明地址被接受，也证明 Python 未被调用
        assert code == REFUSAL_EXIT, (url, code, out)
        assert "python_missing" in out, (url, out)
        assert "exit-code=" not in out, (url, out)
        assert not (root / STATE_NAME).exists(), url


def test_runner_default_evidence_root_uses_localappdata(tmp_path):
    interpreters = _powershell_interpreters()
    if not interpreters:
        _no_powershell_fallback()
        assert "Get-R3DefaultEvidenceRoot -LocalAppData $localAppData" in SOURCE
        return
    local = tmp_path / "localappdata"
    local.mkdir()
    env = dict(os.environ)
    env["LOCALAPPDATA"] = str(local)
    code, out, err = _run_runner(
        interpreters[0][1],
        ["-Phase", "Before", "-PythonCommand",
         str(tmp_path / "no-such-python.exe")],
        cwd=tmp_path, env=env)
    expected = os.path.join(str(local), "semantic-camera", "acceptance",
                            STATE_NAME)
    assert code == REFUSAL_EXIT, (code, out, err)
    assert _slash(expected).lower() in _slash(out).lower(), (expected, out)
    assert "python_missing" in out, out

    env_without = dict(os.environ)
    env_without.pop("LOCALAPPDATA", None)
    code, out, err = _run_runner(
        interpreters[0][1],
        ["-Phase", "Before", "-PythonCommand",
         str(tmp_path / "no-such-python.exe")],
        cwd=tmp_path, env=env_without)
    assert code == REFUSAL_EXIT, (code, out, err)
    assert "localappdata_missing" in out, out
    assert "LOCALAPPDATA" in out and "-EvidenceRoot" in out, out
    assert "python_missing" not in out, out


def test_runner_refuses_existing_artifacts_before_python(tmp_path):
    interpreters = _powershell_interpreters()
    if not interpreters:
        _no_powershell_fallback()
        return
    executable = interpreters[0][1]

    root = _evidence_case(tmp_path, "clobber-state")
    state = root / STATE_NAME
    state.write_text("{}", encoding="utf-8")
    code, out, err = _run_runner(
        executable,
        ["-Phase", "Before", "-EvidenceRoot", str(root), "-PythonCommand",
         str(tmp_path / "no-such-python.exe")],
        cwd=tmp_path)
    assert code == REFUSAL_EXIT, (code, out, err)
    assert "state_exists" in out, out
    assert "python_missing" not in out, out
    assert "exit-code=" not in out, out
    assert state.read_text(encoding="utf-8") == "{}"

    root = _evidence_case(tmp_path, "clobber-report")
    (root / STATE_NAME).write_text("{}", encoding="utf-8")
    report = root / REPORT_NAME
    report.write_text("{}", encoding="utf-8")
    code, out, err = _run_runner(
        executable,
        ["-Phase", "After", "-EvidenceRoot", str(root), "-PythonCommand",
         str(tmp_path / "no-such-python.exe")],
        cwd=tmp_path)
    assert code == REFUSAL_EXIT, (code, out, err)
    assert "report_exists" in out, out
    assert "python_missing" not in out, out
    assert report.read_text(encoding="utf-8") == "{}"

    # 状态存在、报告不存在：覆盖门禁放行，停在解释器门禁
    root = _evidence_case(tmp_path, "after-ready")
    (root / STATE_NAME).write_text("{}", encoding="utf-8")
    code, out, err = _run_runner(
        executable,
        ["-Phase", "After", "-EvidenceRoot", str(root), "-PythonCommand",
         str(tmp_path / "no-such-python.exe")],
        cwd=tmp_path)
    assert code == REFUSAL_EXIT, (code, out, err)
    assert "python_missing" in out, out
    assert "loopback-ok" not in out, out  # After 不校验地址，也不接受 -BaseUrl


def test_runner_refuses_missing_state_and_base_url_for_after(tmp_path):
    interpreters = _powershell_interpreters()
    if not interpreters:
        _no_powershell_fallback()
        return
    executable = interpreters[0][1]

    root = _evidence_case(tmp_path, "after-no-state")
    code, out, err = _run_runner(
        executable,
        ["-Phase", "After", "-EvidenceRoot", str(root), "-PythonCommand",
         str(tmp_path / "no-such-python.exe")],
        cwd=tmp_path)
    assert code == REFUSAL_EXIT, (code, out, err)
    assert "state_missing" in out, out
    assert sorted(path.name for path in root.iterdir()) == []

    code, out, err = _run_runner(
        executable,
        ["-Phase", "After", "-BaseUrl", DEFAULT_BASE_URL, "-EvidenceRoot",
         str(root), "-PythonCommand", str(tmp_path / "no-such-python.exe")],
        cwd=tmp_path)
    assert code == REFUSAL_EXIT, (code, out, err)
    assert "base_url_not_applicable" in out, out


def test_runner_passes_the_driver_exit_code_through(tmp_path):
    """退出码与驱动的结构化失败文档（JSON，写 stderr）的透传，用真实驱动证明（`C-062`）。

    恢复用 `sys.executable` 真实执行 `-m scam.win11_r3_acceptance`（ZW-016 的 `.cmd` 假驱动
    在 Windows 上不等价：经 `cmd.exe` 转交的参数不形成原生 Python 的参数边界，只记到 `-m`，
    记录文件还会落在被测目录里污染断言，已删除）。子进程环境把仓库根**前置**到 `PYTHONPATH`，
    于是从任意临时 cwd 都能导入真实驱动，也不再依赖本机是否安装过本项目。状态文件是 `{}`：
    覆盖门禁放行、固定 schema 校验必然拒绝，驱动写下结构化失败文档并以 2 结束；包装脚本自己
    只可能以 3 拒绝，因此取到 2 就同时证明子进程真的跑过且退出码被原样透传。
    """
    interpreters = _powershell_interpreters()
    if not interpreters:
        _no_powershell_fallback()
        return
    root = _evidence_case(tmp_path, "passthrough")
    state = root / STATE_NAME
    # 空对象：只满足“存在”这一道包装脚本门禁，驱动随后在固定 schema 处结构化拒绝
    state.write_text("{}", encoding="utf-8")
    code, out, err = _run_runner(
        interpreters[0][1],
        ["-Phase", "After", "-EvidenceRoot", str(root),
         "-PythonCommand", sys.executable],
        cwd=tmp_path, env=_child_env())
    combined = out + err
    assert code == DRIVER_PRECONDITION_EXIT, (code, out, err)
    assert "exit-code=2" in out, out
    # 真实驱动写 stderr 的结构化失败文档必须原样转发：按 JSON 键值结构断言（`_compact`
    # 只吸收 PS 5.1 的折行与行首前缀，不改变键值本身）
    document = _compact(combined)
    error_code, marker = _expected_after_refusal()
    assert '"phase":"after"' in document, (out, err)
    assert '"ok":false' in document, (out, err)
    assert '"schema":"' + REPORT_SCHEMA + '"' in document, (out, err)
    assert '"error_code":"' + error_code + '"' in document, (out, err)
    assert marker in document, (out, err)
    # 不得被吞掉、不得升级成包装脚本的内部错误，也不得打印“下一步”（那是 Before 成功专属）
    assert "internal_error" not in combined, (out, err)
    assert "next-step" not in out, out
    # 前置门禁失败即零产物：状态文件内容不变，证据目录里没有报告或任何新增
    assert state.read_text(encoding="utf-8") == "{}"
    assert not (root / REPORT_NAME).exists(), (code, out)
    assert sorted(path.name for path in root.iterdir()) == [STATE_NAME], (code, out)


def test_runner_accepts_a_dash_leading_evidence_directory(tmp_path):
    """以 '-' 开头的证据目录名必须仍是路径值：既不能被当成参数，也不能被改写。

    走的是真实进程：After 用真实驱动（`sys.executable` + 前置仓库根的 `PYTHONPATH`，见
    `C-062`）越过解释器门禁，因此第 7 段的目录创建真的执行了；驱动在 `{}` 状态文件的固定
    schema 处结构化失败并以 2 结束，包装脚本只可能透传该退出码，所以取到 2 就同时证明目录
    创建与后续调用都正常。目录名以 '-' 开头是这里唯一与其它用例不同的输入。
    """
    interpreters = _powershell_interpreters()
    if not interpreters:
        _no_powershell_fallback()
        assert "New-Item -Path $resolvedEvidenceRoot -ItemType Directory -Force" in SOURCE
        return
    parent = tmp_path / "dash"
    parent.mkdir()
    dash_root = parent / "-evidence"     # 目录名以 '-' 开头
    state = parent / STATE_NAME          # 状态文件放在普通目录里，先满足覆盖门禁
    state.write_text("{}", encoding="utf-8")
    code, out, err = _run_runner(
        interpreters[0][1],
        ["-Phase", "After", "-EvidenceRoot", str(dash_root),
         "-StateFile", str(state), "-PythonCommand", sys.executable],
        cwd=tmp_path, env=_child_env())
    combined = out + err
    # 目录按字面路径创建：没有多出别的目录，也没有被当成参数而创建到别处
    assert dash_root.is_dir(), (code, out, err)
    assert sorted(path.name for path in parent.iterdir()) == \
        sorted(["-evidence", STATE_NAME]), (code, out)
    # 证据目录只被创建、没有被写入任何产物（驱动在前置门禁处就退出了，报告无从产生）
    assert sorted(path.name for path in dash_root.iterdir()) == [], (code, out)
    assert not (dash_root / REPORT_NAME).exists(), (code, out)
    # 破折号目录仍然是路径值：包装脚本打印的产物路径正是在它下面逐字拼出来的
    assert _slash(dash_root / REPORT_NAME).lower() in _slash(out).lower(), out
    assert _slash(dash_root).lower() in _slash(out).lower(), out
    # 驱动真的跑过：结构化失败文档原样转发、退出码透传为 2，且不是包装脚本的内部错误
    assert code == DRIVER_PRECONDITION_EXIT, (code, out, err)
    assert "exit-code=2" in out, out
    document = _compact(combined)
    error_code, marker = _expected_after_refusal()
    assert '"phase":"after"' in document, (out, err)
    assert '"error_code":"' + error_code + '"' in document, (out, err)
    assert marker in document, (out, err)
    assert "internal_error" not in combined, (out, err)
    assert state.read_text(encoding="utf-8") == "{}"


def test_runner_rejects_invalid_phase(tmp_path):
    interpreters = _powershell_interpreters()
    if not interpreters:
        _no_powershell_fallback()
        return
    root = _evidence_case(tmp_path, "phase")
    for value in ("Restart", "before-after", "Before After"):
        code, out, err = _run_runner(
            interpreters[0][1],
            ["-Phase", value, "-EvidenceRoot", str(root)],
            cwd=tmp_path)
        assert code == REFUSAL_EXIT, (value, code, out, err)
        assert "phase_invalid" in out, (value, out)
        assert "exit-code=" not in out, (value, out)
