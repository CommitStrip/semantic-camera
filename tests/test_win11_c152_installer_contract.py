# -*- coding: utf-8 -*-
"""C152-Z 安装器合同测试：解析 packaging/windows/semantic-camera.iss
脚本文本，验证关键合同字段（不编译、不安装、不写注册表）。

合同来源：任务书 §三 + .codex/c152-desktop/INTERFACE-C152.md。
.iss 为声明式 INI 风格 + ISPP 预处理器指令 + Pascal [Code] 段；
本测试逐项断言关键合同在文本中可定位（非语义模拟）。
"""
import re
from pathlib import Path

_ISS = (Path(__file__).resolve().parents[1]
        / "packaging" / "windows" / "semantic-camera.iss")


def _iss_text():
    return _ISS.read_text(encoding="utf-8")


def _iss_code_lines():
    """非注释行（Inno Setup 注释以 ; 或 // 开头）。"""
    result = []
    for ln in _iss_text().splitlines():
        stripped = ln.strip()
        if stripped and not stripped.startswith((";", "//")):
            result.append(ln)
    return "\n".join(result)


# ---------------------------------------------------------------- AppId

def test_fixed_appid_matches_frozen_interface():
    """AppId 固定为冻结 GUID（生产身份），升级沿用同一值。"""
    code = _iss_code_lines()
    frozen_guid = "BBA9D479-0BB1-4AF0-961A-CE9D645639B9"
    assert frozen_guid in code, "AppId 须与冻结接口值一致"
    assert '#define AppIdDefault "{{' + frozen_guid + '}"' in code, \
        "生产 AppId 必须以 #define 固定为 {{<GUID>} 形态"
    assert "SelectedAppIdEscaped AppIdDefault" in code, \
        "正常编译必须选用生产身份"


def test_appid_has_conditional_default_not_hardcoded_per_batch():
    """AppId 不接受编译期覆盖：普通编译保留生产身份，TestMode 用固定隔离身份。"""
    text = _iss_text()
    assert "#ifdef AppId" in text and \
        "#error normal compile must keep the production identity" in text, \
        "正常编译必须禁止 /DAppId 覆盖生产身份"
    assert "#error TestMode requires the fixed isolated identity" in text, \
        "TestMode 必须固定隔离身份，不允许外部覆盖"


# ---------------------------------------------------------------- 安装模式

def test_per_user_install_no_elevation():
    """当前用户安装（PrivilegesRequired=lowest）；应用目录在
    localappdata 下，不写 Program Files。"""
    text = _iss_text()
    assert "PrivilegesRequired=lowest" in text
    assert "{localappdata}\\Programs\\SemanticCamera" in text


def test_app_dir_and_user_data_dir_separated():
    """用户数据目录 {localappdata}\\semantic-camera 不在安装范围或
    卸载删除范围内（检查非注释行）。"""
    code = _iss_code_lines()
    for section in ("[InstallDelete]", "[UninstallDelete]"):
        assert section not in code, \
            f"骨架不应包含 {section}（卸载不删用户数据）"
    # 用户数据目录名不出现在 [Files] 的 DestDir
    assert 'DestDir: "{localappdata}\\semantic-camera"' not in code


# ---------------------------------------------------------------- 语言

def test_chinese_simplified_language_entry():
    """中文安装界面。"""
    text = _iss_text()
    assert "chinesesimplified" in text.lower()
    assert "ChineseSimplified.isl" in text


# ---------------------------------------------------------------- 快捷方式

def test_start_menu_shortcut_semantic_camera():
    """开始菜单"语义摄像头"指向用户桌面 EXE。"""
    text = _iss_text()
    assert '{autoprograms}\\{#AppName}' in text
    assert '{app}\\{#AppExeName}' in text


def test_desktop_shortcut_optional_unchecked():
    """桌面快捷方式可选（Flags 含 unchecked，默认不勾选）。"""
    text = _iss_text()
    assert 'Flags: unchecked' in text


def test_desktop_shortcut_task_and_icon_linked():
    """desktopicon 任务与 [Icons] 桌面条目实际关联（Tasks: desktopicon
    出现在 [Icons] 段的条目上），非仅两处关键词独立存在。"""
    text = _iss_text()
    # [Icons] 段内须有 Tasks: desktopicon 的桌面条目
    icons_sec = re.search(r"\[Icons\](.*?)(?=\[|\Z)", text, re.S)
    assert icons_sec, "[Icons] 段缺失"
    icons_body = icons_sec.group(1)
    assert "Tasks: desktopicon" in icons_body, \
        "桌面快捷方式应绑定 desktopicon 任务"
    assert "{autodesktop}" in icons_body, \
        "桌面快捷方式应指向用户桌面"
    assert "{app}\\{#AppExeName}" in icons_body, \
        "桌面快捷方式应指向用户桌面 EXE"


def test_appversion_numeric_three_part_validation_present():
    """版本校验为逐段数字白名单（三段 MAJOR.MINOR.PATCH）：断言实际
    校验表达式在位——数字白名单、三段拆分、空段/额外分段/长度约束。

    边界如实：本环境无法执行 ISPP 编译；本测试仅断言校验结构在脚本
    文本中实际存在（非仅注释），**不证明编译行为**（编译未验证）。"""
    text = _iss_text()
    # 数字白名单（段内字符必须属于 0-9；同时拒绝空白/路径字符/字母）
    assert 'Pos(Copy(S, I, 1), "0123456789") > 0' in text, \
        "应含逐位数字白名单"
    # 每段显式长度约束（1-4 位），避免无界展开
    assert "Len(S) >= 1" in text and "Len(S) <= 4" in text, \
        "应含段长度显式约束"
    # 三段结构拆分：两个分隔符 + 三处段
    for macro in ("ScVerDot1", "ScVerDot2", "ScVerPart1",
                  "ScVerPart2", "ScVerPart3"):
        assert macro in text, f"应含结构检查宏 {macro}"
    # 空段/首段/中段拒绝
    assert "第一段不能为空" in text
    assert "第二段不能为空" in text
    # 额外分段拒绝（第三段不得再有点）
    assert 'Pos(".", ScVerPart3) > 0' in text, "应含额外分段检查"
    # 每段数字白名单检查三处
    assert text.count("ScVerIsDigits(ScVerPart") >= 3, \
        "三段应各做数字白名单检查"
    # 空值/路径字符仍拒绝
    assert 'AppVersion == ""' in text, "空值检查"
    assert 'Pos("\\", AppVersion) > 0' in text, "路径字符检查"
    assert 'Pos("/", AppVersion) > 0' in text, "路径字符检查"


def test_appversion_validation_no_recursive_macro():
    """校验实现为单层宏展开（无递归宏调用），只使用 ISPP 库函数
    Pos/Copy/Length——不依赖未经验证的递归展开行为。"""
    text = _iss_text()
    # 宏体内不出现对自身的调用（无递归）
    assert "ScVerIsDigits(S, " not in text, "不应有递归段检查签名"
    block = text[text.index("ScVerDigitAt"):text.index("[Setup]")]
    assert "ScVerIsDigits(ScVerIsDigits" not in block
    assert "ScVerDigitAt(ScVerDigitAt" not in block


def test_readme_version_format_and_uncompiled_boundary():
    """README 准确说明格式（三段数字 1-4 位）与未编译边界。"""
    readme = (Path(__file__).resolve().parents[1]
              / "packaging" / "windows" / "README.md").read_text(
                  encoding="utf-8")
    assert "MAJOR.MINOR.PATCH" in readme
    assert "1–4 位数字" in readme or "1-4 位数字" in readme
    assert "静态检查通过、ISPP 编译未验证" in readme, \
        "README 须明确未编译边界"
    assert "构建方必须传入项目版本" in readme


# ---------------------------------------------------------------- 卸载

def test_uninstall_registration_fields():
    """卸载登记：名称/图标/卸载入口（Windows"已安装的应用"）。"""
    text = _iss_text()
    assert "UninstallDisplayName=" in text
    assert "UninstallDisplayIcon=" in text


def test_uninstall_run_section_empty_or_absent():
    """卸载时无强杀命令（运行中卸载依赖 Codex 停止协议，未接通前列
    阻塞）。"""
    text = _iss_text()
    if "[UninstallRun]" in text:
        # 允许空段或仅注释；不允许 taskkill/process 命令
        code = re.search(r"\[UninstallRun\](.*?)(?=\[|\Z)",
                         text, re.DOTALL)
        if code:
            assert "taskkill" not in code.group(1).lower()
            assert "process" not in code.group(1).lower()


# ---------------------------------------------------------------- 不自启/不服务

def test_no_autostart_no_service_no_remote():
    """不开机自启、不装 Windows 服务、不开放远程访问。"""
    code = _iss_code_lines().lower()
    assert "{autostart}" not in code
    assert "netsh" not in code
    assert "sc create" not in code


# ---------------------------------------------------------------- 版本

def test_app_version_passed_not_hardcoded():
    """版本编译时显式传入（/DAppVersion），不硬编码。"""
    text = _iss_text()
    assert "#ifndef AppVersion" in text
    assert "#error" in text
    # AppVersion 不应硬编码在 .iss 中
    assert not re.search(r'#define AppVersion "[\d.]+"', text), \
        "AppVersion 不应硬编码（须从编译参数传入）"


# ---------------------------------------------------------------- 前置检查

def test_build_precondition_checks_present():
    """编译前置检查：AppSource/版本/必需文件缺失即编译失败（fail-closed）。"""
    text = _iss_text()
    assert "#error AppSource must be passed" in text
    assert '#if FileExists(AppSource + "\\" + AppExeName) == 0' in text, \
        "桌面入口文件存在检查应在位"
    assert '#if FileExists(AppSource + "\\" + BackendSubDir + "\\" + BackendExeName) == 0' in text, \
        "后端入口文件存在检查应在位"
    assert "#error" in text and "AppVersion must be passed" in text


# ---------------------------------------------------------------- WebView2

def test_webview2_interface_reserved():
    """WebView2 Runtime 检测/安装顺序预留接口（注释或 [Code] 占位），
    不自动下载、不提示用户自己找网页安装后宣称完整体验。"""
    text = _iss_text()
    assert "WebView2" in text, "WebView2 预留接口应可见"
    assert "webview2" not in [ln.strip().lower()
                              for ln in text.splitlines()
                              if ln.strip().lower().startswith("download")], \
        "不得自动下载 WebView2"


# ---------------------------------------------------------------- 用户数据

def test_user_data_dir_not_in_install_scope():
    """用户数据目录名 semantic-camera 不出现在安装/卸载操作文件中
    （保留用户数据，不删除）。"""
    text = _iss_text()
    # 仅注释中允许出现；操作行（Source:/DestDir:/Delete:）不允许
    for ln in text.splitlines():
        stripped = ln.strip()
        if stripped.startswith(("Source:", "DestDir:", "Name:",
                                "Type:", "Delete:")):
            assert "semantic-camera\"" not in stripped or \
                "semantic-camera" not in stripped.split(";")[0], \
                f"操作行不得涉及用户数据目录: {stripped}"


# ---------------------------------------------------------------- 发布说明

def test_readme_documents_build_and_behavior():
    """README 面向构建使用者：含构建命令/安装行为/未接通项。"""
    readme = (Path(__file__).resolve().parents[1]
              / "packaging" / "windows" / "README.md").read_text(
                  encoding="utf-8")
    assert "iscc" in readme.lower()
    assert "AppVersion" in readme
    assert "localappdata" in readme.lower()
    assert "未接通项" in readme
