"""Pure, redacted Chinese text formatting for config-check reports."""

from __future__ import annotations

from typing import Any


SCHEMA = "scam.win11-config-check/v1"
UNKNOWN = "诊断结果格式无效，无法提供恢复指引。"
PASS_HEADER = "配置静态检查通过。此结果不代表摄像头、模型或运行时已验证。"
FAIL_HEADER = "配置静态检查未通过。"
GENERIC_FAILURE = "发现未识别的问题，请使用完整诊断报告排查。"


GUIDANCE = {
    "config_not_absolute": "配置文件路径必须是绝对路径。",
    "config_reparse_point": "配置文件不能位于重解析点。",
    "config_missing": "找不到配置文件，请确认文件存在。",
    "config_invalid_json": "配置文件不是有效 JSON。",
    "config_too_large": "配置文件过大，请使用不超过 4 MiB 的配置文件。",
    "config_structure_invalid": "配置文件结构无效。",
    "config_resolution_failed": "配置无法解析，请检查配置结构。",
    "venue_invalid": "配置校验未通过。",
    "install_root_required": "此配置需要显式安装根目录。",
    "install_root_not_absolute": "安装根目录必须是绝对路径。",
    "install_root_reparse_point": "安装根目录不能位于重解析点。",
    "install_root_missing": "找不到安装根目录。",
    "l1_enabled_invalid": "L1 启用开关必须是布尔值。",
    "l1_model_missing": "确认 L1 模型文件存在。",
    "l1_model_not_absolute": "L1 模型路径必须是绝对路径。",
    "l1_model_reparse_point": "L1 模型路径不能位于重解析点。",
    "l2_enabled_invalid": "L2 启用开关必须是布尔值。",
    "l2_structure_invalid": "L2 配置结构无效。",
    "l2_repo_missing": "确认 L2 代码目录存在。",
    "l2_repo_not_absolute": "L2 代码目录必须是绝对路径。",
    "l2_repo_reparse_point": "L2 代码目录不能位于重解析点。",
    "l2_checkpoint_missing": "确认 L2 检查点文件存在。",
    "l2_checkpoint_not_absolute": "L2 检查点路径必须是绝对路径。",
    "l2_checkpoint_reparse_point": "L2 检查点路径不能位于重解析点。",
    "l3_enabled_invalid": "L3 启用开关必须是布尔值。",
    "l3_model_missing": "确认本地 L3 模型目录存在。",
    "l3_model_not_absolute": "本地 L3 模型路径必须是绝对路径。",
    "l3_model_reparse_point": "本地 L3 模型路径不能位于重解析点。",
    "l3_consent_missing": "使用云端理解前请明确同意图片外发。",
    "l3_vision_not_declared": "请明确声明云端模型支持图片。",
    "l3_key_env_invalid": "请填写合法的密钥环境变量名称，不要填写密钥值。",
    "usage_error": "命令行参数无效，请使用完整诊断命令。",
    "internal_error": "诊断工具发生内部错误，请重新检查配置。",
}


def _valid_issue(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("code"), str)
        and isinstance(value.get("role"), str)
    )


def _valid_report(report: Any) -> bool:
    if not isinstance(report, dict):
        return False
    if report.get("schema") != SCHEMA:
        return False
    if not isinstance(report.get("checks"), dict):
        return False
    if report.get("verdict") not in ("static_config_pass", "failed"):
        return False
    if report.get("runtime_verified") is not False:
        return False
    if report.get("release_ready") is not False:
        return False
    issues = report.get("issues")
    if not isinstance(issues, list) or not all(_valid_issue(item) for item in issues):
        return False
    if report["verdict"] == "static_config_pass" and issues:
        return False
    if report["verdict"] == "failed" and not issues:
        return False
    return True


def format_summary(report: Any) -> str:
    """Return bounded, constant Chinese guidance without echoing report values."""
    if not _valid_report(report):
        return UNKNOWN
    if report["verdict"] == "static_config_pass":
        return PASS_HEADER

    lines = [FAIL_HEADER]
    seen: set[str] = set()
    for issue in report["issues"][:8]:
        code = issue["code"]
        if code in seen:
            continue
        seen.add(code)
        lines.append(GUIDANCE.get(code, GENERIC_FAILURE))
    return "\n".join(lines)
