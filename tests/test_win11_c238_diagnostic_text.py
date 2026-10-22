from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scam.win11_diagnostic_text import format_summary


def _report(verdict="static_config_pass", issues=None, **extra):
    value = {
        "schema": "scam.win11-config-check/v1",
        "verdict": verdict,
        "issues": [] if issues is None else issues,
        "runtime_verified": False,
        "release_ready": False,
        "checks": {},
    }
    value.update(extra)
    return value


def test_static_pass_is_explicitly_not_runtime_verification():
    text = format_summary(_report())
    assert "配置静态检查通过" in text
    assert "不代表摄像头" in text
    assert "模型" in text
    assert "运行时" in text


def test_known_failure_codes_have_constant_chinese_guidance():
    text = format_summary(_report("failed", [
        {"code": "config_invalid_json", "role": "external_config"},
        {"code": "l3_model_missing", "role": "l3_model"},
        {"code": "l3_consent_missing", "role": "l3_model"},
        {"code": "l2_enabled_invalid", "role": "l2_model"},
    ]))
    assert "配置静态检查未通过" in text
    assert "配置文件不是有效 JSON" in text
    assert "确认本地 L3 模型目录存在" in text
    assert "明确同意图片外发" in text
    assert "启用开关必须是布尔值" in text
    assert "C:" not in text


def test_unknown_code_and_bad_shapes_use_fixed_unknown_text():
    unknown = format_summary(_report("failed", [
        {"code": "some_unknown_code", "role": "external_config"},
    ], candidate_path=r"C:\Users\example\secret"))
    assert "发现未识别的问题" in unknown
    assert "some_unknown_code" not in unknown
    assert "example" not in unknown

    for bad in (
        {"schema": "wrong", "verdict": "failed", "issues": [],
         "runtime_verified": False, "release_ready": False, "checks": {}},
        _report("failed", ["not-a-dict"]),
        _report("failed", [{"code": 123, "role": "external_config"}]),
        _report("failed", [{"code": "config_missing", "role": "external_config"}],
                runtime_verified=True),
    ):
        text = format_summary(bad)
        assert text == "诊断结果格式无效，无法提供恢复指引。"


def test_at_most_eight_issue_lines_and_no_raw_values():
    issues = [
        {"code": f"unknown_{index}", "role": "external_config"}
        for index in range(12)
    ]
    text = format_summary(_report("failed", issues,
                                  source="rtsp://user:password@secret",
                                  api_key="cloud-secret"))
    assert text.count("\n") <= 9
    assert "password" not in text
    assert "cloud-secret" not in text
    assert "unknown_0" not in text
