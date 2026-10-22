# -*- coding: utf-8 -*-
"""C168-Z hook required 并集合同测试（真实子进程跑 hook 文件；mock=PYTHONPATH stub）。

先红后绿合同（主协调批复）：
- 基础五 + 显式 requested **去重并集**；基础五不可被自定义列表绕过；
- 任一项失败 ⇒ all_ok=False 且退出码非零（"基础全好但 PIL.ImageDraw 失败"
  必须非零——红例）；
- 严格 bool；空串/非法项可审计拒绝（problems 落盘）。

机制：宿主 python 直接执行 hook 文件（五基础用宿主已装真包；requested 子模块
经 PYTHONPATH stub 目录注入 ImportError——PYTHONPATH 对宿主 python 有效）。
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

pytestmark = pytest.mark.filterwarnings("error")

REPO = pathlib.Path(__file__).resolve().parents[1]
HOOK = REPO / "packaging" / "runtime_hook_deps.py"


@pytest.fixture()
def hook_env(tmp_path):
    """stub 目录：PIL/ImageDraw.py 导入即失败（红例形态）。"""
    stub = tmp_path / "stub"
    (stub / "PIL").mkdir(parents=True)
    (stub / "PIL" / "__init__.py").write_text("", encoding="utf-8")
    (stub / "PIL" / "ImageDraw.py").write_text(
        "raise ImportError('cannot import name ImageDraw from blocked stub')\n",
        encoding="utf-8")
    return stub


def run_hook(tmp_path, hook_env_stub, requested_env):
    env = os.environ.copy()
    if hook_env_stub is not None:
        env["PYTHONPATH"] = str(hook_env_stub)
    env["C161_SELFCHECK"] = "1"
    env["C161_SELFCHECK_MODULES"] = requested_env
    env["PYTHONUTF8"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONHOME", None)
    p = subprocess.run([sys.executable, str(HOOK)], env=env,
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=120)
    lines = (p.stdout or "").strip().splitlines()
    report = json.loads(lines[0]) if lines else {}
    return p.returncode, report


def test_base_five_ok_no_requested_exits_zero(tmp_path):
    rc, report = run_hook(tmp_path, None, "")
    assert rc == 0, report.get("problems")
    assert report["all_ok"] is True
    assert report["requested_modules"] == []
    for m in ("torch", "transformers", "tokenizers", "safetensors",
              "onnxruntime"):
        assert report[m]["ok"] is True, m


def test_base_all_ok_but_requested_submodule_failed_exits_nonzero(
        tmp_path, hook_env):
    """红例（R1 版 exit 0）：基础五全好 + requested PIL.ImageDraw 导入失败
    ⇒ 必须非零 + all_ok=False + 可审计。"""
    rc, report = run_hook(tmp_path, hook_env,
                          "torch,transformers,tokenizers,safetensors,"
                          "onnxruntime,PIL.ImageDraw")
    assert rc != 0, report.get("problems")
    assert report["all_ok"] is False
    assert report["PIL.ImageDraw"]["ok"] is False
    assert report["PIL.ImageDraw"]["error"], report["PIL.ImageDraw"]


def test_base_five_cannot_be_bypassed_by_custom_list(tmp_path):
    """requested 只含非基础模块 → 基础五仍全部被检查并要求 ok。"""
    stub = tmp_path / "stub-ok"
    (stub / "MyStub").mkdir(parents=True)
    (stub / "MyStub" / "__init__.py").write_text("", encoding="utf-8")
    rc, report = run_hook(tmp_path, stub, "MyStub")
    assert rc == 0, report.get("problems")
    for m in ("torch", "transformers", "tokenizers", "safetensors",
              "onnxruntime"):
        assert report[m]["ok"] is True, m
    assert report["MyStub"]["ok"] is True


def test_missing_requested_module_is_audited_and_nonzero(tmp_path):
    rc, report = run_hook(tmp_path, None, "torch,no_such_module_xyz")
    assert rc != 0
    assert report["all_ok"] is False
    assert report["no_such_module_xyz"]["ok"] is False


def test_empty_segment_and_invalid_name_audited(tmp_path):
    rc, report = run_hook(tmp_path, None,
                          "torch,,bad-name,transformers")
    assert rc != 0
    problems = report.get("problems", [])
    assert any("empty_module_name" in p for p in problems), problems
    assert any("invalid_module_name:bad-name" in p for p in problems), problems


def test_strict_bool_semantics():
    src = (REPO / "packaging" / "runtime_hook_deps.py").read_text(
        encoding="utf-8")
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    assert "is True" in code, "hook 必须用严格 bool 判据（ok is True）"
    assert "all_ok = bool(not problems" in code or \
        "all_ok = bool(not problems and" in code or \
        "all_ok = bool(" in code
