# -*- coding: utf-8 -*-
"""运行时 hook 自检合同：子模块检查必须 importlib.import_module。

`__import__(name)` 对 "PIL.ImageDraw" 类**子模块路径**返回**顶层包**——
报告的 origin/version 语义错（顶层 ≠ 子模块），且对"父包 __init__ 预挂
同名属性"的形态会假绿。合同：hook 必须用 `importlib.import_module(name)`
使报告 origin=子模块自身 __file__。
"""
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
HOOK = REPO / "packaging" / "runtime_hook_deps.py"


def test_hook_uses_importlib_import_module_for_named_modules():
    src = HOOK.read_text(encoding="utf-8")
    code_lines = [l for l in src.splitlines()
                  if not l.strip().startswith("#")]
    code = "\n".join(code_lines)
    assert "module = __import__(name)" not in code, \
        "hook 仍用 __import__：对子模块路径返回顶层包（C167 更正）"
    assert "module = importlib.import_module(name)" in code


def test_importlib_returns_submodule_not_top_level():
    """行为对照（真实 PIL）：importlib.import_module("PIL.ImageDraw") 返回
    ImageDraw 子模块（__file__ 指向 ImageDraw.py），而 __import__ 返回顶层
    PIL——两者 origin 语义不同，hook 必须报告子模块自身。"""
    import importlib

    top = __import__("PIL.ImageDraw")
    sub = importlib.import_module("PIL.ImageDraw")
    assert top.__name__ == "PIL"                # __import__：顶层
    assert sub.__name__ == "PIL.ImageDraw"      # importlib：子模块
    assert pathlib.Path(sub.__file__).name.lower() == "imagedraw.py"
