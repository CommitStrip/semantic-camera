"""运行时旁置 hook：只加 `_deps/` 到 sys.path；不扩展 models 代码搜索。

离线环境变量只声明"不主动联网"，**不是**网络硬隔离。
`SEMANTIC_CAMERA_SELFCHECK=1` 时在**冻进程内**真实 import 依赖并打印 JSON
（不含权重加载），供构建器记录 origin/version；导入失败原样抛出，绝不吞。

旧变量名 `C161_SELFCHECK` / `C161_SELFCHECK_MODULES` 继续被识别（已发布
构建链的兼容别名），但报告与文档使用 `SEMANTIC_CAMERA_*` 命名。
"""
import json
import os
import pathlib
import re
import sys

_root = os.path.dirname(os.path.abspath(sys.executable))
_deps = os.path.join(_root, "_deps")
if os.path.isdir(_deps) and _deps not in sys.path:
    sys.path.insert(0, _deps)
_stdlib = os.path.join(_deps, "stdlib")
if os.path.isdir(_stdlib) and _stdlib not in sys.path:
    sys.path.append(_stdlib)   # stdlib 承载：frozen importer 优先，仅补未冻结模块
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("SEMANTIC_CAMERA_FULL_BACKEND", "1")


def _flag(name: str) -> str:
    """读取开关：新名优先，旧名作为兼容别名。"""
    value = os.environ.get(name)
    if value is None and name.startswith("SEMANTIC_CAMERA_"):
        value = os.environ.get("C161_" + name[len("SEMANTIC_CAMERA_"):])
    return value or ""


if _flag("SEMANTIC_CAMERA_SELFCHECK") == "1":
    report = {"hook": "semantic-camera/runtime_hook_deps"}
    # 检查集 = 基础五 ∪ 显式 requested（去重）；基础五**不可**被自定义
    # 列表绕过，requested 任一项失败同样计入 all_ok/退出码。空串与非法
    # 标识符路径**可审计拒绝**（problems 落盘，不静默丢弃）。
    BASE_REQUIRED = ("torch", "transformers", "tokenizers", "safetensors",
                     "onnxruntime")
    problems = []
    requested_raw = _flag("SEMANTIC_CAMERA_SELFCHECK_MODULES")
    requested = []
    for token in requested_raw.split(","):
        token = token.strip()
        if not token:
            if requested_raw.strip():
                problems.append("empty_module_name")   # 空段：可审计拒绝
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", token):
            problems.append("invalid_module_name:" + token)
            continue
        requested.append(token)
    required_all = list(dict.fromkeys(list(BASE_REQUIRED) + requested))
    report["problems"] = problems
    report["requested_modules"] = requested
    for name in required_all:
        try:
            # importlib.import_module —— 子模块路径（如 PIL.ImageDraw）返回
            # **子模块本身**（origin=子模块 __file__）；`__import__(name)`
            # 会返回顶层包，origin/version 语义错。
            import importlib
            module = importlib.import_module(name)
            report[name] = {"ok": True,
                            "version": getattr(module, "__version__", None),
                            "origin": getattr(module, "__file__", None)}
        except Exception as exc:
            report[name] = {"ok": False, "error": type(exc).__name__ + ": " + str(exc)[:200]}
    import hashlib
    try:
        report["exe_sha256"] = hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest()
    except Exception as exc:
        report["exe_sha256"] = None
        report["exe_hash_error"] = type(exc).__name__
    all_ok = bool(not problems and all(
        report.get(m, {}).get("ok") is True for m in required_all))
    report["all_ok"] = all_ok
    print(json.dumps(report, ensure_ascii=False))
    sys.stdout.flush()
    sys.exit(0 if all_ok else 1)
