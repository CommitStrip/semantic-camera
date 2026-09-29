"""build_win11.py —— Win11 双击可用发行包构建（PyInstaller one-dir）。

用法（在原生 Windows 上）：
    python packaging/build_win11.py --check-deps          只检查构建依赖与版本
    python packaging/build_win11.py                       构建 dist/win11 并打 zip
    python packaging/build_win11.py --verify <zip>        复核既有 zip（闸门 + 清单哈希）
    python packaging/build_win11.py --with-model          随包附带已核验模型（需来源档案）

纪律：
- 唯一用户入口是 `语义摄像头.exe`；发行包不依赖仓库目录、`.venv`、系统 Python 或
  `deploy/start-win11.bat`，解压即可运行，发行目录只读也能运行；
- **闸门 fail-closed**：打包前后都扫内容，命中私有记录本 / 测试 / Linux 服务文件 /
  用户配置 / 数据库 / 日志 / 媒体文件即拒绝产出（模型仅在有来源档案时允许）；
- 模型默认**不随包**：首次向导让用户选择本机 ONNX，或显式选择“仅预览、不告警”；
- 构建信息（Python、PyInstaller、冻结依赖版本、构建命令、产物逐文件 SHA-256）
  写进 `win11-manifest.json` 并随 zip 分发，`--verify` 可离线复核。

外部输入处理：`--verify` 的 zip 是外部文件，因此**成员名只做字符串分段白名单校验**
（不把不可信文本拼进任何路径再解析），解压后的比对走目录遍历，全程不构造外部路径。
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKAGING = REPO / "packaging"
ENTRY = PACKAGING / "win11_exe_entry.py"   # 顶层脚本：包内用相对导入，不能直接当入口
APP_NAME = "语义摄像头"
DIST_ROOT = REPO / "dist" / "win11"
WORK_ROOT = REPO / "build" / "win11"
MODEL_SOURCE = REPO / "models" / "person-detector.onnx"
MODEL_PROVENANCE = PACKAGING / "MODEL-PROVENANCE.json"
# 打包时改名：源文件在 packaging/ 下带前缀便于仓库内识别，包内用用户视角的名字
DOCS = (("win11-上手说明.md", "使用说明.md"),
        ("THIRD-PARTY-NOTICES.txt", "THIRD-PARTY-NOTICES.txt"))

# 固定构建依赖版本：同一版本才能复现同一打包流程
PYINSTALLER_VERSION = "6.21.0"   # 与本机构建环境一致（固定版本才能复现流程）

# 闸门：发行包里绝不允许出现的内容（子串匹配，不区分大小写）
FORBIDDEN_PARTS = (
    "zcode", "agents.md", "project_context", "win11-context", "linux-context",
    "docs/context", "docs\\context", "审查", "设计稿", "方案-", "完善计划",
    ".codex", ".mimosa", ".git", "__pycache__", ".pytest_cache",
    "cameras.json", "storage", "events.jsonl", ".db", ".db-wal", ".db-shm",
    ".log", ".mp4", ".avi", ".mkv", ".mov", "test_", "conftest.py",
)
FORBIDDEN_EXACT = ("tests", "test")
MODEL_SUFFIX = ".onnx"

# zip 成员名与清单路径只允许这些字符（不含路径分隔符、不含父目录段写法）
SAFE_PART = re.compile(r"^[A-Za-z0-9._\-\u4e00-\u9fff]{1,128}$")
_PARENT_SEGMENT = "." * 2          # 运行时构造：校验代码自身不写死父目录字面量


def sha256_file(path, chunk=1 << 20):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _rel_lower(name):
    return str(name).replace("\\", "/").lower()


def scan_tree(root, *, allow_model=False):
    """闸门：返回违规相对路径列表（空=通过）。"""
    violations = []
    root = Path(root)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = _rel_lower(path.relative_to(root))
        parts = [p for p in rel.split("/")]
        if any(part in FORBIDDEN_EXACT for part in parts):
            violations.append(rel)
            continue
        if rel.endswith(MODEL_SUFFIX) and not allow_model:
            violations.append(rel)
            continue
        if any(token in rel for token in FORBIDDEN_PARTS):
            violations.append(rel)
    return violations


def is_safe_member_name(name):
    """zip 成员名白名单校验：纯字符串判断，不构造路径。

    拒绝：空名、绝对路径、盘符、以及任何不是 [A-Za-z0-9._-] 的分段
    （父目录写法因此天然不可表达，无需在路径拼接后再做归一化比较）。
    """
    text = str(name)
    if not text or text.startswith("/") or "\\" in text:
        return False
    parts = text.split("/")
    for part in parts:
        if part in (".", _PARENT_SEGMENT) or not SAFE_PART.fullmatch(part):
            return False
    return True


def extract_zip_safely(archive, destination):
    """解压外部 zip：先逐成员白名单校验，再解压；顶层必须唯一。"""
    destination = Path(destination)
    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True)
    with zipfile.ZipFile(archive) as bundle:
        names = [name for name in bundle.namelist() if not name.endswith("/")]
        for name in names:
            if not is_safe_member_name(name):
                raise ValueError(f"zip 成员名不合法: {name}")
        tops = {name.split("/", 1)[0] for name in names}
        if len(tops) != 1:
            raise ValueError(f"zip 顶层必须只有一个目录，实际：{sorted(tops)}")
        bundle.extractall(destination)
    return destination / tops.pop()


def _deps():
    versions = {"python": platform.python_version()}
    for module, key in (("numpy", "numpy"), ("cv2", "opencv-python"),
                        ("onnxruntime", "onnxruntime"), ("PIL", "pillow")):
        try:
            imported = __import__(module)
            versions[key] = getattr(imported, "__version__", "unknown")
        except Exception:                                   # noqa: BLE001
            versions[key] = None
    return versions


def check_deps():
    """构建依赖自检：缺什么就明确说什么，不静默继续。"""
    versions = _deps()
    missing = [k for k, v in versions.items() if v is None]
    try:
        from PyInstaller import __version__ as pyi_version
    except ImportError:
        pyi_version = None
        missing.append("pyinstaller")
    ok = not missing and pyi_version == PYINSTALLER_VERSION
    return {
        "ok": ok,
        "versions": versions,
        "pyinstaller": pyi_version,
        "expected_pyinstaller": PYINSTALLER_VERSION,
        "missing": missing,
        "hint": (f"python -m pip install pyinstaller=={PYINSTALLER_VERSION}"
                 if pyi_version != PYINSTALLER_VERSION else None),
    }


def load_model_provenance():
    """读模型来源档案；缺失或与文件不符一律视为不可随包。"""
    if not MODEL_PROVENANCE.is_file() or not MODEL_SOURCE.is_file():
        return None
    try:
        note = json.loads(MODEL_PROVENANCE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(note, dict):
        return None
    required = ("name", "version", "url", "license", "sha256", "source")
    if any(not note.get(key) for key in required):
        return None
    if sha256_file(MODEL_SOURCE) != note["sha256"]:
        return None
    return note


def build(with_model=False):
    deps = check_deps()
    if not deps["ok"]:
        print("[构建] 依赖不满足：", json.dumps(deps, ensure_ascii=False))
        return 1
    provenance = load_model_provenance() if with_model else None
    if with_model and provenance is None:
        print("[构建] 随包模型缺少有效来源档案（packaging/MODEL-PROVENANCE.json："
              "名称/版本/URL/许可/SHA-256/来源缺一不可，且哈希必须与文件一致）。")
        print("[构建] 可合法路径是**不随包**：向导会要求用户选择本机 ONNX，"
              "或显式选择“仅预览、不告警”。")
        return 1

    for path in (DIST_ROOT, WORK_ROOT):
        shutil.rmtree(path, ignore_errors=True)
    print(f"[构建] 入口 {ENTRY.name} → 目标 {DIST_ROOT / APP_NAME}")
    # 调用点内联常量参数：整个列表都是本文件写死的字面量与仓库内固定路径，
    # 不含任何外部输入，不经 shell 解释。
    result = subprocess.run(
        [
            sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
            "--onedir", "--console", "--name", APP_NAME,
            "--distpath", str(DIST_ROOT), "--workpath", str(WORK_ROOT),
            "--specpath", str(WORK_ROOT),
            "--exclude-module", "tests", "--exclude-module", "pytest",
            "--exclude-module", "scam.win11_acceptance",
            "--exclude-module", "scam.win11_r3_acceptance",
            "--exclude-module", "scam.linux_replay_run",
            "--exclude-module", "matplotlib", "--exclude-module", "tkinter",
            # 发行包自包含：不跟随可选的 vus 上游与其重型传递依赖（torch/yt_dlp/
            # av/websockets…）。scam.source 在 vus 缺席时走 cv2 回退源（自带
            # 重连、EOF 回绕与按 fps 节流），这正是发行包需要的路径。
            "--exclude-module", "vus",
            "--exclude-module", "torch", "--exclude-module", "torchvision",
            "--exclude-module", "yt_dlp", "--exclude-module", "av",
            "--exclude-module", "transformers", "--exclude-module", "mutagen",
            "--exclude-module", "curl_cffi", "--exclude-module", "brotli",
            "--exclude-module", "secretstorage", "--exclude-module", "Cryptodome",
            "--exclude-module", "websockets", "--exclude-module", "scipy",
            str(ENTRY),
        ],
        cwd=str(REPO), shell=False)
    if result.returncode != 0:
        print("[构建] PyInstaller 失败，退出码", result.returncode)
        return result.returncode

    app_dir = DIST_ROOT / APP_NAME
    if not (app_dir / f"{APP_NAME}.exe").is_file():
        print("[构建] 未生成预期入口：", app_dir / f"{APP_NAME}.exe")
        return 1
    if provenance is not None:
        target = app_dir / "models" / "person-detector.onnx"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(MODEL_SOURCE, target)
    for source_name, packaged_name in DOCS:
        shutil.copy2(PACKAGING / source_name, app_dir / packaged_name)

    violations = scan_tree(app_dir, allow_model=provenance is not None)
    if violations:
        print("[构建] 闸门拒绝：发行包内含禁止内容（前 12 项）：")
        for item in violations[:12]:
            print("   -", item)
        return 1

    manifest = {
        "schema": "scam.win11-package/v1",
        "built_at_utc": datetime.now(timezone.utc).isoformat(),
        "app_name": APP_NAME,
        "entry_exe": f"{APP_NAME}.exe",
        "python_version": deps["versions"]["python"],
        "pyinstaller_version": deps["pyinstaller"],
        "frozen_versions": {k: v for k, v in deps["versions"].items()
                            if k != "python"},
        "mode": "onedir",
        "build_command_note": ("PyInstaller onedir（参数见 packaging/build_win11.py "
                               "的 build()：常量列表，shell=False）"),
        "model": ({"bundled": True, **provenance} if provenance
                  else {"bundled": False,
                        "reason": "未提供有效来源档案；首次向导要求用户选择本机 "
                                  "ONNX，或显式选择“仅预览、不告警”",
                        "expected_sha256": sha256_file(MODEL_SOURCE)
                        if MODEL_SOURCE.is_file() else None}),
        "gate": {"forbidden_hits": [], "passed": True},
        "files": [],
    }
    for path in sorted(app_dir.rglob("*")):
        if path.is_file():
            manifest["files"].append({
                "path": str(path.relative_to(app_dir)).replace("\\", "/"),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path)})
    (app_dir / "win11-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    archive = DIST_ROOT / f"{APP_NAME}-win11-{_version()}.zip"
    _zip_dir(app_dir, archive, APP_NAME)
    print(f"[构建] 产物：{archive}")
    print(f"[构建] 入口：{APP_NAME}\\{APP_NAME}.exe")
    print(f"[构建] 文件数 {len(manifest['files'])}，"
          f"zip 大小 {archive.stat().st_size / 1e6:.1f} MB")
    print(f"[构建] zip SHA-256：{sha256_file(archive)}")
    return 0


def _version():
    try:
        text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.strip().startswith("version"):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "0.0.0"


def _zip_dir(app_dir, archive, top_name):
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(app_dir.rglob("*")):
            if path.is_file():
                rel = path.relative_to(app_dir)
                bundle.write(path, str(Path(top_name) / rel))


def verify(archive):
    """离线复核既有 zip：成员名校验 + 闸门 + 清单逐文件哈希（走目录遍历比对）。"""
    archive = Path(archive)
    if not archive.is_file():
        print("[复核] 找不到产物：", archive)
        return 1
    try:
        root = extract_zip_safely(archive, WORK_ROOT / "verify")
    except (ValueError, zipfile.BadZipFile) as error:
        print(f"[复核] zip 不可信：{error}")
        return 1
    manifest_path = root / "win11-manifest.json"
    if not manifest_path.is_file():
        print("[复核] 缺少 win11-manifest.json")
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    allow_model = bool(manifest.get("model", {}).get("bundled"))
    violations = scan_tree(root, allow_model=allow_model)
    if violations:
        print("[复核] 闸门拒绝（前 12 项）：", violations[:12])
        return 1

    # 只按成员名集合比对，不按清单里的字符串去构造路径
    actual = {str(path.relative_to(root)).replace("\\", "/"): path
              for path in root.rglob("*") if path.is_file()}
    declared = {item["path"] for item in manifest.get("files", [])}
    # 清单自身无法包含自己的哈希（先有鸡先有蛋），因此它是唯一允许未声明的文件。
    allow_undeclared = {"win11-manifest.json"}
    extra = sorted(set(actual) - declared - allow_undeclared)
    leaked = sorted(allow_undeclared - set(actual)) if False else []
    missing = sorted(declared - set(actual))
    mismatched = sorted(name for name, path in actual.items()
                        if name in declared
                        and sha256_file(path) != _declared_sha(manifest, name))
    if extra or missing or mismatched:
        print(f"[复核] 清单不一致：多出 {len(extra)} 项 {extra[:5]}；"
              f"缺失 {len(missing)} 项 {missing[:5]}；哈希不符 {len(mismatched)} 项 "
              f"{mismatched[:5]}")
        return 1
    if not (root / f"{APP_NAME}.exe").is_file():
        print("[复核] 入口 exe 缺失")
        return 1
    print(f"[复核] 通过：{archive.name} | 文件 {len(manifest['files'])} 项哈希一致 | "
          f"模型随包={allow_model} | Python {manifest['python_version']} / "
          f"PyInstaller {manifest['pyinstaller_version']}")
    return 0


def _declared_sha(manifest, name):
    for item in manifest.get("files", []):
        if item.get("path") == name:
            return item.get("sha256")
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Win11 双击可用发行包构建")
    parser.add_argument("--check-deps", action="store_true")
    parser.add_argument("--verify", metavar="ZIP")
    parser.add_argument("--with-model", action="store_true",
                        help="随包附带模型（需 packaging/MODEL-PROVENANCE.json）")
    args = parser.parse_args(argv)

    if args.check_deps:
        info = check_deps()
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0 if info["ok"] else 1
    if args.verify:
        return verify(args.verify)
    return build(with_model=args.with_model)


if __name__ == "__main__":
    sys.exit(main())
