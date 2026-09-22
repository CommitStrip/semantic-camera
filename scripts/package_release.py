"""package_release.py —— 发布打包（可复现 tar.gz + 敏感面防护）。

用法：
    python scripts/package_release.py --dry-run          列出将打包文件
    python scripts/package_release.py                    打包 dist/scam-<ver>.tar.gz
    python scripts/package_release.py --check dist/x.tar.gz   敏感面扫描既有包

安全红线：cameras.json（RTSP 凭据）、私有记录本、模型权重、storage、.git、
.mimosa、内部设计稿**绝不入包**——include 白名单 + 逐文件敏感模式双闸，
任一命中即拒绝打包（fail-closed）。归一化 mtime/uid/gid 与 gzip mtime=0
保证同一工作树两次打包哈希一致（可复核）。
"""

import argparse
import gzip
import hashlib
import io
import os
import sys
import tarfile
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _safe_path(raw):
    """输出/读取路径围栏：拒绝 .. 段；绝对路径须在仓库内。"""
    text = str(raw)
    if ".." in text.replace("\\", "/").split("/"):
        raise ValueError("路径不得包含 .. 路径段")
    if os.path.isabs(text):
        full = os.path.normcase(os.path.abspath(text))
        root = os.path.normcase(REPO)
        if full != root and not full.startswith(root + os.sep):
            raise ValueError("路径越出仓库根")
    return text

# include 白名单（顶层）：只有这些能进包
INCLUDE_TOPS = ("scam", "deploy", "scripts", "tests", "pyproject.toml",
                "README.md", "README-CN.md", "LICENSE", "RELEASE_NOTES.md")

# 敏感模式（任一命中=拒绝）：凭据/私有上下文/权重/运行时产物/历史
SENSITIVE_PATTERNS = (
    "cameras.json",              # RTSP 凭据
    "CONTEXT.md",                # 私有记录本（WIN11/LINUX/ZCODE 等全部）
    "AGENTS.md", "PROJECT_CONTEXT.md",
    "docs/context",
    ".mimosa", ".git", "__pycache__", ".pytest_cache",
    ".onnx", "storage", "events.jsonl",
    "设计稿", "审查-", "方案-", "完善计划",
    "smoke-cameras.json",        # CI 临时配置（含示例流地址）
    "nul",
)


def version():
    """读 pyproject 版本（tomllib 优先，3.10 简易解析回退）。"""
    try:
        import tomllib
        with Path(os.path.join(REPO, "pyproject.toml")).open("rb") as handle:
            return tomllib.load(handle)["project"]["version"]
    except Exception:
        text = Path(os.path.join(REPO, "pyproject.toml")).read_text(
            encoding="utf-8")
        for line in text.splitlines():
            if line.strip().startswith("version"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
        return "0.0.0"


def _collect():
    """白名单收集 + 敏感双闸；返回相对路径列表（POSIX）。"""
    files = []
    for top in INCLUDE_TOPS:
        path = os.path.join(REPO, top)
        if not os.path.exists(path):
            continue
        if os.path.isfile(path):
            files.append(top)
            continue
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if d not in
                       ("__pycache__", ".pytest_cache", ".mimosa")]
            for name in names:
                rel = os.path.relpath(os.path.join(root, name), REPO)
                files.append(rel.replace(os.sep, "/"))
    blocked = []
    for rel in files:
        low = rel.lower()
        if any(p.lower() in low for p in SENSITIVE_PATTERNS):
            blocked.append(rel)
    if blocked:
        raise ValueError("敏感文件命中打包闸（拒绝打包）: "
                         + ", ".join(sorted(blocked)[:10]))
    return sorted(files)


def build(output=None):
    """打包：归一化元数据 + 固定头 gzip → 可复现 tar.gz。

    tar 成员归一化（mtime=0/uid=gid=0/无名）之外，gzip 头的 mtime 与
    文件名也必须固定——否则两次打包哈希必不同。
    """
    ver = version()
    files = _collect()
    out = _safe_path(output or os.path.join(REPO, "dist",
                                            f"scam-{ver}.tar.gz"))
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    anchor = "scam"
    with Path(out).open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                           compresslevel=9, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                for rel in files:
                    full = os.path.join(REPO, rel)
                    info = tar.gettarinfo(full, arcname=f"{anchor}/{rel}")
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    with Path(full).open("rb") as handle:
                        tar.addfile(info, handle)
    digest = sha256_archive(out)
    return out, digest, len(files)


def sha256_archive(path):
    digest = hashlib.sha256()
    with Path(_safe_path(path)).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def check(archive):
    """敏感面扫描既有包：包内任何敏感模式命中即失败。"""
    hits = []
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            low = member.name.lower()
            if any(p.lower() in low for p in SENSITIVE_PATTERNS):
                hits.append(member.name)
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(description="发布打包（敏感面防护）")
    ap.add_argument("--dry-run", action="store_true", help="只列文件不落盘")
    ap.add_argument("--output", help="输出路径（缺省 dist/scam-<ver>.tar.gz）")
    ap.add_argument("--check", metavar="ARCHIVE", help="扫描既有包敏感面")
    args = ap.parse_args(argv)

    if args.check:
        try:
            hits = check(_safe_path(args.check))
        except ValueError as exc:
            print(f"[FAIL] {exc}")
            return 1
        if hits:
            print(f"[FAIL] 包内敏感文件 {len(hits)} 个:")
            for name in hits[:20]:
                print("  -", name)
            return 1
        print("[OK] 未发现敏感文件")
        return 0
    try:
        files = _collect()
    except ValueError as exc:
        print(f"[FAIL] {exc}")
        return 1
    if args.dry_run:
        for rel in files:
            print(rel)
        print(f"-- 共 {len(files)} 个文件（未落盘）")
        return 0
    path, digest, count = build(args.output)
    print(f"[OK] {path}")
    print(f"     files={count} sha256={digest}")
    print(f"     敏感面自查: python scripts/package_release.py "
          f"--check {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
