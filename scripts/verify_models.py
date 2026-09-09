#!/usr/bin/env python3
"""verify_models.py - 模型资产完整性校验（fail-closed 装载的配套）
按 assets/manifest.json 逐文件重算 sha256，任何缺失/不匹配都以非零码退出——
防止静默失效的权重混入发布（沿用前身仓"任务级闸门"思路）。
用法: python scripts/verify_models.py   （在仓库根目录运行）
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "assets", "manifest.json")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    with open(MANIFEST, encoding="utf-8") as f:
        manifest = json.load(f)
    fail = 0
    for entry in manifest["files"]:
        path = os.path.join(ROOT, entry["path"])
        if not os.path.isfile(path):
            print(f"[缺失] {entry['path']}")
            fail = 1
            continue
        actual = sha256(path)
        if actual != entry["sha256"]:
            print(f"[哈希不符] {entry['path']}\n  期望 {entry['sha256']}\n  实际 {actual}")
            fail = 1
        else:
            print(f"[OK] {entry['path']} {entry['sha256'][:16]}…")
    sys.exit(fail)


if __name__ == "__main__":
    main()
