"""fetch_models.py —— 检测/嵌入模型交付脚本（下载 + 冻结哈希校验）。

用法：
    python scripts/fetch_models.py --list                 查看清单与就位状态
    python scripts/fetch_models.py --model nanodet        下载并校验入位
    python scripts/fetch_models.py --verify-local path    校验仓库内本地文件
                                                          （V-JEPA 导出权重无
                                                          公开 URL，导出后就位
                                                          校验）

纪律：URL 只来自本文件冻结白名单（不接受外部传入）；HTTPS + 发布域名白名单
+ 禁止重定向 + 解析后 IP 阻断私网/环回/链路本地；SHA-256 与 URL 成对冻结
（改动=更新白名单并重跑校验，不允许"先下再算"）；下载到临时文件、校验通过
原子改名——失败绝不留半文件冒充可用模型；--verify-local 限定仓库内路径且
拒绝 .. 路径段；标准库实现，零新依赖。
"""

import argparse
import hashlib
import ipaddress
import os
import shutil
import socket
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

# 冻结白名单：模型 → (固定 URL, SHA-256, 相对路径)
# NanoDet-Plus 人物检测（官方 release）。sha256 占位 None：首次人工下载后由
# 维护者 --freeze 登记实测值；占位期间拒绝自动下载（fail-closed）。
MODELS = {
    "nanodet": {
        "url": ("https://github.com/RangiLyu/nanodet/releases/download/"
                "v1.0.0-alpha-1/nanodet_m.onnx"),
        "sha256": None,
        "path": os.path.join("models", "person-detector.onnx"),
    },
}

# 发布源域名白名单（github release 及其资产域；禁重定向故无第三方跳转）
_ALLOWED_HOSTS = {"github.com", "objects.githubusercontent.com",
                  "release-assets.githubusercontent.com"}


def _no_dotdot(path):
    """文本级拒绝 .. 路径段（围栏第一层；_inside_repo 为第二层）。"""
    if ".." in str(path).replace("\\", "/").split("/"):
        raise ValueError("路径不得包含 .. 路径段")
    return path


def sha256_file(path, chunk=1 << 20):
    digest = hashlib.sha256()
    with Path(_no_dotdot(path)).open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _inside_repo(path):
    root = os.path.normcase(_repo_root())
    full = os.path.normcase(os.path.abspath(path))
    return full == root or full.startswith(root + os.sep)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """下载源禁止重定向：白名单域名外的任何跳转直接失败。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError(f"拒绝重定向到 {newurl}")


def _assert_safe_url(url):
    """白名单 URL 边界：HTTPS + 域名白名单 + 解析后 IP 阻私网/环回。"""
    if url not in {item["url"] for item in MODELS.values()}:
        raise ValueError("URL 不在冻结白名单内")
    if not url.lower().startswith("https://"):
        raise ValueError("只允许 HTTPS 下载源")
    host = urllib.request.urlparse(url).hostname or ""
    if host.lower() not in _ALLOWED_HOSTS:
        raise ValueError(f"下载源域名不在白名单: {host}")
    try:
        infos = socket.getaddrinfo(host, 443)
    except OSError as exc:
        raise ValueError(f"下载源域名解析失败: {host}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise ValueError(f"下载源解析到非公网地址: {ip}")


def _download_to(url, dest_dir):
    """白名单 URL 流式下载到仓库内临时文件；返回临时路径。"""
    if not _inside_repo(dest_dir):
        raise ValueError("下载目录越出仓库根")
    _assert_safe_url(url)
    opener = urllib.request.build_opener(_NoRedirect)
    fd, tmp = tempfile.mkstemp(suffix=".download", dir=dest_dir)
    os.close(fd)
    try:
        with opener.open(url, timeout=60) as resp, \
                Path(_no_dotdot(tmp)).open("wb") as out:
            shutil.copyfileobj(resp, out, 1 << 20)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return tmp


def status():
    """清单与就位状态（不下载）。"""
    rows = []
    for name, item in MODELS.items():
        target = os.path.join(_repo_root(), item["path"])
        exists = os.path.isfile(target)
        digest = sha256_file(target) if exists else None
        frozen = item["sha256"]
        ok = exists and frozen is not None and digest == frozen
        rows.append({"model": name, "path": item["path"],
                     "exists": exists, "frozen_sha256": frozen,
                     "actual_sha256": digest,
                     "state": "ok" if ok else
                     ("unfrozen" if exists and frozen is None else
                      "missing" if not exists else "mismatch")})
    return rows


def fetch(name, force=False):
    """下载 + 冻结哈希校验 + 原子入位。返回 (state, detail)。"""
    if name not in MODELS:
        return "unknown_model", f"未知模型: {name}（--list 查看清单）"
    item = MODELS[name]
    if item["sha256"] is None:
        return "unfrozen", (
            f"{name} 的 SHA-256 白名单未冻结：请先人工下载一次，用 "
            f"`--freeze {name} <sha256>` 登记实测哈希后再开放自动下载")
    root = _repo_root()
    target = os.path.join(root, item["path"])
    if not _inside_repo(target):
        return "invalid_path", "目标路径越出仓库根"
    if os.path.isfile(target) and not force:
        digest = sha256_file(target)
        if digest == item["sha256"]:
            return "ok", "已就位且校验一致（--force 可重下）"
    os.makedirs(os.path.dirname(target), exist_ok=True)
    tmp = _download_to(item["url"], os.path.dirname(target))
    try:
        digest = sha256_file(tmp)
        if digest != item["sha256"]:
            return "mismatch", (
                f"下载内容哈希不符：期望 {item['sha256']}，实测 {digest}"
                "（文件已丢弃，不落位）")
        os.replace(tmp, target)
        return "ok", f"已校验入位: {item['path']}"
    finally:
        if os.path.isfile(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def verify_local(path, expect_sha256=None):
    """校验仓库内本地模型文件（V-JEPA 导出权重就位用）。"""
    if ".." in str(path).replace("\\", "/").split("/"):
        return "invalid_path", "路径不得包含 .. 路径段（verify-local）"
    if not _inside_repo(path):
        return "invalid_path", "只允许校验仓库内路径（外置文件先拷入 models/）"
    if not os.path.isfile(path):
        return "missing", f"文件不存在: {path}"
    digest = sha256_file(path)
    if expect_sha256 is None:
        return "unfrozen", f"未提供期望哈希；实测 SHA-256:\\n  {digest}"
    if digest == expect_sha256:
        return "ok", "哈希一致"
    return "mismatch", f"期望 {expect_sha256}，实测 {digest}"


def freeze(name, digest):
    """把实测哈希写回本脚本白名单（维护者动作，产出可复核 diff）。"""
    if name not in MODELS:
        return "unknown_model", f"未知模型: {name}"
    if not (len(digest) == 64 and all(c in "0123456789abcdef"
                                      for c in digest.lower())):
        return "invalid_hash", "SHA-256 必须为 64 位十六进制"
    script = os.path.abspath(__file__)
    text = Path(_no_dotdot(script)).read_text(encoding="utf-8")
    old = '"sha256": None,'
    if name != "nanodet" or old not in text:
        return "manual", "请手工更新 MODELS 白名单（结构已变化）"
    new = f'"sha256": "{digest.lower()}",'
    Path(_no_dotdot(script)).write_text(
        text.replace(old, new, 1), encoding="utf-8", newline="\\n")
    return "ok", f"已冻结 {name} = {digest.lower()}（请提交本文件 diff 供复核）"


def main(argv=None):
    ap = argparse.ArgumentParser(description="检测/嵌入模型交付脚本")
    ap.add_argument("--list", action="store_true", help="清单与就位状态")
    ap.add_argument("--model", help="下载并校验入位（当前: nanodet）")
    ap.add_argument("--force", action="store_true", help="已就位也重下")
    ap.add_argument("--verify-local", metavar="PATH",
                    help="校验仓库内本地模型文件")
    ap.add_argument("--expect", help="--verify-local 的期望 SHA-256")
    ap.add_argument("--freeze", nargs=2, metavar=("MODEL", "SHA256"),
                    help="冻结实测哈希（维护者）")
    args = ap.parse_args(argv)

    if args.list or not any((args.model, args.verify_local, args.freeze)):
        for row in status():
            print(f"[{row['state']:>9}] {row['model']}  {row['path']}"
                  + (f"  sha256={row['actual_sha256'][:12]}…"
                     if row["actual_sha256"] else ""))
        return 0
    if args.model:
        state, detail = fetch(args.model, force=args.force)
        print(f"[{state}] {detail}")
        return 0 if state == "ok" else 1
    if args.verify_local:
        state, detail = verify_local(args.verify_local, args.expect)
        print(f"[{state}] {detail}")
        return 0 if state == "ok" else 1
    if args.freeze:
        state, detail = freeze(args.freeze[0], args.freeze[1])
        print(f"[{state}] {detail}")
        return 0 if state == "ok" else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
