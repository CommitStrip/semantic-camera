"""Linux L4 upgrade/rollback transaction contract (queue P).

One CLI with two subcommands over one immutable contract directory that
holds exactly one entry, ``contract.json``::

    prepare --current-release-dir DIR --candidate-release-dir DIR
            --backup-bundle DIR --output-dir DIR
    verify  --contract-dir DIR

The option that binds the state bundle is spelled exactly
``--backup-bundle``, the frozen LC-041 spelling; argparse's option
abbreviation stays off, so neither a longer variant nor an abbreviated
one (``--backup``, ``--backup-bundle-d``) is ever accepted.

``prepare`` only *plans and records* one upgrade transaction.  It reads
the two release trees and one state bundle, then creates the contract
directory atomically and exclusively -- an existing path is never
overwritten, and a failed run removes only the directory that same run
created.  Both release roots must exist, must not be symlinks, must
differ and must not be nested; each tree walk rejects symlinks,
non-regular files, escaping paths and any file whose identity changes
while it is read, and nothing is silently skipped.  Files are recorded in
normalised relative POSIX-path order with their size and SHA-256, and
summarised as a file count, a byte total and one deterministic tree
SHA-256; a tree without ``pyproject.toml`` or without ``scam/`` sources is
refused.

The bundle is never taken on the operator's word: the contract binds it by
re-using ``scam.linux_backup.verify_bundle`` read-only, and records the
manifest SHA-256, the database/config content digests and the
``bundle_valid`` verdict -- a contract can never cite a bundle that the O
module itself refuses, so an upgrade without a verified state backup
cannot even be planned.

``verify`` is strictly read-only and re-checks the whole contract: root or
entry symlinks, extra or missing paths, unknown or missing root fields,
a changed phase order, unsafe or escaping relative paths, any change to
either release tree or to the bound bundle, and an unsafe rollback order
are all refused.  Every failure is a non-zero CLI result with structured
JSON.

Nothing here executes anything.  The module performs no network access,
starts no child process, never talks to systemd or any service, never
switches a release pointer, never writes to the live database or
configuration, never installs anything, and never copies, deletes, moves
or renames a release tree: ``actions_executed``, ``service_controlled``,
``release_switched``, ``rollback_executed`` and ``native_linux_validated``
are false and ``quality_gate_passed`` and ``release_gate_passed`` stay
null everywhere.  The fixed rollback order is recorded, not performed:
stop the failed candidate, restore the previous release, start it and
verify health *first*, and only then -- when the upgrade explicitly ran a
data migration that the previous release cannot read -- restore the O
bundle into a brand-new staging directory for operator review before a
controlled swap.  The operator-facing commands, manual confirmation
points and evidence list live in ``docs/linux-operations-runbook.md``.
This is planning plus Windows-synthetic tests plus a documented contract
only; it is not native-Linux, real-RTSP, 24-hour, quality or release-gate
evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone

import scam.linux_backup as backup

SCHEMA = "scam.linux-upgrade-contract/v1"
CONTRACT_ENTRY = "contract.json"
CONTRACT_ENTRY_SET = frozenset((CONTRACT_ENTRY,))
KIND = "upgrade_contract"
TOOL_NAME = "scam.linux_upgrade_contract"
SERVICE_NAME = "scam-nvr.service"
HEALTH_ENDPOINT = "http://127.0.0.1:8600/api/health"
PHASES = ("preflight_verified", "stop_service", "switch_release",
          "start_and_healthcheck", "accept_or_rollback")
RELEASE_MANIFEST_FILE = "pyproject.toml"
RELEASE_SOURCE_DIR = "scam"
HONESTY_FIELDS = (("actions_executed", False), ("service_controlled", False),
                  ("release_switched", False), ("rollback_executed", False),
                  ("native_linux_validated", False),
                  ("quality_gate_passed", None), ("release_gate_passed", None))
# 合同根是**精确封闭**的固定 schema：固定字段 + 诚实字段。未知根字段、缺失字段、
# 类型或固定值不符都拒绝——合同形状本身必须可被独立证伪，不能任意扩展。
CONTRACT_FIXED_FIELDS = ("schema", "kind", "created_at", "tool", "note",
                         "service", "health_endpoint", "phases",
                         "current_release", "candidate_release", "backup",
                         "success_checklist", "rollback_checklist")
CONTRACT_FIELDS = CONTRACT_FIXED_FIELDS + tuple(field for field, _ in
                                                HONESTY_FIELDS)
CONTRACT_FIELD_SET = frozenset(CONTRACT_FIELDS)
RELEASE_FIELDS = ("root", "tree", "files")
TREE_FIELDS = ("files", "bytes", "sha256")
FILE_ENTRY_FIELDS = ("path", "size", "sha256")
BACKUP_FIELDS = ("bundle_dir", "bundle_valid", "manifest_sha256", "contents")
CONTENT_ROLES = (("database", backup.DB_ENTRY, ("entry", "size", "sha256",
                                                "integrity_check")),
                 ("config", backup.CONFIG_ENTRY, ("entry", "size", "sha256")))
ROLLBACK_ALWAYS = "always"
# 只有升级过程明确执行过数据迁移、且旧发布无法读取当前状态时，才允许状态恢复。
ROLLBACK_CONDITION = ("only_if_data_migration_executed_and_previous_release_"
                      "cannot_read_current_state")
SUCCESS_CHECKLIST = (
    {"step": "stop_service_confirmed",
     "evidence": "停服命令退出码与服务状态查询输出（谁执行、何时、结果）",
     "runbook": "docs/linux-operations-runbook.md §4 停服与发布切换"},
    {"step": "release_switch_recorded",
     "evidence": "旧/新发布工作目录的切换记录与人工确认点签名",
     "runbook": "docs/linux-operations-runbook.md §4 停服与发布切换"},
    {"step": "start_service_confirmed",
     "evidence": "启动命令退出码与 unit 渲染结果复核记录",
     "runbook": "docs/linux-operations-runbook.md §5 启动与健康确认"},
    {"step": "health_endpoint_ok",
     "evidence": "健康端点 HTTP 状态与完整 JSON 响应（含录像/告警解耦字段）",
     "runbook": "docs/linux-operations-runbook.md §5 启动与健康确认"},
    {"step": "logs_archived",
     "evidence": "命令历史、退出码与日志归档路径及校验值",
     "runbook": "docs/linux-operations-runbook.md §9 证据归档"},
    {"step": "operator_decision_recorded",
     "evidence": "运维人员接受或回退的明确决定与依据",
     "runbook": "docs/linux-operations-runbook.md §6 接受"},
)
# 回滚顺序固定：先停失败候选→恢复旧发布→启动旧版本→先验健康；状态恢复是**条件性**
# 最后手段，只能恢复到全新 staging 目录并人工复核后受控替换，绝不默认覆盖在线数据。
ROLLBACK_CHECKLIST = (
    {"step": "stop_failed_candidate", "condition": ROLLBACK_ALWAYS,
     "evidence": "失败候选的停止命令退出码与进程/端口占用确认",
     "runbook": "docs/linux-operations-runbook.md §7 代码回退"},
    {"step": "restore_previous_release", "condition": ROLLBACK_ALWAYS,
     "evidence": "工作目录/发布指针回到旧版本的记录（人工确认点）",
     "runbook": "docs/linux-operations-runbook.md §7 代码回退"},
    {"step": "start_previous_release", "condition": ROLLBACK_ALWAYS,
     "evidence": "旧版本启动命令退出码",
     "runbook": "docs/linux-operations-runbook.md §7 代码回退"},
    {"step": "verify_previous_health", "condition": ROLLBACK_ALWAYS,
     "evidence": "旧版本健康端点响应与旧版本自身日志",
     "runbook": "docs/linux-operations-runbook.md §7 代码回退"},
    {"step": "restore_state_to_fresh_staging", "condition": ROLLBACK_CONDITION,
     "evidence": "O 包先 verify 再 restore 到全新 staging 目录的完整输出",
     "runbook": "docs/linux-operations-runbook.md §8 条件性状态恢复"},
    {"step": "operator_review_staging", "condition": ROLLBACK_CONDITION,
     "evidence": "运维人员对 staging 内容的逐项复核记录",
     "runbook": "docs/linux-operations-runbook.md §8 条件性状态恢复"},
    {"step": "controlled_swap_after_review", "condition": ROLLBACK_CONDITION,
     "evidence": "人工确认后的受控替换记录与替换前后校验值",
     "runbook": "docs/linux-operations-runbook.md §8 条件性状态恢复"},
)
CONTRACT_NOTE = ("升级事务合同：只规划与验证升级/回滚顺序，不执行安装、服务控制、"
                 "发布切换、数据迁移或在线状态覆盖；不代表原生Linux、真实RTSP、"
                 "24小时、识别质量或发布门禁证据。")
CHUNK_SIZE = 1024 * 1024
CONTRACT_LIMIT = 4 * 1024 * 1024
MANIFEST_LIMIT = backup.MANIFEST_LIMIT
# 写入侧统一的独占创建标志：必须带 ``O_BINARY``，否则 Windows CRT 文本模式会把
# 落盘字节里的 ``\n`` 翻成 ``\r\n``，合同字节不再确定。
EXCLUSIVE_WRITE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_BINARY", 0))


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_timestamp(value):
    """``created_at`` 必须是以 ``Z`` 结尾的 ISO-8601 UTC 时间戳。"""
    if not isinstance(value, str) or len(value) < 2 or not value.endswith("Z"):
        return False
    try:
        stamp = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return stamp.tzinfo is not None and stamp.utcoffset() == timedelta(0)


def _identity(info):
    """身份快照五项（设备/inode/大小/mtime/ctime）：读取前后必须完全一致。"""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns)


def _lstat_now(path):
    """路径身份采样点（测试经此注入确定性时序；生产即 ``os.lstat``）。"""
    return os.lstat(path)


def _fstat_now(path):
    """句柄权威的路径身份采样点（测试经此注入确定性时序）。

    只读打开该路径并取 ``fstat``：与持有的 fd 快照同源，可直接比对；路径层
    ``lstat`` 仅用于链接/普通文件判断，跨来源比较 size/mtime/ctime 会把刚写
    出的文件在 Windows 目录条目元数据滞后时误判为"读取中被替换"。
    """
    fd = _open_readonly(path)
    try:
        return os.fstat(fd)
    finally:
        os.close(fd)


def _open_readonly(path):
    return os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                   | getattr(os, "O_NOFOLLOW", 0))


def _base_result(kind):
    result = {"schema": SCHEMA, "kind": kind, "created_at": _utc_now(),
              "note": CONTRACT_NOTE, "errors": []}
    for field, expected in HONESTY_FIELDS:
        result[field] = expected
    return result


def _unsafe_relative_path(value):
    """树内相对路径必须是规范化 POSIX 单层以上路径：绝对、反斜杠、``..`` 都拒绝。"""
    if not isinstance(value, str) or not value:
        return True
    if value.startswith(("/", "\\")) or "\\" in value or "\x00" in value:
        return True
    if len(value) >= 2 and value[1] == ":":
        return True
    return any(part in ("", ".", "..") for part in value.split("/"))


def _fixed_entry_path(root, name):
    """把固定条目名解析为根目录内的路径（条目名来自固定常量，绝不拼接用户输入）。"""
    root_absolute = os.path.abspath(str(root))
    candidate = os.path.abspath(os.path.join(root_absolute, name))
    if os.path.dirname(candidate) != root_absolute:
        raise ValueError(f"entry path escapes its root: {name!r}")
    return candidate


def _write_all(fd, chunk):
    """完整写出一个分块：``os.write`` 可能短写，循环到写完为止。"""
    view = memoryview(chunk)
    while len(view):
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _checked_destination(root, path, errors):
    """新建文件的落点校验，返回规范化路径；不合格即结构化拒绝。"""
    root_absolute = os.path.abspath(str(root))
    candidate = os.path.abspath(str(path))
    if os.path.dirname(candidate) != root_absolute:
        errors.append("destination: path escapes its root; refusing to write")
        return None
    if os.path.basename(candidate) not in CONTRACT_ENTRY_SET:
        errors.append("destination: not the fixed contract entry; "
                      "refusing to write")
        return None
    return candidate


def _write_at(target, payload, label, errors):
    """独占创建一个新文件并完整写出；绝不覆盖已有文件。"""
    fd = None
    try:
        fd = os.open(target, EXCLUSIVE_WRITE_FLAGS, 0o600)
        _write_all(fd, payload)
        os.fsync(fd)
    except OSError as exc:
        errors.append(f"{label}: cannot write ({type(exc).__name__}: {exc})")
        return False
    finally:
        if fd is not None:
            os.close(fd)
    return True


def _remove_created_dir(path, created):
    """只清理本次运行新建的合同目录：删掉自己写出的唯一合同文件后删空目录。

    ``created`` 为假时绝不触碰该路径；目录里出现非本次写出的对象时 ``rmdir``
    失败，函数如实返回 False，由调用方报告“残留不完整目录”，绝不做递归删除。
    """
    if not created:
        return False
    root_absolute = os.path.abspath(str(path))
    target = _fixed_entry_path(root_absolute, CONTRACT_ENTRY)
    try:
        if os.path.lexists(target):
            info = _lstat_now(target)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                return False
            os.unlink(target)
        os.rmdir(root_absolute)
    except OSError:
        pass
    return not os.path.exists(root_absolute)


def _check_directory_root(root, label, errors):
    """目录根必须是真实目录且不是软链接（拒绝后绝不再遍历）。"""
    try:
        info = _lstat_now(root)
    except OSError:
        errors.append(f"{label}: missing")
        return None
    if stat.S_ISLNK(info.st_mode):
        errors.append(f"{label}: symlink is not accepted")
        return None
    if not stat.S_ISDIR(info.st_mode):
        errors.append(f"{label}: not a directory")
        return None
    return info


def _is_inside(child, parent):
    child = os.path.normcase(os.path.abspath(str(child)))
    parent = os.path.normcase(os.path.abspath(str(parent)))
    return child.startswith(parent.rstrip(os.sep) + os.sep)


def _check_root_relation(current, candidate, current_info, candidate_info,
                         errors):
    """当前与候选发布根必须互不相同且互不嵌套。"""
    if os.path.normcase(os.path.abspath(str(current))) \
            == os.path.normcase(os.path.abspath(str(candidate))) \
            or os.path.samestat(current_info, candidate_info):
        errors.append("release_roots: current and candidate are the same "
                      "directory")
        return
    if _is_inside(current, candidate) or _is_inside(candidate, current):
        errors.append("release_roots: current and candidate must not be "
                      "nested")


def _check_output_location(output_dir, roots, errors):
    """合同目录不得落在任何输入根内，也不得与输入根相同。"""
    for label, root in roots:
        if os.path.normcase(os.path.abspath(str(output_dir))) \
                == os.path.normcase(os.path.abspath(str(root))) \
                or _is_inside(output_dir, root):
            errors.append(f"output_dir: must not be {label} or inside it")
            return
        if _is_inside(root, output_dir):
            errors.append(f"output_dir: must not contain {label}")
            return


def _hash_file(path, relative, label, errors):
    """按严格身份绑定读取发布树内一个普通文件，返回 path/size/sha256。"""
    where = f"{label}: {relative}"
    try:
        before = _lstat_now(path)
    except OSError:
        errors.append(f"{where}: missing")
        return None
    if stat.S_ISLNK(before.st_mode):
        errors.append(f"{where}: symlink is not accepted")
        return None
    if not stat.S_ISREG(before.st_mode):
        errors.append(f"{where}: not a regular file")
        return None
    try:
        fd = _open_readonly(path)
    except OSError as exc:
        errors.append(f"{where}: open failed ({type(exc).__name__}: {exc})")
        return None
    digest = hashlib.sha256()
    size = 0
    try:
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                errors.append(f"{where}: opened object is not a regular file")
                return None
            if not os.path.samestat(before, opened):
                errors.append(f"{where}: identity changed between check and "
                              "open")
                return None
            while True:
                chunk = os.read(fd, CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
            after_read = os.fstat(fd)
        except OSError as exc:
            errors.append(f"{where}: read failed "
                          f"({type(exc).__name__}: {exc})")
            return None
    finally:
        os.close(fd)
    if (after_read.st_size, after_read.st_mtime_ns, after_read.st_ctime_ns) \
            != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
        errors.append(f"{where}: changed while reading")
        return None
    if size != after_read.st_size:
        errors.append(f"{where}: truncated while reading")
        return None
    try:
        after = _lstat_now(path)
    except OSError as exc:
        errors.append(f"{where}: replaced while reading "
                      f"({type(exc).__name__}: {exc})")
        return None
    if stat.S_ISLNK(after.st_mode) or not stat.S_ISREG(after.st_mode):
        errors.append(f"{where}: replaced while reading")
        return None
    try:
        current = _fstat_now(path)
    except OSError as exc:
        errors.append(f"{where}: replaced while reading "
                      f"({type(exc).__name__}: {exc})")
        return None
    if not stat.S_ISREG(current.st_mode) \
            or not os.path.samestat(opened, current) \
            or _identity(current) != _identity(opened):
        errors.append(f"{where}: replaced while reading")
        return None
    return {"path": relative, "size": size, "sha256": digest.hexdigest()}


def _walk_tree(directory, prefix, files, label, errors):
    """递归枚举发布树：任何非普通文件/链接/逃逸名字都记错，绝不静默忽略。"""
    try:
        with os.scandir(directory) as scanner:
            entries = sorted(scanner, key=lambda item: item.name)
    except OSError as exc:
        errors.append(f"{label}: {prefix or '.'}: cannot list "
                      f"({type(exc).__name__}: {exc})")
        return
    for item in entries:
        relative = item.name if not prefix else f"{prefix}/{item.name}"
        if "/" in item.name or "\\" in item.name or "\x00" in item.name \
                or item.name in (".", ".."):
            errors.append(f"{label}: unsafe entry name at {prefix or '.'}")
            continue
        if item.is_symlink():
            errors.append(f"{label}: {relative}: symlink is not accepted")
            continue
        if item.is_dir(follow_symlinks=False):
            _walk_tree(item.path, relative, files, label, errors)
            continue
        if not item.is_file(follow_symlinks=False):
            errors.append(f"{label}: {relative}: not a regular file")
            continue
        record = _hash_file(item.path, relative, label, errors)
        if record is not None:
            files.append(record)


def _canonical_line(record):
    """树摘要的规范行：相对路径、大小、摘要三段以 NUL 分隔，行尾 LF。"""
    return f"{record['path']}\x00{record['size']}\x00{record['sha256']}\n"


def _tree_summary(records):
    """确定性树摘要：文件数、总字节与按规范行计算的树 SHA-256。"""
    digest = hashlib.sha256()
    total = 0
    for record in records:
        digest.update(_canonical_line(record).encode("utf-8"))
        total += record["size"]
    return {"files": len(records), "bytes": total,
            "sha256": digest.hexdigest()}


def _has_required_release_files(records, label, errors):
    """发布树至少要有 pyproject.toml 与 scam/ 源码，否则不算可升级发布。"""
    paths = {record["path"] for record in records}
    ok = True
    if RELEASE_MANIFEST_FILE not in paths:
        errors.append(f"{label}: missing required file "
                      f"{RELEASE_MANIFEST_FILE}")
        ok = False
    prefix = RELEASE_SOURCE_DIR + "/"
    if not any(path.startswith(prefix) for path in paths):
        errors.append(f"{label}: missing required "
                      f"{RELEASE_SOURCE_DIR}/ sources")
        ok = False
    return ok


def _scan_tree(root, label, errors):
    """只读遍历一个发布树并按规范化相对 POSIX 路径排序记录摘要。"""
    before = _check_directory_root(root, label, errors)
    if before is None:
        return None
    files = []
    _walk_tree(root, "", files, label, errors)
    try:
        after = _lstat_now(root)
    except OSError as exc:
        errors.append(f"{label}: root replaced while scanning "
                      f"({type(exc).__name__}: {exc})")
        return None
    if stat.S_ISLNK(after.st_mode) or not stat.S_ISDIR(after.st_mode):
        errors.append(f"{label}: root replaced while scanning")
        return None
    if not os.path.samestat(before, after):
        errors.append(f"{label}: root identity changed while scanning")
        return None
    if errors:
        return None
    records = sorted((dict(record) for record in files),
                     key=lambda record: record["path"])
    if not _has_required_release_files(records, label, errors):
        return None
    return {"root": os.path.abspath(str(root)),
            "tree": _tree_summary(records), "files": records}


def _check_bundle_shape(bundle_dir, errors):
    """状态包形态预检（只读、不读内容）：根与固定三条目都必须是普通非链接路径。"""
    if _check_directory_root(bundle_dir, "backup_bundle", errors) is None:
        return False
    before = len(errors)
    for name in backup.FIXED_ENTRIES:
        path = _fixed_entry_path(bundle_dir, name)
        try:
            info = _lstat_now(path)
        except OSError:
            errors.append(f"backup_bundle: entry {name}: missing")
            continue
        if stat.S_ISLNK(info.st_mode):
            errors.append(f"backup_bundle: entry {name}: symlink is not "
                          "accepted")
        elif not stat.S_ISREG(info.st_mode):
            errors.append(f"backup_bundle: entry {name}: not a regular file")
    return len(errors) == before


def _verify_backup(bundle_dir):
    """只读复核状态包（测试注入点；生产直接复用 O 模块的 verify_bundle）。"""
    return backup.verify_bundle(bundle_dir)


def _read_bounded_file(path, label, errors, *, limit):
    """按 LC-036 严格身份绑定读入一个受限大小的普通文件全字节。"""
    try:
        before = _lstat_now(path)
    except OSError:
        errors.append(f"{label}: missing")
        return None
    if stat.S_ISLNK(before.st_mode):
        errors.append(f"{label}: symlink is not accepted")
        return None
    if not stat.S_ISREG(before.st_mode):
        errors.append(f"{label}: not a regular file")
        return None
    try:
        fd = _open_readonly(path)
    except OSError as exc:
        errors.append(f"{label}: open failed ({type(exc).__name__}: {exc})")
        return None
    chunks = []
    size = 0
    try:
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                errors.append(f"{label}: opened object is not a regular file")
                return None
            if not os.path.samestat(before, opened):
                errors.append(f"{label}: identity changed between check and "
                              "open")
                return None
            if opened.st_size > limit:
                errors.append(f"{label}: too large ({opened.st_size} bytes)")
                return None
            while True:
                chunk = os.read(fd, CHUNK_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            after_read = os.fstat(fd)
        except OSError as exc:
            errors.append(f"{label}: read failed "
                          f"({type(exc).__name__}: {exc})")
            return None
    finally:
        os.close(fd)
    if (after_read.st_size, after_read.st_mtime_ns, after_read.st_ctime_ns) \
            != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) \
            or size != after_read.st_size:
        errors.append(f"{label}: changed while reading")
        return None
    try:
        current = _fstat_now(path)
    except OSError as exc:
        errors.append(f"{label}: replaced while reading "
                      f"({type(exc).__name__}: {exc})")
        return None
    if not stat.S_ISREG(current.st_mode) \
            or not os.path.samestat(opened, current) \
            or _identity(current) != _identity(opened):
        errors.append(f"{label}: replaced while reading")
        return None
    return b"".join(chunks)


def _manifest_digest(bundle_dir, errors):
    raw = _read_bounded_file(_fixed_entry_path(bundle_dir,
                                               backup.MANIFEST_ENTRY),
                             "backup bundle manifest", errors,
                             limit=MANIFEST_LIMIT)
    if raw is None:
        return None
    return hashlib.sha256(raw).hexdigest()


def _payload_fingerprint(verification):
    """O 包两个 payload 的 (entry, size, sha256) 指纹，用于绑定期间复核对齐。"""
    contents = verification.get("contents")
    if not isinstance(contents, dict):
        return None
    fingerprint = []
    for role, _entry, _fields in CONTENT_ROLES:
        report = contents.get(role)
        if not isinstance(report, dict):
            return None
        fingerprint.append((role, report.get("entry"), report.get("size"),
                            report.get("sha256")))
    return tuple(fingerprint)


def _backup_document(bundle_dir, errors):
    """把已经 O 模块只读验证的状态包固定进合同（含 manifest 与 payload 摘要）。"""
    try:
        before = _lstat_now(bundle_dir)
    except OSError as exc:
        errors.append(f"backup_bundle: missing ({type(exc).__name__}: {exc})")
        return None
    first, _ = _verify_backup(bundle_dir)
    if not isinstance(first, dict) or not first.get("bundle_valid") \
            or first.get("errors"):
        errors.append("backup_bundle: state bundle failed read-only "
                      "verification; run `python -m scam.linux_backup verify` "
                      "and fix it before planning an upgrade")
        return None
    if first.get("schema") != backup.SCHEMA:
        schema = first.get("schema")
        errors.append(f"backup_bundle: unknown schema ({schema!r})")
        return None
    fingerprint = _payload_fingerprint(first)
    if fingerprint is None:
        errors.append("backup_bundle: verification result lacks the fixed "
                      "database/config contents")
        return None
    manifest_sha256 = _manifest_digest(bundle_dir, errors)
    if manifest_sha256 is None:
        return None
    # 复核：绑定期间包不得变化（结构与 payload 摘要都要重新对齐）
    second, _ = _verify_backup(bundle_dir)
    if not isinstance(second, dict) or not second.get("bundle_valid") \
            or second.get("errors"):
        errors.append("backup_bundle: bundle changed while binding")
        return None
    if _payload_fingerprint(second) != fingerprint:
        errors.append("backup_bundle: payload digests changed while binding")
        return None
    if _manifest_digest(bundle_dir, errors) != manifest_sha256:
        errors.append("backup_bundle: manifest changed while binding")
        return None
    try:
        after = _lstat_now(bundle_dir)
    except OSError as exc:
        errors.append(f"backup_bundle: replaced while binding "
                      f"({type(exc).__name__}: {exc})")
        return None
    if stat.S_ISLNK(after.st_mode) or not stat.S_ISDIR(after.st_mode) \
            or not os.path.samestat(before, after):
        errors.append("backup_bundle: identity changed while binding")
        return None
    if errors:
        return None
    contents = {}
    for role, entry, fields in CONTENT_ROLES:
        report = first["contents"][role]
        record = {"entry": report["entry"], "size": report["size"],
                  "sha256": report["sha256"]}
        if "integrity_check" in fields:
            if report.get("integrity_check") != "ok":
                errors.append(f"backup_bundle: {role} integrity check missing")
                return None
            record["integrity_check"] = "ok"
        contents[role] = record
    return {"bundle_dir": os.path.abspath(str(bundle_dir)),
            "bundle_valid": True, "manifest_sha256": manifest_sha256,
            "contents": contents}


def _contract_document(current_dir, candidate_dir, bundle_dir, errors):
    current = _scan_tree(current_dir, "current_release", errors)
    candidate = _scan_tree(candidate_dir, "candidate_release", errors)
    bound = _backup_document(bundle_dir, errors)
    if errors or current is None or candidate is None or bound is None:
        return None
    document = {
        "schema": SCHEMA,
        "kind": KIND,
        "created_at": _utc_now(),
        "tool": TOOL_NAME,
        "note": CONTRACT_NOTE,
        "service": SERVICE_NAME,
        "health_endpoint": HEALTH_ENDPOINT,
        "phases": list(PHASES),
        "current_release": current,
        "candidate_release": candidate,
        "backup": bound,
        "success_checklist": [dict(step) for step in SUCCESS_CHECKLIST],
        "rollback_checklist": [dict(step) for step in ROLLBACK_CHECKLIST],
    }
    for field, expected in HONESTY_FIELDS:
        document[field] = expected
    return document


def _write_contract(output_dir, document, errors):
    target = _checked_destination(output_dir,
                                 _fixed_entry_path(output_dir,
                                                   CONTRACT_ENTRY), errors)
    if target is None:
        return False
    payload = json.dumps(document, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8") + b"\n"
    return _write_at(target, payload, "contract", errors)


def _fail(result, output_dir, errors):
    removed = _remove_created_dir(output_dir, True)
    result["output_dir_removed"] = removed
    if not removed:
        errors.append("output_dir: cleanup failed; a partial directory "
                      "remains")
    result["errors"] = list(errors)
    return result, errors


def prepare_contract(current_release_dir, candidate_release_dir,
                     backup_bundle_dir, output_dir):
    """只读规划一个升级事务合同；返回 (result, errors)。

    阶段0只做形态预检（不创建任何路径）：两个发布根存在、非链接、互不相同且互不
    嵌套，状态包形态可用，合同目录此前不存在且不落在任何输入根内。阶段1原子排他
    创建合同目录，随后遍历两棵树、绑定已 O 模块验证的状态包、写出唯一合同文件。
    任何失败只清理本次新建目录，绝不删除发布树或备份包。
    """
    errors = []
    result = _base_result("upgrade_contract_prepare_result")
    result.update({"contract_dir": str(output_dir), "contract_created": False,
                   "output_dir_removed": None, "current_release": None,
                   "candidate_release": None, "backup": None,
                   "service": SERVICE_NAME, "health_endpoint": HEALTH_ENDPOINT,
                   "phases": list(PHASES), "errors": []})

    current_info = _check_directory_root(current_release_dir,
                                        "current_release", errors)
    candidate_info = _check_directory_root(candidate_release_dir,
                                           "candidate_release", errors)
    if current_info is not None and candidate_info is not None:
        _check_root_relation(current_release_dir, candidate_release_dir,
                             current_info, candidate_info, errors)
    _check_bundle_shape(backup_bundle_dir, errors)
    _check_output_location(output_dir,
                           (("current_release", current_release_dir),
                            ("candidate_release", candidate_release_dir),
                            ("backup_bundle", backup_bundle_dir)), errors)
    if errors:
        result["errors"] = list(errors)
        return result, errors

    try:
        os.mkdir(output_dir)
    except FileExistsError:
        errors.append("output_dir: already exists; refusing to overwrite")
        result["errors"] = list(errors)
        return result, errors
    except OSError as exc:
        errors.append(f"output_dir: cannot create "
                      f"({type(exc).__name__}: {exc})")
        result["errors"] = list(errors)
        return result, errors

    document = None
    try:
        document = _contract_document(current_release_dir,
                                      candidate_release_dir,
                                      backup_bundle_dir, errors)
    except Exception as exc:  # 任何未预期异常都转结构化失败并清理本目录
        errors.append(f"prepare: unexpected {type(exc).__name__}: {exc}")
        document = None

    if errors or document is None:
        return _fail(result, output_dir, errors)

    if not _write_contract(output_dir, document, errors):
        return _fail(result, output_dir, errors)

    result.update({"contract_created": True, "output_dir_removed": None,
                   "current_release": document["current_release"],
                   "candidate_release": document["candidate_release"],
                   "backup": document["backup"], "errors": []})
    return result, errors


def _validate_release(release, label, errors):
    """校验一个发布条目：固定字段、安全相对路径、确定性排序与自洽摘要。"""
    where = f"contract: {label}"
    if not isinstance(release, dict):
        errors.append(f"{where} must be a JSON object")
        return
    unknown = sorted(set(release) - set(RELEASE_FIELDS))
    if unknown:
        errors.append(f"{where}: unknown fields " + "/".join(unknown))
    for field in RELEASE_FIELDS:
        if field not in release:
            errors.append(f"{where}: missing field {field}")
    root = release.get("root")
    if not isinstance(root, str) or not root or "\x00" in root \
            or not os.path.isabs(root):
        errors.append(f"{where}.root: must be an absolute path string")
    records = []
    files = release.get("files")
    if not isinstance(files, list) or not files:
        errors.append(f"{where}.files: must be a non-empty list")
        files = []
    for index, item in enumerate(files):
        item_where = f"{where}.files[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{item_where} must be a JSON object")
            continue
        unknown = sorted(set(item) - set(FILE_ENTRY_FIELDS))
        if unknown:
            errors.append(f"{item_where}: unknown fields " + "/".join(unknown))
            continue
        path = item.get("path")
        if _unsafe_relative_path(path):
            errors.append(f"{item_where}.path: must be a safe relative POSIX "
                          "path")
            continue
        size = item.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            errors.append(f"{item_where}.size: must be a non-negative integer")
            continue
        digest = item.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 \
                or any(char not in "0123456789abcdef" for char in digest):
            errors.append(f"{item_where}.sha256: must be a 64-character "
                          "lowercase hex digest")
            continue
        records.append({"path": path, "size": size, "sha256": digest})
    if records and records != sorted(records, key=lambda record:
                                     record["path"]):
        errors.append(f"{where}.files: must be sorted by relative path and "
                      "unique")
    if files:
        _has_required_release_files(records, f"{where}.files", errors)
    tree = release.get("tree")
    if not isinstance(tree, dict):
        errors.append(f"{where}.tree must be a JSON object")
        return
    unknown = sorted(set(tree) - set(TREE_FIELDS))
    if unknown:
        errors.append(f"{where}.tree: unknown fields " + "/".join(unknown))
        return
    for field in TREE_FIELDS:
        if field not in tree:
            errors.append(f"{where}.tree: missing field {field}")
    if not files or len(records) != len(files):
        return  # 已逐条记录坏条目，摘要无法在此自洽比较
    summary = _tree_summary(records)
    if tree.get("files") != summary["files"]:
        errors.append(f"{where}.tree.files: must equal the recorded "
                      "file count")
    if tree.get("bytes") != summary["bytes"]:
        errors.append(f"{where}.tree.bytes: must equal the recorded "
                      "byte total")
    if tree.get("sha256") != summary["sha256"]:
        errors.append(f"{where}.tree.sha256: must equal the recorded "
                      "file list")


def _validate_backup(bound, errors):
    """校验备份引用：固定字段、O 包固定条目名、64 位十六进制摘要。"""
    where = "contract: backup"
    if not isinstance(bound, dict):
        errors.append(f"{where} must be a JSON object")
        return
    unknown = sorted(set(bound) - set(BACKUP_FIELDS))
    if unknown:
        errors.append(f"{where}: unknown fields " + "/".join(unknown))
    for field in BACKUP_FIELDS:
        if field not in bound:
            errors.append(f"{where}: missing field {field}")
    bundle_dir = bound.get("bundle_dir")
    if not isinstance(bundle_dir, str) or not bundle_dir \
            or "\x00" in bundle_dir or not os.path.isabs(bundle_dir):
        errors.append(f"{where}.bundle_dir: must be an absolute path string")
    if bound.get("bundle_valid") is not True:
        errors.append(f"{where}.bundle_valid: must be True")
    digest = bound.get("manifest_sha256")
    if not isinstance(digest, str) or len(digest) != 64 \
            or any(char not in "0123456789abcdef" for char in digest):
        errors.append(f"{where}.manifest_sha256: must be a 64-character "
                      "lowercase hex digest")
    contents = bound.get("contents")
    if not isinstance(contents, dict):
        errors.append(f"{where}.contents must be a JSON object")
        return
    unknown = sorted(set(contents) - {role for role, _e, _f in CONTENT_ROLES})
    if unknown:
        errors.append(f"{where}.contents: unknown entries "
                      + "/".join(unknown))
    for role, entry, fields in CONTENT_ROLES:
        role_where = f"{where}.contents.{role}"
        report = contents.get(role)
        if not isinstance(report, dict):
            errors.append(f"{role_where} must be a JSON object")
            continue
        unknown = sorted(set(report) - set(fields))
        if unknown:
            errors.append(f"{role_where}: unknown fields " + "/".join(unknown))
            continue
        if report.get("entry") != entry:
            errors.append(f"{role_where}.entry: unknown entry "
                          f"({report.get('entry')!r})")
        size = report.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            errors.append(f"{role_where}.size: must be a non-negative integer")
        role_digest = report.get("sha256")
        if not isinstance(role_digest, str) or len(role_digest) != 64 \
                or any(char not in "0123456789abcdef"
                       for char in role_digest):
            errors.append(f"{role_where}.sha256: must be a 64-character "
                          "lowercase hex digest")
        if "integrity_check" in fields \
                and report.get("integrity_check") != "ok":
            errors.append(f"{role_where}.integrity_check: must be 'ok'")


def _validate_checklist(stored, fixed, label, errors):
    """校验检查表为精确固定 schema：步序不得变化，字段集合与固定值必须一致。"""
    where = f"contract: {label}"
    if not isinstance(stored, list) or len(stored) != len(fixed):
        errors.append(f"{where}: must contain exactly "
                      f"{len(fixed)} fixed steps")
        return
    expected_steps = [step["step"] for step in fixed]
    actual_steps = [step.get("step") if isinstance(step, dict) else None
                    for step in stored]
    if actual_steps != expected_steps:
        errors.append(f"{where}: unsafe order; expected "
                      + " -> ".join(expected_steps))
        return
    for index, (item, expected) in enumerate(zip(stored, fixed)):
        item_where = f"{where}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{item_where} must be a JSON object")
            continue
        unknown = sorted(set(item) - set(expected))
        if unknown:
            errors.append(f"{item_where}: unknown fields " + "/".join(unknown))
            continue
        for field, value in expected.items():
            if item.get(field) != value:
                errors.append(f"{item_where}.{field}: must be {value!r}")


def _validate_rollback_conditions(stored, errors):
    """状态恢复必须显式条件化：把它标成无条件执行即拒绝。"""
    where = "contract: rollback_checklist"
    if not isinstance(stored, list):
        return
    conditional = {step["step"] for step in ROLLBACK_CHECKLIST
                   if step["condition"] == ROLLBACK_CONDITION}
    for index, item in enumerate(stored):
        if not isinstance(item, dict):
            continue
        if item.get("step") not in conditional:
            continue
        if item.get("condition") != ROLLBACK_CONDITION:
            errors.append(f"{where}[{index}].condition: state restore must be "
                          "conditional on an explicit data migration")


def _validate_contract(raw, errors):
    """校验合同结构与固定 schema；返回解析后的字典（有错即 None）。"""
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        errors.append(f"contract: invalid UTF-8 JSON ({type(exc).__name__})")
        return None
    if not isinstance(document, dict):
        errors.append("contract: root must be a JSON object")
        return None
    if document.get("schema") != SCHEMA:
        errors.append(f"contract: unknown schema ({document.get('schema')!r})")
        return None
    if document.get("kind") != KIND:
        errors.append(f"contract: unknown kind ({document.get('kind')!r})")
        return None
    # 精确封闭的根 schema：未知根字段与缺失固定字段都拒绝（继续收集其余错误）
    unknown = sorted(set(document) - CONTRACT_FIELD_SET)
    if unknown:
        errors.append("contract: unknown root fields " + "/".join(unknown))
    for field in CONTRACT_FIELDS:
        if field not in document:
            errors.append(f"contract: missing field {field}")
    if "created_at" in document and not _utc_timestamp(document["created_at"]):
        errors.append("contract: created_at must be a UTC Z timestamp")
    if "tool" in document and document["tool"] != TOOL_NAME:
        errors.append(f"contract: tool must be {TOOL_NAME!r}")
    if "note" in document and document["note"] != CONTRACT_NOTE:
        errors.append("contract: note must be the fixed module note")
    if "service" in document and document["service"] != SERVICE_NAME:
        errors.append(f"contract: service must be {SERVICE_NAME!r}")
    if "health_endpoint" in document \
            and document["health_endpoint"] != HEALTH_ENDPOINT:
        errors.append(f"contract: health_endpoint must be {HEALTH_ENDPOINT!r}")
    if "phases" in document and document["phases"] != list(PHASES):
        errors.append("contract: phases must be the fixed order "
                      + " -> ".join(PHASES))
    for field, expected in HONESTY_FIELDS:
        if field not in document:
            continue
        value = document[field]
        if expected is False and value is not False:
            errors.append(f"contract: {field} must be False")
        elif expected is None and value is not None:
            errors.append(f"contract: {field} must be None")
    if "current_release" in document:
        _validate_release(document["current_release"], "current_release",
                          errors)
    if "candidate_release" in document:
        _validate_release(document["candidate_release"], "candidate_release",
                          errors)
    if "backup" in document:
        _validate_backup(document["backup"], errors)
    if "success_checklist" in document:
        _validate_checklist(document["success_checklist"], SUCCESS_CHECKLIST,
                            "success_checklist", errors)
    if "rollback_checklist" in document:
        _validate_rollback_conditions(document["rollback_checklist"], errors)
        _validate_checklist(document["rollback_checklist"], ROLLBACK_CHECKLIST,
                            "rollback_checklist", errors)
    if errors:
        return None
    return document


def _scan_contract_entries(contract_dir, errors):
    """合同目录必须精确只含 contract.json 一个普通非链接文件。"""
    try:
        with os.scandir(contract_dir) as scanner:
            scanned = sorted(scanner, key=lambda item: item.name)
    except OSError as exc:
        errors.append(f"contract_dir: cannot list "
                      f"({type(exc).__name__}: {exc})")
        return None
    found = {}
    for item in scanned:
        if item.is_symlink():
            errors.append(f"contract_entry: {item.name}: symlink is not "
                          "accepted")
            continue
        if not item.is_file(follow_symlinks=False):
            errors.append(f"contract_entry: {item.name}: not a regular file")
            continue
        if item.name not in CONTRACT_ENTRY_SET:
            errors.append(f"contract_entry: {item.name}: unexpected path in "
                          "contract directory")
            continue
        found[item.name] = _fixed_entry_path(contract_dir, item.name)
    if CONTRACT_ENTRY not in found:
        errors.append(f"contract_entry: {CONTRACT_ENTRY}: missing")
    if errors:
        return None
    return found


def _verify_release_content(release, label, errors):
    """按合同记录重新只读遍历发布树，要求逐文件与摘要完全一致。"""
    scanned = _scan_tree(release["root"], label, errors)
    if scanned is None:
        return None
    if scanned["files"] != release["files"]:
        errors.append(f"{label}: tree content no longer matches the contract")
        return None
    if scanned["tree"] != release["tree"]:
        errors.append(f"{label}: tree summary no longer matches the contract")
        return None
    return scanned


def _verify_backup_content(bound, errors):
    """按合同记录重新只读复核状态包，要求结构与 payload 摘要仍完全一致。"""
    verification, _ = _verify_backup(bound["bundle_dir"])
    if not isinstance(verification, dict) \
            or not verification.get("bundle_valid") \
            or verification.get("errors"):
        errors.append("backup: state bundle no longer verifies read-only")
        return None
    fingerprint = _payload_fingerprint(verification)
    if fingerprint is None:
        errors.append("backup: verification result lacks the fixed "
                      "database/config contents")
        return None
    for role, entry, _fields in CONTENT_ROLES:
        recorded = bound["contents"][role]
        actual = verification["contents"][role]
        if actual.get("entry") != recorded.get("entry") \
                or actual.get("entry") != entry \
                or actual.get("size") != recorded.get("size") \
                or actual.get("sha256") != recorded.get("sha256"):
            errors.append(f"backup: {role} bytes no longer match the "
                          "contract")
            return None
    digest = _manifest_digest(bound["bundle_dir"], errors)
    if digest is None:
        return None
    if digest != bound["manifest_sha256"]:
        errors.append("backup: manifest SHA-256 no longer matches the "
                      "contract")
        return None
    return verification


def verify_contract(contract_dir):
    """严格只读复核合同；返回 (result, errors)。任何失败非零。"""
    errors = []
    result = _base_result("upgrade_contract_verify_result")
    result.update({"contract_dir": str(contract_dir), "contract_valid": False,
                   "current_release": None, "candidate_release": None,
                   "backup": None, "service": SERVICE_NAME,
                   "health_endpoint": HEALTH_ENDPOINT, "phases": list(PHASES),
                   "errors": []})

    if _check_directory_root(contract_dir, "contract_dir", errors) is None:
        result["errors"] = list(errors)
        return result, errors
    entries = _scan_contract_entries(contract_dir, errors)
    if entries is None:
        result["errors"] = list(errors)
        return result, errors
    raw = _read_bounded_file(entries[CONTRACT_ENTRY], "contract", errors,
                             limit=CONTRACT_LIMIT)
    if raw is None:
        result["errors"] = list(errors)
        return result, errors
    document = _validate_contract(raw, errors)
    if document is None:
        result["errors"] = list(errors)
        return result, errors

    current = _verify_release_content(document["current_release"],
                                      "current_release", errors)
    candidate = _verify_release_content(document["candidate_release"],
                                        "candidate_release", errors)
    if current is not None and candidate is not None:
        try:
            current_info = _lstat_now(current["root"])
            candidate_info = _lstat_now(candidate["root"])
        except OSError as exc:
            errors.append(f"release_roots: cannot inspect "
                          f"({type(exc).__name__}: {exc})")
        else:
            _check_root_relation(current["root"], candidate["root"],
                                 current_info, candidate_info, errors)
    _verify_backup_content(document["backup"], errors)
    if errors:
        result["errors"] = list(errors)
        return result, errors

    result.update({"contract_valid": True,
                   "current_release": document["current_release"],
                   "candidate_release": document["candidate_release"],
                   "backup": document["backup"], "errors": []})
    return result, errors


def main(argv=None):
    # 冻结 CLI 拼写：选项缩写一律关闭，杜绝靠前缀猜出 --backup-bundle 的近似拼写。
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="Linux L4 升级/回滚事务合同：prepare 只读规划并原子排他生成合同，"
                    "verify 只读复核合同与两棵树/备份包的一致性"
                    "（零网络/零子进程/零服务控制/零发布切换；不代表任何门禁通过）")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser(
        "prepare", allow_abbrev=False,
        help="只读规划升级事务并原子排他创建合同目录（只含 contract.json）")
    # LC-041 冻结 prepare 的四个路径占位符：help/usage 一律显示 DIR，不暴露
    # 由选项名派生的 CURRENT_RELEASE_DIR/CANDIDATE_RELEASE_DIR/OUTPUT_DIR 别名。
    prepare_parser.add_argument("--current-release-dir", required=True,
                                metavar="DIR")
    prepare_parser.add_argument("--candidate-release-dir", required=True,
                                metavar="DIR")
    # LC-041 冻结拼写 --backup-bundle；dest 保留内部变量名 backup_bundle_dir。
    prepare_parser.add_argument("--backup-bundle", dest="backup_bundle_dir",
                                required=True, metavar="DIR")
    prepare_parser.add_argument("--output-dir", required=True, metavar="DIR")

    verify_parser = subparsers.add_parser(
        "verify", allow_abbrev=False,
        help="只读复核合同、两个发布树与已绑定状态包")
    verify_parser.add_argument("--contract-dir", required=True)

    args = parser.parse_args(argv)
    if args.command == "prepare":
        result, errors = prepare_contract(args.current_release_dir,
                                         args.candidate_release_dir,
                                         args.backup_bundle_dir,
                                         args.output_dir)
    else:
        result, errors = verify_contract(args.contract_dir)

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
