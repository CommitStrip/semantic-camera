"""Linux 原生运维证据封存器（队列Q工具）。

只在原生 Linux（``sys.platform == "linux"``，精确比对，不接受 ``linux-proxy``
这类近似值）上把运维人员已经产生的只读证据封存成一份固定 schema 的
``manifest.json``：六类输入分别是主机预检输出、单相机 acceptance 报告、浸泡
证据目录、状态备份包、升级合同与固定步序 operations ledger，另有承载被引用
证据文件的 evidence root。``prepare`` 在不满足原生平台时于创建输出目录之前
结构化失败，命令行不提供任何绕过开关；``verify`` 是跨平台只读复核，可把同一
份封存目录带到另一台机器离线审计。

诚实边界：本模块不执行命令、不联网、不起子进程、不提权、不控制服务、不安装、
不切换发布、不恢复状态，也不写入在线数据库或配置；它只读复用既有 O/P/浸泡
复核函数，并封存运维人员自己产生的记录。ledger 结构完整**不等于**任何门禁
通过：``operator_confirmed`` 与 ``exit_code`` 只是被如实记录的事实，不构成
第三方真实性证明；三个门禁字段（含两个总门禁）恒为 null。离线可 verify 也
不等于采集发生在 Linux——采集平台以 manifest 的 ``collected_on`` 为准。

用法::

  python -m scam.linux_ops_evidence prepare --host-probe FILE \\
      --acceptance-report FILE --soak-dir DIR --backup-bundle DIR \\
      --upgrade-contract DIR --operations-ledger FILE --evidence-root DIR \\
      --output-dir DIR
  python -m scam.linux_ops_evidence verify --bundle-dir DIR
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
import scam.linux_soak_verify as soak_verify
import scam.linux_upgrade_contract as upgrade_contract

SCHEMA = "scam.linux-ops-evidence/v1"
KIND = "ops_evidence_bundle"
LEDGER_SCHEMA = "scam.linux-ops-ledger/v1"
LEDGER_KIND = "operations_ledger"
HOST_PROBE_SCHEMA = "scam.linux-host-probe/v1"
HOST_PROBE_KIND = "host_preflight"
MANIFEST_ENTRY = "manifest.json"
MANIFEST_ENTRY_SET = frozenset((MANIFEST_ENTRY,))
TOOL_NAME = "scam.linux_ops_evidence"
# 与 pyproject.toml 的 [project].version 保持一致；manifest 记录采集工具版本。
TOOL_VERSION = "0.1.0"
NATIVE_PLATFORM = "linux"
ACCEPTANCE_SCHEMA_VERSION = 2
ACCEPTANCE_SCOPE = "single_camera_lab_probe"
# LC-044 冻结的运维步序：漏步、重复、改序或换名都拒绝，绝不自动补步。
STEP_IDS = ("clean_install",
            "initial_start_health",
            "restart_recovery",
            "backup_create_verify",
            "upgrade_prepare_verify",
            "candidate_switch_start_health",
            "code_rollback_start_health",
            "staging_restore_rehearsal",
            "capacity_gate_rehearsal",
            "privacy_network_audit")
STEP_FIELDS = ("id", "started_at", "finished_at", "command", "exit_code",
               "stdout", "stderr", "artifacts", "operator_confirmed")
LEDGER_FIELDS = ("schema", "kind", "created_at", "operator", "note", "steps")
LEDGER_FIELD_SET = frozenset(LEDGER_FIELDS)
# 诚实字段固定值：两个总门禁与质量门禁恒为 null，工具自身也从未执行任何动作。
HONESTY_FIELDS = (("artifacts_bound", True),
                  ("actions_executed", False),
                  ("service_controlled", False),
                  ("release_switched", False),
                  ("operator_records_verified", False),
                  ("native_linux_collected", True),
                  ("host_gate_passed", None),
                  ("quality_gate_passed", None),
                  ("release_gate_passed", None))
MANIFEST_FIXED_FIELDS = ("schema", "kind", "created_at", "tool",
                         "tool_version", "note", "collected_on", "step_order",
                         "host_probe", "acceptance_report", "soak",
                         "backup_bundle", "upgrade_contract",
                         "operations_ledger", "steps", "evidence_root")
MANIFEST_FIELDS = MANIFEST_FIXED_FIELDS + tuple(field for field, _ in
                                                HONESTY_FIELDS)
MANIFEST_FIELD_SET = frozenset(MANIFEST_FIELDS)
# 七类“带路径”绑定：binding 键 → ``_bindings`` 的入参键。verify 只从已校验的
# 记录里取回这些路径重新绑定，路径不安全就拒绝，绝不按未校验字符串读盘。
PATH_BINDINGS = (("host_probe", "host_probe"),
                 ("acceptance_report", "acceptance_report"),
                 ("soak", "soak_dir"),
                 ("backup_bundle", "backup_bundle"),
                 ("upgrade_contract", "upgrade_contract"),
                 ("operations_ledger", "operations_ledger"),
                 ("evidence_root", "evidence_root"))
BINDING_KEYS = tuple(key for key, _ in PATH_BINDINGS) + ("steps",)
STEP_RECORD_FIELDS = ("id", "exit_code", "operator_confirmed", "stdout",
                      "stderr", "artifacts")
EVIDENCE_RECORD_FIELDS = ("path", "size", "sha256")
SOAK_ENTRIES = ("manifest.json", "samples.ndjson", "summary.json")
CHUNK_SIZE = 1024 * 1024
ERROR_DETAIL_LIMIT = 8
HOST_PROBE_LIMIT = 1024 * 1024
ACCEPTANCE_LIMIT = 32 * 1024 * 1024
LEDGER_LIMIT = 4 * 1024 * 1024
MANIFEST_LIMIT = 8 * 1024 * 1024
SOAK_PAYLOAD_LIMIT = 512 * 1024 * 1024
SOAK_SUMMARY_LIMIT = 4 * 1024 * 1024
BUNDLE_MANIFEST_LIMIT = 64 * 1024 * 1024
CONTRACT_ENTRY_LIMIT = 64 * 1024 * 1024
MAX_EVIDENCE_FILES = 256
MAX_EVIDENCE_FILE_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_TOTAL_BYTES = 256 * 1024 * 1024
O_BINARY = getattr(os, "O_BINARY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
READ_FLAGS = os.O_RDONLY | O_BINARY | O_NOFOLLOW
# 写入侧独占创建：必须带 ``O_BINARY``，否则 Windows CRT 文本模式会把落盘字节
# 里的 ``\n`` 翻成 ``\r\n``，manifest 的哈希与字节都不再与记录一致。
EXCLUSIVE_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_BINARY
OPS_NOTE = ("运维证据封存器：只在原生 Linux 上只读绑定已产生的运维证据并写出固定 "
            "manifest；不执行任何命令、不控制服务、不切换发布、不恢复状态、不写入"
            "在线数据；封存完整性不等于任何门禁通过，两个总门禁恒为 null。")
HONESTY_NOTE = ("九个诚实字段描述的是封存记录与本次工具运行：采集平台以 manifest 的 "
                "collected_on 为准；verify 在任何平台都只读复核，绝不宣称本机是原生 "
                "Linux；三个门禁字段（含两个总门禁）恒为 null，证据保管完整不推导"
                "任何门禁通过。")


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _utc_timestamp(value):
    """UTC 时间戳必须是以 ``Z`` 结尾的 ISO-8601；本地时区或裸时间一律拒绝。"""
    if not isinstance(value, str) or len(value) < 2 or not value.endswith("Z"):
        return False
    try:
        stamp = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return stamp.tzinfo is not None and stamp.utcoffset() == timedelta(0)


def _parse_utc(value):
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and set(value) <= set("0123456789abcdef"))


def _platform_now():
    """采集平台观测点：生产即 ``sys.platform``；测试只 patch 本函数。

    命令行**不**暴露任何平台开关，非精确 ``linux`` 一律在创建输出目录前失败。
    """
    return sys.platform


def _lstat_now(path):
    """路径身份采样点（测试经此注入确定性时序；生产即 ``os.lstat``）。"""
    return os.lstat(path)


def _fstat_now(fd):
    """句柄身份采样点（测试经此注入读取中变化；生产即 ``os.fstat``）。"""
    return os.fstat(fd)


def _open_readonly(path):
    return os.open(path, READ_FLAGS)


def _open_exclusive(path):
    return os.open(path, EXCLUSIVE_WRITE_FLAGS, 0o600)


def _abspath(value):
    return os.path.abspath(str(value))


def _norm(value):
    return os.path.normcase(os.path.abspath(str(value)))


def _is_inside(child, parent):
    child = _norm(child)
    parent = _norm(parent)
    return child.startswith(parent.rstrip(os.sep) + os.sep)


def _same_path(left, right):
    return _norm(left) == _norm(right)


def _unsafe_relative(value):
    """证据相对路径必须是规范化的 POSIX 相对路径。

    反斜杠、绝对路径、盘符、NUL、空段与 ``.``/``..`` 段全部拒绝——ledger 的
    记录不参与任何"先拼接再清理"的路径运算。
    """
    if not isinstance(value, str) or not value or "\x00" in value:
        return True
    if value.startswith("/") or "\\" in value:
        return True
    if len(value) >= 2 and value[1] == ":":
        return True
    return any(part in ("", ".", "..") for part in value.split("/"))


def _unsafe_recorded_root(value):
    """manifest 记录的输入根必须是安全绝对路径：相对、空段与 ``.``/``..`` 拒绝。"""
    if not isinstance(value, str) or not value or "\x00" in value:
        return True
    if not os.path.isabs(value):
        return True
    parts = [part for part in value.replace("\\", "/").split("/") if part]
    if not parts:
        return True
    skip = 1 if (len(parts[0]) == 2 and parts[0][1] == ":") else 0
    for part in parts[skip:]:
        if part in (".", ".."):
            return True
    return False


# ---------- 只读复核原语 ----------

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


def _check_regular_file(path, label, errors):
    """输入文件必须是存在、非软链接、非目录的普通文件（不读取内容）。"""
    try:
        info = _lstat_now(path)
    except OSError:
        errors.append(f"{label}: missing")
        return None
    if stat.S_ISLNK(info.st_mode):
        errors.append(f"{label}: symlink is not accepted")
        return None
    if not stat.S_ISREG(info.st_mode):
        errors.append(f"{label}: not a regular file")
        return None
    return info


def _stream_file(path, label, errors, limit, sink=None):
    """按身份绑定流式读取一个普通文件，返回 ``path/size/sha256``。

    读取前 lstat、打开后 fstat 与路径快照 ``samestat`` 比对（换入即拒绝），
    读取后再用句柄快照复核 size/mtime/ctime，最后用路径快照复核 inode。任何
    环节变化都结构化失败；``limit`` 是单文件上界，超出立即停止读取，证据内容
    绝不整份载入内存（``sink`` 只服务有界 JSON 输入）。
    """
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
    digest = hashlib.sha256()
    size = 0
    overflow = False
    after_read = None
    try:
        try:
            opened = _fstat_now(fd)
        except OSError as exc:
            errors.append(f"{label}: cannot inspect the opened object "
                          f"({type(exc).__name__}: {exc})")
            return None
        if not stat.S_ISREG(opened.st_mode):
            errors.append(f"{label}: opened object is not a regular file")
            return None
        if not os.path.samestat(before, opened):
            errors.append(f"{label}: identity changed between check and open")
            return None
        try:
            while True:
                chunk = os.read(fd, CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    overflow = True
                    break
                digest.update(chunk)
                if sink is not None:
                    sink.append(chunk)
            after_read = _fstat_now(fd)
        except OSError as exc:
            errors.append(f"{label}: read failed "
                          f"({type(exc).__name__}: {exc})")
            return None
    finally:
        os.close(fd)
    if overflow:
        errors.append(f"{label}: exceeds the {limit} byte limit")
        return None
    if (after_read.st_size, after_read.st_mtime_ns, after_read.st_ctime_ns) \
            != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
        errors.append(f"{label}: changed while reading")
        return None
    if size != after_read.st_size:
        errors.append(f"{label}: truncated while reading")
        return None
    try:
        after = _lstat_now(path)
    except OSError as exc:
        errors.append(f"{label}: replaced while reading "
                      f"({type(exc).__name__}: {exc})")
        return None
    if stat.S_ISLNK(after.st_mode) or not stat.S_ISREG(after.st_mode) \
            or not os.path.samestat(before, after):
        errors.append(f"{label}: replaced while reading")
        return None
    return {"path": _abspath(path), "size": size, "sha256": digest.hexdigest()}


def _read_json_document(path, label, errors, limit):
    """有界读取一个 JSON 输入，返回 ``(记录, 文档)``；任何失败返回两个 None。"""
    raw = []
    record = _stream_file(path, label, errors, limit, sink=raw)
    if record is None:
        return None, None
    try:
        document = json.loads(b"".join(raw).decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        errors.append(f"{label}: invalid JSON ({type(exc).__name__})")
        return None, None
    if not isinstance(document, dict):
        errors.append(f"{label}: root must be a JSON object")
        return None, None
    return record, document


def _collect_errors(prefix, payload, errors):
    """把被复用复核函数返回的结构化错误折叠成前若干条，便于定位。"""
    if not isinstance(payload, dict):
        return
    for item in list(payload.get("errors") or [])[:ERROR_DETAIL_LIMIT]:
        errors.append(f"{prefix}: {item}")


# ---------- 输入形态与路径关系 ----------

def _check_input_relations(paths, errors):
    """输入之间必须互不相同且互不嵌套。

    任何一项落在另一项内部都拒绝：既避免证据被重复计入或被改写，也禁止把输出
    写进任何输入树。
    """
    for index, (left_label, left) in enumerate(paths):
        for right_label, right in paths[index + 1:]:
            if _same_path(left, right):
                errors.append(f"{left_label}: must not be the same path as "
                              f"{right_label}")
                continue
            if _is_inside(left, right):
                errors.append(f"{left_label}: must not be inside "
                              f"{right_label}")
                continue
            if _is_inside(right, left):
                errors.append(f"{right_label}: must not be inside "
                              f"{left_label}")


def _check_output_location(output_dir, roots, errors):
    """输出目录必须此前不存在，且不在任何输入根内、也不包含任何输入。"""
    try:
        info = _lstat_now(output_dir)
    except OSError:
        info = None
    if info is not None:
        if stat.S_ISLNK(info.st_mode):
            errors.append("output_dir: symlink is not accepted")
        else:
            errors.append("output_dir: already exists; refusing to overwrite")
        return False
    for label, root in roots:
        if _same_path(output_dir, root) or _is_inside(output_dir, root):
            errors.append(f"output_dir: must not be {label} or inside it")
            return False
        if _is_inside(root, output_dir):
            errors.append(f"output_dir: must not contain {label}")
            return False
    return True


def _create_output_dir(output_dir, errors):
    """阶段1的唯一创建面：原子排他创建输出目录，已存在即拒绝且绝不覆盖。"""
    try:
        os.mkdir(output_dir)
    except FileExistsError:
        errors.append("output_dir: already exists; refusing to overwrite")
        return False
    except OSError as exc:
        errors.append(f"output_dir: cannot create "
                      f"({type(exc).__name__}: {exc})")
        return False
    return True


def _cleanup_output_dir(output_dir):
    """失败时的唯一删除面：只回收本次新建目录里的固定 manifest 与空目录本身。

    绝不递归删除、绝不触碰既有目录——本函数只在 ``_create_output_dir`` 成功后
    调用；目录里若出现任何非本次写出的条目，``rmdir`` 会失败并如实返回 False。
    """
    entry = os.path.join(output_dir, MANIFEST_ENTRY)
    try:
        os.unlink(entry)
    except FileNotFoundError:
        pass
    except OSError:
        pass
    try:
        os.rmdir(output_dir)
    except OSError:
        return False
    return True


# ---------- 证据根扫描 ----------

def _walk_evidence(directory, prefix, records, totals, errors):
    """递归枚举证据根：软链接、设备/FIFO、危险名字与非常规条目一律记错。"""
    if totals["stop"]:
        return
    try:
        with os.scandir(directory) as scanner:
            entries = sorted(scanner, key=lambda item: item.name)
    except OSError as exc:
        errors.append(f"evidence_root: {prefix or '.'}: cannot list "
                      f"({type(exc).__name__}: {exc})")
        return
    for item in entries:
        relative = item.name if not prefix else f"{prefix}/{item.name}"
        if "/" in item.name or "\\" in item.name or "\x00" in item.name \
                or item.name in (".", ".."):
            errors.append(f"evidence_root: unsafe entry name at "
                          f"{prefix or '.'}")
            continue
        if item.is_symlink():
            errors.append(f"evidence_root: {relative}: symlink is not "
                          "accepted")
            continue
        if item.is_dir(follow_symlinks=False):
            _walk_evidence(item.path, relative, records, totals, errors)
            if totals["stop"]:
                return
            continue
        if not item.is_file(follow_symlinks=False):
            errors.append(f"evidence_root: {relative}: not a regular file")
            continue
        if totals["count"] >= MAX_EVIDENCE_FILES:
            errors.append(f"evidence_root: more than "
                          f"{MAX_EVIDENCE_FILES} regular files")
            totals["stop"] = True
            return
        record = _stream_file(item.path, f"evidence_root: {relative}", errors,
                              MAX_EVIDENCE_FILE_BYTES)
        if record is None:
            continue
        totals["count"] += 1
        totals["bytes"] += record["size"]
        if totals["bytes"] > MAX_EVIDENCE_TOTAL_BYTES:
            errors.append(f"evidence_root: exceeds the "
                          f"{MAX_EVIDENCE_TOTAL_BYTES} byte total limit")
            totals["stop"] = True
            return
        record["path"] = relative
        records.append(record)


def _scan_evidence_root(root, references, errors):
    """只读扫描证据根并与 ledger 引用集合对账。

    返回 ``path/file_count/total_bytes/files``。引用缺失、未引用文件、超限、
    根被替换或任何身份变化都结构化失败；成功返回的视图只在无错时产生。
    """
    before = _check_directory_root(root, "evidence_root", errors)
    if before is None:
        return None
    records = []
    totals = {"count": 0, "bytes": 0, "stop": False}
    _walk_evidence(root, "", records, totals, errors)
    try:
        after = _lstat_now(root)
    except OSError as exc:
        errors.append(f"evidence_root: root replaced while scanning "
                      f"({type(exc).__name__}: {exc})")
        return None
    if stat.S_ISLNK(after.st_mode) or not stat.S_ISDIR(after.st_mode) \
            or not os.path.samestat(before, after):
        errors.append("evidence_root: root identity changed while scanning")
        return None
    files = sorted(records, key=lambda record: record["path"])
    present = {record["path"] for record in files}
    for path in sorted(set(references) - present):
        errors.append(f"evidence_root: referenced file missing: {path}")
    for path in sorted(present - set(references)):
        errors.append(f"evidence_root: unreferenced file: {path}")
    if errors:
        return None
    return {"path": _abspath(root), "file_count": len(files),
            "total_bytes": totals["bytes"], "files": files}


# ---------- ledger 合同 ----------

def _validate_step(step, index, expected_id, errors):
    """按固定九字段校验一步；返回规范化视图（错误由调用方统一裁决）。"""
    where = f"operations_ledger: steps[{index}]"
    if not isinstance(step, dict):
        errors.append(f"{where} must be a JSON object")
        return None
    unknown = sorted(set(step) - set(STEP_FIELDS))
    if unknown:
        errors.append(f"{where}: unknown fields " + "/".join(unknown))
    for field in STEP_FIELDS:
        if field not in step:
            errors.append(f"{where}: missing field {field}")
    identifier = step.get("id")
    if not isinstance(identifier, str) or not identifier:
        errors.append(f"{where}: id must be a non-empty string")
    elif expected_id is not None and identifier != expected_id:
        errors.append(f"{where}: id must be {expected_id!r} "
                      "(the fixed step order)")
    started = step.get("started_at")
    finished = step.get("finished_at")
    if not _utc_timestamp(started):
        errors.append(f"{where}: started_at must be a UTC Z timestamp")
    if not _utc_timestamp(finished):
        errors.append(f"{where}: finished_at must be a UTC Z timestamp")
    if _utc_timestamp(started) and _utc_timestamp(finished) \
            and _parse_utc(finished) < _parse_utc(started):
        errors.append(f"{where}: finished_at must not precede started_at")
    command = step.get("command")
    if not isinstance(command, str) or not command.strip():
        errors.append(f"{where}: command must be a non-empty string")
    exit_code = step.get("exit_code")
    if not _is_int(exit_code):
        errors.append(f"{where}: exit_code must be an integer")
    for field in ("stdout", "stderr"):
        value = step.get(field)
        if not isinstance(value, str) or _unsafe_relative(value):
            errors.append(f"{where}: {field} must be a safe relative POSIX "
                          "path under the evidence root")
    artifacts = step.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append(f"{where}: artifacts must be a JSON array")
        artifacts = []
    else:
        for position, artifact in enumerate(artifacts):
            if not isinstance(artifact, str) or _unsafe_relative(artifact):
                errors.append(f"{where}: artifacts[{position}] must be a safe "
                              "relative POSIX path under the evidence root")
    if not isinstance(step.get("operator_confirmed"), bool):
        errors.append(f"{where}: operator_confirmed must be a boolean")
    return {"id": identifier, "exit_code": exit_code,
            "stdout": step.get("stdout"), "stderr": step.get("stderr"),
            "artifacts": [item for item in artifacts
                          if isinstance(item, str)],
            "operator_confirmed": step.get("operator_confirmed")}


def _validate_ledger(document, errors):
    """校验固定 schema、封闭根字段、固定十步步序与每步固定九字段。"""
    unknown = sorted(set(document) - LEDGER_FIELD_SET)
    if unknown:
        errors.append("operations_ledger: unknown root fields "
                      + "/".join(unknown))
    for field in LEDGER_FIELDS:
        if field not in document:
            errors.append(f"operations_ledger: missing field {field}")
    if document.get("schema") != LEDGER_SCHEMA:
        errors.append("operations_ledger: unknown schema "
                      f"({document.get('schema')!r})")
    if document.get("kind") != LEDGER_KIND:
        errors.append(f"operations_ledger: kind must be {LEDGER_KIND!r}")
    if not _utc_timestamp(document.get("created_at")):
        errors.append("operations_ledger: created_at must be a UTC Z "
                      "timestamp")
    operator = document.get("operator")
    if not isinstance(operator, str) or not operator.strip():
        errors.append("operations_ledger: operator must be a non-empty string")
    note = document.get("note")
    if not isinstance(note, str) or not note.strip():
        errors.append("operations_ledger: note must be a non-empty string")
    steps = document.get("steps")
    if not isinstance(steps, list):
        errors.append("operations_ledger: steps must be a JSON array")
        return None
    if len(steps) != len(STEP_IDS):
        errors.append("operations_ledger: steps must contain exactly "
                      f"{len(STEP_IDS)} entries in the fixed order")
    validated = []
    for index, step in enumerate(steps):
        expected_id = STEP_IDS[index] if index < len(STEP_IDS) else None
        validated.append(_validate_step(step, index, expected_id, errors))
    return validated


def _collect_references(steps, errors):
    """收集证据引用：同一条相对路径只允许被引用一次。"""
    references = {}
    for step in steps:
        if not isinstance(step, dict):
            continue
        paths = [step.get("stdout"), step.get("stderr")]
        artifacts = step.get("artifacts")
        if isinstance(artifacts, list):
            paths.extend(artifacts)
        for path in paths:
            if not isinstance(path, str) or _unsafe_relative(path):
                continue
            if path in references:
                errors.append("operations_ledger: duplicate evidence "
                              f"reference {path}")
                continue
            references[path] = step.get("id")
    return references


def _step_records(steps, evidence_by_path):
    """按固定步序把每步的退出码、人工确认与证据摘要固化成 manifest 记录。

    记录的只是"运维人员写了什么、证据字节的摘要是什么"，不是真实性证明。
    任何引用未落在证据根视图里都返回 None，由调用方结构化失败——绝不静默补零。
    """
    records = []
    for step in steps:
        paths = [step["stdout"], step["stderr"]] + list(step["artifacts"])
        if any(path not in evidence_by_path for path in paths):
            return None
        records.append({
            "id": step["id"], "exit_code": step["exit_code"],
            "operator_confirmed": step["operator_confirmed"],
            "stdout": dict(evidence_by_path[step["stdout"]]),
            "stderr": dict(evidence_by_path[step["stderr"]]),
            "artifacts": [dict(evidence_by_path[path])
                          for path in step["artifacts"]]})
    return records


# ---------- 六类输入 + 证据根绑定 ----------

def _bind_host_probe(path, errors):
    record, document = _read_json_document(path, "host_probe", errors,
                                           HOST_PROBE_LIMIT)
    if document is None:
        return None
    if document.get("schema") != HOST_PROBE_SCHEMA:
        errors.append("host_probe: unknown schema "
                      f"({document.get('schema')!r})")
    if document.get("kind") != HOST_PROBE_KIND:
        errors.append(f"host_probe: kind must be {HOST_PROBE_KIND!r}")
    if document.get("platform_system") != NATIVE_PLATFORM:
        errors.append("host_probe: platform_system must be 'linux'")
    if document.get("native_linux") is not True:
        errors.append("host_probe: native_linux must be true")
    # 预检自身未评估的两个门禁必须仍是 null：工具可发现性不升级为兼容或健康证据。
    for field in ("host_gate_passed", "release_gate_passed"):
        if document.get(field) is not None:
            errors.append(f"host_probe: {field} must stay null")
    version = document.get("python_version")
    if not isinstance(version, str) or not version:
        errors.append("host_probe: python_version must be a non-empty string")
    tools = document.get("tools")
    view = []
    if not isinstance(tools, list):
        errors.append("host_probe: tools must be a JSON array")
    else:
        for position, item in enumerate(tools):
            if not isinstance(item, dict):
                errors.append(f"host_probe: tools[{position}] must be a "
                              "JSON object")
                continue
            name = item.get("name")
            available = item.get("available")
            if not isinstance(name, str) or not name:
                errors.append(f"host_probe: tools[{position}].name must be a "
                              "non-empty string")
                continue
            if not isinstance(available, bool):
                errors.append(f"host_probe: tools[{position}].available must "
                              "be a boolean")
                continue
            view.append({"name": name, "available": available})
    record["structure"] = {"schema": HOST_PROBE_SCHEMA,
                           "kind": HOST_PROBE_KIND,
                           "platform_system": NATIVE_PLATFORM,
                           "native_linux": True,
                           "python_version": version, "tools": view}
    return record


def _bind_acceptance_report(path, errors):
    record, document = _read_json_document(path, "acceptance_report", errors,
                                           ACCEPTANCE_LIMIT)
    if document is None:
        return None
    version = document.get("schema_version")
    if not _is_int(version) or version != ACCEPTANCE_SCHEMA_VERSION:
        errors.append("acceptance_report: schema_version must be "
                      f"{ACCEPTANCE_SCHEMA_VERSION}")
    if document.get("scope") != ACCEPTANCE_SCOPE:
        errors.append(f"acceptance_report: scope must be "
                      f"{ACCEPTANCE_SCOPE!r}")
    # 单相机实验报告不得自带发布结论：置真即拒绝，局部子门禁绝不升级为总门禁。
    if document.get("release_gate_passed") is not None:
        errors.append("acceptance_report: release_gate_passed must stay null")
    camera = document.get("camera")
    if not isinstance(camera, str) or not camera:
        errors.append("acceptance_report: camera must be a non-empty string")
    duration = document.get("duration_s")
    if not _is_number(duration):
        errors.append("acceptance_report: duration_s must be a number")
        duration = None
    digests = {}
    for field in ("config_sha256", "model_sha256"):
        value = document.get(field)
        if value is not None and not _is_hex64(value):
            errors.append(f"acceptance_report: {field} must be 64 hex chars "
                          "or null")
        digests[field] = value if _is_hex64(value) else None
    record["structure"] = {
        "schema_version": ACCEPTANCE_SCHEMA_VERSION, "scope": ACCEPTANCE_SCOPE,
        "release_gate_passed": None, "camera": camera,
        "duration_s": float(duration) if duration is not None else None,
        "config_sha256": digests["config_sha256"],
        "model_sha256": digests["model_sha256"]}
    return record


def _bind_soak(soak_dir, errors):
    verification = soak_verify.verify_soak_directory(soak_dir)
    if not isinstance(verification, dict) \
            or not verification.get("integrity_passed"):
        errors.append("soak: evidence package integrity did not verify")
        _collect_errors("soak", verification, errors)
        return None
    manifest_record = _stream_file(os.path.join(soak_dir, SOAK_ENTRIES[0]),
                                   "soak: manifest.json", errors,
                                   SOAK_PAYLOAD_LIMIT)
    samples_record = _stream_file(os.path.join(soak_dir, SOAK_ENTRIES[1]),
                                  "soak: samples.ndjson", errors,
                                  SOAK_PAYLOAD_LIMIT)
    summary_record, summary = _read_json_document(
        os.path.join(soak_dir, SOAK_ENTRIES[2]), "soak: summary.json", errors,
        SOAK_SUMMARY_LIMIT)
    if manifest_record is None or samples_record is None \
            or summary_record is None:
        return None
    # ``completed_requested_duration`` 只作事实记录：完整性通过不等于 24 小时完成，
    # 未跑满也只如实写 false，绝不改写成任何门禁结论。
    completed = summary.get("completed_requested_duration")
    if not isinstance(completed, bool):
        errors.append("soak: summary.completed_requested_duration must be a "
                      "boolean")
        completed = None
    count = verification.get("sample_count")
    if not _is_int(count) or count < 0:
        errors.append("soak: verified sample_count must be a non-negative int")
        count = None
    return {"path": _abspath(soak_dir), "integrity_passed": True,
            "sample_count": count, "completed_requested_duration": completed,
            "manifest_sha256": manifest_record["sha256"],
            "samples_sha256": samples_record["sha256"],
            "summary_sha256": summary_record["sha256"]}


def _bind_backup_bundle(bundle_dir, errors):
    verification, _ = backup.verify_bundle(bundle_dir)
    if not isinstance(verification, dict) \
            or not verification.get("bundle_valid"):
        errors.append("backup_bundle: state bundle does not verify read-only")
        _collect_errors("backup_bundle", verification, errors)
        return None
    contents = verification.get("contents")
    if not isinstance(contents, dict):
        errors.append("backup_bundle: verification result lacks contents")
        return None
    manifest_record = _stream_file(os.path.join(bundle_dir,
                                                backup.MANIFEST_ENTRY),
                                   "backup_bundle: manifest.json", errors,
                                   BUNDLE_MANIFEST_LIMIT)
    if manifest_record is None:
        return None
    return {"path": _abspath(bundle_dir), "bundle_valid": True,
            "manifest_sha256": manifest_record["sha256"],
            "contents": contents}


def _bind_upgrade_contract(contract_dir, errors):
    verification, _ = upgrade_contract.verify_contract(contract_dir)
    if not isinstance(verification, dict) \
            or not verification.get("contract_valid"):
        errors.append("upgrade_contract: contract does not verify read-only")
        _collect_errors("upgrade_contract", verification, errors)
        return None
    record = _stream_file(os.path.join(contract_dir,
                                       upgrade_contract.CONTRACT_ENTRY),
                          "upgrade_contract: contract.json", errors,
                          CONTRACT_ENTRY_LIMIT)
    if record is None:
        return None
    current = verification.get("current_release")
    candidate = verification.get("candidate_release")
    bound = verification.get("backup")
    if not isinstance(current, dict) or not isinstance(candidate, dict):
        errors.append("upgrade_contract: verification result lacks both "
                      "release trees")
        return None
    if not isinstance(bound, dict):
        errors.append("upgrade_contract: verification result lacks the bound "
                      "state bundle")
        return None
    return {"path": _abspath(contract_dir), "contract_valid": True,
            "contract_sha256": record["sha256"],
            "service": verification.get("service"),
            "health_endpoint": verification.get("health_endpoint"),
            "phases": list(verification.get("phases") or []),
            "current_release": {"root": current.get("root"),
                                "tree": current.get("tree")},
            "candidate_release": {"root": candidate.get("root"),
                                  "tree": candidate.get("tree")},
            "backup": {"bundle_dir": bound.get("bundle_dir"),
                       "bundle_valid": bound.get("bundle_valid"),
                       "manifest_sha256": bound.get("manifest_sha256"),
                       "contents": bound.get("contents")}}


def _bind_ledger(path, evidence_root, errors):
    """只读绑定 ledger 与证据根，返回 ``ledger/evidence/steps`` 三件套。"""
    record, document = _read_json_document(path, "operations_ledger", errors,
                                           LEDGER_LIMIT)
    if document is None:
        return None
    steps = _validate_ledger(document, errors)
    if steps is None:
        return None
    references = _collect_references(steps, errors)
    evidence = _scan_evidence_root(evidence_root, references, errors)
    if evidence is None:
        return None
    evidence_by_path = {item["path"]: item for item in evidence["files"]}
    step_records = _step_records(steps, evidence_by_path)
    if step_records is None:
        errors.append("operations_ledger: step evidence binding is incomplete")
        return None
    ledger = {"path": record["path"], "size": record["size"],
              "sha256": record["sha256"],
              "created_at": document.get("created_at"),
              "operator": document.get("operator"),
              "step_ids": [STEP_IDS[index] for index in range(len(steps))],
              "reference_count": len(references)}
    return {"ledger": ledger, "evidence": evidence, "steps": step_records}


def _bindings(paths, errors):
    """按固定顺序只读绑定六类输入与证据根；返回与 manifest 同形的 bindings。"""
    ledger_view = _bind_ledger(paths["operations_ledger"],
                               paths["evidence_root"], errors)
    bindings = {"host_probe": _bind_host_probe(paths["host_probe"], errors),
                "acceptance_report": _bind_acceptance_report(
                    paths["acceptance_report"], errors),
                "soak": _bind_soak(paths["soak_dir"], errors),
                "backup_bundle": _bind_backup_bundle(paths["backup_bundle"],
                                                     errors),
                "upgrade_contract": _bind_upgrade_contract(
                    paths["upgrade_contract"], errors)}
    if ledger_view is None:
        bindings.update({"operations_ledger": None, "evidence_root": None,
                         "steps": None})
    else:
        bindings.update({"operations_ledger": ledger_view["ledger"],
                         "evidence_root": ledger_view["evidence"],
                         "steps": ledger_view["steps"]})
    if errors:
        return None
    return bindings


def _manifest_document(bindings):
    """固定 schema 与封闭根字段的 manifest；不含任何推导出的门禁结论。"""
    document = {"schema": SCHEMA, "kind": KIND, "created_at": _utc_now(),
                "tool": TOOL_NAME, "tool_version": TOOL_VERSION,
                "note": OPS_NOTE,
                "collected_on": {"platform_system": NATIVE_PLATFORM,
                                 "python_version": sys.version.split()[0]},
                "step_order": list(STEP_IDS)}
    for key in BINDING_KEYS:
        document[key] = bindings[key]
    for field, expected in HONESTY_FIELDS:
        document[field] = expected
    return document


def _write_manifest_bytes(path, payload):
    """唯一写入点（测试经此注入写失败）：独占创建 + flush + fsync。"""
    fd = _open_exclusive(path)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _manifest_summary(size, sha256):
    """manifest 摘要的固定三字段（``entry``/``size``/``sha256``）。

    封存（``prepare`` 写出后）与复核（``verify`` 读完封存目录后）必须给出**同形**
    摘要：复核方据 ``entry`` 断定这确实是本封存目录的 ``manifest.json``，不会因为
    缺少 ``entry`` 或带上一台机器的绝对路径而与其它记录混淆。
    """
    return {"entry": MANIFEST_ENTRY, "size": size, "sha256": sha256}


def _write_manifest(output_dir, document, errors):
    """唯一写面：写出固定 manifest.json 并返回它的固定摘要。"""
    payload = _canonical(document) + b"\n"
    try:
        _write_manifest_bytes(os.path.join(output_dir, MANIFEST_ENTRY),
                              payload)
    except OSError as exc:
        errors.append(f"manifest.json: cannot write "
                      f"({type(exc).__name__}: {exc})")
        return None
    digest = hashlib.sha256(payload).hexdigest()
    return _manifest_summary(len(payload), digest)


def _base_result(kind):
    result = {"schema": SCHEMA, "kind": kind, "created_at": _utc_now(),
              "tool": TOOL_NAME, "tool_version": TOOL_VERSION,
              "note": OPS_NOTE, "honesty_note": HONESTY_NOTE, "errors": []}
    for field, expected in HONESTY_FIELDS:
        result[field] = expected
    return result


# ---------- prepare / verify ----------

def prepare_bundle(*, host_probe, acceptance_report, soak_dir, backup_bundle,
                   upgrade_contract_dir, operations_ledger, evidence_root,
                   output_dir):
    """在原生 Linux 上封存一次运维证据；返回 ``(result, errors)``。

    阶段0 平台闸：非精确 ``linux`` 直接结构化失败，不读输入、不创建任何路径。
    阶段1 形态预检与路径关系：只 lstat，不读内容、不创建路径。
    阶段2 原子排他创建输出目录，只读绑定六类输入与证据根后写出唯一 manifest。
    任何失败只回收本次新建目录，绝不改写、复制或删除任何输入证据。
    """
    errors = []
    result = _base_result("ops_evidence_prepare_result")
    result.update({"output_dir": str(output_dir), "bundle_created": False,
                   "output_dir_removed": None, "manifest": None,
                   "step_order": list(STEP_IDS), "errors": []})

    platform = _platform_now()
    if platform != NATIVE_PLATFORM:
        errors.append("platform: prepare requires an exact native Linux host "
                      f"(observed platform={platform!r})")
        result["errors"] = list(errors)
        return result, errors

    paths = {"host_probe": host_probe, "acceptance_report": acceptance_report,
             "soak_dir": soak_dir, "backup_bundle": backup_bundle,
             "upgrade_contract": upgrade_contract_dir,
             "operations_ledger": operations_ledger,
             "evidence_root": evidence_root}
    for label in ("host_probe", "acceptance_report", "operations_ledger"):
        _check_regular_file(paths[label], label, errors)
    for label in ("soak_dir", "backup_bundle", "upgrade_contract",
                  "evidence_root"):
        _check_directory_root(paths[label], label, errors)
    roots = sorted(paths.items())
    _check_input_relations(roots, errors)
    _check_output_location(output_dir, roots, errors)
    if errors:
        result["errors"] = list(errors)
        return result, errors

    created = False
    try:
        created = _create_output_dir(output_dir, errors)
        if not created:
            return result, errors
        bindings = _bindings(paths, errors)
        if bindings is None:
            return result, errors
        record = _write_manifest(output_dir, _manifest_document(bindings),
                                 errors)
        if record is None:
            return result, errors
        result.update({"bundle_created": True, "manifest": record})
        return result, errors
    finally:
        # 失败只回收**本次新建**的目录；未曾创建（输出已存在/创建失败）或成功
        # 完成时都不调用删除面，既有目录与既有文件绝不会被本模块触碰。
        if created and not result["bundle_created"]:
            result["output_dir_removed"] = _cleanup_output_dir(output_dir)
        # 返回的错误与状态对象**同步**：try 段任一处失败（建目录/绑定/写 manifest）
        # 都以非空 ``errors`` 返回，状态对象也必须是同一份非空结构化错误——绝不出现
        # 退出码 1 而 ``errors`` 为空。
        result["errors"] = list(errors)


def _scan_bundle_entries(bundle_dir, errors):
    """输出目录固定条目枚举：只允许 manifest.json，额外条目一律拒绝。"""
    try:
        with os.scandir(bundle_dir) as scanner:
            scanned = sorted(scanner, key=lambda item: item.name)
    except OSError as exc:
        errors.append(f"bundle_dir: cannot list ({type(exc).__name__}: {exc})")
        return None
    found = {}
    for item in scanned:
        if item.is_symlink():
            errors.append(f"bundle_entry: {item.name}: symlink is not "
                          "accepted")
            continue
        if not item.is_file(follow_symlinks=False):
            errors.append(f"bundle_entry: {item.name}: not a regular file")
            continue
        if item.name not in MANIFEST_ENTRY_SET:
            errors.append(f"bundle_entry: {item.name}: unexpected path in the "
                          "evidence bundle")
            continue
        found[item.name] = os.path.join(bundle_dir, item.name)
    for name in MANIFEST_ENTRY_SET:
        if name not in found:
            errors.append(f"bundle_entry: {name}: missing")
    if errors:
        return None
    return found


def _validate_evidence_record(value, where, errors):
    """封存记录里的证据条目：固定三字段 + 安全相对 POSIX 路径。"""
    if not isinstance(value, dict):
        errors.append(f"{where} must be a JSON object")
        return
    unknown = sorted(set(value) - set(EVIDENCE_RECORD_FIELDS))
    if unknown:
        errors.append(f"{where}: unknown fields " + "/".join(unknown))
    path = value.get("path")
    if not isinstance(path, str) or _unsafe_relative(path):
        errors.append(f"{where}.path must be a safe relative POSIX path")
    size = value.get("size")
    if not _is_int(size) or size < 0:
        errors.append(f"{where}.size must be a non-negative integer")
    if not _is_hex64(value.get("sha256")):
        errors.append(f"{where}.sha256 must be 64 hex chars")


def _validate_recorded_steps(steps, errors):
    """封存记录里的固定十步：id 必须逐位等于固定步序。"""
    if not isinstance(steps, list):
        errors.append("manifest: steps must be a JSON array")
        return
    if len(steps) != len(STEP_IDS):
        errors.append("manifest: steps must contain exactly "
                      f"{len(STEP_IDS)} entries")
    for position, entry in enumerate(steps):
        where = f"manifest: steps[{position}]"
        if not isinstance(entry, dict):
            errors.append(f"{where} must be a JSON object")
            continue
        unknown = sorted(set(entry) - set(STEP_RECORD_FIELDS))
        if unknown:
            errors.append(f"{where}: unknown fields " + "/".join(unknown))
        expected_id = STEP_IDS[position] if position < len(STEP_IDS) else None
        if entry.get("id") != expected_id:
            errors.append(f"{where}: id must be {expected_id!r} "
                          "(the fixed step order)")
        if not _is_int(entry.get("exit_code")):
            errors.append(f"{where}: exit_code must be an integer")
        if not isinstance(entry.get("operator_confirmed"), bool):
            errors.append(f"{where}: operator_confirmed must be a boolean")
        _validate_evidence_record(entry.get("stdout"), f"{where}.stdout",
                                  errors)
        _validate_evidence_record(entry.get("stderr"), f"{where}.stderr",
                                  errors)
        artifacts = entry.get("artifacts")
        if not isinstance(artifacts, list):
            errors.append(f"{where}: artifacts must be a JSON array")
            continue
        for index, item in enumerate(artifacts):
            _validate_evidence_record(item, f"{where}.artifacts[{index}]",
                                      errors)


def _validate_manifest(document, errors):
    """校验 manifest 的封闭根字段、固定值与记录的输入路径安全。

    返回 ``{"paths", "bindings"}``；任何失败返回 None。
    """
    unknown = sorted(set(document) - MANIFEST_FIELD_SET)
    if unknown:
        errors.append("manifest: unknown root fields " + "/".join(unknown))
    for field in MANIFEST_FIELDS:
        if field not in document:
            errors.append(f"manifest: missing field {field}")
    if document.get("schema") != SCHEMA:
        errors.append(f"manifest: unknown schema ({document.get('schema')!r})")
    if document.get("kind") != KIND:
        errors.append(f"manifest: kind must be {KIND!r}")
    if not _utc_timestamp(document.get("created_at")):
        errors.append("manifest: created_at must be a UTC Z timestamp")
    if document.get("tool") != TOOL_NAME:
        errors.append(f"manifest: tool must be {TOOL_NAME!r}")
    if document.get("tool_version") != TOOL_VERSION:
        errors.append(f"manifest: tool_version must be {TOOL_VERSION!r}")
    if document.get("note") != OPS_NOTE:
        errors.append("manifest: note must be the fixed module note")
    collected = document.get("collected_on")
    if not isinstance(collected, dict):
        errors.append("manifest: collected_on must be a JSON object")
    else:
        if set(collected) != {"platform_system", "python_version"}:
            errors.append("manifest: collected_on must contain exactly "
                          "platform_system and python_version")
        if collected.get("platform_system") != NATIVE_PLATFORM:
            errors.append("manifest: collected_on.platform_system must be "
                          "'linux'")
        if not isinstance(collected.get("python_version"), str):
            errors.append("manifest: collected_on.python_version must be a "
                          "string")
    if document.get("step_order") != list(STEP_IDS):
        errors.append("manifest: step_order must be the fixed ten step order")
    for field, expected in HONESTY_FIELDS:
        if field not in document:
            continue
        value = document[field]
        if expected is False and value is not False:
            errors.append(f"manifest: {field} must be False")
        elif expected is True and value is not True:
            errors.append(f"manifest: {field} must be True")
        elif expected is None and value is not None:
            errors.append(f"manifest: {field} must be None")
    _validate_recorded_steps(document.get("steps"), errors)
    paths = {}
    bindings = {}
    for key in BINDING_KEYS:
        value = document.get(key)
        if not isinstance(value, (dict, list)):
            errors.append(f"manifest: {key} must be a JSON object or array")
            continue
        bindings[key] = value
    for binding_key, paths_key in PATH_BINDINGS:
        value = bindings.get(binding_key)
        if not isinstance(value, dict):
            errors.append(f"manifest: {binding_key} must be a JSON object")
            continue
        root = value.get("path")
        if _unsafe_recorded_root(root):
            errors.append(f"manifest: {binding_key}.path must be a safe "
                          "absolute path")
            continue
        paths[paths_key] = root
    if errors:
        return None
    return {"paths": paths, "bindings": bindings}


def verify_bundle(bundle_dir):
    """跨平台只读复核一份封存目录；返回 ``(result, errors)``，任何变化非零。

    只读重算六类输入、证据根与固定步序并与 manifest 记录的摘要逐一比对：输入
    被改写、证据被换入、步序变化、危险路径或 manifest 形状不符都失败。本函数
    在自己的平台上不判定原生 Linux——采集平台只以 manifest 记录为准。
    """
    errors = []
    result = _base_result("ops_evidence_verify_result")
    result.update({"bundle_dir": str(bundle_dir), "bundle_valid": False,
                   "manifest": None, "step_order": list(STEP_IDS),
                   "errors": []})
    if _check_directory_root(bundle_dir, "bundle_dir", errors) is None:
        result["errors"] = list(errors)
        return result, errors
    entries = _scan_bundle_entries(bundle_dir, errors)
    if entries is None:
        result["errors"] = list(errors)
        return result, errors
    record, document = _read_json_document(entries[MANIFEST_ENTRY], "manifest",
                                           errors, MANIFEST_LIMIT)
    if record is None:
        result["errors"] = list(errors)
        return result, errors
    declared = _validate_manifest(document, errors)
    if declared is None:
        result["errors"] = list(errors)
        return result, errors
    actual = _bindings(declared["paths"], errors)
    if actual is None:
        result["errors"] = list(errors)
        return result, errors
    for key in BINDING_KEYS:
        if _canonical(actual[key]) != _canonical(declared["bindings"][key]):
            errors.append(f"manifest: {key} no longer matches the sealed "
                          "evidence")
    if errors:
        result["errors"] = list(errors)
        return result, errors
    result.update({"bundle_valid": True,
                   "manifest": _manifest_summary(record["size"],
                                                 record["sha256"])})
    return result, errors


def main(argv=None):
    # 冻结 CLI 拼写：选项缩写一律关闭，杜绝靠前缀猜出选项名的近似拼写。
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description="原生 Linux 运维证据封存器：prepare 只在精确原生 Linux 上只读"
                    "绑定六类证据并原子排他写出 manifest.json，verify 跨平台只读"
                    "复核（零网络/零子进程/零服务控制/零发布切换；不代表任何"
                    "门禁通过）")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser(
        "prepare", allow_abbrev=False,
        help="在原生 Linux 上封存运维证据，原子排他创建只含 manifest.json 的输出目录")
    prepare_parser.add_argument("--host-probe", required=True, metavar="FILE")
    prepare_parser.add_argument("--acceptance-report", required=True,
                                metavar="FILE")
    prepare_parser.add_argument("--soak-dir", required=True, metavar="DIR")
    prepare_parser.add_argument("--backup-bundle", required=True,
                                metavar="DIR")
    prepare_parser.add_argument("--upgrade-contract", required=True,
                                metavar="DIR")
    prepare_parser.add_argument("--operations-ledger", required=True,
                                metavar="FILE")
    prepare_parser.add_argument("--evidence-root", required=True,
                                metavar="DIR")
    prepare_parser.add_argument("--output-dir", required=True, metavar="DIR")

    verify_parser = subparsers.add_parser(
        "verify", allow_abbrev=False,
        help="跨平台只读复核封存目录、全部输入摘要与固定步序")
    verify_parser.add_argument("--bundle-dir", required=True, metavar="DIR")

    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result, errors = prepare_bundle(
                host_probe=args.host_probe,
                acceptance_report=args.acceptance_report,
                soak_dir=args.soak_dir, backup_bundle=args.backup_bundle,
                upgrade_contract_dir=args.upgrade_contract,
                operations_ledger=args.operations_ledger,
                evidence_root=args.evidence_root, output_dir=args.output_dir)
        else:
            result, errors = verify_bundle(args.bundle_dir)
    except Exception as exc:
        # 未预期异常同样结构化失败：不回显堆栈，也不留下半成品目录。错误同时进入
        # ``errors`` 数组，保证任何非零退出都带非空结构化错误。
        failure = _base_result("ops_evidence_error")
        failure["error"] = f"{type(exc).__name__}: {exc}"
        failure["bundle_created"] = False
        failure["errors"] = [failure["error"]]
        json.dump(failure, sys.stderr, ensure_ascii=False, sort_keys=True)
        sys.stderr.write("\n")
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
