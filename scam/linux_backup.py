"""Linux L4 operational state backup and restore (queue O).

One CLI with three subcommands over one fixed bundle layout::

    create  --db --config --output-dir
    verify  --bundle-dir
    restore --bundle-dir --target-dir

A bundle holds exactly three entries: ``manifest.json`` (written last),
``db.sqlite3`` (a consistent SQLite online-backup snapshot of committed
transactions only) and ``config.bin`` (the configuration file's raw
bytes).  ``create`` creates the output directory atomically and
exclusively -- an existing path is never overwritten, and a failed run
removes only the directory that same run created.  ``verify`` is strictly
read-only and rejects symlinked roots or payloads, non-regular files,
unexpected paths, path escapes, missing entries, size/SHA-256 mismatches,
unexpected manifest structure and SQLite integrity failures.  The manifest
root is a closed schema: the accepted key set is exactly ``schema``,
``kind``, ``created_at``, ``tool``, ``contents``, ``source``, ``note`` and
the honesty fields, so an unknown root field, a missing one, a wrong type
or a wrong fixed value is refused -- ``created_at`` must be an ISO-8601
UTC ``Z`` timestamp, ``tool`` and ``note`` must carry their fixed values,
and ``source`` must declare two safe single-segment file names plus one of
the known database open modes.  ``restore`` verifies the whole bundle
first, materialises it into a brand-new directory that did not exist
before, and never overwrites or switches the live database or
configuration.

Every entry this module creates is resolved through `_entry_path` and
written only through `_checked_destination`, which normalises the target
path, requires its parent to be exactly the root the run just created and
requires the file name to be one of the three fixed entries -- an absolute
path, a separator or ``..`` can never reach a write -- and each write is an
exclusive ``O_CREAT|O_EXCL`` binary create that never follows a symlink or
overwrites an existing file.

Recordings, thumbnails, models and evidence assets are never part of a
bundle, and no path here touches the network, starts a child process or
controls a service: ``media_included``, ``recordings_included`` and
``evidence_assets_included`` are false and ``quality_gate_passed`` and
``release_gate_passed`` stay null everywhere.  This is a state backup module
only -- not an upgrade/rollback flow, and not native-Linux or release-gate
evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = "scam.linux-backup/v1"
MANIFEST_ENTRY = "manifest.json"
DB_ENTRY = "db.sqlite3"
CONFIG_ENTRY = "config.bin"
FIXED_ENTRIES = (DB_ENTRY, CONFIG_ENTRY, MANIFEST_ENTRY)
FIXED_ENTRY_SET = frozenset(FIXED_ENTRIES)
PAYLOAD_ROLES = (("database", DB_ENTRY), ("config", CONFIG_ENTRY))
KIND = "state_bundle"
TOOL_NAME = "scam.linux_backup"
HONESTY_FIELDS = (("media_included", False), ("recordings_included", False),
                  ("evidence_assets_included", False),
                  ("quality_gate_passed", None),
                  ("release_gate_passed", None))
# 清单根是**精确封闭**的固定 schema：固定字段 + 诚实字段。未知根字段、缺失字段、
# 类型或固定值不符都拒绝——清单形状本身必须可被独立证伪，不能任意扩展。
ROOT_FIXED_FIELDS = ("schema", "kind", "created_at", "tool", "contents",
                     "source", "note")
ROOT_FIELDS = ROOT_FIXED_FIELDS + tuple(field for field, _ in HONESTY_FIELDS)
ROOT_FIELD_SET = frozenset(ROOT_FIELDS)
SOURCE_FIELDS = ("database_filename", "config_filename", "database_open_mode")
SOURCE_FILENAME_FIELDS = SOURCE_FIELDS[:2]
OPEN_MODES = ("read_only", "query_only")
CHUNK_SIZE = 1024 * 1024
MANIFEST_LIMIT = 1024 * 1024
# 写入侧统一的独占创建标志：必须带 ``O_BINARY``，否则 Windows CRT 文本模式会把
# 落盘字节里的 ``\n`` 翻成 ``\r\n``，配置原始字节与清单字节都不再是源字节。
EXCLUSIVE_WRITE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_BINARY", 0))
SQLITE_MAGIC = b"SQLite format 3\x00"
BACKUP_NOTE = ("状态备份模块：仅含SQLite一致性快照与配置原始字节；不含录像、缩略图、"
               "模型或证据资产；不是升级/回滚流程，也不构成原生Linux或发布门禁证据。")


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _identity(info):
    """身份快照五项（设备/inode/大小/mtime/ctime）：读取前后必须完全一致。"""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns)


def _lstat_now(path):
    """路径身份采样点（测试经此注入确定性时序；生产即 ``os.lstat``）。"""
    return os.lstat(path)


def _fstat_now(path):
    """句柄权威的路径身份采样点（测试经此注入确定性时序）。

    只读打开该路径并取 ``fstat``：与持有的 fd 快照同源，可直接比对。
    路径层 ``lstat`` 仅用于链接/普通文件判断——Windows 目录条目的元数据
    可能滞后到 flush 之后（本仓 `linux_replay_run._input_identity` 同款
    结论），跨来源比较 size/mtime/ctime 会把刚写出的文件误判为"读取中
    被替换"。按 LC-031/LC-032：身份绑定只用 ``samestat``/dev+ino，内容
    变化另用持有 fd 的 size/mtime/ctime 前后复核。
    """
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) \
        | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        return os.fstat(fd)
    finally:
        os.close(fd)


def _base_result(kind):
    result = {
        "schema": SCHEMA,
        "kind": kind,
        "created_at": _utc_now(),
        "note": BACKUP_NOTE,
        "errors": [],
    }
    for field, expected in HONESTY_FIELDS:
        result[field] = expected
    return result


def _escapes_root(name):
    """条目名必须是单层固定名：绝对路径、分隔符、盘符与 ``..`` 全拒绝。"""
    if not name or name in (".", ".."):
        return True
    if name.startswith(("/", "\\")):
        return True
    if "/" in name or "\\" in name:
        return True
    if len(name) >= 2 and name[1] == ":":
        return True
    return ".." in name


def _unsafe_filename(value):
    """声明用文件名的安全检查：必须是单层纯名字（非空、非 ``.`` 或 ``..``）。

    与 `_escapes_root` 的差别：这里只判断"是不是一个纯名字"，不把 ``..``
    子串当逃逸——``source`` 里的名字只作声明、从不参与路径拼接，因此
    ``a..b`` 这类合法文件名必须接受，保证 create 写出的名字不会被自己的
    校验拒绝。
    """
    if not isinstance(value, str) or not value or value in (".", ".."):
        return True
    if value.startswith(("/", "\\")) or "/" in value or "\\" in value:
        return True
    return len(value) >= 2 and value[1] == ":"


def _entry_path(root, name):
    """把固定条目名解析为根目录内的路径。

    条目名只可能是固定常量或已通过 `_validate_manifest` 的清单声明；这里
    再做白名单、规范化与包含性校验：非固定名、含分隔符或 ``..``、以及
    规范化后不在根目录内的结果全部拒绝，杜绝路径穿越。
    """
    if not isinstance(name, str) or name not in FIXED_ENTRY_SET \
            or _escapes_root(name):
        raise ValueError(f"not a fixed bundle entry: {name!r}")
    root_absolute = os.path.abspath(str(root))
    candidate = os.path.abspath(os.path.join(root_absolute, name))
    if os.path.dirname(candidate) != root_absolute:
        raise ValueError(f"entry path escapes its root: {name!r}")
    return candidate


def _checked_destination(root, path, errors):
    """新建文件的落点校验，返回规范化路径；不合格即结构化拒绝。

    先 ``abspath`` 规范化，再要求父目录正是本次新建的根目录与基名属于固定
    条目白名单：绝对路径、分隔符或 ``..`` 都无法通过，写入只会落在该根目录
    内、且只会写固定三个条目名。
    """
    root_absolute = os.path.abspath(str(root))
    candidate = os.path.abspath(str(path))
    if os.path.dirname(candidate) != root_absolute:
        errors.append("destination: path escapes its root; refusing to write")
        return None
    if os.path.basename(candidate) not in FIXED_ENTRY_SET:
        errors.append("destination: not a fixed bundle entry; refusing to write")
        return None
    return candidate


def _write_all(fd, chunk):
    """完整写出一个分块：``os.write`` 可能短写，循环到写完为止。"""
    view = memoryview(chunk)
    while len(view):
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _write_at(target, payload, label, errors):
    """独占创建一个新文件并完整写出；绝不覆盖已有文件。"""
    fd = None
    try:
        fd = os.open(target, EXCLUSIVE_WRITE_FLAGS, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        errors.append(f"{label}: cannot write ({type(exc).__name__}: {exc})")
        return False
    return True


def _stat_regular(path, label, errors):
    """输入预检：必须存在、是普通文件且不是软链接（不读取内容）。"""
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


def _check_payload_file(path, label, errors):
    """普通非链接文件 + 无 ``-wal``/``-shm`` 旁路文件的冻结态检查。"""
    info = _stat_regular(path, label, errors)
    if info is None:
        return None
    for suffix in ("-wal", "-shm"):
        try:
            os.lstat(str(path) + suffix)
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(f"{label}: cannot inspect {suffix} companion "
                          f"({type(exc).__name__}: {exc})")
            return None
        errors.append(f"{label}: uncheckpointed {suffix} companion exists; "
                      "refusing to treat the database as frozen")
        return None
    return info


def _read_payload(path, label, errors, *, sink=None, limit=None):
    """按 LC-036 严格身份绑定读取普通文件。

    lstat 快照（可注入）→ ``O_NOFOLLOW`` 打开 → ``samestat`` 一致性 →
    持有 fd 分块读取（累计 SHA-256，可同时写入 sink）→ 读取前后 fstat
    比对 size/mtime/ctime → 读后路径须仍为非链接普通文件，且身份与
    size/mtime/ctime 都与持有的 fd 快照一致（复核同样取句柄快照，避免
    跨来源元数据比较）。任何异常都转结构化错误，返回 None。
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
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) \
        | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        errors.append(f"{label}: open failed ({type(exc).__name__}: {exc})")
        return None
    digest = hashlib.sha256()
    size = 0
    try:
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                errors.append(
                    f"{label}: opened object is not a regular file")
                return None
            if not os.path.samestat(before, opened):
                errors.append(
                    f"{label}: identity changed between check and open")
                return None
            if limit is not None and opened.st_size > limit:
                errors.append(f"{label}: too large ({opened.st_size} bytes)")
                return None
            while True:
                chunk = os.read(fd, CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
                if sink is not None:
                    try:
                        sink(chunk)
                    except OSError as exc:
                        errors.append(f"{label}: write failed "
                                      f"({type(exc).__name__}: {exc})")
                        return None
            after_read = os.fstat(fd)
        except OSError as exc:
            errors.append(f"{label}: read failed ({type(exc).__name__}: {exc})")
            return None
    finally:
        os.close(fd)
    if (after_read.st_size, after_read.st_mtime_ns,
            after_read.st_ctime_ns) != (opened.st_size, opened.st_mtime_ns,
                                        opened.st_ctime_ns):
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
    if stat.S_ISLNK(after.st_mode) or not stat.S_ISREG(after.st_mode):
        errors.append(f"{label}: replaced while reading")
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
    return {"entry": os.path.basename(str(path)), "size": size,
            "sha256": digest.hexdigest(), "identity": _identity(opened)}


def _connect_readonly(path, expect):
    """保持已验证描述符打开，交给 SQLite 只读读取；返回 (连接, fd, 快照, 原因)。

    Linux 经 ``/proc/self/fd`` 连接，SQLite 无法跟随 lstat 后被换入的路
    径；其他平台保留描述符并做前后身份复核。``immutable`` 让 SQLite 不
    加锁、不创建 ``-wal``/``-shm``，满足 verify 的只读要求。打开对象的
    身份与调用方持有的句柄快照（``expect``）比对：两者同源，路径层
    ``lstat`` 不参与 size/mtime/ctime 比较。失败返回原因字符串，由调用方
    统一按“完整性校验失败”结构化报告。
    """
    fd = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) \
            | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            os.close(fd)
            return None, None, None, "opened object is not a regular file"
        if expect is not None and _identity(opened) != tuple(expect):
            os.close(fd)
            return None, None, None, "changed while opening"
        connect_path = (f"/proc/self/fd/{fd}" if sys.platform == "linux"
                        else os.path.abspath(path))
        uri = Path(connect_path).as_uri() + "?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True)
        connection.execute("PRAGMA query_only = ON")
        return connection, fd, opened, None
    except (OSError, sqlite3.Error, ValueError) as exc:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        return None, None, None, f"{type(exc).__name__}: {exc}"


def _sqlite_integrity(path, label, errors, *, expect=None):
    """只读校验 SQLite 完整性；任何异常或非 ``ok`` 都是结构化失败。

    ``expect`` 是此前对该文件哈希时的句柄快照：连接前后都用句柄快照与它
    比对（含 size/mtime/ctime），证明"校验的就是刚哈希的那份字节"，同时
    不依赖路径层元数据的新鲜度。
    """
    if _check_payload_file(path, label, errors) is None:
        return None
    connection, fd, opened, reason = _connect_readonly(path, expect)
    if connection is None:
        errors.append(f"{label}: integrity check failed ({reason})")
        return None
    try:
        row = connection.execute("PRAGMA integrity_check").fetchone()
        verdict = str(row[0]).lower() if row else ""
        if verdict != "ok":
            errors.append(f"{label}: integrity check failed "
                          f"({row[0] if row else 'no result'})")
            return None
        current = _fstat_now(path)
        if not stat.S_ISREG(current.st_mode) \
                or not os.path.samestat(opened, current) \
                or _identity(current) != _identity(opened):
            errors.append(f"{label}: changed while checking")
            return None
    except OSError as exc:
        errors.append(f"{label}: changed while checking "
                      f"({type(exc).__name__}: {exc})")
        return None
    except sqlite3.DatabaseError as exc:
        errors.append(f"{label}: integrity check failed "
                      f"({type(exc).__name__}: {exc})")
        return None
    finally:
        connection.close()
        os.close(fd)
    return "ok"


def _open_source(path, errors):
    """打开源数据库用于在线 backup。

    优先只读 URI 连接（不写入源库内容；不使用 ``immutable``，源库可能
    正在被在线写入）；本机不支持只读 URI 或只读打开失败时回退
    ``query_only`` 普通连接，仍然禁止写入库内容。
    """
    absolute = os.path.abspath(path)
    uri = None
    try:
        uri = Path(absolute).as_uri() + "?mode=ro"
    except (OSError, ValueError):
        uri = None
    if uri is not None:
        try:
            connection = sqlite3.connect(uri, uri=True)
            connection.execute("PRAGMA query_only = ON")
            return connection, "read_only"
        except sqlite3.Error:
            pass
    try:
        info = os.lstat(absolute)
    except OSError:
        info = None
    if info is None or not stat.S_ISREG(info.st_mode):
        errors.append("database: disappeared before opening")
        return None, None
    try:
        connection = sqlite3.connect(absolute)
        connection.execute("PRAGMA query_only = ON")
        return connection, "query_only"
    except sqlite3.Error as exc:
        errors.append(f"database: cannot open ({type(exc).__name__}: {exc})")
        return None, None


def _check_source_file(path, errors):
    """源数据库预检：普通非链接文件且带 SQLite 文件头（不解释内容）。"""
    try:
        info = _lstat_now(path)
    except OSError:
        errors.append("database: missing")
        return None
    if stat.S_ISLNK(info.st_mode):
        errors.append("database: symlink is not accepted")
        return None
    if not stat.S_ISREG(info.st_mode):
        errors.append("database: not a regular file")
        return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) \
        | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        errors.append(f"database: open failed ({type(exc).__name__}: {exc})")
        return None
    try:
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                errors.append("database: opened object is not a regular file")
                return None
            if not os.path.samestat(info, opened):
                errors.append("database: identity changed between check and open")
                return None
            header = os.read(fd, len(SQLITE_MAGIC))
        except OSError as exc:
            errors.append(f"database: read failed ({type(exc).__name__}: {exc})")
            return None
    finally:
        os.close(fd)
    if header != SQLITE_MAGIC:
        errors.append("database: not a SQLite database file")
        return None
    return info


def _snapshot_database(db_path, destination, root, result, errors):
    """SQLite 在线 backup API：只复制已提交事务的一致快照。"""
    target = _checked_destination(root, destination, errors)
    if target is None:
        return None
    connection, mode = _open_source(db_path, errors)
    if connection is None:
        return None
    destination_connection = None
    try:
        try:
            destination_connection = sqlite3.connect(target)
        except sqlite3.Error as exc:
            errors.append(f"snapshot: cannot create "
                          f"({type(exc).__name__}: {exc})")
            return None
        try:
            connection.backup(destination_connection)
            row = destination_connection.execute(
                "PRAGMA integrity_check").fetchone()
            verdict = str(row[0]).lower() if row else ""
            if verdict != "ok":
                errors.append("snapshot: integrity check failed "
                              f"({row[0] if row else 'no result'})")
                return None
            # 规范化为 rollback journal：快照此后是无旁路文件的自洽字节
            journal = destination_connection.execute(
                "PRAGMA journal_mode=DELETE").fetchone()
            normalised = str(journal[0]).lower() if journal else ""
            if normalised != "delete":
                errors.append("snapshot: journal mode not normalised "
                              f"({journal[0] if journal else 'no result'})")
                return None
        except sqlite3.Error as exc:
            errors.append(f"snapshot: {type(exc).__name__}: {exc}")
            return None
        finally:
            destination_connection.close()
    finally:
        connection.close()
    result["source_open_mode"] = mode
    return mode


def _copy_payload(source, destination, root, label, errors):
    """把源文件字节流式复制为新建目标文件（读侧仍走严格身份绑定）。"""
    target = _checked_destination(root, destination, errors)
    if target is None:
        return None
    try:
        fd = os.open(target, EXCLUSIVE_WRITE_FLAGS, 0o600)
    except OSError as exc:
        errors.append(f"{label}: cannot create entry "
                      f"({type(exc).__name__}: {exc})")
        return None
    copied = None
    try:
        copied = _read_payload(source, label, errors,
                               sink=lambda chunk: _write_all(fd, chunk))
        os.fsync(fd)
    finally:
        os.close(fd)
    return copied


def _source_filename(path):
    """源的最后一层名字：去掉尾部分隔符，保证写出的 ``source`` 通过校验。"""
    return os.path.basename(str(path).rstrip("/\\"))


def _manifest_document(database, config, db_path, config_path, mode):
    return {
        "schema": SCHEMA,
        "kind": KIND,
        "created_at": _utc_now(),
        "tool": TOOL_NAME,
        "contents": {
            "database": {"entry": DB_ENTRY, "size": database["size"],
                         "sha256": database["sha256"]},
            "config": {"entry": CONFIG_ENTRY, "size": config["size"],
                       "sha256": config["sha256"]},
        },
        "source": {
            "database_filename": _source_filename(db_path),
            "config_filename": _source_filename(config_path),
            "database_open_mode": mode,
        },
        "media_included": False,
        "recordings_included": False,
        "evidence_assets_included": False,
        "quality_gate_passed": None,
        "release_gate_passed": None,
        "note": BACKUP_NOTE,
    }


def _write_manifest(destination, root, document, errors):
    target = _checked_destination(root, destination, errors)
    if target is None:
        return False
    payload = json.dumps(document, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8") + b"\n"
    return _write_at(target, payload, "manifest", errors)


def _remove_created_dir(path, created):
    """只清理本次运行新建的目录（``created`` 为假时绝不触碰该路径）。"""
    if not created:
        return False
    try:
        shutil.rmtree(path)
    except OSError:
        pass
    return not os.path.exists(path)


def _write_bundle(db_path, config_path, output_dir, result, errors):
    db_entry = _entry_path(output_dir, DB_ENTRY)
    config_entry = _entry_path(output_dir, CONFIG_ENTRY)
    manifest_entry = _entry_path(output_dir, MANIFEST_ENTRY)

    mode = _snapshot_database(db_path, db_entry, output_dir, result, errors)
    if mode is None:
        return None
    copied = _copy_payload(config_path, config_entry, output_dir, "config",
                           errors)
    if copied is None:
        return None
    database = _read_payload(db_entry, "database", errors)
    if database is None:
        return None
    config = _read_payload(config_entry, "config", errors)
    if config is None:
        return None
    if copied["size"] != config["size"] \
            or copied["sha256"] != config["sha256"]:
        errors.append("config: copied bytes differ from the source file")
        return None
    if _sqlite_integrity(db_entry, "database", errors,
                         expect=database["identity"]) is None:
        return None

    document = _manifest_document(database, config, db_path, config_path, mode)
    _write_manifest(manifest_entry, output_dir, document, errors)
    if errors:
        return None
    manifest = _read_payload(manifest_entry, "manifest", errors)
    if manifest is None:
        return None
    return {
        "manifest": {"entry": MANIFEST_ENTRY, "size": manifest["size"],
                     "sha256": manifest["sha256"]},
        "contents": {
            "database": {"entry": DB_ENTRY, "size": database["size"],
                         "sha256": database["sha256"], "integrity_check": "ok"},
            "config": {"entry": CONFIG_ENTRY, "size": config["size"],
                       "sha256": config["sha256"]},
        },
    }


def create_bundle(db_path, config_path, output_dir):
    """生成状态包；返回 (result, errors)。失败只清理本次新建目录。"""
    errors = []
    result = _base_result("backup_create_result")
    result.update({"bundle_dir": str(output_dir), "bundle_created": False,
                   "output_dir_removed": None, "source_open_mode": None,
                   "manifest": None, "contents": None})

    # 阶段 0：输入形态预检（不创建目录、不读取内容）
    _check_source_file(db_path, errors)
    _stat_regular(config_path, "config", errors)
    if errors:
        result["errors"] = list(errors)
        return result, errors

    # 阶段 1：输出目录原子排他创建（已存在即非零且绝不覆盖）
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
    created = True

    contents = None
    try:
        contents = _write_bundle(db_path, config_path, output_dir, result,
                                 errors)
    except Exception as exc:  # 任何未预期异常都转结构化失败并清理本目录
        errors.append(f"create: unexpected {type(exc).__name__}: {exc}")
        contents = None

    if errors or contents is None:
        removed = _remove_created_dir(output_dir, created)
        result["bundle_created"] = not removed
        result["output_dir_removed"] = removed
        result["contents"] = None
        if not removed:
            errors.append("output_dir: cleanup failed; "
                          "a partial directory remains")
        result["errors"] = list(errors)
        return result, errors

    result.update(contents)
    result["bundle_created"] = True
    result["errors"] = []
    return result, errors


def _utc_timestamp(value):
    """``created_at`` 必须是以 ``Z`` 结尾的 ISO-8601 UTC 时间戳。"""
    if not isinstance(value, str) or len(value) < 2 or not value.endswith("Z"):
        return False
    try:
        stamp = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return stamp.tzinfo is not None and stamp.utcoffset() == timedelta(0)


def _validate_source(declaration, errors):
    """``source`` 必须是固定三字段对象：安全单层文件名 + 已知打开模式。"""
    where = "manifest: source"
    if not isinstance(declaration, dict):
        errors.append(f"{where} must be a JSON object")
        return
    unknown = sorted(set(declaration) - set(SOURCE_FIELDS))
    if unknown:
        errors.append(f"{where}: unknown fields " + "/".join(unknown))
    for field in SOURCE_FILENAME_FIELDS:
        name = declaration.get(field)
        if _unsafe_filename(name):
            errors.append(f"{where}.{field}: must be a plain file name")
    mode = declaration.get("database_open_mode")
    if mode not in OPEN_MODES:
        errors.append(f"{where}.database_open_mode: unknown mode ({mode!r})")


def _validate_manifest(raw, errors):
    """校验固定 schema、诚实字段与两个 payload 的声明；返回声明字典。"""
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        errors.append(f"manifest: invalid UTF-8 JSON ({type(exc).__name__})")
        return None
    if not isinstance(document, dict):
        errors.append("manifest: root must be a JSON object")
        return None
    if document.get("schema") != SCHEMA:
        errors.append(f"manifest: unknown schema ({document.get('schema')!r})")
        return None
    if document.get("kind") != KIND:
        errors.append(f"manifest: unknown kind ({document.get('kind')!r})")
        return None
    # 精确封闭的根 schema：未知根字段与缺失固定字段都拒绝（继续收集其余错误）
    unknown = sorted(set(document) - ROOT_FIELD_SET)
    if unknown:
        errors.append("manifest: unknown root fields " + "/".join(unknown))
    for field in ROOT_FIELDS:
        if field not in document:
            errors.append(f"manifest: missing field {field}")
    if "created_at" in document and not _utc_timestamp(document["created_at"]):
        errors.append("manifest: created_at must be a UTC Z timestamp")
    if "tool" in document and document["tool"] != TOOL_NAME:
        errors.append(f"manifest: tool must be {TOOL_NAME!r}")
    if "note" in document and document["note"] != BACKUP_NOTE:
        errors.append("manifest: note must be the fixed module note")
    if "source" in document:
        _validate_source(document["source"], errors)
    for field, expected in HONESTY_FIELDS:
        if field not in document:
            errors.append(f"manifest: missing field {field}")
            continue
        value = document[field]
        if expected is False and value is not False:
            errors.append(f"manifest: {field} must be False")
        elif expected is None and value is not None:
            errors.append(f"manifest: {field} must be None")
    contents = document.get("contents")
    if not isinstance(contents, dict):
        errors.append("manifest: contents must be a JSON object")
        return None
    unknown = sorted(set(contents) - {role for role, _ in PAYLOAD_ROLES})
    if unknown:
        errors.append("manifest: unknown content entries " + "/".join(unknown))
    declared = {}
    for role, entry in PAYLOAD_ROLES:
        where = f"manifest: contents.{role}"
        spec = contents.get(role)
        if not isinstance(spec, dict):
            errors.append(f"{where} must be a JSON object")
            continue
        extra = sorted(set(spec) - {"entry", "size", "sha256"})
        if extra:
            errors.append(f"{where}: unknown fields " + "/".join(extra))
            continue
        name = spec.get("entry")
        if not isinstance(name, str) or _escapes_root(name):
            errors.append(f"{where}.entry: path escapes the bundle root")
            continue
        if name != entry:
            errors.append(f"{where}.entry: unknown entry ({name!r})")
            continue
        size = spec.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            errors.append(f"{where}.size: must be a non-negative integer")
            continue
        digest = spec.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 \
                or any(char not in "0123456789abcdef" for char in digest):
            errors.append(f"{where}.sha256: must be a 64-character "
                          "lowercase hex digest")
            continue
        declared[role] = {"entry": name, "size": size, "sha256": digest}
    if errors or len(declared) != len(PAYLOAD_ROLES):
        return None
    return declared


def _check_bundle_root(bundle_dir, errors):
    """bundle 根必须是真实目录且不是软链接（拒绝后绝不再遍历）。"""
    try:
        info = _lstat_now(bundle_dir)
    except OSError:
        errors.append("bundle_root: missing")
        return None
    if stat.S_ISLNK(info.st_mode):
        errors.append("bundle_root: symlink is not accepted")
        return None
    if not stat.S_ISDIR(info.st_mode):
        errors.append("bundle_root: not a directory")
        return None
    return info


def _scan_bundle_entries(bundle_dir, errors):
    """固定条目枚举：拒绝软链接、非普通文件、额外路径与缺失条目。"""
    try:
        with os.scandir(bundle_dir) as scanner:
            scanned = sorted(scanner, key=lambda item: item.name)
    except OSError as exc:
        errors.append(f"bundle_root: cannot list ({type(exc).__name__}: {exc})")
        return None
    found = {}
    for item in scanned:
        if item.is_symlink():
            errors.append(f"bundle_entry: {item.name}: symlink is not accepted")
            continue
        if not item.is_file(follow_symlinks=False):
            errors.append(f"bundle_entry: {item.name}: not a regular file")
            continue
        if item.name not in FIXED_ENTRY_SET:
            errors.append(f"bundle_entry: {item.name}: unexpected path in bundle")
            continue
        found[item.name] = _entry_path(bundle_dir, item.name)
    for name in FIXED_ENTRIES:
        if name not in found:
            errors.append(f"bundle_entry: {name}: missing")
    if errors:
        return None
    return found


def verify_bundle(bundle_dir):
    """只读校验状态包；返回 (result, errors)。任何缺失/篡改/坏库非零。"""
    errors = []
    result = _base_result("backup_verify_result")
    result.update({"bundle_dir": str(bundle_dir), "bundle_valid": False,
                   "contents": None})

    if _check_bundle_root(bundle_dir, errors) is None:
        result["errors"] = list(errors)
        return result, errors
    entries = _scan_bundle_entries(bundle_dir, errors)
    if entries is None:
        result["errors"] = list(errors)
        return result, errors

    raw = []
    manifest = _read_payload(entries[MANIFEST_ENTRY], "manifest", errors,
                             sink=raw.append, limit=MANIFEST_LIMIT)
    if manifest is None:
        result["errors"] = list(errors)
        return result, errors
    declared = _validate_manifest(b"".join(raw), errors)
    if declared is None:
        result["errors"] = list(errors)
        return result, errors

    contents = {}
    for role, entry in PAYLOAD_ROLES:
        spec = declared[role]
        payload_path = entries[entry]
        actual = _read_payload(payload_path, role, errors)
        if actual is None:
            continue
        if actual["size"] != spec["size"]:
            errors.append(f"{role}: size mismatch "
                          f"(manifest {spec['size']} != payload "
                          f"{actual['size']})")
            continue
        if actual["sha256"] != spec["sha256"]:
            errors.append(f"{role}: sha256 mismatch "
                          f"(manifest {spec['sha256']} != payload "
                          f"{actual['sha256']})")
            continue
        report = {"entry": entry, "size": actual["size"],
                  "sha256": actual["sha256"]}
        if role == "database":
            if _sqlite_integrity(payload_path, role, errors,
                                 expect=actual["identity"]) is None:
                continue
            report["integrity_check"] = "ok"
        contents[role] = report

    if errors:
        result["errors"] = list(errors)
        return result, errors
    result["bundle_valid"] = True
    result["contents"] = contents
    return result, errors


def _materialise(bundle_dir, target_dir, verified, errors):
    restored = {}
    for role, entry in PAYLOAD_ROLES:
        source = _entry_path(bundle_dir, entry)
        destination = _entry_path(target_dir, entry)
        spec = verified[role]
        copied = _copy_payload(source, destination, target_dir, role, errors)
        if copied is None:
            return None
        if copied["size"] != spec["size"] \
                or copied["sha256"] != spec["sha256"]:
            errors.append(f"{role}: bundle bytes changed after verification")
            return None
        # 恢复后独立复核：重新严格读取目标文件并与清单声明比对
        check = _read_payload(destination, f"restored {role}", errors)
        if check is None:
            return None
        if check["size"] != spec["size"] \
                or check["sha256"] != spec["sha256"]:
            errors.append(f"restored {role}: sha256 mismatch "
                          "(copy is not byte-identical)")
            return None
        report = {"entry": entry, "size": check["size"],
                  "sha256": check["sha256"]}
        if role == "database":
            if _sqlite_integrity(destination, "restored database", errors,
                                 expect=check["identity"]) is None:
                return None
            report["integrity_check"] = "ok"
        restored[role] = report
    return restored


def restore_bundle(bundle_dir, target_dir):
    """先完整 verify，再恢复到此前不存在的全新目录；返回 (result, errors)。"""
    errors = []
    result = _base_result("backup_restore_result")
    result.update({"bundle_dir": str(bundle_dir), "target_dir": str(target_dir),
                   "bundle_valid": False, "restored": False,
                   "target_dir_removed": None, "contents": None})

    verification, _ = verify_bundle(bundle_dir)
    if not verification["bundle_valid"]:
        errors.extend(verification["errors"])
        result["errors"] = list(errors)
        return result, errors
    result["bundle_valid"] = True

    # 新目标目录：此前不存在才允许，绝不覆盖在线DB/配置或其他路径
    try:
        os.mkdir(target_dir)
    except FileExistsError:
        errors.append("target_dir: already exists; refusing to overwrite")
        result["errors"] = list(errors)
        return result, errors
    except OSError as exc:
        errors.append(f"target_dir: cannot create "
                      f"({type(exc).__name__}: {exc})")
        result["errors"] = list(errors)
        return result, errors
    created = True

    restored = None
    try:
        restored = _materialise(bundle_dir, target_dir,
                                verification["contents"], errors)
    except Exception as exc:  # 任何未预期异常都转结构化失败并清理本目录
        errors.append(f"restore: unexpected {type(exc).__name__}: {exc}")
        restored = None

    if errors or restored is None:
        removed = _remove_created_dir(target_dir, created)
        result["target_dir_removed"] = removed
        result["contents"] = None
        if not removed:
            errors.append("target_dir: cleanup failed; "
                          "a partial directory remains")
        result["errors"] = list(errors)
        return result, errors

    result["restored"] = True
    result["contents"] = restored
    result["errors"] = []
    return result, errors


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Linux L4 运维状态备份与恢复：create 生成一致状态包，"
                    "verify 只读校验，restore 先验后恢复到全新目录"
                    "（零网络/零子进程/零服务控制；不代表任何发布门禁通过）")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser(
        "create", help="生成状态包（输出目录原子排他创建，已存在即拒绝）")
    create_parser.add_argument("--db", required=True)
    create_parser.add_argument("--config", required=True)
    create_parser.add_argument("--output-dir", required=True)

    verify_parser = subparsers.add_parser("verify", help="只读校验状态包")
    verify_parser.add_argument("--bundle-dir", required=True)

    restore_parser = subparsers.add_parser(
        "restore", help="先完整verify再恢复到此前不存在的全新目录")
    restore_parser.add_argument("--bundle-dir", required=True)
    restore_parser.add_argument("--target-dir", required=True)

    args = parser.parse_args(argv)
    if args.command == "create":
        result, errors = create_bundle(args.db, args.config, args.output_dir)
    elif args.command == "verify":
        result, errors = verify_bundle(args.bundle_dir)
    else:
        result, errors = restore_bundle(args.bundle_dir, args.target_dir)

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
