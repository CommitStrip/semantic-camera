"""LC-036 队列O状态备份与恢复测试：单一CLI三子命令 + 固定三条目状态包。

覆盖 LC-036 全部安全与诚实边界：WAL在线快照只含已提交事务、create/restore
目标已存在即拒绝且内容不变、配置/根/payload 软链接拒绝、manifest 与 payload
篡改/坏库/额外路径/路径逃逸拒绝（manifest 根为封闭固定 schema：未知根字段、
缺失或坏类型/坏固定值的 created_at/tool/source/note 一律拒绝）、注入失败不留
可验证半成品且不删除输入、恢复目录哈希与完整性独立成立、CLI 退出码与四项
诚实字段。

软链接用例按仓库既有约定：本机不允许创建符号链接时 `pytest.skip`，同一条
生产拒绝分支另由 `_lstat_now`（类型/链接）与 `_fstat_now`（句柄身份）两个模块
本地采样点注入身份回归确定性覆盖（无平台 `os.name` skip、
无 sleep、无重试）。证据等级仅为模块+单测（Windows 合成接线），不代表原生
Linux、真实视频/ONNX、模型质量或发布门禁通过。
"""

import hashlib
import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest

import scam.linux_backup as backup_mod

BUNDLE_ENTRIES = ["config.bin", "db.sqlite3", "manifest.json"]


# ---------- 合成输入 ----------

def _make_database(path, rows=("cam-1", "cam-2")):
    connection = sqlite3.connect(str(path))
    try:
        connection.execute(
            "CREATE TABLE cameras (id TEXT PRIMARY KEY, label TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO cameras (id, label) VALUES (?, ?)",
            [(row, "label-" + row) for row in rows])
        connection.commit()
    finally:
        connection.close()
    return path


def _expected_rows(rows=("cam-1", "cam-2")):
    return [(row, "label-" + row) for row in sorted(rows)]


def _make_inputs(root, *, rows=("cam-1", "cam-2"),
                 config_bytes=b'{"version": "0.3"}',
                 db_name="cameras.sqlite3", config_name="cameras.json"):
    directory = Path(root)
    directory.mkdir(parents=True, exist_ok=True)
    db = directory / db_name
    _make_database(db, rows)
    config = directory / config_name
    config.write_bytes(config_bytes)
    return db, config


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _entries(directory):
    with os.scandir(directory) as scanner:
        return sorted(item.name for item in scanner)


def _fingerprint(directory):
    """目录指纹：条目名 → (大小, SHA-256, mtime_ns)，用于证明零写入。"""
    result = {}
    with os.scandir(directory) as scanner:
        items = sorted(scanner, key=lambda item: item.name)
    for item in items:
        info = os.stat(item.path)
        result[item.name] = (info.st_size, _sha256(item.path),
                             info.st_mtime_ns)
    return result


def _rows(path):
    """只读打开一个状态快照并取出行（不写入任何旁路文件）。"""
    connection = sqlite3.connect(Path(str(path)).as_uri() + "?mode=ro",
                                 uri=True)
    try:
        return connection.execute(
            "SELECT id, label FROM cameras ORDER BY id").fetchall()
    finally:
        connection.close()


def _manifest_of(bundle):
    return json.loads((Path(bundle) / "manifest.json")
                      .read_text(encoding="utf-8"))


def _rewrite_manifest(bundle, document):
    (Path(bundle) / "manifest.json").write_bytes(
        json.dumps(document, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode("utf-8") + b"\n")


def _fake_stat(mode, size=0):
    """构造可注入的身份结果（不触及文件系统）。"""
    return os.stat_result((mode, 0, 0, 1, 0, 0, size, 0, 0, 0))


def _make_bundle(tmp_path, *, name="bundle", **kwargs):
    db, config = _make_inputs(tmp_path, **kwargs)
    bundle = tmp_path / name
    result, errors = backup_mod.create_bundle(str(db), str(config),
                                              str(bundle))
    assert errors == [], errors
    assert result["bundle_created"] is True
    return bundle, db, config, result


def _run_cli(args, capsys):
    code = backup_mod.main(args)
    captured = capsys.readouterr()
    return code, json.loads(captured.out)


def _assert_honesty(payload):
    assert payload["media_included"] is False
    assert payload["recordings_included"] is False
    assert payload["evidence_assets_included"] is False
    assert payload["quality_gate_passed"] is None
    assert payload["release_gate_passed"] is None


# ---------- 1. create：固定条目、一致快照与诚实清单 ----------

def test_create_bundle_writes_fixed_entries_and_honest_manifest(tmp_path):
    bundle, db, config, result = _make_bundle(tmp_path)

    assert _entries(bundle) == BUNDLE_ENTRIES
    document = _manifest_of(bundle)
    assert document["schema"] == backup_mod.SCHEMA
    assert document["kind"] == "state_bundle"
    _assert_honesty(document)
    assert document["contents"]["database"]["entry"] == "db.sqlite3"
    assert document["contents"]["config"]["entry"] == "config.bin"
    assert document["contents"]["config"]["sha256"] == _sha256(config)
    assert document["contents"]["database"]["sha256"] \
        == _sha256(bundle / "db.sqlite3")
    # 结果同时是机器可读的诚实报告
    _assert_honesty(result)
    assert result["contents"]["database"]["integrity_check"] == "ok"
    assert result["source_open_mode"] in {"read_only", "query_only"}
    assert result["manifest"]["entry"] == "manifest.json"


def test_create_snapshot_matches_source_committed_state(tmp_path):
    rows = ("cam-1", "cam-2", "cam-3")
    bundle, db, _, result = _make_bundle(tmp_path, rows=rows)

    assert _rows(bundle / "db.sqlite3") == _expected_rows(rows)
    assert _rows(db) == _expected_rows(rows)
    assert result["contents"]["database"]["size"] \
        == (bundle / "db.sqlite3").stat().st_size


def test_config_bytes_preserved_exactly(tmp_path):
    payload = b'{"venue": "\xe5\x8c\x97\xe4\xba\xac", "flag": true}\n'
    bundle, _, _, result = _make_bundle(tmp_path, config_bytes=payload)

    assert (bundle / "config.bin").read_bytes() == payload
    assert result["contents"]["config"]["size"] == len(payload)
    assert result["contents"]["config"]["sha256"] \
        == hashlib.sha256(payload).hexdigest()


def test_create_success_reports_bundle_created_true(tmp_path):
    """成功路径必须把 bundle_created 置为 True，与失败路径的 False 成对。"""
    db, config = _make_inputs(tmp_path)
    bundle = tmp_path / "bundle"

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                             str(bundle))

    assert errors == []
    assert result["bundle_created"] is True
    assert result["contents"] is not None
    assert result["manifest"]["entry"] == "manifest.json"
    assert _entries(bundle) == BUNDLE_ENTRIES


def test_written_entries_keep_exact_bytes_on_binary_handles(tmp_path):
    """落盘字节不得被平台翻译（Windows 文本模式会把 ``\\n`` 写成 ``\\r\\n``）。

    覆盖两处写入点：清单（``_write_at``）与 payload 复制（``_copy_payload``）；
    配置原始字节与清单字节都必须与源字节逐字节相同，恢复侧同样不得改写。
    """
    payload = b'{\n  "version": "0.3",\n  "venue": "beijing"\n}\n'
    db, config = _make_inputs(tmp_path, config_bytes=payload)
    bundle = tmp_path / "bundle"

    created, errors = backup_mod.create_bundle(str(db), str(config),
                                               str(bundle))

    assert errors == []
    assert (bundle / "config.bin").read_bytes() == payload
    manifest_bytes = (bundle / "manifest.json").read_bytes()
    assert manifest_bytes.endswith(b"\n")
    assert b"\r\n" not in manifest_bytes

    target = tmp_path / "restored"
    restored, errors = backup_mod.restore_bundle(str(bundle), str(target))

    assert errors == []
    assert (target / "config.bin").read_bytes() == payload
    assert restored["contents"]["config"]["sha256"] \
        == created["contents"]["config"]["sha256"]
    assert restored["contents"]["database"]["sha256"] \
        == created["contents"]["database"]["sha256"]


def test_bundle_contains_no_media_or_evidence_assets(tmp_path):
    inputs = tmp_path / "inputs"
    db, config = _make_inputs(inputs)
    (inputs / "clip.mp4").write_bytes(b"video")
    (inputs / "thumb.jpg").write_bytes(b"thumb")
    (inputs / "person.onnx").write_bytes(b"weights")
    bundle = tmp_path / "bundle"

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                             str(bundle))

    assert errors == []
    assert _entries(bundle) == BUNDLE_ENTRIES
    assert result["media_included"] is False
    assert result["recordings_included"] is False
    assert result["evidence_assets_included"] is False


def test_create_does_not_modify_inputs(tmp_path):
    inputs = tmp_path / "inputs"
    db, config = _make_inputs(inputs)
    db_before, config_before = _sha256(db), _sha256(config)
    bundle = tmp_path / "bundle"

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                             str(bundle))

    assert errors == []
    assert _sha256(db) == db_before
    assert _sha256(config) == config_before
    # 源目录不被写入任何旁路文件：只有两份输入
    assert _entries(inputs) == ["cameras.json", "cameras.sqlite3"]


# ---------- 2. create：WAL 在线一致性（已提交进入、未提交不进入） ----------

def test_create_snapshot_from_live_wal_connection_is_consistent(tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    db = inputs / "live.sqlite3"
    writer = sqlite3.connect(str(db))
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] \
            .lower() == "wal"
        writer.execute("CREATE TABLE cameras (id TEXT PRIMARY KEY, "
                       "label TEXT NOT NULL)")
        writer.execute("INSERT INTO cameras VALUES ('cam-1', 'committed')")
        writer.commit()
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("INSERT INTO cameras VALUES ('cam-2', 'uncommitted')")

        config = inputs / "cameras.json"
        config.write_bytes(b'{"version": "0.3"}')
        bundle = tmp_path / "bundle"
        result, errors = backup_mod.create_bundle(str(db), str(config),
                                                  str(bundle))

        assert errors == []
        # 在线 backup API：只复制已提交事务
        assert _rows(bundle / "db.sqlite3") == [("cam-1", "committed")]
        # 写事务未被干扰：本连接仍见未提交行，且可继续提交
        assert writer.execute(
            "SELECT count(*) FROM cameras").fetchone()[0] == 2
        writer.commit()
        assert _rows(db) == [("cam-1", "committed"),
                             ("cam-2", "uncommitted")]
    finally:
        writer.close()


# ---------- 3. create：拒绝路径 ----------

def test_create_rejects_existing_output_dir_and_keeps_content(tmp_path):
    db, config = _make_inputs(tmp_path)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    sentinel = bundle / "keep.txt"
    sentinel.write_bytes(b"untouched")

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                              str(bundle))

    assert any("output_dir: already exists" in err for err in errors)
    assert result["bundle_created"] is False
    assert result["contents"] is None
    assert _entries(bundle) == ["keep.txt"]
    assert sentinel.read_bytes() == b"untouched"


def test_create_rejects_missing_config_without_creating_dir(tmp_path):
    db, _ = _make_inputs(tmp_path)
    bundle = tmp_path / "bundle"

    result, errors = backup_mod.create_bundle(
        str(db), str(tmp_path / "gone.json"), str(bundle))

    assert any("config: missing" in err for err in errors)
    assert not bundle.exists()


def test_create_rejects_non_sqlite_database(tmp_path):
    db = tmp_path / "not-a-db.sqlite3"
    db.write_bytes(b"definitely not a SQLite file")
    config = tmp_path / "cameras.json"
    config.write_bytes(b'{"version": "0.3"}')
    bundle = tmp_path / "bundle"

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                              str(bundle))

    assert any("database: not a SQLite database file" in err for err in errors)
    assert not bundle.exists()


def test_create_rejects_config_symlink(tmp_path):
    db, config = _make_inputs(tmp_path)
    link = tmp_path / "link.json"
    try:
        os.symlink(config, link)
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接")
    bundle = tmp_path / "bundle"

    result, errors = backup_mod.create_bundle(str(db), str(link), str(bundle))

    assert any("config: symlink is not accepted" in err for err in errors)
    assert not bundle.exists()


def test_create_rejects_symlink_identity_without_os_symlink(tmp_path,
                                                            monkeypatch):
    """确定性注入：本机不能建软链接时，仍证明生产拒绝分支成立。"""
    db, config = _make_inputs(tmp_path)
    bundle = tmp_path / "bundle"
    real_lstat = backup_mod._lstat_now

    def fake_lstat(path):
        if os.path.abspath(path) == os.path.abspath(str(config)):
            return _fake_stat(stat.S_IFLNK | 0o777)
        return real_lstat(path)

    monkeypatch.setattr(backup_mod, "_lstat_now", fake_lstat)

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                              str(bundle))

    assert errors == ["config: symlink is not accepted"]
    assert not bundle.exists()


def test_create_rejects_config_swapped_between_check_and_open(tmp_path,
                                                              monkeypatch):
    """LC-032/033 式身份回归：lstat 与 open 之间换入必须立即拒绝。"""
    db, config = _make_inputs(tmp_path)
    stale = os.lstat(str(config))
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(b'{"swapped": true}')
    os.replace(str(replacement), str(config))
    bundle = tmp_path / "bundle"
    real_lstat = backup_mod._lstat_now

    def fake_lstat(path):
        if os.path.abspath(path) == os.path.abspath(str(config)):
            return stale
        return real_lstat(path)

    monkeypatch.setattr(backup_mod, "_lstat_now", fake_lstat)

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                              str(bundle))

    assert any("config: identity changed between check and open" in err
               for err in errors)
    assert not bundle.exists()


def test_create_rejects_config_replaced_while_reading(tmp_path, monkeypatch):
    """读后路径身份须与持有的 fd 快照同源同值（无 sleep、无平台 skip）。

    生产读后复核取句柄快照（`_fstat_now`）与 fd 比对，避免跨来源比较
    size/mtime/ctime（Windows 目录条目元数据可能滞后）；此注入让读后
    句柄身份与 fd 不一致，必须立即拒绝。
    """
    db, config = _make_inputs(tmp_path)
    bundle = tmp_path / "bundle"
    real_fstat = backup_mod._fstat_now

    def fake_fstat(path):
        if os.path.abspath(path) == os.path.abspath(str(config)):
            return _fake_stat(stat.S_IFREG | 0o644, size=999)
        return real_fstat(path)

    monkeypatch.setattr(backup_mod, "_fstat_now", fake_fstat)

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                              str(bundle))

    assert any("config: replaced while reading" in err for err in errors)
    assert not bundle.exists()


def test_create_rejects_config_linked_while_reading(tmp_path, monkeypatch):
    """读后路径类型采样为软链接：即使句柄未变也必须拒绝。"""
    db, config = _make_inputs(tmp_path)
    bundle = tmp_path / "bundle"
    real_lstat = backup_mod._lstat_now
    calls = {"count": 0}

    def fake_lstat(path):
        if os.path.abspath(path) == os.path.abspath(str(config)):
            calls["count"] += 1
            if calls["count"] >= 3:      # 第 3 次即读取之后的那次采样
                return _fake_stat(stat.S_IFLNK | 0o777)
        return real_lstat(path)

    monkeypatch.setattr(backup_mod, "_lstat_now", fake_lstat)

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                              str(bundle))

    assert any("config: replaced while reading" in err for err in errors)
    assert not bundle.exists()


def test_create_rejects_snapshot_changed_after_hashing(tmp_path, monkeypatch):
    """哈希快照与校验句柄不一致（句柄 vs 句柄）时必须拒绝。"""
    db, config = _make_inputs(tmp_path)
    bundle = tmp_path / "bundle"
    real_read = backup_mod._read_payload

    def forged_read(path, label, errors, **kwargs):
        report = real_read(path, label, errors, **kwargs)
        if report is not None and label == "database":
            report["identity"] = (0, 0, 999, 0, 0)
        return report

    monkeypatch.setattr(backup_mod, "_read_payload", forged_read)

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                              str(bundle))

    assert any("integrity check failed" in err for err in errors)
    assert not bundle.exists()
    assert result["output_dir_removed"] is True


# ---------- 4. create：失败只清理本次新建目录 ----------

def test_create_snapshot_failure_removes_only_new_dir(tmp_path, monkeypatch):
    inputs = tmp_path / "inputs"
    db, config = _make_inputs(inputs)
    db_before, config_before = _sha256(db), _sha256(config)
    keeper = tmp_path / "sibling"
    keeper.mkdir()
    sentinel = keeper / "keep.txt"
    sentinel.write_bytes(b"keep")
    bundle = tmp_path / "bundle"

    def _boom(*args, **kwargs):
        raise RuntimeError("snapshot exploded")

    monkeypatch.setattr(backup_mod, "_snapshot_database", _boom)

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                              str(bundle))

    assert any("snapshot exploded" in err for err in errors)
    assert not bundle.exists()
    assert result["output_dir_removed"] is True
    assert result["bundle_created"] is False
    # 输入与无关路径都不被删除或改写
    assert _sha256(db) == db_before and _sha256(config) == config_before
    assert _rows(db) == _expected_rows()
    assert sentinel.read_bytes() == b"keep"


def test_create_manifest_failure_leaves_no_half_bundle(tmp_path, monkeypatch):
    db, config = _make_inputs(tmp_path)
    bundle = tmp_path / "bundle"

    def _boom(*args, **kwargs):
        raise RuntimeError("manifest exploded")

    monkeypatch.setattr(backup_mod, "_write_manifest", _boom)

    result, errors = backup_mod.create_bundle(str(db), str(config),
                                              str(bundle))

    assert any("manifest exploded" in err for err in errors)
    assert not bundle.exists()          # snapshot 已写出也不留半成品
    assert result["output_dir_removed"] is True


# ---------- 5. verify：只读、成功与拒绝路径 ----------

def test_verify_accepts_fresh_bundle_and_is_read_only(tmp_path):
    bundle, *_ = _make_bundle(tmp_path)
    before = _fingerprint(bundle)

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert errors == []
    assert result["bundle_valid"] is True
    assert result["contents"]["database"]["integrity_check"] == "ok"
    assert result["contents"]["config"]["sha256"] == _sha256(bundle
                                                             / "config.bin")
    _assert_honesty(result)
    assert _fingerprint(bundle) == before      # 零写入：字节与 mtime 不变


def test_verify_rejects_root_symlink_without_traversal(tmp_path, monkeypatch):
    root = tmp_path / "synthetic-link"
    real_lstat = backup_mod._lstat_now

    def fake_lstat(path):
        if os.path.abspath(path) == os.path.abspath(str(root)):
            return _fake_stat(stat.S_IFLNK | 0o777)
        return real_lstat(path)

    def fail_if_traversed(*_args, **_kwargs):
        raise AssertionError("被拒绝的 bundle 根绝不能被遍历")

    monkeypatch.setattr(backup_mod, "_lstat_now", fake_lstat)
    monkeypatch.setattr(backup_mod, "_scan_bundle_entries", fail_if_traversed)

    result, errors = backup_mod.verify_bundle(str(root))

    assert result["bundle_valid"] is False
    assert errors == ["bundle_root: symlink is not accepted"]


def test_verify_rejects_extra_path_and_subdirectory(tmp_path):
    bundle, *_ = _make_bundle(tmp_path)
    (bundle / "extra.txt").write_bytes(b"extra")
    (bundle / "nested").mkdir()

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any("bundle_entry: extra.txt: unexpected path in bundle" in err
               for err in errors)
    assert any("bundle_entry: nested: not a regular file" in err
               for err in errors)


def test_verify_rejects_missing_entry(tmp_path):
    bundle, *_ = _make_bundle(tmp_path)
    os.unlink(str(bundle / "config.bin"))

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any("bundle_entry: config.bin: missing" in err for err in errors)


def test_verify_rejects_payload_symlink_on_disk(tmp_path):
    bundle, *_ = _make_bundle(tmp_path)
    outside = tmp_path / "outside.sqlite3"
    outside.write_bytes((bundle / "db.sqlite3").read_bytes())
    os.unlink(str(bundle / "db.sqlite3"))
    try:
        os.symlink(outside, bundle / "db.sqlite3")
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接")

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any("db.sqlite3: symlink is not accepted" in err for err in errors)


def test_verify_rejects_payload_symlink_identity(tmp_path, monkeypatch):
    """确定性注入：payload 身份为软链接时读取层立即拒绝。"""
    bundle, *_ = _make_bundle(tmp_path)
    payload = bundle / "db.sqlite3"
    real_lstat = backup_mod._lstat_now

    def fake_lstat(path):
        if os.path.abspath(path) == os.path.abspath(str(payload)):
            return _fake_stat(stat.S_IFLNK | 0o777)
        return real_lstat(path)

    monkeypatch.setattr(backup_mod, "_lstat_now", fake_lstat)

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any("database: symlink is not accepted" in err for err in errors)


def test_verify_rejects_manifest_honesty_tamper(tmp_path):
    bundle, *_ = _make_bundle(tmp_path)
    document = _manifest_of(bundle)
    document["media_included"] = True
    _rewrite_manifest(bundle, document)

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any("manifest: media_included must be False" in err for err in errors)


def test_verify_rejects_manifest_hash_tamper(tmp_path):
    bundle, *_ = _make_bundle(tmp_path)
    document = _manifest_of(bundle)
    document["contents"]["config"]["sha256"] = "0" * 64
    _rewrite_manifest(bundle, document)

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any("config: sha256 mismatch" in err for err in errors)


@pytest.mark.parametrize("escape", ["../config.bin", "sub/config.bin",
                                    "C:\\evil.bin", "/etc/passwd"])
def test_verify_rejects_manifest_path_escape(tmp_path, escape):
    bundle, *_ = _make_bundle(tmp_path)
    document = _manifest_of(bundle)
    document["contents"]["config"]["entry"] = escape
    _rewrite_manifest(bundle, document)

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any("path escapes the bundle root" in err for err in errors)


def test_manifest_root_keys_are_the_closed_fixed_schema(tmp_path):
    """写入侧只能产出固定根键集合与固定值（根 schema 封闭的另一半证据）。"""
    bundle, *_ = _make_bundle(tmp_path)
    document = _manifest_of(bundle)

    assert sorted(document) == [
        "contents", "created_at", "evidence_assets_included", "kind",
        "media_included", "note", "quality_gate_passed",
        "recordings_included", "release_gate_passed", "schema", "source",
        "tool"]
    assert document["tool"] == "scam.linux_backup"
    assert document["note"] == backup_mod.BACKUP_NOTE
    assert document["created_at"].endswith("Z")
    assert sorted(document["source"]) == ["config_filename",
                                          "database_filename",
                                          "database_open_mode"]
    assert document["source"]["database_open_mode"] \
        in {"read_only", "query_only"}


def test_verify_accepts_source_name_with_dots(tmp_path):
    """``source`` 只要求单层纯名字：含 ``..`` 子串的合法文件名不得被误拒。"""
    bundle, *_ = _make_bundle(tmp_path, db_name="cameras..sqlite3",
                              config_name="cameras..json")
    document = _manifest_of(bundle)
    assert document["source"]["database_filename"] == "cameras..sqlite3"

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert errors == []
    assert result["bundle_valid"] is True


def test_source_filename_drops_trailing_separator():
    """声明名与平台无关：尾部分隔符不影响名字（create 不会自拒）。"""
    assert backup_mod._source_filename("/x/cameras.sqlite3/") \
        == "cameras.sqlite3"
    assert backup_mod._source_filename("/x/cameras.sqlite3") \
        == "cameras.sqlite3"


def test_verify_rejects_manifest_unknown_root_field(tmp_path):
    """未知根字段必须拒绝：根 schema 不接受任何扩展。"""
    bundle, *_ = _make_bundle(tmp_path)
    document = _manifest_of(bundle)
    document["future_root_field"] = {"anything": True}
    _rewrite_manifest(bundle, document)

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any("manifest: unknown root fields future_root_field" in err
               for err in errors), errors


@pytest.mark.parametrize("field", ["created_at", "tool", "source", "note"])
def test_verify_rejects_manifest_missing_root_field(tmp_path, field):
    """四个固定根字段缺失任一都必须非零（存在性本身是契约）。"""
    bundle, *_ = _make_bundle(tmp_path)
    document = _manifest_of(bundle)
    del document[field]
    _rewrite_manifest(bundle, document)

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any(f"manifest: missing field {field}" in err for err in errors), \
        errors


@pytest.mark.parametrize("mutate, expected", [
    (lambda document: document.update(created_at=1758412345),
     "manifest: created_at must be a UTC Z timestamp"),
    (lambda document: document.update(created_at="2026-09-21T00:40:12+08:00"),
     "manifest: created_at must be a UTC Z timestamp"),
    (lambda document: document.update(created_at="not-a-timestampZ"),
     "manifest: created_at must be a UTC Z timestamp"),
    (lambda document: document.update(created_at=None),
     "manifest: created_at must be a UTC Z timestamp"),
    (lambda document: document.update(tool="scam.linux_backup.v2"),
     "manifest: tool must be 'scam.linux_backup'"),
    (lambda document: document.update(tool=None),
     "manifest: tool must be 'scam.linux_backup'"),
    (lambda document: document.update(note="请信任本次校验"),
     "manifest: note must be the fixed module note"),
    (lambda document: document.update(note=None),
     "manifest: note must be the fixed module note"),
    (lambda document: document.update(source=["cameras.sqlite3"]),
     "manifest: source must be a JSON object"),
    (lambda document: document["source"].update(extra="x"),
     "manifest: source: unknown fields extra"),
    (lambda document: document["source"].update(
        database_filename="../cameras.sqlite3"),
     "manifest: source.database_filename: must be a plain file name"),
    (lambda document: document["source"].update(
        config_filename="sub/cameras.json"),
     "manifest: source.config_filename: must be a plain file name"),
    (lambda document: document["source"].update(database_open_mode="rw"),
     "manifest: source.database_open_mode: unknown mode"),
], ids=["created_at-int", "created_at-offset", "created_at-garbage",
        "created_at-null", "tool-other", "tool-null", "note-other",
        "note-null", "source-not-object", "source-extra-field",
        "source-db-escape", "source-config-escape", "source-mode"])
def test_verify_rejects_manifest_root_field_tamper(tmp_path, mutate,
                                                   expected):
    """固定根字段的类型、固定值或结构被破坏时 verify 必须非零。"""
    bundle, *_ = _make_bundle(tmp_path)
    document = _manifest_of(bundle)
    mutate(document)
    _rewrite_manifest(bundle, document)

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any(expected in err for err in errors), errors


def test_verify_rejects_payload_size_tamper(tmp_path):
    bundle, *_ = _make_bundle(tmp_path)
    path = bundle / "config.bin"
    path.write_bytes(path.read_bytes() + b"x")

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any("config: size mismatch" in err for err in errors)


def test_verify_rejects_payload_byte_tamper(tmp_path):
    bundle, *_ = _make_bundle(tmp_path)
    path = bundle / "config.bin"
    data = bytearray(path.read_bytes())
    data[0] ^= 0x20
    path.write_bytes(bytes(data))          # 等长改写：只有哈希能发现

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any("config: sha256 mismatch" in err for err in errors)


def test_verify_rejects_corrupt_sqlite_with_self_consistent_manifest(tmp_path):
    """清单与坏库自洽时，只有 SQLite 完整性校验能发现。"""
    bundle, *_ = _make_bundle(tmp_path)
    corrupt = b"SQLite format 3\x00" + b"\x00" * 4096
    (bundle / "db.sqlite3").write_bytes(corrupt)
    document = _manifest_of(bundle)
    document["contents"]["database"]["size"] = len(corrupt)
    document["contents"]["database"]["sha256"] \
        = hashlib.sha256(corrupt).hexdigest()
    _rewrite_manifest(bundle, document)

    result, errors = backup_mod.verify_bundle(str(bundle))

    assert result["bundle_valid"] is False
    assert any("database: integrity check failed" in err for err in errors)


def test_payload_file_check_rejects_uncheckpointed_companions(tmp_path):
    """旁路文件检查（扫描层之外的第二道防线）单独可证。"""
    db = tmp_path / "cameras.sqlite3"
    _make_database(db)
    (tmp_path / "cameras.sqlite3-wal").write_bytes(b"")
    errors = []

    assert backup_mod._check_payload_file(str(db), "database", errors) is None
    assert any("uncheckpointed -wal companion" in err for err in errors)


# ---------- 6. restore：先验后恢复、独立副本、失败清理 ----------

def test_restore_creates_independent_copy(tmp_path):
    rows = ("cam-1", "cam-2")
    bundle, db, _, created = _make_bundle(tmp_path, rows=rows)
    target = tmp_path / "restored"

    result, errors = backup_mod.restore_bundle(str(bundle), str(target))

    assert errors == []
    assert result["bundle_valid"] is True and result["restored"] is True
    assert _entries(target) == ["config.bin", "db.sqlite3"]
    for role, entry in (("database", "db.sqlite3"), ("config", "config.bin")):
        assert _sha256(target / entry) == created["contents"][role]["sha256"]
        assert result["contents"][role]["sha256"] \
            == created["contents"][role]["sha256"]
    assert result["contents"]["database"]["integrity_check"] == "ok"
    assert _rows(target / "db.sqlite3") == _expected_rows(rows)
    _assert_honesty(result)
    # 与 bundle 独立：改写 bundle 后已恢复副本不受影响
    (bundle / "config.bin").write_bytes(b"tampered-after-restore")
    (bundle / "db.sqlite3").write_bytes(b"tampered-after-restore")
    assert _sha256(target / "config.bin") == created["contents"]["config"]["sha256"]
    assert _sha256(target / "db.sqlite3") \
        == created["contents"]["database"]["sha256"]


def test_restore_rejects_existing_target_and_keeps_content(tmp_path):
    bundle, *_ = _make_bundle(tmp_path)
    target = tmp_path / "existing"
    target.mkdir()
    sentinel = target / "keep.txt"
    sentinel.write_bytes(b"untouched")

    result, errors = backup_mod.restore_bundle(str(bundle), str(target))

    assert any("target_dir: already exists" in err for err in errors)
    assert result["restored"] is False
    assert _entries(target) == ["keep.txt"]
    assert sentinel.read_bytes() == b"untouched"


def test_restore_verifies_before_creating_target(tmp_path):
    bundle, *_ = _make_bundle(tmp_path)
    (bundle / "config.bin").write_bytes(b"tampered")
    target = tmp_path / "restored"

    result, errors = backup_mod.restore_bundle(str(bundle), str(target))

    assert result["bundle_valid"] is False and result["restored"] is False
    assert any("config: size mismatch" in err for err in errors)
    assert not target.exists()      # 未通过 verify 就绝不新建目标目录


def test_restore_failure_removes_target_only(tmp_path, monkeypatch):
    bundle, *_ = _make_bundle(tmp_path)
    bundle_before = _fingerprint(bundle)
    target = tmp_path / "restored"

    def _boom(*args, **kwargs):
        raise RuntimeError("restore exploded")

    monkeypatch.setattr(backup_mod, "_copy_payload", _boom)

    result, errors = backup_mod.restore_bundle(str(bundle), str(target))

    assert any("restore exploded" in err for err in errors)
    assert not target.exists()
    assert result["target_dir_removed"] is True
    assert result["restored"] is False
    assert _fingerprint(bundle) == bundle_before


# ---------- 7. CLI 退出码、诚实字段与零网络/零子进程边界 ----------

def test_cli_create_verify_restore_exit_codes(tmp_path, capsys):
    db, config = _make_inputs(tmp_path)
    bundle = tmp_path / "bundle"
    target = tmp_path / "restored"

    code, created = _run_cli(
        ["create", "--db", str(db), "--config", str(config),
         "--output-dir", str(bundle)], capsys)
    assert code == 0
    _assert_honesty(created)

    code, verified = _run_cli(["verify", "--bundle-dir", str(bundle)], capsys)
    assert code == 0
    assert verified["bundle_valid"] is True
    _assert_honesty(verified)

    code, restored = _run_cli(
        ["restore", "--bundle-dir", str(bundle), "--target-dir", str(target)],
        capsys)
    assert code == 0
    assert restored["restored"] is True
    _assert_honesty(restored)
    assert _rows(target / "db.sqlite3") == _expected_rows()


def test_cli_failures_are_nonzero_and_structured(tmp_path, capsys):
    db, config = _make_inputs(tmp_path)
    bundle = tmp_path / "bundle"
    code, _ = _run_cli(
        ["create", "--db", str(db), "--config", str(config),
         "--output-dir", str(bundle)], capsys)
    assert code == 0

    # 已存在的输出目录：非零且不覆盖
    code, payload = _run_cli(
        ["create", "--db", str(db), "--config", str(config),
         "--output-dir", str(bundle)], capsys)
    assert code == 1
    assert any("already exists" in err for err in payload["errors"])
    _assert_honesty(payload)

    # 被篡改的状态包：verify 非零，restore 也不新建目录
    (bundle / "config.bin").write_bytes(b"tampered")
    code, payload = _run_cli(["verify", "--bundle-dir", str(bundle)], capsys)
    assert code == 1
    assert payload["bundle_valid"] is False

    target = tmp_path / "restored"
    code, payload = _run_cli(
        ["restore", "--bundle-dir", str(bundle), "--target-dir", str(target)],
        capsys)
    assert code == 1
    assert payload["restored"] is False
    _assert_honesty(payload)
    assert not target.exists()


def test_cli_results_always_declare_quality_gate_passed(tmp_path, capsys):
    """三子命令的成功与失败结果都必须带 quality_gate_passed=null。"""
    db, config = _make_inputs(tmp_path)
    bundle = tmp_path / "bundle"
    target = tmp_path / "restored"

    code, created = _run_cli(
        ["create", "--db", str(db), "--config", str(config),
         "--output-dir", str(bundle)], capsys)
    assert code == 0
    code, verified = _run_cli(["verify", "--bundle-dir", str(bundle)], capsys)
    assert code == 0
    code, restored = _run_cli(
        ["restore", "--bundle-dir", str(bundle), "--target-dir", str(target)],
        capsys)
    assert code == 0
    code, refused = _run_cli(
        ["create", "--db", str(db), "--config", str(config),
         "--output-dir", str(bundle)], capsys)
    assert code == 1
    code, failed = _run_cli(
        ["verify", "--bundle-dir", str(tmp_path / "absent")], capsys)
    assert code == 1

    for payload in (created, verified, restored, refused, failed):
        assert payload["quality_gate_passed"] is None
        _assert_honesty(payload)


def test_module_keeps_zero_network_zero_subprocess_boundary():
    source = Path(backup_mod.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "socket", "urllib", "requests", "http.client",
                   "os.system", "Popen", "shutil.which"):
        assert banned not in source
