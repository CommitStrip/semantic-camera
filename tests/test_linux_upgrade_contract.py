"""LC-041 队列P升级/回滚事务合同测试：prepare/verify 两子命令 + 九类边界。

覆盖 LC-041 全部安全与诚实边界：两个发布树的确定性文件列表与树摘要（输入顺序
与重复运行不改变结果）、有效 O 状态包被只读绑定而篡改/缺失/坏库/未知清单结构
一律阻止 prepare、当前=候选/相互嵌套/根与树内软链接/非普通文件/路径逃逸/打开前
换入/读取中变化全部拒绝、输出已存在不覆盖、树扫描或合同写入或备份复核注入失败
只清理本次新建目录且输入哈希不变、合同根与发布条目/备份引用/阶段/两检查表为
精确固定 schema（未知/缺失/坏类型/阶段乱序/危险回滚顺序全部拒绝）、合同生成后
改动树或备份包 verify 非零而未经变化时只读且不改变 mtime/哈希、CLI 退出码与七个
诚实字段、CLI 冻结拼写（prepare 的 help/usage 只展示 `--backup-bundle`，该拼写
成功、旧错误拼写与任何缩写拼写解析期非零拒绝，且与模块 docstring、runbook 三处
一致）、模块源码静态零网络/零子进程/零服务控制/无发布树 rename-replace-unlink、
runbook 契约（实际命令、人工确认点、备份先于停服、代码回退先于条件性状态恢复、
install.sh 限制与非自动化边界）。

软链接用例按仓库既有约定：本机不允许创建符号链接时 `pytest.skip`；同一批生产
拒绝分支另由 `_lstat_now`（类型/链接/换入）与 `_fstat_now`（句柄身份）两个模块
本地采样点注入回归确定性覆盖（无平台 `os.name` skip、无 sleep、无重试）。
证据等级仅为模块+单测（Windows 合成接线），不代表原生 Linux、真实 RTSP、24 小时、
识别质量或发布门禁通过。
"""

import hashlib
import json
import os
import re
import sqlite3
import stat
from pathlib import Path

import pytest

import scam.linux_backup as backup_mod
import scam.linux_upgrade_contract as upgrade_mod
from scam.linux_upgrade_contract import (
    CONTRACT_ENTRY, HEALTH_ENDPOINT, HONESTY_FIELDS, PHASES,
    ROLLBACK_CHECKLIST, ROLLBACK_CONDITION, SCHEMA, SERVICE_NAME,
    SUCCESS_CHECKLIST, verify_contract)

MODULE_PATH = Path(upgrade_mod.__file__)
ROOT = Path(__file__).resolve().parents[1]
RUNBOOK_PATH = ROOT / "docs" / "linux-operations-runbook.md"
RUNBOOK_SECTIONS = ("1. 干净安装", "2. 升级前备份", "3. 候选准备",
                    "4. 停服与发布切换", "5. 启动与健康确认", "6. 接受",
                    "7. 代码回退", "8. 条件性状态恢复", "9. 证据归档",
                    "10. 已知限制")
RUNBOOK_COMMANDS = ("deploy/install.sh", "python -m scam.linux_unit render",
                    "python -m scam.linux_backup create",
                    "python -m scam.linux_backup verify",
                    "python -m scam.linux_backup restore",
                    "python -m scam.linux_upgrade_contract prepare",
                    "python -m scam.linux_upgrade_contract verify",
                    "http://127.0.0.1:8600/api/health", "scam-nvr.service")
# 模块源码静态围栏：网络、子进程、服务控制、安装器或发布树改名的任何一处出现
# 都会让本批次声称的"只规划、不改变外部世界"失效。
BANNED_SOURCE_TOKENS = ("subprocess", "socket", "urllib", "requests",
                        "http.client", "os.system", "Popen", "shutil",
                        "os.rename", "os.replace", "rmtree", "os.remove(",
                        "os.truncate", "copytree", "copyfile", "os.chdir",
                        "os.symlink", "os.link", "pip install", "systemctl",
                        "sudo ", "winreg", "ctypes", "shelve", "threading")
# P-R1 冻结 CLI 拼写：绑定状态包的选项只能是 --backup-bundle。argparse 的选项缩写
# 已关闭，因此更长的旧拼写与任何前缀缩写都必须在解析期非零拒绝，绝不能靠缩写
# 兼容旧错误拼写。
FROZEN_BUNDLE_OPTION = "--backup-bundle"
REJECTED_BUNDLE_SPELLINGS = ("--backup-bundle-dir", "--backup-bundle-d",
                             "--backup-bundl", "--backup")


# ---------- 合成输入 ----------

def _write(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, bytes):
        path.write_bytes(payload)
    else:
        path.write_text(payload, encoding="utf-8")
    return path


def _make_release(root, version="0.3.0", sources=None):
    """构造最小合法发布树：pyproject.toml + scam/ 源码（LC-041 要求两项都在）。"""
    sources = sources if sources is not None else {
        "scam/__init__.py": f'__version__ = "{version}"\n',
        "scam/nvr.py": f"# {version} nvr entry\n",
    }
    _write(Path(root) / "pyproject.toml",
           f'[project]\nname = "scam"\nversion = "{version}"\n')
    for relative, text in sources.items():
        _write(Path(root) / relative, text)
    return Path(root)


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


def _make_bundle(tmp_path, *, name="bundle",
                 config_bytes=b'{"version": "0.3"}'):
    """用 O 模块自产一个有效状态包（测试不绕开 O 校验自造包）。"""
    inputs = Path(tmp_path) / (name + "-inputs")
    inputs.mkdir(parents=True, exist_ok=True)
    db = _make_database(inputs / "cameras.sqlite3")
    config = _write(inputs / "cameras.json", config_bytes)
    bundle = Path(tmp_path) / name
    result, errors = backup_mod.create_bundle(str(db), str(config),
                                              str(bundle))
    assert errors == [], errors
    assert result["bundle_created"] is True
    return bundle, db, config


def _inputs(tmp_path, *, current_version="0.3.0", candidate_version="0.4.0"):
    current = _make_release(tmp_path / "release-current", current_version)
    candidate = _make_release(tmp_path / "release-candidate",
                              candidate_version)
    bundle, _db, _config = _make_bundle(tmp_path)
    return current, candidate, bundle


def _prepare_dirs(tmp_path, current, candidate, bundle, *, name="contract"):
    contract_dir = Path(tmp_path) / name
    result, errors = upgrade_mod.prepare_contract(
        str(current), str(candidate), str(bundle), str(contract_dir))
    return (result, errors), contract_dir


def _prepare(tmp_path, *, name="contract"):
    current, candidate, bundle = _inputs(tmp_path)
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle, name=name)
    assert errors == [], errors
    assert result["contract_created"] is True
    assert contract_dir.is_dir()
    return result, errors, contract_dir, current, candidate, bundle


def _contract(contract_dir):
    return json.loads((Path(contract_dir) / CONTRACT_ENTRY)
                      .read_text(encoding="utf-8"))


def _contract_bytes(document):
    return json.dumps(document, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8") + b"\n"


def _rewrite_contract(contract_dir, document):
    (Path(contract_dir) / CONTRACT_ENTRY).write_bytes(
        _contract_bytes(document))


def _manifest_of(bundle):
    return json.loads((Path(bundle) / "manifest.json")
                      .read_text(encoding="utf-8"))


def _rewrite_bundle_manifest(bundle, document):
    (Path(bundle) / "manifest.json").write_bytes(_contract_bytes(document))


def _reseal_config(bundle, payload):
    """换掉 config 字节并按 O 模块的规范重封清单：包本身仍然自洽有效。"""
    (Path(bundle) / "config.bin").write_bytes(payload)
    document = _manifest_of(bundle)
    document["contents"]["config"]["size"] = len(payload)
    document["contents"]["config"]["sha256"] = \
        hashlib.sha256(payload).hexdigest()
    _rewrite_bundle_manifest(bundle, document)
    return document


def _run_cli(args, capsys):
    code = upgrade_mod.main(args)
    captured = capsys.readouterr()
    return code, json.loads(captured.out)


def _flat(text):
    """折叠空白：help 断行随终端宽度变化，断言只看词序列而非排版。"""
    return re.sub(r"\s+", " ", text)


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _tree_fingerprint(root):
    """递归目录指纹：相对路径 → (大小, SHA-256, mtime_ns)，用于证明零写入。"""
    root = Path(root)
    if not root.exists():
        return {"__missing__": True}
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        info = os.stat(path)
        result[str(path.relative_to(root))] = (info.st_size, _sha256(path),
                                               info.st_mtime_ns)
    return result


def _all_fingerprints(*roots):
    return {str(root): _tree_fingerprint(root) for root in roots}


def _entries(directory):
    with os.scandir(directory) as scanner:
        return sorted(item.name for item in scanner)


def _fake_stat(mode, size=0):
    """构造可注入的身份结果（不触及文件系统；dev/ino 与真实句柄必然不同）。"""
    return os.stat_result((mode, 0, 0, 1, 0, 0, size, 0, 0, 0))


def _assert_honesty(payload):
    assert payload["actions_executed"] is False
    assert payload["service_controlled"] is False
    assert payload["release_switched"] is False
    assert payload["rollback_executed"] is False
    assert payload["native_linux_validated"] is False
    assert payload["quality_gate_passed"] is None
    assert payload["release_gate_passed"] is None


def _function_source(name):
    source = MODULE_PATH.read_text(encoding="utf-8")
    start = source.index(f"def {name}(")
    rest = source[start:]
    end = rest.find("\ndef ")
    return rest if end == -1 else rest[:end]


def _sections():
    """把 runbook 切成 (标题, 正文) 段，用于按段检查人工确认点。"""
    text = RUNBOOK_PATH.read_text(encoding="utf-8")
    parts = re.split(r"^## ", text, flags=re.M)
    sections = []
    for part in parts[1:]:
        heading, _, body = part.partition("\n")
        sections.append((heading.strip(), body))
    return sections


# ---------- 1. 两个发布树的确定性摘要 ----------

def test_prepare_records_deterministic_file_list_and_tree_digest(tmp_path):
    prepared = _prepare(tmp_path)
    result, errors, contract_dir, current, candidate, bundle = prepared
    document = _contract(contract_dir)

    assert document["schema"] == SCHEMA
    assert document["kind"] == "upgrade_contract"
    assert document["service"] == SERVICE_NAME
    assert document["health_endpoint"] == HEALTH_ENDPOINT
    assert document["phases"] == list(PHASES)

    for label, root in (("current_release", current),
                        ("candidate_release", candidate)):
        recorded = document[label]
        assert recorded["root"] == os.path.abspath(str(root))
        paths = [entry["path"] for entry in recorded["files"]]
        assert paths == sorted(paths), label
        assert "pyproject.toml" in paths
        assert any(path.startswith("scam/") for path in paths)
        for entry in recorded["files"]:
            payload = (Path(root) / entry["path"]).read_bytes()
            assert entry["size"] == len(payload)
            assert entry["sha256"] == hashlib.sha256(payload).hexdigest()
        assert recorded["tree"]["files"] == len(recorded["files"])
        assert recorded["tree"]["bytes"] == sum(
            entry["size"] for entry in recorded["files"])
        digest = hashlib.sha256()
        for entry in recorded["files"]:
            digest.update(
                f"{entry['path']}\x00{entry['size']}\x00{entry['sha256']}\n"
                .encode("utf-8"))
        assert recorded["tree"]["sha256"] == digest.hexdigest()

    assert document["current_release"]["tree"]["sha256"] \
        != document["candidate_release"]["tree"]["sha256"]


def test_tree_digest_ignores_argument_order_and_repeated_runs(tmp_path):
    current = _make_release(tmp_path / "rel-a", "0.3.0")
    candidate = _make_release(tmp_path / "rel-b", "0.4.0")
    bundle, _db, _config = _make_bundle(tmp_path)
    (first, errors), first_dir = _prepare_dirs(tmp_path, current, candidate,
                                               bundle, name="c1")
    assert errors == []
    (swapped, errors), swapped_dir = _prepare_dirs(
        tmp_path, candidate, current, bundle, name="c2")
    assert errors == []
    (again, errors), again_dir = _prepare_dirs(tmp_path, current, candidate,
                                               bundle, name="c3")
    assert errors == []
    document = _contract(first_dir)
    other = _contract(swapped_dir)
    repeat = _contract(again_dir)
    # 同一棵树无论当作 current 还是 candidate，摘要必须逐字节一致
    assert document["current_release"]["tree"] \
        == other["candidate_release"]["tree"]
    assert document["candidate_release"]["tree"] \
        == other["current_release"]["tree"]
    # 重复运行不改变结果
    assert repeat["current_release"]["tree"] \
        == document["current_release"]["tree"]
    assert repeat["candidate_release"]["files"] \
        == document["candidate_release"]["files"]


def test_tree_digest_changes_when_one_byte_changes(tmp_path):
    current, candidate, bundle = _inputs(tmp_path)
    (first, errors), first_dir = _prepare_dirs(tmp_path, current, candidate,
                                               bundle, name="c1")
    assert errors == []
    target = Path(candidate) / "scam" / "nvr.py"
    target.write_bytes(target.read_bytes() + b"\n")
    (second, errors), second_dir = _prepare_dirs(tmp_path, current, candidate,
                                                 bundle, name="c2")
    assert errors == []
    before = _contract(first_dir)["candidate_release"]
    after = _contract(second_dir)["candidate_release"]
    assert after["tree"]["sha256"] != before["tree"]["sha256"]
    changed = {entry["path"]: entry["sha256"] for entry in after["files"]}
    original = {entry["path"]: entry["sha256"] for entry in before["files"]}
    assert changed["scam/nvr.py"] != original["scam/nvr.py"]
    assert changed["scam/__init__.py"] == original["scam/__init__.py"]


def test_prepare_rejects_tree_without_required_release_files(tmp_path):
    current, candidate, bundle = _inputs(tmp_path)
    (Path(candidate) / "pyproject.toml").unlink()
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle)
    assert result["contract_created"] is False
    assert any("pyproject.toml" in error for error in errors)
    assert not contract_dir.exists()


# ---------- 2. O 状态包的只读绑定 ----------

def test_prepare_binds_the_verified_state_bundle(tmp_path):
    prepared = _prepare(tmp_path)
    result, errors, contract_dir, current, candidate, bundle = prepared
    bound = _contract(contract_dir)["backup"]

    assert bound["bundle_dir"] == os.path.abspath(str(bundle))
    assert bound["bundle_valid"] is True
    assert bound["manifest_sha256"] == _sha256(Path(bundle) / "manifest.json")
    for role, entry in (("database", "db.sqlite3"), ("config", "config.bin")):
        recorded = bound["contents"][role]
        payload = (Path(bundle) / entry).read_bytes()
        assert recorded["entry"] == entry
        assert recorded["size"] == len(payload)
        assert recorded["sha256"] == hashlib.sha256(payload).hexdigest()
    assert bound["contents"]["database"]["integrity_check"] == "ok"

    verification, bundle_errors = backup_mod.verify_bundle(str(bundle))
    assert bundle_errors == []
    assert verification["bundle_valid"] is True
    for role in ("database", "config"):
        assert bound["contents"][role]["sha256"] \
            == verification["contents"][role]["sha256"]


@pytest.mark.parametrize("case", [
    "manifest-unknown-root-field",
    "manifest-missing-field",
    "manifest-unknown-kind",
    "database-not-sqlite",
    "config-truncated",
    "manifest-removed",
    "database-removed",
    "extra-entry",
])
def test_prepare_rejects_invalid_state_bundle(tmp_path, case):
    current, candidate, bundle = _inputs(tmp_path)
    if case == "manifest-unknown-root-field":
        document = _manifest_of(bundle)
        document["unknown_root_field"] = True
        _rewrite_bundle_manifest(bundle, document)
    elif case == "manifest-missing-field":
        document = _manifest_of(bundle)
        document.pop("created_at")
        _rewrite_bundle_manifest(bundle, document)
    elif case == "manifest-unknown-kind":
        document = _manifest_of(bundle)
        document["kind"] = "not_a_state_bundle"
        _rewrite_bundle_manifest(bundle, document)
    elif case == "database-not-sqlite":
        (bundle / "db.sqlite3").write_bytes(b"definitely not a database")
    elif case == "config-truncated":
        payload = (bundle / "config.bin").read_bytes()
        (bundle / "config.bin").write_bytes(payload[:-1])
    elif case == "manifest-removed":
        (bundle / "manifest.json").unlink()
    elif case == "database-removed":
        (bundle / "db.sqlite3").unlink()
    else:
        (bundle / "bypass.bin").write_bytes(b"extra")

    before = _all_fingerprints(current, candidate, bundle)
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle)
    assert errors, case
    assert result["contract_created"] is False, case
    assert not contract_dir.exists(), case
    assert _all_fingerprints(current, candidate, bundle) == before, case


def test_prepare_rejects_missing_bundle_before_creating_anything(tmp_path):
    current, candidate, _bundle = _inputs(tmp_path)
    absent = tmp_path / "absent-bundle"
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, absent)
    assert any("backup_bundle: missing" in error for error in errors)
    assert result["contract_created"] is False
    assert result["output_dir_removed"] is None
    assert not contract_dir.exists()


# ---------- 3. 发布根与树围栏 ----------

def test_prepare_rejects_same_current_and_candidate(tmp_path):
    current, candidate, bundle = _inputs(tmp_path)
    (result, errors), contract_dir = _prepare_dirs(tmp_path, current, current,
                                                   bundle)
    assert any("same directory" in error for error in errors)
    assert result["contract_created"] is False
    assert result["output_dir_removed"] is None
    assert not contract_dir.exists()


def test_prepare_rejects_nested_release_roots(tmp_path):
    current = _make_release(tmp_path / "release", "0.3.0")
    nested = _make_release(Path(current) / "releases" / "0.4.0", "0.4.0")
    bundle, _db, _config = _make_bundle(tmp_path)
    (result, errors), contract_dir = _prepare_dirs(tmp_path, current, nested,
                                                   bundle, name="c1")
    assert any("nested" in error for error in errors)
    assert not contract_dir.exists()
    (result, errors), contract_dir = _prepare_dirs(tmp_path, nested, current,
                                                   bundle, name="c2")
    assert any("nested" in error for error in errors)
    assert not contract_dir.exists()


def test_root_relation_helper_rejects_same_and_nested_paths(tmp_path):
    outer = _make_release(tmp_path / "outer", "0.3.0")
    inner = _make_release(Path(outer) / "inner", "0.4.0")
    sibling = _make_release(tmp_path / "sibling", "0.5.0")
    errors = []
    upgrade_mod._check_root_relation(outer, outer, os.lstat(outer),
                                     os.lstat(outer), errors)
    assert any("same directory" in error for error in errors)
    errors = []
    upgrade_mod._check_root_relation(outer, inner, os.lstat(outer),
                                     os.lstat(inner), errors)
    assert any("nested" in error for error in errors)
    errors = []
    upgrade_mod._check_root_relation(inner, outer, os.lstat(inner),
                                     os.lstat(outer), errors)
    assert any("nested" in error for error in errors)
    errors = []
    upgrade_mod._check_root_relation(outer, sibling, os.lstat(outer),
                                     os.lstat(sibling), errors)
    assert errors == []


def test_prepare_rejects_release_root_that_is_not_a_directory(tmp_path):
    current, candidate, bundle = _inputs(tmp_path)
    file_root = _write(tmp_path / "not-a-directory", "x")
    (result, errors), contract_dir = _prepare_dirs(tmp_path, file_root,
                                                   candidate, bundle)
    assert any("not a directory" in error for error in errors)
    assert not contract_dir.exists()


def test_prepare_rejects_output_dir_inside_a_release_tree(tmp_path):
    current, candidate, bundle = _inputs(tmp_path)
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle,
        name="release-current/upgrades")
    assert any("output_dir:" in error for error in errors)
    assert not contract_dir.exists()


def test_prepare_rejects_symlinked_release_root(tmp_path):
    current, candidate, bundle = _inputs(tmp_path)
    link = tmp_path / "current-link"
    try:
        os.symlink(str(current), str(link), target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlink creation is not permitted in this environment")
    (result, errors), contract_dir = _prepare_dirs(tmp_path, link, candidate,
                                                   bundle)
    assert any("symlink is not accepted" in error for error in errors)
    assert not contract_dir.exists()


def test_prepare_rejects_symlinked_tree_entry(tmp_path):
    current, candidate, bundle = _inputs(tmp_path)
    outside = _write(tmp_path / "outside.onnx", "model-bytes")
    link = Path(current) / "models" / "person.onnx"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(str(outside), str(link))
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlink creation is not permitted in this environment")
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle)
    assert any("symlink is not accepted" in error for error in errors)
    assert not contract_dir.exists()


def test_prepare_rejects_tree_entry_reported_as_non_regular(tmp_path,
                                                           monkeypatch):
    current, candidate, bundle = _inputs(tmp_path)
    target = os.path.abspath(str(Path(current) / "scam" / "nvr.py"))
    real_lstat = upgrade_mod._lstat_now

    def fake_lstat(path):
        if os.path.abspath(str(path)) == target:
            return _fake_stat(stat.S_IFIFO)
        return real_lstat(path)

    monkeypatch.setattr(upgrade_mod, "_lstat_now", fake_lstat)
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle)
    assert any("not a regular file" in error for error in errors)
    assert result["output_dir_removed"] is True
    assert not contract_dir.exists()


def test_prepare_rejects_tree_entry_swapped_before_open(tmp_path, monkeypatch):
    """打开前换入：路径 lstat 与句柄 fstat 不再是同一对象即拒绝。"""
    current, candidate, bundle = _inputs(tmp_path)
    target = os.path.abspath(str(Path(candidate) / "scam" / "nvr.py"))
    real_lstat = upgrade_mod._lstat_now

    def fake_lstat(path):
        info = real_lstat(path)
        if os.path.abspath(str(path)) == target:
            return _fake_stat(stat.S_IFREG, info.st_size)
        return info

    monkeypatch.setattr(upgrade_mod, "_lstat_now", fake_lstat)
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle)
    assert any("identity changed between check and open" in error
               for error in errors)
    assert not contract_dir.exists()


def test_prepare_rejects_tree_entry_replaced_mid_read(tmp_path, monkeypatch):
    """读取中变化：读后句柄身份与读前快照不一致（size/mtime/ctime）即拒绝。"""
    current, candidate, bundle = _inputs(tmp_path)
    target = os.path.abspath(str(Path(current) / "scam" / "__init__.py"))
    real_fstat = upgrade_mod._fstat_now

    def fake_fstat(path):
        info = real_fstat(path)
        if os.path.abspath(str(path)) == target:
            return _fake_stat(stat.S_IFREG, info.st_size + 1)
        return info

    monkeypatch.setattr(upgrade_mod, "_fstat_now", fake_fstat)
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle)
    assert any("replaced while reading" in error for error in errors)
    assert not contract_dir.exists()


@pytest.mark.parametrize("value", [
    "/etc/passwd", "\\windows\\system32", "C:/scam/nvr.py", "../escape.py",
    "scam/../../escape.py", "scam//nvr.py", "scam/", "./scam/nvr.py", "",
    "scam\\nvr.py", "scam/\x00nvr.py", "..",
])
def test_unsafe_relative_path_rejects_dangerous_names(value):
    assert upgrade_mod._unsafe_relative_path(value) is True


@pytest.mark.parametrize("value", [
    "scam/nvr.py", "pyproject.toml", "a/b/c/d.txt", "scam..py",
    "a..b/c..d.txt", "scam/__init__.py",
])
def test_unsafe_relative_path_accepts_plain_names(value):
    assert upgrade_mod._unsafe_relative_path(value) is False


# ---------- 4. 输出目录与失败清理 ----------

def test_prepare_rejects_existing_output_dir_and_keeps_content(tmp_path):
    current, candidate, bundle = _inputs(tmp_path)
    output = tmp_path / "contract"
    output.mkdir()
    marker = _write(output / "keep.txt", "keep")
    before = _tree_fingerprint(output)
    result, errors = upgrade_mod.prepare_contract(
        str(current), str(candidate), str(bundle), str(output))
    assert any("already exists" in error for error in errors)
    assert result["contract_created"] is False
    assert result["output_dir_removed"] is None
    assert _tree_fingerprint(output) == before
    assert marker.read_text(encoding="utf-8") == "keep"
    assert not (output / CONTRACT_ENTRY).exists()


def test_prepare_scan_failure_removes_only_new_dir_and_keeps_inputs(
        tmp_path, monkeypatch):
    current, candidate, bundle = _inputs(tmp_path)
    before = _all_fingerprints(current, candidate, bundle)

    def boom(path, relative, label, errors):
        errors.append(f"{label}: injected scan failure at {relative}")
        return None

    monkeypatch.setattr(upgrade_mod, "_hash_file", boom)
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle)
    assert any("injected scan failure" in error for error in errors)
    assert result["contract_created"] is False
    assert result["output_dir_removed"] is True
    assert not contract_dir.exists()
    assert _all_fingerprints(current, candidate, bundle) == before


def test_prepare_contract_write_failure_removes_only_new_dir(tmp_path,
                                                             monkeypatch):
    current, candidate, bundle = _inputs(tmp_path)
    before = _all_fingerprints(current, candidate, bundle)

    def fail_write(target, payload, label, errors):
        errors.append("contract: injected write failure")
        return False

    monkeypatch.setattr(upgrade_mod, "_write_at", fail_write)
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle)
    assert any("injected write failure" in error for error in errors)
    assert result["output_dir_removed"] is True
    assert not contract_dir.exists()
    assert _all_fingerprints(current, candidate, bundle) == before


def test_prepare_backup_verification_failure_cleans_up_only_new_dir(
        tmp_path, monkeypatch):
    """备份复核失败：目录已创建，必须只清理本次新建目录且输入哈希不变。"""
    current, candidate, bundle = _inputs(tmp_path)
    before = _all_fingerprints(current, candidate, bundle)

    def failing_verify(bundle_dir):
        return ({"bundle_valid": False, "errors": ["injected"]}, ["injected"])

    monkeypatch.setattr(upgrade_mod, "_verify_backup", failing_verify)
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle)
    assert any("failed read-only verification" in error for error in errors)
    assert result["contract_created"] is False
    assert result["output_dir_removed"] is True
    assert not contract_dir.exists()
    assert _all_fingerprints(current, candidate, bundle) == before


def test_prepare_backup_verification_exception_is_structured(tmp_path,
                                                             monkeypatch):
    current, candidate, bundle = _inputs(tmp_path)
    before = _all_fingerprints(current, candidate, bundle)

    def raising_verify(bundle_dir):
        raise OSError("injected backup verification failure")

    monkeypatch.setattr(upgrade_mod, "_verify_backup", raising_verify)
    (result, errors), contract_dir = _prepare_dirs(
        tmp_path, current, candidate, bundle)
    assert any("unexpected OSError" in error for error in errors)
    assert result["output_dir_removed"] is True
    assert not contract_dir.exists()
    assert _all_fingerprints(current, candidate, bundle) == before


# ---------- 5. 合同固定 schema（未知/缺失/坏类型/乱序/危险回滚顺序） ----------

def _root_field(key, value):
    def mutate(document):
        document[key] = value
    return mutate


def _drop_root_field(key):
    def mutate(document):
        document.pop(key)
    return mutate


def _release_field(key, value):
    def mutate(document):
        document["current_release"][key] = value
    return mutate


def _drop_release_root(document):
    document["current_release"].pop("root")


def _tree_field(key, value):
    def mutate(document):
        document["current_release"]["tree"][key] = value
    return mutate


def _file_field(index, key, value):
    def mutate(document):
        document["current_release"]["files"][index][key] = value
    return mutate


def _file_extra_field(key, value):
    def mutate(document):
        document["current_release"]["files"][0][key] = value
    return mutate


def _reverse_release_files(document):
    document["current_release"]["files"].reverse()


def _backup_field(key, value):
    def mutate(document):
        document["backup"][key] = value
    return mutate


def _drop_manifest_digest(document):
    document["backup"].pop("manifest_sha256")


def _add_unknown_content_entry(document):
    document["backup"]["contents"]["extra"] = {}


def _content_field(role, key, value):
    def mutate(document):
        document["backup"]["contents"][role][key] = value
    return mutate


def _swap_steps(label, first, second):
    def mutate(document):
        steps = document[label]
        steps[first], steps[second] = steps[second], steps[first]
    return mutate


def _checklist_field(label, index, key, value):
    def mutate(document):
        document[label][index][key] = value
    return mutate


def _drop_step(label):
    def mutate(document):
        del document[label][-1]
    return mutate


def _state_restore_condition(value):
    def mutate(document):
        for step in document["rollback_checklist"]:
            if step["step"] == "restore_state_to_fresh_staging":
                step["condition"] = value
    return mutate


CONTRACT_TAMPER_CASES = (
    ("unknown root field", _root_field("unknown_root", 1),
     "unknown root fields"),
    ("missing created_at", _drop_root_field("created_at"),
     "missing field created_at"),
    ("missing service", _drop_root_field("service"), "missing field service"),
    ("missing rollback checklist",
     _drop_root_field("rollback_checklist"),
     "missing field rollback_checklist"),
    ("created_at not a Z timestamp", _root_field("created_at", 1737440000),
     "created_at must be a UTC Z timestamp"),
    ("created_at with offset",
     _root_field("created_at", "2026-09-21T01:00:00+08:00"),
     "created_at must be a UTC Z timestamp"),
    ("tool renamed", _root_field("tool", "scam.other_tool"), "tool must be"),
    ("note rewritten", _root_field("note", "任意注记"), "note must be"),
    ("service renamed", _root_field("service", "other.service"),
     "service must be"),
    ("health endpoint changed",
     _root_field("health_endpoint", "http://127.0.0.1:9999/api/health"),
     "health_endpoint must be"),
    ("unknown schema", _root_field("schema", "scam.other/v1"),
     "unknown schema"),
    ("unknown kind", _root_field("kind", "other_contract"), "unknown kind"),
    ("phases reordered",
     _root_field("phases", [PHASES[1], PHASES[0], *PHASES[2:]]),
     "phases must be the fixed order"),
    ("phases shortened", _root_field("phases", list(PHASES[:-1])),
     "phases must be the fixed order"),
    ("actions_executed true", _root_field("actions_executed", True),
     "actions_executed must be False"),
    ("release_switched text", _root_field("release_switched", "no"),
     "release_switched must be False"),
    ("quality gate claimed", _root_field("quality_gate_passed", "yes"),
     "quality_gate_passed must be None"),
    ("current root relative", _release_field("root", "releases/0.3.0"),
     "absolute path string"),
    ("release entry unknown field", _release_field("extra_field", 1),
     "unknown fields"),
    ("release entry missing root", _drop_release_root, "missing field root"),
    ("release files empty", _release_field("files", []), "non-empty list"),
    ("release tree not an object", _release_field("tree", []),
     "tree must be a JSON object"),
    ("tree file count changed", _tree_field("files", 99),
     "tree.files: must equal the recorded"),
    ("tree byte total changed", _tree_field("bytes", 123456),
     "tree.bytes: must equal the recorded"),
    ("tree digest changed", _tree_field("sha256", "0" * 64),
     "tree.sha256: must equal the recorded"),
    ("files unsorted", _reverse_release_files,
     "must be sorted by relative path"),
    ("files entry unknown field", _file_extra_field("extra", 1),
     "unknown fields"),
    ("files path escapes", _file_field(0, "path", "../escape.py"),
     "safe relative POSIX path"),
    ("files path absolute", _file_field(0, "path", "/etc/passwd"),
     "safe relative POSIX path"),
    ("files path with backslash", _file_field(0, "path", "scam\\nvr.py"),
     "safe relative POSIX path"),
    ("files path empty", _file_field(0, "path", ""),
     "safe relative POSIX path"),
    ("files size string", _file_field(0, "size", "12"),
     "non-negative integer"),
    ("files size bool", _file_field(0, "size", True), "non-negative integer"),
    ("files size negative", _file_field(0, "size", -1),
     "non-negative integer"),
    ("files sha uppercase", _file_field(0, "sha256", "A" * 64),
     "64-character lowercase hex digest"),
    ("files sha short", _file_field(0, "sha256", "abc"),
     "64-character lowercase hex digest"),
    ("backup unknown field", _backup_field("extra_backup_field", 1),
     "unknown fields"),
    ("backup missing manifest digest", _drop_manifest_digest,
     "missing field manifest_sha256"),
    ("backup marked invalid", _backup_field("bundle_valid", False),
     "bundle_valid: must be True"),
    ("backup manifest digest malformed",
     _backup_field("manifest_sha256", "not-a-digest"), "64-character"),
    ("backup contents not an object", _backup_field("contents", []),
     "must be a JSON object"),
    ("backup contents unknown entry", _add_unknown_content_entry,
     "unknown entries"),
    ("backup database entry renamed",
     _content_field("database", "entry", "other.sqlite3"), "unknown entry"),
    ("backup database integrity failed",
     _content_field("database", "integrity_check", "failed"),
     "integrity_check: must be 'ok'"),
    ("backup config digest malformed",
     _content_field("config", "sha256", "zz"), "64-character"),
    ("backup bundle dir relative",
     _backup_field("bundle_dir", "var/backups/scam"),
     "absolute path string"),
    ("success checklist shortened", _drop_step("success_checklist"),
     "must contain exactly 6 fixed steps"),
    ("success checklist reordered", _swap_steps("success_checklist", 0, 1),
     "unsafe order"),
    ("success checklist evidence rewritten",
     _checklist_field("success_checklist", 0, "evidence", "随便写"),
     "success_checklist[0].evidence: must be"),
    ("success checklist runbook ref rewritten",
     _checklist_field("success_checklist", 0, "runbook", "docs/nowhere.md §1"),
     "success_checklist[0].runbook: must be"),
    ("rollback checklist shortened", _drop_step("rollback_checklist"),
     "must contain exactly 7 fixed steps"),
    ("rollback checklist reordered", _swap_steps("rollback_checklist", 0, 1),
     "unsafe order"),
    ("rollback state restore unconditional",
     _state_restore_condition("always"),
     "state restore must be conditional"),
    ("rollback state restore before health",
     _swap_steps("rollback_checklist", 3, 4), "unsafe order"),
    ("rollback step unknown field",
     _checklist_field("rollback_checklist", 0, "extra", 1), "unknown fields"),
)


@pytest.mark.parametrize("name, mutate, expected", CONTRACT_TAMPER_CASES)
def test_verify_rejects_contract_schema_tamper(tmp_path, name, mutate,
                                               expected):
    _result, _errors, contract_dir, *_rest = _prepare(tmp_path)
    document = _contract(contract_dir)
    mutate(document)
    _rewrite_contract(contract_dir, document)
    outcome, errors = verify_contract(str(contract_dir))
    assert errors, name
    assert outcome["contract_valid"] is False, name
    assert any(expected in error for error in errors), (name, errors)


def test_verify_rejects_invalid_json_contract(tmp_path):
    _result, _errors, contract_dir, *_rest = _prepare(tmp_path)
    (contract_dir / CONTRACT_ENTRY).write_bytes(b"{not json")
    outcome, errors = verify_contract(str(contract_dir))
    assert any("invalid UTF-8 JSON" in error for error in errors)
    assert outcome["contract_valid"] is False


def test_verify_rejects_non_object_contract_root(tmp_path):
    _result, _errors, contract_dir, *_rest = _prepare(tmp_path)
    (contract_dir / CONTRACT_ENTRY).write_bytes(b"[]\n")
    outcome, errors = verify_contract(str(contract_dir))
    assert any("root must be a JSON object" in error for error in errors)
    assert outcome["contract_valid"] is False


def test_verify_rejects_extra_path_in_contract_dir(tmp_path):
    _result, _errors, contract_dir, *_rest = _prepare(tmp_path)
    _write(contract_dir / "extra.json", "{}\n")
    outcome, errors = verify_contract(str(contract_dir))
    assert any("unexpected path in contract directory" in error
               for error in errors)
    assert outcome["contract_valid"] is False


def test_verify_rejects_missing_contract_entry(tmp_path):
    _result, _errors, contract_dir, *_rest = _prepare(tmp_path)
    (contract_dir / CONTRACT_ENTRY).unlink()
    outcome, errors = verify_contract(str(contract_dir))
    assert any(f"{CONTRACT_ENTRY}: missing" in error for error in errors)
    assert outcome["contract_valid"] is False


def test_verify_rejects_subdirectory_in_contract_dir(tmp_path):
    _result, _errors, contract_dir, *_rest = _prepare(tmp_path)
    (contract_dir / "nested").mkdir()
    outcome, errors = verify_contract(str(contract_dir))
    assert any("not a regular file" in error for error in errors)
    assert outcome["contract_valid"] is False


def test_verify_rejects_symlinked_contract_entry(tmp_path):
    _result, _errors, contract_dir, *_rest = _prepare(tmp_path)
    payload = (contract_dir / CONTRACT_ENTRY).read_bytes()
    target = _write(tmp_path / "copy.json", payload)
    (contract_dir / CONTRACT_ENTRY).unlink()
    try:
        os.symlink(str(target), str(contract_dir / CONTRACT_ENTRY))
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlink creation is not permitted in this environment")
    outcome, errors = verify_contract(str(contract_dir))
    assert any("symlink is not accepted" in error for error in errors)
    assert outcome["contract_valid"] is False


def test_verify_rejects_symlinked_contract_root(tmp_path):
    _result, _errors, contract_dir, *_rest = _prepare(tmp_path)
    link = tmp_path / "contract-link"
    try:
        os.symlink(str(contract_dir), str(link), target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlink creation is not permitted in this environment")
    outcome, errors = verify_contract(str(link))
    assert any("symlink is not accepted" in error for error in errors)
    assert outcome["contract_valid"] is False


def test_contract_carries_the_seven_honesty_fields(tmp_path):
    _result, _errors, contract_dir, *_rest = _prepare(tmp_path)
    document = _contract(contract_dir)
    assert len(HONESTY_FIELDS) == 7
    for field, expected in HONESTY_FIELDS:
        assert document[field] == expected, field
    assert set(document) == set(upgrade_mod.CONTRACT_FIELDS)
    assert document["success_checklist"] \
        == [dict(step) for step in SUCCESS_CHECKLIST]
    assert document["rollback_checklist"] \
        == [dict(step) for step in ROLLBACK_CHECKLIST]
    assert all(step["condition"] == ROLLBACK_CONDITION
               for step in document["rollback_checklist"][4:])


# ---------- 6. 生成后的变更检测与只读性 ----------

def test_verify_is_read_only_for_an_untouched_contract(tmp_path):
    _result, _errors, contract_dir, current, candidate, bundle = _prepare(
        tmp_path)
    before = _all_fingerprints(contract_dir, current, candidate, bundle)
    assert before
    outcome, errors = verify_contract(str(contract_dir))
    assert errors == []
    assert outcome["contract_valid"] is True
    assert outcome["errors"] == []
    assert outcome["service"] == SERVICE_NAME
    assert outcome["health_endpoint"] == HEALTH_ENDPOINT
    assert outcome["phases"] == list(PHASES)
    after = _all_fingerprints(contract_dir, current, candidate, bundle)
    assert after == before


@pytest.mark.parametrize("case", [
    "current-modified",
    "current-added",
    "current-removed",
    "candidate-modified",
    "candidate-added",
    "bundle-config-bytes",
    "bundle-database-bytes",
    "bundle-manifest-field",
    "bundle-resealed-config",
])
def test_verify_rejects_any_change_after_prepare(tmp_path, case):
    _result, _errors, contract_dir, current, candidate, bundle = _prepare(
        tmp_path)
    if case == "current-modified":
        target = Path(current) / "scam" / "nvr.py"
        target.write_bytes(target.read_bytes() + b"# changed\n")
    elif case == "current-added":
        _write(Path(current) / "scam" / "extra.py", "# extra\n")
    elif case == "current-removed":
        (Path(current) / "scam" / "nvr.py").unlink()
    elif case == "candidate-modified":
        target = Path(candidate) / "pyproject.toml"
        target.write_bytes(target.read_bytes() + b"\n")
    elif case == "candidate-added":
        _write(Path(candidate) / "scam" / "extra.py", "# extra\n")
    elif case == "bundle-config-bytes":
        (Path(bundle) / "config.bin").write_bytes(b'{"version": "9.9"}')
    elif case == "bundle-database-bytes":
        (Path(bundle) / "db.sqlite3").write_bytes(b"not a database")
    elif case == "bundle-manifest-field":
        document = _manifest_of(bundle)
        document["extra_root_field"] = True
        _rewrite_bundle_manifest(bundle, document)
    else:
        _reseal_config(bundle, b'{"version": "9.9"}')

    outcome, errors = verify_contract(str(contract_dir))
    assert errors, case
    assert outcome["contract_valid"] is False, case


def test_verify_rejects_resealed_bundle_contents(tmp_path):
    """重封的包仍能通过 O 校验，但必须被合同的 payload 摘要绑定拒绝。"""
    _result, _errors, contract_dir, _current, _candidate, bundle = _prepare(
        tmp_path)
    _reseal_config(bundle, b'{"version": "9.9"}')
    assert backup_mod.verify_bundle(str(bundle))[0]["bundle_valid"] is True
    outcome, errors = verify_contract(str(contract_dir))
    assert outcome["contract_valid"] is False
    assert any("config bytes no longer match the contract" in error
               for error in errors)


def test_verify_rejects_resealed_bundle_manifest(tmp_path):
    """payload 未变但清单被重写（新时间戳）：manifest 摘要绑定必须非零。"""
    _result, _errors, contract_dir, _current, _candidate, bundle = _prepare(
        tmp_path)
    document = _manifest_of(bundle)
    document["created_at"] = "2026-09-21T02:00:00Z"
    _rewrite_bundle_manifest(bundle, document)
    assert backup_mod.verify_bundle(str(bundle))[0]["bundle_valid"] is True
    outcome, errors = verify_contract(str(contract_dir))
    assert outcome["contract_valid"] is False
    assert any("manifest SHA-256 no longer matches the contract" in error
               for error in errors)


def test_verify_rejects_recorded_root_that_points_elsewhere(tmp_path):
    """合同记录的发布根被指向另一棵树：逐文件比对必须非零。"""
    _result, _errors, contract_dir, current, _candidate, _bundle = _prepare(
        tmp_path)
    document = _contract(contract_dir)
    document["candidate_release"]["root"] = os.path.abspath(
        str(Path(current) / "scam"))
    _rewrite_contract(contract_dir, document)
    outcome, errors = verify_contract(str(contract_dir))
    assert outcome["contract_valid"] is False
    assert any("candidate_release" in error for error in errors)


# ---------- 7. CLI：退出码、结构化错误与诚实字段 ----------

def test_cli_prepare_and_verify_success(tmp_path, capsys):
    current, candidate, bundle = _inputs(tmp_path)
    contract_dir = tmp_path / "contract"
    code, payload = _run_cli([
        "prepare",
        "--current-release-dir", str(current),
        "--candidate-release-dir", str(candidate),
        "--backup-bundle", str(bundle),
        "--output-dir", str(contract_dir),
    ], capsys)
    assert code == 0
    assert payload["kind"] == "upgrade_contract_prepare_result"
    assert payload["contract_created"] is True
    assert payload["errors"] == []
    assert payload["service"] == SERVICE_NAME
    assert payload["health_endpoint"] == HEALTH_ENDPOINT
    assert payload["phases"] == list(PHASES)
    assert payload["current_release"]["tree"]["sha256"]
    assert _entries(contract_dir) == [CONTRACT_ENTRY]
    _assert_honesty(payload)

    code, payload = _run_cli(["verify", "--contract-dir", str(contract_dir)],
                             capsys)
    assert code == 0
    assert payload["kind"] == "upgrade_contract_verify_result"
    assert payload["contract_valid"] is True
    assert payload["errors"] == []
    assert payload["current_release"]["tree"]["bytes"] > 0
    _assert_honesty(payload)


def test_cli_prepare_failure_is_nonzero_and_structured(tmp_path, capsys):
    current, candidate, bundle = _inputs(tmp_path)
    (Path(bundle) / "config.bin").unlink()
    contract_dir = tmp_path / "contract"
    code, payload = _run_cli([
        "prepare",
        "--current-release-dir", str(current),
        "--candidate-release-dir", str(candidate),
        "--backup-bundle", str(bundle),
        "--output-dir", str(contract_dir),
    ], capsys)
    assert code == 1
    assert payload["kind"] == "upgrade_contract_prepare_result"
    assert payload["contract_created"] is False
    assert payload["errors"]
    assert not contract_dir.exists()
    _assert_honesty(payload)


def test_cli_verify_failure_is_nonzero_and_structured(tmp_path, capsys):
    _result, _errors, contract_dir, *_rest = _prepare(tmp_path)
    document = _contract(contract_dir)
    document["actions_executed"] = True
    _rewrite_contract(contract_dir, document)
    code, payload = _run_cli(["verify", "--contract-dir", str(contract_dir)],
                             capsys)
    assert code == 1
    assert payload["kind"] == "upgrade_contract_verify_result"
    assert payload["contract_valid"] is False
    assert any("actions_executed must be False" in error
               for error in payload["errors"])
    _assert_honesty(payload)


def test_cli_verify_failure_when_tree_changed(tmp_path, capsys):
    _result, _errors, contract_dir, current, _candidate, _bundle = _prepare(
        tmp_path)
    _write(Path(current) / "scam" / "extra.py", "# extra\n")
    code, payload = _run_cli(["verify", "--contract-dir", str(contract_dir)],
                             capsys)
    assert code == 1
    assert payload["contract_valid"] is False
    assert payload["errors"]
    _assert_honesty(payload)


# ---------- 7b. 冻结 CLI 拼写：--backup-bundle 且关闭选项缩写 ----------

def test_cli_prepare_help_exposes_only_the_frozen_backup_bundle_option(capsys):
    """精确锁定 prepare 的 help/usage：绑定状态包的选项只以冻结拼写出现。"""
    with pytest.raises(SystemExit) as excinfo:
        upgrade_mod.main(["prepare", "--help"])
    assert excinfo.value.code == 0
    helped = _flat(capsys.readouterr().out)
    # usage 是否给必填选项加方括号/圆括号随 argparse 版本而异：去括号后锁词序列。
    unbracketed = _flat(helped.replace("[", " ").replace("]", " ")
                        .replace("(", " ").replace(")", " "))
    assert ("--current-release-dir DIR --candidate-release-dir DIR "
            "--backup-bundle DIR --output-dir DIR") in unbracketed
    assert FROZEN_BUNDLE_OPTION in helped
    assert "--backup-bundle-" not in helped
    assert "BACKUP_BUNDLE_DIR" not in helped


def test_cli_prepare_binds_the_bundle_through_the_frozen_spelling(tmp_path,
                                                                 capsys):
    """冻结拼写 --backup-bundle 的成功调用：合同只认传入的那个状态包。"""
    current, candidate, bundle = _inputs(tmp_path)
    contract_dir = tmp_path / "contract"
    code, payload = _run_cli([
        "prepare",
        "--current-release-dir", str(current),
        "--candidate-release-dir", str(candidate),
        FROZEN_BUNDLE_OPTION, str(bundle),
        "--output-dir", str(contract_dir),
    ], capsys)
    assert code == 0
    assert payload["errors"] == []
    assert payload["backup"]["bundle_valid"] is True
    assert payload["backup"]["bundle_dir"] == os.path.abspath(str(bundle))
    assert _entries(contract_dir) == [CONTRACT_ENTRY]
    _assert_honesty(payload)


@pytest.mark.parametrize("spelling", REJECTED_BUNDLE_SPELLINGS)
def test_cli_rejects_wrong_or_abbreviated_backup_bundle_spellings(
        tmp_path, capsys, spelling):
    """旧拼写与任何缩写拼写：解析期非零拒绝，且不产生任何副作用。"""
    current, candidate, bundle = _inputs(tmp_path)
    contract_dir = tmp_path / "contract"
    before = _all_fingerprints(current, candidate, bundle)
    with pytest.raises(SystemExit) as excinfo:
        upgrade_mod.main([
            "prepare",
            "--current-release-dir", str(current),
            "--candidate-release-dir", str(candidate),
            spelling, str(bundle),
            "--output-dir", str(contract_dir),
        ])
    assert excinfo.value.code != 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage:" in captured.err
    assert not contract_dir.exists()
    assert _all_fingerprints(current, candidate, bundle) == before


@pytest.mark.parametrize("spelling", ("--contract", "--contract-d"))
def test_cli_verify_rejects_abbreviated_contract_dir_spellings(
        tmp_path, capsys, spelling):
    """verify 同样关闭缩写：指到同一份合法合同也必须因拼写非零拒绝。"""
    _result, _errors, contract_dir, *_rest = _prepare(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        upgrade_mod.main(["verify", spelling, str(contract_dir)])
    assert excinfo.value.code != 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage:" in captured.err


def test_frozen_cli_spelling_is_identical_in_code_help_and_runbook():
    """代码（docstring/parser）、help 与 runbook 三处拼写一致且不再是旧拼写。"""
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert "--backup-bundle DIR" in source
    assert "--backup-bundle-dir" not in source
    assert source.count("allow_abbrev=False") >= 3
    runbook = RUNBOOK_PATH.read_text(encoding="utf-8")
    assert "--backup-bundle " in runbook
    assert "--backup-bundle-dir" not in runbook


# ---------- 8. 源码静态围栏 ----------

def test_module_keeps_zero_network_zero_subprocess_zero_service_control():
    source = MODULE_PATH.read_text(encoding="utf-8")
    for token in BANNED_SOURCE_TOKENS:
        assert token not in source, token
    assert "O_EXCL" in source and "O_CREAT" in source
    assert " open(" not in source, "内建 open() 不是本模块的写路径"


def test_module_has_exactly_one_delete_surface_and_one_create_site():
    source = MODULE_PATH.read_text(encoding="utf-8")
    cleanup = _function_source("_remove_created_dir")
    assert "os.unlink(" in cleanup and "os.rmdir(" in cleanup
    assert source.count("os.unlink(") == 1
    assert source.count("os.rmdir(") == 1
    assert source.count("os.mkdir(") == 1
    assert source.count("os.open(") == 2
    assert source.count("os.write(") == 1
    assert cleanup.index("if not created:") < cleanup.index("os.unlink(")


def test_module_write_surface_is_the_contract_entry_only():
    source = MODULE_PATH.read_text(encoding="utf-8")
    write_call = _function_source("_write_at")
    assert "EXCLUSIVE_WRITE_FLAGS" in write_call
    for token in ("release", "candidate", "RELEASE_"):
        assert token not in write_call
    destination = _function_source("_checked_destination")
    assert "CONTRACT_ENTRY_SET" in destination


def test_module_reuses_the_queue_o_verifier_read_only():
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert "import scam.linux_backup as backup" in source
    assert "backup.verify_bundle(" in source
    assert "backup.create_bundle(" not in source
    assert "backup.restore_bundle(" not in source


# ---------- 9. runbook 契约 ----------

def test_runbook_has_the_fixed_sections_in_order():
    text = RUNBOOK_PATH.read_text(encoding="utf-8")
    indexes = []
    for section in RUNBOOK_SECTIONS:
        marker = f"## {section}"
        assert marker in text, section
        indexes.append(text.index(marker))
    assert indexes == sorted(indexes)


def test_runbook_references_the_real_commands():
    text = RUNBOOK_PATH.read_text(encoding="utf-8")
    for command in RUNBOOK_COMMANDS:
        assert command in text, command


def test_runbook_marks_every_privileged_section_with_a_confirmation_point():
    sections = _sections()
    assert len(sections) >= len(RUNBOOK_SECTIONS)
    assert sum(body.count("人工确认点") for _heading, body in sections) >= 8
    for heading, body in sections:
        if "sudo " in body:
            assert "人工确认点" in body, heading


def test_runbook_states_target_layout_and_install_sh_limits():
    compact = re.sub(r"\s+", "", RUNBOOK_PATH.read_text(encoding="utf-8"))
    assert "目标运维布局" in compact
    assert "不是`deploy/install.sh`当前已实现的行为" in compact
    assert "不做原子指针切换" in compact
    assert "不做数据库迁移" in compact
    assert "不做在线DB/配置覆盖" in compact
    assert "不支持版本化" in compact
    assert "未验证" in compact
    assert "quality_gate_passed" in compact
    assert "release_gate_passed" in compact


def test_runbook_orders_backup_before_stop_and_code_before_state_restore():
    text = RUNBOOK_PATH.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", "", text)
    assert text.index("python -m scam.linux_backup verify") \
        < text.index("systemctl stop")
    assert text.index("## 7. 代码回退") < text.index("## 8. 条件性状态恢复")
    assert "明确执行过数据迁移" in compact
    assert "旧版本无法读取当前状态" in compact
    assert "先验证旧版本健康" in compact
    assert "不得绕过" in compact
    assert "恢复到全新staging目录" in compact


def test_runbook_checklist_references_resolve_to_real_sections():
    text = RUNBOOK_PATH.read_text(encoding="utf-8")
    for step in SUCCESS_CHECKLIST + ROLLBACK_CHECKLIST:
        reference = step["runbook"]
        assert reference.startswith("docs/linux-operations-runbook.md §")
        number, title = reference.split("§", 1)[1].split(" ", 1)
        assert f"## {number}. {title}" in text, reference
