"""LC-044 队列Q 原生Linux运维证据封存器测试（Windows 合成接线）。

按 LC-044 最小测试矩阵覆盖九类：非精确 Linux 的 `prepare` 在创建输出目录前
fail-closed 且 CLI 无绕过开关；六类有效合成输入生成固定 schema、输出只含
`manifest.json`、七类绑定摘要完整；host probe 伪 Linux/门禁置真、acceptance
坏 scope、浸泡损坏/未通过完整性、O/P 无效全部拒绝；ledger 未知或缺失字段、
步序变化、非整数 exit、漏步/重复步、危险路径、未引用/重复引用拒绝；证据根
软链接、非普通文件、路径逃逸、打开前换入、读取中变化、数量/单文件/总量超限
拒绝；失败只清理本次新建目录且全部输入哈希不变；seal 后任一输入或证据变化
`verify` 非零、未变化时只读验证零写入；源码静态断言无网络、无子进程、无服务
控制/安装/切换/恢复调用，写面仅固定 manifest、删除面仅本次新建目录；CLI
退出码、结构化错误与九个诚实字段完整，三个门禁字段恒为 null。

输入全部在 `tmp_path` 内由既有 O/P/浸泡模块真实生成，`prepare` 的原生平台
观测点由 `_platform_now` 注入。**证据等级仅为模块 + Windows 合成接线**：本
文件不证明原生 Linux 主机、真实 RTSP、systemd、24 小时浸泡、资源平台期、
识别质量、运维备份恢复或发布门禁通过；未预期的异常、链接与设备节点用仓库
既有确定性注入覆盖（不依赖本机是否有创建权限）。
"""

import ast
import hashlib
import inspect
import json
import os
import sqlite3
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import scam.linux_backup as backup
import scam.linux_ops_evidence as ops
import scam.linux_upgrade_contract as upgrade_contract
from scam.linux_soak import SCHEMA as SOAK_SCHEMA, EvidenceWriter

MANIFEST_NAME = "manifest.json"
ANCHOR_TIME = datetime(2026, 9, 21, 0, 0, 0, tzinfo=timezone.utc)


# ---------- 合成输入与通用工具 ----------

def _utc(offset_seconds=0):
    stamp = ANCHOR_TIME + timedelta(seconds=offset_seconds)
    return stamp.isoformat().replace("+00:00", "Z")


def _fake_stat(mode, size=0):
    """构造可注入的身份结果（不触及文件系统）。"""
    return os.stat_result((mode, 0, 0, 1, 0, 0, size, 0, 0, 0))


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def _remove_tree(path):
    """递归删除一个合成目录（测试自建，逐条删除，不用任何递归删除工具）。"""
    path = Path(path)
    for item in sorted(path.rglob("*"), reverse=True):
        if item.is_dir():
            item.rmdir()
        else:
            item.unlink()
    path.rmdir()


def _fingerprint(path):
    """文件/目录指纹：相对名 → (大小, SHA-256, mtime_ns)，用于证明零写入。"""
    path = Path(path)
    if not path.exists():
        return {}
    result = {}
    items = [path] if path.is_file() else sorted(path.rglob("*"))
    for item in items:
        if not item.is_file():
            continue
        info = os.lstat(str(item))
        name = item.name if path.is_file() else str(item.relative_to(path))
        result[name] = (info.st_size, _sha256(item), info.st_mtime_ns)
    return result


def _inputs_fingerprint(inputs):
    """七类输入 + 证据根 + 输出目录的合成指纹快照。"""
    return {name: _fingerprint(path) for name, path in (
        ("probe", inputs.probe), ("acceptance", inputs.acceptance),
        ("ledger", inputs.ledger), ("soak", inputs.soak),
        ("bundle", inputs.bundle), ("contract", inputs.contract),
        ("evidence", inputs.evidence), ("output", inputs.output))}


def _assert_honesty_fields(payload):
    """九个诚实字段固定值，三个门禁字段（含两个总门禁）恒为 null。"""
    assert payload["artifacts_bound"] is True
    assert payload["actions_executed"] is False
    assert payload["service_controlled"] is False
    assert payload["release_switched"] is False
    assert payload["operator_records_verified"] is False
    assert payload["native_linux_collected"] is True
    assert payload["host_gate_passed"] is None
    assert payload["quality_gate_passed"] is None
    assert payload["release_gate_passed"] is None


def _dump_json(path, document):
    _write(path, json.dumps(document, ensure_ascii=False,
                            indent=2).encode("utf-8") + b"\n")
    return Path(path)


def _evidence_payloads(artifact_count=1):
    """固定十步的证据文件（相对路径 → 内容）：每步独立，不构成重复引用。"""
    payloads = {}
    for step_id in ops.STEP_IDS:
        payloads[f"steps/{step_id}.stdout"] = f"[{step_id}] stdout\n".encode()
        payloads[f"steps/{step_id}.stderr"] = f"[{step_id}] stderr\n".encode()
        for index in range(artifact_count):
            name = f"artifacts/{step_id}.{index}.log"
            payloads[name] = f"[{step_id}] artifact {index}\n".encode()
    return payloads


def _make_evidence(root, payloads=None):
    payloads = _evidence_payloads() if payloads is None else dict(payloads)
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    for name, payload in payloads.items():
        _write(root / name, payload)
    return payloads


def _ledger_step(step_id, index, *, exit_code=0, operator_confirmed=True,
                 artifacts=1, **overrides):
    step = {"id": step_id,
            "started_at": _utc(index * 60),
            "finished_at": _utc(index * 60 + 30),
            "command": f"runbook step: {step_id}",
            "exit_code": exit_code,
            "stdout": f"steps/{step_id}.stdout",
            "stderr": f"steps/{step_id}.stderr",
            "artifacts": [f"artifacts/{step_id}.{item}.log"
                          for item in range(artifacts)],
            "operator_confirmed": operator_confirmed}
    step.update(overrides)
    return step


def _ledger_steps(**overrides):
    return [_ledger_step(step_id, index, **overrides)
            for index, step_id in enumerate(ops.STEP_IDS)]


def _ledger_document(steps=None, **overrides):
    document = {"schema": ops.LEDGER_SCHEMA, "kind": ops.LEDGER_KIND,
                "created_at": _utc(),
                "operator": "lab-operator",
                "note": "按 runbook 人工执行并保存的原始记录（工具未复核）",
                "steps": _ledger_steps() if steps is None else steps}
    document.update(overrides)
    return document


def _host_probe_document(**overrides):
    document = {
        "schema": ops.HOST_PROBE_SCHEMA, "kind": ops.HOST_PROBE_KIND,
        "observed_at": _utc(),
        "platform_system": "linux",
        "platform_platform": "Linux-6.8.0-45-generic-x86_64-with-glibc2.39",
        "python_version": "3.11.9", "python_executable": "/usr/bin/python3",
        "native_linux": True,
        "tools": [{"name": "ffmpeg", "available": True,
                   "path": "/usr/bin/ffmpeg"},
                  {"name": "ffprobe", "available": True,
                   "path": "/usr/bin/ffprobe"},
                  {"name": "systemctl", "available": True,
                   "path": "/usr/bin/systemctl"}],
        "host_gate_passed": None, "release_gate_passed": None,
        "unevaluated_gates": ["dependency_installation",
                             "systemd_service_runtime"],
        "host_gate_note": "只读环境基线；不代表任何验收结论"}
    document.update(overrides)
    return document


def _acceptance_document(**overrides):
    document = {
        "schema_version": 2, "scope": "single_camera_lab_probe",
        "release_gate_passed": None,
        "unevaluated_gates": ["dual_rtsp_sources", "soak_24h"],
        "camera": "front-door", "started_at": 1.0, "ended_at": 61.0,
        "duration_s": 60.0, "config_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "metrics": {"frames": 600, "stream_drops": 0},
        "latency": {"sample_count": 20, "p50_ms": 40.0, "passed": True},
        "gates": {"detector": True, "frame_processing": True}}
    document.update(overrides)
    return document


def _build_soak(directory, *, samples=3, request_seconds=86400.0,
                observed_seconds=86400.0,
                termination_reason="duration_reached"):
    """用真实 EvidenceWriter 生成对端格式的浸泡证据目录。"""
    manifest = {"schema": SOAK_SCHEMA, "kind": "manifest",
                "run_id": "00000000-0000-4000-8000-000000000000",
                "started_at": _utc(), "base_url": "http://127.0.0.1:8600",
                "duration_s": request_seconds, "interval_s": 10.0,
                "timeout_s": 5.0, "hostname": "lab-host",
                "platform": "Linux-6.8.0", "python": "3.11.9"}
    writer = EvidenceWriter(str(directory), manifest)
    for sequence in range(samples):
        writer.append({"schema": SOAK_SCHEMA, "kind": "sample",
                       "sequence": sequence, "observed_at": _utc(sequence),
                       "endpoints": {}, "cameras": {}})
    writer.finish({"requested_duration_s": request_seconds,
                   "observed_duration_s": observed_seconds,
                   "endpoint_successes": {}, "endpoint_failures": {},
                   "camera_state_observations": {},
                   "termination_reason": termination_reason,
                   "completed_requested_duration": (
                       termination_reason == "duration_reached"
                       and observed_seconds >= request_seconds),
                   "release_gate_passed": None})
    return Path(directory)


def _release_tree(root, name):
    _write(root / "pyproject.toml",
           f'[project]\nname = "scam-{name}"\nversion = "0.1.0"\n'.encode())
    _write(root / "scam" / "__init__.py", f'"""release {name}"""\n'.encode())
    _write(root / "scam" / "linux_nvr.py", f"# release {name}\n".encode())
    return Path(root)


def _build_bundle(root, *, rows=("cam-1", "cam-2")):
    """用真实 O 模块生成状态包（合成 SQLite + 配置原始字节）。"""
    sources = Path(root) / "sources"
    sources.mkdir(parents=True, exist_ok=True)
    database = sources / "cameras.sqlite3"
    connection = sqlite3.connect(str(database))
    try:
        connection.execute("CREATE TABLE cameras (id TEXT PRIMARY KEY)")
        connection.executemany("INSERT INTO cameras (id) VALUES (?)",
                               [(row,) for row in rows])
        connection.commit()
    finally:
        connection.close()
    config = _write(sources / "cameras.json", b'{"version": "0.3"}\n')
    bundle = Path(root) / "backup-bundle"
    result, errors = backup.create_bundle(str(database), str(config),
                                          str(bundle))
    assert errors == [], errors
    assert result["bundle_created"] is True
    return bundle


def _build_contract(root, bundle):
    """用真实 P 模块生成升级合同（两棵最小发布树 + 已绑定的状态包）。"""
    current = _release_tree(Path(root) / "release-current", "current")
    candidate = _release_tree(Path(root) / "release-candidate", "candidate")
    contract = Path(root) / "upgrade-contract"
    result, errors = upgrade_contract.prepare_contract(
        str(current), str(candidate), str(bundle), str(contract))
    assert errors == [], errors
    assert result["contract_created"] is True
    return contract


class _Inputs:
    """一次合成封存所需的全部路径：互不嵌套，全部落在同一个 tmp 根下。"""

    def __init__(self, root):
        self.root = Path(root)
        self.probe = self.root / "inputs" / "host-probe.json"
        self.acceptance = self.root / "inputs" / "acceptance-report.json"
        self.ledger = self.root / "inputs" / "operations-ledger.json"
        self.soak = self.root / "soak"
        self.bundle = self.root / "backup-bundle"
        self.contract = self.root / "upgrade-contract"
        self.evidence = self.root / "evidence"
        self.output = self.root / "ops-evidence"

    def build(self):
        _dump_json(self.probe, _host_probe_document())
        _dump_json(self.acceptance, _acceptance_document())
        _build_soak(self.soak)
        self.bundle = _build_bundle(self.root)
        self.contract = _build_contract(self.root, self.bundle)
        _make_evidence(self.evidence)
        _dump_json(self.ledger, _ledger_document())
        return self


def _arguments(inputs, **overrides):
    """CLI 参数（LC-044 冻结的八个选项 + verify 的一个选项）。"""
    arguments = {"--host-probe": str(inputs.probe),
                 "--acceptance-report": str(inputs.acceptance),
                 "--soak-dir": str(inputs.soak),
                 "--backup-bundle": str(inputs.bundle),
                 "--upgrade-contract": str(inputs.contract),
                 "--operations-ledger": str(inputs.ledger),
                 "--evidence-root": str(inputs.evidence),
                 "--output-dir": str(inputs.output)}
    arguments.update(overrides)
    flat = []
    for option, value in arguments.items():
        flat.extend([option, value])
    return flat


def _prepare(inputs, **overrides):
    arguments = {"host_probe": str(inputs.probe),
                 "acceptance_report": str(inputs.acceptance),
                 "soak_dir": str(inputs.soak),
                 "backup_bundle": str(inputs.bundle),
                 "upgrade_contract_dir": str(inputs.contract),
                 "operations_ledger": str(inputs.ledger),
                 "evidence_root": str(inputs.evidence),
                 "output_dir": str(inputs.output)}
    arguments.update(overrides)
    return ops.prepare_bundle(**arguments)


def _seal(inputs):
    result, errors = _prepare(inputs)
    assert errors == [], errors
    assert result["bundle_created"] is True
    return result


def _manifest_document(inputs):
    return json.loads((inputs.output / MANIFEST_NAME).read_text(
        encoding="utf-8"))


def _reject(inputs, message):
    """预备必须失败：输出未创建、结构化错误命中，且不留下任何目录。"""
    result, errors = _prepare(inputs)
    assert result["bundle_created"] is False
    assert not inputs.output.exists()
    assert result["output_dir_removed"] in (None, True)
    assert any(message in error for error in errors), errors
    return errors


@pytest.fixture
def inputs(tmp_path):
    return _Inputs(tmp_path).build()


@pytest.fixture
def linux(monkeypatch):
    """prepare 的原生平台观测点注入：测试不依赖真实 Linux 主机。"""
    monkeypatch.setattr(ops, "_platform_now", lambda: "linux")


# ---------- 组1：平台闸 fail-closed（CLI 无绕过开关） ----------

def test_platform_observation_point_reads_sys_platform():
    """生产平台观测点就是 ``sys.platform``，没有第二来源。"""
    assert ops._platform_now() == sys.platform


def test_prepare_signature_exposes_no_platform_override():
    """函数面也没有绕过开关：调用方无法把非 Linux 主机伪装成原生 Linux。"""
    parameters = inspect.signature(ops.prepare_bundle).parameters
    assert "platform" not in " ".join(parameters)
    assert list(parameters) == ["host_probe", "acceptance_report", "soak_dir",
                                "backup_bundle", "upgrade_contract_dir",
                                "operations_ledger", "evidence_root",
                                "output_dir"]


@pytest.mark.parametrize("platform", ["win32", "darwin", "linux-proxy",
                                      "linux2", "Linux", "java"])
def test_prepare_fails_closed_before_reading_any_input(inputs, monkeypatch,
                                                       platform):
    """非精确 Linux：不读输入、不创建输出目录，结构化失败。"""
    monkeypatch.setattr(ops, "_platform_now", lambda: platform)
    read = []
    real_stream = ops._stream_file

    def spy_stream(*arguments, **keywords):
        read.append(arguments[0])
        return real_stream(*arguments, **keywords)

    monkeypatch.setattr(ops, "_stream_file", spy_stream)
    result, errors = _prepare(inputs)

    assert any("platform" in error for error in errors), errors
    assert result["bundle_created"] is False
    assert result["output_dir_removed"] is None
    assert read == []
    assert not inputs.output.exists()
    _assert_honesty_fields(result)


def test_prepare_succeeds_with_injected_native_linux(inputs, linux):
    result = _seal(inputs)
    assert result["manifest"]["entry"] == MANIFEST_NAME
    _assert_honesty_fields(result)


def test_cli_prepare_matches_the_observed_platform(inputs, capsys):
    """CLI 只按采集平台观测点决定成败，没有任何额外开关。"""
    code = ops.main(["prepare"] + _arguments(inputs))
    payload = json.loads(capsys.readouterr().out)

    assert code == (0 if sys.platform == "linux" else 1)
    _assert_honesty_fields(payload)
    if sys.platform == "linux":
        assert payload["bundle_created"] is True
    else:
        assert payload["bundle_created"] is False
        assert not inputs.output.exists()


def test_cli_help_freezes_the_command_surface(inputs, capsys):
    with pytest.raises(SystemExit) as exit_info:
        ops.main(["prepare", "--help"])
    assert exit_info.value.code == 0
    printed = capsys.readouterr().out

    for option in ("--host-probe", "--acceptance-report", "--soak-dir",
                   "--backup-bundle", "--upgrade-contract",
                   "--operations-ledger", "--evidence-root", "--output-dir"):
        assert option in printed
    assert "platform" not in printed.lower()


def test_cli_refuses_unfrozen_option_spellings(inputs, linux):
    frozen = _arguments(inputs)
    frozen[frozen.index("--backup-bundle")] = "--backup-bundle-dir"
    with pytest.raises(SystemExit) as exit_info:
        ops.main(["prepare"] + frozen)
    assert exit_info.value.code == 2
    assert not inputs.output.exists()

    with pytest.raises(SystemExit) as exit_info:
        ops.main(["prepare", "--host"] + _arguments(inputs))
    assert exit_info.value.code == 2
    assert not inputs.output.exists()


# ---------- 组2：六类有效合成输入 → 固定 schema ----------

def test_seal_writes_only_the_fixed_manifest(inputs, linux):
    _seal(inputs)
    entries = sorted(item.name for item in inputs.output.iterdir())

    assert entries == [MANIFEST_NAME]
    document = _manifest_document(inputs)
    assert document["schema"] == "scam.linux-ops-evidence/v1"
    assert document["kind"] == "ops_evidence_bundle"
    assert document["tool"] == "scam.linux_ops_evidence"
    assert document["tool_version"] == ops.TOOL_VERSION
    assert document["note"] == ops.OPS_NOTE
    assert document["collected_on"]["platform_system"] == "linux"
    assert document["step_order"] == list(ops.STEP_IDS)
    assert set(document) == set(ops.MANIFEST_FIELDS)


def test_seal_binds_all_seven_inputs_by_digest(inputs, linux):
    _seal(inputs)
    document = _manifest_document(inputs)

    bindings = (("host_probe", inputs.probe), ("acceptance_report",
                                               inputs.acceptance),
                ("operations_ledger", inputs.ledger))
    for key, path in bindings:
        assert document[key]["path"] == os.path.abspath(str(path))
        assert document[key]["size"] == os.lstat(str(path)).st_size
        assert document[key]["sha256"] == _sha256(path)
    assert document["soak"]["path"] == os.path.abspath(str(inputs.soak))
    assert document["soak"]["integrity_passed"] is True
    assert document["soak"]["sample_count"] == 3
    assert document["soak"]["completed_requested_duration"] is True
    assert document["soak"]["manifest_sha256"] == _sha256(
        inputs.soak / "manifest.json")
    assert document["soak"]["samples_sha256"] == _sha256(
        inputs.soak / "samples.ndjson")
    assert document["soak"]["summary_sha256"] == _sha256(
        inputs.soak / "summary.json")
    assert document["backup_bundle"]["bundle_valid"] is True
    assert document["backup_bundle"]["manifest_sha256"] == _sha256(
        inputs.bundle / backup.MANIFEST_ENTRY)
    assert set(document["backup_bundle"]["contents"]) == {"database", "config"}
    assert document["upgrade_contract"]["contract_valid"] is True
    assert document["upgrade_contract"]["contract_sha256"] == _sha256(
        inputs.contract / upgrade_contract.CONTRACT_ENTRY)
    assert document["upgrade_contract"]["service"] \
        == upgrade_contract.SERVICE_NAME
    assert document["upgrade_contract"]["phases"] == list(
        upgrade_contract.PHASES)
    assert document["operations_ledger"]["operator"] == "lab-operator"
    assert document["operations_ledger"]["step_ids"] == list(ops.STEP_IDS)
    assert document["operations_ledger"]["reference_count"] == 30


def test_seal_records_fixed_step_order_and_evidence_digests(inputs, linux):
    _seal(inputs)
    document = _manifest_document(inputs)

    assert [step["id"] for step in document["steps"]] == list(ops.STEP_IDS)
    for index, step in enumerate(document["steps"]):
        step_id = ops.STEP_IDS[index]
        assert step["exit_code"] == 0
        assert step["operator_confirmed"] is True
        assert set(step) == set(ops.STEP_RECORD_FIELDS)
        for stream in ("stdout", "stderr"):
            record = step[stream]
            assert record["path"] == f"steps/{step_id}.{stream}"
            assert record["sha256"] == _sha256(
                inputs.evidence / record["path"])
        assert [item["path"] for item in step["artifacts"]] == [
            f"artifacts/{step_id}.0.log"]
    assert document["evidence_root"]["file_count"] == 30
    assert document["evidence_root"]["total_bytes"] == sum(
        item["size"] for item in document["evidence_root"]["files"])
    assert [item["path"] for item in document["evidence_root"]["files"]] \
        == sorted(item["path"]
                  for item in document["evidence_root"]["files"])


def test_seal_does_not_copy_or_rewrite_any_input(inputs, linux):
    before = _inputs_fingerprint(inputs)
    _seal(inputs)

    after = _inputs_fingerprint(inputs)
    for name in ("probe", "acceptance", "ledger", "soak", "bundle",
                 "contract", "evidence"):
        assert after[name] == before[name], name
    assert before["output"] == {}
    assert _fingerprint(inputs.output) != {}


def test_seal_honesty_fields_never_claim_gates(inputs, linux):
    _seal(inputs)
    document = _manifest_document(inputs)

    assert document["host_gate_passed"] is None
    assert document["quality_gate_passed"] is None
    assert document["release_gate_passed"] is None
    assert document["artifacts_bound"] is True
    assert document["actions_executed"] is False
    assert document["service_controlled"] is False
    assert document["release_switched"] is False
    assert document["operator_records_verified"] is False
    assert document["native_linux_collected"] is True


def test_frozen_contract_constants():
    assert ops.SCHEMA == "scam.linux-ops-evidence/v1"
    assert ops.LEDGER_SCHEMA == "scam.linux-ops-ledger/v1"
    assert ops.HOST_PROBE_SCHEMA == "scam.linux-host-probe/v1"
    assert ops.NATIVE_PLATFORM == "linux"
    assert ops.ACCEPTANCE_SCHEMA_VERSION == 2
    assert ops.ACCEPTANCE_SCOPE == "single_camera_lab_probe"
    assert ops.STEP_IDS == ("clean_install", "initial_start_health",
                            "restart_recovery", "backup_create_verify",
                            "upgrade_prepare_verify",
                            "candidate_switch_start_health",
                            "code_rollback_start_health",
                            "staging_restore_rehearsal",
                            "capacity_gate_rehearsal",
                            "privacy_network_audit")
    assert ops.STEP_FIELDS == ("id", "started_at", "finished_at", "command",
                               "exit_code", "stdout", "stderr", "artifacts",
                               "operator_confirmed")
    assert ops.MAX_EVIDENCE_FILES == 256
    assert ops.MAX_EVIDENCE_FILE_BYTES == 16 * 1024 * 1024
    assert ops.MAX_EVIDENCE_TOTAL_BYTES == 256 * 1024 * 1024
    assert dict(ops.HONESTY_FIELDS) == {
        "artifacts_bound": True, "actions_executed": False,
        "service_controlled": False, "release_switched": False,
        "operator_records_verified": False, "native_linux_collected": True,
        "host_gate_passed": None, "quality_gate_passed": None,
        "release_gate_passed": None}


def test_tool_version_matches_pyproject():
    text = (Path(__file__).resolve().parents[1]
            / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{ops.TOOL_VERSION}"' in text


# ---------- 组3：输入合同拒绝面 ----------

HOST_PROBE_MUTATIONS = (
    ("lookalike_platform_system",
     lambda doc: doc.update({"platform_system": "linux-proxy"}),
     "platform_system must be 'linux'"),
    ("native_flag_false", lambda doc: doc.update({"native_linux": False}),
     "native_linux must be true"),
    ("host_gate_forced_true",
     lambda doc: doc.update({"host_gate_passed": True}),
     "host_gate_passed must stay null"),
    ("release_gate_forced_true",
     lambda doc: doc.update({"release_gate_passed": True}),
     "release_gate_passed must stay null"),
    ("unknown_schema", lambda doc: doc.update({"schema": "scam.other/v1"}),
     "unknown schema"),
    ("unknown_kind", lambda doc: doc.update({"kind": "other"}),
     "kind must be"),
    ("tools_not_a_list", lambda doc: doc.update({"tools": "ffmpeg"}),
     "tools must be a JSON array"),
    ("tool_availability_not_boolean",
     lambda doc: doc["tools"][0].update({"available": "yes"}),
     "available must be a boolean"),
    ("python_version_missing", lambda doc: doc.pop("python_version"),
     "python_version must be a non-empty string"),
)


@pytest.mark.parametrize("name,mutate,message", HOST_PROBE_MUTATIONS,
                         ids=[item[0] for item in HOST_PROBE_MUTATIONS])
def test_host_probe_mutations_are_rejected(inputs, linux, name, mutate,
                                           message):
    document = _host_probe_document()
    mutate(document)
    _dump_json(inputs.probe, document)
    errors = _reject(inputs, message)
    assert errors, name


ACCEPTANCE_MUTATIONS = (
    ("unknown_schema_version",
     lambda doc: doc.update({"schema_version": 1}),
     "schema_version must be 2"),
    ("boolean_schema_version",
     lambda doc: doc.update({"schema_version": True}),
     "schema_version must be 2"),
    ("wrong_scope", lambda doc: doc.update({"scope": "dual_camera_release"}),
     "scope must be 'single_camera_lab_probe'"),
    ("release_gate_forced_true",
     lambda doc: doc.update({"release_gate_passed": True}),
     "release_gate_passed must stay null"),
    ("camera_missing", lambda doc: doc.pop("camera"),
     "camera must be a non-empty string"),
    ("duration_not_a_number", lambda doc: doc.update({"duration_s": "60"}),
     "duration_s must be a number"),
    ("broken_config_digest",
     lambda doc: doc.update({"config_sha256": "not-a-digest"}),
     "config_sha256 must be 64 hex chars or null"),
)


@pytest.mark.parametrize("name,mutate,message", ACCEPTANCE_MUTATIONS,
                         ids=[item[0] for item in ACCEPTANCE_MUTATIONS])
def test_acceptance_mutations_are_rejected(inputs, linux, name, mutate,
                                           message):
    document = _acceptance_document()
    mutate(document)
    _dump_json(inputs.acceptance, document)
    errors = _reject(inputs, message)
    assert errors, name


def test_tampered_soak_samples_are_rejected(inputs, linux):
    samples = inputs.soak / "samples.ndjson"
    lines = samples.read_text(encoding="utf-8").splitlines()
    samples.write_text("".join(line + "\n" for line in lines[:-1]),
                       encoding="utf-8")
    _reject(inputs, "soak: evidence package integrity did not verify")


def test_missing_soak_summary_is_rejected(inputs, linux):
    (inputs.soak / "summary.json").unlink()
    _reject(inputs, "soak: evidence package integrity did not verify")


def test_soak_without_the_completed_flag_is_rejected(inputs, linux):
    summary = json.loads((inputs.soak / "summary.json").read_text(
        encoding="utf-8"))
    summary.pop("completed_requested_duration")
    (inputs.soak / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False) + "\n", encoding="utf-8")
    _reject(inputs, "completed_requested_duration must be a boolean")


def test_soak_shorter_than_requested_is_recorded_not_gated(inputs, linux):
    """完整性通过 ≠ 24 小时完成：未跑满只如实记录 false，绝不改写任何门禁。"""
    _remove_tree(inputs.soak)
    _build_soak(inputs.soak, samples=2, request_seconds=86400.0,
                observed_seconds=60.0, termination_reason="operator_stop")
    result = _seal(inputs)
    document = _manifest_document(inputs)

    assert document["soak"]["integrity_passed"] is True
    assert document["soak"]["completed_requested_duration"] is False
    assert document["quality_gate_passed"] is None
    assert document["release_gate_passed"] is None
    assert result["quality_gate_passed"] is None
    assert result["release_gate_passed"] is None


def test_tampered_state_bundle_is_rejected(inputs, linux):
    _write(inputs.bundle / backup.CONFIG_ENTRY, b'{"tampered": true}\n')
    _reject(inputs, "backup_bundle: state bundle does not verify read-only")


def test_tampered_upgrade_contract_is_rejected(inputs, linux):
    _write(inputs.contract / upgrade_contract.CONTRACT_ENTRY,
           b'{"schema": "scam.linux-upgrade-contract/v1"}\n')
    _reject(inputs, "upgrade_contract: contract does not verify read-only")


def test_missing_inputs_are_rejected_without_creating_output(inputs, linux):
    inputs.probe.unlink()
    _reject(inputs, "host_probe: missing")
    assert not inputs.output.exists()

    inputs.acceptance.unlink()
    _reject(inputs, "acceptance_report: missing")
    assert not inputs.output.exists()


# ---------- 组4：ledger 合同拒绝面 ----------

def _swap_first_two_steps(document):
    steps = document["steps"]
    steps[0], steps[1] = steps[1], steps[0]


LEDGER_MUTATIONS = (
    ("unknown_root_field", lambda doc: doc.update({"extra": "x"}),
     "unknown root fields"),
    ("missing_root_field", lambda doc: doc.pop("operator"),
     "missing field operator"),
    ("unknown_schema", lambda doc: doc.update({"schema": "scam.other/v1"}),
     "unknown schema"),
    ("unknown_kind", lambda doc: doc.update({"kind": "other"}),
     "kind must be"),
    ("non_utc_created_at",
     lambda doc: doc.update({"created_at": "2026-09-21T00:00:00+08:00"}),
     "created_at must be a UTC Z timestamp"),
    ("empty_operator", lambda doc: doc.update({"operator": "   "}),
     "operator must be a non-empty string"),
    ("unknown_step_field",
     lambda doc: doc["steps"][3].update({"note": "extra"}),
     "unknown fields note"),
    ("missing_step_field", lambda doc: doc["steps"][4].pop("stderr"),
     "missing field stderr"),
    ("reordered_steps", _swap_first_two_steps, "id must be"),
    ("missing_step", lambda doc: doc["steps"].pop(),
     "exactly 10 entries"),
    ("extra_step", lambda doc: doc["steps"].append(dict(doc["steps"][-1])),
     "exactly 10 entries"),
    ("duplicated_step_id",
     lambda doc: doc["steps"][5].update({"id": doc["steps"][4]["id"]}),
     "id must be"),
    ("renamed_step",
     lambda doc: doc["steps"][6].update({"id": "custom_rollback"}),
     "id must be"),
    ("non_integer_exit_code",
     lambda doc: doc["steps"][0].update({"exit_code": "0"}),
     "exit_code must be an integer"),
    ("boolean_exit_code",
     lambda doc: doc["steps"][1].update({"exit_code": True}),
     "exit_code must be an integer"),
    ("non_boolean_confirmation",
     lambda doc: doc["steps"][2].update({"operator_confirmed": "yes"}),
     "operator_confirmed must be a boolean"),
    ("command_not_a_string",
     lambda doc: doc["steps"][9].update({"command": 7}),
     "command must be a non-empty string"),
    ("escaping_stdout",
     lambda doc: doc["steps"][0].update({"stdout": "../escape.txt"}),
     "stdout must be a safe relative POSIX path"),
    ("absolute_artifact",
     lambda doc: doc["steps"][0].update({"artifacts": ["/etc/passwd"]}),
     "artifacts[0] must be a safe relative POSIX path"),
    ("backslash_artifact",
     lambda doc: doc["steps"][1].update({"artifacts": ["a\\b.txt"]}),
     "artifacts[0] must be a safe relative POSIX path"),
    ("drive_letter_artifact",
     lambda doc: doc["steps"][2].update({"artifacts": ["C:/x.txt"]}),
     "artifacts[0] must be a safe relative POSIX path"),
    ("empty_segment_artifact",
     lambda doc: doc["steps"][3].update({"artifacts": ["a//b.txt"]}),
     "artifacts[0] must be a safe relative POSIX path"),
    ("dot_segment_artifact",
     lambda doc: doc["steps"][4].update({"artifacts": ["a/./b.txt"]}),
     "artifacts[0] must be a safe relative POSIX path"),
    ("artifacts_not_a_list",
     lambda doc: doc["steps"][6].update({"artifacts": "steps/x.stdout"}),
     "artifacts must be a JSON array"),
    ("non_z_started_at",
     lambda doc: doc["steps"][7].update({"started_at": "2026-09-21 00:00:00"}),
     "started_at must be a UTC Z timestamp"),
    ("finished_before_started",
     lambda doc: doc["steps"][8].update({"started_at": _utc(600),
                                         "finished_at": _utc(300)}),
     "finished_at must not precede started_at"),
    ("duplicate_reference",
     lambda doc: doc["steps"][1].update({"stdout": doc["steps"][0]["stdout"]}),
     "duplicate evidence reference"),
)


@pytest.mark.parametrize("name,mutate,message", LEDGER_MUTATIONS,
                         ids=[item[0] for item in LEDGER_MUTATIONS])
def test_ledger_mutations_are_rejected(inputs, linux, name, mutate, message):
    document = _ledger_document()
    mutate(document)
    _dump_json(inputs.ledger, document)
    errors = _reject(inputs, message)
    assert errors, name


def test_unreferenced_evidence_file_is_rejected(inputs, linux):
    _write(inputs.evidence / "stray.txt", b"not referenced\n")
    _reject(inputs, "unreferenced file: stray.txt")


def test_missing_referenced_evidence_is_rejected(inputs, linux):
    (inputs.evidence / "steps" / "clean_install.stdout").unlink()
    _reject(inputs, "referenced file missing: steps/clean_install.stdout")


def test_nested_inputs_are_rejected(inputs, linux):
    nested = inputs.soak / "evidence"
    nested.mkdir()
    result, errors = _prepare(inputs, evidence_root=str(nested))

    assert any("must not be inside soak_dir" in error for error in errors)
    assert result["bundle_created"] is False
    assert not inputs.output.exists()


def test_output_inside_an_input_root_is_rejected(inputs, linux):
    result, errors = _prepare(inputs, output_dir=str(inputs.evidence / "out"))

    assert any("output_dir: must not be evidence_root or inside it" in error
               for error in errors), errors
    assert result["bundle_created"] is False
    assert not inputs.output.exists()


def test_duplicate_input_path_is_rejected(inputs, linux):
    result, errors = _prepare(inputs, evidence_root=str(inputs.soak))

    assert any("must not be the same path as" in error for error in errors)
    assert result["bundle_created"] is False
    assert not inputs.output.exists()


# ---------- 组5：证据根安全边界 ----------

def _fake_symlink_lstat(target, *, after_calls=0):
    """确定性注入：把 `target` 报告为软链接（本机有无创建权限都成立）。"""
    real_lstat = ops._lstat_now
    calls = {"count": 0}

    def fake_lstat(path):
        if os.path.abspath(str(path)) == os.path.abspath(str(target)):
            calls["count"] += 1
            if calls["count"] > after_calls:
                return _fake_stat(stat.S_IFLNK | 0o777)
        return real_lstat(path)

    return fake_lstat


class _FakeEntry:
    """注入用的目录条目：本机无法创建设备/FIFO 时证明拒绝分支成立。"""

    def __init__(self, name, path):
        self.name = name
        self.path = path

    def is_symlink(self):
        return False

    def is_dir(self, follow_symlinks=False):
        return False

    def is_file(self, follow_symlinks=False):
        return False


class _FakeScandir:
    def __init__(self, entries):
        self._entries = entries

    def __enter__(self):
        return iter(self._entries)

    def __exit__(self, *exc_info):
        return False


def test_evidence_root_symlink_is_rejected(inputs, linux, monkeypatch):
    """扫描阶段发现证据根是软链接：拒绝且只回收本次新建的目录。"""
    monkeypatch.setattr(ops, "_lstat_now",
                        _fake_symlink_lstat(inputs.evidence, after_calls=1))
    result, errors = _prepare(inputs)

    assert any("evidence_root: symlink is not accepted" in error
               for error in errors), errors
    assert result["bundle_created"] is False
    assert result["output_dir_removed"] is True
    assert not inputs.output.exists()


def test_evidence_entry_symlink_is_rejected(inputs, linux, monkeypatch):
    target = inputs.evidence / "steps" / "clean_install.stdout"
    monkeypatch.setattr(ops, "_lstat_now", _fake_symlink_lstat(target))
    _reject(inputs, "symlink is not accepted")


def test_real_symlink_referenced_as_evidence_is_rejected(inputs, linux):
    """真实软链接（本机不允许创建时跳过；确定性分支见上一条）。"""
    outside = _write(inputs.root / "outside.txt", b"outside evidence\n")
    link = inputs.evidence / "linked.stdout"
    try:
        os.symlink(str(outside), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接")

    document = _ledger_document()
    document["steps"][0]["stdout"] = "linked.stdout"
    _dump_json(inputs.ledger, document)
    _reject(inputs, "linked.stdout: symlink is not accepted")


def test_non_regular_evidence_entry_is_rejected(inputs, linux, monkeypatch):
    """设备/FIFO 类非常规条目：本机无法创建，用确定性 scandir 注入证明。"""
    root = os.path.abspath(str(inputs.evidence))
    real_scandir = os.scandir

    def fake_scandir(path):
        if os.path.abspath(str(path)) == root:
            return _FakeScandir([_FakeEntry("fifo",
                                            os.path.join(root, "fifo"))])
        return real_scandir(path)

    monkeypatch.setattr(ops.os, "scandir", fake_scandir)
    _reject(inputs, "not a regular file")


def test_evidence_swapped_between_check_and_open_is_rejected(inputs, linux,
                                                             monkeypatch):
    """lstat 与 open 之间换入：句柄身份与路径快照不一致，立即拒绝。"""
    target = os.path.abspath(str(inputs.evidence / "steps"
                                 / "clean_install.stdout"))
    decoy = _write(inputs.root / "decoy.stdout", b"decoy bytes\n")
    real_open = ops._open_readonly

    def fake_open(path):
        if os.path.abspath(str(path)) == target:
            return real_open(str(decoy))
        return real_open(path)

    monkeypatch.setattr(ops, "_open_readonly", fake_open)
    _reject(inputs, "identity changed between check and open")


def test_evidence_changed_while_reading_is_rejected(inputs, linux,
                                                    monkeypatch):
    """读取中变化：同一句柄的前后快照必须一致（第 2 次采样即读后复核）。"""
    real_fstat = ops._fstat_now
    calls = {"count": 0}

    def fake_fstat(fd):
        info = real_fstat(fd)
        calls["count"] += 1
        if calls["count"] % 2 == 0:
            return _fake_stat(info.st_mode, size=info.st_size + 1)
        return info

    monkeypatch.setattr(ops, "_fstat_now", fake_fstat)
    _reject(inputs, "changed while reading")


def test_evidence_file_count_limit_is_enforced(inputs, linux, monkeypatch):
    monkeypatch.setattr(ops, "MAX_EVIDENCE_FILES", 3)
    _reject(inputs, "more than 3 regular files")


def test_single_evidence_file_limit_is_enforced(inputs, linux, monkeypatch):
    monkeypatch.setattr(ops, "MAX_EVIDENCE_FILE_BYTES", 8)
    _reject(inputs, "exceeds the 8 byte limit")


def test_evidence_total_bytes_limit_is_enforced(inputs, linux, monkeypatch):
    monkeypatch.setattr(ops, "MAX_EVIDENCE_TOTAL_BYTES", 16)
    _reject(inputs, "byte total limit")


# ---------- 组6：失败只清理本次新建目录 ----------

def test_existing_output_directory_is_never_touched(inputs, linux):
    """输出已存在即拒绝：既有目录与既有 manifest 既不覆盖也不删除。"""
    inputs.output.mkdir()
    kept = _write(inputs.output / MANIFEST_NAME, b"previous run\n")
    before = _fingerprint(inputs.output)
    result, errors = _prepare(inputs)

    assert any("already exists" in error for error in errors), errors
    assert result["bundle_created"] is False
    assert result["output_dir_removed"] is None
    assert _fingerprint(inputs.output) == before
    assert kept.read_bytes() == b"previous run\n"


def test_failed_binding_removes_only_the_new_directory(inputs, linux):
    _write(inputs.evidence / "stray.txt", b"stray\n")
    before = _inputs_fingerprint(inputs)
    result, errors = _prepare(inputs)

    assert any("unreferenced file" in error for error in errors), errors
    assert result["bundle_created"] is False
    assert result["output_dir_removed"] is True
    assert not inputs.output.exists()
    after = _inputs_fingerprint(inputs)
    for name in ("probe", "acceptance", "ledger", "soak", "bundle",
                 "contract", "evidence"):
        assert after[name] == before[name], name


def test_invalid_state_bundle_failure_keeps_all_inputs_unchanged(inputs,
                                                                 linux):
    _write(inputs.bundle / backup.CONFIG_ENTRY, b'{"tampered": true}\n')
    before = _inputs_fingerprint(inputs)
    result, errors = _prepare(inputs)

    assert any("backup_bundle" in error for error in errors), errors
    assert result["output_dir_removed"] is True
    assert not inputs.output.exists()
    after = _inputs_fingerprint(inputs)
    for name in ("probe", "acceptance", "ledger", "soak", "bundle",
                 "contract", "evidence"):
        assert after[name] == before[name], name


def test_manifest_write_failure_leaves_no_partial_bundle(inputs, linux,
                                                         monkeypatch):
    def _boom(path, payload):
        raise OSError("injected write failure")

    monkeypatch.setattr(ops, "_write_manifest_bytes", _boom)
    result, errors = _prepare(inputs)

    assert any("manifest.json: cannot write" in error for error in errors)
    assert result["bundle_created"] is False
    assert result["output_dir_removed"] is True
    assert not inputs.output.exists()


def test_unexpected_failure_is_structured_and_cleans_up(inputs, linux,
                                                        monkeypatch, capsys):
    before = _inputs_fingerprint(inputs)

    def _boom(path, payload):
        raise RuntimeError("injected failure")

    monkeypatch.setattr(ops, "_write_manifest_bytes", _boom)
    code = ops.main(["prepare"] + _arguments(inputs))
    payload = json.loads(capsys.readouterr().err)

    assert code == 1
    assert payload["bundle_created"] is False
    assert "RuntimeError" in payload["error"]
    assert not inputs.output.exists()
    _assert_honesty_fields(payload)
    after = _inputs_fingerprint(inputs)
    for name in ("probe", "acceptance", "ledger", "soak", "bundle",
                 "contract", "evidence"):
        assert after[name] == before[name], name


# ---------- 组7：verify 只读复核与变化检测 ----------

def test_verify_is_read_only_and_leaves_inputs_untouched(inputs, linux):
    _seal(inputs)
    before_inputs = _inputs_fingerprint(inputs)
    before_bundle = _fingerprint(inputs.output)
    result, errors = ops.verify_bundle(str(inputs.output))

    assert errors == []
    assert result["bundle_valid"] is True
    assert result["manifest"]["entry"] == MANIFEST_NAME
    assert result["manifest"]["sha256"] == _sha256(
        inputs.output / MANIFEST_NAME)
    assert result["step_order"] == list(ops.STEP_IDS)
    _assert_honesty_fields(result)
    assert _fingerprint(inputs.output) == before_bundle
    after_inputs = _inputs_fingerprint(inputs)
    for name in ("probe", "acceptance", "ledger", "soak", "bundle",
                 "contract", "evidence"):
        assert after_inputs[name] == before_inputs[name], name


def test_verify_does_not_require_a_native_linux_host(inputs, monkeypatch):
    """采集平台只以 manifest 的 collected_on 为准；复核机不必是 Linux。"""
    monkeypatch.setattr(ops, "_platform_now", lambda: "linux")
    _seal(inputs)
    monkeypatch.setattr(ops, "_platform_now", lambda: "win32")

    result, errors = ops.verify_bundle(str(inputs.output))

    assert errors == []
    assert result["bundle_valid"] is True
    assert _manifest_document(inputs)["collected_on"]["platform_system"] \
        == "linux"


def _tamper_host_probe(inputs):
    return _dump_json(inputs.probe,
                      _host_probe_document(python_version="3.12.7"))


def _tamper_acceptance(inputs):
    return _dump_json(inputs.acceptance,
                      _acceptance_document(duration_s=61.0))


def _tamper_soak_samples(inputs):
    samples = inputs.soak / "samples.ndjson"
    _write(samples, samples.read_bytes() + b"{}\n")
    return samples


def _tamper_soak_summary(inputs):
    summary = inputs.soak / "summary.json"
    document = json.loads(summary.read_text(encoding="utf-8"))
    document["observed_duration_s"] = 1.0
    return _dump_json(summary, document)


def _tamper_state_bundle(inputs):
    return _write(inputs.bundle / backup.CONFIG_ENTRY, b'{"tampered": 1}\n')


def _tamper_upgrade_contract(inputs):
    return _write(inputs.contract / upgrade_contract.CONTRACT_ENTRY,
                  b'{"schema": "scam.linux-upgrade-contract/v1"}\n')


def _tamper_ledger(inputs):
    document = _ledger_document()
    document["steps"][0]["command"] = "a different command"
    return _dump_json(inputs.ledger, document)


def _tamper_evidence_file(inputs):
    return _write(inputs.evidence / "steps" / "restart_recovery.stdout",
                  b"replaced evidence bytes\n")


VERIFY_TAMPER = (
    ("host_probe", _tamper_host_probe, "host_probe"),
    ("acceptance_report", _tamper_acceptance, "acceptance_report"),
    ("soak_samples", _tamper_soak_samples, "soak"),
    ("soak_summary", _tamper_soak_summary,
     "no longer matches the sealed evidence"),
    ("state_bundle", _tamper_state_bundle, "backup_bundle"),
    ("upgrade_contract", _tamper_upgrade_contract, "upgrade_contract"),
    ("operations_ledger", _tamper_ledger, "operations_ledger"),
    ("evidence_file", _tamper_evidence_file,
     "no longer matches the sealed evidence"),
)


@pytest.mark.parametrize("name,tamper,message", VERIFY_TAMPER,
                         ids=[item[0] for item in VERIFY_TAMPER])
def test_verify_rejects_any_changed_input(inputs, linux, name, tamper,
                                          message):
    _seal(inputs)
    tamper(inputs)
    before = _fingerprint(inputs.output)
    result, errors = ops.verify_bundle(str(inputs.output))
    joined = " ".join(errors)

    assert result["bundle_valid"] is False
    assert errors, name
    assert message in joined, joined
    assert _fingerprint(inputs.output) == before      # 复核零写入


MANIFEST_TAMPER = (
    ("unknown_root_field", lambda doc: doc.update({"extra": 1}),
     "unknown root fields"),
    ("missing_root_field", lambda doc: doc.pop("evidence_root"),
     "missing field evidence_root"),
    ("forced_host_gate", lambda doc: doc.update({"host_gate_passed": True}),
     "host_gate_passed must be None"),
    ("forced_quality_gate",
     lambda doc: doc.update({"quality_gate_passed": True}),
     "quality_gate_passed must be None"),
    ("forced_release_gate",
     lambda doc: doc.update({"release_gate_passed": True}),
     "release_gate_passed must be None"),
    ("forced_actions", lambda doc: doc.update({"actions_executed": True}),
     "actions_executed must be False"),
    ("dropped_artifact_binding",
     lambda doc: doc.update({"artifacts_bound": False}),
     "artifacts_bound must be True"),
    ("unknown_tool_version",
     lambda doc: doc.update({"tool_version": "9.9.9"}),
     "tool_version must be"),
    ("custom_note", lambda doc: doc.update({"note": "自定义说明"}),
     "note must be the fixed module note"),
    ("reordered_step_order",
     lambda doc: doc.update({"step_order": list(reversed(ops.STEP_IDS))}),
     "step_order must be the fixed ten step order"),
    ("window_collection_platform",
     lambda doc: doc["collected_on"].update({"platform_system": "win32"}),
     "platform_system must be 'linux'"),
    ("escaped_recorded_root",
     lambda doc: doc["evidence_root"].update({"path": "../escape"}),
     "evidence_root.path must be a safe absolute path"),
    ("relative_recorded_root",
     lambda doc: doc["operations_ledger"].update(
         {"path": "inputs/ledger.json"}),
     "operations_ledger.path must be a safe absolute path"),
    ("steps_not_an_array",
     lambda doc: doc.update({"steps": {"id": "clean_install"}}),
     "steps must be a JSON array"),
    ("escaped_recorded_evidence_path",
     lambda doc: doc["steps"][0]["stdout"].update({"path": "../escape.txt"}),
     "stdout.path must be a safe relative POSIX path"),
    ("unknown_evidence_record_field",
     lambda doc: doc["steps"][1]["stderr"].update({"extra": "x"}),
     "unknown fields extra"),
    ("changed_evidence_digest",
     lambda doc: doc["steps"][2]["stdout"].update({"sha256": "0" * 64}),
     "no longer matches the sealed evidence"),
    ("changed_soak_digest",
     lambda doc: doc["soak"].update({"samples_sha256": "0" * 64}),
     "no longer matches the sealed evidence"),
)


@pytest.mark.parametrize("name,mutate,message", MANIFEST_TAMPER,
                         ids=[item[0] for item in MANIFEST_TAMPER])
def test_verify_rejects_tampered_manifest(inputs, linux, name, mutate,
                                          message):
    _seal(inputs)
    document = _manifest_document(inputs)
    mutate(document)
    _dump_json(inputs.output / MANIFEST_NAME, document)
    result, errors = ops.verify_bundle(str(inputs.output))
    joined = " ".join(errors)

    assert result["bundle_valid"] is False
    assert errors, name
    assert message in joined, joined


def test_verify_rejects_extra_output_entries(inputs, linux):
    _seal(inputs)
    _write(inputs.output / "extra.txt", b"extra\n")
    result, errors = ops.verify_bundle(str(inputs.output))

    assert result["bundle_valid"] is False
    assert "unexpected path" in " ".join(errors)


def test_verify_rejects_missing_manifest(inputs, linux):
    _seal(inputs)
    (inputs.output / MANIFEST_NAME).unlink()
    result, errors = ops.verify_bundle(str(inputs.output))

    assert result["bundle_valid"] is False
    assert "manifest.json: missing" in " ".join(errors)


def test_verify_rejects_bundle_root_symlink_without_traversal(inputs, linux,
                                                              monkeypatch):
    _seal(inputs)
    traversed = []

    def fail_if_traversed(*arguments, **keywords):
        traversed.append(True)
        return {}

    monkeypatch.setattr(ops, "_scan_bundle_entries", fail_if_traversed)
    monkeypatch.setattr(ops, "_lstat_now", _fake_symlink_lstat(inputs.output))
    result, errors = ops.verify_bundle(str(inputs.output))

    assert result["bundle_valid"] is False
    assert "bundle_dir: symlink is not accepted" in " ".join(errors)
    assert traversed == []


# ---------- 组8：源码静态断言（零外部动作，写/删面固定） ----------

FORBIDDEN_MODULES = frozenset((
    "subprocess", "socket", "shutil", "urllib", "http", "requests", "ctypes",
    "paramiko", "ftplib", "telnetlib", "asyncio"))
FORBIDDEN_CALL_NAMES = frozenset((
    "system", "popen", "Popen", "run", "call", "check_call", "check_output",
    "rmtree", "remove", "rename", "replace", "chmod", "chown", "makedirs",
    "mknod", "symlink", "link", "truncate", "utime", "chdir", "kill", "fork",
    "spawn", "execv", "execve", "eval", "exec", "compile", "__import__",
    "open", "input"))
# ``_module_calls()`` 收集的 ``os.<属性>`` 键是**去掉 ``os.`` 前缀**的属性路径，
# 而 ``FORBIDDEN_CALL_NAMES`` 里的 ``open`` 针对的是 builtins 裸调用。限定名
# ``os.open`` 是 LC-044 要求保留的唯一安全读取入口（``O_RDONLY|O_NOFOLLOW``）与
# 独占写入口，其完整白名单由 ``ALLOWED_OS_CALLS`` 精确锁定、调用点由组8 的写/删面
# 测试锁定，因此**不**参与裸调用黑名单的误分类；这里显式列出该豁免名。
QUALIFIED_CALL_EXEMPTIONS = frozenset(("open",))
MUTATING_OS_CALLS = {"mkdir": 1, "open": 2, "fdopen": 1, "unlink": 1,
                     "rmdir": 1, "fsync": 1}
ALLOWED_OS_CALLS = frozenset((
    "lstat", "fstat", "open", "fdopen", "read", "close", "fsync", "mkdir",
    "rmdir", "unlink", "scandir", "path.abspath", "path.isabs", "path.join",
    "path.normcase", "path.samestat"))
FORBIDDEN_SOURCE_TOKENS = ("subprocess", "socket", "urllib", "requests",
                           "shutil", "rmtree", "systemctl", "sudo", "curl",
                           "wget", "popen", "shell", "http://", "https://",
                           "os.system")


def _module_source():
    return Path(ops.__file__).read_text(encoding="utf-8")


def _enclosing_function(node, parents):
    current = parents.get(node)
    while current is not None:
        if isinstance(current, ast.FunctionDef):
            return current.name
        current = parents.get(current)
    return "<module>"


def _module_calls():
    """返回 (``os.<属性>`` 调用 → 所在函数列表, 裸函数名调用集合)。"""
    tree = ast.parse(_module_source())
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    os_calls = {}
    plain_calls = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            attributes = []
            current = func
            while isinstance(current, ast.Attribute):
                attributes.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name) and current.id == "os":
                name = ".".join(reversed(attributes))
                os_calls.setdefault(name, []).append(
                    _enclosing_function(node, parents))
        elif isinstance(func, ast.Name):
            plain_calls.add(func.id)
    return os_calls, plain_calls


def test_module_imports_only_read_only_standard_library():
    tree = ast.parse(_module_source())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert imported & FORBIDDEN_MODULES == set()
    assert imported == {"__future__", "argparse", "hashlib", "json", "os",
                        "stat", "sys", "datetime", "scam"}


def test_module_has_no_process_service_or_install_call_sites():
    os_calls, plain_calls = _module_calls()

    # 裸调用（builtins 与裸函数名）里不得出现任何危险动作名——``open`` 也在其中：
    # 模块没有任何 builtins ``open`` 调用点。
    assert plain_calls & FORBIDDEN_CALL_NAMES == set()
    assert "open" not in plain_calls
    # 限定 ``os.<属性>`` 调用被精确白名单锁定：任何白名单之外的调用都已失败，
    # 因此限定名不需要、也不允许再被裸调用黑名单按前缀名误分类。
    assert set(os_calls) == ALLOWED_OS_CALLS
    assert set(os_calls["open"]) == {"_open_readonly", "_open_exclusive"}
    # 除显式豁免的限定 ``os.open``（安全只读 + 独占写）外，限定调用里同样不得
    # 残留任何危险动作名：``os.system``/``os.remove``/``os.rename`` 等一律缺席。
    assert set(os_calls) & (FORBIDDEN_CALL_NAMES
                            - QUALIFIED_CALL_EXEMPTIONS) == set()


def test_module_write_and_delete_surface_is_exactly_the_fixed_manifest():
    os_calls, _ = _module_calls()

    for name, count in MUTATING_OS_CALLS.items():
        assert len(os_calls.get(name, [])) == count, name
    # 写面：独占创建唯一 manifest；读面：只读打开 + 流式 read/close。
    assert set(os_calls["open"]) == {"_open_readonly", "_open_exclusive"}
    assert os_calls["fdopen"] == ["_write_manifest_bytes"]
    assert os_calls["fsync"] == ["_write_manifest_bytes"]
    assert os_calls["read"] == ["_stream_file"]
    assert set(os_calls["close"]) == {"_stream_file", "_write_manifest_bytes"}
    # 删除面：只回收本次新建目录里的固定 manifest 与空目录本身。
    assert os_calls["mkdir"] == ["_create_output_dir"]
    assert os_calls["unlink"] == ["_cleanup_output_dir"]
    assert os_calls["rmdir"] == ["_cleanup_output_dir"]
    assert os_calls["lstat"] == ["_lstat_now"]
    assert os_calls["fstat"] == ["_fstat_now"]


def test_module_source_has_no_network_or_privilege_tokens():
    source = _module_source()
    for token in FORBIDDEN_SOURCE_TOKENS:
        assert token not in source, token


def test_module_has_no_recursive_delete_or_state_restore_entry():
    source = _module_source()
    for token in ("rmtree", "restore_bundle", "materialise", "materialize",
                  "chmod", "chown"):
        assert token not in source, token


# ---------- 组9：CLI 退出码、结构化错误与诚实字段 ----------

def test_cli_prepare_and_verify_exit_codes(inputs, linux, capsys):
    code = ops.main(["prepare"] + _arguments(inputs))
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["bundle_created"] is True
    assert payload["errors"] == []
    _assert_honesty_fields(payload)

    code = ops.main(["verify", "--bundle-dir", str(inputs.output)])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["bundle_valid"] is True
    _assert_honesty_fields(payload)


def test_cli_prepare_failure_returns_structured_error(inputs, linux, capsys):
    _dump_json(inputs.ledger, _ledger_document(steps=[]))
    code = ops.main(["prepare"] + _arguments(inputs))
    payload = json.loads(capsys.readouterr().out)

    assert code == 1
    assert payload["bundle_created"] is False
    assert payload["output_dir_removed"] in (None, True)
    assert payload["errors"]
    assert all(isinstance(error, str) for error in payload["errors"])
    assert not inputs.output.exists()
    _assert_honesty_fields(payload)


def test_cli_verify_failure_returns_structured_error(inputs, linux, capsys):
    _seal(inputs)
    _write(inputs.evidence / "stray.txt", b"stray\n")
    code = ops.main(["verify", "--bundle-dir", str(inputs.output)])
    payload = json.loads(capsys.readouterr().out)

    assert code == 1
    assert payload["bundle_valid"] is False
    assert payload["errors"]
    _assert_honesty_fields(payload)


def test_cli_never_claims_gates_even_after_a_successful_seal(inputs, linux,
                                                             capsys):
    ops.main(["prepare"] + _arguments(inputs))
    prepared = json.loads(capsys.readouterr().out)
    ops.main(["verify", "--bundle-dir", str(inputs.output)])
    verified = json.loads(capsys.readouterr().out)

    for payload in (prepared, verified):
        assert payload["host_gate_passed"] is None
        assert payload["quality_gate_passed"] is None
        assert payload["release_gate_passed"] is None
        assert payload["operator_records_verified"] is False
        assert payload["actions_executed"] is False
        assert payload["service_controlled"] is False
        assert payload["release_switched"] is False

