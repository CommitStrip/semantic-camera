"""LC-007 浸泡证据包完整性验证器测试。

用真实 `EvidenceWriter` 生成对端格式的证据目录，再以篡改/缺失/替换等手段
覆盖拒绝面与诚实边界。进程内、无网络、无子进程；合成证据，非真实 Linux
主机、真实 RTSP 或 24 小时证据。

所有文件访问统一经 `_evidence_path` 围栏：只允许证据目录内的普通文件名，
拒绝 `..` 与越出目录的路径；读写走 pathlib。
"""

import json
import os
import stat
from pathlib import Path

import pytest

from scam.linux_soak import ENDPOINTS, SCHEMA, EvidenceWriter
import scam.linux_soak_verify as verifier_module
from scam.linux_soak_verify import GENESIS_HASH, main, verify_soak_directory


SAMPLES_NAME = "samples.ndjson"
SUMMARY_NAME = "summary.json"
MANIFEST_NAME = "manifest.json"


def _evidence_path(base, name):
    """构造并校验证据目录内固定文件路径：拒绝 .. 与目录外越界。"""
    if not isinstance(name, str) or not name or os.path.basename(name) != name:
        raise ValueError("文件名必须为证据目录内的普通文件名")
    root = os.path.abspath(str(base))
    target = Path(os.path.abspath(os.path.join(root, name)))
    if Path(root) not in target.parents:
        raise ValueError("路径越出证据目录")
    return target


def _samples_file(base):
    return _evidence_path(base, SAMPLES_NAME)


def _summary_file(base):
    return _evidence_path(base, SUMMARY_NAME)


def _manifest_file(base):
    return _evidence_path(base, MANIFEST_NAME)


def _read_samples(base):
    return _samples_file(base).read_text(encoding="utf-8").splitlines()


def _write_samples(base, lines):
    payload = "".join(line + "\n" for line in lines)
    _samples_file(base).write_text(payload, encoding="utf-8")


def _dump_record(record):
    return json.dumps(record, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def _rewrite_json(path, mutate):
    guarded = Path(_evidence_path(os.path.dirname(path),
                                  os.path.basename(path)))
    payload = json.loads(guarded.read_bytes().decode("utf-8"))
    mutate(payload)
    guarded.write_bytes(_dump_record(payload).encode("utf-8") + b"\n")


def _rewrite_summary(base, mutate):
    _rewrite_json(_summary_file(base), mutate)


def _sample(seq):
    return {
        "schema": SCHEMA,
        "kind": "sample",
        "sequence": seq,
        "observed_at": f"2026-09-20T00:00:0{seq % 10}Z",
        "elapsed_s": round(seq * 5.0, 3),
        "endpoints": {
            "/api/health": {"ok": True, "status": 200, "latency_ms": 1.0,
                            "payload": {}, "error": None},
            "/api/stats": {"ok": False, "status": None, "latency_ms": 2.0,
                           "payload": None, "error": "connect"},
        },
    }


def _make_evidence(tmp_path, count=3, name="run"):
    out = Path(tmp_path) / name
    manifest = {
        "schema": SCHEMA, "kind": "manifest", "run_id": f"run-{name}",
        "started_at": "2026-09-20T00:00:00Z",
        "base_url": "http://127.0.0.1:8765",
        "duration_s": 60.0, "interval_s": 5.0, "timeout_s": 1.0,
        "hostname": "host", "platform": "test", "python": "3.x",
    }
    writer = EvidenceWriter(str(out), manifest)
    for seq in range(count):
        writer.append(_sample(seq))
    writer.finish({
        "requested_duration_s": 60.0,
        "observed_duration_s": round(count * 5.0, 3),
        "endpoint_successes": {path: count for path in ENDPOINTS},
        "endpoint_failures": {path: 0 for path in ENDPOINTS},
        "camera_state_observations": {},
        "termination_reason": "duration_reached",
        "completed_requested_duration": False,
        "release_gate_passed": None,
        "release_gate_note": "raw observation only",
    })
    return out


# ---------- 1. 正常链：完整通过且诚实边界保持 ----------

def test_intact_package_passes_and_keeps_gate_null(tmp_path):
    out = _make_evidence(tmp_path, count=3)

    result = verify_soak_directory(str(out))

    assert result["integrity_passed"] is True
    assert result["errors"] == []
    assert result["sample_count"] == 3
    assert result["release_gate_passed"] is None  # 结构完整≠发布门禁通过
    assert "host, RTSP, duration" in result["release_gate_note"]


# ---------- 2. 空包：仅当 summary 明确 sample_count=0 ----------

def test_empty_package_valid_only_with_explicit_zero_count(tmp_path):
    out = _make_evidence(tmp_path, count=0)
    result = verify_soak_directory(str(out))
    assert result["integrity_passed"] is True
    assert result["sample_count"] == 0

    _rewrite_summary(out, lambda payload: payload.update(sample_count=1))
    result = verify_soak_directory(str(out))
    assert result["integrity_passed"] is False
    assert any("sample_count" in err for err in result["errors"])


# ---------- 3. 篡改记录内容：哈希不匹配 ----------

def test_tampered_record_fails_hash_check(tmp_path):
    out = _make_evidence(tmp_path, count=2)
    lines = _read_samples(out)
    record = json.loads(lines[0])
    record["elapsed_s"] = 999.0  # 改内容但保留原 record_sha256
    lines[0] = _dump_record(record)
    _write_samples(out, lines)

    result = verify_soak_directory(str(out))

    assert result["integrity_passed"] is False
    assert any("record_sha256 mismatch" in err for err in result["errors"])


# ---------- 4. 跳号与重复序列 ----------

def test_skipped_sequence_fails(tmp_path):
    out = _make_evidence(tmp_path, count=3)
    _write_samples(out, _read_samples(out)[1:])  # 丢掉 sequence 0

    result = verify_soak_directory(str(out))

    assert result["integrity_passed"] is False
    assert any("sequence 1 != expected 0" in err for err in result["errors"])


def test_duplicated_sequence_fails(tmp_path):
    out = _make_evidence(tmp_path, count=2)
    lines = _read_samples(out)
    _write_samples(out, [lines[0], lines[0]])

    result = verify_soak_directory(str(out))

    assert result["integrity_passed"] is False
    assert any("sequence 0 != expected 1" in err for err in result["errors"])


# ---------- 5. 非法 JSON 与空行 ----------

def test_invalid_json_and_blank_line_fail(tmp_path):
    out = _make_evidence(tmp_path, count=1)
    _write_samples(out, _read_samples(out) + ["not-json"])
    result = verify_soak_directory(str(out))
    assert result["integrity_passed"] is False
    assert any("invalid JSON" in err for err in result["errors"])

    out2 = _make_evidence(tmp_path, count=1, name="run-blank")
    _write_samples(out2, _read_samples(out2) + [""])
    result = verify_soak_directory(str(out2))
    assert result["integrity_passed"] is False
    assert any("blank line" in err for err in result["errors"])


# ---------- 6. summary 错计数 / 错末哈希 ----------

def test_summary_wrong_count_and_last_hash_fail(tmp_path):
    out = _make_evidence(tmp_path, count=3)
    _rewrite_summary(out, lambda payload: payload.update(sample_count=2))
    result = verify_soak_directory(str(out))
    assert result["integrity_passed"] is False
    assert any("sample_count 2 != observed 3" in err
               for err in result["errors"])

    out2 = _make_evidence(tmp_path, count=3, name="run-lasthash")
    _rewrite_summary(
        out2, lambda payload: payload.update(last_record_sha256=GENESIS_HASH))
    result = verify_soak_directory(str(out2))
    assert result["integrity_passed"] is False
    assert any("last_record_sha256 mismatch" in err
               for err in result["errors"])


# ---------- 7. 缺文件 ----------

def test_missing_files_fail(tmp_path):
    out = _make_evidence(tmp_path, count=1)
    os.unlink(_summary_file(out))
    result = verify_soak_directory(str(out))
    assert result["integrity_passed"] is False
    assert "summary.json: missing" in result["errors"]

    out2 = _make_evidence(tmp_path, count=1, name="run-nomanifest")
    os.unlink(_manifest_file(out2))
    result = verify_soak_directory(str(out2))
    assert result["integrity_passed"] is False
    assert "manifest.json: missing" in result["errors"]


# ---------- 8. 非普通文件 / 软链接拒绝 ----------

def test_non_regular_samples_file_rejected(tmp_path):
    out = _make_evidence(tmp_path, count=1)
    os.unlink(_samples_file(out))
    os.mkdir(_samples_file(out))  # 目录冒充样本文件

    result = verify_soak_directory(str(out))

    assert result["integrity_passed"] is False
    assert any("not a regular file" in err for err in result["errors"])


def test_symlink_samples_file_rejected(tmp_path):
    outside = _evidence_path(tmp_path, "outside.ndjson")
    outside.write_bytes(b"{}\n")
    out = _make_evidence(tmp_path, count=1)
    os.unlink(_samples_file(out))
    try:
        os.symlink(outside, _samples_file(out))
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接")
    result = verify_soak_directory(str(out))
    assert result["integrity_passed"] is False
    assert any("symlink" in err for err in result["errors"])


def test_symlinked_output_dir_rejected(tmp_path):
    real = _make_evidence(tmp_path, count=1)
    link = _evidence_path(tmp_path, "link-to-run")
    try:
        os.symlink(real, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接")
    result = verify_soak_directory(str(link))
    assert result["integrity_passed"] is False
    assert any("output_dir: symlink" in err for err in result["errors"])


def test_symlinked_output_dir_is_not_traversed(monkeypatch, tmp_path):
    """Cross-platform proof that a rejected root link is never inspected."""
    root = _evidence_path(tmp_path, "synthetic-link")
    real_lstat = verifier_module.os.lstat

    def fake_lstat(path):
        if os.path.abspath(path) == os.path.abspath(root):
            return type("LinkStat", (), {"st_mode": stat.S_IFLNK})()
        return real_lstat(path)

    def fail_if_traversed(*_args, **_kwargs):
        raise AssertionError("rejected output_dir must not be traversed")

    monkeypatch.setattr(verifier_module.os, "lstat", fake_lstat)
    monkeypatch.setattr(verifier_module, "_check_regular_file",
                        fail_if_traversed)

    result = verify_soak_directory(str(root))

    assert result["integrity_passed"] is False
    assert result["sample_count"] is None
    assert result["errors"] == ["output_dir: symlink is not accepted"]


def test_output_dir_must_be_a_directory(tmp_path):
    root = _evidence_path(tmp_path, "not-a-directory")
    root.write_bytes(b"not a package")

    result = verify_soak_directory(str(root))

    assert result["integrity_passed"] is False
    assert result["sample_count"] is None
    assert result["errors"] == ["output_dir: not a directory"]


# ---------- 9. 未知 schema/kind ----------

def test_unknown_schema_or_kind_fail(tmp_path):
    out = _make_evidence(tmp_path, count=1)
    manifest = json.loads(_manifest_file(out).read_bytes().decode("utf-8"))
    manifest["schema"] = "other/v1"
    _manifest_file(out).write_bytes(_dump_record(manifest).encode("utf-8")
                                    + b"\n")
    result = verify_soak_directory(str(out))
    assert result["integrity_passed"] is False
    assert "manifest.json: unknown schema" in result["errors"]

    out2 = _make_evidence(tmp_path, count=1, name="run-kind")
    lines = _read_samples(out2)
    record = json.loads(lines[0])
    record["kind"] = "other"
    record["record_sha256"] = GENESIS_HASH  # kind 校验先于哈希即可达
    lines[0] = _dump_record(record)
    _write_samples(out2, lines)
    result = verify_soak_directory(str(out2))
    assert result["integrity_passed"] is False
    assert any("kind must be sample" in err for err in result["errors"])


# ---------- 10. CLI：机器可读 JSON 与退出码 ----------

def test_cli_machine_readable_json_and_exit_codes(tmp_path, capsys):
    out = _make_evidence(tmp_path, count=2)
    assert main(["--output-dir", str(out)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["integrity_passed"] is True
    assert payload["release_gate_passed"] is None

    _rewrite_summary(out, lambda item: item.update(sample_count=99))
    assert main(["--output-dir", str(out)]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["integrity_passed"] is False
