"""LC-013 replay 输入指纹清单测试。

以真实临时文件验证确定性哈希、basename 不泄露绝对路径、JSON 根对象校验、
缺失/目录/软链接拒绝与诚实边界；零子进程/零解码经 monkeypatch 与静态
源检查证明。合成证据，不代表任何真实 replay 执行或门禁通过。
"""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

import scam.linux_replay_manifest as manifest_mod
from scam.linux_replay_manifest import SCHEMA, main


def _make_input(base, name, payload):
    target = Path(base) / name
    target.write_bytes(payload)
    return str(target)


def _dump_record(record):
    return json.dumps(record, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def _make_inputs(tmp_path, config_payload=b'{"a": 1}'):
    video = _make_input(tmp_path, "clip.mp4", b"\x00\x01video-bytes")
    config = _make_input(tmp_path, "cameras.json", config_payload)
    model = _make_input(tmp_path, "person.onnx", b"model-weights")
    return video, config, model


def _forbidden(*args, **kwargs):
    raise AssertionError("指纹清单建立不得创建子进程或解码视频")


# ---------- 1. 三输入确定性指纹 + 诚实字段固定 ----------

def test_manifest_fingerprints_inputs_deterministically(tmp_path):
    video, config, model = _make_inputs(tmp_path)

    manifest, errors = manifest_mod.build_manifest(
        video, config, model, "sw-2026.09")

    assert errors == []
    assert manifest["schema"] == SCHEMA
    assert manifest["kind"] == "replay_input_manifest"
    assert manifest["software_id"] == "sw-2026.09"
    assert manifest["created_at"].endswith("Z")
    assert [entry["role"] for entry in manifest["inputs"]] == \
        ["video", "config", "model"]
    video_entry = manifest["inputs"][0]
    assert video_entry["name"] == "clip.mp4"
    assert video_entry["size_bytes"] == len(b"\x00\x01video-bytes")
    assert video_entry["sha256"] == \
        hashlib.sha256(b"\x00\x01video-bytes").hexdigest()
    # 诚实边界三件套：冻结≠执行≠质量结论≠发布结论
    assert manifest["replay_executed"] is False
    assert manifest["quality_gate_passed"] is None
    assert manifest["release_gate_passed"] is None
    assert "real decoding" in manifest["next_steps_note"]


def test_manifest_is_deterministic_except_created_at(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    first, _ = manifest_mod.build_manifest(video, config, model, "sw")
    second, _ = manifest_mod.build_manifest(video, config, model, "sw")
    first.pop("created_at")
    second.pop("created_at")
    assert first == second


# ---------- 2. basename：输出不泄露绝对路径 ----------

def test_manifest_output_never_leaks_absolute_paths(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    manifest, errors = manifest_mod.build_manifest(video, config, model, "sw")
    assert errors == []
    text = json.dumps(manifest, ensure_ascii=False)
    assert str(tmp_path) not in text
    assert [entry["name"] for entry in manifest["inputs"]] == \
        ["clip.mp4", "cameras.json", "person.onnx"]


# ---------- 3. config 必须是 UTF-8 JSON 根对象 ----------

def test_config_must_be_json_root_object(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    manifest, errors = manifest_mod.build_manifest(video, config, model, "sw")
    assert errors == []  # {"a": 1} 是合法根对象

    _, config, model = _make_inputs(tmp_path, config_payload=b"[1, 2]")
    video2 = _make_input(tmp_path, "clip.mp4", b"\x00\x01video-bytes")
    _, errors = manifest_mod.build_manifest(video2, config, model, "sw")
    assert any("root is not an object" in err for err in errors)

    _, config, model = _make_inputs(tmp_path, config_payload=b"hello")
    video3 = _make_input(tmp_path, "clip.mp4", b"\x00\x01video-bytes")
    _, errors = manifest_mod.build_manifest(video3, config, model, "sw")
    assert any("not readable as UTF-8 JSON" in err for err in errors)


# ---------- 4. 缺失 / 目录 / 软链接拒绝 ----------

def test_missing_input_rejected(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    os.unlink(video)
    manifest, errors = manifest_mod.build_manifest(video, config, model, "sw")
    assert manifest is None
    assert "video: missing" in errors


def test_directory_as_input_rejected(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    os.unlink(video)
    os.mkdir(video)
    manifest, errors = manifest_mod.build_manifest(video, config, model, "sw")
    assert manifest is None
    assert any("not a regular file" in err for err in errors)


def test_symlink_input_rejected(tmp_path):
    outside = tmp_path / "outside.mp4"
    outside.write_bytes(b"video")
    video, config, model = _make_inputs(tmp_path)
    os.unlink(video)
    try:
        os.symlink(outside, video)
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接")
    manifest, errors = manifest_mod.build_manifest(video, config, model, "sw")
    assert manifest is None
    assert any("symlink" in err for err in errors)


def test_input_changed_while_hashing_is_rejected(tmp_path):
    video, config, model = _make_inputs(tmp_path)

    def mutate_after_hash(path):
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        if path == video:
            Path(path).write_bytes(b"changed-video-content")
        return digest

    manifest, errors = manifest_mod.build_manifest(
        video, config, model, "sw", sha256_fn=mutate_after_hash)

    assert manifest is None
    assert "video: changed while fingerprinting" in errors


def test_same_size_replacement_with_preserved_mtime_is_rejected(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    original = os.stat(video)

    def replace_after_hash(path):
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        if path == video:
            replacement = tmp_path / "replacement.mp4"
            replacement.write_bytes(b"X" * original.st_size)
            os.utime(replacement,
                     ns=(original.st_atime_ns, original.st_mtime_ns))
            os.replace(replacement, video)
        return digest

    manifest, errors = manifest_mod.build_manifest(
        video, config, model, "sw", sha256_fn=replace_after_hash)

    assert manifest is None
    assert "video: changed while fingerprinting" in errors


# ---------- 5. software_id 非空 ----------

@pytest.mark.parametrize("bad", ["", "   "])
def test_empty_software_id_rejected(tmp_path, bad):
    video, config, model = _make_inputs(tmp_path)
    manifest, errors = manifest_mod.build_manifest(video, config, model, bad)
    assert manifest is None
    assert any("software_id" in err for err in errors)


# ---------- 6. 零子进程 / 零解码（monkeypatch + 静态源检查） ----------

def test_no_subprocess_and_no_decoder(tmp_path, monkeypatch):
    def _forbidden(*args, **kwargs):
        raise AssertionError("输入冻结不得创建子进程")

    for name in ("run", "Popen", "check_output", "call", "check_call"):
        monkeypatch.setattr(subprocess, name, _forbidden)

    source = Path(manifest_mod.__file__).read_text(encoding="utf-8")
    assert "import cv2" not in source
    assert "import subprocess" not in source
    assert "onnxruntime" not in source

    video, config, model = _make_inputs(tmp_path)
    manifest, errors = manifest_mod.build_manifest(video, config, model, "sw")
    assert errors == []


# ---------- 7. CLI 退出码与机器可读错误 ----------

def test_cli_exit_codes_and_machine_readable_errors(tmp_path, capsys):
    video, config, model = _make_inputs(tmp_path)

    assert main(["--video", video, "--config", config, "--model", model,
                 "--software-id", "sw-1"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "replay_input_manifest"
    assert payload["replay_executed"] is False
    assert payload["quality_gate_passed"] is None
    assert payload["release_gate_passed"] is None

    assert main(["--video", str(tmp_path / "nope.mp4"),
                 "--config", config, "--model", model,
                 "--software-id", "sw-1"]) == 1
    error = json.loads(capsys.readouterr().err)
    assert error["kind"] == "replay_input_manifest_error"
    assert error["replay_executed"] is False
    assert error["quality_gate_passed"] is None
    assert error["release_gate_passed"] is None


def test_cli_missing_required_argument_fails_nonzero():
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code != 0


# ---------- LC-015：归档清单离线复核 ----------

def _archive(manifest, tmp_path):
    archived = tmp_path / "archived.json"
    archived.write_bytes(_dump_record(manifest).encode("utf-8") + b"\n")
    return str(archived)


def test_verify_matching_inputs_reports_true(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    manifest, _ = manifest_mod.build_manifest(video, config, model, "sw-1")
    result, errors = manifest_mod.verify_manifest_against_inputs(
        manifest, video, config, model)

    assert errors == []
    assert result["kind"] == "replay_input_verification"
    assert result["inputs_match"] is True
    assert all(entry["match"] for entry in result["comparisons"])
    assert result["replay_executed"] is False
    assert result["quality_gate_passed"] is None
    assert result["release_gate_passed"] is None

    # 归档文件路径形态同样通过（lstat+严格结构校验）
    result, errors = manifest_mod.verify_manifest_against_inputs(
        _archive(manifest, tmp_path), video, config, model)
    assert errors == []
    assert result["inputs_match"] is True
    assert result["software_id"] == "sw-1"


def test_verify_detects_content_change(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    manifest, _ = manifest_mod.build_manifest(video, config, model, "sw-1")
    Path(video).write_bytes(b"changed-video-content")

    result, errors = manifest_mod.verify_manifest_against_inputs(
        manifest, video, config, model)

    assert errors == []
    assert result["inputs_match"] is False
    by_role = {entry["role"]: entry for entry in result["comparisons"]}
    assert by_role["video"]["hash_match"] is False
    assert by_role["video"]["size_match"] is False
    assert by_role["config"]["match"] is True
    assert by_role["model"]["match"] is True


def test_verify_detects_name_change(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    manifest, _ = manifest_mod.build_manifest(video, config, model, "sw-1")
    renamed = _make_input(tmp_path, "renamed.mp4", b"\x00\x01video-bytes")

    result, _ = manifest_mod.verify_manifest_against_inputs(
        manifest, renamed, config, model)

    assert result["inputs_match"] is False
    by_role = {entry["role"]: entry for entry in result["comparisons"]}
    assert by_role["video"]["name_match"] is False
    assert by_role["video"]["hash_match"] is True  # 内容相同、仅名称不同
    assert by_role["config"]["match"] is True


def test_verify_current_input_missing_rejected(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    manifest, _ = manifest_mod.build_manifest(video, config, model, "sw-1")
    os.unlink(video)

    result, errors = manifest_mod.verify_manifest_against_inputs(
        manifest, video, config, model)

    assert result["inputs_match"] is False
    assert any("video: missing" in err for err in errors)
    assert result["quality_gate_passed"] is None


def test_verify_rejects_tampered_archived_manifest(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    base, _ = manifest_mod.build_manifest(video, config, model, "sw-1")

    mutations = (
        lambda m: m.update(schema="other/v1"),
        lambda m: m.update(kind="other"),
        lambda m: m.update(software_id=""),
        lambda m: m.update(inputs=None),
        lambda m: m["inputs"][0].update(sha256="nothex"),
        lambda m: m["inputs"][1].update(size_bytes=-1),
    )
    for mutate in mutations:
        tampered = json.loads(_dump_record(base))
        mutate(tampered)
        result, errors = manifest_mod.verify_manifest_against_inputs(
            tampered, video, config, model)
        assert result["inputs_match"] is False
        assert errors, mutate


def test_verify_duplicate_and_missing_roles_rejected(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    base, _ = manifest_mod.build_manifest(video, config, model, "sw-1")

    duplicated = json.loads(_dump_record(base))
    duplicated["inputs"].append(dict(duplicated["inputs"][0]))
    result, errors = manifest_mod.verify_manifest_against_inputs(
        duplicated, video, config, model)
    assert result["inputs_match"] is False
    assert any("exactly one entry per role" in err for err in errors)


def test_verify_malformed_entries_fail_closed_without_crashing(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    base, _ = manifest_mod.build_manifest(video, config, model, "sw-1")

    mutations = (
        lambda m: m["inputs"][0].pop("name"),
        lambda m: m["inputs"][0].update(role=None),
        lambda m: m["inputs"][0].update(role="unknown"),
        lambda m: m["inputs"][0].update(name="../clip.mp4"),
    )
    for mutate in mutations:
        tampered = json.loads(_dump_record(base))
        mutate(tampered)
        result, errors = manifest_mod.verify_manifest_against_inputs(
            tampered, video, config, model)
        assert result["inputs_match"] is False
        assert errors
        assert result["replay_executed"] is False

    missing = json.loads(_dump_record(base))
    missing["inputs"] = missing["inputs"][:2]  # 丢掉 model role
    result, errors = manifest_mod.verify_manifest_against_inputs(
        missing, video, config, model)
    assert result["inputs_match"] is False
    assert any("exactly one entry per role" in err for err in errors)


def test_verify_rejects_symlinked_archived_manifest(tmp_path):
    video, config, model = _make_inputs(tmp_path)
    manifest, _ = manifest_mod.build_manifest(video, config, model, "sw-1")
    real = tmp_path / "real-archived.json"
    real.write_bytes(_dump_record(manifest).encode("utf-8"))
    link = tmp_path / "archived.json"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接")
    result, errors = manifest_mod.verify_manifest_against_inputs(
        str(link), video, config, model)
    assert result["inputs_match"] is False
    assert any("symlink" in err for err in errors)
    assert result["replay_executed"] is False


def test_verify_cli_mode_exit_codes(tmp_path, capsys):
    video, config, model = _make_inputs(tmp_path)
    manifest, _ = manifest_mod.build_manifest(video, config, model, "sw-1")
    archived = _archive(manifest, tmp_path)

    assert main(["--video", video, "--config", config, "--model", model,
                 "--verify-manifest", archived]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["inputs_match"] is True
    assert payload["replay_executed"] is False
    assert payload["quality_gate_passed"] is None
    assert payload["release_gate_passed"] is None

    Path(video).write_bytes(b"tampered")
    assert main(["--video", video, "--config", config, "--model", model,
                 "--verify-manifest", archived]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["inputs_match"] is False  # 差异经 JSON 如实呈现

    missing_archive = str(tmp_path / "gone.json")
    assert main(["--video", video, "--config", config, "--model", model,
                 "--verify-manifest", missing_archive]) == 1
    error = json.loads(capsys.readouterr().err)
    assert error["kind"] == "replay_input_manifest_error"
