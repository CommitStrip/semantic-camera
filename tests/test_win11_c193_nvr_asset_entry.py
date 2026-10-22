"""NVR's actual JSON loader consumes explicit packaged asset resolution."""
import json
import pytest

from scam import config, nvr


def test_marked_venue_uses_shared_resolver(tmp_path, monkeypatch):
    source = {"asset_paths": {"schema": "scam.package-assets/v1", "root": "config"},
              "cameras": []}
    path = tmp_path / "venue.json"
    path.write_text(json.dumps(source), encoding="utf-8-sig")
    calls = []
    resolved = {**source, "resolved_test_marker": True}

    def resolver(value, config_path):
        calls.append((value, config_path))
        return resolved

    monkeypatch.setattr(config, "resolve_venue_asset_paths", resolver, raising=False)
    assert nvr._load_json(path) is resolved
    assert calls == [(source, path)]


def test_legacy_venue_never_changes_asset_resolution(tmp_path, monkeypatch):
    source = {"cameras": [{"detector": {"model": "relative/model.onnx"}}]}
    path = tmp_path / "venue.json"
    path.write_text(json.dumps(source), encoding="utf-8")

    def forbidden(*args, **kwargs):
        raise AssertionError("legacy venue must preserve original paths")

    monkeypatch.setattr(config, "resolve_venue_asset_paths", forbidden, raising=False)
    assert nvr._load_json(path) == source


def test_real_loader_uses_config_root_from_other_working_directory(tmp_path, monkeypatch):
    root = tmp_path / "installed"
    root.mkdir()
    model = root / "models" / "person-detector.onnx"
    model.parent.mkdir()
    model.write_bytes(b"path-test-only")
    value = {"asset_paths": {"schema": "scam.package-assets/v1", "root": "config"},
             "cameras": [{"detector": {"engine": "onnx", "model": "models/person-detector.onnx"}}]}
    path = root / "example.json"
    path.write_text(json.dumps(value), encoding="utf-8-sig")
    monkeypatch.chdir(tmp_path)
    actual = nvr._load_json(path)
    assert actual["cameras"][0]["detector"]["model"] == str(model)
    assert nvr._detector_plan(actual["cameras"][0]["detector"]) == ("alerting", None)
    assert json.loads(path.read_text(encoding="utf-8-sig")) == value


@pytest.mark.parametrize("relative", ["../elsewhere", "..\\elsewhere", "C:relative"])
def test_real_loader_rejects_ambiguous_or_escaping_assets(tmp_path, relative):
    value = {"asset_paths": {"schema": "scam.package-assets/v1", "root": "config"},
             "cameras": [], "l2": {"checkpoint": relative}}
    path = tmp_path / "example.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError):
        nvr._load_json(path)
