"""config 校验：合法/非法用例（P0 验收）。"""

import pytest

from scam.config import validate_venue


def valid_venue():
    return {
        "venue": {"name": "测试场所"},
        "cameras": [
            {
                "id": "front-door",
                "source": "rtsp://192.168.1.64:554/Streaming/Channels/102",
                "detector": {"engine": "onnx", "model": "person-detector.onnx",
                             "classes": ["person"], "conf": 0.4},
                "alert_cls": "person",
                "grid": {"rows": 18, "cols": 22},
                "zones": [{"id": "z1", "name": "门口", "cells": [0, 1, 23, 24],
                           "rules": [{"cls": "person", "template": "enter-dwell",
                                      "dwell_s": 5, "severity": "high"}]}],
                "schedule": [{"from": "22:00", "to": "06:00"}],
            }
        ],
    }


def test_valid_venue_passes():
    assert validate_venue(valid_venue()) == []


def test_empty_cameras_fails():
    errs = validate_venue({"cameras": []})
    assert any("cameras" in e for e in errs)


@pytest.mark.parametrize("mutate,fragment", [
    (lambda v: v["cameras"][0].__setitem__("id", ""), "id"),
    (lambda v: v["cameras"][0].__setitem__("source", ""), "source"),
    (lambda v: v["cameras"][0]["detector"].__setitem__("engine", "magic"), "engine"),
    (lambda v: v["cameras"][0]["detector"].__setitem__("model", ""), "model"),
    (lambda v: v["cameras"][0]["detector"].__setitem__("classes", []), "classes"),
    (lambda v: v["cameras"][0]["detector"].__setitem__("conf", 1.2), "conf"),
    (lambda v: v["cameras"][0].__setitem__("grid", {"rows": 2, "cols": 22}), "grid"),
    (lambda v: v["cameras"][0]["zones"][0].__setitem__("cells", [999999]), "格子"),
    (lambda v: v["cameras"][0]["zones"][0]["rules"][0].__setitem__("dwell_s", -1), "dwell_s"),
    (lambda v: v["cameras"][0].__setitem__(
        "schedule", [{"from": "25:00", "to": "06:00"}]), "schedule"),
])
def test_invalid_mutations_fail_closed(mutate, fragment):
    v = valid_venue()
    mutate(v)
    errs = validate_venue(v)
    assert errs, f"变异应报错（{fragment}）"


def test_duplicate_camera_id_fails():
    v = valid_venue()
    v["cameras"].append(dict(v["cameras"][0]))
    errs = validate_venue(v)
    assert any("重复" in e for e in errs)


def test_zone_without_cells_fails():
    v = valid_venue()
    v["cameras"][0]["zones"][0]["cells"] = []
    assert validate_venue(v), "空格子区域必须报错"


@pytest.mark.parametrize("key,value", [
    ("record_enabled", "yes"),
    ("record_retention_days", -1),
    ("record_retention_days", True),
    ("record_cap_gb", 0),
    ("record_cap_gb", False),
    ("record_segment_seconds", 9),
])
def test_invalid_recording_settings_fail_closed(key, value):
    venue = valid_venue()
    venue["cameras"][0][key] = value
    errors = validate_venue(venue)
    assert any(key in error for error in errors)


def test_valid_recording_settings_pass():
    venue = valid_venue()
    venue["cameras"][0].update({
        "record_enabled": True,
        "record_retention_days": 7,
        "record_cap_gb": 25.5,
        "record_segment_seconds": 600,
    })
    assert validate_venue(venue) == []
