"""LC-018 语义事件 replay 比较器测试。

多重集比较的顺序无关、重复计数、缺失/意外、运行期 ID 忽略、非法字段/
NaN/根对象/软链接拒绝、CLI 退出码与诚实字段。合成事实，不代表任何真实
视频/模型 replay 执行或门禁通过。
"""

import contextlib
import io
import json
import math
import os
from pathlib import Path

import pytest

from scam.linux_replay_compare import SCHEMA, main


def _event(**overrides):
    fact = {"camera": "front", "template": "person_enter_yard",
            "zone_id": "yard", "cls": "person", "state": "active",
            "t_start": 100.0, "t_end": 145.5, "end_reason": "ended"}
    fact.update(overrides)
    return fact


def _event_file(base, name, events):
    target = Path(base) / name
    target.write_bytes(json.dumps(events, ensure_ascii=False).encode("utf-8"))
    return str(target)


def _run_main(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


def _run_json(args):
    code, out, _ = _run_main(args)
    return code, (json.loads(out) if out else None)


def _run_error(args):
    code, _, err = _run_main(args)
    return code, (json.loads(err) if err else None)


# ---------- 1. 顺序无关：多重集一致即 match 且退出 0 ----------

def test_order_independent_multiset_match(tmp_path):
    expected = _event_file(tmp_path, "expected.json",
                           [_event(t_start=1.0), _event(t_start=2.0),
                            _event(camera="back")])
    actual = _event_file(tmp_path, "actual.json",
                         [_event(camera="back"), _event(t_start=2.0),
                          _event(t_start=1.0)])

    code, result = _run_json(["--expected", expected, "--actual", actual])

    assert code == 0
    assert result["match"] is True
    assert result["missing"] == [] and result["unexpected"] == []
    assert result["counts"] == {"matched": 3, "missing": 0, "unexpected": 0}


# ---------- 2. 重复事件按多重集计数 ----------

def test_duplicate_events_counted_as_multiset(tmp_path):
    expected = _event_file(tmp_path, "expected.json",
                           [_event(), _event(), _event(),
                            _event(camera="back")])
    actual = _event_file(tmp_path, "actual.json",
                         [_event(), _event(camera="back")])

    code, result = _run_json(["--expected", expected, "--actual", actual])

    assert code == 1 and result["match"] is False
    assert result["missing"] == [_event(), _event()]
    assert result["counts"] == {"matched": 2, "missing": 2, "unexpected": 0}


# ---------- 3. 缺失与意外分列 ----------

def test_missing_and_unexpected_reported_separately(tmp_path):
    expected = _event_file(tmp_path, "expected.json", [_event(t_start=9.0)])
    actual = _event_file(tmp_path, "actual.json",
                         [_event(t_start=9.0),
                          _event(camera="back", t_start=11.0)])

    code, result = _run_json(["--expected", expected, "--actual", actual])

    assert code == 1 and result["match"] is False
    assert result["missing"] == []
    assert result["unexpected"] == [_event(camera="back", t_start=11.0)]


# ---------- 4. 运行期 ID 忽略，事实相同即匹配 ----------

def test_runtime_ids_ignored(tmp_path):
    expected = _event_file(tmp_path, "expected.json",
                           [_event(semantic_event_id="run-A:1")])
    actual = _event_file(tmp_path, "actual.json",
                         [_event(semantic_event_id="run-B:99")])

    code, result = _run_json(["--expected", expected, "--actual", actual])

    assert code == 0 and result["match"] is True


# ---------- 5. 非法结构：未知/缺失字段、坏类型、NaN、根对象、软链接 ----------

def test_unknown_and_missing_fields_rejected(tmp_path):
    good = _event_file(tmp_path, "good.json", [_event()])
    unknown = _event_file(tmp_path, "unknown.json", [_event(score=0.9)])
    missing = _event_file(tmp_path, "missing.json",
                          [{k: v for k, v in _event().items()
                            if k != "zone_id"}])

    code, error = _run_error(["--expected", unknown, "--actual", good])
    assert code == 1
    assert any("unknown fields ['score']" in err for err in error["errors"])

    code, error = _run_error(["--expected", missing, "--actual", good])
    assert code == 1
    assert any("missing fields ['zone_id']" in err for err in error["errors"])


def test_bad_time_values_rejected(tmp_path):
    good = _event_file(tmp_path, "good.json", [_event()])

    nan_event = _event()
    nan_event["t_end"] = float("nan")
    code, _ = _run_error(["--expected",
                          _event_file(tmp_path, "nan.json", [nan_event]),
                          "--actual", good])
    assert code == 1

    inf_event = _event()
    inf_event["t_start"] = math.inf
    code, _ = _run_error(["--expected",
                          _event_file(tmp_path, "inf.json", [inf_event]),
                          "--actual", good])
    assert code == 1

    str_event = _event()
    str_event["t_start"] = "100.0"
    code, error = _run_error(
        ["--expected", _event_file(tmp_path, "str.json", [str_event]),
         "--actual", good])
    assert code == 1
    assert any("t_start must be a finite number" in err
               for err in error["errors"])


def test_open_or_unzoned_database_facts_accept_nulls(tmp_path):
    event = _event(zone_id=None, cls=None, t_end=None, end_reason=None,
                   state="open")
    expected = _event_file(tmp_path, "expected.json", [event])
    actual = _event_file(tmp_path, "actual.json", [event])

    code, result = _run_json(["--expected", expected, "--actual", actual])

    assert code == 0
    assert result["match"] is True


def test_root_object_rejected(tmp_path):
    good = _event_file(tmp_path, "good.json", [_event()])
    bad = _event_file(tmp_path, "bad.json", {"events": []})

    code, error = _run_error(["--expected", bad, "--actual", good])

    assert code == 1
    assert any("root must be a JSON array" in err for err in error["errors"])


def test_symlink_input_rejected(tmp_path):
    good = _event_file(tmp_path, "good.json", [_event()])
    real = tmp_path / "real.json"
    real.write_bytes(b"[]")
    link = tmp_path / "link.json"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("当前环境不允许创建符号链接")

    code, error = _run_error(["--expected", str(link),
                              "--actual", str(good)])

    assert code == 1
    assert any("symlink" in err for err in error["errors"])


def test_missing_input_file_reports_error(tmp_path):
    good = _event_file(tmp_path, "good.json", [_event()])

    code, error = _run_error(["--expected", str(tmp_path / "gone.json"),
                              "--actual", good])

    assert code == 1
    assert "expected: missing" in error["errors"]


def test_input_replaced_while_reading_is_rejected(tmp_path, monkeypatch):
    expected = Path(_event_file(tmp_path, "expected.json", [_event()]))
    actual = _event_file(tmp_path, "actual.json", [_event()])
    real_read = os.read
    replaced = False

    def replace_after_first_read(fd, size):
        nonlocal replaced
        chunk = real_read(fd, size)
        if chunk and not replaced:
            replacement = tmp_path / "replacement.json"
            replacement.write_bytes(expected.read_bytes())
            os.replace(replacement, expected)
            replaced = True
        return chunk

    monkeypatch.setattr(os, "read", replace_after_first_read)
    code, error = _run_error(
        ["--expected", str(expected), "--actual", actual])

    assert code == 1
    # Linux permits replacement of an open file and reaches the snapshot
    # check; Windows may reject os.replace while the read handle is open.
    assert any("changed while reading" in err or "not readable" in err
               for err in error["errors"])


# ---------- 6. 诚实字段恒定 ----------

def test_honest_fields_stay_null_even_on_match(tmp_path):
    expected = _event_file(tmp_path, "expected.json", [_event()])
    actual = _event_file(tmp_path, "actual.json", [_event()])

    code, result = _run_json(["--expected", expected, "--actual", actual])

    assert code == 0
    assert result["replay_executed"] is False
    assert result["quality_gate_passed"] is None
    assert result["release_gate_passed"] is None
    assert result["schema"] == SCHEMA
    assert "no video decoding" in result["comparison_note"]
