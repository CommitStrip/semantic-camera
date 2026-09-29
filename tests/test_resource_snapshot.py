"""资源快照脚本解析与判定逻辑验证（注入数据，不跑真实进程命令）。"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

from win11_resource_snapshot import (build_snapshot, parse_cim_csv,
                                     parse_tasklist)


def test_parse_tasklist_filters_and_counts():
    csv_text = (
        '"映像名称","PID","会话名","会话#","内存使用"\n'
        '"ollama.exe","1234","Console","1","21,248 K"\n'
        '"llama-server.exe","1300","Console","1","1,204,000 K"\n'
        '"chrome.exe","2000","Console","1","300,000 K"\n'
        '\n')
    rows = parse_tasklist(csv_text)
    watched = [r for r in rows if "ollama" in r["name"].lower()
               or "llama" in r["name"].lower()]
    assert len(watched) == 2
    assert watched[0] == {"name": "ollama.exe", "pid": 1234, "mem_kb": 21248}
    assert watched[1]["mem_kb"] == 1204000
    assert all("chrome" not in r["name"] for r in watched)


def test_parse_cim_csv_parents():
    csv_text = (
        '"ProcessId","ParentProcessId","Name"\n'
        '"1234","900","ollama.exe"\n'
        '"900","100","explorer.exe"\n')
    parents = parse_cim_csv(csv_text)
    assert parents[1234] == {"ppid": 900, "name": "ollama.exe"}
    assert parents[900]["ppid"] == 100


def test_verdict_flags_duplicate_instances_and_exhaustion(monkeypatch):
    import win11_resource_snapshot as mod

    def fake_snapshot():
        return [{"name": "ollama.exe", "pid": 1, "mem_kb": 1},
                {"name": "ollama.exe", "pid": 2, "mem_kb": 2}], None

    def fake_parents():
        return {1: {"ppid": 0, "name": "x"},
                2: {"ppid": 0, "name": "x"}}, None

    def fake_exhaust(hours):
        return [{"time": "t", "id": "2001"}], None

    monkeypatch.setattr(mod, "snapshot_processes", fake_snapshot)
    monkeypatch.setattr(mod, "parent_map", fake_parents)
    monkeypatch.setattr(mod, "exhaustion_events", fake_exhaust)
    snap = build_snapshot()
    assert snap["verdict"] == "attention"
    assert any("2 个 ollama 实例" in r for r in snap["reasons"])
    assert any("资源耗尽" in r for r in snap["reasons"])
    assert snap["process_count"] == 2


def test_verdict_ok_single_instance(monkeypatch):
    import win11_resource_snapshot as mod

    monkeypatch.setattr(
        mod, "snapshot_processes",
        lambda: ([{"name": "ollama.exe", "pid": 1, "mem_kb": 1}], None))
    monkeypatch.setattr(mod, "parent_map",
                        lambda: ({1: {"ppid": 0, "name": "x"}}, None))
    monkeypatch.setattr(mod, "exhaustion_events",
                        lambda hours: ([], None))
    snap = build_snapshot()
    assert snap["verdict"] == "ok"
    assert snap["reasons"] == []
    assert snap["process_count"] == 1
