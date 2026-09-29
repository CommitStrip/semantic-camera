"""win11_resource_snapshot.py —— 只读资源预检快照（重模型运行前）。

记录：Ollama/llama-server 实例数与内存、父进程映射、Windows 资源耗尽事件。
绝不结束任何进程、不改任何配置——异常只报告，处置权在用户。

用法：python scripts/win11_resource_snapshot.py [--out 快照.json]
输出：JSON 快照（verdict=ok|attention 与理由）。
"""

import argparse
import csv
import io
import json
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

WATCH_NAMES = ("ollama", "llama-server")
EXHAUSTION_LOG = "Microsoft-Windows-Resource-Exhaustion-Detector/Operational"


def _run(command):
    """只读命令执行；失败返回 (False, 错误说明)。"""
    try:
        proc = subprocess.run(command, capture_output=True, text=True,
                              timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "").strip()[:300]
    return True, proc.stdout


def parse_tasklist(csv_text):
    """tasklist /FO CSV /NH → [{name, pid, mem_kb}]（容错空行/表头）。"""
    out = []
    for row in csv.reader(io.StringIO(csv_text)):
        if len(row) < 5 or row[0].strip() in ("", "映像名称", "Image Name"):
            continue
        name = row[0].strip()
        mem = row[4].replace(",", "").replace(" K", "").replace("K", "").strip()
        try:
            out.append({"name": name, "pid": int(row[1]),
                        "mem_kb": int(mem) if mem.isdigit() else None})
        except ValueError:
            continue
    return out


def parse_cim_csv(csv_text):
    """Get-CimInstance CSV → {pid: {ppid, name}}（容错）。"""
    parents = {}
    for row in csv.DictReader(io.StringIO(csv_text)):
        try:
            parents[int(row["ProcessId"])] = {
                "ppid": int(row["ParentProcessId"]),
                "name": (row.get("Name") or "").strip()}
        except (KeyError, TypeError, ValueError):
            continue
    return parents


def snapshot_processes():
    """受关注的模型进程实例（名称子串匹配，大小写不敏感）。"""
    ok, text = _run(["tasklist", "/FO", "CSV", "/NH"])
    if not ok:
        return None, f"tasklist 失败：{text}"
    rows = parse_tasklist(text)
    watched = [r for r in rows
               if any(w in r["name"].lower() for w in WATCH_NAMES)]
    return watched, None


def parent_map():
    ok, text = _run(["powershell", "-NoProfile", "-Command",
                     "Get-CimInstance Win32_Process | "
                     "Select-Object ProcessId,ParentProcessId,Name | "
                     "ConvertTo-Csv -NoTypeInformation"])
    if not ok:
        return None, f"Get-CimInstance 失败：{text}"
    return parse_cim_csv(text), None


def exhaustion_events(hours=48):
    """近 N 小时资源耗尽事件（日志不存在/拒绝访问 → 如实记录错误）。"""
    since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    ok, text = _run([
        "powershell", "-NoProfile", "-Command",
        f"Get-WinEvent -FilterHashtable @{{LogName='{EXHAUSTION_LOG}';"
        f" StartTime='{since}'}} -ErrorAction Stop | "
        "Select-Object TimeCreated,Id | ConvertTo-Csv -NoTypeInformation"])
    if not ok:
        return None, text[:200]
    rows = list(csv.DictReader(io.StringIO(text)))
    return [{"time": r.get("TimeCreated"), "id": r.get("Id")}
            for r in rows], None


def build_snapshot(exhaustion_hours=48):
    watched, err_proc = snapshot_processes()
    parents, err_parent = parent_map()
    exhaust, err_exhaust = exhaustion_events(exhaustion_hours)
    reasons = []
    if watched is None:
        reasons.append("进程枚举失败：" + (err_proc or ""))
    if exhaust is None:
        reasons.append("资源耗尽日志不可读：" + (err_exhaust or ""))
    if watched:
        ollama_count = sum(1 for p in watched
                           if "ollama" in p["name"].lower())
        if ollama_count > 1:
            reasons.append(f"发现 {ollama_count} 个 ollama 实例（异常重复）")
    if exhaust:
        reasons.append(f"近 {exhaustion_hours}h 有 {len(exhaust)} 条资源耗尽事件")
    verdict = "attention" if reasons else "ok"
    for p in (watched or []):
        ppid = (parents or {}).get(p["pid"], {}).get("ppid")
        p["parent_pid"] = ppid
        p["parent_name"] = (parents or {}).get(ppid, {}).get("name")
    return {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
            "watched_processes": watched or [],
            "process_count": len(watched or []),
            "exhaustion_events": exhaust or [],
            "verdict": verdict,
            "reasons": reasons,
            "errors": [r for r in (err_proc, err_parent, err_exhaust) if r],
            "note": "只读快照：不结束任何进程、不改任何配置；"
                    "verdict=attention 时应停止重模型试验并报告用户。"}


def main(argv=None):
    ap = argparse.ArgumentParser(description="只读资源预检快照")
    ap.add_argument("--out", default=None)
    ap.add_argument("--exhaustion-hours", type=int, default=48)
    args = ap.parse_args(argv)
    snap = build_snapshot(args.exhaustion_hours)
    text = json.dumps(snap, ensure_ascii=False, indent=1)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
