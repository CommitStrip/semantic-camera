"""measure_report.py —— Win11 用户闭环时延与事实测量报告（离线只读工具）。

读单个 events.db，产出 JSON 报告：各时间点样本、分布、缺失数、采样窗口。
时钟与统计口径见报告内 clock_sources / sampling_windows 字段；本工具只读落库
事实，不宣称质量合格。

只读保证：
- 输入先校验（不存在/目录/不可读 → 不同退出码），绝不因默认连接行为创建库；
- 以 SQLite URI `mode=ro` 打开并启用 `PRAGMA query_only`；
- 运行前后对输入库与 -wal/-shm 伴随文件做 SHA-256 核对，变化即失败（exit 6）；
- --out 与输入路径（含伴随文件）冲突即拒绝（exit 5）。

时钟来源（逐项注明）：
- t_source        源帧时间：event_facts.t_start；可信仅当事件 payload
                  timestamp_kind=='source_capture'（源显式证明采集时间）。
                  'host_receive'=本机收到时间（OpenCV 源），不得当作采集时延。
- t_event_insert  事件事实落库时间：**无独立时钟列**——以同链 initial_fact
                  created_at（服务端钟）作上界代理，字段名如实标注 proxy。
- t_notify        提醒创建时间：event_notifications.created_at（服务端钟）。
- t_display       显示回执时间：acknowledged_at（服务端钟，客户端提交 ack；
                  回执≠人工确认）。
- t_user_confirm  用户主动确认时间：user_confirmed_at（服务端钟，仅用户动作）。

时延指标：event_to_notify_s（仅源钟可信）、notify_to_display_s（服务端同钟）。
每项输出 n/缺失数/采样窗口/客户端在线条件；n<20 不出百分位并标「样本不足」。
客户端在线窗口：本工具不做推断——无独立客户端会话/心跳证据时不定义在线子集。
"""

import argparse
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

TOOL_VERSION = "2.0.0"
PERCENTILE_MIN_N = 20
SIDECAR_SUFFIXES = ("-wal", "-shm")
_CLIENT_ONLINE_NOTE = "未确立（本报告无独立客户端会话/心跳证据，不作在线子集推断）"


class MeasureError(Exception):
    """测量失败基类；exit_code 供 CLI 映射非零退出。"""
    exit_code = 1

    def __init__(self, message, exit_code=None):
        super().__init__(message)
        if exit_code is not None:
            self.exit_code = exit_code


class InputInvalid(MeasureError):
    exit_code = 2


class InputUnreadable(MeasureError):
    exit_code = 3


class DbUnusable(MeasureError):
    exit_code = 4


class OutputInvalid(MeasureError):
    exit_code = 5


class IntegrityChanged(MeasureError):
    exit_code = 6


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _input_fingerprint(db_path):
    """输入库 + 伴随文件 → {标识: sha256}（伴随文件可不存在，不记录）。"""
    files = {"db": _sha256(db_path)}
    for suffix in SIDECAR_SUFFIXES:
        side = db_path.with_name(db_path.name + suffix)
        if side.exists():
            files[suffix] = _sha256(side)
    return files


def _validate_input(db_path):
    if not db_path.exists():
        raise InputInvalid(f"输入数据库不存在：{db_path}")
    if db_path.is_dir():
        raise InputInvalid(f"输入路径是目录，不是数据库文件：{db_path}")
    try:
        with open(db_path, "rb"):
            pass
    except OSError as exc:
        raise InputUnreadable(f"输入数据库不可读：{exc}") from exc


def _connect_readonly(db_path):
    """SQLite 只读连接（mode=ro + immutable=1 + query_only），绝不创建文件。

    immutable=1：输入必须是已停写、伴随文件已收口的库快照——SQLite 完全不
    接触 -wal/-shm，保证运行前后伴随文件零变化。
    """
    uri = db_path.resolve().as_uri() + "?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.OperationalError as exc:
        raise InputUnreadable(f"无法以只读方式打开数据库：{exc}") from exc
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only = ON")
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1")
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise DbUnusable(f"数据库损坏或不可用：{exc}") from exc
    return conn


def _require_tables(conn):
    """缺表/缺列 → 明确失败（不静默空报告）。表名经参数绑定查询。"""
    required = {
        "event_facts": {"event_id", "camera", "t_start", "t_end", "state",
                        "end_reason", "evidence_state", "payload"},
        "event_notifications": {"notification_id", "event_id", "kind",
                                "created_at", "acknowledged_at",
                                "user_confirmed_at"},
        "event_descriptions": {"event_id", "source"}}
    for table, cols in required.items():
        try:
            found = {r["name"] for r in conn.execute(
                "SELECT name FROM pragma_table_info(?)", (table,))}
        except sqlite3.DatabaseError as exc:
            raise DbUnusable(f"读取表结构失败（{table}）：{exc}") from exc
        if not found:
            raise DbUnusable(f"缺少必需表：{table}")
        missing = cols - found
        if missing:
            raise DbUnusable(
                f"表 {table} 缺少必需列：{', '.join(sorted(missing))}")


def _samples(values):
    """样本列表 → 分布摘要；n<20 不出百分位（样本不足）。"""
    clean = sorted(v for v in values if v is not None)
    n = len(clean)
    out = {"n": n, "missing": sum(1 for v in values if v is None)}
    if n == 0:
        out["note"] = "样本不足（n=0）：无可用样本"
        return out
    if n < PERCENTILE_MIN_N:
        note = f"样本不足（n={n}）：小于 {PERCENTILE_MIN_N} 不出百分位"
        out.update({"note": note + "，列全部样本",
                    "samples_s": [round(v, 3) for v in clean]})
        return out

    def pct(p):
        idx = min(n - 1, max(0, int(round(p * (n - 1)))))
        return round(clean[idx], 3)

    out.update({"min_s": round(clean[0], 3), "p50_s": pct(0.50),
                "p90_s": pct(0.90), "p95_s": pct(0.95),
                "max_s": round(clean[-1], 3)})
    return out


def build_report(db_path, health=None):
    """读库构建报告 dict。失败抛 MeasureError（含非零 exit_code）。

    查询全部为字面量 SQL，唯一参数（kind/表名）走占位符绑定。
    运行前后核对输入指纹（库+伴随文件），变化抛 IntegrityChanged。
    """
    db_path = Path(db_path)
    _validate_input(db_path)
    before = _input_fingerprint(db_path)
    conn = _connect_readonly(db_path)
    try:
        _require_tables(conn)
        events = [dict(r) for r in conn.execute(
            "SELECT event_id, camera, t_start, t_end, state, end_reason,"
            " evidence_state, payload FROM event_facts ORDER BY t_start")]
        vlm = {r["event_id"]: r["n"] for r in conn.execute(
            "SELECT event_id, COUNT(*) AS n FROM event_descriptions"
            " WHERE source = ? GROUP BY event_id", ("vlm",))}
        notifs = [dict(r) for r in conn.execute(
            "SELECT event_id, created_at, acknowledged_at, user_confirmed_at"
            " FROM event_notifications WHERE kind = ?"
            " ORDER BY created_at", ("initial_fact",))]
    finally:
        conn.close()
    after = _input_fingerprint(db_path)
    if after != before:
        raise IntegrityChanged(
            "输入数据库或伴随文件在测量期间发生变化："
            f"before={sorted(before.items())} after={sorted(after.items())}")

    notify_by_event = {}
    for n in notifs:
        notify_by_event.setdefault(n["event_id"], n)

    per_event = []
    ev_to_notify, notify_to_display = [], []
    ev_window, disp_window = [], []
    trust_kinds = {}
    for ev in events:
        kind = None
        try:
            payload = json.loads(ev["payload"] or "{}")
            if isinstance(payload, dict):
                kind = payload.get("timestamp_kind")
        except (TypeError, ValueError):
            kind = None
        trust_kinds[kind or "none"] = trust_kinds.get(kind or "none", 0) + 1
        trusted = kind == "source_capture"
        notif = notify_by_event.get(ev["event_id"])
        row = {"event_id": ev["event_id"], "camera": ev["camera"],
               "state": ev["state"],
               "end_reason": ev["end_reason"],
               "t_source": ev["t_start"], "timestamp_kind": kind,
               "source_trusted": trusted,
               "t_notify_proxy_event_insert": (notif or {}).get("created_at"),
               "t_display_receipt": (notif or {}).get("acknowledged_at"),
               "t_user_confirm": (notif or {}).get("user_confirmed_at"),
               "evidence_state": ev["evidence_state"],
               "semantic_versions": vlm.get(ev["event_id"], 0)}
        notify_at = row["t_notify_proxy_event_insert"]
        display_at = row["t_display_receipt"]
        if notify_at is not None:
            # 事件落库时间无独立列：notify_at 为其上界代理（如实标注），
            # 只有源钟可信时才构成时延样本，否则计入缺失。
            row["event_to_notify_s"] = (
                round(notify_at - ev["t_start"], 3) if trusted else None)
            if trusted:
                ev_to_notify.append(row["event_to_notify_s"])
                ev_window += [ev["t_start"], notify_at]
            else:
                ev_to_notify.append(None)
            if display_at is not None:
                row["notify_to_display_s"] = round(
                    display_at - notify_at, 3)
                notify_to_display.append(row["notify_to_display_s"])
                disp_window += [notify_at, display_at]
            else:
                row["notify_to_display_s"] = None
                notify_to_display.append(None)
        else:
            row["event_to_notify_s"] = None
            row["notify_to_display_s"] = None
            ev_to_notify.append(None)
            if notify_at is None:
                notify_to_display.append(None)
        per_event.append(row)

    def _window(stamps):
        if not stamps:
            return None
        return {"from": round(min(stamps), 3), "to": round(max(stamps), 3)}

    n_total = len(events)
    no_notify = sum(1 for e in per_event
                    if e["t_notify_proxy_event_insert"] is None)
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
        "tool_version": TOOL_VERSION,
        "generated_note": "离线测量报告：只读落库事实，不宣称质量合格；"
                          "用户确认时间是用户动作事实，不算系统送达速度。",
        "rebuild": {
            "command": "python scripts/measure_report.py --db <本数据库路径>",
            "input_sha256": before["db"],
            "input_sidecars": dict(
                (k, v) for k, v in before.items() if k != "db"),
            "integrity_verified": True,
            "client_online_condition": _CLIENT_ONLINE_NOTE},
        "clock_sources": {
            "t_source": "event_facts.t_start；可信仅当 timestamp_kind=="
                        "source_capture（host_receive=本机收到，非采集时间）",
            "t_event_insert": "无独立时钟列；以 initial_fact created_at 作"
                              "上界代理（字段 t_notify_proxy_event_insert）",
            "t_notify": "event_notifications.created_at（服务端钟）",
            "t_display_receipt": "acknowledged_at（服务端钟，客户端提交回执）",
            "t_user_confirm": "user_confirmed_at（服务端钟，仅用户动作）"},
        "totals": {
            "events": n_total,
            "events_open": sum(1 for e in per_event if e["state"] == "open"),
            "events_without_notification": no_notify,
            "events_with_semantic": sum(1 for e in per_event
                                        if e["semantic_versions"] > 0),
            "source_timestamp_kinds": trust_kinds,
            "user_confirmed_count": sum(
                1 for e in per_event if e["t_user_confirm"] is not None)},
        "latency": {
            "event_to_notify_s": _samples(ev_to_notify),
            "notify_to_display_s": _samples(notify_to_display)},
        "sampling_windows": {
            "event_to_notify_s": _window(ev_window),
            "notify_to_display_s": _window(disp_window),
            "client_online_condition": _CLIENT_ONLINE_NOTE},
        "per_event": per_event}
    if health is not None:
        report["health_snapshot"] = health
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description="Win11 用户闭环测量报告（只读）")
    ap.add_argument("--db", required=True)
    ap.add_argument("--health", default=None,
                    help="可选：运行时 /api/health 快照 JSON，并入报告")
    ap.add_argument("--out", default=None, help="写出 JSON 文件（默认打印）")
    args = ap.parse_args(argv)
    db_path = Path(args.db)
    out_path = Path(args.out) if args.out else None
    try:
        if out_path is not None:
            resolved_out = out_path.resolve()
            resolved_db = db_path.resolve()
            if resolved_out == resolved_db:
                raise OutputInvalid("--out 不得与输入数据库相同")
            for suffix in SIDECAR_SUFFIXES:
                if resolved_out == (resolved_db.parent /
                                    (resolved_db.name + suffix)):
                    raise OutputInvalid(
                                        f"--out 不得覆盖数据库伴随文件 {suffix}")
            if out_path.exists() and out_path.is_dir():
                raise OutputInvalid("--out 指向目录")
        if args.health and not Path(args.health).is_file():
            raise InputInvalid(f"健康快照文件不存在：{args.health}")
        health = None
        if args.health:
            try:
                health = json.loads(
                    Path(args.health).read_text(encoding="utf-8"))
            except (TypeError, ValueError) as exc:
                raise InputInvalid(f"健康快照不是合法 JSON：{exc}") from exc
        report = build_report(db_path, health=health)
    except MeasureError as exc:
        sys.stderr.write(f"measure_report: 失败（exit {exc.exit_code}）："
                         f"{exc}\n")
        return exc.exit_code
    text = json.dumps(report, ensure_ascii=False, indent=1)
    if out_path is not None:
        out_path.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
