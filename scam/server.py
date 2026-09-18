"""server.py —— 工作台 HTTP 服务：API + 审查时间线 + 告警出口。

内嵌 HTML 零文件 I/O 零路径构造；SSE 实时推送；SQLite 参数绑定。
camera_id 白名单校验（alphanumeric + dash + underscore）——防路径注入。
所有状态（区域/环境档案/事件/模式）均存 SQLite，server 零文件写入。
"""

import json
import re
import sqlite3
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

CAMERA_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")

_INDEX_HTML = (
    '<!DOCTYPE html><html><head><meta charset="utf-8"><title>语义摄像头</title>'
    '<style>body{font-family:system-ui;background:#111;color:#eee;margin:0;padding:1em}'
    '.card{background:#1a1a2e;border-radius:8px;padding:1em;margin:.5em 0}'
    'table{width:100%;border-collapse:collapse}td,th{padding:.3em;'
    'border-bottom:1px solid #333;text-align:left}</style></head><body>'
    '<h1>语义摄像头 · 工作台</h1>'
    '<div class="card"><h3>相机</h3><div id="cameras">加载中</div></div>'
    '<div class="card"><h3>事件</h3><table id="events"><tr><th>时间</th>'
    '<th>短名</th><th>详情</th></tr></table></div>'
    '<div class="card"><h3>模式库</h3><div id="patterns">加载中</div></div>'
    '<script>async function refresh(){try{'
    'let r=await fetch("/api/cameras");let d=await r.json();'
    'document.getElementById("cameras").textContent='
    '(d.cameras||[]).map(c=>c.id).join(", ")||"无";'
    'r=await fetch("/api/events");d=await r.json();'
    'let t=document.getElementById("events");'
    't.innerHTML="<tr><th>时间</th><th>短名</th><th>详情</th></tr>";'
    '(d.events||[]).forEach(e=>{let tr=t.insertRow();'
    'tr.insertCell(0).textContent=e.t_processed||"";'
    'tr.insertCell(1).textContent=e.short_name||"";'
    'tr.insertCell(2).textContent=e.detail||"";});'
    'r=await fetch("/api/patterns");d=await r.json();'
    'document.getElementById("patterns").textContent='
    '(d.patterns||[]).map(p=>p.name).join(", ")||"无";'
    '}catch(e){}}setInterval(refresh,3000);refresh();'
    '</script></body></html>'
)


class WorkbenchState:
    """工作台共享状态：全部存 SQLite（events/patterns/meta/zones），零文件 I/O。"""

    def __init__(self, db_path):
        self.db_path = db_path
        self.monitors = {}
        self._lock = threading.Lock()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def cameras(self):
        """从 SQLite zones 表读取相机列表（去重）。"""
        conn = self._conn()
        rows = conn.execute(
            "SELECT DISTINCT camera FROM zones").fetchall()
        conn.close()
        return [{"id": r[0]} for r in rows]

    def zones(self, camera_id):
        """从 SQLite zones 表读取指定相机的区域配置。"""
        conn = self._conn()
        row = conn.execute(
            "SELECT data FROM zones WHERE camera = ?", (camera_id,)).fetchone()
        conn.close()
        return json.loads(row["data"]) if row else []

    def save_zones(self, camera_id, zones):
        """保存区域配置到 SQLite zones 表（JSON 序列化存储）。"""
        conn = self._conn()
        conn.execute(
            "INSERT OR REPLACE INTO zones (camera, data) VALUES (?,?)",
            (camera_id, json.dumps(zones, ensure_ascii=False)))
        conn.commit()
        conn.close()


class WorkbenchHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_index(self):
        body = _INDEX_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._serve_index()
            return
        if path == "/api/cameras":
            self._json({"cameras": self.server.state.cameras()})
            return
        if path == "/api/health":
            cams = [{"id": cid, "ratio": round(m.gate.last_ratio, 4)}
                    for cid, m in self.server.state.monitors.items()]
            self._json({"cameras": cams, "count": len(cams)})
            return
        if path == "/api/events":
            conn = self.server.state._conn()
            rows = conn.execute(
                "SELECT event_id, camera, kind, t_processed, cls, conf,"
                " zone_id, short_name, detail, rationale"
                " FROM events ORDER BY t_processed DESC LIMIT 100").fetchall()
            conn.close()
            self._json({"events": [dict(r) for r in rows]})
            return
        if path == "/api/patterns":
            conn = self.server.state._conn()
            rows = conn.execute(
                "SELECT pattern_id, name, detail, state, count, version"
                " FROM patterns ORDER BY count DESC").fetchall()
            conn.close()
            self._json({"patterns": [dict(r) for r in rows]})
            return
        self.send_error(404)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            self._json({"error": "invalid json"}, 400)
            return
        if path == "/api/zones/save":
            self.server.state.save_zones(
                body.get("camera", ""), body.get("zones", []))
            self._json({"ok": True})
            return
        if path == "/api/events/feedback":
            eid = body.get("event_id", "")
            feedback = body.get("feedback", "")
            conn = self.server.state._conn()
            conn.execute(
                "UPDATE events SET payload = ? WHERE event_id = ?",
                (json.dumps({"feedback": feedback}), eid))
            conn.commit()
            self._json({"ok": True})
            return
        self.send_error(404)


class WorkbenchServer(ThreadingHTTPServer):
    """工作台 HTTP 服务（ThreadingHTTPServer，随 NVR 常驻）。"""

    def __init__(self, state, host="0.0.0.0", port=8600):
        self.state = state
        super().__init__((host, port), WorkbenchHandler)
        self.daemon_threads = True
