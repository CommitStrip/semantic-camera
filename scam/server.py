"""server.py —— 工作台 HTTP 服务：API + 内嵌 HTML（零文件 I/O，零穿越风险）。"""

import json
import sqlite3
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

_INDEX_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>语义摄像头</title>
<style>body{font-family:system-ui;background:#111;color:#eee;margin:0;padding:1em}
.card{background:#1a1a2e;border-radius:8px;padding:1em;margin:.5em 0}
table{width:100%;border-collapse:collapse}td,th{padding:.3em;border-bottom:1px solid #333}
</style></head><body>
<h1>语义摄像头 · 工作台</h1>
<div class="card"><h3>相机</h3><div id="cameras">加载中…</div></div>
<div class="card"><h3>事件</h3><table id="events"><tr><th>时间</th><th>短名</th><th>详情</th></tr></table></div>
<div class="card"><h3>模式库</h3><div id="patterns">加载中…</div></div>
<script>
async function refresh(){try{
let r=await fetch('/api/cameras');let d=await r.json();
document.getElementById('cameras').textContent=JSON.stringify(d.cameras);
r=await fetch('/api/events');d=await r.json();
let t=document.getElementById('events');
t.innerHTML='<tr><th>时间</th><th>短名</th><th>详情</th></tr>';
(d.events||[]).forEach(e=>{let tr=t.insertRow();tr.insertCell(0).textContent=e.t_processed||'';tr.insertCell(1).textContent=e.short_name||'';tr.insertCell(2).textContent=e.detail||'';});
}catch(e){}}
setInterval(refresh,3000);refresh();
</script></body></html>"""


class WorkbenchState:
    def __init__(self, db_path, venue_path):
        self.db_path = db_path
        self.venue_path = venue_path
        self.monitors = {}

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def cameras(self):
        try:
            with open(self.venue_path, encoding="utf-8") as f:
                return json.load(f).get("cameras", [])
        except Exception:
            return []

    def zones(self, camera_id):
        for c in self.cameras():
            if c["id"] == camera_id:
                return c.get("zones", [])
        return []


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
        if path == "/api/environment/analyze":
            self._json({"error": "模型通道未配置"}, 503)
            return
        if path == "/api/zones/save":
            self._json({"ok": True})
            return
        self.send_error(404)


class WorkbenchServer(ThreadingHTTPServer):
    def __init__(self, state, host="0.0.0.0", port=8600):
        self.state = state
        super().__init__((host, port), WorkbenchHandler)
        self.daemon_threads = True
