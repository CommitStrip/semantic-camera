"""scam.notify —— 通知出口（MQTT + webhook，可选启用）。

独立线程扫 semantic_events 增量（游标存 meta.notify:cursor）→ 发布：
- MQTT（topic: <prefix>/<camera>/alarm，QoS 1）：paho-mqtt 为**可选依赖**
  （pyproject extras [mqtt]），缺席时该出口降级并在 health 披露；
- webhook（POST 事件 JSON）：仅管理员显式配置的 URL；每次发布前执行
  目标校验（scheme 限 http/https、拒绝 userinfo、解析后 IP 分类记录
  loopback/private/public 入状态供审计）；禁止重定向；超时与体积上限固定。

纪律：出口任何失败只计数降级（publish_failures/last_error），绝不阻断
告警落库（DEC-004 同纪律）；重启后游标回退一个窗口=at-least-once 重发
（去重由订阅方按 event id 做）；未配置 notify 段=线程不启动、零开销。
"""

import ipaddress
import json
import socket
import threading
import time
import urllib.error
import urllib.request

from .db import connect

DEFAULT_INTERVAL_S = 2.0
WEBHOOK_TIMEOUT_S = 5.0
MAX_EVENT_BYTES = 64 * 1024
RESEND_WINDOW_S = 30.0     # 重启后重发窗口（at-least-once 语义）
MAX_DELIVERY_ATTEMPTS = 5  # 单事件投递尝试上限（防毒丸阻塞游标）


def _sanitize_event(row):
    """事件 → 通知载荷：只含可读事实字段（无路径/凭据/自由文本细节）。"""
    return {
        "schema": "scam.notify/v1",
        "event_id": row["semantic_event_id"],
        "camera": row["camera"],
        "t_start": row["t_start"],
        "t_end": row["t_end"],
        "state": row["state"],
        "cls": row["cls"],
        "conf": row["conf"],
        "zone_id": row["zone_id"],
        "template": row["template"],
        "severity": row["severity"],
        "short_name": row["short_name"],
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """webhook 目标禁止重定向：防 302 跳转到未审计地址（含云元数据）。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError(f"webhook 拒绝重定向到 {newurl}")


def assert_webhook_target(url):
    """发布前目标校验：scheme 白名单、拒绝 userinfo、解析 IP 分类审计。

    私网/环回是**合法目标**（n8n/Home Assistant 等内网自动化是产品场景）；
    校验的作用是把目标地址类别如实记录（loopback/private/public）供管理员
    审计，而不是冒充安全判断。返回类别字符串；非法目标抛 ValueError。
    """
    parsed = urllib.request.urlparse(str(url))
    if parsed.scheme not in ("http", "https"):
        raise ValueError("webhook url 必须为 http(s)")
    if parsed.username or parsed.password:
        raise ValueError("webhook url 不得携带 userinfo")
    host = parsed.hostname
    if not host:
        raise ValueError("webhook url 缺少主机名")
    kinds = set()
    try:
        for info in socket.getaddrinfo(host, parsed.port or 80):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_loopback:
                kinds.add("loopback")
            elif ip.is_private or ip.is_link_local:
                kinds.add("private")
            else:
                kinds.add("public")
    except OSError:
        pass                     # 解析失败不阻断：发布时的连接错误会如实计数
    return "+".join(sorted(kinds)) if kinds else "unresolved"


class MqttOutlet:
    """paho-mqtt 薄封装：缺席/连接失败降级可见，不抛出。"""

    def __init__(self, cfg):
        self.host = cfg["host"]
        self.port = int(cfg.get("port", 1883))
        self.prefix = str(cfg.get("topic_prefix", "scam"))
        self.client = None
        self.error = None
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            self.error = "paho-mqtt not installed (extras: pip install " \
                         "scam[mqtt])"
            return
        client = mqtt.Client()
        if cfg.get("user"):
            client.username_pw_set(cfg["user"], cfg.get("pass", ""))
        # P1-5：连接移入后台线程——broker 不可达时不阻塞 NVR 启动；
        # 连接结果异步进 status（connected/error）。
        self._connecting = True
        def _bg_connect():
            try:
                client.connect(self.host, self.port, keepalive=30)
                client.loop_start()
                self.client = client
            except Exception as exc:
                self.error = f"mqtt connect failed: {type(exc).__name__}"
            finally:
                self._connecting = False
        threading.Thread(target=_bg_connect, name="scam-mqtt-connect",
                         daemon=True).start()

    def publish(self, event):
        if self.client is None:
            return False
        topic = f"{self.prefix}/{event['camera']}/alarm"
        try:
            info = self.client.publish(
                topic, json.dumps(event, ensure_ascii=False), qos=1)
            return info.rc == 0
        except Exception:
            return False

    def stop(self):
        if self.client is not None:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass

    def status(self):
        return {"configured": True, "connected": self.client is not None,
                "connecting": getattr(self, "_connecting", False),
                "error": self.error}


class WebhookOutlet:
    """POST 事件 JSON 到管理员显式配置的 URL；失败计数降级不抛出。"""

    def __init__(self, cfg):
        self.url = cfg["url"]
        self.error = None
        self.target_kind = None
        if not isinstance(self.url, str):
            self.error = "webhook url 必须为字符串"
            return
        try:
            self.target_kind = assert_webhook_target(self.url)
        except ValueError as exc:
            self.error = str(exc)

    def publish(self, event):
        if self.error:
            return False
        try:
            # 每次发布前重校验：管理员改 DNS/目标漂移时类别如实更新
            self.target_kind = assert_webhook_target(self.url)
        except ValueError:
            return False
        try:
            body = json.dumps(event, ensure_ascii=False).encode("utf-8")
            if len(body) > MAX_EVENT_BYTES:
                return False
            req = urllib.request.Request(
                self.url, data=body, method="POST",
                headers={"Content-Type": "application/json"})
            opener = urllib.request.build_opener(_NoRedirect)
            with opener.open(req, timeout=WEBHOOK_TIMEOUT_S) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    def stop(self):
        pass

    def status(self):
        return {"configured": True, "url_ok": self.error is None,
                "target_kind": self.target_kind, "error": self.error}


class NotificationHub:
    """增量扫描 + 双出口发布 + 观测快照（health 数据源）。"""

    def __init__(self, db_path, notify_cfg, *, stop_event=None,
                 interval_s=DEFAULT_INTERVAL_S):
        self.db_path = db_path
        self.interval_s = max(0.5, float(interval_s))
        self.stop_event = stop_event or threading.Event()
        self.mqtt = MqttOutlet(notify_cfg["mqtt"]) \
            if notify_cfg.get("mqtt") else None
        self.webhook = WebhookOutlet(notify_cfg["webhook"]) \
            if notify_cfg.get("webhook") else None
        self._thread = None
        self.counters = {"events_seen": 0, "mqtt_ok": 0, "mqtt_failed": 0,
                         "webhook_ok": 0, "webhook_failed": 0, "rounds": 0}
        self.last_error = None

    # ---------- 生命周期 ----------

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return False
        self._thread = threading.Thread(
            target=self._run, name="scam-notify", daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout=5.0):
        self.stop_event.set()
        if self._thread is None:
            return True
        self._thread.join(timeout=timeout)
        for outlet in (self.mqtt, self.webhook):
            if outlet is not None:
                outlet.stop()
        return self._thread is None or not self._thread.is_alive()

    def _run(self):
        conn = connect(self.db_path)
        try:
            while not self.stop_event.wait(self.interval_s):
                try:
                    self._round(conn)
                except Exception as exc:
                    self.last_error = type(exc).__name__
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ---------- 增量扫描与发布 ----------

    def _cursor(self, conn):
        row = conn.execute(
            "SELECT value FROM meta WHERE key='notify:cursor'").fetchone()
        try:
            return float(row[0]) if row else 0.0
        except (TypeError, ValueError):
            return 0.0

    def _attempts(self, conn, event_id):
        row = conn.execute(
            "SELECT value FROM meta WHERE key=?",
            (f"notify:fail:{event_id}",)).fetchone()
        try:
            return int(row[0]) if row else 0
        except (TypeError, ValueError):
            return 0

    def _round(self, conn):
        """成败感知投递（P0-2）：游标只推进到"已送达或已放弃"边界。

        任一启用出口失败→该事件保持未决（游标不越过它，下轮重扫重投）；
        单事件尝试超上限→放弃（dropped 计数）不再阻塞游标——at-least-once
        对运行期失败同样成立（不只救崩溃）。
        """
        now = time.time()
        cursor = self._cursor(conn)
        since = max(0.0, cursor - RESEND_WINDOW_S) if cursor > 0 else 0.0
        rows = conn.execute(
            "SELECT semantic_event_id,camera,t_start,t_end,state,cls,conf,"
            " zone_id,template,severity,short_name FROM semantic_events"
            " WHERE t_start > ? AND t_start <= ? ORDER BY t_start LIMIT 50",
            (since, now)).fetchall()
        if not rows:
            self.counters["rounds"] += 1
            self.last_error = None
            return
        # 逐事件按 t_start 升序投递；游标=已决前缀（送达/放弃）的最大值
        decided_max = None
        undelivered_earliest = None
        for row in rows:
            event = _sanitize_event(row)
            attempts = self._attempts(conn, event["event_id"])
            if attempts >= MAX_DELIVERY_ATTEMPTS:
                self.counters["events_seen"] += 1
                self.counters["dropped"] = self.counters.get("dropped", 0) + 1
                decided_max = float(row["t_start"])
                continue
            ok = True
            if self.mqtt is not None:
                if self.mqtt.publish(event):
                    self.counters["mqtt_ok"] += 1
                else:
                    ok = False
                    self.counters["mqtt_failed"] += 1
            if self.webhook is not None:
                if self.webhook.publish(event):
                    self.counters["webhook_ok"] += 1
                else:
                    ok = False
                    self.counters["webhook_failed"] += 1
            self.counters["events_seen"] += 1
            if ok:
                conn.execute(
                    "DELETE FROM meta WHERE key=?",
                    (f"notify:fail:{event['event_id']}",))
                decided_max = float(row["t_start"])
            else:
                conn.execute(
                    "INSERT INTO meta (key,value) VALUES (?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (f"notify:fail:{event['event_id']}", str(attempts + 1)))
                undelivered_earliest = float(row["t_start"])
                break            # 保持前缀语义：停在这条，不决后续
        conn.commit()
        # 游标推进：无未决→最大已决；有未决→未决前一条（含重发窗口冗余）
        target = decided_max if undelivered_earliest is None \
            else undelivered_earliest - 1.0
        if target is not None and (cursor == 0 or target > cursor):
            conn.execute(
                "INSERT INTO meta (key,value) VALUES ('notify:cursor',?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(target),))
            conn.commit()
        self.counters["rounds"] += 1
        self.last_error = None

    # ---------- 观测 ----------

    def snapshot(self):
        return {
            "enabled": True,
            "mqtt": self.mqtt.status() if self.mqtt else None,
            "webhook": self.webhook.status() if self.webhook else None,
            "counters": dict(self.counters),
            "last_error": self.last_error,
        }
