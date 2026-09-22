"""config.py —— 场所档案（venue profile）加载与 fail-closed 校验。

场所档案 = 唯一配置产物，两层：
  venue   场所语义层（多相机共享）：名称等
  cameras 相机工程层（单相机视角）：源/检测绑定/网格/区域/规则/布防表

校验 fail-closed：任何不合法 → 返回错误列表，调用方拒绝布防。
"""

import json

TIME_RE = __import__("re").compile(r"^([01]\d|2[0-3]):[0-5]\d$")
PRESET_TEMPLATES = ("enter-dwell", "loiter", "immediate")
ENGINES = ("onnx", "none")
SEVERITIES = ("high", "medium", "low")


def validate_venue(v):
    """校验场所档案，返回错误列表（空列表=合法）。"""
    errs = []
    if not isinstance(v, dict):
        return ["场所档案必须为对象"]
    cams = v.get("cameras")
    if not isinstance(cams, list) or not cams:
        return ["cameras 必须为非空数组"]

    seen_ids = set()
    for cam in cams:
        if not isinstance(cam, dict):
            errs.append("相机条目必须为对象")
            continue
        cid = cam.get("id")
        if not cid or not isinstance(cid, str):
            errs.append("相机缺少非空 id")
            continue
        if cid in seen_ids:
            errs.append(f"相机 id 重复: {cid}")
        seen_ids.add(cid)

        if not isinstance(cam.get("source"), str) or not cam["source"]:
            errs.append(f"{cid}: source 必须为非空字符串")

        det = cam.get("detector")
        if not isinstance(det, dict):
            errs.append(f"{cid}: detector 必须为对象")
            continue
        engine = det.get("engine")
        if engine not in ENGINES:
            errs.append(f"{cid}: detector.engine 必须为 onnx|none")
        if engine == "onnx":
            if not isinstance(det.get("model"), str) or not det["model"]:
                errs.append(f"{cid}: onnx 引擎必须给 model 路径")
            classes = det.get("classes")
            if not isinstance(classes, list) or not classes or \
                    not all(isinstance(c, str) for c in classes):
                errs.append(f"{cid}: classes 必须为非空字符串数组")
        # 校验 detector.conf——与运行时 _make_detector 读的字段一致（此前错查 cam.conf）
        conf = det.get("conf")
        if conf is not None and not (isinstance(conf, (int, float)) and 0 < conf <= 1):
            errs.append(f"{cid}: detector.conf 必须在 (0,1]")

        # 源角色（Z2）：source 为兼容真值（缺省同 URL 双角色），可按角色覆盖；
        # 录像默认关闭——配置缺省绝不开启 24/7 录像。
        kind = cam.get("source_kind")
        if kind is not None and kind not in ("rtsp", "file", "camera"):
            errs.append(f"{cid}: source_kind 必须为 rtsp|file|camera")
        for role_key in ("detect_source", "record_source"):
            val = cam.get(role_key)
            if val is not None and (not isinstance(val, str) or not val):
                errs.append(f"{cid}: {role_key} 必须为非空字符串")
        record_enabled = cam.get("record_enabled")
        if record_enabled is not None and not isinstance(record_enabled, bool):
            errs.append(f"{cid}: record_enabled 必须为布尔（缺省 False，不默认录像）")
        for key, default_min, allow_zero in (
                ("record_retention_days", 0, True),
                ("record_cap_gb", 0, False),
                ("record_segment_seconds", 10, False)):
            value = cam.get(key)
            if value is None:
                continue
            valid_number = isinstance(value, (int, float)) and \
                not isinstance(value, bool)
            valid_range = value >= default_min if allow_zero \
                else value > default_min
            if not (valid_number and valid_range):
                relation = "≥0" if allow_zero else f">{default_min}"
                errs.append(f"{cid}: {key} 必须为 {relation} 的数值")
        # V-JEPA 段嵌入模型（可选）：字符串路径；缺席=纯结构匹配（零成本降级）
        embed_model = cam.get("slow_embed_model")
        if embed_model is not None and (not isinstance(embed_model, str)
                                        or not embed_model):
            errs.append(f"{cid}: slow_embed_model 必须为非空字符串（可选）")

        grid = cam.get("grid")
        if grid is not None and not isinstance(grid, dict):
            errs.append(f"{cid}: grid 必须为对象")
            grid = {}
        rows = grid.get("rows", 18) if isinstance(grid, dict) else 18
        cols = grid.get("cols", 22) if isinstance(grid, dict) else 22
        if not (isinstance(rows, int) and rows >= 4 and isinstance(cols, int) and cols >= 4):
            errs.append(f"{cid}: grid 行列必须为 ≥4 的整数")

        ncells = rows * cols
        zone_ids = set()
        zones = cam.get("zones")
        if zones is not None and not isinstance(zones, list):
            errs.append(f"{cid}: zones 必须为数组")
            zones = []
        for z in zones or []:
            if not isinstance(z, dict):
                errs.append(f"{cid}: 区域必须为对象")
                continue
            zid = z.get("id")
            if not zid or zid in zone_ids:
                errs.append(f"{cid}: 区域 id 缺失或重复: {zid}")
                continue
            zone_ids.add(zid)
            cells = z.get("cells")
            if not isinstance(cells, list) or not cells or \
                    not all(isinstance(c, int) and 0 <= c < ncells for c in cells):
                errs.append(f"{cid}: 区域 {zid} 的格子索引非法")
            rules = z.get("rules")
            if rules is not None and not isinstance(rules, list):
                errs.append(f"{cid}: 区域 {zid} 的 rules 必须为数组")
                rules = []
            for r in rules or []:
                if not isinstance(r, dict):
                    errs.append(f"{cid}: 规则必须为对象")
                    continue
                if not isinstance(r.get("cls"), str):
                    errs.append(f"{cid}: 规则缺少 cls")
                ds = r.get("dwell_s", 0)
                if not (isinstance(ds, (int, float)) and ds >= 0):
                    errs.append(f"{cid}: dwell_s 必须为 ≥0 数值")
                if r.get("severity") not in (None,) + SEVERITIES:
                    errs.append(f"{cid}: severity 非法")

        schedule = cam.get("schedule")
        if schedule is not None and not isinstance(schedule, list):
            errs.append(f"{cid}: schedule 必须为数组")
            schedule = []
        for w in schedule or []:
            if not isinstance(w, dict) or not (
                    TIME_RE.match(w.get("from", ""))
                    and TIME_RE.match(w.get("to", ""))):
                errs.append(f"{cid}: schedule 必须为 HH:MM 格式")
                break

    errs.extend(_validate_notify(v))
    return errs


def _validate_notify(v):
    """通知出口配置（可选顶层 notify 段）——fail-closed 校验。"""
    errs = []
    notify = v.get("notify")
    if notify is None:
        return errs
    if not isinstance(notify, dict):
        return ["notify 必须为对象"]
    mqtt = notify.get("mqtt")
    if mqtt is not None:
        if not isinstance(mqtt, dict) or not mqtt.get("host") or \
                not isinstance(mqtt.get("host"), str):
            errs.append("notify.mqtt 必须为对象且 host 为非空字符串")
        else:
            port = mqtt.get("port", 1883)
            if not (isinstance(port, int) and not isinstance(port, bool)
                    and 1 <= port <= 65535):
                errs.append("notify.mqtt.port 必须为 1..65535 整数")
            for key in ("topic_prefix", "user", "pass"):
                val = mqtt.get(key)
                if val is not None and not isinstance(val, str):
                    errs.append(f"notify.mqtt.{key} 必须为字符串")
    webhook = notify.get("webhook")
    if webhook is not None:
        if not isinstance(webhook, dict) or \
                not isinstance(webhook.get("url"), str) or \
                not webhook["url"].lower().startswith(
                    ("http://", "https://")):
            errs.append("notify.webhook 必须为对象且 url 为 http(s) 字符串")
    return errs


def load_venue(path):
    """读取场所档案 JSON；解析失败抛 ValueError（调用方拒绝布防）。"""
    import io
    with io.open(path, encoding="utf-8") as f:
        return json.load(f)
