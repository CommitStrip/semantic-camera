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
        conf = cam.get("conf")
        if conf is not None and not (isinstance(conf, (int, float)) and 0 < conf <= 1):
            errs.append(f"{cid}: conf 必须在 (0,1]")

        grid = cam.get("grid") or {}
        rows, cols = grid.get("rows", 18), grid.get("cols", 22)
        if not (isinstance(rows, int) and rows >= 4 and isinstance(cols, int) and cols >= 4):
            errs.append(f"{cid}: grid 行列必须为 ≥4 的整数")

        ncells = rows * cols
        zone_ids = set()
        for z in cam.get("zones") or []:
            zid = z.get("id")
            if not zid or zid in zone_ids:
                errs.append(f"{cid}: 区域 id 缺失或重复: {zid}")
                continue
            zone_ids.add(zid)
            cells = z.get("cells")
            if not isinstance(cells, list) or not cells or \
                    not all(isinstance(c, int) and 0 <= c < ncells for c in cells):
                errs.append(f"{cid}: 区域 {zid} 的格子索引非法")
            for r in z.get("rules") or []:
                if not isinstance(r.get("cls"), str):
                    errs.append(f"{cid}: 规则缺少 cls")
                ds = r.get("dwell_s", 0)
                if not (isinstance(ds, (int, float)) and ds >= 0):
                    errs.append(f"{cid}: dwell_s 必须为 ≥0 数值")
                if r.get("severity") not in (None,) + SEVERITIES:
                    errs.append(f"{cid}: severity 非法")

        for w in cam.get("schedule") or []:
            if not (TIME_RE.match(w.get("from", "")) and TIME_RE.match(w.get("to", ""))):
                errs.append(f"{cid}: schedule 必须为 HH:MM 格式")
                break

    return errs


def load_venue(path):
    """读取场所档案 JSON；解析失败抛 ValueError（调用方拒绝布防）。"""
    import io
    with io.open(path, encoding="utf-8") as f:
        return json.load(f)
