"""config.py —— 场所档案（venue profile）加载与 fail-closed 校验。

场所档案 = 唯一配置产物，两层：
  venue   场所语义层（多相机共享）：名称等
  cameras 相机工程层（单相机视角）：源/检测绑定/网格/区域/规则/布防表

校验 fail-closed：任何不合法 → 返回错误列表，调用方拒绝布防。
"""

import json
import copy
from pathlib import Path, PureWindowsPath
import re
import sys
from urllib.parse import urlsplit

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

    errs.extend(_validate_models(v))
    errs.extend(_validate_notify(v))
    if "l3" in v:
        errs.extend(validate_l3_config(v["l3"]))
    if "asset_paths" in v:
        errs.extend(_validate_asset_paths(v["asset_paths"]))
    return errs


def validate_l3_config(value):
    """离线配置合同；只校验字面值，不查询DNS或验证远端模型能力。"""
    if not isinstance(value, dict):
        return ["l3 必须为对象"]
    errors = []
    if "enabled" in value and type(value["enabled"]) is not bool:
        errors.append("l3.enabled 必须为布尔")
    provider = value.get("provider", "local")
    if provider not in ("local", "cloud"):
        errors.append("l3.provider 必须为 local|cloud")
        return errors
    # 禁止在任意L3配置内保存密钥字面值，连禁用配置也不能携带。
    pending = [value]
    secret_literal = False
    while pending:
        entry = pending.pop()
        if isinstance(entry, dict):
            secret_literal |= any(str(key).casefold() in
                                  ("api_key", "token", "password") for key in entry)
            pending.extend(entry.values())
        elif isinstance(entry, list):
            pending.extend(entry)
    if secret_literal:
        errors.append("l3 不接受密钥字面值，请仅填写 key_env 环境变量名")
    if provider == "local":
        if value.get("enabled") is True:
            path = value.get("model_path")
            if not isinstance(path, str) or not path.strip() or len(path) > 4096:
                errors.append("启用本地 L3 时必须填写 model_path")
        return errors
    if value.get("image_upload_consent") is not True:
        errors.append("使用云端理解前必须明确同意外发图片")
    if value.get("vision_capable") is not True:
        errors.append("必须明确声明所选云模型支持图片；此声明不是能力验证")
    base = value.get("base_url")
    try:
        valid = isinstance(base, str) and 0 < len(base) <= 2048
        valid = valid and not any(c.isspace() or ord(c) < 32 for c in base)
        parsed = urlsplit(base) if valid else None
        valid = valid and parsed.scheme == "https" and bool(parsed.hostname)
        valid = valid and not parsed.username and not parsed.password and "@" not in parsed.netloc
        valid = valid and "?" not in base and "#" not in base and "\\" not in base
        if valid:
            port = parsed.port  # 坏端口/IPv6结构在保存前拒绝；不访问网络。
            valid = port is None or 1 <= port <= 65535
    except ValueError:
        valid = False
    if not valid:
        errors.append("l3.base_url 必须为无凭据、查询或片段的 HTTPS API 前缀")
    model = value.get("model")
    if (not isinstance(model, str) or not model.strip() or len(model) > 256
            or any(ord(c) < 32 for c in model)):
        errors.append("l3.model 必须为非空云模型名称")
    env = value.get("key_env")
    if not isinstance(env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", env):
        errors.append("l3.key_env 必须为合法环境变量名，不是密钥内容")
    return errors


def _validate_models(v):
    """模型通道配置（可选顶层 models 段）——本地通道可指定本地模型名。"""
    models = v.get("models")
    if models is None:
        return []
    if not isinstance(models, dict):
        return ["models 必须为对象"]
    errs = []
    channel = models.get("channel", "local")
    if channel not in ("local", "cloud"):
        errs.append("models.channel 必须为 local|cloud")
    for key in ("model", "base"):
        value = models.get(key)
        if value is not None and (not isinstance(value, str) or not value):
            errs.append(f"models.{key} 必须为非空字符串")
    if channel == "cloud" and not models.get("model"):
        errs.append("models.channel=cloud 时必须指定 models.model")
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
        value = json.load(f)
    return resolve_venue_asset_paths(value, path)


def _validate_asset_paths(value):
    if (not isinstance(value, dict)
            or value.get("schema") != "scam.package-assets/v1"
            or value.get("root") not in ("config", "install")
            or set(value) - {"schema", "root"}):
        return ["asset_paths 必须声明 scam.package-assets/v1 与 config|install 根"]
    return []


def _frozen_install_root():
    """仅识别正式 backend 子目录布局；不依赖cwd或向任意父目录搜索。"""
    if not getattr(sys, "frozen", False):
        raise ValueError("源码运行的 install 资产模式需要显式 install_root")
    executable = Path(sys.executable).resolve()
    if (not executable.is_file()
            or executable.name.casefold() != "semantic-camera-backend.exe"
            or executable.parent.name.casefold() != "backend"
            or not (executable.parent.parent / "SemanticCamera.Desktop.dll").is_file()):
        raise ValueError("install 资产根不符合桌面壳/backend 安装布局")
    return executable.parent.parent


def resolve_venue_asset_paths(value, path, install_root=None):
    """仅显式打包配置解析模型资产；无marker和用户绝对路径原样保留。

    config根为配置父目录；install根为显式绝对根或严格冻结桌面布局。
    不修改输入、不chdir、不检查/载入模型，不触碰相机source和凭据。
    """
    if not isinstance(value, dict) or "asset_paths" not in value:
        return value
    marker = value["asset_paths"]
    errors = _validate_asset_paths(marker)
    if errors:
        raise ValueError(errors[0])
    if marker["root"] == "config":
        root = Path(path).resolve().parent
    elif install_root is not None:
        root = Path(install_root)
        if not root.is_absolute():
            raise ValueError("install_root 必须为显式绝对路径")
        root = root.resolve()
    else:
        root = _frozen_install_root()
    result = copy.deepcopy(value)

    def rewrite(container, key):
        if not isinstance(container, dict) or key not in container:
            return
        text = container[key]
        if text is None or text == "":
            return
        if not isinstance(text, str) or any(ord(c) < 32 for c in text):
            raise ValueError("打包模型资产路径必须为无控制字符的字符串")
        windows = PureWindowsPath(text)
        if windows.is_absolute() or Path(text).is_absolute():
            return  # 显式用户绝对路径不改写、不访问。
        if windows.drive or windows.root or ":" in text:
            raise ValueError("打包模型资产路径不能为含糊的驱动器相对路径")
        target = (root / text).resolve()
        if not target.is_relative_to(root):
            raise ValueError("打包模型资产相对路径越出已声明根")
        container[key] = str(target)

    cameras = result.get("cameras")
    for camera in cameras if isinstance(cameras, list) else ():
        if isinstance(camera, dict):
            rewrite(camera.get("detector"), "model")
    for key in ("repo_path", "checkpoint"):
        rewrite(result.get("l2"), key)
    local = result.get("l3")
    if isinstance(local, dict) and local.get("provider", "local") == "local":
        rewrite(local, "model_path")
    return result
