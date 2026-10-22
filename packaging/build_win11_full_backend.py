"""完整后端构建器 v2（四态分离/清单树外/硬失败/敏感件拒发）。

产出：PyInstaller onedir 冻结后端 + `_deps/` 旁置依赖树 + 树外 provenance
与校验清单。运行 hook 随源码位于 `packaging/runtime_hook_deps.py`。
"""
from __future__ import annotations
import argparse, hashlib, importlib.metadata as md, json, os, pathlib, re, shutil, subprocess, sys

REPO = pathlib.Path(__file__).resolve().parents[1]
ENTRY = REPO / "packaging" / "win11_exe_entry.py"
PREVIEW = REPO / "packaging" / "build_win11.py"
# 构建产物根（dist/build/spec/自检/日志/树外 provenance）；默认在仓库 build/ 下。
WORK = REPO / "build" / "win11-full-backend"
APP = "semantic-camera-backend"
PIN = "6.21.0"
HEAVY = ("torch", "transformers", "torchvision")
DEPS = ("torch", "transformers", "tokenizers", "safetensors",
        "huggingface_hub", "onnxruntime", "cv2", "numpy")
SENSITIVE = ("EBWebView", "User Data", "Cookies", "Local Storage",
             "Service Worker", "GPUCache", ".ldb", ".log", ".mp4", ".jpg",
             ".png", ".db", ".db-wal", ".db-shm")
HOOK = REPO / "packaging" / "runtime_hook_deps.py"


def sha(path, chunk=1 << 20):
    d = hashlib.sha256()
    with path.open("rb") as h:
        while True:
            b = h.read(chunk)
            if not b:
                break
            d.update(b)
    return d.hexdigest()


def deps_tree_digest(root):
    """整棵 `_deps` 树摘要：相对路径 + 每文件 sha256（大小写敏感路径序）。"""
    root = pathlib.Path(root)
    digest = hashlib.sha256()
    if not root.is_dir():
        return "absent"
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel = str(path.relative_to(root)).replace("\\", "/")
            digest.update(rel.encode("utf-8", "replace"))
            digest.update(sha(path).encode("ascii"))
    return digest.hexdigest()


def selfcheck_report_valid(exe_path, deps_root, report):
    """严格校验：类型必须是 dict / bool is True；任何异常转为可审计拒绝。"""
    problems = []
    try:
        if not isinstance(report, dict):
            return False, ["report_not_object"]
        if report.get("ok") is not True:
            problems.append("report_ok_not_true")
        exe_hash = report.get("exe_sha256")
        if not isinstance(exe_hash, str):
            problems.append("exe_sha256_not_str")
        elif exe_hash != sha(pathlib.Path(exe_path)):
            problems.append("exe_mismatch")
        deps_hash = report.get("deps_tree_sha256")
        if not isinstance(deps_hash, str):
            problems.append("deps_digest_not_str")
        elif deps_hash != deps_tree_digest(deps_root):
            problems.append("deps_tree_mismatch")
        modules = report.get("modules")
        if not isinstance(modules, dict):
            problems.append("modules_not_dict")
        else:
            for name in ("torch", "transformers", "tokenizers", "safetensors",
                         "onnxruntime"):
                entry = modules.get(name)
                if not isinstance(entry, dict):
                    problems.append("module_not_dict:" + name)
                elif entry.get("ok") is not True:
                    problems.append("import_not_true:" + name)
    except Exception as exc:
        return False, ["validator_error:" + type(exc).__name__]
    return (not problems), problems


def _emit(result, json_out):
    """所有分支落盘；独占写（不带覆盖旧证据）。"""
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if json_out:
        path = pathlib.Path(json_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as handle:   # 独占：已存在即失败
            handle.write(payload)
    print(payload)


def installed():
    out = {}
    for name in ("pyinstaller", "numpy", "opencv-python", "onnxruntime", *HEAVY):
        try:
            out[name] = md.version(name)
        except Exception:
            out[name] = None
    return out


def hf_models():
    hub = pathlib.Path(os.environ.get("USERPROFILE", "")) / ".cache" / "huggingface" / "hub"
    found = []
    if hub.is_dir():
        for d in sorted(hub.iterdir()):
            if d.is_dir() and d.name.startswith("models--"):
                found.append({"repo": d.name[7:].replace("--", "/"),
                              "bytes": sum(p.stat().st_size for p in d.rglob("*") if p.is_file())})
    return found


def resources():
    import ctypes

    class MS(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
    s = MS(); s.dwLength = ctypes.sizeof(MS)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s))
    return {"ram_available_bytes": s.ullAvailPhys,
            "disk_free_C": shutil.disk_usage("C:\\").free,
            "disk_free_D": shutil.disk_usage("D:\\").free}


def deps_tree(app=None):
    root = (app or (WORK / "out" / "dist" / APP)) / "_deps"
    present = {n: (root / n.split(".")[0]).exists() for n in DEPS}
    return {"path": "_deps", "exists": root.is_dir(), "present": present,
            "complete": root.is_dir() and all(present.values())}


def check():
    res, deps = resources(), installed()
    problems = []
    if deps["pyinstaller"] != PIN:
        problems.append("pyinstaller_pin:" + str(deps["pyinstaller"]))
    for n in ("numpy", "opencv-python", "onnxruntime", *HEAVY):
        if not deps[n]:
            problems.append("missing:" + n)
    if not (REPO / "models" / "person-detector.onnx").is_file():
        problems.append("missing:models/person-detector.onnx")
    ram, disk = res["ram_available_bytes"], max(res["disk_free_C"], res["disk_free_D"])
    modes = {}
    for name, need_ram, need_disk in (("sideload", 2.0, 2.5), ("full-freeze", 10.0, 12.0)):
        modes[name] = {"allowed": ram >= need_ram * 1024 ** 3 and disk >= need_disk * 1024 ** 3,
                       "ram_have_GiB": round(ram / 1024 ** 3, 2), "ram_need_GiB": need_ram,
                       "disk_have_GiB": round(disk / 1024 ** 3, 2), "disk_need_GiB": need_disk}
    return {"ok": not problems, "problems": problems, "deps": deps,
            "resources": res, "modes": modes, "hf_models_local": hf_models(),
            "model_config_parse_only": "AutoConfig(trust_remote_code, local_files_only) 仅证明自定义配置可解析；不代表权重可加载或推理可用",
            "deps_tree": deps_tree(), "hook_present": HOOK.is_file(),
            "offline_env_note": "HF_HUB_OFFLINE/TRANSFORMERS_OFFLINE 只表示不主动联网，不是网络硬隔离"}


def excludes():
    return re.findall(r'"--exclude-module",\s*"([^"]+)"', PREVIEW.read_text(encoding="utf-8"))


def argv(mode, dist, work, spec):
    out = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onedir", "--console",
           "--name", APP, "--distpath", str(dist), "--workpath", str(work),
           "--specpath", str(spec), "--paths", str(REPO)]
    keep = []
    for m in excludes():
        if m in HEAVY:
            if mode == "sideload":
                keep.append(m)
            continue
        keep.append(m)
    if mode == "sideload":
        keep += [m for m in HEAVY if m not in keep]
    for m in keep:
        out += ["--exclude-module", m]
    if mode == "full-freeze":
        out += ["--collect-all", "torch", "--collect-all", "transformers"]
    if mode == "sideload":
        out += ["--hidden-import", "timeit"]
        # C167-Z（RA 依赖闭包实测缺口，冻结内 import relsgg 失败的根因）：
        # ① PIL 完整化——精简版 _internal\PIL 缺 ImageDraw，
        #    relsgg→torchvision.transforms.v2 链断（C166 冻结自检实测）；
        # ② timm 补包——relsgg 上游 backbone 依赖面（本机已装，不下载）。
        out += ["--collect-all", "PIL", "--collect-all", "timm"]
        out += ["--hidden-import", "torchvision.transforms.v2"]
        out += ["--runtime-hook", str(HOOK)]
    out.append(str(ENTRY))
    return out


def copy_deps_sidecar(src_deps, app_root):
    """C168 固化（R2 窄修）：把**已验收依赖源**的 `_deps` 树完整复制到新后端根。

    - 显式 `--deps-source`（已验收候选的 `_deps`，如 out-v4）——不默认、
      不猜；源缺失/非目录/含重解析点/大小写冲突/清单冲突 → 结构化拒绝；
    - **源根与子项都查重解析点**；lstat 异常 **fail-closed**（视为 reparse，
      不 fail-open）；
    - **拒源位于输出/输出位于源**（互相嵌套）；
    - **两阶段**：先验证整份源清单（枚举+冲突+类型），全部通过后才写目标——
      不留半成品；
    - 逐文件 sha256 复制后校验（源==目标）；copy2/sha 的 OSError/IOError
      原样上抛（execute 侧结构化 deps_copy_failed）；
    - 返回 (copied_count, files_record, digest, provenance)；provenance 的
      source 为**实际 deps 源路径**（非复制后输出）。
    （V5 的复制曾是 DSH 手工步骤——本函数将其固化为构建器合同。）"""
    import stat as _stat

    # C171 ①：源 root 的 reparse 身份不得被 resolve 抹掉——先对**原始路径**
    # 做 lstat 重解析检查，再检查祖先链逐级重解析，全部通过后才 resolve。
    def _is_reparse_raw(p):
        try:
            st = os.lstat(p)
        except OSError:
            return True          # fail-closed
        return bool(_stat.S_ISLNK(st.st_mode)
                    or (getattr(st, "st_file_attributes", 0)
                        & getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))
    src_deps_raw = pathlib.Path(src_deps)
    if _is_reparse_raw(src_deps_raw):
        raise ValueError("deps_source_reparse_point:" + str(src_deps_raw))
    for ancestor in list(src_deps_raw.parents)[:6]:
        if ancestor.is_dir() and _is_reparse_raw(ancestor):
            raise ValueError("deps_source_reparse_point:ancestor:"
                             + str(ancestor))
    if not src_deps_raw.is_dir():
        raise ValueError("deps_source_missing:" + str(src_deps_raw))
    src_deps = src_deps_raw.resolve()
    app_root = pathlib.Path(app_root).resolve()
    dest = app_root / "_deps"
    if dest.exists():
        raise ValueError("deps_dest_exists:" + str(dest))
    # C168-R2：互嵌套拒绝（源在输出内 / 输出在源内——含 app_root 尚未建时
    # 的逻辑父级判断）。
    def _within(child, parent):
        child, parent = child.resolve(), parent.resolve()
        return child == parent or parent in child.parents
    if _within(src_deps, app_root) or _within(app_root, src_deps):
        raise ValueError("deps_source_nested_with_output")
    reparse = getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

    def _is_reparse(p):
        """R2 窄修：lstat 失败 **fail-closed**（异常视为 reparse 拒绝，
        不 fail-open 放行）。"""
        try:
            st = os.lstat(p)
        except OSError:
            return True
        return bool(_stat.S_ISLNK(st.st_mode)
                    or (getattr(st, "st_file_attributes", 0) & reparse))

    # ---- 阶段一：整份源清单验证（零写入；含源根本身） ----
    if _is_reparse(src_deps):
        raise ValueError("deps_source_reparse_point:" + str(src_deps))
    plan, seen = [], set()
    all_paths = sorted(src_deps.rglob("*"), key=lambda p: str(p).casefold())
    for p in all_paths:
        if _is_reparse(p):
            raise ValueError("deps_source_reparse_point:" + str(p))
        if p.is_file():
            rel = str(p.relative_to(src_deps)).replace("\\", "/")
            key = rel.casefold()
            if key in seen:
                raise ValueError("deps_case_conflict:" + rel)
            seen.add(key)
            plan.append((p, rel))
    if not plan:
        raise ValueError("deps_source_empty")

    # ---- 阶段二：完整复制（全部验证通过后才开始写目标） ----
    dest.mkdir(parents=True, exist_ok=False)
    records, provenance = [], {}
    try:
        for src, rel in plan:
            d = dest / rel
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, d)
            s_sha, d_sha = sha(src), sha(d)
            if s_sha != d_sha:
                raise IOError("deps_copy_mismatch:" + rel)
            records.append({"path": "_deps/" + rel,
                            "bytes": d.stat().st_size, "sha256": d_sha})
            # C168-R2：provenance 记**实际 deps 源路径**+源哈希
            provenance["_deps/" + rel] = {
                "source": str(src.resolve()), "source_sha256": s_sha}
    except Exception:
        # C171 ②：复制失败按既有合同**保留 partial**（不 rmtree）——
        # 结构化失败由 execute 侧 deps_copy_failed 承载、清单不产出；
        # 半成品留待主协调处置，构建器绝不静默删除。
        raise
    digest = hashlib.sha256()
    for rel in sorted(seen):
        digest.update(rel.encode("utf-8", "replace"))
        digest.update(sha(dest / rel).encode("ascii"))
    return len(records), records, digest.hexdigest(), provenance


def scan_sensitive(app):
    """候选内**默认拒绝所有 .log**：不存在 `.log`/`_deps/` 之类后缀豁免。

    顺序合同（钉死）：敏感令牌（Cookies/User Data/EBWebView/数据库/录像/
    截图/.log…）命中**优先且无条件**，先于并压倒一切判定——本函数不存在
    任何后缀/目录豁免路径，命中即入拒发清单，published=false、清单不落盘。
    已验收依赖树没有必须承载的 .log，不为假设场景放宽门禁；未来确有
    第三方发行必需的静态文件，须以**确切路径+来源+sha256+内容审查个案**
    批准并写进发布记录——绝不按目录/后缀整类放行，本构建器不实现任何
    白名单机制。"""
    hits = []
    for p in app.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(app)).replace("\\", "/")
            if any(t.casefold() in rel.casefold() for t in SENSITIVE):
                hits.append(rel)
    return sorted(hits)[:20]


def manifest(mode, version, files, facts):
    incomplete = []
    if not facts["deps_complete"]:
        incomplete.append("deps_incomplete:_deps")
    if not facts["import_verified"]:
        incomplete.append("import_not_verified:frozen_process")
    incomplete.append("inference_not_verified:weights")
    return {"schema": "scam.win11-full-backend-manifest/v1", "artifact": APP + ".exe",
            "build_mode": mode, "version": version,
            "provenance_binding": "manifest_sha256 + per-file source_sha256 (sidecar outside release tree)",
            "capabilities_declared": {"L1": "onnxruntime (L1 权重存在性已核)",
                                      "L2": "cv2 (非 RelateAnything)",
                                      "L3": "transformers+torch via _deps" if mode == "sideload" else "bundled torch/transformers",
                                      "L4": "scam core"},
            "verification": facts, "incomplete": incomplete,
            "files": sorted(files, key=lambda f: f["path"])}


def main(argv_list=None):
    ap = argparse.ArgumentParser(description="完整后端构建器 v2")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument("--mode", choices=("sideload", "full-freeze"), default="sideload")
    ap.add_argument("--allow-heavy", action="store_true")
    ap.add_argument("--version", default="0.1.0")
    ap.add_argument("--dist-root", default=str(WORK / "out" / "dist"))
    ap.add_argument("--work-root", default=str(WORK / "out" / "build"))
    ap.add_argument("--spec-path", default=str(WORK / "out" / "spec"))
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--deps-source", default=None,
                    help="C168: 已验收依赖源 _deps 根（显式；sideload 复制固化）")
    a = ap.parse_args(argv_list)
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    dist, work, spec = pathlib.Path(a.dist_root), pathlib.Path(a.work_root), pathlib.Path(a.spec_path)
    app, exe = dist / APP, dist / APP / (APP + ".exe")
    r = {"tool": "semantic-camera/build_win11_full_backend", "mode": a.mode}
    if a.check or not (a.plan or a.execute or a.selfcheck):
        r.update(check())
        r["hf_models_local"] = [m["repo"] for m in r["hf_models_local"]]
    if a.selfcheck:
        _deps_root = dist / APP / "_deps"
        deps_digest = deps_tree_digest(_deps_root)
        report = {"ok": False, "problems": [], "exe_sha256": None,
                  "deps_tree_sha256": deps_digest, "modules": None,
                  "returncode": None}
        if not exe.is_file():
            report["problems"].append("exe_missing")
            r["selfcheck"] = report
        else:
            exe_digest = sha(exe)
            env = dict(os.environ)
            env["SEMANTIC_CAMERA_SELFCHECK"] = "1"
            parsed = None
            try:
                proc = subprocess.run([str(exe)], env=env, cwd=str(app),
                                      shell=False, capture_output=True,
                                      text=True, timeout=180)
                report["returncode"] = proc.returncode
                lines = (proc.stdout or "").strip().splitlines()
                try:
                    parsed = json.loads(lines[0]) if lines else None
                    if parsed is None:
                        report["problems"].append("selfcheck_null_payload")
                except json.JSONDecodeError:
                    parsed = None
                    report["problems"].append("selfcheck_bad_json")
            except subprocess.TimeoutExpired:
                report["problems"].append("selfcheck_timeout")
            except Exception as exc:                       # noqa: BLE001
                report["problems"].append("selfcheck_error:" + type(exc).__name__)

            required = ("torch", "transformers", "tokenizers", "safetensors",
                        "onnxruntime")
            if parsed is not None and not isinstance(parsed, dict):
                report["problems"].append("selfcheck_not_object")
                parsed = None
            if parsed is not None:
                normalized = {
                    "ok": parsed.get("all_ok") is True,
                    "exe_sha256": parsed.get("exe_sha256"),
                    "deps_tree_sha256": deps_digest,
                    "modules": ({name: parsed.get(name) for name in required}
                                if all(isinstance(parsed.get(n), dict) for n in required)
                                else None)}
                ok_bind, bind_problems = selfcheck_report_valid(
                    exe, _deps_root, normalized)
                report["modules"] = normalized["modules"]
                report["exe_sha256"] = parsed.get("exe_sha256")
                report["problems"].extend(bind_problems)
                if report["returncode"] not in (0, None) and not bind_problems:
                    report["problems"].append("selfcheck_returncode_nonzero")
                report["ok"] = bool(ok_bind and report["returncode"] == 0)
            report["batch_dir"] = str(WORK / "selfcheck")
            out_dir = WORK / "selfcheck"
            out_dir.mkdir(parents=True, exist_ok=True)
            stamp = __import__("time").strftime("%Y%m%dT%H%M%S")
            base = exe_digest[:16] + "-" + stamp
            attempt = 0
            while True:
                name = base + ("" if attempt == 0 else "-" + str(attempt)) + ".json"
                target = out_dir / name
                try:
                    with target.open("x", encoding="utf-8") as handle:  # 独占
                        handle.write(json.dumps(report, ensure_ascii=False, indent=2))
                    break
                except FileExistsError:
                    attempt += 1
                    if attempt > 50:
                        raise
            report["bound_report"] = str(target)
            r["selfcheck"] = report
            r["selfcheck_ok"] = report["ok"]
    if a.plan or a.execute:
        r["paths_exist"] = [str(p) for p in (dist, work, spec) if p.exists()]
        r["hook_present"] = HOOK.is_file()
        r["argv"] = argv(a.mode, dist, work, spec)
    if a.execute:
        facts = check()
        refused = None
        if not HOOK.is_file():
            refused = "runtime_hook_missing"
        elif r["paths_exist"]:
            refused = "paths_exist"
        elif a.mode == "full-freeze" and not a.allow_heavy:
            refused = "full_freeze_requires_allow_heavy"
        elif not facts["modes"][a.mode]["allowed"]:
            refused = "resource_gate:" + a.mode
        elif (a.mode == "sideload" and a.deps_source
                and not pathlib.Path(a.deps_source).is_dir()):
            # C168-R2：缺依赖源**执行前拒绝**——不白跑 PyInstaller 构建。
            refused = "deps_source_missing:" + str(a.deps_source)
        r["refused"] = refused
        if refused:
            _emit(r, a.json_out)
            return 1
        env = dict(os.environ); env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
        log = WORK / ("build-" + a.mode + "-" + __import__("time").strftime("%Y%m%dT%H%M%S") + ".log")
        with log.open("w", encoding="utf-8", errors="replace") as h:
            p = subprocess.run(r["argv"], cwd=str(REPO), env=env, shell=False,
                               stdout=h, stderr=subprocess.STDOUT)
        r.update({"pyinstaller_returncode": p.returncode, "log": str(log)})
        if p.returncode != 0 or not exe.is_file():
            r["published"] = False
            r["reasons"] = ["build_failed" if p.returncode else "exe_missing"]
            _emit(r, a.json_out)
            return 1
        # C168：_deps 旁置复制固化（V5 曾为 DSH 手工步骤）。显式
        # --deps-source（已验收依赖源）→ 完整复制到全新后端根（逐文件
        # sha256 校验；缺源/冲突/重解析点/已存在即失败），完成后才继续
        # 敏感扫描与清单封存。
        deps_copied = None
        deps_provenance = {}
        if a.mode == "sideload" and a.deps_source:
            try:
                count, deps_files, deps_digest, deps_prov = copy_deps_sidecar(
                    a.deps_source, app)
                deps_copied = {"source": str(a.deps_source), "files": count,
                               "tree_digest": deps_digest}
                deps_provenance = deps_prov
            except (ValueError, OSError, IOError) as exc:
                # C168-R2：copy2/sha 的 OSError/IOError 同样结构化——
                # published=false + deps_copy_failed + 非零，不裸崩不静默。
                r.update({"published": False,
                          "reasons": ["deps_copy_failed:" + type(exc).__name__
                                      + ": " + str(exc)[:200]]})
                _emit(r, a.json_out)
                return 1
        sensitive = scan_sensitive(app)
        if sensitive:
            r.update({"published": False, "sensitive_files_in_tree": sensitive,
                      "reasons": ["sensitive_files_in_tree"]})
            _emit(r, a.json_out)
            return 1
        sc = None
        bound = WORK / "selfcheck" / (sha(exe)[:16] + ".json")
        if bound.is_file():
            try:
                candidate = json.loads(bound.read_text(encoding="utf-8"))
                ok_bind, _problems = selfcheck_report_valid(exe, app / "_deps", candidate)
                if ok_bind:
                    sc = candidate
            except Exception:
                sc = None
        facts = {"build_mode": a.mode, "deps_complete": bool(deps_tree(app)["complete"]),
                 "import_verified": bool(sc and sc.get("ok")),
                 "inference_verified": False}
        files, srcs = [], {}
        for p in sorted(app.rglob("*")):
            if p.is_file():
                rel = str(p.relative_to(app)).replace("\\", "/")
                files.append({"path": rel, "bytes": p.stat().st_size, "sha256": sha(p)})
                # C168-R2：_deps 旁置文件的 provenance 指向**实际依赖源**
                # （--deps-source 的原始路径），非复制后输出。
                if rel.startswith("_deps/") and rel in deps_provenance:
                    srcs[rel] = {"source_absolute_path":
                                 deps_provenance[rel]["source"],
                                 "source_sha256":
                                 deps_provenance[rel]["source_sha256"]}
                else:
                    srcs[rel] = {"source_absolute_path": str(p.resolve()),
                                 "source_sha256": sha(p)}
        man = manifest(a.mode, a.version, files, facts)
        body = json.dumps(man, ensure_ascii=False, indent=2, sort_keys=True)
        if str(REPO).replace("\\", "/") in body.replace("\\\\", "/"):
            r.update({"published": False, "reasons": ["absolute_path_in_public_manifest"]})
            _emit(r, a.json_out)
            return 1
        mp = app / "full-backend-manifest.json"
        mp.write_text(body, encoding="utf-8")
        digest = sha(mp)
        prov = WORK / "provenance" / (digest + ".json")   # 发布树之外
        prov.parent.mkdir(parents=True, exist_ok=True)
        sidecar = {"manifest_sha256": digest,
           "provenance": {rel: {"source": v["source_absolute_path"],
                               "source_sha256": v["source_sha256"]}
                          for rel, v in srcs.items()}}
        prov.write_text(json.dumps(sidecar, ensure_ascii=False, indent=2,
                                   sort_keys=True), encoding="utf-8")
        r.update({"published": True, "exe_bytes": exe.stat().st_size, "manifest_sha256": digest,
                  "deps_copied": deps_copied,
                  "manifest_incomplete": man["incomplete"], "provenance_path": str(prov),
                  "provenance_inside_release_tree": False})
    _emit(r, a.json_out)
    if a.selfcheck:
        return 0 if r.get("selfcheck_ok") else 1
    return 0 if not r.get("refused") and not r.get("reasons") else 1


if __name__ == "__main__":
    sys.exit(main())
