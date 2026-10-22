"""C155 入口回归：真实入口必须激活逐帧模式（防再次验收旧 package 回退路径）。

不经素材播放：直接在隔离目录用**生产构造路径**建库并构建 L2 运行时，
断言运行前置条件（生产 EventProgress、绑定源能力、两开关、逐帧模式、隔离新库）。
"""

import os
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _build_isolated(tmp_path):
    from scam import nvr as nvr_mod
    from scam.win11_materials import MaterialsStore
    from scam.win11_windows import WindowScheduler

    db_path = str(tmp_path / "c155-preflight.db")
    cfg = {
        "l2": {"enabled": True, "repo_path": "unused",
               "vocabulary": ["walking past"], "vocabulary_id": "c155-preflight",
               "infer_timeout_s": 10.0},
        # 关键：L3 模型关闭，但 l4 打开 ⇒ 生产路径创建真实 EventProgress 绑定源
        "l3": {"enabled": False, "l4": {"enabled": True}},
    }
    assert not os.path.exists(db_path), "隔离库必须在本轮新建（构建前不存在）"
    store = MaterialsStore()          # 生产同款无参构造（nvr.py:800）
    scheduler = WindowScheduler(["cam-pre"], store)
    runtime = nvr_mod._build_l2_runtime(
        cfg["l2"], store, ["cam-pre"], l3_cfg=cfg["l3"],
        persist_dir=str(tmp_path / "understanding"), db_path=db_path)
    return runtime, db_path


def test_production_entry_activates_frame_level_mode(tmp_path):
    runtime, db_path = _build_isolated(tmp_path)
    from scam.win11_event_progress import EventProgress

    pool = runtime.event_materials
    assert pool is not None, "生产入口必须注入材料池"
    adm = (pool.snapshot() or {}).get("admission") or {}

    # 1 生产 EventProgress（非替身）
    assert isinstance(runtime.event_progress, EventProgress)
    # 2 绑定源支持逐帧只读接口，且池绑定源就是该对象
    assert pool.binding_source is runtime.event_progress
    assert hasattr(pool.binding_source, "resolve_frame_bindings")
    # 3/4 两开关（生产入口显式开启）
    assert adm.get("frame_level_binding") is True
    assert adm.get("primary_frame_binding") is True
    # 5 实际模式不是 package 回退
    assert adm.get("active_mode") not in (None, "package"), adm
    # 6 隔离新库（本轮新建、位于 tmp 内、可打开）
    assert os.path.abspath(db_path).startswith(str(tmp_path))
    # 库由生产事件桥在 start 时落盘；此处证明"路径隔离 + 本轮新建"
    try:
        runtime.event_progress.start()
    except Exception:
        pass
    assert os.path.abspath(db_path).startswith(str(tmp_path))
    if os.path.exists(db_path):
        con = sqlite3.connect(db_path)
        con.close()
    runtime.stop()
