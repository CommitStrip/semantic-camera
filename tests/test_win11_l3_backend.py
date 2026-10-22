"""C-136 tests: scam.win11_l3_backend —— 唯一 L3 生产适配器
LocalTransformersL3Backend（冻结签名，docs/context/L2L3L4-接口冻结-C136.md §一）。

覆盖：
- 双构造路径：生产 model_path 真实构造（延迟加载，不触 provider）+ 假
  provider 注入；两者缺一即 ValueError（离线红线：不收隐式 hub id）；
- 委托正确性：BGR→JPEG b64（缺帧 None 直通）、meta 规范化/等长对齐、
  prompt 与返回 dict 原样透传、load 单飞一次；经真实 LocalTransformers
  多帧映射的端到端捕获（[2,3,448,448]/占位符=2——映射断言归
  tests/test_models.py 既有覆盖，此处只证 backend 委托到位，不重写）；
- 离线与来源：model_path 缺失 → 结构化 model_unavailable（missing 清单），
  任何 socket 创建=网络企图=测试失败；不自动下载；
- 生产超时真实化：加载慢超 load_timeout_s → 结构化 load_timeout + 隔离 +
  加载线程残留如实（executor_threads_alive≥1，迟到的加载按代次丢弃）；
  推理慢超 infer_timeout_s → L3InferTimeout + poisoned 拒派；上游自身的
  TimeoutError（future 已完成）≠ 等待超时 → infer_failed 不毒化；
- 生命周期（与 l2_backend 同一收尾合同）：close 空闲干净收口（幂等、
  无线程遗留）、在途不可中止 → closed=False + close_incomplete=True +
  残留如实（解除后收敛）、关闭自身异常 → closed=False + close_incomplete
  + error="close_failed"（绝不视为停止成功）、停止后完成的返回结果丢弃
  （不发布，计数如实）、隔离/关闭后立即拒收；
- C-137 §6 B1/B2/B3/B4：交付前重检（交付闸门）——阻塞推理 → close →
  释放 → 调用方收到结构化拒收（closed_rejected/poisoned_rejected/
  generation_rejected），绝无成功值；generation 随 close/隔离递增；
  加载超时/推理超时/关闭中加载同一"不交成功值"合同；
- diagnostic 冻结六字段与 l2_backend 同形、健康面（diagnostic/snapshot）
  无绝对路径；
- 加载失败非终态可重试（结构化 model_unavailable，phase 回 unloaded）；
- models.LocalTransformers.load(timeout_s) 预算入口：超时 False + 线程
  残留如实、失败上抛原异常、成功 True。
"""

from __future__ import annotations

import base64
import socket
import threading
import time
from pathlib import Path

import numpy as np
import pytest

from scam import win11_l3_backend as backend_mod
from scam.models import LocalTransformers
from scam.win11_l3_backend import (
    INFER_TIMEOUT_S_DEFAULT,
    LOAD_TIMEOUT_S_DEFAULT,
    L3InferFailed,
    L3InferTimeout,
    LocalTransformersL3Backend,
    TOTAL_TIMEOUT_S_DEFAULT,
)
from scam.win11_l3_contract import L3AdapterIsolated, L3ModelUnavailable, L3VisionModel

_DRIVE_PATH_RE = None  # 占位：正则在 _assert_no_abs_paths 处惰性编译


def _drive_path_re():
    global _DRIVE_PATH_RE
    import re
    if _DRIVE_PATH_RE is None:
        _DRIVE_PATH_RE = re.compile(r"[A-Za-z]:[\\/]")
    return _DRIVE_PATH_RE


# ---------------------------------------------------------------------------
# 工具：假 provider / 假快照目录 / 假模型内部（捕获级，绝不真实加载）
# ---------------------------------------------------------------------------


class FakeProvider:
    """假 L3 provider：load/understand_frames 可编程（慢/失败/阻塞），记录调用。"""

    def __init__(self, model_id="fake-snap"):
        self.model_id = model_id
        self.load_calls = 0
        self.load_delay = 0.0
        self.fail_on_load = None
        self.block_event = None        # 推理阻塞（有界：30s 自行返回）
        self.infer_delay = 0.0
        self.fail_on_infer = None
        self.calls = []
        self.result = {"observation": "假观察", "inference": "假推断"}

    def load(self, timeout_s=None):
        self.load_calls += 1
        if self.load_delay > 0:
            time.sleep(min(self.load_delay, 5.0))   # 真实占住加载线程
        if self.fail_on_load is not None:
            raise self.fail_on_load
        return True

    def understand_frames(self, prompt, frames_b64, frames_meta=None):
        self.calls.append({"prompt": prompt, "frames": list(frames_b64),
                           "meta": list(frames_meta or ())})
        if self.block_event is not None:
            self.block_event.wait(timeout=30.0)
        if self.infer_delay > 0:
            time.sleep(min(self.infer_delay, 5.0))
        if self.fail_on_infer is not None:
            raise self.fail_on_infer
        return self.result


def make_fake_snapshot(tmp_path: Path) -> Path:
    """最小本地 HF 快照目录布局（含 config.json——自建路径的缺失检查项）。"""
    snap = tmp_path / "hf-home" / "snapshots" / "5648fa26deadbeef"
    snap.mkdir(parents=True)
    (snap / "config.json").write_text("{}", encoding="utf-8")
    return snap


class _FakeChatModel:
    """按上游 chat() 签名接收并记录（捕获 LocalTransformers 实际送进模型的
    张量——映射语义归 models.py，此处只证 backend 委托链路真实到位）。"""

    def __init__(self):
        self.calls = []

    def chat(self, tokenizer, pixel_values, question, generation_config,
             history=None, return_history=False, num_patches_list=None, **kw):
        self.calls.append({
            "question": question,
            "marker_count": question.count("<image>"),
            "pixel_values_shape": tuple(pixel_values.shape),
            "num_patches_list": (None if num_patches_list is None
                                 else list(num_patches_list)),
        })
        assert num_patches_list is not None
        assert pixel_values.shape[0] == sum(num_patches_list)
        return '{"observation": "捕获", "inference": "无"}'


class _FakeTransform:
    def __call__(self, img):
        import torch
        return torch.full((3, 448, 448), float(img.size[0]),
                          dtype=torch.float32)


def _capture_real_provider(snapshot_dir: Path) -> LocalTransformers:
    """真实 LocalTransformers（自建路径的产物）+ 注入假内部：_model 非 None
    即跳过 _ensure_loaded，绝不触发真实加载/联网。"""
    lt = LocalTransformers(model_path=str(snapshot_dir), timeout=5)
    lt._model = _FakeChatModel()
    lt._tokenizer = object()
    lt._transform = _FakeTransform()
    return lt


_FRAME_A = np.zeros((8, 10, 3), dtype=np.uint8)
_FRAME_B = np.full((6, 12, 3), 200, dtype=np.uint8)


def _backend(ns=None, **kw):
    defaults = dict(infer_timeout_s=5.0, load_timeout_s=5.0)
    defaults.update(kw)
    if ns is not None:
        return LocalTransformersL3Backend(provider=ns.provider, **defaults)
    return LocalTransformersL3Backend(**defaults)


def _l3_threads():
    """本适配器专属 executor 的残留线程（threading.enumerate 口径）。"""
    return [t for t in threading.enumerate()
            if t.name.startswith("scam-l3-backend")]


def _wait_until(pred, timeout_s: float = 8.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(interval)
    return bool(pred())


def _assert_no_abs_paths(value, _key="") -> None:
    """健康面口径：任意字符串字段不得含盘符绝对路径形态（含键名）。"""
    if isinstance(value, str):
        assert not _drive_path_re().search(value), \
            "绝对路径泄漏进健康面字段 {}: {!r}".format(_key, value)
    elif isinstance(value, dict):
        for k, v in value.items():
            _assert_no_abs_paths(k, _key)
            _assert_no_abs_paths(v, _key)
    elif isinstance(value, (list, tuple, set)):
        for i, v in enumerate(value):
            _assert_no_abs_paths(v, "{}[{}]".format(_key, i))


@pytest.fixture
def fake_ns():
    """假 provider + 各状态复位。"""
    return types_namespace(FakeProvider())


class types_namespace:
    def __init__(self, provider):
        self.provider = provider


# ---------------------------------------------------------------------------
# 1. 双构造路径（生产 model_path 真实构造 / 假 provider 注入）
# ---------------------------------------------------------------------------


def test_production_construction_by_model_path_is_lazy(tmp_path):
    """生产构造路径：model_path 自建 LocalTransformers，延迟加载（构造后
    provider 未加载、无 torch 依赖触发），model_ref=快照目录短码。"""
    snap = make_fake_snapshot(tmp_path)
    b = LocalTransformersL3Backend(model_path=str(snap))

    assert isinstance(b, L3VisionModel)
    assert isinstance(b._provider, LocalTransformers)
    assert b._provider._model is None            # 延迟：构造绝不加载
    assert b.model_ref == "transformers/5648fa26deadbeef"
    assert "/" in b.model_ref
    snap_name = snap.name
    assert snap_name in b.model_ref and str(snap) not in b.model_ref
    s = b.snapshot()
    assert s["provider_built_here"] is True
    assert s["loaded"] is False and s["poisoned"] is False


def test_provider_injection_construction_uses_provider_declaration(tmp_path):
    """注入路径：provider 声明（model_id）进 model_ref；provider_built_here
    如实为 False；构造不触碰 provider。"""
    snap = make_fake_snapshot(tmp_path)
    provider = _capture_real_provider(snap)
    provider.model_id = "my-snapshot-code"
    b = LocalTransformersL3Backend(provider=provider)

    assert b._provider is provider
    assert b.model_ref == "transformers/my-snapshot-code"
    assert b.snapshot()["provider_built_here"] is False
    assert b._provider._model is not None        # 注入的已就绪内部未被改动


def test_construction_requires_provider_or_explicit_model_path(tmp_path, monkeypatch):
    """provider 与 model_path 双缺 → ValueError（离线红线：绝不隐式收 hub id）。
    hub id 形态的 model_path 允许构造（延迟加载，同 l2_backend：构造只存
    配置），但首次调用即结构化拒绝且零网络——绝不触发下载。"""
    with pytest.raises(ValueError):
        LocalTransformersL3Backend()

    def _no_network(*args, **kwargs):
        raise AssertionError("network attempted for hub-id-shaped model_path")

    monkeypatch.setattr(socket, "socket", _no_network)
    b = LocalTransformersL3Backend(
        model_path="OpenGVLab/InternVL3_5-1B-Instruct")
    assert b.model_ref == "transformers/InternVL3_5-1B-Instruct"  # 短码，非路径
    with pytest.raises(L3ModelUnavailable) as ei:
        b.understand_frames("描述。", [_FRAME_A], None)
    missing = ei.value.details.get("missing") or []
    assert any("local model path not found" in m for m in missing)


def test_default_timeouts_frozen_signature():
    """冻结签名：默认超时 180/120/60、close(timeout_s=5.0)、协议方法齐。"""
    import inspect
    sig = inspect.signature(LocalTransformersL3Backend.__init__)
    assert sig.parameters["timeout_s"].default == 180.0
    assert sig.parameters["infer_timeout_s"].default == 120.0
    assert sig.parameters["load_timeout_s"].default == 60.0
    assert sig.parameters["provider"].default is None
    assert sig.parameters["model_path"].default is None
    csig = inspect.signature(LocalTransformersL3Backend.close)
    assert list(csig.parameters) == ["self", "timeout_s"]
    assert csig.parameters["timeout_s"].default == 5.0
    usig = inspect.signature(LocalTransformersL3Backend.understand_frames)
    assert [p for p in usig.parameters if p != "self"] == \
        ["prompt", "frames_bgr", "frames_meta"]
    assert INFER_TIMEOUT_S_DEFAULT == 120.0
    assert LOAD_TIMEOUT_S_DEFAULT == 60.0
    assert TOTAL_TIMEOUT_S_DEFAULT == 180.0


# ---------------------------------------------------------------------------
# 1b. C153 A：批处理/并行能力如实声明（unsupported 不是失败态）
# ---------------------------------------------------------------------------


def test_capabilities_declares_batch_unsupported_honestly(fake_ns):
    """真实批处理 unsupported：唯一生产 provider 只有单次入口，绝不把循环
    调用改名 batch；并行同样如实 False（预处理与推理同一专属单线程）。"""
    ns = fake_ns
    b = _backend(ns)

    caps = b.capabilities()

    assert caps["model_ref"] == b.model_ref
    assert caps["batch"]["supported"] is False
    assert caps["batch"]["reason"] == "provider_has_no_batch_api"
    assert "not real batching" in caps["batch"]["note"]
    assert caps["parallel"]["supported"] is False
    assert caps["parallel"]["reason"] == "single_worker_thread"
    assert caps["parallel"]["workers"] == 1
    # 能力声明不是失败态：不毒化、不加载、无异常状态
    assert caps["poisoned"] is False and caps["phase"] == "unloaded"
    assert ns.provider.load_calls == 0
    # 没有"循环调用改名 batch"的入口
    assert not hasattr(b, "understand_frames_batch")


def test_capabilities_is_pure_and_path_free(tmp_path):
    """只读快照：构造后即可读（绝不触发加载）；健康面口径零绝对路径。"""
    snap = make_fake_snapshot(tmp_path)
    b = LocalTransformersL3Backend(model_path=str(snap))
    first = b.capabilities()
    second = b.capabilities()

    assert first == second                      # 无副作用、可重复读
    assert b._provider._model is None           # 未触发加载
    _assert_no_abs_paths(first)
    assert b.snapshot()["loaded"] is False
    assert b.diagnostic()["phase"] == "unloaded"


def test_capabilities_reports_timeout_and_phase_after_isolation(tmp_path):
    """隔离/关闭等终态如实反映在能力快照（不是重新可用的假象）。"""
    provider = FakeProvider(model_id="cap-snap")
    provider.infer_delay = 1.0
    b = LocalTransformersL3Backend(provider=provider, infer_timeout_s=0.2,
                                   load_timeout_s=5.0)
    with pytest.raises(L3InferTimeout):
        b.understand_frames("描述。", [_FRAME_A], None)

    caps = b.capabilities()
    assert caps["poisoned"] is True
    assert caps["phase"] == "poisoned"
    assert caps["infer_timeout_s"] == 0.2
    # 能力声明与"实际还能不能服务"分开：batch 仍 unsupported（与隔离无关）
    assert caps["batch"]["supported"] is False
    b.close()


# ---------------------------------------------------------------------------
# 2. 委托正确性（backend 只做委托与生命周期，不改写 models 映射）
# ---------------------------------------------------------------------------


def test_understand_frames_delegates_b64_meta_prompt_and_result(fake_ns):
    ns = fake_ns
    b = _backend(ns)
    meta = [{"branch": "panorama", "frame_id": "f-1"}, None,
            {"branch": "change_region", "frame_id": "f-3"}]
    import cv2

    out = b.understand_frames("比较三帧。", [_FRAME_A, None, _FRAME_B], meta)

    assert out == ns.provider.result                     # 返回原样透传
    assert ns.provider.load_calls == 1                   # load 单飞一次
    assert len(ns.provider.calls) == 1
    call = ns.provider.calls[0]
    assert call["prompt"] == "比较三帧。"                # prompt 原样
    # 帧转换：在位帧=纯 base64 JPEG（可解码回原尺寸）；缺帧=None 直通
    assert call["frames"][1] is None
    dec_a = cv2.imdecode(np.frombuffer(
        base64.b64decode(call["frames"][0]), dtype=np.uint8), cv2.IMREAD_COLOR)
    dec_b = cv2.imdecode(np.frombuffer(
        base64.b64decode(call["frames"][2]), dtype=np.uint8), cv2.IMREAD_COLOR)
    assert dec_a.shape == _FRAME_A.shape and dec_b.shape == _FRAME_B.shape
    # meta 规范化：None→{}，dict 浅拷贝透传
    assert call["meta"][0] == {"branch": "panorama", "frame_id": "f-1"}
    assert call["meta"][1] == {}
    assert call["meta"][2]["frame_id"] == "f-3"

    # 第二次调用：不再触发 load（已就绪）
    b.understand_frames("再看。", [_FRAME_A], None)
    assert ns.provider.load_calls == 1
    assert ns.provider.calls[1]["meta"] == [{}]


def test_delegation_through_real_localtransformers_multiframe_mapping(tmp_path):
    """端到端委托（生产构造路径 + 假模型内部捕获）：backend → 真实
    LocalTransformers 多帧映射 → 模型入口张量。映射断言只到「委托到位」，
    详尽映射回归归 tests/test_models.py（不重写）。"""
    snap = make_fake_snapshot(tmp_path)
    b = LocalTransformersL3Backend(model_path=str(snap), infer_timeout_s=5.0,
                                   load_timeout_s=5.0)
    fake_chat = _FakeChatModel()
    b._provider._model = fake_chat
    b._provider._tokenizer = object()
    b._provider._transform = _FakeTransform()

    out = b.understand_frames("比较两帧。", [_FRAME_A, _FRAME_B],
                              [{"frame_id": "a"}, {"frame_id": "b"}])

    assert out == {"observation": "捕获", "inference": "无"}
    assert b.snapshot()["loaded"] is True
    assert len(fake_chat.calls) == 1
    call = fake_chat.calls[0]
    assert call["pixel_values_shape"] == (2, 3, 448, 448)   # 两帧都进了模型
    assert call["num_patches_list"] == [1, 1]
    assert call["marker_count"] == 2
    assert b.diagnostic()["phase"] == "ready"
    assert b.diagnostic()["load_stage"] == "done"


# ---------------------------------------------------------------------------
# 3. 离线与来源：缺失 → 结构化失败，零网络
# ---------------------------------------------------------------------------


def test_missing_model_path_structured_and_never_downloads(tmp_path, monkeypatch):
    """model_path 不存在 → 结构化 model_unavailable（missing 清单），任何
    socket 创建=网络企图=测试失败；绝不自动下载、实例不隔离（可修复重试）。"""
    nonexistent = tmp_path / "not-here" / "snapshot"
    b = LocalTransformersL3Backend(model_path=str(nonexistent),
                                   load_timeout_s=5.0, infer_timeout_s=5.0)

    def _no_network(*args, **kwargs):
        raise AssertionError("network attempted during model_unavailable path")

    monkeypatch.setattr(socket, "socket", _no_network)

    with pytest.raises(L3ModelUnavailable) as ei:
        b.understand_frames("描述。", [_FRAME_A], None)
    exc = ei.value
    assert "model_unavailable" in str(exc)
    assert exc.details.get("code") == "model_unavailable"
    missing = exc.details.get("missing") or []
    assert any("local model path not found" in m for m in missing)
    assert not b.poisoned
    d = b.diagnostic()
    assert d["phase"] == "unloaded" and d["load_error"] is None
    assert d["pending_calls"] == 0
    _assert_no_abs_paths(d)
    assert b._provider._model is None            # 绝未触发加载/下载


def test_model_path_without_config_json_is_rejected(tmp_path):
    """目录存在但缺 config.json（非本地快照布局）→ 结构化拒绝，不交给
    from_pretrained 试错。"""
    bare = tmp_path / "bare-dir"
    bare.mkdir()
    b = LocalTransformersL3Backend(model_path=str(bare))
    with pytest.raises(L3ModelUnavailable) as ei:
        b.understand_frames("描述。", [_FRAME_A], None)
    missing = ei.value.details.get("missing") or []
    assert any("config.json" in m for m in missing)


# ---------------------------------------------------------------------------
# 4. 生产超时真实化：加载有界 / 推理有界 / 隔离拒派
# ---------------------------------------------------------------------------


def test_slow_load_times_out_isolates_and_reports_residual_honestly(fake_ns):
    """加载慢超 load_timeout_s：结构化 load_timeout + 隔离 + 加载线程仍存活
    如实；迟到的加载结果按代次丢弃（不绕过隔离采用）；收敛后 close 干净。"""
    ns = fake_ns
    ns.provider.load_delay = 1.0
    b = _backend(ns, load_timeout_s=0.3)

    t0 = time.monotonic()
    with pytest.raises(L3ModelUnavailable) as ei:
        b.understand_frames("描述。", [_FRAME_A], None)
    assert time.monotonic() - t0 < 3.0, "加载超时必须有界返回"
    exc = ei.value
    assert exc.details.get("code") == "load_timeout"
    assert "load_timeout" in str(exc)

    d = b.diagnostic()
    assert d["phase"] == "isolated"
    assert d["executor_threads_alive"] >= 1       # 加载线程仍存活——不隐瞒
    assert d["load_stage"] in ("provider_load",)
    assert d["load_error"] and "load_timeout" in d["load_error"]
    assert d["close_incomplete"] is False         # 未 close，只是隔离
    _assert_no_abs_paths(d)
    assert b.poisoned

    # 隔离后立即拒收，不再给卡住的加载派任务
    t1 = time.monotonic()
    with pytest.raises(L3AdapterIsolated) as ei2:
        b.understand_frames("描述。", [_FRAME_A], None)
    assert time.monotonic() - t1 < 0.5
    assert ei2.value.details.get("code") == "backend_isolated"
    assert ns.provider.load_calls == 1

    # 慢加载线程随后自然结束：迟到的模型被丢弃（隔离不因迟到结果翻转）
    assert _wait_until(lambda: b.diagnostic()["executor_threads_alive"] == 0,
                       timeout_s=8.0)
    snap = b.snapshot()
    assert snap["loaded"] is False
    assert snap["discarded_loads"] == 1
    assert b.diagnostic()["phase"] == "isolated"
    r = b.close(timeout_s=5.0)
    assert r == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                 "close_incomplete": False}


def test_load_failure_is_model_unavailable_and_retryable(fake_ns):
    """provider 加载异常 → 结构化 model_unavailable；phase 回 unloaded、
    load_error 只含类型+阶段；失败非终态：修复后同一实例可重试成功。"""
    ns = fake_ns
    ns.provider.fail_on_load = RuntimeError("boom: C:\\snap\\model.safetensors")
    b = _backend(ns)

    with pytest.raises(L3ModelUnavailable) as ei:
        b.understand_frames("描述。", [_FRAME_A], None)
    assert ei.value.details.get("code") == "model_unavailable"
    assert getattr(ei.value, "code", None) == "model_unavailable"
    assert (ei.value.details.get("missing") or [])   # 详细异常进结构化异常
    d = b.diagnostic()
    assert d["phase"] == "unloaded"
    assert d["load_error"] == "RuntimeError: provider_load failed"  # 无路径
    _assert_no_abs_paths(d)
    assert not b.poisoned

    ns.provider.fail_on_load = None
    out = b.understand_frames("描述。", [_FRAME_A], None)
    assert out == ns.provider.result
    d2 = b.diagnostic()
    assert d2["phase"] == "ready" and d2["load_stage"] == "done"
    assert ns.provider.load_calls == 2


def test_infer_timeout_poisons_and_refuses_new_work(fake_ns):
    """推理慢超 infer_timeout_s：L3InferTimeout（TimeoutError 子类）+ 实例
    poisoned 拒派；残留如实；解除后迟到结果丢弃、close 收敛干净。"""
    ns = fake_ns
    release = threading.Event()
    ns.provider.block_event = release
    baseline = {t.ident for t in _l3_threads()}
    b = _backend(ns, infer_timeout_s=0.3)

    t0 = time.monotonic()
    with pytest.raises(L3InferTimeout) as ei:
        b.understand_frames("描述。", [_FRAME_A, _FRAME_B], None)
    waited = time.monotonic() - t0
    assert waited < 5.0, "超时必须准时返回，不得等卡住的调用"
    assert getattr(ei.value, "code", None) == "timeout"
    assert isinstance(ei.value, TimeoutError)
    assert b.poisoned

    d = b.diagnostic()
    assert d["phase"] == "poisoned"
    assert d["pending_calls"] == 1 and d["executor_threads_alive"] == 1
    _assert_no_abs_paths(d)

    # 后续调用立即拒收，不再派给卡住实例
    calls_before = len(ns.provider.calls)
    t1 = time.monotonic()
    with pytest.raises(L3AdapterIsolated) as ei2:
        b.understand_frames("描述。", [_FRAME_A], None)
    assert time.monotonic() - t1 < 0.5
    assert ei2.value.details.get("code") == "backend_isolated"
    assert len(ns.provider.calls) == calls_before

    # 释放：卡住的调用完成→迟到结果丢弃不发布；poisoned 终态不复活
    release.set()
    assert _wait_until(lambda: b.diagnostic()["pending_calls"] == 0
                       and b.diagnostic()["executor_threads_alive"] == 0,
                       timeout_s=10.0)
    assert all(t.ident in baseline or t.name.startswith("scam-l3-backend")
               for t in _l3_threads())
    snap = b.snapshot()
    assert snap["discarded_results"] == 1
    assert snap["poisoned"] is True
    with pytest.raises(L3AdapterIsolated):
        b.understand_frames("描述。", [_FRAME_A], None)

    # 收敛后 close 干净退出
    r = b.close(timeout_s=5.0)
    assert r == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                 "close_incomplete": False}


def test_upstream_own_timeouterror_maps_to_infer_failed_not_poison(fake_ns):
    """上游自身抛出的 TimeoutError（future 已完成）≠ 等待超时 → infer_failed，
    不毒化（与 l2_backend 同一区分）。"""
    ns = fake_ns
    ns.provider.fail_on_infer = TimeoutError("upstream internal timeout")
    b = _backend(ns)
    with pytest.raises(L3InferFailed) as ei:
        b.understand_frames("描述。", [_FRAME_A], None)
    assert getattr(ei.value, "code", None) == "infer_failed"
    assert not b.poisoned
    assert b.diagnostic()["phase"] == "ready"     # 实例仍可用
    ns.provider.fail_on_infer = None
    assert b.understand_frames("描述。", [_FRAME_A], None) == ns.provider.result


def test_generic_upstream_error_maps_to_infer_failed(fake_ns):
    ns = fake_ns
    ns.provider.fail_on_infer = RuntimeError("boom inside upstream")
    b = _backend(ns)
    with pytest.raises(L3InferFailed) as ei:
        b.understand_frames("描述。", [_FRAME_A], None)
    assert getattr(ei.value, "code", None) == "infer_failed"
    assert "boom inside upstream" in str(ei.value)
    assert not b.poisoned


# ---------------------------------------------------------------------------
# 5. 生命周期：close 收尾合同（与 l2_backend 同一结构）
# ---------------------------------------------------------------------------


def test_close_idle_clean_idempotent_and_no_leftover_threads(fake_ns):
    """正常调用后 close：干净收口（closed=True、无线程遗留）、幂等、停止接单。"""
    ns = fake_ns
    baseline = {t.ident for t in _l3_threads()}
    b = _backend(ns)
    assert b.understand_frames("描述。", [_FRAME_A], None) == ns.provider.result
    assert b.snapshot()["loaded"] is True

    r1 = b.close(timeout_s=5.0)
    assert r1 == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                  "close_incomplete": False}
    assert _wait_until(lambda: all(t.ident in baseline
                                   for t in _l3_threads()), timeout_s=5.0), (
        "干净收口后不得遗留本 backend 线程: {}".format(
            [t.name for t in _l3_threads()]))

    r2 = b.close()                                # 幂等
    assert r2 == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                  "close_incomplete": False}

    d = b.diagnostic()
    assert d["phase"] == "isolated"
    assert d["executor_threads_alive"] == 0
    assert d["close_incomplete"] is False

    t0 = time.monotonic()
    with pytest.raises(L3AdapterIsolated) as ei:
        b.understand_frames("描述。", [_FRAME_A], None)
    assert time.monotonic() - t0 < 0.5            # 已关闭：立即拒收
    assert ei.value.details.get("code") == "backend_isolated"
    assert len(ns.provider.calls) == 1            # 关闭后无新任务派给 provider


def test_close_incomplete_on_stuck_call_then_converges(fake_ns):
    """在途不可中止：close 如实报告残留（closed=False + close_incomplete），
    停止接单；解除后收敛为干净收口；close 不改变 poison 终态；迟到结果
    丢弃不发布。"""
    ns = fake_ns
    release = threading.Event()
    ns.provider.block_event = release
    b = _backend(ns, infer_timeout_s=0.3)

    with pytest.raises(L3InferTimeout):
        b.understand_frames("描述。", [_FRAME_A], None)
    assert b.poisoned

    r = b.close(timeout_s=0.5)
    assert r["closed"] is False
    assert r["close_incomplete"] is True
    assert r["pending_calls"] >= 1 and r["threads_alive"] >= 1
    d = b.diagnostic()
    assert d["close_incomplete"] is True
    assert d["phase"] == "poisoned"               # close 不改变 poison 终态
    _assert_no_abs_paths(d)

    # 停止接单：立即拒收
    calls_before = len(ns.provider.calls)
    with pytest.raises(L3AdapterIsolated):
        b.understand_frames("描述。", [_FRAME_A], None)
    assert len(ns.provider.calls) == calls_before

    # 解除：残留收敛，迟到结果丢弃（绝不发布）
    release.set()
    assert _wait_until(lambda: b.diagnostic()["pending_calls"] == 0
                       and b.diagnostic()["executor_threads_alive"] == 0,
                       timeout_s=10.0)
    r2 = b.close(timeout_s=5.0)
    assert r2 == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                  "close_incomplete": False}
    snap = b.snapshot()
    assert snap["discarded_results"] == 1
    assert snap["poisoned"] is True


def test_close_during_inflight_stops_and_discards_late_result(fake_ns):
    """C-137 B1/B4 交付闸门（确定性竞态）：close 落在在途调用中间（未毒化）
    → 停止接单 + close_incomplete 如实；释放后在途调用完成——收集调用方
    实际收到的返回值/异常：必须是结构化拒收（closed_rejected），绝无成功
    值；丢弃计数恰一次；随后收敛干净。"""
    ns = fake_ns
    release = threading.Event()
    ns.provider.block_event = release
    b = _backend(ns, infer_timeout_s=30.0)        # 调用方等得住：毒化不触发
    gen_before = b.snapshot()["delivery_generation"]

    errs = []

    def _call():
        try:
            errs.append(("result", b.understand_frames("描述。", [_FRAME_A], None)))
        except BaseException as exc:
            errs.append(("exception", exc))

    t = threading.Thread(target=_call, name="c136-close-during-infer")
    t.start()
    # 等推理 future 真正进入在途（而非加载 future 的瞬时计数）
    assert _wait_until(
        lambda: b.snapshot()["pending_call_still_running"] is True,
        timeout_s=5.0)

    r = b.close(timeout_s=0.3)                    # 在途调用等不完
    assert r["closed"] is False and r["close_incomplete"] is True
    assert r["pending_calls"] >= 1 and r["threads_alive"] >= 1

    release.set()
    t.join(timeout=10.0)
    assert not t.is_alive()
    # C-137 B1：调用方收不到成功值——收到的必须是结构化拒收
    assert len(errs) == 1 and errs[0][0] == "exception"
    exc = errs[0][1]
    assert isinstance(exc, L3AdapterIsolated)
    assert getattr(exc, "code", None) == "closed_rejected"
    assert exc.details.get("reject_code") == "closed_rejected"
    # 代次已随 close 递增；丢弃计数恰一次（回调/闸门不双计）
    assert b.snapshot()["delivery_generation"] == gen_before + 1
    assert _wait_until(lambda: b.diagnostic()["executor_threads_alive"] == 0,
                       timeout_s=8.0)
    snap = b.snapshot()
    assert snap["discarded_results"] == 1         # 停止后完成的结果丢弃不发布
    r2 = b.close(timeout_s=5.0)                   # 收敛：干净收口
    assert r2 == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                  "close_incomplete": False}


def test_close_shutdown_exception_is_never_reported_as_success(fake_ns):
    """关闭自身异常 → 返回结构如实 closed=False + close_incomplete=True +
    error 码（C-137 B2 三态之三，供停机汇总判定，绝不视为停止成功）；
    diagnostic 同步如实反映关闭未完成。"""
    ns = fake_ns
    b = _backend(ns)
    assert b.understand_frames("描述。", [_FRAME_A], None)

    def _boom(wait=True):
        raise RuntimeError("executor shutdown exploded")

    import unittest.mock as mock
    with mock.patch.object(b._executor, "shutdown", _boom):
        r = b.close(timeout_s=1.0)
    assert r["closed"] is False
    assert r["close_incomplete"] is True
    assert r["pending_calls"] == 0
    assert r.get("error") == "close_failed"      # C-137 B2：错误码
    assert b.diagnostic()["close_incomplete"] is True   # 诊断如实


def test_close_during_load_gives_structured_refusal_not_runtime_error():
    """close 落在加载中：在途调用得到结构化拒收（迟到的加载结果丢弃不采用），
    绝不泄漏裸 RuntimeError（submit-after-shutdown 竞态回归）；close 如实报
    close_incomplete，收敛后干净收口。"""
    provider = FakeProvider()
    provider.load_delay = 0.8
    b = LocalTransformersL3Backend(provider=provider, load_timeout_s=5.0,
                                   infer_timeout_s=5.0)
    errs = []

    def _call():
        try:
            b.understand_frames("描述。", [_FRAME_A], None)
        except BaseException as exc:
            errs.append(exc)

    t = threading.Thread(target=_call, name="c136-close-during-load")
    t.start()
    assert _wait_until(lambda: b.diagnostic()["phase"] == "loading", timeout_s=3.0)

    r = b.close(timeout_s=0.2)                    # 0.2 << 0.8：加载等不完
    assert r["closed"] is False and r["close_incomplete"] is True
    assert r["pending_calls"] >= 1 and r["threads_alive"] >= 1

    t.join(timeout=10.0)
    assert not t.is_alive()
    assert errs and isinstance(errs[0], L3AdapterIsolated), errs
    assert errs[0].details.get("reject_code") == "closed_rejected"  # 交付闸门码
    assert _wait_until(lambda: b.diagnostic()["executor_threads_alive"] == 0,
                       timeout_s=8.0)
    snap = b.snapshot()
    assert snap["loaded"] is False and snap["discarded_loads"] == 1
    r2 = b.close(timeout_s=5.0)                   # 收敛：干净收口
    assert r2 == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                  "close_incomplete": False}


def test_close_before_any_load_is_clean_and_refuses_afterwards():
    """从未加载即 close：干净收口；此后调用/加载一律拒收。"""
    b = LocalTransformersL3Backend(provider=FakeProvider())
    r = b.close(timeout_s=1.0)
    assert r == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                 "close_incomplete": False}
    with pytest.raises(L3AdapterIsolated):
        b.understand_frames("描述。", [_FRAME_A], None)


# ---------------------------------------------------------------------------
# 5b. C-137 交付前重检（交付闸门）+ 统一关闭合同（B1/B2/B3/B4）
# ---------------------------------------------------------------------------


def test_delivery_gate_generation_semantics(fake_ns):
    """C-137 B1 generation 语义（确定性白盒）：代次随 close/隔离请求递增，
    交付时代次不符 → generation_rejected；裁决只读不改状态——无新 close
    的普通调用不受影响。"""
    ns = fake_ns
    b = _backend(ns)
    assert b.understand_frames("描述。", [_FRAME_A], None) == ns.provider.result
    gen = b.snapshot()["delivery_generation"]

    with b._lock:
        # 未关闭未毒化：仅代次不符即可触发（三条拒收码的第三条可达）
        assert b._delivery_reject_code_locked(gen) is None
        b._delivery_gen = gen + 1
        assert b._delivery_reject_code_locked(gen) == "generation_rejected"
        assert b._delivery_reject_code_locked(gen + 1) is None

    # 裁决只读：代次对齐后普通交付照常（无新 close 不受影响）
    assert b.understand_frames("描述。", [_FRAME_A], None) == ns.provider.result
    assert b.snapshot()["delivery_generation"] == gen + 1


def test_timeout_and_load_paths_never_deliver_success_values(fake_ns):
    """C-137 B4：加载超时/推理超时——同一交付闸门合同：调用方收到结构化
    异常（拒绝或丢弃+拒收），绝不收到成功值；迟到结果/迟到加载只计丢弃。"""
    # (a) 加载超时：调用方收到 load_timeout（异常，非成功值）；迟到的加载
    #     完成后只进 discarded_loads，provider 加载结果从未被任何人采用
    ns = fake_ns
    ns.provider.load_delay = 0.6
    b = _backend(ns, load_timeout_s=0.2)
    with pytest.raises(L3ModelUnavailable) as ei:
        b.understand_frames("描述。", [_FRAME_A], None)
    assert ei.value.details.get("code") == "load_timeout"
    assert _wait_until(lambda: b.snapshot()["discarded_loads"] == 1,
                       timeout_s=8.0)
    assert b.snapshot()["loaded"] is False
    assert b.diagnostic()["executor_threads_alive"] == 0

    # (b) 推理超时：调用方收到 L3InferTimeout（异常，非成功值）；解除后
    #     迟到的成功结果只进 discarded_results，无第二接收方
    ns2 = types_namespace(FakeProvider())
    release = threading.Event()
    ns2.provider.block_event = release
    b2 = _backend(ns2, infer_timeout_s=0.2)
    with pytest.raises(L3InferTimeout):
        b2.understand_frames("描述。", [_FRAME_A], None)
    release.set()
    assert _wait_until(lambda: b2.snapshot()["discarded_results"] == 1,
                       timeout_s=8.0)
    assert b2.snapshot()["poisoned"] is True     # 终态保持，绝不假装恢复


def test_runtime_shutdown_contract_close_return_and_diagnostic_shapes(fake_ns):
    """C-137 B3：向 runtime 显式暴露的关闭/诊断接口冻结——close 干净收口
    返回键集恒 {closed, pending_calls, threads_alive, close_incomplete}
    （error 码仅在关闭自身异常出现，见专属用例）；diagnostic 恒六字段，
    与 l2_backend 逐字段同形（跨 backend 逐字段一致性由
    tests/test_win11_l2_backend.py 的统一合同用例锁定）。"""
    ns = fake_ns
    b = _backend(ns)
    assert b.understand_frames("描述。", [_FRAME_A], None) == ns.provider.result
    r = b.close(timeout_s=2.0)
    assert set(r) == {"closed", "pending_calls", "threads_alive",
                      "close_incomplete"}
    assert set(b.diagnostic()) == {"phase", "load_stage", "pending_calls",
                                   "executor_threads_alive", "close_incomplete",
                                   "load_error"}


# ---------------------------------------------------------------------------
# 6. diagnostic 冻结结构 + 健康面无路径
# ---------------------------------------------------------------------------


def test_diagnostic_frozen_structure_matches_l2_shape(fake_ns):
    """diagnostic 六冻结字段与 l2_backend 同形：键集恒定、phase 取值域、
    加载阶段推进；健康面（diagnostic/snapshot）全程无绝对路径。"""
    ns = fake_ns
    b = _backend(ns)

    d0 = b.diagnostic()
    assert set(d0) == {"phase", "load_stage", "pending_calls",
                       "executor_threads_alive", "close_incomplete", "load_error"}
    assert d0["phase"] == "unloaded" and d0["load_stage"] is None
    assert d0["pending_calls"] == 0 and d0["executor_threads_alive"] == 0
    assert d0["close_incomplete"] is False and d0["load_error"] is None

    assert b.understand_frames("描述。", [_FRAME_A], None) == ns.provider.result

    d1 = b.diagnostic()
    assert set(d1) == set(d0)                     # 冻结结构：键集不变
    assert d1["phase"] == "ready" and d1["load_stage"] == "done"
    assert d1["pending_calls"] == 0 and d1["executor_threads_alive"] >= 1
    _assert_no_abs_paths(d1)
    _assert_no_abs_paths(b.snapshot())
    assert b.snapshot()["load_stages_seen"] == ["provider_load", "done"]
    assert b.snapshot()["model_ref"] == "transformers/fake-snap"

    # loading 相位可达（慢加载期间观察）
    ns2_provider = FakeProvider()
    ns2_provider.load_delay = 0.5
    b2 = LocalTransformersL3Backend(provider=ns2_provider, load_timeout_s=5.0,
                                    infer_timeout_s=5.0)
    errs = []

    def _call():
        try:
            b2.understand_frames("描述。", [_FRAME_A], None)
        except BaseException as exc:
            errs.append(exc)

    t = threading.Thread(target=_call, name="c136-loading-phase")
    t.start()
    assert _wait_until(lambda: b2.diagnostic()["phase"] == "loading",
                       timeout_s=3.0)
    assert b2.diagnostic()["load_stage"] in ("provider_load", None)
    t.join(timeout=10.0)
    assert not errs and b2.diagnostic()["phase"] == "ready"


def test_backend_module_has_no_fake_download_or_network_paths():
    """backend 模块代码（docstring 叙述除外）不得含任何下载/网络/子进程路径。"""
    import ast

    src_path = Path(backend_mod.__file__)
    tree = ast.parse(src_path.read_text(encoding="utf-8"))
    if (tree.body and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
            and isinstance(tree.body[0].value.value, str)):
        tree.body = tree.body[1:]          # 去掉模块 docstring
    code_src = ast.unparse(tree)
    for forbidden in ("from_pretrained", "snapshot_download", "hf_hub_download",
                      "urlopen", "requests.", "subprocess"):
        assert forbidden not in code_src, \
            f"backend 模块代码不得出现 {forbidden}"


# ---------------------------------------------------------------------------
# 7. models.LocalTransformers.load(timeout_s) 预算入口（B2 参数化）
# ---------------------------------------------------------------------------


def _patch_load(lt, monkeypatch, *, delay=0.0, fail=None, marker=None):
    """替换实例 _ensure_loaded：可编程慢/失败，成功时置 _model。"""
    def _fake_ensure():
        if delay:
            time.sleep(min(delay, 5.0))
        if fail is not None:
            raise fail
        lt._model = marker or object()

    monkeypatch.setattr(lt, "_ensure_loaded", _fake_ensure)


def test_models_load_unbounded_sync_path(monkeypatch):
    lt = LocalTransformers(model_path="capture/fake", timeout=5)
    _patch_load(lt, monkeypatch, marker="loaded-model")
    assert lt.load() is True                       # 缺省：调用线程同步加载
    assert lt._model == "loaded-model"
    assert lt.load() is True                       # 已就绪：幂等直返
    assert lt.load_thread_alive() is False


def test_models_load_budget_timeout_reports_residual_honestly(monkeypatch):
    """加载慢超预算：load(timeout_s) 返回 False（有界返回，不假装停止）；
    加载线程残留由 load_thread_alive 如实呈现；结束后重试成功。"""
    lt = LocalTransformers(model_path="capture/fake", timeout=5)
    _patch_load(lt, monkeypatch, delay=0.6, marker="late-model")
    t0 = time.monotonic()
    assert lt.load(timeout_s=0.2) is False
    assert time.monotonic() - t0 < 3.0
    assert lt.load_thread_alive() is True          # 残留如实——不隐瞒
    assert lt._model is None                       # 绝不采用未完成结果
    assert _wait_until(lambda: not lt.load_thread_alive(), timeout_s=5.0)
    monkeypatch.setattr(lt, "_ensure_loaded", lambda: None)
    lt._model = "late-model"                       # 加载线程的自然产物
    assert lt.load() is True


def test_models_load_failure_raises_original_exception(monkeypatch):
    """加载失败：load() 上抛原异常（失败非终态，可重试）。"""
    lt = LocalTransformers(model_path="capture/fake", timeout=5)
    _patch_load(lt, monkeypatch, fail=RuntimeError("oom during load"))
    with pytest.raises(RuntimeError, match="oom during load"):
        lt.load(timeout_s=2.0)
    assert lt._model is None
    _patch_load(lt, monkeypatch, marker="ok-model")
    assert lt.load(timeout_s=2.0) is True
    assert lt._model == "ok-model"


def test_models_existing_callers_untouched(monkeypatch):
    """既有调用方兼容：understand/understand_frames/构造默认零变化（捕获级
    冒烟——假内部注入后行为与 C-135 交付一致）。"""
    lt = LocalTransformers(model_path="capture/fake", timeout=5)
    fake = _FakeChatModel()
    lt._model = fake
    lt._tokenizer = object()
    lt._transform = _FakeTransform()
    import cv2
    arr = np.full((8, 8, 3), 200, dtype=np.uint8)
    ok, buf = cv2.imencode(".jpg", arr)
    assert ok
    b64 = base64.b64encode(buf.tobytes()).decode("ascii")
    out = lt.understand("描述。", [b64])
    assert out == {"observation": "捕获", "inference": "无"}
    assert fake.calls[0]["question"] == "<image>\n描述。"   # 单帧旧格式字节级保持
