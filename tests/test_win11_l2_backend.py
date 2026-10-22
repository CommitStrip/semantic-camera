"""C-134/C-135 tests: scam.win11_l2_backend —— 真实 RelateAnything 延迟加载适配器。

覆盖（L2-接口冻结-C134.md §5 C 侧分界 + L2L3-接口冻结-C135.md §5/§7）：
- 延迟加载：构造只存配置，不 import 上游、不加载权重、不动 sys.path；
- 缺权重 → ModelUnavailable 结构化（固定码 + 缺失项清单），零网络；
- 假上游注入（sys.modules import 钩子）验证映射：输出→协议 dict、空→空、
  上游异常→infer_failed；
- 超时隔离：超时→timeout + poisoned，后续 infer 立即 AdapterIsolated，
  残留如实报告（线程不可中止），绝不假装恢复；
- C-135 生命周期：diagnostic() 冻结字段（phase/load_stage/...）、加载
  阶段推进、close() 空闲干净收口（幂等、无线程遗留）、在途不可中止时
  close_incomplete=True+残留如实（解除后收敛）、停止后完成的结果丢弃
  不发布、慢加载有界超时（load_timeout + 隔离 + 线程仍存活如实）、
  close 期间迟到的加载结果不采用、来源防错配（source_mismatch）、
  model_ref 携带权重 sha256 前 16 位、健康面字段不含绝对路径；
- C-137 §6 B1/B2/B3/B4：交付前重检（交付闸门）——close/隔离先到时
  调用方只收到结构化拒收（closed_rejected/poisoned_rejected/
  generation_rejected），绝无成功值；generation 随 close/隔离递增；
  加载超时/推理超时同一"不交成功值"合同；与 l3_backend 的
  close(timeout_s)->dict + diagnostic() 六字段逐字段统一（runtime 停机
  合同显式暴露）；
- 真实模型证据（slow）：本机上游+权重可用时对固定本地素材跑一次真实
  infer，证据落 %TEMP%/c134_l2/real-infer.json；依赖缺失→skip（理由如实）；
- 生产禁 fake：scam/nvr.py 契约式静态断言 + 本模块无网络/无 fake 路径。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import types
from pathlib import Path

import numpy as np
import pytest

from scam import win11_l2_backend as backend
from scam.win11_l2_backend import (
    AdapterIsolated,
    InferFailed,
    InferTimeout,
    ModelUnavailable,
    RelateAnythingAdapter,
)

# 适配器优先抛 B 的合同异常类（win11_l2_contract），缺位时才是本地回退——
# 测试与该解析保持一致（存在即断言合同类）。
try:
    from scam.win11_l2_contract import AdapterIsolated as _AdapterIsolatedRaised
    from scam.win11_l2_contract import ModelUnavailable as _ModelUnavailableRaised
except ImportError:  # pragma: no cover - B 模块缺位时的回退
    _AdapterIsolatedRaised = AdapterIsolated
    _ModelUnavailableRaised = ModelUnavailable

# 真实上游/素材/检查点由环境变量指认；缺省时相关用例自动 skip。
UPSTREAM_REPO = Path(os.environ.get("SCAM_RELATE_REPO")
                     or "_unset_relate_repo")
HF_SNAPSHOT_DIR = Path.home() / ".cache" / "huggingface" / "hub" / "models--maelic--relsgg-vits16plus" / "snapshots"
REAL_MATERIAL = Path(os.environ.get(
    "SCAM_REAL_MATERIAL", "C:/data/scenario.mp4"))
EVIDENCE_DIR = Path(tempfile.gettempdir()) / "c134_l2"

_DRIVE_PATH_RE = re.compile(r"[A-Za-z]:[\\/]")


# ---------------------------------------------------------------------------
# 工具：假上游（经 sys.modules 注入的 import 钩子）
# ---------------------------------------------------------------------------


class _FakeTriplet:
    def __init__(self, s, o, predicate, score):
        self.subject_idx = s
        self.object_idx = o
        self.predicate = predicate
        self.score = score


class _FakeRelateAnythingCls:
    """from_checkpoint 的假类：记录调用、可编程慢加载/加载失败、返回假实例。"""

    calls = []

    @classmethod
    def from_checkpoint(cls, ckpt_path, predicates=None, device="cpu",
                        text_student=None, **kw):
        assert os.path.isfile(str(ckpt_path)), "fake loader got nonexistent ckpt"
        cls.calls.append({
            "ckpt": str(ckpt_path),
            "predicates": list(predicates) if predicates else None,
            "text_student": str(text_student),
        })
        delay = float(_FAKE_STATE.get("load_delay") or 0.0)
        if delay > 0:
            time.sleep(min(delay, 30.0))   # 有界慢加载：真实占住加载线程，不拖死进程
        if _FAKE_STATE.get("fail_on_load") is not None:
            raise _FAKE_STATE["fail_on_load"]
        return FakeRelateAnything()


class FakeRelateAnything:
    """假 ra 实例：默认输出 1 spatial + 1 semantic 三元组；可编程阻塞/失败/空。"""

    def __init__(self):
        self.predicates = ["holding"]
        self.set_vocab_calls = []
        self.predict_calls = []

    def set_vocabulary(self, predicates, **kw):
        self.set_vocab_calls.append(list(predicates))
        self.predicates = list(predicates)
        return self

    def predict(self, image, boxes, box_labels=None, decompose=False, **kw):
        self.predict_calls.append({
            "image_is_frame": True,
            "image_ref": image,
            "boxes": boxes,
            "box_labels": list(box_labels) if box_labels is not None else None,
            "decompose": decompose,
            "state": _FAKE_STATE,
        })
        state = _FAKE_STATE
        if state.get("block_event") is not None:
            # 有界阻塞：真实模拟卡死，但不拖死整个测试进程（30s 后自行返回）。
            state["block_event"].wait(timeout=30.0)
        if state.get("fail_on_predict"):
            raise state["fail_on_predict"]
        if state.get("empty"):
            return {"spatial": [], "semantic": []}
        return {
            "spatial": [_FakeTriplet(0, 1, "to the left of", 0.42)],
            "semantic": [_FakeTriplet(1, 0, "holding", 0.9)],
        }


_FAKE_STATE = {"block_event": None, "fail_on_predict": None, "empty": False,
               "load_delay": 0.0, "fail_on_load": None}


def _make_fake_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "RelateAnything"
    (repo / "relsgg").mkdir(parents=True)
    (repo / "relsgg" / "__init__.py").write_text("", encoding="utf-8")
    return repo


def _make_fake_checkpoint(tmp_path: Path) -> Path:
    ckpt_dir = tmp_path / "hf-home" / "snap123"
    ckpt_dir.mkdir(parents=True)
    (ckpt_dir / "model.pth").write_bytes(b"fake-weights")
    (ckpt_dir / "text_student.pt").write_bytes(b"fake-student")
    (ckpt_dir / "tokenizer.json").write_bytes(b"{}")
    return ckpt_dir / "model.pth"


@pytest.fixture
def fake_upstream(monkeypatch, tmp_path):
    """注入假 relsgg/torch 模块（import 钩子）+ 假仓库/检查点文件布局。

    C-135：假 relsgg 必须自带位于假仓库内的 ``__file__``——适配器的来源
    防错配检查要求同名校验可验证来源，否则按 source_mismatch 结构化拒绝
    （这正是生产语义，假上游如实配合）。"""
    _FAKE_STATE.update({"block_event": None, "fail_on_predict": None,
                        "empty": False, "load_delay": 0.0, "fail_on_load": None})
    _FakeRelateAnythingCls.calls = []
    repo = _make_fake_repo(tmp_path)
    ckpt = _make_fake_checkpoint(tmp_path)
    fake_relsgg = types.ModuleType("relsgg")
    fake_relsgg.RelateAnything = _FakeRelateAnythingCls
    fake_relsgg.__file__ = str(repo / "relsgg" / "__init__.py")
    fake_torch = types.ModuleType("torch")
    monkeypatch.setitem(sys.modules, "relsgg", fake_relsgg)
    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    yield types.SimpleNamespace(repo=repo, ckpt=ckpt, state=_FAKE_STATE,
                                loader_calls=_FakeRelateAnythingCls.calls)
    # 适配器可能把假仓库插进了 sys.path——清理，不污染其它测试。
    try:
        sys.path.remove(str(repo))
    except ValueError:
        pass


def _adapter(ns, **kw):
    defaults = dict(repo_path=str(ns.repo), checkpoint=str(ns.ckpt),
                    infer_timeout_s=5.0)
    defaults.update(kw)
    return RelateAnythingAdapter(**defaults)


_FRAME = np.zeros((8, 10, 3), dtype=np.uint8)
_BOXES = [(1, 1, 4, 6), (5, 2, 9, 7)]
_LABELS = ["p", "q"]


def _adapter_threads():
    """本适配器专属 executor 的残留线程（threading.enumerate 口径）。"""
    return [t for t in threading.enumerate()
            if t.name.startswith("scam-l2-relateanything")]


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
        assert not _DRIVE_PATH_RE.search(value), \
            "绝对路径泄漏进健康面字段 {}: {!r}".format(_key, value)
    elif isinstance(value, dict):
        for k, v in value.items():
            _assert_no_abs_paths(k, _key)
            _assert_no_abs_paths(v, _key)
    elif isinstance(value, (list, tuple, set)):
        for i, v in enumerate(value):
            _assert_no_abs_paths(v, "{}[{}]".format(_key, i))


# ---------------------------------------------------------------------------
# 1. 延迟加载
# ---------------------------------------------------------------------------


def test_construction_is_lazy(tmp_path, monkeypatch):
    """构造只存配置：不 import 上游、不加载权重、不动 sys.path。"""
    monkeypatch.delitem(sys.modules, "relsgg", raising=False)
    repo = _make_fake_repo(tmp_path)          # 有 .git 也没有：纯配置
    ckpt = _make_fake_checkpoint(tmp_path)
    path_len_before = len(sys.path)

    a = RelateAnythingAdapter(str(repo), str(ckpt), infer_timeout_s=3.0)

    assert a.model_ref == "relateanything/local/model.pth"   # 占位（未加载）
    assert a._model is None
    assert not a.poisoned
    assert "relsgg" not in sys.modules        # 上游模块未被 import
    assert len(sys.path) == path_len_before   # sys.path 未被注入
    assert str(repo) not in sys.path
    snap = a.snapshot()
    assert snap["loaded"] is False and snap["poisoned"] is False


def test_conforms_to_contract_protocol_and_exception_classes():
    """与 B 的 win11_l2_contract 集成：协议基类 isinstance + 合同异常类自愈。"""
    from scam import win11_l2_contract as contract

    a = RelateAnythingAdapter(r"D:\no-such-repo", r"D:\no-such\model.pth")
    assert isinstance(a, contract.L2RelationModel)
    assert isinstance(a.model_ref, str) and "/" in a.model_ref

    # 抛出的必须是 B 的合同类（动态解析，非本地回退）
    with pytest.raises(contract.ModelUnavailable) as ei:
        a.infer(_FRAME, _BOXES, _LABELS, ())
    assert ei.value.reason and ei.value.details is not None
    assert ei.value.details.get("missing")

    # InferTimeout 兼容 B 的 stage 分类：必须是内建 TimeoutError 子类
    from scam.win11_l2_backend import InferTimeout as it_cls
    assert issubclass(it_cls, TimeoutError)


def test_model_ref_uses_real_commit_short_code():
    """model_ref = relateanything/<commit 短码>/<checkpoint 文件名>（真实克隆）。"""
    if not UPSTREAM_REPO.exists():  # pragma: no cover - 本机外
        pytest.skip("上游克隆不存在，跳过真实 model_ref 断言")
    a = RelateAnythingAdapter(str(UPSTREAM_REPO), r"X:\does-not-matter\model.pth")
    m = re.fullmatch(r"relateanything/([0-9a-f]{12})/model\.pth", a.model_ref)
    assert m, a.model_ref
    # 短码必须等于真实 .git HEAD（本仓实测 06766fd...），且不含绝对路径
    head_file = UPSTREAM_REPO / ".git" / "refs" / "heads" / "main"
    expected = head_file.read_text().strip()[:12]
    assert m.group(1) == expected


# ---------------------------------------------------------------------------
# 2. 缺权重 → ModelUnavailable 结构化 + 零网络
# ---------------------------------------------------------------------------


def test_missing_checkpoint_structured_no_network(fake_upstream, monkeypatch):
    ns = fake_upstream
    missing_ckpt = ns.ckpt.parent / "not-here" / "model.pth"
    a = _adapter(ns, checkpoint=str(missing_ckpt))

    def _no_network(*args, **kwargs):  # 任何 socket 创建=网络企图=测试失败
        raise AssertionError("network attempted during ModelUnavailable path")

    monkeypatch.setattr(socket, "socket", _no_network)
    monkeypatch.delitem(sys.modules, "relsgg", raising=False)

    with pytest.raises(_ModelUnavailableRaised) as ei:
        a.infer(_FRAME, _BOXES, _LABELS, ())

    exc = ei.value
    assert getattr(exc, "code", None) == "model_unavailable"
    assert "model_unavailable" in str(exc)
    missing = getattr(exc, "missing", None)
    assert missing, "结构化缺失清单缺失"
    assert any("checkpoint file not found" in m for m in missing)
    assert "relsgg" not in sys.modules           # 未走到 import
    assert not a.poisoned                        # 缺可用性 ≠ 被隔离
    assert a.snapshot()["loaded"] is False
    assert a.snapshot()["load_error"] is None    # 纯预检失败，无加载残迹


def test_missing_repo_and_text_student_listed(fake_upstream):
    ns = fake_upstream
    a = RelateAnythingAdapter(
        repo_path=str(ns.repo.parent / "no-such-repo"),
        checkpoint=str(ns.ckpt.parent / "not-here" / "model.pth"),
        infer_timeout_s=5.0,
    )
    with pytest.raises(_ModelUnavailableRaised) as ei:
        a.infer(_FRAME, _BOXES, _LABELS, ())
    missing = " ".join(getattr(ei.value, "missing", []))
    assert "repo directory not found" in missing
    assert "checkpoint file not found" in missing


# ---------------------------------------------------------------------------
# 3. 假上游注入：映射 / 空态 / 异常分类 / 词表
# ---------------------------------------------------------------------------


def test_mapping_output_to_protocol_dicts(fake_upstream):
    ns = fake_upstream
    a = _adapter(ns)
    out = a.infer(_FRAME, _BOXES, _LABELS, ("holding", "near"))

    assert out == [
        {"s": 0, "o": 1, "relation": "to the left of", "graph": "spatial", "score": 0.42},
        {"s": 1, "o": 0, "relation": "holding", "graph": "semantic", "score": 0.9},
    ]
    # 加载调用拿到显式 text_student（旁路 hf:// 分支）与构造词表
    assert len(ns.loader_calls) == 1
    call = ns.loader_calls[0]
    assert call["text_student"] == str(ns.ckpt.parent / "text_student.pt")
    # 框以 [N,4] float32 像素直喂上游；labels 仅作展示标签透传
    ra = a._model
    fa = ra.predict_calls[0]
    assert fa["boxes"].dtype == np.float32 and fa["boxes"].shape == (2, 4)
    assert fa["box_labels"] == ["p", "q"]
    assert fa["image_ref"] is _FRAME            # BGR 帧原样直喂，无拷贝换算
    # 词表切换发生在 infer 侧且只编一次
    assert ra.set_vocab_calls == [["holding", "near"]]

    # 同词表第二次 infer：不再触发 set_vocabulary（缓存激活词表）
    a.infer(_FRAME, _BOXES, _LABELS, ("holding", "near"))
    assert ra.set_vocab_calls == [["holding", "near"]]
    # 空词表=沿用当前，也不切换
    a.infer(_FRAME, _BOXES, _LABELS, ())
    assert ra.set_vocab_calls == [["holding", "near"]]


def test_mapping_empty_relation_list(fake_upstream):
    ns = fake_upstream
    ns.state["empty"] = True
    a = _adapter(ns)
    out = a.infer(_FRAME, _BOXES, _LABELS, ())
    assert out == []
    assert a.snapshot()["loaded"] is True


def test_upstream_exception_maps_to_infer_failed(fake_upstream):
    ns = fake_upstream
    ns.state["fail_on_predict"] = RuntimeError("boom inside upstream")
    a = _adapter(ns)
    with pytest.raises(InferFailed) as ei:
        a.infer(_FRAME, _BOXES, _LABELS, ())
    assert getattr(ei.value, "code", None) == "infer_failed"
    assert "boom inside upstream" in str(ei.value)


def test_fewer_than_two_boxes_returns_empty_without_loading(fake_upstream):
    ns = fake_upstream
    a = _adapter(ns)
    assert a.infer(_FRAME, [(0, 0, 1, 1)], ["only"], ()) == []
    assert a.infer(_FRAME, [], [], ()) == []
    assert a.snapshot()["loaded"] is False       # 未触发加载
    assert len(ns.loader_calls) == 0


# ---------------------------------------------------------------------------
# 4. 超时隔离
# ---------------------------------------------------------------------------


def test_timeout_poisons_and_reports_residue_honestly(fake_upstream):
    ns = fake_upstream
    release = threading.Event()
    ns.state["block_event"] = release
    a = _adapter(ns, infer_timeout_s=0.3)

    t0 = time.monotonic()
    with pytest.raises(InferTimeout) as ei:
        a.infer(_FRAME, _BOXES, _LABELS, ())
    waited = time.monotonic() - t0
    assert waited < 5.0, "超时必须准时返回，不得等卡住的调用"
    assert getattr(ei.value, "code", None) == "timeout"
    assert a.poisoned

    snap = a.snapshot()
    assert snap["poisoned"] is True
    assert snap["worker_abortable"] is False
    assert snap["worker_threads_alive"] >= 1
    assert snap["pending_call_still_running"] is True   # 卡住的调用仍在跑（事实）
    assert "cannot be aborted" in snap["note"]

    # 后续 infer 立即 AdapterIsolated，不再派任务
    predicts_before = len(a._model.predict_calls)
    t1 = time.monotonic()
    with pytest.raises(_AdapterIsolatedRaised) as ei2:
        a.infer(_FRAME, _BOXES, _LABELS, ())
    assert time.monotonic() - t1 < 0.5
    assert getattr(ei2.value, "code", None) == "backend_isolated"
    assert len(a._model.predict_calls) == predicts_before  # 无新任务派给卡住实例

    # 释放卡住的调用：残留如实变化（调用完成），但隔离是终态，绝不假装恢复
    release.set()
    for _ in range(200):
        if a.snapshot()["pending_call_still_running"] is False:
            break
        time.sleep(0.05)
    snap2 = a.snapshot()
    assert snap2["pending_call_still_running"] is False
    assert snap2["pending_call_done"] is True
    assert snap2["poisoned"] is True                     # 不假装恢复
    with pytest.raises(_AdapterIsolatedRaised):
        a.infer(_FRAME, _BOXES, _LABELS, ())


# ---------------------------------------------------------------------------
# 4b. C-135 生命周期：diagnostic / close / 有界加载 / 来源防错配 / model_ref
# ---------------------------------------------------------------------------


def test_diagnostic_frozen_structure_and_stage_progression(fake_upstream):
    """diagnostic() 冻结字段全量断言 + 加载阶段推进（加载线程内 set，锁保护）。"""
    ns = fake_upstream
    a = _adapter(ns, vocabulary=("holding",))

    d = a.diagnostic()
    assert set(d) == {"phase", "load_stage", "pending_calls",
                      "executor_threads_alive", "close_incomplete", "load_error"}
    assert d["phase"] == "unloaded" and d["load_stage"] is None
    assert d["pending_calls"] == 0 and d["executor_threads_alive"] == 0
    assert d["close_incomplete"] is False and d["load_error"] is None

    out = a.infer(_FRAME, _BOXES, _LABELS, ("holding",))
    assert out                                       # 假上游默认输出

    d2 = a.diagnostic()
    assert set(d2) == set(d)                          # 冻结结构：键集不变
    assert d2["phase"] == "ready" and d2["load_stage"] == "done"
    assert d2["pending_calls"] == 0 and d2["executor_threads_alive"] >= 1
    _assert_no_abs_paths(d2)

    snap = a.snapshot()
    # 三阶段推进如实留痕（构造期词表编码在上游 from_checkpoint 内完成，
    # 计时并入 checkpoint 阶段；"vocabulary" 为其完成标记）
    assert snap["load_stages_seen"] == ["import", "checkpoint", "vocabulary", "done"]
    assert snap["load_ms"] is not None and "total_ms" in snap["load_ms"]
    assert snap["load_ms"]["import_ms"] >= 0.0
    assert snap["load_ms"]["checkpoint_ms"] >= 0.0


def test_close_idle_clean_idempotent_and_no_leftover_threads(fake_upstream):
    """正常 infer 后 close：干净收口（closed=True、无线程遗留）、幂等、停止接单。"""
    ns = fake_upstream
    # threading.enumerate 是进程全局的：以测试开始时的 adapter 线程为基线，
    # 只断言本 adapter 不新增遗留（他测试尚未被 GC 的线程不计入）。
    baseline = {t.ident for t in _adapter_threads()}
    a = _adapter(ns)
    assert a.infer(_FRAME, _BOXES, _LABELS, ())
    assert a.snapshot()["loaded"] is True

    r1 = a.close(timeout_s=5.0)
    assert r1 == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                  "close_incomplete": False}
    assert _wait_until(lambda: all(t.ident in baseline
                                   for t in _adapter_threads()), timeout_s=5.0), (
        "干净收口后不得遗留本 adapter 线程: {}".format(
            [t.name for t in _adapter_threads()]))

    r2 = a.close()                                    # 幂等
    assert r2 == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                  "close_incomplete": False}

    d = a.diagnostic()
    assert d["phase"] == "isolated"
    assert d["executor_threads_alive"] == 0
    assert d["close_incomplete"] is False

    # 已关闭：后续 infer 立即拒收（停止接单）
    t0 = time.monotonic()
    with pytest.raises(_AdapterIsolatedRaised) as ei:
        a.infer(_FRAME, _BOXES, _LABELS, ())
    assert time.monotonic() - t0 < 0.5
    assert getattr(ei.value, "code", None) == "backend_isolated"


def test_close_incomplete_on_stuck_infer_then_converges(fake_upstream):
    """在途不可中止：close 如实报告残留（close_incomplete=True），停止后完成
    的结果丢弃不发布；解除后收敛为干净收口（既有 poison 终态保持）。"""
    ns = fake_upstream
    release = threading.Event()
    ns.state["block_event"] = release
    baseline = {t.ident for t in _adapter_threads()}   # 进程全局枚举的基线对照
    a = _adapter(ns, infer_timeout_s=0.3)

    with pytest.raises(InferTimeout):
        a.infer(_FRAME, _BOXES, _LABELS, ())
    assert a.poisoned
    d = a.diagnostic()
    assert d["phase"] == "poisoned"
    assert d["pending_calls"] == 1 and d["executor_threads_alive"] == 1

    r = a.close(timeout_s=0.5)
    assert r["closed"] is False
    assert r["close_incomplete"] is True
    assert r["pending_calls"] >= 1 and r["threads_alive"] >= 1
    assert a.diagnostic()["close_incomplete"] is True
    _assert_no_abs_paths(a.diagnostic())

    # 后续 infer 立即拒收（停止接单），不再给卡住实例派任务
    predicts_before = len(a._model.predict_calls)
    with pytest.raises(_AdapterIsolatedRaised):
        a.infer(_FRAME, _BOXES, _LABELS, ())
    assert len(a._model.predict_calls) == predicts_before

    # 解除：残留收敛，迟到的"结果"被丢弃（绝不发布），隔离终态不复活
    release.set()
    assert _wait_until(lambda: a.diagnostic()["pending_calls"] == 0
                       and a.diagnostic()["executor_threads_alive"] == 0,
                       timeout_s=10.0)
    r2 = a.close(timeout_s=5.0)
    assert r2 == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                  "close_incomplete": False}
    assert all(t.ident in baseline for t in _adapter_threads())
    snap = a.snapshot()
    assert snap["discarded_results"] == 1    # 卡住调用完成后被包装层丢弃
    assert snap["poisoned"] is True          # close 不改变 poison 终态
    assert a.diagnostic()["phase"] == "poisoned"


def test_slow_load_times_out_and_isolates_honestly(fake_upstream):
    """慢加载超过 load_timeout_s：结构化 load_timeout + 隔离 + 加载线程仍
    存活如实；迟到的加载结果按代次丢弃（不绕过隔离采用）。"""
    ns = fake_upstream
    ns.state["load_delay"] = 1.0
    a = _adapter(ns, load_timeout_s=0.3)

    t0 = time.monotonic()
    with pytest.raises(_ModelUnavailableRaised) as ei:
        a.infer(_FRAME, _BOXES, _LABELS, ())
    waited = time.monotonic() - t0
    assert waited < 3.0, "加载超时必须有界返回，不得等慢加载"
    exc = ei.value
    assert getattr(exc, "code", None) == "load_timeout"
    assert "load_timeout" in str(exc)

    d = a.diagnostic()
    assert d["phase"] == "isolated"
    assert d["executor_threads_alive"] >= 1          # 加载线程仍存活——不隐瞒
    assert d["close_incomplete"] is False            # 未 close，只是隔离
    assert d["load_stage"] in ("import", "checkpoint", "vocabulary")
    assert d["load_error"] and "load_timeout" in d["load_error"]
    _assert_no_abs_paths(d)
    assert a.poisoned
    t1 = time.monotonic()
    with pytest.raises(_AdapterIsolatedRaised) as ei2:
        a.infer(_FRAME, _BOXES, _LABELS, ())
    assert time.monotonic() - t1 < 0.5               # 隔离后立即拒收
    assert getattr(ei2.value, "code", None) == "backend_isolated"

    # 慢加载线程随后自然结束：迟到的模型被丢弃（隔离不因迟到结果翻转）
    assert _wait_until(lambda: a.diagnostic()["executor_threads_alive"] == 0,
                       timeout_s=8.0)
    assert a.snapshot()["loaded"] is False
    assert a.snapshot()["discarded_loads"] == 1
    assert a.diagnostic()["phase"] == "isolated"
    # 收敛后 close 干净退出
    r = a.close(timeout_s=5.0)
    assert r == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                 "close_incomplete": False}


def test_close_during_load_stops_and_discards_late_model(fake_upstream):
    """加载进行中 close：停止接单 + close_incomplete 如实；迟到的加载结果
    丢弃不采用（不重建实例绕过隔离）。"""
    ns = fake_upstream
    ns.state["load_delay"] = 0.8
    a = _adapter(ns, load_timeout_s=5.0)

    errs: list = []

    def _call():
        try:
            a.infer(_FRAME, _BOXES, _LABELS, ())
        except BaseException as exc:  # 线程内捕获：迟到模型被丢弃→AdapterIsolated
            errs.append(exc)

    t = threading.Thread(target=_call, name="c135-close-during-load")
    t.start()
    time.sleep(0.15)                 # 加载已开跑（0.15 << 0.8）
    assert a.diagnostic()["phase"] == "loading"

    r = a.close(timeout_s=0.3)       # 0.15+0.3 < 0.8：在途加载等不完
    assert r["closed"] is False and r["close_incomplete"] is True
    assert r["pending_calls"] >= 1 and r["threads_alive"] >= 1

    t.join(timeout=10.0)
    assert not t.is_alive()
    # C-137 B1：调用方收不到成功值——收到的必须是结构化拒收（加载闸门）
    assert errs and isinstance(errs[0], BaseException)
    assert getattr(errs[0], "code", None) == "backend_isolated"
    assert errs[0].details.get("reject_code") == "closed_rejected"
    assert _wait_until(lambda: a.diagnostic()["executor_threads_alive"] == 0,
                       timeout_s=8.0)
    snap = a.snapshot()
    assert snap["loaded"] is False and snap["discarded_loads"] == 1
    r2 = a.close(timeout_s=5.0)      # 收敛：干净收口
    assert r2 == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                  "close_incomplete": False}


# ---------------------------------------------------------------------------
# 4c. C-137 交付前重检（交付闸门）+ 统一关闭合同（B1/B2/B3/B4）
# ---------------------------------------------------------------------------


def test_close_midflight_caller_never_receives_success_value(fake_upstream):
    """C-137 B1/B4 交付闸门（确定性竞态）：阻塞推理 → close → 释放 →
    收集调用方实际收到的返回值/异常——必须是结构化拒收（closed_rejected），
    绝无成功值；代次随 close 递增；丢弃计数恰一次（回调/闸门不双计）。"""
    ns = fake_upstream
    a = _adapter(ns, infer_timeout_s=30.0)     # 调用方等得住：毒化不触发
    assert a.infer(_FRAME, _BOXES, _LABELS, ())  # 无 close 的普通交付不受影响
    gen_before = a.snapshot()["delivery_generation"]

    release = threading.Event()
    ns.state["block_event"] = release
    outcomes: list = []

    def _call():
        try:
            outcomes.append(("result", a.infer(_FRAME, _BOXES, _LABELS, ())))
        except BaseException as exc:
            outcomes.append(("exception", exc))

    t = threading.Thread(target=_call, name="c137-l2-midflight")
    t.start()
    assert _wait_until(
        lambda: a.snapshot()["pending_call_still_running"] is True,
        timeout_s=5.0)

    r = a.close(timeout_s=0.2)                 # 在途调用等不完
    assert r["closed"] is False and r["close_incomplete"] is True
    assert r["pending_calls"] >= 1 and r["threads_alive"] >= 1

    release.set()
    t.join(timeout=10.0)
    assert not t.is_alive()

    # 调用方实际收到的东西：一个结构化拒收异常，绝不是成功结果
    assert len(outcomes) == 1 and outcomes[0][0] == "exception"
    exc = outcomes[0][1]
    assert isinstance(exc, _AdapterIsolatedRaised)
    assert getattr(exc, "code", None) == "closed_rejected"
    assert exc.details.get("reject_code") == "closed_rejected"

    # 代次已随 close 递增；丢弃计数恰一次
    assert a.snapshot()["delivery_generation"] == gen_before + 1
    assert a.snapshot()["discarded_results"] == 1
    assert _wait_until(lambda: a.diagnostic()["executor_threads_alive"] == 0,
                       timeout_s=8.0)
    r2 = a.close(timeout_s=5.0)                # 收敛：干净收口
    assert r2 == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                  "close_incomplete": False}


def test_delivery_gate_generation_semantics(fake_upstream):
    """C-137 B1 generation 语义（确定性白盒）：代次随 close/隔离请求递增，
    交付时代次不符 → generation_rejected；裁决只读不改状态——无新 close
    的普通 infer 不受影响。"""
    ns = fake_upstream
    a = _adapter(ns)
    assert a.infer(_FRAME, _BOXES, _LABELS, ())
    gen = a.snapshot()["delivery_generation"]

    with a._lock:
        # 未关闭未毒化：仅代次不符即可触发（三条拒收码的第三条可达）
        assert a._delivery_reject_code_locked(gen) is None
        a._delivery_gen = gen + 1
        assert a._delivery_reject_code_locked(gen) == "generation_rejected"
        assert a._delivery_reject_code_locked(gen + 1) is None

    # 裁决只读：代次对齐后普通交付照常（无新 close 不受影响）
    assert a.infer(_FRAME, _BOXES, _LABELS, ())
    assert a.snapshot()["delivery_generation"] == gen + 1


def test_timeout_and_load_paths_never_deliver_success_values(fake_upstream):
    """C-137 B4：加载超时/推理超时——同一交付闸门合同：调用方收到结构化
    异常（拒绝或丢弃+拒收），绝不收到成功值；迟到结果/迟到模型只计丢弃。"""
    # (a) 加载超时：调用方收到 load_timeout（异常，非成功值）；迟到的加载
    #     完成后只进 discarded_loads，模型从未被任何人采用
    ns = fake_upstream
    ns.state["load_delay"] = 0.6
    a = _adapter(ns, load_timeout_s=0.2, infer_timeout_s=5.0)
    with pytest.raises(_ModelUnavailableRaised) as ei:
        a.infer(_FRAME, _BOXES, _LABELS, ())
    assert getattr(ei.value, "code", None) == "load_timeout"
    assert _wait_until(lambda: a.snapshot()["discarded_loads"] == 1,
                       timeout_s=8.0)
    assert a.snapshot()["loaded"] is False
    assert a.diagnostic()["executor_threads_alive"] == 0

    # (b) 推理超时：调用方收到 InferTimeout（异常，非成功值）；解除后迟到
    #     的成功结果只进 discarded_results，无第二接收方
    ns.state["load_delay"] = 0.0
    release = threading.Event()
    ns.state["block_event"] = release
    b = _adapter(ns, infer_timeout_s=0.2)
    with pytest.raises(InferTimeout):
        b.infer(_FRAME, _BOXES, _LABELS, ())
    release.set()
    assert _wait_until(lambda: b.snapshot()["discarded_results"] == 1,
                       timeout_s=8.0)
    assert b.snapshot()["poisoned"] is True    # 终态保持，绝不假装恢复


def test_runtime_shutdown_contract_uniform_across_backends(tmp_path):
    """C-137 B3：runtime 停机合同显式暴露——两 backend 的 diagnostic() 六
    冻结字段与 close(timeout_s)->dict 逐字段同形同口径（三态中的
    自身异常 error 码由各自专属用例覆盖；此处锁定空闲两态逐字段一致）。"""
    import inspect

    from scam.win11_l3_backend import LocalTransformersL3Backend

    for cls in (RelateAnythingAdapter, LocalTransformersL3Backend):
        csig = inspect.signature(cls.close)
        assert list(csig.parameters) == ["self", "timeout_s"]
        assert csig.parameters["timeout_s"].default == 5.0
        assert callable(cls.diagnostic)

    repo = _make_fake_repo(tmp_path)
    ckpt = _make_fake_checkpoint(tmp_path)
    l2 = RelateAnythingAdapter(str(repo), str(ckpt))
    l3_snap = tmp_path / "hf" / "snap-p"
    l3_snap.mkdir(parents=True)
    (l3_snap / "config.json").write_text("{}", encoding="utf-8")
    l3 = LocalTransformersL3Backend(model_path=str(l3_snap))

    six = {"phase", "load_stage", "pending_calls", "executor_threads_alive",
           "close_incomplete", "load_error"}
    assert set(l2.diagnostic()) == set(l3.diagnostic()) == six
    assert l2.diagnostic() == l3.diagnostic()   # 未加载初态逐字段同值

    r2 = l2.close(timeout_s=1.0)
    r3 = l3.close(timeout_s=1.0)
    assert r2 == r3 == {"closed": True, "pending_calls": 0, "threads_alive": 0,
                        "close_incomplete": False}
    assert l2.diagnostic() == l3.diagnostic()   # 关闭后同形（phase=isolated）


def test_source_mismatch_rejects_foreign_and_unverifiable_relsgg(monkeypatch, tmp_path):
    """来源防错配：sys.modules 已有 relsgg 且 __file__ 不在配置 repo_path 内
    （或来源不可验证）→ 结构化 source_mismatch，绝不静默使用错来源模块。"""
    repo = _make_fake_repo(tmp_path)
    ckpt = _make_fake_checkpoint(tmp_path)
    _FAKE_STATE.update({"block_event": None, "fail_on_predict": None,
                        "empty": False, "load_delay": 0.0, "fail_on_load": None})
    _FakeRelateAnythingCls.calls = []

    # 子例 1：__file__ 指向别处 → source_mismatch
    foreign = types.ModuleType("relsgg")
    foreign.RelateAnything = _FakeRelateAnythingCls
    foreign.__file__ = str(tmp_path / "elsewhere" / "relsgg" / "__init__.py")
    monkeypatch.setitem(sys.modules, "relsgg", foreign)
    a = RelateAnythingAdapter(str(repo), str(ckpt), infer_timeout_s=5.0)
    with pytest.raises(_ModelUnavailableRaised) as ei:
        a.infer(_FRAME, _BOXES, _LABELS, ())
    assert getattr(ei.value, "code", None) == "source_mismatch"
    assert "source_mismatch" in str(ei.value)
    assert _FakeRelateAnythingCls.calls == []        # 假加载从未被调用
    d = a.diagnostic()
    assert d["phase"] == "unloaded" and d["load_error"] is None
    assert not a.poisoned                            # 来源拒绝 ≠ 隔离
    _assert_no_abs_paths(d)

    # 子例 2：__file__ 缺失 → 来源不可验证 → 同样结构化拒绝
    anon = types.ModuleType("relsgg")
    anon.RelateAnything = _FakeRelateAnythingCls
    monkeypatch.setitem(sys.modules, "relsgg", anon)
    a2 = RelateAnythingAdapter(str(repo), str(ckpt), infer_timeout_s=5.0)
    with pytest.raises(_ModelUnavailableRaised) as ei2:
        a2.infer(_FRAME, _BOXES, _LABELS, ())
    assert getattr(ei2.value, "code", None) == "source_mismatch"

    # 拒绝发生在 import 之前：sys.path 未被注入
    assert str(repo) not in sys.path


def test_model_ref_carries_checkpoint_sha16_after_load(fake_upstream):
    """model_ref 区分权重实际版本：加载成功后尾段=checkpoint sha256 前 16 位
    （实算）；加载未成功时保留文件名占位。"""
    ns = fake_upstream
    a = _adapter(ns)
    assert a.model_ref == "relateanything/local/model.pth"   # 占位
    assert a.snapshot()["checkpoint_sha256_16"] is None

    a.infer(_FRAME, _BOXES, _LABELS, ())
    expected = hashlib.sha256(ns.ckpt.read_bytes()).hexdigest()[:16]
    assert a.model_ref == "relateanything/local/{}".format(expected)
    assert a.snapshot()["checkpoint_sha256_16"] == expected
    assert "/" in a.model_ref and not _DRIVE_PATH_RE.search(a.model_ref)


def test_load_failure_health_face_has_no_absolute_paths(fake_upstream):
    """健康面字段不含绝对路径：load_error 只含类型与失败阶段（详细异常只进
    本机日志/抛出的结构化异常）。"""
    ns = fake_upstream
    ns.state["fail_on_load"] = RuntimeError(
        "boom: C:\\Users\\someone\\snap\\model.pth is not a checkpoint")
    a = _adapter(ns)
    with pytest.raises(_ModelUnavailableRaised) as ei:
        a.infer(_FRAME, _BOXES, _LABELS, ())
    assert getattr(ei.value, "code", None) == "model_unavailable"
    assert getattr(ei.value, "missing"), "详细异常（含路径）走结构化异常/本机日志"

    d = a.diagnostic()
    assert d["load_error"] == "RuntimeError: checkpoint failed"
    assert d["phase"] == "unloaded"
    _assert_no_abs_paths(d)
    _assert_no_abs_paths(a.snapshot())


# ---------------------------------------------------------------------------
# 5. 真实模型证据（slow；依赖缺失→skip，理由如实）
# ---------------------------------------------------------------------------


def _real_checkpoint():
    snaps = sorted(HF_SNAPSHOT_DIR.glob("*/model.pth"))
    return snaps[0] if snaps else None


@pytest.mark.slow
@pytest.mark.skipif(not UPSTREAM_REPO.exists(),
                    reason="上游克隆不存在（D:\\Program\\Zcode\\RelateAnything）")
@pytest.mark.skipif(_real_checkpoint() is None,
                    reason="relsgg-vits16plus 权重不在本机 HF 缓存；按约定不联网下载")
def test_real_infer_evidence_on_fixed_material():
    """真实加载 + 真实推理：素材路径由 SCAM_REAL_MATERIAL 指定。
    证据（三元组+耗时+model_ref+权重 sha256 前 16 位）写 %TEMP%/c134_l2/。
    框为固定手摆框（适配器冒烟证据，非检测器输出）——如实记录。"""
    torch = pytest.importorskip("torch", reason="本解释器缺 torch：真实加载不可行")
    cv2 = pytest.importorskip("cv2", reason="缺 cv2：无法从固定素材抽帧")

    ckpt = _real_checkpoint()
    cap = cv2.VideoCapture(str(REAL_MATERIAL))
    if not cap.isOpened():
        pytest.skip(f"固定素材无法打开：{REAL_MATERIAL}")
    cap.set(cv2.CAP_PROP_POS_FRAMES, 30)
    ok, frame = cap.read()
    cap.release()
    if not ok:
        pytest.skip(f"固定素材第 30 帧无法解码：{REAL_MATERIAL}")
    h, w = frame.shape[:2]

    vocabulary = ("holding", "standing beside", "walking past",
                  "looking at", "carrying", "talking to")
    a = RelateAnythingAdapter(str(UPSTREAM_REPO), str(ckpt),
                              vocabulary=vocabulary, infer_timeout_s=120.0)
    boxes = [
        (0.34 * w, 0.22 * h, 0.56 * w, 0.88 * h),
        (0.54 * w, 0.28 * h, 0.74 * w, 0.88 * h),
    ]

    t0 = time.perf_counter()
    result = a.infer(frame, boxes, ["person-a", "person-b"], vocabulary)
    first_ms = (time.perf_counter() - t0) * 1000.0     # 含首次 import+权重加载
    t1 = time.perf_counter()
    warm = a.infer(frame, boxes, ["person-a", "person-b"], vocabulary)
    warm_ms = (time.perf_counter() - t1) * 1000.0      # 纯 predict 路径

    # 结构断言（内容不预设：记录什么就是什么，分数原样）
    assert isinstance(result, list)
    for item in list(result) + list(warm):
        assert set(item) == {"s", "o", "relation", "graph", "score"}
        assert item["graph"] in ("spatial", "semantic")
        assert isinstance(item["s"], int) and isinstance(item["o"], int)
        assert 0 <= item["s"] < len(boxes) and 0 <= item["o"] < len(boxes)
        assert isinstance(item["relation"], str) and item["relation"]
        assert isinstance(item["score"], float) and 0.0 <= item["score"] <= 1.0
    snap = a.snapshot()
    assert snap["loaded"] is True and snap["poisoned"] is False

    # C-135 生命周期真实路径：phase ready / 阶段推进 done / 加载分段计时
    diag = a.diagnostic()
    assert diag["phase"] == "ready" and diag["load_stage"] == "done"
    assert diag["load_error"] is None
    assert snap["load_stages_seen"] == ["import", "checkpoint", "vocabulary", "done"]
    assert snap["load_ms"] and snap["load_ms"]["total_ms"] > 0.0

    # 权重指纹（sha256 前 16 位，独立实算并与 model_ref 对账）
    sha = hashlib.sha256()
    with open(ckpt, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha.update(chunk)
    sha16 = sha.hexdigest()[:16]

    evidence = {
        "title": "C-135 L2 真实 RelateAnything 适配器本机推理证据",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "model_ref": a.model_ref,
        "upstream_repo": str(UPSTREAM_REPO),
        "upstream_commit": a.model_ref.split("/")[1],
        "checkpoint_file": ckpt.name,
        "checkpoint_snapshot_dir": ckpt.parent.name,
        "checkpoint_sha256_16": sha16,
        "torch": torch.__version__,
        "frame_source": str(REAL_MATERIAL),
        "frame_index": 30,
        "frame_size_hw": [h, w],
        "boxes_source": "fixed hand-placed boxes (adapter evidence, not detector output)",
        "boxes_px": [[round(float(v), 1) for v in b] for b in boxes],
        "vocabulary": list(vocabulary),
        "first_infer_ms_incl_load": round(first_ms, 1),
        "warm_infer_ms": round(warm_ms, 1),
        "load_ms_by_stage": snap["load_ms"],
        "triplets_first_call": result,
        "triplets_warm_call": warm,
        "snapshot_after": snap,
        "timeout_policy": "infer_timeout_s=120 (test generous); production default 10.0",
    }
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVIDENCE_DIR / "real-infer.json"
    out_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=1),
                        encoding="utf-8")
    assert out_path.exists()
    # C-135：加载成功后 model_ref 尾段=权重实际版本（sha256 前 16 位）
    assert re.fullmatch(r"relateanything/[0-9a-f]{12}/[0-9a-f]{16}",
                        evidence["model_ref"]), evidence["model_ref"]
    assert evidence["model_ref"].rsplit("/", 1)[1] == sha16
    assert a.snapshot()["checkpoint_sha256_16"] == sha16


# ---------------------------------------------------------------------------
# 6. 生产禁 fake（静态契约）
# ---------------------------------------------------------------------------


def test_backend_module_has_no_fake_or_network_paths():
    """backend 模块代码（docstring 叙述除外）不得含任何下载/网络/子进程路径。"""
    import ast

    src_path = Path(backend.__file__)
    tree = ast.parse(src_path.read_text(encoding="utf-8"))
    if (tree.body and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
            and isinstance(tree.body[0].value.value, str)):
        tree.body = tree.body[1:]          # 去掉模块 docstring（许可证/文档叙述）
    code_src = ast.unparse(tree)
    for forbidden in ("from_pretrained", "snapshot_download", "hf_hub_download",
                      "urlopen", "requests.", "subprocess"):
        assert forbidden not in code_src, f"backend 模块代码不得出现 {forbidden}"


def test_nvr_l2_wiring_must_come_from_real_backend():
    """契约：nvr.py 一旦出现 L2 构造，必须 import scam.win11_l2_backend；
    任何 fake L2 形态都禁止（生产禁 fake，L2-接口冻结-C134.md §0/§5）。"""
    import scam

    nvr_path = Path(scam.__file__).parent / "nvr.py"
    assert nvr_path.exists(), "生产入口 scam/nvr.py 不存在"
    src = nvr_path.read_text(encoding="utf-8")

    for marker in ("FakeL2", "fake_l2", "FakeRelation", "StubL2", "MockL2",
                   "FakeRelateAnything", "RelateAnythingFake"):
        assert marker not in src, f"生产入口出现 fake L2 标记：{marker}"

    constructs_l2 = any(c in src for c in (
        "RelateAnythingAdapter(", "L2RelationStage(", "L2RelationModel(",
        "win11_l2_contract", "l2_model",
    ))
    if constructs_l2 or "RelateAnything" in src:
        assert "win11_l2_backend" in src, (
            "nvr.py 存在 L2 构造则必须来自 scam.win11_l2_backend 的真实 adapter"
            "（生产禁 fake）")


# ---------------------------------------------------------------------------
# 7. C-136：timeout 参数口径一致性回归
# ---------------------------------------------------------------------------


def test_close_timeout_parameter_naming_is_uniform_across_backends():
    """C-136 B1：backend 的 close 等待参数全仓统一 ``*_timeout_s`` 口径——
    l2/l3 两个 backend 的 close 签名必须是 timeout_s（kwargs-only 关键字），
    任何裸 ``timeout`` 参数都是回归。nvr.py 历史调用
    ``adapter.close(timeout=...)``（nvr.py:107）与冻结签名
    ``close(timeout_s=5.0)`` 不一致——现网该调用抛 TypeError 被停机路径
    吞掉、adapter executor 从不 join，归主会话 M1 改为 ``timeout_s=``。"""
    import inspect

    from scam.win11_l3_backend import LocalTransformersL3Backend

    for cls in (RelateAnythingAdapter, LocalTransformersL3Backend):
        close_params = inspect.signature(cls.close).parameters
        assert "timeout_s" in close_params, \
            "{}.close 必须用 timeout_s 口径".format(cls.__name__)
        assert "timeout" not in close_params, \
            "{}.close 不得出现裸 timeout 参数".format(cls.__name__)
        init_params = inspect.signature(cls.__init__).parameters
        assert "timeout" not in init_params, \
            "{}.__init__ 不得出现裸 timeout 参数（统一 *_timeout_s）".format(
                cls.__name__)
