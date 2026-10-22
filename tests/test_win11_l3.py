"""C-135 tests: scam.win11_l3 —— L3Stage 状态机 + LocalTransformers 薄壳适配器。

覆盖（L2L3-接口冻结-C135.md §8 第二/三条 + C-136 C2/C3/C4 整改）：
- 合同（零模型依赖）：__slots__ 冻结、frame_bgr 隔离副本+只读、enhanced
  默认 None、预算冻结默认值、状态/分支枚举冻结值、窗口-帧身份匹配、
  InternVL 预算口径常量（448/14/0.5 → 256 token/帧段）；
- 假模型注入 stage（禁 fake 进生产——生产入口只在本仓 models.py 真实路径）：
  ok / partial（缺帧）/ identity_rejected（身份与分支错配，模型零调用）/
  unsupported（空帧、全缺帧、非法数组、prompt 携带 <image>）/ 失败四分类
  （model_unavailable、infer_failed、timeout、backend_isolated）/ 预算截断
  与降采样显式进 omission / 任务预算优先 / 并发=1 信号量闸 / 在途 gauge；
- C-136 C2 缺帧固定序位：序位 0 基（0=前/1=当前/2=后）、缺帧保留序位
  present=False、只有 cur 在场 partial 如实、帧间隔（缺帧侧 None）与
  region_only 进结果；
- C-136 C3 实际模型预算：原图/传输/真实 patch-token 三层记账、调用边界
  断言、448 输入 → effective_patch=1/帧 tokens=256/帧、降采样被 provider
  放回 448 不虚报 patch 预算下降、失败侧如实携带/未到边界为 None；
- C-136 C4 结构化输出：模型 dict（observation/inference 键）→ 结构化
  unstructured=False；纯文本/未知 dict → 原文保留 + unstructured=True；
  结果自带 window/crop_id/model_ref 身份；
- C-139 失败血缘（R2）：失败/拒绝终态产单条失败分支结果——窗口（含
  material 附加段）/分支/crop_id/帧身份/观察钟时间/时间类型/帧间隔从
  task 透传不清空，观察/推断/不确定性置 None 不编造；失败分类保留
  adapter 结构化细分码（detail_code 受控词表：load_timeout/
  closed_rejected/poisoned_rejected/...，词表外回退分类码）；
- 窗口输入冻结：模型收到的帧与元信息恰为 task.frames 给定内容（不扩窗）；
- LocalTransformersL3Adapter（薄壳；C-136 起生产适配器归 win11_l3_backend.py
  由 B 交付，本文件保留 C-135 交付薄壳的既有覆盖）：BGR→b64→真实多帧路径
  （捕获 chat：pixel_values 行数=帧数、占位符数=帧数、缺帧占位不编码）；
  加载失败→L3ModelUnavailable；等待超时→timeout + poisoned + 残留如实
  （线程不可中止，绝不假装取消/恢复）；此后一律立即 L3AdapterIsolated；
  上游自身 TimeoutError（future 已完成）→infer_failed 不毒化（C-134 同一
  区分）。

注：prompt 内「第 N 帧缺失」标注由模型适配层渲染（models.py，人类可读
1 基标签），合同序位（0 基固定）经 frames_meta.position 直通；stage 级
测试断言 frames_meta 的 position/present 直通模型协议；prompt 级断言在
tests/test_models.py 与本文件的捕获测试（走真实 LocalTransformers 路径）。
"""

from __future__ import annotations

import threading
import time

import numpy as np
import pytest

from scam import win11_l3 as l3
from scam.models import LocalTransformers
from scam.win11_l3_contract import (
    INTERNVL_DOWNSAMPLE,
    INTERNVL_IMAGE_SIDE,
    INTERNVL_PATCH_SIDE,
    INTERNVL_TOKENS_PER_PATCH_SEGMENT,
    L3AdapterIsolated,
    L3BranchKind,
    L3BranchResult,
    L3Budget,
    L3BudgetAccounting,
    L3FrameBudgetUsage,
    L3FrameIdentity,
    L3FrameInput,
    L3ModelUnavailable,
    L3Status,
    L3Task,
    L3Uncertainty,
    L3VisionModel,
    L3WindowIdentity,
    window_matches_frame,
)


# ---------------------------------------------------------------------------
# 工具：假 L3 模型（仅测试注入）与任务构造
# ---------------------------------------------------------------------------

class _FakeL3Model:
    """L3VisionModel 假实现：记录调用、可配置返回/异常/耗时/并发观测。"""

    model_ref = "fake/l3"

    def __init__(self, result=None, exc=None, sleep_s=0.0):
        self.calls = []
        self._result = result
        self._exc = exc
        self._sleep_s = sleep_s
        self._lock = threading.Lock()
        self._cur = 0
        self.max_concurrent = 0

    def understand_frames(self, prompt, frames_bgr, frames_meta):
        with self._lock:
            self.calls.append({
                "prompt": prompt,
                "frames": [None if f is None else tuple(f.shape)
                           for f in frames_bgr],
                "meta": [dict(m) for m in frames_meta],
            })
            self._cur += 1
            self.max_concurrent = max(self.max_concurrent, self._cur)
        try:
            if self._sleep_s:
                time.sleep(self._sleep_s)
            if self._exc is not None:
                raise self._exc
            if self._result is not None:
                return self._result
            return {"observation": "画面观察文本", "inference": "时序推断文本"}
        finally:
            with self._lock:
                self._cur -= 1


def _frame(fid="f1", cam="c1", run="r1", cfg=1,
           branch=L3BranchKind.PANORAMA, shape=(4, 6, 3), t=1000,
           present=True, enhanced=None):
    """present=False 即显式缺帧占位（frame_bgr=None 的 L3FrameInput）。"""
    ident = L3FrameIdentity(cam, run, cfg, fid)
    arr = np.full(shape, 1, dtype=np.uint8) if present else None
    return L3FrameInput(branch=branch, identity=ident, t_capture_ms=t,
                        timestamp_kind="observed", frame_bgr=arr,
                        enhanced=enhanced)


def _task(frames, branch=L3BranchKind.PANORAMA, prompt="分析画面变化。",
          budget=None, window=None, crop_id=None):
    return L3Task(window=window or L3WindowIdentity("c1", "r1", 1, "w1"),
                  branch=branch, frames=frames, prompt=prompt, budget=budget,
                  crop_id=crop_id)


# ---------------------------------------------------------------------------
# 1. 合同：形状/枚举/预算/隔离副本
# ---------------------------------------------------------------------------

def test_contract_slots_frozen():
    fr = _frame()
    with pytest.raises(AttributeError):
        fr.nonexistent = 1
    task = _task([fr])
    with pytest.raises(AttributeError):
        task.nonexistent = 1


def test_frame_bgr_is_isolated_readonly_copy():
    raw = np.full((4, 6, 3), 1, dtype=np.uint8)
    fr = L3FrameInput(L3BranchKind.PANORAMA,
                      L3FrameIdentity("c1", "r1", 1, "f2"),
                      1000, "observed", raw)
    raw[:] = 9                                   # 调用方后续改写原数组
    assert fr.frame_bgr[0, 0, 0] == 1            # 任务副本不受影响
    with pytest.raises(ValueError):
        fr.frame_bgr[0, 0, 0] = 5                # 只读：L3 只读消费
    assert L3FrameInput(L3BranchKind.PANORAMA,
                        L3FrameIdentity("c1", "r1", 1, "f3"),
                        1000, "observed", None).frame_bgr is None


def test_enhanced_defaults_to_none_explicit_unenhanced():
    assert _frame().enhanced is None
    assert _frame(enhanced=np.zeros((2, 2, 3),
                                    np.uint8)).enhanced is not None


def test_budget_frozen_defaults():
    b = L3Budget()
    assert b.max_frames_per_task == 8
    assert b.max_total_pixels == 8 * 448 * 448
    assert b.max_queue == 4
    assert b.in_flight == 1
    assert b.concurrency == 1


def test_status_enum_frozen_eight_values():
    assert {s.value for s in L3Status} == {
        "ok", "partial", "unsupported", "model_unavailable", "infer_failed",
        "timeout", "backend_isolated", "identity_rejected"}


def test_branch_kind_frozen_values():
    assert {b.value for b in L3BranchKind} == {
        "panorama", "relation_crop", "change_region"}


def test_internvl_budget_constants_frozen():
    """C-136 C3 口径常量：InternVL 448/14/0.5 → 每帧 1 patch 段=256 token。"""
    assert INTERNVL_IMAGE_SIDE == 448
    assert INTERNVL_PATCH_SIDE == 14
    assert INTERNVL_DOWNSAMPLE == 0.5
    assert INTERNVL_TOKENS_PER_PATCH_SEGMENT == 256
    assert (INTERNVL_IMAGE_SIDE // INTERNVL_PATCH_SIDE) ** 2 \
        * INTERNVL_DOWNSAMPLE ** 2 == 256


def test_task_frames_coerced_to_tuple():
    task = _task([_frame("a"), _frame("b")])
    assert isinstance(task.frames, tuple) and len(task.frames) == 2


def test_window_matches_frame_helper():
    window = L3WindowIdentity("c1", "r1", 1, "w1")
    assert window_matches_frame(window, L3FrameIdentity("c1", "r1", 1, "f9"))
    assert not window_matches_frame(window,
                                    L3FrameIdentity("c1", "r2", 1, "f1"))
    assert not window_matches_frame(window,
                                    L3FrameIdentity("c1", "r1", 2, "f1"))
    assert not window_matches_frame(window,
                                    L3FrameIdentity("c2", "r1", 1, "f1"))


# ---------------------------------------------------------------------------
# 2. 状态机（假模型注入 stage）
# ---------------------------------------------------------------------------

def test_ok_all_frames_present():
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake)
    out = stage.process(_task([_frame("a", t=100), _frame("b", t=300),
                               _frame("c", t=500)]))

    assert out.status == L3Status.OK and out.error_code is None
    assert out.model_ref == "fake/l3"
    (result,) = out.results
    assert isinstance(result, L3BranchResult)
    assert result.observation == "画面观察文本"
    assert result.inference == "时序推断文本"
    assert result.unstructured is False          # dict 显式键 → 结构化
    u = result.uncertainty
    assert (u.frame_missing, u.frames_truncated, u.pixels_downscaled,
            u.unenhanced) == (False, False, False, True)
    # C-136 C2：序位 0 基固定（0=前、1=当前、2=后）
    assert [s.position for s in result.sources] == [0, 1, 2]
    assert all(s.present for s in result.sources)
    assert result.frame_gaps_ms == (200.0, 200.0)   # 观察钟间隔进结果
    assert result.region_only is True               # 同区域不保证同一对象
    assert result.window is out.window              # 窗口身份随结果
    assert result.crop_id is None
    assert result.model_ref == "fake/l3"
    assert out.omission.frames_dropped == 0
    assert set(out.timings_ms) >= {"preprocess", "infer", "total"}
    # 窗口冻结：模型收到的恰是任务给定的 3 帧（不扩窗）
    assert len(fake.calls) == 1 and len(fake.calls[0]["frames"]) == 3
    assert stage.snapshot()["in_flight"] == 0


def test_partial_on_missing_frame_placeholder_passes_through_honestly():
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake)
    out = stage.process(_task([_frame("cur", t=300),
                               _frame("prev", t=100, present=False)]))

    assert out.status == L3Status.PARTIAL
    (result,) = out.results
    assert result.uncertainty.frame_missing is True
    # C-136 C2：只有 cur 在场绝不呈现三帧齐全；序位 0 基、缺帧保留序位
    assert [s.position for s in result.sources] == [0, 1]
    assert [s.present for s in result.sources] == [True, False]
    # 缺帧位仍是输入给的帧身份，绝不伪造来源
    assert result.sources[1].frame_id == "prev"
    assert result.frame_gaps_ms == (None,)       # 缺帧侧间隔未知，如实
    assert out.omission.frames_dropped == 0      # 缺帧≠丢弃（记账分离）
    # 缺帧占位 None 直通模型协议（适配层跳过编码）；present=False 进元信息
    assert fake.calls[0]["frames"][1] is None
    assert fake.calls[0]["meta"][1]["present"] is False
    assert fake.calls[0]["meta"][0]["position"] == 0    # 序位 0 基直通
    assert fake.calls[0]["meta"][1]["position"] == 1


def test_identity_rejected_mismatch_no_model_call():
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake)
    out = stage.process(_task([_frame("a"), _frame("b", run="r2")]))
    assert out.status == L3Status.IDENTITY_REJECTED
    assert out.error_code == "identity_mismatch:frame1"
    assert not fake.calls
    # C-139 §3：拒绝态保留已知身份事实（窗口/分支随行，文本不编造）
    (result,) = out.results
    assert result.status == L3Status.IDENTITY_REJECTED
    assert result.observation is None and result.inference is None
    assert result.window is out.window and result.branch is out.branch


def test_identity_rejected_branch_mismatch():
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake)
    out = stage.process(
        _task([_frame("a", branch=L3BranchKind.CHANGE_REGION)]))
    assert out.status == L3Status.IDENTITY_REJECTED
    assert out.error_code == "branch_mismatch:frame0"
    assert not fake.calls


def test_unsupported_cases():
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake)
    assert stage.process(_task([])).error_code == "empty_frames"
    assert stage.process(
        _task([_frame("a", present=False),
               _frame("b", present=False)])).error_code == "no_present_frames"
    bad = stage.process(_task([_frame("a", shape=(0, 6, 3))]))
    assert bad.status == L3Status.UNSUPPORTED
    assert bad.error_code == "invalid_frame:frame0"
    out = stage.process(_task([_frame("a")], prompt="图：<image> 描述。"))
    assert out.status == L3Status.UNSUPPORTED
    assert out.error_code == "prompt_contains_image_marker"
    assert not fake.calls                        # 所有 unsupported 零模型调用


def test_model_exception_four_classification():
    cases = [
        (L3ModelUnavailable("no weights"), L3Status.MODEL_UNAVAILABLE,
         "model_unavailable"),
        (ValueError("upstream boom"), L3Status.INFER_FAILED, "infer_failed"),
        (TimeoutError("upstream slow"), L3Status.TIMEOUT, "timeout"),
        (L3AdapterIsolated("poisoned"), L3Status.BACKEND_ISOLATED,
         "backend_isolated"),
    ]
    for exc, want_status, want_code in cases:
        fake = _FakeL3Model(exc=exc)
        stage = l3.L3Stage(fake)
        out = stage.process(_task([_frame("a")]))
        assert out.status == want_status, exc
        assert out.error_code == want_code
        # 失败态不产出观察/推断文本；已知身份事实随失败结果保留
        (result,) = out.results
        assert result.status == want_status
        assert result.error_code == want_code
        assert result.observation is None and result.inference is None
        assert result.uncertainty is None


def test_failure_result_preserves_task_identity_crop_and_frames():
    """C-139 §3：失败（stage 异常/超时/拒绝）不清空已知材料事实——窗口
    （含 material 附加段）/分支/crop_id/帧身份/观察钟时间/时间类型/帧间隔
    从 task 透传到失败结果。"""
    window = L3WindowIdentity("c1", "r1", 1, "w1", material_id=42)
    frames = [_frame("prev", t=100), _frame("frame2", t=300, present=False),
              _frame("nxt", t=500)]
    task = _task(frames, crop_id="cropA", window=window)
    fake = _FakeL3Model(exc=TimeoutError("slow"))
    out = l3.L3Stage(fake).process(task)
    assert out.status == L3Status.TIMEOUT
    assert len(fake.calls) == 1                   # 模型被调用后超时失败
    (result,) = out.results
    assert result.window is window and window.material_id == 42
    assert result.branch == task.branch and result.crop_id == "cropA"
    assert [(s.position, s.frame_id) for s in result.sources] == \
        [(0, "prev"), (1, "frame2"), (2, "nxt")]
    assert [s.present for s in result.sources] == [True, False, True]
    assert [s.t_capture_ms for s in result.sources] == [100, 300, 500]
    assert all(s.timestamp_kind == "observed" for s in result.sources)
    assert result.frame_gaps_ms == (None, None)   # 缺帧任一侧→间隔未知如实
    assert result.model_ref == "fake/l3" == out.model_ref


def test_failure_detail_code_refined_from_structured_exception():
    """C-139-R1 §2 detail_code 受控词表：adapter 结构化异常的细分码
    （.code）原样保留不压平；词表外码回退 stage 分类码（不透传未受控
    字符串）。加载超时模型 → detail_code=load_timeout。"""
    load_boom = L3ModelUnavailable("load exceeded budget")
    load_boom.code = "load_timeout"               # adapter 结构化细分码
    out = l3.L3Stage(_FakeL3Model(exc=load_boom)).process(
        _task([_frame("a", shape=(4, 4, 3))]))
    assert out.status == L3Status.MODEL_UNAVAILABLE
    assert out.error_code == "load_timeout"
    (result,) = out.results
    assert result.error_code == "load_timeout"

    iso = L3AdapterIsolated("closed", details={"code": "closed_rejected"})
    iso.code = "closed_rejected"
    out2 = l3.L3Stage(_FakeL3Model(exc=iso)).process(_task([_frame("a")]))
    assert out2.status == L3Status.BACKEND_ISOLATED
    assert out2.error_code == "closed_rejected"

    poison = L3AdapterIsolated("poisoned")
    poison.code = "poisoned_rejected"
    out3 = l3.L3Stage(_FakeL3Model(exc=poison)).process(_task([_frame("a")]))
    assert out3.status == L3Status.BACKEND_ISOLATED
    assert out3.error_code == "poisoned_rejected"

    rogue = ValueError("upstream boom")
    rogue.code = "not:in:vocabulary"              # 词表外 → 回退分类码
    out4 = l3.L3Stage(_FakeL3Model(exc=rogue)).process(_task([_frame("a")]))
    assert out4.status == L3Status.INFER_FAILED
    assert out4.error_code == "infer_failed"


def test_budget_truncates_frames_into_omission():
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake, budget=L3Budget(max_frames_per_task=4))
    frames = [_frame(f"f{i}", t=i) for i in range(10)]
    out = stage.process(_task(frames))

    assert out.status == L3Status.PARTIAL
    assert out.omission.frames_dropped == 6
    assert "frames_budget_cap=6" in out.omission.reason
    (result,) = out.results
    assert result.uncertainty.frames_truncated is True
    assert len(result.sources) == 4
    # C153 A：模型输入侧序位仍稠密 0..M-1（prompt 固定序位声明成立），
    # 保留帧在**原窗口**的原位次由 omission 记账单独给出（不塌缩、不丢）。
    assert [s.position for s in result.sources] == [0, 1, 2, 3]
    assert len(fake.calls[0]["frames"]) == 4
    assert [m["frame_id"] for m in fake.calls[0]["meta"]] == \
        ["f0", "f1", "f5", "f9"]          # 首帧 + 中间等距取样 + 最新帧
    assert [m["position"] for m in fake.calls[0]["meta"]] == [0, 1, 2, 3]
    # 被省略的原窗口原位次如实进 omission（不静默）；角色只有首/末是真锚点，
    # 中间帧是**中间采样**（C153-R1 §4：等距中间帧不得自动称为"关键转折"）
    assert "kept_positions=0,1,5,9" in out.omission.reason
    assert "dropped_positions=2,3,4,6,7,8" in out.omission.reason
    assert ("roles=0:start,1:middle_sample,5:middle_sample,9:latest"
            in out.omission.reason)
    # 无来源可追溯的转折标记 → omission 必须如实写"转折覆盖未证明"
    assert "turn_coverage=中间采样，转折覆盖未证明" in out.omission.reason
    assert "turning" not in out.omission.reason
    # prompt 不制造"连续过程"错觉：如实声明这是保留帧子集
    assert "原窗口原位次 0,1,5,9" in fake.calls[0]["prompt"]
    assert "不虚构完整连续过程" in fake.calls[0]["prompt"]


def test_budget_downscales_pixels_explicitly():
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake, budget=L3Budget(max_total_pixels=100))
    out = stage.process(_task([_frame("a", shape=(8, 8, 3)),
                               _frame("b", shape=(8, 8, 3))]))

    assert out.status == L3Status.PARTIAL
    (result,) = out.results
    assert result.uncertainty.pixels_downscaled is True
    assert "pixels_downscaled=1" in out.omission.reason
    assert fake.calls[0]["frames"] == [(7, 7, 3), (7, 7, 3)]  # 98 ≤ 100


def test_preprocess_bounds_long_side_to_448():
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake)
    stage.process(_task([_frame("a", shape=(100, 800, 3))]))
    h, w = fake.calls[0]["frames"][0][:2]
    assert max(h, w) == 448 and (h, w) == (56, 448)   # 等比、只缩不放


def test_task_budget_takes_precedence_over_stage_budget():
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake, budget=L3Budget(max_frames_per_task=8))
    out = stage.process(_task([_frame(f"f{i}") for i in range(3)],
                              budget=L3Budget(max_frames_per_task=2)))
    assert out.omission.frames_dropped == 1
    assert len(fake.calls[0]["frames"]) == 2


def test_concurrency_one_semaphore_gate():
    fake = _FakeL3Model(sleep_s=0.05)
    stage = l3.L3Stage(fake, budget=L3Budget(concurrency=1))
    tasks = [_task([_frame(f"f{i}")]) for i in range(3)]
    threads = [threading.Thread(target=stage.process, args=(t,))
               for t in tasks]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert fake.max_concurrent == 1          # 模型调用并发恒 ≤ concurrency


def test_stage_snapshot_reports_gauge_and_budget_passthrough():
    stage = l3.L3Stage(_FakeL3Model(), budget=L3Budget(concurrency=2))
    snap = stage.snapshot()
    assert snap["in_flight"] == 0
    assert snap["concurrency"] == 2
    assert snap["max_frames_per_task"] == 8
    assert snap["max_queue"] == 4            # 生产队列字段，stage 不排队
    assert snap["max_total_pixels"] == 8 * 448 * 448
    assert snap["model_image_side"] == 448
    assert snap["tokens_per_patch_segment"] == 256


class _ProbingTimeoutModel:
    """等待超时但执行未结束的 model 替身（自报探测源同生产 adapter 形状）。

    `understand_frames` 抛 TimeoutError（stage 按 TimeoutError 分类），
    `snapshot()` 自报"实际执行是否仍在跑"——用于验证执行资源不提前返还。
    """

    model_ref = "fake/probing-timeout"

    def __init__(self):
        self.calls = 0
        self.still_running = True
        self.poisoned = False
        self.close_requested = False
        self.phase = "ready"

    def understand_frames(self, prompt, frames_bgr, frames_meta):
        self.calls += 1
        if self.still_running:
            raise TimeoutError("wait timeout: worker call NOT cancelled")
        return {"observation": "画面恢复", "inference": "对象继续移动"}

    def snapshot(self):
        return {
            "pending_call_still_running": bool(self.still_running),
            "pending_calls": 1 if self.still_running else 0,
            "executor_threads_alive": 1 if self.still_running else 0,
            "poisoned": self.poisoned,
            "close_requested": self.close_requested,
            "phase": self.phase,
        }


def test_wait_timeout_keeps_execution_resource_until_evidence():
    """C153-R1 §2：等待超时**未中止**的调用，其执行资源（并发槽 + 在途
    gauge）不提前返还；只有在证据表明实际执行结束后才返还；占用期间后续
    分支如实判 timeout（**不再发第二次模型调用**），不超发。"""
    model = _ProbingTimeoutModel()
    stage = l3.L3Stage(model, budget=L3Budget(concurrency=1),
                       slot_wait_timeout_s=0.3)
    frames = [_frame("a")]

    first = stage.process(_task(frames))
    assert first.status == L3Status.TIMEOUT
    assert model.calls == 1
    res = stage.execution_resources()
    assert res["in_flight"] == 1             # 执行仍在跑 → gauge 不返还
    assert res["held_unfinished"] == 1
    assert res["concurrency"] == 1

    # 占用期间：后续分支拿不到槽位 → 如实 timeout，且**没有**发出新调用
    second = stage.process(_task(frames))
    assert second.status == L3Status.TIMEOUT
    assert "concurrency_unavailable=1" in second.omission.reason
    assert "held_unfinished=1" in second.omission.reason
    assert model.calls == 1, "执行资源未返还时绝不超发第二次调用"

    # 证据（model 自报执行结束）→ 回收槽位，后续任务恢复正常
    model.still_running = False
    third = stage.process(_task(frames))
    assert third.status == L3Status.OK
    assert model.calls == 2
    res = stage.execution_resources()
    assert res["in_flight"] == 0 and res["held_unfinished"] == 0


def test_poisoned_model_is_refused_immediately_not_starved():
    """model 自报已隔离/关闭 → 不空等槽位，立即如实判 backend_isolated。"""
    model = _ProbingTimeoutModel()
    stage = l3.L3Stage(model, budget=L3Budget(concurrency=1),
                       slot_wait_timeout_s=30.0)   # 若空等会超时失败
    frames = [_frame("a")]
    assert stage.process(_task(frames)).status == L3Status.TIMEOUT
    model.poisoned = True
    model.phase = "poisoned"
    started = time.monotonic()
    out = stage.process(_task(frames))
    elapsed = time.monotonic() - started
    assert out.status == L3Status.BACKEND_ISOLATED
    assert out.error_code == "backend_isolated"
    assert "model_refuses_new_work=1" in out.omission.reason
    assert elapsed < 5.0, "已隔离的 provider 不得让后续分支长期饥饿"
    assert model.calls == 1, "隔离拒收路径不派新调用"

    # C153-R1 §3：收口请求**只回收真实结束**的执行——model 仍自报在跑
    # （`still_running=True`）→ 记录、槽位与 gauge 一律保留（不假装释放）
    assert stage.release_held_executions() == 0
    res = stage.execution_resources()
    assert res["held_unfinished"] == 1, "执行未结束 → 记录不得被收口清空"
    assert res["in_flight"] == 1, "执行未结束 → 槽位/gauge 不得归零"
    assert res["reclaimed_total"] == 0, "无真实结束证据 → 一次也不得回收"
    (held,) = res["held"]
    assert held["branch_key"] == ["c1", "r1", 1, "w1", "panorama", None, None], \
        "在途执行必须带可识别身份（task/branch 键）"

    # 真实结束（model 自报执行线程已退出）→ 恰一次回收；重复收口不重复释放
    model.still_running = False
    assert stage.release_held_executions() == 1
    assert stage.execution_resources()["held_unfinished"] == 0
    assert stage.execution_resources()["in_flight"] == 0
    assert stage.release_held_executions() == 0        # 幂等
    assert stage.execution_resources()["reclaimed_total"] == 1


def test_future_completion_is_the_end_evidence_for_execution_resource():
    """C153-R1 §3：执行结束证据以**真实 future 完成**（`future.done()`，生产
    adapter 的 `pending_call_done`）为准——future 未完成 → 槽位/gauge 保持
    占用且收口不回收；`future.done()` → **恰一次**回收（不靠线程计数口径）。"""

    class _FutureProbeModel:
        model_ref = "fake/future-probe"

        def __init__(self):
            self.calls = 0
            self.done = False

        def understand_frames(self, prompt, frames_bgr, frames_meta):
            self.calls += 1
            raise TimeoutError("wait timeout: future NOT cancelled")

        def snapshot(self):
            return {"pending_call_done": bool(self.done)}

    model = _FutureProbeModel()
    stage = l3.L3Stage(model, budget=L3Budget(concurrency=1),
                       slot_wait_timeout_s=0.2)
    out = stage.process(_task([_frame("a")]))
    assert out.status == L3Status.TIMEOUT
    res = stage.execution_resources()
    assert res["in_flight"] == 1 and res["held_unfinished"] == 1, \
        "future 未完成 → 执行资源不提前返还"
    assert stage.release_held_executions() == 0, "future 未完成 → 收口不回收"
    model.done = True                          # 真实 future 完成
    assert stage.release_held_executions() == 1, "future.done() → 恰一次回收"
    res = stage.execution_resources()
    assert res["in_flight"] == 0 and res["held_unfinished"] == 0
    assert res["reclaimed_total"] == 1
    assert stage.release_held_executions() == 0


def test_stage_without_probe_releases_slot_on_synchronous_timeout():
    """model 无自报能力（同步返回的 TimeoutError=调用已结束）→ 按旧语义
    立即返还执行资源，绝不把无证据的怀疑变成永久占用。"""
    model = _FakeL3Model(exc=TimeoutError("slow"))
    stage = l3.L3Stage(model, budget=L3Budget(concurrency=1))
    out = stage.process(_task([_frame("a")]))
    assert out.status == L3Status.TIMEOUT
    res = stage.execution_resources()
    assert res["held_unfinished"] == 0 and res["in_flight"] == 0
    assert stage.process(_task([_frame("a")])).status == L3Status.TIMEOUT


def test_model_output_without_known_keys_serialized_honestly():
    """C-136 C4：无法结构化 → 原文保留 + unstructured=True（不靠关键词猜
    "已确认行为"）；未知 dict 整包 JSON 序列化也如实标记。"""
    fake = _FakeL3Model(result={"foo": 1})
    (result,) = l3.L3Stage(fake).process(_task([_frame("a")])).results
    assert result.observation == '{"foo": 1}'
    assert result.inference is None
    assert result.unstructured is True
    fake2 = _FakeL3Model(result={"text": "纯文本输出"})
    (result2,) = l3.L3Stage(fake2).process(_task([_frame("a")])).results
    assert result2.observation == "纯文本输出"
    assert result2.unstructured is True
    fake3 = _FakeL3Model(result="模型自由文本，未按 JSON 返回")
    (result3,) = l3.L3Stage(fake3).process(_task([_frame("a")])).results
    assert result3.observation == "模型自由文本，未按 JSON 返回"
    assert result3.unstructured is True


# ---------------------------------------------------------------------------
# 2.5 C-136 C3/C4：实际模型预算记账 + 结构化分支输出
# ---------------------------------------------------------------------------

def test_budget_accounting_three_layers_at_448():
    """C-136 C3：448×448 输入 → effective_patch=1/帧、tokens=256/帧如实；
    三层数值（原图证据尺寸/传输尺寸/模型真实预算）齐备。"""
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake)
    out = stage.process(_task([_frame("a", shape=(448, 448, 3)),
                               _frame("b", shape=(448, 448, 3))]))
    acc = out.budget_accounting
    assert isinstance(acc, L3BudgetAccounting)
    assert (acc.image_side, acc.patch_side, acc.downsample_ratio) \
        == (448, 14, 0.5)
    assert acc.tokens_per_patch_segment == 256
    assert acc.image_count == 2
    assert acc.total_patches == 2 and acc.total_tokens == 512
    assert acc.downscale_reduced_patch_budget is False   # 不虚报
    assert acc.context_limit_tokens is None              # fake 未声明
    u0, u1 = acc.frames
    for u in (u0, u1):
        assert isinstance(u, L3FrameBudgetUsage)
        assert (u.source_width, u.source_height) == (448, 448)
        assert (u.transport_width, u.transport_height) == (448, 448)
        assert u.provider_rescaled is False              # 恰在 448 不放回
        assert u.effective_patches == 1
        assert u.effective_tokens == 256


def test_budget_accounting_records_source_vs_transport_and_rescale():
    """C-136 C3：原图 800×100 → 预处理 448×56 传输；传输 <448 侧被
    provider 放回 448（provider_rescaled=True 如实），patch 预算仍 1 段
    =256 token——不因降采样虚报。"""
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake)
    out = stage.process(_task([_frame("a", shape=(100, 800, 3))]))
    (u,) = out.budget_accounting.frames
    assert (u.source_width, u.source_height) == (800, 100)
    assert (u.transport_width, u.transport_height) == (448, 56)
    assert u.provider_rescaled is True
    assert u.effective_patches == 1 and u.effective_tokens == 256
    assert out.budget_accounting.total_tokens == 256


def test_budget_accounting_downscale_not_claimed_as_patch_reduction():
    """C-136 C3 关键：预处理降采样（8×8→7×7）后 provider 放回 448——
    记账必须如实标注 effective_patch 仍 1/帧、tokens 仍 256/帧，且
    downscale_does_not_reduce_patch_budget 进 notes；partial 语义不受影响。"""
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake, budget=L3Budget(max_total_pixels=100))
    out = stage.process(_task([_frame("a", shape=(8, 8, 3)),
                               _frame("b", shape=(8, 8, 3))]))
    assert out.status == L3Status.PARTIAL
    (result,) = out.results
    assert result.uncertainty.pixels_downscaled is True
    acc = out.budget_accounting
    assert acc.image_count == 2
    assert [u.effective_patches for u in acc.frames] == [1, 1]
    assert [u.effective_tokens for u in acc.frames] == [256, 256]
    assert acc.total_patches == 2 and acc.total_tokens == 512
    assert acc.downscale_reduced_patch_budget is False
    assert "provider_rescales_to_tile=2" in acc.notes
    assert "downscale_does_not_reduce_patch_budget=1" in acc.notes


def test_budget_accounting_missing_frame_slot_recorded():
    """缺帧序位在记账中 present=False、patch/token 记 0；image_count 只数
    真实进模型图像（调用边界断言通过）。"""
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake)
    out = stage.process(_task([_frame("cur", shape=(8, 8, 3)),
                               _frame("prev", present=False)]))
    acc = out.budget_accounting
    assert acc.image_count == 1
    assert [u.present for u in acc.frames] == [True, False]
    assert acc.frames[1].effective_patches == 0
    assert acc.frames[1].effective_tokens == 0
    assert acc.total_patches == 1 and acc.total_tokens == 256


def test_budget_accounting_context_limit_declared_and_verified():
    """adapter 声明上下文上限：记账如实透传；超限进 notes（验证发生）。
    未声明 → None，不编造。"""
    fake = _FakeL3Model()
    fake.context_token_limit = 512          # 2 帧 ×256 恰不超
    out = l3.L3Stage(fake).process(_task([_frame("a"), _frame("b")]))
    assert out.budget_accounting.context_limit_tokens == 512
    assert "context_limit_exceeded" not in out.budget_accounting.notes
    fake2 = _FakeL3Model()
    fake2.context_token_limit = 511         # 512 > 511 → 如实记录超限
    out2 = l3.L3Stage(fake2).process(_task([_frame("a"), _frame("b")]))
    assert "context_limit_exceeded=1" in out2.budget_accounting.notes


def test_budget_accounting_on_infer_failure_but_not_pre_boundary():
    """失败侧记账如实：已到调用边界（infer_failed）→ 携带记账；未到边界
    （identity_rejected / empty_frames）→ None，绝不编造。"""
    boom = _FakeL3Model(exc=ValueError("upstream boom"))
    out = l3.L3Stage(boom).process(_task([_frame("a")]))
    assert out.status == L3Status.INFER_FAILED
    assert len(out.results) == 1                  # 失败结果仅身份事实，无文本
    assert out.results[0].observation is None
    assert out.budget_accounting is not None
    assert out.budget_accounting.image_count == 1
    out_rej = l3.L3Stage(_FakeL3Model()).process(
        _task([_frame("a", run="r2")]))
    assert out_rej.status == L3Status.IDENTITY_REJECTED
    assert out_rej.budget_accounting is None
    out_empty = l3.L3Stage(_FakeL3Model()).process(_task([]))
    assert out_empty.budget_accounting is None


def test_structured_result_carries_identity_crop_origin_and_region_flag():
    """C-136 C4：每条观察/推断自带 window+branch 身份、crop_id 裁剪来源、
    model_ref；region_only=True（同区域不保证同一对象）。"""
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake)
    out = stage.process(_task([_frame("cur",
                                       branch=L3BranchKind.RELATION_CROP)],
                              branch=L3BranchKind.RELATION_CROP,
                              crop_id="c1:r1:window:w1:crop:1"))
    (result,) = out.results
    assert result.branch == L3BranchKind.RELATION_CROP
    assert result.window is out.window
    assert result.crop_id == "c1:r1:window:w1:crop:1"
    assert result.model_ref == "fake/l3" == out.model_ref
    assert result.region_only is True


def test_prompt_declares_fixed_ordinals_and_region_only():
    """C-136 C2/C1：prompt 头如实声明固定序位（0=前/1=当前/2=后）与
    「同空间区域切片，不保证同一对象」；crop_id 显式键进 prompt。"""
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake)
    stage.process(_task([_frame("prev"), _frame("cur"), _frame("nxt")],
                        crop_id="c1:r1:window:w1:crop:0"))
    prompt = fake.calls[0]["prompt"]
    assert "0=前" in prompt and "1=当前" in prompt and "2=后" in prompt
    assert "crop_id=c1:r1:window:w1:crop:0" in prompt
    assert "不保证同一对象" in prompt


# ---------------------------------------------------------------------------
# 3. LocalTransformersL3Adapter 薄壳（捕获真实多帧路径 + 超时隔离）
# ---------------------------------------------------------------------------

class _CaptureChatModel:
    """上游 chat() 签名桩：记录并复断言多图协议（同 tests/test_models.py）。"""

    def __init__(self):
        self.calls = []

    def chat(self, tokenizer, pixel_values, question, generation_config,
             num_patches_list=None, **kw):
        self.calls.append({
            "question": question,
            "marker_count": question.count("<image>"),
            "shape": tuple(pixel_values.shape),
            "num_patches_list": list(num_patches_list or []),
        })
        assert pixel_values.shape[0] == sum(num_patches_list or [])
        return '{"observation": "适配捕获", "inference": "无"}'


class _FakeTransformByWidth:
    def __call__(self, img):
        import torch
        return torch.full((3, 448, 448), float(img.size[0]),
                          dtype=torch.float32)


def _capture_lt():
    lt = LocalTransformers(model_path="capture/fake", timeout=5)
    lt._model = _CaptureChatModel()
    lt._tokenizer = object()
    lt._transform = _FakeTransformByWidth()
    return lt


def _bgr(width, height, gray=90):
    return np.full((height, width, 3), gray, dtype=np.uint8)


def test_adapter_encodes_bgr_and_multi_frame_reaches_chat_in_order():
    lt = _capture_lt()
    adapter = l3.LocalTransformersL3Adapter(lt)

    out = adapter.understand_frames(
        "比较两帧。", [_bgr(8, 8), None, _bgr(12, 4)],
        [{"position": 1, "frame_id": "a"}, {"position": 2, "frame_id": "b"},
         {"position": 3, "frame_id": "c"}])

    assert out == {"observation": "适配捕获", "inference": "无"}
    call = lt._model.calls[0]
    assert call["shape"] == (2, 3, 448, 448)      # 缺帧占位不编码，2 张真实图
    assert call["num_patches_list"] == [1, 1]
    assert call["marker_count"] == 2
    # prompt 级缺帧标注（models.py 渲染）如实出现在模型问题文本中
    assert "第2帧" in call["question"] and "缺失" in call["question"]
    assert lt._last_call_info["images_into_model"] == 2
    snap = adapter.snapshot()
    assert snap["loaded"] is True and snap["poisoned"] is False
    assert snap["worker_abortable"] is False


def test_adapter_load_failure_is_model_unavailable():
    lt = LocalTransformers(model_path="capture/fake", timeout=5)

    def _boom():
        raise RuntimeError("weights missing")

    lt._ensure_loaded = _boom                     # 绝不触发真实加载
    adapter = l3.LocalTransformersL3Adapter(lt)
    with pytest.raises(L3ModelUnavailable):
        adapter.understand_frames("比较。", [_bgr(4, 4)], [])
    assert adapter.snapshot()["loaded"] is False


class _SlowProvider:
    model_id = "slow"

    def __init__(self, sleep_s, error=None):
        self._sleep_s = sleep_s
        self._error = error
        self._model = None

    def _ensure_loaded(self):
        self._model = object()

    def understand_frames(self, prompt, b64s, meta):
        time.sleep(self._sleep_s)
        if self._error is not None:
            raise self._error
        return {"text": "done"}


def test_adapter_timeout_poisons_and_reports_residual_honestly():
    adapter = l3.LocalTransformersL3Adapter(_SlowProvider(0.6),
                                            infer_timeout_s=0.05)
    with pytest.raises(l3.L3InferTimeout) as ei:
        adapter.understand_frames("比较。", [_bgr(4, 4)], [])
    assert isinstance(ei.value, TimeoutError)     # stage 按 TimeoutError 分类
    assert ei.value.code == "timeout"

    snap = adapter.snapshot()
    assert snap["poisoned"] is True
    assert snap["pending_call_still_running"] is True   # 不可中止，残留如实
    assert snap["worker_threads_alive"] == 1
    assert snap["worker_abortable"] is False

    with pytest.raises(L3AdapterIsolated):        # 拒派后续任务
        adapter.understand_frames("比较。", [_bgr(4, 4)], [])

    adapter._pending_future.result(timeout=5)     # 等工作线程自然结束
    snap2 = adapter.snapshot()
    assert snap2["pending_call_still_running"] is False
    assert snap2["pending_call_done"] is True
    assert snap2["poisoned"] is True              # 不假装恢复
    with pytest.raises(L3AdapterIsolated):
        adapter.understand_frames("比较。", [_bgr(4, 4)], [])


def test_adapter_upstream_own_timeout_error_is_infer_failed_not_poison():
    # 上游自己抛 TimeoutError 且 future 已完成——不是等待超时：不毒化
    adapter = l3.LocalTransformersL3Adapter(
        _SlowProvider(0.0, error=TimeoutError("upstream internal")),
        infer_timeout_s=5.0)
    with pytest.raises(l3.L3InferFailed) as ei:
        adapter.understand_frames("比较。", [_bgr(4, 4)], [])
    assert ei.value.code == "infer_failed"
    assert adapter.snapshot()["poisoned"] is False
    # 正常路径可继续
    adapter2 = l3.LocalTransformersL3Adapter(_SlowProvider(0.0),
                                             infer_timeout_s=5.0)
    assert adapter2.understand_frames("比较。", [_bgr(4, 4)], []) == \
        {"text": "done"}


def test_stage_over_adapter_end_to_end_capture():
    """D1+D2 合流：stage→adapter→真实多帧路径，第二帧真实进入模型张量。"""
    lt = _capture_lt()
    adapter = l3.LocalTransformersL3Adapter(lt)
    stage = l3.L3Stage(adapter)
    task = _task([_frame("prev", t=100, shape=(6, 8, 3)),
                  _frame("cur", t=300, shape=(4, 10, 3))])
    out = stage.process(task)

    assert out.status == L3Status.OK
    assert out.model_ref.startswith("transformers/")
    (result,) = out.results
    assert result.observation == "适配捕获"
    call = lt._model.calls[0]
    assert call["shape"] == (2, 3, 448, 448)
    assert call["marker_count"] == 2
    assert "camera=c1" in call["question"]
    assert "分支=panorama" in call["question"]
    assert "frame=prev" in call["question"]
    assert "frame=cur" in call["question"]


# ---------------------------------------------------------------------------
# 4. 协议基类（合同层）
# ---------------------------------------------------------------------------

def test_l3_vision_model_protocol_raises_without_impl():
    model = L3VisionModel()
    with pytest.raises(NotImplementedError):
        model.understand_frames("p", [], [])


# ---------------------------------------------------------------------------
# 5. C153 A：预算内帧选择（保开始/转折/最新状态）+ 计时别名不变
# ---------------------------------------------------------------------------

def test_select_frames_keeps_start_and_latest_within_budget():
    """预算内选择：首帧（开始）与末帧（最新状态）必留；名额=1 时留最新。
    中间位是**中间采样**（无来源可追溯的转折标记时绝不称"关键转折"）。"""
    kept, source, roles, dropped = l3.select_frames_within_budget(10, None, 4)
    assert kept[0] == 0 and kept[-1] == 9          # 开始 + 最新
    assert kept == sorted(kept) and len(kept) == 4
    assert source == kept                          # 原位次口径（无 positions 时同值）
    assert roles[0] == "start" and roles[9] == "latest"
    assert all(roles[i] == "middle_sample" for i in kept[1:-1])
    assert "turning" not in set(roles.values())    # 无标记 → 不虚标转折
    assert dropped == [i for i in range(10) if i not in kept]

    one, _, one_roles, _ = l3.select_frames_within_budget(10, None, 1)
    assert one == [9] and one_roles[9] == "latest"
    two, _, _, _ = l3.select_frames_within_budget(10, None, 2)
    assert two == [0, 9]


def test_select_frames_only_picks_frames_with_pixels():
    """C153-R1：**只在有像素的帧里选**——永久缺帧占位不占名额、也不得挤掉
    真正可分析的帧（窗口首/尾帧"只有一帧在手"是常见形状）。"""
    present = [False, True, False]                 # 中间帧在手，前后缺位
    kept, source, roles, dropped = l3.select_frames_within_budget(
        3, None, 1, present=present)
    assert kept == [1]                             # 不是末位占位 2
    assert source == [1]
    assert roles == {1: "latest"}                  # 唯一可分析位=最新状态
    assert dropped == [0, 2]

    kept2, _, roles2, _ = l3.select_frames_within_budget(
        3, None, 2, present=present)
    assert kept2 == [1] and roles2 == {1: "latest"}
    # 全部缺位 → 四个空值（调用方如实报 no_present_frames，不编造帧）
    assert l3.select_frames_within_budget(
        3, None, 2, present=[False, False, False]) == ([], [], {}, [])
    # present=None → 旧口径（纯形状调用，不受像素信息影响）
    assert l3.select_frames_within_budget(3, None, 1) == ([2], [2],
                                                          {2: "latest"}, [0, 1])


def test_declared_turning_marker_is_the_only_way_to_role_turning():
    """C153-R1 §4：只有**来源可追溯**的转折标记才标 `turning`；缺标记时
    omission 写"中间采样，转折覆盖未证明"。无来源说明的标记一律不认。"""
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake, budget=L3Budget(max_frames_per_task=3))
    frames = [_frame(f"f{i}", t=i) for i in range(6)]

    class _Marked:
        """显式扩展点形状：标记位次 + 非空来源说明（可追溯）。"""

        def __init__(self, task, positions, source):
            self._task = task
            self.turning_positions = positions
            self.turning_positions_source = source

        def __getattr__(self, name):
            return getattr(self._task, name)

    base = _task(frames)
    marked = _Marked(base, [2], "l1:change_box@frame2")
    out = stage.process(marked)
    assert "roles=0:start,2:turning,5:latest" in out.omission.reason
    assert "turn_evidence=declared_source_traceable" in out.omission.reason
    assert "turn_coverage" not in out.omission.reason
    # 只有标记、没有来源说明 → 不认（不虚标转折）
    unmarked = _Marked(base, [2], None)
    out2 = stage.process(unmarked)
    assert "turning" not in out2.omission.reason
    assert "turn_coverage=中间采样，转折覆盖未证明" in out2.omission.reason


def test_select_frames_is_deterministic_and_respects_explicit_positions():
    """确定性 + 显式 positions：返回的是**原位次标签**（不塌缩、不重排）。"""
    args = (12, tuple(f"p{i}" for i in range(12)), 5)
    first = l3.select_frames_within_budget(*args)
    second = l3.select_frames_within_budget(*args)
    assert first == second
    kept, source, roles, dropped = first
    assert len(kept) <= 5
    assert source == [f"p{i}" for i in kept]
    assert roles["p0"] == "start" and roles["p11"] == "latest"
    assert sorted(source + dropped) == sorted(f"p{i}" for i in range(12))
    assert l3.select_frames_within_budget(0, None, 4) == ([], [], {}, [])
    assert l3.select_frames_within_budget(3, None, 0)[0] == [2]   # 非法档：保最新


def test_budget_selection_beats_prefix_truncation_on_window_shape():
    """窗口形状（10 帧、窗口 4 名额）：旧口径"保前 4 帧"丢掉转折与最新状态；
    新选择同时保住开始与最新状态（这是时效改造的用户可见差异）。"""
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake, budget=L3Budget(max_frames_per_task=4))
    frames = [_frame(f"f{i}", t=i * 100) for i in range(10)]

    out = stage.process(_task(frames))
    sent = [m["frame_id"] for m in fake.calls[0]["meta"]]

    assert sent[0] == "f0"          # 开始
    assert sent[-1] == "f9"         # 最新状态（旧口径会丢）
    assert sent != ["f0", "f1", "f2", "f3"]
    assert len(sent) == 4
    assert out.omission.frames_dropped == 6
    assert "dropped_positions=" in out.omission.reason


class _TraceStub:
    """runtime 侧最小 trace 桩（只记 _trace_emit 调用，不触真实 runtime）。"""

    def __init__(self):
        self.stages = []
        self.records = []

    def _trace_emit(self, stage, **fields):
        self.stages.append(stage)
        self.records.append((stage, fields))


def test_measurement_stage_aliases_unchanged_by_selection():
    """C149 别名不合并、不新增：选择/截断路径仍只发既有阶段名（分列计时）。"""
    fake = _FakeL3Model()
    stage = l3.L3Stage(fake, budget=L3Budget(max_frames_per_task=2))
    rt = _TraceStub()
    measurement = l3.L3MeasurementContext(rt, ("c1", "r1", 1, "w1", "panorama",
                                                None, 5))
    out = stage.process_measured(
        _task([_frame(f"f{i}") for i in range(6)]), measurement)

    assert out.omission.frames_dropped == 4
    assert rt.stages == ["l3_preprocess_start", "l3_preprocess_end",
                         "model_measurement_unavailable"]
    assert "model_start" not in rt.stages          # 不透明模型边界：不伪造
    assert all(stage_name in {
        "l3_preprocess_start", "l3_preprocess_end", "model_start", "model_end",
        "model_failed", "model_wait_timeout", "model_measurement_unavailable",
        "backend_preprocess_start", "backend_preprocess_end",
    } for stage_name in rt.stages)
    task_key = rt.records[0][1]["task_key"]
    assert len(task_key) == 7 and list(task_key[4:]) == ["panorama", None, 5]
