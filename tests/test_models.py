"""C-135 tests: scam.models.LocalTransformers 真实有序多帧输入。

覆盖（L2L3-接口冻结-C135.md §8 第一条）：
- 捕获级（核心证据，无模型加载、毫秒级）：2/3 帧任务时 chat 实际收到的
  pixel_values 形状 [N,3,448,448]（N=帧数）、prompt 中 <image> 占位符数=N、
  pixel_values 行序=输入帧序（逐帧可区分张量）——证明第二/第三张图真实
  进入模型，不是只存在于参数列表；
- 缺帧显式：None 占位被跳过（无占位符）+ prompt 标注「第 N 帧缺失」；
- frames_meta 逐帧身份/时间/分支标签进 prompt；
- 单帧路径字节级兼容："<image>\\n"+prompt（含 context 变体）、pv [1,3,448,448]、
  返回 dict 格式不变；understand 失败→None（既有语义）；
- 上游多图协议契约复断言：len(pixel_values)==sum(num_patches_list)（本机
  HF 快照 modeling_internvl_chat.py chat() L273 的硬断言）；
- 真实模型证据（slow + SCAM_L3_REAL_MODEL=1 门禁，由主会话统一串行调度，
  默认 pytest 运行一律 skip）：素材路径由环境变量 SCAM_REAL_MATERIAL 指定，
  前/当前/后三帧，分别跑「仅当前帧」与「有序三帧」，证据落
  %TEMP%/c135_l3/real-multiframe.json。

捕获方式：向 LocalTransformers 实例注入假 _model/_tokenizer/_transform
（_model 非 None 即跳过 _ensure_loaded，绝不触发真实加载/联网）；假 chat
按上游 chat 签名接收参数并记录——捕获的是 LocalTransformers 实际传给模型
入口的 pixel_values/num_patches_list/question，不是它自己的入参。
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
from pathlib import Path

import numpy as np
import pytest

from scam import models
from scam.models import LocalTransformers

REAL_MATERIAL = Path(os.environ.get(
    "SCAM_REAL_MATERIAL", "C:/data/scenario.mp4"))
EVIDENCE_DIR = Path(tempfile.gettempdir()) / "c135_l3"
HF_SNAPSHOT_ROOT = (Path.home() / ".cache" / "huggingface" / "hub"
                    / "models--OpenGVLab--InternVL3_5-1B-Instruct"
                    / "snapshots")


# ---------------------------------------------------------------------------
# 工具：帧素材与假模型内部（捕获级，绝不触发真实加载）
# ---------------------------------------------------------------------------

def _tiny_jpg_b64(width, height, gray=200):
    """cv2 编码的纯色 JPEG（尺寸参与帧序判别；内容无关紧要）。"""
    import cv2
    arr = np.full((height, width, 3), gray, dtype=np.uint8)
    ok, buf = cv2.imencode(".jpg", arr)
    assert ok
    return base64.b64encode(buf.tobytes()).decode("ascii")


class _FakeTransform:
    """把每帧变成「按帧宽填充」的可区分张量：捕获行序=输入帧序的铁证。"""

    def __call__(self, img):
        import torch
        return torch.full((3, 448, 448), float(img.size[0]),
                          dtype=torch.float32)


class _FakeChatModel:
    """按上游 chat() 签名（modeling_internvl_chat.py L264-266）接收并记录。

    复断言上游硬契约 L273：len(pixel_values) == sum(num_patches_list)。
    """

    def __init__(self, response=None, error=None):
        self.calls = []
        self._response = response or '{"observation": "捕获", "inference": "无"}'
        self._error = error

    def chat(self, tokenizer, pixel_values, question, generation_config,
             history=None, return_history=False, num_patches_list=None,
             **kw):
        n_patches = (None if num_patches_list is None
                     else list(num_patches_list))
        self.calls.append({
            "question": question,
            "marker_count": question.count("<image>"),
            "pixel_values_shape": tuple(pixel_values.shape),
            "row_values": [float(pixel_values[i, 0, 0, 0])
                           for i in range(pixel_values.shape[0])],
            "num_patches_list": n_patches,
            "generation_config": dict(generation_config),
        })
        assert n_patches is not None, "必须显式传 num_patches_list（多图协议）"
        assert pixel_values.shape[0] == sum(n_patches), \
            "上游 chat() L273 硬断言：len(pixel_values)==sum(num_patches_list)"
        assert pixel_values.shape[1:] == (3, 448, 448)
        if self._error is not None:
            raise self._error
        return self._response


def _capture_provider(fake_model):
    """注入假内部的 LocalTransformers：_model 非 None 即不触发真实加载。"""
    lt = LocalTransformers(model_path="capture/fake", timeout=5)
    lt._model = fake_model
    lt._tokenizer = object()          # 假 chat 不消费 tokenizer
    lt._transform = _FakeTransform()
    return lt


# ---------------------------------------------------------------------------
# 1. 捕获级：多帧真实进入模型
# ---------------------------------------------------------------------------

def test_capture_two_frames_both_enter_model_in_order():
    fake = _FakeChatModel()
    lt = _capture_provider(fake)
    frames = [_tiny_jpg_b64(8, 8), _tiny_jpg_b64(10, 6)]

    out = lt.understand("比较两帧差异。", frames)

    assert len(fake.calls) == 1
    call = fake.calls[0]
    # pixel_values 形状 [N*patch,3,448,448]：两帧都进了模型张量
    assert call["pixel_values_shape"] == (2, 3, 448, 448)
    assert call["num_patches_list"] == [1, 1]
    # prompt 占位符数 == 帧数
    assert call["marker_count"] == 2
    # 行序=输入帧序（行值=各帧宽度 8/10）
    assert call["row_values"] == [8.0, 10.0]
    info = lt._last_call_info
    assert info["images_into_model"] == 2
    assert info["prompt_marker_count"] == 2
    assert info["pixel_values_shape"] == [2, 3, 448, 448]
    # 返回格式不变（JSON 提取对齐 LocalOllama）
    assert out == {"observation": "捕获", "inference": "无"}


def test_capture_three_frames_all_enter_model_in_order():
    fake = _FakeChatModel()
    lt = _capture_provider(fake)
    frames = [_tiny_jpg_b64(8, 8), _tiny_jpg_b64(10, 6), _tiny_jpg_b64(12, 4)]

    lt.understand("按时间顺序比较三帧。", frames)

    call = fake.calls[0]
    assert call["pixel_values_shape"] == (3, 3, 448, 448)
    assert call["num_patches_list"] == [1, 1, 1]
    assert call["marker_count"] == 3
    assert call["row_values"] == [8.0, 10.0, 12.0]   # 第三帧真实进模型且有序
    assert lt._last_call_info["prompt_marker_count"] == 3


def test_capture_frames_meta_labels_rendered_into_prompt():
    fake = _FakeChatModel()
    lt = _capture_provider(fake)
    meta = [
        {"branch": "panorama", "frame_id": "f-28",
         "t_capture_ms": 28000, "timestamp_kind": "observed"},
        {"branch": "panorama", "frame_id": "f-30",
         "t_capture_ms": 30000, "timestamp_kind": "observed"},
    ]

    lt.understand("比较前后两帧。", [_tiny_jpg_b64(8, 8), _tiny_jpg_b64(10, 6)],
                  frames_meta=meta)

    question = fake.calls[0]["question"]
    assert "第1帧[branch=panorama;frame=f-28;t=28000;kind=observed]" in question
    assert "第2帧[branch=panorama;frame=f-30;t=30000;kind=observed]" in question
    assert question.endswith("比较前后两帧。")
    assert fake.calls[0]["marker_count"] == 2


def test_capture_missing_frame_skipped_and_annotated_never_faked():
    fake = _FakeChatModel()
    lt = _capture_provider(fake)
    frames = [_tiny_jpg_b64(8, 8), None, _tiny_jpg_b64(12, 4)]

    lt.understand("三帧比较，缺帧如实说明。", frames)

    call = fake.calls[0]
    # 只有 2 张真实图像进模型；缺失位既无占位符也无伪造图像
    assert call["pixel_values_shape"] == (2, 3, 448, 448)
    assert call["num_patches_list"] == [1, 1]
    assert call["marker_count"] == 2
    assert call["row_values"] == [8.0, 12.0]         # 第 2 位被跳过
    question = call["question"]
    assert "第2帧缺失" in question
    assert "（第2帧缺失，无图像输入）" in question
    info = lt._last_call_info
    assert info["frames_input"] == 3
    assert info["images_into_model"] == 2
    assert info["missing_frame_positions"] == [2]


def test_prompt_marker_count_mismatch_is_rejected_not_silently_corrupted():
    # 自带占位符数与实际帧数不符 → understand None（兼容语义）、
    # _understand_ordered ValueError（分类路径），绝不静默错位送模型。
    fake = _FakeChatModel()
    lt = _capture_provider(fake)
    frames = [_tiny_jpg_b64(8, 8), _tiny_jpg_b64(10, 6)]
    assert lt.understand("图：<image>\n两帧比较。", frames) is None
    assert not fake.calls                     # 未进模型
    with pytest.raises(ValueError, match="占位符数"):
        lt._understand_ordered("图：<image>\n两帧比较。", frames)


def test_caller_supplied_markers_matching_frame_count_pass_through():
    fake = _FakeChatModel()
    lt = _capture_provider(fake)
    frames = [_tiny_jpg_b64(8, 8), _tiny_jpg_b64(10, 6)]

    lt.understand("帧A：<image>\n帧B：<image>\n比较。", frames)

    call = fake.calls[0]
    assert call["question"] == "帧A：<image>\n帧B：<image>\n比较。"
    assert call["marker_count"] == 2


# ---------------------------------------------------------------------------
# 2. 单帧路径兼容（C-134 前行为不回归）
# ---------------------------------------------------------------------------

def test_single_frame_legacy_prompt_and_shape_unchanged():
    fake = _FakeChatModel()
    lt = _capture_provider(fake)

    lt.understand("描述画面。", [_tiny_jpg_b64(8, 8)])

    call = fake.calls[0]
    assert call["question"] == "<image>\n描述画面。"
    assert call["pixel_values_shape"] == (1, 3, 448, 448)
    assert call["num_patches_list"] == [1]


def test_single_frame_with_context_legacy_format_unchanged():
    fake = _FakeChatModel()
    lt = _capture_provider(fake)

    lt.understand("描述画面。", [_tiny_jpg_b64(8, 8)],
                  context={"camera_id": "cam-1"})

    ctx = json.dumps({"camera_id": "cam-1"}, ensure_ascii=False)
    assert fake.calls[0]["question"] == f"<image>\n{ctx}\n描述画面。"


def test_single_frame_text_output_wrapped_as_dict():
    fake = _FakeChatModel(response="画面里有一个人。")
    lt = _capture_provider(fake)

    out = lt.understand("描述画面。", [_tiny_jpg_b64(8, 8)])

    assert out == {"text": "画面里有一个人。"}


# ---------------------------------------------------------------------------
# 3. 失败语义（既有契约不变：understand→None；understand_frames→异常）
# ---------------------------------------------------------------------------

def test_understand_returns_none_on_model_error():
    fake = _FakeChatModel(error=RuntimeError("boom"))
    lt = _capture_provider(fake)
    assert lt.understand("描述。", [_tiny_jpg_b64(8, 8)]) is None


def test_understand_returns_none_on_empty_or_all_missing_frames():
    fake = _FakeChatModel()
    lt = _capture_provider(fake)
    assert lt.understand("描述。", []) is None
    assert lt.understand("描述。", [None, None]) is None
    assert not fake.calls


def test_understand_frames_raises_for_caller_classification():
    fake = _FakeChatModel()
    lt = _capture_provider(fake)
    out = lt.understand_frames("比较。", [_tiny_jpg_b64(8, 8),
                                          _tiny_jpg_b64(10, 6)],
                               frames_meta=[{"frame_id": "a"},
                                            {"frame_id": "b"}])
    assert out == {"observation": "捕获", "inference": "无"}
    # 显式失败版本：无效输入上抛（供适配层分类），不吞成 None
    with pytest.raises(ValueError):
        lt.understand_frames("比较。", [])
    assert len(fake.calls) == 1
    broken = _FakeChatModel(error=ValueError("decode fail"))
    lt2 = _capture_provider(broken)
    with pytest.raises(ValueError, match="帧解码失败"):
        lt2.understand_frames("比较。", ["not-base64!!"])


# ---------------------------------------------------------------------------
# 4. 真实模型证据（slow + 门禁；默认一律 skip，主会话统一串行调度）
# ---------------------------------------------------------------------------

def _internvl_snapshot():
    if not HF_SNAPSHOT_ROOT.is_dir():
        return None
    for snap in sorted(HF_SNAPSHOT_ROOT.iterdir()):
        if (snap / "config.json").is_file():
            return snap
    return None


def _extract_frame_b64(cap, index):
    cap.set(2, index)  # cv2.CAP_PROP_POS_FRAMES
    ok, frame = cap.read()
    if not ok:
        return None
    import cv2
    ok2, buf = cv2.imencode(".jpg", frame)
    if not ok2:
        return None
    return base64.b64encode(buf.tobytes()).decode("ascii")


@pytest.mark.slow
@pytest.mark.skipif(os.environ.get("SCAM_L3_REAL_MODEL") != "1",
                    reason="需 SCAM_L3_REAL_MODEL=1：真实模型运行由主会话"
                           "统一串行调度，默认 pytest 一律 skip")
def test_real_multiframe_evidence_prev_cur_next():
    """真实 LocalTransformers：固定素材前/当前/后三帧，「仅当前帧」与
    「有序三帧」各跑一次；证据（prompt 占位符数、pixel_values 形状、模型
    文本输出、耗时）写 %TEMP%/c135_l3/real-multiframe.json。

    运行（装有 torch/transformers 的 Python，repo 根目录执行）：
      SCAM_L3_REAL_MODEL=1 SCAM_REAL_MATERIAL=<素材路径> python \
          -m pytest tests/test_models.py -k real_multiframe -q -s
    模型路径直接传本机 HF 快照目录（受控本地路径，不触网、不需要 HF_HUB_OFFLINE）。
    """
    torch = pytest.importorskip("torch", reason="本解释器缺 torch")
    tf = pytest.importorskip("transformers", reason="本解释器缺 transformers")
    cv2 = pytest.importorskip("cv2", reason="缺 cv2：无法从固定素材抽帧")

    snap = _internvl_snapshot()
    if snap is None:
        pytest.skip("InternVL3_5-1B-Instruct 快照不在本机 HF 缓存；按约定不联网下载")
    if not REAL_MATERIAL.is_file():
        pytest.skip(f"固定素材不存在：{REAL_MATERIAL}")

    cap = cv2.VideoCapture(str(REAL_MATERIAL))
    if not cap.isOpened():
        pytest.skip(f"固定素材无法打开：{REAL_MATERIAL}")
    prev_b64 = _extract_frame_b64(cap, 28)
    cur_b64 = _extract_frame_b64(cap, 30)
    nxt_b64 = _extract_frame_b64(cap, 32)
    cap.release()
    if cur_b64 is None:
        pytest.skip("固定素材当前帧（#30）无法解码")
    prev_b64 = prev_b64 or cur_b64
    nxt_b64 = nxt_b64 or cur_b64

    lt = LocalTransformers(model_path=str(snap), timeout=600)
    prompt = ("比较监控画面并只输出 JSON："
              '{"observation": "画面观察", "inference": "时序推断"}。')
    meta = lambda fid, t: {"branch": "panorama", "frame_id": fid,
                           "t_capture_ms": t, "timestamp_kind": "observed"}

    evidence = {
        "title": "C-135 L3 真实多帧输入证据（InternVL3_5-1B，前/中/后三帧）",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "model_snapshot": snap.name,
        "torch": torch.__version__,
        "transformers": tf.__version__,
        "frame_source": str(REAL_MATERIAL),
        "frame_indices": [28, 30, 32],
    }

    t0 = time.perf_counter()
    try:
        single = lt.understand(prompt, [cur_b64],
                               frames_meta=[meta("frame-30", 30000)])
    except Exception as exc:
        single, single_err = None, f"{type(exc).__name__}: {exc}"
    else:
        single_err = None
    single_ms = (time.perf_counter() - t0) * 1000.0
    single_info = dict(lt._last_call_info or {})

    t1 = time.perf_counter()
    try:
        triple = lt.understand(
            prompt, [prev_b64, cur_b64, nxt_b64],
            frames_meta=[meta("frame-28", 28000), meta("frame-30", 30000),
                         meta("frame-32", 32000)])
    except Exception as exc:
        triple, triple_err = None, f"{type(exc).__name__}: {exc}"
    else:
        triple_err = None
    triple_ms = (time.perf_counter() - t1) * 1000.0
    triple_info = dict(lt._last_call_info or {})

    evidence.update({
        "single_frame": {"call_info": single_info, "output": single,
                         "error": single_err, "elapsed_ms": round(single_ms, 1)},
        "three_frames": {"call_info": triple_info, "output": triple,
                         "error": triple_err, "elapsed_ms": round(triple_ms, 1)},
    })
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "real-multiframe.json").write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")

    # 结构断言（内容不预设：模型说什么就记什么；形状/占位符必须真实）
    assert single_err is None, f"单帧真实调用失败：{single_err}"
    assert triple_err is None, f"三帧真实调用失败：{triple_err}"
    assert isinstance(single, dict) and isinstance(triple, dict)
    assert single_info["images_into_model"] == 1
    assert single_info["pixel_values_shape"] == [1, 3, 448, 448]
    assert single_info["prompt_marker_count"] == 1
    assert triple_info["images_into_model"] == 3
    assert triple_info["pixel_values_shape"] == [3, 3, 448, 448]
    assert triple_info["num_patches_list"] == [1, 1, 1]
    assert triple_info["prompt_marker_count"] == 3
