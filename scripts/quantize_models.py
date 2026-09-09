#!/usr/bin/env python3
"""
quantize_models.py - 端侧模型 int8 量化（帧率杠杆）+ 保真度校验 + 基准对比
==========================================================================
把 web/ 下的 fp32 模型量化为 int8 并产出可决策的实测数据：

  yolov8s-drone.onnx      → yolov8s-drone-int8.onnx      静态 QDQ（校准集=本仓库
                                                           test_drone.mp4 提帧，预处理
                                                           与 web 前端逐像素同款 letterbox）
  dinov2_vits14_feat.onnx → dinov2_vits14_feat-int8.onnx 动态量化（ViT 以 MatMul 为主，
                                                           无需校准集）

每一步都打印：体积 / 单次推理耗时（Python onnxruntime CPU——为 wasm 的代理指标，
量级与相对加速方向可参考）/ 保真度（YOLO=高置信 anchor 的 conf 与框偏差；
DINOv2=归一化特征余弦相似度）。app 是否切换 int8 由这些数字决定，不盲切。

用法: python scripts/quantize_models.py   （在仓库根目录运行）
"""

import os
import sys
import time

import cv2
import numpy as np
import onnxruntime as ort

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "web")
YOLO32 = os.path.join(WEB, "yolov8s-drone.onnx")
YOLO8 = os.path.join(WEB, "yolov8s-drone-int8.onnx")
DINO32 = os.path.join(WEB, "dinov2_vits14_feat.onnx")
DINO8 = os.path.join(WEB, "dinov2_vits14_feat-int8.onnx")
CALIB_VIDEO = os.path.join(WEB, "test_drone.mp4")

N_CALIB = 48          # 校准帧数
N_BENCH_WARM = 10     # 基准预热
N_BENCH = 30          # 基准计时次数
YOLO_SIZE = 640
DINO_SIZE = 224


def letterbox640(bgr):
    """与 web/index.html _preprocess 逐像素同款：短边缩放 + 114 灰底 + RGB/255 + CHW。"""
    h, w = bgr.shape[:2]
    r = min(YOLO_SIZE / w, YOLO_SIZE / h)
    nw, nh = max(1, round(w * r)), max(1, round(h * r))
    resized = cv2.resize(bgr, (nw, nh), interpolation=cv2.INTER_LINEAR)
    canvas = np.full((YOLO_SIZE, YOLO_SIZE, 3), 114, dtype=np.uint8)
    top, left = (YOLO_SIZE - nh) // 2, (YOLO_SIZE - nw) // 2
    canvas[top:top + nh, left:left + nw] = resized
    rgb = cv2.cvtColor(canvas, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
    return rgb.transpose(2, 0, 1)[np.newaxis]  # 1,3,640,640


def center224(bgr):
    """DINOv2 输入（与 web 前端同款：RGB /255，无 mean/std——探针训练口径）。"""
    h, w = bgr.shape[:2]
    s = min(h, w)
    top, left = (h - s) // 2, (w - s) // 2
    crop = cv2.resize(bgr[top:top + s, left:left + s], (DINO_SIZE, DINO_SIZE),
                      interpolation=cv2.INTER_LINEAR)
    rgb = cv2.cvtColor(crop, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
    return rgb.transpose(2, 0, 1)[np.newaxis]  # 1,3,224,224


def load_frames(n, size_fn):
    """从校准视频均匀抽帧并预处理。"""
    cap = cv2.VideoCapture(CALIB_VIDEO)
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    idxs = np.linspace(0, max(0, total - 1), n).astype(int)
    frames, last = {}, 0
    for i in idxs:
        if i != last:
            cap.set(cv2.CAP_PROP_POS_FRAMES, int(i))
        ok, bgr = cap.read()
        last = i
        if ok:
            frames[int(i)] = size_fn(bgr)
    cap.release()
    return frames


def bench(sess, feed, warm=N_BENCH_WARM, n=N_BENCH):
    inp = {sess.get_inputs()[0].name: feed}
    for _ in range(warm):
        sess.run(None, inp)
    t0 = time.perf_counter()
    for _ in range(n):
        sess.run(None, inp)
    return (time.perf_counter() - t0) / n * 1000


def mb(path):
    return os.path.getsize(path) / 1048576


def nms_final(o, conf_th=0.25, iou_th=0.45):
    """任务级校验用：conf 阈值 + NMS 后的最终检出 [[x1,y1,x2,y2,conf]]。"""
    cx, cy, w, h = o[0, :4]
    score = o[0, 4]
    keep = score > conf_th
    b = np.stack([cx[keep] - w[keep] / 2, cy[keep] - h[keep] / 2,
                  cx[keep] + w[keep] / 2, cy[keep] + h[keep] / 2], axis=1)
    s = score[keep]
    order = np.argsort(-s)
    out = []
    while len(order):
        i = order[0]
        out.append([*b[i], s[i]])
        order = order[1:]
        if not len(order):
            break
        xx1 = np.maximum(b[order, 0], b[i, 0]); yy1 = np.maximum(b[order, 1], b[i, 1])
        xx2 = np.minimum(b[order, 2], b[i, 2]); yy2 = np.minimum(b[order, 3], b[i, 3])
        iw = np.clip(xx2 - xx1, 0, None); ih = np.clip(yy2 - yy1, 0, None)
        inter = iw * ih
        ua = (b[order, 2] - b[order, 0]) * (b[order, 3] - b[order, 1]) \
            + (b[i, 2] - b[i, 0]) * (b[i, 3] - b[i, 1]) - inter
        order = order[(ua <= 0) | (inter / ua <= iou_th)]
    return np.array(out)


def quantize_yolo():
    print("=" * 64)
    print("[YOLOv8s-drone] fp32 → int8 静态量化（QOperator QLinearConv u8s8）")
    calib = load_frames(N_CALIB, letterbox640)
    print(f"  校准帧: {len(calib)} 张 @{YOLO_SIZE}px")
    sess32 = ort.InferenceSession(YOLO32, providers=["CPUExecutionProvider"])
    in_name = sess32.get_inputs()[0].name
    print(f"  fp32 IO: {sess32.get_inputs()[0].shape} → {sess32.get_outputs()[0].shape}")

    from onnxruntime.quantization import (CalibrationMethod, QuantFormat,
                                          QuantType, quantize_static)
    from onnxruntime.quantization.shape_inference import quant_pre_process

    pre = YOLO32 + ".pre.onnx"
    quant_pre_process(YOLO32, pre)

    class Reader:
        def __init__(self, data):
            self.items = list(data.items()); self.i = 0
        def get_next(self):
            if self.i >= len(self.items):
                return None
            _, f = self.items[self.i]; self.i += 1
            return {in_name: f}

    # QOperator(QLinearConv u8s8) 而非 QDQ：原模型 opset 12，QDQ 的 per-channel
    # bias 需要 DequantizeLinear(axis)（opset≥13）会产出非法图；QLinearConv 的
    # bias 走 int32 输入无此依赖，且是 wasm 端最经典的量化算子路径。
    quantize_static(pre, YOLO8, Reader(calib),
                    quant_format=QuantFormat.QOperator,
                    activation_type=QuantType.QUInt8,
                    weight_type=QuantType.QInt8,
                    per_channel=True,
                    calibrate_method=CalibrationMethod.MinMax)
    os.remove(pre)
    print(f"  体积: {mb(YOLO32):.1f}MB → {mb(YOLO8):.1f}MB")

    sess8 = ort.InferenceSession(YOLO8, providers=["CPUExecutionProvider"])
    ms32 = bench(sess32, next(iter(calib.values())))
    ms8 = bench(sess8, next(iter(calib.values())))
    print(f"  推理耗时(ORT-CPU 代理): {ms32:.0f}ms → {ms8:.0f}ms（{ms32 / ms8:.2f}×）")

    # 保真度校验①：任务级——NMS 后最终检出集合对比（这是验收口径）。
    # 教训：anchor 级指标会被"无目标帧"欺骗（fp32/int8 都接近 0，偏差假性很小），
    # 2026-09-06 实测 int8 输出在有检出的帧上恒为零、anchor 级却显示 0.04 偏差。
    n_det32, n_det8, matched_ious = 0, 0, []
    for f in calib.values():
        d32 = nms_final(sess32.run(None, {in_name: f})[0])
        d8 = nms_final(sess8.run(None, {in_name: f})[0])
        n_det32 += len(d32); n_det8 += len(d8)
        for a in d32:
            best = 0.0
            for b in d8:
                xx1 = max(a[0], b[0]); yy1 = max(a[1], b[1])
                xx2 = min(a[2], b[2]); yy2 = min(a[3], b[3])
                inter = max(0, xx2 - xx1) * max(0, yy2 - yy1)
                ua = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
                best = max(best, inter / ua if ua > 0 else 0.0)
            matched_ious.append(best)
    print(f"  任务级保真度(全部 {len(calib)} 校准帧): fp32 检出 {n_det32} 个 → "
          f"int8 检出 {n_det8} 个"
          + (f"，IoU 均值 {np.mean(matched_ious):.3f} 最小 {min(matched_ious):.3f}"
             if matched_ious else ""))
    if n_det32 == 0:
        print("  ⚠ 校准视频在 conf=0.25 下无任何检出——保真度校验不可信，"
              "请更换含目标的校准素材")
        return False
    ok = n_det8 >= n_det32 * 0.9 and (not matched_ious or np.mean(matched_ious) >= 0.8)
    print(f"  判定: {'✅ 可用' if ok else '❌ 不可用（量化破坏检出能力，禁止切换）'}")
    return ok


def quantize_dino():
    print("=" * 64)
    print("[DINOv2 ViT-S/14] fp32 → int8 动态量化（MatMul/Gemm 权重）")
    frames = load_frames(5, center224)
    sess32 = ort.InferenceSession(DINO32, providers=["CPUExecutionProvider"])
    in_name = sess32.get_inputs()[0].name
    print(f"  fp32 IO: {sess32.get_inputs()[0].shape} → {sess32.get_outputs()[0].shape}")

    from onnxruntime.quantization import quantize_dynamic, QuantType
    try:
        try:
            quantize_dynamic(DINO32, DINO8, weight_type=QuantType.QInt8, per_channel=True)
        except Exception as e:
            # per-channel 权重的 DQL(axis) 需要 opset≥13；低 opset 模型回退 per-tensor
            print(f"  per_channel=True 失败({type(e).__name__})，回退 per_channel=False")
            if os.path.exists(DINO8):
                os.remove(DINO8)
            quantize_dynamic(DINO32, DINO8, weight_type=QuantType.QInt8, per_channel=False)
        print(f"  体积: {mb(DINO32):.1f}MB → {mb(DINO8):.1f}MB")
        sess8 = ort.InferenceSession(DINO8, providers=["CPUExecutionProvider"])
        ms32 = bench(sess32, next(iter(frames.values())))
        ms8 = bench(sess8, next(iter(frames.values())))
        print(f"  推理耗时(ORT-CPU 代理): {ms32:.0f}ms → {ms8:.0f}ms（{ms32 / ms8:.2f}×）")

        # 保真度：归一化特征余弦相似度（探针头在 fp32 特征上训练，特征漂移直接伤精度）
        sims = []
        for f in frames.values():
            f32 = sess32.run(None, {in_name: f})[0].reshape(-1)
            f8 = sess8.run(None, {in_name: f})[0].reshape(-1)
            f32 = f32 / (np.linalg.norm(f32) + 1e-8)
            f8 = f8 / (np.linalg.norm(f8) + 1e-8)
            sims.append(float(f32 @ f8))
        print(f"  保真度: 特征余弦相似度 min={min(sims):.4f} mean={np.mean(sims):.4f}（5 帧）")
        return min(sims)
    except Exception as e:
        # 量化器内部优化可能破坏特定算子（如 Resize cubic 初始化校验）——
        # DINOv2 只在确认目标上跑、是次要杠杆，失败优雅跳过、不留坏产物
        print(f"  ⚠ DINOv2 int8 不可用（{type(e).__name__}: {str(e)[:120]}），保持 fp32")
        if os.path.exists(DINO8):
            os.remove(DINO8)
        return None


def main():
    ok = quantize_yolo()
    sim = quantize_dino()
    print("=" * 64)
    print(f"结论: yolo_int8={'OK' if ok else 'FAIL（禁止切换，app 保持 fp32）'} "
          f"dino_min_cos={'跳过' if sim is None else f'{sim:.4f}'}")
    print("切换判据: 任务级——NMS 后检出数不降 10% 且 IoU 均值 ≥0.8；dino 余弦 >0.98")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
