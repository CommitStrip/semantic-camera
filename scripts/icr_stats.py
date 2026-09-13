#!/usr/bin/env python3
"""icr_stats.py - 合成 ICR 回放素材生成（Phase 1 验证闸门，图像域统计合成）

从本地测试视频（web/test_person.webm，不入库）均匀采样，计算逐采样图像统计
（饱和度/噪声/亮度），按预设合成时间线拼接昼/夜(黑白+噪声)统计，输出：
  scripts/out/replay_stats.json  逐采样 {sat,noise,luma}（500ms 虚拟间隔）
  scripts/out/replay_truth.json  真值切换边界

诚实标注：统计为"合成 ICR"（真实昼帧 + 图像域黑白/噪声变换），
非真实 IR-CUT 相机输出；真实录像到位后须复验。
"""
import json
import os
import sys
from pathlib import Path

import cv2
import numpy as np

VIDEO = os.path.join("web", "test_person.webm")
OUT_STATS = Path("scripts/out/replay_stats.json")
OUT_TRUTH = Path("scripts/out/replay_truth.json")
N_SAMPLES = 240          # 240 采样 × 500ms 虚拟间隔 = 120s 虚拟时间
# 合成时间线（采样下标）：昼 → 夜 → 昼 → 夜 → 昼 → 夜（含振荡簇）
SEGMENTS = [(0, 80, "day"), (80, 200, "night"), (200, 210, "day"),
            (210, 220, "night"), (220, 230, "day"), (230, 240, "night")]


def frame_stats(bgr):
    hsv = cv2.cvtColor(bgr, cv2.COLOR_BGR2HSV)
    sat = float(np.mean(hsv[:, :, 1])) / 255.0
    luma = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY).astype(np.float32)
    noise = float(np.mean(np.abs(np.diff(luma, axis=1)))) / 255.0
    return {"sat": sat, "noise": noise, "luma": float(np.mean(luma)) / 255.0}


def main():
    if not os.path.isfile(VIDEO):
        print(f"缺少本地素材 {VIDEO}（不入库）——回放需在含素材的机器运行")
        sys.exit(2)
    cap = cv2.VideoCapture(VIDEO)
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    day_stats = []
    while len(day_stats) < N_SAMPLES:
        ok, frame = cap.read()
        if not ok:
            cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            continue
        day_stats.append(frame_stats(cv2.resize(frame, (320, 180))))
    cap.release()
    day_stats = day_stats[:N_SAMPLES]

    def to_night(st):
        # 合成黑白红外特征：饱和度崩塌、噪声抬升（红外高增益）、亮度压低
        return {"sat": 0.01, "noise": st["noise"] * 2.2 + 0.02,
                "luma": max(0.02, st["luma"] * 0.55 + 0.03)}

    def seg_at(i):
        for a, b, kind in SEGMENTS:
            if a <= i < b:
                return kind
        return SEGMENTS[-1][2]

    samples, truth = [], []
    for i in range(N_SAMPLES):
        base = day_stats[i]
        samples.append(base if seg_at(i) == "day" else to_night(base))
    for k in range(1, len(SEGMENTS)):
        a, _, kind = SEGMENTS[k]
        truth.append({"sample": a, "from": SEGMENTS[k - 1][2], "to": kind})

    OUT_STATS.parent.mkdir(parents=True, exist_ok=True)
    OUT_STATS.write_text(json.dumps({"intervalMs": 500, "samples": samples}), encoding="utf-8")
    OUT_TRUTH.write_text(json.dumps(
        {"boundaries": truth, "segments": SEGMENTS,
         "source": "synthetic-ICR (image-domain transform of real daytime footage)"},
        ensure_ascii=False), encoding="utf-8")
    print(f"stats={len(samples)} samples, truth boundaries={len(truth)} -> {OUT_STATS}")


if __name__ == "__main__":
    main()
