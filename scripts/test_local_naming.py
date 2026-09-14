#!/usr/bin/env python3
"""慢脑命名真模型实测探针（手动工具，非 CI 测试）。

从本地测试视频抽帧 → 组装 sc.segment-label 上游的 segment-name 请求 →
直调 bridge.arbiters.OllamaArbiter.name_segment → 校验输出规范并计时。

用法: python scripts/test_local_naming.py [模型名] [--frames "GLOB"]
      缺省模型 qwen3-vl:2b；--frames 指定图片 glob（如网关拉流抽帧），
      缺省从 web/test_person.webm 抽 3 帧。
前置: ollama 服务运行中、对应视觉模型已 pull；素材存在。
"""
import asyncio
import base64
import glob as globmod
import json
import os
import sys
import time

import cv2

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from bridge.arbiters import OllamaArbiter  # noqa: E402

VIDEO = os.path.join(ROOT, "web", "test_person.webm")
ARGS = sys.argv[1:]
MODEL = ARGS[0] if ARGS and not ARGS[0].startswith("--") else "qwen3-vl:2b"
FRAME_GLOB = None
if "--frames" in ARGS:
    FRAME_GLOB = ARGS[ARGS.index("--frames") + 1]

SUMMARY = {"classes": ["person"], "peakCount": 1, "tracksSeen": 1,
           "pathShape": "pass-through", "zones": [], "lines": [],
           "durMs": 34000, "modality": "DAY-COLOR", "tod": "day"}
BEHAVIORS = [
    {"id": "loitering", "name": "可疑滞留",
     "description": "人员在门口区域停留超过 60 秒且不通行",
     "observable": "同一人持续出现在画面中且位置基本不变"},
    {"id": "fence-climb", "name": "翻墙",
     "description": "人员攀爬围栏或围墙进入，而非经由大门通行",
     "observable": "人体出现在围栏上方且越过"},
]


def grab_keyframes(n=3):
    if FRAME_GLOB:
        paths = sorted(globmod.glob(FRAME_GLOB))[:n]
        jpegs = []
        for p in paths:
            img = cv2.imread(p)
            if img is None:
                continue
            h, w = img.shape[:2]
            if w > 320:                      # 与页面管线同规格：320 宽关键帧
                img = cv2.resize(img, (320, round(h * 320.0 / w)))
            ok2, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 60])
            if ok2:
                jpegs.append(base64.b64encode(buf.tobytes()).decode())
        return jpegs
    cap = cv2.VideoCapture(VIDEO)
    if not cap.isOpened():
        raise SystemExit("打不开测试视频: " + VIDEO)
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 1
    jpegs = []
    for i in range(n):
        cap.set(cv2.CAP_PROP_POS_FRAMES, int(total * (i + 0.5) / n))
        ok, frame = cap.read()
        if not ok:
            continue
        h, w = frame.shape[:2]
        scale = 320.0 / w
        small = cv2.resize(frame, (320, round(h * scale)))
        ok2, buf = cv2.imencode(".jpg", small, [cv2.IMWRITE_JPEG_QUALITY, 60])
        if ok2:
            jpegs.append(base64.b64encode(buf.tobytes()).decode())
    cap.release()
    return jpegs


async def main():
    kfs = grab_keyframes()
    if not kfs:
        raise SystemExit("抽帧失败")
    print(f"[probe] 模型={MODEL} 关键帧={len(kfs)} 张（320 宽 JPEG，与页面管线同规格）")
    arb = OllamaArbiter(model=MODEL, prompts={"person": ""})
    req = {"segmentId": "probe:1", "summary": SUMMARY, "behaviors": BEHAVIORS,
           "keyframes": kfs, "packId": "restricted-area"}
    t0 = time.time()
    out = await arb.name_segment(req)
    dt = time.time() - t0
    print(f"[probe] 延迟 {dt:.1f}s  输出: {json.dumps(out, ensure_ascii=False)}")
    problems = []
    if not out.get("name"):
        problems.append("无 name（弃权/解析失败）")
    else:
        if len(out["name"]) > 16:
            problems.append(f"name 超 16 字: {len(out['name'])}")
        if not (0.0 <= float(out.get("conf", 0)) <= 1.0):
            problems.append("conf 越界")
    r = out.get("rationale") or ""
    if len(r) > 60:
        problems.append("rationale 超 60 字")
    print("[probe] " + ("FAIL: " + "; ".join(problems) if problems
                        else "PASS —— 输出符合命名规范" + ("（undecidable 诚实弃权）" if out.get("name") is None and "无法解析" not in r else "")))
    return 1 if problems and out.get("name") else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
