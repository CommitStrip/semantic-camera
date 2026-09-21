<div align="center">

# Semantic Camera v2

**Budget-aware semantic video event runtime for Linux NVR and Windows 11**

A surveillance camera is just "eyes" — it sees but doesn't understand. We give it a brain, but that brain must meet three harsh conditions simultaneously: **fast** (alarm ≤1s), **cheap** (nearly zero long-term cost), and **obedient** (all rules defined by the admin, the system never decides on its own).

[![CI](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml/badge.svg)](https://github.com/CommitStrip/semantic-camera/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[**English**](README.md) · [**简体中文**](README-CN.md)

</div>

---

Core philosophy: **wrap uncertain models with deterministic engineering**. The fast system (frame gating + NanoDet detection + grid rules) guards every frame with millisecond response; the slow system (VLM naming + V-JEPA embedding comparison) only engages for genuinely new events, and its call volume decays with habituation.

## Product editions

| Edition | Dedicated entry point | Product focus |
|---|---|---|
| Linux NVR | `python -m scam.linux_nvr` | Always-on service, multi-camera, recording, remote operations, 24-hour soak |
| Windows 11 Workstation | `python -m scam.win11` | Local desktop workflow, Windows data paths, interactive startup and recovery |

Both editions share the `scam` domain core. Entry points, defaults, deployment,
roadmaps, and release gates are maintained independently. `python -m scam.nvr`
is retained for compatibility only.

Edition roadmaps: [Linux NVR](docs/linux-nvr-roadmap.md) ·
[Linux release plan](docs/linux-release-plan.md) ·
[Windows 11 Workstation](docs/win11-roadmap.md)

## Linux NVR Quick Start

```bash
git clone https://github.com/CommitStrip/semantic-camera.git
cd semantic-camera
pip install numpy opencv-python-headless onnxruntime pillow

# Discover cameras on your LAN
python -m scam.discover

# Edit cameras.json (fill in RTSP address and credentials)

# Start monitoring + workbench
python -m scam.linux_nvr
# Open http://127.0.0.1:8600 (workbench binds localhost only — no auth,
# never exposed to the LAN; remote access: ssh -L 8600:127.0.0.1:8600 <NVR>)
```

## Architecture

```
RTSP Camera
   │ FrameSource (vus, auto-fallback to cv2)
   ▼
┌────────── Fast System (per-frame, zero model) ─────────────────┐
│ T0 Frame gating(1.6ms) → T1 NanoDet(motion 400ms/patrol 5s)   │
│ → Track confirm → Grid zone → Four-state verdict → Alarm ≤1s  │
└────────────────────────────────────────────────────────────────┘
   ▼ Motion trigger
┌────────── Slow System (budget-controlled, novelty-only) ──────┐
│ T2a V-JEPA embedding match → self-name (zero VLM)             │
│ T2b VLM naming → novelty archive                               │
└────────────────────────────────────────────────────────────────┘
   ▼
SQLite fully auditable
```

## Performance

| Metric | Value | Conditions |
|---|---|---|
| Alarm latency (structural) | **≤1s** | NanoDet ONNX CPU, motion in managed cells |
| Frame gating per frame | 1.6ms | Downsampled grayscale 96×54 |
| Detection (NanoDet CPU) | 23-24ms | 416×416 input |
| pytest | 116 passed, 1 Linux-only skip on Windows | Editions, event/evidence lifecycle, recording, source recovery, deployment contracts, workbench |

## License

MIT
