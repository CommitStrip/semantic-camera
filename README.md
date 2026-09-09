# semantic-camera — Semantic Camera: Venue-Mode Realtime Video Understanding on Device

[![CI](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml/badge.svg)](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml)

**English** | [简体中文](README-CN.md)

**A semantic camera = a venue-aware semantic discrimination layer on top of commodity NVR building blocks.** Turn a live video stream (Hikvision RTSP / phone camera / local video) into on-device realtime semantic understanding and alerting: frame-difference motion gating → triggered YOLOv8s detection → constant-velocity tracking + multi-frame confirmation → **fully-automatic** JEPA (DINOv2) semantic discrimination → venue-mode-driven alerting. Discrimination is organized as **venue mode packs** — the first pack is "airfield anti-drone" (bird/drone discrimination and alerting); extending to a new venue only adds a mode-pack config plus a discrimination head, with zero pipeline changes. The platform design (multi-camera scheduling / spatiotemporal rule engine / open-set rejection / privacy / continual-learning governance / evaluation gates) lives in [docs/semantic-camera-design.md](docs/semantic-camera-design.md).

This repository is the mainline of the library family: `vus` is the general video-understanding engine, `rvs` the robotics increment, and the predecessor `anti-drone-monitor` (single-scene anti-drone demo) is frozen while this repo carries the evolution forward.

Two design red lines: **no step of the discrimination pipeline may depend on human judgment** (a feature that needs a human judge is no feature); **cost has a hard cap** (budget-based, never growing linearly with runtime).

Current validation status: probe-head offline accuracy **98.15%** (162 authoritative Drone-vs-Bird samples, evidence `web/jepa_probe_init.json`: acc=0.9815, n_train=162, dim=768, inherited as measured from the predecessor repo); WHEP signaling verified end-to-end against a local MediaMTX v1.20.0 + H.264 test stream; **42 unit tests + GitHub Actions CI all green**. On-device end-to-end fps/latency benchmarks are **pending** — per-frame telemetry is already built in (see [Performance & validation status](#performance--validation-status)).

## Key capabilities

| Capability | Description |
|------|------|
| Realtime detection | Frame-difference gate (fast) → triggered detection (slow): motion fires detection within 400 ms, a 5 s patrol covers stillness; motion-area floor 0.003 suppresses sensor noise |
| Target tracking | IoU + center-distance association + constant-velocity prediction (no track loss across long detection gaps), multi-frame confirmation (≥2) cuts false positives; confirmed targets get a 12 s survival window — hovering targets are not lost |
| Fully-automatic semantic discrimination | JEPA four-state verdict: alert / pending-arbitration / cleared / suppressed — **no human judgment anywhere**; gray-zone cases enter a budget-capped arbitration queue; high-confidence dual-signal agreement auto-updates the probe head |
| Venue mode packs | Modes are data + a validator: `?mode=` selects, new venues plug in with zero code; `validatePack` is fail-closed — a bad config refuses to arm |
| Arming schedule | Mode packs may declare arming windows (overnight-capable); outside the window alerts downgrade to records and arbitration spends no budget |
| Smooth zoom | Pinch / slider / buttons + **target-following** auto-centering, smooth interpolation 1×-8× |
| Distance estimation | Pinhole model with per-class size (drone 0.35 m / bird 0.20 m); digital zoom is a center crop and does not affect the reading |
| Data traceability | IndexedDB persistence + CSV/JSON export + native bridge (Android JSONL / Harmony CSV); full chain detection→verdict→arbitration→self-training is logged |

## System layout

```
semantic-camera/
├── web/index.html        # shared HTML5 core (reused by both WebViews)
├── web/core.js           # pure-logic core (config/validation/tracking/gating/policy/queue/learning math; node:test-able)
├── gateway/              # MediaMTX gateway: Hikvision RTSP → WebRTC(WHEP)/HLS
├── android/              # Android app (Kotlin WebView shell + telemetry)
├── harmony/              # HarmonyOS(NEXT) app (ArkWeb shell + telemetry)
└── docs/                 # platform design (architecture/roadmap/risks)
```

> After editing shared files under `web/`, run `bash scripts/sync-web.sh` to sync the android/harmony packaged copies; CI enforces consistency with `--check`.

## Venue mode packs

A mode pack is pure data: detection model + discrimination head + alert rules + arming schedule + budgets, fully validated at load by `validatePack` (fail-closed: a bad config refuses to arm). First-wave venue catalog:

| Mode pack | Discrimination task | Value (false-alarm killer) | Status |
|---|---|---|---|
| **airfield anti-drone** | bird / drone | flocks and drifting objects don't alert; real drones do; gray zones never false-alarm | ✅ shipped |
| **depot smoke/fire** | smoke / fog·sunset | smoke false alarms are the industry's #1 pain | M3 |
| **site PPE compliance** | helmet / no-helmet | person detection alone cannot tell | M3 |
| **campus perimeter** | person / shadow·objects | low-light false-alarm suppression | M3 |
| **farm deterrence** | bird / animal / human | species decides the deterrence action | M5 |

## JEPA fully-automatic discrimination + auto evolution (integrated)

On top of YOLO localization, a **JEPA-style self-supervised discriminator** (`web/dinov2_vits14_feat.onnx`, 85 MB, DINOv2-ViT-S feature extractor + `web/jepa_probe_init.json` linear probe head):

- **Four-state fully-automatic verdict**: the probe outputs P(target class); the policy emits `alert` (target side, high confidence → alert) / `escalate` (target side, low confidence → **abstain and queue for arbitration** — never a false alert) / `clear` (confidently not the target → suppress) / `suppress` (silent). Before a verdict exists, the detector is authoritative (no missed alerts).
- **Auto evolution (no human-in-the-loop)**: when the logreg head and the prototype distance **agree with confidence ≥0.90**, the probe head updates itself (centroid moving average + one-step SGD with gradient descent), persisted to `localStorage`; "Reset learning" restores the initial weights (an ops action). The manual feedback buttons are gone.
- **Gray-zone arbitration queue**: `escalate` cases queue under a hard budget cap (20/hour) with per-track dedup (15 s TTL); milestone M2 bridges the vus slow brain (VLM arbitration) whose verdicts feed back as pseudo-labels (protocol in the design doc §8). Without the bridge the edge stays fully autonomous.

## Hikvision RTSP intake (verified)

- **Division of labor**: MediaMTX pulls the Hikvision RTSP stream (camera IP/credentials in `gateway/mediamtx.yml`) → WebRTC/WHEP (8889) or HLS (8888); `whep-client.js` implements standard WHEP signaling (exponential-backoff reconnect) and falls back to HLS on failure.
- **How to connect**: tap "🔌 海康" in the app, enter the gateway address and stream path (e.g. `http://gatewayIP:8889` + `cam1`) — the same detection + discrimination pipeline runs on top.
- **Hikvision RTSP URLs**: main stream `rtsp://user:pass@IP:554/Streaming/Channels/101`, sub-stream `.../102`; the main stream (1080p H.264) is recommended for detection; H.265 cameras need transcoding (see `gateway/README.md`).
- Verified end-to-end with local MediaMTX v1.20.0 + an H.264 test stream (**full WHEP signaling**: OPTIONS→POST→PATCH→DELETE all pass).

## Quick start (browser / phone)

```bash
cd web && python3 -m http.server 8899
# on a phone in the same network, open http://<PC-IP>:8899/index.html
# or open web/index.html directly in a browser
```

- Tap **▶ Start** to use the phone camera, **📁 Video** for local playback, **🔌 海康** for a real camera stream.
- Tap **⏺ Record** to open the telemetry panel; events accumulate live; **export CSV/JSON** to download.
- Zoom via slider / ＋− buttons / two-finger pinch; enable **target-following** to auto-center on confirmed targets.

## Native shells

### Android

See `android/README.md`. The core runs in a WebView loading the shared `index.html`; a `JsBridge` writes telemetry as JSONL into app-private storage; the camera is granted explicitly via `WebChromeClient.onPermissionRequest`.

### HarmonyOS

See `harmony/README.md`. The core runs in an ArkWeb component; `javaScriptProxy` writes telemetry to sandboxed CSV; the camera is granted via `onPermissionRequest` plus a runtime `ohos.permission.CAMERA` request in `EntryAbility`.

> Note: this project is a **runnable real-inference core + two native shells**. The `web/` core runs standalone in any phone browser and exercises every feature; the native shells must be built in Android Studio / DevEco Studio (no build artifacts are shipped in the repo).

## Development: tests, CI and multi-copy sync

```bash
node --test tests/core.test.mjs     # 42 unit tests (node:test, zero deps)
bash scripts/sync-web.sh            # web/ → android assets + harmony rawfile
bash scripts/sync-web.sh --check    # consistency check only (same as CI)
```

CI (node 20/22 matrix): JS syntax checks → unit tests → three-copy consistency. All pure logic (config/validation/IoU/tracker/gate/ranging/four-state policy/arbitration queue/arming schedule/probe-learning math) lives in `web/core.js` with zero DOM dependencies, directly unit-testable; the `index.html` inline script has a syntax-guard test.

## Performance & validation status

| Item | Status |
|----|------|
| WHEP signaling end-to-end | ✅ verified (MediaMTX v1.20.0 + H.264 test stream, OPTIONS→POST→PATCH→DELETE all pass) |
| Probe-head offline accuracy | ✅ 98.15% (162 samples, `web/jepa_probe_init.json`, inherited as measured from the predecessor) |
| Unit tests / CI | ✅ 42 tests green, node 20/22 matrix |
| On-device fps/latency | ⏳ pending — telemetry already records per-frame `detMs/trackMs/motionRatio`; export CSV/JSON for measured data |

Model size & strategy: YOLOv8s fp32 43 MB + DINOv2 85 MB; a single wasm-side inference takes seconds — hence detection is **trigger-based** (gating + cooldown) rather than per-frame, and JEPA runs only on confirmed targets with lazy loading.

**int8 quantization — measured verdict (2026-09-06, `scripts/quantize_models.py`)**: the current model is a custom export at opset 12 and is **not quantizable into a working model** — the QOperator path shrinks 42.7→10.9 MB and speeds inference 62→34 ms (1.8×), but post-NMS detections drop 41→0 (outputs collapse to zero). The validation tool ships with a task-level gate (detections must not drop by more than 10%, mean IoU ≥ 0.8) precisely to keep such silent failures out. The real fps lever is re-exporting yolov8n with a modern opset; DINOv2 int8 is blocked by the same quantizer operator-compatibility issue and stays fp32 (it only runs on confirmed targets, so its cost is already bounded).

## Platform roadmap

Milestones M1 (discrimination automation) → M1.5 (standalone repo + config governance, this release) → M2 (vus bridge arbitration feedback) → M3 (spatiotemporal rules + open-set + smoke/fire pack) → M4 (multi-camera scheduling + health monitoring) → M5 (retraining loop + evaluation gates + alert sinks + license decision) → M6 (multi-stream gateway box). Details and risks in [docs/semantic-camera-design.md](docs/semantic-camera-design.md).

## Platforms & hardware

Browsers need WASM and WebRTC (Android 8+ WebView / modern desktop browsers); the HarmonyOS shell needs HarmonyOS NEXT + ArkWeb. No GPU dependency — all inference is wasm CPU.

## Acknowledgments

- [MediaMTX](https://github.com/bluenviron/mediamtx) — RTSP → WebRTC/HLS streaming gateway (MIT). This repo only ships configuration and a launch script under `gateway/`.
- [onnxruntime-web](https://github.com/microsoft/onnxruntime) — wasm inference engine (MIT).
- [hls.js](https://github.com/video-dev/hls.js) — HLS fallback playback (Apache-2.0).
- [DINOv2](https://github.com/facebookresearch/dinov2) ViT-S/14 (Meta AI) — discrimination feature extractor; upstream code is Apache-2.0 while the official weights are CC-BY-NC 4.0 (non-commercial). `dinov2_vits14_feat.onnx` in this repo is an export of its vision tower; verify upstream terms before redistribution or commercial use.
- [YOLOv8 / ultralytics](https://github.com/ultralytics/ultralytics) — detection architecture (AGPL-3.0). `yolov8s-drone.onnx` in this repo is a fine-tuned drone-detection export of that architecture; redistribution and commercial use must comply with AGPL-3.0 and upstream terms.

## License

MIT © 2026 (applies to the repository code; the bundled model weights `*.onnx` follow their upstream licenses — see Acknowledgments)
