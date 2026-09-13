# semantic-camera — Semantic Camera: Venue-Mode Realtime Video Understanding on Device

[![CI](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml/badge.svg)](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml)

**English** | [简体中文](README-CN.md)

**A budget-aware, mode-configurable edge vision event runtime** — **a semantic camera = a venue-aware semantic discrimination layer on top of commodity NVR building blocks.** Turn a live video stream (Hikvision RTSP / phone camera / local video) into on-device realtime semantic understanding and alerting: frame-difference motion gating → triggered detection → constant-velocity tracking + multi-frame confirmation → fully-automatic semantic discrimination → venue-mode-driven alerting and disposition. Discrimination is organized as **venue mode packs** — extending to a new venue only adds data to `web/mode-packs.js` (plus optional model/discrimination head files) with **zero core changes, enforced by CI two-mode acceptance and source-cleanliness tests**. The platform design (multi-camera scheduling / spatiotemporal rule engine / open-set rejection / privacy / continual-learning governance / evaluation gates) lives in [docs/semantic-camera-design.md](docs/semantic-camera-design.md); runtime ER diagram in [docs/architecture-er.html](docs/architecture-er.html) (open directly in a browser).

This repository is the mainline of the library family: `vus` is the general video-understanding engine, `rvs` the robotics increment, and the predecessor `anti-drone-monitor` (single-scene anti-drone demo) is frozen while this repo carries the evolution forward.

Three design red lines: **the discrimination pipeline runs fully automatically with no human judgment step** (discrimination never waits for a human; but "automatic understanding ≠ automatic execution of everything" — human review never blocks the realtime pipeline, and whether high-impact external effects need human confirmation is decided by the effect policy); **cost has a hard cap** (budget-based, never growing linearly with runtime); **new venues require no core-logic changes** (the platform-viability criterion; mode selection is fail-closed — an unknown mode refuses to arm and never silently falls back to another venue).

**Claims discipline**: today's algorithms are a "configurable event camera + per-venue discrimination heads" — we do not claim universal scene understanding, zero false alarms, human-level semantics, or "zero-code venue onboarding" (the accurate claim: new venues require no core-logic changes, while still adding registry data and redeploying); we report measured numbers only, and everything unmeasured is marked "pending / design / roadmap".

Current validation status: probe-head offline accuracy **98.15%** (162 authoritative Drone-vs-Bird samples, evidence `web/jepa_probe_init.json`: acc=0.9815, n_train=162, dim=768, inherited as measured from the predecessor repo); **the person model is validated on real street footage**: NanoDet-Plus-m-1.5x@416 (Apache-2.0) detects 7–58 persons/frame on sampled frames of a CC-licensed Shibuya crossing video at 23–24 ms/frame CPU (selection and measurements in [docs/model-selection.md](docs/model-selection.md)); WHEP signaling verified end-to-end against a local MediaMTX v1.20.0 + H.264 test stream; **99 unit tests + GitHub Actions CI all green** (including two-mode end-to-end acceptance, source-cleanliness, evidence-schema contract, mode-selection fail-closed, asset-integrity, and spatiotemporal-rule gates). On-device end-to-end fps/latency benchmarks are **pending**.

## Key capabilities

| Capability | Description |
|------|------|
| Realtime detection | Frame-difference gate (fast) → triggered detection (slow): motion fires detection within 400 ms, a 5 s patrol covers stillness; motion-area floor 0.003 suppresses sensor noise |
| Target tracking | IoU + center-distance association + constant-velocity prediction (no track loss across long detection gaps), multi-frame confirmation (≥2) cuts false positives; confirmed targets get a 12 s survival window — hovering targets are not lost |
| Fully-automatic semantic discrimination | Four-state verdict (discriminated / detector-authority dual paths): alert / pending-arbitration / cleared / suppressed — **no human judgment anywhere**; gray-zone cases enter a budget-capped arbitration queue; high-confidence dual-signal agreement auto-updates the probe head |
| Venue mode packs | Modes are data + a validator: `?mode=` selects, new venues plug in with zero code; domain terms live only in `web/mode-packs.js` (enforced by a CI cleanliness test); `validatePack` is fail-closed — a bad config refuses to arm |
| Evidence events | Versioned `sc.evidence/v1` envelope: stable event ID, dual timestamps (source/processed), mode-pack config fingerprint, policy version, model SHA-256, detector and discriminator confidences kept separate, alert crop frame with its content hash — auditable, machine-consumable events |
| Arming schedule | Mode packs may declare arming windows (overnight-capable); outside the window alerts downgrade to records and arbitration spends no budget |
| Spatiotemporal rules | Polygon zones (enter + dwell + occupancy count) and trip lines (direction-filtered crossing with cooldown): rules are pure pack data, read-only overlay | 
| Scene auto-recognition | The first confirmed trigger sends frames to the slow brain to identify the venue (CLIP zero-shot fallback / ollama VLM refine); conf≥0.85 auto-arms; unidentified = observation mode (records only, never fabricates); manual assignment always wins |
| vus bridge arbitration (M2) | Gray-zone cases escalate to a pluggable slow brain (CLIP zero-shot / ollama VLM): verdicts feed back as pseudo-labels, cases archived to JSONL; bridge down = edge stays fully autonomous, never fabricates |
| Zone rules | Polygon zones (normalized coords): entering + dwelling past `dwellMs` escalates to an alert (`zone-intrusion`), outside-zone targets downgrade to records; read-only overlay |
| Detector head registry | `HEAD_DECODERS`: `yolo8head` (no objectness) / `nanodethead` (GFL distribution regression) / `mock` (deterministic timeline) — the head name is a provider-registry key, extending adds no core changes |
| Asset single-sourcing | Models/runtime live once under `assets/` (manifest with sha256/license/source), staged to the three copies at build time, CI hash gate against silent drift |
| Smooth zoom | Pinch / slider / buttons + **target-following** auto-centering, smooth interpolation 1×-8× |
| Distance estimation | Pinhole model with per-class size (drone 0.35 m / bird 0.20 m); digital zoom is a center crop and does not affect the reading |
| Data traceability | IndexedDB persistence + CSV/JSON export + native bridge (Android JSONL / Harmony CSV); full chain detection→verdict→arbitration→self-training is logged |

## System layout

```
semantic-camera/
├── web/index.html        # shared HTML5 core (reused by both WebViews; domain-free)
├── web/core.js           # pure-logic core (config/validation/tracking/gating/policy/queue/learning math/mock detector/evidence events)
├── web/mode-packs.js     # venue mode-pack registry (pure data; the only home of domain terms)
├── gateway/              # MediaMTX gateway: Hikvision RTSP → WebRTC(WHEP)/HLS
├── bridge/               # vus slow-brain arbitration bridge (M2): gray-zone cases → CLIP/ollama verdicts → probe feedback
├── android/              # Android app (Kotlin WebView shell + telemetry)
├── harmony/              # HarmonyOS(NEXT) app (ArkWeb shell + telemetry)
└── docs/                 # platform design (architecture/roadmap/risks)
```

> After editing shared files under `web/`, run `bash scripts/sync-web.sh` to sync the android/harmony packaged copies; CI enforces consistency with `--check`.

## Venue mode packs

A mode pack is pure data: detection model (pluggable onnx/mock) + optional discrimination head + alert rules + arming schedule + budgets, fully validated at load by `validatePack` (fail-closed: a bad config refuses to arm). **Platform-viability criterion: new venues require no core changes** — the second pack `restricted-area` proves the abstraction via a CI two-mode end-to-end test. First-wave venue catalog:

| Mode pack | Discrimination task | Value (false-alarm killer) | Status |
|---|---|---|---|
| **airfield anti-drone** | bird / drone | flocks and drifting objects don't alert; real drones do; gray zones never false-alarm | ✅ fully shipped |
| **restricted-area intrusion** | person (detector-authority, no discrimination head) | night arming + abstain semantics; zone rules land in M3 | ✅ abstraction proven (mock demo; real model pending) |
| **depot smoke/fire** | smoke / fog·sunset | smoke false alarms are the industry's #1 pain | M3 |
| **site PPE compliance** | helmet / no-helmet | person detection alone cannot tell | M3 |
| **campus perimeter** | person / shadow·objects | low-light false-alarm suppression | M3 |
| **farm deterrence** | bird / animal / human | species decides the deterrence action | M5 |

## JEPA fully-automatic discrimination + auto evolution (integrated)

On top of YOLO localization, a **JEPA-style self-supervised discriminator** (`web/dinov2_vits14_feat.onnx`, 85 MB, DINOv2-ViT-S feature extractor + `web/jepa_probe_init.json` linear probe head):

- **Four-state fully-automatic verdict**: the probe outputs P(target class); the policy emits `alert` (target side, high confidence → alert) / `escalate` (target side, low confidence → **abstain and queue for arbitration** — never a false alert) / `clear` (confidently not the target → suppress) / `suppress` (silent). Before a verdict exists, the detector is authoritative (no missed alerts).
- **Auto evolution (capability shipped, disabled by default)**: on frozen features, when the logreg head and the prototype distance agree with confidence ≥0.90, the probe head can update itself (centroid moving average + one-step SGD). **Defaults to `enabled:false`** — the two signals are not independent evidence; until the governance stack (frozen evaluation set, versioned rollback, open-set rejection) is complete (M5), the head must not be modified online by default; per-venue opt-in follows. Learning state is isolated per mode pack (`jepa_probe_v2:<modeId>`) so one venue's pseudo-labels never pollute another. "Reset learning" restores the initial weights (an ops action). The manual feedback buttons are gone.
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
- **Scene auto-recognition**: start without picking a mode = observation mode (person detection, records only); with the bridge connected, the first confirmed trigger auto-identifies the venue and arms (conf≥0.85); switch anytime via the "场景" dropdown.

## Native shells

### Android

See `android/README.md`. The core runs in a WebView loading the shared `index.html`; a `JsBridge` writes telemetry as JSONL into app-private storage; the camera is granted explicitly via `WebChromeClient.onPermissionRequest`.

### HarmonyOS

See `harmony/README.md`. The core runs in an ArkWeb component; `javaScriptProxy` writes telemetry to sandboxed CSV; the camera is granted via `onPermissionRequest` plus a runtime `ohos.permission.CAMERA` request in `EntryAbility`.

> Note: this project is a **runnable real-inference core + two native shells**. The `web/` core runs standalone in any phone browser and exercises every feature; the native shells must be built in Android Studio / DevEco Studio (no build artifacts are shipped in the repo).

## Development: tests, CI and multi-copy sync

```bash
node --test tests/core.test.mjs     # 99 unit tests (node:test, zero deps)
python scripts/verify_models.py    # model asset sha256 integrity (fail-closed)
bash scripts/sync-web.sh            # web/ → android assets + harmony rawfile
bash scripts/sync-web.sh --check    # consistency check only (same as CI)
```

CI (node 20/22 matrix): JS syntax checks → unit tests → three-copy consistency. All pure logic (config/validation/IoU/tracker/gate/ranging/four-state policy/arbitration queue/arming schedule/probe-learning math/mock detector/evidence events) lives in `web/core.js` with zero DOM dependencies, directly unit-testable. Two signature tests: the **two-mode end-to-end acceptance** (the same core pipeline drives both the airfield and restricted-area packs — the standing proof of the platform abstraction) and the **source-cleanliness meta-test** (core.js and the inline script must not contain venue domain terms — preventing "platform in name, single scene in code" regression).

## Performance & validation status

| Item | Status |
|----|------|
| WHEP signaling end-to-end | ✅ verified (MediaMTX v1.20.0 + H.264 test stream, OPTIONS→POST→PATCH→DELETE all pass) |
| Probe-head offline accuracy | ✅ 98.15% (162 samples, `web/jepa_probe_init.json`, inherited as measured from the predecessor) |
| Unit tests / CI | ✅ 99 tests green (incl. two-mode acceptance, cleanliness, schema contract, fail-closed, asset-integrity, spatiotemporal-rule gates), node 20/22 matrix |
| Person model on real street footage | ✅ NanoDet-Plus@416: 7–58 persons/frame on sampled frames, 23–24 ms/frame CPU ([selection record](docs/model-selection.md)); browser wasm fps ⏳ pending |
| On-device fps/latency | ⏳ pending — telemetry already records per-frame `detMs/trackMs/motionRatio`; export CSV/JSON for measured data |

Model size & strategy: YOLOv8s fp32 43 MB + DINOv2 85 MB; a single wasm-side inference takes seconds — hence detection is **trigger-based** (gating + cooldown) rather than per-frame, and JEPA runs only on confirmed targets with lazy loading.

**int8 quantization — measured verdict (2026-09-06, `scripts/quantize_models.py`)**: the current model is a custom export at opset 12 and is **not quantizable into a working model** — the QOperator path shrinks 42.7→10.9 MB and speeds inference 62→34 ms (1.8×), but post-NMS detections drop 41→0 (outputs collapse to zero). The validation tool ships with a task-level gate (detections must not drop by more than 10%, mean IoU ≥ 0.8) precisely to keep such silent failures out. The real fps lever is re-exporting yolov8n with a modern opset; DINOv2 int8 is blocked by the same quantizer operator-compatibility issue and stays fp32 (it only runs on confirmed targets, so its cost is already bounded).

## Platform roadmap

Milestones M1 (discrimination automation) → M1.5 (standalone repo + config governance) → M1.6 (platform consolidation: domain-free core + two-mode acceptance + evidence events) → M1.7 (provenance hardening: fail-closed mode selection + evidence provenance fields + self-training off by default) → **P1-①② (real restricted-area model + zone rules / single-source model assets, this release)** → M2 (vus bridge arbitration feedback, ✅) → → M2.6 scene auto-recognition (✅) → M3-a/b (✅) → M5-partial Outbox (✅) → **v3 core loop (M3-c imaging modality / M3-d segmentation / M2.7 naming / M3-e habituation, this release)** → M3 (spatiotemporal rules + open-set + smoke/fire pack) → M4 (multi-camera scheduling + health monitoring) → M5 (retraining loop + evaluation gates + alert sinks + license decision — the precondition for enabling self-training) → M6 (multi-stream gateway box). Details and risks in [docs/semantic-camera-design.md](docs/semantic-camera-design.md).

## Platforms & hardware

Browsers need WASM and WebRTC (Android 8+ WebView / modern desktop browsers); the HarmonyOS shell needs HarmonyOS NEXT + ArkWeb. No GPU dependency — all inference is wasm CPU.

## Acknowledgments

- [MediaMTX](https://github.com/bluenviron/mediamtx) — RTSP → WebRTC/HLS streaming gateway (MIT). This repo only ships configuration and a launch script under `gateway/`.
- [onnxruntime-web](https://github.com/microsoft/onnxruntime) — wasm inference engine (MIT).
- [hls.js](https://github.com/video-dev/hls.js) — HLS fallback playback (Apache-2.0).
- [NanoDet-Plus](https://github.com/RangiLyu/nanodet) (Apache-2.0) — person detection model (person-detector.onnx is the official COCO-pretrained export, see docs/model-selection.md).
- [DINOv2](https://github.com/facebookresearch/dinov2) ViT-S/14 (Meta AI) — discrimination feature extractor; upstream code is Apache-2.0 while the official weights are CC-BY-NC 4.0 (non-commercial). `dinov2_vits14_feat.onnx` in this repo is an export of its vision tower; verify upstream terms before redistribution or commercial use.
- [YOLOv8 / ultralytics](https://github.com/ultralytics/ultralytics) — detection architecture (AGPL-3.0). `yolov8s-drone.onnx` in this repo is a fine-tuned drone-detection export of that architecture; redistribution and commercial use must comply with AGPL-3.0 and upstream terms.

## License

MIT © 2026 (applies to the repository code; the bundled model weights `*.onnx` follow their upstream licenses — see Acknowledgments)
