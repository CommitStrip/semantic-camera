<div align="center">

<img src="docs/logo.svg" width="104" alt="Semantic Camera"/>

# Semantic Camera v2

**Budget-aware on-device semantic video event runtime — Linux NVR and Windows 11 editions**

[![CI](https://github.com/CommitStrip/semantic-camera/actions/workflows/ci.yml/badge.svg)](https://github.com/CommitStrip/semantic-camera/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1109%20passed%2C%2016%20skipped-brightgreen)](tests/)

[**English**](README.md) · [**简体中文**](README-CN.md)

</div>

---

A surveillance camera is just "eyes" — it sees but doesn't understand. We give it a brain, but that brain must meet three harsh conditions at once: **fast** (alarm ≤ 1s), **cheap** (nearly zero long-term cost), and **obedient** (every rule is defined by the admin; the system never decides on its own).

Core idea: **wrap uncertain models with deterministic engineering**. The fast system (frame-difference gating + NanoDet detection + grid rules) guards every frame with millisecond response; the slow system (VLM naming + V-JEPA embedding comparison) engages only for genuinely new events, and its call volume decays as patterns become familiar.

## ✨ Core features

- **Fast/slow layering** — T0 gating 0.4ms per frame → T1 detection on motion → structural verdict alarms ≤ 1s → T2 understanding under budget → T3 habituation batching
- **Zero slow-layer on the alarm path** — alarm = detection + admin rules, with no model in front of it
- **Grid zone selection** — the admin paints cells on the frame to define managed areas
- **Custom alarm templates** — structural conditions evaluated in real time, semantic descriptions as backup
- **Habituation saves tokens** — a V-JEPA embedding hit lets a known pattern name itself with zero VLM calls; repeated scenes trend to zero
- **Dual model channels** — local ollama (data never leaves the NVR) or a cloud OpenAI-compatible API, switchable in the workbench
- **Events archived as they happen** — every event has its own bounded context; SQLite stays fully auditable and never accumulates
- **One slow-system execution core** — CAS-based claim mutual exclusion, single-transaction terminal writes, one authoritative backlog entry point; corrupt or unknown state is never touched (fail-closed) yet stays honestly visible as pending work
- **No special setup** — auto-discovery plus a single command to start; the workbench is just a browser tab

## 🧭 Product editions

| Edition | Dedicated entry point | Product focus | Release gate |
|---|---|---|---|
| Linux NVR | `python -m scam.linux_nvr` | Always-on service, multi-camera, recording, remote operations, 24h soak | Linux CI + systemd + on-device soak |
| Windows 11 Workstation | `python -m scam.win11` | Local interactive use, desktop startup, Windows data paths, recovery | Windows CI + native Windows 11 acceptance |

Both editions share the `scam` domain core, while entry points, defaults, deployment chains and acceptance reports are maintained separately. `python -m scam.nvr` is kept for legacy deployments only.

Operations (install / upgrade / rollback / backup and restore) are covered by the
[operations runbook](docs/linux-operations-runbook.md).

## 🚀 Quick start

### Install

```bash
git clone https://github.com/CommitStrip/semantic-camera.git
cd semantic-camera
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[detect,vision]"                   # the core needs only numpy; these add detection and video decoding
# optional: pip install -e ".[discover]"   LAN camera discovery (WS-Discovery)
# optional: pip install -e ".[mqtt]"       notification outlet
```

Detection and embedding **weights are not distributed in the package**; fetch them with the script:

```bash
python scripts/fetch_models.py --list                              # manifest and on-disk status
python scripts/fetch_models.py --model nanodet                     # download + verify once the hash is frozen
python scripts/fetch_models.py --verify-local <path> --expect <sha256>   # verify your own export
```

### Linux NVR

```bash
python -m scam.discover        # discover cameras on your LAN (writes a cameras.json draft)
# edit cameras.json: fill in RTSP address and credentials
python -m scam.linux_nvr       # start monitoring + workbench
# open http://127.0.0.1:8600
# the workbench binds localhost only and has no auth — it is never exposed to the LAN;
# remote access: ssh -L 8600:127.0.0.1:8600 <NVR> and open the same address
```

### NVR deployment (systemd)

```bash
bash deploy/install.sh
sudo systemctl enable --now scam-nvr
```

Upgrades, rollbacks and backup/restore are covered by the
[operations runbook](docs/linux-operations-runbook.md), where every destructive
step requires explicit human confirmation.

### Windows 11 Workstation

```powershell
powershell -ExecutionPolicy Bypass -File deploy\install-win11.ps1
deploy\start-win11.bat
```

Equivalent entry point: `python -m scam.win11`.

## 🏗️ Architecture

```
RTSP camera
   │ FrameSource (VUS first, automatic fallback to cv2)
   ▼
┌─────────────── Fast system (per-frame, zero model) ────────────────┐
│ T0 frame gating (0.4ms) → T1 NanoDet (on motion / on patrol)       │
│ → track confirm → grid decision → four-state verdict → alarm ≤ 1s  │
└────────────────────────────────────────────────────────────────────┘
   ▼ motion trigger
┌─────────────── Slow system (budget-controlled, novelty only) ──────┐
│ single execution core: claim CAS · whole-snapshot CAS · one backlog │
│ T2a V-JEPA embedding match → known pattern names itself (zero VLM)  │
│ T2b VLM naming → new-event archive                                  │
└────────────────────────────────────────────────────────────────────┘
   ▼
SQLite, fully auditable
```

## 📊 Measured performance

| Metric | Value | Basis and conditions |
|---|---|---|
| Tests | **1109 passed / 16 skipped** (1125 collected) | Full suite on this Windows machine (2026-09-23); CI additionally runs Linux 3.10 / 3.12 and Windows jobs |
| Alarm latency (structural trigger) | **≤ 1s** | End-to-end assertion in `tests/test_monitor.py`: an alarm must fire within one second of the target entering a managed cell (synthetic frames, detection verdict path) |
| T0 frame gating | **0.39ms per frame** (P95 0.43ms) | 1080p → 96×54 grayscale → gate decision, pure Python; re-measured locally over 199 frames |
| T1 detection | NanoDet-Plus ONNX, 416×416 input | Weights are not distributed; per-inference latency depends on the host CPU — an earlier local measurement gave 23–24ms, not re-measured this round |

## ✅ Quality gates

CI runs three jobs ([workflow](.github/workflows/ci.yml)):

- **test (Linux, Python 3.10 and 3.12)** — deploy script syntax (`bash -n`), single-source systemd unit rendering + `systemd-analyze verify`, full test suite (including Linux service-level smoke), Linux NVR edition contract, release packaging gate (sensitive-surface double gate + reproducible packaging self-check)
- **test-windows** — full test suite (service-level smoke skips automatically), release packaging dry-run, platform-layer smoke (UTF-8 output and data directory), Win11 entry smoke, deploy scripts parsed by both PowerShell 5.1 and 7

Most recent run (#61, 2026-09-23): all three jobs green.

## 📁 Repository layout

```
scam/                    domain core (pure Python)
  config.py              venue profile, fail-closed validation
  gate.py                T0 frame-difference gating
  detect.py              T1 NanoDet-Plus ONNX detection
  track.py               track confirmation
  zones.py               grid zone selection
  verdict.py             four-state verdict
  monitor.py             fast-system monitoring loop
  source.py              camera source (VUS first, cv2 fallback)
  slow_core.py           the single slow-system execution core (claim CAS / whole-snapshot CAS / one backlog truth)
  slow_worker.py         bounded background worker for the slow system
  linux_slow_path.py     thin compatibility adapter for the legacy Linux entry (no write state machine)
  segments.py            event segmentation and signatures
  patterns.py            habituation pattern library
  naming.py              dual-lane naming
  embed.py               V-JEPA segment embeddings
  evidence.py            evidence index and path fencing
  quality_gate.py        annotation-alignment quality gate
  db.py                  SQLite persistence (events / segments / patterns / zones)
  server.py              workbench HTTP (loopback only)
  sinks.py               alarm sinks
  notify.py              notification outlets (webhook / MQTT, optional)
  recording.py recorder.py   recording and clip export
  health.py              health water level
  nvr.py linux_nvr.py    always-on entry points
  win11*.py              Windows 11 entry, setup and on-device acceptance
  linux_*.py             operations line: host probe, backup, upgrade contract, replay, soak, unit rendering
  models.py              dual VLM channels (local / cloud, explicit opt-in)
deploy/                  NVR (install.sh + systemd unit) and Windows 11 (install-win11.ps1 / start-win11.bat)
scripts/                 acceptance, model fetch and verification, release packaging
tests/                   pytest (1125 test cases)
docs/                    roadmaps, benchmark analyses, operations runbook
```

## 📖 Documentation

| Document | Contents |
|---|---|
| [Operations runbook](docs/linux-operations-runbook.md) | Install / upgrade / rollback / backup and restore, with human confirmation points |

## ⚠️ Known limitations (honest list)

- All current evidence is **Windows-local synthetic automation**: real RTSP, real
  detection and embedding inference, the native Linux operations chain, a 24-hour
  soak, and real P95/P99 and privacy network audits are **not verified**;
- Detection and embedding weights are not distributed (`scripts/fetch_models.py`);
  automatic download is refused fail-closed until the hash is frozen;
- The slow-system VLM channel is not wired by default: new events are marked
  `pending_naming`, and repeated scenes fall back to pure structural matching plus
  profile reuse;
- The workbench is a single-admin loopback form: no authentication, no multi-user;
  remote access goes through an SSH tunnel;
- For the Windows 11 edition, Windows CI only proves automated compatibility;
  native on-device acceptance is tracked separately.

## 🙏 Acknowledgements

- [VUS](https://github.com/CommitStrip/video-understanding-skill) — the single upstream: perception, budget mechanism and stream service are all reused
- [NanoDet-Plus](https://github.com/RangiLyu/nanodet) — person detection model (Apache-2.0)
- [ollama](https://ollama.com) — local VLM inference
- [Meta AI](https://ai.meta.com) — V-JEPA 2 video representation model (CC-BY-NC 4.0)

## License

MIT, see [LICENSE](LICENSE).
