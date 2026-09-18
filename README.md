# Semantic Camera v2

> **Budget-aware edge vision event runtime**
> Turn surveillance cameras into a guard that understands what it sees — fast, accurate, and nearly free to run.

Surveillance cameras are just "eyes" — they see but don't understand. We give them a brain, but that brain must meet three harsh conditions simultaneously: **fast** (alarm ≤1s), **cheap** (nearly zero long-term cost), and **obedient** (all rules defined by the admin, the system never decides on its own).

## What it is

A semantic monitoring system on Linux NVR. Connect an RTSP camera, auto-discover it, understand the scene, alarm according to zones and rules you define — video and semantic data stay entirely on the NVR.

Core philosophy: **wrap uncertain models with deterministic engineering**. The fast system (frame gating + detection + rules) guards every frame with millisecond response; the slow system (VLM naming + JEPA embedding comparison) only engages for genuinely new events, and its call volume decays with habituation.

## Quick Start

```bash
# Discover cameras on your LAN
python -m scam.discover

# Edit cameras.json (fill in RTSP address and credentials)

# Start monitoring + workbench
python -m scam.nvr
# Open http://<NVR-IP>:8600 in your browser
```

## License

MIT
