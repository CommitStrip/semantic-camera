#!/usr/bin/env bash
# sync-web.sh — sync shared web/ files into packaged copies for Android & HarmonyOS.
# Usage:
#   bash scripts/sync-web.sh           copy each listed file from web/ to both targets
#   bash scripts/sync-web.sh --check   verify packaged copies match web/ (no copying)
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="web"
TARGETS=(
  "android/app/src/main/assets/web"
  "harmony/entry/src/main/resources/rawfile"
)
FILES=(
  index.html
  core.js
  whep-client.js
  hls.min.js
  jepa_probe_init.json
  ort.wasm.js
  ort-wasm-simd-threaded.mjs
  ort-wasm-simd-threaded.wasm
  dinov2_vits14_feat.onnx
  yolov8s-drone.onnx
)

mode="${1:-}"
if [ "$mode" != "" ] && [ "$mode" != "--check" ]; then
  echo "usage: bash scripts/sync-web.sh [--check]" >&2
  exit 2
fi

if [ "$mode" = "--check" ]; then
  fail=0
  for f in "${FILES[@]}"; do
    if [ ! -f "$SRC/$f" ]; then
      echo "missing source: $SRC/$f"
      fail=1
      continue
    fi
    for t in "${TARGETS[@]}"; do
      if [ ! -f "$t/$f" ]; then
        echo "missing copy: $t/$f"
        fail=1
      elif ! cmp -s "$SRC/$f" "$t/$f"; then
        echo "differs from source: $t/$f"
        fail=1
      fi
    done
  done
  if [ "$fail" -ne 0 ]; then
    exit 1
  fi
  echo "all packaged copies in sync"
  exit 0
fi

count=0
for f in "${FILES[@]}"; do
  if [ ! -f "$SRC/$f" ]; then
    echo "missing source: $SRC/$f" >&2
    exit 1
  fi
  for t in "${TARGETS[@]}"; do
    mkdir -p "$t"
    cp "$SRC/$f" "$t/$f"
  done
  count=$((count + 1))
done
echo "synced $count files × 2 targets"
