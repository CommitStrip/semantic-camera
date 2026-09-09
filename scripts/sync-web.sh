#!/usr/bin/env bash
# sync-web.sh — 把共享源码与模型资产分发到三端副本（web / android / harmony）。
# 代码文件源在 web/；大文件（模型/运行时）单源在 assets/，此处做构建期 staging。
# 用法:
#   bash scripts/sync-web.sh           分发到 android/harmony + staging web/
#   bash scripts/sync-web.sh --check   只校验一致性（CI 同款）
set -euo pipefail
cd "$(dirname "$0")/.."

NATIVE_TARGETS=(
  "android/app/src/main/assets/web"
  "harmony/entry/src/main/resources/rawfile"
)
ALL_TARGETS=(
  "web"
  "${NATIVE_TARGETS[0]}"
  "${NATIVE_TARGETS[1]}"
)

# 代码文件（源: web/ → 两个原生副本）
CODE_FILES=(
  index.html
  core.js
  mode-packs.js
  whep-client.js
  hls.min.js
  jepa_probe_init.json
  ort.wasm.js
)

# 大文件（单源: assets/ → 三个副本，含 web/）
MODEL_SRC="assets/models"
RUNTIME_SRC="assets/runtime"
declare -A ASSET_SRC=(
  ["yolov8s-drone.onnx"]="$MODEL_SRC/yolov8s-drone.onnx"
  ["person-detector.onnx"]="$MODEL_SRC/person-detector.onnx"
  ["dinov2_vits14_feat.onnx"]="$MODEL_SRC/dinov2_vits14_feat.onnx"
  ["ort-wasm-simd-threaded.mjs"]="$RUNTIME_SRC/ort-wasm-simd-threaded.mjs"
  ["ort-wasm-simd-threaded.wasm"]="$RUNTIME_SRC/ort-wasm-simd-threaded.wasm"
)

mode="${1:-}"
if [ "$mode" != "" ] && [ "$mode" != "--check" ]; then
  echo "usage: bash scripts/sync-web.sh [--check]" >&2
  exit 2
fi

fail=0

# ---- 代码文件 ----
for f in "${CODE_FILES[@]}"; do
  if [ ! -f "web/$f" ]; then echo "missing source: web/$f"; fail=1; continue; fi
  for t in "${NATIVE_TARGETS[@]}"; do
    if [ "$mode" = "--check" ]; then
      if [ ! -f "$t/$f" ]; then echo "missing copy: $t/$f"; fail=1;
      elif ! cmp -s "web/$f" "$t/$f"; then echo "differs: $t/$f"; fail=1; fi
    else
      mkdir -p "$t"; cp "web/$f" "$t/$f"
    fi
  done
done

# ---- 资产文件（单源 staging） ----
for f in "${!ASSET_SRC[@]}"; do
  src="${ASSET_SRC[$f]}"
  if [ ! -f "$src" ]; then echo "missing asset source: $src"; fail=1; continue; fi
  for t in "${ALL_TARGETS[@]}"; do
    if [ "$mode" = "--check" ]; then
      if [ ! -f "$t/$f" ]; then echo "missing copy: $t/$f"; fail=1;
      elif ! cmp -s "$src" "$t/$f"; then echo "differs from asset source: $t/$f"; fail=1; fi
    else
      mkdir -p "$t"; cp "$src" "$t/$f"
    fi
  done
done

if [ "$fail" -ne 0 ]; then exit 1; fi
if [ "$mode" = "--check" ]; then echo "all copies in sync"; else echo "synced ${#CODE_FILES[@]} code files + ${#ASSET_SRC[@]} assets × 3 targets"; fi
