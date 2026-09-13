#!/usr/bin/env bash
# sync-web.sh — 把 assets/ 单源（模型/运行时）staging 到 web/ 本地开发目录。
# 用法:
#   bash scripts/sync-web.sh           staging（新机器 clone 后先跑一次）
#   bash scripts/sync-web.sh --check   只校验一致性（CI 同款）
# 说明: 仓库已收敛为纯 web 端侧（浏览器直接打开 web/index.html），
#       无双端原生壳；web/ 的大文件为 staging 产物不入库。
set -euo pipefail
cd "$(dirname "$0")/.."

# 大文件（单源: assets/ → web/ 本地 staging）
RUNTIME_SRC="assets/runtime"
MODEL_SRC="assets/models"
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
for f in "${!ASSET_SRC[@]}"; do
  src="${ASSET_SRC[$f]}"
  if [ ! -f "$src" ]; then echo "missing asset source: $src"; fail=1; continue; fi
  if [ "$mode" = "--check" ]; then
    if [ ! -f "web/$f" ]; then continue; fi   # web/ staging 缺失属预期（CI 无本地副本）
    if ! cmp -s "$src" "web/$f"; then echo "differs from asset source: web/$f"; fail=1; fi
  else
    cp "$src" "web/$f"
  fi
done

if [ "$fail" -ne 0 ]; then exit 1; fi
if [ "$mode" = "--check" ]; then echo "staging consistent"; else echo "staged ${#ASSET_SRC[@]} assets → web/"; fi
