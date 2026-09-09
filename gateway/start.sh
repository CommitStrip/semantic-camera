# 反无人机监控 · 海康接入网关 —— 一键启动 (MediaMTX)
# 用法：
#   ./start.sh           启动（默认读取 ./mediamtx.yml）
# 依赖：
#   - Docker（推荐）或本机已装 mediamtx 二进制
# 说明：先编辑 mediamtx.yml 里的海康相机 IP/账号/密码，再启动。
set -e
cd "$(dirname "$0")"

# 优先用 Docker 运行（最省事，无需安装二进制）
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "[gateway] 使用 Docker 启动 MediaMTX ..."
  docker run --rm -it \
    --name drone-gateway \
    -p 8554:8554 -p 1935:1935 -p 8888:8888 -p 8889:8889 \
    -v "$(pwd)/mediamtx.yml:/mediamtx.yml" \
    bluenviron/mediamtx:latest
  exit 0
fi

# 否则用本机 mediamtx 二进制
if command -v mediamtx >/dev/null 2>&1; then
  echo "[gateway] 使用本机 mediamtx ..."
  exec mediamtx ./mediamtx.yml
fi

echo "[gateway] 未找到 Docker 或 mediamtx，请先安装其一："
echo "  Docker:  https://docs.docker.com/engine/install/"
echo "  MediaMTX: https://github.com/bluenviron/mediamtx/releases"
exit 1