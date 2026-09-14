#!/usr/bin/env bash
# family_stream_check.sh - 家庭网关（授权测试源）推流上线探测 + 真实流检测验证
# 用法: bash scripts/family_stream_check.sh
# 逻辑: 轮询 WHEP POST 直到推流方上线（非 404）→ 抓 HLS 段提帧 → NanoDet 检出验证
set -u
cd "$(dirname "$0")/.."

HOST="${HOST:?设置 HOST 环境变量（网关地址）}"
WHEP="http://$HOST:8889/cam/whep"
AUTH="user=${GATEWAY_USER:-cam}&pass=${GATEWAY_PASS:?设置 GATEWAY_PASS 环境变量（网关密码，禁止写回仓库）}"
OUT="scripts/out"
mkdir -p "$OUT"

probe_whep() {
  printf 'v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' > "$OUT/sdp_min.txt"
  code=$(curl -s --max-time 8 -X POST -H "Content-Type: application/sdp" \
    --data-binary @"$OUT/sdp_min.txt" -o "$OUT/whep_resp.txt" -w "%{http_code}" \
    "$WHEP?$AUTH")
  echo "$code"
}

echo "[probe] 轮询 WHEP（每 30s，Ctrl-C 退出）——推流方上线后自动进入检测验证"
while true; do
  code=$(probe_whep)
  ts=$(date +%H:%M:%S)
  if [ "$code" = "404" ]; then
    echo "[$ts] 无推流方（404）——等待（家人手机打开 http://$HOST:8080/u/cam 即可开始推流）"
  elif [ "$code" = "401" ]; then
    echo "[$ts] 鉴权失败（401）——检查 user/pass"
    exit 1
  else
    echo "[$ts] WHEP 返回 $code —— 推流方在线！"
    break
  fi
  sleep 30
done

echo "[validate] 抓取 HLS 段提帧做 NanoDet 检出验证..."
curl -sL --max-time 20 -o "$OUT/live.m3u8" "http://$HOST:8888/cam/index.m3u8?$AUTH"
ffmpeg -y -loglevel error -i "$OUT/live.m3u8" -frames:v 3 "$OUT/live_frame_%d.jpg" 2>/dev/null \
  || ffmpeg -y -loglevel error -i "$OUT/live.m3u8" -frames:v 3 "$OUT/live_frame_%d.jpg"
ls "$OUT"/live_frame_*.jpg 2>/dev/null || { echo "[validate] 提帧失败（HLS 未就绪？稍后重跑）"; exit 1; }

python - << 'EOF'
import glob, json
import cv2
import numpy as np
import onnxruntime as ort

ort.set_default_logger_severity(4)
sess = ort.InferenceSession("assets/models/person-detector.onnx",
                            providers=["CPUExecutionProvider"])
SIZE = 416
results = []
for path in sorted(glob.glob("scripts/out/live_frame_*.jpg")):
    img = cv2.imread(path)
    if img is None:
        print(f"  {path}: 读帧失败，跳过")
        continue
    h0, w0 = img.shape[:2]
    r = min(SIZE / w0, SIZE / h0)
    nw, nh = round(w0 * r), round(h0 * r)
    canvas = np.full((SIZE, SIZE, 3), 114, np.uint8)
    t, l = (SIZE - nh) // 2, (SIZE - nw) // 2
    rs = cv2.resize(img, (nw, nh))
    canvas[t:t + nh, l:l + nw] = rs
    x = cv2.cvtColor(canvas, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
    x = x.transpose(2, 0, 1)[np.newaxis]
    out = sess.run(None, {"data": x})[0][0]
    cls = out[:, :80]                       # 图内已 sigmoid
    reg = out[:, 80:].reshape(-1, 4, 8)
    reg = np.exp(reg - reg.max(-1, keepdims=True)); reg /= reg.sum(-1, keepdims=True)
    dis = (reg * np.arange(8.0)).sum(-1)
    lvl = [(52, 8), (26, 16), (13, 32), (7, 64)]
    pts, strd = [], []
    for hs, s in lvl:
        ys, xx = np.mgrid[0:hs, 0:hs]
        pts.append(np.stack([(xx.flatten() + 0.5) * s, (ys.flatten() + 0.5) * s], 1))
        strd.append(np.full(hs * hs, s))
    P = np.concatenate(pts); S = np.concatenate(strd)
    L, T, B, R = dis[:, 0] * S, dis[:, 1] * S, dis[:, 2] * S, dis[:, 3] * S
    bx = np.stack([P[:, 0] - L, P[:, 1] - T, P[:, 0] + R, P[:, 1] + B], 1)
    sc = cls[:, 0]
    n = int((sc > 0.4).sum())
    top = float(sc.max()) if n else 0.0
    results.append({"frame": path, "persons>0.4": n, "topConf": round(top, 3)})
    print(f"  {path}: person>{0.4} 命中 {n}，最高置信 {top:.3f}")
json.dump(results, open("scripts/out/family_validation.json", "w"), ensure_ascii=False, indent=2)
print("[validate] 完成 → scripts/out/family_validation.json（真实家庭监控流检出证据）")
EOF
