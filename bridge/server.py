"""server.py - 语义摄像头慢脑仲裁桥（M2，设计文档 §8）

WS 服务：边缘灰区案件 → 慢脑仲裁 → 结论回灌边缘探针。

协议：
  连接后第一条消息 {type:'hello', token}，5s 内不匹配即断开（4401）；
  之后 {type:'arb-request', requestId, packId, task, trackId, classes, cropJpeg, scores, ts}
  →   {type:'arb-verdict', requestId, trackId, label, conf, arbiter, latencyMs}

归档：每案件输入+输出追加 bridge/archive/YYYYMMDD-arb.jsonl（M5 复训语料；
含灰区裁剪帧——该通道本就是设计允许的唯一上云内容，可经 archiveCrops 关闭）。

用法: python bridge/server.py --config bridge/config.json
"""
import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import websockets

from arbiters import build_arbiter


class Bridge:
    def __init__(self, cfg, arbiter):
        self.token = cfg.get('token', '')
        self.archive_dir = cfg.get('archiveDir', os.path.join('bridge', 'archive'))
        self.archive_crops = cfg.get('archiveCrops', True)
        self.arbiter = arbiter

    def archive(self, req, out):
        try:
            os.makedirs(self.archive_dir, exist_ok=True)
            path = os.path.join(self.archive_dir,
                                datetime.now().strftime('%Y%m%d') + '-arb.jsonl')
            rec = {
                'ts': datetime.now().isoformat(),
                'request': {k: req.get(k) for k in
                            ('requestId', 'packId', 'task', 'trackId', 'scores', 'ts')},
                'verdict': {k: out.get(k) for k in ('label', 'conf', 'arbiter', 'latencyMs')},
            }
            if self.archive_crops:
                rec['cropJpeg'] = req.get('cropJpeg')
            with open(path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        except OSError:
            pass  # 归档失败不阻断仲裁

    async def handle(self, ws):
        peer = getattr(ws, 'remote_address', ('?', 0))
        try:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        except Exception:
            return
        if msg.get('type') != 'hello' or msg.get('token') != self.token:
            await ws.close(code=4401, reason='auth failed')
            print(f'[bridge] 鉴权失败 {peer}')
            return
        await ws.send(json.dumps({'type': 'hello-ok', 'arbiter': self.arbiter.name}))
        print(f'[bridge] 边缘已连接 {peer} (arbiter={self.arbiter.name})')
        async for raw in ws:
            try:
                req = json.loads(raw)
            except Exception:
                continue
            if req.get('type') != 'arb-request':
                continue
            t0 = time.time()
            try:
                verdict = await self.arbiter.arbitrate(req)
            except Exception as e:  # 仲裁器异常不炸桥，按弃权返回
                verdict = {'label': None, 'conf': 0.0, 'abstain': True,
                           'error': str(e)[:120]}
            out = {'type': 'arb-verdict', 'requestId': req.get('requestId'),
                   'trackId': req.get('trackId'), 'label': verdict.get('label'),
                   'conf': verdict.get('conf'), 'arbiter': self.arbiter.name,
                   'latencyMs': round((time.time() - t0) * 1000)}
            try:
                await ws.send(json.dumps(out))
            except Exception:
                break
            self.archive(req, out)
            print(f"[bridge] 案件 {req.get('requestId')} → {out.get('label')} "
                  f"({out.get('conf')}) {out.get('latencyMs')}ms")


async def main(cfg):
    arbiter = build_arbiter(cfg.get('arbiter', {'type': 'abstain'}))
    bridge = Bridge(cfg, arbiter)
    host, port = cfg.get('host', '127.0.0.1'), cfg.get('port', 8390)
    print(f'[bridge] 语义摄像头仲裁桥启动 ws://{host}:{port} '
          f'(arbiter={arbiter.name}, 归档={bridge.archive_dir})')
    async with websockets.serve(bridge.handle, host, port):
        await asyncio.Future()


if __name__ == '__main__':
    ap = argparse.ArgumentParser('语义摄像头慢脑仲裁桥')
    ap.add_argument('--config', default='bridge/config.json')
    args = ap.parse_args()
    if not os.path.isfile(args.config):
        print(f'缺少配置 {args.config}——复制 bridge/config.example.json 为 bridge/config.json 后修改', file=sys.stderr)
        sys.exit(2)
    with open(args.config, encoding='utf-8') as f:
        cfg = json.load(f)
    try:
        asyncio.run(main(cfg))
    except KeyboardInterrupt:
        pass
