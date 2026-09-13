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

    def archive_named(self, kind, req, out):
        """段命名/行为判定案件归档（M2.7）——命名修订语料"""
        try:
            os.makedirs(self.archive_dir, exist_ok=True)
            path = os.path.join(self.archive_dir,
                                datetime.now().strftime('%Y%m%d') + '-' + kind + '.jsonl')
            rec = {
                'ts': datetime.now().isoformat(),
                'request': {k: req.get(k) for k in
                            ('requestId', 'segmentId', 'summary', 'behaviors', 'behavior')},
                'verdict': {k: out.get(k) for k in
                            ('name', 'matchedBehaviors', 'verdict', 'behaviorId',
                             'conf', 'rationale', 'arbiter', 'latencyMs')},
            }
            if self.archive_crops:
                rec['keyframes'] = req.get('keyframes')
                rec['frames'] = req.get('frames')
            with open(path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        except OSError:
            pass

    def archive_scene(self, req, out):
        """场所识别案件归档（§9）：目录/帧/裁决——模式包目录生长机制的语料"""
        try:
            os.makedirs(self.archive_dir, exist_ok=True)
            path = os.path.join(self.archive_dir,
                                datetime.now().strftime('%Y%m%d') + '-scene.jsonl')
            rec = {
                'ts': datetime.now().isoformat(),
                'request': {'requestId': req.get('requestId'),
                            'catalog': req.get('catalog')},
                'verdict': {k: out.get(k) for k in
                            ('packId', 'conf', 'rationale', 'arbiter', 'latencyMs')},
            }
            if self.archive_crops:
                rec['frames'] = req.get('frames')
            with open(path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        except OSError:
            pass

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
            if req.get('type') == 'scene-identify':
                t0 = time.time()
                try:
                    verdict = await self.arbiter.scene_identify(req)
                except Exception as e:
                    verdict = {'packId': None, 'conf': 0.0,
                               'rationale': str(e)[:120]}
                out = {'type': 'scene-verdict', 'requestId': req.get('requestId'),
                       'packId': verdict.get('packId'), 'conf': verdict.get('conf'),
                       'rationale': verdict.get('rationale', ''),
                       'arbiter': self.arbiter.name,
                       'latencyMs': round((time.time() - t0) * 1000)}
                try:
                    await ws.send(json.dumps(out))
                except Exception:
                    break
                self.archive_scene(req, out)
                print(f"[bridge] 场景识别 {req.get('requestId')} → {out.get('packId')} "
                      f"({out.get('conf')}) {out.get('latencyMs')}ms")
                continue
            if req.get('type') == 'segment-name':
                # M2.7 事件段命名：摘要+关键帧+行为定义表 → 语义名称
                t0 = time.time()
                try:
                    verdict = await self.arbiter.name_segment(req)
                except Exception as e:
                    verdict = {'name': None, 'conf': 0.0, 'matchedBehaviors': [],
                               'rationale': str(e)[:120]}
                out = {'type': 'segment-label', 'requestId': req.get('requestId'),
                       'segmentId': req.get('segmentId'),
                       'name': verdict.get('name'), 'conf': verdict.get('conf'),
                       'matchedBehaviors': verdict.get('matchedBehaviors') or [],
                       'rationale': verdict.get('rationale', ''),
                       'arbiter': self.arbiter.name,
                       'latencyMs': round((time.time() - t0) * 1000)}
                try:
                    await ws.send(json.dumps(out))
                except Exception:
                    break
                self.archive_named('segment', req, out)
                print(f"[bridge] 段命名 {req.get('segmentId')} → {out.get('name')} "
                      f"({out.get('conf')}) {out.get('latencyMs')}ms")
                continue
            if req.get('type') == 'behavior-check':
                # 行为判定（段中即时，独立预算在边缘侧）
                t0 = time.time()
                try:
                    verdict = await self.arbiter.behavior_check(req)
                except Exception as e:
                    verdict = {'verdict': 'undecidable', 'conf': 0.0,
                               'behaviorId': (req.get('behavior') or {}).get('id'),
                               'rationale': str(e)[:120]}
                out = {'type': 'behavior-verdict', 'requestId': req.get('requestId'),
                       'behaviorId': verdict.get('behaviorId'),
                       'verdict': verdict.get('verdict'), 'conf': verdict.get('conf'),
                       'arbiter': self.arbiter.name,
                       'latencyMs': round((time.time() - t0) * 1000)}
                try:
                    await ws.send(json.dumps(out))
                except Exception:
                    break
                self.archive_named('behavior', req, out)
                print(f"[bridge] 行为判定 {out.get('behaviorId')} → {out.get('verdict')} "
                      f"({out.get('conf')}) {out.get('latencyMs')}ms")
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
