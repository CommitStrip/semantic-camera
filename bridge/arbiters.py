"""arbiters.py - 慢脑仲裁器注册表（可插拔，设计文档 §8）

abstain  永久弃权（默认；桥通但无慢脑时诚实不产出伪标签）
clip     本地 CLIP 零样本（完整 CLIPModel ONNX——vus models 目录即有；prompt 可配。
         与边缘 DINOv2 探针不同模型族 = 独立证据，正是仲裁的价值所在）
ollama   本地 ollama 视觉模型（vus 慢脑同款路线；需本机 ollama + 视觉模型）

约定：arbitrate(req) 为协程，req 含 cropJpeg(base64) / classes / packId；
返回 {label: 类名或 None, conf: float, model: str}，弃权时 label=None。

安全（SSRF 防线）：ollama 主机走 validate_http_base——仅 http(s)、主机必须在
显式允许表（默认仅环回 127.0.0.1/localhost/::1），解析后的 IP 落在私网/保留段且
未列入允许表即拒绝；http.client 直连不跟随重定向。
"""
import asyncio
import base64
import http.client
import ipaddress
import json
import socket
from urllib.parse import urlsplit

import numpy as np

try:
    from tokenizer_clip import clip_tokenize          # 脚本直跑（server.py 注入 path）
except ImportError:
    from bridge.tokenizer_clip import clip_tokenize   # 包导入（测试/外部加载）


def validate_http_base(url, allowed_hosts):
    """校验服务端出网目标：协议白名单 + 主机允许表 + 解析 IP 边界。
    返回 (host, port, path)；非法抛 ValueError。"""
    u = urlsplit(url)
    if u.scheme not in ('http', 'https'):
        raise ValueError('仅允许 http/https 协议')
    host = u.hostname
    if not host:
        raise ValueError('缺少主机名')
    allowed = {h.lower() for h in allowed_hosts} | {'127.0.0.1', 'localhost', '::1'}
    if host.lower() not in allowed:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_loopback or ip.is_private or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast):
                raise ValueError(f'目标地址 {ip} 处于受限网段且未列入允许表')
    port = u.port or (443 if u.scheme == 'https' else 80)
    return host, port, u.path or ''


def post_json_http(url, body, timeout=60, allowed_hosts=()):
    """http.client 直连 POST JSON（不跟随重定向），带 SSRF 主机校验"""
    host, port, path = validate_http_base(url, allowed_hosts)
    conn = (http.client.HTTPSConnection(host, port, timeout=timeout)
            if url.startswith('https')
            else http.client.HTTPConnection(host, port, timeout=timeout))
    try:
        conn.request('POST', path, body=body, headers={'Content-Type': 'application/json'})
        resp = conn.getresponse()
        if resp.status != 200:
            raise ValueError(f'上游返回 {resp.status}')
        return json.loads(resp.read().decode('utf-8'))
    finally:
        conn.close()


class BaseArbiter:
    name = 'base'

    async def arbitrate(self, req):
        raise NotImplementedError

    async def scene_identify(self, req):
        """场所识别（§9）：req 含 catalog[{id,description}] 与 frames[{wide,crops[]}]。
        默认弃权；返回 {packId: str|None, conf: float, rationale: str}"""
        return {'packId': None, 'conf': 0.0, 'rationale': 'arbiter 无场所识别能力'}

    async def name_segment(self, req):
        """事件段命名（M2.7）：req 含 segmentId/summary/signature/keyframes/behaviors。
        返回 {name: str|None(=弃权/不可判定), conf, matchedBehaviors, rationale}"""
        return {'name': None, 'conf': 0.0, 'matchedBehaviors': [],
                'rationale': 'arbiter 无命名能力'}

    async def behavior_check(self, req):
        """行为判定：req 含 behavior{id,description,observable} 与 frames。
        返回 {verdict: 'match'|'no'|'undecidable', conf, behaviorId}"""
        return {'verdict': 'undecidable', 'conf': 0.0,
                'behaviorId': (req.get('behavior') or {}).get('id')}


class AbstainArbiter(BaseArbiter):
    name = 'abstain'

    async def arbitrate(self, req):
        return {'label': None, 'conf': 0.0, 'abstain': True}


class ClipZeroShotArbiter(BaseArbiter):
    """CLIP 零样本仲裁：prompts = {类名: 文本}；logits_per_image softmax 即分数。
    CLIP 预处理与 openai/CLIP 官方对齐（短边 224 中心裁剪 + RGB/255 + mean/std）。"""
    name = 'clip'

    def __init__(self, model_path, prompts):
        import cv2
        import onnxruntime as ort
        self._cv2 = cv2
        self.labels = list(prompts.keys())
        self.mean = np.array([0.481, 0.457, 0.408], dtype=np.float32)
        self.std = np.array([0.269, 0.261, 0.275], dtype=np.float32)
        self.sess = ort.InferenceSession(model_path, providers=['CPUExecutionProvider'])
        self.out_names = [o.name for o in self.sess.get_outputs()]
        self._ids, self._mask = clip_tokenize([prompts[l] for l in self.labels])
        self._logits_idx = self.out_names.index('logits_per_image')
        # 文本塔预热（缓存 ids；图像侧每次按请求前向）
        self.sess.run(None, {'input_ids': self._ids, 'attention_mask': self._mask,
                             'pixel_values': np.zeros((1, 3, 224, 224), dtype=np.float32)})

    def _prep(self, jpeg_bytes):
        cv2 = self._cv2
        img = cv2.imdecode(np.frombuffer(jpeg_bytes, np.uint8), cv2.IMREAD_COLOR)
        h, w = img.shape[:2]
        s = min(h, w)
        top, left = (h - s) // 2, (w - s) // 2
        img = cv2.resize(img[top:top + s, left:left + s], (224, 224))
        rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
        return ((rgb - self.mean) / self.std).transpose(2, 0, 1)[np.newaxis]

    async def arbitrate(self, req):
        jpeg = base64.b64decode(req['cropJpeg'])
        px = self._prep(jpeg)
        out = self.sess.run(None, {'pixel_values': px,
                                   'input_ids': self._ids,
                                   'attention_mask': self._mask})
        logits = out[self._logits_idx][0]
        p = np.exp(logits - logits.max())
        p /= p.sum()
        bi = int(np.argmax(p))
        return {'label': self.labels[bi], 'conf': round(float(p[bi]), 4),
                'model': 'clip-vitb32-zeroshot'}

    async def scene_identify(self, req):
        """CLIP 零样本场所分类：以各模式包的场所描述文本为 prompt，宽帧为图像。
        离线可跑的兜底通道（细粒度场景弱，VLM 通道可用时优先）。"""
        catalog = req.get('catalog') or []
        if not catalog:
            return {'packId': None, 'conf': 0.0, 'rationale': 'catalog 为空'}
        descriptions = [c.get('description') or c['id'] for c in catalog]
        ids, mask = self._tokenize(descriptions)
        frames = req.get('frames') or []
        if not frames or not frames[0].get('wide'):
            return {'packId': None, 'conf': 0.0, 'rationale': '缺宽帧'}
        jpeg = base64.b64decode(frames[0]['wide'])
        px = self._prep(jpeg)
        out = self.sess.run(None, {'pixel_values': px,
                                   'input_ids': ids,
                                   'attention_mask': mask})
        logits = out[self._logits_idx][0]
        p = np.exp(logits - logits.max())
        p /= p.sum()
        bi = int(np.argmax(p))
        return {'packId': catalog[bi]['id'], 'conf': round(float(p[bi]), 4),
                'rationale': 'clip 零样本场所分类'}


class OllamaArbiter(BaseArbiter):
    """ollama 视觉模型仲裁（vus 慢脑同款路线；主机经 validate_http_base 校验）"""
    name = 'ollama'

    def __init__(self, model, prompts, host='http://127.0.0.1:11434',
                 allowed_hosts=()):
        self.model = model
        self.host = host.rstrip('/')
        self.allowed_hosts = list(allowed_hosts)
        self.labels = list(prompts.keys())

    async def arbitrate(self, req):
        labels = ' / '.join(self.labels)
        prompt = (f'This is a surveillance camera crop. Which of the following is shown: '
                  f'{labels}? Reply with exactly one word.')
        body = json.dumps({'model': self.model, 'prompt': prompt,
                           'images': [req['cropJpeg']], 'stream': False,
                           'options': {'temperature': 0}})
        resp = await asyncio.to_thread(
            post_json_http, self.host + '/api/generate', body, 60, self.allowed_hosts)
        text = (resp.get('response') or '').strip().lower()
        for l in self.labels:
            if l in text:
                return {'label': l, 'conf': 1.0, 'model': 'ollama:' + self.model}
        return {'label': None, 'conf': 0.0, 'abstain': True}

    async def scene_identify(self, req):
        """VLM 场所识别：宽帧+裁剪帧 + 模式包目录文本 → 选择最匹配的 packId"""
        catalog = req.get('catalog') or []
        if not catalog:
            return {'packId': None, 'conf': 0.0, 'rationale': 'catalog 为空'}
        frames = req.get('frames') or []
        images = []
        for fr in frames[:2]:
            if fr.get('wide'):
                images.append(fr['wide'])
            images.extend(fr.get('crops') or [])
        if not images:
            return {'packId': None, 'conf': 0.0, 'rationale': '无帧'}
        listing = '\n'.join(f"- {c['id']}: {c.get('description') or c['id']}"
                            for c in catalog)
        prompt = (f'You are configuring a surveillance camera. These frames come from '
                  f'ONE camera. Which venue type does this camera most likely watch?\n'
                  f'{listing}\n'
                  f'Reply with exactly one venue id from the list.')
        body = json.dumps({'model': self.model, 'prompt': prompt,
                           'images': images, 'stream': False,
                           'options': {'temperature': 0}})
        resp = await asyncio.to_thread(
            post_json_http, self.host + '/api/generate', body, 90, self.allowed_hosts)
        text = (resp.get('response') or '').strip().lower()
        for c in catalog:
            if c['id'].lower() in text:
                return {'packId': c['id'], 'conf': 0.9,
                        'rationale': 'ollama vlm 场所识别'}
        return {'packId': None, 'conf': 0.0, 'rationale': '回复未含目录 id: ' + text[:80]}

    def _extract_json(self, text):
        """宽松提取首个 JSON 对象（VLM 输出常带前后缀）"""
        start = text.find('{')
        end = text.rfind('}')
        if start < 0 or end <= start:
            return None
        try:
            return json.loads(text[start:end + 1])
        except Exception:
            return None

    async def name_segment(self, req):
        """ollama VLM 段命名：摘要+关键帧+行为定义表 → 输出规范 JSON。
        undecidable=画面证据不足（诚实选项，不硬猜）；无 ollama 视觉模型时走弃权。"""
        images = [f for f in (req.get('keyframes') or []) if f][:3]
        if not images:
            return {'name': None, 'conf': 0.0, 'matchedBehaviors': [],
                    'rationale': '无关键帧'}
        behaviors = req.get('behaviors') or []
        btable = '\n'.join(
            f"- {b.get('id')}: {b.get('description') or ''}（观测特征: {b.get('observable') or '未填'}）"
            for b in behaviors) or '-（无）'
        prompt = (
            '你是监控事件分析器。以下是一个事件时间段的结构化摘要与最多 3 张关键帧。\n'
            f"摘要: {json.dumps(req.get('summary') or {}, ensure_ascii=False)}\n"
            f'危险行为定义表（如命中返回其 id）:\n{btable}\n'
            '请严格只输出一个 JSON 对象: '
            '{"name": "不超过16个汉字的事件名", "conf": 0.0到1.0, '
            '"matchedBehaviors": ["行为id"], "undecidable": false, '
            '"rationale": "不超过30字的理由"}。'
            '画面证据不足判断行为时 undecidable 置 true 且 matchedBehaviors 为空。')
        body = json.dumps({'model': self.model, 'prompt': prompt,
                           'images': images, 'stream': False,
                           'options': {'temperature': 0}})
        resp = await asyncio.to_thread(
            post_json_http, self.host + '/api/generate', body, 90, self.allowed_hosts)
        text = (resp.get('response') or '').strip()
        obj = self._extract_json(text)
        if not obj or not obj.get('name'):
            return {'name': None, 'conf': 0.0, 'matchedBehaviors': [],
                    'rationale': '输出无法解析: ' + text[:80]}
        if obj.get('undecidable'):
            return {'name': None, 'conf': 0.0, 'matchedBehaviors': [],
                    'rationale': (obj.get('rationale') or 'undecidable')[:80]}
        name = str(obj.get('name'))[:24]
        mb = [b for b in (obj.get('matchedBehaviors') or [])
              if isinstance(b, str)] if isinstance(obj.get('matchedBehaviors'), list) else []
        conf = obj.get('conf')
        return {'name': name,
                'conf': round(float(conf), 3) if isinstance(conf, (int, float)) else 0.7,
                'matchedBehaviors': mb,
                'rationale': str(obj.get('rationale') or '')[:60]}

    async def behavior_check(self, req):
        """ollama VLM 行为判定：当前帧+单条行为定义 → match/no/undecidable"""
        behavior = req.get('behavior') or {}
        frames = req.get('frames') or []
        if not frames:
            return {'verdict': 'undecidable', 'conf': 0.0,
                    'behaviorId': behavior.get('id')}
        prompt = (
            f"监控画面行为判定。行为定义: {behavior.get('name')} — "
            f"{behavior.get('description') or ''}（观测特征: {behavior.get('observable') or '未填'}）。\n"
            '该帧是否呈现此行为？严格只输出 JSON: '
            '{"verdict": "match"|"no"|"undecidable", "conf": 0.0到1.0}。证据不足用 undecidable。')
        body = json.dumps({'model': self.model, 'prompt': prompt,
                           'images': frames[:1], 'stream': False,
                           'options': {'temperature': 0}})
        resp = await asyncio.to_thread(
            post_json_http, self.host + '/api/generate', body, 60, self.allowed_hosts)
        obj = self._extract_json((resp.get('response') or '').strip())
        verdict = obj.get('verdict') if obj else None
        if verdict not in ('match', 'no', 'undecidable'):
            return {'verdict': 'undecidable', 'conf': 0.0,
                    'behaviorId': behavior.get('id'), 'rationale': '输出无法解析'}
        conf = obj.get('conf')
        return {'verdict': verdict,
                'conf': round(float(conf), 3) if isinstance(conf, (int, float)) else 0.5,
                'behaviorId': behavior.get('id')}


def build_arbiter(cfg):
    """cfg: {type: abstain|clip|ollama, ...} 按类型构造仲裁器"""
    t = cfg.get('type', 'abstain')
    if t == 'abstain':
        return AbstainArbiter()
    if t == 'clip':
        return ClipZeroShotArbiter(cfg['clipModel'], cfg['prompts'])
    if t == 'ollama':
        return OllamaArbiter(cfg['model'], cfg['prompts'], cfg.get('host'),
                             cfg.get('allowedHosts', ()))
    raise ValueError('未知仲裁器类型: ' + t)
