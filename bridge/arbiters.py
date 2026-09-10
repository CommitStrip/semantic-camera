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
