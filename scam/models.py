"""models.py —— 模型双通道 Provider（本地 ollama / 云端 OpenAI 兼容）。

纪律：
- 密钥只从环境变量读取（cloud.key_ref 指向环境变量名），源码/配置零凭据字面量；
- URL 三层校验：协议白名单 + 主机边界 + 解析后 IP 阻断私网/环回/链路本地/保留段；
- 本地通道（数据不出 NVR）允许环回与私网；云端通道强制 https+公网（SSRF 防线）；
- urllib 默认跟随重定向——用不跟随重定向的 opener 防重定向绕过 SSRF；
- 所有调用带超时；本地通道故障可返回 None，云端故障显式给出脱敏错误。
"""

import json
import os
import re
import socket
import threading
import time
import urllib.request
from urllib.parse import urlsplit

import numpy as np


def _post_json(url, body, timeout, headers=None):
    """POST JSON，不跟随重定向（防重定向绕过 SSRF 校验）。"""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          **(headers or {})})
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _resolve_ips(host):
    try:
        return {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return set()


def _ip_is_local(ip):
    o = ip.split(".")
    if len(o) == 4 and all(x.isdigit() for x in o):
        n = [int(x) for x in o]
        if n[0] == 10 or n[0] == 127 or (n[0] == 192 and n[1] == 168) or \
                (n[0] == 172 and 16 <= n[1] <= 31) or (n[0] == 169 and n[1] == 254):
            return True
        if n[0] == 0 or n[0] >= 224:
            return True
    if ":" in ip:
        return True   # IPv6 内网/链路本地前缀一律按本地处理
    return False


def validate_base(url, *, allow_local, allow_public):
    """校验 base URL：协议 + 主机 + 解析 IP 边界。返回 (scheme, host)。"""
    u = urlsplit(url)
    if u.scheme not in ("http", "https"):
        raise ValueError("仅允许 http/https")
    host = u.hostname or ""
    if not host:
        raise ValueError("缺少主机名")
    ips = _resolve_ips(host)
    if not ips:
        raise ValueError(f"无法解析主机: {host}")
    local = {ip for ip in ips if _ip_is_local(ip)}
    public = ips - local
    if public and not allow_public:
        raise ValueError(f"公网地址未授权: {host}")
    if local and not allow_local:
        raise ValueError(f"本地/私网地址未授权: {host}")
    return host, ips


def _extract_json(text):
    s = text.find("{")
    e = text.rfind("}")
    if s < 0 or e <= s:
        return None
    try:
        return json.loads(text[s:e + 1])
    except json.JSONDecodeError:
        return None


class CloudProviderError(RuntimeError):
    """Structured cloud error without original transport details."""

    def __init__(self, code, *, status=None, detail=None):
        self.code = str(code)
        self.status = status
        self.detail = detail
        message = self.code
        if status is not None:
            message += f":{status}"
        if detail is not None:
            message += f":{detail}"
        super().__init__(message)


class LocalOllama:
    """本地 ollama（OpenAI 兼容端点）。数据不出 NVR——仅允许环回/私网。"""

    name = "local"

    def __init__(self, base="http://127.0.0.1:11434", model="qwen3-vl:2b",
                 num_ctx=16384, num_predict=2048, timeout=90):
        validate_base(base, allow_local=True, allow_public=False)
        self.base = base.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.num_predict = num_predict

    @staticmethod
    def _context_text(context):
        """把上下文渲染成纯文本。

        聊天接口的 system 消息 content 必须是字符串：直接塞 dict 会被接口拒绝，
        整次调用静默失败（实测表现为"环境识别永远 unavailable"）。这里统一
        序列化，保证任何调用方传 dict/None/字符串都能发出去。
        """
        if context is None:
            return ""
        if isinstance(context, str):
            return context
        try:
            return json.dumps(context, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            return str(context)

    def understand(self, prompt, frames_b64, context=None):
        """frames_b64: 纯 base64 JPEG 列表（无 data: 前缀）。返回 JSON 或 None。"""
        body = {"model": self.model, "stream": False, "keep_alive": "30m",
                "messages": [{"role": "system", "content": self._context_text(context)},
                             {"role": "user", "content": prompt,
                              "images": frames_b64}],
                # 结构化输出是本通道的唯一契约（环境档案/命名都要求 JSON）。
                # 显式约束同时抑制小模型的重复退化：实测不加约束时非思考模型
                # 会退化成复读（"…有一个黑色的桌子"刷屏），加了才稳定出 JSON。
                "response_format": {"type": "json_object"},
                "options": {"temperature": 0,
                            "num_predict": self.num_predict,
                            "num_ctx": self.num_ctx,
                            "repeat_penalty": 1.15,
                            "repeat_last_n": 128}}
        try:
            resp = _post_json(self.base + "/v1/chat/completions", body, self.timeout)
            content = resp["choices"][0]["message"]["content"]
        except Exception:
            return None
        return _extract_json(content)


class CloudOpenAICompat:
    """云端 OpenAI 兼容 VLM（帧/内容会出 NVR——启用需管理员显式确认）。

    强制 https + 解析后 IP 全公网（DNS 也解析校验，防 DNS 重绑定绕过）；
    请求带 Authorization 头；图片走 OpenAI 标准 content parts（data URL）。
    """

    name = "cloud"

    def __init__(self, base, model, key_env="SCAM_CLOUD_KEY", timeout=60):
        u = urlsplit(base)
        if u.scheme != "https":
            raise ValueError("云端通道必须 https")
        if u.username is not None or u.password is not None:
            raise ValueError("云端通道禁止 URL 凭据")
        if u.query or u.fragment:
            raise ValueError("云端通道禁止 URL 查询参数或片段")
        # 解析 DNS 后逐 IP 阻断私网/环回/链路本地（不只查字面 IP）
        self.host, _ = validate_base(base, allow_local=False, allow_public=True)
        self.base = base.rstrip("/")
        self.model = model
        key = os.environ.get(key_env, "")
        if not isinstance(key, str) or not key.strip():
            raise ValueError("云端通道缺少密钥")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in key):
            raise ValueError("云端通道密钥包含控制字符")
        self.key = key
        self.timeout = timeout

    @staticmethod
    def _context_text(context):
        """Serialize context to deterministic chat text."""
        if context is None:
            return ""
        if isinstance(context, str):
            return context
        try:
            return json.dumps(context, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            return str(context)

    @staticmethod
    def _safe_status(exc):
        status = getattr(exc, "code", None)
        if type(status) is int and 100 <= status <= 599:
            return status
        try:
            text = str(exc)
        except Exception:
            return None
        match = re.search(r"\bHTTP\s+([1-5]\d\d)\b", text, re.IGNORECASE)
        return int(match.group(1)) if match else None

    def understand(self, prompt, frames_b64, context=None):
        content = [{"type": "text", "text": prompt}]
        for b64 in frames_b64:
            content.append({"type": "image_url",
                            "image_url": {"url": "data:image/jpeg;base64,"
                                                + b64}})
        body = {"model": self.model, "stream": False, "temperature": 0,
                "messages": [{"role": "system", "content": self._context_text(context)},
                             {"role": "user", "content": content}]}
        headers = {"Authorization": f"Bearer {self.key}"}
        try:
            resp = _post_json(self.base + "/v1/chat/completions", body,
                              self.timeout, headers)
        except Exception as exc:
            status = self._safe_status(exc)
            if status is not None:
                raise CloudProviderError("cloud_http_error", status=status) from None
            raise CloudProviderError(
                "cloud_transport_failed", detail=type(exc).__name__) from None
        try:
            content = resp["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise CloudProviderError(
                "cloud_bad_response", detail=type(exc).__name__) from None
        return _extract_json(content)


# C173-A3 dtype 方案 B：唯一合法 dtype 名单。只接受规范名（不猜别名、
# 不做大小写归一）；其他值在构造时明确拒绝（ValueError），绝不静默降级。
_L3_DTYPE_CHOICES = ("float32", "bfloat16")


class LocalTransformers:
    """本地 transformers VLM（如 InternVL3.5-1B）——数据不出 NVR。

    延迟加载（首次 understand 才加载模型），接口与 LocalOllama 对齐：
    understand(prompt, frames_b64, context) → dict 或 None。
    C-136 B2：加载阶段可被调用方预算约束——load(timeout_s) 显式有界预加载
    （超时返回 False、加载线程残留如实），缺省路径零变化。
    C-135 §8：有序多帧真实输入——全部帧按序进模型（多图占位符 + pixel_values
    按 patch 拼接，协议见 _understand_ordered）；None 项=显式缺帧（prompt
    标注，不伪造）；frames_meta 携带逐帧身份/时间/分支标签进 prompt。
    C173-A3 dtype 方案 B：``dtype`` 显式选择模型精度。缺省 None=FP32（与
    既有调用逐字节一致；显式 torch_dtype 参数保留——HF 快照 config 自带
    torch_dtype: bfloat16，省略参数会静默变 BF16，绝不那样做）。``float32``
    与缺省等价；``bfloat16`` 才改变加载与 pixel_values 精度（两处由同一
    self.dtype 经 _torch_dtype() 派生，同源防漂移）。加载失败如实上抛，
    **绝不自动回退 FP32**（回退会让 BF16 实验前提失真）。约束记忆：
    CPU BF16 加载可行但生成慢（C169/C171 实测）；量化/模型版本/生成预算/
    设备选择不在本参数职责内。最近一次调用的 请求精度(dtype_requested)
    与实际精度(model_dtype/pixel_values_dtype) 由 ``_last_call_info`` 如实
    记录（实际取不到时如实 None，绝不编造）。

    ``precision_mode="mixed_vision_fp32"`` 需显式 ``dtype="bfloat16"``：
    视觉塔与投影为FP32，语言权重/跨模态特征为BF16；默认uniform不转换。
    该模式不量化、不减少帧或输出预算、不自动回退；实际分组件精度进入调用快照。
    """

    name = "transformers"

    def __init__(self, model_path="OpenGVLab/InternVL3_5-1B-Instruct",
                 timeout=120, dtype=None, precision_mode=None,
                 attention_implementation=None, vision_chunk_size=None):
        self.model_path = model_path
        self.model_id = model_path.split("/")[-1]
        self._model = None
        self._tokenizer = None
        self._transform = None
        self.timeout = timeout
        # C173-A3：构造只做字符串校验（不 import torch，延迟加载语义不变）
        if dtype is None:
            dtype = "float32"
        dtype = str(dtype)
        if dtype not in _L3_DTYPE_CHOICES:
            raise ValueError(
                "不支持的 dtype {!r}（仅允许 {}；显式拒绝，绝不静默降级）"
                .format(dtype, "/".join(repr(c) for c in _L3_DTYPE_CHOICES)))
        self.dtype = dtype
        self.precision_mode = "uniform" if precision_mode is None else precision_mode
        if self.precision_mode not in ("uniform", "mixed_vision_fp32"):
            raise ValueError("unsupported precision_mode")
        if self.precision_mode == "mixed_vision_fp32" and self.dtype != "bfloat16":
            raise ValueError("mixed_vision_fp32 requires explicit bfloat16 language dtype")
        if attention_implementation is not None and attention_implementation not in ("eager", "sdpa"):
            raise ValueError("unsupported attention_implementation")
        if vision_chunk_size is not None and (type(vision_chunk_size) is not int or vision_chunk_size != 1):
            raise ValueError("vision_chunk_size supports only explicit integer 1")
        self.attention_implementation = attention_implementation
        self.vision_chunk_size = vision_chunk_size
        # 最近一次真实调用的事实记录（捕获测试/证据用；只读，不影响行为）
        self._last_call_info = None
        # 有界加载状态（C-136 load(timeout_s) 预算入口；单飞，残留如实）
        self._load_lock = threading.Lock()
        self._load_thread = None
        self._load_error = None

    def _torch_dtype(self):
        """C173-A3：加载 dtype 与 pixel_values dtype 的**唯一派生源**。

        两处必须同源（同一 self.dtype 派生），杜绝"改了加载忘了输入"的
        混合精度漂移；torch 延迟导入——构造仍零 import。
        """
        import torch
        return torch.bfloat16 if self.dtype == "bfloat16" else torch.float32

    def _configure_precision(self, model):
        """Opt-in FP32 vision/projector with BF16 language; no fallback or cache writes.

        InternVL's extract_feature owns vision+projector. Cast at that boundary,
        preserving every image and its order; ordinary FP32/BF16 paths are untouched.
        """
        if self.precision_mode == "uniform":
            return
        import torch
        import types
        if getattr(model, "_scam_mixed_vision_configured", False):
            raise ValueError("mixed precision already configured")
        components = [getattr(model, name, None)
                      for name in ("vision_model", "mlp1", "language_model")]
        if (not all(isinstance(item, torch.nn.Module) for item in components)
                or not callable(getattr(model, "extract_feature", None))):
            raise ValueError("mixed_vision_fp32 requires vision_model, mlp1, language_model and extract_feature")
        if any(p.dtype != torch.bfloat16 for p in model.language_model.parameters()
               if p.is_floating_point()):
            raise ValueError("mixed precision requires BF16 language weights")
        original = model.extract_feature
        model.vision_model.float()
        model.mlp1.float()

        def extract_feature(this, pixel_values):
            return original(pixel_values.to(torch.float32)).to(torch.bfloat16)

        model.extract_feature = types.MethodType(extract_feature, model)
        model._scam_mixed_vision_configured = True

    def _configure_attention(self, model):
        """Select the installed language-model implementation; never change vision.

        Default None preserves upstream behavior. No fallback if explicit selection
        fails; SDPA has floating-point rounding differences, not a quality guarantee.
        """
        if self.attention_implementation is None:
            return
        language = getattr(model, "language_model", None)
        setter = getattr(language, "set_attn_implementation", None)
        if not callable(setter):
            raise ValueError("attention selection requires language-model setter")
        setter(self.attention_implementation)
        actual = getattr(getattr(language, "config", None), "_attn_implementation", None)
        if actual != self.attention_implementation:
            raise RuntimeError("attention selection not effective")

    def _configure_vision_execution(self, model):
        """Bound visual intermediates, not evidence: every image remains in order.

        Only the visual feature extraction is sequential; language receives the
        concatenated full sequence. This is not model batching or parallel inference.
        """
        if self.vision_chunk_size is None:
            return
        import torch
        import types
        if getattr(model, "_scam_vision_execution_configured", False):
            raise ValueError("vision execution already configured")
        original = getattr(model, "extract_feature", None)
        if not callable(original):
            raise ValueError("vision execution requires extract_feature")
        chunk_size = self.vision_chunk_size

        def extract_feature(this, pixel_values):
            return torch.cat([original(part) for part in pixel_values.split(chunk_size, dim=0)], dim=0)

        model.extract_feature = types.MethodType(extract_feature, model)
        model._scam_vision_execution_configured = True

    def _ensure_loaded(self):
        if self._model is not None:
            return
        from transformers import AutoTokenizer, AutoModel
        from transformers.modeling_utils import PreTrainedModel
        # transformers 5.x 兼容：InternVL 自定义代码缺少 all_tied_weights_keys
        if not hasattr(PreTrainedModel, "all_tied_weights_keys"):
            PreTrainedModel.all_tied_weights_keys = {}
        # InternVL 自定义 __init__ 不接受 dtype 参数（用 torch_dtype）；
        # C173-A3：显式传参（缺省 FP32 与既有合同一致），失败如实上抛，
        # 绝不自动回退 FP32。
        model = AutoModel.from_pretrained(
            self.model_path, torch_dtype=self._torch_dtype(),
            low_cpu_mem_usage=True, trust_remote_code=True).eval()
        self._configure_precision(model)
        self._configure_attention(model)
        self._configure_vision_execution(model)
        self._model = model
        self._tokenizer = AutoTokenizer.from_pretrained(
            self.model_path, trust_remote_code=True)
        import torchvision.transforms as T
        self._transform = T.Compose([
            T.Lambda(lambda img: img.convert("RGB")
                     if img.mode != "RGB" else img),
            T.Resize((448, 448), interpolation=T.InterpolationMode.BICUBIC),
            T.ToTensor(),
            T.Normalize(mean=[0.485, 0.456, 0.406],
                        std=[0.229, 0.224, 0.225]),
        ])

    def load(self, timeout_s=None):
        """显式预加载模型（延迟加载的预算化入口；C-136 B2 参数化）。

        - ``timeout_s`` 为 None 或 <=0：在调用线程内同步加载（与既有
          _ensure_loaded 延迟加载语义一致，无额外上限）；
        - ``timeout_s > 0``：加载在辅助线程内执行并限时等待。就绪返回
          True；预算内未完成返回 False——加载线程不可中止，仍存活的
          残留由 :meth:`load_thread_alive` 如实呈现，绝不假装已停止；
          加载失败上抛原异常（失败非终态，可再次调用）。

        并发调用单飞合并：同一时刻至多一个加载线程（其余调用汇入同一
        次加载等待）。默认参数零变化——既有调用方（environment/
        semantic_updater/slow_core 的延迟加载路径）行为不受影响。
        """
        if self._model is not None:
            return True
        if timeout_s is None or float(timeout_s) <= 0:
            with self._load_lock:
                if self._model is None:
                    self._ensure_loaded()
            return True
        deadline = time.monotonic() + float(timeout_s)
        with self._load_lock:
            if self._model is not None:
                return True
            if self._load_thread is None or not self._load_thread.is_alive():
                self._load_error = None
                self._load_thread = threading.Thread(
                    target=self._load_worker_once, name="scam-models-load",
                    daemon=True)
                self._load_thread.start()
        # 不持锁 join：加载线程内部需要 _load_lock 推进 _ensure_loaded。
        self._load_thread.join(max(deadline - time.monotonic(), 0.0))
        if self._model is not None:
            return True
        if self._load_thread.is_alive():
            return False   # 预算内未完成；线程残留如实（不可中止）
        if self._load_error is not None:
            raise self._load_error
        return self._model is not None

    def load_thread_alive(self):
        """有界加载的辅助线程是否仍存活（加载超时残留的如实口径）。"""
        t = self._load_thread
        return bool(t is not None and t.is_alive())

    def _load_worker_once(self):
        """加载线程体：结果进 self._model / 失败进 self._load_error
        （不假装成功；失败非终态）。"""
        try:
            with self._load_lock:
                if self._model is None:
                    self._ensure_loaded()
        except BaseException as exc:  # noqa: BLE001 - 原样存证交 load() 上抛
            self._load_error = exc

    def understand(self, prompt, frames_b64, context=None, frames_meta=None):
        """frames_b64: 纯 base64 JPEG 列表（无 data: 前缀）；None 项=显式缺帧
        （跳过该图并在 prompt 标注「第 N 帧缺失」，绝不伪造图像）。
        frames_meta: 与 frames_b64 等长的可选元信息列表（None 项或 dict；
        dict 的 branch/frame_id/t_capture_ms/timestamp_kind 键会渲染进
        prompt 逐帧标签，键序冻结）。
        返回 JSON dict 或 None（既有失败语义不变；需要异常分类的调用方用
        understand_frames()）。C-135 §8：全部有序帧真实进模型（C-134 前只
        取 frames_b64[:1] 的缺陷已修）。
        """
        try:
            return self._understand_ordered(prompt, frames_b64, context,
                                            frames_meta)
        except Exception:
            return None

    def understand_frames(self, prompt, frames_b64, frames_meta=None):
        """understand 的显式失败版本：异常上抛（供 win11_l3 适配层分类为
        model_unavailable/infer_failed 等），返回值语义与 understand 一致。
        """
        return self._understand_ordered(prompt, frames_b64, None, frames_meta)

    @staticmethod
    def _frame_label(position, meta):
        """第 N 帧的确定性标签：`第N帧[branch=…;frame=…;t=…;kind=…]`。"""
        parts = []
        if isinstance(meta, dict):
            for key, tag in (("branch", "branch"), ("frame_id", "frame"),
                             ("t_capture_ms", "t"), ("timestamp_kind", "kind")):
                value = meta.get(key)
                if value is not None:
                    parts.append(f"{tag}={value}")
        label = f"第{position}帧"
        if parts:
            label += "[" + ";".join(parts) + "]"
        return label

    def _understand_ordered(self, prompt, frames_b64, context=None,
                            frames_meta=None):
        """C-135 §8 有序多帧真实推理路径（失败抛异常，分类归调用方）。

        上游多图协议（本机 HF 缓存快照 5648fa26 的 modeling_internvl_chat.py，
        不凭文档猜）：
        - chat() L271-273：num_patches_list 缺省=[pixel_values.shape[0]]，
          断言 len(pixel_values) == sum(num_patches_list)——每项=一张图的
          patch 展开段数，pixel_values 沿 patch 维按帧序拼接；
        - chat() L294-296：按序把 question 中每个 `<image>` 占位符替换为
          `<img>` + `<IMG_CONTEXT>`*num_image_token*num_patches + `</img>`
          （num_image_token=(448//14)**2*0.25=256，config: force_image_size
          448 / patch_size 14 / downsample_ratio 0.5；本类固定 Resize(448,448)
          → 每帧恰 1 个 patch 段）；
        - generate() L332-345：input_ids 中 IMG_CONTEXT 位置按
          vit_embeds.reshape(-1,C) 顺序填入——pixel_values 行序=帧序=
          占位符序，三者的第 2/3 帧对应关系由此成立。
        加载只走 _ensure_loaded 既有本地受控路径（trust_remote_code 读本机
        HF 缓存）；本方法不设任何全局环境变量、不触网。
        """
        import base64
        import io
        self._ensure_loaded()
        import torch
        from PIL import Image

        frames = list(frames_b64 or [])
        if not frames:
            raise ValueError("frames_b64 为空")
        missing = [i + 1 for i, b in enumerate(frames) if b is None]
        try:
            io_dtype = self._torch_dtype()   # C173-A3：与加载 dtype 同源
            patches = []
            for b64 in frames:
                if b64 is None:
                    continue
                img = Image.open(io.BytesIO(base64.b64decode(b64)))
                patches.append(self._transform(img).unsqueeze(0)
                               .to(io_dtype))
        except Exception as exc:
            raise ValueError(f"帧解码失败: {exc}") from exc
        if not patches:
            raise ValueError("全部帧缺失（无实际图像输入）")
        # pixel_values 按帧序沿 patch 维拼接：[Σpatch, 3, 448, 448]
        pv = torch.cat(patches, dim=0)
        num_patches_list = [t.shape[0] for t in patches]
        n_present = len(patches)

        # prompt 组装：调用方自带 <image> 占位符时数量必须=实际帧数（不符
        # 如实拒绝，绝不静默错位）；否则由本层渲染逐帧段——缺帧段只写标注、
        # 无占位符，保证占位符数==图像数（上游 generate 的硬协议）。
        markers = prompt.count("<image>")
        if markers:
            if markers != n_present:
                raise ValueError(
                    f"prompt <image> 占位符数 {markers} != 实际帧数 "
                    f"{n_present}")
            full_prompt = prompt
        elif n_present == 1 and not frames_meta:
            # 既有单图路径字节级兼容（C-134 前行为）
            ctx = ""
            if context:
                ctx = (json.dumps(context, ensure_ascii=False)
                       if isinstance(context, dict) else str(context))
            full_prompt = "<image>\n" + (ctx + "\n" if ctx else "") + prompt
        else:
            meta = list(frames_meta) if frames_meta else []
            lines = []
            for i, b64 in enumerate(frames):
                head = self._frame_label(i + 1,
                                         meta[i] if i < len(meta) else None)
                if b64 is None:
                    lines.append(f"{head}：（第{i + 1}帧缺失，无图像输入）")
                else:
                    lines.append(f"{head}: <image>")
            full_prompt = "\n".join(lines) + "\n" + prompt

        # 调用事实快照（捕获测试/真实运行证据断言第二/三帧真实进模型）
        # C173-A3：请求精度 vs 实际精度如实可查；实际 model dtype 取不到
        # （无参/假模型）时如实 None，绝不编造。
        try:
            model_dtype = str(next(self._model.parameters()).dtype)
        except Exception:               # noqa: BLE001 - 观测失败不影响计算
            model_dtype = None
        self._last_call_info = {
            "frames_input": len(frames),
            "images_into_model": n_present,
            "missing_frame_positions": missing,
            "num_patches_list": list(num_patches_list),
            "pixel_values_shape": list(pv.shape),
            "prompt_marker_count": full_prompt.count("<image>"),
            "dtype_requested": self.dtype,
            "model_dtype": ("mixed" if self.precision_mode == "mixed_vision_fp32" else model_dtype),
            "pixel_values_dtype": str(pv.dtype),
        }
        if self.precision_mode == "mixed_vision_fp32":
            self._last_call_info["precision_mode"] = self.precision_mode
            components = {}
            for name in ("vision_model", "mlp1", "language_model"):
                try:
                    components[name] = str(next(getattr(self._model, name).parameters()).dtype)
                except (AttributeError, StopIteration):
                    components[name] = None
            self._last_call_info["component_dtypes"] = components
        if self.attention_implementation is not None:
            self._last_call_info["attention_requested"] = self.attention_implementation
            language = getattr(self._model, "language_model", None)
            self._last_call_info["language_attention"] = getattr(
                getattr(language, "config", None), "_attn_implementation", None)
        if self.vision_chunk_size is not None:
            self._last_call_info["vision_chunk_size"] = self.vision_chunk_size
        with torch.no_grad():
            result = self._model.chat(
                self._tokenizer, pv, full_prompt,
                generation_config=dict(max_new_tokens=200,
                                       do_sample=False),
                num_patches_list=num_patches_list)
        # 尝试提取 JSON（与 LocalOllama 对齐）
        extracted = _extract_json(result)
        return extracted if extracted else {"text": result.strip()}


def build_provider(cfg):
    """cfg: {"channel": "local"|"cloud"|"transformers", ...} → provider 实例；
    异常返回 None。"""
    if not isinstance(cfg, dict):
        return None
    ch = cfg.get("channel", "local")
    try:
        if ch == "local":
            return LocalOllama(cfg.get("base", "http://127.0.0.1:11434"),
                               cfg.get("model", "qwen3-vl:2b"),
                               cfg.get("num_ctx", 16384),
                               cfg.get("num_predict", 2048),
                               cfg.get("timeout", 90))
        if ch == "cloud":
            return CloudOpenAICompat(cfg.get("base", ""),
                                     cfg.get("model", ""),
                                     cfg.get("key_env", "SCAM_CLOUD_KEY"),
                                     cfg.get("timeout", 60))
        if ch == "transformers":
            return LocalTransformers(cfg.get("model_path",
                                     "OpenGVLab/InternVL3_5-1B-Instruct"),
                                     cfg.get("timeout", 120))
    except (ValueError, KeyError, socket.gaierror):
        return None
    return None
