"""Explicit attention selection; no downloaded weights or heavyweight model jobs."""
from types import SimpleNamespace
import pytest
from scam.models import LocalTransformers
from scam.win11_l3_backend import LocalTransformersL3Backend


class Language:
    def __init__(self, accept=True):
        self.config = SimpleNamespace(_attn_implementation='eager')
        self.calls = []
        self.accept = accept

    def set_attn_implementation(self, value):
        self.calls.append(value)
        if self.accept:
            self.config._attn_implementation = value


def test_default_does_not_override_upstream_attention():
    language = Language()
    LocalTransformers()._configure_attention(SimpleNamespace(language_model=language))
    assert language.calls == []
    assert language.config._attn_implementation == 'eager'


def test_real_small_qwen_sdpa_preserves_causal_and_cached_logits():
    """Installed Qwen3 path with random tiny weights, not semantic-quality proof."""
    import torch
    from transformers import Qwen3Config, Qwen3ForCausalLM
    with torch.random.fork_rng():
        torch.manual_seed(176)
        config = Qwen3Config(vocab_size=32, hidden_size=32, intermediate_size=64,
            num_hidden_layers=1, num_attention_heads=4, num_key_value_heads=2,
            head_dim=8, attention_dropout=0.0)
        model = Qwen3ForCausalLM(config).eval()
        ids = torch.tensor([[1, 2, 3, 4]])
        with torch.no_grad():
            model.set_attn_implementation('eager')
            eager = model(ids, use_cache=False).logits
            model.set_attn_implementation('sdpa')
            full = model(ids, use_cache=False).logits
            prefix = model(ids[:, :3], use_cache=True)
            cached = model(ids[:, 3:], past_key_values=prefix.past_key_values,
                use_cache=True).logits
            changed = model(torch.tensor([[1, 2, 3, 9]]), use_cache=False).logits
        torch.testing.assert_close(full, eager, atol=1e-5, rtol=1e-4)
        torch.testing.assert_close(cached[:, -1], full[:, -1], atol=1e-5, rtol=1e-4)
        torch.testing.assert_close(changed[:, :3], full[:, :3], atol=1e-5, rtol=1e-4)


@pytest.mark.parametrize('attention', ['eager', 'sdpa'])
def test_explicit_selection_only_changes_language(attention):
    language = Language()
    vision = SimpleNamespace(config=SimpleNamespace(_attn_implementation='unchanged'))
    provider = LocalTransformers(attention_implementation=attention)
    provider._configure_attention(SimpleNamespace(language_model=language, vision_model=vision))
    assert language.calls == [attention]
    assert language.config._attn_implementation == attention
    assert vision.config._attn_implementation == 'unchanged'


@pytest.mark.parametrize('attention', ['', True, {}, 'auto', 'flash_attention_2'])
def test_invalid_choice_refused_before_loading(attention):
    for cls in (LocalTransformers, LocalTransformersL3Backend):
        with pytest.raises(ValueError):
            cls(model_path='unused', attention_implementation=attention)


def test_silent_noop_is_not_accepted():
    provider = LocalTransformers(attention_implementation='sdpa')
    with pytest.raises(RuntimeError, match='not effective'):
        provider._configure_attention(SimpleNamespace(language_model=Language(accept=False)))


def test_missing_setter_is_explicit_failure_not_fallback():
    provider = LocalTransformers(attention_implementation='sdpa')
    with pytest.raises(ValueError, match='requires'):
        provider._configure_attention(SimpleNamespace(language_model=object()))


def test_injected_provider_must_declare_requested_attention():
    with pytest.raises(ValueError, match='attention.*mismatch'):
        LocalTransformersL3Backend(provider=SimpleNamespace(model_id='stub'), attention_implementation='sdpa')


def test_real_entry_backend_provider_route(tmp_path):
    from scam.nvr import _build_l2_runtime
    from scam.win11_materials import MaterialsStore
    model = tmp_path / 'snapshot'
    model.mkdir()
    (model/'config.json').write_text('{}', encoding='utf-8')
    runtime = _build_l2_runtime({}, MaterialsStore(), ['camera'], l3_cfg={
        'enabled': True, 'model_path': str(model), 'dtype': 'bfloat16',
        'precision_mode': 'mixed_vision_fp32', 'attention_implementation': 'sdpa'})
    try:
        backend = runtime.l3_backend
        assert backend.snapshot()['attention_implementation'] == 'sdpa'
        assert backend._provider.attention_implementation == 'sdpa'
        assert backend._provider._model is None
    finally:
        assert runtime.stop() is True


def test_vision_chunks_preserve_all_features_in_order():
    import torch
    class Model:
        def __init__(self):
            self.batches = []
        def extract_feature(self, pixels):
            self.batches.append(pixels.shape[0])
            return pixels * 2
    model = Model()
    pixels = torch.arange(18).reshape(3, 2, 3).float()
    provider = LocalTransformers(vision_chunk_size=1)
    provider._configure_vision_execution(model)
    result = model.extract_feature(pixels)
    assert model.batches == [1, 1, 1]
    assert torch.equal(result, pixels*2)
    assert result.shape == pixels.shape
    with pytest.raises(ValueError, match='already configured'):
        provider._configure_vision_execution(model)


@pytest.mark.parametrize('chunk', [0, -1, True, '1', 2, {}])
def test_only_explicit_single_frame_execution_supported(chunk):
    for cls in (LocalTransformers, LocalTransformersL3Backend):
        with pytest.raises(ValueError):
            cls(model_path='unused', vision_chunk_size=chunk)


def test_chunked_entry_routes_both_options(tmp_path):
    from scam.nvr import _build_l2_runtime
    from scam.win11_materials import MaterialsStore
    runtime = _build_l2_runtime({}, MaterialsStore(), ['camera'], l3_cfg={
        'enabled': True, 'model_path': str(tmp_path), 'dtype': 'bfloat16',
        'precision_mode': 'mixed_vision_fp32', 'attention_implementation': 'sdpa',
        'vision_chunk_size': 1})
    try:
        snap = runtime.l3_backend.snapshot()
        assert snap['vision_chunk_size'] == 1
        assert runtime.l3_backend._provider.vision_chunk_size == 1
        assert snap['attention_implementation'] == 'sdpa'
    finally:
        assert runtime.stop() is True
