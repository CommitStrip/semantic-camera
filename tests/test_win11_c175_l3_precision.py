"""Default-entry precision wiring and explicit mixed-vision boundaries; no weights."""
from contextlib import contextmanager

import pytest


@contextmanager
def runtime_for(tmp_path, **options):
    from scam.nvr import _build_l2_runtime
    from scam.win11_materials import MaterialsStore
    model = tmp_path / 'snapshot'
    model.mkdir(exist_ok=True)
    (model / 'config.json').write_text('{}', encoding='utf-8')
    runtime = _build_l2_runtime(
        {}, MaterialsStore(), ['test-camera'],
        l3_cfg={'enabled': True, 'model_path': str(model), **options})
    try:
        yield runtime
    finally:
        assert runtime.stop() is True


@pytest.mark.parametrize('dtype', ['float32', 'bfloat16'])
def test_entry_passes_explicit_dtype_to_real_backend_and_provider(tmp_path, dtype):
    with runtime_for(tmp_path, dtype=dtype) as runtime:
        backend = runtime.l3_backend
        assert backend.snapshot()['dtype'] == dtype
        assert backend._provider.dtype == dtype
        assert backend._provider._model is None


def test_entry_default_stays_fp32(tmp_path):
    with runtime_for(tmp_path) as runtime:
        assert runtime.l3_backend.snapshot()['dtype'] == 'float32'


@pytest.mark.parametrize('dtype', ['bf16', '', True, 3, {}])
def test_entry_rejects_invalid_explicit_dtype(tmp_path, dtype):
    with pytest.raises(ValueError):
        with runtime_for(tmp_path, dtype=dtype):
            pytest.fail('invalid precision silently accepted')


def test_entry_routes_mixed_precision_without_loading_weights(tmp_path):
    with runtime_for(tmp_path, dtype='bfloat16', precision_mode='mixed_vision_fp32') as runtime:
        backend = runtime.l3_backend
        assert backend.snapshot()['precision_mode'] == 'mixed_vision_fp32'
        assert backend._provider.precision_mode == 'mixed_vision_fp32'
        assert backend._provider._model is None


@pytest.mark.parametrize('mode', ['', True, {}, 'auto', 'mixed'])
def test_bad_precision_mode_rejected_by_entry(tmp_path, mode):
    with pytest.raises(ValueError):
        with runtime_for(tmp_path, dtype='bfloat16', precision_mode=mode):
            pytest.fail('invalid mode silently accepted')


def test_mixed_mode_requires_explicit_bf16_language():
    from scam.models import LocalTransformers
    from scam.win11_l3_backend import LocalTransformersL3Backend
    for factory in (LocalTransformers, LocalTransformersL3Backend):
        with pytest.raises(ValueError):
            factory(model_path='unused', precision_mode='mixed_vision_fp32')


def test_real_module_precision_bridge_preserves_language_and_feature_order():
    import torch
    from scam.models import LocalTransformers

    class Tiny(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.vision_model = torch.nn.Linear(2, 2).bfloat16()
            self.mlp1 = torch.nn.Linear(2, 2).bfloat16()
            self.language_model = torch.nn.Linear(2, 2).bfloat16()
            self.seen = []

        def extract_feature(self, pixels):
            self.seen.append((pixels.clone(), pixels.dtype))
            return self.mlp1(self.vision_model(pixels))

    model = Tiny()
    original_language = model.language_model.weight.detach().clone()
    pixels = torch.tensor([[1, 2], [3, 4], [5, 6]], dtype=torch.bfloat16)
    provider = LocalTransformers(dtype='bfloat16', precision_mode='mixed_vision_fp32')
    provider._configure_precision(model)
    out = model.extract_feature(pixels)
    assert model.seen[0][1] == torch.float32
    assert torch.equal(model.seen[0][0], pixels.float())
    assert out.shape == (3, 2) and out.dtype == torch.bfloat16
    assert next(model.vision_model.parameters()).dtype == torch.float32
    assert next(model.mlp1.parameters()).dtype == torch.float32
    assert torch.equal(original_language, model.language_model.weight)
    assert pixels.dtype == torch.bfloat16
    with pytest.raises(ValueError, match='already configured'):
        provider._configure_precision(model)


def test_mixed_mode_refuses_missing_components_without_partial_conversion():
    import torch
    from scam.models import LocalTransformers
    model = torch.nn.Module()
    model.vision_model = torch.nn.Linear(2, 2).bfloat16()
    provider = LocalTransformers(dtype='bfloat16', precision_mode='mixed_vision_fp32')
    with pytest.raises(ValueError, match='requires'):
        provider._configure_precision(model)
    assert next(model.vision_model.parameters()).dtype == torch.bfloat16


def test_injected_provider_cannot_claim_unconfigured_mixed_mode():
    from scam.win11_l3_backend import LocalTransformersL3Backend
    class Provider:
        dtype = 'bfloat16'
    with pytest.raises(ValueError, match='precision_mode mismatch'):
        LocalTransformersL3Backend(provider=Provider(), dtype='bfloat16',
                                  precision_mode='mixed_vision_fp32')


def test_uniform_mode_never_casts_or_wraps_existing_model():
    import torch
    from scam.models import LocalTransformers
    model = torch.nn.Linear(2, 2).bfloat16()
    provider = LocalTransformers(dtype='bfloat16')
    before = model.weight.detach().clone()
    provider._configure_precision(model)
    assert torch.equal(model.weight, before)
    assert not hasattr(model, '_scam_mixed_vision_configured')


def test_language_dtype_mismatch_refuses_before_visual_conversion():
    import torch
    from scam.models import LocalTransformers
    class Model(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.vision_model = torch.nn.Linear(2, 2).bfloat16()
            self.mlp1 = torch.nn.Linear(2, 2).bfloat16()
            self.language_model = torch.nn.Linear(2, 2).float()
        def extract_feature(self, x):
            return x
    model = Model()
    provider = LocalTransformers(dtype='bfloat16', precision_mode='mixed_vision_fp32')
    with pytest.raises(ValueError, match='BF16 language'):
        provider._configure_precision(model)
    assert next(model.vision_model.parameters()).dtype == torch.bfloat16
