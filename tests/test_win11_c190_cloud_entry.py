"""Production builder routing without external requests or local weights."""
import pytest

from scam import nvr
from scam.win11_materials import MaterialsStore


def cloud_config(**changes):
    cfg = dict(enabled=True, provider="cloud",
               base_url="https://vision.example.invalid/v1", model="vision-model",
               key_env="SC_ENTRY_TEST_KEY", image_upload_consent=True,
               vision_capable=True)
    cfg.update(changes)
    return cfg


def test_cloud_entry_does_not_construct_local_model(monkeypatch):
    import scam.win11_l3_cloud as cloud
    import scam.win11_l3_backend as local
    captured = {}

    class Backend:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    def forbid_local(**kwargs):
        pytest.fail("cloud selection constructed local weights")

    monkeypatch.setattr(cloud, "CloudOpenAICompatibleL3Backend", Backend)
    monkeypatch.setattr(local, "LocalTransformersL3Backend", forbid_local)
    runtime = nvr._build_l2_runtime({}, MaterialsStore(), ["cam"],
                                    l3_cfg=cloud_config())
    assert isinstance(runtime.l3_backend, Backend)
    assert captured["consent"] is True
    assert captured["base_url"].endswith("/v1")
    assert captured["key_env"] == "SC_ENTRY_TEST_KEY"
    assert "model_path" not in captured
    assert "dtype" not in captured


@pytest.mark.parametrize("changes", [
    {"image_upload_consent": False}, {"image_upload_consent": 1},
    {"vision_capable": "true"}, {"provider": "unknown"},
    {"base_url": "https://user:secret@example.invalid/v1"},
])
def test_direct_builder_rejects_invalid_cloud_before_transport(changes):
    with pytest.raises(ValueError):
        nvr._build_l2_runtime({}, MaterialsStore(), ["cam"],
                              l3_cfg=cloud_config(**changes))


def test_disabled_cloud_needs_no_environment_or_endpoint():
    runtime = nvr._build_l2_runtime({}, MaterialsStore(), ["cam"],
                                   l3_cfg={"enabled": False, "provider": "cloud"})
    assert runtime.l3_backend is None


def test_default_local_still_requires_explicit_model():
    with pytest.raises(ValueError, match="model_path"):
        nvr._build_l2_runtime({}, MaterialsStore(), ["cam"], l3_cfg={"enabled": True})
