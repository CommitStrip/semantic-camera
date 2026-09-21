"""ZW-001 环境档案核心测试：R-004 契约九场景 + 溯源/隔离/重复读。"""

import json

import numpy as np
import pytest

import scam.db as db
from scam.environment import EnvironmentStore, validate_camera_id


def _conn(tmp_path):
    conn = db.connect(str(tmp_path / "env.db"))
    db.init_schema(conn)
    return conn


def _frame():
    return np.zeros((8, 8, 3), dtype=np.uint8)


class FakeProvider:
    """可编程 Provider 替身：计数调用、返回预设。"""

    def __init__(self, name="local", result=None):
        self.name = name
        self.result = result
        self.calls = 0

    def understand(self, prompt, frames_b64, context=None):
        self.calls += 1
        return self.result


GOOD = {
    "scene_type": "住宅门口",
    "elements": ["大门", "台阶", "绿植"],
    "lighting": "夜间红外，黑白画面",
    "risk_notes": "夜间光线弱，人物细节有限",
    "suggested_zones": ["大门台阶区域"],
}


def _store(tmp_path):
    return EnvironmentStore(_conn(tmp_path))


# ---------- 1. 本地成功：持久化 + 读取 ----------

def test_local_success_persists_and_reads(tmp_path):
    store = _store(tmp_path)
    provider = FakeProvider("local", result=json.dumps(GOOD))

    status, profile = store.analyze("front", provider=provider,
                                    frame_bgr=_frame())

    assert status == "ok"
    assert profile["scene_type"] == "住宅门口"
    assert profile["provider"] == "local"
    assert len(profile["frame_sha256"]) == 64
    loaded = store.load("front")
    assert loaded == profile
    assert provider.calls == 1


# ---------- 2. 无 provider ----------

def test_missing_provider_is_unavailable_and_calls_nothing(tmp_path):
    store = _store(tmp_path)

    status, profile = store.analyze("front", provider=None,
                                    frame_bgr=_frame())

    assert status == "unavailable" and profile is None
    assert store.load("front") is None


# ---------- 3. 模型返回 None：不覆盖旧档案 ----------

def test_model_none_keeps_old_profile(tmp_path):
    store = _store(tmp_path)
    good = FakeProvider("local", result=json.dumps(GOOD))
    store.analyze("front", provider=good, frame_bgr=_frame())

    broken = FakeProvider("local", result=None)
    status, profile = store.analyze("front", provider=broken,
                                    frame_bgr=_frame())

    assert status == "unavailable" and profile is None
    assert store.load("front")["scene_type"] == "住宅门口"


# ---------- 4. 非法结构：不覆盖旧档案 ----------

@pytest.mark.parametrize("bad", [
    {"scene_type": ""},
    {"scene_type": "x" * 65, "lighting": "夜", "risk_notes": "r",
     "elements": [], "suggested_zones": []},
    {"scene_type": "门", "lighting": "夜", "risk_notes": "r",
     "elements": "不是列表", "suggested_zones": []},
    {"scene_type": "门", "lighting": "夜", "risk_notes": "r",
     "elements": ["x" * 65], "suggested_zones": []},
    "不是字典",
])
def test_invalid_structure_keeps_old_profile(tmp_path, bad):
    store = _store(tmp_path)
    store.analyze("front", provider=FakeProvider("local",
                                                 result=json.dumps(GOOD)),
                  frame_bgr=_frame())

    status, _ = store.analyze("front",
                              provider=FakeProvider("local", result=bad),
                              frame_bgr=_frame())

    assert status == "invalid"
    assert store.load("front")["scene_type"] == "住宅门口"


@pytest.mark.parametrize("bad_zone", [
    {"name": "模型不能直接提交结构化区域"},
    "x" * 201,
    "",
])
def test_unbounded_or_structured_suggested_zone_is_rejected(tmp_path,
                                                            bad_zone):
    store = _store(tmp_path)
    result = dict(GOOD)
    result["suggested_zones"] = [bad_zone]

    status, profile = store.analyze(
        "front", provider=FakeProvider("local", result=result),
        frame_bgr=_frame())

    assert status == "invalid" and profile is None
    assert store.load("front") is None


# ---------- 5/6. 云端逐次确认 ----------

def test_cloud_without_confirmation_makes_zero_calls(tmp_path):
    store = _store(tmp_path)
    cloud = FakeProvider("cloud", result=json.dumps(GOOD))

    status, _ = store.analyze("front", provider=cloud, frame_bgr=_frame())

    assert status == "confirmation_required"
    assert cloud.calls == 0
    assert store.load("front") is None


def test_cloud_with_confirmation_calls_once(tmp_path):
    store = _store(tmp_path)
    cloud = FakeProvider("cloud", result=json.dumps(GOOD))

    status, _ = store.analyze("front", provider=cloud, frame_bgr=_frame(),
                              cloud_confirmed=True)

    assert status == "ok"
    assert cloud.calls == 1
    assert store.load("front")["provider"] == "cloud"


def test_unknown_provider_cannot_bypass_cloud_confirmation(tmp_path):
    store = _store(tmp_path)
    provider = FakeProvider("Cloud", result=json.dumps(GOOD))

    status, profile = store.analyze("front", provider=provider,
                                    frame_bgr=_frame())

    assert status == "unavailable" and profile is None
    assert provider.calls == 0


# ---------- 7. 图片不入库，只有哈希 ----------

def test_frame_image_never_stored_only_sha256(tmp_path):
    store = _store(tmp_path)
    store.analyze("front", provider=FakeProvider("local",
                                                 result=json.dumps(GOOD)),
                  frame_bgr=_frame())

    row = store.conn.execute(
        "SELECT value FROM meta WHERE key='env:front'").fetchone()
    blob = row[0]
    assert "data:image" not in blob
    assert "/9j/" not in blob            # JPEG base64 头
    stored = json.loads(blob)
    assert set(stored) >= {"scene_type", "elements", "lighting",
                           "risk_notes", "suggested_zones", "provider",
                           "analyzed_at", "frame_sha256"}


# ---------- 8. 相机 id 注入拒绝 ----------

@pytest.mark.parametrize("evil", [
    "cam'; DROP TABLE meta;--",
    "a/b",
    "../cam",
    "",
    "x" * 65,
    None,
])
def test_camera_id_injection_rejected(tmp_path, evil):
    store = _store(tmp_path)
    with pytest.raises(ValueError):
        validate_camera_id(evil)
    with pytest.raises(ValueError):
        store.load(evil)
    with pytest.raises(ValueError):
        store.analyze(evil, provider=FakeProvider("local",
                                                  result=json.dumps(GOOD)),
                      frame_bgr=_frame())


# ---------- 9. 相机 A/B 隔离 + 重复读不调模型 ----------

def test_camera_isolation_and_repeat_read_calls_model_once(tmp_path):
    store = _store(tmp_path)
    provider = FakeProvider("local", result=json.dumps(GOOD))

    store.analyze("front", provider=provider, frame_bgr=_frame())
    first = store.load("front")
    second = store.load("front")
    store.load("back")

    assert first == second
    assert store.load("back") is None
    assert provider.calls == 1, "重复读取不得调用模型"


# ---------- 溯源：frame_sha256 与输入一致 ----------

def test_frame_sha256_matches_input_jpeg(tmp_path):
    import base64
    import hashlib
    import cv2

    store = _store(tmp_path)
    frame = _frame()
    ok, encoded = cv2.imencode(".jpg", frame,
                               [cv2.IMWRITE_JPEG_QUALITY, 85])
    assert ok
    expected = hashlib.sha256(encoded.tobytes()).hexdigest()

    _, profile = store.analyze("front",
                               provider=FakeProvider("local",
                                                     result=json.dumps(GOOD)),
                               frame_bgr=frame)

    assert profile["frame_sha256"] == expected
    # 哈希可反查输入等价性：同一帧再编码的 base64 解码即原 JPEG
    assert base64.b64decode(base64.b64encode(encoded.tobytes())) == \
        encoded.tobytes()


def test_provider_exception_and_bad_frame_degrade_honestly(tmp_path):
    class RaisingProvider(FakeProvider):
        def understand(self, prompt, frames_b64, context=None):
            self.calls += 1
            raise RuntimeError("provider down")

    store = _store(tmp_path)
    status, profile = store.analyze(
        "front", provider=RaisingProvider("local"), frame_bgr=_frame())
    assert status == "unavailable" and profile is None

    provider = FakeProvider("local", result=json.dumps(GOOD))
    status, profile = store.analyze("front", provider=provider,
                                    frame_bgr=None)
    assert status == "unavailable" and profile is None
    assert provider.calls == 0


def test_corrupt_stored_profile_is_not_returned(tmp_path):
    store = _store(tmp_path)
    corrupt = dict(GOOD)
    corrupt.update({"provider": "local", "analyzed_at": 1,
                    "frame_sha256": "not-a-real-hash"})
    store.conn.execute("INSERT INTO meta(key, value) VALUES (?, ?)",
                       ("env:front", json.dumps(corrupt)))
    store.conn.commit()

    assert store.load("front") is None
