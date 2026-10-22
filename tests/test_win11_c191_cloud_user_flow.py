"""Independent saved-setup -> config -> actual nvr entry contract, no network."""
import threading

from scam import nvr
from scam.config import load_venue
from scam.win11_setup import build_initial_venue, write_initial_config


def saved_setup(tmp_path, cloud=True):
    payload={'camera_id':'contract-camera','source_kind':'camera','source':'0',
             'detector_model':'','monitor_only':True}
    if cloud:
        payload['l3']={'enabled':True,'provider':'cloud',
            'base_url':'https://vision.example.invalid/v1','model':'test-vision-model',
            'key_env':'SC_TEST_CLOUD_KEY','image_upload_consent':True,'vision_capable':True}
    path=tmp_path/'isolated/cameras.json'
    write_initial_config(path,build_initial_venue(payload))
    return path,load_venue(path)


def test_saved_cloud_actual_factory_selects_cloud_not_local_path(tmp_path,monkeypatch):
    from scam import models
    from scam.win11_l3_cloud import CloudOpenAICompatibleL3Backend,CloudOpenAICompatibleL3Provider
    from scam.win11_materials import MaterialsStore
    _,cfg=saved_setup(tmp_path)
    # Deterministic public-DNS substitute, not an external lookup or allow-local bypass.
    monkeypatch.setattr(models,'_resolve_ips',lambda host:{'8.8.8.8'})
    def forbidden_network(*args,**kwargs):
        raise AssertionError('real cloud request forbidden')
    monkeypatch.setattr(CloudOpenAICompatibleL3Provider,'_transport_call',forbidden_network)
    runtime=None
    try:
        runtime=nvr._build_l2_runtime({},MaterialsStore(),['contract-camera'],l3_cfg=cfg['l3'])
        assert isinstance(runtime.l3_backend,CloudOpenAICompatibleL3Backend)
        assert runtime.l3_backend.model_ref=='cloud/test-vision-model'
    finally:
        if runtime is not None:
            runtime.stop()


def test_saved_cloud_reaches_runtime_with_l2_default_missing(tmp_path,monkeypatch):
    path,cfg=saved_setup(tmp_path)
    assert 'l2' not in cfg and cfg['l3']['provider']=='cloud'
    calls=[]
    class Runtime:
        def start(self):
            pass
        def stop(self,*args,**kwargs):
            return True
        def snapshot(self):
            return {}
    def factory(l2_cfg,store,cameras,**kwargs):
        calls.append({'l2_cfg':l2_cfg,'l3_cfg':kwargs.get('l3_cfg'),'cameras':cameras})
        return Runtime()
    monkeypatch.setattr(nvr,'_build_l2_runtime',factory)
    monkeypatch.setattr(nvr,'_run_camera',lambda *args,**kwargs:None)
    monkeypatch.setattr(nvr.signal,'signal',lambda *args:None)
    stopped=threading.Event()
    stopped.set()
    result=nvr.main(['--config',str(path),'--db',str(tmp_path/'isolated/events.db'),
                     '--no-workbench','--no-slow'],edition='win11',stop_event=stopped)
    assert result==0
    assert len(calls)==1,'saved cloud option silently ignored because l2.enabled defaults off'
    assert calls[0]['l3_cfg']==cfg['l3']


def test_unchanged_local_preview_does_not_create_l2_runtime(tmp_path,monkeypatch):
    path,cfg=saved_setup(tmp_path,cloud=False)
    # 新向导显式写入未勾选的选项（l3.enabled=False）；缺 l3 才是旧配置信号。
    assert cfg.get('l3', {}).get('enabled') is False
    calls=[]
    monkeypatch.setattr(nvr,'_build_l2_runtime',lambda *args,**kwargs:calls.append(True))
    monkeypatch.setattr(nvr,'_run_camera',lambda *args,**kwargs:None)
    monkeypatch.setattr(nvr.signal,'signal',lambda *args:None)
    stopped=threading.Event();stopped.set()
    result=nvr.main(['--config',str(path),'--db',str(tmp_path/'isolated/events.db'),
                     '--no-workbench','--no-slow'],edition='win11',stop_event=stopped)
    assert result==0 and calls==[]


def test_saved_cloud_has_event_progress_for_progressive_user_records(tmp_path,monkeypatch):
    from scam import db,models
    from scam.win11_l3_cloud import CloudOpenAICompatibleL3Provider
    from scam.win11_materials import MaterialsStore
    _,cfg=saved_setup(tmp_path)
    monkeypatch.setattr(models,'_resolve_ips',lambda host:{'8.8.8.8'})
    def no_external_request(*args,**kwargs):
        raise AssertionError('no external API request allowed')
    monkeypatch.setattr(CloudOpenAICompatibleL3Provider,'_transport_call',no_external_request)
    path=tmp_path/'isolated/progress.db'
    conn=db.connect(str(path));db.init_schema(conn);conn.close()
    runtime=nvr._build_l2_runtime({},MaterialsStore(),['contract-camera'],
                                  l3_cfg=cfg['l3'],db_path=str(path))
    try:
        assert runtime.l3_backend is not None
        assert runtime.l4_factory is not None, 'cloud setup has no L4 progressive fusion path'
        assert runtime.event_progress is not None, 'cloud setup has no event progress bridge'
    finally:
        runtime.stop()


def test_explicit_cloud_l4_disabled_is_respected(tmp_path,monkeypatch):
    from scam import db,models
    from scam.win11_materials import MaterialsStore
    _,cfg=saved_setup(tmp_path)
    # Explicit config opt-out is distinct from the setup's missing default.
    cfg['l3']['l4']={'enabled':False}
    monkeypatch.setattr(models,'_resolve_ips',lambda host:{'8.8.8.8'})
    path=tmp_path/'isolated/opt-out.db'
    conn=db.connect(str(path));db.init_schema(conn);conn.close()
    runtime=nvr._build_l2_runtime({},MaterialsStore(),['contract-camera'],
                                  l3_cfg=cfg['l3'],db_path=str(path))
    try:
        assert runtime.l3_backend is not None
        assert runtime.l4_factory is None
        assert runtime.event_progress is None
    finally:
        runtime.stop()


def test_legacy_local_l3_keeps_l4_default_off(tmp_path):
    from scam.win11_materials import MaterialsStore
    runtime=nvr._build_l2_runtime({},MaterialsStore(),['contract-camera'],
        l3_cfg={'enabled':True,'model_path':str(tmp_path/'not-loaded-local-model')})
    try:
        assert runtime.l3_backend is not None
        assert runtime.l4_factory is None and runtime.event_progress is None
    finally:
        runtime.stop()
