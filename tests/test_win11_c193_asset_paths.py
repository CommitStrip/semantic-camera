"""Explicit packaged model roots and real desktop first-use prefill; no models."""
import copy
import json
from pathlib import Path
import pytest


def venue():
    return {'cameras':[{'id':'cam','source':'0','source_kind':'camera',
             'detector':{'engine':'onnx','model':'models/person-detector.onnx','classes':['person']}}],
            'asset_paths':{'schema':'scam.package-assets/v1','root':'config'},
            'l2':{'repo_path':'assets/relsgg','checkpoint':'assets/ra/model.pth'},
            'l3':{'enabled':True,'model_path':'assets/internvl'}}


def test_marked_paths_follow_configuration_not_cwd(tmp_path,monkeypatch):
    from scam.config import load_venue
    root=tmp_path/'candidate';root.mkdir()
    config=root/'example.json';config.write_text(json.dumps(venue()),encoding='utf-8')
    elsewhere=tmp_path/'different-cwd';elsewhere.mkdir();monkeypatch.chdir(elsewhere)
    actual=load_venue(config)
    assert actual['cameras'][0]['detector']['model']==str(root/'models/person-detector.onnx')
    assert actual['l2']['repo_path']==str(root/'assets/relsgg')
    assert actual['l2']['checkpoint']==str(root/'assets/ra/model.pth')
    assert actual['l3']['model_path']==str(root/'assets/internvl')
    assert json.loads(config.read_text(encoding='utf-8'))==venue()


def test_ordinary_config_and_user_absolute_paths_unchanged(tmp_path):
    from scam.config import load_venue
    config=tmp_path/'ordinary.json'
    v=venue();v.pop('asset_paths')
    config.write_text(json.dumps(v),encoding='utf-8')
    assert load_venue(config)==v
    v['asset_paths']={'schema':'scam.package-assets/v1','root':'config'}
    absolute=str(tmp_path/'custom-model.onnx')
    v['cameras'][0]['detector']['model']=absolute
    config.write_text(json.dumps(v),encoding='utf-8')
    assert load_venue(config)['cameras'][0]['detector']['model']==absolute


def test_explicit_install_root_pure_no_mutation(tmp_path):
    import scam.config as cfg
    resolve=getattr(cfg,'resolve_venue_asset_paths',None)
    assert callable(resolve), 'production root resolver missing'
    v=venue();v['asset_paths']['root']='install'
    before=copy.deepcopy(v)
    actual=resolve(v,tmp_path/'user/config.json',install_root=tmp_path/'install')
    assert actual['l3']['model_path']==str(tmp_path/'install/assets/internvl')
    assert v==before


@pytest.mark.parametrize('marker',[
    {'schema':'other','root':'config'}, {'schema':'scam.package-assets/v1','root':'cwd'},
    {'schema':'scam.package-assets/v1','root':True}, 'config'])
def test_bad_packaged_schema_rejected(tmp_path,marker):
    from scam.config import load_venue
    v=venue();v['asset_paths']=marker
    p=tmp_path/'bad.json';p.write_text(json.dumps(v),encoding='utf-8')
    with pytest.raises(ValueError):load_venue(p)


def test_packaged_relative_traversal_rejected(tmp_path):
    from scam.config import load_venue
    v=venue();v['l3']['model_path']='../outside'
    p=tmp_path/'bad.json';p.write_text(json.dumps(v),encoding='utf-8')
    with pytest.raises(ValueError):load_venue(p)


def test_real_desktop_setup_receives_bundled_model_prefill(tmp_path,monkeypatch):
    from scam.win11_desktop import desktop_main
    from scam import win11_launcher
    model=tmp_path/'models/person-detector.onnx';model.parent.mkdir();model.write_bytes(b'fixture')
    monkeypatch.setattr(win11_launcher,'bundled_model_path',lambda:str(model))
    seen={}
    def setup(path,*,browser_opener,stop_event,default_model_path=None):
        seen['model']=default_model_path
        stop_event.set()
        return False
    code=desktop_main(['--config',str(tmp_path/'unsaved/config.json')],edition='win11',
        runtime_main=lambda *a,**kw:pytest.fail('unsaved setup entered runtime'),setup_runner=setup,stdin=None)
    assert code==0 and seen['model']==str(model)
    assert not (tmp_path/'unsaved').exists()


def test_nvr_actual_config_reader_uses_explicit_asset_root(tmp_path):
    from scam.nvr import _load_json
    p=tmp_path/'example.json';p.write_text(json.dumps(venue()),encoding='utf-8')
    actual=_load_json(p)
    assert actual['l2']['checkpoint']==str(tmp_path/'assets/ra/model.pth')


def test_frozen_nested_backend_resolves_standard_install_root(tmp_path,monkeypatch):
    import sys
    from scam.config import resolve_venue_asset_paths
    root=tmp_path/'install';(root/'backend').mkdir(parents=True)
    exe=root/'backend/semantic-camera-backend.exe';exe.write_bytes(b'not-executed-fixture')
    (root/'SemanticCamera.Desktop.dll').write_bytes(b'layout-anchor')
    monkeypatch.setattr(sys,'frozen',True,raising=False)
    monkeypatch.setattr(sys,'executable',str(exe))
    v=venue();v['asset_paths']['root']='install'
    actual=resolve_venue_asset_paths(v,tmp_path/'user/cameras.json')
    assert actual['l2']['checkpoint']==str(root/'assets/ra/model.pth')


def test_source_install_root_without_argument_is_rejected(tmp_path,monkeypatch):
    import sys
    from scam.config import resolve_venue_asset_paths
    monkeypatch.delattr(sys,'frozen',raising=False)
    v=venue();v['asset_paths']['root']='install'
    with pytest.raises(ValueError,match='install_root'):
        resolve_venue_asset_paths(v,tmp_path/'config.json')


def test_frozen_wrong_layout_is_not_arbitrarily_searched(tmp_path,monkeypatch):
    import sys
    from scam.config import resolve_venue_asset_paths
    exe=tmp_path/'random/backend.exe';exe.parent.mkdir();exe.write_bytes(b'fixture')
    (tmp_path/'SemanticCamera.Desktop.dll').write_bytes(b'not-a-valid-layout')
    monkeypatch.setattr(sys,'frozen',True,raising=False)
    monkeypatch.setattr(sys,'executable',str(exe))
    v=venue();v['asset_paths']['root']='install'
    with pytest.raises(ValueError,match='布局'):
        resolve_venue_asset_paths(v,tmp_path/'config.json')


def test_resolution_is_idempotent_and_does_not_rewrite_source_or_cloud(tmp_path):
    from scam.config import resolve_venue_asset_paths
    v=venue();v['cameras'][0]['source']='rtsp://synthetic:pass@camera.invalid/live'
    v['l3']={'provider':'cloud','model_path':'../irrelevant-to-cloud','base_url':'https://vision.example.invalid/v1'}
    first=resolve_venue_asset_paths(v,tmp_path/'config.json')
    second=resolve_venue_asset_paths(first,tmp_path/'config.json')
    assert first==second
    assert first['cameras'][0]['source']==v['cameras'][0]['source']
    assert first['l3']==v['l3']


@pytest.mark.parametrize('bad',['C:drive-relative.onnx','\\root-relative.onnx','models/../..'])
def test_ambiguous_or_escaping_paths_rejected(tmp_path,bad):
    from scam.config import resolve_venue_asset_paths
    v=venue();v['cameras'][0]['detector']['model']=bad
    with pytest.raises(ValueError):resolve_venue_asset_paths(v,tmp_path/'config.json')


def test_actual_bundled_lookup_prefills_standard_meipass_model(tmp_path,monkeypatch):
    import sys
    from scam.win11_desktop import desktop_main
    model=tmp_path/'models/person-detector.onnx';model.parent.mkdir();model.write_bytes(b'fixture')
    monkeypatch.setattr(sys,'_MEIPASS',str(tmp_path),raising=False)
    seen={}
    def setup(path,*,browser_opener,stop_event,default_model_path):
        seen['default']=default_model_path;stop_event.set();return False
    assert desktop_main(['--config',str(tmp_path/'no-config.json')],edition='win11',
        setup_runner=setup,stdin=None)==0
    assert seen['default']==str(model)


def test_nested_backend_install_models_prefill_fallback(tmp_path,monkeypatch):
    import sys
    from scam.win11_desktop import desktop_main
    root=tmp_path/'install';(root/'backend/_internal').mkdir(parents=True)
    exe=root/'backend/semantic-camera-backend.exe';exe.write_bytes(b'fixture')
    (root/'SemanticCamera.Desktop.dll').write_bytes(b'fixture')
    model=root/'models/person-detector.onnx';model.parent.mkdir();model.write_bytes(b'fixture')
    monkeypatch.setattr(sys,'frozen',True,raising=False)
    monkeypatch.setattr(sys,'executable',str(exe))
    monkeypatch.setattr(sys,'_MEIPASS',str(root/'backend/_internal'),raising=False)
    seen={}
    def setup(path,*,browser_opener,stop_event,default_model_path):
        seen['default']=default_model_path;stop_event.set();return False
    assert desktop_main(['--config',str(tmp_path/'no-config.json')],edition='win11',
        setup_runner=setup,stdin=None)==0
    assert seen['default']==str(model)


def test_older_setup_runner_without_new_keyword_is_compatible(tmp_path):
    from scam.win11_desktop import desktop_main
    calls=[]
    def setup(path,*,browser_opener):
        calls.append(path);return False
    assert desktop_main(['--config',str(tmp_path/'no-config.json')],edition='win11',
        setup_runner=setup,stdin=None)==1
    assert calls==[str(tmp_path/'no-config.json')]
