"""Model-reported uncertainty must survive L3 -> L4 -> persisted JSON."""
import json
import numpy as np
import pytest
from scam.win11_l3 import L3Stage
from scam.win11_l3_contract import (
    L3Task, L3FrameInput, L3FrameIdentity, L3WindowIdentity, L3BranchKind)
from scam.win11_l4 import L4Stage
from scam.win11_l4_contract import (
    FusionInput, fusion_version_to_json, fusion_version_from_json,
    l3_fingerprint_rows)


def branch(result, cfg=1, fid=0, t=0, clock='observed'):
    class Model:
        model_ref = 'test/model'
        def understand_frames(self, *args):
            return result
    window = L3WindowIdentity('cam', 'run', cfg, 'window')
    frame = L3FrameInput(L3BranchKind.PANORAMA,
        L3FrameIdentity('cam', 'run', cfg, fid), t, clock,
        np.zeros((4, 6, 3), dtype=np.uint8))
    return L3Stage(Model()).process(L3Task(window, L3BranchKind.PANORAMA,
        [frame], prompt='只描述可见内容。')).results[0]


def input_for(b):
    return FusionInput('cam', 'run', 1, 'window', l3_branches=[b],
        clock_kinds=['observed'])


def test_unknown_survives_stage_fusion_and_json_without_confirming_claim():
    b = branch({'observation':'人物离开画面', 'inference':'可能进入室内',
        'unknown':'去向无法确认'})
    assert b.model_unknown == '去向无法确认'
    v = L4Stage('cam','run',1).fuse(input_for(b))
    assert any(i.kind=='inference' and i.text=='可能进入室内'
        and i.certainty=='model_inferred' for i in v.items)
    unknown = [i for i in v.items if '去向无法确认' in i.text]
    assert len(unknown)==1
    assert unknown[0].kind=='gap' and unknown[0].certainty=='unknown'
    assert unknown[0].sources[0].kind=='l3_branch'
    reread = fusion_version_from_json(fusion_version_to_json(v))
    assert [(i.kind,i.text,i.certainty) for i in reread.items] == [
        (i.kind,i.text,i.certainty) for i in v.items]


def test_unknown_only_output_is_not_observation():
    b = branch({'unknown':'动作无法确认'})
    assert b.model_unknown=='动作无法确认'
    assert b.observation is None and b.inference is None
    assert b.unstructured is False


@pytest.mark.parametrize('payload', [['门是否打开未知'], {'door':'unknown'}, False, 0])
def test_json_unknown_values_are_preserved_not_silently_dropped(payload):
    b=branch({'observation':'门口', 'unknown':payload})
    assert json.loads(b.model_unknown)==payload


def test_changed_unknown_produces_new_version_and_replay_is_idempotent():
    stage=L4Stage('cam','run',1)
    a=branch({'observation':'门口','unknown':'门状态未知'})
    b=branch({'observation':'门口','unknown':'人物去向未知'})
    key=('cam','run',1,'window')
    first=stage.accumulate(key,input_for(a))
    second=stage.accumulate(key,input_for(b))
    assert first.version_id!=second.version_id
    assert second.parent_version_id==first.version_id
    assert stage.accumulate(key,input_for(b)) is second
    assert any('门状态未知' in i.text for i in second.items)
    assert any('人物去向未知' in i.text for i in second.items)


def test_absent_unknown_does_not_change_legacy_fingerprint():
    b=branch({'observation':'门口'})
    assert b.model_unknown is None
    rows=l3_fingerprint_rows(b)
    class Legacy:
        pass
    old=Legacy()
    for name in b.__slots__:
        if name!='model_unknown':
            setattr(old,name,getattr(b,name))
    assert l3_fingerprint_rows(old)==rows
    assert not any(b'l3unknown' in row for row in rows)


def test_real_event_bridge_sqlite_and_workbench_detail_keep_unknown(tmp_path):
    """Synthetic perception, real tracker/binding/L4 worker/SQLite/detail reader."""
    from scam import nvr
    from scam.monitor import Monitor, to_gray
    from scam.sinks import SqliteSink
    from scam.win11_pipeline import L1Task, L1Result
    from scam.win11_event_progress import EventProgress
    from scam.win11_l2_runtime import L2Runtime
    from scam.win11_l4_contract import FusionFrameRef
    path=str(tmp_path/'events.db')
    sink=SqliteSink(path)
    bridge=EventProgress(path)
    runtime=L2Runtime(['cam'],None,None)
    monitor=Monitor({'id':'cam','zones':[],'grid':{}},None,[sink],
        run_id='run',detection_mode='async')
    monitor.timestamp_kind='host_receive'
    image=np.zeros((16,24,3),dtype=np.uint8)
    try:
        for fid,t in ((1,1000),(2,1100)):
            task=L1Task('cam','run',fid,t,image,'patrol',[],24,16,
                monitor.zone_revision,False)
            result=L1Result(task,[{'cls':'person','conf':0.9,
                'bbox':[0.2,0.2,0.15,0.3]}],'ok',None,['person'],0,0)
            monitor.apply_detection_result(result,t)
            monitor.step(image,to_gray(image),t)
            conclusion=monitor.consume_conclusion()
            assert conclusion['accepted']
            assert bridge.record_conclusion(monitor,conclusion)
        event=monitor._event_facts[1]['event_id']
        b=branch({'observation':'人物在门口','inference':'可能进入室内',
            'unknown':'去向无法确认'},cfg=monitor.zone_revision,
            fid=2,t=1100,clock='host_receive')
        fusion=L4Stage('cam','run',monitor.zone_revision).fuse(FusionInput(
            'cam','run',monitor.zone_revision,'window',l3_branches=[b],
            l1_object_refs=[monitor._object_id(1)],
            clock_kinds=['host_receive'],
            frame_refs=[FusionFrameRef('2',1100,'host_receive')]))
        bridge.start()
        assert bridge.submit(runtime._l4_history_payload(
            ('cam','run',monitor.zone_revision,'window'), fusion))
        assert bridge.close(timeout=5)
        assert bridge.snapshot()['counts'].get('appended')==1, (bridge.snapshot(), bridge.unassociated())
        detail=nvr.WorkbenchState(path).event_fact_detail(event)
        latest=detail['descriptions'][-1]
        assert '模型未确认：去向无法确认' in latest['text']
        assert '可能进入室内' in latest['text']  # not rewritten to a fact or erased
        assert latest['uncertainty']=='high'
        assert latest['model_id']=='l4-fusion'
        stored=sink.conn.execute('SELECT payload FROM event_descriptions '
            'WHERE event_id=? ORDER BY version DESC LIMIT 1',(event,)).fetchone()
        payload=json.loads(stored['payload'])
        unknowns=[i for i in payload['items'] if '去向无法确认' in i['text']]
        assert len(unknowns)==1 and unknowns[0]['certainty']=='unknown'
    finally:
        runtime.stop()
        bridge.close(timeout=5)
        sink.conn.close()
