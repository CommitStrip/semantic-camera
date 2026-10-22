"""Real cloud backend/Stage/fusion/fact bridge/SQLite/loopback detail API.

Only external HTTP response and source perception/pixels are synthetic. No API
uploads, real camera, model quality or WPF evidence is claimed.
"""
import http.client
import io
import json
import threading
from urllib.parse import quote

import numpy as np
import pytest


@pytest.mark.parametrize('mode',['ok','timeout'])
def test_cloud_result_survives_to_bound_event_detail_or_honest_failure(tmp_path,monkeypatch,mode):
    from scam import nvr,models
    from scam.monitor import Monitor,to_gray
    from scam.sinks import SqliteSink
    from scam.win11_pipeline import L1Task,L1Result
    from scam.win11_materials import MaterialsStore
    from scam.win11_l3_cloud import CloudOpenAICompatibleL3Provider
    from scam.win11_l3_contract import L3Task,L3FrameInput,L3FrameIdentity,L3WindowIdentity,L3BranchKind
    from scam.win11_l4_contract import FusionInput,FusionFrameRef
    from scam.server import WorkbenchState,WorkbenchServer
    calls=[]
    monkeypatch.setattr(models,'_resolve_ips',lambda host:{'8.8.8.8'})
    monkeypatch.setenv('SC_C192_ONLY','synthetic-key-never-uploaded')
    def fake_http(self,request,timeout):
        payload=json.loads(request.data)
        calls.append(payload)
        assert request.full_url=='https://vision.example.invalid/v1/chat/completions'
        if mode=='timeout':
            raise TimeoutError('synthetic remote timeout')
        answer=json.dumps({'observation':'人物在门口','inference':'可能进入室内',
                           'unknown':'去向无法确认'},ensure_ascii=False)
        return io.BytesIO(json.dumps({'choices':[{'message':{'content':answer}}]},
                                     ensure_ascii=False).encode('utf-8'))
    monkeypatch.setattr(CloudOpenAICompatibleL3Provider,'_transport_call',fake_http)
    path=str(tmp_path/'events.db')
    sink=SqliteSink(path)
    monitor=Monitor({'id':'cam','zones':[],'grid':{}},None,[sink],run_id='run',detection_mode='async')
    monitor.timestamp_kind='host_receive'
    cfg={'enabled':True,'provider':'cloud','base_url':'https://vision.example.invalid/v1',
         'model':'test-vision-model','key_env':'SC_C192_ONLY',
         'image_upload_consent':True,'vision_capable':True}
    runtime=nvr._build_l2_runtime({},MaterialsStore(),['cam'],l3_cfg=cfg,db_path=path)
    bridge=runtime.event_progress
    server=None;thread=None
    image=np.zeros((16,24,3),dtype=np.uint8)
    try:
        assert bridge is not None and runtime.l4_factory is not None
        for fid,t in ((1,1000),(2,1100)):
            task=L1Task('cam','run',fid,t,image,'patrol',[],24,16,monitor.zone_revision,False)
            result=L1Result(task,[{'cls':'person','conf':0.9,'bbox':[.2,.2,.15,.3]}],
                            'ok',None,['person'],0,0)
            monitor.apply_detection_result(result,t)
            monitor.step(image,to_gray(image),t)
            conclusion=monitor.consume_conclusion()
            assert conclusion['accepted'] and bridge.record_conclusion(monitor,conclusion)
        event=monitor._event_facts[1]['event_id']
        window=L3WindowIdentity('cam','run',monitor.zone_revision,'window')
        frame=L3FrameInput(L3BranchKind.PANORAMA,
            L3FrameIdentity('cam','run',monitor.zone_revision,2),1100,'host_receive',image)
        output=runtime.l3_stage.process(L3Task(window,L3BranchKind.PANORAMA,[frame],prompt='只描述所给帧。'))
        assert len(calls)==1
        assert any(row['type']=='image_url' for row in calls[0]['messages'][0]['content'])
        b=output.results[0]
        if mode=='ok':
            assert b.model_unknown=='去向无法确认'
        else:
            assert b.status.value not in ('ok','partial')
            assert b.observation is None and b.inference is None and b.model_unknown is None
        fusion=runtime.l4_factory('cam','run',monitor.zone_revision).fuse(FusionInput(
            'cam','run',monitor.zone_revision,'window',l3_branches=[b],
            l1_object_refs=[monitor._object_id(1)],clock_kinds=['host_receive'],
            frame_refs=[FusionFrameRef('2',1100,'host_receive')]))
        bridge.start()
        assert bridge.submit(runtime._l4_history_payload(('cam','run',monitor.zone_revision,'window'),fusion))
        assert bridge.close(timeout=5)
        assert bridge.snapshot()['counts'].get('appended')==1
        server=WorkbenchServer(WorkbenchState(path),host='127.0.0.1',port=0)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
        try:
            conn.request('GET','/api/v2/events/'+quote(event,safe=''))
            response=conn.getresponse()
            assert response.status==200
            detail=json.loads(response.read())
        finally:conn.close()
        latest=detail['descriptions'][-1]
        stored=sink.conn.execute('SELECT payload,evidence_refs FROM event_descriptions WHERE event_id=? '
                                'ORDER BY version DESC LIMIT 1',(event,)).fetchone()
        payload=json.loads(stored['payload'])
        assert latest['model_id']=='l4-fusion'
        assert payload['identity']['camera_id']=='cam' and payload['identity']['run_id']=='run'
        assert payload['identity']['config_version']==monitor.zone_revision and payload['window_id']=='window'
        evidence_refs=json.loads(stored['evidence_refs'])
        assert len(evidence_refs)==1
        evidence=evidence_refs[0]
        assert (evidence['frame_id'],evidence['t_ms'],evidence['time_kind'])==('2',1100,'host_receive')
        assert latest['evidence_refs']==evidence_refs
        assert detail['event_id']==event
        if mode=='ok':
            unknown_items=[i for i in payload['items'] if '去向无法确认' in i['text']]
            assert unknown_items and all(s['kind']=='l3_branch' for i in unknown_items for s in i['sources'])
        if mode=='ok':
            assert '模型未确认：去向无法确认' in latest['text']
            assert '可能进入室内' in latest['text']
            assert latest['uncertainty']=='high'
            assert any(i['certainty']=='unknown' and '去向无法确认' in i['text'] for i in payload['items'])
        else:
            assert '可能进入室内' not in latest['text'] and '人物在门口' not in latest['text']
            assert any(i['kind']=='gap' for i in payload['items'])
    finally:
        if server:
            server.shutdown();server.server_close()
        if thread:thread.join(timeout=3)
        runtime.stop()
        sink.conn.close()
