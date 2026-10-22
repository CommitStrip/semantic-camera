"""L3 branch exports and summaries must retain model unknowns without upgrading."""
import json
import numpy as np
import pytest
from scam.win11_l3 import L3Stage
from scam.win11_l3_contract import (
    L3Task,L3FrameInput,L3FrameIdentity,L3WindowIdentity,L3BranchKind)
from scam.win11_l3_tasks import results_from_output,summary_text


def output(payload):
    class Model:
        model_ref='test/export'
        def understand_frames(self,*args):
            return payload
    window=L3WindowIdentity('cam','run',1,'window',material_id=9)
    frame=L3FrameInput(L3BranchKind.PANORAMA,
        L3FrameIdentity('cam','run',1,0),0,'observed',
        np.zeros((4,6,3),dtype=np.uint8))
    return L3Stage(Model()).process(L3Task(window,L3BranchKind.PANORAMA,
        [frame],prompt='检查可见事实。'))


def test_saved_branch_and_summary_retain_unknown_and_source():
    out=output({'observation':'人物离开画面','inference':'可能进入房屋',
        'unknown':'人物去向无法确认'})
    row=results_from_output(out)[0]
    assert row['model_unknown']=={'text':'人物去向无法确认','certainty':'unknown'}
    assert row['inference']['certainty']=='model_inferred'
    assert row['branch_key']==['cam','run',1,'window','panorama',None,9]
    assert row['sources'][0]['frame_id']==0
    assert row['sources'][0]['timestamp_kind']=='observed'
    assert json.loads(json.dumps(row,ensure_ascii=False))==row
    assert '模型未确认：人物去向无法确认' in summary_text(out)


def test_unknown_only_is_not_reported_as_no_text_result():
    out=output({'unknown':'门是否打开未知'})
    text=summary_text(out)
    assert '模型未确认：门是否打开未知' in text
    assert '（无文本结果）' not in text


def test_absent_unknown_keeps_legacy_export_keys_and_summary():
    out=output({'observation':'门口','inference':'变化未知'})
    row=results_from_output(out)[0]
    assert 'model_unknown' not in row
    assert '模型未确认' not in summary_text(out)
    assert row['observation']['text']=='门口'
    assert row['inference']['text']=='变化未知'


def test_unknown_summary_is_bounded_and_newlines_folded_but_export_complete():
    unknown=('无法确认\n'*300)
    out=output({'unknown':unknown})
    row=results_from_output(out)[0]
    assert row['model_unknown']['text']==unknown
    text=summary_text(out)
    assert '\n' not in text and '…' in text and len(text)<400


@pytest.mark.parametrize('unknown',[False,0,{'door':'unknown'},['去向未知']])
def test_json_unknown_retained_as_canonical_text(unknown):
    out=output({'unknown':unknown})
    value=results_from_output(out)[0]['model_unknown']
    assert json.loads(value['text'])==unknown
    assert value['certainty']=='unknown'


def test_real_store_reload_and_existing_workbench_view_keep_unknown(tmp_path):
    from scam.win11_understanding_store import UnderstandingStore
    from scam.server import enrich_understanding_view
    root=tmp_path/'understanding'
    store=UnderstandingStore(root=str(root))
    out=output({'observation':'人物离开画面','inference':'去向未明',
        'unknown':'不能确认进入房屋'})
    record={'window_key':['cam','run',1,'window'],'run_id':'run',
        'config_version':1,'window':'window','status':'ok',
        'results':results_from_output(out),'at':1.0}
    assert store.append('cam','l3',record)
    reloaded=UnderstandingStore(root=str(root))
    assert reloaded.history('cam','l3')[0]['results'][0]['model_unknown'][
        'text']=='不能确认进入房屋'
    summarized=reloaded.summary('cam')
    row=summarized['branches'][0]
    assert '模型未确认：不能确认进入房屋' in row['text']
    assert set(row)=={'branch_key','kind','status','text','sources','missing'}
    view=enrich_understanding_view('cam',reloaded,summarized,lambda _:False,
        current_identity={'run_id':'run','config_version':1})
    assert '模型未确认：不能确认进入房屋' in view['branches'][0]['text']
    assert view['branches'][0]['certainty_label']=='模型推断'
