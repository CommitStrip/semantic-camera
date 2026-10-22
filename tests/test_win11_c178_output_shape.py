"""Malformed real-model JSON must not crash L4 or impersonate valid fields."""
import json
import numpy as np
import pytest
from scam.win11_l3 import L3Stage, _split_model_output
from scam.win11_l3_contract import (
    L3Task, L3FrameInput, L3FrameIdentity, L3WindowIdentity, L3BranchKind)
from scam.win11_l4 import L4Stage
from scam.win11_l4_contract import FusionInput, fusion_version_to_json


def fuse_output(output):
    class Model:
        model_ref='test/shape'
        def understand_frames(self,*args):
            return output
    window=L3WindowIdentity('cam','run',1,'window')
    frame=L3FrameInput(L3BranchKind.PANORAMA,
        L3FrameIdentity('cam','run',1,0),0,'observed',
        np.zeros((4,6,3),dtype=np.uint8))
    branch=L3Stage(Model()).process(L3Task(window,L3BranchKind.PANORAMA,
        [frame],prompt='检查画面。')).results[0]
    version=L4Stage('cam','run',1).fuse(FusionInput('cam','run',1,'window',
        l3_branches=[branch],clock_kinds=['observed']))
    return branch,version


def test_actual_array_response_is_retained_and_fusable():
    # Actual C177 response shape; its visual statements are not verified facts.
    raw={'observation':[{'frame':1,'person':'no visible person','action':'no action'},
        {'frame':2,'person':'no visible person','action':'no action'},
        {'frame':3,'person':'no visible person','action':'no action'}],
        'inference':'no visible changes in the scene between frames 1 and 2, '
        'and no visible changes between frames 2 and 3.'}
    branch,version=fuse_output(raw)
    assert branch.unstructured is True
    assert isinstance(branch.observation,str)
    assert json.loads(branch.observation)==raw
    assert branch.inference is None
    item=next(i for i in version.items if i.kind=='observation')
    assert item.certainty=='model_inferred' and item.unstructured is True
    assert item.sources[0].kind=='l3_branch'
    assert json.loads(item.text)==raw
    json.dumps(fusion_version_to_json(version),ensure_ascii=False)


@pytest.mark.parametrize('field',['observation','inference'])
@pytest.mark.parametrize('bad',[[],{'text':'door'},False,0,2.5])
def test_nontext_structured_fields_do_not_enter_fusion_as_objects(field,bad):
    raw={'observation':'门口','inference':'未确认',field:bad,
        'unknown':'去向未知'}
    branch,version=fuse_output(raw)
    assert branch.unstructured is True
    assert json.loads(branch.observation)==raw
    assert branch.inference is None
    assert branch.model_unknown=='去向未知'
    assert any(i.kind=='gap' and i.certainty=='unknown'
        and '去向未知' in i.text for i in version.items)


@pytest.mark.parametrize('value',[[],{},False,0])
def test_nontext_text_wrapper_is_preserved_without_fusion_error(value):
    branch,version=fuse_output({'text':value})
    assert branch.unstructured is True
    assert json.loads(branch.observation)==value
    assert branch.inference is None
    json.dumps(fusion_version_to_json(version))


@pytest.mark.parametrize('raw',[
    {'observation':'门口','inference':'未知'},
    {'observation':None,'inference':'未知'},
    {'unknown':'无法确认'},
])
def test_valid_structured_text_and_unknown_only_remain_compatible(raw):
    observation,inference,unstructured=_split_model_output(raw)
    assert observation==raw.get('observation')
    assert inference==raw.get('inference')
    assert unstructured is False


def test_plain_text_is_not_rewritten():
    value='  原始文本\n保留格式  '
    assert _split_model_output(value)==(value,None,True)
