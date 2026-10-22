"""Sparse supplied frames are not a complete continuous movie."""
from types import SimpleNamespace
import numpy as np
import pytest
from scam.win11_l3_tasks import _prompt_for_branch,_fallback_prompt
from scam.win11_l3_contract import (
    L3BranchKind,L3Task,L3FrameInput,L3FrameIdentity,L3WindowIdentity)
from scam.win11_l3 import L3Stage

@pytest.mark.parametrize('kind',list(L3BranchKind))
def test_production_branch_prompt_does_not_assert_continuity_or_fill_gaps(kind):
    branch=SimpleNamespace(crop_id='crop' if kind!=L3BranchKind.PANORAMA else None,
        crop_ref=SimpleNamespace(bbox_norm=(0.1,0.2,0.3,0.4)))
    prompt=_prompt_for_branch(branch,kind,vocabulary_id=None,vocabulary=())
    assert '采样帧' in prompt
    assert '连续全景帧' not in prompt and '连续三帧' not in prompt
    assert '不能视为连续录像' in prompt
    assert '不得补全' in prompt
    assert '"unknown"' in prompt
    if kind!=L3BranchKind.PANORAMA:
        assert '不保证同一对象' in prompt
        assert '不代表全景' in prompt

@pytest.mark.parametrize('missing',[False,True])
def test_fallback_prompt_also_requests_unknown_and_honest_sampling(missing):
    frames=[SimpleNamespace(frame_bgr=None if missing and i==1 else object())
        for i in range(3)]
    prompt=_fallback_prompt(frames,'l1_pending',vocabulary_id=None,vocabulary=())
    assert 'l1_pending' in prompt
    assert '采样帧' in prompt and '不能视为连续录像' in prompt
    assert '"unknown"' in prompt
    if missing:
        assert '缺失序位：1' in prompt

def test_sparse_stage_call_retains_actual_timestamps_and_sampling_prompt():
    calls=[]
    class Model:
        model_ref='test/sampling'
        def understand_frames(self,prompt,frames,meta):
            calls.append((prompt,meta))
            return {'observation':'采样画面','unknown':'间隔内经过未知'}
    frames=[L3FrameInput(L3BranchKind.PANORAMA,L3FrameIdentity('c','r',0,fid),
        fid*1000/30,'video_pts',np.zeros((4,6,3),dtype=np.uint8))
        for fid in (0,149,480)]
    prompt=_prompt_for_branch(SimpleNamespace(crop_id=None),L3BranchKind.PANORAMA,
        vocabulary_id=None,vocabulary=())
    task=L3Task(L3WindowIdentity('c','r',0,1),L3BranchKind.PANORAMA,frames,prompt)
    out=L3Stage(Model()).process(task)
    sent,meta=calls[0]
    assert [m['frame_id'] for m in meta]==[0,149,480]
    assert [m['t_capture_ms'] for m in meta]==[0,149*1000/30,16000]
    assert '不能视为连续录像' in sent
    assert out.results[0].model_unknown=='间隔内经过未知'
