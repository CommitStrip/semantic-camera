"""Independent fixed C155 regressions; real task builder, tiny synthetic pixels.

No model/source/runtime started. C155-R1 fix: the plan→task API
(`tasks_from_package(..., plan_frames=...)`) now exists, so the event-mode
examples call the builder through it — the task frame set must be a
same-source, strictly-bound subset of the declared plan frames
(bound turning 122 preserved; unbound 120/437 never laundered in).
The unassociated standalone panorama path (test 3) keeps the old
carried_frames shape and must remain byte-compatible.
"""
from types import SimpleNamespace

import numpy as np
import pytest

from scam.win11_event_materials import EventMaterialPool, SequenceFrame, _merge_and_bound
from scam.win11_materials import MaterialFrame, MaterialPackage
from scam.win11_l3_tasks import tasks_from_package

CAM, RUN, CFG = 'integrity-cam', 'integrity-run', 0
EVENT, OBJECT = CAM + ':' + RUN + ':event:1', CAM + ':' + RUN + ':track:1'


def source(fid, time, window, material):
    return SequenceFrame(camera_id=CAM, run_id=RUN, config_version=CFG,
        window_id=window, window_key=(CAM,RUN,CFG,window), material_id=material,
        frame_id=str(fid), t_capture_ms=float(time), timestamp_kind='host_receive',
        frame_bgr=np.zeros((2,3,3),dtype=np.uint8), width=3,height=2,
        source_width=3,source_height=2,downscaled=False,material_reason='change_start',
        change_boxes=(),change_area=0.,origin='window_material',event_id=EVENT,
        object_id=OBJECT,track_id=1,bound=True,observed_mono_ms=None,crop_id=None)


def unbound(fid, time, window, material):
    """Local plan row without its own strict binding (context, not evidence)."""
    return SequenceFrame(camera_id=CAM, run_id=RUN, config_version=CFG,
        window_id=window, window_key=(CAM,RUN,CFG,window), material_id=material,
        frame_id=str(fid), t_capture_ms=float(time), timestamp_kind='host_receive',
        frame_bgr=np.zeros((2,3,3),dtype=np.uint8), width=3,height=2,
        source_width=3,source_height=2,downscaled=False,material_reason='change_start',
        change_boxes=(),change_area=0.,origin='window_material',event_id=None,
        object_id=None,track_id=None,bound=False,observed_mono_ms=None,crop_id=None)


def package(ids, times, material=10):
    fs=[MaterialFrame(str(fid),np.full((2,3,3),i,dtype=np.uint8),float(t),'host_receive')
        for i,(fid,t) in enumerate(zip(ids,times))]
    pkg=MaterialPackage(CAM,RUN,CFG,material,0.,fs[1],[],3,2)
    pkg.prev,pkg.nxt=fs[0],fs[2]
    return pkg


def build(pkg, window, carried=(), plan_frames=()):
    branch=SimpleNamespace(branch_kind='panorama',crop_id=None,
        identity=SimpleNamespace(camera_id=CAM,run_id=RUN,config_version=CFG,
                                 material_id=pkg.material_id))
    if plan_frames:
        # C155-R1 fixed shape: event task is sourced from the declared plan
        # frames (same-source strict-bound subset); carried re-merge is
        # mutually exclusive by contract.
        tasks=tasks_from_package(pkg=pkg,branches=(branch,),window_id=window,
            plan_frames=tuple(plan_frames),carried_frames=(),
            plan_event_key=(CAM,RUN,CFG,EVENT,OBJECT),
            carried_reason='change_start')
    else:
        tasks=tasks_from_package(pkg=pkg,branches=(branch,),window_id=window,
            carried_frames=tuple(carried),carried_limit=3,carried_reason='change_start')
    assert len(tasks)==1
    return tasks[0]


def present_ids(task):
    return [str(frame.identity.frame_id) for frame in task.frames if frame.frame_bgr is not None]


def test_plan9_verified_turning_122_is_not_replaced_by_unbound_120():
    """real-p7: declared [118,122,130] must not become [118,120,130]."""
    pkg=package((118,120,122),(1000,1017,1070))
    retained=[source(122,1070,4,10),source(130,13530,None,14)]
    rows=[dict(frame_id=str(fid),frame_bgr=None,t_capture_ms=float(t),
        timestamp_kind='host_receive',window_id=4,material_id=10,
        material_reason='change_start',change_boxes=(),event_id=EVENT,
        object_id=None,track_id=None) for fid,t in zip((118,120,122),(1000,1017,1070))]
    marked=EventMaterialPool._mark_primary_row_evidence(
        SimpleNamespace(frame_level_binding=True),rows,
        SimpleNamespace(frames=retained),primary_event_id=EVENT)
    expected,_,_=_merge_and_bound(marked,[retained[1]],window_key=(CAM,RUN,CFG,4),
        limit=3,window_id=4,material_id=10,primary_window_id=4)
    declared=[str(f.frame_id) for f in expected]
    assert '122' in declared and '120' not in declared
    # Same-source plan frames as the fixed production wiring passes them:
    # the declared local rows (118 unbound) plus the event-page retained
    # copies (122 bound turning, 130 bound carried), pixels included.
    plan=(unbound(118,1000,4,10),retained[0],retained[1])
    actual=present_ids(build(pkg,4,plan_frames=plan))
    assert set(actual)<=set(declared), (declared,actual)
    assert '122' in actual and '120' not in actual, (declared,actual)


def test_event_task33_does_not_mix_unbound_current_context_437():
    """Event-bound carried evidence cannot launder current unbound context."""
    pkg=package((336,437,438),(16000,20000,21000),material=24)
    pkg.nxt=None  # Fixed task-33 shape: 336 is bound, current 437 is not.
    # Declared plan frames for task-33: bound carried 214/230 plus the
    # unbound local current 437 (declared latest placeholder in real-p7).
    plan=(source(214,7000,6,12),source(230,7600,None,13),unbound(437,20000,9,24))
    # Only these frames have their own strict event binding in this fixed case.
    strict_ids={'214','230','336'}
    actual=present_ids(build(pkg,9,plan_frames=plan))
    assert actual, 'omitting the task is not evidence of a successful event input'
    assert set(actual)<=strict_ids, {'actual':actual,'unbound_context':set(actual)-strict_ids}
    assert '437' not in actual, actual


def test_independent_unassociated_panorama_context_remains_legal():
    """No event/carry claim: preserve the old standalone panorama path."""
    pkg=package((118,120,122),(1000,1017,1070))
    actual=present_ids(build(pkg,4))
    assert actual==['118','120','122']


def strict_build(frames, *, key=(CAM, RUN, CFG, EVENT, OBJECT), **kwargs):
    pkg = package((118,120,122),(1000,1017,1070))
    branch = SimpleNamespace(branch_kind='panorama', crop_id=None,
        identity=SimpleNamespace(camera_id=CAM,run_id=RUN,config_version=CFG,
                                 material_id=pkg.material_id))
    return tasks_from_package(pkg=pkg, branches=(branch,), window_id=4,
                              plan_frames=frames, plan_event_key=key, **kwargs)


@pytest.mark.parametrize('field,value', [
    ('camera_id','other-camera'), ('run_id','other-run'),
    ('config_version',9), ('event_id','other-event'),
    ('object_id','other-object'), ('window_key',('other-camera',RUN,CFG,4))])
def test_strict_event_plan_rejects_foreign_binding(field, value):
    frame = source(122,1070,4,10)
    setattr(frame, field, value)
    with pytest.raises(ValueError, match='identity'):
        strict_build((frame,))


def test_explicit_empty_event_plan_never_falls_back_to_package():
    with pytest.raises(ValueError, match='bound'):
        strict_build(())


def test_event_plan_key_is_required_not_inferred_from_frame():
    with pytest.raises(ValueError, match='key'):
        strict_build((source(122,1070,4,10),), key=None)


def test_legacy_fallback_cannot_ignore_event_plan():
    pkg = package((118,120,122),(1000,1017,1070))
    with pytest.raises(ValueError, match='fallback'):
        tasks_from_package(pkg=pkg, window_id=4, fallback_reason='empty',
                           plan_frames=(source(122,1070,4,10),))


def test_valid_strict_event_plan_keeps_exact_order_and_pixels():
    frames = (source(122,1070,4,10), source(130,13530,None,14))
    task, = strict_build(frames)
    assert present_ids(task) == ['122','130']
    for sent, original in zip(task.frames, frames):
        np.testing.assert_array_equal(sent.frame_bgr, original.frame_bgr)


def test_runtime_selector_distinguishes_empty_event_plan_from_independent():
    from scam.win11_l2_runtime import L2Runtime
    assert L2Runtime._event_task_frames(SimpleNamespace(aggregated=True,frames=())) == ()
    assert L2Runtime._event_task_frames(SimpleNamespace(aggregated=False,frames=())) is None
    assert L2Runtime._event_task_frames(None) is None
