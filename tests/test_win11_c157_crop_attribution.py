"""Independent crop attribution contracts. Synthetic pixels, no model/service.

Intentional red tests preserve demonstrated boundary defects, not xfail/skip.
Event labels below are fixture ground truth; L2 schema currently has no event key.
"""
import numpy as np
import pytest
from types import SimpleNamespace

from scam.win11_event_materials import SequenceFrame
from scam.win11_l2_contract import (FrameIdentity, L2TaskInput, L2Budget,
    L2RelationStage, ObjectRef, RelationCandidate, Uncertainty)
from scam.win11_l2_crops import (CropRequest, build_candidate_crops,
                               norm_box_to_px, slice_region)
from scam.win11_l3_tasks import tasks_from_package
from scam.win11_materials import MaterialFrame, MaterialPackage

CAM,RUN,CFG='crop-cam','crop-run',0

def image(tag):
    y,x=np.indices((24,32))
    return np.stack((np.full_like(x,tag),x,y),axis=2).astype(np.uint8)

def scene(window, tag):
    ids=[window*100+i for i in (1,2,3)]
    frames=[MaterialFrame(fid,image(tag+i),float(fid)*100,'host_receive')
            for i,fid in enumerate(ids)]
    pkg=MaterialPackage(CAM,RUN,CFG,window,0.,frames[1],[],32,24)
    pkg.prev,pkg.nxt=frames[0],frames[2]
    def task(fr):
        identity=FrameIdentity(CAM,RUN,CFG,fr.frame_id,window,
                               fr.t_capture_ms,fr.timestamp_kind)
        return L2TaskInput(identity,fr.frame_bgr,32,24,(), 'ok',(),
            None,None,None,None,'crop-v1',('near',),L2Budget())
    current=task(frames[1])
    current.prev,current.next=task(frames[0]),task(frames[2])
    current.prev_gap_ms=current.next_gap_ms=100.
    refs=[ObjectRef(f'{CAM}:{RUN}:track:{window*10+i}',ids[1],True)
          for i in (1,2)]
    candidate=RelationCandidate(refs[0],refs[1],'near','spatial',.9,'crop-v1',Uncertainty())
    request=CropRequest(candidate,(.2,.2,.1,.1),(.35,.2,.1,.1))
    records,images,dropped,notes=build_candidate_crops(
        current.frame_bgr,32,24,current.identity,(request,),L2Budget())
    assert len(records)==len(images)==1 and dropped==0,notes
    stage=L2RelationStage(model=None)
    branch,=stage._build_l3_branches(current,records,(candidate,),{})
    return pkg,current,branch,records[0],images[0],request

def build(pkg,branch,window=1,**kwargs):
    return tasks_from_package(pkg=pkg,branches=(branch,),window_id=window,**kwargs)

def event_plan(pkg):
    fr=pkg.cur
    event=f'{CAM}:{RUN}:event:1'
    obj=f'{CAM}:{RUN}:track:11'
    source=SequenceFrame(camera_id=CAM,run_id=RUN,config_version=CFG,
        window_id=1,window_key=(CAM,RUN,CFG,1),material_id=pkg.material_id,
        frame_id=fr.frame_id,t_capture_ms=fr.t_capture_ms,timestamp_kind=fr.timestamp_kind,
        frame_bgr=fr.frame_bgr,width=32,height=24,source_width=32,source_height=24,
        downscaled=False,material_reason='change_start',change_boxes=(),change_area=0.,
        origin='window_material',event_id=event,object_id=obj,track_id=11,bound=True,
        observed_mono_ms=None,crop_id=None)
    return dict(plan_frames=(source,),plan_event_key=(CAM,RUN,CFG,event,obj))

@pytest.mark.parametrize('window,tag',[(1,17),(2,199)])
def test_production_crop_to_task_preserves_source_pixels_and_crop_id(window,tag):
    pkg,current,branch,record,crop,_=scene(window,tag)
    task,=build(pkg,branch,window)
    assert task.crop_id==record.crop_id==branch.crop_id
    assert (task.window.camera_id,task.window.run_id,task.window.config_version)==(CAM,RUN,0)
    assert {p.object_id for p in record.participants}=={
        f'{CAM}:{RUN}:track:{window*10+1}',f'{CAM}:{RUN}:track:{window*10+2}'}
    for sent,fr in zip(task.frames,(pkg.prev,pkg.cur,pkg.nxt)):
        px=norm_box_to_px(record.transform.bbox_norm,fr.width,fr.height)
        x1,y1,x2,y2=px
        np.testing.assert_array_equal(sent.frame_bgr,fr.frame_bgr[y1:y2,x1:x2,:])
        assert sent.identity.frame_id==fr.frame_id
    np.testing.assert_array_equal(task.frames[1].frame_bgr,crop)
    assert all(s.crop_id==record.crop_id for s in branch.frame_sequence)

@pytest.mark.parametrize('field,value',[('camera_id','other'),('run_id','other'),
    ('config_version',9),('material_id',9)])
def test_branch_package_foreign_identity_is_rejected(field,value):
    pkg,_,branch,_,_,_=scene(1,17)
    setattr(branch.identity,field,value)
    with pytest.raises(ValueError):
        build(pkg,branch)

def test_missing_adjacent_crops_remain_absent():
    pkg,current,_,record,_,_=scene(1,17)
    current.prev=current.next=None
    branch,=L2RelationStage(None)._build_l3_branches(current,(record,),(),{})
    task,=build(pkg,branch)
    assert [f.frame_bgr is not None for f in task.frames]==[False,True,False]

@pytest.mark.parametrize('box',[(0,0,0,5),(30,20,50,50),(-5,-7,5,6)])
def test_pixel_crop_empty_or_clamped_matches_real_slice(box):
    arr=image(17)
    result=slice_region(arr,box)
    x1,y1,x2,y2=box
    x1,x2=max(0,min(x1,32)),max(0,min(x2,32))
    y1,y2=max(0,min(y1,24)),max(0,min(y2,24))
    if x2<=x1 or y2<=y1:
        assert result is None
    else:
        np.testing.assert_array_equal(result,arr[y1:y2,x1:x2,:])
        assert not np.shares_memory(result,arr)

@pytest.mark.parametrize('budget,reason',[
    (L2Budget(max_crop_pixels_fixed=1),'crop_pixels_cap'),
    (L2Budget(max_crop_bytes=1),'crop_bytes_cap'),
    (L2Budget(max_crop_area_ratio=.001),'crop_area_ratio_cap'),
    (L2Budget(max_crops_total=0),'budget_cap')])
def test_relation_crop_real_budget_rejects_with_reason(budget,reason):
    _,current,_,_,_,request=scene(1,17)
    records,images,dropped,notes=build_candidate_crops(current.frame_bgr,32,24,
        current.identity,(request,),budget)
    assert not records and not images and dropped==1 and reason in notes

def test_foreign_event_sequence_cannot_be_relabelled_as_current_crop():
    pkg,_,a,_,_,_=scene(1,17)
    _,_,b,_,_,_=scene(2,199)
    # Actual production slices from another event/window, not fabricated arrays.
    a.frame_sequence=b.frame_sequence
    with pytest.raises(ValueError):
        build(pkg,a,**event_plan(pkg))

def test_event_local_task_cannot_mix_unbound_context_frames():
    pkg,_,branch,_,_,_=scene(1,17)
    tasks=build(pkg,branch,**event_plan(pkg))
    actual=[f.identity.frame_id for t in tasks for f in t.frames if f.frame_bgr is not None]
    assert actual and set(actual)<={pkg.cur.frame_id}, {'actual':actual,'strict':[pkg.cur.frame_id]}

def test_legacy_crop_map_cannot_accept_foreign_event_pixels_under_current_key():
    pkg,_,a,_,_,_=scene(1,17)
    _,_,_,_,b_pixels,_=scene(2,199)
    a.frame_sequence=()
    with pytest.raises(ValueError):
        build(pkg,a,crop_images_by_crop_id={a.crop_id:b_pixels},**event_plan(pkg))


def test_legacy_independent_crop_map_still_works_without_event_claim():
    pkg,_,a,_,pixels,_=scene(1,17)
    a.frame_sequence=()
    task,=build(pkg,a,crop_images_by_crop_id={a.crop_id:pixels})
    assert [f.frame_bgr is not None for f in task.frames]==[False,True,False]
    np.testing.assert_array_equal(task.frames[1].frame_bgr,pixels)


def test_event_local_valid_bound_current_pixels_and_crop_are_preserved():
    pkg,_,branch,record,pixels,_=scene(1,17)
    task,=build(pkg,branch,**event_plan(pkg))
    assert len(task.frames)==1 and task.frames[0].identity.frame_id==102
    assert task.crop_id==record.crop_id
    np.testing.assert_array_equal(task.frames[0].frame_bgr,pixels)


@pytest.mark.parametrize('field,value',[('crop_id','foreign-crop'),
    ('frame_id',999),('t_capture_ms',-1),('timestamp_kind','foreign-clock'),
    ('position',8),('present',False)])
def test_slice_source_metadata_rejects_inconsistent_shape(field,value):
    pkg,_,branch,_,_,_=scene(1,17)
    setattr(branch.frame_sequence[1],field,value)
    with pytest.raises(ValueError):
        build(pkg,branch,**event_plan(pkg))


def test_duplicate_slice_positions_rejected():
    pkg,_,branch,_,_,_=scene(1,17)
    branch.frame_sequence[2].position=1
    with pytest.raises(ValueError):
        build(pkg,branch)


def test_event_crop_rejects_foreign_pixels_despite_matching_slice_labels():
    pkg,_,branch,_,_,_=scene(1,17)
    _,_,foreign,_,_,_=scene(2,199)
    branch.frame_sequence[1].frame_bgr=foreign.frame_sequence[1].frame_bgr
    with pytest.raises(ValueError,match='pixels'):
        build(pkg,branch,**event_plan(pkg))


def test_event_crop_cannot_borrow_other_object_participant():
    pkg,_,branch,_,_,_=scene(1,17)
    _,_,foreign,_,_,_=scene(2,199)
    branch.candidates=foreign.candidates
    with pytest.raises(ValueError,match='participant'):
        build(pkg,branch,**event_plan(pkg))


@pytest.mark.parametrize('key_index,value',[(0,'foreign'),(1,'foreign'),(2,7),
    (3,'foreign-event'),(4,'foreign-object')])
def test_event_local_complete_key_is_checked(key_index,value):
    pkg,_,branch,_,_,_=scene(1,17)
    options=event_plan(pkg)
    key=list(options['plan_event_key'])
    key[key_index]=value
    options['plan_event_key']=tuple(key)
    with pytest.raises(ValueError):
        build(pkg,branch,**options)


@pytest.mark.parametrize('frames',[(),None])
def test_event_local_explicit_empty_or_missing_plan_is_rejected(frames):
    pkg,_,branch,_,_,_=scene(1,17)
    options=event_plan(pkg)
    options['plan_frames']=frames
    with pytest.raises(ValueError):
        build(pkg,branch,**options)


def test_pool_string_frame_id_matches_same_integer_slice_id():
    pkg,_,branch,_,pixels,_=scene(1,17)
    options=event_plan(pkg)
    options['plan_frames'][0].frame_id=str(pkg.cur.frame_id)
    task,=build(pkg,branch,**options)
    assert task.frames[0].identity.frame_id==102
    np.testing.assert_array_equal(task.frames[0].frame_bgr,pixels)


def test_boolean_slice_frame_id_is_not_an_integer_frame_identity():
    pkg,_,branch,_,_,_=scene(1,17)
    branch.frame_sequence[1].frame_id=False
    with pytest.raises(ValueError):
        build(pkg,branch)


def test_event_local_zero_frame_id_remains_legal():
    pkg,_,branch,_,pixels,_=scene(1,17)
    pkg.cur.frame_id=0
    branch.identity.frame_id=0
    branch.frame_sequence[1].frame_id=0
    for candidate in branch.candidates:
        candidate.subject.frame_id=candidate.obj.frame_id=0
    options=event_plan(pkg)
    options['plan_frames'][0].frame_id='0'
    task,=build(pkg,branch,**options)
    assert task.frames[0].identity.frame_id==0
    np.testing.assert_array_equal(task.frames[0].frame_bgr,pixels)


def test_rejected_local_keeps_valid_panorama_and_visible_diagnostic():
    pkg,_,bad,_,_,_=scene(1,17)
    _,_,foreign,_,_,_=scene(2,199)
    bad.frame_sequence=foreign.frame_sequence
    panorama=SimpleNamespace(branch_kind='panorama',identity=bad.identity,crop_id=None)
    diagnostics=[]
    tasks=tasks_from_package(pkg=pkg,branches=(panorama,bad),window_id=1,
        material_selection_out=diagnostics.append,**event_plan(pkg))
    assert len(tasks)==1 and tasks[0].branch.value=='panorama'
    assert diagnostics[0]['rejected_branches'][0]['status']=='input_rejected'
    assert diagnostics[0]['rejected_branches'][0]['crop_id']==bad.crop_id
    assert diagnostics[0]['rejected_branches'][0]['reason']


def test_runtime_local_rejection_does_not_leave_pending_window():
    from scam.win11_l2_runtime import L2Runtime
    from scam.win11_l3_contract import L3Budget
    from scam.win11_materials import MaterialsStore
    pkg,_,bad,_,_,_=scene(1,17)
    _,_,foreign,_,_,_=scene(2,199)
    bad.frame_sequence=foreign.frame_sequence
    runtime=L2Runtime([CAM],MaterialsStore(clock=lambda:0.),L2RelationStage(None),
        l3_stage=SimpleNamespace(budget=L3Budget()),mono_clock=lambda:0.)
    runtime.set_camera_identity(CAM,RUN,CFG)
    settled=[]
    completed=[]
    handle=SimpleNamespace(camera_id=CAM,packages=(pkg,),window_id=1,
        mark_window_settled=lambda:settled.append(True),
        mark_branch_done=lambda k:completed.append(k))
    key=runtime._register_window(handle)
    plan=event_plan(pkg)
    runtime._plan_event_materials=lambda *a,**k:SimpleNamespace(
        aggregated=True,frames=plan['plan_frames'],event_key=plan['plan_event_key'],limit=3,
        as_ledger=lambda:{'status':'aggregated'})
    panorama=SimpleNamespace(branch_kind='panorama',identity=bad.identity,crop_id=None)
    output=SimpleNamespace(l3_branches=(panorama,bad),crop_images=(),crops=(),candidates=())
    runtime._maybe_enqueue_l3(CAM,pkg,output,key)
    assert len(runtime._l3_queues[CAM])==1
    rejection_key=key+('relation_crop',bad.crop_id,pkg.material_id)
    assert runtime._open_windows[key]['branches'][rejection_key]=='input_rejected'
    assert runtime.last_material_selection(key)['selection']['rejected_branches']
    runtime._seal_window(key)
    assert not settled  # Valid panorama is still honestly pending.
    task,context=runtime._l3_dequeue()
    assert task.branch.value=='panorama'
    runtime._settle_branch_terminal(CAM,key,context['branch_key'],'stop_cancelled')
    assert settled==[True] and key not in runtime._open_windows
    assert len(completed)==2
    assert runtime._counts[CAM].get('settled_branch_ok',0)==0
