"""Assessments + the workflow engine.

The engine enforces the RiskVision discipline modernized in the playbooks:
each stage is a two-phase gate — an **actor** submits for review, then a
**different** user holding the approver role advances it. The submitter can
never approve their own work (separation of duty), and every gate action is
written to the append-only Transition + AuditLog tables.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlmodel import Session, select

from ..database import get_session
from ..models import (
    Assessment,
    Catalog,
    Control,
    ControlResult,
    Entity,
    Finding,
    Transition,
    User,
    WorkflowStage,
    WorkflowTemplate,
)
from ..security import audit, flash, has_role, require_user, roles_for
from ..templating import render

router = APIRouter()

RESULT_STATUSES = ["implemented", "partial", "planned", "not_implemented", "not_applicable"]


# --------------------------------------------------------------------------- #
# Engine helpers
# --------------------------------------------------------------------------- #
def get_stages(session: Session, template_id: int) -> list[WorkflowStage]:
    return session.exec(
        select(WorkflowStage)
        .where(WorkflowStage.template_id == template_id)
        .order_by(WorkflowStage.order)
    ).all()


def current_stage(stages: list[WorkflowStage], a: Assessment):
    if 0 <= a.stage_order < len(stages):
        return stages[a.stage_order]
    return None


# --------------------------------------------------------------------------- #
# List / create
# --------------------------------------------------------------------------- #
@router.get("/assessments")
def list_assessments(
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    rows = session.exec(select(Assessment).order_by(Assessment.id.desc())).all()
    templates = {t.id: t for t in session.exec(select(WorkflowTemplate)).all()}
    entities = {e.id: e for e in session.exec(select(Entity)).all()}
    # current stage name per assessment
    stage_names = {}
    for a in rows:
        stages = get_stages(session, a.template_id)
        st = current_stage(stages, a)
        stage_names[a.id] = st.name if st else "—"
    return render(
        request, "assessments/list.html", user=user, roles=roles,
        rows=rows, templates=templates, entities=entities, stage_names=stage_names,
    )


@router.get("/assessments/new")
def new_assessment(
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    if not has_role(session, user, "analyst"):
        flash(request, "You need the analyst role to start an assessment.", "error")
        return RedirectResponse("/assessments", status_code=303)
    templates = session.exec(select(WorkflowTemplate)).all()
    entities = session.exec(select(Entity).order_by(Entity.name)).all()
    catalogs = session.exec(select(Catalog)).all()
    return render(
        request, "assessments/new.html", user=user, roles=roles,
        templates=templates, entities=entities, catalogs=catalogs,
    )


@router.post("/assessments")
def create_assessment(
    request: Request,
    title: str = Form(...),
    template_id: int = Form(...),
    entity_id: str = Form(""),
    catalog_id: str = Form(""),
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    if not has_role(session, user, "analyst"):
        flash(request, "Insufficient role.", "error")
        return RedirectResponse("/assessments", status_code=303)
    template = session.get(WorkflowTemplate, template_id)
    if not template:
        flash(request, "Unknown workflow template.", "error")
        return RedirectResponse("/assessments/new", status_code=303)

    cat_id = int(catalog_id) if catalog_id else None
    assessment = Assessment(
        title=title.strip(),
        template_id=template_id,
        entity_id=int(entity_id) if entity_id else None,
        catalog_id=cat_id,
        stage_order=0,
        created_by=user.id,
    )
    session.add(assessment)
    session.commit()
    session.refresh(assessment)

    # Seed control results from the chosen catalog for control-based tracks.
    if template.uses_controls and cat_id:
        controls = session.exec(select(Control).where(Control.catalog_id == cat_id)).all()
        for c in controls:
            session.add(
                ControlResult(
                    assessment_id=assessment.id,
                    control_id=c.id,
                    status="not_implemented",
                    updated_by=user.id,
                )
            )
        session.commit()

    audit(session, user, "create", "assessment", assessment.id, assessment.title)
    flash(request, "Assessment created.", "success")
    return RedirectResponse(f"/assessments/{assessment.id}", status_code=303)


# --------------------------------------------------------------------------- #
# Detail
# --------------------------------------------------------------------------- #
@router.get("/assessments/{aid}")
def assessment_detail(
    aid: int,
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    a = session.get(Assessment, aid)
    if not a:
        flash(request, "Assessment not found.", "error")
        return RedirectResponse("/assessments", status_code=303)
    template = session.get(WorkflowTemplate, a.template_id)
    stages = get_stages(session, a.template_id)
    stage = current_stage(stages, a)
    entity = session.get(Entity, a.entity_id) if a.entity_id else None

    # control results joined to control definitions
    results = session.exec(
        select(ControlResult).where(ControlResult.assessment_id == aid)
    ).all()
    controls = {c.id: c for c in session.exec(select(Control)).all()}
    results = sorted(results, key=lambda r: controls.get(r.control_id).control_id if controls.get(r.control_id) else "")

    findings = session.exec(select(Finding).where(Finding.assessment_id == aid)).all()
    transitions = session.exec(
        select(Transition).where(Transition.assessment_id == aid).order_by(Transition.id.desc())
    ).all()
    users = {u.id: u for u in session.exec(select(User)).all()}
    submitter = users.get(a.submitted_by) if a.submitted_by else None

    can_submit = bool(stage) and a.state == "active" and not a.pending_review and has_role(
        session, user, stage.actor_role
    )
    can_approve = (
        bool(stage)
        and a.state == "active"
        and a.pending_review
        and has_role(session, user, stage.approver_role)
        and user.id != a.submitted_by
    )
    sod_block = (
        bool(stage)
        and a.pending_review
        and has_role(session, user, stage.approver_role)
        and user.id == a.submitted_by
    )
    can_edit = bool(stage) and a.state == "active" and not a.pending_review and has_role(
        session, user, stage.actor_role
    )

    return render(
        request, "assessments/detail.html", user=user, roles=roles,
        a=a, template=template, stages=stages, stage=stage, entity=entity,
        results=results, controls=controls, findings=findings,
        transitions=transitions, users=users, submitter=submitter,
        can_submit=can_submit, can_approve=can_approve, can_edit=can_edit,
        sod_block=sod_block, statuses=RESULT_STATUSES,
    )


# --------------------------------------------------------------------------- #
# Control results
# --------------------------------------------------------------------------- #
@router.post("/assessments/{aid}/results")
async def save_results(
    aid: int,
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    a = session.get(Assessment, aid)
    if not a:
        flash(request, "Assessment not found.", "error")
        return RedirectResponse("/assessments", status_code=303)
    stages = get_stages(session, a.template_id)
    stage = current_stage(stages, a)
    if not (stage and a.state == "active" and not a.pending_review and has_role(session, user, stage.actor_role)):
        flash(request, "You can't edit results right now (wrong role or awaiting review).", "error")
        return RedirectResponse(f"/assessments/{aid}", status_code=303)

    form = await request.form()
    results = session.exec(select(ControlResult).where(ControlResult.assessment_id == aid)).all()
    changed = 0
    for r in results:
        new_status = form.get(f"status_{r.id}")
        new_detail = form.get(f"detail_{r.id}")
        if new_status is not None and new_status != r.status:
            r.status = new_status
            changed += 1
        if new_detail is not None and new_detail != r.detail:
            r.detail = new_detail
        r.updated_by = user.id
        r.updated_at = datetime.utcnow()
        session.add(r)
    session.commit()
    audit(session, user, "update_results", "assessment", aid, f"{changed} status change(s)")
    flash(request, "Control results saved.", "success")
    return RedirectResponse(f"/assessments/{aid}", status_code=303)


# --------------------------------------------------------------------------- #
# Workflow gates
# --------------------------------------------------------------------------- #
@router.post("/assessments/{aid}/submit")
def submit_stage(
    aid: int,
    request: Request,
    comment: str = Form(""),
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    a = session.get(Assessment, aid)
    if not a:
        return RedirectResponse("/assessments", status_code=303)
    stages = get_stages(session, a.template_id)
    stage = current_stage(stages, a)
    if not (stage and a.state == "active" and not a.pending_review and has_role(session, user, stage.actor_role)):
        flash(request, "You can't submit this stage.", "error")
        return RedirectResponse(f"/assessments/{aid}", status_code=303)
    a.pending_review = True
    a.submitted_by = user.id
    a.submitted_at = datetime.utcnow()
    session.add(a)
    session.add(Transition(
        assessment_id=aid, from_stage=a.stage_order, to_stage=a.stage_order,
        action="submit", actor_id=user.id, comment=comment.strip(),
    ))
    session.commit()
    audit(session, user, "submit", "assessment", aid, f"stage '{stage.name}'")
    flash(request, f"Stage '{stage.name}' submitted for review.", "success")
    return RedirectResponse(f"/assessments/{aid}", status_code=303)


@router.post("/assessments/{aid}/approve")
def approve_stage(
    aid: int,
    request: Request,
    comment: str = Form(""),
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    a = session.get(Assessment, aid)
    if not a:
        return RedirectResponse("/assessments", status_code=303)
    stages = get_stages(session, a.template_id)
    stage = current_stage(stages, a)
    if not (stage and a.state == "active" and a.pending_review and has_role(session, user, stage.approver_role)):
        flash(request, "You can't approve this stage.", "error")
        return RedirectResponse(f"/assessments/{aid}", status_code=303)
    if user.id == a.submitted_by:
        flash(request, "Separation of duty: the submitter cannot approve their own work.", "error")
        return RedirectResponse(f"/assessments/{aid}", status_code=303)

    last_index = len(stages) - 1
    from_order = a.stage_order
    if a.stage_order < last_index:
        a.stage_order += 1
        a.pending_review = False
        a.submitted_by = None
        outcome = f"advanced to '{stages[a.stage_order].name}'"
    else:
        a.state = "closed"
        a.pending_review = False
        a.submitted_by = None
        outcome = "final approval — assessment authorized & closed"
    session.add(a)
    session.add(Transition(
        assessment_id=aid, from_stage=from_order, to_stage=a.stage_order,
        action="approve", actor_id=user.id, comment=comment.strip(),
    ))
    session.commit()
    audit(session, user, "approve", "assessment", aid, outcome)
    flash(request, f"Approved — {outcome}.", "success")
    return RedirectResponse(f"/assessments/{aid}", status_code=303)


@router.post("/assessments/{aid}/reject")
def reject_stage(
    aid: int,
    request: Request,
    comment: str = Form(""),
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    a = session.get(Assessment, aid)
    if not a:
        return RedirectResponse("/assessments", status_code=303)
    stages = get_stages(session, a.template_id)
    stage = current_stage(stages, a)
    if not (stage and a.state == "active" and a.pending_review and has_role(session, user, stage.approver_role)):
        flash(request, "You can't reject this stage.", "error")
        return RedirectResponse(f"/assessments/{aid}", status_code=303)
    a.pending_review = False
    a.submitted_by = None
    session.add(a)
    session.add(Transition(
        assessment_id=aid, from_stage=a.stage_order, to_stage=a.stage_order,
        action="reject", actor_id=user.id, comment=comment.strip(),
    ))
    session.commit()
    audit(session, user, "reject", "assessment", aid, f"stage '{stage.name}' returned")
    flash(request, "Returned to the submitter for rework.", "info")
    return RedirectResponse(f"/assessments/{aid}", status_code=303)


@router.post("/assessments/{aid}/close")
def close_assessment(
    aid: int,
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    a = session.get(Assessment, aid)
    if not a:
        return RedirectResponse("/assessments", status_code=303)
    if not has_role(session, user, "approver"):
        flash(request, "Only an approver can close an assessment.", "error")
        return RedirectResponse(f"/assessments/{aid}", status_code=303)
    a.state = "closed"
    a.pending_review = False
    session.add(a)
    session.add(Transition(
        assessment_id=aid, from_stage=a.stage_order, to_stage=a.stage_order,
        action="close", actor_id=user.id,
    ))
    session.commit()
    audit(session, user, "close", "assessment", aid)
    flash(request, "Assessment closed.", "info")
    return RedirectResponse(f"/assessments/{aid}", status_code=303)
