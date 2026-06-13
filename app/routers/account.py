"""My Account — a role-adaptive page surfacing each user's work queues + account controls.

Panels are chosen from the logged-in user's *actual* roles (admin is not auto-expanded
here, so admins get the org snapshot rather than every queue). The queues are derived from
existing workflow state — no schema change.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlmodel import Session, func, select

from ..database import get_session
from ..models import (
    Assessment,
    AuditLog,
    Entity,
    Evidence,
    Finding,
    User,
    WorkflowStage,
    WorkflowTemplate,
)
from ..models import Exception as GrcException
from ..security import (
    audit,
    flash,
    hash_password,
    require_user,
    roles_for,
    verify_password,
)
from ..templating import render


def _stages_by_template(session: Session) -> dict[int, list[WorkflowStage]]:
    out: dict[int, list[WorkflowStage]] = {}
    for s in session.exec(select(WorkflowStage).order_by(WorkflowStage.order)).all():
        out.setdefault(s.template_id, []).append(s)
    return out


def _current_stage(stages_by_tpl, a: Assessment):
    stages = stages_by_tpl.get(a.template_id, [])
    return stages[a.stage_order] if 0 <= a.stage_order < len(stages) else None


def _count(session: Session, model, *where) -> int:
    stmt = select(func.count()).select_from(model)
    for w in where:
        stmt = stmt.where(w)
    return session.exec(stmt).one()


router = APIRouter()


@router.get("/account")
def account(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_user),
):
    roles = roles_for(session, user)
    templates = {t.id: t for t in session.exec(select(WorkflowTemplate)).all()}
    entities = {e.id: e for e in session.exec(select(Entity)).all()}
    sbt = _stages_by_template(session)
    active = session.exec(select(Assessment).where(Assessment.state == "active")).all()

    def decorate(items):
        rows = []
        for a in items:
            st = _current_stage(sbt, a)
            rows.append({
                "a": a,
                "stage": st.name if st else "—",
                "track": templates[a.template_id].name if templates.get(a.template_id) else "—",
                "entity": entities[a.entity_id].name if a.entity_id and entities.get(a.entity_id) else None,
            })
        return rows

    ctx: dict = {}

    if "analyst" in roles:
        ctx["awaiting_submission"] = decorate([
            a for a in active
            if (st := _current_stage(sbt, a)) and st.actor_role == "analyst" and not a.pending_review
        ])
        ctx["my_assessments"] = decorate(session.exec(
            select(Assessment).where(Assessment.created_by == user.id).order_by(Assessment.id.desc())
        ).all())
        ctx["my_findings"] = session.exec(
            select(Finding).where(Finding.created_by == user.id).order_by(Finding.id.desc())
        ).all()

    if "reviewer" in roles:
        ctx["review_queue"] = decorate([
            a for a in active
            if a.pending_review and (st := _current_stage(sbt, a))
            and st.approver_role == "reviewer" and a.submitted_by != user.id
        ])

    if "approver" in roles:
        ctx["authorize_queue"] = decorate([
            a for a in active
            if a.pending_review and (st := _current_stage(sbt, a))
            and st.approver_role == "approver" and a.submitted_by != user.id
        ])
        ctx["open_findings"] = session.exec(
            select(Finding).where(Finding.status == "open").order_by(Finding.id.desc())
        ).all()
        ctx["exception_requests"] = session.exec(
            select(GrcException).where(GrcException.state == "requested")
        ).all()

    if "vendor" in roles:
        ctx["questionnaires"] = decorate([
            a for a in active
            if (st := _current_stage(sbt, a)) and st.actor_role == "vendor"
        ])
        ctx["my_evidence"] = session.exec(
            select(Evidence).where(Evidence.collected_by == user.id).order_by(Evidence.id.desc())
        ).all()

    if "admin" in roles:
        ctx["admin_stats"] = {
            "users": _count(session, User),
            "entities": _count(session, Entity),
            "active_assessments": _count(session, Assessment, Assessment.state == "active"),
            "open_findings": _count(session, Finding, Finding.status == "open"),
        }

    if "reviewer" in roles or "approver" in roles:
        ctx["recent_decisions"] = session.exec(
            select(AuditLog)
            .where(AuditLog.actor_id == user.id, AuditLog.action.in_(["approve", "reject"]))
            .order_by(AuditLog.id.desc()).limit(6)
        ).all()

    my_audit = session.exec(
        select(AuditLog).where(AuditLog.actor_id == user.id).order_by(AuditLog.id.desc()).limit(8)
    ).all()
    last_login = session.exec(
        select(AuditLog)
        .where(AuditLog.actor_id == user.id, AuditLog.action == "login")
        .order_by(AuditLog.id.desc()).limit(1)
    ).first()

    return render(
        request, "account/index.html", user=user, roles=roles,
        my_audit=my_audit, last_login=last_login, **ctx,
    )


@router.post("/account/profile")
def update_profile(
    request: Request,
    full_name: str = Form(""),
    email: str = Form(""),
    session: Session = Depends(get_session),
    user: User = Depends(require_user),
):
    user.full_name = full_name.strip()
    user.email = email.strip()
    session.add(user)
    session.commit()
    audit(session, user, "update_profile", "user", user.id)
    flash(request, "Profile updated.", "success")
    return RedirectResponse("/account", status_code=303)


@router.post("/account/password")
def change_password(
    request: Request,
    current: str = Form(...),
    new: str = Form(...),
    confirm: str = Form(...),
    session: Session = Depends(get_session),
    user: User = Depends(require_user),
):
    if not verify_password(current, user.hashed_password):
        flash(request, "Current password is incorrect.", "error")
        return RedirectResponse("/account", status_code=303)
    if len(new) < 6:
        flash(request, "New password must be at least 6 characters.", "error")
        return RedirectResponse("/account", status_code=303)
    if new != confirm:
        flash(request, "New password and confirmation do not match.", "error")
        return RedirectResponse("/account", status_code=303)
    user.hashed_password = hash_password(new)
    user.must_change_password = False
    session.add(user)
    session.commit()
    audit(session, user, "change_password", "user", user.id)
    flash(request, "Password changed.", "success")
    return RedirectResponse("/account", status_code=303)
