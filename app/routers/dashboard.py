"""Landing dashboard with cross-track rollups."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlmodel import Session, func, select

from ..database import get_session
from ..models import (
    Assessment,
    AuditLog,
    Entity,
    Finding,
    Risk,
    WorkflowTemplate,
)
from ..security import get_current_user, roles_for
from ..templating import render

router = APIRouter()


def _count(session: Session, model, *where) -> int:
    stmt = select(func.count()).select_from(model)
    for w in where:
        stmt = stmt.where(w)
    return session.exec(stmt).one()


@router.get("/")
def home(
    request: Request,
    session: Session = Depends(get_session),
):
    user = get_current_user(request, session)
    if not user:
        # Anonymous visitors get the public marketing landing page.
        return render(request, "landing.html")
    roles = roles_for(session, user)
    stats = {
        "entities": _count(session, Entity),
        "assessments_active": _count(session, Assessment, Assessment.state == "active"),
        "findings_open": _count(session, Finding, Finding.status == "open"),
        "findings_critical": _count(
            session, Finding, Finding.status == "open", Finding.severity == "Critical"
        ),
        "risks_open": _count(session, Risk, Risk.status == "open"),
    }
    templates = session.exec(select(WorkflowTemplate)).all()
    pending = session.exec(
        select(Assessment).where(
            Assessment.state == "active", Assessment.pending_review == True  # noqa: E712
        )
    ).all()
    recent_audit = session.exec(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(8)
    ).all()
    recent_findings = session.exec(
        select(Finding).order_by(Finding.id.desc()).limit(6)
    ).all()
    return render(
        request,
        "dashboard.html",
        user=user,
        roles=roles,
        stats=stats,
        templates=templates,
        pending=pending,
        recent_audit=recent_audit,
        recent_findings=recent_findings,
    )
