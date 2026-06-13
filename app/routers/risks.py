"""Risk register, remediation plans, and evidence — the remaining canonical objects.

Kept intentionally light in the MVP, but the objects are first-class and share
the same data model so risk rollups and remediation SLAs work uniformly.
"""
from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlmodel import Session, select

from ..database import get_session
from ..models import Evidence, Finding, Remediation, Risk, User
from ..security import audit, flash, has_role, require_user, roles_for
from ..templating import render

router = APIRouter()

LEVELS = ["Low", "Medium", "High"]
TREATMENTS = ["mitigate", "accept", "transfer", "avoid"]


def _parse_date(value: str):
    value = (value or "").strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Risk register
# --------------------------------------------------------------------------- #
@router.get("/risks")
def list_risks(
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    risks = session.exec(select(Risk).order_by(Risk.id.desc())).all()
    remediations = session.exec(select(Remediation).order_by(Remediation.id.desc())).all()
    users = {u.id: u for u in session.exec(select(User)).all()}
    findings = {f.id: f for f in session.exec(select(Finding)).all()}
    return render(
        request, "risks/list.html", user=user, roles=roles,
        risks=risks, remediations=remediations, users=users, findings=findings,
        levels=LEVELS, treatments=TREATMENTS,
    )


@router.post("/risks")
def create_risk(
    request: Request,
    title: str = Form(...),
    finding_id: str = Form(""),
    likelihood: str = Form("Medium"),
    impact: str = Form("Medium"),
    treatment: str = Form("mitigate"),
    owner_id: str = Form(""),
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    if not has_role(session, user, "analyst", "reviewer", "approver"):
        flash(request, "Insufficient role.", "error")
        return RedirectResponse("/risks", status_code=303)
    risk = Risk(
        title=title.strip(),
        finding_id=int(finding_id) if finding_id else None,
        likelihood=likelihood,
        impact=impact,
        treatment=treatment,
        owner_id=int(owner_id) if owner_id else None,
        inherent=f"{likelihood}/{impact}",
    )
    session.add(risk)
    session.commit()
    session.refresh(risk)
    audit(session, user, "create", "risk", risk.id, risk.title)
    flash(request, "Risk added to the register.", "success")
    return RedirectResponse("/risks", status_code=303)


# --------------------------------------------------------------------------- #
# Remediation (created from a finding)
# --------------------------------------------------------------------------- #
@router.post("/remediations")
def create_remediation(
    request: Request,
    finding_id: int = Form(...),
    title: str = Form(...),
    steps: str = Form(""),
    owner_id: str = Form(""),
    target_date: str = Form(""),
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    if not has_role(session, user, "analyst", "reviewer"):
        flash(request, "Insufficient role.", "error")
        return RedirectResponse(f"/findings/{finding_id}", status_code=303)
    rem = Remediation(
        finding_id=finding_id,
        title=title.strip(),
        steps=steps.strip(),
        owner_id=int(owner_id) if owner_id else None,
        target_date=_parse_date(target_date),
    )
    session.add(rem)
    session.commit()
    session.refresh(rem)
    audit(session, user, "create", "remediation", rem.id, rem.title)
    flash(request, "Remediation plan created.", "success")
    return RedirectResponse(f"/findings/{finding_id}", status_code=303)


# --------------------------------------------------------------------------- #
# Evidence (attached to any subject)
# --------------------------------------------------------------------------- #
@router.post("/evidence")
def add_evidence(
    request: Request,
    subject_type: str = Form(...),
    subject_id: int = Form(...),
    title: str = Form(...),
    type: str = Form("document"),
    uri: str = Form(""),
    note: str = Form(""),
    redirect: str = Form("/"),
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    if not has_role(session, user, "analyst", "reviewer", "vendor"):
        flash(request, "Insufficient role.", "error")
        return RedirectResponse(redirect, status_code=303)
    ev = Evidence(
        subject_type=subject_type,
        subject_id=subject_id,
        title=title.strip(),
        type=type,
        uri=uri.strip(),
        note=note.strip(),
        collected_by=user.id,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    audit(session, user, "evidence", subject_type, subject_id, ev.title)
    flash(request, "Evidence attached.", "success")
    return RedirectResponse(redirect, status_code=303)
