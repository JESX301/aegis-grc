"""Findings — gaps, deficiencies, and vulnerabilities (one shape across tracks)."""
from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlmodel import Session, select

from ..database import get_session
from ..models import Assessment, Control, Entity, Finding, Remediation, Risk, User
from ..security import audit, flash, has_role, require_user, roles_for
from ..templating import render

router = APIRouter()

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SOURCES = ["manual", "scanner", "assessment", "incident"]


def dedupe_hash(entity_id, title, cve) -> str:
    raw = f"{entity_id}|{(title or '').strip().lower()}|{(cve or '').strip().lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@router.get("/findings")
def list_findings(
    request: Request,
    status: str = "",
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    stmt = select(Finding).order_by(Finding.id.desc())
    if status:
        stmt = stmt.where(Finding.status == status)
    findings = session.exec(stmt).all()
    entities = {e.id: e for e in session.exec(select(Entity)).all()}
    return render(
        request, "findings/list.html", user=user, roles=roles,
        findings=findings, entities=entities, status=status,
    )


@router.get("/findings/new")
def new_finding(
    request: Request,
    entity_id: str = "",
    assessment_id: str = "",
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    if not has_role(session, user, "analyst", "reviewer"):
        flash(request, "You need an analyst/reviewer role to raise findings.", "error")
        return RedirectResponse("/findings", status_code=303)
    entities = session.exec(select(Entity).order_by(Entity.name)).all()
    return render(
        request, "findings/new.html", user=user, roles=roles,
        entities=entities, severities=SEVERITIES, sources=SOURCES,
        sel_entity=entity_id, sel_assessment=assessment_id,
    )


@router.post("/findings")
def create_finding(
    request: Request,
    title: str = Form(...),
    description: str = Form(""),
    entity_id: str = Form(""),
    assessment_id: str = Form(""),
    severity: str = Form("Medium"),
    source: str = Form("manual"),
    cve: str = Form(""),
    cvss: str = Form(""),
    epss: str = Form(""),
    kev: str = Form(""),
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    if not has_role(session, user, "analyst", "reviewer"):
        flash(request, "Insufficient role.", "error")
        return RedirectResponse("/findings", status_code=303)
    eid = int(entity_id) if entity_id else None
    finding = Finding(
        title=title.strip(),
        description=description.strip(),
        entity_id=eid,
        assessment_id=int(assessment_id) if assessment_id else None,
        severity=severity,
        source=source,
        cve=cve.strip(),
        cvss=float(cvss) if cvss.strip() else None,
        epss=float(epss) if epss.strip() else None,
        kev=bool(kev),
        dedupe_hash=dedupe_hash(eid, title, cve),
        created_by=user.id,
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    audit(session, user, "create", "finding", finding.id, finding.title)
    flash(request, "Finding raised.", "success")
    return RedirectResponse(f"/findings/{finding.id}", status_code=303)


@router.get("/findings/{fid}")
def finding_detail(
    fid: int,
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    f = session.get(Finding, fid)
    if not f:
        flash(request, "Finding not found.", "error")
        return RedirectResponse("/findings", status_code=303)
    entity = session.get(Entity, f.entity_id) if f.entity_id else None
    assessment = session.get(Assessment, f.assessment_id) if f.assessment_id else None
    control = session.get(Control, f.control_id) if f.control_id else None
    remediations = session.exec(select(Remediation).where(Remediation.finding_id == fid)).all()
    risks = session.exec(select(Risk).where(Risk.finding_id == fid)).all()
    users = {u.id: u for u in session.exec(select(User)).all()}
    return render(
        request, "findings/detail.html", user=user, roles=roles,
        f=f, entity=entity, assessment=assessment, control=control,
        remediations=remediations, risks=risks, users=users,
    )


@router.post("/findings/{fid}/status")
def set_finding_status(
    fid: int,
    request: Request,
    status: str = Form(...),
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    f = session.get(Finding, fid)
    if not f:
        return RedirectResponse("/findings", status_code=303)
    if not has_role(session, user, "analyst", "reviewer", "approver"):
        flash(request, "Insufficient role.", "error")
        return RedirectResponse(f"/findings/{fid}", status_code=303)
    if status == "risk_accepted" and not has_role(session, user, "approver"):
        flash(request, "Only an approver can accept risk.", "error")
        return RedirectResponse(f"/findings/{fid}", status_code=303)
    f.status = status
    session.add(f)
    session.commit()
    audit(session, user, "status", "finding", fid, status)
    flash(request, f"Finding marked '{status}'.", "success")
    return RedirectResponse(f"/findings/{fid}", status_code=303)
