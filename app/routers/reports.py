"""Reporting — the JasperReports replacement.

Renders a printable assessment/authorization summary (the SSP/SAR analogue)
and an OSCAL-flavoured JSON export so artifacts are machine-readable, not
locked in a proprietary report format.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlmodel import Session, select

from ..database import get_session
from ..models import (
    Assessment,
    Control,
    ControlResult,
    Entity,
    Evidence,
    Finding,
    WorkflowStage,
    WorkflowTemplate,
)
from ..security import require_user, roles_for
from ..templating import render

router = APIRouter()


@router.get("/reports")
def reports_index(
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    rows = session.exec(select(Assessment).order_by(Assessment.id.desc())).all()
    templates = {t.id: t for t in session.exec(select(WorkflowTemplate)).all()}
    entities = {e.id: e for e in session.exec(select(Entity)).all()}
    return render(
        request, "reports/index.html", user=user, roles=roles,
        rows=rows, templates=templates, entities=entities,
    )


def _assemble(session: Session, aid: int):
    a = session.get(Assessment, aid)
    if not a:
        return None
    template = session.get(WorkflowTemplate, a.template_id)
    entity = session.get(Entity, a.entity_id) if a.entity_id else None
    stages = session.exec(
        select(WorkflowStage).where(WorkflowStage.template_id == a.template_id).order_by(WorkflowStage.order)
    ).all()
    results = session.exec(select(ControlResult).where(ControlResult.assessment_id == aid)).all()
    controls = {c.id: c for c in session.exec(select(Control)).all()}
    rows = []
    summary = {}
    for r in results:
        c = controls.get(r.control_id)
        rows.append({"control": c, "result": r})
        summary[r.status] = summary.get(r.status, 0) + 1
    rows.sort(key=lambda x: x["control"].control_id if x["control"] else "")
    findings = session.exec(select(Finding).where(Finding.assessment_id == aid)).all()
    evidence = session.exec(
        select(Evidence).where(Evidence.subject_type == "assessment", Evidence.subject_id == aid)
    ).all()
    return {
        "a": a, "template": template, "entity": entity, "stages": stages,
        "rows": rows, "summary": summary, "findings": findings, "evidence": evidence,
    }


@router.get("/assessments/{aid}/report")
def assessment_report(
    aid: int,
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    data = _assemble(session, aid)
    if not data:
        return RedirectResponse("/reports", status_code=303)
    return render(request, "reports/assessment_report.html", user=user, roles=roles, **data)


@router.get("/assessments/{aid}/export.json")
def assessment_export(
    aid: int,
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    data = _assemble(session, aid)
    if not data:
        return JSONResponse({"error": "not found"}, status_code=404)
    a = data["a"]
    entity = data["entity"]
    # OSCAL-flavoured (not full schema) system-security-plan-ish payload.
    payload = {
        "$schema": "aegis://oscal-flavored/assessment",
        "assessment": {
            "uuid": f"aegis-assessment-{a.id}",
            "title": a.title,
            "track": data["template"].name if data["template"] else None,
            "state": a.state,
            "current_stage": (
                data["stages"][a.stage_order].name
                if 0 <= a.stage_order < len(data["stages"]) else None
            ),
        },
        "system-characteristics": {
            "system-name": entity.name if entity else None,
            "type": entity.type if entity else None,
            "criticality": entity.criticality if entity else None,
            "security-impact-level": {
                "confidentiality": entity.confidentiality if entity else None,
                "integrity": entity.integrity if entity else None,
                "availability": entity.availability if entity else None,
            } if entity else None,
        },
        "control-implementation": [
            {
                "control-id": row["control"].control_id if row["control"] else None,
                "title": row["control"].title if row["control"] else None,
                "implementation-status": row["result"].status,
                "remarks": row["result"].detail,
            }
            for row in data["rows"]
        ],
        "findings": [
            {
                "uuid": f"aegis-finding-{f.id}",
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "cve": f.cve or None,
                "cvss": f.cvss,
            }
            for f in data["findings"]
        ],
        "summary": data["summary"],
    }
    return JSONResponse(payload)
