"""Entities / assets (systems, applications, databases, vendors, business units)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlmodel import Session, select

from ..database import get_session
from ..models import Assessment, Entity, Finding, User
from ..security import audit, flash, has_role, require_user, roles_for
from ..templating import render

router = APIRouter()

ENTITY_TYPES = ["system", "application", "computer", "database", "vendor", "business_unit"]
CRITICALITIES = ["Critical", "High", "Moderate", "Low"]
CIA_LEVELS = ["", "Low", "Moderate", "High"]


@router.get("/entities")
def list_entities(
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    entities = session.exec(select(Entity).order_by(Entity.name)).all()
    owners = {u.id: u for u in session.exec(select(User)).all()}
    return render(
        request, "entities/list.html", user=user, roles=roles,
        entities=entities, owners=owners,
    )


@router.get("/entities/new")
def new_entity(
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    if not has_role(session, user, "analyst"):
        flash(request, "You need the analyst role to create entities.", "error")
        return RedirectResponse("/entities", status_code=303)
    users = session.exec(select(User)).all()
    parents = session.exec(select(Entity).order_by(Entity.name)).all()
    return render(
        request, "entities/new.html", user=user, roles=roles,
        users=users, parents=parents, types=ENTITY_TYPES,
        criticalities=CRITICALITIES, cia=CIA_LEVELS,
    )


@router.post("/entities")
def create_entity(
    request: Request,
    name: str = Form(...),
    type: str = Form("system"),
    owner_id: str = Form(""),
    parent_id: str = Form(""),
    criticality: str = Form("Moderate"),
    data_classification: str = Form(""),
    confidentiality: str = Form(""),
    integrity: str = Form(""),
    availability: str = Form(""),
    description: str = Form(""),
    tags: str = Form(""),
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    if not has_role(session, user, "analyst"):
        flash(request, "Insufficient role.", "error")
        return RedirectResponse("/entities", status_code=303)
    entity = Entity(
        name=name.strip(),
        type=type,
        owner_id=int(owner_id) if owner_id else None,
        parent_id=int(parent_id) if parent_id else None,
        criticality=criticality,
        data_classification=data_classification.strip(),
        confidentiality=confidentiality,
        integrity=integrity,
        availability=availability,
        description=description.strip(),
        tags=tags.strip(),
    )
    session.add(entity)
    session.commit()
    session.refresh(entity)
    audit(session, user, "create", "entity", entity.id, entity.name)
    flash(request, f"Entity '{entity.name}' created.", "success")
    return RedirectResponse(f"/entities/{entity.id}", status_code=303)


@router.get("/entities/{entity_id}")
def entity_detail(
    entity_id: int,
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    entity = session.get(Entity, entity_id)
    if not entity:
        flash(request, "Entity not found.", "error")
        return RedirectResponse("/entities", status_code=303)
    owner = session.get(User, entity.owner_id) if entity.owner_id else None
    parent = session.get(Entity, entity.parent_id) if entity.parent_id else None
    assessments = session.exec(
        select(Assessment).where(Assessment.entity_id == entity_id)
    ).all()
    findings = session.exec(
        select(Finding).where(Finding.entity_id == entity_id)
    ).all()
    children = session.exec(
        select(Entity).where(Entity.parent_id == entity_id)
    ).all()
    return render(
        request, "entities/detail.html", user=user, roles=roles,
        entity=entity, owner=owner, parent=parent,
        assessments=assessments, findings=findings, children=children,
    )
