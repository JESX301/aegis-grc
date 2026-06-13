"""Control catalog browser (controls-as-data)."""
from __future__ import annotations

from collections import OrderedDict

from fastapi import APIRouter, Depends, Request
from sqlmodel import Session, select

from ..database import get_session
from ..models import Catalog, Control
from ..security import require_user, roles_for
from ..templating import render

router = APIRouter()


@router.get("/catalog")
def catalog_view(
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    catalogs = session.exec(select(Catalog)).all()
    grouped = OrderedDict()
    for cat in catalogs:
        controls = session.exec(
            select(Control).where(Control.catalog_id == cat.id).order_by(Control.control_id)
        ).all()
        families = OrderedDict()
        for c in controls:
            families.setdefault(c.family, []).append(c)
        grouped[cat.id] = {"catalog": cat, "families": families, "count": len(controls)}
    return render(request, "catalog/list.html", user=user, roles=roles, grouped=grouped)
