"""Shared Jinja2 templating + a `render` helper that injects common context."""
from __future__ import annotations

from typing import Optional

from fastapi import Request
from fastapi.templating import Jinja2Templates

from .config import BASE_DIR, settings
from .models import User
from .security import pop_flashes

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# severity / status -> CSS badge class, used by templates
BADGE = {
    "Critical": "crit", "High": "high", "Medium": "med", "Moderate": "med",
    "Low": "low", "Info": "info",
    "open": "high", "closed": "low", "risk_accepted": "med",
    "active": "info", "implemented": "low", "partial": "med",
    "planned": "info", "not_implemented": "high", "not_applicable": "muted",
}


def render(
    request: Request,
    template_name: str,
    *,
    user: Optional[User] = None,
    roles: Optional[set[str]] = None,
    status_code: int = 200,
    **context,
):
    ctx = {
        "request": request,
        "app_name": settings.APP_NAME,
        "user": user,
        "roles": roles or set(),
        "flashes": pop_flashes(request),
        "badge": BADGE,
        **context,
    }
    return templates.TemplateResponse(request, template_name, ctx, status_code=status_code)
