"""Admin: user/role directory and the append-only audit log."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlmodel import Session, select

from ..database import get_session
from ..models import AuditLog, Role, User, UserRoleLink
from ..security import has_role, require_user, roles_for
from ..templating import render

router = APIRouter()


@router.get("/admin/users")
def admin_users(
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    if not has_role(session, user, "admin"):
        return render(request, "error.html", user=user, roles=roles, code=403,
                      message="Admin only.", status_code=403)
    users = session.exec(select(User).order_by(User.username)).all()
    links = session.exec(select(UserRoleLink)).all()
    role_by_id = {r.id: r.name for r in session.exec(select(Role)).all()}
    user_roles: dict[int, list[str]] = {}
    for link in links:
        user_roles.setdefault(link.user_id, []).append(role_by_id.get(link.role_id, "?"))
    return render(
        request, "admin/users.html", user=user, roles=roles,
        users=users, user_roles=user_roles,
    )


@router.get("/admin/audit")
def admin_audit(
    request: Request,
    session: Session = Depends(get_session),
    user=Depends(require_user),
):
    roles = roles_for(session, user)
    if not has_role(session, user, "admin", "read_only"):
        return render(request, "error.html", user=user, roles=roles, code=403,
                      message="Admin / auditor only.", status_code=403)
    rows = session.exec(select(AuditLog).order_by(AuditLog.id.desc()).limit(300)).all()
    return render(request, "admin/audit.html", user=user, roles=roles, rows=rows)
