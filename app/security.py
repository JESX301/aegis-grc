"""Authentication, password hashing, RBAC, audit + flash helpers.

Password hashing uses stdlib PBKDF2-HMAC-SHA256 (no native build deps).
Auth is cookie-session based. For production, front this with an OIDC IdP
(Okta / Entra) — see README. RBAC is role-name based; the workflow engine
adds separation-of-duty on top (submitter must differ from approver).
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from sqlmodel import Session, select

from .database import get_session
from .models import AuditLog, Role, User, UserRoleLink

_PBKDF2_ROUNDS = 240_000


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


# --------------------------------------------------------------------------- #
# Roles
# --------------------------------------------------------------------------- #
def user_role_names(session: Session, user: User) -> set[str]:
    if user.id is None:
        return set()
    rows = session.exec(
        select(Role.name)
        .join(UserRoleLink, UserRoleLink.role_id == Role.id)
        .where(UserRoleLink.user_id == user.id)
    ).all()
    return set(rows)


def has_role(session: Session, user: User, *roles: str) -> bool:
    names = user_role_names(session, user)
    if "admin" in names:
        return True
    return bool(names.intersection(roles))


# --------------------------------------------------------------------------- #
# Current-user dependencies
# --------------------------------------------------------------------------- #
def get_current_user(
    request: Request, session: Session = Depends(get_session)
) -> Optional[User]:
    uid = request.session.get("user_id")
    if not uid:
        return None
    user = session.get(User, uid)
    if user and user.is_active:
        return user
    return None


def require_user(
    request: Request, session: Session = Depends(get_session)
) -> User:
    user = get_current_user(request, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )
    return user


def require_roles(*roles: str):
    """Dependency factory: require any of the given roles (admin always allowed)."""

    def _dep(
        request: Request, session: Session = Depends(get_session)
    ) -> User:
        user = require_user(request, session)
        if not has_role(session, user, *roles):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return user

    return _dep


# --------------------------------------------------------------------------- #
# Audit + flash helpers
# --------------------------------------------------------------------------- #
def audit(
    session: Session,
    actor: Optional[User],
    action: str,
    object_type: str = "",
    object_id: Optional[int] = None,
    detail: str = "",
) -> None:
    session.add(
        AuditLog(
            actor_id=actor.id if actor else None,
            actor_name=actor.username if actor else "system",
            action=action,
            object_type=object_type,
            object_id=object_id,
            detail=detail,
        )
    )
    session.commit()


def flash(request: Request, message: str, category: str = "info") -> None:
    request.session.setdefault("_flashes", []).append({"m": message, "c": category})


def pop_flashes(request: Request) -> list[dict]:
    flashes = request.session.pop("_flashes", [])
    return flashes


def roles_for(session: Session, user: Optional[User]) -> set[str]:
    return user_role_names(session, user) if user else set()
