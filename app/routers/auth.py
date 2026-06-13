"""Login / logout (cookie session)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlmodel import Session, select

from ..database import get_session
from ..models import User
from ..security import audit, flash, get_current_user, verify_password
from ..templating import render

router = APIRouter()


@router.get("/login")
def login_form(request: Request, session: Session = Depends(get_session)):
    if get_current_user(request, session):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html")


@router.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    user = session.exec(select(User).where(User.username == username)).first()
    if not user or not user.is_active or not verify_password(password, user.hashed_password):
        flash(request, "Invalid username or password.", "error")
        return render(request, "login.html", username=username, status_code=401)
    request.session["user_id"] = user.id
    audit(session, user, "login", "user", user.id)
    flash(request, f"Welcome back, {user.full_name or user.username}.", "success")
    if user.must_change_password:
        flash(request, "You're signed in with a temporary password — change it now in My Account.", "error")
    return RedirectResponse("/", status_code=303)


@router.get("/logout")
def logout(request: Request, session: Session = Depends(get_session)):
    user = get_current_user(request, session)
    if user:
        audit(session, user, "logout", "user", user.id)
    request.session.clear()
    flash(request, "Signed out.", "info")
    return RedirectResponse("/login", status_code=303)
