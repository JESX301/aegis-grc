"""Aegis GRC — FastAPI application entrypoint."""
from __future__ import annotations

import logging
import mimetypes
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .config import BASE_DIR, settings
from .database import init_db
from .routers import (
    account,
    admin,
    assessments,
    auth,
    catalog,
    dashboard,
    entities,
    findings,
    reports,
    risks,
)
from .seed import seed_all
from .templating import render

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("aegis")

# Correct MIME for the self-hosted webfont (Python's default doesn't know .woff2).
mimetypes.add_type("font/woff2", ".woff2")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_all()
    if settings.SECRET_KEY.startswith("dev-insecure"):
        log.warning("Using the default dev SECRET_KEY — set AEGIS_SECRET_KEY in production.")
    if settings.SEED_DEMO:
        log.info("Demo data seeded. Log in at /login (e.g. analyst / %s).", settings.DEMO_PASSWORD)
    yield


app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY, max_age=60 * 60 * 12)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(account.router)
app.include_router(entities.router)
app.include_router(catalog.router)
app.include_router(assessments.router)
app.include_router(findings.router)
app.include_router(risks.router)
app.include_router(reports.router)
app.include_router(admin.router)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "app": settings.APP_NAME, "version": "0.1.0"}


@app.exception_handler(403)
async def forbidden_handler(request: Request, exc):
    return render(request, "error.html", code=403, message="You don't have permission to do that.", status_code=403)


@app.exception_handler(404)
async def notfound_handler(request: Request, exc):
    return render(request, "error.html", code=404, message="Not found.", status_code=404)
