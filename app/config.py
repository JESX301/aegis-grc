"""Runtime configuration, read from environment variables.

All settings have sane local-first defaults so the app runs with zero config
(`uvicorn app.main:app`). Override via environment / .env for cloud.
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent          # .../app
PROJECT_DIR = BASE_DIR.parent                       # repo root
DATA_DIR = Path(os.getenv("AEGIS_DATA_DIR", PROJECT_DIR / "data"))


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    APP_NAME: str = os.getenv("AEGIS_APP_NAME", "Aegis GRC")

    # SQLite by default (local); set to postgresql+psycopg://user:pass@host/db for cloud.
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", f"sqlite:///{(DATA_DIR / 'aegis.db').as_posix()}"
    )

    # Session signing key. CHANGE THIS IN PRODUCTION.
    SECRET_KEY: str = os.getenv(
        "AEGIS_SECRET_KEY", "dev-insecure-change-me-please-0123456789abcdef"
    )

    # Seed demo data (sample users / catalog / templates / an example assessment).
    SEED_DEMO: bool = _bool(os.getenv("AEGIS_SEED_DEMO"), default=True)

    # Default password for seeded demo accounts.
    DEMO_PASSWORD: str = os.getenv("AEGIS_DEMO_PASSWORD", "aegis123")

    # Bootstrap maintenance/superuser account — created on every startup if absent,
    # so a real (non-demo) deployment always has a way to sign in. Set the password
    # via AEGIS_ADMIN_PASSWORD; if unset in a non-demo deploy, a strong random one is
    # generated and logged once on first boot (and flagged to be changed).
    ADMIN_USERNAME: str = os.getenv("AEGIS_ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("AEGIS_ADMIN_PASSWORD", "")

    # Anthropic key — only used if you later enable the (stubbed) AI assist layer.
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")


settings = Settings()
