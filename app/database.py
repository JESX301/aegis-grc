"""Database engine + session management (SQLite local, PostgreSQL in cloud)."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from sqlmodel import Session, SQLModel, create_engine

from .config import DATA_DIR, settings

# Ensure the data directory exists for the default SQLite file.
Path(DATA_DIR).mkdir(parents=True, exist_ok=True)

connect_args = {"check_same_thread": False} if settings.is_sqlite else {}
engine = create_engine(settings.DATABASE_URL, echo=False, connect_args=connect_args)


def init_db() -> None:
    """Create all tables. Models must be imported before calling this."""
    from . import models  # noqa: F401  (register models on metadata)

    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    """FastAPI dependency that yields a scoped DB session."""
    with Session(engine) as session:
        yield session
