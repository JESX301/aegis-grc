"""Pytest fixtures. Isolate the DB to a temp dir BEFORE importing the app so the
test run never touches a real database, then expose a TestClient (which runs the
app's lifespan = create tables + seed demo data once)."""
import os
import tempfile

# Must be set before importing app.config (settings are read at import time).
os.environ["AEGIS_DATA_DIR"] = tempfile.mkdtemp(prefix="aegis-test-")
os.environ["AEGIS_SECRET_KEY"] = "test-secret-key"
os.environ["AEGIS_SEED_DEMO"] = "true"
os.environ["AEGIS_DEMO_PASSWORD"] = "aegis123"

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:   # `with` triggers startup (init_db + seed)
        yield c


def login(client, username, password="aegis123"):
    return client.post("/login", data={"username": username, "password": password})
