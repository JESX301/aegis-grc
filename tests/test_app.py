"""Integration tests driving the real ASGI app via TestClient.

These mirror the post-deploy smoke_test.py but run in-process (no server), so
they're fast enough to gate every push in CI. The most important behaviour under
test is the workflow engine's separation of duty: a submitter cannot approve
their own work.
"""
from tests.conftest import login


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["app"] == "Aegis GRC"


def test_login_reaches_dashboard(client):
    r = login(client, "analyst")
    assert r.status_code == 200
    assert "Dashboard" in r.text


def test_seeded_assessment_listed(client):
    login(client, "analyst")
    r = client.get("/assessments")
    assert "Customer Portal" in r.text


def test_rbac_vendor_cannot_create_entity(client):
    login(client, "vendor")
    r = client.get("/entities/new")          # vendor lacks analyst role -> redirected away
    assert "analyst role" in r.text or "Entities" in r.text
    # vendor should not see the create form's submit control
    assert "Create entity" not in r.text


def test_report_and_oscal_export(client):
    login(client, "analyst")
    assert "Control implementation summary" in client.get("/assessments/1/report").text
    payload = client.get("/assessments/1/export.json").json()
    assert "control-implementation" in payload
    assert payload["assessment"]["title"]


def test_separation_of_duty(client):
    # analyst (actor for the Implement stage) submits for review
    login(client, "analyst")
    r = client.post("/assessments/1/submit", data={"comment": "ready for review"})
    assert "awaiting approval" in r.text

    # analyst tries to approve their OWN submission -> must be blocked, still pending
    r = client.post("/assessments/1/approve", data={"comment": "approving my own"})
    assert "awaiting approval" in r.text

    # a different role (reviewer) approves -> stage advances
    login(client, "review")
    r = client.post("/assessments/1/approve", data={"comment": "looks good"})
    assert ("Approved" in r.text) or ("Assess" in r.text)
    assert "awaiting approval" not in r.text
