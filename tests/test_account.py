"""Tests for the role-adaptive /account page and its account controls.

Password-mutating tests use the `ciso` user (no other test logs in as ciso) and
restore the password, so they don't contaminate the shared session DB.
"""
from tests.conftest import login


def test_account_renders_for_analyst(client):
    login(client, "analyst")
    r = client.get("/account")
    assert r.status_code == 200
    assert "My Account" in r.text
    assert "Awaiting my submission" in r.text   # analyst panel
    assert "Change password" in r.text          # common control


def test_account_admin_snapshot(client):
    login(client, "admin")
    r = client.get("/account")
    assert "Organization snapshot" in r.text
    assert "Manage users" in r.text


def test_account_vendor_is_scoped(client):
    login(client, "vendor")
    r = client.get("/account")
    assert "My questionnaires" in r.text
    assert "no internal data" in r.text
    assert "Organization snapshot" not in r.text   # vendor must not see admin panel


def test_account_readonly_has_no_action_buttons(client):
    login(client, "auditor")
    r = client.get("/account")
    assert "Auditor access" in r.text
    assert "+ New assessment" not in r.text        # read-only: no create actions


def test_edit_profile(client):
    login(client, "ciso")
    client.post("/account/profile", data={"full_name": "Casey Updated", "email": "casey@example.test"})
    r = client.get("/account")
    assert "Casey Updated" in r.text


def test_change_password_rejects_wrong_current(client):
    login(client, "ciso")
    r = client.post("/account/password", data={"current": "wrong-pw", "new": "whatever123", "confirm": "whatever123"})
    assert "Current password is incorrect" in r.text
    # password unchanged: original still works
    assert "Dashboard" in login(client, "ciso", "aegis123").text


def test_change_password_success_then_restore(client):
    login(client, "ciso")
    r = client.post("/account/password", data={"current": "aegis123", "new": "newpass123", "confirm": "newpass123"})
    assert "Password changed" in r.text
    assert "Dashboard" in login(client, "ciso", "newpass123").text   # new password works
    # restore so other tests (and reruns) keep the default
    login(client, "ciso", "newpass123")
    client.post("/account/password", data={"current": "newpass123", "new": "aegis123", "confirm": "aegis123"})
    assert "Dashboard" in login(client, "ciso", "aegis123").text
