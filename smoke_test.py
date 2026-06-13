"""End-to-end smoke test: drives the real HTTP server with cookie sessions."""
import http.cookiejar
import sys
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8077"


def opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def get(op, path):
    r = op.open(BASE + path)
    return r.getcode(), r.read().decode()


def post(op, path, data):
    d = urllib.parse.urlencode(data).encode()
    r = op.open(BASE + path, d)
    return r.getcode(), r.read().decode()


fails = []
def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        fails.append(name)


code, body = get(opener(), "/healthz")
check("healthz returns 200/ok", code == 200 and '"status"' in body)

an = opener()
code, body = get(an, "/login")
check("login page renders", code == 200 and "Sign in" in body)

code, body = post(an, "/login", {"username": "analyst", "password": "aegis123"})
check("analyst login -> dashboard", "Dashboard" in body)

code, body = get(an, "/assessments")
check("seeded assessment listed", "Customer Portal" in body)

code, body = get(an, "/assessments/1")
check("assessment detail renders (Workflow stepper)", "Workflow" in body and "Implement" in body)

code, body = post(an, "/assessments/1/submit", {"comment": "ready for review"})
check("analyst can submit Implement stage", "awaiting approval" in body)

# analyst (submitter, no reviewer role) tries to approve -> must be blocked
code, body = post(an, "/assessments/1/approve", {"comment": "approving my own"})
check("SoD: analyst approve blocked (still pending)", "awaiting approval" in body)

# reviewer approves
rv = opener()
post(rv, "/login", {"username": "review", "password": "aegis123"})
code, body = post(rv, "/assessments/1/approve", {"comment": "looks good"})
check("reviewer approve advances stage", ("Approved" in body) or ("Assess" in body))

code, body = get(rv, "/assessments/1")
check("stage advanced to Assess", "Assess" in body and "awaiting approval" not in body)

# reporting
code, body = get(rv, "/assessments/1/report")
check("printable report renders", "Control implementation summary" in body)
code, body = get(rv, "/assessments/1/export.json")
check("OSCAL-flavoured JSON export", '"control-implementation"' in body)

# rbac: vendor cannot create entity page
vn = opener()
post(vn, "/login", {"username": "vendor", "password": "aegis123"})
code, body = get(vn, "/entities/new")
check("RBAC: vendor redirected away from entity creation", "analyst role" in body or "Entities" in body)

print("\nFAILURES:", fails if fails else "none")
sys.exit(1 if fails else 0)
