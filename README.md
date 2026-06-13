# Aegis GRC — a self-hostable GRC platform

A small, modern, **self-hostable** Governance-Risk-Compliance platform that operationalizes the
[`Modernized-Workflows/`](../Modernized-Workflows) playbooks. It is the working successor to the
Agiliance RiskVision pattern: one canonical data model driven by a configurable **workflow engine that
enforces submit → review → approve separation of duty**, pre-seeded with the four tracks from the playbooks.

Built with **Python + FastAPI**, server-rendered (Jinja2), **SQLite** by default (zero-config) and
**PostgreSQL** for cloud. Runs locally with one command or as a container anywhere.

---

## What it implements

| Playbook concept | In Aegis |
|---|---|
| Canonical data model (00 — Overview) | `Entity · Catalog/Control · Assessment · ControlResult · Finding · Risk · Exception · Remediation · Ticket · Evidence · AuditLog` |
| Workflow gates + separation of duty | Two-phase stage engine: an **actor** submits, a **different** approver advances. Submitter can never approve their own work. |
| Dev→UAT→PROD promotion discipline | Mirrored as the append-only `Transition` + `AuditLog` trail on every gate action. |
| Compliance / RMF / ATO (01) | Pre-seeded **rmf** track (Prepare→…→Monitor), control-based, NIST 800-53 sample catalog. |
| Third-Party Risk (02) | Pre-seeded **tprm** track with a vendor-questionnaire stage. |
| Incident Response / SOC (03) | Pre-seeded **ir** track (EOI→triage→…→close). |
| Vulnerability Mgmt (04) | Pre-seeded **vuln** track; findings carry CVE / CVSS / EPSS / KEV. |
| JasperReports | Printable assessment summary (HTML→PDF via browser print) **+ OSCAL-flavoured JSON export**. |
| RBAC / access filters | Role model: `admin, analyst, reviewer, approver, vendor, read_only`. |

> All client identities in the seed data use the same sector pseudonyms as the playbooks (Client-FS, Client-HC, …).

---

## Quick start (local, no Docker)

Requires Python 3.11+.

```bash
cd Aegis-GRC-Platform
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000** and sign in. A SQLite DB + demo data is created automatically on first run.

## Quick start (Docker — recommended)

```bash
cd Aegis-GRC-Platform
docker compose up --build
```

Open **http://127.0.0.1:8000**. Data persists in the `aegis-data` volume.

### With PostgreSQL (cloud-style)

```bash
# uncomment DATABASE_URL + depends_on in docker-compose.yml, then:
docker compose --profile postgres up --build
```

---

## Demo accounts

All use the demo password (default **`aegis123`**, set via `AEGIS_DEMO_PASSWORD`):

| Username | Roles | Use it to… |
|---|---|---|
| `admin`   | admin | manage users, see the audit log |
| `analyst` | analyst | create entities/assessments, fill control results, **submit** stages |
| `review`  | reviewer + approver | **approve** stages (different person than the submitter) |
| `ciso`    | approver | act as authorizing official / risk acceptor |
| `vendor`  | vendor | external questionnaire role |
| `auditor` | read_only | read-only + audit log |

### See separation of duty in action
1. Sign in as **`analyst`**, open the seeded *“Customer Portal — Initial Authorization”* assessment, edit control results, and **Submit for review**.
2. Sign out, sign in as **`review`** (or `ciso`), and **Approve & advance**.
3. Note that `analyst` *cannot* approve their own submission, and the whole gate history is recorded under **Gate history** and **Audit**.

---

## Configuration

All via environment variables (see `.env.example`):

| Var | Default | Purpose |
|---|---|---|
| `AEGIS_SECRET_KEY` | dev key (warns) | **set in production** — signs session cookies |
| `DATABASE_URL` | `sqlite:///…/data/aegis.db` | use `postgresql+psycopg://…` for cloud |
| `AEGIS_DATA_DIR` | `./data` | where SQLite + data live |
| `AEGIS_SEED_DEMO` | `true` | seed demo users + example assessment |
| `AEGIS_DEMO_PASSWORD` | `aegis123` | demo account password |
| `AEGIS_APP_NAME` | `Aegis GRC` | UI title |

---

## Deploying to the cloud

The image is a standard stateless container — it runs on any container host:

- **VM / VPS:** `docker compose up -d` behind a reverse proxy (Caddy/Nginx) for TLS.
- **AWS ECS / Fargate, Azure Container Apps, Google Cloud Run, Fly.io, Render:** push the image, set `DATABASE_URL` to a managed Postgres (RDS/Cloud SQL), set `AEGIS_SECRET_KEY`, mount no local volume (Postgres holds state).
- **Kubernetes:** one Deployment + Service; put secrets in a `Secret`, Postgres via your operator of choice.

Production checklist: set `AEGIS_SECRET_KEY`, use Postgres, terminate TLS at the proxy, set `AEGIS_SEED_DEMO=false` (and create real users), and front auth with an IdP (see below).

---

## Architecture

```
app/
  main.py          FastAPI app, middleware, startup (init_db + seed)
  config.py        env-driven settings
  database.py      engine/session (SQLite or Postgres)
  models.py        the canonical data model (SQLModel tables)
  security.py      PBKDF2 passwords, session auth, RBAC, audit + flash
  seed.py          roles, demo users, 800-53 sample catalog, 4 workflow tracks
  templating.py    Jinja2 + render() helper
  routers/         auth, dashboard, entities, catalog, assessments,
                   findings, risks, reports, admin
  templates/ , static/ , data/   UI, CSS, control catalog JSON
```

The **workflow engine** lives in `routers/assessments.py`: each track is rows in
`WorkflowTemplate` + `WorkflowStage` (with `actor_role` and `approver_role`). An assessment carries a
`stage_order` and a two-phase `pending_review` flag; `/submit`, `/approve`, `/reject`, `/close`
enforce the role checks and the **submitter ≠ approver** rule, writing every action to `Transition`.

---

## Extending it

- **Swap the control catalog:** drop another OSCAL/JSON catalog into `app/data/` and load it in `seed.py` (ISO 27002, CSF 2.0, FedRAMP, CMMC — the engine is catalog-agnostic).
- **Add a workflow track:** append to `TEMPLATES` in `seed.py` — no code changes to the engine.
- **Real SSO:** put an OIDC proxy (oauth2-proxy) in front, or wire `authlib` into `routers/auth.py`; map IdP groups → roles (replaces the demo password login).
- **The agentic-AI layer (doc 05):** an `ANTHROPIC_API_KEY` hook is reserved in `config.py`. The intended pattern is AI **drafts** (control narratives, triage, remediation tickets) that land in the *same* human submit→review→approve gates — never auto-approve.

---

## Security notes (MVP honesty)

This is a working MVP, not a hardened product. Before real use: change the secret key, move to Postgres,
add TLS + an IdP, add CSRF protection on state-changing forms, rate-limit login, and review the RBAC
matrix against your separation-of-duty policy. The append-only `AuditLog`/`Transition` tables give you the
evidence trail; the rest is deployment hygiene.

*Generated as a companion to the `Modernized-Workflows/` playbooks.*
