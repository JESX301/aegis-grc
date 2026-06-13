"""Idempotent seed data: roles, demo users, control catalog, and the four
pre-built workflow tracks (mapped from the Modernized-Workflows playbooks).

Runs on startup when AEGIS_SEED_DEMO is true (default). Safe to run repeatedly —
it only creates objects that are missing.
"""
from __future__ import annotations

import json

from sqlmodel import Session, select

from .config import BASE_DIR, settings
from .models import (
    Assessment,
    Catalog,
    Control,
    ControlResult,
    Entity,
    Finding,
    Role,
    User,
    UserRoleLink,
    WorkflowStage,
    WorkflowTemplate,
)
from .security import hash_password

# --------------------------------------------------------------------------- #
# Static seed definitions
# --------------------------------------------------------------------------- #
ROLES = [
    ("admin", "Full administrative access; manages users, catalogs, and config."),
    ("analyst", "Performs assessments, fills control results, raises findings (submitter)."),
    ("reviewer", "Reviews submitted work before approval."),
    ("approver", "Authorizing official; approves gate transitions (must differ from submitter)."),
    ("vendor", "External third party; responds to questionnaires only."),
    ("read_only", "Read-only auditor / stakeholder access."),
]

# username -> (full_name, email, team, [roles])
DEMO_USERS = {
    "admin":   ("Platform Admin",     "admin@example.local",   "IT",        ["admin"]),
    "analyst": ("Alex Analyst",       "analyst@example.local", "Security",  ["analyst"]),
    "review":  ("Riley Reviewer",     "review@example.local",  "Security",  ["reviewer", "approver"]),
    "ciso":    ("Casey CISO",         "ciso@example.local",    "Exec",      ["approver", "reviewer"]),
    "vendor":  ("Vic Vendor",         "vendor@example.local",  "External",  ["vendor"]),
    "auditor": ("Avery Auditor",      "auditor@example.local", "Audit",     ["read_only"]),
}

# Workflow tracks. Each stage: (name, actor_role, approver_role, description)
TEMPLATES = [
    {
        "key": "rmf",
        "name": "Compliance / RMF / ATO",
        "description": "NIST SP 800-37 Risk Management Framework as a controls-as-code authorization pipeline (modernizes the Client-FS IS-RMF program).",
        "uses_controls": True,
        "stages": [
            ("Prepare",   "analyst", "approver", "Establish context, boundary, and common controls."),
            ("Categorize","analyst", "approver", "FIPS-199 categorization (C-I-A high-water mark)."),
            ("Select",    "analyst", "approver", "Tailor the baseline into a system control profile."),
            ("Implement", "analyst", "reviewer", "Implement controls; record implementation status + evidence."),
            ("Assess",    "reviewer","approver", "Independently assess control effectiveness (SAR)."),
            ("Authorize", "approver","approver", "Authorizing official issues the authorization decision (ATO)."),
            ("Monitor",   "analyst", "approver", "Continuous monitoring (cATO); ongoing assessment."),
        ],
    },
    {
        "key": "tprm",
        "name": "Third-Party / Vendor Risk Management",
        "description": "Vendor risk lifecycle with a preliminary questionnaire that scopes the deep-dive assessment (modernizes the Client-MEDIA VRM program).",
        "uses_controls": True,
        "stages": [
            ("Intake",            "analyst", "reviewer", "Vendor request received; entity created."),
            ("Preliminary Qnr",   "vendor",  "analyst",  "Vendor completes preliminary questionnaire."),
            ("Scoping",           "analyst", "reviewer", "Tier the vendor; scope the assessment from PQ answers."),
            ("Assessment",        "analyst", "reviewer", "Deep-dive assessment / evidence review."),
            ("Findings",          "reviewer","approver", "Findings issued; management response captured."),
            ("Remediation",       "vendor",  "analyst",  "Time-boxed remediation + follow-up."),
            ("Final Report",      "analyst", "approver", "Final report issued; residual risk accepted/closed."),
        ],
    },
    {
        "key": "ir",
        "name": "Incident Response / SOC",
        "description": "EOI -> triage -> investigate -> respond -> validate -> close (modernizes the Client-HC Incident Manager).",
        "uses_controls": False,
        "stages": [
            ("Intake (EOI)",   "analyst", "reviewer", "Event of interest captured from SIEM/SOAR or manually."),
            ("Triage",         "analyst", "reviewer", "SOC triage: close / escalate / convert to incident."),
            ("Investigation",  "analyst", "reviewer", "Level-2 analysis; scope and impact determination."),
            ("Remediation",    "analyst", "reviewer", "Contain / eradicate / recover; raise tickets."),
            ("Validation",     "reviewer","approver", "Independent validation of closure (ASM != SIR)."),
            ("Close",          "approver","approver", "Incident formally closed and documented."),
        ],
    },
    {
        "key": "vuln",
        "name": "Vulnerability Management / ConMon",
        "description": "Scope -> scan -> validate -> risk-rate -> report -> remediate -> verify (modernizes the Client-HOSP / Client-RETAIL AVR engagements).",
        "uses_controls": False,
        "stages": [
            ("Scope",      "analyst", "reviewer", "Define scan scope by network-segment criticality."),
            ("Scan",       "analyst", "reviewer", "Authenticated + unauthenticated scanning."),
            ("Validate",   "analyst", "reviewer", "False-positive validation (3-tier corroboration)."),
            ("Risk-Rate",  "analyst", "reviewer", "Prioritize with CVSS + EPSS + CISA KEV."),
            ("Report",     "reviewer","approver", "Issue the assessment report (AVR equivalent)."),
            ("Remediate",  "analyst", "reviewer", "SLA-driven remediation tracking."),
            ("Verify",     "reviewer","approver", "Re-scan and verify closure."),
        ],
    },
]


# --------------------------------------------------------------------------- #
# Seeding
# --------------------------------------------------------------------------- #
def _get_role(session: Session, name: str) -> Role:
    role = session.exec(select(Role).where(Role.name == name)).first()
    if not role:
        role = Role(name=name)
        session.add(role)
        session.commit()
        session.refresh(role)
    return role


def seed_roles(session: Session) -> None:
    for name, desc in ROLES:
        role = session.exec(select(Role).where(Role.name == name)).first()
        if not role:
            session.add(Role(name=name, description=desc))
    session.commit()


def seed_users(session: Session) -> None:
    pw = hash_password(settings.DEMO_PASSWORD)
    for username, (full_name, email, team, roles) in DEMO_USERS.items():
        user = session.exec(select(User).where(User.username == username)).first()
        if user:
            continue
        user = User(
            username=username,
            full_name=full_name,
            email=email,
            team=team,
            hashed_password=pw,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        for role_name in roles:
            role = _get_role(session, role_name)
            session.add(UserRoleLink(user_id=user.id, role_id=role.id))
        session.commit()


def seed_catalog(session: Session) -> Catalog:
    path = BASE_DIR / "data" / "catalog_nist_800-53_sample.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    catalog = session.exec(select(Catalog).where(Catalog.key == data["key"])).first()
    if not catalog:
        catalog = Catalog(
            key=data["key"],
            name=data["name"],
            version=data["version"],
            source=data["source"],
        )
        session.add(catalog)
        session.commit()
        session.refresh(catalog)
    existing = session.exec(
        select(Control).where(Control.catalog_id == catalog.id)
    ).first()
    if not existing:
        for c in data["controls"]:
            session.add(
                Control(
                    catalog_id=catalog.id,
                    control_id=c["control_id"],
                    family=c["family"],
                    title=c["title"],
                    statement=c["statement"],
                    baseline=c["baseline"],
                )
            )
        session.commit()
    return catalog


def seed_templates(session: Session) -> None:
    for tpl in TEMPLATES:
        template = session.exec(
            select(WorkflowTemplate).where(WorkflowTemplate.key == tpl["key"])
        ).first()
        if template:
            continue
        template = WorkflowTemplate(
            key=tpl["key"],
            name=tpl["name"],
            description=tpl["description"],
            uses_controls=tpl["uses_controls"],
        )
        session.add(template)
        session.commit()
        session.refresh(template)
        for order, (name, actor, approver, desc) in enumerate(tpl["stages"]):
            session.add(
                WorkflowStage(
                    template_id=template.id,
                    order=order,
                    name=name,
                    description=desc,
                    actor_role=actor,
                    approver_role=approver,
                    is_terminal=(order == len(tpl["stages"]) - 1),
                )
            )
        session.commit()


def seed_example(session: Session, catalog: Catalog) -> None:
    """A single worked example so the dashboard isn't empty on first run."""
    if session.exec(select(Entity)).first():
        return
    admin = session.exec(select(User).where(User.username == "admin")).first()
    analyst = session.exec(select(User).where(User.username == "analyst")).first()

    entity = Entity(
        name="Customer Portal (Production)",
        type="system",
        owner_id=analyst.id if analyst else None,
        criticality="High",
        data_classification="PII",
        confidentiality="Moderate",
        integrity="Moderate",
        availability="High",
        description="Internet-facing customer web application and its supporting database tier.",
        tags="web,production,internet-facing",
    )
    session.add(entity)
    session.commit()
    session.refresh(entity)

    rmf = session.exec(
        select(WorkflowTemplate).where(WorkflowTemplate.key == "rmf")
    ).first()
    assessment = Assessment(
        title="Customer Portal — Initial Authorization",
        template_id=rmf.id,
        entity_id=entity.id,
        catalog_id=catalog.id,
        stage_order=3,  # at "Implement"
        created_by=admin.id if admin else None,
    )
    session.add(assessment)
    session.commit()
    session.refresh(assessment)

    controls = session.exec(
        select(Control).where(Control.catalog_id == catalog.id)
    ).all()
    for i, ctrl in enumerate(controls):
        status = "implemented" if i % 3 else "partial"
        session.add(
            ControlResult(
                assessment_id=assessment.id,
                control_id=ctrl.id,
                status=status,
                detail="Seeded example result.",
                updated_by=analyst.id if analyst else None,
            )
        )
    session.commit()

    session.add(
        Finding(
            title="MFA not enforced for administrative accounts",
            description="Administrative access to the portal does not require multi-factor authentication.",
            entity_id=entity.id,
            assessment_id=assessment.id,
            severity="High",
            status="open",
            source="assessment",
            created_by=analyst.id if analyst else None,
        )
    )
    session.commit()


def seed_all() -> None:
    from .database import engine

    with Session(engine) as session:
        seed_roles(session)
        if settings.SEED_DEMO:
            seed_users(session)
            catalog = seed_catalog(session)
            seed_templates(session)
            seed_example(session, catalog)
        else:
            # still load the catalog + templates so the app is usable
            catalog = seed_catalog(session)
            seed_templates(session)
