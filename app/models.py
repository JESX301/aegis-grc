"""Canonical GRC data model.

One shape per object across every track, mirroring the design in
`Modernized-Workflows/00-Overview-Platform-and-Operating-Model.md`:

    Entity / Asset, Control (+ Catalog), Assessment (+ ControlResult),
    Finding, Risk, Exception, Remediation, Ticket, Evidence,
    plus Users/Roles and an append-only AuditLog and Workflow templates.

Foreign keys are plain int fields; relationships are resolved with explicit
queries in the routers to keep behaviour predictable.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Optional

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.utcnow()


# --------------------------------------------------------------------------- #
# Identity & access
# --------------------------------------------------------------------------- #
class UserRoleLink(SQLModel, table=True):
    user_id: Optional[int] = Field(default=None, foreign_key="user.id", primary_key=True)
    role_id: Optional[int] = Field(default=None, foreign_key="role.id", primary_key=True)


class Role(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    description: str = ""


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    email: str = ""
    full_name: str = ""
    hashed_password: str = ""
    team: str = ""           # optional org unit / line-of-business scope
    is_active: bool = True
    must_change_password: bool = False   # set for the auto-generated bootstrap admin
    created_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Control catalogs (controls-as-data; OSCAL-aligned)
# --------------------------------------------------------------------------- #
class Catalog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True)
    name: str = ""
    version: str = ""
    source: str = ""


class Control(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    catalog_id: int = Field(foreign_key="catalog.id", index=True)
    control_id: str = Field(index=True)       # e.g. "AC-2"
    family: str = ""
    title: str = ""
    statement: str = ""
    baseline: str = ""                        # comma list: low,moderate,high


# --------------------------------------------------------------------------- #
# Entities / assets (systems, apps, databases, vendors, business units)
# --------------------------------------------------------------------------- #
class Entity(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    type: str = "system"                      # system|application|computer|database|vendor|business_unit
    owner_id: Optional[int] = Field(default=None, foreign_key="user.id")
    parent_id: Optional[int] = Field(default=None, foreign_key="entity.id")
    criticality: str = "Moderate"             # Critical|High|Moderate|Low
    data_classification: str = ""             # e.g. PHI, PII, Public
    confidentiality: str = ""                 # FIPS-199 style: Low|Moderate|High
    integrity: str = ""
    availability: str = ""
    description: str = ""
    tags: str = ""
    created_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Workflow templates (per-track stage definitions with SoD roles)
# --------------------------------------------------------------------------- #
class WorkflowTemplate(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    key: str = Field(index=True, unique=True)        # rmf|tprm|ir|vuln
    name: str = ""
    description: str = ""
    uses_controls: bool = False                      # seed ControlResults from a catalog?


class WorkflowStage(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    template_id: int = Field(foreign_key="workflowtemplate.id", index=True)
    order: int = 0
    name: str = ""
    description: str = ""
    actor_role: str = "analyst"          # who may submit this stage for review
    approver_role: str = "approver"      # who may approve to advance (must differ from submitter)
    is_terminal: bool = False


# --------------------------------------------------------------------------- #
# Assessments (a running instance of a workflow against an entity)
# --------------------------------------------------------------------------- #
class Assessment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = ""
    template_id: int = Field(foreign_key="workflowtemplate.id", index=True)
    entity_id: Optional[int] = Field(default=None, foreign_key="entity.id", index=True)
    catalog_id: Optional[int] = Field(default=None, foreign_key="catalog.id")
    stage_order: int = 0                  # index into the template's ordered stages
    state: str = "active"                 # active|closed
    # Two-phase gate state for the *current* stage:
    pending_review: bool = False
    submitted_by: Optional[int] = Field(default=None, foreign_key="user.id")
    submitted_at: Optional[datetime] = None
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")
    created_at: datetime = Field(default_factory=utcnow)


class ControlResult(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    control_id: int = Field(foreign_key="control.id", index=True)
    status: str = "not_implemented"       # implemented|partial|planned|not_implemented|not_applicable
    detail: str = ""
    updated_by: Optional[int] = Field(default=None, foreign_key="user.id")
    updated_at: datetime = Field(default_factory=utcnow)


class Transition(SQLModel, table=True):
    """Append-only record of every workflow gate action (audit of SoD)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    from_stage: int = 0
    to_stage: int = 0
    action: str = ""                      # submit|approve|reject|close
    actor_id: Optional[int] = Field(default=None, foreign_key="user.id")
    comment: str = ""
    created_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Findings / risks / exceptions / remediation / tickets / evidence
# --------------------------------------------------------------------------- #
class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = ""
    description: str = ""
    entity_id: Optional[int] = Field(default=None, foreign_key="entity.id", index=True)
    assessment_id: Optional[int] = Field(default=None, foreign_key="assessment.id")
    control_id: Optional[int] = Field(default=None, foreign_key="control.id")
    severity: str = "Medium"              # Critical|High|Medium|Low|Info
    status: str = "open"                  # open|closed|risk_accepted
    source: str = "manual"                # manual|scanner|assessment|incident
    cve: str = ""
    cvss: Optional[float] = None
    epss: Optional[float] = None
    kev: bool = False                     # on CISA Known Exploited Vulnerabilities list
    dedupe_hash: str = Field(default="", index=True)
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")
    created_at: datetime = Field(default_factory=utcnow)


class Risk(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = ""
    finding_id: Optional[int] = Field(default=None, foreign_key="finding.id")
    likelihood: str = "Medium"            # Low|Medium|High
    impact: str = "Medium"
    inherent: str = ""
    residual: str = ""
    treatment: str = "mitigate"           # accept|mitigate|transfer|avoid
    owner_id: Optional[int] = Field(default=None, foreign_key="user.id")
    status: str = "open"                  # open|treated|accepted|closed
    created_at: datetime = Field(default_factory=utcnow)


class Exception(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: Optional[int] = Field(default=None, foreign_key="finding.id")
    control_ref: str = ""
    justification: str = ""
    compensating: str = ""
    expiry: Optional[date] = None
    approver_id: Optional[int] = Field(default=None, foreign_key="user.id")
    state: str = "requested"              # requested|approved|expired|rejected
    created_at: datetime = Field(default_factory=utcnow)


class Remediation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: Optional[int] = Field(default=None, foreign_key="finding.id", index=True)
    title: str = ""
    owner_id: Optional[int] = Field(default=None, foreign_key="user.id")
    steps: str = ""
    target_date: Optional[date] = None
    state: str = "open"                   # open|in_progress|done|verified
    created_at: datetime = Field(default_factory=utcnow)


class Ticket(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    remediation_id: Optional[int] = Field(default=None, foreign_key="remediation.id")
    title: str = ""
    assignee_id: Optional[int] = Field(default=None, foreign_key="user.id")
    priority: str = "P3"
    sla_due: Optional[date] = None
    external_ref: str = ""                # link to ServiceNow/Jira when bridged
    state: str = "open"
    created_at: datetime = Field(default_factory=utcnow)


class Evidence(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    subject_type: str = ""                # assessment|finding|entity|control
    subject_id: int = 0
    title: str = ""
    type: str = "document"               # document|screenshot|config|scan|attestation
    collected_by: Optional[int] = Field(default=None, foreign_key="user.id")
    auto_collected: bool = False
    uri: str = ""
    note: str = ""
    created_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Audit log (append-only)
# --------------------------------------------------------------------------- #
class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    actor_id: Optional[int] = Field(default=None, foreign_key="user.id")
    actor_name: str = ""
    action: str = ""
    object_type: str = ""
    object_id: Optional[int] = None
    detail: str = ""
    created_at: datetime = Field(default_factory=utcnow)
