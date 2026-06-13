# Federal security baseline readiness & implementation epics

How Aegis GRC maps to current US federal security baselines, what it already satisfies, the gaps,
and the epics (feature efforts) to close them.

## Target baselines
- **NIST SP 800-53 Rev 5 — Moderate** (the control catalog; FedRAMP Moderate ≈ 323 controls).
- **FedRAMP Rev 5 Moderate** (cloud authorization; 2026 "CR26" relabels Moderate → **Class C**).
- **NIST SP 800-63-4 / 800-63B — AAL2** (digital identity / authentication).
- **OMB M-22-09 (Zero Trust)** — phishing-resistant MFA, encryption in transit, robust logging.
- **OMB M-21-31** — event-logging maturity.

> Anchor target = **FedRAMP Moderate / 800-53 r5 Moderate**. Status legend: ✅ done · ⚠️ partial · ❌ gap.

## Current posture (what the product already does)
- ✅ **AC-5 Separation of duty** — workflow engine: submitter ≠ approver, enforced + audited.
- ✅ **AC-6 Least privilege / AC-3** — role-based access (admin/analyst/reviewer/approver/vendor/read_only).
- ✅ **AU-2/AU-3 (partial) Audit events** — append-only `AuditLog` on logins, workflow gates, CRUD.
- ✅ **IA-5 (partial)** — PBKDF2-HMAC-SHA256 password storage (FIPS-approved algorithm).
- ✅ **SC-8 in transit** — TLS at the edge via Caddy (deploy stack); app not host-published (SC-7).
- ✅ **CM-2/CM-6** — baseline config as code (Docker/compose), hardening checklist (vm-deploy skill).
- ✅ **RA-5/SI-2 (partial)** — CI builds + tests on every change (no dependency scan yet).

---

## Epics

### EPIC 1 — Authentication & MFA  (Phase 1 + 2)
**Controls:** IA-2, IA-2(1)(2), IA-5, AC-7, 800-63B AAL2, M-22-09
- ⚠️ Password policy: enforce length (≥12), screen against breached-password lists, **no forced periodic rotation** (per 800-63B), block common passwords. *(AC-7/IA-5)*
- ❌ Account lockout / throttling after N failed attempts. *(AC-7)*
- ❌ **MFA** — *Phase 1:* TOTP (authenticator app) for AAL2. *Phase 2:* **WebAuthn/FIDO2 (phishing-resistant)** to satisfy M-22-09; OTP/push are MFA but **not** phishing-resistant.
- ❌ SSO via OIDC/SAML to an agency IdP (PIV/CAC-backed). *(IA-2, Phase 2)*
**Done when:** failed-login lockout active; password policy enforced; TOTP enrollment + challenge working; WebAuthn available; all auth events audited.

### EPIC 2 — Session security  (Phase 1)
**Controls:** AC-11, AC-12, SC-23
- ❌ Idle **session timeout** + absolute lifetime; re-auth on expiry. *(AC-11/AC-12)*
- ⚠️ Session cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax/Strict`. *(SC-23)*
- ❌ **CSRF protection** on all state-changing POSTs. *(SC-23/SI-10)*
**Done when:** sessions expire on idle + absolute limit; cookies hardened; CSRF tokens enforced and tested.

### EPIC 3 — Account lifecycle & access management  (Phase 2)
**Controls:** AC-2, AC-2(3), AC-3, AC-5 ✅, AC-6 ✅
- ❌ Account lifecycle: create/modify/**disable**/remove; auto-disable after inactivity; disabled ≠ deleted.
- ❌ Admin user-management UI (create users, assign/revoke roles) — currently seed-only.
- ❌ Periodic **access review** report (who has which role; last login).
**Done when:** admins manage the full account lifecycle in-app; inactive accounts auto-disable; access-review export exists.

### EPIC 4 — Audit & accountability  (Phase 1 + 2)
**Controls:** AU-2, AU-3, AU-6, AU-8, AU-9, AU-11, AU-12, M-21-31
- ⚠️ Event coverage: add **failed logins, authz denials, privilege/role changes, exports**. *(AU-2/AU-12)*
- ⚠️ Record content: who/what/when/where/outcome + source IP. *(AU-3)*
- ❌ **Tamper-evidence**: hash-chain audit records (detect modification). *(AU-9)*
- ❌ UTC/synchronized timestamps documented (AU-8); retention config (AU-11); SIEM export (JSON/syslog).
**Done when:** auth + authz + admin events captured with full content + source IP; audit log is hash-chained and integrity-verifiable; export endpoint for SIEM.

### EPIC 5 — Cryptographic protection  (Phase 1 doc + Phase 2 impl)
**Controls:** SC-8, SC-13, SC-28, IA-7
- ✅ In transit (Caddy TLS 1.2+/1.3). ⚠️ Document **FIPS 140-validated** crypto module / FIPS mode. *(SC-13)*
- ❌ **Encryption at rest** for the database (Postgres TDE / encrypted volume) + secrets. *(SC-28)*
**Done when:** at-rest encryption documented + enabled in the deploy path; FIPS-mode guidance shipped.

### EPIC 6 — Flaw remediation & supply chain  (Phase 1)
**Controls:** RA-5, SI-2, SI-3, SR-3, SR-11
- ❌ **Dependency / SCA scanning** in CI (pip-audit / OSV-Scanner) + Dependabot. *(RA-5/SI-2)*
- ❌ **SBOM** (CycloneDX) generated on build. *(SR-3/SR-4)*
- ❌ Static analysis (Semgrep/Bandit) gate. *(SA-11)*
**Done when:** CI fails on known-vuln deps; SBOM published per release; SAST gate green.

### EPIC 7 — Contingency & availability  (Phase 2)
**Controls:** CP-9, CP-10
- ⚠️ Backup guidance exists (volume snapshot in vm-deploy). ❌ Automated, tested DB backup + documented restore.
**Done when:** scheduled backups + a verified restore runbook.

### EPIC 8 — Configuration & least functionality  (mostly ✅)
**Controls:** CM-2 ✅, CM-6 ✅, CM-7, SC-7 ✅
- ⚠️ App-level security headers (CSP, X-Frame-Options) for deployments without Caddy. *(SC-7/SI-10)*
**Done when:** secure headers emitted by the app itself as defense-in-depth.

### EPIC 9 — Continuous monitoring & authorization package  (Phase 3)
**Controls:** CA-2, CA-5, CA-7, PL-2, RA-3
- The product already generates OSCAL SSP/SAR/POA&M — use Aegis to author **its own** authorization
  package (dogfooding), and add a continuous-monitoring dashboard for control status drift.
**Done when:** an OSCAL SSP for Aegis-on-Aegis exists; ConMon dashboard shows control posture over time.

---

## Suggested phasing
- **Phase 1 (now, fits the architecture):** EPIC 2 (session security + CSRF), EPIC 1 password policy + lockout, EPIC 4 audit hardening (events + hash-chain + UTC), EPIC 6 dependency scan + SBOM in CI, EPIC 8 app security headers.
- **Phase 2:** MFA (TOTP → WebAuthn phishing-resistant), OIDC SSO, account lifecycle UI + access review, encryption at rest, automated backups.
- **Phase 3:** Full FedRAMP Moderate control coverage, 3PAO-ready OSCAL SSP (Aegis-on-Aegis), ConMon dashboards, supply-chain (SR) controls.

> Reality check: full **FedRAMP Moderate authorization is an organizational + 3PAO process**, not just code. These epics make the *product technically capable* of meeting the control intents; formal ATO requires policies, an assessment, and continuous monitoring on top.
