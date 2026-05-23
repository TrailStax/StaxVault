# CRA Compliance mapping

## EU Cyber Resilience Act — Component Mapping
Mandatory reporting: September 2026
Enforcement: December 2027

---

## Core Position

Traditional compliance is a photograph — a snapshot
of one day in 365. This stack makes compliance
continuous and cryptographically tamper-proof.

Every agent action is signed, chained, and audit-ready
the moment it happens — not the week before an auditor
arrives. The audit trail operates on the same continuous
timeline as the adversary.

---

## Component Mapping to CRA Requirements

### Vulnerability Reporting (Article 11)
**Component: TrailStax**
Every gate interaction — pass or deny — is committed
to an append-only hash-chained audit log with reason
codes. Vulnerability attempts are logged automatically
with full context at the moment they occur, not
reconstructed after the fact.

### Software Supply Chain Security (Article 13)
**Component: TrailStax guardian.py**
Pre-install verification and package allowlist
enforcement for all Python dependencies. Every
package installation is verified against a
Redis-backed registry before being permitted.
Unapproved packages are blocked and logged.

### Access Control and Authentication (Article 13)
**Component: RealAgentID + ragid_gate**
Cryptographic keypair authentication with TTL
enforcement, nonce-based replay attack prevention,
scope-gate binding, uniform error responses, and
Redis-backed rate limiting. Two independent
verification factors required for every agent action.

### Incident Logging (Article 14)
**Component: TrailStax + ragid_gate**
Every gate result — authorized or denied — is
committed to the audit chain with agent identity,
requested gate, decision, reason code, and timestamp.
Deny reasons include: keypair_invalid, ttl_expired,
scope_sig_invalid, nonce_replayed, wrong_gate,
rate_limited, trail_commit_failed.

### Secure by Default (Article 13)
**Component: ragid_gate**
Deny by default at every check. If the audit chain
is unavailable, nothing gets through. Valid credentials
at the wrong gate are denied. Rate limiting engages
before verification compute is spent. Explicit deny
always beats permitted.

### Software Integrity (Article 13)
**Component: Ira-Digital-Blueprints + TrailStax**
Every blueprint is provenance-hashed at generation
time and committed to TrailStax. Hash is verified
at application time. Mismatch results in deny and
quarantine entry. Training data only enters pipelines
from verified agent sources — enforced at the gate
level, not by policy.

---

## Continuous Compliance vs Point-in-Time

Point-in-time audits capture one day in 365.
This stack generates compliance evidence
automatically at every agent action.

Key properties:
- Hash-chained entries cannot be altered retroactively
- Deletion is recorded as a tombstone, not a silent gap
- Audit evidence exists before the auditor asks for it
- Non-compliance is as permanently recorded as compliance

---

## Known Limitations

**Right to Erasure**
GDPR Article 17 and CRA create tension with
immutable audit chains. Mitigation: TTL-based
retention with erasure tombstones — deletions
are recorded as chain entries rather than silent
gaps. Chain integrity is preserved. Planned
implementation in TrailStax roadmap.

**Insider Threat**
Cryptographic verification confirms agent identity,
not the integrity of the human who issued the
credential. A compromised credential issuer can
generate legitimate-looking trail entries.
Mitigation: agent lineage registry and behavioral
attestation via reasoning.py — planned roadmap items.

**Infrastructure Dependency**
Hard deny-by-default means TrailStax or Redis
outages halt agent activity. This is the correct
security posture but requires careful SLA design
for production deployments.

**Clock Skew**
TTL relies on system time. Mitigation: server-side
timestamp validation and NTP enforcement — planned
roadmap item.

---

## Framework Alignment

- SLSA Level 2+ — provenance and build integrity
- SOC 2 Type II — continuous control monitoring
- NIST SSDF — secure development framework
- EU CRA — mandatory reporting and supply chain
- GDPR — erasure tombstone pattern
- ISO 27001 — access control and audit logging

---

*This document covers ragid_gate, RealAgentID,
TrailStax, and Ira-Digital-Blueprints collectively.
Each repo's COMPLIANCE.md contains the shared
cross-system authorization invariant.*
