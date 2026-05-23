# CrossroadCode Stack Roadmap

This roadmap spans RealAgentID, TrailStax, ragid_gate, and
Ira-Digital-Blueprints. All four projects share a unified
security architecture governed by the Cross-System Authorization
Invariant documented in each repo's COMPLIANCE.md.

---

## ragid_gate

**Next — Rate Limiting**
- Redis-based rate limiter per agent_id
- X attempts per Y seconds before lockout
- Lockout events logged to TrailStax

**Then — Constant-Time Comparisons**
- Extend hmac.compare_digest to all verification steps
- Close timing attack surface

---

## RealAgentID

**Next — Agent Lineage Registry**
- Full lineage array replacing single parent_agent_id
- Generation limit enforcement
- Spawn as a gated action
- TTL cascade — entire tree expires with root
- Permissions narrow down tree, never expand

**Then — Clock Skew Hardening**
- Server-side timestamp validation
- NTP enforcement
- Remove trust from claim's own issued_at

---

## TrailStax

**Next — TTL + Erasure Tombstones**
- retain_until and erasure_eligible fields at write time
- Automated purge job for eligible entries
- Tombstone entries replace erased records
- Chain integrity preserved through documented gaps

**Then — Neo4j Integration**
- Trail events ingested into Neo4j as graph
- Agent nodes, spawn edges, gate interaction relationships
- Orphan detection and permission creep queries
- Behavioral anomaly detection across lineage trees

---

## Ira-Digital-Blueprints

**Core Objective**
Securely structure verified agentic activity into trainable
data chunks for org-specific LLM training pipelines. Only
verified agents can produce data that enters the pipeline —
enforced at the gate level, not by policy.

**Next — Pipeline Scheduling**
- is_off_peak() check before training jobs launch
- CPU/memory threshold as secondary safety valve
- training_execution as a gated action in ragid_gate
- Off-peak enforcement at the identity layer

**Then — Milestone-Driven Blueprinting**
- On-demand optimization triggered by human or authorized agent
- Ira reads Neo4j graph at trigger time
- Produces blueprint + gap report for human review
- Human approves before application
- Each cycle is a discrete compliance artifact

**Then — Blueprint Provenance Hardening**
- Hash committed to TrailStax at generation time
- Verification at application time
- Mismatch results in deny and quarantine entry

---

## Cross-Stack

**Immediate — CRA_COMPLIANCE.md**
- Map each component to specific CRA articles
- Known limitations section
- Continuous compliance positioning
- September 2026 mandatory reporting context

**Then — Neo4j as Unified Observability Layer**
- Single queryable surface across all four projects
- Security queries and architectural gap detection
- Training data lineage mapping
- Agentic behavioral intelligence

**Then — reasoning.py**
- Reasoning hop measurement across model providers
- Dead end and confidence signal scoring
- Neo4j as query surface across reasoning,
  lineage, and audit data simultaneously

---

## Architectural Invariant

A valid action across this stack must satisfy three
independent conditions:

1. Keypair Authenticity — the agent is who it claims to be
2. Scope-Gate Binding — the credential is valid for this gate
3. Blueprint Provenance Integrity — the artifact matches its
   TrailStax-committed hash

Satisfaction of any one or two does not constitute
authorization.
