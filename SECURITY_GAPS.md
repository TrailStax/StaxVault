# Security Gaps and Continued Development

This document tracks known incomplete implementations,
hardening opportunities, and new vulnerabilities that
require attention as the stack evolves.

Updated continuously. Cross-references ROADMAP.md.

---

## Known Code Gaps

**core/sandbox.py — _inspect_output**
Current output inspection only catches empty output,
oversized output, and private key patterns.
Needs: expanded pattern library, semantic output
analysis, and integration with tool registry to
verify output matches expected tool output format.

**core/vault.py — Key Management**
Vault keys currently stored in Redis with TTL.
Needs: hardware security module (HSM) integration
for production deployments. Redis key storage is
acceptable for development only.

**ragid_gate/gate.py — Clock Skew**
Current implementation uses fixed 30 second threshold.
Needs: statistical anomaly detection for drift patterns.
Slow clock manipulation (1 second per hour) currently
undetectable.

**ragid_gate/gate.py — Tool Call Interception**
Gate currently verifies agent identity and scope.
Tool calls after gate passage are not yet intercepted
and verified against tool registry.
Needs: tool call interceptor wired into gate flow.

**core/lineage.py — Federated Root Scope Enforcement**
Federated roots have scope_limit field defined but
gate does not yet enforce it.
Needs: ragid_gate to check federated root scope_limit
against requested gate before passing Factor 3.

**core/tool_registry.py — Anomaly Detection**
Current anomaly detection uses simple frequency
threshold.
Needs: time-series analysis, per-agent behavioral
baseline, and alert escalation to TrailStax when
anomaly detected.

---

## Hardening Opportunities

**Constant-Time Comparisons**
Extend hmac.compare_digest to all string comparisons
in gate.py to close timing attack surface completely.

**NTP Enforcement**
Server-side NTP sync verification before timestamp
checks. Prevents host clock manipulation.

**Output Sanitization**
Sandbox output inspection needs semantic analysis
not just pattern matching.

**Redis Persistence**
Current Redis setup is in-memory. Production deployments
need Redis persistence configured to survive restarts.

---

## Intelligence Pipeline Targets

Monitor these sources for new vulnerabilities
affecting adjacent frameworks:

- CrewAI CVE feed
- LangChain security advisories
- AutoGen GitHub security alerts
- OWASP LLM Top 10 updates
- Five Eyes agentic AI guidance updates
- ENISA CRA implementation guidance
- arXiv cs.CR new papers

---

## Planned Mitigations

See ROADMAP.md for implementation schedule:
- Statistical clock skew detection
- Tool call interception in gate flow
- Federated root scope enforcement
- Neo4j behavioral anomaly graph queries
- HSM integration for vault key management
