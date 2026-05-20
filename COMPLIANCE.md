
---

## Framework 7: OWASP Top 10 for Agentic Applications

**Added:** 2026-05-20
**Reference:** OWASP Top 10 for Agentic AI Systems (2025-2026)

| ASI ID | Category | Status | Module |
|--------|----------|--------|--------|
| ASI01 | Agent Goal Hijack | Gap | Planned: prompt validation layer |
| ASI02 | Tool Misuse | Partial | RealAgentID identity; tool-scope planned |
| ASI03 | Identity & Privilege Abuse | Covered | RealAgentID |
| ASI04 | Memory Poisoning | Partial | codebank.py; embedding integrity planned |
| ASI05 | Resource Overuse | Gap | Planned: Redis rate limiting |
| ASI06 | Supply Chain Vulnerabilities | Covered | guardian.py |
| ASI07 | Data Exfiltration | Partial | trail.py forensics; active prevention planned |
| ASI08 | Cascading Failures | Partial | trail.py tracing; circuit breaker planned |
| ASI09 | Insecure Output Handling | Partial | codebank.py; downstream validation planned |
| ASI10 | Shared Resource Abuse | Partial | Redis controlled via RealAgentID signatures |
