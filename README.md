# TrailStax
### *The stack that builds trust.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![RealAgentID](https://img.shields.io/badge/RealAgentID-v0.1-00e5a0.svg)](https://github.com/wishuponascar22/RealAgentID)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

---

## The First Implementation of RealAgentID

[RealAgentID](https://github.com/wishuponascar22/RealAgentID) established the protocol — cryptographic identity for AI agents. **TrailStax is where that protocol runs in the real world.**

This is not a companion tool. This is the reference implementation. Every audit trail entry and every code commit in TrailStax is bound to a RealAgentID-verified agent identity, producing a complete, tamper-evident record of:

- **Who** the agent was — verified by RealAgentID keypair
- **What** it did — append-only, hash-chained action log
- **What code** it ran — append-only, hash-chained code commit registry

No platform lock-in. No MCP workaround required. The trail is yours.

---

## Why TrailStax Exists

Cloud consoles are already vulnerable to insider threats. A malicious or compromised actor can quietly modify IAM roles, escalate permissions, or loosen firewall rules — and traditional logging often can't prove the record wasn't altered after the fact.

**Agentic AI multiplies that risk.**

An agent with misconfigured permissions or a compromised identity can make those same changes faster, at scale, and without a human approving each action. Worse, most enterprise agent platforms — including Google's Gemini Enterprise — lock audit trails inside the platform. Viewing them externally requires building a custom MCP server and a dedicated agent. That's not governance. That's a workaround.

TrailStax is built on a different premise:

> *Audit trails and code commits belong to the operator, not the platform. They must be cryptographically verifiable, append-only, and portable by design.*

---

## Threat Model

| Threat | TrailStax Response |
|---|---|
| Insider swaps agent code before execution | CodeBank detects hash mismatch at registration time |
| Compromised dependency slipped into pipeline | CodeBank flags any unregistered module hash |
| Agent self-modification at runtime | trail.py + codebank.py together catch the divergence |
| Agent silently changes IAM / firewall rules | trail.py logs every action with full payload, tamper-proof |
| Platform holds audit data hostage | JSON export runs anywhere — no vendor required |
| Replay attack on agent identity | RealAgentID TTL enforcement blocks stale credentials |

---

## Architecture

```
TrailStax
├── trailstax/
│   ├── __init__.py
│   ├── trail.py        Append-only, hash-chained agent action audit log
│   ├── codebank.py     Append-only, hash-chained code commit registry
│   └── sign.py         RealAgentID keypair signing layer (v0.5 roadmap)
├── tests/
│   ├── test_trail.py
│   └── test_codebank.py
├── docs/
│   ├── ARCHITECTURE.md
│   └── THREAT_MODEL.md
├── demo.py
├── COMPLIANCE.md       NIST CSF / SOC 2 / ISO 27001 / NIST AI RMF mapping
├── CHANGELOG.md
├── setup.py
└── README.md
```

### How the Chain Works

Every entry — whether an action log or a code commit — is hashed with its predecessor's hash. The chain begins at a genesis sentinel (`0x000...000`) and grows forward, append-only. Modifying any entry anywhere in the chain breaks every hash that follows it. Detection is instant.

```
GENESIS (0x000...000)
     │
     ▼
[Entry 0] ──hash──▶ [Entry 1] ──hash──▶ [Entry 2] ──hash──▶ ... ──hash──▶ [Entry N]
session.start       iam.role_check        firewall.query                    session.end

Tamper any entry here ──────────────────^ breaks every hash forward
```

---

## Modules

### `trail.py` — Agent Action Audit Log

Tamper-proof, append-only log of every action an agent takes during a session.

```python
from trailstax import TrailStax

trail = TrailStax(agent_id="recon-agent-001")

trail.log("session.start",    {"target": "example.com", "mode": "passive"})
trail.log("iam.role_check",   {"role": "storage.admin", "granted": True})
trail.log("firewall.query",   {"rule": "allow-all-ingress", "found": True})
trail.log("recon.port_scan",  {"ports_checked": [80, 443], "open": [443]})
trail.log("session.complete", {"duration_ms": 2140, "findings": 2})

print(trail.verify_chain())   # True — untampered
trail.export("session_trail.json")
```

### `codebank.py` — Code Commit Registry

Append-only registry of every code artifact an agent is authorized to run. Hash a file when it's approved. Verify it hasn't changed before execution.

```python
from trailstax import CodeBank

bank = CodeBank(agent_id="recon-agent-001")

# Register approved code at deployment time
bank.register_file("agents/recon_agent.py")
bank.register_file("agents/utils.py", metadata={"version": "1.2.0"})
bank.register_content("firewall.rule", "deny all inbound port 22")

print(bank.verify_chain())    # True — registry untampered

# Verify at runtime before execution
ok, detail = bank.verify_file("agents/recon_agent.py")
print(ok, detail)             # True, {"match": True, "label": "recon_agent.py"}

bank.export("codebank.json")
```

---

## Quickstart

```bash
git clone https://github.com/TrailStax/trailstax.git
cd trailstax
pip install -e .
python demo.py
```

---

## Compliance Framework Alignment

| Framework | Controls |
|---|---|
| NIST CSF | DE.CM-3, RS.AN-1, PR.PT-1 |
| SOC 2 | CC7.2, CC4.1, CC6.1 |
| ISO 27001 | A.12.4.1, A.12.4.3, A.9.4.1 |
| NIST AI RMF | GOVERN 1.2, MEASURE 2.5, MAP 1.5 |
| NIST SP 800-53 | AU-9, AU-10, AU-12 |
| GDPR | Art. 5(1)(f), Art. 32 |

Full control mapping in [`COMPLIANCE.md`](COMPLIANCE.md).

---

## Roadmap

| Phase | Feature | Status |
|---|---|---|
| v0.1 | `trail.py` — hash-chained action audit log | ✅ Alpha |
| v0.2 | `codebank.py` — hash-chained code commit registry | 🔨 In Progress |
| v0.3 | `tests/` — pytest suite, chain integrity + tamper cases | 🔜 |
| v0.4 | Redis backend — live agent session streaming | 🔜 |
| v0.5 | `sign.py` — RealAgentID keypair signing of trail + code commits | 🔜 |
| v0.6 | Multi-agent session merging + cross-agent audit | 🔜 |
| v1.0 | Full COMPLIANCE.md + NIST AI RMF alignment | 🔜 |

---

## Relationship to RealAgentID

| Layer | Project | Question Answered |
|---|---|---|
| Protocol | [RealAgentID](https://github.com/wishuponascar22/RealAgentID) | Who is this agent? |
| Implementation | TrailStax | What did it do? What code did it run? |
| Combined | Both | Can this agent's actions be trusted end-to-end? |

TrailStax is the first production implementation of the RealAgentID protocol. When `sign.py` lands in v0.5, every trail entry and code commit will carry a RealAgentID keypair signature — binding identity to action to code in a single verifiable artifact.

---

## License

MIT — Use it, build on it, cite it when you publish.

---

*Built by [CrossroadCode](https://github.com/wishuponascar22) — at the crossroads of trust and automation.*
