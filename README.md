# TrailStax
### *The stacks that builds trust.*

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

An agent with misconfigured permissions or a compromised identity can make those same changes faster, at scale, and without a human approving each action. Worse, most enterprise agent platforms — including major enterprise platforms — lock audit trails inside the platform. Viewing them externally requires building a custom MCP server and a dedicated agent. That's not governance. That's a workaround.

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
| Agent reward hacking — solves task via unintended artifact access | trail.py scope policies flag out-of-scope access before commit; violation locked into hash chain |

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

trail.log("session.start", {"target": "example.com", "mode": "passive"})

# Method attestation — declare how the task was done and what was accessed
trail.log(
    "feature.reimplement",
    payload={"status": "complete"},
    method_declared=["read_spec", "write_code", "run_tests"],
    artifacts_accessed=["src/feature.py", "tests/test_feature.py"],
    task_type="feature_reimplementation"
)

# Scope violation fires automatically if agent accesses out-of-bounds artifacts
# [TrailStax] WARNING: SCOPE VIOLATION - agent=... task=feature_reimplementation

print(trail.verify_chain())     # True — chain intact, violation locked in
report = trail.audit_report()
print(report["scope_violations"])  # 1
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
git clone https://github.com/TrailStax/StaxVault.git
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
| v0.1 | `trail.py` — hash-chained action audit log | Alpha |
| v0.2 | `codebank.py` — hash-chained code commit registry | Alpha|
| v0.3 | `tests/` — pytest suite, chain integrity + tamper cases | Alpha |
| v0.3.5 | Method attestation + scope enforcement in `trail.py` | ✅ Shipped |
| v0.4 | Redis backend — live agent session streaming | In Progress |
| v0.5 | `sign.py` — RealAgentID keypair signing of trail + code commits | Alpha |
| v0.6 | Multi-agent session merging + cross-agent audit | In Progress |
| v1.0 | Full COMPLIANCE.md + NIST AI RMF alignment | Alpha |

---

## Relationship to RealAgentID

| Layer | Project | Question Answered |
|---|---|---|
| Protocol | [RealAgentID](https://github.com/wishuponascar22/RealAgentID) | Who is this agent? |
| Implementation | TrailStax | What did it do? What code did it run? |
| Combined | Both | Can this agent's actions be trusted end-to-end? |

The four trust layers:

| Layer | Mechanism | Question Answered |
|---|---|---|
| Identity | RealAgentID keypair | Who is this agent? |
| Action | `trail.py` hash chain | What did it do? |
| Method | Attestation fields + scope policies | How did it do it? |
| Reasoning | `reasoning.py` (roadmap) | Did it reason legitimately? |

TrailStax is the first production implementation of the RealAgentID protocol. When `sign.py` lands in v0.5, every trail entry and code commit will carry a RealAgentID keypair signature — binding identity to action to code in a single verifiable artifact.

---

## License

MIT — Use it, build on it, cite it when you publish.

---

*Built by [CrossroadCode](https://github.com/wishuponascar22) — at the crossroads of trust and automation.*
