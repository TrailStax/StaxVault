# TrailStax

### *The stack that builds trust.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![RealAgentID](https://img.shields.io/badge/RealAgentID-v0.1-00e5a0.svg)](https://github.com/wishuponascar22/RealAgentID)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](https://github.com/TrailStax/StaxVault)
[![OWASP Agentic](https://img.shields.io/badge/OWASP-Agentic%20Top%2010-red.svg)](docs/TrailStax_OWASP_Gap_Analysis.docx)

-----

## What TrailStax Is

TrailStax is a **secure ModelOps governance platform** — the cryptographic trust stack that makes AI agent pipelines safe enough to ship in regulated environments.

> *“Future AI platforms will likely treat AI agents as a platform persona, with permissions, quotas, and policies alongside their human colleagues.”*
> — platformengineering.org, Intro to AI in Platform Engineering

**We didn’t wait for that future. We built it.**

- **Permissions** → RealAgentID
- **Quotas** → quota.py *(in development)*
- **Policies** → guardian.py + validator.py *(in development)*

-----

## The Problem

**40% of platform teams report their AI-generated code is unstable.**
**74.9% of platform teams are already hosting agents or will be soon.**
**Most have no governance layer for what those agents do.**

Cloud consoles are already vulnerable to insider threats. Agentic AI multiplies that risk — an agent with misconfigured permissions or a compromised identity can modify IAM roles, escalate permissions, or introduce malicious dependencies faster than any human reviewer can catch.

Worse: most enterprise agent platforms lock audit trails inside the platform. That’s not governance. That’s a workaround.

TrailStax is built on a different premise:

> *Audit trails, code commits, and supply chain verification belong to the operator — not the platform. They must be cryptographically verifiable, append-only, and portable by design.*

-----

## The First Implementation of RealAgentID

[RealAgentID](https://github.com/wishuponascar22/RealAgentID) established the protocol — cryptographic identity for AI agents. **TrailStax is where that protocol runs in the real world.**

Every audit trail entry, code commit, and package install in TrailStax is bound to a RealAgentID-verified agent identity, producing a complete, tamper-evident record of:

- **Who** the agent was — verified by RealAgentID keypair
- **What** it did — append-only, hash-chained action log
- **What code** it ran — append-only, hash-chained code commit registry
- **What it installed** — signed package registry with pre-install verification

No platform lock-in. No MCP workaround required. The trail is yours.

-----

## Real-World Validation

**May 2026 — Grafana Labs supply chain attack:**
A compromised TanStack npm package led to stolen GitHub workflow tokens, repository access, and a ransom demand. `guardian.py`’s pre-install hash verification and signed registry directly address this attack pattern.

**Industry data:**

- 40% of platform teams report unstable AI-generated code *(Weave Intelligence, State of AI in Platform Engineering)*
- 74.9% of platform teams are already hosting or about to host AI agents *(platformengineering.org)*
- Supply chain attacks are in the Trough of Disillusionment on the Gartner Hype Cycle — meaning real buyers are now looking for real solutions

-----

## Modules

### `trail.py` — Agent Action Audit Log ✅ Alpha

Tamper-proof, append-only log of every action an agent takes during a session. Hash-chained from genesis — modifying any entry breaks every hash that follows.

```python
from trailstax import TrailStax

trail = TrailStax(agent_id="recon-agent-001")
trail.log("session.start",    {"target": "example.com", "mode": "passive"})
trail.log("iam.role_check",   {"role": "storage.admin", "granted": True})
trail.log("session.complete", {"duration_ms": 2140, "findings": 2})

print(trail.verify_chain())   # True — untampered
trail.export("session_trail.json")
```

### `codebank.py` — Code Commit Registry ✅ Alpha

Append-only registry of every code artifact an agent is authorized to run. Hash a file when it’s approved. Verify it hasn’t changed before execution.

```python
from trailstax import CodeBank

bank = CodeBank(agent_id="recon-agent-001")
bank.register_file("agents/recon_agent.py")
bank.register_file("agents/utils.py", metadata={"version": "1.2.0"})

ok, detail = bank.verify_file("agents/recon_agent.py")
print(ok, detail)   # True, {"match": True, "label": "recon_agent.py"}
```

### `guardian.py` — Supply Chain Defense ✅ Alpha

Pre-install verification and pip hook enforcement for Python agent environments. Intercepts every `pip install` before execution, verifies against a signed package registry, and alerts the agent mesh via Redis pub/sub on any blocked attempt.

```bash
# Install pip hook
python guardian.py install-hook

# Approve packages
python guardian.py approve requests 2.31.0
python guardian.py approve redis 5.0.1

# Every install attempt now verified before execution
pip install requests
# [guardian] ✓ requests — Approved

# View tamper-proof audit trail
python guardian.py trail
```

**Features:**

- HMAC-SHA256 signed package registry via RealAgentID secret
- Redis-backed registry shared across agent mesh (falls back to local file)
- Hash-chained audit trail — every attempt logged, approved or blocked
- Redis pub/sub alerts broadcast to all agents on blocked installs
- PyPI hash verification for pinned versions

### `validator.py` — Prompt Validation Layer 🔨 In Development

Input sanitization, intent verification, and output schema enforcement. Addresses ASI01 (Agent Goal Hijack) — the highest severity unmitigated threat in the OWASP Agentic Top 10.

### `quota.py` — Resource Quota Enforcement 🔜 Planned

Redis-based per-agent rate limiting. Tracks API calls, token consumption, and compute time. Agents exceeding quotas are automatically quarantined from the mesh. Addresses ASI05 (Resource Overuse).

### `codeguard.py` — Auto-Generated Code Scanning 🔜 Planned

Pre-signature static analysis gate for AI-generated code. Runs Semgrep and Bandit before `codebank.py` signs anything. No vulnerable or malicious generated code enters the signed registry.

### `lifecycle.py` — Model Lifecycle Management 🔜 Planned

Manages the full model lifecycle: Train → Evaluate → Stage → Promote → Monitor → Detect drift → Retrain → Rollback. RealAgentID-gated promotions. Drift detection triggers automatic Ira retraining pipeline.

### `sentinel.py` — Vulnerability Intelligence 🔜 Planned

Research monitoring agent. Continuously ingests arXiv, OWASP updates, CVE feeds, and HackerOne disclosed reports. Classifies findings against the TrailStax compliance framework and drafts threat model updates. Built on Ira’s ingestion pattern.

### `reasoning.py` — Reasoning Auditability 🔜 Planned

Measures and compares model reasoning across GPT/Gemini/Claude using graph queries on reasoning hops, dead ends, and confidence signals. Neo4j integration. The fourth trust layer above RealAgentID, trail, and codebank.

-----

## Architecture

```
TrailStax
├── trailstax/
│   ├── __init__.py
│   ├── trail.py          Append-only hash-chained agent action audit log
│   ├── codebank.py       Append-only hash-chained code commit registry
│   └── sign.py           RealAgentID keypair signing layer (v0.5 roadmap)
├── guardian.py           Supply chain defense — pip hook + signed registry
├── tests/
│   ├── test_trail.py
│   └── test_codebank.py
├── docs/
│   ├── TrailStax_OWASP_Gap_Analysis.docx
│   └── Ira_Threat_Model_v1.docx
├── COMPLIANCE.md         7-framework alignment including OWASP Agentic Top 10
├── CHANGELOG.md
├── setup.py
└── README.md
```

### How the Chain Works

Every entry — whether an action log, code commit, or install attempt — is hashed with its predecessor’s hash. The chain begins at a genesis sentinel (`0x000...000`) and grows forward, append-only. Modifying any entry anywhere in the chain breaks every hash that follows it. Detection is instant.

```
GENESIS (0x000...000)
     │
     ▼
[Entry 0] ──hash──▶ [Entry 1] ──hash──▶ [Entry 2] ──hash──▶ ... ──hash──▶ [Entry N]
session.start       iam.role_check        firewall.query                    session.end

Tamper any entry here ──────────────────^ breaks every hash forward
```

-----

## Threat Model

|Threat                                        |TrailStax Response                                  |
|----------------------------------------------|----------------------------------------------------|
|Insider swaps agent code before execution     |codebank.py detects hash mismatch at registration   |
|Compromised dependency slipped into pipeline  |guardian.py blocks at install — before execution    |
|Post-install script executes malicious code   |guardian.py pip hook intercepts before pip runs     |
|Agent self-modification at runtime            |trail.py + codebank.py catch the divergence         |
|Agent silently changes IAM / firewall rules   |trail.py logs every action with full payload        |
|Platform holds audit data hostage             |JSON export runs anywhere — no vendor required      |
|Replay attack on agent identity               |RealAgentID TTL enforcement blocks stale credentials|
|Auto-generated code introduces vulnerabilities|codeguard.py static analysis gate *(planned)*       |
|Model drift in production                     |lifecycle.py drift detection + rollback *(planned)* |
|Prompt injection via agent inputs             |validator.py intent verification *(in development)* |

Full threat model for Ira integration: [`docs/Ira_Threat_Model_v1.docx`](docs/Ira_Threat_Model_v1.docx)

-----

## OWASP Agentic Top 10 Coverage

TrailStax maps to the OWASP Top 10 for Agentic Applications (2025–2026):

|ASI ID|Category                    |Status          |Module              |
|------|----------------------------|----------------|--------------------|
|ASI01 |Agent Goal Hijack           |🔨 In Development|validator.py        |
|ASI02 |Tool Misuse                 |🟡 Partial       |RealAgentID identity|
|ASI03 |Identity & Privilege Abuse  |✅ Covered       |RealAgentID         |
|ASI04 |Memory Poisoning            |🟡 Partial       |codebank.py         |
|ASI05 |Resource Overuse            |🔜 Planned       |quota.py            |
|ASI06 |Supply Chain Vulnerabilities|✅ Covered       |guardian.py         |
|ASI07 |Data Exfiltration           |🟡 Partial       |trail.py forensics  |
|ASI08 |Cascading Failures          |🟡 Partial       |trail.py tracing    |
|ASI09 |Insecure Output Handling    |🟡 Partial       |codebank.py         |
|ASI10 |Shared Resource Abuse       |🟡 Partial       |Redis + RealAgentID |

Full gap analysis: [`docs/TrailStax_OWASP_Gap_Analysis.docx`](docs/TrailStax_OWASP_Gap_Analysis.docx)

-----

## Compliance Framework Alignment

|Framework           |Controls                        |
|--------------------|--------------------------------|
|NIST CSF            |DE.CM-3, RS.AN-1, PR.PT-1       |
|SOC 2               |CC7.2, CC4.1, CC6.1             |
|ISO 27001           |A.12.4.1, A.12.4.3, A.9.4.1     |
|NIST AI RMF         |GOVERN 1.2, MEASURE 2.5, MAP 1.5|
|NIST SP 800-53      |AU-9, AU-10, AU-12              |
|NIST SP 800-161     |Supply chain risk management    |
|OWASP Agentic Top 10|ASI01–ASI10 *(Framework 7)*     |

Full control mapping in [`COMPLIANCE.md`](COMPLIANCE.md)

-----

## Quickstart

```bash
git clone https://github.com/TrailStax/StaxVault.git
cd StaxVault
pip install -e .
python demo.py

# guardian.py supply chain defense
python guardian.py install-hook
python guardian.py approve requests 2.31.0
python guardian.py status
```

-----

## Roadmap

|Version|Feature                                                   |Status          |
|-------|----------------------------------------------------------|----------------|
|v0.1   |`trail.py` — hash-chained action audit log                |✅ Alpha         |
|v0.2   |`codebank.py` — hash-chained code commit registry         |✅ Alpha         |
|v0.3   |`guardian.py` — supply chain defense + pip hook + Redis   |✅ Alpha         |
|v0.4   |`validator.py` — prompt validation and intent verification|🔨 In Development|
|v0.5   |`quota.py` — Redis-based per-agent resource quotas        |🔜 Planned       |
|v0.6   |Ollama model serving integration                          |🔜 Planned       |
|v0.7   |`codeguard.py` — auto-generated code static analysis gate |🔜 Planned       |
|v0.8   |`lifecycle.py` — model lifecycle management               |🔜 Planned       |
|v0.9   |`sentinel.py` — continuous vulnerability intelligence     |🔜 Planned       |
|v1.0   |`reasoning.py` — reasoning auditability + Neo4j           |🔜 Planned       |

-----

## Relationship to RealAgentID

|Layer         |Project                                                      |Question Answered                                         |
|--------------|-------------------------------------------------------------|----------------------------------------------------------|
|Protocol      |[RealAgentID](https://github.com/wishuponascar22/RealAgentID)|Who is this agent?                                        |
|Implementation|TrailStax                                                    |What did it do? What code did it run? What did it install?|
|Combined      |Both                                                         |Can this agent’s actions be trusted end-to-end?           |

-----

## Relationship to Ira

[Ira](https://github.com/Ira-Digital-Blueprints/Ira) is a secure ModelOps platform that maps organizational data into a digital blueprint and trains org-specific open source models on that blueprint. TrailStax is Ira’s governance backbone:

- RealAgentID — cryptographic identity for all Ira agents
- trail.py — audit trail for every pipeline event
- codebank.py — signed registry for all datasets and model commits
- guardian.py — supply chain defense for all Ira dependencies
- lifecycle.py — model lifecycle management *(planned)*

-----

## License

MIT — Use it, build on it, cite it when you publish.

-----

*Built by [CrossroadCode](https://github.com/wishuponascar22) — at the crossroads of trust and automation.*