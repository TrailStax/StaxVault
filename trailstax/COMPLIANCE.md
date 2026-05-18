# TrailStax — Compliance Framework Mapping

**Version:** 0.1.0 
**Modules:** `trail.py` · `codebank.py` 
**Protocol:** RealAgentID 
**Maintainer:** CrossroadCode / TrailStax Org

-----

## Overview

TrailStax provides an append-only, hash-chained audit and code commit registry for AI agents. Every agent action and every code artifact is cryptographically signed, sequenced, and tamper-evident at the time of execution. This document maps TrailStax controls to six security and compliance frameworks.

-----

## 1. NIST Cybersecurity Framework (CSF 2.0)

|Function    |Category                     |TrailStax Control                                                                                                      |
|------------|-----------------------------|-----------------------------------------------------------------------------------------------------------------------|
|**IDENTIFY**|Asset Management (ID.AM)     |`codebank.py` registers every agent module, script, and dependency as a `CodeCommit` with file path, hash, and agent ID|
|**PROTECT** |Data Security (PR.DS)        |SHA-256 hash-chaining ensures no commit can be silently modified — tamper detection is structural, not policy-based    |
|**PROTECT** |Protective Technology (PR.PT)|Append-only registry prevents deletion or reordering of audit records                                                  |
|**DETECT**  |Anomalies & Events (DE.AE)   |`verify_chain()` detects any break in the hash chain; `verify_file()` re-hashes on-disk files and flags mismatches     |
|**DETECT**  |Continuous Monitoring (DE.CM)|`verify_content()` enables runtime re-verification of inline configs, IAM rules, and firewall policies                 |
|**RESPOND** |Analysis (RS.AN)             |`bank_report()` exports full commit history with chain validity, genesis hash, and tail hash for incident analysis     |
|**RECOVER** |Improvements (RC.IM)         |Exported registry JSON enables post-incident reconstruction of the exact code state at any point in time               |

-----

## 2. SOC 2 (Trust Services Criteria)

|Criteria                             |TrailStax Control                                                                                                                                                |
|-------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
|**CC6.1** — Logical access controls  |`agent_id` is a required field on every `CodeCommit` and `TrailLog` entry — no anonymous writes                                                                  |
|**CC6.6** — Boundary protection      |`verify_file()` detects unauthorized file modifications at the boundary between registered state and runtime state                                               |
|**CC7.2** — Monitoring for anomalies |`verify_chain()` provides continuous integrity verification; any tampered commit breaks the chain and returns `False`                                            |
|**CC8.1** — Change management        |Every code artifact registration is an immutable, timestamped, sequenced record — constitutes a cryptographic change log                                         |
|**A1.2** — Availability and integrity|Hash-chained commits ensure the integrity of the audit trail itself cannot be silently compromised                                                               |
|**PI1.4** — Processing integrity     |`_compute_hash()` includes `commit_id`, `agent_id`, `label`, `code_hash`, `file_path`, `timestamp`, `sequence`, and `prev_hash` — full provenance on every record|

-----

## 3. ISO/IEC 27001:2022

|Control                                |Clause|TrailStax Control                                                                                                             |
|---------------------------------------|------|------------------------------------------------------------------------------------------------------------------------------|
|Information classification             |5.12  |All registered artifacts carry `label`, `file_path`, `agent_id`, and `metadata` — enabling classification at registration time|
|Logging and monitoring                 |8.15  |`trail.py` provides append-only agent action logging; `codebank.py` provides code artifact logging — dual-layer audit         |
|Protection of log information          |8.15  |Hash-chaining ensures log integrity; appended records cannot be altered without breaking the chain                            |
|Management of technical vulnerabilities|8.8   |`verify_file()` enables detection of compromised dependencies by re-hashing registered files at runtime                       |
|Secure development lifecycle           |8.25  |`codebank.py` enforces cryptographic registration of code before execution — structural shift-left security                   |
|Supplier relationships                 |5.19  |Third-party dependencies can be registered at deployment time and verified continuously against their registered hash         |

-----

## 4. GDPR (General Data Protection Regulation)

|Article     |Requirement                     |TrailStax Control                                                                                                              |
|------------|--------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
|Art. 5(1)(f)|Integrity and confidentiality   |SHA-256 hash-chaining provides structural integrity guarantees for all logged agent actions and code artifacts                 |
|Art. 5(2)   |Accountability                  |Every action in `trail.py` and every commit in `codebank.py` carries `agent_id` and `timestamp` — full accountability chain    |
|Art. 25     |Data protection by design       |Tamper-evidence is a structural property of the registry, not an add-on control — integrity is built in at the data model level|
|Art. 30     |Records of processing activities|`bank_report()` and trail export provide auditable records of what agents processed, when, and in what sequence                |
|Art. 32     |Security of processing          |Append-only, hash-chained logs prevent unauthorized alteration of processing records                                           |
|Art. 33     |Breach notification support     |Exported registry enables forensic reconstruction of agent activity to support breach investigation and notification timelines |

-----

## 5. SLSA (Supply Chain Levels for Software Artifacts)

|Level                             |Requirement                               |TrailStax Control                                                                                                                                    |
|----------------------------------|------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
|**SLSA L1**                       |Provenance exists                         |Every `CodeCommit` records `file_path`, `code_hash`, `agent_id`, `timestamp`, and `sequence` — provenance is structural                              |
|**SLSA L2**                       |Hosted build, signed provenance           |`commit_hash` is computed from all fields including `prev_hash` — each record is self-authenticating                                                 |
|**SLSA L3**                       |Hardened build, non-falsifiable provenance|Hash-chaining means no record can be inserted, deleted, or modified without breaking `verify_chain()` — chain integrity is cryptographically enforced|
|**SLSA L3**                       |Dependencies tracked                      |`register_file()` hashes and registers every dependency at deployment time; `verify_file()` re-verifies at runtime                                   |
|**Threat: Compromised dependency**|Detect tampered packages                  |Registered hash vs. runtime hash comparison via `verify_file()` directly addresses this SLSA threat                                                  |
|**Threat: Insider code swap**     |Detect unauthorized code changes          |`verify_file()` re-hashes on-disk files and compares against registered `code_hash` — mismatch is flagged immediately                                |

-----

## 6. NIST SP 800-53 (Security and Privacy Controls)

|Control Family          |Control ID|TrailStax Control                                                                                                                      |
|------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------|
|Audit & Accountability  |AU-2      |`trail.py` logs agent actions as auditable events with timestamp, sequence, and agent identity                                         |
|Audit & Accountability  |AU-9      |Hash-chaining protects audit log integrity — logs cannot be altered without detection                                                  |
|Audit & Accountability  |AU-10     |`agent_id` on every record provides non-repudiation — actions are cryptographically bound to the agent that performed them             |
|Configuration Management|CM-3      |`codebank.py` provides cryptographic change control — every registered artifact is a tamper-evident configuration record               |
|Configuration Management|CM-5      |`register_file()` enforces that only registered (approved) code hashes are on record — unauthorized changes surface via `verify_file()`|
|System Integrity        |SI-7      |`verify_chain()` and `verify_file()` implement software and firmware integrity verification                                            |
|Risk Assessment         |RA-5      |`verify_content()` enables continuous re-verification of inline configs, IAM policies, and firewall rules against registered state     |

-----

## Threat Model Coverage Summary

|Threat                                   |Detection Mechanism                           |Framework Coverage                    |
|-----------------------------------------|----------------------------------------------|--------------------------------------|
|Insider swaps agent code before execution|`verify_file()` hash mismatch                 |SLSA L3, NIST SI-7, SOC 2 CC6.6       |
|Compromised dependency in pipeline       |`register_file()` + `verify_file()` at runtime|SLSA L3, ISO 27001 8.8, NIST CM-5     |
|Agent self-modification at runtime       |`trail.py` action log + chain verification    |NIST AU-9, SOC 2 CC7.2, ISO 27001 8.15|
|Silent IAM / firewall rule changes       |`register_content()` + `verify_content()`     |NIST RA-5, GDPR Art. 32, SOC 2 CC8.1  |
|Audit log tampering                      |`verify_chain()` — any break returns False    |NIST AU-9, SOC 2 A1.2, ISO 27001 8.15 |
|Replay attacks                           |`sequence` + `prev_hash` chain linkage        |RealAgentID TTL enforcement           |

-----

## Usage for Compliance Reporting

```python
from trailstax.codebank import CodeBank

bank = CodeBank(agent_id="compliance-agent-001")
bank.register_file("agents/recon_agent.py")
bank.register_content("firewall.rule", "deny all inbound port 22")

# Export full registry for audit
bank.export("trailstax_audit_report.json")

# Verify chain integrity
print("Chain valid:", bank.verify_chain())
```

-----

*TrailStax is the first production implementation of the RealAgentID protocol.* 
*CrossroadCode · github.com/TrailStax*
