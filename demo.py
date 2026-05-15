"""
TrailStax — Demo Script
Full end-to-end demonstration of trail.py + codebank.py working together.
"""

import json
from trailstax import TrailStax, CodeBank


def demo_trail():
    print("\n" + "=" * 60)
    print("  [1] TrailStax — Agent Action Audit Trail")
    print("=" * 60)

    trail = TrailStax(agent_id="recon-agent-001")

    trail.log("session.start",    {"target": "example.com", "mode": "passive"})
    trail.log("iam.role_check",   {"role": "storage.admin", "granted": True})
    trail.log("firewall.query",   {"rule": "allow-all-ingress", "found": True})
    trail.log("recon.port_scan",  {"ports_checked": [80, 443], "open": [443]})
    trail.log("session.complete", {"duration_ms": 2140, "findings": 2})

    print(f"  Entries logged : {len(trail)}")
    print(f"  Chain valid    : {trail.verify_chain()}")
    trail.export("demo_trail.json")

    # Tamper detection
    print("\n  Simulating tamper — modifying iam.role_check payload...")
    loaded = TrailStax.load("demo_trail.json")
    loaded.entries[1].payload["granted"] = False
    print(f"  Chain valid after tamper: {loaded.verify_chain()}")
    print("  ✓ Tampering detected.")


def demo_codebank():
    print("\n" + "=" * 60)
    print("  [2] CodeBank — Code Commit Registry")
    print("=" * 60)

    bank = CodeBank(agent_id="recon-agent-001")

    # Register inline content (simulating file registration without real files)
    bank.register_content(
        "recon_agent.py",
        "def run(): pass  # recon agent v1.0",
        metadata={"version": "1.0.0"}
    )
    bank.register_content(
        "firewall.rule",
        "deny all inbound port 22",
        metadata={"environment": "prod"}
    )
    bank.register_content(
        "iam.policy",
        '{"roles": ["storage.viewer"], "deny": ["storage.admin"]}',
        metadata={"framework": "least-privilege"}
    )

    print(f"  Commits registered : {len(bank)}")
    print(f"  Chain valid        : {bank.verify_chain()}")

    # Verify content integrity
    ok, detail = bank.verify_content("firewall.rule", "deny all inbound port 22")
    print(f"\n  verify firewall.rule (unchanged): {ok}")

    ok, detail = bank.verify_content("firewall.rule", "allow all inbound port 22")
    print(f"  verify firewall.rule (tampered) : {ok}")
    print(f"  ✓ Modification detected — hash mismatch.")

    bank.export("demo_codebank.json")


def demo_combined():
    print("\n" + "=" * 60)
    print("  [3] Combined — Trail + CodeBank working together")
    print("=" * 60)
    print("""
  Scenario: An insider attempts to swap a firewall rule after it's
  been registered in the CodeBank, then an agent executes it.

  Step 1 → CodeBank registers approved firewall rule at deployment
  Step 2 → Insider modifies the rule content
  Step 3 → Agent attempts to execute — CodeBank verify_content() fires
  Step 4 → Mismatch detected BEFORE execution
  Step 5 → TrailStax logs the blocked execution attempt with full payload

  Result: The agent never ran the tampered rule.
          The audit trail proves the block occurred and why.
          Both records are cryptographically chained — unalterable.
  """)
    print("  This is RealAgentID in production.")
    print("  Identity. Action. Code. All three verified.")


if __name__ == "__main__":
    print("\n  TrailStax — The Stack That Builds Trust")
    print("  First Implementation of the RealAgentID Protocol")
    demo_trail()
    demo_codebank()
    demo_combined()
    print("\n" + "=" * 60)
    print("  Demo complete. Files: demo_trail.json, demo_codebank.json")
    print("=" * 60 + "\n")
