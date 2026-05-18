import pytest
from trailstax.trail import TrailStax, TrailEntry

def test_trail_init():
    trail = TrailStax(agent_id="test-agent-001")
    assert trail.agent_id == "test-agent-001"
    assert len(trail) == 0

def test_trail_append():
    trail = TrailStax(agent_id="test-agent-001")
    entry = trail.log(action="test_action", payload={"key": "value"})
    assert len(trail) == 1
    assert entry.action == "test_action"

def test_chain_integrity():
    trail = TrailStax(agent_id="test-agent-001")
    trail.log(action="action_one", payload={})
    trail.log(action="action_two", payload={})
    trail.log(action="action_three", payload={})
    assert trail.verify_chain() == True

def test_tamper_detection():
    trail = TrailStax(agent_id="test-agent-001")
    trail.log(action="action_one", payload={})
    trail.log(action="action_two", payload={})
    # Tamper with first entry
    trail.entries[0].action = "tampered"
    assert trail.verify_chain() == False


def test_legitimate_agent_no_violation():
    trail = TrailStax(agent_id="test-agent-001")
    entry = trail.log(
        "feature.reimplement",
        payload={"status": "complete"},
        method_declared=["read_spec", "write_code", "run_tests"],
        artifacts_accessed=["src/feature.py", "tests/test_feature.py"],
        task_type="feature_reimplementation"
    )
    assert entry.scope_violation == False
    assert trail.audit_report()["scope_violations"] == 0


def test_reward_hacking_detected():
    trail = TrailStax(agent_id="test-agent-001")
    entry = trail.log(
        "feature.reimplement",
        payload={"status": "complete"},
        method_declared=["read_spec", "write_code"],
        artifacts_accessed=["src/feature.py", "__pycache__/feature.cpython.pyc"],
        task_type="feature_reimplementation"
    )
    assert entry.scope_violation == True
    assert trail.audit_report()["scope_violations"] == 1


def test_violation_locked_in_chain():
    trail = TrailStax(agent_id="test-agent-001")
    trail.log(
        "feature.reimplement",
        artifacts_accessed=["__pycache__/feature.cpython.pyc"],
        task_type="feature_reimplementation"
    )
    assert trail.verify_chain() == True


def test_attestation_fields_in_entry():
    trail = TrailStax(agent_id="test-agent-001")
    entry = trail.log(
        "recon.scan",
        method_declared=["port_scan", "banner_grab"],
        artifacts_accessed=["targets/example.com"],
        task_type="recon"
    )
    assert entry.method_declared == ["port_scan", "banner_grab"]
    assert entry.artifacts_accessed == ["targets/example.com"]
    assert entry.scope_violation == False
