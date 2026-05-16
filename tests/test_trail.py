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
