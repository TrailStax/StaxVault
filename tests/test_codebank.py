import pytest
from trailstax.codebank import CodeBank

def test_codebank_init():
    bank = CodeBank(agent_id="test-agent-001")
    assert bank.agent_id == "test-agent-001"
    assert len(bank) == 0

def test_register_content():
    bank = CodeBank(agent_id="test-agent-001")
    commit = bank.register_content("firewall.rule", "deny all inbound port 22")
    assert commit.label == "firewall.rule"
    assert len(bank) == 1

def test_chain_integrity():
    bank = CodeBank(agent_id="test-agent-001")
    bank.register_content("rule_one", "deny port 22")
    bank.register_content("rule_two", "allow port 443")
    bank.register_content("rule_three", "deny port 80")
    assert bank.verify_chain() == True

def test_verify_content():
    bank = CodeBank(agent_id="test-agent-001")
    bank.register_content("firewall.rule", "deny all inbound port 22")
    match, detail = bank.verify_content("firewall.rule", "deny all inbound port 22")
    assert match == True

def test_tamper_detection():
    bank = CodeBank(agent_id="test-agent-001")
    bank.register_content("rule_one", "deny port 22")
    bank.register_content("rule_two", "allow port 443")
    bank.commits[0].code_hash = "tampered"
    assert bank.verify_chain() == False
