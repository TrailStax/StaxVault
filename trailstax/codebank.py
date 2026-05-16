"""
TrailStax — codebank.py
Append-only, hash-chained code commit registry.

Every agent module, script, or dependency registered here produces a
CodeCommit — a tamper-evident record that can be verified at execution time.

Threat model:
  - Insider swaps agent code before execution    → hash mismatch detected
  - Compromised dependency in pipeline           → unregistered hash flagged
  - Agent self-modification at runtime           → divergence caught vs. trail
  - Unauthorized IAM / firewall rule changes     → pair with trail.py for full coverage
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


CODEBANK_VERSION = "0.1.0"


@dataclass
class CodeCommit:
    """Immutable record of a code artifact in the registry."""
    commit_id:   str
    agent_id:    str
    label:       str
    code_hash:   str
    file_path:   str
    metadata:    dict
    timestamp:   float
    sequence:    int
    prev_hash:   str
    commit_hash: str = field(default="", init=False)

    def __post_init__(self):
        self.commit_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        data = {
            "commit_id":  self.commit_id,
            "agent_id":   self.agent_id,
            "label":      self.label,
            "code_hash":  self.code_hash,
            "file_path":  self.file_path,
            "metadata":   self.metadata,
            "timestamp":  self.timestamp,
            "sequence":   self.sequence,
            "prev_hash":  self.prev_hash,
        }
        raw = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()

    def verify(self) -> bool:
        return self.commit_hash == self._compute_hash()

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class CodeBank:
    """
    Append-only, hash-chained code commit registry for AI agent modules.

    Usage:
        bank = CodeBank(agent_id="recon-agent-001")

        # Register approved code at deployment time
        bank.register_file("agents/recon_agent.py")
        bank.register_file("agents/utils.py", metadata={"version": "1.2.0"})
        bank.register_content("firewall.rule", "deny all inbound port 22")

        # Verify registry integrity
        print(bank.verify_chain())   # True

        # Verify file at runtime before execution
        ok, detail = bank.verify_file("agents/recon_agent.py")
        print(ok, detail)            # True, {"match": True, "label": "recon_agent.py"}

        bank.export("codebank.json")
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, agent_id: str, bank_id: Optional[str] = None):
        self.agent_id  = agent_id
        self.bank_id   = bank_id or str(uuid.uuid4())
        self.commits:  list[CodeCommit] = []
        self._sequence = 0
        self._last_hash = self.GENESIS_HASH
        self._index: dict[str, CodeCommit] = {}  # label → latest commit

    # ── Hashing ──────────────────────────────

    @staticmethod
    def _hash_content(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    # ── Registration ─────────────────────────

    def _append(self, commit: CodeCommit) -> CodeCommit:
        self.commits.append(commit)
        self._index[commit.label] = commit
        self._last_hash = commit.commit_hash
        self._sequence += 1
        return commit

    def register_file(
        self,
        filepath: str,
        label: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> CodeCommit:
        """
        Hash a file on disk and append a CodeCommit to the registry.
        Raises FileNotFoundError if the file doesn't exist.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"[CodeBank] File not found: {filepath}")

        content   = path.read_bytes()
        code_hash = self._hash_content(content)
        resolved_label = label or path.name

        commit = CodeCommit(
            commit_id=  str(uuid.uuid4()),
            agent_id=   self.agent_id,
            label=      resolved_label,
            code_hash=  code_hash,
            file_path=  str(path.resolve()),
            metadata=   metadata or {},
            timestamp=  time.time(),
            sequence=   self._sequence,
            prev_hash=  self._last_hash,
        )
        return self._append(commit)

    def register_content(
        self,
        label: str,
        content: str,
        metadata: Optional[dict] = None,
    ) -> CodeCommit:
        """
        Hash an inline string (rule, config, script snippet) and register it.
        Useful for firewall rules, IAM policies, or any string artifact.
        """
        code_hash = self._hash_content(content.encode())

        commit = CodeCommit(
            commit_id=  str(uuid.uuid4()),
            agent_id=   self.agent_id,
            label=      label,
            code_hash=  code_hash,
            file_path=  "<inline>",
            metadata=   metadata or {},
            timestamp=  time.time(),
            sequence=   self._sequence,
            prev_hash=  self._last_hash,
        )
        return self._append(commit)

    # ── Verification ─────────────────────────

    def verify_chain(self) -> bool:
        """Validate the entire commit chain for tampering."""
        expected_prev = self.GENESIS_HASH
        for commit in self.commits:
            if not commit.verify():
                return False
            if commit.prev_hash != expected_prev:
                return False
            expected_prev = commit.commit_hash
        return True

    def verify_file(self, filepath: str, label: Optional[str] = None) -> tuple[bool, dict]:
        """
        Re-hash a file on disk and compare against the registered commit.
        Returns (match: bool, detail: dict).
        """
        path = Path(filepath)
        resolved_label = label or path.name

        if resolved_label not in self._index:
            return False, {"error": f"Label '{resolved_label}' not found in registry"}

        if not path.exists():
            return False, {"error": f"File not found on disk: {filepath}"}

        current_hash = self._hash_content(path.read_bytes())
        registered   = self._index[resolved_label]
        match        = current_hash == registered.code_hash

        return match, {
            "label":           resolved_label,
            "match":           match,
            "registered_hash": registered.code_hash,
            "current_hash":    current_hash,
            "registered_at":   registered.timestamp,
        }

    def verify_content(self, label: str, content: str) -> tuple[bool, dict]:
        """
        Re-hash inline content and compare against registered commit.
        """
        if label not in self._index:
            return False, {"error": f"Label '{label}' not found in registry"}

        current_hash = self._hash_content(content.encode())
        registered   = self._index[label]
        match        = current_hash == registered.code_hash

        return match, {
            "label":           label,
            "match":           match,
            "registered_hash": registered.code_hash,
            "current_hash":    current_hash,
        }

    # ── Export / Import ───────────────────────

    def bank_report(self) -> dict:
        return {
            "codebank_version": CODEBANK_VERSION,
            "bank_id":          self.bank_id,
            "agent_id":         self.agent_id,
            "total_commits":    len(self.commits),
            "chain_valid":      self.verify_chain(),
            "genesis_hash":     self.GENESIS_HASH,
            "tail_hash":        self._last_hash,
            "commits":          [c.to_dict() for c in self.commits],
        }

    def export(self, filepath: str) -> None:
        with open(filepath, "w") as f:
            json.dump(self.bank_report(), f, indent=2)
        print(f"[CodeBank] Registry exported → {filepath}")

    @classmethod
    def load(cls, filepath: str) -> "CodeBank":
        with open(filepath, "r") as f:
            data = json.load(f)

        instance = cls(agent_id=data["agent_id"], bank_id=data["bank_id"])
        instance.commits = []

        for c in data["commits"]:
            commit = CodeCommit(
                commit_id=  c["commit_id"],
                agent_id=   c["agent_id"],
                label=      c["label"],
                code_hash=  c["code_hash"],
                file_path=  c["file_path"],
                metadata=   c["metadata"],
                timestamp=  c["timestamp"],
                sequence=   c["sequence"],
                prev_hash=  c["prev_hash"],
            )
            object.__setattr__(commit, "commit_hash", c["commit_hash"])
            instance.commits.append(commit)
            instance._index[commit.label] = commit

        if instance.commits:
            instance._last_hash = instance.commits[-1].commit_hash
            instance._sequence  = len(instance.commits)

        return instance

    def __len__(self):
        return len(self.commits)

    def __repr__(self):
        return (
            f"<CodeBank agent={self.agent_id} "
            f"bank={self.bank_id[:8]}... "
            f"commits={len(self.commits)}>"
        )
