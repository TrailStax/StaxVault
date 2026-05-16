"""
TrailStax — trail.py
Append-only, hash-chained agent action audit log.

The first production implementation of the RealAgentID protocol.

Each TrailEntry is hashed with its predecessor's hash, forming an
unbreakable chain. Any modification to any past entry breaks every
hash that follows it — detectable instantly with verify_chain().
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional


TRAILSTAX_VERSION = "0.1.0"


@dataclass
class TrailEntry:
    """A single immutable audit record in the trail chain."""
    entry_id:   str
    agent_id:   str
    action:     str
    payload:    dict
    timestamp:  float
    session_id: str
    sequence:   int
    prev_hash:  str
    entry_hash: str = field(default="", init=False)

    def __post_init__(self):
        self.entry_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        data = {
            "entry_id":   self.entry_id,
            "agent_id":   self.agent_id,
            "action":     self.action,
            "payload":    self.payload,
            "timestamp":  self.timestamp,
            "session_id": self.session_id,
            "sequence":   self.sequence,
            "prev_hash":  self.prev_hash,
        }
        raw = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()

    def verify(self) -> bool:
        return self.entry_hash == self._compute_hash()

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class TrailStax:
    """
    Append-only, hash-chained audit trail for AI agent sessions.

    Usage:
        trail = TrailStax(agent_id="recon-agent-001")
        trail.log("session.start",   {"target": "example.com"})
        trail.log("iam.role_check",  {"role": "storage.admin", "granted": True})
        trail.log("firewall.query",  {"rule": "allow-all-ingress", "found": True})
        trail.log("session.complete",{"duration_ms": 2140})

        print(trail.verify_chain())  # True
        trail.export("session_trail.json")
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, agent_id: str, session_id: Optional[str] = None):
        self.agent_id   = agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.entries:   list[TrailEntry] = []
        self._sequence  = 0
        self._last_hash = self.GENESIS_HASH

    def log(self, action: str, payload: Optional[dict] = None) -> TrailEntry:
        """Append a new entry to the trail."""
        entry = TrailEntry(
            entry_id=   str(uuid.uuid4()),
            agent_id=   self.agent_id,
            action=     action,
            payload=    payload or {},
            timestamp=  time.time(),
            session_id= self.session_id,
            sequence=   self._sequence,
            prev_hash=  self._last_hash,
        )
        self.entries.append(entry)
        self._last_hash = entry.entry_hash
        self._sequence += 1
        return entry

    def verify_chain(self) -> bool:
        """
        Validate the entire chain. Returns True only if:
        - Every entry's own hash is valid (no field tampering)
        - Every entry's prev_hash links correctly to the prior entry
        """
        expected_prev = self.GENESIS_HASH
        for entry in self.entries:
            if not entry.verify():
                return False
            if entry.prev_hash != expected_prev:
                return False
            expected_prev = entry.entry_hash
        return True

    def audit_report(self) -> dict:
        return {
            "trailstax_version": TRAILSTAX_VERSION,
            "session_id":        self.session_id,
            "agent_id":          self.agent_id,
            "total_entries":     len(self.entries),
            "chain_valid":       self.verify_chain(),
            "genesis_hash":      self.GENESIS_HASH,
            "tail_hash":         self._last_hash,
            "entries":           [e.to_dict() for e in self.entries],
        }

    def export(self, filepath: str) -> None:
        with open(filepath, "w") as f:
            json.dump(self.audit_report(), f, indent=2)
        print(f"[TrailStax] Trail exported → {filepath}")

    @classmethod
    def load(cls, filepath: str) -> "TrailStax":
        with open(filepath, "r") as f:
            data = json.load(f)

        instance = cls(agent_id=data["agent_id"], session_id=data["session_id"])
        instance.entries = []

        for e in data["entries"]:
            entry = TrailEntry(
                entry_id=   e["entry_id"],
                agent_id=   e["agent_id"],
                action=     e["action"],
                payload=    e["payload"],
                timestamp=  e["timestamp"],
                session_id= e["session_id"],
                sequence=   e["sequence"],
                prev_hash=  e["prev_hash"],
            )
            object.__setattr__(entry, "entry_hash", e["entry_hash"])
            instance.entries.append(entry)

        if instance.entries:
            instance._last_hash = instance.entries[-1].entry_hash
            instance._sequence  = len(instance.entries)

        return instance

    def __len__(self):
        return len(self.entries)

    def __repr__(self):
        return (
            f"<TrailStax agent={self.agent_id} "
            f"session={self.session_id[:8]}... "
            f"entries={len(self.entries)}>"
        )
