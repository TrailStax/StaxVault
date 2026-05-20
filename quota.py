"""
quota.py — TrailStax Resource Quota Enforcement Module
=======================================================
Redis-based per-agent resource quota enforcement with three-tier
limit hierarchy: global → role-based → per-agent override.

Priority order: per-agent override → role limit → global ceiling.
Whichever is most restrictive wins.

Tracked resources:
  - API calls (count per session/window)
  - Token consumption (input + output tokens)
  - Compute time (seconds)

On breach:
  - Agent quarantined from mesh
  - Breach logged to hash-chained trail
  - Redis pub/sub alert broadcast to all agents

Part of the TrailStax trust stack:
  trail.py      → append-only agent audit log
  codebank.py   → append-only code commit registry
  guardian.py   → supply chain / pre-install verification
  validator.py  → prompt validation & intent verification
  quota.py      → resource quota enforcement  ← YOU ARE HERE

Signed by RealAgentID. Protects both Ira pipeline and TrailStax agent mesh.
"""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Redis ──────────────────────────────────────────────────────────────────────
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# ── Configuration ──────────────────────────────────────────────────────────────
QUOTA_DIR = Path.home() / ".trailstax" / "quota"
TRAIL_LOG = QUOTA_DIR / "quota_trail.jsonl"
QUOTA_CONFIG = QUOTA_DIR / "quota_config.json"
QUARANTINE_LIST = QUOTA_DIR / "quarantine.json"

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_ALERTS_CHANNEL = "trailstax:quota:alerts"
REDIS_QUARANTINE_CHANNEL = "trailstax:quota:quarantine"

# Redis key prefixes
KEY_CALLS = "trailstax:quota:calls:"
KEY_TOKENS = "trailstax:quota:tokens:"
KEY_COMPUTE = "trailstax:quota:compute:"
KEY_QUARANTINE = "trailstax:quota:quarantine:"
KEY_CONFIG = "trailstax:quota:config"

SIGNING_SECRET = os.getenv("REALAGENTID_SECRET", "changeme-set-env-var")

# ── Default Global Limits ──────────────────────────────────────────────────────
DEFAULT_GLOBAL_LIMITS = {
    "api_calls": 1000,        # calls per window
    "tokens": 500000,         # total tokens per window
    "compute_seconds": 3600,  # compute time per window
    "window_seconds": 86400,  # 24-hour rolling window
}

# ── Default Role Limits ────────────────────────────────────────────────────────
DEFAULT_ROLE_LIMITS = {
    "ingestion_agent": {
        "api_calls": 500,
        "tokens": 200000,
        "compute_seconds": 1800,
    },
    "query_agent": {
        "api_calls": 200,
        "tokens": 50000,
        "compute_seconds": 300,
    },
    "training_agent": {
        "api_calls": 100,
        "tokens": 300000,
        "compute_seconds": 3600,
    },
    "blueprint_agent": {
        "api_calls": 300,
        "tokens": 150000,
        "compute_seconds": 900,
    },
    "audit_agent": {
        "api_calls": 50,
        "tokens": 10000,
        "compute_seconds": 120,
    },
    "default": {
        "api_calls": 100,
        "tokens": 25000,
        "compute_seconds": 300,
    },
}

# ── Redis Connection ───────────────────────────────────────────────────────────
def get_redis() -> Optional["redis.Redis"]:
    if not REDIS_AVAILABLE:
        return None
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB,
                        decode_responses=True, socket_connect_timeout=2)
        r.ping()
        return r
    except Exception:
        return None

# ── Trail Logging ──────────────────────────────────────────────────────────────
def _chain_hash(prev_hash: str, entry: dict) -> str:
    payload = prev_hash + json.dumps(entry, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()

def log_to_trail(event_type: str, agent_id: str, outcome: str,
                 resource: str = "", used: float = 0,
                 limit: float = 0, detail: str = "") -> None:
    QUOTA_DIR.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if TRAIL_LOG.exists():
        lines = TRAIL_LOG.read_text().strip().splitlines()
        if lines:
            try:
                prev_hash = json.loads(lines[-1]).get("chain_hash", "0" * 64)
            except Exception:
                pass

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "agent_id": agent_id,
        "outcome": outcome,
        "resource": resource,
        "used": round(used, 4),
        "limit": round(limit, 4),
        "detail": detail,
    }
    entry["chain_hash"] = _chain_hash(prev_hash, entry)

    with open(TRAIL_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

# ── Config Management ──────────────────────────────────────────────────────────
def _load_config() -> dict:
    """Load quota config — Redis first, fallback to local file."""
    r = get_redis()
    if r:
        try:
            data = r.get(KEY_CONFIG)
            if data:
                return json.loads(data)
        except Exception:
            pass

    if QUOTA_CONFIG.exists():
        try:
            return json.loads(QUOTA_CONFIG.read_text())
        except Exception:
            pass

    # Return defaults
    return {
        "global": DEFAULT_GLOBAL_LIMITS,
        "roles": DEFAULT_ROLE_LIMITS,
        "agents": {},  # per-agent overrides
    }

def _save_config(config: dict) -> None:
    QUOTA_DIR.mkdir(parents=True, exist_ok=True)
    QUOTA_CONFIG.write_text(json.dumps(config, indent=2))
    r = get_redis()
    if r:
        try:
            r.set(KEY_CONFIG, json.dumps(config))
        except Exception:
            pass

def get_limit(agent_id: str, role: str, resource: str) -> float:
    """
    Resolve the effective limit for an agent/role/resource.
    Priority: per-agent override → role limit → global ceiling.
    Most restrictive wins.
    """
    config = _load_config()

    global_limit = config["global"].get(resource, float("inf"))
    role_limits = config["roles"].get(role, config["roles"].get("default", {}))
    role_limit = role_limits.get(resource, float("inf"))
    agent_limits = config["agents"].get(agent_id, {})
    agent_limit = agent_limits.get(resource, float("inf"))

    # Most restrictive wins
    return min(global_limit, role_limit, agent_limit)

# ── Quarantine Management ──────────────────────────────────────────────────────
def _load_quarantine() -> dict:
    r = get_redis()
    if r:
        try:
            data = r.get(KEY_QUARANTINE + "list")
            if data:
                return json.loads(data)
        except Exception:
            pass

    if QUARANTINE_LIST.exists():
        try:
            return json.loads(QUARANTINE_LIST.read_text())
        except Exception:
            pass
    return {}

def _save_quarantine(quarantine: dict) -> None:
    QUOTA_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_LIST.write_text(json.dumps(quarantine, indent=2))
    r = get_redis()
    if r:
        try:
            r.set(KEY_QUARANTINE + "list", json.dumps(quarantine))
        except Exception:
            pass

def quarantine_agent(agent_id: str, reason: str) -> None:
    """Quarantine an agent — blocks all future quota checks until released."""
    quarantine = _load_quarantine()
    quarantine[agent_id] = {
        "quarantined_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
    }
    _save_quarantine(quarantine)

    log_to_trail("QUARANTINE", agent_id, "QUARANTINED",
                 detail=reason)

    # Broadcast quarantine alert
    r = get_redis()
    if r:
        try:
            r.publish(REDIS_QUARANTINE_CHANNEL, json.dumps({
                "alert": "AGENT_QUARANTINED",
                "agent_id": agent_id,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
        except Exception:
            pass

    print(f"[quota] ⚠️  QUARANTINED: {agent_id} — {reason}")

def release_agent(agent_id: str) -> None:
    """Release an agent from quarantine."""
    quarantine = _load_quarantine()
    if agent_id in quarantine:
        del quarantine[agent_id]
        _save_quarantine(quarantine)
        log_to_trail("RELEASE", agent_id, "RELEASED",
                     detail="Manually released from quarantine")
        print(f"[quota] ✓ Released: {agent_id}")

        # Reset usage counters
        r = get_redis()
        if r:
            try:
                r.delete(KEY_CALLS + agent_id)
                r.delete(KEY_TOKENS + agent_id)
                r.delete(KEY_COMPUTE + agent_id)
            except Exception:
                pass
    else:
        print(f"[quota] Agent not in quarantine: {agent_id}")

def is_quarantined(agent_id: str) -> tuple[bool, str]:
    """Check if an agent is quarantined. Returns (quarantined, reason)."""
    quarantine = _load_quarantine()
    if agent_id in quarantine:
        return True, quarantine[agent_id].get("reason", "Unknown")
    return False, ""

# ── Usage Tracking ─────────────────────────────────────────────────────────────
def _get_usage(agent_id: str, resource: str) -> float:
    """Get current usage for an agent/resource from Redis or local fallback."""
    r = get_redis()
    key_map = {
        "api_calls": KEY_CALLS,
        "tokens": KEY_TOKENS,
        "compute_seconds": KEY_COMPUTE,
    }
    prefix = key_map.get(resource, KEY_CALLS)

    if r:
        try:
            val = r.get(prefix + agent_id)
            return float(val) if val else 0.0
        except Exception:
            pass

    # Local fallback
    usage_file = QUOTA_DIR / f"usage_{agent_id}_{resource}.txt"
    if usage_file.exists():
        try:
            return float(usage_file.read_text().strip())
        except Exception:
            pass
    return 0.0

def _increment_usage(agent_id: str, resource: str, amount: float,
                     window_seconds: int) -> float:
    """Increment usage counter. Returns new total."""
    r = get_redis()
    key_map = {
        "api_calls": KEY_CALLS,
        "tokens": KEY_TOKENS,
        "compute_seconds": KEY_COMPUTE,
    }
    prefix = key_map.get(resource, KEY_CALLS)

    if r:
        try:
            pipe = r.pipeline()
            pipe.incrbyfloat(prefix + agent_id, amount)
            pipe.expire(prefix + agent_id, window_seconds)
            results = pipe.execute()
            return float(results[0])
        except Exception:
            pass

    # Local fallback
    QUOTA_DIR.mkdir(parents=True, exist_ok=True)
    usage_file = QUOTA_DIR / f"usage_{agent_id}_{resource}.txt"
    current = 0.0
    if usage_file.exists():
        try:
            current = float(usage_file.read_text().strip())
        except Exception:
            pass
    new_total = current + amount
    usage_file.write_text(str(new_total))
    return new_total

# ── Main Quota Interface ───────────────────────────────────────────────────────

class QuotaResult:
    def __init__(self, allowed: bool, outcome: str, resource: str,
                 used: float, limit: float, detail: str = ""):
        self.allowed = allowed
        self.outcome = outcome
        self.resource = resource
        self.used = used
        self.limit = limit
        self.detail = detail

    def __bool__(self):
        return self.allowed

    def __repr__(self):
        icon = "✓" if self.allowed else "✗"
        pct = (self.used / self.limit * 100) if self.limit > 0 else 0
        return (f"[quota] {icon} {self.outcome} | {self.resource}: "
                f"{self.used:.0f}/{self.limit:.0f} ({pct:.1f}%)")

def check_quota(agent_id: str, role: str = "default",
                resource: str = "api_calls",
                amount: float = 1.0) -> QuotaResult:
    """
    Check and increment quota for an agent.

    Args:
        agent_id: RealAgentID of the agent
        role: Agent role (ingestion_agent, query_agent, etc.)
        resource: Resource to check (api_calls, tokens, compute_seconds)
        amount: Amount to consume

    Returns:
        QuotaResult — allowed=False means agent is over quota
    """
    QUOTA_DIR.mkdir(parents=True, exist_ok=True)

    # Quarantine check first
    quarantined, reason = is_quarantined(agent_id)
    if quarantined:
        detail = f"Agent is quarantined: {reason}"
        log_to_trail("QUOTA_CHECK", agent_id, "QUARANTINED",
                     resource, 0, 0, detail)
        return QuotaResult(False, "QUARANTINED", resource, 0, 0, detail)

    config = _load_config()
    window = config["global"].get("window_seconds", 86400)
    limit = get_limit(agent_id, role, resource)

    # Get current usage
    current = _get_usage(agent_id, resource)

    # Check before incrementing
    if current + amount > limit:
        detail = (f"Quota exceeded for {resource}: "
                  f"{current + amount:.0f} > {limit:.0f}")
        log_to_trail("QUOTA_BREACH", agent_id, "BLOCKED",
                     resource, current + amount, limit, detail)

        # Alert via Redis
        r = get_redis()
        if r:
            try:
                r.publish(REDIS_ALERTS_CHANNEL, json.dumps({
                    "alert": "QUOTA_BREACH",
                    "agent_id": agent_id,
                    "role": role,
                    "resource": resource,
                    "used": current + amount,
                    "limit": limit,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
            except Exception:
                pass

        # Auto-quarantine on breach
        quarantine_agent(agent_id,
                         f"Quota breach: {resource} "
                         f"({current + amount:.0f}/{limit:.0f})")

        return QuotaResult(False, "BLOCKED", resource,
                           current + amount, limit, detail)

    # Increment usage
    new_total = _increment_usage(agent_id, resource, amount, window)

    log_to_trail("QUOTA_CHECK", agent_id, "ALLOWED",
                 resource, new_total, limit)

    return QuotaResult(True, "ALLOWED", resource, new_total, limit)


def check_all(agent_id: str, role: str = "default",
              api_calls: float = 1.0,
              tokens: float = 0.0,
              compute_seconds: float = 0.0) -> tuple[bool, list[QuotaResult]]:
    """
    Check all three resources in one call.
    Returns (all_allowed: bool, results: list[QuotaResult])
    All checks run before any are incremented — atomic-style.
    """
    results = []
    all_allowed = True

    if api_calls > 0:
        r = check_quota(agent_id, role, "api_calls", api_calls)
        results.append(r)
        if not r.allowed:
            all_allowed = False

    if tokens > 0 and all_allowed:
        r = check_quota(agent_id, role, "tokens", tokens)
        results.append(r)
        if not r.allowed:
            all_allowed = False

    if compute_seconds > 0 and all_allowed:
        r = check_quota(agent_id, role, "compute_seconds", compute_seconds)
        results.append(r)
        if not r.allowed:
            all_allowed = False

    return all_allowed, results


# ── Config CLI Helpers ─────────────────────────────────────────────────────────

def set_role_limit(role: str, resource: str, limit: float) -> None:
    config = _load_config()
    if role not in config["roles"]:
        config["roles"][role] = {}
    config["roles"][role][resource] = limit
    _save_config(config)
    print(f"[quota] ✓ Role limit set: {role}.{resource} = {limit}")
    log_to_trail("CONFIG_UPDATE", "system", "UPDATED",
                 resource, limit, limit,
                 f"Role {role} {resource} limit set to {limit}")

def set_agent_limit(agent_id: str, resource: str, limit: float) -> None:
    config = _load_config()
    if agent_id not in config["agents"]:
        config["agents"][agent_id] = {}
    config["agents"][agent_id][resource] = limit
    _save_config(config)
    print(f"[quota] ✓ Agent limit set: {agent_id}.{resource} = {limit}")
    log_to_trail("CONFIG_UPDATE", agent_id, "UPDATED",
                 resource, limit, limit,
                 f"Agent {agent_id} {resource} limit set to {limit}")

def set_global_limit(resource: str, limit: float) -> None:
    config = _load_config()
    config["global"][resource] = limit
    _save_config(config)
    print(f"[quota] ✓ Global limit set: {resource} = {limit}")

def reset_usage(agent_id: str) -> None:
    """Reset all usage counters for an agent."""
    r = get_redis()
    if r:
        try:
            r.delete(KEY_CALLS + agent_id)
            r.delete(KEY_TOKENS + agent_id)
            r.delete(KEY_COMPUTE + agent_id)
        except Exception:
            pass

    for resource in ["api_calls", "tokens", "compute_seconds"]:
        usage_file = QUOTA_DIR / f"usage_{agent_id}_{resource}.txt"
        if usage_file.exists():
            usage_file.unlink()

    log_to_trail("RESET", agent_id, "RESET", detail="Usage counters reset")
    print(f"[quota] ✓ Usage reset: {agent_id}")


# ── Status / Audit ─────────────────────────────────────────────────────────────

def show_status() -> None:
    config = _load_config()
    quarantine = _load_quarantine()
    r = get_redis()

    print("\n⚡ Quota Status")
    print("=" * 50)
    print(f"Redis         : {'Connected' if r else 'Not available'}")
    print(f"Quarantined   : {len(quarantine)} agent(s)")
    print(f"Trail log     : {TRAIL_LOG}")

    print("\nGlobal limits:")
    for resource, limit in config["global"].items():
        if resource != "window_seconds":
            print(f"  • {resource:<20} {limit}")
    print(f"  • {'window':<20} {config['global'].get('window_seconds', 86400)}s")

    print("\nRole limits:")
    for role, limits in config["roles"].items():
        print(f"  [{role}]")
        for resource, limit in limits.items():
            print(f"    • {resource:<18} {limit}")

    if config["agents"]:
        print("\nPer-agent overrides:")
        for agent, limits in config["agents"].items():
            print(f"  [{agent}]")
            for resource, limit in limits.items():
                print(f"    • {resource:<18} {limit}")

    if quarantine:
        print("\nQuarantined agents:")
        for agent, info in quarantine.items():
            print(f"  ⚠️  {agent}")
            print(f"     Reason: {info.get('reason', 'Unknown')}")
            print(f"     Since:  {info.get('quarantined_at', 'Unknown')[:19]}")

    if TRAIL_LOG.exists():
        lines = TRAIL_LOG.read_text().strip().splitlines()
        recent = lines[-5:] if len(lines) >= 5 else lines
        print(f"\nRecent trail entries ({len(lines)} total):")
        for line in recent:
            try:
                e = json.loads(line)
                icon = "✓" if e["outcome"] in ("ALLOWED", "RESET", "RELEASED") else "✗"
                print(f"  {icon} [{e['timestamp'][:19]}] "
                      f"{e['event']:<18} {e['agent_id']:<20} → {e['outcome']}")
            except Exception:
                pass
    print()


def show_trail() -> None:
    if not TRAIL_LOG.exists():
        print("[quota] No trail log found.")
        return
    lines = TRAIL_LOG.read_text().strip().splitlines()
    print(f"\n📋 Quota Trail ({len(lines)} entries)")
    print("=" * 70)
    for line in lines:
        try:
            e = json.loads(line)
            icon = "✓" if e["outcome"] in ("ALLOWED", "RESET", "RELEASED") else "✗"
            usage_str = ""
            if e.get("used") and e.get("limit"):
                usage_str = f"{e['used']:.0f}/{e['limit']:.0f}"
            print(f"{icon} {e['timestamp'][:19]} | {e['event']:<18} | "
                  f"{e['agent_id']:<20} | {e['outcome']:<12} {usage_str}")
            if e.get("detail") and e["outcome"] not in ("ALLOWED",):
                print(f"  → {e['detail']}")
        except Exception:
            print(line)
    print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    if not args or args[0] in ("help", "--help", "-h"):
        print("""
⚡ quota.py — TrailStax Resource Quota Enforcement

Usage:
  python quota.py status                                    Show status
  python quota.py trail                                     Show audit trail
  python quota.py check <agent_id> <role> [calls] [tokens] Check quota
  python quota.py set-role <role> <resource> <limit>        Set role limit
  python quota.py set-agent <agent_id> <resource> <limit>   Set agent limit
  python quota.py set-global <resource> <limit>             Set global limit
  python quota.py quarantine <agent_id> <reason>            Quarantine agent
  python quota.py release <agent_id>                        Release agent
  python quota.py reset <agent_id>                          Reset usage
  python quota.py test                                      Run test suite

Resources: api_calls, tokens, compute_seconds

Examples:
  python quota.py check ira-agent-001 ingestion_agent 1 500
  python quota.py set-role query_agent api_calls 50
  python quota.py set-agent ira-agent-001 tokens 100000
  python quota.py quarantine rogue-agent-001 "Exceeded api_calls limit"
  python quota.py release ira-agent-001
        """)
        return

    cmd = args[0]

    if cmd == "status":
        show_status()

    elif cmd == "trail":
        show_trail()

    elif cmd == "check":
        if len(args) < 3:
            print("Usage: quota check <agent_id> <role> [calls] [tokens]")
            sys.exit(1)
        agent_id = args[1]
        role = args[2]
        calls = float(args[3]) if len(args) > 3 else 1.0
        tokens = float(args[4]) if len(args) > 4 else 0.0
        allowed, results = check_all(agent_id, role, calls, tokens)
        for r in results:
            print(r)
        sys.exit(0 if allowed else 1)

    elif cmd == "set-role":
        if len(args) < 4:
            print("Usage: quota set-role <role> <resource> <limit>")
            sys.exit(1)
        set_role_limit(args[1], args[2], float(args[3]))

    elif cmd == "set-agent":
        if len(args) < 4:
            print("Usage: quota set-agent <agent_id> <resource> <limit>")
            sys.exit(1)
        set_agent_limit(args[1], args[2], float(args[3]))

    elif cmd == "set-global":
        if len(args) < 3:
            print("Usage: quota set-global <resource> <limit>")
            sys.exit(1)
        set_global_limit(args[1], float(args[2]))

    elif cmd == "quarantine":
        if len(args) < 3:
            print("Usage: quota quarantine <agent_id> <reason>")
            sys.exit(1)
        quarantine_agent(args[1], " ".join(args[2:]))

    elif cmd == "release":
        if len(args) < 2:
            print("Usage: quota release <agent_id>")
            sys.exit(1)
        release_agent(args[1])

    elif cmd == "reset":
        if len(args) < 2:
            print("Usage: quota reset <agent_id>")
            sys.exit(1)
        reset_usage(args[1])

    elif cmd == "test":
        print("\n🧪 Running quota test suite...\n")
        test_agent = "test-agent-quota-001"
        passed = 0
        failed = 0

        def check(name, condition):
            nonlocal passed, failed
            icon = "✓" if condition else "✗"
            status = "PASS" if condition else "FAIL"
            print(f"  {icon} {status} | {name}")
            if condition:
                passed += 1
            else:
                failed += 1

        # Reset before tests
        reset_usage(test_agent)
        if test_agent in _load_quarantine():
            release_agent(test_agent)

        # Set tight limits for testing
        set_agent_limit(test_agent, "api_calls", 3)
        set_agent_limit(test_agent, "tokens", 100)

        # Test 1: Normal call allowed
        r1 = check_quota(test_agent, "default", "api_calls", 1)
        check("Normal API call allowed", r1.allowed)

        # Test 2: Second call allowed
        r2 = check_quota(test_agent, "default", "api_calls", 1)
        check("Second API call allowed", r2.allowed)

        # Test 3: Third call allowed (at limit)
        r3 = check_quota(test_agent, "default", "api_calls", 1)
        check("Third API call allowed (at limit)", r3.allowed)

        # Test 4: Fourth call blocked (over limit)
        r4 = check_quota(test_agent, "default", "api_calls", 1)
        check("Fourth API call blocked (over limit)", not r4.allowed)

        # Test 5: Quarantine triggered
        q, _ = is_quarantined(test_agent)
        check("Agent auto-quarantined on breach", q)

        # Test 6: Quarantined agent blocked
        r5 = check_quota(test_agent, "default", "api_calls", 1)
        check("Quarantined agent blocked", not r5.allowed)

        # Test 7: Release works
        release_agent(test_agent)
        q2, _ = is_quarantined(test_agent)
        check("Agent released from quarantine", not q2)

        # Test 8: Token quota
        reset_usage(test_agent)
        rt = check_quota(test_agent, "default", "tokens", 50)
        check("Token quota allowed", rt.allowed)

        rt2 = check_quota(test_agent, "default", "tokens", 60)
        check("Token quota breach blocked", not rt2.allowed)

        # Cleanup
        reset_usage(test_agent)
        release_agent(test_agent) if is_quarantined(test_agent)[0] else None

        print(f"\n  Results: {passed}/{passed+failed} passed")
        sys.exit(0 if failed == 0 else 1)

    else:
        print(f"[quota] Unknown command: {cmd}. Run 'python quota.py help'")
        sys.exit(1)


if __name__ == "__main__":
    main()
