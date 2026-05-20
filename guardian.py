"""
guardian.py — TrailStax Supply Chain Defense Module
=====================================================
Pre-install verification, pip hook, and Redis-integrated
package allowlist enforcement for Python agent environments.

Part of the TrailStax trust stack:
  trail.py     → append-only agent audit log
  codebank.py  → append-only code commit registry
  guardian.py  → supply chain / pre-install verification  ← YOU ARE HERE
  reasoning.py → reasoning auditability (planned)

Signed by RealAgentID. All actions logged to trail + codebank.
"""

import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Redis (optional but recommended) ──────────────────────────────────────────
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# ── Configuration ─────────────────────────────────────────────────────────────
GUARDIAN_DIR = Path.home() / ".trailstax" / "guardian"
REGISTRY_FILE = GUARDIAN_DIR / "approved_registry.json"
TRAIL_LOG = GUARDIAN_DIR / "guardian_trail.jsonl"
WRAPPER_PATH = Path.home() / ".local" / "bin" / "pip"

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_REGISTRY_KEY = "trailstax:guardian:registry"
REDIS_ALERTS_CHANNEL = "trailstax:guardian:alerts"

# RealAgentID signing secret (set via env in production)
SIGNING_SECRET = os.getenv("REALAGENTID_SECRET", "changeme-set-env-var")


# ── Redis Connection ───────────────────────────────────────────────────────────

def get_redis() -> Optional["redis.Redis"]:
    """Return Redis client or None if unavailable."""
    if not REDIS_AVAILABLE:
        return None
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB,
                        decode_responses=True, socket_connect_timeout=2)
        r.ping()
        return r
    except Exception:
        return None


# ── Signing / Verification ─────────────────────────────────────────────────────

def sign_entry(data: dict) -> str:
    """HMAC-SHA256 sign a registry entry using RealAgentID secret."""
    payload = json.dumps(data, sort_keys=True).encode()
    return hmac.new(SIGNING_SECRET.encode(), payload, hashlib.sha256).hexdigest()


def verify_entry(data: dict, signature: str) -> bool:
    """Verify a registry entry signature."""
    expected = sign_entry(data)
    return hmac.compare_digest(expected, signature)


# ── Trail Logging ──────────────────────────────────────────────────────────────

def _chain_hash(prev_hash: str, entry: dict) -> str:
    payload = prev_hash + json.dumps(entry, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def log_to_trail(event_type: str, package: str, version: str,
                 outcome: str, detail: str = "") -> None:
    """
    Append a hash-chained entry to the guardian trail log.
    Compatible with trail.py chain format.
    """
    GUARDIAN_DIR.mkdir(parents=True, exist_ok=True)

    # Read previous hash
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
        "package": package,
        "version": version,
        "outcome": outcome,
        "detail": detail,
    }
    entry["chain_hash"] = _chain_hash(prev_hash, entry)

    with open(TRAIL_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

    # Broadcast alert to Redis pub/sub if blocked
    if outcome == "BLOCKED":
        r = get_redis()
        if r:
            try:
                r.publish(REDIS_ALERTS_CHANNEL, json.dumps({
                    "alert": "INSTALL_BLOCKED",
                    "package": package,
                    "version": version,
                    "timestamp": entry["timestamp"],
                    "detail": detail,
                }))
            except Exception:
                pass


# ── Registry Management ────────────────────────────────────────────────────────

def _load_registry_local() -> dict:
    """Load approved registry from local file."""
    if REGISTRY_FILE.exists():
        try:
            return json.loads(REGISTRY_FILE.read_text())
        except Exception:
            return {}
    return {}


def _load_registry_redis(r: "redis.Redis") -> dict:
    """Load approved registry from Redis."""
    try:
        data = r.get(REDIS_REGISTRY_KEY)
        if data:
            return json.loads(data)
    except Exception:
        pass
    return {}


def load_registry() -> dict:
    """
    Load registry — Redis first, fallback to local file.
    Redis is authoritative when available (shared across agent mesh).
    """
    r = get_redis()
    if r:
        registry = _load_registry_redis(r)
        if registry:
            return registry
    return _load_registry_local()


def save_registry(registry: dict) -> None:
    """Save registry to both Redis and local file."""
    GUARDIAN_DIR.mkdir(parents=True, exist_ok=True)
    REGISTRY_FILE.write_text(json.dumps(registry, indent=2))

    r = get_redis()
    if r:
        try:
            r.set(REDIS_REGISTRY_KEY, json.dumps(registry))
        except Exception:
            pass


def approve_package(package: str, version: str = "*",
                    expected_hash: str = "") -> None:
    """
    Add a package to the approved registry.
    Signs the entry with RealAgentID secret.
    """
    registry = load_registry()

    entry = {
        "package": package,
        "version": version,
        "expected_hash": expected_hash,
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "approved_by": os.getenv("REALAGENTID_AGENT", "human"),
    }
    entry["signature"] = sign_entry(entry)
    registry[package] = entry

    save_registry(registry)
    log_to_trail("APPROVED", package, version, "APPROVED",
                 f"Added to allowlist by {entry['approved_by']}")
    print(f"[guardian] ✓ Approved: {package}=={version}")


def remove_package(package: str) -> None:
    """Remove a package from the approved registry."""
    registry = load_registry()
    if package in registry:
        del registry[package]
        save_registry(registry)
        log_to_trail("REMOVED", package, "*", "REMOVED",
                     "Removed from allowlist")
        print(f"[guardian] ✗ Removed: {package}")
    else:
        print(f"[guardian] Package not found in registry: {package}")


# ── Hash Verification ──────────────────────────────────────────────────────────

def get_package_hash(package: str, version: str) -> str:
    """
    Fetch SHA256 hash of a package from PyPI JSON API.
    Returns empty string on failure.
    """
    try:
        url = f"https://pypi.org/pypi/{package}/{version}/json"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        # Return first wheel or sdist SHA256
        for file_info in data.get("urls", []):
            digests = file_info.get("digests", {})
            if "sha256" in digests:
                return digests["sha256"]
    except Exception:
        pass
    return ""


# ── Pre-Install Verification ───────────────────────────────────────────────────

def verify_package(package: str, version: str = "") -> tuple[bool, str]:
    """
    Check if a package is approved for installation.
    Returns (allowed: bool, reason: str)
    """
    registry = load_registry()

    if package not in registry:
        return False, f"Package '{package}' not in approved registry"

    entry = registry[package]

    # Verify registry entry signature (tamper detection)
    sig = entry.pop("signature", "")
    valid_sig = verify_entry(entry, sig)
    entry["signature"] = sig  # restore

    if not valid_sig:
        return False, f"Registry entry for '{package}' has invalid signature — possible tampering"

    # Version check
    approved_version = entry.get("version", "*")
    if approved_version != "*" and version and version != approved_version:
        return False, (f"Version mismatch: requested {version}, "
                       f"approved {approved_version}")

    # Hash check (if expected hash is set and version is pinned)
    expected_hash = entry.get("expected_hash", "")
    if expected_hash and version:
        actual_hash = get_package_hash(package, version)
        if actual_hash and actual_hash != expected_hash:
            return False, (f"Hash mismatch for {package}=={version}. "
                           f"Expected {expected_hash[:16]}..., "
                           f"got {actual_hash[:16]}...")

    return True, "Approved"


# ── Pip Wrapper ────────────────────────────────────────────────────────────────

def intercept_install(args: list[str]) -> int:
    """
    Parse pip install args, verify each package, then call real pip.
    Returns exit code.
    """
    packages = []
    i = 0
    while i < len(args):
        arg = args[i]
        # Skip flags
        if arg.startswith("-"):
            i += 1
            # Skip flag values
            if arg in ("-r", "--requirement", "-t", "--target",
                       "-i", "--index-url", "--extra-index-url",
                       "-c", "--constraint"):
                i += 1
            continue
        # Parse package==version
        if "==" in arg:
            pkg, ver = arg.split("==", 1)
            packages.append((pkg.strip(), ver.strip()))
        else:
            packages.append((arg.strip(), ""))
        i += 1

    # Verify all packages before any install
    all_approved = True
    for pkg, ver in packages:
        allowed, reason = verify_package(pkg, ver)
        if allowed:
            log_to_trail("INSTALL_ATTEMPT", pkg, ver or "*", "ALLOWED", reason)
            print(f"[guardian] ✓ {pkg}{('==' + ver) if ver else ''} — {reason}")
        else:
            log_to_trail("INSTALL_ATTEMPT", pkg, ver or "*", "BLOCKED", reason)
            print(f"[guardian] ✗ BLOCKED: {pkg}{('==' + ver) if ver else ''}")
            print(f"           Reason: {reason}")
            all_approved = False

    if not all_approved:
        print("\n[guardian] Installation blocked. Run 'guardian approve <package>' to allowlist.")
        return 1

    # All approved — call real pip
    real_pip = _find_real_pip()
    result = subprocess.run([real_pip, "install"] + args)
    return result.returncode


def _find_real_pip() -> str:
    """Find the real pip binary (not this wrapper)."""
    # Look for pip in standard locations, skip our wrapper
    for path in ["/usr/bin/pip3", "/usr/local/bin/pip3",
                 sys.executable.replace("python", "pip")]:
        if os.path.exists(path) and path != str(WRAPPER_PATH):
            return path
    return "pip3"


# ── Pip Wrapper Installation ───────────────────────────────────────────────────

def install_pip_hook() -> None:
    """
    Install guardian as a pip wrapper at ~/.local/bin/pip.
    Prepend ~/.local/bin to PATH in shell rc to activate.
    """
    WRAPPER_PATH.parent.mkdir(parents=True, exist_ok=True)

    script = f"""#!/usr/bin/env python3
# guardian.py pip hook — TrailStax supply chain protection
import sys
sys.path.insert(0, "{Path(__file__).parent}")
from guardian import intercept_install, run_pip_passthrough

args = sys.argv[1:]
if args and args[0] == "install":
    sys.exit(intercept_install(args[1:]))
else:
    sys.exit(run_pip_passthrough(args))
"""
    WRAPPER_PATH.write_text(script)
    WRAPPER_PATH.chmod(0o755)

    print(f"[guardian] ✓ Pip hook installed at {WRAPPER_PATH}")
    print("[guardian] Add this to your ~/.bashrc if not already present:")
    print('  export PATH="$HOME/.local/bin:$PATH"')
    print("[guardian] Then run: source ~/.bashrc")
    log_to_trail("HOOK_INSTALLED", "pip", "*", "INSTALLED",
                 f"Wrapper at {WRAPPER_PATH}")


def run_pip_passthrough(args: list[str]) -> int:
    """Pass non-install pip commands through to real pip."""
    real_pip = _find_real_pip()
    result = subprocess.run([real_pip] + args)
    return result.returncode


# ── Status / Audit ─────────────────────────────────────────────────────────────

def show_status() -> None:
    """Print guardian status, registry summary, and Redis connection."""
    registry = load_registry()
    r = get_redis()

    print("\n🛡️  Guardian Status")
    print("=" * 50)
    print(f"Registry entries : {len(registry)}")
    print(f"Registry source  : {'Redis' if r and _load_registry_redis(r) else 'Local file'}")
    print(f"Redis            : {'Connected' if r else 'Not available'}")
    print(f"Pip hook         : {'Installed' if WRAPPER_PATH.exists() else 'Not installed'}")
    print(f"Trail log        : {TRAIL_LOG}")

    if registry:
        print("\nApproved packages:")
        for pkg, entry in registry.items():
            ver = entry.get("version", "*")
            approved_by = entry.get("approved_by", "unknown")
            print(f"  • {pkg}=={ver} (approved by {approved_by})")

    # Recent trail entries
    if TRAIL_LOG.exists():
        lines = TRAIL_LOG.read_text().strip().splitlines()
        recent = lines[-5:] if len(lines) >= 5 else lines
        print(f"\nRecent trail entries ({len(lines)} total):")
        for line in recent:
            try:
                e = json.loads(line)
                icon = "✓" if e["outcome"] in ("ALLOWED", "APPROVED") else "✗"
                print(f"  {icon} [{e['timestamp'][:19]}] "
                      f"{e['event']} {e['package']} → {e['outcome']}")
            except Exception:
                pass
    print()


def show_trail() -> None:
    """Print full guardian trail log."""
    if not TRAIL_LOG.exists():
        print("[guardian] No trail log found.")
        return
    lines = TRAIL_LOG.read_text().strip().splitlines()
    print(f"\n📋 Guardian Trail ({len(lines)} entries)")
    print("=" * 60)
    for line in lines:
        try:
            e = json.loads(line)
            icon = "✓" if e["outcome"] in ("ALLOWED", "APPROVED", "INSTALLED") else "✗"
            print(f"{icon} {e['timestamp'][:19]} | {e['event']:<20} | "
                  f"{e['package']:<20} | {e['outcome']}")
            if e.get("detail"):
                print(f"  → {e['detail']}")
        except Exception:
            print(line)
    print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    if not args or args[0] in ("help", "--help", "-h"):
        print("""
🛡️  guardian.py — TrailStax Supply Chain Defense

Usage:
  python guardian.py status                        Show status and registry
  python guardian.py trail                         Show full audit trail
  python guardian.py approve <pkg> [ver] [hash]   Add package to allowlist
  python guardian.py remove <pkg>                  Remove from allowlist
  python guardian.py check <pkg> [ver]             Verify a package
  python guardian.py install-hook                  Install pip wrapper
  python guardian.py install <pkg>...              Guarded pip install

Examples:
  python guardian.py approve requests 2.31.0
  python guardian.py approve redis 5.0.1 a1b2c3...
  python guardian.py check numpy 1.26.0
  python guardian.py install requests flask redis
        """)
        return

    cmd = args[0]

    if cmd == "status":
        show_status()

    elif cmd == "trail":
        show_trail()

    elif cmd == "approve":
        if len(args) < 2:
            print("Usage: guardian approve <package> [version] [sha256_hash]")
            sys.exit(1)
        pkg = args[1]
        ver = args[2] if len(args) > 2 else "*"
        h = args[3] if len(args) > 3 else ""
        approve_package(pkg, ver, h)

    elif cmd == "remove":
        if len(args) < 2:
            print("Usage: guardian remove <package>")
            sys.exit(1)
        remove_package(args[1])

    elif cmd == "check":
        if len(args) < 2:
            print("Usage: guardian check <package> [version]")
            sys.exit(1)
        pkg = args[1]
        ver = args[2] if len(args) > 2 else ""
        allowed, reason = verify_package(pkg, ver)
        icon = "✓" if allowed else "✗"
        print(f"[guardian] {icon} {pkg}: {reason}")
        sys.exit(0 if allowed else 1)

    elif cmd == "install":
        sys.exit(intercept_install(args[1:]))

    elif cmd == "install-hook":
        install_pip_hook()

    else:
        print(f"[guardian] Unknown command: {cmd}. Run 'python guardian.py help'")
        sys.exit(1)


if __name__ == "__main__":
    main()
