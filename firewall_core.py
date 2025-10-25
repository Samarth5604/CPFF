"""
firewall_core.py
----------------
Core logic for the Windows-based Packet Filtering Firewall.

Responsibilities:
 - Load and normalize rules from YAML
 - Match packets against rules (protocol, IP, ports, GeoIP, rate-limit)
 - Log allowed/blocked packets to JSON files (with UTC timestamps)
 - Provide reusable, thread-safe API for the daemon layer

This module does NOT capture or inject packets — that’s handled by firewall_daemon.py.
"""

import os
import time
import json
import yaml
import uuid
import ipaddress
from datetime import datetime, timezone
from collections import defaultdict, deque
import threading

# ----------------------------
# Configuration
# ----------------------------
RULES_PATH = "rules.yaml"
LOG_DIR = "logs"
ALLOWED_DIR = os.path.join(LOG_DIR, "allowed_packets")
BLOCKED_DIR = os.path.join(LOG_DIR, "blocked_packets")
ALL_DIR = os.path.join(LOG_DIR, "all_packets")
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"

# Try to load GeoIP support
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except Exception:
    GEOIP_AVAILABLE = False

# ----------------------------
# Global data structures
# ----------------------------
rate_counters = defaultdict(lambda: deque())  # for rate-limiting
_rules = []                                   # loaded rules
_rules_last_load_time = 0                     # timestamp of last reload
_rules_lock = threading.Lock()                # thread safety lock


# ----------------------------
# Initialization Helpers
# ----------------------------
def initialize_log_dirs():
    """Ensure all log directories exist (only called once)."""
    for d in (ALLOWED_DIR, BLOCKED_DIR, ALL_DIR):
        os.makedirs(d, exist_ok=True)


initialize_log_dirs()  # Run at import


# ----------------------------
# GeoIP Utilities
# ----------------------------
def validate_geoip():
    """Validate that GeoIP database is working properly."""
    if not GEOIP_AVAILABLE or not os.path.exists(GEOIP_DB_PATH):
        print("[!] GeoIP unavailable or database missing.")
        return False
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            result = reader.country("8.8.8.8")
            print(f"[+] GeoIP test passed: 8.8.8.8 -> {result.country.iso_code}")
            return True
    except Exception:
        print("[!] GeoIP validation failed.")
        return False


def check_geoip(ip):
    """Return ISO country code for given IP, or None if lookup fails."""
    if not GEOIP_AVAILABLE or not os.path.exists(GEOIP_DB_PATH):
        return None
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            resp = reader.country(ip)
            return resp.country.iso_code
    except Exception:
        return None


# ----------------------------
# Utility Functions
# ----------------------------
def _get_attr(obj, attr, default=None):
    """Safely get an attribute or dict key."""
    try:
        return getattr(obj, attr)
    except Exception:
        try:
            return obj.get(attr, default)
        except Exception:
            return default


def get_protocol_name(packet):
    """Normalize protocol to string, handling multiple pydivert representations."""
    proto = _get_attr(packet, "protocol", None)
    try:
        if proto is None:
            return None
        if hasattr(proto, "name"):
            return proto.name.upper()
        if isinstance(proto, (tuple, list)):
            return str(proto[1]).upper() if len(proto) > 1 else str(proto[0]).upper()
        if isinstance(proto, int):
            mapping = {6: "TCP", 17: "UDP", 1: "ICMP"}
            return mapping.get(proto, str(proto))
        return str(proto).upper()
    except Exception:
        return str(proto)


def matches_cidr(ip_str, net):
    """Return True if IP belongs to CIDR network, False otherwise."""
    if not net:
        return False
    try:
        return ipaddress.ip_address(ip_str) in net
    except Exception:
        return False


# ----------------------------
# Rule Loading and Normalization
# ----------------------------
def _parse_single_rule(r):
    """Normalize one rule dict: protocol, IPs, ports, rate-limit."""
    pr = dict(r)

    # Normalize protocol
    if "protocol" in pr and pr["protocol"]:
        pr["protocol"] = str(pr["protocol"]).upper()

    # Parse CIDRs (store as *_net)
    for field in ("src_ip", "dst_ip"):
        val = pr.get(field)
        if val:
            try:
                pr[field + "_net"] = ipaddress.ip_network(str(val), strict=False)
            except Exception:
                pr[field + "_net"] = None
        else:
            pr[field + "_net"] = None

    # Normalize ports
    for p in ("src_port", "dst_port"):
        if p in pr and pr[p] is not None:
            try:
                pr[p] = int(pr[p])
            except Exception:
                pr[p] = None

    # Handle rate-limit block
    rl = pr.get("rate_limit")
    if rl:
        try:
            pr["_rate_threshold"] = int(rl.get("threshold", 100))
            pr["_rate_window"] = int(rl.get("window_seconds", 10))
        except Exception:
            pr["_rate_threshold"], pr["_rate_window"] = None, None
    else:
        pr["_rate_threshold"], pr["_rate_window"] = None, None

    return pr


def load_rules(path=RULES_PATH):
    """Load and preprocess rules from YAML file."""
    global _rules, _rules_last_load_time
    try:
        mtime = os.path.getmtime(path)
    except FileNotFoundError:
        print(f"[!] Rules file not found: {path}")
        return 0

    if mtime == _rules_last_load_time:
        return len(_rules)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
    except Exception as e:
        print(f"[!] Error reading {path}: {e}")
        return 0

    processed = []
    for r in data:
        try:
            processed.append(_parse_single_rule(r))
        except Exception as e:
            print(f"[WARN] Skipping invalid rule: {e}")
            continue

    with _rules_lock:
        _rules = processed
        _rules_last_load_time = mtime

    print(f"[+] Loaded {len(processed)} rules (mtime: {datetime.fromtimestamp(mtime)})")
    return len(processed)


def get_rules():
    """Thread-safe getter for loaded rules."""
    with _rules_lock:
        return list(_rules)


# ----------------------------
# Rate Limiting Logic
# ----------------------------
def rate_limited(key, rule):
    """Return True if the key (usually src_ip) exceeds rate limit."""
    thr = rule.get("_rate_threshold")
    window = rule.get("_rate_window")
    if not thr or not window:
        return False

    now = time.time()
    dq = rate_counters[key]

    # Remove old timestamps
    while dq and dq[0] < now - window:
        dq.popleft()

    dq.append(now)
    return len(dq) > thr


# ----------------------------
# Rule Matching Logic
# ----------------------------
def match_rule(packet, rules=None):
    """
    Compare a packet against rules.
    Return a copy of the first matching rule dict or None.
    """
    if rules is None:
        rules = get_rules()

    proto_name = get_protocol_name(packet)
    src_ip = _get_attr(packet, "src_addr")
    dst_ip = _get_attr(packet, "dst_addr")
    src_port = _get_attr(packet, "src_port")
    dst_port = _get_attr(packet, "dst_port")

    for rule in rules:
        # Protocol check
        if rule.get("protocol") and proto_name and proto_name.upper() != rule["protocol"].upper():
            continue

        # Source and destination IP check (CIDR aware)
        if rule.get("src_ip_net") and not matches_cidr(src_ip, rule["src_ip_net"]):
            continue
        if rule.get("dst_ip_net") and not matches_cidr(dst_ip, rule["dst_ip_net"]):
            continue

        # Port checks
        if rule.get("src_port") and int(src_port or 0) != int(rule["src_port"]):
            continue
        if rule.get("dst_port") and int(dst_port or 0) != int(rule["dst_port"]):
            continue

        # GeoIP check
        if rule.get("geoip_country"):
            country = check_geoip(src_ip)
            if not country or country.upper() != rule["geoip_country"].upper():
                continue

        # Rate limit check
        if rule.get("_rate_threshold") and rule.get("_rate_window"):
            if rate_limited(src_ip, rule):
                r = dict(rule)
                r["_rate_hit"] = True
                r["rule_id"] = rule.get("id")
                return r

        # Return a safe copy of rule
        matched = dict(rule)
        matched["rule_id"] = rule.get("id")
        return matched

    return None


# ----------------------------
# Safe Logging (Final Stable Fix)
# ----------------------------
import uuid
import os
import time
import json
from datetime import datetime


def safe_write(filepath, content):
    """
    Safely write content to a unique file to avoid WinError 183.
    Each call produces a new unique filename with a UUID suffix.
    """
    base, ext = os.path.splitext(filepath)

    for _ in range(3):
        unique_path = f"{base}_{uuid.uuid4().hex}{ext}"
        try:
            # Use 'x' mode to ensure the file must not already exist
            with open(unique_path, "x", encoding="utf-8") as f:
                f.write(content)
            return unique_path
        except FileExistsError:
            # If a UUID collision somehow occurs, retry
            time.sleep(0.002)
            continue
        except OSError as e:
            if getattr(e, "winerror", None) == 183:
                # Another process created it in the same instant — retry
                time.sleep(0.003)
                continue
            else:
                print(f"[Write Error] {e}")
                break
    return None


def log_packet(entry):
    """
    Log allowed or blocked packets to structured JSON + summary JSONL.
    Writes each packet to a uniquely named JSON file.
    """
    from firewall_core import ALLOWED_DIR, BLOCKED_DIR, ALL_DIR, initialize_log_dirs

    initialize_log_dirs()
    action = entry.get("action", "UNKNOWN").upper()
    date_str = datetime.now().strftime("%Y-%m-%d")

    # Directories
    dir_target = BLOCKED_DIR if action == "BLOCK" else ALLOWED_DIR

    # Always generate a unique name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"packet_{timestamp}_{uuid.uuid4().hex[:6]}_{action.lower()}.json"
    filepath = os.path.join(dir_target, filename)

    # Write the detailed JSON safely
    json_content = json.dumps(entry, indent=4, default=str)
    safe_write(filepath, json_content)

    # Append summary
    summary_path = os.path.join(ALL_DIR, f"firewall_all_{date_str}.jsonl")
    try:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        print(f"[Summary Log Error] {e}")
# ----------------------------
# Pretty-print helper
# ----------------------------
def rule_to_string(rule):
    """Generate human-readable string summary of a rule."""
    if not rule:
        return "<no rule>"
    parts = []
    if rule.get("id"):
        parts.append(f"id={rule['id']}")
    parts.append(f"action={rule.get('action', 'allow')}")
    if rule.get("protocol"):
        parts.append(f"proto={rule['protocol']}")
    if rule.get("dst_port"):
        parts.append(f"dst_port={rule['dst_port']}")
    if rule.get("src_ip"):
        parts.append(f"src_ip={rule['src_ip']}")
    if rule.get("dst_ip"):
        parts.append(f"dst_ip={rule['dst_ip']}")
    if rule.get("geoip_country"):
        parts.append(f"geo={rule['geoip_country']}")
    return ", ".join(parts)


# ----------------------------
# Self-test entrypoint
# ----------------------------
if __name__ == "__main__":
    print("=== Firewall Core Self-Test ===")
    print(f"GeoIP available: {GEOIP_AVAILABLE}")
    if GEOIP_AVAILABLE:
        validate_geoip()

    count = load_rules()
    print(f"[+] Loaded {count} rules.")

    pkt = {
        "src_addr": "8.8.8.8",
        "dst_addr": "1.1.1.1",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "TCP"
    }

    rule = match_rule(pkt)
    print("Matched Rule:", rule_to_string(rule) if rule else "None")
