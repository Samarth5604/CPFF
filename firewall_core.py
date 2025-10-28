"""
firewall_core.py
----------------
Core logic for the Windows-based Packet Filtering Firewall.

Features:
 - YAML-based rule loading
 - Packet-to-rule matching (protocol, port, IP, GeoIP, rate-limit)
 - Buffered (asynchronous) logging with flush-on-shutdown
 - Thread-safe rule reloading and rate-limiting
"""

import os
import time
import json
import yaml
import uuid
import ipaddress
import threading
import queue
from datetime import datetime, timezone
from collections import defaultdict, deque

# ----------------------------
# Configuration
# ----------------------------
RULES_PATH = "rules.yaml"
LOG_DIR = "logs"
ALL_DIR = os.path.join(LOG_DIR, "all_packets")
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"

LOG_FLUSH_INTERVAL = 3        # seconds between flushes
LOG_QUEUE_MAXSIZE = 5000      # prevent memory overflow

# ----------------------------
# Directories
# ----------------------------
os.makedirs(ALL_DIR, exist_ok=True)

# ----------------------------
# GeoIP setup
# ----------------------------
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except Exception:
    GEOIP_AVAILABLE = False

# ----------------------------
# Global State
# ----------------------------
rate_counters = defaultdict(lambda: deque())
_rules = []
_rules_mtime = 0
_rules_lock = threading.Lock()

# ----------------------------
# Buffered Logging System
# ----------------------------
_log_queue = queue.Queue(maxsize=LOG_QUEUE_MAXSIZE)
_log_lock = threading.Lock()
_log_stop_event = threading.Event()


def _flush_once():
    """Write all queued logs to disk immediately with readable timestamps."""
    logs_to_flush = []
    try:
        while not _log_queue.empty():
            logs_to_flush.append(_log_queue.get_nowait())
    except queue.Empty:
        pass

    if not logs_to_flush:
        return

    # Normalize timestamps (convert epoch -> ISO string)
    for log in logs_to_flush:
        ts = log.get("timestamp")
        if isinstance(ts, (int, float)):
            # Convert epoch seconds to human-readable UTC time
            log["timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")
        elif isinstance(ts, datetime):
            # Convert datetime object to ISO8601
            log["timestamp"] = ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")
        elif isinstance(ts, str):
            # Keep ISO strings but normalize spacing
            if "T" in ts:
                log["timestamp"] = ts.replace("T", " ").split("+")[0] + " UTC"

    date_str = datetime.now().strftime("%Y-%m-%d")
    summary_path = os.path.join(ALL_DIR, f"firewall_all_{date_str}.jsonl")

    try:
        with _log_lock, open(summary_path, "a", encoding="utf-8") as f:
            for log in logs_to_flush:
                f.write(json.dumps(log, ensure_ascii=False) + "\n")
        print(f"[Log Flush] Wrote {len(logs_to_flush)} entries → {summary_path}")
    except Exception as e:
        print(f"[Log Flush Error] {e}")


def _log_writer():
    """Background thread: periodically flush logs until stop event."""
    while not _log_stop_event.is_set():
        time.sleep(LOG_FLUSH_INTERVAL)
        _flush_once()
    # Final flush before exit
    _flush_once()
    print("[Log Flush] Final flush complete.")


def start_logger():
    """Start the background log writer thread."""
    t = threading.Thread(target=_log_writer, daemon=True)
    t.start()
    return t


def stop_logger():
    """Signal logger thread to stop and flush."""
    _log_stop_event.set()
    time.sleep(0.5)
    _flush_once()


def log_packet(entry):
    """Queue packet log entry for asynchronous flush."""
    try:
        _log_queue.put_nowait(entry)
    except queue.Full:
        print("[!] Log queue full — dropping entries.")


# Start the logger as soon as module loads
start_logger()

# ----------------------------
# GeoIP Functions
# ----------------------------
def validate_geoip():
    """Check GeoIP availability."""
    if not GEOIP_AVAILABLE or not os.path.exists(GEOIP_DB_PATH):
        return False
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            result = reader.country("8.8.8.8")
            print(f"[+] GeoIP test passed: 8.8.8.8 -> {result.country.iso_code}")
            return True
    except Exception:
        return False


def check_geoip(ip):
    """Return ISO country code for given IP."""
    if not GEOIP_AVAILABLE or not os.path.exists(GEOIP_DB_PATH):
        return None
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            resp = reader.country(ip)
            return resp.country.iso_code
    except Exception:
        return None


# ----------------------------
# Rule Handling
# ----------------------------
def _parse_single_rule(r):
    """Normalize one rule dict for internal use."""
    pr = dict(r)

    if "protocol" in pr and pr["protocol"]:
        pr["protocol"] = str(pr["protocol"]).upper()

    for field in ("src_ip", "dst_ip"):
        if field in pr and pr[field]:
            try:
                pr[field + "_net"] = ipaddress.ip_network(str(pr[field]), strict=False)
            except Exception:
                pr[field + "_net"] = None
        else:
            pr[field + "_net"] = None

    for p in ("src_port", "dst_port"):
        if p in pr and pr[p] is not None:
            try:
                if isinstance(pr[p], list):
                    pr[p] = [int(x) for x in pr[p]]
                else:
                    pr[p] = int(pr[p])
            except Exception:
                pr[p] = None

    rl = pr.get("rate_limit")
    if rl:
        try:
            pr["_rate_threshold"] = int(rl.get("threshold", 100))
            pr["_rate_window"] = int(rl.get("window_seconds", 10))
        except Exception:
            pr["_rate_threshold"] = pr["_rate_window"] = None
    else:
        pr["_rate_threshold"] = pr["_rate_window"] = None

    return pr


def load_rules(path=RULES_PATH):
    """Load and preprocess rules from YAML file."""
    global _rules, _rules_mtime
    try:
        mtime = os.path.getmtime(path)
    except FileNotFoundError:
        return 0

    if mtime == _rules_mtime:
        return len(_rules)

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []

    processed = [_parse_single_rule(r) for r in data]
    with _rules_lock:
        _rules = processed
        _rules_mtime = mtime

    return len(processed)


def get_rules():
    """Thread-safe getter for loaded rules."""
    with _rules_lock:
        return list(_rules)


# ----------------------------
# Rate Limiting
# ----------------------------
def rate_limited(ip, rule):
    thr, window = rule.get("_rate_threshold"), rule.get("_rate_window")
    if not thr or not window:
        return False
    now = time.time()
    dq = rate_counters[ip]
    while dq and dq[0] < now - window:
        dq.popleft()
    dq.append(now)
    return len(dq) > thr


# ----------------------------
# Packet Matching
# ----------------------------
def matches_cidr(ip, net):
    if not net:
        return False
    try:
        return ipaddress.ip_address(ip) in net
    except Exception:
        return False


def get_protocol_name(packet):
    proto = getattr(packet, "protocol", None)
    if proto is None:
        return None
    if hasattr(proto, "name"):
        return proto.name.upper()
    if isinstance(proto, (tuple, list)):
        return str(proto[1]).upper() if len(proto) > 1 else str(proto[0])
    if isinstance(proto, int):
        return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
    return str(proto).upper()


def match_rule(packet, rules=None):
    """Match a packet against loaded firewall rules."""
    if rules is None:
        rules = get_rules()

    proto = get_protocol_name(packet)
    src_ip = getattr(packet, "src_addr", None)
    dst_ip = getattr(packet, "dst_addr", None)
    src_port = getattr(packet, "src_port", None)
    dst_port = getattr(packet, "dst_port", None)

    for r in rules:
        if r.get("protocol") and proto != r["protocol"]:
            continue
        if r.get("src_ip_net") and not matches_cidr(src_ip, r["src_ip_net"]):
            continue
        if r.get("dst_ip_net") and not matches_cidr(dst_ip, r["dst_ip_net"]):
            continue

        # Handle port lists and single ports
        if isinstance(r.get("dst_port"), list):
            if dst_port not in r["dst_port"]:
                continue
        elif r.get("dst_port") and int(dst_port or -1) != int(r["dst_port"]):
            continue

        if r.get("geoip_country"):
            c = check_geoip(src_ip)
            if c is None or c.upper() != r["geoip_country"].upper():
                continue

        if rate_limited(src_ip, r):
            r["_rate_hit"] = True
            return r

        return r

    return None


# ----------------------------
# Self-Test (optional)
# ----------------------------
if __name__ == "__main__":
    print("=== Firewall Core Self-Test ===")
    validate_geoip()
    n = load_rules()
    print(f"[+] Loaded {n} rules.")
    pkt = {
        "src_addr": "8.8.8.8",
        "dst_addr": "1.1.1.1",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "TCP"
    }
    rule = match_rule(pkt)
    print("Matched Rule:", rule)
