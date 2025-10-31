"""
firewall_core.py
----------------
Core logic for the Windows-based Packet Filtering Firewall (CPFF).

Optimized Features:
 - YAML-based rule loading (with preprocessing)
 - Fast rule grouping by protocol for quick matching
 - CIDR and port precompilation (done at load time)
 - Packet-to-rule matching (protocol, port, IP, GeoIP, rate-limit)
 - Buffered (asynchronous) logging with flush-on-shutdown
 - Thread-safe rule reloading and token-bucket rate-limiting
 - YAML-safe serializer helper for daemon persistence
 - Rule-hit profiling + adaptive reordering (background thread)
 - Automatic token-bucket cleanup for memory stability
 - Profiling access functions for integration with daemon/client
"""

import os
import time
import json
import yaml
import ipaddress
import threading
import queue
from datetime import datetime, timezone
from collections import defaultdict
from functools import lru_cache

# ----------------------------
# Configuration
# ----------------------------
RULES_PATH = "rules.yaml"
LOG_DIR = "logs"
ALL_DIR = os.path.join(LOG_DIR, "all_packets")
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"

LOG_FLUSH_INTERVAL = 3
LOG_QUEUE_MAXSIZE = 5000

PROFILER_INTERVAL_SECONDS = 60
ADAPTIVE_WEIGHT = 1000

BUCKET_CLEAN_INTERVAL = 60
BUCKET_IDLE_TIMEOUT = 300

# ----------------------------
# Directory setup
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
rate_buckets = {}
_rule_hits = defaultdict(int)
_rules = []
_rules_by_proto = defaultdict(list)
_rules_mtime = 0
_rules_lock = threading.Lock()

# ----------------------------
# Buffered Logging
# ----------------------------
_log_queue = queue.Queue(maxsize=LOG_QUEUE_MAXSIZE)
_log_lock = threading.Lock()
_log_stop_event = threading.Event()


def _flush_once():
    logs_to_flush = []
    try:
        while not _log_queue.empty():
            logs_to_flush.append(_log_queue.get_nowait())
    except queue.Empty:
        pass

    if not logs_to_flush:
        return

    for log in logs_to_flush:
        ts = log.get("timestamp")
        if isinstance(ts, (int, float)):
            log["timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")
        elif isinstance(ts, datetime):
            log["timestamp"] = ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")
        elif isinstance(ts, str) and "T" in ts:
            log["timestamp"] = ts.replace("T", " ").split("+")[0] + " UTC"

    date_str = datetime.now().strftime("%Y-%m-%d")
    path = os.path.join(ALL_DIR, f"firewall_all_{date_str}.jsonl")

    try:
        with _log_lock, open(path, "a", encoding="utf-8") as f:
            for log in logs_to_flush:
                f.write(json.dumps(log, ensure_ascii=False) + "\n")
        print(f"[Log Flush] {len(logs_to_flush)} entries → {path}")
    except Exception as e:
        print(f"[Log Flush Error] {e}")


def _log_writer():
    while not _log_stop_event.is_set():
        time.sleep(LOG_FLUSH_INTERVAL)
        _flush_once()
    _flush_once()
    print("[Log Flush] Final flush complete.")


def start_logger():
    t = threading.Thread(target=_log_writer, daemon=True)
    t.start()
    return t


def stop_logger():
    _log_stop_event.set()
    time.sleep(0.5)
    _flush_once()


def log_packet(entry):
    try:
        _log_queue.put_nowait(entry)
    except queue.Full:
        print("[!] Log queue full — dropping entries.")


# start logger immediately
start_logger()

# ----------------------------
# GeoIP (cached)
# ----------------------------
@lru_cache(maxsize=16384)
def check_geoip_cached(ip):
    if not GEOIP_AVAILABLE or not os.path.exists(GEOIP_DB_PATH):
        return None
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            resp = reader.country(ip)
            return resp.country.iso_code
    except Exception:
        return None


def check_geoip(ip):
    return check_geoip_cached(ip)


def validate_geoip():
    if not GEOIP_AVAILABLE:
        print("[!] GeoIP library not available.")
    elif not os.path.exists(GEOIP_DB_PATH):
        print(f"[!] GeoIP database not found at {GEOIP_DB_PATH}")
    else:
        print("[+] GeoIP database validated.")


# ----------------------------
# Rule Parsing / Preprocessing
# ----------------------------
def _parse_single_rule(r):
    pr = dict(r)
    pr.setdefault("priority", 100)
    pr.setdefault("enabled", True)
    pr.setdefault("log", True)

    if "protocol" in pr and pr["protocol"]:
        pr["protocol"] = str(pr["protocol"]).upper()

    # IP preprocessing
    for field in ("src_ip", "dst_ip"):
        if pr.get(field):
            try:
                pr[field + "_net"] = ipaddress.ip_network(str(pr[field]), strict=False)
            except Exception:
                pr[field + "_net"] = None
        else:
            pr[field + "_net"] = None

    # Ports preprocessing
    for p in ("src_port", "dst_port"):
        if pr.get(p) is not None:
            try:
                if isinstance(pr[p], list):
                    pr["_" + p + "_set"] = set(int(x) for x in pr[p])
                    pr["_" + p + "_single"] = None
                else:
                    pr["_" + p + "_single"] = int(pr[p])
                    pr["_" + p + "_set"] = None
            except Exception:
                pr["_" + p + "_set"] = pr["_" + p + "_single"] = None
        else:
            pr["_" + p + "_set"] = pr["_" + p + "_single"] = None

    # Rate limit params
    rl = pr.get("rate_limit")
    if rl:
        try:
            if isinstance(rl, str) and "/" in rl:
                t, w = rl.split("/")
                thr, window = int(t), int(w)
            elif isinstance(rl, dict):
                thr = int(rl.get("threshold", 0))
                window = int(rl.get("window_seconds", 0))
            else:
                thr = window = 0
            if thr > 0 and window > 0:
                pr["_rate_capacity"] = thr
                pr["_rate_window"] = window
                pr["_rate_fill_per_sec"] = thr / window
            else:
                pr["_rate_capacity"] = pr["_rate_window"] = pr["_rate_fill_per_sec"] = None
        except Exception:
            pr["_rate_capacity"] = pr["_rate_window"] = pr["_rate_fill_per_sec"] = None
    else:
        pr["_rate_capacity"] = pr["_rate_window"] = pr["_rate_fill_per_sec"] = None

    return pr


def serialize_rules_for_yaml(rules):
    """Convert internal rule dicts to YAML-safe format."""
    safe_rules = []
    for r in rules:
        cleaned = {}
        for k, v in r.items():
            if k.startswith("_") or k.endswith("_net"):
                continue
            if hasattr(v, "exploded") or isinstance(v, (ipaddress._BaseNetwork, ipaddress._BaseAddress)):
                cleaned[k] = str(v)
            elif isinstance(v, (list, tuple)):
                cleaned[k] = list(v)
            elif isinstance(v, dict):
                cleaned[k] = {kk: str(vv) for kk, vv in v.items()}
            else:
                try:
                    json.dumps(v)
                    cleaned[k] = v
                except Exception:
                    cleaned[k] = str(v)
        cleaned.setdefault("priority", r.get("priority", 100))
        cleaned.setdefault("enabled", r.get("enabled", True))
        cleaned.setdefault("log", r.get("log", True))
        safe_rules.append(cleaned)
    return safe_rules


# ----------------------------
# Rule Loading
# ----------------------------
def load_rules(path=RULES_PATH):
    global _rules, _rules_mtime, _rules_by_proto
    try:
        mtime = os.path.getmtime(path)
    except FileNotFoundError:
        return 0

    if mtime == _rules_mtime:
        return len(_rules)

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []

    proto_buckets = defaultdict(list)
    for raw in data:
        try:
            pr = _parse_single_rule(raw)
            proto_key = pr.get("protocol") or "ANY"
            proto_buckets[proto_key].append(pr)
        except Exception as e:
            print(f"[Rule Parse Error] {e}")

    for proto_key in proto_buckets:
        proto_buckets[proto_key].sort(key=lambda x: int(x.get("priority", 100)))

    all_rules = [r for lst in proto_buckets.values() for r in lst]
    merged = sorted(all_rules, key=lambda x: int(x.get("priority", 100)))

    with _rules_lock:
        _rules = merged
        _rules_by_proto = proto_buckets
        _rules_mtime = mtime

    return len(_rules)


def get_rules():
    with _rules_lock:
        return list(_rules)


# ----------------------------
# Token-Bucket Rate Limiting
# ----------------------------
def _bucket_key(rule_id, ip):
    return f"{rule_id}::{ip}"


def _init_bucket_if_missing(rule, ip, now):
    key = _bucket_key(rule.get("id"), ip)
    if key not in rate_buckets:
        cap = rule.get("_rate_capacity")
        fill = rule.get("_rate_fill_per_sec")
        if not cap or not fill:
            return None
        rate_buckets[key] = {"tokens": cap, "last": now, "rate_per_sec": fill, "capacity": cap}
    return rate_buckets.get(key)


def rate_limited(ip, rule):
    cap = rule.get("_rate_capacity")
    fill = rule.get("_rate_fill_per_sec")
    if not cap or not fill:
        return False
    now = time.time()
    key = _bucket_key(rule.get("id"), ip)
    bucket = rate_buckets.get(key) or _init_bucket_if_missing(rule, ip, now)
    if bucket is None:
        return False
    elapsed = now - bucket["last"]
    if elapsed > 0:
        bucket["tokens"] = min(bucket["capacity"], bucket["tokens"] + elapsed * bucket["rate_per_sec"])
        bucket["last"] = now
    if bucket["tokens"] >= 1:
        bucket["tokens"] -= 1
        return False
    return True


# ----------------------------
# Bucket Cleanup Thread
# ----------------------------
_bucket_clean_stop = threading.Event()


def _bucket_cleaner_worker():
    while not _bucket_clean_stop.is_set():
        time.sleep(BUCKET_CLEAN_INTERVAL)
        now = time.time()
        removed = 0
        try:
            for key, b in list(rate_buckets.items()):
                if now - b.get("last", 0) > BUCKET_IDLE_TIMEOUT:
                    del rate_buckets[key]
                    removed += 1
            if removed > 0:
                print(f"[Bucket Cleanup] Removed {removed} stale buckets ({len(rate_buckets)} active).")
        except Exception as e:
            print(f"[Bucket Cleanup Error] {e}")


_bucket_clean_thread = threading.Thread(target=_bucket_cleaner_worker, daemon=True)
_bucket_clean_thread.start()


def stop_bucket_cleaner():
    _bucket_clean_stop.set()
    if _bucket_clean_thread.is_alive():
        _bucket_clean_thread.join(timeout=1)


# ----------------------------
# Packet Matching + Profiling
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
    if rules is None:
        proto = get_protocol_name(packet) or "ANY"
        with _rules_lock:
            candidates = list(_rules_by_proto.get(proto, [])) + list(_rules_by_proto.get("ANY", []))
    else:
        candidates = rules

    src_ip = getattr(packet, "src_addr", None)
    dst_ip = getattr(packet, "dst_addr", None)
    dst_port = getattr(packet, "dst_port", None)

    for r in candidates:
        if not r.get("enabled", True):
            continue
        if r.get("src_ip_net") and not matches_cidr(src_ip, r["src_ip_net"]):
            continue
        if r.get("dst_ip_net") and not matches_cidr(dst_ip, r["dst_ip_net"]):
            continue
        if r.get("_dst_port_set") and int(dst_port) not in r["_dst_port_set"]:
            continue
        if r.get("_dst_port_single") and int(dst_port or -1) != int(r["_dst_port_single"]):
            continue
        if r.get("geoip_country"):
            c = check_geoip(src_ip)
            if not c or c.upper() != r["geoip_country"].upper():
                continue
        if rate_limited(src_ip, r):
            _rule_hits[int(r.get("id", -1))] += 1
            return r
        _rule_hits[int(r.get("id", -1))] += 1
        return r
    return None


# ----------------------------
# Adaptive Profiler Thread
# ----------------------------
_profiler_stop = threading.Event()


def _profiler_worker():
    while not _profiler_stop.is_set():
        time.sleep(PROFILER_INTERVAL_SECONDS)
        snapshot = dict(_rule_hits)
        with _rules_lock:
            for proto, lst in _rules_by_proto.items():
                def key_fn(rule):
                    base = int(rule.get("priority", 100))
                    hits = snapshot.get(int(rule.get("id", 0)), 0)
                    return (base, -hits * ADAPTIVE_WEIGHT)
                _rules_by_proto[proto] = sorted(lst, key=key_fn)
            _rules[:] = [r for lst in _rules_by_proto.values() for r in lst]
        print("[Profiler] Adaptive rule ordering updated.")


_profiler_thread = threading.Thread(target=_profiler_worker, daemon=True)
_profiler_thread.start()


def stop_profiler():
    _profiler_stop.set()
    if _profiler_thread.is_alive():
        _profiler_thread.join(timeout=1)


# ----------------------------
# Profiling Access Functions
# ----------------------------
def get_rule_hits():
    """Return snapshot of rule hit counts."""
    return dict(_rule_hits)


def get_top_rules(n=10):
    """Return top-N most hit rules."""
    hits = sorted(_rule_hits.items(), key=lambda x: x[1], reverse=True)
    rules = get_rules()
    return [
        {
            "id": rid,
            "hits": cnt,
            "comment": next((r.get("comment") for r in rules if r.get("id") == rid), ""),
            "action": next((r.get("action") for r in rules if r.get("id") == rid), ""),
        }
        for rid, cnt in hits[:n]
    ]


def reset_rule_hits():
    """Clear profiling counters."""
    _rule_hits.clear()


# ----------------------------
# Self-Test
# ----------------------------
if __name__ == "__main__":
    print("=== Firewall Core Self-Test ===")
    print("GeoIP available:", GEOIP_AVAILABLE and os.path.exists(GEOIP_DB_PATH))
    n = load_rules()
    print(f"[+] Loaded {n} rules.")
    class P: pass
    pkt = P()
    pkt.src_addr = "8.8.8.8"
    pkt.dst_addr = "1.1.1.1"
    pkt.src_port = 12345
    pkt.dst_port = 80
    pkt.protocol = "TCP"
    rule = match_rule(pkt)
    print("Matched Rule:", rule)
    print("Top Rules Snapshot:", get_top_rules())
    stop_logger()
    stop_profiler()
    stop_bucket_cleaner()
