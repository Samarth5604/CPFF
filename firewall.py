import time
import os
import threading
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
import yaml
import ipaddress

try:
    import pydivert
except Exception as e:
    raise SystemExit("pydivert is required. Install it and ensure WinDivert files are in place and run as Admin.") from e

# Optional GeoIP
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except Exception:
    GEOIP_AVAILABLE = False

RULES_PATH = "rules.yaml"
LOG_PATH = "firewall_log.jsonl"
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"

rate_counters = defaultdict(lambda: deque())
_rules = []
_rules_mtime = 0
_rules_lock = threading.Lock()

# --- FIX: Safe protocol normalization ---
def get_protocol_name(packet):
    proto = getattr(packet, "protocol", None)
    if proto is None:
        return None
    if hasattr(proto, "name"):  # enum-like
        return proto.name.upper()
    if isinstance(proto, (tuple, list)):
        return str(proto[1]).upper() if len(proto) > 1 else str(proto[0])
    if isinstance(proto, int):
        mapping = {6: "TCP", 17: "UDP", 1: "ICMP"}
        return mapping.get(proto, str(proto))
    return str(proto).upper()

def load_rules():
    global _rules, _rules_mtime
    try:
        mtime = os.path.getmtime(RULES_PATH)
    except FileNotFoundError:
        print(f"[!] {RULES_PATH} not found.")
        return

    if mtime == _rules_mtime:
        return

    with open(RULES_PATH, "r") as f:
        data = yaml.safe_load(f) or []

    processed = []
    for r in data:
        pr = dict(r)
        if "protocol" in pr and pr["protocol"]:
            pr["protocol"] = pr["protocol"].upper()
        for field in ("src_ip", "dst_ip"):
            if field in pr and pr[field]:
                try:
                    pr[field + "_net"] = ipaddress.ip_network(pr[field], strict=False)
                except Exception:
                    pr[field + "_net"] = None
        if "rate_limit" in pr and pr["rate_limit"]:
            rl = pr["rate_limit"]
            pr.setdefault("_rate_threshold", int(rl.get("threshold", 100)))
            pr.setdefault("_rate_window", int(rl.get("window_seconds", 10)))
        processed.append(pr)

    with _rules_lock:
        _rules = processed
        _rules_mtime = mtime
    print(f"[+] Loaded {len(processed)} rules (mtime: {datetime.fromtimestamp(mtime)})")

def rules_watcher(interval=2):
    while True:
        try:
            load_rules()
        except Exception as e:
            print("Error loading rules:", e)
        time.sleep(interval)

def matches_cidr(packet_ip, net):
    if not net:
        return False
    try:
        return ipaddress.ip_address(packet_ip) in net
    except Exception:
        return False

def check_geoip(ip):
    if not GEOIP_AVAILABLE:
        return None
    if not os.path.exists(GEOIP_DB_PATH):
        return None
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            resp = reader.country(ip)
            return resp.country.iso_code
    except Exception:
        return None

def rate_limited(src_ip, rule):
    thr = rule.get("_rate_threshold")
    window = rule.get("_rate_window")
    if not thr or not window:
        return False
    now = time.time()
    dq = rate_counters[src_ip]
    while dq and dq[0] < now - window:
        dq.popleft()
    dq.append(now)
    if len(dq) > thr:
        return True
    return False

def match_rule(packet, rules):
    with _rules_lock:
        local_rules = list(_rules)

    proto_name = get_protocol_name(packet)
    src_ip = packet.src_addr
    dst_ip = packet.dst_addr
    src_port = getattr(packet, "src_port", None)
    dst_port = getattr(packet, "dst_port", None)

    for rule in local_rules:
        if "protocol" in rule and rule.get("protocol"):
            if proto_name != rule["protocol"]:
                continue
        if "src_ip_net" in rule and rule["src_ip_net"] is not None:
            if not matches_cidr(src_ip, rule["src_ip_net"]):
                continue
        elif "src_ip" in rule and rule.get("src_ip"):
            if src_ip != rule["src_ip"]:
                continue
        if "dst_ip_net" in rule and rule["dst_ip_net"] is not None:
            if not matches_cidr(dst_ip, rule["dst_ip_net"]):
                continue
        elif "dst_ip" in rule and rule.get("dst_ip"):
            if dst_ip != rule["dst_ip"]:
                continue
        if "dst_port" in rule and rule.get("dst_port") is not None:
            if dst_port != int(rule["dst_port"]):
                continue
        if "src_port" in rule and rule.get("src_port") is not None:
            if src_port != int(rule["src_port"]):
                continue
        if "geoip_country" in rule and rule.get("geoip_country"):
            country = check_geoip(src_ip)
            if country is None:
                continue
            if country.upper() != rule["geoip_country"].upper():
                continue
        if "rate_limit" in rule and rule.get("rate_limit"):
            if rate_limited(src_ip, rule):
                rule = dict(rule)
                rule["_rate_hit"] = True
                return rule
        return rule
    return None

def log_decision(entry):
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        print("Failed to write log:", e)

def run_firewall():
    load_rules()
    t = threading.Thread(target=rules_watcher, daemon=True)
    t.start()

    with pydivert.WinDivert("true") as w:
        print("[*] Firewall running with rules... Press Ctrl+C to stop.")
        for packet in w:
            try:
                pkt_info = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "src_ip": getattr(packet, "src_addr", None),
                    "dst_ip": getattr(packet, "dst_addr", None),
                    "src_port": getattr(packet, "src_port", None),
                    "dst_port": getattr(packet, "dst_port", None),
                    "protocol": get_protocol_name(packet)
                }

                rule = match_rule(packet, _rules)
                if rule:
                    action = rule.get("action", "block").lower()
                    if action == "block":
                        entry = {**pkt_info, "action": "BLOCK", "rule_id": rule.get("id"), "comment": rule.get("comment")}
                        if rule.get("_rate_hit"):
                            entry["reason"] = "rate_limit"
                        log_decision(entry)
                        print(f"[BLOCK] {entry['src_ip']}:{entry['src_port']} -> {entry['dst_ip']}:{entry['dst_port']} rule={rule.get('id')}")
                        continue
                    elif action == "allow":
                        entry = {**pkt_info, "action": "ALLOW", "rule_id": rule.get("id"), "comment": rule.get("comment")}
                        log_decision(entry)
                        w.send(packet)
                        continue
                    elif action == "log":
                        entry = {**pkt_info, "action": "LOG", "rule_id": rule.get("id"), "comment": rule.get("comment")}
                        log_decision(entry)
                        w.send(packet)
                        continue
                    else:
                        w.send(packet)
                        continue
                else:
                    w.send(packet)
            except Exception as e:
                print("Runtime error:", e)
                try:
                    w.send(packet)
                except Exception:
                    pass

if __name__ == "__main__":
    print("Make sure you run this script as Administrator.")
    run_firewall()
