"""
firewall_ai.py — CPFF AI Rule Suggestion Engine (safe version)

Analyzes recent firewall logs and suggests intelligent block rules based on:
 - Aggressive source IPs
 - High-volume destination ports
 - Frequent (src, dst_port) pairs

✅ Improvements:
 - Skips local/private IPs (127.x, 192.168.x, 10.x, etc.)
 - Skips your own machine’s IPs
 - Maintains performance and compatibility
"""

import os
import time
import json
import yaml
import socket
import ipaddress
from collections import Counter, defaultdict
from datetime import datetime
import math
import firewall_core

# =========================
# Configurable Parameters
# =========================
LOG_LOOKBACK_SECONDS = 60 * 60 * 6   # 6 hours lookback
MAX_LINES_READ = 20000               # safety limit
IP_HIT_THRESHOLD = 150               # per-IP volume threshold
PORT_HIT_THRESHOLD = 500             # per-port hit threshold
PAIR_HIT_THRESHOLD = 60              # per (src,port) hit threshold
MIN_CONFIDENCE = 0.2                 # min confidence to include
SUGGESTION_PATH = "rules_suggestion.yaml"
TOP_N = 50                           # max suggestions to keep

# =========================
# Helpers for local IP filtering
# =========================
def _is_private_or_local(ip: str) -> bool:
    """Return True if IP is local, private, or loopback."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return True
    except Exception:
        return False
    return False


def _get_local_ips():
    """Return a set of local machine IPs to avoid self-blocks."""
    local_ips = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for addr in socket.getaddrinfo(hostname, None):
            ip = addr[4][0]
            if ":" not in ip:  # skip IPv6 for simplicity
                local_ips.add(ip)
    except Exception:
        pass
    return local_ips


LOCAL_IPS = _get_local_ips()


# =========================
# Log Reader
# =========================
def _iter_log_lines():
    """
    Yield parsed JSON entries from the most recent firewall_all_*.jsonl files.
    Reads newest files first and stops when MAX_LINES_READ or LOG_LOOKBACK_SECONDS reached.
    """
    all_dir = getattr(firewall_core, "ALL_DIR", "logs/all_packets")
    if not os.path.isdir(all_dir):
        return

    files = sorted(
        [os.path.join(all_dir, f) for f in os.listdir(all_dir)
         if f.startswith("firewall_all_") and f.endswith(".jsonl")],
        key=os.path.getmtime,
        reverse=True
    )

    lines_read = 0
    now_ts = time.time()

    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                for line in fh:
                    if lines_read >= MAX_LINES_READ:
                        return
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue

                    # Filter by timestamp if present
                    ts = None
                    for k in ("timestamp", "time", "ts"):
                        if k in obj:
                            try:
                                ts = datetime.fromisoformat(str(obj[k])).timestamp()
                            except Exception:
                                ts = None
                            break
                    if ts and (now_ts - ts) > LOG_LOOKBACK_SECONDS:
                        continue

                    yield obj
                    lines_read += 1
                    if lines_read >= MAX_LINES_READ:
                        return
        except Exception:
            continue


# =========================
# Confidence Scoring
# =========================
def _score_confidence(count, total_count):
    """Compute a confidence metric (0–1) based on frequency and volume."""
    if total_count <= 0:
        return 0.0
    ratio = count / total_count
    val = 1 - math.exp(-5 * ratio)  # sigmoid-like curve
    vol_factor = min(1.0, math.log1p(count) / 6.0)
    conf = val * 0.7 + vol_factor * 0.3
    return max(0.0, min(1.0, conf))


# =========================
# Main Analysis Function
# =========================
def analyze_and_suggest():
    """
    Analyze recent logs and return AI rule suggestions.

    Returns a list of rule dicts:
      {id, action, protocol, src_ip, dst_ip, dst_port, comment, confidence}
    """
    src_counter = Counter()
    dst_port_counter = Counter()
    pair_counter = Counter()
    src_unique_dstports = defaultdict(set)
    total_entries = 0

    for entry in _iter_log_lines():
        total_entries += 1
        src = entry.get("src_ip")
        dst_port = entry.get("dst_port")
        proto = entry.get("protocol") or entry.get("proto")

        try:
            dst_port = int(dst_port) if dst_port is not None else None
        except Exception:
            dst_port = None

        if src:
            src_counter[src] += 1
        if dst_port is not None:
            dst_port_counter[dst_port] += 1
        if src and dst_port is not None:
            pair_counter[(src, dst_port)] += 1
            src_unique_dstports[src].add(dst_port)

    suggestions = []

    # ---------------------------------------------------------
    # Heuristic 1: Aggressive Source IPs (external only)
    # ---------------------------------------------------------
    for ip, cnt in src_counter.most_common(TOP_N):
        if _is_private_or_local(ip) or ip in LOCAL_IPS:
            continue  # skip local/internal IPs
        if cnt >= IP_HIT_THRESHOLD:
            conf = _score_confidence(cnt, total_entries)
            if conf < MIN_CONFIDENCE:
                continue
            rule = {
                "id": f"ai-{int(time.time())}-{abs(hash(ip)) % 100000}",
                "action": "block",
                "protocol": None,
                "src_ip": ip,
                "dst_ip": None,
                "dst_port": None,
                "comment": (
                    f"AI-suggested block: external source {ip} made {cnt} "
                    f"connections recently (auto-generated, review before enabling)."
                ),
                "confidence": round(conf, 3),
            }
            suggestions.append(rule)

    # ---------------------------------------------------------
    # Heuristic 2: High-volume Destination Ports
    # ---------------------------------------------------------
    for port, cnt in dst_port_counter.most_common(TOP_N):
        if cnt >= PORT_HIT_THRESHOLD:
            conf = _score_confidence(cnt, total_entries)
            if conf < MIN_CONFIDENCE:
                continue
            rule = {
                "id": f"ai-port-{int(time.time())}-{port}",
                "action": "block",
                "protocol": "TCP",
                "src_ip": None,
                "dst_ip": None,
                "dst_port": int(port),
                "comment": (
                    f"AI-suggested block: destination port {port} had {cnt} hits "
                    f"from many sources (auto-generated, review)."
                ),
                "confidence": round(conf, 3),
            }
            suggestions.append(rule)

    # ---------------------------------------------------------
    # Heuristic 3: Concentrated (src_ip, dst_port) pairs
    # ---------------------------------------------------------
    for (src, port), cnt in pair_counter.most_common(TOP_N):
        if _is_private_or_local(src) or src in LOCAL_IPS:
            continue
        if cnt >= PAIR_HIT_THRESHOLD:
            src_total = src_counter.get(src, 1)
            relative = cnt / src_total if src_total else 0.0
            conf_pair = _score_confidence(cnt, total_entries) * 0.7 + min(1.0, relative * 1.5) * 0.3
            if conf_pair < MIN_CONFIDENCE:
                continue
            rule = {
                "id": f"ai-pair-{int(time.time())}-{abs(hash((src, port))) % 100000}",
                "action": "block",
                "protocol": "TCP",
                "src_ip": src,
                "dst_ip": None,
                "dst_port": int(port),
                "comment": (
                    f"AI-suggested block: {src} → port {port} observed {cnt} times; "
                    f"high concentration detected (auto-generated, review)."
                ),
                "confidence": round(conf_pair, 3),
            }
            suggestions.append(rule)

    # ---------------------------------------------------------
    # Deduplicate and Persist
    # ---------------------------------------------------------
    unique = {}
    for s in suggestions:
        key = (s.get("src_ip"), s.get("dst_port"), s.get("action"))
        if key not in unique or s.get("confidence", 0) > unique[key].get("confidence", 0):
            unique[key] = s

    final = sorted(unique.values(), key=lambda x: x.get("confidence", 0), reverse=True)[:TOP_N]

    try:
        os.makedirs(os.path.dirname(SUGGESTION_PATH) or ".", exist_ok=True)
        with open(SUGGESTION_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(final, f, sort_keys=False)
    except Exception:
        pass

    return final


# ---------------------------------------------------------
# Safe Wrapper (used by daemon)
# ---------------------------------------------------------
def analyze_and_suggest_safe():
    try:
        return analyze_and_suggest()
    except Exception:
        return []
