"""
firewall_ai.py

Simple rule-suggestion "AI" for CPFF:
 - Reads JSONL logs produced by firewall_core (ALL_DIR)
 - Finds frequent IPs / ports / ip-port pairs
 - Produces suggestions in the same rule format used by rules.yaml
 - Writes suggestions to rules_suggestion.yaml
 - Exposes analyze_and_suggest() for the daemon to call
"""

import os
import time 
import json
import yaml
from collections import Counter, defaultdict
from datetime import datetime
import math
import firewall_core

# Configurable thresholds (tweak for your environment)
LOG_LOOKBACK_SECONDS = 60 * 60 * 6   # look back 6 hours by default
MAX_LINES_READ = 20000               # safety cap to avoid huge scans
IP_HIT_THRESHOLD = 150               # suggest blocking IPs with >= this hits in lookback
PORT_HIT_THRESHOLD = 500             # suggest blocking dst_port if many hits across srcs
PAIR_HIT_THRESHOLD = 60              # suggest blocking specific (src, dst_port) pairs with >= this hits
MIN_CONFIDENCE = 0.2                 # min computed confidence to include suggestion
SUGGESTION_PATH = "rules_suggestion.yaml"
TOP_N = 50                           # maximum number of suggestions to return

def _iter_log_lines():
    """
    Yield parsed JSON entries from the most recent firewall_all_*.jsonl files.
    Reads newest files first and stops when MAX_LINES_READ or LOG_LOOKBACK_SECONDS reached.
    """
    all_dir = getattr(firewall_core, "ALL_DIR", "logs/all_packets")
    if not os.path.isdir(all_dir):
        return

    files = sorted(
        [os.path.join(all_dir, f) for f in os.listdir(all_dir) if f.startswith("firewall_all_") and f.endswith(".jsonl")],
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

                    # If there's a timestamp in the entry attempt to filter by lookback
                    ts = None
                    for k in ("timestamp", "time", "ts"):
                        if k in obj:
                            try:
                                # tolerant parse: expect ISO
                                ts = datetime.fromisoformat(obj[k])
                                ts = ts.timestamp()
                            except Exception:
                                ts = None
                            break

                    if ts and (now_ts - ts) > LOG_LOOKBACK_SECONDS:
                        # since files are newest-first, if this file's line is too old,
                        # continue to next line but do not break (there may be newer entries in same file).
                        continue

                    yield obj
                    lines_read += 1
                    if lines_read >= MAX_LINES_READ:
                        return
        except Exception:
            continue


def _score_confidence(count, total_count):
    """
    Compute a simple confidence metric from counts.
    Returns a float between 0 and 1.
    Formula: sigmoid-like scaling with diminishing returns.
    """
    if total_count <= 0:
        return 0.0
    ratio = count / total_count
    # map ratio to [0,1] with a curve
    val = 1 - math.exp(-5 * ratio)  # steeper curve
    # scale by log of count to prefer absolute volume too
    vol_factor = min(1.0, math.log1p(count) / 6.0)
    conf = val * 0.7 + vol_factor * 0.3
    return max(0.0, min(1.0, conf))


def analyze_and_suggest():
    """
    Main entry: analyze recent logs and return a list of rule suggestion dicts.

    Each suggestion is a dict in the same user-facing rule format:
      id, action, protocol, src_ip, dst_ip, dst_port, comment, confidence

    Returns an empty list if no meaningful suggestions.
    """
    # Counters
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
        # normalize types
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

    # Heuristic 1: block top aggressive source IPs by volume
    for ip, cnt in src_counter.most_common(TOP_N):
        if cnt >= IP_HIT_THRESHOLD:
            conf = _score_confidence(cnt, total_entries)
            if conf < MIN_CONFIDENCE:
                continue
            rule = {
                "id": f"ai-{int(time.time())}-{abs(hash(ip))%100000}",
                "action": "block",
                "protocol": None,
                "src_ip": ip,
                "dst_ip": None,
                "dst_port": None,
                "comment": f"AI-suggested block: source {ip} generated {cnt} connections in recent logs; likely abusive. (auto-generated, review before enabling)",
                "confidence": round(conf, 3),
            }
            suggestions.append(rule)

    # Heuristic 2: block dst_ports with very high total hits (many sources hitting same port)
    for port, cnt in dst_port_counter.most_common(TOP_N):
        if cnt >= PORT_HIT_THRESHOLD:
            conf = _score_confidence(cnt, total_entries)
            if conf < MIN_CONFIDENCE:
                continue
            rule = {
                "id": f"ai-port-{int(time.time())}-{port}",
                "action": "block",
                "protocol": "TCP",  # assume TCP for common ports
                "src_ip": None,
                "dst_ip": None,
                "dst_port": int(port),
                "comment": f"AI-suggested block: destination port {port} received {cnt} hits from many sources; consider blocking or rate-limiting. (auto-generated, review before enabling)",
                "confidence": round(conf, 3),
            }
            suggestions.append(rule)

    # Heuristic 3: block frequent (src, dst_port) pairs that are unusually concentrated
    for (src, port), cnt in pair_counter.most_common(TOP_N):
        if cnt >= PAIR_HIT_THRESHOLD:
            # relative confidence: fraction of this pair among that src's hits
            src_total = src_counter.get(src, 1)
            relative = cnt / src_total if src_total else 0.0
            conf_pair = _score_confidence(cnt, total_entries) * 0.7 + min(1.0, relative * 1.5) * 0.3
            if conf_pair < MIN_CONFIDENCE:
                continue
            rule = {
                "id": f"ai-pair-{int(time.time())}-{abs(hash((src, port)))%100000}",
                "action": "block",
                "protocol": "TCP",
                "src_ip": src,
                "dst_ip": None,
                "dst_port": int(port),
                "comment": f"AI-suggested block: {src} -> port {port} observed {cnt} times (concentrated traffic). (auto-generated, review)",
                "confidence": round(conf_pair, 3),
            }
            suggestions.append(rule)

    # dedupe by (src_ip, dst_port, action)
    unique = {}
    for s in suggestions:
        key = (s.get("src_ip"), s.get("dst_port"), s.get("action"))
        # keep highest confidence
        if key not in unique or s.get("confidence", 0) > unique[key].get("confidence", 0):
            unique[key] = s

    final = sorted(unique.values(), key=lambda x: x.get("confidence", 0), reverse=True)[:TOP_N]

    # Persist suggestions to YAML for review
    try:
        os.makedirs(os.path.dirname(SUGGESTION_PATH) or ".", exist_ok=True)
        with open(SUGGESTION_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(final, f, sort_keys=False)
    except Exception:
        pass

    return final


# convenience wrapper used by daemon if it wants a simple list
def analyze_and_suggest_safe():
    try:
        return analyze_and_suggest()
    except Exception:
        return []
