"""
firewall_daemon.py
------------------
Windows Firewall Daemon using WinDivert + Named Pipe IPC.

Features:
 - Handles packets via WinDivert
 - Logs packets through firewall_core
 - Supports commands: status, reload, list, addrule, updaterule, delrule, profile, profile-reset, stop
 - Buffered logging for performance
 - Thread-safe and admin-safe execution
 - Continuous AI-based rule suggestion and integration
"""

import os
import sys
import json
import time
import threading
import traceback
from datetime import datetime, timezone
import ctypes

# win32 imports (used for Named Pipe IPC)
try:
    import win32pipe
    import win32file
    import pywintypes
except Exception as e:
    print("[!] win32 extensions not available. This daemon must run on Windows with pywin32 installed.")
    raise

import firewall_core
import yaml
import firewall_ai  # <-- ADDED: AI module integration

# ----------------------------
# Configuration
# ----------------------------
PIPE_NAME = r"\\.\pipe\cpff_firewall"
WIN_FILTER = "true"
STATS_INTERVAL = 1

# ADDED: AI configuration
AI_REFRESH_INTERVAL = 300  # seconds (10 minutes)
CONFIDENCE_THRESHOLD = 0.92  # only merge rules with confidence >= 0.92

stop_event = threading.Event()

stats = {
    "allowed": 0,
    "blocked": 0,
    "start_time": time.time(),
    "rules_count": 0,
}


# ----------------------------
# Admin Privilege Check
# ----------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


# ----------------------------
# Helper: safe YAML write for rules
# ----------------------------
def _write_rules_yaml(rules_list):
    """
    Convert in-memory rules to YAML-safe primitives using the core helper and write to disk.
    Returns True on success, False on failure.
    """
    try:
        safe_rules = firewall_core.serialize_rules_for_yaml(rules_list)
        with open(firewall_core.RULES_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(safe_rules, f, sort_keys=False)
        return True
    except Exception as e:
        print(f"[!] Failed to write rules.yaml: {e}")
        traceback.print_exc()
        return False


# ----------------------------
# ADDED: Continuous AI Rule Monitor with Logging
# ----------------------------
AI_LOG_PATH = os.path.join("logs", "ai_activity.log")


def _log_ai_event(message):
    """Append AI-related messages to ai_activity.log."""
    try:
        os.makedirs(os.path.dirname(AI_LOG_PATH), exist_ok=True)
        with open(AI_LOG_PATH, "a", encoding="utf-8") as f:
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            f.write(f"[{ts}] {message}\n")
    except Exception:
        print(f"[AI-LogError] Failed to write to {AI_LOG_PATH}")


def ai_rule_monitor():
    """Background AI process that continuously learns and suggests new rules."""
    print("[AI] Continuous AI rule analysis thread started.")
    _log_ai_event("AI rule monitor started.")
    while not stop_event.is_set():
        try:
            _log_ai_event("Starting new AI analysis cycle.")
            suggestions = firewall_ai.analyze_and_suggest()
            if suggestions:
                msg = f"{len(suggestions)} new rule suggestions detected. Merging high-confidence rules..."
                print(f"[AI] {msg}")
                _log_ai_event(msg)
                merge_ai_rules(suggestions)
            else:
                _log_ai_event("No new rule suggestions this cycle.")
        except Exception as e:
            print(f"[AI ERROR] {e}")
            _log_ai_event(f"[ERROR] AI analysis failed: {e}")

        # Sleep until next analysis cycle
        for _ in range(AI_REFRESH_INTERVAL):
            if stop_event.is_set():
                break
            time.sleep(1)

    print("[AI] AI rule monitor stopped.")
    _log_ai_event("AI rule monitor stopped.")


def merge_ai_rules(suggestions, main_rules_path=firewall_core.RULES_PATH):
    """
    Merge AI-suggested rules into main rules.yaml based on confidence >= threshold.
    Also removes merged rules from rules_suggestion.yaml.
    """
    if not suggestions:
        _log_ai_event("merge_ai_rules() called with empty suggestion list.")
        return

    SUGGESTION_PATH = "rules_suggestion.yaml"

    try:
        # Load current rules
        if os.path.exists(main_rules_path):
            with open(main_rules_path, "r", encoding="utf-8") as f:
                existing_rules = yaml.safe_load(f) or []
        else:
            existing_rules = []

        existing_ids = {str(r.get("id")) for r in existing_rules}
        merged_rules = []
        kept_suggestions = []

        for s in suggestions:
            rid = str(s.get("id"))
            conf = s.get("confidence", 0.0)

            # If already in main rules, skip
            if rid in existing_ids:
                kept_suggestions.append(s)
                continue

            if conf >= CONFIDENCE_THRESHOLD:
                s["enabled"] = True
                existing_rules.append(s)
                merged_rules.append(s)
            else:
                kept_suggestions.append(s)

        # Save updated main rules
        if merged_rules:
            with open(main_rules_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(existing_rules, f, sort_keys=False)
            msg = f"Merged {len(merged_rules)} new AI-generated rules into {main_rules_path}."
            print(f"[AI] {msg}")
            _log_ai_event(msg)
        else:
            msg = "No new unique AI rules to merge (all duplicates or low-confidence)."
            print(f"[AI] {msg}")
            _log_ai_event(msg)

        # Update suggestions file — keep only unmerged rules
        try:
            with open(SUGGESTION_PATH, "w", encoding="utf-8") as f:
                yaml.safe_dump(kept_suggestions, f, sort_keys=False)
            if merged_rules:
                _log_ai_event(f"Removed {len(merged_rules)} merged rules from {SUGGESTION_PATH}.")
        except Exception as e:
            _log_ai_event(f"[WARN] Failed to update {SUGGESTION_PATH}: {e}")

    except Exception as e:
        msg = f"[AI Merge Error] {e}"
        print(msg)
        _log_ai_event(msg)

# ----------------------------
# Named Pipe IPC Server
# ----------------------------
def ipc_server():
    """Threaded named pipe IPC server."""
    print(f"[*] Named Pipe IPC server listening on {PIPE_NAME}")
    while not stop_event.is_set():
        try:
            pipe = win32pipe.CreateNamedPipe(
                PIPE_NAME,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                1, 65536, 65536, 0, None,
            )

            # Wait for client to connect (blocking)
            win32pipe.ConnectNamedPipe(pipe, None)

            # Read request
            data = win32file.ReadFile(pipe, 65536)[1]
            try:
                payload = json.loads(data.decode("utf-8"))
            except Exception:
                payload = {}

            response = handle_command(payload)

            # Write response
            try:
                win32file.WriteFile(pipe, json.dumps(response).encode("utf-8"))
            except Exception as e:
                print(f"[IPC Write Error] {e}")

            try:
                win32file.CloseHandle(pipe)
            except Exception:
                pass

        except pywintypes.error as e:
            # Common pipe errors
            if e.winerror == 109:  # Broken pipe
                continue
            elif e.winerror == 2:
                # ERROR_FILE_NOT_FOUND: rare, sleep a bit
                time.sleep(0.3)
            else:
                print(f"[IPC Error] {e}")
                time.sleep(0.2)
        except Exception as e:
            print(f"[IPC Exception] {e}")
            traceback.print_exc()
            time.sleep(0.5)
    print("[*] IPC server stopped")


# ----------------------------
# Command Handling
# ----------------------------
def handle_command(payload):
    """Handles JSON IPC commands sent from client."""
    cmd = payload.get("cmd")

    # ---------------- status ----------------
    if cmd == "status":
        uptime = int(time.time() - stats["start_time"])
        # include top rules snapshot (top 5)
        try:
            top_rules = firewall_core.get_top_rules(5)
        except Exception:
            top_rules = []
        return {
            "status": "ok",
            "uptime": uptime,
            "rules_loaded": stats["rules_count"],
            "allowed_packets": stats["allowed"],
            "blocked_packets": stats["blocked"],
            "top_rules": top_rules,
        }

    # ---------------- reload ----------------
    elif cmd == "reload":
        stats["rules_count"] = firewall_core.load_rules()
        return {"status": "ok", "message": f"Reloaded {stats['rules_count']} rules"}

    # ---------------- list ----------------
    elif cmd == "list":
        try:
            rules = firewall_core.get_rules()
            hits = {}
            try:
                hits = firewall_core.get_rule_hits()
            except Exception:
                hits = {}

            safe_rules = []
            for r in rules:
                cleaned = {}
                for k, v in r.items():
                    # Skip internal derived fields
                    if k.startswith("_") or k.endswith("_net"):
                        continue
                    # Convert network objects to strings
                    if hasattr(v, "exploded"):
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
                cleaned["hits"] = int(hits.get(r.get("id"), 0))
                safe_rules.append(cleaned)
            return {"status": "ok", "rules": safe_rules}
        except Exception as e:
            return {"status": "error", "message": f"Failed to list rules: {e}"}

    # ---------------- addrule ----------------
    elif cmd == "addrule":
        try:
            # Build new rule (user-level fields only)
            new_rule = {
                "id": int(time.time()),  # simple but reasonably-unique id
                "action": payload.get("action", "allow"),
                "protocol": payload.get("protocol"),
                "src_ip": payload.get("src_ip"),
                "dst_ip": payload.get("dst_ip"),
                "dst_port": payload.get("dst_port"),
                "geoip_country": payload.get("geoip_country"),
                "comment": payload.get("comment"),
            }

            # Normalize dst_port if comma-separated string provided
            dp = new_rule.get("dst_port")
            if isinstance(dp, str) and "," in dp:
                try:
                    new_rule["dst_port"] = [int(x.strip()) for x in dp.split(",") if x.strip()]
                except Exception:
                    pass

            # Rate limit parsing
            rl = payload.get("rate_limit")
            if rl and isinstance(rl, str) and "/" in rl:
                t, w = rl.split("/")
                new_rule["rate_limit"] = {"threshold": int(t), "window_seconds": int(w)}
            elif isinstance(rl, dict):
                new_rule["rate_limit"] = rl

            # Append and persist — load current memory copy and write YAML via core serializer
            rules = firewall_core.get_rules()
            rules.append(new_rule)

            ok = _write_rules_yaml(rules)
            if not ok:
                return {"status": "error", "message": "Failed to persist new rule to rules.yaml"}

            stats["rules_count"] = firewall_core.load_rules()
            return {"status": "ok", "rule_id": new_rule["id"], "rule": new_rule}

        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------------- delrule ----------------
    elif cmd == "delrule":
        try:
            rule_id = payload.get("id")
            if rule_id is None:
                return {"status": "error", "message": "Missing rule ID"}

            rules = firewall_core.get_rules()
            new_rules = [r for r in rules if str(r.get("id")) != str(rule_id)]
            if len(new_rules) == len(rules):
                return {"status": "error", "message": f"No rule found with ID {rule_id}"}

            ok = _write_rules_yaml(new_rules)
            if not ok:
                return {"status": "error", "message": "Failed to persist rules after deletion"}

            stats["rules_count"] = firewall_core.load_rules()
            return {"status": "ok", "message": f"Deleted rule ID {rule_id}"}

        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------------- updaterule ----------------
    elif cmd == "updaterule":
        try:
            rule_id = payload.get("id")
            if rule_id is None:
                return {"status": "error", "message": "Missing rule ID"}

            rules = firewall_core.get_rules()
            found = False
            for r in rules:
                if str(r.get("id")) == str(rule_id):
                    # update provided fields only
                    for key in ["action", "protocol", "src_ip", "dst_ip", "dst_port", "geoip_country", "comment", "rate_limit", "priority", "enabled", "log"]:
                        if key in payload and payload[key] is not None:
                            r[key] = payload[key]
                    found = True
                    break

            if not found:
                # if client asked to add if missing, create it
                if payload.get("add_if_missing"):
                    new_rule = {
                        "id": int(rule_id) if isinstance(rule_id, int) or (isinstance(rule_id, str) and rule_id.isdigit()) else int(time.time()),
                        "action": payload.get("action", "allow"),
                        "protocol": payload.get("protocol"),
                        "src_ip": payload.get("src_ip"),
                        "dst_ip": payload.get("dst_ip"),
                        "dst_port": payload.get("dst_port"),
                        "geoip_country": payload.get("geoip_country"),
                        "comment": payload.get("comment"),
                    }
                    rl = payload.get("rate_limit")
                    if rl and isinstance(rl, str) and "/" in rl:
                        t, w = rl.split("/")
                        new_rule["rate_limit"] = {"threshold": int(t), "window_seconds": int(w)}
                    rules.append(new_rule)
                else:
                    return {"status": "not_found", "message": f"No rule found with ID {rule_id}.", "suggestion": "Use add_if_missing to create one instead."}

            ok = _write_rules_yaml(rules)
            if not ok:
                return {"status": "error", "message": "Failed to persist updated rules"}

            stats["rules_count"] = firewall_core.load_rules()
            return {"status": "ok", "message": f"Updated rule ID {rule_id}"}

        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------------- profile: top-N ----------------
    elif cmd == "profile":
        try:
            n = int(payload.get("n", 10))
            top_rules = firewall_core.get_top_rules(n)
            return {"status": "ok", "top_rules": top_rules}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------------- profile-reset ----------------
    elif cmd == "profile-reset":
        try:
            firewall_core.reset_rule_hits()
            return {"status": "ok", "message": "Rule hit counters reset."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ---------------- stop ----------------
    elif cmd == "stop":
        try:
            print("[!] Stop command received via client — shutting down firewall daemon...")
            stop_event.set()

            # Attempt graceful shutdown of core subsystems
            try:
                firewall_core.stop_logger()
            except Exception as e:
                print(f"[!] Logger flush error during stop: {e}")

            try:
                firewall_core.stop_profiler()
            except Exception:
                pass

            try:
                firewall_core.stop_bucket_cleaner()
            except Exception:
                pass

            uptime = int(time.time() - stats["start_time"])
            msg = (
                f"Firewall daemon stopped gracefully. "
                f"Uptime: {uptime}s | Allowed: {stats['allowed']} | Blocked: {stats['blocked']}"
            )
            print("[✓] " + msg)
            return {"status": "ok", "message": msg}

        except Exception as e:
            return {"status": "error", "message": f"Failed to stop daemon: {e}"}

    else:
        return {"status": "error", "message": f"Unknown command: {cmd}"}


# ----------------------------
# Firewall Packet Loop
# ----------------------------
def firewall_loop():
    """WinDivert packet processing loop with async logging."""
    try:
        import pydivert
    except Exception as e:
        print("[!] pydivert not available. WinDivert-based loop cannot run.")
        print(e)
        return

    stats["rules_count"] = firewall_core.load_rules()
    print(f"[+] Loaded {stats['rules_count']} rules.")

    last_stats_time = time.time()

    try:
        with pydivert.WinDivert(WIN_FILTER) as w:
            print("[+] WinDivert handle opened.")
            while not stop_event.is_set():
                try:
                    packet = w.recv()
                    # match_rule expects a packet-like object; pydivert Packet works with the helper in core
                    rule = firewall_core.match_rule(packet)

                    entry = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "src_ip": getattr(packet, "src_addr", None),
                        "dst_ip": getattr(packet, "dst_addr", None),
                        "src_port": getattr(packet, "src_port", None),
                        "dst_port": getattr(packet, "dst_port", None),
                        "protocol": firewall_core.get_protocol_name(packet),
                    }

                    # Default action
                    action = "allow"

                    if rule:
                        action = rule.get("action", "allow").lower()
                        # Include metadata from rule
                        if "_match_metadata" in rule:
                            entry.update(rule["_match_metadata"])

                    # Assign action + log
                    entry["action"] = action.upper()

                    try:
                        firewall_core.log_packet(entry)
                    except Exception as e:
                        print(f"[Packet Error] {e}")

                    # Handle block / allow
                    if action == "block":
                        stats["blocked"] += 1
                        continue  # Drop packet
                    else:
                        stats["allowed"] += 1
                        w.send(packet)

                    entry["action"] = action.upper()

                    # Respect per-rule logging toggle (if rule present and has log=False, skip)
                    if rule and rule.get("log") is False:
                        pass  # do not log packet
                    else:
                        firewall_core.log_packet(entry)

                    if action == "block":
                        stats["blocked"] += 1
                        # drop packet by not calling w.send(packet)
                        continue
                    else:
                        stats["allowed"] += 1
                        w.send(packet)

                except Exception:
                    # ignore per-packet errors to keep loop running
                    continue

                # Combined stats to stdout every STATS_INTERVAL seconds
                if time.time() - last_stats_time >= STATS_INTERVAL:
                    uptime = int(time.time() - stats["start_time"])
                    print(
                        f"[Stats] Allowed: {stats['allowed']} | Blocked: {stats['blocked']} | "
                        f"Uptime: {uptime//60}m{uptime%60:02d}s | Rules: {stats['rules_count']}"
                    )
                    last_stats_time = time.time()
    except Exception as e:
        print(f"[!] WinDivert error: {e}")
        traceback.print_exc()
    finally:
        print("[*] Firewall loop stopped.")


# ----------------------------
# Main Entrypoint
# ----------------------------
def main():
    print("Make sure you run this script as Administrator.")
    if not is_admin():
        print("[!] Administrator privileges required.")
        sys.exit(1)

    print("[*] Initializing firewall daemon...")
    firewall_core.validate_geoip()

    stats["rules_count"] = firewall_core.load_rules()
    print(f"[+] Loaded {stats['rules_count']} rules.")

    # Start IPC + Firewall + AI threads
    ipc_thread = threading.Thread(target=ipc_server, daemon=True)
    fw_thread = threading.Thread(target=firewall_loop, daemon=True)
    ai_thread = threading.Thread(target=ai_rule_monitor, daemon=True)  # ADDED: AI thread

    ipc_thread.start()
    fw_thread.start()
    ai_thread.start()

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping firewall (user requested).")
        stop_event.set()

    print("[*] Waiting for threads to exit...")
    try:
        if "fw_thread" in locals() and fw_thread.is_alive():
            fw_thread.join(timeout=2)
        if "ipc_thread" in locals() and ipc_thread.is_alive():
            ipc_thread.join(timeout=2)
        if "ai_thread" in locals() and ai_thread.is_alive():
            ai_thread.join(timeout=2)
    except KeyboardInterrupt:
        print("[!] Forced shutdown during thread join (Ctrl+C pressed again).")
    except Exception as e:
        print(f"[!] Error during thread cleanup: {e}")
    finally:
        # Final core shutdown calls (best-effort)
        try:
            firewall_core.stop_logger()
        except Exception as e:
            print(f"[!] Logger flush error: {e}")
        try:
            firewall_core.stop_profiler()
        except Exception:
            pass
        try:
            firewall_core.stop_bucket_cleaner()
        except Exception:
            pass

        uptime = int(time.time() - stats["start_time"])
        print(
            f"[*] Firewall daemon stopped. Uptime: {uptime}s | "
            f"Allowed: {stats['allowed']} | Blocked: {stats['blocked']}"
        )


if __name__ == "__main__":
    main()
