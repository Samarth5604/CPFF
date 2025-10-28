"""
firewall_daemon.py
------------------
Windows Firewall Daemon using WinDivert + Named Pipe IPC.

Features:
 - Handles packets via WinDivert
 - Logs packets through firewall_core
 - Supports commands: status, reload, list, addrule
 - Buffered logging for performance
 - Thread-safe and admin-safe execution
"""

import os
import sys
import json
import time
import threading
import traceback
import win32pipe, win32file, pywintypes
from datetime import datetime, timezone
import ctypes

import firewall_core

# ----------------------------
# Configuration
# ----------------------------
PIPE_NAME = r"\\.\pipe\cpff_firewall"
WIN_FILTER = "true"
STATS_INTERVAL = 5

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
    except:
        return False


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

            win32pipe.ConnectNamedPipe(pipe, None)
            data = win32file.ReadFile(pipe, 65536)[1]
            payload = json.loads(data.decode("utf-8"))

            response = handle_command(payload)
            win32file.WriteFile(pipe, json.dumps(response).encode("utf-8"))

            win32file.CloseHandle(pipe)

        except pywintypes.error as e:
            if e.winerror == 109:  # Broken pipe
                continue
            elif e.winerror == 2:
                time.sleep(0.3)
            else:
                print(f"[IPC Error] {e}")
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

    if cmd == "status":
        uptime = int(time.time() - stats["start_time"])
        return {
            "status": "ok",
            "uptime": uptime,
            "rules_loaded": stats["rules_count"],
            "allowed_packets": stats["allowed"],
            "blocked_packets": stats["blocked"],
        }

    elif cmd == "reload":
        stats["rules_count"] = firewall_core.load_rules()
        return {"status": "ok", "message": f"Reloaded {stats['rules_count']} rules"}

    elif cmd == "list":
        rules = firewall_core.get_rules()
        safe_rules = []
        for r in rules:
            cleaned = {}
            for k, v in r.items():
                # Convert complex objects to JSON-safe types
                if hasattr(v, "exploded"):  # IPv4Network/IPv6Network
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
            safe_rules.append(cleaned)
        return {"status": "ok", "rules": safe_rules}

    elif cmd == "addrule":
        # Basic rule construction
        try:
            new_rule = {
                "id": int(time.time()),  # simple unique id
                "action": payload.get("action", "allow"),
                "protocol": payload.get("protocol"),
                "src_ip": payload.get("src_ip"),
                "dst_ip": payload.get("dst_ip"),
                "dst_port": payload.get("dst_port"),
                "geoip_country": payload.get("geoip_country"),
                "comment": payload.get("comment"),
            }

            # Handle rate limit "100/10" format
            rl = payload.get("rate_limit")
            if rl and "/" in rl:
                t, w = rl.split("/")
                new_rule["rate_limit"] = {"threshold": int(t), "window_seconds": int(w)}

            # Append and persist
            rules = firewall_core.get_rules()
            rules.append(new_rule)

            # Write back to YAML
            import yaml
            with open(firewall_core.RULES_PATH, "w", encoding="utf-8") as f:
                yaml.safe_dump(rules, f)

            # Reload into memory
            stats["rules_count"] = firewall_core.load_rules()

            return {"status": "ok", "rule_id": new_rule["id"], "rule": new_rule}

        except Exception as e:
            return {"status": "error", "message": str(e)}

    else:
        return {"status": "error", "message": f"Unknown command: {cmd}"}


# ----------------------------
# Firewall Packet Loop
# ----------------------------
def firewall_loop():
    """WinDivert packet processing loop with async logging."""
    import pydivert

    stats["rules_count"] = firewall_core.load_rules()
    print(f"[+] Loaded {stats['rules_count']} rules.")

    last_stats_time = time.time()

    try:
        with pydivert.WinDivert(WIN_FILTER) as w:
            print("[+] WinDivert handle opened.")
            while not stop_event.is_set():
                try:
                    packet = w.recv()
                    rule = firewall_core.match_rule(packet)
                    entry = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "src_ip": getattr(packet, "src_addr", None),
                        "dst_ip": getattr(packet, "dst_addr", None),
                        "src_port": getattr(packet, "src_port", None),
                        "dst_port": getattr(packet, "dst_port", None),
                        "protocol": firewall_core.get_protocol_name(packet),
                    }

                    action = "allow"
                    if rule:
                        action = rule.get("action", "allow").lower()

                    entry["action"] = action.upper()
                    firewall_core.log_packet(entry)

                    if action == "block":
                        stats["blocked"] += 1
                        continue
                    else:
                        stats["allowed"] += 1
                        w.send(packet)

                except Exception:
                    continue

                # Combined log every 5s
                if time.time() - last_stats_time >= STATS_INTERVAL:
                    uptime = int(time.time() - stats["start_time"])
                    print(
                        f"[Stats] Allowed: {stats['allowed']} | Blocked: {stats['blocked']} | "
                        f"Uptime: {uptime//60}m{uptime%60:02d}s | Rules: {stats['rules_count']}"
                    )
                    last_stats_time = time.time()
    except Exception as e:
        print(f"[!] WinDivert error: {e}")
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

    # Start IPC + Firewall threads
    ipc_thread = threading.Thread(target=ipc_server, daemon=True)
    fw_thread = threading.Thread(target=firewall_loop, daemon=True)
    ipc_thread.start()
    fw_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping firewall (user requested).")
        stop_event.set()

    print("[*] Waiting for threads to exit...")
        # --- Graceful shutdown and cleanup ---
    print("[!] Stopping firewall (user requested).")
    stop_event.set()

    print("[*] Waiting for threads to exit...")
    try:
        if "fw_thread" in locals() and fw_thread.is_alive():
            fw_thread.join(timeout=2)
        if "ipc_thread" in locals() and ipc_thread.is_alive():
            ipc_thread.join(timeout=2)
    except KeyboardInterrupt:
        print("[!] Forced shutdown during thread join (Ctrl+C pressed again).")
    except Exception as e:
        print(f"[!] Error during thread cleanup: {e}")
    finally:
        try:
            firewall_core.stop_logger()
            print("[✓] Logger stopped and flushed.")
        except Exception as e:
            print(f"[!] Logger flush error: {e}")

        uptime = int(time.time() - stats["start_time"])
        print(
            f"[*] Firewall daemon stopped. Uptime: {uptime}s | "
            f"Allowed: {stats['allowed']} | Blocked: {stats['blocked']}"
        )

if __name__ == "__main__":
    main()
