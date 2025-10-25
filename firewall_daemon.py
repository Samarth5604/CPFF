"""
firewall_daemon.py
------------------
Windows Packet-Filtering Firewall Daemon with Linger Fix (for reliable IPC).

Features:
 - Handles live packet filtering via WinDivert
 - IPC interface (status/reload/shutdown) using JSON-over-TCP
 - Proper socket flush and linger handling (prevents client timeouts)
 - Periodic firewall stats (allowed/blocked packets)
 - Compatible with firewall_core.py
"""

import threading
import time
import socket
import json
import argparse
import traceback
import struct

from firewall_core import load_rules, match_rule, log_packet, validate_geoip

try:
    import pydivert
except Exception:
    pydivert = None


IPC_HOST = "127.0.0.1"
IPC_PORT = 9999
IPC_TIMEOUT = 3.0


# -----------------------------
# IPC SERVER
# -----------------------------
def ipc_server(stats, stop_event, debug=False):
    """TCP JSON command server that listens for CLI client commands."""
    print(f"[*] IPC server listening on {IPC_HOST}:{IPC_PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((IPC_HOST, IPC_PORT))
    s.listen(5)
    s.settimeout(1.0)

    while not stop_event.is_set():
        try:
            conn, addr = s.accept()
            if debug:
                print(f"[IPC DEBUG] Connection accepted from {addr}")
            conn.settimeout(IPC_TIMEOUT)
            data_chunks = []
            start = time.time()

            while True:
                try:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data_chunks.append(chunk)
                    if debug:
                        print(f"[IPC DEBUG] recv chunk ({len(chunk)}): {chunk!r}")
                    if b"\n" in chunk:
                        break
                except socket.timeout:
                    if debug:
                        print("[IPC DEBUG] recv timeout")
                    break
                if time.time() - start > 5:
                    break

            raw = b"".join(data_chunks).strip()
            if not raw:
                conn.close()
                continue

            try:
                req = json.loads(raw.decode("utf-8"))
                if debug:
                    print(f"[IPC DEBUG] Parsed JSON: {req}")
            except Exception as e:
                resp = {"error": f"Invalid JSON: {e}"}
            else:
                cmd = req.get("cmd", "").lower()
                if cmd == "ping":
                    resp = {"status": "alive", "message": "daemon is running"}
                elif cmd == "status":
                    resp = {
                        "status": "ok",
                        "uptime": round(time.time() - stats["start_time"], 2),
                        "rules_loaded": stats["rules_count"],
                        "allowed_packets": stats["allowed"],
                        "blocked_packets": stats["blocked"],
                }


                elif cmd == "reload":
                    count = load_rules()
                    stats["rules_count"] = count
                    resp = {"status": "ok", "message": f"Reloaded {count} rules."}
                elif cmd == "shutdown":
                    stop_event.set()
                    resp = {"status": "shutting_down"}
                else:
                    resp = {"error": f"Unknown command: {cmd}"}

            # --- Send response safely with linger and flush ---
            msg = json.dumps(resp) + "\n"
            try:
                if debug:
                    print(f"[IPC DEBUG] Sending response bytes: {msg.encode('utf-8')!r}")
                conn.sendall(msg.encode("utf-8"))
                conn.shutdown(socket.SHUT_WR)  # signal end of transmission
                time.sleep(0.1)  # ensure full flush before close


                if debug:
                    print("[IPC DEBUG] Response sent and flushed successfully")
            except Exception as e:
                if debug:
                    print("[IPC DEBUG] sendall exception:", e)
                    traceback.print_exc()
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        except socket.timeout:
            continue
        except Exception as e:
            if debug:
                print("[IPC DEBUG] accept loop exception:", repr(e))
                traceback.print_exc()
            time.sleep(0.2)

    s.close()
    print("[*] IPC server stopped")


# -----------------------------
# IPC SELF-TEST
# -----------------------------
def ipc_self_test(debug=False, timeout=2.0):
    """Checks if IPC server is reachable."""
    time.sleep(0.3)
    try:
        if debug:
            print("[IPC SELF-TEST] Attempting connection")
        with socket.create_connection((IPC_HOST, IPC_PORT), timeout=timeout) as sock:
            payload = json.dumps({"cmd": "status"}) + "\n"
            if debug:
                print(f"[IPC SELF-TEST DEBUG] Sending: {payload!r}")
            sock.sendall(payload.encode("utf-8"))
            sock.settimeout(timeout)
            data = b""
            start = time.time()

            while True:
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if b"\n" in chunk:
                        break
                except socket.timeout:
                    if time.time() - start > timeout:
                        break
                    continue

            if not data:
                print("[✗] IPC self-test failed: no data")
                return False

            try:
                resp = json.loads(data.decode("utf-8").strip())
                if "status" in resp:
                    print("[✓] IPC self-test successful!")
                    return True
                else:
                    print("[✗] Invalid response:", resp)
                    return False
            except Exception as e:
                print("[✗] IPC self-test JSON error:", e)
                return False

    except Exception as e:
        if debug:
            print("[IPC SELF-TEST DEBUG] Exception:", e)
        print("[✗] IPC self-test failed:", e)
        return False


# -----------------------------
# FIREWALL LOOP
# -----------------------------
def firewall_loop(stats, stop_event, debug=False):
    """Main packet filter loop."""
    if pydivert is None:
        print("[!] pydivert not available — skipping firewall loop.")
        return

    print("[*] Starting firewall loop...")
    FILTER = "true"

    while not stop_event.is_set():
        try:
            with pydivert.WinDivert(FILTER) as w:
                if debug:
                    print("[DEBUG] WinDivert handle opened.")
                while not stop_event.is_set():
                    try:
                        packet = w.recv()
                        rule = match_rule(packet)
                        if rule and rule.get("action") == "block":
                            stats["blocked"] += 1
                            log_packet({
                                "timestamp": time.time(),
                                "action": "BLOCK",
                                "src": getattr(packet, "src_addr", None),
                                "dst": getattr(packet, "dst_addr", None),
                                "proto": getattr(packet, "protocol", None)
                            })
                        else:
                            stats["allowed"] += 1
                            w.send(packet)
                    except Exception as e:
                        if getattr(e, "winerror", None) == 183:
                            if debug:
                                print("[DEBUG] WinDivert runtime collision (183)")
                            continue
                        if debug:
                            print("[Packet DEBUG] Exception:", repr(e))
                        continue
        except Exception as e:
            if getattr(e, "winerror", None) == 183:
                print("[!] WinDivert collision — retrying...")
                time.sleep(0.5)
                continue
            else:
                print("[!] Firewall loop error:", e)
                if debug:
                    traceback.print_exc()
                time.sleep(0.5)
                continue

    print("[*] Firewall loop stopped.")


# -----------------------------
# STATS PRINTER
# -----------------------------
def stats_printer(stats, stop_event):
    while not stop_event.is_set():
        time.sleep(5)
        uptime = int(time.time() - stats["start_time"])
        print(f"[Stats] Allowed: {stats['allowed']} | Blocked: {stats['blocked']} | Uptime: {uptime//60}m{uptime%60:02d}s")


# -----------------------------
# MAIN
# -----------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Enable debug logs")
    args = parser.parse_args()
    debug = args.debug

    print("Make sure you run this script as Administrator.")
    print("[*] Initializing firewall daemon...")

    if validate_geoip():
        print("[+] GeoIP test passed.")
    else:
        print("[!] GeoIP not available or DB missing (continuing)")

    rules_count = load_rules()
    print(f"[+] Loaded {rules_count} rules.")

    stats = {
        "start_time": time.time(),
        "rules_count": rules_count,
        "allowed": 0,
        "blocked": 0,
    }
    stop_event = threading.Event()

    # Start IPC server thread
    ipc_thread = threading.Thread(target=ipc_server, args=(stats, stop_event, debug), daemon=True)
    ipc_thread.start()

    # Self-test IPC
    ipc_self_test(debug=debug)

    # Stats printer thread
    printer_thread = threading.Thread(target=stats_printer, args=(stats, stop_event), daemon=True)
    printer_thread.start()

    # Firewall loop thread
    fw_thread = threading.Thread(target=firewall_loop, args=(stats, stop_event, debug), daemon=True)
    fw_thread.start()

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping firewall (user requested).")
        stop_event.set()

    print("[*] Stopping threads...")

# Graceful join with fallback
    try:
        fw_thread.join(timeout=5.0)
    except Exception as e:
        print(f"[!] Warning: Firewall thread shutdown delay ({e})")

    if fw_thread.is_alive():
        print("[!] Firewall thread still cleaning up (WinDivert handle). Waiting briefly...")
        time.sleep(1.5)

    print("[*] Firewall daemon stopped cleanly.")
    uptime = int(time.time() - stats["start_time"])
    print(f"[*] Uptime: {uptime}s | Allowed: {stats['allowed']} | Blocked: {stats['blocked']}")



if __name__ == "__main__":
    main()
