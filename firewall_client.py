"""
firewall_client.py
------------------
Command-line interface for CPFF Firewall Daemon.

Stage 4 (Profiling Integration + Full Command Set)
 - start / stop / restart lifecycle commands
 - monitor with crash detection and optional auto-restart
 - health check (with psutil fallback)
 - all rule management: addrule, delrule, updaterule
 - profiling support (profile, profile-reset, top rules in status)
"""

import os
import sys
import json
import time
import argparse
import subprocess
import win32pipe, win32file, pywintypes
from datetime import datetime

PIPE_NAME = r"\\.\pipe\cpff_firewall"

# optional psutil for process inspection (CPU / memory)
try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    PSUTIL_AVAILABLE = False


# =====================================================
# Utility helpers
# =====================================================
def send_command(payload, timeout=5):
    """Send JSON command to the daemon via named pipe. Returns parsed JSON or None."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            handle = win32file.CreateFile(
                PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None,
                win32file.OPEN_EXISTING,
                0, None
            )
            win32file.WriteFile(handle, json.dumps(payload).encode("utf-8"))
            result = win32file.ReadFile(handle, 65536)[1]
            win32file.CloseHandle(handle)
            return json.loads(result.decode("utf-8"))
        except pywintypes.error as e:
            if e.winerror == 2:
                return None
            time.sleep(0.25)
        except Exception as e:
            print(f"[!] IPC Error: {e}")
            return None
    return None


def find_daemon_process():
    """Try to find the firewall daemon process using psutil."""
    if not PSUTIL_AVAILABLE:
        return None
    for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            cmdline = p.info.get("cmdline") or []
            if any("firewall_daemon.py" in str(x) for x in cmdline):
                return p
        except Exception:
            continue
    return None


def human_bytes(n):
    """Simple human readable bytes"""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(n) < 1024.0:
            return f"{n:3.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


# =====================================================
# Core CLI behaviors
# =====================================================
def cmd_status():
    resp = send_command({"cmd": "status"})
    if not resp:
        print("[!] Firewall daemon not running or not responding.")
        return
    if resp.get("status") != "ok":
        print("[!] Daemon error:", resp.get("message"))
        return

    print("\n🔥 CPFF Firewall Status 🔥")
    print(f"  Uptime         : {resp['uptime']}s")
    print(f"  Rules Loaded   : {resp['rules_loaded']}")
    print(f"  Allowed Packets: {resp['allowed_packets']}")
    print(f"  Blocked Packets: {resp['blocked_packets']}")

    # ---- Show top rules from profiling ----
    top_rules = resp.get("top_rules", [])
    if top_rules:
        print("\n📊 Top Rule Hits (from profiler):")
        print("===================================================")
        for r in top_rules:
            print(f"Rule {r['id']:>3} | {r['action'].upper():<6} | Hits={r['hits']:<6} | {r['comment']}")
        print("===================================================")
    print()


def cmd_reload():
    resp = send_command({"cmd": "reload"})
    if resp and resp.get("status") == "ok":
        print("[✓] Rules reloaded successfully.")
    else:
        print("[!] Failed to reload rules.")


def cmd_list():
    resp = send_command({"cmd": "list"})
    if not resp or resp.get("status") != "ok":
        print("[!] Failed to retrieve rules.")
        return

    rules = resp["rules"]
    if not rules:
        print("[!] No rules found.")
        return

    print("📜 Active Firewall Rules (with hit counters):")
    print("=" * 90)
    for r in rules:
        rid = r.get("id", "-")
        action = (r.get("action") or "-").upper()
        proto = (r.get("protocol") or "-").upper()
        dst = r.get("dst_port")
        if isinstance(dst, list):
            dst = ",".join(str(p) for p in dst)
        elif dst is None:
            dst = "-"
        else:
            dst = str(dst)
        geo = r.get("geoip_country") or "-"
        hits = r.get("hits", 0)
        comment = r.get("comment") or ""
        print(f"[{rid:>4}] {action:<6} {proto:<6} dst={dst:<12} geo={geo:<4} hits={hits:<6} {comment}")
    print("=" * 90)


# =====================================================
# Profiling Commands
# =====================================================
def cmd_profile(n=10):
    """Show top-N most-hit rules."""
    resp = send_command({"cmd": "profile", "n": n})
    if not resp:
        print("[!] No response from daemon.")
        return
    if resp.get("status") != "ok":
        print("[!] Error:", resp.get("message"))
        return

    rules = resp.get("top_rules", [])
    if not rules:
        print("[!] No profiling data available yet.")
        return

    print(f"🔥 Top {n} Most-Hit Rules:")
    print("=" * 90)
    for i, r in enumerate(rules, 1):
        print(f"[{i}] Rule {r['id']:>3} | {r['action'].upper():<6} | Hits={r['hits']:<6} | {r['comment']}")
    print("=" * 90)


def cmd_profile_reset():
    """Reset profiling counters."""
    resp = send_command({"cmd": "profile-reset"})
    if not resp:
        print("[!] No response from daemon.")
        return
    print(resp.get("message", "Profiling counters reset."))


# =====================================================
# Lifecycle commands
# =====================================================
def cmd_start(no_monitor=False, auto_restart=False):
    print("[*] Checking if firewall daemon already running...")
    r = send_command({"cmd": "status"})
    if r and r.get("status") == "ok":
        print("[✓] Daemon already running.")
        if not no_monitor:
            cmd_monitor(auto_restart=auto_restart)
        return

    daemon_path = os.path.join(os.path.dirname(__file__), "firewall_daemon.py")
    if not os.path.exists(daemon_path):
        print(f"[!] Cannot find {daemon_path}.")
        return

    print("[*] Starting firewall daemon in a new console (may prompt for UAC)...")
    try:
        creationflags = subprocess.CREATE_NEW_CONSOLE
        subprocess.Popen(["python", daemon_path], creationflags=creationflags, shell=True)
    except Exception as e:
        print(f"[!] Failed to launch daemon process: {e}")
        return

    print("[*] Waiting for daemon to initialize (15s timeout)...")
    for i in range(15):
        time.sleep(1)
        r = send_command({"cmd": "status"})
        if r and r.get("status") == "ok":
            print("[✓] Daemon is online.")
            if not no_monitor:
                cmd_monitor(auto_restart=auto_restart)
            return
    print("[!] Timeout: daemon did not respond within 15s.")


def cmd_stop():
    print("[*] Sending stop to daemon...")
    resp = send_command({"cmd": "stop"})
    if not resp:
        print("[!] No response — daemon may not be running.")
        return
    if resp.get("status") == "ok":
        print(f"[✓] {resp['message']}")
        time.sleep(1)
    else:
        print("[!] Error:", resp.get("message"))


def cmd_restart(no_monitor=False, auto_restart=False):
    print("[*] Restarting daemon...")
    cmd_stop()
    time.sleep(2)
    cmd_start(no_monitor=no_monitor, auto_restart=auto_restart)


# =====================================================
# Rule Management
# =====================================================
def cmd_addrule(args):
    payload = {
        "cmd": "addrule",
        "action": args.action,
        "protocol": args.protocol,
        "dst_port": args.dst_port,
        "src_ip": args.src_ip,
        "dst_ip": args.dst_ip,
        "geoip_country": args.geoip_country,
        "rate_limit": args.rate_limit,
        "comment": args.comment,
    }
    resp = send_command(payload)
    if not resp:
        print("[!] No response from daemon.")
        return
    if resp.get("status") == "ok":
        print(f"[✓] Rule added (ID={resp['rule_id']})")
    else:
        print("[!] Error:", resp.get("message"))


def cmd_updaterule(args):
    payload = {
        "cmd": "updaterule",
        "id": args.id,
        "action": args.action,
        "protocol": args.protocol,
        "dst_port": args.dst_port,
        "src_ip": args.src_ip,
        "dst_ip": args.dst_ip,
        "geoip_country": args.geoip_country,
        "rate_limit": args.rate_limit,
        "comment": args.comment,
        "add_if_missing": args.add_if_missing,
    }
    resp = send_command(payload)
    if not resp:
        print("[!] No response from daemon.")
        return
    if resp.get("status") == "ok":
        print(f"[✓] {resp['message']}")
    elif resp.get("status") == "not_found":
        print(f"[!] {resp['message']}")
        if args.add_if_missing:
            print("[*] Adding new rule instead...")
            cmd_addrule(args)
    else:
        print("[!] Error:", resp.get("message"))


def cmd_delrule(args):
    payload = {"cmd": "delrule", "id": args.id}
    resp = send_command(payload)
    if not resp:
        print("[!] No response from daemon.")
        return
    if resp.get("status") == "ok":
        print(f"[✓] {resp['message']}")
    else:
        print("[!] Error:", resp.get("message"))


# =====================================================
# Monitor
# =====================================================
def cmd_monitor(auto_restart=False, interval=2, fail_threshold=3, max_restarts=2):
    print("\033[96m[*] Entering live monitor — press CTRL+C to exit.\033[0m")
    last_allowed = last_blocked = 0
    consecutive_fails = 0
    restarts_attempted = 0
    retries_after_down = 0
    MAX_RETRIES_AFTER_DOWN = 3

    try:
        while True:
            resp = send_command({"cmd": "status"}, timeout=1)
            now_ts = datetime.now().strftime("%H:%M:%S")

            if not resp or resp.get("status") != "ok":
                consecutive_fails += 1
                print(f"[{now_ts}] \033[91mLost connection to daemon ({consecutive_fails}/{fail_threshold})\033[0m")

                if consecutive_fails >= fail_threshold:
                    retries_after_down += 1
                    if auto_restart and restarts_attempted < max_restarts:
                        restarts_attempted += 1
                        print(f"[!] Attempting automatic restart ({restarts_attempted}/{max_restarts})...")
                        cmd_start(no_monitor=True, auto_restart=auto_restart)
                        for _ in range(10):
                            time.sleep(1)
                            resp = send_command({"cmd": "status"}, timeout=1)
                            if resp and resp.get("status") == "ok":
                                print("[✓] Daemon recovered after auto-restart.")
                                consecutive_fails = retries_after_down = 0
                                last_allowed = last_blocked = 0
                                break
                        else:
                            print("[!] Auto-restart attempt failed.")
                    else:
                        print(f"[!] Daemon appears offline. Retrying... ({retries_after_down}/{MAX_RETRIES_AFTER_DOWN})")
                        if retries_after_down >= MAX_RETRIES_AFTER_DOWN:
                            print("[✗] Daemon did not recover after 3 retries — exiting monitor gracefully.")
                            break

                time.sleep(interval)
                continue

            # Normal status
            consecutive_fails = retries_after_down = 0
            allowed = resp["allowed_packets"]
            blocked = resp["blocked_packets"]
            delta_a = (allowed - last_allowed) / (interval or 1)
            delta_b = (blocked - last_blocked) / (interval or 1)
            total = allowed + blocked
            block_ratio = (blocked / total * 100) if total > 0 else 0
            uptime = resp["uptime"]
            rules = resp["rules_loaded"]

            proc = find_daemon_process()
            proc_info = ""
            if proc:
                try:
                    cpu = proc.cpu_percent(interval=None)
                    mem = proc.memory_info().rss
                    proc_info = f" | PID={proc.pid} CPU={cpu:.1f}% MEM={human_bytes(mem)}"
                except Exception:
                    proc_info = ""

            os.system("cls" if os.name == "nt" else "clear")
            print("\033[96m==============================\033[0m")
            print("\033[96m   CPFF Firewall Live Monitor \033[0m")
            print("\033[96m==============================\033[0m")
            print(f" Time            : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f" Uptime          : {uptime//60}m{uptime%60:02d}s")
            print(f" Rules Loaded    : {rules}")
            print(f" Allowed Packets : \033[92m{allowed}\033[0m (+{delta_a:.1f}/s)")
            print(f" Blocked Packets : \033[91m{blocked}\033[0m (+{delta_b:.1f}/s)")
            print(f" Total Packets   : \033[96m{total}\033[0m")
            print(f" Block Ratio     : \033[91m{block_ratio:.1f}%\033[0m{proc_info}")

            # Show top profiling summary
            top_rules = resp.get("top_rules", [])
            if top_rules:
                print("\n📊 Top Rules:")
                for tr in top_rules[:3]:
                    print(f"  ID {tr['id']:<3} | {tr['action'].upper():<6} | Hits={tr['hits']:<5} | {tr['comment']}")
            print("\033[96m==============================\033[0m")

            last_allowed, last_blocked = allowed, blocked
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\033[93m[!] Exiting monitor.\033[0m")


# =====================================================
# CLI Parser Setup
# =====================================================
def main():
    parser = argparse.ArgumentParser(description="CPFF Firewall Client (Stage 4)")
    subparsers = parser.add_subparsers(dest="command")

    # core
    subparsers.add_parser("status", help="Show firewall status (with profiling)")
    subparsers.add_parser("reload", help="Reload firewall rules")
    subparsers.add_parser("list", help="List all rules (with hit counters)")
    subparsers.add_parser("health", help="Health check")

    # lifecycle
    start_p = subparsers.add_parser("start", help="Start daemon")
    start_p.add_argument("--no-monitor", action="store_true")
    start_p.add_argument("--auto-restart", action="store_true")
    subparsers.add_parser("stop", help="Stop daemon")
    restart_p = subparsers.add_parser("restart", help="Restart daemon")
    restart_p.add_argument("--no-monitor", action="store_true")
    restart_p.add_argument("--auto-restart", action="store_true")

    # profiling
    prof_p = subparsers.add_parser("profile", help="Show top N most-hit rules")
    prof_p.add_argument("--n", type=int, default=10)
    subparsers.add_parser("profile-reset", help="Reset profiling counters")

    # rule mgmt
    add_p = subparsers.add_parser("addrule", help="Add rule")
    add_p.add_argument("--action", required=True)
    add_p.add_argument("--protocol")
    add_p.add_argument("--dst_port")
    add_p.add_argument("--src_ip")
    add_p.add_argument("--dst_ip")
    add_p.add_argument("--geoip_country")
    add_p.add_argument("--rate_limit")
    add_p.add_argument("--comment")

    upd_p = subparsers.add_parser("updaterule", help="Update rule")
    upd_p.add_argument("--id", required=True)
    upd_p.add_argument("--action")
    upd_p.add_argument("--protocol")
    upd_p.add_argument("--dst_port")
    upd_p.add_argument("--src_ip")
    upd_p.add_argument("--dst_ip")
    upd_p.add_argument("--geoip_country")
    upd_p.add_argument("--rate_limit")
    upd_p.add_argument("--comment")
    upd_p.add_argument("--add-if-missing", action="store_true")

    del_p = subparsers.add_parser("delrule", help="Delete rule")
    del_p.add_argument("--id", required=True)

    # monitor
    mon_p = subparsers.add_parser("monitor", help="Live monitor")
    mon_p.add_argument("--auto-restart", action="store_true")
    mon_p.add_argument("--interval", type=float, default=2.0)
    mon_p.add_argument("--fail-threshold", type=int, default=3)

    args = parser.parse_args()

    if args.command == "status":
        cmd_status()
    elif args.command == "reload":
        cmd_reload()
    elif args.command == "list":
        cmd_list()
    elif args.command == "profile":
        cmd_profile(args.n)
    elif args.command == "profile-reset":
        cmd_profile_reset()
    elif args.command == "start":
        cmd_start(no_monitor=args.no_monitor, auto_restart=args.auto_restart)
    elif args.command == "stop":
        cmd_stop()
    elif args.command == "restart":
        cmd_restart(no_monitor=args.no_monitor, auto_restart=args.auto_restart)
    elif args.command == "monitor":
        cmd_monitor(auto_restart=args.auto_restart, interval=args.interval, fail_threshold=args.fail_threshold)
    elif args.command == "addrule":
        cmd_addrule(args)
    elif args.command == "updaterule":
        cmd_updaterule(args)
    elif args.command == "delrule":
        cmd_delrule(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
