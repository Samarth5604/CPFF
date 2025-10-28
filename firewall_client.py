"""
firewall_client.py
------------------
Command-line interface for CPFF Firewall Daemon.
Communicates via Windows Named Pipe IPC.

Usage:
    python firewall_client.py status
    python firewall_client.py reload
    python firewall_client.py list
    python firewall_client.py monitor
    python firewall_client.py addrule --action block --protocol TCP --dst_port 8080 --comment "Block test"
"""

import os
import sys
import json
import time
import argparse
import win32pipe, win32file, pywintypes
from datetime import datetime

PIPE_NAME = r"\\.\pipe\cpff_firewall"


# =====================================================
# IPC Client Function
# =====================================================
def send_command(payload, timeout=5):
    """Send JSON command to the daemon via named pipe."""
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
                print("[!] Firewall daemon is not running or pipe not found.")
                return None
            time.sleep(0.3)
        except Exception as e:
            print(f"[!] IPC Error: {e}")
            return None
    print("[!] Error: Timed out waiting for response.")
    return None


# =====================================================
# Command Handlers
# =====================================================
def cmd_status():
    resp = send_command({"cmd": "status"})
    if not resp:
        return
    if resp.get("status") != "ok":
        print("[!] Daemon Error:", resp.get("message"))
        return

    print("\n🔥 CPFF Firewall Status 🔥")
    print(f"  Uptime         : {resp['uptime']}s")
    print(f"  Rules Loaded   : {resp['rules_loaded']}")
    print(f"  Allowed Packets: {resp['allowed_packets']}")
    print(f"  Blocked Packets: {resp['blocked_packets']}")
    print()


def cmd_reload():
    resp = send_command({"cmd": "reload"})
    if resp and resp.get("status") == "ok":
        print("[✓] Rules reloaded successfully.")
    else:
        print("[!] Failed to reload rules.")


def cmd_list():
    """Display active firewall rules in a formatted table."""
    print("📜 Active Firewall Rules:")
    print("=" * 80)

    rules = send_command({"cmd": "list"})
    if not rules or rules.get("status") != "ok":
        print("[!] Failed to retrieve rules.")
        return

    rules = rules["rules"]
    if not rules:
        print("[!] No rules found.")
        return

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
        comment = r.get("comment") or ""
        print(f"[{rid:>2}] {action:<6} {proto:<6} dst={dst:<10} geo={geo:<4} {comment}")

    print("=" * 80)


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
        print(f"[✓] Rule added successfully (ID={resp['rule_id']})")
        print(json.dumps(resp["rule"], indent=4))
    else:
        print("[!] Error:", resp.get("message"))


def cmd_monitor():
    print("\033[96m[*] Entering live monitor mode — press CTRL+C to exit.\033[0m")
    last_allowed = last_blocked = 0
    try:
        while True:
            resp = send_command({"cmd": "status"})
            if not resp or resp.get("status") != "ok":
                print("[!] Lost connection to daemon.")
                break

            allowed = resp["allowed_packets"]
            blocked = resp["blocked_packets"]
            delta_a = allowed - last_allowed
            delta_b = blocked - last_blocked
            total = allowed + blocked
            block_ratio = (blocked / total * 100) if total > 0 else 0
            uptime = resp["uptime"]
            rules = resp["rules_loaded"]

            os.system("cls" if os.name == "nt" else "clear")
            print("\033[96m==============================\033[0m")
            print("\033[96m   CPFF Firewall Live Monitor \033[0m")
            print("\033[96m==============================\033[0m")
            print(f" Uptime          : {uptime//60}m{uptime%60:02d}s")
            print(f" Rules Loaded    : {rules}")
            print(f" Allowed Packets : \033[92m{allowed}\033[0m (+{delta_a}/s)")
            print(f" Blocked Packets : \033[91m{blocked}\033[0m (+{delta_b}/s)")
            print(f" Total Packets   : \033[96m{total}\033[0m")
            print(f" Block Ratio     : \033[91m{block_ratio:.1f}%\033[0m")
            print("\033[96m==============================\033[0m")

            last_allowed, last_blocked = allowed, blocked
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n\033[93m[!] Exiting monitor mode.\033[0m")


# =====================================================
# CLI Parser Setup
# =====================================================
def main():
    parser = argparse.ArgumentParser(description="CPFF Firewall Client")
    subparsers = parser.add_subparsers(dest="command")

    # status
    subparsers.add_parser("status", help="Show firewall status")

    # reload
    subparsers.add_parser("reload", help="Reload firewall rules")

    # list
    subparsers.add_parser("list", help="List all loaded rules")

    # monitor
    subparsers.add_parser("monitor", help="Live monitoring of packet counts")

    # addrule
    add_parser = subparsers.add_parser("addrule", help="Add a new firewall rule")
    add_parser.add_argument("--action", required=True, help="Action: allow or block")
    add_parser.add_argument("--protocol", help="Protocol (TCP, UDP, ICMP)")
    add_parser.add_argument("--dst_port", help="Destination port or comma-separated list")
    add_parser.add_argument("--src_ip", help="Source IP/CIDR")
    add_parser.add_argument("--dst_ip", help="Destination IP/CIDR")
    add_parser.add_argument("--geoip_country", help="Country code (e.g., CN, US)")
    add_parser.add_argument("--rate_limit", help="Rate limit (e.g., 100/10 for 100 pkts in 10s)")
    add_parser.add_argument("--comment", help="Optional comment/description")

    args = parser.parse_args()

    if args.command == "status":
        cmd_status()
    elif args.command == "reload":
        cmd_reload()
    elif args.command == "list":
        cmd_list()
    elif args.command == "addrule":
        cmd_addrule(args)
    elif args.command == "monitor":
        cmd_monitor()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
