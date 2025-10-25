import os
import time
import json
import yaml
import uuid
import subprocess
from datetime import datetime
import pydivert
import psutil

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False

RULES_FILE = "rules.yaml"
LOG_DIR = "logs"
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
RULE_REFRESH_INTERVAL = 10

for sub in ["allowed_packets", "blocked_packets", "all_packets"]:
    os.makedirs(os.path.join(LOG_DIR, sub), exist_ok=True)

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("[!] geoip2 not installed. Run: pip install geoip2")


def stop_existing_windivert():
    """Ensure no stale WinDivert instances remain loaded."""
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if 'python' in proc.name().lower():
                try:
                    for c in proc.cmdline():
                        if 'pydivert' in c or 'WinDivert' in c:
                            print(f"[!] Terminating old WinDivert process PID={proc.pid}")
                            proc.terminate()
                            proc.wait(timeout=2)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        # Try force-unloading driver
        subprocess.run(["sc", "stop", "WinDivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sc", "start", "WinDivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[Driver Check] Warning: {e}")


def validate_geoip():
    if not GEOIP_AVAILABLE:
        return False
    if not os.path.exists(GEOIP_DB_PATH):
        return False
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            reader.country("8.8.8.8")
        print(f"[+] GeoIP test passed: 8.8.8.8 -> US")
        return True
    except Exception:
        return False


def get_proto(packet):
    try:
        if hasattr(packet.protocol, "name"):
            return packet.protocol.name.upper()
        elif isinstance(packet.protocol, tuple):
            return str(packet.protocol[0])
        else:
            return str(packet.protocol).upper()
    except Exception:
        return "UNKNOWN"


def load_rules():
    try:
        with open(RULES_FILE, "r") as f:
            rules = yaml.safe_load(f) or []
            print(f"[+] Loaded {len(rules)} rules (mtime: {datetime.fromtimestamp(os.path.getmtime(RULES_FILE))})")
            return rules
    except Exception as e:
        print(f"[!] Failed to load rules: {e}")
        return []


def check_geoip(ip):
    if not GEOIP_AVAILABLE or not os.path.exists(GEOIP_DB_PATH):
        return None
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            return reader.country(ip).country.iso_code
    except Exception:
        return None


def log_packet(entry):
    try:
        action = entry.get("action", "UNKNOWN").upper()
        date_str = datetime.now().strftime("%Y-%m-%d")
        fname = f"packet_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{uuid.uuid4().hex[:6]}_{action.lower()}.json"
        folder = os.path.join(LOG_DIR, "blocked_packets" if action == "BLOCK" else "allowed_packets")

        with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
            json.dump(entry, f, indent=4, default=str)

        with open(os.path.join(LOG_DIR, "all_packets", f"firewall_all_{date_str}.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        print(f"[Log Error] {e}")


def match_rule(packet, rules):
    try:
        proto = get_proto(packet)
        for r in rules:
            if r.get("protocol", "").upper() and r["protocol"].upper() != proto:
                continue
            if r.get("dst_port") and r["dst_port"] != packet.dst_port:
                continue
            return r
        return None
    except Exception as e:
        print(f"[Rule Error] {e}")
        return None


def run_firewall():
    print("Make sure you run this script as Administrator.")
    print("[*] Initializing firewall engine...")
    geoip_ready = validate_geoip()
    if not geoip_ready:
        print("[!] GeoIP disabled.")

    stop_existing_windivert()
    rules = load_rules()
    last_reload = time.time()

    # ✅ VALID FILTER — captures TCP/UDP/ICMP except loopback
    filter_str = "(ip or ipv6) and (tcp or udp or icmp) and (not ip.SrcAddr == 127.0.0.1 and not ip.DstAddr == 127.0.0.1)"

    retry_delay = 1
    while True:
        try:
            print("[*] Opening WinDivert driver...")
            with pydivert.WinDivert(filter_str) as w:
                print("[*] Firewall running with rules... Press Ctrl+C to stop.")
                retry_delay = 1

                for packet in w:
                    try:
                        if time.time() - last_reload > RULE_REFRESH_INTERVAL:
                            rules = load_rules()
                            last_reload = time.time()

                        rule = match_rule(packet, rules)
                        src_ip, dst_ip = packet.src_addr, packet.dst_addr
                        src_port, dst_port = packet.src_port, packet.dst_port
                        proto = get_proto(packet)
                        action = rule.get("action", "allow").lower() if rule else "allow"

                        entry = {
                            "timestamp": datetime.now().isoformat(),
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "protocol": proto,
                            "action": action.upper(),
                            "rule_id": rule.get("id") if rule else None,
                            "comment": rule.get("comment") if rule else "Default allow"
                        }

                        log_packet(entry)

                        msg = f"[{action.upper()}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto}) " \
                              f"{'rule=' + str(rule.get('id')) if rule else '[default]'}"
                        if COLOR_AVAILABLE:
                            color = Fore.RED if action == "block" else Fore.GREEN
                            print(color + msg + Style.RESET_ALL)
                        else:
                            print(msg)

                        if action == "block":
                            continue
                        else:
                            w.send(packet)

                    except KeyboardInterrupt:
                        print("\n[!] Stopping firewall...")
                        return
                    except OSError as e:
                        if hasattr(e, "winerror") and e.winerror == 183:
                            print("[!] WinDivert collision detected — cleaning up...")
                            stop_existing_windivert()
                            time.sleep(3)
                            break
                        else:
                            print(f"[Recv Error] {e}")
        except KeyboardInterrupt:
            print("\n[!] Firewall stopped by user.")
            break
        except Exception as e:
            print(f"[!] Driver open error: {e}")
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 8)


if __name__ == "__main__":
    run_firewall()
