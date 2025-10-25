from datetime import datetime, timezone
import json
import os
from types import SimpleNamespace

from firewall_core import (
    load_rules,
    match_rule,
    log_packet,
    check_geoip,
    rate_limited
)

print("[*] Loading rules...")
num_rules = load_rules()
print(f"[+] Loaded {num_rules} rules successfully!\n")

# Create a mock packet similar to what pydivert provides
mock_packet = SimpleNamespace(
    src_addr="192.168.29.118",
    dst_addr="142.250.183.110",  # example: google.com
    src_port=53211,
    dst_port=443,
    protocol="TCP"
)

print("[*] Matching packet against rules...")
rule = match_rule(mock_packet)

if rule:
    print(f"[+] Matched Rule: {rule.get('id')} ({rule.get('action')})")
else:
    print("[+] No matching rule (default allow)")

# Check GeoIP (if DB is available)
country = check_geoip(mock_packet.dst_addr)
print(f"[+] GeoIP result: {country or 'N/A'}")

# Simulate rate limiting (optional)
if rate_limited(mock_packet.src_addr, {"_rate_threshold": 3, "_rate_window": 5}):
    print("[!] Rate limit hit")
else:
    print("[+] Below rate limit")

# Log this packet decision (simulate a firewall entry)
entry = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "src_ip": mock_packet.src_addr,
    "dst_ip": mock_packet.dst_addr,
    "src_port": mock_packet.src_port,
    "dst_port": mock_packet.dst_port,
    "protocol": mock_packet.protocol,
    "action": "ALLOW" if not rule else rule.get("action", "BLOCK")
}

print("[*] Logging packet entry...")
log_packet(entry)
print("[+] Log entry written!")

# Confirm logs were written
if os.path.exists("logs/all_packets"):
    print(f"[✓] Log files found in: {os.path.abspath('logs/all_packets')}")
else:
    print("[!] Log directory missing — check permissions")
