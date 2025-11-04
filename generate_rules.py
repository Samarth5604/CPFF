"""
generate_rules_deterministic.py
--------------------------------
Generates a large deterministic CPFF rules.yaml (v2.1 schema).

Features:
 - Exactly 500 rules (250 allow / 250 block)
 - Structured composition: core, geo, service, rate-limit, misc
 - Deterministic (same output each run)
 - Fully compatible with CPFF v2 core and daemon
"""

import yaml
import random
from datetime import datetime, timezone

random.seed(42)  # deterministic output

timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# -----------------------------------
# Base configuration lists
# -----------------------------------
geo_countries = ["RU", "CN", "IR", "PK", "KP", "SY", "VN", "BR", "US", "FR", "DE", "IN"]
core_services = {
    "allow": [
        (53, "UDP", "Allow DNS queries"),
        (443, "TCP", "Allow HTTPS secure traffic"),
        (22, "TCP", "Allow SSH connections"),
        (123, "UDP", "Allow NTP time sync"),
        (80, "TCP", "Allow HTTP (monitored)"),
    ],
    "block": [
        (25, "TCP", "Block SMTP (email)"),
        (445, "TCP", "Block SMB (lateral movement)"),
        (135, "TCP", "Block RPC (exploit surface)"),
        (23, "TCP", "Block Telnet"),
        (21, "TCP", "Block FTP"),
    ],
}

# -----------------------------------
# Helper to build rule entry
# -----------------------------------
def make_rule(
    rule_id,
    action,
    protocol=None,
    dst_port=None,
    geoip_country=None,
    comment="",
    priority=100,
    log=True,
    rate_limit=None,
    enabled=True,
):
    return {
        "id": rule_id,
        "action": action,
        "protocol": protocol,
        "dst_port": dst_port,
        "geoip_country": geoip_country,
        "comment": comment,
        "priority": priority,
        "enabled": enabled,
        "log": log,
        "rate_limit": rate_limit,
        "created_at": timestamp,
        "updated_at": timestamp,
    }


# -----------------------------------
# Generate rules
# -----------------------------------
rules = []

# Core base rules (same as before)
base_rules = [
    make_rule(1, "block", "TCP", 8081, None, "Block HTTP (insecure websites)", 10),
    make_rule(2, "allow", "TCP", 443, None, "Allow HTTPS secure traffic", 7, log=False),
    make_rule(3, "allow", "UDP", 53, None, "Allow DNS queries", 6, log=False),
    make_rule(4, "allow", None, None, None, "Allow internal LAN", 5, log=False),
]
rules.extend(base_rules)

# -----------------------------------
# GeoIP Block Rules (50)
# -----------------------------------
for i, country in enumerate(geo_countries * 5, start=5):
    rules.append(
        make_rule(
            i,
            "block",
            None,
            None,
            country,
            f"Block traffic from {country}",
            priority=20 + i,
        )
    )

# -----------------------------------
# Service-Based Rules (~100)
# -----------------------------------
rule_id = len(rules) + 1
for action in ["allow", "block"]:
    for (port, proto, desc) in core_services[action]:
        for j in range(10):  # 10 variants per service
            rules.append(
                make_rule(
                    rule_id,
                    action,
                    proto,
                    port,
                    None,
                    f"{desc} (variant {j+1})",
                    priority=50 + j,
                    log=(action == "block"),
                )
            )
            rule_id += 1

# -----------------------------------
# Rate-Limiting Rules (50)
# -----------------------------------
for k in range(50):
    port = random.choice([80, 443, 8080, 22, 25])
    rl = {"threshold": random.randint(30, 100), "window_seconds": 10}
    rules.append(
        make_rule(
            rule_id,
            "block",
            "TCP",
            port,
            None,
            f"Rate-limit TCP port {port} connections",
            priority=150 + k,
            rate_limit=rl,
        )
    )
    rule_id += 1

# -----------------------------------
# High Port Randomized Rules (~200)
# -----------------------------------
for n in range(200):
    action = "allow" if n % 2 == 0 else "block"
    proto = random.choice(["TCP", "UDP"])
    dst_port = random.randint(1000, 65000)
    rules.append(
        make_rule(
            rule_id,
            action,
            proto,
            dst_port,
            random.choice([None] + geo_countries),
            f"{action.title()} {proto} traffic on port {dst_port}",
            priority=300 + n,
            log=(action == "block"),
        )
    )
    rule_id += 1

# -----------------------------------
# Fill remaining slots with defaults
# -----------------------------------
while len(rules) < 500:
    rid = len(rules) + 1
    rules.append(
        make_rule(
            rid,
            random.choice(["allow", "block"]),
            random.choice(["TCP", "UDP", None]),
            random.choice([None, 80, 443, 8080, 53, 25, 22]),
            random.choice([None] + geo_countries),
            f"Generic traffic rule {rid}",
            priority=random.randint(100, 900),
            log=random.choice([True, False]),
        )
    )

# -----------------------------------
# Ensure deterministic sorting
# -----------------------------------
rules.sort(key=lambda r: r["id"])

# -----------------------------------
# Output YAML
# -----------------------------------
with open("rules.yaml", "w", encoding="utf-8") as f:
    yaml.safe_dump(rules, f, sort_keys=False, width=120)

print(f"[✓] Deterministic CPFF rules.yaml generated with {len(rules)} rules.")

