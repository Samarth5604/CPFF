import pydivert
import yaml

# Load rules from YAML file
with open("rules.yaml", "r") as f:
    rules = yaml.safe_load(f)

def match_rule(packet, rules):
    """
    Match a packet against the rules in the YAML file.
    Currently supports protocol + destination port.
    """
    for rule in rules:
        # Check protocol match
        if rule.get("protocol", "").lower() != packet.protocol.name.lower():
            continue

        # Check destination port match (if rule specifies it)
        if "dst_port" in rule and packet.dst_port != rule["dst_port"]:
            continue

        return rule  # Found a matching rule

    return None  # No rule matched

# Capture all packets
with pydivert.WinDivert("true") as w:
    print("Firewall running with rules...")
    for packet in w:
        rule = match_rule(packet, rules)

        if rule:
            if rule["action"] == "block":
                print(f"BLOCKED [{rule['id']}]: {packet.src_addr}:{packet.src_port} -> "
                      f"{packet.dst_addr}:{packet.dst_port} ({rule['comment']})")
                # Drop packet (don't reinject)
                continue
            elif rule["action"] == "allow":
                print(f"ALLOWED [{rule['id']}]: {packet.src_addr}:{packet.src_port} -> "
                      f"{packet.dst_addr}:{packet.dst_port} ({rule['comment']})")

        # Default action: allow
        w.send(packet)
