import sqlite3
from datetime import datetime, timezone

DB_PATH = "firewall_logs.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            action TEXT,
            rule_id INTEGER,
            comment TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_packet(packet, action, rule=None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": getattr(packet, "src_addr", None),
        "dst_ip": getattr(packet, "dst_addr", None),
        "src_port": getattr(packet, "src_port", None),
        "dst_port": getattr(packet, "dst_port", None),
        "protocol": getattr(packet.protocol, "name", str(packet.protocol)),
        "action": action.upper(),
        "rule_id": rule.get("id") if rule else None,
        "comment": rule.get("comment") if rule else None
    }

    cur.execute("""
        INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port,
                             protocol, action, rule_id, comment)
        VALUES (:timestamp, :src_ip, :dst_ip, :src_port, :dst_port,
                :protocol, :action, :rule_id, :comment)
    """, entry)

    conn.commit()
    conn.close()

    # Optional: Print live monitoring to console
    print(f"[{entry['action']}] {entry['src_ip']}:{entry['src_port']} -> {entry['dst_ip']}:{entry['dst_port']}")
