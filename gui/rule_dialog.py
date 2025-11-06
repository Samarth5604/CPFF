# gui/rule_dialog.py
import re, ipaddress
from PyQt6.QtWidgets import QDialog, QFormLayout, QLineEdit, QComboBox, QHBoxLayout, QPushButton
from PyQt6.QtCore import Qt

def mark_field(widget, valid):
    color = "#2ecc71" if valid else "#e74c3c"
    widget.setStyleSheet(f"border: 2px solid {color}; border-radius: 4px; padding: 2px;")

def valid_port(s):
    s = s.strip()
    if not s:
        return True
    try:
        for p in s.split(","):
            v = int(p)
            if v < 1 or v > 65535:
                return False
        return True
    except:
        return False

def valid_ip(s):
    s = s.strip()
    if not s:
        return True
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except:
        return False

def valid_proto(s):
    return s.strip().upper() in ("", "TCP", "UDP", "ICMP", "ANY")

def valid_geoip(s):
    s = s.strip()
    return s == "" or bool(re.fullmatch(r"[A-Z]{2}", s))


class RuleDialog(QDialog):
    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        self.setWindowTitle("Add Rule" if rule is None else "Edit Rule")
        self.rule = rule or {}
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        layout = QFormLayout(self)

        self.id_field = QLineEdit(str(self.rule.get("id", "")))
        self.id_field.setReadOnly(bool(self.rule.get("id")))
        self.action = QComboBox(); self.action.addItems(["allow", "block"])
        self.action.setCurrentText(self.rule.get("action", "allow"))

        self.protocol = QLineEdit(self.rule.get("protocol", ""))
        self.src_ip = QLineEdit(self.rule.get("src_ip", ""))
        self.dst_ip = QLineEdit(self.rule.get("dst_ip", ""))
        self.dst_port = QLineEdit(str(self.rule.get("dst_port", "")))
        self.geoip = QLineEdit(self.rule.get("geoip_country", ""))
        self.comment = QLineEdit(self.rule.get("comment", ""))

        layout.addRow("ID:", self.id_field)
        layout.addRow("Action:", self.action)
        layout.addRow("Protocol:", self.protocol)
        layout.addRow("Src IP/CIDR:", self.src_ip)
        layout.addRow("Dst IP/CIDR:", self.dst_ip)
        layout.addRow("Dst Port(s):", self.dst_port)
        layout.addRow("GeoIP (CC):", self.geoip)
        layout.addRow("Comment:", self.comment)

        btns = QHBoxLayout()
        ok = QPushButton("OK"); ok.clicked.connect(self.accept)
        cancel = QPushButton("Cancel"); cancel.clicked.connect(self.reject)
        btns.addWidget(ok); btns.addWidget(cancel)
        layout.addRow(btns)

        # Validation hooks
        for w in [self.protocol, self.src_ip, self.dst_ip, self.dst_port, self.geoip]:
            w.textChanged.connect(self.validate_all)
        self.validate_all()

    def validate_all(self):
        mark_field(self.protocol, valid_proto(self.protocol.text()))
        mark_field(self.src_ip, valid_ip(self.src_ip.text()))
        mark_field(self.dst_ip, valid_ip(self.dst_ip.text()))
        mark_field(self.dst_port, valid_port(self.dst_port.text()))
        mark_field(self.geoip, valid_geoip(self.geoip.text()))

    def get_payload(self):
        # Convert empty strings to None to keep IPC payload clean
        def norm(s):
            s = s.strip()
            return s if s != "" else None
        return {
            "id": norm(self.id_field.text()),
            "action": self.action.currentText(),
            "protocol": norm(self.protocol.text()).upper() if norm(self.protocol.text()) else None,
            "src_ip": norm(self.src_ip.text()),
            "dst_ip": norm(self.dst_ip.text()),
            "dst_port": norm(self.dst_port.text()),
            "geoip_country": norm(self.geoip.text()).upper() if norm(self.geoip.text()) else None,
            "comment": norm(self.comment.text()),
        }
