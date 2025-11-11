# gui/rules_tab.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, \
    QHeaderView, QLineEdit, QTableWidgetItem, QMessageBox
from PyQt6.QtCore import Qt, QTimer
from .rule_dialog import RuleDialog
from cpff_ipc_client import CPFFIPCClient
import json, hashlib, time

ipc = CPFFIPCClient()

class RulesTab(QWidget):
    def __init__(self):
        super().__init__()
        self.rules = []
        self._last_rules_hash = None
        self.init_ui()
        # defer first load slightly, so daemon has time to initialize
        self.init_timer = QTimer()
        self.init_timer.setSingleShot(True)
        self.init_timer.timeout.connect(self.load_rules)
        self.init_timer.start(1200)

    def init_ui(self):
        layout = QVBoxLayout()
        sbox = QHBoxLayout()
        sbox.addWidget(QLabel("Search:"))
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter rules by ID, comment, IP, port...")
        self.search.textChanged.connect(self.filter_rules)
        sbox.addWidget(self.search)
        layout.addLayout(sbox)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["ID", "Action", "Protocol", "Dst Port", "GeoIP", "Hits", "Comment"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        bbar = QHBoxLayout()
        for txt, func in [
            ("Refresh", self.load_rules),
            ("Add", self.add_rule),
            ("Edit", self.edit_rule),
            ("Delete", self.del_rule)
        ]:
            b = QPushButton(txt)
            b.clicked.connect(func)
            bbar.addWidget(b)
        layout.addLayout(bbar)
        self.setLayout(layout)

    def normalize_rules(self, response):
        """Normalize IPC response to ensure we always get a list of rule dicts."""
        if not response or not isinstance(response, dict):
            return []
        rules = response.get("rules") or response.get("data") or response.get("rule_list")
        if not rules:
            for k, v in response.items():
                if isinstance(v, list) and all(isinstance(i, dict) for i in v):
                    rules = v
                    break
                if isinstance(v, str) and v.strip().startswith("["):
                    try:
                        parsed = json.loads(v)
                        if isinstance(parsed, list):
                            rules = parsed
                            break
                    except Exception:
                        pass
        return rules or []

    def load_rules(self):
        try:
            r = ipc.send("list")
            new_rules = self.normalize_rules(r)
        except Exception as e:
            self.display_error(f"IPC Error: {e}")
            return

        if not new_rules and (r and r.get("status") == "ok"):
            time.sleep(0.8)
            try:
                r = ipc.send("list")
                new_rules = self.normalize_rules(r)
            except Exception:
                pass

        if not new_rules:
            self.display_error("No rules available or daemon not ready.")
            return

        try:
            key = hashlib.md5(json.dumps(new_rules, sort_keys=True).encode("utf-8")).hexdigest()
        except Exception:
            key = None

        if key and key == self._last_rules_hash:
            return

        self._last_rules_hash = key
        self.rules = new_rules
        self.render(self.rules)

    def render(self, rules):
        self.table.setRowCount(len(rules))
        for i, r in enumerate(rules):
            for j, k in enumerate(["id", "action", "protocol", "dst_port", "geoip_country", "hits", "comment"]):
                val = r.get(k, "")
                item = QTableWidgetItem(str(val))
                # ✅ PyQt6-compatible flags
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(i, j, item)

    def display_error(self, text):
        self.table.setRowCount(1)
        self.table.setItem(0, 0, QTableWidgetItem(text))
        for col in range(1, 7):
            self.table.setItem(0, col, QTableWidgetItem(""))

    def filter_rules(self):
        text = self.search.text().lower().strip()
        if not text:
            filtered = self.rules
        else:
            filtered = [r for r in self.rules if any(text in str(v).lower() for v in r.values())]
        self.render(filtered)

    def _normalize_payload_defaults(self, payload):
        """
        Ensure the payload includes a consistent, explicit set of keys so rules created from GUI
        are complete (no silent mismatches).
        """
        # Common user-level fields expected by daemon/core
        defaults = {
            "action": "allow",
            "protocol": None,      # None => wildcard/any
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "geoip_country": None,
            "comment": "",
            "enabled": True,
            "log": True,
            "rate_limit": None,
            "priority": 100,
        }

        # copy and ensure correct types for ports if comma-separated
        normalized = {}
        for k, v in defaults.items():
            normalized[k] = payload.get(k, v)

        # fix dst_port if user provided csv string
        dp = normalized.get("dst_port")
        if isinstance(dp, str) and "," in dp:
            try:
                normalized["dst_port"] = [int(x.strip()) for x in dp.split(",") if x.strip()]
            except Exception:
                normalized["dst_port"] = None
        # ensure ints where appropriate
        try:
            if isinstance(normalized.get("priority"), str) and normalized["priority"].isdigit():
                normalized["priority"] = int(normalized["priority"])
        except Exception:
            pass

        # ensure action is lower-case string
        if normalized.get("action"):
            normalized["action"] = str(normalized["action"]).lower()

        return normalized

    def add_rule(self):
        dlg = RuleDialog(self)
        if dlg.exec():
            try:
                payload = dlg.get_payload()
                payload = self._normalize_payload_defaults(payload)
                # use the IPC client's send wrapper (supports named-pipe)
                ipc.send("addrule", **payload)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add rule: {e}")
            self.load_rules()

    def edit_rule(self):
        sel = self.table.currentRow()
        if sel < 0:
            return
        rid_item = self.table.item(sel, 0)
        if rid_item is None:
            return
        rid = rid_item.text()
        rule = next((r for r in self.rules if str(r.get("id")) == rid), None)
        if not rule:
            return
        dlg = RuleDialog(self, rule)
        if dlg.exec():
            try:
                payload = dlg.get_payload()
                payload["id"] = rule.get("id")
                payload = self._normalize_payload_defaults(payload)
                ipc.send("updaterule", **payload)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to update rule: {e}")
            self.load_rules()

    def del_rule(self):
        sel = self.table.currentRow()
        if sel < 0:
            return
        rid_item = self.table.item(sel, 0)
        if rid_item is None:
            return
        rid = rid_item.text()
        if QMessageBox.question(self, "Confirm", f"Delete rule {rid}?") == QMessageBox.StandardButton.Yes:
            try:
                ipc.send("delrule", id=rid)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete rule: {e}")
            self.load_rules()
