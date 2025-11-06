from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QPushButton, QHBoxLayout, QMessageBox
import cpff_ipc_client as ipc
from gui.rule_dialog import RuleDialog

class RulesTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID", "Action", "Protocol", "Dst Port", "GeoIP", "Comment"])
        layout.addWidget(self.table)

        buttons = QHBoxLayout()
        self.add_btn = QPushButton("Add Rule")
        self.del_btn = QPushButton("Delete Rule")
        self.reload_btn = QPushButton("Reload")
        for b in (self.add_btn, self.del_btn, self.reload_btn):
            buttons.addWidget(b)
        layout.addLayout(buttons)

        self.add_btn.clicked.connect(self.add_rule)
        self.del_btn.clicked.connect(self.delete_rule)
        self.reload_btn.clicked.connect(self.load_rules)
        self.load_rules()

    def load_rules(self):
        resp = ipc.send_command({"cmd": "list"})
        if not resp or resp.get("status") != "ok":
            QMessageBox.warning(self, "Error", "Failed to load rules.")
            return
        self.table.setRowCount(0)
        for r in resp["rules"]:
            row = self.table.rowCount()
            self.table.insertRow(row)
            for i, key in enumerate(["id", "action", "protocol", "dst_port", "geoip_country", "comment"]):
                self.table.setItem(row, i, QTableWidgetItem(str(r.get(key, ""))))

    def add_rule(self):
        dlg = RuleDialog(self)
        if dlg.exec():
            rule = dlg.get_data()
            r = ipc.send_command({"cmd": "addrule", **rule})
            if r and r.get("status") == "ok":
                QMessageBox.information(self, "Success", "Rule added successfully.")
                self.load_rules()

    def delete_rule(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select", "Select a rule to delete.")
            return
        rule_id = self.table.item(row, 0).text()
        resp = ipc.send_command({"cmd": "delrule", "id": rule_id})
        if resp and resp.get("status") == "ok":
            QMessageBox.information(self, "Deleted", f"Rule {rule_id} deleted.")
            self.load_rules()
