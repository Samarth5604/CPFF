from PyQt6.QtWidgets import QDialog, QFormLayout, QLineEdit, QDialogButtonBox
from gui.validators import Validator

class RuleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Rule")
        self.form = QFormLayout(self)

        self.fields = {}
        for f in ["action", "protocol", "src_ip", "dst_ip", "dst_port", "geoip_country", "comment"]:
            le = QLineEdit()
            le.textChanged.connect(lambda _, k=f, le=le: Validator.validate_inline(k, le))
            self.form.addRow(f.capitalize() + ":", le)
            self.fields[f] = le

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.form.addWidget(self.buttons)

    def get_data(self):
        return {k: v.text().strip() or None for k, v in self.fields.items()}
