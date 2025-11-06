from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton
from PyQt6.QtCore import QTimer
import os, glob

class LogsTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.view = QTextEdit()
        self.view.setReadOnly(True)
        self.refresh_btn = QPushButton("Refresh Logs")
        layout.addWidget(self.view)
        layout.addWidget(self.refresh_btn)

        self.refresh_btn.clicked.connect(self.load_latest)
        self.timer = QTimer()
        self.timer.timeout.connect(self.load_latest)
        self.timer.start(1500)
        self.load_latest()

    def load_latest(self):
        try:
            files = sorted(glob.glob("logs/all_packets/firewall_all_*.jsonl"), key=os.path.getmtime)
            if not files: return
            latest = files[-1]
            with open(latest, "r", encoding="utf-8") as f:
                lines = f.readlines()[-50:]
            self.view.setText("".join(lines))
        except Exception:
            pass
