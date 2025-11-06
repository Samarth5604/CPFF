# gui/logs_tab.py
import os
from datetime import datetime
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QLabel
from PyQt6.QtCore import QTimer

BASE_DIR = os.path.dirname(os.path.dirname(__file__)) if "__file__" in globals() else "."
LOG_JSONL = os.path.join(BASE_DIR, "logs", "all_packets", f"firewall_all_{datetime.now().strftime('%Y-%m-%d')}.jsonl")

class LogsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.tail_timer = QTimer()
        self.tail_timer.timeout.connect(self.load_logs_tail)
        # tail mode will not start automatically; user toggles it

    def init_ui(self):
        layout = QVBoxLayout()
        controls = QHBoxLayout()
        self.lbl_info = QLabel("Logs")
        controls.addWidget(self.lbl_info)
        self.btn_refresh = QPushButton("Refresh"); self.btn_refresh.clicked.connect(self.load_logs)
        self.btn_tail = QPushButton("Tail"); self.btn_tail.setCheckable(True); self.btn_tail.clicked.connect(self.toggle_tail)
        controls.addWidget(self.btn_refresh); controls.addWidget(self.btn_tail)
        layout.addLayout(controls)

        self.txt_logs = QTextEdit()
        self.txt_logs.setReadOnly(True)
        layout.addWidget(self.txt_logs)
        self.setLayout(layout)
        # initial load
        self.load_logs()

    def load_logs(self):
        try:
            if not os.path.exists(LOG_JSONL):
                self.txt_logs.setPlainText("[No logs found]")
                return
            # read only the last ~8 KB of the file to limit IO
            with open(LOG_JSONL, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                # read last 8KB or full file if smaller
                read_from = max(0, size - 8192)
                f.seek(read_from)
                raw = f.read()
            text = raw.decode("utf-8", errors="ignore")
            # splitlines to avoid partial last line issues
            lines = text.splitlines()
            # keep only last 300 lines at most
            lines = lines[-300:]
            self.txt_logs.setPlainText("\n".join(lines))
        except Exception as e:
            # show the exception briefly to user but do not crash
            self.txt_logs.setPlainText(f"[Error reading logs]\n{e}")

    def toggle_tail(self):
        if self.btn_tail.isChecked():
            # start lightweight tailing at 1500ms interval
            self.tail_timer.start(1500)
            self.btn_tail.setText("Tailing...")
        else:
            self.tail_timer.stop()
            self.btn_tail.setText("Tail")

    def load_logs_tail(self):
        # just call load_logs (optimized above)
        self.load_logs()
