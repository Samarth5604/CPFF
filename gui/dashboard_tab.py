from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QMessageBox
from PyQt6.QtCore import QTimer
import threading, time, subprocess, sys, os
import pyqtgraph as pg
import cpff_ipc_client as ipc

class DashboardTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.status_label = QLabel("Status: Unknown")
        self.chart = pg.PlotWidget(title="Live Packet Rate (packets/sec)")
        self.start_btn = QPushButton("Start Daemon")
        self.stop_btn = QPushButton("Stop Daemon")
        self.reload_btn = QPushButton("Reload Rules")

        btn_layout = QHBoxLayout()
        for b in (self.start_btn, self.stop_btn, self.reload_btn):
            btn_layout.addWidget(b)

        layout.addWidget(self.status_label)
        layout.addLayout(btn_layout)
        layout.addWidget(self.chart)

        self.chart_data = {"x": [], "y": []}
        self.plot = self.chart.plot([], [], pen='y')

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh)
        self.timer.start(2500)

        self.start_btn.clicked.connect(lambda: threading.Thread(target=self.start_daemon, daemon=True).start())
        self.stop_btn.clicked.connect(lambda: ipc.send_command({"cmd": "stop"}))
        self.reload_btn.clicked.connect(lambda: ipc.send_command({"cmd": "reload"}))

    def refresh(self):
        resp = ipc.send_command({"cmd": "status"})
        if not resp or resp.get("status") != "ok":
            self.status_label.setText("Status: Offline")
            return

        uptime = resp["uptime"]
        rules = resp["rules_loaded"]
        total = resp["allowed_packets"] + resp["blocked_packets"]

        self.status_label.setText(f"🟢 Online | Uptime: {uptime}s | Rules: {rules}")
        self.chart_data["x"].append(time.time())
        self.chart_data["y"].append(total)
        self.chart_data["x"] = self.chart_data["x"][-30:]
        self.chart_data["y"] = self.chart_data["y"][-30:]
        self.plot.setData(self.chart_data["x"], self.chart_data["y"])

    def start_daemon(self):
        daemon = os.path.join(os.path.dirname(__file__), "..", "firewall_daemon.py")
        subprocess.Popen([sys.executable, daemon], creationflags=subprocess.CREATE_NEW_CONSOLE)
        time.sleep(2)
        QMessageBox.information(self, "CPFF", "Firewall daemon started (if not already running).")
