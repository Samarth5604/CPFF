# gui/dashboard_tab.py
import os
import sys
import time
import threading
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QMessageBox
from PyQt6.QtCore import QTimer
import pyqtgraph as pg
from cpff_ipc_client import CPFFIPCClient

ipc = CPFFIPCClient()
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DAEMON_SCRIPT = os.path.join(BASE_DIR, "firewall_daemon.py")

class DashboardTab(QWidget):
    def __init__(self):
        super().__init__()
        self.chart_data = []
        self.last_chart_update = 0.0
        self.init_ui()

        # Unified timer handles status polling and occasional chart updates
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)
        # poll status every 3000 ms (3s)
        self.timer.start(3000)

    def init_ui(self):
        layout = QVBoxLayout()
        self.lbl_status = QLabel("Daemon: Unknown")
        self.lbl_allowed = QLabel("Allowed: -")
        self.lbl_blocked = QLabel("Blocked: -")
        self.lbl_rules = QLabel("Rules: -")
        for lbl in [self.lbl_status, self.lbl_allowed, self.lbl_blocked, self.lbl_rules]:
            lbl.setStyleSheet("font-size:15px; font-weight:bold;")
            layout.addWidget(lbl)

        btns = QHBoxLayout()
        for txt, func in [
            ("Start", self.start_daemon), ("Stop", self.stop_daemon),
            ("Restart", self.restart_daemon), ("Reload Rules", self.reload_rules)
        ]:
            b = QPushButton(txt); b.clicked.connect(func); btns.addWidget(b)
        layout.addLayout(btns)

        self.chart = pg.PlotWidget(title="Packet Rate (Allowed vs Blocked)")
        self.chart.addLegend()
        # turn off antialiasing to speed up redraws
        self.chart.setAntialiasing(False)
        self.chart.setBackground("#1e1e1e")
        self.chart_allowed = self.chart.plot([], [], pen=pg.mkPen("g", width=2), name="Allowed")
        self.chart_blocked = self.chart.plot([], [], pen=pg.mkPen("r", width=2), name="Blocked")
        layout.addWidget(self.chart)
        self.setLayout(layout)

    # unified tick function reduces timers and work
    def tick(self):
        # Refresh status each tick (lightweight)
        self.refresh_status()
        # Update chart only every ~6 seconds to reduce redraw cost
        if time.time() - self.last_chart_update > 6.0:
            self.update_chart()
            self.last_chart_update = time.time()

    def is_daemon_running(self):
        try:
            r = ipc.send("status")
            return r and r.get("status") == "ok"
        except Exception:
            return False

    def start_daemon(self):
        if self.is_daemon_running():
            QMessageBox.information(self, "Info", "Daemon already running."); return
        if not os.path.exists(DAEMON_SCRIPT):
            QMessageBox.critical(self, "Error", f"Daemon not found: {DAEMON_SCRIPT}"); return
        def _run():
            import subprocess
            subprocess.Popen([sys.executable, DAEMON_SCRIPT], creationflags=subprocess.CREATE_NEW_CONSOLE)
        threading.Thread(target=_run, daemon=True).start()
        time.sleep = getattr(time, "sleep", lambda s: None)
        time.sleep(1.2)
        self.refresh_status()

    def stop_daemon(self):
        try:
            ipc.send("stop")
        except Exception:
            pass
        # slight pause to let daemon exit/ack
        try: time.sleep(0.8)
        except Exception: pass
        self.refresh_status()

    def restart_daemon(self):
        threading.Thread(target=lambda: (self.stop_daemon(), time.sleep(1.5), self.start_daemon()), daemon=True).start()

    def reload_rules(self):
        try:
            ipc.send("reload")
        except Exception:
            pass
        self.refresh_status()

    def refresh_status(self):
        # Non-blocking: keep exceptions local so GUI doesn't freeze
        try:
            r = ipc.send("status")
        except Exception:
            r = None
        # if offline, update status label but skip heavy work
        if not r or r.get("status") != "ok":
            # only set text if different to avoid extra repaints
            if self.lbl_status.text() != "Daemon: Offline ❌":
                self.lbl_status.setText("Daemon: Offline ❌")
                self.lbl_status.setStyleSheet("color:red; font-weight:bold;")
            return

        # update labels only if values changed (minimize repaints)
        if self.lbl_status.text() != "Daemon: Online ✅":
            self.lbl_status.setText("Daemon: Online ✅")
            self.lbl_status.setStyleSheet("color:green; font-weight:bold;")
        allowed = r.get("allowed_packets", 0)
        blocked = r.get("blocked_packets", 0)
        rules_loaded = r.get("rules_loaded", 0)

        if self.lbl_allowed.text() != f"Allowed: {allowed}":
            self.lbl_allowed.setText(f"Allowed: {allowed}")
        if self.lbl_blocked.text() != f"Blocked: {blocked}":
            self.lbl_blocked.setText(f"Blocked: {blocked}")
        if self.lbl_rules.text() != f"Rules: {rules_loaded}":
            self.lbl_rules.setText(f"Rules: {rules_loaded}")

        # keep history for charting (append only)
        self.chart_data.append(r)
        if len(self.chart_data) > 120:
            self.chart_data.pop(0)

    def update_chart(self):
        # update with delta rates; avoid computing if insufficient data
        if len(self.chart_data) < 2:
            return
        dt = 3.0  # approximate seconds between samples (because tick runs every 3s)
        y_allowed, y_blocked, t = [], [], []
        base = max(0, len(self.chart_data) - 40)
        sliced = self.chart_data[base:]
        for i in range(1, len(sliced)):
            prev, curr = sliced[i - 1], sliced[i]
            da = (curr.get("allowed_packets", 0) - prev.get("allowed_packets", 0)) / dt
            db = (curr.get("blocked_packets", 0) - prev.get("blocked_packets", 0)) / dt
            y_allowed.append(max(da, 0))
            y_blocked.append(max(db, 0))
            t.append(i * dt)
        # setData is efficient; avoid calling if identical lengths and values (simple check)
        try:
            self.chart_allowed.setData(t, y_allowed)
            self.chart_blocked.setData(t, y_blocked)
        except Exception:
            pass
