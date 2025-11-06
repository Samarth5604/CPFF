# gui/educational_tab.py
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QHBoxLayout, QFrame,
    QScrollArea
)
from PyQt6.QtCore import Qt, QTimer, QRectF
from PyQt6.QtGui import QColor, QPainter, QPen, QFont
import yaml

class PacketFlowWidget(QFrame):
    """Animated packet flow visualizer for educational demonstration."""
    def __init__(self):
        super().__init__()
        self.setMinimumHeight(200)
        self.stage = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.animate)
        self.timer.start(1800)  # smooth and low CPU

    def animate(self):
        if not self.isVisible():
            return
        self.stage = (self.stage + 1) % 5
        self.update()

    def paintEvent(self, event):
        if not self.isVisible():
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        try:
            stages = ["Ingress", "Rule Engine", "GeoIP / Rate-Limit", "Decision", "Egress"]
            spacing = 25
            w = int(max(40, (self.width() - spacing * (len(stages) + 1)) / len(stages)))
            h = 80
            y = int(self.height() / 2 - h / 2)

            rects = []
            for i in range(len(stages)):
                x = int(spacing + i * (w + spacing))
                rects.append((x, y, w, h))

            for i, (x, y, w, h) in enumerate(rects):
                color = QColor("#3498db")
                if i == self.stage:
                    if stages[i] == "Decision":
                        color = QColor("#f39c12")
                    elif stages[i] == "Egress":
                        color = QColor("#2ecc71")
                    else:
                        color = QColor("#1abc9c")
                painter.setBrush(color)
                painter.setPen(QPen(Qt.GlobalColor.black, 2))
                painter.drawRoundedRect(QRectF(x, y, w, h), 12.0, 12.0)
                painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
                painter.drawText(QRectF(x, y + h / 2 - 10, w, 20),
                                 Qt.AlignmentFlag.AlignCenter,
                                 stages[i])

            painter.setPen(QPen(Qt.GlobalColor.white, 3))
            for i in range(len(rects) - 1):
                x1 = rects[i][0] + rects[i][2]
                y1 = rects[i][1] + rects[i][3] / 2
                x2 = rects[i + 1][0]
                y2 = rects[i + 1][1] + rects[i + 1][3] / 2
                painter.drawLine(int(x1), int(y1), int(x2 - 10), int(y2))
                painter.setFont(QFont("Segoe UI", 10))
                painter.drawText(int((x1 + x2) / 2 - 10), int(y1 - 8), "→")
        finally:
            painter.end()  # ensure cleanup

class EducationalTab(QWidget):
    """Comprehensive learning and insight section for CPFF."""
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        title = QLabel("📘 Learn: Understanding and Building Firewalls")
        title.setStyleSheet("font-size:20px; font-weight:bold;")
        layout.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        vbox = QVBoxLayout(container)

        # Section 1 – Firewall Basics
        section1 = QLabel("""
        <h2>🔹 What is a Firewall?</h2>
        A <b>firewall</b> monitors and controls network traffic based on security rules. 
        It acts as a barrier between trusted and untrusted networks.
        """)
        section1.setWordWrap(True)
        vbox.addWidget(section1)

        # Section 2 – CPFF internals
        vbox.addWidget(QLabel("<h2>🔧 How CPFF Works Internally</h2>"))
        self.flow = PacketFlowWidget()
        vbox.addWidget(self.flow)

        cpff_desc = QLabel("""
        CPFF (Custom Packet Filtering Firewall) shows real-time packet filtering and AI-assisted rule suggestions.
        Components include:
        <ul>
          <li>Firewall Daemon (packet capture + filtering)</li>
          <li>AI Engine (log-based rule discovery)</li>
          <li>IPC Interface (communication between GUI and daemon)</li>
          <li>YAML Rule System (human-friendly configuration)</li>
        </ul>
        """)
        cpff_desc.setWordWrap(True)
        vbox.addWidget(cpff_desc)

        # Section 3 – Build Your Own
        vbox.addWidget(QLabel("<h2>🧠 Build Your Own Packet Filtering Firewall</h2>"))
        build_guide = QTextEdit()
        build_guide.setReadOnly(True)
        build_guide.setStyleSheet("background:#1e1e1e; color:#dcdcdc; font-family:Consolas; font-size:13px;")
        build_guide.setPlainText(
            """# Step-by-Step: Creating Your Own Firewall in Python

1) Install dependencies:
    pip install pydivert pyyaml jsonlines

2) Capture packets:
    from pydivert import WinDivert
    with WinDivert("true") as w:
        for packet in w:
            print(packet.src_addr, "->", packet.dst_addr)
            w.send(packet)

3) Simple rule example:
    rules = [
      {"action":"block", "dst_port":8080},
      {"action":"allow"}
    ]

4) Apply rules:
    for packet in w:
        for rule in rules:
            if rule.get("action") == "block" and getattr(packet, "dst_port", None) == 8080:
                break  # drop
        else:
            w.send(packet)
"""
        )
        vbox.addWidget(build_guide)

        # Section 4 – Rule Simulation
        vbox.addWidget(QLabel("<h2>💡 Try Simulating a Rule</h2>"))
        sim_area = QHBoxLayout()
        self.rule_edit = QTextEdit()
        self.rule_edit.setPlainText(
            "- action: block\n  protocol: TCP\n  dst_port: 8080\n  comment: Block HTTP traffic"
        )
        sim_area.addWidget(self.rule_edit)

        self.btn_simulate = QPushButton("Simulate")
        self.btn_simulate.clicked.connect(self.simulate_rule)
        self.lbl_result = QLabel("Result will appear here.")
        self.lbl_result.setStyleSheet("font-size:14px; font-weight:bold;")
        side = QVBoxLayout()
        side.addWidget(self.btn_simulate)
        side.addWidget(self.lbl_result)
        sim_area.addLayout(side)
        vbox.addLayout(sim_area)

        # Footer
        footer = QLabel("<i>CPFF Educational Module © 2025 • Built for learning and security research.</i>")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet("color:gray; margin-top:10px;")
        vbox.addWidget(footer)

        container.setLayout(vbox)
        scroll.setWidget(container)
        layout.addWidget(scroll)
        self.setLayout(layout)

    def simulate_rule(self):
        try:
            data = yaml.safe_load(self.rule_edit.toPlainText())
            if not isinstance(data, list) or not data[0].get("action"):
                raise ValueError("Invalid YAML format or missing 'action'")
            rule = data[0]
            action = rule.get("action", "allow").lower()
            if action == "block":
                color, text = "red", "❌ BLOCKED"
            else:
                color, text = "green", "✅ ALLOWED"
            self.lbl_result.setStyleSheet(f"font-size:14px; font-weight:bold; color:{color};")
            self.lbl_result.setText(f"Packet {text} by rule")
        except Exception as e:
            self.lbl_result.setStyleSheet("color:orange; font-weight:bold;")
            self.lbl_result.setText(f"⚠️ YAML Error: {e}")
