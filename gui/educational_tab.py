# gui/educational_tab.py
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QHBoxLayout, QFrame, QScrollArea
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
        self.timer.start(1800)

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
            painter.end()


class EducationalTab(QWidget):
    """Comprehensive learning and insight section for CPFF."""
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        title = QLabel("📘 Learn: Understanding Firewalls & The CPFF Project")
        title.setStyleSheet("font-size:20px; font-weight:bold;")
        layout.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        vbox = QVBoxLayout(container)

        # === SECTION 1: FIREWALL BASICS ===
        section1 = QLabel("""
        🔹 <b>What is a Firewall?</b><br>
        A <b>firewall</b> is a network security device or software that monitors, filters, and controls 
        incoming and outgoing network traffic based on predefined security rules.<br><br>
        Firewalls act as the first line of defense, separating trusted internal networks from untrusted external networks (like the internet). 
        They can block malicious traffic, prevent data exfiltration, and enforce organizational security policies.
        
        🔸 <b>Types of Firewalls</b><br>
        • <b>Packet Filtering Firewall</b>: Inspects packets independently, based on IP, port, and protocol.<br>
        • <b>Stateful Firewall</b>: Tracks the state of active connections to allow only legitimate packets.<br>
        • <b>Proxy Firewall</b>: Acts as an intermediary between clients and servers.<br>
        • <b>Next-Generation Firewall (NGFW)</b>: Integrates intrusion prevention, application control, and AI analysis.<br><br>
        
        🔸 <b>Where It Works in OSI Model</b><br>
        - Network Layer (Layer 3): IP-based filtering.<br>
        - Transport Layer (Layer 4): Port-based control.<br>
        - Application Layer (Layer 7): Deep packet inspection and filtering by service type.<br><br>

        🔸 <b>Example:</b><br>
        You can block all incoming TCP packets on port 23 (Telnet) to prevent unauthorized remote access.
        """)
        section1.setWordWrap(True)
        vbox.addWidget(section1)

        vbox.addWidget(PacketFlowWidget())

        # === SECTION 2: CPFF INSIGHTS ===
        vbox.addWidget(QLabel("<h2>🔧 Inside CPFF: The Custom Packet Filtering Firewall</h2>"))

        cpff_desc = QLabel("""
        CPFF (Custom Packet Filtering Firewall) is a complete educational and practical firewall system built in Python.
        It demonstrates how packet inspection, rule enforcement, and even AI-assisted rule optimization can work together in real time.

        🧩 Core Components:
        • firewall_daemon.py – Runs as a background process, captures packets via WinDivert, and applies filtering rules.
        • firewall_core.py – Contains the main rule engine, YAML parser, GeoIP filter, and logging system.
        • firewall_ai.py – Continuously analyzes packet logs and generates intelligent rule suggestions based on abnormal patterns.
        • cpff_ipc_client.py – Handles inter-process communication (IPC) between GUI and the daemon using Windows named pipes.
        • GUI (PyQt6) – Offers a real-time control center with dashboards, rule editors, and a learning module.

        CPFF merges the principles of traditional network firewalls and modern adaptive AI systems. 
        It shows how a security tool can evolve by learning from its own traffic data.
        """)
        cpff_desc.setWordWrap(True)
        vbox.addWidget(cpff_desc)

        # === SECTION 3: BUILD YOUR OWN FIREWALL ===
        vbox.addWidget(QLabel("<h2>🧠 Build Your Own Packet Filtering Firewall (Step-by-Step Guide)</h2>"))
        build_guide = QTextEdit()
        build_guide.setReadOnly(True)
        build_guide.setStyleSheet("background:#1e1e1e; color:#dcdcdc; font-family:Consolas; font-size:13px;")
        build_guide.setPlainText(
            """# 🧱 Building a Packet Filtering Firewall in Python (Concept + Practice)

[1] Install required libraries
    pip install pydivert pyyaml jsonlines geoip2

[2] Capture packets using WinDivert
    from pydivert import WinDivert
    with WinDivert("inbound and ip") as w:
        for packet in w:
            print(packet.src_addr, "->", packet.dst_addr)
            w.send(packet)  # reinject packet after inspection

[3] Define filtering rules
    rules = [
        {"id":1, "action":"block", "protocol":"TCP", "dst_port":8080, "comment":"Block HTTP traffic"},
        {"id":2, "action":"allow"}
    ]

[4] Match rules
    for packet in w:
        match = None
        for rule in rules:
            if rule["action"] == "block" and packet.dst_port == rule["dst_port"]:
                match = rule
                break
        if match:
            continue  # drop packet
        w.send(packet)

[5] Add logging
    Log allowed/blocked packets using jsonlines for analysis:
    import jsonlines
    with jsonlines.open("logs/firewall.jsonl", mode="a") as writer:
        writer.write({"src":packet.src_addr, "dst":packet.dst_addr, "action":action})

[6] Enhance with AI or analytics
    Use Python’s pandas and counters to detect repetitive attacks.
    Example: block any IP sending >100 connections in 1 minute.

[7] Create a GUI (optional)
    Use PyQt6 to visualize real-time stats, rules, and logs for educational and control purposes.
"""
        )
        vbox.addWidget(build_guide)

        # === SECTION 4: ADVANCED TOPICS ===
        advanced_info = QLabel("""
        <h2>⚙️ Advanced Concepts</h2>
        🔸 <b>Stateful vs Stateless Filtering</b><br>
        Stateless firewalls inspect packets individually, while stateful firewalls maintain a session table to track connection states.<br><br>

        🔸 <b>GeoIP Filtering</b><br>
        CPFF supports GeoIP lookups to block or allow traffic from specific countries based on IP mapping.<br><br>

        🔸 <b>Rate Limiting</b><br>
        Helps prevent DoS attacks by limiting the number of allowed packets from a source within a time window.<br><br>

        🔸 <b>AI-Assisted Rule Generation</b><br>
        CPFF’s AI analyzes packet logs, identifies suspicious patterns, and generates block suggestions. 
        It can automatically merge safe suggestions into your rule set.<br><br>

        🔸 <b>Packet Logging Format</b><br>
        Each packet entry is logged in JSONL format with details like timestamp, src_ip, dst_ip, ports, and matched rule ID.
        """)
        advanced_info.setWordWrap(True)
        vbox.addWidget(advanced_info)

        # === SECTION 5: SIMULATION TOOL ===
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

        # === SECTION 6: REFERENCES ===
        references = QLabel("""
        <h2>📚 Further Reading & Resources</h2>
        • <b>RFC 2979</b> – Behavior of and Requirements for Internet Firewalls<br>
        • <b>WinDivert Documentation</b> – https://reqrypt.org/windivert.html<br>
        • <b>Python Network Programming</b> – Python docs & socket library<br>
        • <b>AI in Security</b> – Research on adaptive intrusion detection and learning firewalls<br><br>
        Explore the codebase of CPFF to understand how a Python-based firewall can bridge education and real-world cybersecurity.
        """)
        references.setWordWrap(True)
        vbox.addWidget(references)

        footer = QLabel("<i>CPFF Educational Module © 2025 • Designed for research, learning, and innovation.</i>")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet("color:gray; margin-top:10px;")
        vbox.addWidget(footer)

        container.setLayout(vbox)
        scroll.setWidget(container)
        layout.addWidget(scroll)
        self.setLayout(layout)

    def simulate_rule(self):
        """Simple YAML-based rule simulation."""
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
