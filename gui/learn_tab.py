from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel, QPushButton, QHBoxLayout
from PyQt6.QtCore import Qt

class LearnTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        title = QLabel("🧠 Learn About Firewalls & CPFF")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title)

        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setStyleSheet("background-color: #1e1e1e; color: #e0e0e0; font-family: Consolas; font-size: 14px;")
        layout.addWidget(self.text)

        btns = QHBoxLayout()
        self.btn_intro = QPushButton("Introduction")
        self.btn_how = QPushButton("How Firewalls Work")
        self.btn_cpff = QPushButton("Inside CPFF")
        self.btn_build = QPushButton("Build Your Own")
        for b in [self.btn_intro, self.btn_how, self.btn_cpff, self.btn_build]:
            btns.addWidget(b)
        layout.addLayout(btns)

        self.btn_intro.clicked.connect(self.show_intro)
        self.btn_how.clicked.connect(self.show_how_firewalls_work)
        self.btn_cpff.clicked.connect(self.show_cpff_details)
        self.btn_build.clicked.connect(self.show_build_guide)

        self.show_intro()

    def show_intro(self):
        self.text.setPlainText("""
🧱 What is a Firewall?

A firewall is a network security system that monitors and controls incoming
and outgoing network traffic based on predetermined rules.

Firewalls create a barrier between a trusted internal network and untrusted
external networks such as the internet.

There are different types of firewalls:
 - **Packet-filtering firewalls** (like CPFF)
 - **Stateful inspection firewalls**
 - **Proxy firewalls**
 - **Next-generation firewalls**

CPFF is an educational packet-filtering firewall built in Python
to help students understand the internal logic and flow of network filtering.
        """)

    def show_how_firewalls_work(self):
        self.text.setPlainText("""
⚙️ How Firewalls Work

Firewalls operate by matching packets against a set of filtering rules.

Each rule defines:
 - The **protocol** (TCP, UDP, ICMP)
 - The **source or destination IP**
 - The **port number**
 - The **action**: allow or block

Example:
    action: block
    protocol: TCP
    dst_port: 80
    comment: Block HTTP traffic

When a packet arrives:
 1. The firewall reads its headers (source IP, dest IP, protocol, ports)
 2. It checks each rule in order of **priority**
 3. If a rule matches, the **action** is applied (allow/block)
 4. If no rule matches, a **default policy** is used (usually allow)

This is how packet-filtering firewalls like CPFF work internally.
        """)

    def show_cpff_details(self):
        self.text.setPlainText("""
🧩 Inside CPFF

CPFF (Custom Packet Filtering Firewall) is a Python-based learning project
that simulates a simplified firewall using WinDivert for Windows.

Modules:

 1. **firewall_core.py** → Handles rule parsing, matching, and logging.
 2. **firewall_daemon.py** → The background service that processes packets.
 3. **firewall_client.py** → CLI for managing rules and monitoring.
 4. **firewall_ai.py** → Analyzes logs to suggest new rules automatically.
 5. **GUI (PyQt6)** → A graphical dashboard for managing and visualizing activity.

Main Concepts:
 - YAML-based rule engine
 - Rate limiting and GeoIP-based blocking
 - Packet profiling (rule hit counting)
 - Asynchronous logging (JSONL)
 - AI rule suggestion

The GUI interacts with the daemon using an IPC channel (Named Pipe on Windows).
        """)

    def show_build_guide(self):
        self.text.setPlainText("""
🛠️ How to Build Your Own Firewall (Educational Guide)

1️⃣ Understand the basics:
   - Learn about networking: IP addresses, ports, TCP/UDP protocols.
   - Study how packets move through network layers.

2️⃣ Start small:
   - Use libraries like **Scapy** or **PyDivert** for packet capture.
   - Print packet summaries before filtering anything.

3️⃣ Add filtering:
   - Define rules as dictionaries or YAML files.
   - Write a function to match each packet to a rule.

4️⃣ Log and monitor:
   - Save each processed packet to a JSONL log file.
   - Add counters for blocked vs allowed packets.

5️⃣ Optional enhancements:
   - Add rate limiting (token bucket algorithm)
   - Add GeoIP lookups (MaxMind)
   - Build a small GUI (like CPFF!)

Example (mini snippet):

    from pydivert import WinDivert

    with WinDivert("true") as w:
        for packet in w:
            if packet.dst_port == 80:
                print("Blocked HTTP packet!")
                continue
            w.send(packet)

This minimal example forms the base of a packet filter.

CPFF expands on this idea with structured rules, logging,
profiling, AI learning, and a beautiful dashboard.
        """)
