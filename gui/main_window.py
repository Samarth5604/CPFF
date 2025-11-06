# gui/main_window.py
from PyQt6.QtWidgets import QMainWindow, QTabWidget
from .dashboard_tab import DashboardTab
from .rules_tab import RulesTab
from .logs_tab import LogsTab

# optional educational tab (if file exists)
try:
    from .educational_tab import EducationalTab
    HAS_LEARN = True
except ImportError:
    HAS_LEARN = False

class CPFFGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CPFF - Firewall Control Center")
        self.resize(1150, 750)

        # keep it accessible as self.tabs (for older compatibility)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # add base tabs
        self.tabs.addTab(DashboardTab(), "Dashboard")
        self.tabs.addTab(RulesTab(), "Rules")
        self.tabs.addTab(LogsTab(), "Logs")

        # optional Learn / Educational tab
        if HAS_LEARN:
            try:
                learn = EducationalTab()
                self.tabs.addTab(learn, "Learn")
            except Exception as e:
                print(f"[WARN] Failed to load Learn tab: {e}")
