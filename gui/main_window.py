from PyQt6.QtWidgets import QMainWindow, QTabWidget
from gui.dashboard_tab import DashboardTab
from gui.rules_tab import RulesTab
from gui.logs_tab import LogsTab

class CPFFGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CPFF Firewall Dashboard")
        self.setMinimumSize(1050, 720)

        self.tabs = QTabWidget()
        self.dashboard = DashboardTab()
        self.rules = RulesTab()
        self.logs = LogsTab()

        self.tabs.addTab(self.dashboard, "Dashboard")
        self.tabs.addTab(self.rules, "Rules")
        self.tabs.addTab(self.logs, "Logs")
        from gui.learn_tab import LearnTab
        learn = LearnTab()
        self.tabs.addTab(learn, "Learn")
        self.setCentralWidget(self.tabs)
