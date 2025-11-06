# main.py
import sys
import warnings
from PyQt6.QtWidgets import QApplication
# local import
from gui.main_window import CPFFGUI

# suppress some noisy warnings that can cause slight slowdowns during UI bootstrap
warnings.filterwarnings("ignore", category=RuntimeWarning)

def main():
    app = QApplication(sys.argv)
    # use a compact style for smoother rendering on Windows
    try:
        app.setStyle("Fusion")
    except Exception:
        pass

    w = CPFFGUI()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
