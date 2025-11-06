import sys
import subprocess
import os

def main():
    if "--cli" in sys.argv:
        subprocess.run([sys.executable, "firewall_client.py"] + sys.argv[1:])
    else:
        from gui_main import main as gui_main
        gui_main()

if __name__ == "__main__":
    main()
