import subprocess
import sys
import ctypes
import os
import psutil

MODULES = {
    "sniffer": "sniffer.py",
    "blocker": "blocker.py",
    "firewall": "firewall.py"
}

running_processes = {}

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def start_module(choice):
    if choice in running_processes:
        print(f"[!] {choice} is already running.")
        return
    script = MODULES.get(choice)
    if not script or not os.path.exists(script):
        print(f"[!] Script not found: {script}")
        return
    print(f"[+] Starting {choice}...")
    proc = subprocess.Popen([sys.executable, script])
    running_processes[choice] = psutil.Process(proc.pid)

def stop_module(choice):
    proc = running_processes.get(choice)
    if not proc:
        print(f"[!] {choice} not running.")
        return
    print(f"[*] Stopping {choice}...")
    proc.terminate()
    proc.wait(timeout=5)
    del running_processes[choice]

def stop_all():
    for choice in list(running_processes.keys()):
        stop_module(choice)

def pause_all():
    for proc in running_processes.values():
        try:
            proc.suspend()
        except Exception:
            pass

def resume_all():
    for proc in running_processes.values():
        try:
            proc.resume()
        except Exception:
            pass
        
def menu():
    print("\n=== Windows Firewall ===")
    print("Running:", ", ".join(running_processes.keys()) or "None")
    print("1. Start Sniffer")
    print("2. Start Blocker")
    print("3. Start Firewall")
    print("4. Stop Sniffer")
    print("5. Stop Blocker")
    print("6. Stop Firewall")
    print("7. Exit")

    choice = input("\nEnter choice: ").strip()
    if choice == "1":
        start_module("sniffer")
    elif choice == "2":
        start_module("blocker")
    elif choice == "3":
        start_module("firewall")
    elif choice == "4":
        stop_module("sniffer")
    elif choice == "5":
        stop_module("blocker")
    elif choice == "6":
        stop_module("firewall")
    elif choice == "7":
        stop_all()
        sys.exit(0)
    else:
        print("[!] Invalid choice.")

if __name__ == "__main__":
    if not is_admin():
        print("[!] Please run as Administrator.")
        sys.exit(1)

    while True:
        input("\n[*] Press ENTER to open menu (pauses all running tasks)...")
        pause_all()
        menu()
        resume_all()
