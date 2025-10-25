import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess, sys, os, threading, time, psutil, yaml, json, ctypes

MODULES = {
    "Sniffer": "sniffer.py",
    "Blocker": "blocker.py",
    "Firewall": "firewall.py"
}

running_processes = {}
LOG_PATH = "firewall_log.jsonl"
RULES_PATH = "rules.yaml"

# --- Helper functions ---

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def start_module(name):
    if name in running_processes:
        messagebox.showinfo("Info", f"{name} is already running.")
        return
    script = MODULES[name]
    if not os.path.exists(script):
        messagebox.showerror("Error", f"{script} not found.")
        return
    proc = subprocess.Popen([sys.executable, script])
    running_processes[name] = psutil.Process(proc.pid)
    update_status()
    log_console.insert(tk.END, f"[+] Started {name}\n")
    log_console.see(tk.END)

def stop_module(name):
    proc = running_processes.get(name)
    if not proc:
        messagebox.showinfo("Info", f"{name} not running.")
        return
    proc.terminate()
    proc.wait(timeout=5)
    del running_processes[name]
    update_status()
    log_console.insert(tk.END, f"[-] Stopped {name}\n")
    log_console.see(tk.END)

def stop_all():
    for name in list(running_processes.keys()):
        stop_module(name)

def update_status():
    for name, label in status_labels.items():
        if name in running_processes and running_processes[name].is_running():
            label.config(text="Running", foreground="green")
        else:
            label.config(text="Stopped", foreground="red")

def load_rules():
    if not os.path.exists(RULES_PATH):
        messagebox.showerror("Error", "rules.yaml not found.")
        return
    with open(RULES_PATH, "r") as f:
        data = yaml.safe_load(f)
    rule_text = json.dumps(data, indent=2)
    rules_window = tk.Toplevel(root)
    rules_window.title("Current Firewall Rules")
    text_box = scrolledtext.ScrolledText(rules_window, wrap=tk.WORD, width=80, height=25)
    text_box.insert(tk.END, rule_text)
    text_box.pack(padx=10, pady=10)
    text_box.config(state="disabled")

def follow_log():
    """Continuously read firewall_log.jsonl."""
    last_size = 0
    while True:
        try:
            if os.path.exists(LOG_PATH):
                size = os.path.getsize(LOG_PATH)
                if size > last_size:
                    with open(LOG_PATH, "r") as f:
                        f.seek(last_size)
                        new_data = f.read()
                        if new_data.strip():
                            log_console.insert(tk.END, new_data)
                            log_console.see(tk.END)
                    last_size = size
        except Exception as e:
            log_console.insert(tk.END, f"[Error reading log] {e}\n")
        time.sleep(2)

# --- GUI Setup ---
root = tk.Tk()
root.title("Windows Firewall Controller")
root.geometry("900x600")
root.configure(bg="#202020")

if not is_admin():
    messagebox.showwarning("Administrator Required", "Please run this program as Administrator.")
    root.destroy()
    sys.exit(1)

title_label = tk.Label(root, text="Custom Packet-Filtering Firewall", font=("Segoe UI", 16, "bold"), fg="white", bg="#202020")
title_label.pack(pady=10)

frame = tk.Frame(root, bg="#202020")
frame.pack(pady=5)

status_labels = {}
for i, name in enumerate(MODULES.keys()):
    tk.Label(frame, text=name, width=12, anchor="w", bg="#202020", fg="white", font=("Segoe UI", 12, "bold")).grid(row=i, column=0, padx=10, pady=5)
    btn_start = ttk.Button(frame, text="Start", width=10, command=lambda n=name: start_module(n))
    btn_stop = ttk.Button(frame, text="Stop", width=10, command=lambda n=name: stop_module(n))
    btn_start.grid(row=i, column=1, padx=5, pady=5)
    btn_stop.grid(row=i, column=2, padx=5, pady=5)
    status_labels[name] = tk.Label(frame, text="Stopped", width=10, bg="#202020", fg="red", font=("Segoe UI", 11))
    status_labels[name].grid(row=i, column=3, padx=5, pady=5)

# --- Log Display ---
log_label = tk.Label(root, text="Firewall Logs", bg="#202020", fg="white", font=("Segoe UI", 13, "bold"))
log_label.pack()
log_console = scrolledtext.ScrolledText(root, width=110, height=20, bg="#111", fg="lightgreen", insertbackground="white", wrap=tk.WORD)
log_console.pack(padx=10, pady=5)

# --- Control Buttons ---
control_frame = tk.Frame(root, bg="#202020")
control_frame.pack(pady=10)
ttk.Button(control_frame, text="View Rules", command=load_rules).grid(row=0, column=0, padx=10)
ttk.Button(control_frame, text="Stop All", command=stop_all).grid(row=0, column=1, padx=10)
ttk.Button(control_frame, text="Exit", command=lambda: (stop_all(), root.destroy())).grid(row=0, column=2, padx=10)

# --- Background Log Thread ---
threading.Thread(target=follow_log, daemon=True).start()

# --- Periodic Status Refresh ---
def periodic_status():
    update_status()
    root.after(3000, periodic_status)

periodic_status()
root.mainloop()
