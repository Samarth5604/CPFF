import socket
import threading
import time
import psutil
import os
import json
import csv
from datetime import datetime

# -----------------------
# Configurations
# -----------------------
TEST_DURATION = 15          # seconds per test phase
PACKET_SIZE = 1024          # bytes
UDP_PORT = 9999
TCP_PORT = 9998
BENCHMARK_DIR = "benchmark_results"
FIREWALL_PROCESS_NAME = "firewall_daemon.py"

os.makedirs(BENCHMARK_DIR, exist_ok=True)


# -----------------------
# Helper Functions
# -----------------------
def find_firewall_proc():
    """Locate the CPFF daemon process safely."""
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = p.info.get('cmdline') or []  # fallback to empty list if None
            if any(FIREWALL_PROCESS_NAME in str(arg) for arg in cmdline):
                return psutil.Process(p.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None



def udp_server(stop_event):
    """Simple UDP echo server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", UDP_PORT))
    s.settimeout(1)
    while not stop_event.is_set():
        try:
            data, addr = s.recvfrom(4096)
            s.sendto(data, addr)
        except socket.timeout:
            continue
        except Exception:
            break
    s.close()


def tcp_server(stop_event):
    """Simple TCP echo server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", TCP_PORT))
    s.listen(5)
    s.settimeout(1)
    while not stop_event.is_set():
        try:
            conn, addr = s.accept()
            data = conn.recv(4096)
            if not data:
                conn.close()
                continue
            conn.sendall(data)
            conn.close()
        except socket.timeout:
            continue
        except Exception:
            break
    s.close()


def traffic_test(proto="udp", duration=TEST_DURATION, packet_size=PACKET_SIZE):
    """Generate local network traffic and measure throughput."""
    print(f"[*] Running {proto.upper()} test for {duration}s...")

    stop_event = threading.Event()
    server_thread = threading.Thread(target=udp_server if proto == "udp" else tcp_server, args=(stop_event,))
    server_thread.start()

    time.sleep(1)  # Give server time to start

    start = time.time()
    packets = 0
    bytes_sent = 0
    data = b"x" * packet_size

    if proto == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while time.time() - start < duration:
            s.sendto(data, ("127.0.0.1", UDP_PORT))
            packets += 1
            bytes_sent += len(data)
        s.close()
    else:  # TCP
        while time.time() - start < duration:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("127.0.0.1", TCP_PORT))
                s.sendall(data)
                s.close()
                packets += 1
                bytes_sent += len(data)
            except Exception:
                continue

    stop_event.set()
    server_thread.join()

    elapsed = time.time() - start
    mbps = (bytes_sent * 8) / (elapsed * 1e6)
    pps = packets / elapsed
    print(f"[+] {proto.upper()} Test Complete → {mbps:.2f} Mbps, {pps:.0f} pkt/s\n")
    return mbps, pps


def monitor_firewall(proc, duration):
    """Monitor CPU and memory usage of CPFF."""
    cpu_samples = []
    mem_samples = []
    start = time.time()

    while time.time() - start < duration:
        try:
            cpu_samples.append(proc.cpu_percent(interval=0.2))
            mem_samples.append(proc.memory_info().rss / (1024 * 1024))
        except psutil.NoSuchProcess:
            break

    avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0
    avg_mem = sum(mem_samples) / len(mem_samples) if mem_samples else 0
    return avg_cpu, avg_mem


def run_benchmark():
    """Main benchmarking routine."""
    print("[*] Starting CPFF performance benchmark...")
    fw_proc = find_firewall_proc()

    if not fw_proc:
        print("[!] Firewall process not found. Ensure firewall_daemon.py is running.")
        return

    print(f"[+] Monitoring firewall PID: {fw_proc.pid}\n")

    # Run UDP and TCP tests sequentially
    results = {}
    cpu_thread = threading.Thread(target=monitor_firewall, args=(fw_proc, TEST_DURATION * 2))
    cpu_thread.start()

    udp_mbps, udp_pps = traffic_test("udp")
    tcp_mbps, tcp_pps = traffic_test("tcp")

    cpu_thread.join()
    avg_cpu, avg_mem = monitor_firewall(fw_proc, 1)

    results = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "udp_mbps": udp_mbps,
        "udp_pps": udp_pps,
        "tcp_mbps": tcp_mbps,
        "tcp_pps": tcp_pps,
        "cpu_avg_percent": avg_cpu,
        "mem_avg_mb": avg_mem,
    }

    # Save JSON
    json_path = os.path.join(BENCHMARK_DIR, f"cpff_benchmark_{int(time.time())}.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[+] Saved JSON → {json_path}")

    # Append to CSV
    csv_path = os.path.join(BENCHMARK_DIR, "cpff_summary.csv")
    write_header = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=list(results.keys()))
        if write_header:
            writer.writeheader()
        writer.writerow(results)
    print(f"[+] Appended results → {csv_path}")

    print("\n✅ Benchmark complete!")


if __name__ == "__main__":
    run_benchmark()
