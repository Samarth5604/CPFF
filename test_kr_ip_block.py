#test_kr_ip_block.py
from scapy.all import IP, TCP, send

# Example South Korean IPs (random public ones, non-routable for safety)
kr_ips = ["211.45.27.5", "58.120.1.10", "121.128.1.50"]

for ip in kr_ips:
    pkt = IP(src=ip, dst="8.8.8.8") / TCP(dport=80, flags="S")
    send(pkt, verbose=False)
    print(f"Sent test packet from simulated KR IP: {ip}")
