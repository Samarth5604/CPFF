# firewall_sniffer.py
import pydivert

# Capture all packets (use "true" as filter)
with pydivert.WinDivert("true") as w:
    print("Firewall is running... Press CTRL+C to stop.")
    for packet in w:
        print(packet)   # Print packet metadata
        w.send(packet)  # Allow packets (for now)
