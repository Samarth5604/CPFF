import pydivert

with pydivert.WinDivert("tcp.DstPort == 80") as w:
    print("Blocking all outbound HTTP traffic...")
    for packet in w:
        print(f"Blocked: {packet.src_addr} → {packet.dst_addr}:{packet.dst_port}")
        # Dropping the packet (not reinjecting)
