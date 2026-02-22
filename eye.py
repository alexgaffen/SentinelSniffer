from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    # We only care about IP packets
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"
        
        # Get the packet size (Length)
        size = len(packet)
        
        # Print it to the console
        print(f"[{protocol}] {src_ip} -> {dst_ip} | Size: {size} bytes")

print("Sentinel Sniffer: The Eye is open. Listening for packets...")
print("Press Ctrl+C to stop.")

# Sniff 50 packets to test the connection.
# store=False means we don't keep them in RAM (prevents crashing)
sniff(prn=process_packet, count=50, store=False)