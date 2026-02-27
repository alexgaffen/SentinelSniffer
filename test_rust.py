import sentinel_sniffer

print("--- HARDWARE DIAGNOSTIC ---")
interfaces = sentinel_sniffer.get_interfaces()

for iface in interfaces:
    print(iface)

print("\n--- ATTEMPTING CAPTURE ---")
try:
    packets = sentinel_sniffer.sniff_packets(10)
    for p in packets:
        print(p)
    print("SUCCESS: Capture operational!")
except Exception as e:
    print(f"FAILED: {e}")