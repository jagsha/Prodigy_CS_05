from scapy.all import sniff, IP, Raw, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = "Unknown"

        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"

        print(f"\n[+] Protocol: {proto}")
        print(f"    Source IP      : {ip_layer.src}")
        print(f"    Destination IP : {ip_layer.dst}")

        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors='replace')
                print(f"    Payload        :\n{payload}")
            except Exception as e:
                print(f"    Payload        : (Could not decode payload: {e})")
        else:
            print("    Payload        : (No Raw payload)")

print("Starting packet analyzer... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
