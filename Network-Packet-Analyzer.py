from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    """
    print("\nPacket Captured:")
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
        
        if TCP in packet:
            print("Protocol Type: TCP")
        elif UDP in packet:
            print("Protocol Type: UDP")
        elif ICMP in packet:
            print("Protocol Type: ICMP")
        
        # Display payload if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet.getlayer(packet.payload).payload).decode('utf-8', errors='ignore')
            print(f"Payload: {payload}")
        else:
            print("No payload data available.")

if __name__ == "__main__":
    print("Starting Packet Sniffer...")
    print("Press Ctrl+C to stop.\n")

    # Start sniffing packets on the default network interface
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nStopping Packet Sniffer.")
    except PermissionError:
        print("Permission denied. Run the program as an administrator or with sudo.")
