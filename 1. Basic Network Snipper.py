# packet_sniffer.py
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    """
    Function to process each captured packet
    """
    print("="*60)
    
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")
        
        # Check for TCP, UDP, or ICMP
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print("Protocol Type  : TCP")
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print("Protocol Type  : UDP")
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            
        elif packet.haslayer(ICMP):
            print("Protocol Type  : ICMP")
        
        # Print Payload (if available)
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load
                print(f"Payload        : {payload[:50]}")  # Print first 50 bytes only
            except:
                print("Payload        : [Could not decode]")
    else:
        print("Non-IP Packet Captured")

# Capture packets
print("Starting packet capture... (Press CTRL+C to stop)\n")
sniff(prn=packet_callback, store=False)