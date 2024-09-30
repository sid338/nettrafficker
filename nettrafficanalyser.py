from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {proto}")

        if TCP in packet:
            print(f"TCP Packet - Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
            print(f"Payload: {bytes(packet[TCP].payload)}")

        elif UDP in packet:
            print(f"UDP Packet - Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")
            print(f"Payload: {bytes(packet[UDP].payload)}")

        print("\n")

def main():
    # Start sniffing packets
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
