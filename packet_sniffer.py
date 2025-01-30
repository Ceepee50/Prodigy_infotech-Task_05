import scapy.all as scapy

def packet_sniffer(packet):

    if packet.haslayer(scapy.IP):

        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        if packet.haslayer(scapy.TCP):

            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport

            print(f"TCP Packet: Source IP: {src_ip} | Source Port: {src_port}")
            print(f"Destination IP: {dst_ip} | Destination Port: {dst_port}")

        elif packet.haslayer(scapy.UDP):

            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport

            print(f"UDP Packet: Source IP: {src_ip} | Source Port: {src_port}")
            print(f"Destination IP: {dst_ip} | Destination Port: {dst_port}")

    if packet.haslayer(scapy.Raw):
        print("Payload:")
        print(packet[scapy.Raw].load)

scapy.sniff(prn=packet_sniffer, store=False)
