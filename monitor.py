from scapy.all import sniff
from collections import Counter
import time

packet_count = 0
ip_counter = Counter()

def process_packet(packet):
    global packet_count
    packet_count += 1

    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_counter[ip_src] += 1

def main():
    global packet_count, ip_counter

    print("Monitoring started... Press Ctrl+C to stop.\n")

    while True:
        packet_count = 0
        ip_counter = Counter()

        sniff(timeout=1, prn=process_packet, store=False)

        print(f"Packets per second: {packet_count}")
        print("Connections per IP:")
        for ip, count in ip_counter.items():
            print(f"{ip} -> {count}")
        print("-" * 40)

if __name__ == "__main__":
    main()