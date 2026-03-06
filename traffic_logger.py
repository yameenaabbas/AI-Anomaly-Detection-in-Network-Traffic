anomaly_model.pkl
from scapy.all import sniff
from collections import Counter
from datetime import datetime
import csv

print("Program Started")

# ---------------- GLOBAL VARIABLES ----------------
packets_per_sec = 0
ip_counter = Counter()
tcp_count = 0
udp_count = 0

pps_history = []
unique_history = []

attack_active = False

baseline_pps = []
baseline_unique = []
learning_phase = True
seconds_passed = 0


# ---------------- PACKET PROCESSOR ----------------
def process_packet(packet):
    global packets_per_sec, tcp_count, udp_count

    packets_per_sec += 1

    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        ip_counter[src_ip] += 1

    if packet.haslayer("TCP"):
        tcp_count += 1

    if packet.haslayer("UDP"):
        udp_count += 1


# ---------------- CSV HEADER (ONLY FIRST TIME) ----------------
try:
    with open("traffic_data.csv", "x", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Timestamp",
            "PPS",
            "Unique_IPs",
            "Top_IP_Count",
            "TCP_Count",
            "UDP_Count"
        ])
except FileExistsError:
    pass


# ---------------- MAIN LOOP ----------------
model = joblib.load("anomaly_model.pkl")
while True:
    sniff(timeout=1, prn=process_packet)

    timestamp = datetime.now().strftime("%H:%M:%S")
    unique_ips = len(ip_counter)

    seconds_passed += 1

    # ---- Store PPS history (5 sec window) ----
    pps_history.append(packets_per_sec)
    if len(pps_history) > 5:
        pps_history.pop(0)

    # ---- Store Unique IP history (5 sec window) ----
    unique_history.append(unique_ips)
    if len(unique_history) > 5:
        unique_history.pop(0)

    average_pps = sum(pps_history) / len(pps_history)
    average_unique = sum(unique_history) / len(unique_history)

   # ---------------- LEARNING PHASE ----------------
    if learning_phase:
    print("📘 Learning baseline...")

    # Only learn if traffic is not too high (prevent poisoning)
    if packets_per_sec < 100:
        baseline_pps.append(average_pps)
        baseline_unique.append(average_unique)

    if seconds_passed >= 30:
        learning_phase = False
        print("✅ Baseline Learning Complete")

    # ---------------- DYNAMIC DETECTION ----------------
     features = [[packets_per_sec, unique_ips, tcp_count, udp_count]]
    prediction = model.predict(features)

    if prediction[0] == -1:
    if not attack_active:
        print("🚨 AI Detected Anomaly")
        attack_active = True
    else:
    if attack_active:
        print("✅ Traffic Back to Normal")
        attack_active = False

    # ---------------- PRINT LIVE STATS ----------------
    print(f"{timestamp} | PPS: {packets_per_sec} | Unique IPs: {unique_ips}")

    # ---------------- TOP IP COUNT ----------------
    if ip_counter:
        top_ip_count = ip_counter.most_common(1)[0][1]
    else:
        top_ip_count = 0

    # ---------------- CSV LOGGING ----------------
    with open("traffic_data.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp,
            packets_per_sec,
            unique_ips,
            top_ip_count,
            tcp_count,
            udp_count
        ])

    # ---------------- RESET COUNTERS ----------------
    packets_per_sec = 0
    ip_counter.clear()
    tcp_count = 0
    udp_count = 0