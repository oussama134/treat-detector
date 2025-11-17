import os
from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
from collections import defaultdict
from tqdm import tqdm

# === CONFIG ===
pcap_file = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\captured\attack_traffic.pcap"

# === READ PCAP ===
print(f"[+] Loading packets from {pcap_file} ...")
packets = rdpcap(pcap_file)
print(f"[+] Total packets loaded: {len(packets)}")

# === BUILD FLOWS ===
flows = defaultdict(list)

for pkt in tqdm(packets, desc="Processing packets"):
    if IP in pkt:
        ip_layer = pkt[IP]
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
        src = ip_layer.src
        dst = ip_layer.dst
        sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else 0
        dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0
        key = (src, dst, sport, dport, proto)
        flows[key].append(pkt)

print(f"[+] Total flows detected: {len(flows)}")

# === EXTRACT FEATURES ===
def extract_features(flow_packets):
    sizes = [len(pkt) for pkt in flow_packets]
    times = [pkt.time for pkt in flow_packets]
    times = np.diff(times) if len(times) > 1 else [0]

    return {
        "packet_count": len(flow_packets),
        "bytes_total": sum(sizes),
        "bytes_mean": np.mean(sizes),
        "bytes_std": np.std(sizes),
        "inter_arrival_mean": np.mean(times),
        "inter_arrival_std": np.std(times),
        "min_size": np.min(sizes),
        "max_size": np.max(sizes),
        "duration": flow_packets[-1].time - flow_packets[0].time if len(flow_packets) > 1 else 0,
    }

rows = []
for key, flow_packets in tqdm(flows.items(), desc="Extracting features"):
    src, dst, sport, dport, proto = key
    features = extract_features(flow_packets)
    row = {"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto}
    row.update(features)
    rows.append(row)

# === SAVE TO CSV ===
df = pd.DataFrame(rows)
output_path = os.path.join(os.path.dirname(pcap_file), "extracted_features.csv")
df.to_csv(output_path, index=False)

print(f"[+] Done! Features saved to: {output_path}")
print(df.head())
