# flowmeter.py
# Lightweight CICFlowMeter-like flow generator
# Creates flow-level features similar to CICIDS2017

import sys
import pandas as pd
from scapy.all import rdpcap, TCP, UDP, IP
import numpy as np
from collections import defaultdict

def compute_stats(values):
    if len(values) == 0:
        return 0, 0, 0, 0
    return (
        float(np.mean(values)),
        float(np.std(values)) if len(values) > 1 else 0,
        float(np.min(values)),
        float(np.max(values)),
    )

def extract_flows(pcap_path):
    pkts = rdpcap(pcap_path)
    flows = defaultdict(list)

    for p in pkts:
        if IP not in p:
            continue

        src = p[IP].src
        dst = p[IP].dst
        proto = p[IP].proto

        sport = p.sport if hasattr(p, "sport") else 0
        dport = p.dport if hasattr(p, "dport") else 0

        key = tuple(sorted([(src, dst), (sport, dport)]) + [proto])

        timestamp = float(p.time)
        size = len(p)

        direction = 1 if (src, sport) == key[0] else -1

        # Flags
        flags = ""
        if TCP in p:
            flags = p[TCP].flags

        flows[key].append({
            "timestamp": timestamp,
            "size": size,
            "direction": direction,
            "flags": flags,
        })

    return flows

def build_features(flows):
    rows = []

    for key, pkt_list in flows.items():
        pkt_list = sorted(pkt_list, key=lambda x: x["timestamp"])

        sizes = [p["size"] for p in pkt_list]
        timestamps = [p["timestamp"] for p in pkt_list]

        # Forward / Backward
        fwd_sizes = [p["size"] for p in pkt_list if p["direction"] == 1]
        bwd_sizes = [p["size"] for p in pkt_list if p["direction"] == -1]

        fwd_times = [p["timestamp"] for p in pkt_list if p["direction"] == 1]
        bwd_times = [p["timestamp"] for p in pkt_list if p["direction"] == -1]

        iat_all = np.diff(timestamps) if len(timestamps) > 1 else [0]
        iat_fwd = np.diff(fwd_times) if len(fwd_times) > 1 else [0]
        iat_bwd = np.diff(bwd_times) if len(bwd_times) > 1 else [0]

        row = {
            "Flow Duration": timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0,

            "Total Fwd Packets": len(fwd_sizes),
            "Total Backward Packets": len(bwd_sizes),

            "Total Length of Fwd Packets": sum(fwd_sizes),
            "Total Length of Bwd Packets": sum(bwd_sizes),

            "Fwd Packet Length Mean": np.mean(fwd_sizes) if fwd_sizes else 0,
            "Bwd Packet Length Mean": np.mean(bwd_sizes) if bwd_sizes else 0,
        }

        # Add statistics
        (row["Packet Length Mean"],
         row["Packet Length Std"],
         row["Packet Length Min"],
         row["Packet Length Max"]) = compute_stats(sizes)

        (row["IAT Mean"],
         row["IAT Std"],
         row["IAT Min"],
         row["IAT Max"]) = compute_stats(iat_all)

        (row["Fwd IAT Mean"],
         row["Fwd IAT Std"],
         row["Fwd IAT Min"],
         row["Fwd IAT Max"]) = compute_stats(iat_fwd)

        (row["Bwd IAT Mean"],
         row["Bwd IAT Std"],
         row["Bwd IAT Min"],
         row["Bwd IAT Max"]) = compute_stats(iat_bwd)

        rows.append(row)

    return pd.DataFrame(rows)

def main():
    if len(sys.argv) < 3:
        print("Usage: python flowmeter.py input.pcap output.csv")
        return

    pcap = sys.argv[1]
    out = sys.argv[2]

    print(f"➡️ Reading PCAP: {pcap}")
    flows = extract_flows(pcap)

    print(f"➡️ Building features ({len(flows)} flows)...")
    df = build_features(flows)

    print(f"➡️ Saving CSV: {out}")
    df.to_csv(out, index=False)

    print("✅ Done!")

if __name__ == "__main__":
    main()
