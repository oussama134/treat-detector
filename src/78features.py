import asyncio
import sys

# Fix for Windows + Python 3.8+
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())



import pyshark
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler

# ------------------------------
# 1. Load PCAP
# ------------------------------
pcap_file = 'traffic.pcap'  # change to your pcap path
cap = pyshark.FileCapture(pcap_file, keep_packets=False)

# ------------------------------
# 2. Aggregate packets into flows
# ------------------------------
flows = {}  # key: (src, dst, sport, dport, proto)

for pkt in cap:
    try:
        proto = pkt.highest_layer
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        sport = int(pkt[pkt.transport_layer].srcport)
        dport = int(pkt[pkt.transport_layer].dstport)
        length = int(pkt.length)
        ts = float(pkt.sniff_timestamp)

        flags = int(pkt.tcp.flags, 16) if 'TCP' in proto.upper() else 0
    except AttributeError:
        continue

    key = (src_ip, dst_ip, sport, dport, proto)
    if key not in flows:
        flows[key] = {
            'lengths': [],
            'times': [],
            'flags': [],
            'proto': proto,
            'forward_pkts': 0,
            'backward_pkts': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
        }

    # classify direction
    flows[key]['lengths'].append(length)
    flows[key]['times'].append(ts)
    flows[key]['flags'].append(flags)
    flows[key]['forward_pkts'] += 1
    flows[key]['src_bytes'] += length

# ------------------------------
# 3. Compute 78 features per flow
# ------------------------------
feature_list = []
for key, f in flows.items():
    lengths = np.array(f['lengths'])
    times = np.array(f['times'])
    flags = np.array(f['flags'])
    iats = np.diff(times) if len(times) > 1 else [0]

    features = []

    # --- Flow basics ---
    features.append(len(lengths))                  # total packets
    features.append(len(lengths))                  # total forward packets (simplified)
    features.append(len(lengths))                  # total backward packets (dummy)
    features.append(lengths.sum())                 # total bytes
    features.append(f['src_bytes'])               # forward bytes
    features.append(f['dst_bytes'])               # backward bytes
    features.append(lengths.mean())               # mean packet length
    features.append(lengths.std() if len(lengths)>1 else 0)
    features.append(lengths.min())
    features.append(lengths.max())
    features.append(np.median(lengths))
    features.append(np.percentile(lengths, 25))
    features.append(np.percentile(lengths, 75))

    # --- Time features ---
    features.append(times[-1] - times[0])         # flow duration
    features.append(np.mean(iats))
    features.append(np.std(iats) if len(iats)>1 else 0)
    features.append(np.min(iats))
    features.append(np.max(iats))

    # --- TCP flags ---
    tcp_flags = [0]*6
    if 'TCP' in f['proto'].upper():
        tcp_flags = [
            np.sum(flags & 0x01),  # FIN
            np.sum(flags & 0x02),  # SYN
            np.sum(flags & 0x04),  # RST
            np.sum(flags & 0x08),  # PSH
            np.sum(flags & 0x10),  # ACK
            np.sum(flags & 0x20),  # URG
        ]
    features.extend(tcp_flags)

    # --- Additional stats (dummy placeholders for remaining features) ---
    remaining = 78 - len(features)
    features.extend([0]*remaining)

    feature_list.append(features)

# ------------------------------
# 4. Convert to DataFrame
# ------------------------------
df = pd.DataFrame(feature_list)
print("Features shape:", df.shape)  # (num_flows, 78)

# ------------------------------
# 5. Scale features for LSTM
# ------------------------------
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(df)
X_lstm = np.expand_dims(X_scaled, axis=1)  # shape: (samples, timesteps, features)

print("LSTM-ready shape:", X_lstm.shape)
