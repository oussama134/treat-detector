import os
import subprocess
import numpy as np
import pandas as pd
import joblib
import torch
from torch import nn
import pyshark
import asyncio

# ======================
# CONFIG
# ======================
SEQ_LEN = 5
MODEL_PATH = r"..\models\lstm_cicids.pth"
SCALER_PATH = r"..\models\scaler.pkl"
LABEL_ENCODER_PATH = r"..\models\label_encoder.pkl"
PCAP_OUTPUT = "live_traffic.pcap"

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ======================
# 1. Capture using tshark
# ======================
def capture_live_pcap(duration=10):
    
    
    print(f"[+] Capturing {duration}s using tshark...")
    
   
    subprocess.run([
        r"C:\Program Files\Wireshark\tshark.exe",
        "-i", "4",              # <---- Force Wi-Fi 2
        "-a", f"duration:{duration}",
        "-w", PCAP_OUTPUT
    ], check=True)

    print("[+] Capture complete:", PCAP_OUTPUT)



# ======================
# Pyshark safe capture (fix event-loop crash)
# ======================
def safe_file_capture(path):
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    return pyshark.FileCapture(path, keep_packets=False)


# ======================
# 2. Extract flows (78 features)
# ======================
def pcap_to_flows(pcap_path):
    print("[+] Extracting flows...")

    cap = safe_file_capture(pcap_path)
    flows = {}

    for pkt in cap:
        try:
            proto = pkt.highest_layer
            src = pkt.ip.src
            dst = pkt.ip.dst
            sport = pkt[pkt.transport_layer].srcport
            dport = pkt[pkt.transport_layer].dstport
            length = int(pkt.length)
            ts = float(pkt.sniff_timestamp)
        except:
            continue

        key = (src, dst, sport, dport, proto)

        if key not in flows:
            flows[key] = {"lengths": [], "times": []}

        flows[key]["lengths"].append(length)
        flows[key]["times"].append(ts)

    # ---- Feature Engineering ----
    feature_rows = []
    for (src, dst, sport, dport, proto), f in flows.items():

        lengths = np.array(f["lengths"])
        times = np.array(f["times"])

        iats = np.diff(times) if len(times) > 1 else [0]

        row = [
            len(lengths),
            lengths.mean(),
            lengths.std() if len(lengths) > 1 else 0,
            lengths.min(),
            lengths.max(),
            np.median(lengths),
            np.mean(iats),
            np.std(iats) if len(iats) > 1 else 0,
            times[-1] - times[0],
        ]

        # pad to 78 features
        while len(row) < 78:
            row.append(0)

        feature_rows.append(row)

    df = pd.DataFrame(feature_rows)
    print(f"[+] Extracted {len(df)} flows.")
    return df


# ======================
# 3. Preprocess (scaler)
# ======================
def preprocess(df):
    scaler = joblib.load(SCALER_PATH)
    df = df.astype(np.float32)
    return scaler.transform(df)


# ======================
# 4. Build sequences
# ======================
def build_sequences(features):
    if len(features) < SEQ_LEN:
        print("[-] Not enough flows for one sequence.")
        return None

    seqs = []

    for i in range(len(features) - SEQ_LEN + 1):
        seqs.append(features[i:i+SEQ_LEN])

    return np.array(seqs, dtype=np.float32)


# ======================
# 5. LSTM Model
# ======================
class LSTMModel(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=2, num_classes=15):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        out, _ = self.lstm(x)
        out = out[:, -1, :]
        return self.fc(out)


def load_model(input_dim, num_classes):
    model = LSTMModel(input_dim, 64, 2, num_classes).to(DEVICE)
    model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE))
    model.eval()
    return model


# ======================
# MAIN
# ======================
if __name__ == "__main__":
    capture_live_pcap(10)

    df = pcap_to_flows(PCAP_OUTPUT)
    if df.empty:
        print("[-] No flows extracted.")
        exit()

    X_scaled = preprocess(df)
    X_seq = build_sequences(X_scaled)
    if X_seq is None:
        exit()

    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    num_classes = len(label_encoder.classes_)

    model = load_model(df.shape[1], num_classes)

    X_tensor = torch.tensor(X_seq, dtype=torch.float32).to(DEVICE)
    logits = model(X_tensor)
    preds = torch.argmax(logits, dim=1).cpu().numpy()

    print("\n=== RESULTS ===")
    for i, p in enumerate(preds):
        print(f"Seq {i+1}: {label_encoder.classes_[p]}")
