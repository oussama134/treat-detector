# evaluate_pcap_lstm.py
import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib
import pyshark
from sklearn.preprocessing import MinMaxScaler
from tqdm import tqdm
 
import asyncio, sys

# ---- Fix PyShark asyncio behaviour on Windows ----
if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

# Create and set a loop if missing
try:
    loop = asyncio.get_event_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

# Ensure PyShark thinks there is a "running" loop
if not loop.is_running():
    asyncio.set_event_loop(loop)

# =========================
# CONFIG
# =========================
MODEL_PATH = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models\lstm_cicids.pth"
SCALER_PATH = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models\scaler.pkl"
ENCODERS_DIR = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models\encoders"
LABEL_ENCODER_PATH = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models\label_encoder.pkl"
PCAP_PATH = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\captured\attack_traffic.pcap"

SEQ_LEN = 5
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# =========================
# 1. Load model and encoders
# =========================
print("Loading model and encoders...")
scaler = joblib.load(SCALER_PATH)
label_encoder = joblib.load(LABEL_ENCODER_PATH)

class LSTMModel(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=2, num_classes=None):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)
    def forward(self, x):
        out, _ = self.lstm(x)
        out = out[:, -1, :]
        return self.fc(out)

# we infer input_dim from scaler
input_dim = len(scaler.min_)
num_classes = len(label_encoder.classes_)
model = LSTMModel(input_dim=input_dim, num_classes=num_classes).to(DEVICE)
model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE))
model.eval()
print("✅ Model loaded successfully.")

# =========================
# 2. Feature extraction
# =========================
def extract_features_from_packet(pkt):
    """Extract minimal subset of CICIDS-like features from pyshark packet."""
    try:
        proto = pkt.highest_layer
        length = int(pkt.length)
        src = pkt.ip.src if hasattr(pkt, 'ip') else "0.0.0.0"
        dst = pkt.ip.dst if hasattr(pkt, 'ip') else "0.0.0.0"
        src_port = getattr(pkt, 'tcp', getattr(pkt, 'udp', None))
        src_port = int(src_port.srcport) if src_port else 0
        dst_port = int(src_port.dstport) if src_port else 0
        return {
            "Protocol": proto,
            "Length": length,
            "SrcPort": src_port,
            "DstPort": dst_port,
            "SrcIP": src,
            "DstIP": dst,
        }
    except Exception:
        return None

print(f"Extracting packets from {PCAP_PATH} ...")

import pyshark

async def run_capture(path):
    # PyShark will run inside an async context, avoiding RuntimeError
    return pyshark.FileCapture(
        path,
        only_summaries=False,
        use_json=True,
        keep_packets=False
    )

# ---- run safely inside a new loop ----
try:
    capture = loop.run_until_complete(run_capture(PCAP_PATH))
except RuntimeError:
    # fallback if loop already running
    capture = pyshark.FileCapture(
        PCAP_PATH,
        only_summaries=False,
        use_json=True,
        keep_packets=False
    )

packets = []
for pkt in tqdm(capture, desc="Reading packets"):
    feat = extract_features_from_packet(pkt)
    if feat:
        packets.append(feat)
capture.close()

df = pd.DataFrame(packets)
if df.empty:
    raise SystemExit("❌ No packets extracted.")

print(f"Extracted {len(df)} packets")

# =========================
# 3. Preprocess features
# =========================
# encode categorical
cat_cols = [c for c in df.select_dtypes(include=["object"]).columns]
for c in cat_cols:
    enc_path = os.path.join(ENCODERS_DIR, f"{c}_encoder.pkl")
    if os.path.exists(enc_path):
        le = joblib.load(enc_path)
        df[c] = df[c].map(lambda x: x if x in le.classes_ else le.classes_[0])
        df[c] = le.transform(df[c])
    else:
        df[c] = df[c].astype("category").cat.codes

# scale numeric
features_scaled = scaler.transform(df.values.astype(np.float32))
print("Features scaled successfully.")

# =========================
# 4. Sequence generation + prediction
# =========================
seqs = []
for i in range(len(features_scaled) - SEQ_LEN + 1):
    seq = features_scaled[i:i+SEQ_LEN]
    seqs.append(seq)
seqs = np.stack(seqs)
tensor = torch.tensor(seqs, dtype=torch.float32).to(DEVICE)

print("Running inference...")
preds = []
with torch.no_grad():
    for i in tqdm(range(0, len(tensor), 128)):
        batch = tensor[i:i+128]
        logits = model(batch)
        preds.extend(torch.argmax(logits, dim=1).cpu().numpy())

decoded = label_encoder.inverse_transform(preds)
df_result = pd.DataFrame({
    "Sequence_Start": np.arange(len(decoded)),
    "Predicted": decoded
})

# =========================
# 5. Save & Alert
# =========================
df_result.to_csv("predictions_from_pcap.csv", index=False)
print("✅ Predictions saved to predictions_from_pcap.csv")

alert_counts = df_result["Predicted"].value_counts()
print("\n=== Summary of detections ===")
print(alert_counts)

if any(df_result["Predicted"] != "BENIGN"):
    print("\n🚨 ALERT: Possible malicious activity detected! 🚨")
else:
    print("\n✅ No anomalies detected. Network seems normal.")
