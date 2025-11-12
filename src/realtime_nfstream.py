# ultimate_realtime_monitor.py
import os
import time
import json
import joblib
import numpy as np
import pandas as pd
import collections
import torch
import torch.nn as nn
from datetime import datetime, timezone
from nfstream import NFStreamer
import psutil

# -------------------- CONFIG --------------------
PROJECT = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector"
MODELS_DIR = os.path.join(PROJECT, "models")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
LABEL_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")
MODEL_PATH = os.path.join(MODELS_DIR, "lstm_cicids.pth")
FEATURE_COLS_PATH = os.path.join(MODELS_DIR, "feature_cols.json")

SEQ_LEN = 5
WINDOW_SECONDS = 60
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
LOG = os.path.join(PROJECT, "alerts.log")

# -------------------- LSTM Model --------------------
class LSTMModel(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=2, num_classes=None):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)
    def forward(self, x):
        out, _ = self.lstm(x)
        out = out[:, -1, :]
        out = self.fc(out)
        return out

# -------------------- Logging --------------------
def log_alert(msg):
    ts = datetime.now(timezone.utc).isoformat()
    print(f"{ts} - {msg}")
    try:
        with open(LOG, "a") as f:
            f.write(f"{ts} - {msg}\n")
    except Exception:
        pass

# -------------------- Load artifacts --------------------
if not all(os.path.exists(p) for p in [SCALER_PATH, LABEL_PATH, MODEL_PATH, FEATURE_COLS_PATH]):
    raise SystemExit("Make sure scaler.pkl, label_encoder.pkl, lstm_cicids.pth and feature_cols.json exist in models/")

scaler = joblib.load(SCALER_PATH)
label_encoder = joblib.load(LABEL_PATH)
with open(FEATURE_COLS_PATH, "r", encoding="utf8") as f:
    feature_cols = json.load(f)

input_dim = getattr(scaler, "n_features_in_", None) or len(feature_cols)
num_classes = len(label_encoder.classes_)

model = LSTMModel(input_dim=input_dim, hidden_dim=64, num_layers=2, num_classes=num_classes).to(DEVICE)
state = torch.load(MODEL_PATH, map_location=DEVICE)
model.load_state_dict(state)
model.eval()

buffers = collections.defaultdict(lambda: collections.deque(maxlen=SEQ_LEN))

# -------------------- Feature Handling --------------------
def safe_select_and_order(df_numeric):
    df_num = df_numeric.select_dtypes(include=[np.number]).copy()
    out = pd.DataFrame(0.0, index=np.arange(len(df_num)), columns=feature_cols, dtype=np.float32)
    for c in df_num.columns:
        if c in out.columns:
            out[c] = df_num[c].values
    return out.values

def process_flows_window(df_flows):
    if df_flows is None or df_flows.shape[0] == 0:
        log_alert("No flows detected this window.")
        return
    groups = df_flows.groupby('src_ip') if 'src_ip' in df_flows.columns else [("global", df_flows)]
    for src, grp in groups:
        grp = grp.fillna(0.0)
        numeric = grp.select_dtypes(include=[np.number])
        if numeric.shape[1] == 0:
            continue
        vec = safe_select_and_order(numeric).mean(axis=0).astype(np.float32)
        handle_vector_for_src(src, vec)

def handle_vector_for_src(src, vec):
    if len(vec) != input_dim:
        log_alert(f"Feature-length mismatch for src={src}: got {len(vec)} expected {input_dim}")
        return
    try:
        x_scaled = scaler.transform(vec.reshape(1, -1))
    except Exception as e:
        log_alert(f"Scaler transform error: {e}")
        return
    buffers[src].append(x_scaled.flatten())
    if len(buffers[src]) == SEQ_LEN:
        seq = np.stack(buffers[src], axis=0)[np.newaxis, ...]
        seq_tensor = torch.tensor(seq, dtype=torch.float32).to(DEVICE)
        with torch.no_grad():
            logits = model(seq_tensor)
            probs = torch.softmax(logits, dim=1).cpu().numpy()[0]
            idx = int(probs.argmax())
            label = label_encoder.inverse_transform([idx])[0]
            score = float(probs[idx])
            if label != "BENIGN" and score >= 0.5:
                log_alert(f"ALERT src={src} label={label} score={score:.3f}")
            else:
                print(f"{datetime.now(timezone.utc).isoformat()} src={src} pred={label} score={score:.3f}")

# -------------------- Interface Resolver --------------------
def resolve_interface(requested_iface=None):
    ifaces = psutil.net_if_addrs()
    if requested_iface is not None:
        for name in ifaces.keys():
            if requested_iface.lower() in name.lower():
                return name
    # fallback to first IPv4 interface
    for name, addrs in ifaces.items():
        for addr in addrs:
            if addr.family.name == "AF_INET":
                return name
    raise RuntimeError("No interface found")



# -------------------- Live capture --------------------
def run_live(interface=None):
    iface = resolve_interface(interface)
    log_alert(f"Starting NFStreamer live capture on {iface}. Window={WINDOW_SECONDS}s, SEQ_LEN={SEQ_LEN}")
    while True:
        start = time.time()
        try:
            streamer = NFStreamer(
                source=iface,
                active_timeout=WINDOW_SECONDS
            )
            df = streamer.to_pandas()
            process_flows_window(df)
        except Exception as e:
            log_alert(f"NFStreamer error: {e}")
        elapsed = time.time() - start
        if elapsed < WINDOW_SECONDS:
            time.sleep(WINDOW_SECONDS - elapsed)

# -------------------- CLI --------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", "-i", type=str, default=None, help="interface name (e.g., Wi-Fi 2)")
    parser.add_argument("--window", "-w", type=int, default=WINDOW_SECONDS)
    args = parser.parse_args()
    WINDOW_SECONDS = args.window
    run_live(args.iface)
