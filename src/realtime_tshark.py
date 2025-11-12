import subprocess, pandas as pd, numpy as np, time, re, joblib, torch, json, collections
from datetime import datetime
from torch import nn

# ==== CONFIG ====
INTERFACE_INDEX = 4  # Replace with your Wi-Fi index
WINDOW_SECONDS = 10
SEQ_LEN = 5

PROJECT = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector"
MODELS_DIR = PROJECT + "\\models"
SCALER_PATH = MODELS_DIR + "\\scaler.pkl"
LABEL_PATH = MODELS_DIR + "\\label_encoder.pkl"
MODEL_PATH = MODELS_DIR + "\\lstm_cicids.pth"
FEATURE_COLS_PATH = MODELS_DIR + "\\feature_cols.json"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ==== MODEL ====
class LSTMModel(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, num_layers=2, num_classes=None):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)
    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])

# ==== LOAD ARTIFACTS ====
scaler = joblib.load(SCALER_PATH)
label_encoder = joblib.load(LABEL_PATH)
with open(FEATURE_COLS_PATH, "r", encoding="utf8") as f:
    feature_cols = json.load(f)
input_dim = len(feature_cols)
num_classes = len(label_encoder.classes_)
model = LSTMModel(input_dim=input_dim, num_classes=num_classes).to(DEVICE)
state = torch.load(MODEL_PATH, map_location=DEVICE)
model.load_state_dict(state)
model.eval()

buffers = collections.defaultdict(lambda: collections.deque(maxlen=SEQ_LEN))

# ==== FEATURE EXTRACTION ====
def parse_tshark_line(line):
    """Extract IP src, dst, and size from tshark line."""
    parts = line.strip().split()
    if len(parts) >= 3:
        return parts[1], parts[2], int(parts[3]) if len(parts) > 3 else 0
    return None

def capture_window():
    cmd = [
        r"C:\Program Files\Wireshark\tshark.exe",
        "-i", str(INTERFACE_INDEX),
        "-a", f"duration:{WINDOW_SECONDS}",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    lines = proc.stdout.readlines()
    return [parse_tshark_line(l) for l in lines if parse_tshark_line(l)]

# ==== MAIN LOOP ====
def log_alert(msg):
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).isoformat()

    print(f"{ts} - {msg}")

def run_live():
    log_alert(f"Starting TShark live capture on iface {INTERFACE_INDEX}")
    while True:
        flows = capture_window()
        if not flows:
            log_alert("No packets in this window.")
            continue

        df = pd.DataFrame(flows, columns=["src_ip", "dst_ip", "frame_len"])
        grouped = df.groupby("src_ip")["frame_len"].agg(["count", "mean", "sum", "std"]).fillna(0)
        for src, row in grouped.iterrows():
            vec = np.zeros(input_dim, dtype=np.float32)
            vec[:4] = [row["count"], row["mean"], row["sum"], row["std"]]  # placeholder minimal features
            vec_scaled = scaler.transform(vec.reshape(1, -1))
            buffers[src].append(vec_scaled.flatten())
            if len(buffers[src]) == SEQ_LEN:
                seq = np.stack(buffers[src])[np.newaxis, ...]
                seq_tensor = torch.tensor(seq, dtype=torch.float32).to(DEVICE)
                with torch.no_grad():
                    logits = model(seq_tensor)
                    probs = torch.softmax(logits, dim=1).cpu().numpy()[0]
                    idx = int(probs.argmax())
                    label = label_encoder.inverse_transform([idx])[0]
                    score = probs[idx]
                    if label != "BENIGN" and score >= 0.5:
                        log_alert(f"⚠️ ALERT src={src} label={label} score={score:.3f}")
                    else:
                        print(f"{datetime.utcnow().isoformat()} src={src} pred={label} score={score:.3f}")

if __name__ == "__main__":
    run_live()
