#!/usr/bin/env python3
"""
realtime_tshark_features.py
Capture live traffic using tshark for a short duration window, compute flow/host features,
map them to feature_cols.json, scale and run LSTM prediction.

Usage:
    python realtime_tshark_features.py --iface "Wi-Fi 2" --window 60
"""
import os
import subprocess
import shlex
import time
import json
import joblib
import numpy as np
import pandas as pd
import collections
import torch
import torch.nn as nn
from datetime import datetime, timezone
import argparse

# ---------- CONFIG ----------
PROJECT = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector"
MODELS_DIR = os.path.join(PROJECT, "models")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
LABEL_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")
MODEL_PATH = os.path.join(MODELS_DIR, "lstm_cicids.pth")
FEATURE_COLS_PATH = os.path.join(MODELS_DIR, "feature_cols.json")

SEQ_LEN = 5               # number of windows to assemble per src_ip before inference
WINDOW_SECONDS = 60       # default capture window
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
LOG = os.path.join(PROJECT, "alerts.log")

# ---------- Model (must match your saved model) ----------
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

def log_alert(msg):
    ts = datetime.now(timezone.utc).isoformat()
    print(f"{ts} - {msg}")
    try:
        with open(LOG, "a") as f:
            f.write(f"{ts} - {msg}\n")
    except Exception:
        pass

# ---------- Load models + feature columns ----------
if not all(os.path.exists(p) for p in [SCALER_PATH, LABEL_PATH, MODEL_PATH, FEATURE_COLS_PATH]):
    raise SystemExit("Missing artifacts in models/: scaler.pkl, label_encoder.pkl, lstm_cicids.pth, feature_cols.json")

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

# rolling buffers per src_ip to create sequences of windows
buffers = collections.defaultdict(lambda: collections.deque(maxlen=SEQ_LEN))

# ---------- TShark fields to capture ----------
# choose fields that will let you compute flow-level features:
TSHARK_FIELDS = [
    "frame.time_epoch",    # timestamp
    "ip.src",
    "ip.dst",
    "ip.proto",
    "frame.len",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",           # raw flags hex/decimal typically
    "tcp.analysis.retransmission"  # optional
]

# helper to build tshark command
def build_tshark_cmd(iface_name, duration_sec, fields):
    # -i interface (use exact name you used with tshark)
    # -a duration:SECONDS to stop after X seconds
    # -T fields -E separator=, -E quote=d to get CSV-like output
    fields_args = " ".join(f'-e {f}' for f in fields)
    cmd = f'"C:\\Program Files\\Wireshark\\tshark.exe" -i "{iface_name}" -a duration:{duration_sec} -T fields -E separator=, -E quote=d {fields_args}'
    return cmd

# parse tshark output lines into DataFrame
def parse_tshark_output(raw_lines, fields):
    rows = []
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        # tshark -T fields returns values separated by the specified separator (we used comma)
        # fields missing are empty strings, so we can split and align to fields length
        parts = [p.strip().strip('"') for p in line.split(",")]
        # if parts shorter than expected, pad
        if len(parts) < len(fields):
            parts += [""] * (len(fields) - len(parts))
        row = dict(zip(fields, parts))
        rows.append(row)
    if len(rows) == 0:
        return pd.DataFrame(columns=fields)
    df = pd.DataFrame(rows)
    # coerce types where possible
    if "frame.time_epoch" in df.columns:
        df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
    if "frame.len" in df.columns:
        df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce").fillna(0).astype(int)
    # normalize ip columns
    for col in ["ip.src", "ip.dst"]:
        if col in df.columns:
            df[col] = df[col].replace("", np.nan)
    # tcp flags: convert hex/dec to int where possible
    if "tcp.flags" in df.columns:
        df["tcp.flags"] = pd.to_numeric(df["tcp.flags"], errors="coerce").fillna(0).astype(int)
    return df

# compute a set of flow/host features per src_ip for this window
def compute_window_features(df):
    """
    Input: DataFrame of packets with columns: frame.time_epoch, ip.src, ip.dst, frame.len, tcp.flags, tcp.srcport/udp.srcport, etc.
    Returns: dict mapping src_ip -> feature vector (dict)
    """
    if df is None or df.shape[0] == 0:
        return {}

    # treat packets with missing ip.src as broadcast/ignore or map to special value
    df = df.dropna(subset=["ip.src"], how="any").copy()
    if df.shape[0] == 0:
        return {}

    # create a normalized src_port/dst_port column by preferring tcp then udp
    def pick_port(row, which):
        if which == "src":
            if row.get("tcp.srcport"):
                return row["tcp.srcport"]
            if row.get("udp.srcport"):
                return row["udp.srcport"]
        else:
            if row.get("tcp.dstport"):
                return row["tcp.dstport"]
            if row.get("udp.dstport"):
                return row["udp.dstport"]
        return ""
    df["src_port"] = df.apply(lambda r: pick_port(r, "src"), axis=1)
    df["dst_port"] = df.apply(lambda r: pick_port(r, "dst"), axis=1)

    groups = {}
    for src, grp in df.groupby("ip.src"):
        g = grp.copy()
        n_pkts = len(g)
        total_bytes = int(g["frame.len"].sum())
        avg_len = float(g["frame.len"].mean())
        std_len = float(g["frame.len"].std(ddof=0) or 0.0)
        unique_dsts = int(g["ip.dst"].nunique(dropna=True))
        unique_dst_ports = int(g["dst_port"].nunique(dropna=True))
        unique_src_ports = int(g["src_port"].nunique(dropna=True))
        tcp_pkt_count = int(g[g["ip.proto"].str.contains("6", na=False)].shape[0]) if "ip.proto" in g.columns else 0
        udp_pkt_count = int(g[g["ip.proto"].str.contains("17", na=False)].shape[0]) if "ip.proto" in g.columns else 0

        # flags stats: simple approach: count packets with each bit set (SYN, ACK, FIN, RST, PSH, URG)
        flags = g.get("tcp.flags", pd.Series(dtype=int))
        syn = int(((flags & 0x02) != 0).sum()) if not flags.empty else 0
        ack = int(((flags & 0x10) != 0).sum()) if not flags.empty else 0
        fin = int(((flags & 0x01) != 0).sum()) if not flags.empty else 0
        rst = int(((flags & 0x04) != 0).sum()) if not flags.empty else 0
        psh = int(((flags & 0x08) != 0).sum()) if not flags.empty else 0
        # approximate flow duration (last pkt - first pkt)
        if "frame.time_epoch" in g.columns and g["frame.time_epoch"].notna().any():
            duration = float(g["frame.time_epoch"].max() - g["frame.time_epoch"].min())
        else:
            duration = 0.0
        pps = n_pkts / duration if duration > 0 else float(n_pkts)  # pkts per second approx
        bps = total_bytes / duration if duration > 0 else float(total_bytes)

        groups[src] = {
            "n_pkts": n_pkts,
            "total_bytes": total_bytes,
            "avg_len": avg_len,
            "std_len": std_len,
            "unique_dsts": unique_dsts,
            "unique_dst_ports": unique_dst_ports,
            "unique_src_ports": unique_src_ports,
            "tcp_pkts": tcp_pkt_count,
            "udp_pkts": udp_pkt_count,
            "syn_count": syn,
            "ack_count": ack,
            "fin_count": fin,
            "rst_count": rst,
            "psh_count": psh,
            "duration": duration,
            "pps": pps,
            "bps": bps
        }
    return groups

# map computed features to your expected feature columns (feature_cols list)
def map_to_feature_vector(feature_dict):
    """
    feature_dict: {feat_name: value}
    returns: numpy array len(feature_cols) with order matching feature_cols
    """
    vec = np.zeros(len(feature_cols), dtype=np.float32)
    for i, name in enumerate(feature_cols):
        if name in feature_dict:
            val = feature_dict[name]
            try:
                vec[i] = float(val)
            except Exception:
                vec[i] = 0.0
        else:
            # try some common name mapping shortcuts
            if name in ["pkt_count", "n_packets", "n_pkts"]:
                vec[i] = float(feature_dict.get("n_pkts", 0))
            elif name in ["bytes", "total_bytes"]:
                vec[i] = float(feature_dict.get("total_bytes", 0))
            elif name in ["avg_len", "mean_len"]:
                vec[i] = float(feature_dict.get("avg_len", 0.0))
            elif name in ["std_len", "len_std"]:
                vec[i] = float(feature_dict.get("std_len", 0.0))
            elif name in ["unique_dsts", "unique_dst_count"]:
                vec[i] = float(feature_dict.get("unique_dsts", 0))
            elif name in ["pps", "pkt_rate"]:
                vec[i] = float(feature_dict.get("pps", 0.0))
            elif name in ["bps", "byte_rate"]:
                vec[i] = float(feature_dict.get("bps", 0.0))
            else:
                vec[i] = 0.0
    return vec

# main loop: capture -> compute -> predict
def run_live_tshark(iface_name, window_seconds):
    log_alert(f"Starting TShark capture on {iface_name}. Window={window_seconds}s, SEQ_LEN={SEQ_LEN}")
    while True:
        cmd = build_tshark_cmd(iface_name, window_seconds, TSHARK_FIELDS)
        # run tshark and capture stdout lines
        try:
            # use shell invocation to allow quoted path
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True, universal_newlines=True)
            stdout, _ = proc.communicate(timeout=window_seconds + 10)
            lines = stdout.splitlines()
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()
            lines = stdout.splitlines()
        except Exception as e:
            log_alert(f"tshark capture error: {e}")
            time.sleep(5)
            continue

        df_pkts = parse_tshark_output(lines, TSHARK_FIELDS)
        # compute features per src_ip
        per_src = compute_window_features(df_pkts)

        # for each src produce a vector, scale and append to buffer
        for src, feat_dict in per_src.items():
            vec = map_to_feature_vector(feat_dict)  # (n_features,)
            if len(vec) != input_dim:
                log_alert(f"Feature length mismatch for src={src}: got {len(vec)} expected {input_dim}")
                continue
            try:
                x_scaled = scaler.transform(vec.reshape(1, -1))
            except Exception as e:
                log_alert(f"Scaler error: {e}")
                continue
            buffers[src].append(x_scaled.flatten())
            # if we have SEQ_LEN windows -> predict
            if len(buffers[src]) == SEQ_LEN:
                seq = np.stack(buffers[src], axis=0)[np.newaxis, ...]  # (1, SEQ_LEN, input_dim)
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

# ---------- CLI ----------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", "-i", type=str, required=True, help='Exact interface name for tshark (e.g., "Wi-Fi 2")')
    parser.add_argument("--window", "-w", type=int, default=WINDOW_SECONDS)
    args = parser.parse_args()
    run_live_tshark(args.iface, args.window)
