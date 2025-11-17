# predict.py
import os
import numpy as np
import pandas as pd
import torch
import joblib
from lstm_model import LSTMModel
from sklearn.preprocessing import LabelEncoder

# =========================
# CONFIG
# =========================
MODEL_PATH = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models\lstm_cicids.pth"
SCALER_PATH = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models\scaler.pkl"
ENCODERS_DIR = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models\encoders"
FEATURES_CSV = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\flows_advanced.csv"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
SEQ_LEN = 5

# =========================
# 1. Load features CSV
# =========================
df = pd.read_csv(FEATURES_CSV)

# Encode non-numeric columns (e.g., IPs, protocols)
for col in df.columns:
    if df[col].dtype == object:
        le_path = os.path.join(ENCODERS_DIR, f"{col}_encoder.pkl")
        if os.path.exists(le_path):
            le = joblib.load(le_path)
            df[col] = le.transform(df[col].astype(str))
        else:
            # fallback: Label encode on the fly
            df[col] = LabelEncoder().fit_transform(df[col].astype(str))

# Ensure all features are numeric
features = df.values.astype(np.float32)

# =========================
# 2. Load scaler + normalize
# =========================
scaler = joblib.load(SCALER_PATH)
features_scaled = scaler.transform(features)

# =========================
# 3. Load LSTM model
# =========================
input_dim = features_scaled.shape[1]
num_classes = 2  # Adjust based on your trained model
model = LSTMModel(input_dim=input_dim, hidden_dim=64, num_layers=2, num_classes=num_classes).to(DEVICE)
model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE))
model.eval()

# =========================
# 4. Build sequences
# =========================
sequences = []
for i in range(len(features_scaled) - SEQ_LEN + 1):
    sequences.append(features_scaled[i:i+SEQ_LEN])
sequences = torch.tensor(sequences, dtype=torch.float32).to(DEVICE)

# =========================
# 5. Predict
# =========================
with torch.no_grad():
    logits = model(sequences)
    preds = torch.argmax(logits, dim=1).cpu().numpy()

print("Predictions:", preds)
print(f"Detected {np.sum(preds)} anomaly sequences out of {len(preds)}")
