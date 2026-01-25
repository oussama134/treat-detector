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
ENCODERS_DIR = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models"
FEATURES_CSV = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\flows_attack_78.csv"  # your test flows
OUT_DIR = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models"

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
SEQ_LEN = 3

# =========================
# 1. Load features CSV
# =========================
df = pd.read_csv(FEATURES_CSV)

# Encode non-numeric columns using saved encoders
for col in df.columns:
    if df[col].dtype == object:
        le_path = os.path.join(ENCODERS_DIR, f"{col}_encoder.pkl")
        if os.path.exists(le_path):
            le = joblib.load(le_path)
            df[col] = le.transform(df[col].astype(str))
        else:
            df[col] = LabelEncoder().fit_transform(df[col].astype(str))

features = df.values.astype(np.float32)

# =========================
# 2. Load scaler + normalize
# =========================
scaler = joblib.load(SCALER_PATH)
features_scaled = scaler.transform(features)

# =========================
# 3. Load label encoder + model
# =========================
label_encoder = joblib.load(os.path.join(ENCODERS_DIR, "label_encoder.pkl"))
num_classes = len(label_encoder.classes_)

input_dim = features_scaled.shape[1]
model = LSTMModel(input_dim=input_dim, hidden_dim=64, num_layers=2, num_classes=num_classes).to(DEVICE)
model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE))
model.eval()

# =========================
# 4. Build sequences
# =========================
if len(features_scaled) < SEQ_LEN:
    raise ValueError(f"Not enough rows ({len(features_scaled)}) for SEQ_LEN={SEQ_LEN}")

sequences = []
for i in range(len(features_scaled) - SEQ_LEN + 1):
    sequences.append(features_scaled[i:i+SEQ_LEN])

sequences = torch.tensor(np.array(sequences), dtype=torch.float32).to(DEVICE)

# =========================
# 5. Predict
# =========================
with torch.no_grad():
    logits = model(sequences)
    preds = torch.argmax(logits, dim=1).cpu().numpy()

# =========================
# 6. Map predictions to labels
# =========================
pred_labels = label_encoder.inverse_transform(preds)

print("Predictions (label names):", pred_labels)
print(f"Detected {np.sum(pred_labels != 'BENIGN')} anomaly sequences out of {len(pred_labels)}")
