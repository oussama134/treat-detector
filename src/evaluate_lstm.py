# src/evaluate_lstm.py
import torch, joblib, numpy as np, pandas as pd
from lstm_model import LSTMModel

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
OUT_DIR = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models"
MODEL_PATH = f"{OUT_DIR}\\lstm_cicids.pth"
SCALER_PATH = f"{OUT_DIR}\\scaler.pkl"
LABEL_ENCODER_PATH = f"{OUT_DIR}\\label_encoder.pkl"

# Load
scaler = joblib.load(SCALER_PATH)
le = joblib.load(LABEL_ENCODER_PATH)

# Load model
num_classes = len(le.classes_)
input_dim = scaler.n_features_in_
model = LSTMModel(input_dim=input_dim, num_classes=num_classes).to(DEVICE)
model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE))
model.eval()

# Example: load a sample CSV
df = pd.read_csv(r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\raw\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv").head(500)


# --- Clean data before scaling ---
import numpy as np
import pandas as pd

# Replace inf and -inf with NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Drop rows with NaN (or you can fill them with 0)
df = df.dropna()

# Optional: ensure all numeric types are float64
df = df.astype(np.float64, errors='ignore')



X = scaler.transform(df.select_dtypes(include=np.number))
X_tensor = torch.tensor(X, dtype=torch.float32).unsqueeze(1).to(DEVICE)

with torch.no_grad():
    preds = torch.argmax(model(X_tensor), dim=1).cpu().numpy()

df['Predicted'] = le.inverse_transform(preds)
df[['Predicted']].to_csv("1.csv", index=False)
print("✅ Predictions saved to rofff.csv")
