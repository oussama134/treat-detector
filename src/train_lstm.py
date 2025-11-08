# train_lstm.py
import os
import random
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader

# =========================
# CONFIG
# =========================
SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

DATA_CSV = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\processed\CICIDS2017_combined.csv"
OUT_DIR = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models"
ENCODERS_DIR = os.path.join(OUT_DIR, "encoders")
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(ENCODERS_DIR, exist_ok=True)

MEMMAP_FEATURES = os.path.join(OUT_DIR, "features_scaled.npy")
MEMMAP_LABELS = os.path.join(OUT_DIR, "labels.npy")

SEQ_LEN = 5
INPUT_DTYPE = np.float32

MAX_PER_CLASS = 20000
TEST_SIZE = 0.2
BATCH_SIZE = 256
EPOCHS = 8
LR = 1e-3
HIDDEN_DIM = 64
NUM_LAYERS = 2
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

LABEL_COL = 'Label'

# =========================
# 1. Load + clean CSV
# =========================
print("1) Loading CSV...")
df = pd.read_csv(DATA_CSV)
df.columns = df.columns.str.strip()
df = df.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
df[LABEL_COL] = df[LABEL_COL].astype(str).str.strip()
print(f"  cleaned rows: {len(df)}")

# =========================
# 2. Encode labels
# =========================
label_encoder = LabelEncoder()
labels = label_encoder.fit_transform(df[LABEL_COL])
joblib.dump(label_encoder, os.path.join(OUT_DIR, "label_encoder.pkl"))
print("  classes:", label_encoder.classes_)

# =========================
# 3. Encode categorical features
# =========================
cat_cols = [c for c in df.select_dtypes(include=["object"]).columns if c != LABEL_COL]
for c in cat_cols:
    le = LabelEncoder()
    df[c] = le.fit_transform(df[c].astype(str))
    joblib.dump(le, os.path.join(ENCODERS_DIR, f"{c}_encoder.pkl"))

feature_cols = [c for c in df.columns if c != LABEL_COL]

# =========================
# 4. Scale features
# =========================
features = df[feature_cols].values.astype(INPUT_DTYPE)
scaler = MinMaxScaler()
features_scaled = scaler.fit_transform(features)
joblib.dump(scaler, os.path.join(OUT_DIR, "scaler.pkl"))

np.save(MEMMAP_FEATURES, features_scaled)
np.save(MEMMAP_LABELS, labels.astype(np.int64))
del features, features_scaled

# =========================
# 5. Build sequences
# =========================
labels_mem = np.load(MEMMAP_LABELS, mmap_mode='r')
n_rows = labels_mem.shape[0]
max_start = n_rows - SEQ_LEN
if max_start <= 0:
    raise SystemExit("SEQ_LEN too large for dataset")

label_ends = labels_mem[SEQ_LEN-1:]
all_start_indices = np.arange(0, max_start+1, dtype=np.int64)
indices_by_class = {}
for cls_idx in np.unique(label_ends):
    cls_mask = (label_ends == cls_idx)
    idxs = all_start_indices[cls_mask]
    indices_by_class[int(cls_idx)] = idxs

sampled_indices = []
for cls, idxs in indices_by_class.items():
    if len(idxs) == 0:
        continue
    take = min(len(idxs), MAX_PER_CLASS)
    chosen = np.random.choice(idxs, size=take, replace=False)
    sampled_indices.append(chosen)
sampled_indices = np.concatenate(sampled_indices)
np.random.shuffle(sampled_indices)
sampled_labels = labels_mem[sampled_indices + SEQ_LEN - 1]

train_idx, test_idx, _, _ = train_test_split(
    sampled_indices, sampled_labels, test_size=TEST_SIZE, random_state=SEED, stratify=sampled_labels
)

# =========================
# 6. Dataset
# =========================
class SequenceDataset(Dataset):
    def __init__(self, features_path, start_indices, seq_len=SEQ_LEN, dtype=np.float32):
        self.features = np.load(features_path, mmap_mode='r')
        self.start_indices = np.array(start_indices, dtype=np.int64)
        self.seq_len = seq_len
        self.dtype = dtype
    def __len__(self):
        return len(self.start_indices)
    def __getitem__(self, idx):
        s = self.start_indices[idx]
        seq = self.features[s:s+self.seq_len].astype(self.dtype)
        return torch.tensor(seq, dtype=torch.float32), s

train_dataset = SequenceDataset(MEMMAP_FEATURES, train_idx)
test_dataset = SequenceDataset(MEMMAP_FEATURES, test_idx)
train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

def labels_for_starts(starts):
    return labels_mem[starts + SEQ_LEN - 1].astype(np.int64)

# =========================
# 7. LSTM model
# =========================
class LSTMModel(nn.Module):
    def __init__(self, input_dim, hidden_dim=HIDDEN_DIM, num_layers=NUM_LAYERS, num_classes=None):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)
    def forward(self, x):
        out, _ = self.lstm(x)
        out = out[:, -1, :]
        out = self.fc(out)
        return out

input_dim = np.load(MEMMAP_FEATURES, mmap_mode='r').shape[1]
num_classes = len(label_encoder.classes_)
model = LSTMModel(input_dim=input_dim, num_classes=num_classes).to(DEVICE)

# =========================
# 8. Loss + optimizer
# =========================
from sklearn.utils.class_weight import compute_class_weight

class_weights = compute_class_weight(
    class_weight="balanced",
    classes=np.arange(num_classes),
    y=labels_for_starts(train_idx)
)
class_weights = torch.tensor(class_weights, dtype=torch.float32).to(DEVICE)
criterion = nn.CrossEntropyLoss(weight=class_weights)
optimizer = optim.Adam(model.parameters(), lr=LR)

# =========================
# 9. Training loop
# =========================
for epoch in range(1, EPOCHS+1):
    model.train()
    total_loss = 0.0
    for seq_batch, starts in train_loader:
        seq_batch = seq_batch.to(DEVICE)
        y_batch = torch.tensor(labels_for_starts(starts.numpy()), dtype=torch.long).to(DEVICE)

        optimizer.zero_grad()
        logits = model(seq_batch)
        loss = criterion(logits, y_batch)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * seq_batch.size(0)

    avg_loss = total_loss / len(train_loader.dataset)

    # Validation
    model.eval()
    all_preds, all_trues = [], []
    with torch.no_grad():
        for seq_batch, starts in test_loader:
            seq_batch = seq_batch.to(DEVICE)
            y_true = labels_for_starts(starts.numpy())
            logits = model(seq_batch)
            preds = torch.argmax(logits, dim=1).cpu().numpy()
            all_preds.append(preds)
            all_trues.append(y_true)
    all_preds = np.concatenate(all_preds)
    all_trues = np.concatenate(all_trues)
    f1 = f1_score(all_trues, all_preds, average='macro')
    print(f"Epoch {epoch}/{EPOCHS} — loss: {avg_loss:.5f} — val f1_macro: {f1:.4f}")

# =========================
# 10. Final evaluation + save
# =========================
model.eval()
all_preds, all_trues = [], []
with torch.no_grad():
    for seq_batch, starts in test_loader:
        seq_batch = seq_batch.to(DEVICE)
        y_true = labels_for_starts(starts.numpy())
        logits = model(seq_batch)
        preds = torch.argmax(logits, dim=1).cpu().numpy()
        all_preds.append(preds)
        all_trues.append(y_true)

all_preds = np.concatenate(all_preds)
all_trues = np.concatenate(all_trues)
print("Classification report:")
print(classification_report(all_trues, all_preds, target_names=label_encoder.classes_))

torch.save(model.state_dict(), os.path.join(OUT_DIR, "lstm_cicids.pth"))
print("✅ Training complete. Model saved at:", OUT_DIR)
