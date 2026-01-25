# src/train.py
import os
import numpy as np
import torch
from torch.utils.data import DataLoader
from sklearn.utils.class_weight import compute_class_weight
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, precision_score, recall_score, classification_report

from dataset import SequenceDataset
from lstm_model import LSTMModel
from data_utils import load_and_clean_csv, encode_labels, encode_categorical, scale_features

# CONFIG
DATA_CSV = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\processed\CICIDS2017_combined.csv"
OUT_DIR = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models"
SEQ_LEN = 5
BATCH_SIZE = 256
EPOCHS = 8
LR = 1e-3
HIDDEN_DIM = 64
NUM_LAYERS = 2
MAX_PER_CLASS = 20000
TEST_SIZE = 0.2
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

os.makedirs(OUT_DIR, exist_ok=True)

# 1️⃣ Load CSV
df = load_and_clean_csv(DATA_CSV)

# 2️⃣ Encode labels
labels, label_encoder = encode_labels(df, 'Label', OUT_DIR)

# 3️⃣ Encode categorical columns
df, feature_cols = encode_categorical(df, OUT_DIR, label_col='Label')

# 4️⃣ Scale features → memmap
MEMMAP_FEATURES = scale_features(df, feature_cols, OUT_DIR)

# 5️⃣ Build balanced sequence indices
labels_mem = np.array(labels, dtype=np.int64)
n_rows = len(labels_mem)
max_start = n_rows - SEQ_LEN
if max_start <= 0:
    raise SystemExit("SEQ_LEN too large for dataset length")
label_ends = labels_mem[SEQ_LEN-1:]
all_start_indices = np.arange(0, max_start + 1)
indices_by_class = {}
for cls_idx in np.unique(label_ends):
    cls_mask = label_ends == cls_idx
    indices_by_class[int(cls_idx)] = all_start_indices[cls_mask]

sampled_indices = []
for cls, idxs in indices_by_class.items():
    if len(idxs) == 0: continue
    take = min(len(idxs), MAX_PER_CLASS)
    sampled_indices.append(np.random.choice(idxs, size=take, replace=False))
sampled_indices = np.concatenate(sampled_indices)
np.random.shuffle(sampled_indices)
sampled_labels = labels_mem[sampled_indices + SEQ_LEN - 1]

train_idx, test_idx, y_train_idx, y_test_idx = train_test_split(
    sampled_indices, sampled_labels, test_size=TEST_SIZE, random_state=42, stratify=sampled_labels
)

# 6️⃣ Datasets & loaders
train_dataset = SequenceDataset(MEMMAP_FEATURES, train_idx, seq_len=SEQ_LEN)
test_dataset = SequenceDataset(MEMMAP_FEATURES, test_idx, seq_len=SEQ_LEN)
train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

# helper for labels
def labels_for_starts(starts): return labels_mem[starts + SEQ_LEN -1].astype(np.int64)

# 7️⃣ Model + loss + optimizer
input_dim = len(feature_cols)
num_classes = len(label_encoder.classes_)
model = LSTMModel(input_dim, hidden_dim=HIDDEN_DIM, num_layers=NUM_LAYERS, num_classes=num_classes).to(DEVICE)
class_weights = compute_class_weight(class_weight='balanced', classes=np.arange(num_classes), y=labels_for_starts(train_idx))
criterion = torch.nn.CrossEntropyLoss(weight=torch.tensor(class_weights, dtype=torch.float32).to(DEVICE))
optimizer = torch.optim.Adam(model.parameters(), lr=LR)

# 8️⃣ Training loop
for epoch in range(1, EPOCHS+1):
    model.train()
    total_loss = 0
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
    prec = precision_score(all_trues, all_preds, average='macro', zero_division=0)
    rec = recall_score(all_trues, all_preds, average='macro', zero_division=0)
    print(f"Epoch {epoch}/{EPOCHS} — loss: {avg_loss:.5f} — f1: {f1:.4f} — prec: {prec:.4f} — rec: {rec:.4f}")

