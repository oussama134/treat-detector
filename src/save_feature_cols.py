# save_feature_cols.py
import json
import pandas as pd
import os

CSV = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\processed\CICIDS2017_combined.csv"
OUT = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\models\feature_cols.json"

df = pd.read_csv(CSV, nrows=1)  # just need header
cols = [c for c in df.columns if c.strip() != 'Label']  # same rule used in train
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf8") as f:
    json.dump(cols, f, indent=2)
print("Saved", len(cols), "feature cols to", OUT)
