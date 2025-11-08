# src/data_utils.py
import os
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import MinMaxScaler, LabelEncoder

def load_and_clean_csv(csv_path, label_col='Label'):
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    if label_col in df.columns:
        df[label_col] = df[label_col].astype(str).str.strip()
    return df

def encode_labels(df, label_col, out_dir):
    le = LabelEncoder()
    labels = le.fit_transform(df[label_col].astype(str))
    joblib.dump(le, os.path.join(out_dir, "label_encoder.pkl"))
    return labels, le

def encode_categorical(df, out_dir, label_col='Label'):
    cat_cols = df.select_dtypes(include=["object"]).columns.tolist()
    cat_cols = [c for c in cat_cols if c != label_col]
    encoders_dir = os.path.join(out_dir, "encoders")
    os.makedirs(encoders_dir, exist_ok=True)

    for c in cat_cols:
        le = LabelEncoder()
        df[c] = df[c].astype(str)
        le.fit(df[c])
        df[c] = le.transform(df[c])
        joblib.dump(le, os.path.join(encoders_dir, f"encoder_{c}.pkl"))

    feature_cols = [c for c in df.columns if c != label_col]
    return df, feature_cols

def scale_features(df, feature_cols, out_dir, dtype=np.float32):
    features = df[feature_cols].values.astype(np.float32)
    scaler = MinMaxScaler()
    features_scaled = scaler.fit_transform(features).astype(dtype)
    joblib.dump(scaler, os.path.join(out_dir, "scaler.pkl"))

    memmap_features = os.path.join(out_dir, "features_scaled.npy")
    np.save(memmap_features, features_scaled)
    return memmap_features
