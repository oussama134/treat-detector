# src/dataset.py
import numpy as np
import torch
from torch.utils.data import Dataset

class SequenceDataset(Dataset):
    def __init__(self, features_path, start_indices, seq_len=5, dtype=np.float32):
        self.features = np.load(features_path, mmap_mode='r')
        self.start_indices = np.array(start_indices, dtype=np.int64)
        self.seq_len = seq_len
        self.dtype = dtype

    def __len__(self):
        return len(self.start_indices)

    def __getitem__(self, idx):
        s = self.start_indices[idx]
        seq = self.features[s:s + self.seq_len].astype(self.dtype)
        return torch.tensor(seq, dtype=torch.float32), s
