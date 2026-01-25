# analyze_predictions.py - Understand why model predicts mostly DoS
"""
Analyzes the model's predictions to understand classification behavior
"""

import joblib
import torch
import numpy as np
import pandas as pd
from flow_extractor import pcap_to_flows
from predictor import Predictor

MODELS_DIR = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\backend\models"
LIVE_PCAP = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\live_traffic.pcap"

def analyze_model_behavior():
    """Analyze what features the model uses for DoS detection"""
    
    print("=" * 70)
    print("🔬 ANALYZING MODEL BEHAVIOR - Why DoS is detected frequently?")
    print("=" * 70)
    
    # Load model artifacts
    scaler = joblib.load(f"{MODELS_DIR}/scaler.pkl")
    label_encoder = joblib.load(f"{MODELS_DIR}/label_encoder.pkl")
    
    print(f"\n📊 Model Info:")
    print(f"   Classes: {label_encoder.classes_}")
    print(f"   Features: {scaler.n_features_in_}")
    
    # Extract features from live traffic
    print(f"\n📁 Analyzing: {LIVE_PCAP}")
    df = pcap_to_flows(LIVE_PCAP)
    
    if df.empty:
        print("⚠️  No flows found in PCAP")
        return
    
    print(f"   Flows extracted: {len(df)}")
    
    # Scale features
    X_scaled = scaler.transform(df.values)
    
    # Analyze feature distributions
    print(f"\n📈 Feature Analysis:")
    
    # Key features for DoS detection (based on CICIDS2017):
    # Feature 0: Duration
    # Feature 1: Total packets
    # Feature 3: Flow bytes/s
    # Feature 4: Flow packets/s
    # Feature 12: Fwd bytes/s
    
    key_features = {
        0: "Duration",
        1: "Total Packets",
        3: "Flow Bytes/s",
        4: "Flow Packets/s",
        12: "Fwd Bytes/s",
        7: "Fwd Packets",
        14: "Bwd Packets"
    }
    
    print("\n   Key DoS Indicators (before scaling):")
    for idx, name in key_features.items():
        if idx < df.shape[1]:
            values = df.iloc[:, idx]
            print(f"   {name:20s}: mean={values.mean():10.2f}, std={values.std():10.2f}, max={values.max():10.2f}")
    
    # DoS characteristics:
    print("\n📋 Typical DoS Characteristics in CICIDS2017:")
    print("   • High packet rate (>100 packets/s)")
    print("   • High byte rate (>100KB/s)")
    print("   • Short duration (<10s)")
    print("   • Many forward packets, few backward")
    print("   • Small packet sizes")
    
    # Analyze your traffic
    print("\n🔍 Your Traffic Characteristics:")
    
    if df.shape[1] > 4:
        packets_per_sec = df.iloc[:, 4] if 4 < df.shape[1] else df.iloc[:, 1]
        bytes_per_sec = df.iloc[:, 3] if 3 < df.shape[1] else df.iloc[:, 2]
        duration = df.iloc[:, 0]
        
        high_rate_flows = (packets_per_sec > 50).sum()
        short_duration = (duration < 10).sum()
        
        print(f"   Flows with high packet rate (>50 pkt/s): {high_rate_flows}/{len(df)} ({high_rate_flows/len(df)*100:.1f}%)")
        print(f"   Flows with short duration (<10s): {short_duration}/{len(df)} ({short_duration/len(df)*100:.1f}%)")
        
        if high_rate_flows > len(df) * 0.3:
            print("\n   ⚠️  WARNING: >30% of flows have DoS-like packet rates!")
            print("   This is why the model classifies them as DoS.")
    
    # Get actual predictions
    print("\n🎯 Current Predictions:")
    predictor = Predictor(MODELS_DIR, confidence_threshold=0.75)
    results = predictor.predict_df_with_scores(df)
    
    if results:
        from collections import Counter
        prediction_counts = Counter(label for label, _ in results)
        
        print("\n   Prediction Distribution:")
        for label, count in sorted(prediction_counts.items(), key=lambda x: -x[1]):
            percentage = count / len(results) * 100
            avg_score = np.mean([score for l, score in results if l == label])
            print(f"   {label:25s}: {count:3d} ({percentage:5.1f}%) - avg confidence: {avg_score:.3f}")
    
    print("\n" + "=" * 70)
    print("💡 RECOMMENDATIONS:")
    print("=" * 70)
    
    print("""
1. ADJUST CONFIDENCE THRESHOLD:
   • Current: 0.75
   • Try: 0.85 or 0.90 to filter more aggressively
   • Command: POST http://localhost:8000/api/set-threshold?threshold=0.85

2. YOUR LOCALHOST TRAFFIC CHARACTERISTICS:
   • Browser auto-refresh = high packet rate → looks like DoS
   • API polling = repetitive connections → looks like DoS
   • WebSocket = continuous connection → looks like Bot
   
3. TO TEST PROPERLY:
   • Run dummy_server.py in another terminal
   • Run attack_simulator_v2.py to generate varied attacks
   • Use higher threshold (0.85) to reduce false positives
   
4. FOR PRODUCTION:
   • Retrain model on your specific network baseline
   • Or whitelist localhost traffic
   • Or use threshold >0.85 for strict filtering
""")

def compare_thresholds():
    """Show how different thresholds affect predictions"""
    print("\n" + "=" * 70)
    print("🎚️  THRESHOLD COMPARISON")
    print("=" * 70)
    
    df = pcap_to_flows(LIVE_PCAP)
    if df.empty:
        return
    
    thresholds = [0.60, 0.70, 0.75, 0.80, 0.85, 0.90]
    
    print("\nPredictions at different confidence thresholds:\n")
    print(f"{'Threshold':<12} {'Benign':<10} {'Malicious':<12} {'Detection Rate':<15}")
    print("-" * 70)
    
    for thresh in thresholds:
        predictor = Predictor(MODELS_DIR, confidence_threshold=thresh)
        results = predictor.predict_df_with_scores(df)
        
        if results:
            benign = sum(1 for label, _ in results if label.upper() == "BENIGN")
            malicious = len(results) - benign
            rate = malicious / len(results) * 100
            
            print(f"{thresh:<12.2f} {benign:<10} {malicious:<12} {rate:<15.1f}%")
    
    print("\n💡 Recommended threshold: 0.75-0.85 for balanced detection")

if __name__ == "__main__":
    analyze_model_behavior()
    compare_thresholds()