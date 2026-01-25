# main.py - Production IDS with database persistence

import os
import subprocess
import time
from datetime import datetime
from threading import Thread, Lock
from collections import Counter, defaultdict
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from flow_extractor import pcap_to_flows_with_metadata
from predictor import Predictor
from database import get_db
from traffic_filter import (
    is_benign_system_traffic,
    post_process_prediction,
    should_generate_alert,
    TrafficStats
)

PCAP_PATH = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\live_traffic.pcap"
MODELS_DIR = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\backend\models"
CAPTURE_INTERFACE = "4"  # Loopback interface
CAPTURE_DURATION = 10
CAPTURE_COOLDOWN = 2

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# Initialize database
db = get_db()

# Initialize predictor
pred = Predictor(MODELS_DIR, confidence_threshold=0.85)

# Global counters (for real-time stats)
history_lock = Lock()
sequence_counter = 0
traffic_stats = TrafficStats()
session_stats = {
    "session_start": datetime.now().isoformat(),
    "captures": 0,
    "flows_processed": 0
}

def capture_live_pcap(duration=CAPTURE_DURATION, iface=CAPTURE_INTERFACE):
    """Capture live traffic using tshark"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] 📡 Capturing {duration}s on interface: {iface}")
    
    try:
        subprocess.run([
            r"C:\Program Files\Wireshark\tshark.exe",
            "-i", iface,
            "-a", f"duration:{duration}",
            "-F", "pcap",
            "-w", PCAP_PATH
        ], check=True, timeout=duration+5, capture_output=True, text=True)
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] ✅ Capture done: {PCAP_PATH}")
        return True
        
    except Exception as e:
        print(f"[{timestamp}] ❌ Capture error: {e}")
        return False

def process_capture():
    """Process captured traffic and save to database"""
    global sequence_counter
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    try:
        if not os.path.exists(PCAP_PATH):
            return
        
        file_size = os.path.getsize(PCAP_PATH)
        if file_size == 0:
            return
        
        print(f"[{timestamp}] 🔍 Processing PCAP ({file_size} bytes)...")
        
        # Extract flows with metadata
        df, flow_metadata = pcap_to_flows_with_metadata(PCAP_PATH)
        
        if df.empty:
            return
        
        print(f"[{timestamp}] 📊 Extracted {len(df)} flows")
        
        # Get predictions
        results = pred.predict_df_with_scores(df)
        
        if not results:
            return
      
        # Save to database
        prediction_counts = Counter()
        
        with history_lock:
            for idx, (label, score) in enumerate(results):
                sequence_counter += 1
                
                # Get flow metadata
                if idx < len(flow_metadata):
                    flow_info = flow_metadata[idx]
                else:
                    continue
                
                # Skip benign system traffic
                if is_benign_system_traffic(flow_info):
                    traffic_stats.record_flow(filtered=True)
                    continue  # Do not analyze this flow
                
                traffic_stats.record_flow(filtered=False)
                
                # Post-process prediction
                label, score = post_process_prediction(label, score, flow_info)
                
                prediction_counts[label] += 1
                
                # Save prediction to database
                db.add_prediction(sequence_counter, label, score, flow_info)
                
                # Smart alert generation
                if should_generate_alert(label, score, flow_info):
                    message = f"Detected {label} attack"
                    db.add_alert(sequence_counter, label, score, message, flow_info)
                    traffic_stats.record_alert()
                    print(f"[{timestamp}] 🚨 ALERT: Seq #{sequence_counter} - {label} (score: {score:.3f})")
                elif label.upper() != "BENIGN":
                    # Low-confidence attack prevented
                    traffic_stats.record_false_positive_prevented()
            
            session_stats["captures"] += 1
            session_stats["flows_processed"] += len(df)
        
        print(f"[{timestamp}] ✅ Processed {len(results)} sequences")
        print(f"           Predictions: {dict(prediction_counts)}")
        
        # Log stats at the end
        stats_summary = traffic_stats.get_summary()
        print(f"[{timestamp}] 📊 Stats: {stats_summary['analyzed_flows']} analyzed, "
              f"{stats_summary['filtered_flows']} filtered ({stats_summary['filter_rate']})")
        
    except Exception as e:
        print(f"[{timestamp}] ❌ Processing error: {e}")
        import traceback
        traceback.print_exc()

def background_capture_and_process():
    """Background thread: capture → process → repeat"""
    print("[*] Background capture thread started")
    print(f"[*] Capturing on interface {CAPTURE_INTERFACE} every {CAPTURE_DURATION}s")
    print(f"[*] Dashboard: http://localhost:3000")
    print("-" * 60)
    
    while True:
        try:
            success = capture_live_pcap(CAPTURE_DURATION)
            
            if success:
                process_capture()
            
            time.sleep(CAPTURE_COOLDOWN)
            
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            break
        except Exception as e:
            print(f"[!] Background error: {e}")
            time.sleep(5)

def cleanup_thread():
    """Background thread: cleanup old data daily"""
    while True:
        try:
            # Run cleanup once per day
            time.sleep(86400)  # 24 hours
            
            print("[*] Running daily cleanup...")
            result = db.cleanup_old_data(days=7)
            print(f"[*] Cleaned up {result['predictions_deleted']} predictions, {result['alerts_deleted']} alerts")
            
        except Exception as e:
            print(f"[!] Cleanup error: {e}")

# Start background threads
Thread(target=background_capture_and_process, daemon=True).start()
Thread(target=cleanup_thread, daemon=True).start()

# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/api/dashboard")
def dashboard():
    """Get dashboard data"""
    try:
        predictions = db.get_recent_predictions(limit=100)
        alerts = db.get_recent_alerts(limit=50, acknowledged=False)
        stats = db.get_statistics(days=1)
        
        return {
            "predictions": predictions,
            "alerts": alerts,
            "stats": stats,
            "session": session_stats
        }
    except Exception as e:
        print(f"[!] Dashboard error: {e}")
        return {"error": str(e)}

@app.get("/api/alerts")
def get_alerts(
    limit: int = Query(50, ge=1, le=1000),
    start_date: str = Query(None),
    end_date: str = Query(None),
    label: str = Query(None),
    src_ip: str = Query(None),
    dst_ip: str = Query(None),
    min_score: float = Query(None, ge=0, le=1),
    max_score: float = Query(None, ge=0, le=1),
    severity: str = Query(None)
):
    """Get filtered alerts"""
    try:
        filters = {}
        if start_date:
            filters['start_date'] = start_date
        if end_date:
            filters['end_date'] = end_date
        if label:
            filters['label'] = label
        if src_ip:
            filters['src_ip'] = src_ip
        if dst_ip:
            filters['dst_ip'] = dst_ip
        if min_score is not None:
            filters['min_score'] = min_score
        if max_score is not None:
            filters['max_score'] = max_score
        if severity:
            filters['severity'] = severity
        
        alerts = db.get_filtered_alerts(filters)
        return {"alerts": alerts[:limit], "total": len(alerts)}
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/stats")
def get_stats(days: int = Query(7, ge=1, le=30)):
    """Get statistics for last N days"""
    try:
        stats = db.get_statistics(days=days)
        return stats
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int):
    """Acknowledge an alert"""
    try:
        success = db.acknowledge_alert(alert_id)
        return {"success": success}
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/export/csv")
def export_csv(
    table: str = Query("alerts", regex="^(alerts|predictions)$"),
    start_date: str = Query(None),
    end_date: str = Query(None)
):
    """Export data to CSV"""
    try:
        filters = {}
        if start_date:
            filters['start_date'] = start_date
        if end_date:
            filters['end_date'] = end_date
        
        filepath = db.export_to_csv(table=table, filters=filters)
        
        if filepath and os.path.exists(filepath):
            return FileResponse(
                filepath,
                media_type='text/csv',
                filename=os.path.basename(filepath)
            )
        else:
            raise HTTPException(status_code=404, detail="No data to export")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/export/json")
def export_json(
    table: str = Query("alerts", regex="^(alerts|predictions)$"),
    start_date: str = Query(None),
    end_date: str = Query(None)
):
    """Export data to JSON"""
    try:
        filters = {}
        if start_date:
            filters['start_date'] = start_date
        if end_date:
            filters['end_date'] = end_date
        
        filepath = db.export_to_json(table=table, filters=filters)
        
        if filepath and os.path.exists(filepath):
            return FileResponse(
                filepath,
                media_type='application/json',
                filename=os.path.basename(filepath)
            )
        else:
            raise HTTPException(status_code=404, detail="No data to export")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/set-threshold")
def set_threshold(threshold: float = Query(..., ge=0.5, le=0.95)):
    """Set confidence threshold"""
    try:
        pred.set_confidence_threshold(threshold)
        return {"status": "success", "threshold": threshold}
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/diagnostic")
def diagnostic():
    """System diagnostic"""
    try:
        import joblib
        
        scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
        label_encoder = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
        
        return {
            "status": "operational",
            "model": {
                "features": scaler.n_features_in_,
                "classes": len(label_encoder.classes_),
                "threshold": pred.confidence_threshold
            },
            "database": {
                "recent_predictions": len(db.get_recent_predictions(100)),
                "recent_alerts": len(db.get_recent_alerts(50))
            },
            "session": session_stats,
            "interface": CAPTURE_INTERFACE
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/")
def root():
    return {
        "name": "IDS Backend API",
        "version": "4.0-production",
        "status": "running",
        "endpoints": {
            "dashboard": "/api/dashboard",
            "alerts": "/api/alerts",
            "stats": "/api/stats",
            "export_csv": "/api/export/csv",
            "export_json": "/api/export/json",
            "diagnostic": "/api/diagnostic"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)