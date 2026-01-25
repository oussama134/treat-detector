# database.py - SQLite database manager for IDS alerts and predictions
"""
Professional IDS database with:
- Unlimited history (7 days retention)
- 5-tuple storage (src_ip, dst_ip, src_port, dst_port, protocol)
- Fast filtering (IP, attack type, date, score)
- Export to CSV/JSON
"""

import sqlite3
import json
from datetime import datetime, timedelta
from contextlib import contextmanager
import os

DB_PATH = r"C:\Users\lenovo\Desktop\cybersec-anamoly-detector\data\ids_alerts.db"
RETENTION_DAYS = 7  # Keep 1 week of history

class IDSDatabase:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self._init_db()
        
        print(f"✅ Database initialized: {db_path}")
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Predictions table (all traffic)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sequence INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    label TEXT NOT NULL,
                    score REAL NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    packet_count INTEGER,
                    byte_count INTEGER,
                    duration REAL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Alerts table (malicious traffic only)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sequence INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    label TEXT NOT NULL,
                    score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    details TEXT,
                    acknowledged BOOLEAN DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Statistics table (daily aggregates)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS daily_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL UNIQUE,
                    total_flows INTEGER DEFAULT 0,
                    benign_count INTEGER DEFAULT 0,
                    malicious_count INTEGER DEFAULT 0,
                    attack_types TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for fast queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_predictions_timestamp 
                ON predictions(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_predictions_label 
                ON predictions(label)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp 
                ON alerts(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_label 
                ON alerts(label)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_src_ip 
                ON alerts(src_ip)
            """)
    
    def add_prediction(self, sequence, label, score, flow_info=None):
        """
        Add a prediction to the database
        
        Args:
            sequence: Sequence number
            label: Predicted label (BENIGN or attack type)
            score: Confidence score
            flow_info: Dict with 5-tuple and stats (optional)
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            timestamp = datetime.now().isoformat()
            
            # Extract flow info if provided
            src_ip = flow_info.get('src_ip') if flow_info else None
            dst_ip = flow_info.get('dst_ip') if flow_info else None
            src_port = flow_info.get('src_port') if flow_info else None
            dst_port = flow_info.get('dst_port') if flow_info else None
            protocol = flow_info.get('protocol') if flow_info else None
            packet_count = flow_info.get('packet_count') if flow_info else None
            byte_count = flow_info.get('byte_count') if flow_info else None
            duration = flow_info.get('duration') if flow_info else None
            
            cursor.execute("""
                INSERT INTO predictions 
                (sequence, timestamp, label, score, src_ip, dst_ip, 
                 src_port, dst_port, protocol, packet_count, byte_count, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (sequence, timestamp, label, score, src_ip, dst_ip, 
                  src_port, dst_port, protocol, packet_count, byte_count, duration))
            
            return cursor.lastrowid
    
    def add_alert(self, sequence, label, score, message, flow_info=None):
        """Add an alert (malicious traffic) to the database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            timestamp = datetime.now().isoformat()
            severity = "high" if score > 0.85 else "medium" if score > 0.75 else "low"
            
            # Extract flow info
            src_ip = flow_info.get('src_ip') if flow_info else None
            dst_ip = flow_info.get('dst_ip') if flow_info else None
            src_port = flow_info.get('src_port') if flow_info else None
            dst_port = flow_info.get('dst_port') if flow_info else None
            protocol = flow_info.get('protocol') if flow_info else None
            details = json.dumps(flow_info) if flow_info else None
            
            cursor.execute("""
                INSERT INTO alerts 
                (sequence, timestamp, label, score, severity, message,
                 src_ip, dst_ip, src_port, dst_port, protocol, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (sequence, timestamp, label, score, severity, message,
                  src_ip, dst_ip, src_port, dst_port, protocol, details))
            
            return cursor.lastrowid
    
    def get_recent_predictions(self, limit=100):
        """Get recent predictions"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM predictions 
                ORDER BY id DESC 
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_recent_alerts(self, limit=50, acknowledged=None):
        """Get recent alerts"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM alerts"
            params = []
            
            if acknowledged is not None:
                query += " WHERE acknowledged = ?"
                params.append(1 if acknowledged else 0)
            
            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_filtered_alerts(self, filters):
        """
        Get filtered alerts
        
        Args:
            filters: Dict with optional keys:
                - start_date: ISO datetime string
                - end_date: ISO datetime string
                - label: Attack type
                - src_ip: Source IP address
                - dst_ip: Destination IP address
                - min_score: Minimum confidence score
                - max_score: Maximum confidence score
                - severity: Alert severity
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if filters.get('start_date'):
                query += " AND timestamp >= ?"
                params.append(filters['start_date'])
            
            if filters.get('end_date'):
                query += " AND timestamp <= ?"
                params.append(filters['end_date'])
            
            if filters.get('label'):
                query += " AND label = ?"
                params.append(filters['label'])
            
            if filters.get('src_ip'):
                query += " AND src_ip = ?"
                params.append(filters['src_ip'])
            
            if filters.get('dst_ip'):
                query += " AND dst_ip = ?"
                params.append(filters['dst_ip'])
            
            if filters.get('min_score') is not None:
                query += " AND score >= ?"
                params.append(filters['min_score'])
            
            if filters.get('max_score') is not None:
                query += " AND score <= ?"
                params.append(filters['max_score'])
            
            if filters.get('severity'):
                query += " AND severity = ?"
                params.append(filters['severity'])
            
            query += " ORDER BY timestamp DESC"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_statistics(self, days=7):
        """
        Get statistics for last N days
        
        Args:
            days: Number of days (can be fractional for hours/minutes)
                  Examples: 0.003 = 5 minutes, 0.042 = 1 hour, 1 = 24 hours
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Convert days to timedelta (supports fractional days)
            start_date = (datetime.now() - timedelta(days=float(days))).isoformat()
            
            # Total predictions
            cursor.execute("""
                SELECT COUNT(*) as total FROM predictions 
                WHERE timestamp >= ?
            """, (start_date,))
            total = cursor.fetchone()['total']
            
            # Benign vs Malicious
            cursor.execute("""
                SELECT 
                    COUNT(CASE WHEN label = 'BENIGN' THEN 1 END) as benign,
                    COUNT(CASE WHEN label != 'BENIGN' THEN 1 END) as malicious
                FROM predictions 
                WHERE timestamp >= ?
            """, (start_date,))
            counts = cursor.fetchone()
            
            # Attack type distribution
            cursor.execute("""
                SELECT label, COUNT(*) as count 
                FROM predictions 
                WHERE timestamp >= ? AND label != 'BENIGN'
                GROUP BY label 
                ORDER BY count DESC
            """, (start_date,))
            attack_types = {row['label']: row['count'] for row in cursor.fetchall()}
            
            # Top source IPs
            cursor.execute("""
                SELECT src_ip, COUNT(*) as count 
                FROM alerts 
                WHERE timestamp >= ? AND src_ip IS NOT NULL
                GROUP BY src_ip 
                ORDER BY count DESC 
                LIMIT 10
            """, (start_date,))
            top_ips = [(row['src_ip'], row['count']) for row in cursor.fetchall()]
            
            # Calculate period label for display
            if days < 0.01:  # Less than ~15 minutes
                period_label = f"{int(days * 24 * 60)} minutes"
            elif days < 0.5:  # Less than 12 hours
                period_label = f"{days * 24:.1f} hours"
            elif days == 1:
                period_label = "24 hours"
            else:
                period_label = f"{int(days)} days"
            
            return {
                'total': total,
                'benign': counts['benign'],
                'malicious': counts['malicious'],
                'attack_types': attack_types,
                'top_source_ips': top_ips,
                'period_days': float(days),
                'period_label': period_label
            }
    
    def cleanup_old_data(self, days=RETENTION_DAYS):
        """Delete data older than N days"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            # Delete old predictions
            cursor.execute("""
                DELETE FROM predictions WHERE timestamp < ?
            """, (cutoff_date,))
            pred_deleted = cursor.rowcount
            
            # Delete old alerts
            cursor.execute("""
                DELETE FROM alerts WHERE timestamp < ?
            """, (cutoff_date,))
            alerts_deleted = cursor.rowcount
            
            # Vacuum to reclaim space
            cursor.execute("VACUUM")
            
            return {
                'predictions_deleted': pred_deleted,
                'alerts_deleted': alerts_deleted,
                'cutoff_date': cutoff_date
            }
    
    def export_to_csv(self, table='alerts', filepath=None, filters=None):
        """Export data to CSV"""
        import csv
        
        if filepath is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"ids_{table}_{timestamp}.csv"
        
        if table == 'alerts':
            data = self.get_filtered_alerts(filters or {})
        else:
            data = self.get_recent_predictions(limit=10000)
        
        if not data:
            return None
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        
        return filepath
    
    def export_to_json(self, table='alerts', filepath=None, filters=None):
        """Export data to JSON"""
        if filepath is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"ids_{table}_{timestamp}.json"
        
        if table == 'alerts':
            data = self.get_filtered_alerts(filters or {})
        else:
            data = self.get_recent_predictions(limit=10000)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        return filepath
    
    def acknowledge_alert(self, alert_id):
        """Mark an alert as acknowledged"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE alerts SET acknowledged = 1 WHERE id = ?
            """, (alert_id,))
            return cursor.rowcount > 0

# Singleton instance
_db_instance = None

def get_db():
    """Get database instance (singleton)"""
    global _db_instance
    if _db_instance is None:
        _db_instance = IDSDatabase()
    return _db_instance

if __name__ == "__main__":
    # Test database
    db = get_db()
    
    # Test adding prediction
    test_flow = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 54321,
        'dst_port': 80,
        'protocol': 'TCP',
        'packet_count': 150,
        'byte_count': 45000,
        'duration': 2.5
    }
    
    db.add_prediction(1, 'BENIGN', 0.95, test_flow)
    db.add_alert(2, 'DoS GoldenEye', 0.92, 'HTTP POST flood detected', test_flow)
    
    # Test queries
    print("Recent predictions:", len(db.get_recent_predictions(10)))
    print("Recent alerts:", len(db.get_recent_alerts(10)))
    print("Statistics:", db.get_statistics(7))
    
    print("\n✅ Database tests passed!")