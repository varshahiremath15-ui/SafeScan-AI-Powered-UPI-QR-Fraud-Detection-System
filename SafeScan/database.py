"""
SQLite Database Layer for SafeScan
Maintains persistent audit logs and scan history for analyzed payments.
"""

import os
import sqlite3
import json
from datetime import datetime

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

def get_db_path() -> str:
    """
    Returns appropriate writable database path.
    In serverless environments like Vercel, the source directory is read-only,
    so we route the SQLite database file to /tmp/safescan.db.
    """
    if os.environ.get('VERCEL') or not os.access(CURRENT_DIR, os.W_OK):
        tmp_db = os.path.join('/tmp', 'safescan.db')
        source_db = os.path.join(CURRENT_DIR, 'safescan.db')
        if not os.path.exists(tmp_db) and os.path.exists(source_db):
            import shutil
            try:
                shutil.copy2(source_db, tmp_db)
            except Exception:
                pass
        return tmp_db
    return os.path.join(CURRENT_DIR, 'safescan.db')

def get_connection():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database and create tables if they do not exist."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_data TEXT NOT NULL,
            prediction TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            features TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()

def insert_scan(input_data: str, prediction: str, risk_score: int, features: dict) -> int:
    """Insert a new scan result into SQLite database."""
    conn = get_connection()
    cursor = conn.cursor()
    features_json = json.dumps(features, ensure_ascii=False)
    cursor.execute("""
        INSERT INTO scans (input_data, prediction, risk_score, features, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (input_data, prediction, risk_score, features_json, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_recent_scans(limit: int = 50):
    """Fetch recent scans ordered by latest first."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, input_data, prediction, risk_score, features, created_at
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    
    results = []
    for row in rows:
        feat_dict = {}
        try:
            feat_dict = json.loads(row['features'])
        except Exception:
            pass
        results.append({
            'id': row['id'],
            'input_data': row['input_data'],
            'prediction': row['prediction'],
            'risk_score': row['risk_score'],
            'features': feat_dict,
            'created_at': row['created_at']
        })
    conn.close()
    return results

def get_scan_by_id(scan_id: int):
    """Retrieve single scan record by ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, input_data, prediction, risk_score, features, created_at
        FROM scans
        WHERE id = ?
    """, (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    try:
        feat_dict = json.loads(row['features'])
    except Exception:
        feat_dict = {}
    return {
        'id': row['id'],
        'input_data': row['input_data'],
        'prediction': row['prediction'],
        'risk_score': row['risk_score'],
        'features': feat_dict,
        'created_at': row['created_at']
    }

def get_scan_statistics():
    """Compute aggregate scan metrics for cybersecurity dashboard."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS total FROM scans")
    total = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) AS safe_count FROM scans WHERE prediction = 'SAFE'")
    safe = cursor.fetchone()['safe_count']

    cursor.execute("SELECT COUNT(*) AS suspicious_count FROM scans WHERE prediction = 'SUSPICIOUS'")
    suspicious = cursor.fetchone()['suspicious_count']

    cursor.execute("SELECT COUNT(*) AS high_risk_count FROM scans WHERE prediction = 'HIGH RISK'")
    high_risk = cursor.fetchone()['high_risk_count']

    cursor.execute("SELECT AVG(risk_score) AS avg_score FROM scans")
    avg_score = cursor.fetchone()['avg_score']
    avg_score = round(avg_score, 1) if avg_score is not None else 0.0

    conn.close()
    return {
        'total': total,
        'safe': safe,
        'suspicious': suspicious,
        'high_risk': high_risk,
        'avg_risk_score': avg_score
    }
