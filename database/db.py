"""
Database Management Module for AI-Based DDoS Detection System
Handles SQLite3 persistence for threat event logs, telemetry snapshots, and statistics.
"""

import os
import sqlite3
import json
import datetime
from typing import Dict, List, Any, Optional

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "threats.db")

def get_connection():
    """Create and return a thread-safe connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables with indexes for optimal query performance."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Table: threat_events (Detected anomalies and security alerts)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            mode TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_level TEXT NOT NULL,
            packets_per_second REAL NOT NULL,
            bytes_per_second REAL NOT NULL,
            syn_count INTEGER NOT NULL,
            tcp_count INTEGER NOT NULL,
            udp_count INTEGER NOT NULL,
            icmp_count INTEGER NOT NULL,
            connection_count INTEGER NOT NULL,
            unique_source_ips INTEGER NOT NULL,
            unique_destination_ips INTEGER NOT NULL,
            observations TEXT
        )
    """)
    
    # Table: telemetry_snapshots (Periodic sliding window telemetry)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            packets_per_second REAL NOT NULL,
            bytes_per_second REAL NOT NULL,
            tcp_count INTEGER NOT NULL,
            udp_count INTEGER NOT NULL,
            icmp_count INTEGER NOT NULL,
            syn_count INTEGER NOT NULL,
            connection_count INTEGER NOT NULL,
            prediction TEXT NOT NULL,
            risk_level TEXT NOT NULL
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threats_ts ON threat_events(timestamp DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_ts ON telemetry_snapshots(timestamp DESC)")

    conn.commit()
    conn.close()

def log_threat_event(event: Dict[str, Any]) -> int:
    """Insert a newly detected threat into threat_events table."""
    conn = get_connection()
    cursor = conn.cursor()
    
    obs = event.get("observations", [])
    if isinstance(obs, list):
        obs_json = json.dumps(obs)
    else:
        obs_json = str(obs)

    ts = event.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO threat_events (
            timestamp, mode, prediction, confidence, risk_level,
            packets_per_second, bytes_per_second, syn_count, tcp_count,
            udp_count, icmp_count, connection_count, unique_source_ips,
            unique_destination_ips, observations
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ts,
        event.get("mode", "LIVE"),
        event.get("prediction", "POSSIBLE DDoS"),
        float(event.get("confidence", 0.95)),
        event.get("risk_level", "HIGH"),
        float(event.get("packets_per_second", 0)),
        float(event.get("bytes_per_second", 0)),
        int(event.get("syn_count", 0)),
        int(event.get("tcp_count", 0)),
        int(event.get("udp_count", 0)),
        int(event.get("icmp_count", 0)),
        int(event.get("connection_count", 0)),
        int(event.get("unique_source_ips", 0)),
        int(event.get("unique_destination_ips", 0)),
        obs_json
    ))
    
    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return event_id

def log_telemetry_snapshot(metrics: Dict[str, Any], prediction: str, risk_level: str):
    """Log periodic telemetry window into database for aggregated reporting."""
    conn = get_connection()
    cursor = conn.cursor()
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute("""
        INSERT INTO telemetry_snapshots (
            timestamp, packets_per_second, bytes_per_second,
            tcp_count, udp_count, icmp_count, syn_count,
            connection_count, prediction, risk_level
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ts,
        float(metrics.get("packets_per_second", 0)),
        float(metrics.get("bytes_per_second", 0)),
        int(metrics.get("tcp_count", 0)),
        int(metrics.get("udp_count", 0)),
        int(metrics.get("icmp_count", 0)),
        int(metrics.get("syn_count", 0)),
        int(metrics.get("connection_count", 0)),
        prediction,
        risk_level
    ))
    conn.commit()
    conn.close()

def get_recent_threats(limit: int = 25) -> List[Dict[str, Any]]:
    """Retrieve recent threat events for dashboard and history table."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_events ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    
    events = []
    for r in rows:
        d = dict(r)
        if d.get("observations"):
            try:
                d["observations"] = json.loads(d["observations"])
            except Exception:
                d["observations"] = [d["observations"]]
        else:
            d["observations"] = []
        events.append(d)
        
    conn.close()
    return events

def get_threat_by_id(event_id: int) -> Optional[Dict[str, Any]]:
    """Fetch complete event detail by event ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if d.get("observations"):
        try:
            d["observations"] = json.loads(d["observations"])
        except Exception:
            d["observations"] = [d["observations"]]
    return d

def get_system_statistics() -> Dict[str, Any]:
    """Calculate aggregated network statistics from telemetry history."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Aggregated volume from telemetry snapshots
    cursor.execute("""
        SELECT 
            COUNT(*) as total_intervals,
            SUM(packets_per_second * 2) as estimated_packets,
            SUM(bytes_per_second * 2) as estimated_bytes,
            SUM(tcp_count) as total_tcp,
            SUM(udp_count) as total_udp,
            SUM(icmp_count) as total_icmp,
            SUM(CASE WHEN prediction = 'NORMAL' THEN 1 ELSE 0 END) as normal_evaluations,
            SUM(CASE WHEN prediction != 'NORMAL' THEN 1 ELSE 0 END) as ddos_evaluations
        FROM telemetry_snapshots
    """)
    row = cursor.fetchone()
    
    # Total threats from threat_events
    cursor.execute("SELECT COUNT(*) as total_threats FROM threat_events")
    threat_row = cursor.fetchone()
    total_threats = threat_row["total_threats"] if threat_row else 0
    
    total_pkts = int(row["estimated_packets"] or 0)
    total_bytes = int(row["estimated_bytes"] or 0)
    tcp_pkts = int(row["total_tcp"] or 0)
    udp_pkts = int(row["total_udp"] or 0)
    icmp_pkts = int(row["total_icmp"] or 0)
    other_pkts = max(0, total_pkts - (tcp_pkts + udp_pkts + icmp_pkts))
    
    norm_evals = int(row["normal_evaluations"] or 0)
    ddos_evals = int(row["ddos_evaluations"] or 0) + total_threats
    
    # Fallback non-zero defaults for initial visual rendering
    if tcp_pkts == 0 and udp_pkts == 0 and icmp_pkts == 0:
        proto_data = [65, 25, 5, 5]
    else:
        total_p = max(1, tcp_pkts + udp_pkts + icmp_pkts + other_pkts)
        proto_data = [
            round((tcp_pkts / total_p) * 100, 1),
            round((udp_pkts / total_p) * 100, 1),
            round((icmp_pkts / total_p) * 100, 1),
            round((other_pkts / total_p) * 100, 1)
        ]
        
    if norm_evals == 0 and ddos_evals == 0:
        class_data = [95, 5]
    else:
        tot_evals = max(1, norm_evals + ddos_evals)
        class_data = [
            round((norm_evals / tot_evals) * 100, 1),
            round((ddos_evals / tot_evals) * 100, 1)
        ]

    conn.close()

    return {
        "total_packets": total_pkts,
        "total_bytes": total_bytes,
        "normal_count": norm_evals,
        "ddos_count": ddos_evals,
        "protocol_breakdown": proto_data,
        "classification_ratio": class_data
    }

def clear_all_events():
    """Reset and truncate threat_events and telemetry_snapshots tables."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM threat_events")
        cursor.execute("DELETE FROM telemetry_snapshots")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('threat_events', 'telemetry_snapshots')")
        conn.commit()
    finally:
        conn.close()

# Initialize on import
init_db()
