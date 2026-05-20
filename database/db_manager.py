"""
SENTINEL - Database Manager
Handles all SQLite operations for storing metrics, threats, and events
"""

import sqlite3
import json
import datetime
import os

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sentinel.db"))


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # Allows concurrent reads + writes
    return conn


def init_db():
    """Create all tables if they don't exist"""
    conn = get_connection()
    c = conn.cursor()

    # Metrics table
    c.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            cpu_percent REAL,
            ram_percent REAL,
            disk_percent REAL,
            ram_used INTEGER,
            bytes_sent INTEGER,
            bytes_recv INTEGER,
            battery_percent REAL,
            temperature TEXT
        )
    """)

    # Processes table
    c.execute("""
        CREATE TABLE IF NOT EXISTS processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            pid INTEGER,
            name TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            risk_score INTEGER,
            is_known INTEGER,
            exe_path TEXT,
            status TEXT
        )
    """)

    # Threats table
    c.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            severity TEXT,
            confidence INTEGER,
            description TEXT,
            detected_at TEXT,
            status TEXT DEFAULT 'ACTIVE',
            auto_action TEXT,
            preventive_steps TEXT,
            user_message TEXT,
            icon TEXT,
            color TEXT,
            anomaly_score REAL,
            raw_data TEXT
        )
    """)

    # Network events table
    c.execute("""
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            local_ip TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER,
            status TEXT,
            pid INTEGER,
            is_suspicious INTEGER
        )
    """)

    # Alerts table
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id TEXT,
            message TEXT,
            sent_at TEXT,
            channel TEXT,
            status TEXT
        )
    """)

    # Packet capture table (for packet inspection)
    c.execute("""
        CREATE TABLE IF NOT EXISTS packet_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            protocol TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            length INTEGER,
            flags TEXT,
            payload_preview TEXT,
            is_suspicious INTEGER DEFAULT 0,
            threat_type TEXT,
            confidence INTEGER
        )
    """)

    # Auto-response history table
    c.execute("""
        CREATE TABLE IF NOT EXISTS auto_response_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id TEXT,
            action TEXT,
            success INTEGER,
            message TEXT,
            executed_at TEXT,
            rollback_instructions TEXT
        )
    """)

    # Quarantine table
    c.execute("""
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            original_path TEXT,
            threat_type TEXT,
            quarantined_at TEXT,
            file_hash TEXT,
            file_size INTEGER
        )
    """)

    conn.commit()
    conn.close()
    print("[OK] Database initialized")


def save_metrics(system_data, network_data):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO metrics (timestamp, cpu_percent, ram_percent, disk_percent,
                             ram_used, bytes_sent, bytes_recv, battery_percent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        system_data.get("timestamp"),
        system_data.get("cpu_percent"),
        system_data.get("ram_percent"),
        system_data.get("disk_percent"),
        system_data.get("ram_used"),
        network_data.get("bytes_sent"),
        network_data.get("bytes_recv"),
        system_data.get("battery_percent")
    ))
    conn.commit()
    conn.close()


def save_threat(threat):
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT OR REPLACE INTO threats
            (id, type, severity, confidence, description, detected_at,
             status, auto_action, preventive_steps, user_message, icon, color, anomaly_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            threat.get("id"),
            threat.get("type"),
            threat.get("severity"),
            threat.get("confidence"),
            threat.get("description"),
            threat.get("detected_at"),
            threat.get("status", "ACTIVE"),
            threat.get("auto_action"),
            json.dumps(threat.get("preventive_steps", [])),
            threat.get("user_message"),
            threat.get("icon"),
            threat.get("color"),
            threat.get("anomaly_score")
        ))
        conn.commit()
    except Exception as e:
        print(f"Error saving threat: {e}")
    finally:
        conn.close()


def get_recent_metrics(limit=60):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM metrics ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_all_threats(status=None):
    conn = get_connection()
    c = conn.cursor()
    if status:
        c.execute("SELECT * FROM threats WHERE status=? ORDER BY detected_at DESC", (status,))
    else:
        c.execute("SELECT * FROM threats ORDER BY detected_at DESC")
    rows = c.fetchall()
    conn.close()
    result = []
    for row in rows:
        d = dict(row)
        try:
            d['preventive_steps'] = json.loads(d.get('preventive_steps') or '[]')
        except Exception:
            d['preventive_steps'] = []
        result.append(d)
    return result


def get_metrics_summary():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT
            AVG(cpu_percent) as avg_cpu,
            MAX(cpu_percent) as max_cpu,
            AVG(ram_percent) as avg_ram,
            COUNT(*) as total_snapshots
        FROM metrics
        WHERE timestamp > datetime('now', '-1 hour')
    """)
    row = c.fetchone()
    conn.close()
    return dict(row) if row else {}


def resolve_threat(threat_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE threats SET status='RESOLVED' WHERE id=?", (threat_id,))
    conn.commit()
    conn.close()


def save_packet_event(packet_data):
    """Save packet event to database"""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO packet_events
            (timestamp, protocol, src_ip, dst_ip, src_port, dst_port,
             length, flags, payload_preview, is_suspicious, threat_type, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            packet_data.get('timestamp', datetime.datetime.now().isoformat()),
            packet_data.get('protocol'),
            packet_data.get('src_ip'),
            packet_data.get('dst_ip'),
            packet_data.get('src_port'),
            packet_data.get('dst_port'),
            packet_data.get('length'),
            packet_data.get('flags'),
            packet_data.get('payload_preview', '')[:200] if packet_data.get('payload_preview') else None,
            1 if packet_data.get('is_suspicious') else 0,
            packet_data.get('threat_type'),
            packet_data.get('confidence', 0)
        ))
        conn.commit()
    except Exception as e:
        print(f"Error saving packet event: {e}")
    finally:
        conn.close()


def get_recent_packets(limit=100, suspicious_only=False):
    """Get recent packet events"""
    conn = get_connection()
    c = conn.cursor()
    if suspicious_only:
        c.execute("""
            SELECT * FROM packet_events 
            WHERE is_suspicious = 1 
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
    else:
        c.execute("""
            SELECT * FROM packet_events 
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_packet_statistics():
    """Get packet statistics"""
    conn = get_connection()
    c = conn.cursor()
    
    stats = {}
    
    # Total packets
    c.execute("SELECT COUNT(*) as total FROM packet_events")
    stats['total'] = c.fetchone()['total']
    
    # Suspicious packets
    c.execute("SELECT COUNT(*) as suspicious FROM packet_events WHERE is_suspicious = 1")
    stats['suspicious'] = c.fetchone()['suspicious']
    
    # Protocol distribution
    c.execute("""
        SELECT protocol, COUNT(*) as count 
        FROM packet_events 
        GROUP BY protocol
    """)
    stats['protocols'] = {row['protocol']: row['count'] for row in c.fetchall()}
    
    # Threat types
    c.execute("""
        SELECT threat_type, COUNT(*) as count 
        FROM packet_events 
        WHERE threat_type IS NOT NULL
        GROUP BY threat_type
    """)
    stats['threat_types'] = {row['threat_type']: row['count'] for row in c.fetchall()}
    
    conn.close()
    return stats


def save_auto_response_log(threat_id, action, success, message, rollback_instructions):
    """Save auto-response execution log"""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO auto_response_history
            (threat_id, action, success, message, executed_at, rollback_instructions)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            threat_id,
            action,
            1 if success else 0,
            message,
            datetime.datetime.now().isoformat(),
            json.dumps(rollback_instructions) if rollback_instructions else None
        ))
        conn.commit()
    except Exception as e:
        print(f"Error saving auto-response log: {e}")
    finally:
        conn.close()


def get_auto_response_history(limit=50):
    """Get auto-response execution history"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT * FROM auto_response_history 
        ORDER BY executed_at DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    result = []
    for row in rows:
        d = dict(row)
        try:
            d['rollback_instructions'] = json.loads(d.get('rollback_instructions') or '[]')
        except Exception:
            d['rollback_instructions'] = []
        result.append(d)
    return result


def save_quarantine_record(file_path, original_path, threat_type, file_hash, file_size):
    """Save quarantine record"""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO quarantine
            (file_path, original_path, threat_type, quarantined_at, file_hash, file_size)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            file_path,
            original_path,
            threat_type,
            datetime.datetime.now().isoformat(),
            file_hash,
            file_size
        ))
        conn.commit()
    except Exception as e:
        print(f"Error saving quarantine record: {e}")
    finally:
        conn.close()


def get_quarantine_records():
    """Get all quarantine records"""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM quarantine ORDER BY quarantined_at DESC")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]


if __name__ == "__main__":
    init_db()
    print("Database ready at:", os.path.abspath(DB_PATH))
