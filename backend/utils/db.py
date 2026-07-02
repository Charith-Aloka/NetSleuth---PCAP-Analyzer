"""
Database utilities for NetSleuth PCAP Analyzer
Simple SQLite database operations
"""

import sqlite3
import os
from contextlib import contextmanager

def get_database_path():
    """Get the path to the SQLite database"""
    return os.path.join(os.path.dirname(__file__), '..', '..', 'database', 'netsleuth.db')

@contextmanager
def get_db_connection(db_path=None):
    """Context manager for database connections"""
    if db_path is None:
        db_path = get_database_path()
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Enable column access by name
    try:
        yield conn
    finally:
        conn.close()

def init_database(db_path=None):
    """Initialize the database with required tables"""
    if db_path is None:
        db_path = get_database_path()
    
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Main PCAP files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pcaps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL UNIQUE,
                mime_type TEXT,
                uploaded_at TEXT NOT NULL,
                file_data BLOB NOT NULL
            )
        ''')

        # Analysis summary tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pcap_id INTEGER NOT NULL,
                analyzed_at TEXT NOT NULL,
                duration_ms INTEGER,
                notes TEXT,
                UNIQUE(pcap_id),
                FOREIGN KEY(pcap_id) REFERENCES pcaps(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pcap_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                count INTEGER NOT NULL,
                UNIQUE(pcap_id, ip),
                FOREIGN KEY(pcap_id) REFERENCES pcaps(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pcap_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                mac TEXT,
                hostname TEXT,
                first_seen REAL,
                last_seen REAL,
                UNIQUE(pcap_id, ip),
                FOREIGN KEY(pcap_id) REFERENCES pcaps(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pcap_id INTEGER NOT NULL,
                ip TEXT,
                domain TEXT NOT NULL,
                source TEXT NOT NULL, -- DNS|HTTP|TLS
                count INTEGER NOT NULL DEFAULT 1,
                verdict TEXT,
                UNIQUE(pcap_id, ip, domain, source),
                FOREIGN KEY(pcap_id) REFERENCES pcaps(id) ON DELETE CASCADE
            )
        ''')

        # Backward-compatible migration: ensure 'verdict' and 'explanation' columns exist
        try:
            cols = cursor.execute("PRAGMA table_info(domains)").fetchall()
            col_names = {c[1] for c in cols}
            if 'verdict' not in col_names:
                cursor.execute('ALTER TABLE domains ADD COLUMN verdict TEXT')
            if 'explanation' not in col_names:
                cursor.execute('ALTER TABLE domains ADD COLUMN explanation TEXT')
        except Exception:
            pass

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pcap_id INTEGER NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER,
                protocol TEXT,
                packet_count INTEGER NOT NULL,
                byte_count INTEGER NOT NULL,
                first_seen REAL,
                last_seen REAL,
                UNIQUE(pcap_id, src_ip, src_port, dst_ip, dst_port, protocol),
                FOREIGN KEY(pcap_id) REFERENCES pcaps(id) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()
