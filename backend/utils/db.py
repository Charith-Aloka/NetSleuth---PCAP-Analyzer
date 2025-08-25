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
        
        conn.commit()
