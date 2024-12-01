# database.py
import sqlite3
from contextlib import contextmanager
import config
from typing import List, Dict
from datetime import datetime

@contextmanager
def get_db_connection():
    """Database connection context manager"""
    conn = sqlite3.connect(config.DATABASE_PATH)
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize database with simplified schema"""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS blocks (
                block_id TEXT,
                file_id TEXT,
                timestamp TEXT,
                PRIMARY KEY (file_id, block_id)
            )
        ''')
        conn.commit()

def get_blocks_by_file_id(file_id: str) -> List[Dict]:
    """Get block IDs for a file"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT block_id, file_id, timestamp 
            FROM blocks 
            WHERE file_id = ?
            ORDER BY timestamp ASC
        ''', (file_id,))
        
        columns = ['block_id', 'file_id', 'timestamp']
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

def add_block(block_id: str, file_id: str):
    """Add block mapping"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO blocks (block_id, file_id, timestamp)
            VALUES (?, ?, ?)
        ''', (block_id, file_id, datetime.now().isoformat()))
        conn.commit()