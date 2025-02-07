import logging
import sqlite3
from pathlib import Path
from typing import List, Dict, Optional
from contextlib import contextmanager
import config
from datetime import datetime

@contextmanager
def get_db_connection():
    """Database connection context manager"""
    conn = sqlite3.connect(config.DATABASE_PATH)
    try:
        yield conn
    finally:
        conn.close()

def get_blocks_by_file_id(file_id: str) -> List[Dict]:
    """Retrieve all blocks for a specific file"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT block_id, file_id, s3_url, auth_tag, timestamp 
            FROM blocks 
            WHERE file_id = ?
            ORDER BY timestamp ASC
        ''', (file_id,))
        
        columns = ['block_id', 'file_id', 's3_url', 'auth_tag', 'timestamp']
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

def get_all_blocks() -> List[Dict]:
    """Retrieve all blocks"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT block_id, file_id, s3_url, auth_tag, timestamp 
            FROM blocks
            ORDER BY timestamp DESC
        ''')
        
        columns = ['block_id', 'file_id', 's3_url', 'auth_tag', 'timestamp']
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

def search_blocks(
    block_id: Optional[str] = None,
    file_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None
) -> List[Dict]:
    """Search blocks with optional filters"""
    query = "SELECT block_id, file_id, s3_url, auth_tag, timestamp FROM blocks WHERE 1=1"
    params = []

    if block_id:
        query += " AND block_id = ?"
        params.append(block_id)
    
    if file_id:
        query += " AND file_id = ?"
        params.append(file_id)
    
    if date_from:
        query += " AND timestamp >= ?"
        params.append(date_from)
    
    if date_to:
        query += " AND timestamp <= ?"
        params.append(date_to)

    query += " ORDER BY timestamp DESC"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        
        columns = ['block_id', 'file_id', 's3_url', 'auth_tag', 'timestamp']
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

def get_file_stats(file_id: str) -> Dict:
    """Get statistics for a specific file"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                COUNT(*) as block_count,
                MIN(timestamp) as first_upload,
                MAX(timestamp) as last_upload
            FROM blocks 
            WHERE file_id = ?
        ''', (file_id,))
        
        row = cursor.fetchone()
        return {
            'file_id': file_id,
            'block_count': row[0],
            'first_upload': row[1],
            'last_upload': row[2]
        }

# Class to manage database configuration        
class DatabaseConfigurator:
    def __init__(self, db_path: str):
        self.db_path = db_path

    @contextmanager
    def get_connection(self):
        """Context manager for SQLite connection."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def init_tables(self):
        """Initializes the tables if they do not exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Create blocks table with composite primary key (block_id, file_id)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocks (
                    block_id TEXT,
                    file_id TEXT,
                    s3_url TEXT,
                    auth_tag TEXT,
                    timestamp TEXT,
                    PRIMARY KEY (block_id, file_id)
                )
            ''')
            # Create keywords table with composite uniqueness on (block_id, file_id, keyword)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS keywords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    block_id TEXT NOT NULL,
                    file_id TEXT NOT NULL,
                    keyword TEXT NOT NULL,
                    UNIQUE (block_id, file_id, keyword)
                )
            ''')
            # Create an index on the keyword field for faster lookups
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_keyword ON keywords(keyword)')
            conn.commit()
            logging.info("Database tables initialized.")

    def drop_table(self, table_name: str):
        """Drops a single table if it exists."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
            conn.commit()
            logging.info(f"Table '{table_name}' dropped.")

    def drop_all_tables(self):
        """Drops all schema-related tables."""
        # Drop keywords first because of potential dependencies on blocks
        self.drop_table("keywords")
        self.drop_table("blocks")
        logging.info("All tables dropped.")

    def reinit_tables(self):
        """Drops all tables and then reinitializes the schema."""
        self.drop_all_tables()
        self.init_tables()
        logging.info("Tables reinitialized successfully.")

# Create an instance using the configured database path
db_configurator = DatabaseConfigurator(config.DATABASE_PATH)
