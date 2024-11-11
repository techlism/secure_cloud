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
        

if __name__ == '__main__':
    # call to prnt all blocks
    print(get_all_blocks())