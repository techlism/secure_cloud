# database.py
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional
import json
from datetime import datetime

from config import DATABASE_PATH

class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.setup_database()
    
    def clear_database(self):
        """Clear all data from the database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM files")
            conn.execute("DELETE FROM blocks")
            conn.execute("DELETE FROM tags")
    
    def see_all_tags(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tags")
            return [dict(row) for row in cursor.fetchall()]
    
    def see_all_blocks(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM blocks")
            return [dict(row) for row in cursor.fetchall()]
    
    def see_all_files(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM files")
            return [dict(row) for row in cursor.fetchall()]
    
    def setup_database(self):
        """Initialize the database schema with updated structure"""
        with sqlite3.connect(self.db_path) as conn:
            # Files table remains largely the same
            conn.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    original_name TEXT NOT NULL,
                    mime_type TEXT,
                    size_bytes INTEGER,
                    created_at TIMESTAMP,
                    metadata TEXT
                )
            """)
            
            # Updated blocks table with content preview
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocks (
                    block_id TEXT PRIMARY KEY,
                    file_id TEXT,
                    block_index INTEGER,
                    s3_key TEXT,
                    hash TEXT,
                    size_bytes INTEGER,
                    content_preview TEXT,
                    iv TEXT,
                    FOREIGN KEY (file_id) REFERENCES files(file_id)
                )
            """)
            
            # Updated tags table to reference blocks instead of files
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tags (
                    tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    block_id TEXT,
                    tag TEXT NOT NULL,
                    tag_type TEXT NOT NULL,
                    relevance_score FLOAT,
                    FOREIGN KEY (block_id) REFERENCES blocks(block_id)
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_files_name ON files(original_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_blocks_file ON blocks(file_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tags_block ON tags(block_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tags_search ON tags(tag)")

    def add_block(self, block_id: str, file_id: str, index: int, 
                  s3_key: str, block_hash: str, size: int, 
                  content_preview: str, iv: str) -> None:
        """Add a new block record with content preview and IV"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO blocks (block_id, file_id, block_index, 
                                  s3_key, hash, size_bytes, content_preview, iv)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (block_id, file_id, index, s3_key, block_hash, 
                  size, content_preview, iv))

    def add_tags(self, block_id: str, tags: List[tuple]) -> None:
        """Add tags for a block with relevance scores"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany("""
                INSERT INTO tags (block_id, tag, tag_type, relevance_score)
                VALUES (?, ?, ?, ?)
            """, [(block_id, tag, tag_type, score) 
                 for tag, tag_type, score in tags])

    def search_blocks(self, query: str, min_score: float = 0.1) -> List[Dict]:
        """Search for blocks based on tags"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            sql = """
                SELECT DISTINCT 
                    b.*,
                    f.original_name,
                    f.mime_type,
                    t.relevance_score,
                    GROUP_CONCAT(t.tag || ':' || t.tag_type) as tags
                FROM blocks b
                JOIN files f ON b.file_id = f.file_id
                JOIN tags t ON b.block_id = t.block_id
                WHERE t.tag LIKE ?
                AND t.relevance_score >= ?
                GROUP BY b.block_id
                ORDER BY t.relevance_score DESC
            """
            
            cursor.execute(sql, (f"%{query}%", min_score))
            return [dict(row) for row in cursor.fetchall()]
        
    def get_file_blocks(self, file_id: str) -> List[Dict]:
        """
        Get all blocks for a file, ordered by block index
        
        Args:
            file_id (str): The ID of the file to get blocks for
            
        Returns:
            List[Dict]: List of block information dictionaries
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Query includes tags for each block
            cursor.execute("""
                SELECT 
                    b.*,
                    GROUP_CONCAT(t.tag || ':' || t.tag_type) as tags,
                    GROUP_CONCAT(t.relevance_score) as tag_scores
                FROM blocks b
                LEFT JOIN tags t ON b.block_id = t.block_id
                WHERE b.file_id = ?
                GROUP BY b.block_id, b.block_index
                ORDER BY b.block_index
            """, (file_id,))
            
            results = []
            for row in cursor.fetchall():
                block_data = dict(row)
                
                # Process tags and scores if they exist
                if block_data['tags']:
                    tags = block_data['tags'].split(',')
                    scores = [float(score) for score in block_data['tag_scores'].split(',')]
                    block_data['tag_info'] = list(zip(tags, scores))
                else:
                    block_data['tag_info'] = []
                
                # Remove the raw concatenated strings
                del block_data['tags']
                del block_data['tag_scores']
                
                results.append(block_data)
                
            return results        
    def add_file(self, file_id: str, filename: str, mime_type: str, 
                 size: int, metadata: Dict[str, Any]) -> None:
        """Add a new file record"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO files (file_id, original_name, mime_type, 
                                 size_bytes, created_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (file_id, filename, mime_type, size, 
                  datetime.utcnow().isoformat(), 
                  json.dumps(metadata)))
    
    def get_file(self, file_id: str) -> Optional[Dict]:
        """Get file information by file_id"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM files WHERE file_id = ?
            """, (file_id,))
            
            row = cursor.fetchone()
            if row:
                result = dict(row)
                result['metadata'] = json.loads(result['metadata'])
                return result
            return None      
          
def __main__():
    db_path = DATABASE_PATH
    print(f"Database path: {db_path}")
    print(f"Database exists: {db_path.exists()}")
    db = DatabaseManager(db_path)
    # db.clear_database()
    db.__init__(db_path)
    # print(db.see_all_files())

if __name__ == '__main__':
    __main__()
    
