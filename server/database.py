import logging
import sqlite3
from contextlib import contextmanager
import config


@contextmanager
def get_db_connection():
    """Database connection context manager"""
    conn = sqlite3.connect(config.DATABASE_PATH)
    try:
        yield conn
    finally:
        conn.close()

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
        """Initializes the tables for entire files."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Create files table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    s3_url TEXT,
                    auth_tag TEXT,
                    timestamp TEXT
                )
            ''')
            # Update keywords table to associate with file_id
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS keywords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT NOT NULL,
                    keyword TEXT NOT NULL,
                    UNIQUE (file_id, keyword),
                    FOREIGN KEY (file_id) REFERENCES files(file_id)
                )
            ''')
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
        self.drop_table("keywords")
        self.drop_table("files")
        logging.info("All tables dropped.")

    def reinit_tables(self):
        """Drops all tables and reinitializes the schema."""
        self.drop_all_tables()
        self.init_tables()
        logging.info("Tables reinitialized successfully.")

db_configurator = DatabaseConfigurator(config.DATABASE_PATH)