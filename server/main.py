# main.py
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
import boto3
import sqlite3
import logging

from fastapi.responses import HTMLResponse
from database import db_configurator
from typing import List, Optional
import config
import json
from datetime import datetime
from pydantic import BaseModel
# Setup logging
logging.basicConfig(
    filename=config.LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize FastAPI
app = FastAPI()

# Initialize S3 client
s3_client = boto3.client('s3', region_name=config.AWS_CONFIG['region_name'])

class VerifyBlocksRequest(BaseModel):
    block_ids: List[str]
    file_id: str

def init_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect(config.DATABASE_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_id TEXT UNIQUE,
            file_id TEXT,
            s3_url TEXT,
            auth_tag TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

@app.post("/upload-block")
async def upload_block(
    file: UploadFile = File(...),
    block_id: str = Form(...),  # Add Form import
    file_id: str = Form(...),
    auth_tag: str = Form(...),
    keywords: str = Form(...)
):
    try:
        keywords = keywords.split('#')
        # Read block content
        content = await file.read()
        
        # Upload to S3
        s3_key = f"{file_id}/{block_id}"
        s3_client.put_object(
            Bucket=config.AWS_CONFIG['bucket_name'],
            Key=s3_key,
            Body=content,
            Metadata={
                'auth_tag': auth_tag,
                'file_id': file_id,
                'block_id': block_id
            }
        )

        # Generate S3 URL
        s3_url = f"https://{config.AWS_CONFIG['bucket_name']}.s3.{config.AWS_CONFIG['region_name']}.amazonaws.com/{s3_key}"

        # Store in database
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO blocks (block_id, file_id, s3_url, auth_tag, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (block_id, file_id, s3_url, auth_tag, datetime.now().isoformat()))
        conn.commit()
        c.executemany('''
            INSERT INTO keywords (block_id, file_id, keyword)
            VALUES (?, ?, ?)
        ''', [(block_id, file_id, keyword) for keyword in keywords])
        conn.commit()
        conn.close()

        logging.info(f"Successfully uploaded block {block_id} for file {file_id}")
        
        return {
            "status": "success",
            "block_id": block_id,
            "s3_url": s3_url
        }

    except Exception as e:
        logging.error(f"Error uploading block {block_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/blocks/{file_id}")
async def get_file_blocks(file_id: str):
    """Get all blocks for a specific file"""
    try:
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM blocks WHERE file_id = ?', (file_id,))
        blocks = c.fetchall()
        conn.close()

        return {
            "file_id": file_id,
            "blocks": [
                {
                    "block_id": block[1],
                    "s3_url": block[3],
                    "auth_tag": block[4],
                    "timestamp": block[5]
                }
                for block in blocks
            ]
        }
    except Exception as e:
        logging.error(f"Error retrieving blocks for file {file_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# @app.post("/verify-blocks")
# async def verify_blocks(request: VerifyBlocksRequest):
#     try:
#         blocks_content = []
#         auth_tags_with_iv = []
        
#         for block_id in request.block_ids:
#             s3_key = f"{request.file_id}/{block_id}"
#             response = s3_client.get_object(
#                 Bucket=config.AWS_CONFIG['bucket_name'],
#                 Key=s3_key
#             )
#             blocks_content.append(response['Body'].read())
#             auth_tags_with_iv.append(response['Metadata']['auth_tag'])
        
#         # No merging of content or auth_tags
#         return {
#             "contents": [content.hex() for content in blocks_content],
#             "auth_tags": auth_tags_with_iv  # List of auth_tags
#         }
        
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

    
@app.get("/")
async def root():
    return {"message": "Welcome to the Secure File Server!"}

@app.post("/admin/init-tables")
async def init_tables():
    """Endpoint to initialize the database tables."""
    try:
        db_configurator.init_tables()
        return {"message": "Tables initialized successfully."}
    except Exception as e:
        logging.error(f"Error initializing tables: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/drop-table/{table_name}")
async def drop_table(table_name: str):
    """Endpoint to drop a specific table."""
    try:
        db_configurator.drop_table(table_name)
        return {"message": f"Table '{table_name}' dropped successfully."}
    except Exception as e:
        logging.error(f"Error dropping table '{table_name}': {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/drop-all-tables")
async def drop_all_tables():
    """Endpoint to drop all tables."""
    try:
        db_configurator.drop_all_tables()
        return {"message": "All tables dropped successfully."}
    except Exception as e:
        logging.error(f"Error dropping all tables: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/reinit-tables")
async def reinit_tables():
    """Endpoint to reinitialize (drop and recreate) all tables."""
    try:
        db_configurator.reinit_tables()
        return {"message": "Tables reinitialized successfully."}
    except Exception as e:
        logging.error(f"Error reinitializing tables: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    


ALLOWED_TABLES = ['blocks', 'keywords']

@app.get("/admin/table/{table_name}", response_class=HTMLResponse)
async def get_table_contents_html(table_name: str):
    """
    Retrieves all the contents of the specified table and returns an HTML page
    with a formatted table. Only 'blocks' and 'keywords' tables are allowed.
    """
    if table_name not in ALLOWED_TABLES:
        raise HTTPException(status_code=400, detail="Invalid table name provided.")

    try:
        conn = sqlite3.connect(config.DATABASE_PATH)
        cursor = conn.cursor()
        query = f"SELECT * FROM {table_name}"
        cursor.execute(query)
        rows = cursor.fetchall()
        # Extract column names from the cursor description
        col_names = [description[0] for description in cursor.description]
        conn.close()

        # Build the HTML content with a simple CSS style for readability
        html_content = f"""
        <html>
            <head>
                <title>Table: {table_name}</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        margin: 20px;
                    }}
                    table {{
                        border-collapse: collapse;
                        width: 100%;
                    }}
                    th, td {{
                        border: 1px solid #dddddd;
                        text-align: left;
                        padding: 8px;
                    }}
                    tr:nth-child(even) {{
                        background-color: #f9f9f9;
                    }}
                    h2 {{
                        color: #333;
                    }}
                </style>
            </head>
            <body>
                <h2>Contents of table: {table_name}</h2>
                <table>
                    <thead>
                        <tr>
        """
        # Add table header with column names
        for col in col_names:
            html_content += f"<th>{col}</th>"
        html_content += "</tr></thead><tbody>"
        
        # Add table rows with cell values
        for row in rows:
            html_content += "<tr>"
            for cell in row:
                html_content += f"<td>{cell}</td>"
            html_content += "</tr>"
        html_content += """
                    </tbody>
                </table>
            </body>
        </html>
        """
        return html_content

    except Exception as e:
        logging.error(f"Error retrieving contents of table '{table_name}': {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
