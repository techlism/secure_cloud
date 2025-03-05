from fastapi import FastAPI, UploadFile, File, Form, HTTPException
import boto3
import sqlite3
import logging
from fastapi.responses import HTMLResponse
from database import db_configurator
from typing import List, Optional
import config
from datetime import datetime

# Setup logging
logging.basicConfig(
    filename=config.LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = FastAPI()

s3_client = boto3.client('s3', region_name=config.AWS_CONFIG['region_name'])

def init_db():
    """Initialize SQLite database."""
    db_configurator.init_tables()

init_db()

@app.post("/upload-file")
async def upload_file(
    file: UploadFile = File(...),
    file_id: str = Form(...),
    auth_tag: str = Form(...),
    keywords: str = Form(...)
):
    """Upload the entire file and store its metadata and keywords."""
    try:
        keywords_list = keywords.split('#')
        content = await file.read()
        
        s3_key = f"files/{file_id}"
        s3_client.put_object(
            Bucket=config.AWS_CONFIG['bucket_name'],
            Key=s3_key,
            Body=content,
            Metadata={'auth_tag': auth_tag, 'file_id': file_id}
        )
        
        s3_url = f"https://{config.AWS_CONFIG['bucket_name']}.s3.{config.AWS_CONFIG['region_name']}.amazonaws.com/{s3_key}"

        with sqlite3.connect(config.DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO files (file_id, s3_url, auth_tag, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (file_id, s3_url, auth_tag, datetime.now().isoformat()))
            
            cursor.executemany('''
                INSERT OR IGNORE INTO keywords (file_id, keyword)
                VALUES (?, ?)
            ''', [(file_id, keyword) for keyword in keywords_list])
            conn.commit()

        logging.info(f"Successfully uploaded file {file_id}")
        return {"status": "success", "file_id": file_id, "s3_url": s3_url}

    except Exception as e:
        logging.error(f"Error uploading file {file_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/get-file/{file_id}")
async def get_file(file_id: str):
    """Retrieve file content and auth_tag for verification."""
    try:
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT s3_url, auth_tag FROM files WHERE file_id = ?', (file_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="File not found")
            
            s3_url, auth_tag = row
            
            s3_key = s3_url.split('/')[-1]
            response = s3_client.get_object(
                Bucket=config.AWS_CONFIG['bucket_name'],
                Key=s3_key
            )
            content = response['Body'].read()
            
            return {"content": content.hex(), "auth_tag": auth_tag}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def root():
    return {"message": "Welcome to the Secure File Server!"}

# Admin Endpoints
@app.post("/admin/init-tables")
async def init_tables():
    try:
        db_configurator.init_tables()
        return {"message": "Tables initialized successfully."}
    except Exception as e:
        logging.error(f"Error initializing tables: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/drop-table/{table_name}")
async def drop_table(table_name: str):
    try:
        db_configurator.drop_table(table_name)
        return {"message": f"Table '{table_name}' dropped successfully."}
    except Exception as e:
        logging.error(f"Error dropping table '{table_name}': {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/drop-all-tables")
async def drop_all_tables():
    try:
        db_configurator.drop_all_tables()
        return {"message": "All tables dropped successfully."}
    except Exception as e:
        logging.error(f"Error dropping all tables: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/reinit-tables")
async def reinit_tables():
    try:
        db_configurator.reinit_tables()
        return {"message": "Tables reinitialized successfully."}
    except Exception as e:
        logging.error(f"Error reinitializing tables: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

ALLOWED_TABLES = ['files', 'keywords']

@app.get("/admin/table/{table_name}", response_class=HTMLResponse)
async def get_table_contents_html(table_name: str):
    if table_name not in ALLOWED_TABLES:
        raise HTTPException(status_code=400, detail="Invalid table name provided.")
    
    try:
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table_name}")
            rows = cursor.fetchall()
            col_names = [description[0] for description in cursor.description]
        
        html_content = f"""
        <html>
            <head>
                <title>Table: {table_name}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #dddddd; text-align: left; padding: 8px; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                    h2 {{ color: #333; }}
                </style>
            </head>
            <body>
                <h2>Contents of table: {table_name}</h2>
                <table>
                    <thead><tr>{''.join(f'<th>{col}</th>' for col in col_names)}</tr></thead>
                    <tbody>{''.join('<tr>' + ''.join(f'<td>{cell}</td>' for cell in row) + '</tr>' for row in rows)}</tbody>
                </table>
            </body>
        </html>
        """
        return html_content
    except Exception as e:
        logging.error(f"Error retrieving table '{table_name}': {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/files-by-keyword/{keyword}", response_class=HTMLResponse)
async def files_by_keyword(keyword: str):
    """Retrieve files associated with a keyword."""
    try:
        with sqlite3.connect(config.DATABASE_PATH) as conn:
            cursor = conn.cursor()
            query = """
                SELECT f.file_id, f.s3_url, f.auth_tag, f.timestamp
                FROM files f
                JOIN keywords k ON f.file_id = k.file_id
                WHERE k.keyword = ?
                ORDER BY f.timestamp DESC
            """
            cursor.execute(query, (keyword,))
            rows = cursor.fetchall()
            columns = [description[0] for description in cursor.description]
        
        html_content = f"""
        <html>
            <head>
                <title>Files for Keyword: {keyword}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #dddddd; text-align: left; padding: 8px; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                    h2 {{ color: #333; }}
                </style>
            </head>
            <body>
                <h2>Files for Keyword: {keyword}</h2>
                <table>
                    <thead><tr>{''.join(f'<th>{col}</th>' for col in columns)}</tr></thead>
                    <tbody>{''.join('<tr>' + ''.join(f'<td>{cell}</td>' for cell in row) + '</tr>' for row in rows)}</tbody>
                </table>
            </body>
        </html>
        """
        return html_content
    except Exception as e:
        logging.error(f"Error retrieving files for keyword '{keyword}': {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))