# main.py
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
import boto3
import sqlite3
import logging
from pathlib import Path
from typing import Optional
import config
import json
from datetime import datetime

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
    auth_tag: str = Form(...)
):
    try:
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
    
@app.get("/")
async def root():
    return {"message": "Welcome to the Secure File Server!"}