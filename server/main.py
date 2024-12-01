# main.py
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
import boto3
import sqlite3
import logging
from pathlib import Path
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
    block_id: str = Form(...),
    file_id: str = Form(...),
    tag: str = Form(...)
):
    try:
        content = await file.read()
        s3_key = f"{file_id}/{block_id}"

        # Upload to S3 with the tag as metadata
        s3_client.put_object(
            Bucket=config.AWS_CONFIG['bucket_name'],
            Key=s3_key,
            Body=content,
            Metadata={
                'tag': tag,
                'file_id': file_id,
                'block_id': block_id
            }
        )

        s3_url = f"https://{config.AWS_CONFIG['bucket_name']}.s3.{config.AWS_CONFIG['region_name']}.amazonaws.com/{s3_key}"

        # Save to database
        conn = sqlite3.connect(config.DATABASE_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO blocks (block_id, file_id, s3_url, auth_tag, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (block_id, file_id, s3_url, tag, datetime.now().isoformat()))
        conn.commit()
        conn.close()

        return {"status": "success", "block_id": block_id, "s3_url": s3_url}

    except Exception as e:
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

# server/main.py - Update verify-blocks endpoint
@app.post("/verify-blocks")
async def verify_blocks(request: VerifyBlocksRequest):
    try:
        tags = []
        block_hashes = []

        for block_id in request.block_ids:
            s3_key = f"{request.file_id}/{block_id}"
            
            # Get tag and block hash from metadata
            response = s3_client.head_object(
                Bucket=config.AWS_CONFIG['bucket_name'],
                Key=s3_key
            )
            tags.append(response['Metadata']['tag'])
            block_hashes.append(response['Metadata']['block_hash'])

        return {
            "tags": tags,
            "block_hashes": block_hashes
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


    
@app.get("/")
async def root():
    return {"message": "Welcome to the Secure File Server!"}

