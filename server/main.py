from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
import boto3
import sqlite3
import logging
import json
from typing import List, Dict, Optional, Any
from datetime import datetime
import config
from database import db_configurator, get_db_connection

# Setup logging
logging.basicConfig(
    filename=config.LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = FastAPI(title="Secure File Server with Shacham-Waters PoR")

# Initialize S3 client
s3_client = boto3.client('s3', region_name=config.AWS_CONFIG['region_name'])

def init_app():
    """Initialize the application."""
    db_configurator.init_tables()
    try:
        s3_client.head_bucket(Bucket=config.AWS_CONFIG['bucket_name'])
    except:
        logging.info(f"Creating S3 bucket: {config.AWS_CONFIG['bucket_name']}")
        s3_client.create_bucket(
            Bucket=config.AWS_CONFIG['bucket_name'],
            CreateBucketConfiguration={'LocationConstraint': config.AWS_CONFIG['region_name']}
        )

init_app()

@app.post("/create-file")
async def create_file(metadata: Dict[str, Any]):
    """Create a new file record with metadata."""
    try:
        file_id = metadata["file_id"]
        filename = metadata["filename"]
        keywords = metadata["keywords"]
        total_blocks = metadata["total_blocks"]
        blocks = metadata["blocks"]

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO files (file_id, filename, total_blocks, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (file_id, filename, total_blocks, datetime.now().isoformat()))

            for keyword in keywords:
                cursor.execute('''
                    INSERT OR IGNORE INTO keywords (file_id, keyword)
                    VALUES (?, ?)
                ''', (file_id, keyword))

            for block in blocks:
                cursor.execute('''
                    INSERT INTO blocks (file_id, block_idx, tag, block_size, s3_key)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    file_id,
                    block["block_idx"],
                    block["tag"],
                    block["size"],
                    f"blocks/{file_id}/{block['block_idx']}"
                ))
            conn.commit()

        return {"status": "success", "file_id": file_id}

    except Exception as e:
        logging.error(f"Error creating file record: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload-block")
async def upload_block(
    block: UploadFile = File(...),
    file_id: str = Form(...),
    block_idx: int = Form(...)
):
    """Upload a file block to S3."""
    try:
        content = await block.read()
        s3_key = f"blocks/{file_id}/{block_idx}"
        s3_client.put_object(
            Bucket=config.AWS_CONFIG['bucket_name'],
            Key=s3_key,
            Body=content
        )
        return {"status": "success", "file_id": file_id, "block_idx": block_idx}

    except Exception as e:
        logging.error(f"Error uploading block {block_idx} of file {file_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/file-info")
async def get_file_info(file_id: str = Query(...)):
    """Get file info (e.g., total blocks) for PoR challenge."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT total_blocks FROM files WHERE file_id = ?
            ''', (file_id,))
            result = cursor.fetchone()
            if not result:
                raise HTTPException(status_code=404, detail="File not found")
            return {"file_id": file_id, "total_blocks": result[0]}
    except Exception as e:
        logging.error(f"Error retrieving file info for {file_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/por-proof")
async def generate_por_proof(request: Dict[str, Any]):
    """Generate a PoR proof for a file based on the challenge."""
    try:
        file_id = request["file_id"]
        challenge = [(item["index"], item["coeff"]) for item in request["challenge"]]
        p = config.P

        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Find all blocks that match the challenge indices
            block_indices = [i for i, _ in challenge]
            placeholders = ",".join(["?"] * len(block_indices))
            
            cursor.execute(f'''
                SELECT block_idx, s3_key, tag, block_size
                FROM blocks
                WHERE file_id = ? AND block_idx IN ({placeholders})
            ''', [file_id] + block_indices)
            
            blocks_data = cursor.fetchall()

        if not blocks_data:
            raise HTTPException(status_code=404, detail="No blocks found for challenge")

        # Create a mapping from block_idx to coefficient for quick lookup
        challenge_dict = {i: nu for i, nu in challenge}
        
        sigma = 0
        mu = 0
        
        for block_idx, s3_key, tag_hex, block_size in blocks_data:
            # Get the correct coefficient for this block
            if block_idx not in challenge_dict:
                continue
                
            coeff = challenge_dict[block_idx]
            
            # Get block content from S3
            response = s3_client.get_object(
                Bucket=config.AWS_CONFIG['bucket_name'],
                Key=s3_key
            )
            block_content = response['Body'].read()
            
            # Compute the block's contribution to mu
            m = int.from_bytes(block_content, 'big') % p
            mu = (mu + coeff * m) % p
            
            # Compute the block's contribution to sigma
            tag = int.from_bytes(bytes.fromhex(tag_hex), 'big')
            sigma = (sigma + coeff * tag) % p

        # Return the proof components
        return {
            "sigma": sigma.to_bytes(32, 'big').hex(),
            "mu": mu.to_bytes(32, 'big').hex()
        }

    except Exception as e:
        logging.error(f"Error generating PoR proof for {request.get('file_id', 'unknown')}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))