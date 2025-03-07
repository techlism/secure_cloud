# server.py
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse
import boto3
import sqlite3
import logging
import json
from pathlib import Path
from typing import List, Dict, Optional, Any
import os
from datetime import datetime
from contextlib import contextmanager
import config
from database import db_configurator, get_db_connection

# Setup logging
logging.basicConfig(
    filename=config.LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = FastAPI(title="Secure File Server with Homomorphic Tags")

# Initialize S3 client
s3_client = boto3.client('s3', region_name=config.AWS_CONFIG['region_name'])

def init_app():
    """Initialize the application."""
    # Ensure database is initialized
    db_configurator.init_tables()
    
    # Ensure S3 bucket exists
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
    """
    Create a new file record with metadata.
    
    Args:
        metadata: File metadata including file_id, filename, keywords, total_blocks, and block data
    """
    try:
        file_id = metadata["file_id"]
        filename = metadata["filename"]
        keywords = metadata["keywords"]
        total_blocks = metadata["total_blocks"]
        blocks = metadata["blocks"]
        
        # Insert file record
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Insert file record
            cursor.execute('''
                INSERT INTO files (file_id, filename, total_blocks, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (file_id, filename, total_blocks, datetime.now().isoformat()))
            
            # Insert keywords
            for keyword in keywords:
                cursor.execute('''
                    INSERT OR IGNORE INTO keywords (file_id, keyword)
                    VALUES (?, ?)
                ''', (file_id, keyword))
            
            # Insert block metadata (tags)
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
    """
    Upload a file block to S3.
    
    Args:
        block: Block data
        file_id: File ID
        block_idx: Block index
    """
    try:
        content = await block.read()
        
        # S3 key for this block
        s3_key = f"blocks/{file_id}/{block_idx}"
        
        # Upload block to S3
        s3_client.put_object(
            Bucket=config.AWS_CONFIG['bucket_name'],
            Key=s3_key,
            Body=content
        )
        
        return {"status": "success", "file_id": file_id, "block_idx": block_idx}
    
    except Exception as e:
        logging.error(f"Error uploading block {block_idx} of file {file_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/get-blocks-by-keyword")
async def get_blocks_by_keyword(
    keyword: str,
    block_indices: Optional[str] = None
):
    """
    Retrieve blocks from files that contain a specific keyword.
    
    Args:
        keyword: Keyword to search for
        block_indices: Optional comma-separated block indices
    """
    try:
        # Parse block indices if provided
        specific_blocks = None
        if block_indices:
            specific_blocks = [int(idx) for idx in block_indices.split(",")]
        
        # Get file IDs that contain the keyword
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_id FROM keywords WHERE keyword = ?
            ''', (keyword,))
            file_ids = [row[0] for row in cursor.fetchall()]
            
            if not file_ids:
                return {"message": f"No files found with keyword: {keyword}"}
            
            # Prepare query for blocks
            if specific_blocks:
                placeholders = ",".join(["?"] * len(specific_blocks))
                block_filter = f"AND block_idx IN ({placeholders})"
                params = file_ids + specific_blocks
            else:
                block_filter = ""
                params = file_ids
            
            # Get blocks
            placeholders = ",".join(["?"] * len(file_ids))
            cursor.execute(f'''
                SELECT file_id, block_idx, s3_key, tag, block_size
                FROM blocks
                WHERE file_id IN ({placeholders}) {block_filter}
                ORDER BY file_id, block_idx
            ''', params)
            
            blocks_data = cursor.fetchall()
        
        # Fetch blocks from S3 and combine
        combined_data = bytearray()
        combined_tag_int = 0
        metadata = []
        
        for file_id, block_idx, s3_key, tag_hex, block_size in blocks_data:
            # Get block from S3
            response = s3_client.get_object(
                Bucket=config.AWS_CONFIG['bucket_name'],
                Key=s3_key
            )
            block_content = response['Body'].read()
            
            # Add to combined data
            combined_data.extend(block_content)
            
            # Add tag to combined tag
            tag_int = int.from_bytes(bytes.fromhex(tag_hex), 'big')
            combined_tag_int = (combined_tag_int + tag_int) % config.P
            
            # Add metadata
            metadata.append({
                "file_id": file_id,
                "block_idx": block_idx,
                "block_len": len(block_content)
            })
        
        # Convert combined tag to hex
        combined_tag_hex = combined_tag_int.to_bytes(32, 'big').hex()
        
        return {
            "combined_data": combined_data.hex(),
            "combined_tag": combined_tag_hex,
            "metadata": metadata
        }
    
    except Exception as e:
        logging.error(f"Error retrieving blocks by keyword {keyword}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/get-blocks-by-file-ids")
async def get_blocks_by_file_ids(request: Dict[str, Dict[str, List[int]]]):
    """
    Retrieve specific blocks from specific files.
    
    Args:
        request: Dictionary mapping file_ids to lists of block indices
            Example: {"file_blocks": {"file_id1": [0, 1], "file_id2": [2]}}
    
    Returns:
        JSON response with combined_data (hex), combined_tag (hex), and metadata
    """
    try:
        # Extract file_blocks from request
        file_blocks = request.get("file_blocks", {})
        if not file_blocks:
            raise HTTPException(status_code=400, detail="No file_blocks provided")

        # Create list of (file_id, block_idx) tuples
        block_requests = [
            (file_id, block_idx)
            for file_id in file_blocks
            for block_idx in file_blocks[file_id]
        ]
        
        if not block_requests:
            return {"message": "No blocks requested"}

        # Prepare SQL query with dynamic placeholders
        placeholders = ",".join(["(?, ?)"] * len(block_requests))
        flat_values = [item for tup in block_requests for item in tup]  # Flatten list of tuples

        # Fetch block metadata from database
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f'''
                SELECT file_id, block_idx, s3_key, tag, block_size
                FROM blocks
                WHERE (file_id, block_idx) IN (VALUES {placeholders})
                ORDER BY file_id, block_idx
            ''', flat_values)
            
            blocks_data = cursor.fetchall()

        if not blocks_data:
            return {"message": "No matching blocks found"}

        # Combine blocks and tags
        combined_data = bytearray()
        combined_tag_int = 0
        metadata = []

        for file_id, block_idx, s3_key, tag_hex, block_size in blocks_data:
            # Fetch block content from S3
            response = s3_client.get_object(
                Bucket=config.AWS_CONFIG['bucket_name'],
                Key=s3_key
            )
            block_content = response['Body'].read()

            # Append block to combined data
            combined_data.extend(block_content)

            # Combine homomorphic tag
            tag_int = int.from_bytes(bytes.fromhex(tag_hex), 'big')
            combined_tag_int = (combined_tag_int + tag_int) % config.P

            # Add block metadata
            metadata.append({
                "file_id": file_id,
                "block_idx": block_idx,
                "block_len": len(block_content)
            })

        # Convert combined tag to hex string
        combined_tag_hex = combined_tag_int.to_bytes(32, 'big').hex()

        # Return response
        return {
            "combined_data": combined_data.hex(),
            "combined_tag": combined_tag_hex,
            "metadata": metadata
        }

    except Exception as e:
        logging.error(f"Error retrieving blocks by file IDs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))