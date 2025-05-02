#server.py
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
    """Get detailed file information from the database."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Get basic file info from the 'files' table
            cursor.execute('''
                SELECT filename, total_blocks, timestamp
                FROM files
                WHERE file_id = ?
            ''', (file_id,))
            file_result = cursor.fetchone()

            if not file_result:
                raise HTTPException(status_code=404, detail="File not found")

            filename, total_blocks, timestamp = file_result

            # Calculate total file size from the 'blocks' table
            cursor.execute('''
                SELECT SUM(block_size)
                FROM blocks
                WHERE file_id = ?
            ''', (file_id,))
            size_result = cursor.fetchone()
            total_size = size_result[0] if size_result and size_result[0] is not None else 0

            # Get associated keywords
            cursor.execute('''
                SELECT keyword
                FROM keywords
                WHERE file_id = ?
            ''', (file_id,))
            keywords = [row[0] for row in cursor.fetchall()]

            return {
                "file_id": file_id,
                "filename": filename,
                "total_blocks": total_blocks,
                "file_size": total_size,
                "keywords": keywords,
                "upload_date": timestamp # Using the timestamp from files table
            }

    except sqlite3.Error as db_err:
        logging.error(f"Database error retrieving file info for {file_id}: {str(db_err)}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(db_err)}")
    except HTTPException as http_exc:
        # Re-raise HTTP exceptions (like 404)
        raise http_exc
    except Exception as e:
        logging.error(f"Unexpected error retrieving file info for {file_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")

@app.post("/por-proof")
async def generate_por_proof(request: Dict[str, Any]):
    """Generate a PoR proof across multiple files based on the challenge."""
    try:
        file_ids = request["file_ids"]
        challenge_items = request["challenge"]
        p = config.P

        # Organize challenge by file_id
        challenge_dict = {item["file_id"]: {} for item in challenge_items}
        for item in challenge_items:
            challenge_dict[item["file_id"]][item["index"]] = item["coeff"]

        logging.info(f"Processing PoR challenge for files {file_ids} with {len(challenge_items)} blocks")

        if not challenge_dict:
            raise HTTPException(status_code=400, detail="Challenge contains no blocks")

        # Aggregate sigma and mu across all files
        sigma = 0
        mu_dict = {file_id: 0 for file_id in file_ids}

        for file_id in file_ids:
            if file_id not in challenge_dict:
                continue  # Skip files with no challenged blocks

            block_indices = list(challenge_dict[file_id].keys())
            placeholders = ",".join(["?" for _ in block_indices])

            # Query blocks for this file
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(f'''
                    SELECT block_idx, s3_key, tag, block_size
                    FROM blocks
                    WHERE file_id = ? AND block_idx IN ({placeholders})
                ''', [file_id] + block_indices)
                
                blocks_data = cursor.fetchall()

            if not blocks_data:
                logging.warning(f"No blocks found for file {file_id} with indices {block_indices}")
                continue

            found_blocks = {block_idx: (s3_key, tag_hex, block_size) 
                           for block_idx, s3_key, tag_hex, block_size in blocks_data}

            for block_idx, (s3_key, tag_hex, _) in found_blocks.items():
                coeff = challenge_dict[file_id][block_idx]

                # Retrieve block from S3 using keyword arguments
                try:
                    response = s3_client.get_object(
                        Bucket=config.AWS_CONFIG['bucket_name'],
                        Key=s3_key
                    )
                    block_content = response['Body'].read()
                except Exception as e:
                    logging.error(f"Error retrieving block {block_idx} from S3 for file {file_id}: {str(e)}")
                    continue

                # Contribution to mu
                m = int.from_bytes(block_content, 'big') % p
                mu_dict[file_id] = (mu_dict[file_id] + coeff * m) % p

                # Contribution to sigma
                tag = int.from_bytes(bytes.fromhex(tag_hex), 'big')
                sigma = (sigma + coeff * tag) % p

        # Prepare response
        return {
            "sigma": sigma.to_bytes(32, 'big').hex(),
            "mu": {file_id: mu.to_bytes(32, 'big').hex() for file_id, mu in mu_dict.items()}
        }

    except Exception as e:
        logging.error(f"Error generating PoR proof: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))