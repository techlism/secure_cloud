from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Query, Body, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
import boto3
from botocore.exceptions import ClientError
import sqlite3
import logging
import json
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from pydantic import BaseModel, Field # For request body validation
import math
import io

# Import project modules AFTER potential environment variable setup
import config
from database import db_configurator, get_db_connection

# Setup logging
logging.basicConfig(
    filename=config.LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("SecureFileServer")


# --- Pydantic Models for Request Validation ---
class InitiateUploadRequest(BaseModel):
    file_id: str
    filename: str
    file_size: int
    file_type: str

class PresignedUrlRequest(BaseModel):
    s3_key: str
    upload_id: str
    part_number: int

class PartInfo(BaseModel):
    PartNumber: int
    ETag: str

class CompleteUploadRequest(BaseModel):
    file_id: str
    s3_key: str
    upload_id: str
    parts: List[PartInfo]
    block_metadata: List[Dict[str, Any]] # Contains block_idx, tag (hex), size
    keywords: List[str]

class AbortUploadRequest(BaseModel):
    s3_key: str
    upload_id: str

class PoRChallengeItem(BaseModel):
    file_id: str
    index: int # block_idx
    coeff: int # nu

class PoRRequest(BaseModel):
    challenge: List[PoRChallengeItem]

class SmallFileMetadata(BaseModel):
    file_id: str
    filename: str
    file_type: str
    file_category: str
    file_size: int
    keywords: List[str]
    total_blocks: int
    blocks: List[Dict[str, Any]] # block_idx, tag (hex), size


# --- FastAPI App ---
app = FastAPI(title="Secure File Server with Shacham-Waters PoR")

# Initialize S3 client (consider using lifespan events for setup/teardown)
try:
    s3_client = boto3.client('s3', region_name=config.AWS_CONFIG['region_name'])
    # Verify bucket exists and we have access
    s3_client.head_bucket(Bucket=config.AWS_CONFIG['bucket_name'])
    logger.info(f"Successfully connected to S3 bucket: {config.AWS_CONFIG['bucket_name']}")
except ClientError as e:
    error_code = e.response.get('Error', {}).get('Code')
    if error_code == 'NoSuchBucket':
        logger.error(f"S3 Bucket '{config.AWS_CONFIG['bucket_name']}' not found. Please create it or check region/permissions.")
    elif error_code == '403':
         logger.error(f"Access Denied for S3 Bucket '{config.AWS_CONFIG['bucket_name']}'. Check IAM permissions.")
    else:
         logger.error(f"Failed to connect to S3 bucket '{config.AWS_CONFIG['bucket_name']}': {e}")
    # Depending on severity, you might want to exit or run in a degraded mode
    # For now, we'll let it potentially fail later if S3 is needed.
    # sys.exit(1) # Uncomment to force exit if S3 connection fails
except Exception as e:
    logger.error(f"An unexpected error occurred during S3 initialization: {e}")
    # sys.exit(1)

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    logger.info("Initializing database tables...")
    try:
        db_configurator.init_tables()
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        # Decide if the app should stop if DB init fails
        # raise # Re-raise to stop FastAPI startup

# --- Helper Functions ---
def generate_s3_key(file_id: str, filename: str) -> str:
    """Generates a unique S3 key for the file."""
    # Example: store files under a prefix based on file_id
    return f"uploads/{file_id}/{filename}"

# --- Small File Upload Endpoint ---
@app.post("/upload-small-file")
async def upload_small_file(
    file_content: UploadFile = File(...),
    metadata: str = Form(...) # Metadata sent as JSON string in form data
):
    """Handles upload for small files (single PUT to S3)."""
    try:
        meta_dict = json.loads(metadata)
        # Validate metadata using Pydantic model
        validated_meta = SmallFileMetadata(**meta_dict)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid metadata format (must be JSON string).")
    except Exception as e: # Catches Pydantic validation errors
         raise HTTPException(status_code=400, detail=f"Invalid metadata content: {e}")

    file_id = validated_meta.file_id
    filename = validated_meta.filename
    s3_key = generate_s3_key(file_id, filename)
    logger.info(f"Processing small file upload: {filename} (ID: {file_id}) -> S3 Key: {s3_key}")

    try:
        # Read content once
        content = await file_content.read()
        if len(content) != validated_meta.file_size:
             logger.warning(f"File size mismatch for {file_id}. Header: {validated_meta.file_size}, Actual: {len(content)}")
             # Decide how to handle: reject or proceed? For now, proceed but log.

        # Upload to S3
        s3_client.put_object(
            Bucket=config.AWS_CONFIG['bucket_name'],
            Key=s3_key,
            Body=content,
            ContentType=validated_meta.file_type
        )
        logger.info(f"Successfully uploaded small file {s3_key} to S3.")

        # Store metadata in DB
        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                # Insert file record
                cursor.execute('''
                    INSERT INTO files (file_id, filename, total_blocks, file_size, s3_key, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    file_id, filename, validated_meta.total_blocks,
                    validated_meta.file_size, s3_key, datetime.now().isoformat()
                ))

                # Insert keywords
                for keyword in set(validated_meta.keywords): # Ensure unique keywords
                    cursor.execute('INSERT OR IGNORE INTO keywords (file_id, keyword) VALUES (?, ?)', (file_id, keyword))

                # Insert block tags
                for block in validated_meta.blocks:
                    cursor.execute('''
                        INSERT INTO blocks (file_id, block_idx, tag, block_size)
                        VALUES (?, ?, ?, ?)
                    ''', (file_id, block["block_idx"], block["tag"], block["size"]))

                conn.commit()
                logger.info(f"Successfully stored metadata for small file {file_id} in DB.")
            except sqlite3.IntegrityError as e:
                 conn.rollback()
                 logger.error(f"Database integrity error for small file {file_id}: {e}")
                 # Attempt to clean up S3 object if DB fails? Or leave it orphaned?
                 # s3_client.delete_object(Bucket=config.AWS_CONFIG['bucket_name'], Key=s3_key)
                 raise HTTPException(status_code=409, detail=f"Database conflict (e.g., file ID exists): {e}")
            except Exception as e:
                 conn.rollback()
                 logger.error(f"Database error storing metadata for small file {file_id}: {e}")
                 raise HTTPException(status_code=500, detail="Database error during small file metadata storage.")

        return {"status": "success", "file_id": file_id, "s3_key": s3_key}

    except ClientError as e:
        logger.error(f"S3 error during small file upload {s3_key}: {e}")
        raise HTTPException(status_code=500, detail=f"S3 upload failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during small file upload {file_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")


# --- Multipart Upload Endpoints ---

@app.post("/initiate-upload")
async def initiate_upload(request: InitiateUploadRequest):
    """Initiates a multipart upload on S3."""
    file_id = request.file_id
    filename = request.filename
    s3_key = generate_s3_key(file_id, filename)
    logger.info(f"Initiating multipart upload for {filename} (ID: {file_id}) -> S3 Key: {s3_key}")

    try:
        response = s3_client.create_multipart_upload(
            Bucket=config.AWS_CONFIG['bucket_name'],
            Key=s3_key,
            ContentType=request.file_type
            # Can add Metadata={'file_id': file_id} here if useful
        )
        upload_id = response['UploadId']
        logger.info(f"Multipart upload initiated for {s3_key}. Upload ID: {upload_id}")
        return {"upload_id": upload_id, "s3_key": s3_key}
    except ClientError as e:
        logger.error(f"Failed to initiate S3 multipart upload for {s3_key}: {e}")
        raise HTTPException(status_code=500, detail=f"S3 initiation failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error initiating upload for {s3_key}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during initiation.")


@app.post("/get-presigned-url")
async def get_presigned_url(request: PresignedUrlRequest):
    """Generates a pre-signed URL for uploading a part."""
    logger.debug(f"Generating pre-signed URL for part {request.part_number}, Upload ID: {request.upload_id}")
    try:
        url = s3_client.generate_presigned_url(
            ClientMethod='upload_part',
            Params={
                'Bucket': config.AWS_CONFIG['bucket_name'],
                'Key': request.s3_key,
                'UploadId': request.upload_id,
                'PartNumber': request.part_number
            },
            ExpiresIn=config.PRESIGNED_URL_EXPIRY_SECONDS
        )
        return {"url": url}
    except ClientError as e:
        logger.error(f"Failed to generate pre-signed URL for part {request.part_number} (Upload ID: {request.upload_id}): {e}")
        raise HTTPException(status_code=500, detail="S3 pre-signed URL generation failed.")
    except Exception as e:
         logger.error(f"Unexpected error generating presigned URL: {e}")
         raise HTTPException(status_code=500, detail="Internal server error generating URL.")


@app.post("/complete-upload")
async def complete_upload(request: CompleteUploadRequest):
    """Completes the multipart upload on S3 and saves metadata to DB."""
    file_id = request.file_id
    s3_key = request.s3_key
    upload_id = request.upload_id
    logger.info(f"Completing multipart upload for {file_id} (Upload ID: {upload_id}, S3 Key: {s3_key}) with {len(request.parts)} parts.")

    # Structure parts for S3 API
    s3_parts_format = {'Parts': [{'PartNumber': p.PartNumber, 'ETag': p.ETag} for p in request.parts]}

    try:
        # Complete the upload on S3
        s3_client.complete_multipart_upload(
            Bucket=config.AWS_CONFIG['bucket_name'],
            Key=s3_key,
            UploadId=upload_id,
            MultipartUpload=s3_parts_format
        )
        logger.info(f"S3 multipart upload completed successfully for {s3_key}.")

        # Get file size after completion
        try:
            s3_meta = s3_client.head_object(Bucket=config.AWS_CONFIG['bucket_name'], Key=s3_key)
            file_size = s3_meta.get('ContentLength', 0)
            file_type = s3_meta.get('ContentType', 'application/octet-stream') # Get actual type
            if file_size == 0: logger.warning(f"Completed file {s3_key} has size 0.")
        except ClientError as e:
            logger.error(f"Failed to get metadata for completed S3 object {s3_key}: {e}")
            # Proceed with DB insertion? Or fail? For now, proceed but log.
            file_size = -1 # Indicate error or unknown size
            file_type = 'unknown'


        # Store metadata in DB
        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                 # Extract filename from s3_key (assuming structure uploads/{file_id}/{filename})
                 filename = s3_key.split('/')[-1] if '/' in s3_key else s3_key

                 # Insert file record
                 cursor.execute('''
                    INSERT INTO files (file_id, filename, total_blocks, file_size, s3_key, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                 ''', (
                    file_id, filename, len(request.block_metadata),
                    file_size, s3_key, datetime.now().isoformat()
                 ))

                 # Insert keywords
                 for keyword in set(request.keywords):
                    cursor.execute('INSERT OR IGNORE INTO keywords (file_id, keyword) VALUES (?, ?)', (file_id, keyword))

                 # Insert block tags
                 for block in request.block_metadata:
                    cursor.execute('''
                        INSERT INTO blocks (file_id, block_idx, tag, block_size)
                        VALUES (?, ?, ?, ?)
                    ''', (file_id, block["block_idx"], block["tag"], block["size"]))

                 conn.commit()
                 logger.info(f"Successfully stored metadata for completed upload {file_id} in DB.")
            except sqlite3.IntegrityError as e:
                 conn.rollback()
                 logger.error(f"Database integrity error during complete_upload for {file_id}: {e}")
                 # S3 upload succeeded, but DB failed. The file exists on S3 but is not tracked.
                 # This is problematic. Manual cleanup might be needed.
                 # Consider adding a 'pending' state or retry mechanism.
                 raise HTTPException(status_code=409, detail=f"Database conflict storing metadata: {e}")
            except Exception as e:
                 conn.rollback()
                 logger.error(f"Database error storing metadata for {file_id}: {e}")
                 raise HTTPException(status_code=500, detail="Database error storing metadata.")

        return {"status": "success", "file_id": file_id}

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        logger.error(f"S3 error completing multipart upload {upload_id} for {s3_key}: {e}")
        # Check if it's an error indicating the upload doesn't exist (e.g., already aborted/completed)
        if error_code == 'NoSuchUpload':
             logger.warning(f"Upload {upload_id} not found on S3. It might have been aborted or already completed.")
             # Check if file metadata exists in DB already?
             # For now, raise error.
             raise HTTPException(status_code=404, detail=f"S3 upload {upload_id} not found.")
        else:
             # Attempt to abort if completion failed for other reasons? Risky.
             # logger.warning(f"Completion failed, attempting to abort {upload_id}")
             # try: s3_client.abort_multipart_upload(...) # Add abort call here?
             # except: pass # Ignore abort errors
             raise HTTPException(status_code=500, detail="S3 completion failed.")
    except Exception as e:
         logger.error(f"Unexpected error completing upload {file_id}: {e}")
         raise HTTPException(status_code=500, detail="Internal server error during completion.")


@app.post("/abort-upload")
async def abort_upload(request: AbortUploadRequest, background_tasks: BackgroundTasks):
    """Aborts a multipart upload on S3."""
    logger.warning(f"Received request to abort multipart upload ID: {request.upload_id}, S3 Key: {request.s3_key}")

    # Run S3 abort in the background to respond quickly
    background_tasks.add_task(
        s3_client.abort_multipart_upload,
        Bucket=config.AWS_CONFIG['bucket_name'],
        Key=request.s3_key,
        UploadId=request.upload_id
    )
    # Log the attempt, actual success/failure is in the background
    logger.info(f"Scheduled background task to abort upload {request.upload_id} for key {request.s3_key}")

    # Note: We don't explicitly check for ClientError here as it runs in background.
    # Consider adding more robust tracking if needed.
    return {"status": "abort scheduled"}


# --- PoR Endpoint (Refactored for single S3 object) ---

@app.post("/por-proof")
async def generate_por_proof(request: PoRRequest):
    """Generates a PoR proof based on the challenge, fetching data from S3 by range."""
    challenge_items = request.challenge
    p = config.P
    logger.info(f"Processing PoR challenge with {len(challenge_items)} items.")

    if not challenge_items:
        return {"sigma": "0", "mu": {}} # No challenge, return zero proof

    # Group challenge by file_id
    challenge_by_file: Dict[str, List[Tuple[int, int]]] = {} # {file_id: [(idx, coeff), ...]}
    file_ids_in_challenge = set()
    for item in challenge_items:
        if item.file_id not in challenge_by_file:
            challenge_by_file[item.file_id] = []
        challenge_by_file[item.file_id].append((item.index, item.coeff))
        file_ids_in_challenge.add(item.file_id)

    # Fetch necessary file info (S3 key) and block tags from DB
    file_metadata = {} # {file_id: {'s3_key': str, 'block_size': int}}
    block_tags = {} # {file_id: {block_idx: tag_int}}

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Get S3 keys for all files in the challenge
            placeholders = ",".join(["?" for _ in file_ids_in_challenge])
            cursor.execute(f'''
                SELECT file_id, s3_key FROM files WHERE file_id IN ({placeholders})
            ''', list(file_ids_in_challenge))
            file_rows = cursor.fetchall()
            if len(file_rows) != len(file_ids_in_challenge):
                 found_ids = {row[0] for row in file_rows}
                 missing_ids = file_ids_in_challenge - found_ids
                 logger.error(f"PoR Error: Files not found in DB: {missing_ids}")
                 raise HTTPException(status_code=404, detail=f"Files not found: {missing_ids}")

            for file_id, s3_key in file_rows:
                file_metadata[file_id] = {'s3_key': s3_key, 'block_size': config.BLOCK_SIZE} # Assume global block size

            # Get tags for all challenged blocks across all files
            tag_query_params = []
            tag_query_parts = []
            for file_id, challenges in challenge_by_file.items():
                 indices = [idx for idx, coeff in challenges]
                 if indices:
                     placeholders = ",".join(["?" for _ in indices])
                     tag_query_parts.append(f"(file_id = ? AND block_idx IN ({placeholders}))")
                     tag_query_params.extend([file_id] + indices)

            if not tag_query_params:
                 logger.warning("No valid blocks to fetch tags for in PoR challenge.")
                 return {"sigma": "0", "mu": {}}

            full_tag_query = f"SELECT file_id, block_idx, tag FROM blocks WHERE {' OR '.join(tag_query_parts)}"
            cursor.execute(full_tag_query, tag_query_params)
            tag_rows = cursor.fetchall()

            for file_id, block_idx, tag_hex in tag_rows:
                if file_id not in block_tags: block_tags[file_id] = {}
                block_tags[file_id][block_idx] = int.from_bytes(bytes.fromhex(tag_hex), 'big')

    except sqlite3.Error as e:
        logger.error(f"Database error during PoR tag fetch: {e}")
        raise HTTPException(status_code=500, detail="Database error fetching PoR data.")

    # Calculate proof components (sigma, mu)
    total_sigma = 0
    mu_dict = {file_id: 0 for file_id in file_ids_in_challenge}

    for file_id, challenges in challenge_by_file.items():
        if file_id not in file_metadata: continue # Should have been caught earlier
        s3_key = file_metadata[file_id]['s3_key']
        block_size = file_metadata[file_id]['block_size']

        for block_idx, coeff_nu in challenges:
            # --- Calculate Sigma Contribution ---
            if file_id not in block_tags or block_idx not in block_tags[file_id]:
                 logger.error(f"PoR Error: Tag not found for file {file_id}, block {block_idx}")
                 # Fail fast if a required tag is missing
                 raise HTTPException(status_code=404, detail=f"Tag not found for {file_id}:{block_idx}")

            tag_int = block_tags[file_id][block_idx]
            total_sigma = (total_sigma + coeff_nu * tag_int) % p

            # --- Calculate Mu Contribution (Fetch block content from S3) ---
            byte_start = block_idx * block_size
            byte_end = byte_start + block_size - 1 # Inclusive range
            byte_range = f'bytes={byte_start}-{byte_end}'

            try:
                logger.debug(f"Fetching {byte_range} from s3://{config.AWS_CONFIG['bucket_name']}/{s3_key}")
                s3_response = s3_client.get_object(
                    Bucket=config.AWS_CONFIG['bucket_name'],
                    Key=s3_key,
                    Range=byte_range
                )
                block_content = s3_response['Body'].read()

                # Pad if the fetched block is smaller than expected (e.g., last block of file)
                if len(block_content) < block_size:
                     block_content += b'\0' * (block_size - len(block_content))
                elif len(block_content) > block_size:
                     logger.warning(f"Fetched more bytes than expected for block {block_idx} of {file_id}. Check logic.")
                     block_content = block_content[:block_size] # Truncate just in case

                m = int.from_bytes(block_content, 'big') % p
                mu_dict[file_id] = (mu_dict[file_id] + coeff_nu * m) % p

            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code')
                if error_code == 'InvalidRange':
                     logger.error(f"S3 InvalidRange error for {file_id}:{block_idx} ({byte_range}). File might be smaller than expected or block index out of bounds.")
                     # This indicates a potential inconsistency. Should we fail?
                     # Option 1: Fail - raise HTTPException(status_code=400, detail=f"Invalid block range for {file_id}:{block_idx}")
                     # Option 2: Treat as zero block - m = 0 (might compromise security if unexpected)
                     # Option 3: Try fetching without range (if it's the only block?) - complex
                     # Let's fail for now.
                     raise HTTPException(status_code=400, detail=f"Invalid block range for {file_id}:{block_idx}")
                else:
                    logger.error(f"S3 error fetching block {block_idx} for {file_id}: {e}")
                    raise HTTPException(status_code=500, detail=f"S3 error fetching block content for {file_id}:{block_idx}")
            except Exception as e:
                 logger.error(f"Unexpected error fetching/processing block {block_idx} for {file_id}: {e}")
                 raise HTTPException(status_code=500, detail="Internal server error during PoR block processing.")


    # Prepare response
    sigma_hex = total_sigma.to_bytes(32, 'big').hex()
    mu_hex_dict = {fid: mu.to_bytes(32, 'big').hex() for fid, mu in mu_dict.items()}

    logger.info("PoR proof calculation complete.")
    return {"sigma": sigma_hex, "mu": mu_hex_dict}


# --- Other Endpoints (List, Search, Info, Download) ---

@app.get("/list-files")
async def list_files():
    """Lists files stored in the database."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT file_id, filename, file_size, timestamp FROM files ORDER BY timestamp DESC')
            files = [{"file_id": r[0], "filename": r[1], "file_size": r[2], "timestamp": r[3]} for r in cursor.fetchall()]
        return files
    except sqlite3.Error as e:
        logger.error(f"Database error listing files: {e}")
        raise HTTPException(status_code=500, detail="Database error listing files.")

@app.get("/search")
async def search_files(keywords: str = Query(...)):
    """Searches for files by keywords."""
    keyword_list = [k.strip().lower() for k in keywords.split(',') if k.strip()]
    if not keyword_list:
        raise HTTPException(status_code=400, detail="No valid keywords provided.")

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Find file_ids matching ALL keywords
            # This query finds files that have *at least one* of the keywords.
            # To find files matching ALL keywords requires a more complex query.
            placeholders = ",".join(["?" for _ in keyword_list])
            query = f'''
                SELECT DISTINCT f.file_id, f.filename, f.file_size
                FROM files f
                JOIN keywords k ON f.file_id = k.file_id
                WHERE k.keyword IN ({placeholders})
            '''
            # Simple relevance: count matching keywords (adjust query for better scoring)
            # query = f'''
            #     SELECT f.file_id, f.filename, f.file_size, COUNT(k.keyword) as match_score
            #     FROM files f
            #     JOIN keywords k ON f.file_id = k.file_id
            #     WHERE k.keyword IN ({placeholders})
            #     GROUP BY f.file_id, f.filename, f.file_size
            #     ORDER BY match_score DESC
            # '''

            cursor.execute(query, keyword_list)
            # results = [{"file_id": r[0], "filename": r[1], "file_size": r[2], "match_score": r[3]} for r in cursor.fetchall()] # if using scoring
            results = [{"file_id": r[0], "filename": r[1], "file_size": r[2]} for r in cursor.fetchall()]
        return results
    except sqlite3.Error as e:
        logger.error(f"Database error searching files: {e}")
        raise HTTPException(status_code=500, detail="Database error searching files.")


@app.get("/file-info")
async def get_file_info(file_id: str = Query(...)):
    """Gets detailed information about a specific file from the DB."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT f.filename, f.total_blocks, f.file_size, f.s3_key, f.timestamp, GROUP_CONCAT(k.keyword)
                FROM files f
                LEFT JOIN keywords k ON f.file_id = k.file_id
                WHERE f.file_id = ?
                GROUP BY f.file_id
            ''', (file_id,))
            result = cursor.fetchone()
            if not result:
                raise HTTPException(status_code=404, detail="File not found")

            keywords = result[5].split(',') if result[5] else []
            # Add file type from S3 metadata? Could be slow.
            # try:
            #     s3_meta = s3_client.head_object(Bucket=config.AWS_CONFIG['bucket_name'], Key=result[3])
            #     file_type = s3_meta.get('ContentType', 'N/A')
            # except ClientError:
            #     file_type = 'Error fetching type'

            return {
                "file_id": file_id,
                "filename": result[0],
                "total_blocks": result[1],
                "file_size": result[2],
                "s3_key": result[3],
                "timestamp": result[4],
                "keywords": keywords,
                # "file_type": file_type # Add if fetched
            }
    except sqlite3.Error as e:
        logger.error(f"Database error getting file info for {file_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error getting file info.")


@app.get("/download")
async def download_file(file_id: str = Query(...)):
    """Downloads a file by streaming its content from S3."""
    logger.info(f"Download requested for file ID: {file_id}")
    try:
        # 1. Get S3 key from DB
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT s3_key, filename FROM files WHERE file_id = ?', (file_id,))
            result = cursor.fetchone()
            if not result:
                raise HTTPException(status_code=404, detail="File not found in database.")
            s3_key, filename = result

        # 2. Get S3 object stream
        try:
            s3_response = s3_client.get_object(Bucket=config.AWS_CONFIG['bucket_name'], Key=s3_key)
        except ClientError as e:
             error_code = e.response.get('Error', {}).get('Code')
             if error_code == 'NoSuchKey':
                  logger.error(f"File {file_id} found in DB but key '{s3_key}' not found in S3.")
                  raise HTTPException(status_code=404, detail="File data not found in storage.")
             else:
                  logger.error(f"S3 error downloading {s3_key}: {e}")
                  raise HTTPException(status_code=500, detail="Storage error during download.")

        # 3. Stream response
        content_type = s3_response.get('ContentType', 'application/octet-stream')
        content_disp = f'attachment; filename="{filename}"' # Suggest download with original name

        return StreamingResponse(
            s3_response['Body'],
            media_type=content_type,
            headers={'Content-Disposition': content_disp}
        )

    except sqlite3.Error as e:
        logger.error(f"Database error during download request for {file_id}: {e}")
        raise HTTPException(status_code=500, detail="Database error processing download.")
    except HTTPException:
        raise # Re-raise specific HTTP exceptions
    except Exception as e:
        logger.error(f"Unexpected error during download for {file_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during download.")


# Example of running with uvicorn (if not using a separate run script)
if __name__ == "__main__":
    import uvicorn
    # Make sure AWS credentials and region are configured (e.g., via env vars or ~/.aws/credentials)
    # Ensure config.AWS_CONFIG['bucket_name'] is set correctly
    print(f"Starting server. Using S3 bucket: {config.AWS_CONFIG['bucket_name']} in region {config.AWS_CONFIG['region_name']}")
    print(f"Ensure bucket exists and IAM permissions are correct.")
    uvicorn.run(app, host="0.0.0.0", port=8000) # Listen on all interfaces