import json
import math
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Union, Any
import requests
import uuid
import os
import hmac
import hashlib
from random import randint, sample
import pickle
import mimetypes
import re
import subprocess
import tempfile
import shutil
import logging
from datetime import datetime

# Configure logging (assuming basicConfig is set elsewhere or use below)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("client.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecureFileClient")

# Try to import optional dependencies
try:
    from keybert import KeyBERT
    KEYBERT_AVAILABLE = True
except ImportError:
    logger.warning("KeyBERT not available. Keyword extraction will be limited.")
    KEYBERT_AVAILABLE = False

try:
    import ffmpeg
    FFMPEG_AVAILABLE = True
except ImportError:
    logger.warning("ffmpeg-python not available. Video subtitle extraction will be limited.")
    FFMPEG_AVAILABLE = False

try:
    from docling.document_converter import DocumentConverter
    DOCLING_AVAILABLE = True
except ImportError:
    logger.warning("Docling not available. Advanced document processing will be limited.")
    DOCLING_AVAILABLE = False

# Import config AFTER potential environment variable setup
import config

class SecureFileClient:
    def __init__(self, server_url: str):
        """Initialize the secure file client."""
        self.server_url = server_url.rstrip('/')
        self.p = config.P
        self.alpha = randint(1, self.p - 1) # Global alpha for the client instance (can be per-file if needed)
        self.k = os.urandom(32) # Global PRF key (can be per-file if needed)
        self.block_size = config.BLOCK_SIZE
        self.l = 80  # Security parameter for PoR challenge size
        self.storage_file = Path(config.CLIENT_STORAGE_FILE)

        # Initialize keyword extractor if available
        self.kw_model = KeyBERT() if KEYBERT_AVAILABLE else None
        self.doc_converter = DocumentConverter() if DOCLING_AVAILABLE else None

        self.text_formats = ['.txt', '.md', '.markdown', '.html', '.htm', '.xhtml', '.csv', '.json', '.xml', '.py', '.js', '.java', '.c', '.cpp']
        self.docling_formats = ['.pdf', '.docx', '.xlsx', '.pptx', '.adoc', '.png', '.jpg', '.jpeg', '.tiff', '.bmp']
        self.video_formats = ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv', '.m4v']

        self._init_storage()

    def _init_storage(self):
        """Initialize or load storage for file parameters."""
        if not self.storage_file.exists():
            self.file_params = {}
            self._save_storage()
        else:
            self._load_storage()

    def _save_storage(self):
        """Save file parameters to disk."""
        try:
            with open(self.storage_file, "wb") as f:
                pickle.dump(self.file_params, f)
        except IOError as e:
            logger.error(f"Error saving client storage: {e}")

    def _load_storage(self):
        """Load file parameters from disk."""
        try:
            with open(self.storage_file, "rb") as f:
                self.file_params = pickle.load(f)
        except (IOError, pickle.UnpicklingError, EOFError) as e:
            logger.error(f"Error loading client storage: {e}. Reinitializing.")
            self.file_params = {}

    def prf(self, i: int, key: bytes) -> int:
        """Pseudorandom function using HMAC-SHA256, reduced modulo p."""
        h = hmac.new(key, str(i).encode(), hashlib.sha256).digest()
        return int.from_bytes(h, 'big') % self.p

    def compute_tag(self, block: bytes, block_idx: int, alpha: int, key: bytes) -> int:
        """Compute Shacham-Waters tag: σ_i = f_k(i) + α * m_i mod p."""
        m = int.from_bytes(block, 'big') % self.p
        prf_val = self.prf(block_idx, key)
        return (prf_val + alpha * m) % self.p

    def detect_file_type(self, file_path: Path) -> Dict[str, Any]:
        """Detect file type information."""
        ext = file_path.suffix.lower()
        mime_type, _ = mimetypes.guess_type(file_path)

        category = "binary" # Default
        is_binary = True
        if ext in self.text_formats:
            category = "text"
            is_binary = False
        elif ext in self.docling_formats:
            category = "document"
        elif ext in self.video_formats:
            category = "video"

        if mime_type is None:
            mime_map = {"text": "text/plain", "document": "application/octet-stream", "video": "video/mp4"}
            mime_type = mime_map.get(category, "application/octet-stream")

        return {"mime_type": mime_type, "category": category, "is_binary": is_binary, "extension": ext}

    def extract_keywords_from_filename(self, filename: str) -> List[str]:
        """Extract potential keywords from the filename."""
        name_only = Path(filename).stem
        clean_name = re.sub(r'[_\-.]', ' ', name_only)
        words = [word.lower() for word in clean_name.split() if len(word) > 2]
        return list(set(words))

    def extract_text_from_video(self, file_path: Path) -> str:
        """Extract subtitles/captions from video files using ffmpeg."""
        if not FFMPEG_AVAILABLE: return ""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                subtitle_path = os.path.join(temp_dir, "subtitles.srt")
                try:
                    ffmpeg.input(str(file_path)).output(subtitle_path, map="s").run(quiet=True, overwrite_output=True)
                except ffmpeg.Error:
                    logger.info(f"No embedded subtitles found in {file_path.name}")
                    return ""

                if os.path.exists(subtitle_path) and os.path.getsize(subtitle_path) > 0:
                    with open(subtitle_path, 'r', errors='ignore') as f:
                        content = f.read()
                    clean_content = re.sub(r'\d+:\d+:\d+,\d+ --> \d+:\d+:\d+,\d+', '', content)
                    clean_content = re.sub(r'^\d+$', '', clean_content, flags=re.MULTILINE).strip()
                    return "\n".join(line for line in clean_content.splitlines() if line.strip())
                return ""
        except Exception as e:
            logger.error(f"Error extracting text from video {file_path.name}: {e}")
            return ""

    def process_document_with_docling(self, file_path: Path) -> str:
        """Process document with Docling and extract text content."""
        if not DOCLING_AVAILABLE or not self.doc_converter: return ""
        try:
            result = self.doc_converter.convert(str(file_path))
            return result.document.export_to_text()
        except Exception as e:
            logger.error(f"Error processing document {file_path.name} with Docling: {e}")
            return ""

    def extract_keywords(self, content: str, file_path: Path) -> List[str]:
        """Extract keywords from text content."""
        filename_keywords = self.extract_keywords_from_filename(file_path.name)
        if not content.strip():
            return filename_keywords

        extracted_kw = []
        if KEYBERT_AVAILABLE and self.kw_model:
            try:
                keywords = self.kw_model.extract_keywords(content, top_n=10)
                extracted_kw = [word for word, _ in keywords]
            except Exception as e:
                logger.error(f"KeyBERT extraction error for {file_path.name}: {e}")

        if not extracted_kw: # Fallback or if KeyBERT fails
            words = re.findall(r'\b\w{4,}\b', content.lower()) # Find words with 4+ chars
            stopwords = {'the', 'and', 'of', 'to', 'a', 'in', 'for', 'is', 'on', 'that', 'by', 'this', 'with', 'you', 'it', 'was', 'as', 'at', 'be'}
            filtered_words = [w for w in words if w not in stopwords]
            word_counts = {}
            for word in filtered_words: word_counts[word] = word_counts.get(word, 0) + 1
            sorted_words = sorted(word_counts.items(), key=lambda x: x[1], reverse=True)
            extracted_kw = [word for word, count in sorted_words[:10]]

        # Combine with filename keywords, ensuring uniqueness
        return list(set(extracted_kw + filename_keywords))

    def get_content_and_keywords(self, file_path: Path) -> Tuple[str, List[str]]:
        """Extract text content and keywords based on file type."""
        file_info = self.detect_file_type(file_path)
        logger.info(f"Getting content/keywords for {file_path.name} (type: {file_info['category']})")
        text_content = ""

        if file_info['category'] == "text":
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    text_content = f.read()
            except Exception as e:
                logger.error(f"Error reading text file {file_path.name}: {e}")
        elif file_info['category'] == "document":
            text_content = self.process_document_with_docling(file_path)
        elif file_info['category'] == "video":
            text_content = self.extract_text_from_video(file_path)
        # For binary or unprocessable files, text_content remains ""

        keywords = self.extract_keywords(text_content, file_path)
        return text_content, keywords

    def split_into_blocks(self, content_chunk: bytes) -> List[bytes]:
        """Split a chunk of content into fixed-size blocks."""
        blocks = []
        total_size = len(content_chunk)
        num_blocks = math.ceil(total_size / self.block_size)

        for i in range(num_blocks):
            start = i * self.block_size
            end = min(start + self.block_size, total_size)
            block = content_chunk[start:end]
            # Pad the last block if necessary
            if len(block) < self.block_size:
                block += b'\0' * (self.block_size - len(block))
            blocks.append(block)
        return blocks

    def _process_blocks(self, blocks: List[bytes], alpha: int, key: bytes, start_idx: int = 0) -> List[Dict]:
        """Generate tags for a list of blocks."""
        block_data = []
        for i, block in enumerate(blocks):
            block_idx = start_idx + i
            tag = self.compute_tag(block, block_idx, alpha, key)
            block_data.append({
                "block_idx": block_idx,
                "tag": tag.to_bytes(32, 'big').hex(),
                "size": self.block_size # Assuming all blocks (except maybe last before padding) are block_size
            })
        return block_data

    # --- Multipart Upload Methods ---

    def _initiate_multipart_upload(self, file_id: str, filename: str, file_size: int, file_type: str) -> Tuple[str, str]:
        """Ask server to initiate multipart upload on S3."""
        logger.info(f"Initiating multipart upload for {filename} (ID: {file_id})")
        try:
            response = requests.post(f"{self.server_url}/initiate-upload", json={
                "file_id": file_id,
                "filename": filename,
                "file_size": file_size,
                "file_type": file_type
            })
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()
            logger.info(f"Multipart upload initiated. Upload ID: {data['upload_id']}, S3 Key: {data['s3_key']}")
            return data['upload_id'], data['s3_key']
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to initiate multipart upload: {e}")
            raise

    def _get_presigned_url(self, s3_key: str, upload_id: str, part_number: int) -> str:
        """Get a pre-signed URL from the server for uploading a chunk."""
        logger.debug(f"Requesting pre-signed URL for part {part_number} (Upload ID: {upload_id})")
        try:
            response = requests.post(f"{self.server_url}/get-presigned-url", json={
                "s3_key": s3_key,
                "upload_id": upload_id,
                "part_number": part_number
            })
            response.raise_for_status()
            data = response.json()
            return data['url']
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get pre-signed URL for part {part_number}: {e}")
            raise

    def _upload_chunk_to_s3(self, url: str, chunk: bytes) -> str:
        """Upload a chunk directly to S3 using a pre-signed URL."""
        logger.debug(f"Uploading chunk of size {len(chunk)} bytes to S3.")
        try:
            # Use a session for potential connection reuse benefits
            with requests.Session() as session:
                response = session.put(url, data=chunk)
                response.raise_for_status()
                etag = response.headers.get('ETag')
                if not etag:
                    raise ValueError("ETag not found in S3 response headers.")
                # ETag often includes quotes, remove them
                return etag.strip('"')
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to upload chunk to S3: {e}")
            # Consider adding retry logic here
            raise

    def _complete_multipart_upload(self, file_id: str, s3_key: str, upload_id: str, parts: List[Dict], block_metadata: List[Dict], keywords: List[str]):
        """Tell the server to complete the multipart upload and store metadata."""
        logger.info(f"Completing multipart upload for {file_id} (Upload ID: {upload_id}) with {len(parts)} parts.")
        try:
            response = requests.post(f"{self.server_url}/complete-upload", json={
                "file_id": file_id,
                "s3_key": s3_key,
                "upload_id": upload_id,
                "parts": parts,
                "block_metadata": block_metadata,
                "keywords": keywords
            })
            response.raise_for_status()
            logger.info(f"Multipart upload completed successfully for {file_id}.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to complete multipart upload for {file_id}: {e}")
            # Consider telling the server to abort if completion fails irrevocably
            # self._abort_multipart_upload(s3_key, upload_id)
            raise

    def _abort_multipart_upload(self, s3_key: str, upload_id: str):
        """Tell the server to abort a multipart upload (cleanup)."""
        logger.warning(f"Aborting multipart upload for Upload ID: {upload_id}")
        try:
            response = requests.post(f"{self.server_url}/abort-upload", json={
                "s3_key": s3_key,
                "upload_id": upload_id
            })
            response.raise_for_status()
            logger.info(f"Multipart upload aborted successfully for Upload ID: {upload_id}.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to abort multipart upload {upload_id}: {e}")
            # Log error, but proceed as cleanup might fail

    # --- Main Upload Method ---

    def upload_file(self, file_path: Path, manual_keywords: List[str] = None) -> str:
        """Upload a file, using multipart upload for large files."""
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        logger.info(f"Starting upload process for: {file_path.name}")
        file_id = str(uuid.uuid4())
        file_info = self.detect_file_type(file_path)
        file_size = file_path.stat().st_size

        # Generate dedicated key and alpha for this file for better security isolation
        file_key = os.urandom(32)
        file_alpha = randint(1, self.p - 1)

        # Get keywords
        _, auto_keywords = self.get_content_and_keywords(file_path)
        keywords = list(set(manual_keywords)) if manual_keywords else auto_keywords
        if not keywords: # Ensure keywords list is not empty, use filename as fallback
             keywords = self.extract_keywords_from_filename(file_path.name)
        logger.info(f"Using keywords: {keywords}")

        # Store parameters locally *before* starting upload
        self.file_params[file_id] = {
            'alpha': file_alpha,
            'key': file_key,
            'filename': file_path.name,
            'file_type': file_info['mime_type'],
            'file_size': file_size,
            'upload_timestamp': datetime.now().isoformat()
            # s3_key will be added after successful completion if needed locally
        }
        self._save_storage() # Save immediately

        # --- Multipart Upload Logic ---
        if file_size > config.LARGE_FILE_THRESHOLD_BYTES:
            upload_id = None
            s3_key = None
            try:
                upload_id, s3_key = self._initiate_multipart_upload(
                    file_id, file_path.name, file_size, file_info['mime_type']
                )

                parts_list = []
                all_block_metadata = []
                current_block_index = 0
                part_number = 1

                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(config.S3_MULTIPART_CHUNK_SIZE_BYTES)
                        if not chunk:
                            break

                        logger.info(f"Processing chunk {part_number} ({len(chunk)} bytes)")

                        # 1. Process chunk for blocks and tags
                        blocks = self.split_into_blocks(chunk)
                        chunk_block_metadata = self._process_blocks(blocks, file_alpha, file_key, start_idx=current_block_index)
                        all_block_metadata.extend(chunk_block_metadata)
                        current_block_index += len(blocks)

                        # 2. Get pre-signed URL
                        presigned_url = self._get_presigned_url(s3_key, upload_id, part_number)

                        # 3. Upload chunk to S3
                        etag = self._upload_chunk_to_s3(presigned_url, chunk)
                        parts_list.append({"PartNumber": part_number, "ETag": etag})
                        logger.info(f"Uploaded part {part_number}, ETag: {etag}")

                        part_number += 1

                # 4. Complete the upload
                self._complete_multipart_upload(
                    file_id, s3_key, upload_id, parts_list, all_block_metadata, keywords
                )
                # Optionally store s3_key locally if needed for direct access later
                # self.file_params[file_id]['s3_key'] = s3_key
                # self._save_storage()
                logger.info(f"Successfully uploaded large file {file_path.name} with ID: {file_id}")
                return file_id

            except Exception as e:
                logger.error(f"Multipart upload failed for {file_path.name}: {e}")
                # Attempt to abort the upload on S3 if it was initiated
                if upload_id and s3_key:
                    logger.warning(f"Attempting to abort failed multipart upload: {upload_id}")
                    self._abort_multipart_upload(s3_key, upload_id)
                # Remove local params if upload failed completely before completion
                if file_id in self.file_params: del self.file_params[file_id]
                self._save_storage()
                raise # Re-raise the exception

        # --- Standard Upload Logic (for small files) ---
        else:
            logger.info(f"Processing small file {file_path.name} using standard upload.")
            try:
                with open(file_path, "rb") as f:
                    content = f.read()

                blocks = self.split_into_blocks(content)
                block_metadata = self._process_blocks(blocks, file_alpha, file_key)

                # Use a single request to create file and upload content
                metadata_payload = {
                    "file_id": file_id,
                    "filename": file_path.name,
                    "file_type": file_info['mime_type'],
                    "file_category": file_info['category'],
                    "file_size": file_size,
                    "keywords": keywords,
                    "total_blocks": len(blocks),
                    "blocks": block_metadata # Send tags with initial request
                }

                files = {'file_content': (file_path.name, content, file_info['mime_type'])}
                data = {'metadata': json.dumps(metadata_payload)}

                response = requests.post(f"{self.server_url}/upload-small-file", files=files, data=data)
                response.raise_for_status()

                logger.info(f"Successfully uploaded small file {file_path.name} with ID: {file_id}")
                # Optionally store s3_key locally if needed
                # s3_key = response.json().get('s3_key')
                # if s3_key: self.file_params[file_id]['s3_key'] = s3_key
                # self._save_storage()
                return file_id

            except Exception as e:
                 logger.error(f"Standard upload failed for {file_path.name}: {e}")
                 # Clean up local state
                 if file_id in self.file_params: del self.file_params[file_id]
                 self._save_storage()
                 raise

    # --- PoR Methods (Unchanged conceptually, but rely on server changes) ---

    def generate_multi_file_por_challenge(self, file_ids: List[str]) -> Dict[str, List[Tuple[int, int]]]:
        """Generate a PoR challenge across multiple files."""
        challenge = {}
        total_blocks_per_file = {}

        # Fetch file info (total blocks) for each file
        for file_id in file_ids:
            try:
                # This endpoint should now just return total_blocks from DB
                response = requests.get(f"{self.server_url}/file-info?file_id={file_id}")
                response.raise_for_status()
                file_info = response.json()
                total_blocks = file_info["total_blocks"]
                total_blocks_per_file[file_id] = total_blocks

                if total_blocks == 0:
                     logger.warning(f"File {file_id} has 0 blocks, cannot challenge.")
                     challenge[file_id] = []
                     continue

                # Determine number of blocks to challenge
                l_effective = min(self.l, total_blocks)
                if total_blocks <= l_effective: # Challenge all blocks if fewer than l
                    indices = list(range(total_blocks))
                else:
                    indices = sample(range(total_blocks), l_effective)

                # Generate random coefficients (nu) for each challenged block index (i)
                challenge[file_id] = [(i, randint(1, self.p - 1)) for i in indices]
                logger.info(f"Challenging {len(indices)} blocks for file {file_id} (total: {total_blocks})")

            except requests.exceptions.RequestException as e:
                 logger.error(f"Failed to get file info for {file_id}: {e}")
                 raise Exception(f"Could not get info for file {file_id}") from e
            except KeyError:
                 logger.error(f"Invalid response format for file info {file_id}")
                 raise Exception(f"Invalid info response for file {file_id}")


        return challenge

    def verify_por_proof(self, file_challenges: Dict[str, List[Tuple[int, int]]], server_sigma_hex: str, server_mu_hex_dict: Dict[str, str]) -> bool:
        """Verify the PoR proof received from the server."""
        logger.info("Verifying PoR proof...")
        expected_sigma = 0
        server_sigma = int(server_sigma_hex, 16)
        server_mu_dict = {fid: int(mu_hex, 16) for fid, mu_hex in server_mu_hex_dict.items()}

        for file_id, challenge in file_challenges.items():
            if not challenge: # Skip files with no challenged blocks
                 continue

            if file_id not in self.file_params:
                logger.error(f"Verification Error: Local parameters not found for file {file_id}")
                return False # Cannot verify without local alpha/key

            file_params = self.file_params[file_id]
            alpha = file_params['alpha']
            key = file_params['key']

            file_sigma_contribution = 0
            for i, nu in challenge:
                # Recompute PRF value locally
                prf_value = self.prf(i, key)
                file_sigma_contribution = (file_sigma_contribution + nu * prf_value) % self.p

            # Add this file's PRF contribution to the total expected sigma
            expected_sigma = (expected_sigma + file_sigma_contribution) % self.p

            # Add this file's mu contribution (using server-provided mu) weighted by local alpha
            if file_id not in server_mu_dict:
                 logger.error(f"Verification Error: Server did not provide mu for file {file_id}")
                 return False # Server must provide mu for challenged files
            expected_sigma = (expected_sigma + alpha * server_mu_dict[file_id]) % self.p

        logger.info(f"Expected sigma: {expected_sigma}")
        logger.info(f"Received sigma: {server_sigma}")
        return server_sigma == expected_sigma 

    def request_por_proof(self, file_ids: List[str]) -> Dict:
        """Request and verify PoR proof for a list of files."""
        logger.info(f"Requesting PoR proof for files: {file_ids}")
        try:
            # 1. Generate challenge locally
            file_challenges = self.generate_multi_file_por_challenge(file_ids)

            # Flatten challenge structure for JSON request
            challenge_json_flat = []
            for file_id, challenges in file_challenges.items():
                for i, nu in challenges:
                    challenge_json_flat.append({"file_id": file_id, "index": i, "coeff": nu})

            if not challenge_json_flat:
                 logger.warning("No blocks to challenge across the specified files.")
                 return {"verified": True, "message": "No blocks challenged.", "file_ids": file_ids}


            # 2. Send challenge to server
            response = requests.post(f"{self.server_url}/por-proof", json={
                "challenge": challenge_json_flat # Send the flat list
            })
            response.raise_for_status()
            data = response.json()

            # 3. Verify the received proof (sigma, mu values)
            server_sigma_hex = data["sigma"]
            server_mu_hex_dict = data["mu"]
            verified = self.verify_por_proof(file_challenges, server_sigma_hex, server_mu_hex_dict)

            return {"verified": verified, "file_ids": file_ids}

        except requests.exceptions.RequestException as e:
            logger.error(f"PoR request failed: {e}")
            raise Exception("PoR request failed") from e
        except Exception as e:
            logger.error(f"PoR verification process failed: {e}")
            # Log the specific error, but return a verification failed status
            return {"verified": False, "error": str(e), "file_ids": file_ids}

    # --- Other Client Methods (Largely Unchanged) ---

    def list_files(self, verbose: bool = False) -> List[Dict]:
        """List files stored on the server."""
        try:
            response = requests.get(f"{self.server_url}/list-files")
            response.raise_for_status()
            file_list = response.json()

            if verbose:
                for file_info in file_list:
                    file_id = file_info["file_id"]
                    local_params = self.file_params.get(file_id)
                    if local_params:
                        file_info["local_info"] = {
                            "stored_locally": True,
                            "filename": local_params.get('filename', 'N/A'),
                            "upload_timestamp": local_params.get('upload_timestamp', 'N/A')
                        }
                    else:
                        file_info["local_info"] = {"stored_locally": False}
            return file_list
        except requests.exceptions.RequestException as e:
            logger.error(f"Error listing files: {e}")
            raise

    def search_files(self, keywords: List[str]) -> List[Dict]:
        """Search for files by keywords."""
        try:
            response = requests.get(f"{self.server_url}/search", params={"keywords": ",".join(keywords)})
            response.raise_for_status()
            search_results = response.json()
            # Add local info marker
            for result in search_results:
                 result["stored_locally"] = result["file_id"] in self.file_params
            return search_results
        except requests.exceptions.RequestException as e:
            logger.error(f"Error searching files: {e}")
            raise

    def get_file_info(self, file_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific file from the server."""
        try:
            response = requests.get(f"{self.server_url}/file-info", params={"file_id": file_id})
            response.raise_for_status()
            file_info = response.json() # Server returns DB info

            # Add local parameter info if available
            local_params = self.file_params.get(file_id)
            if local_params:
                file_info["local_info"] = {
                    "stored_locally": True,
                    "filename": local_params.get('filename', 'N/A'),
                    "upload_timestamp": local_params.get('upload_timestamp', 'N/A'),
                    # Avoid exposing local alpha/key here
                }
            else:
                file_info["local_info"] = {"stored_locally": False}
            return file_info
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting file info for {file_id}: {e}")
            raise

    def download_file(self, file_id: str, output_path: Optional[Path] = None) -> Path:
        """Download a file from the server."""
        logger.info(f"Requesting download for file ID: {file_id}")
        try:
            # Get filename from server info first
            server_info = self.get_file_info(file_id)
            filename = server_info.get("filename", f"downloaded_{file_id}")

            if output_path is None:
                output_path = Path(filename)
            elif output_path.is_dir():
                output_path = output_path / filename
            output_path.parent.mkdir(parents=True, exist_ok=True) # Ensure dir exists

            # Stream the download
            with requests.get(f"{self.server_url}/download", params={"file_id": file_id}, stream=True) as r:
                r.raise_for_status()
                with open(output_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            logger.info(f"Downloaded file {filename} to {output_path}")
            return output_path
        except requests.exceptions.RequestException as e:
            logger.error(f"Error downloading file {file_id}: {e}")
            raise
        except Exception as e:
             logger.error(f"Error saving downloaded file {file_id} to {output_path}: {e}")
             raise

# --- Main execution block (similar to original, adjusted upload call) ---
def check_requirements():
    # (Keep the original check_requirements function)
    missing = []
    if not KEYBERT_AVAILABLE: missing.append("keybert (pip install keybert)")
    if not FFMPEG_AVAILABLE:
        missing.append("ffmpeg-python (pip install ffmpeg-python)")
        try: subprocess.run(["ffmpeg", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError): missing.append("ffmpeg command-line tool (install from ffmpeg.org)")
    if not DOCLING_AVAILABLE: missing.append("docling (pip install docling)")
    if missing:
        print("Optional dependencies missing:")
        for dep in missing: print(f"  - {dep}")
        print("Client will have limited functionality.")
    return not missing


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Secure File Client with Shacham-Waters PoR")
    parser.add_argument("--server", type=str, default=os.environ.get("SECURE_FILE_SERVER_URL", "http://127.0.0.1:8000"), help="Server URL")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute", required=True)

    # Upload subcommand
    upload_parser = subparsers.add_parser("upload", help="Upload a file or directory")
    upload_parser.add_argument("path", type=str, help="Path to the file or directory")
    upload_parser.add_argument("--keywords", type=str, nargs='+', help="Optional manual keywords")
    # upload_parser.add_argument("--split", action="store_true", help="Legacy flag (ignored, multipart used for large files)") # Keep for compatibility? Or remove.

    # PoR subcommand
    por_parser = subparsers.add_parser("por", help="Request PoR proof for files")
    por_parser.add_argument("file_ids", type=str, nargs="+", help="File IDs to verify")

    # List files subcommand
    list_parser = subparsers.add_parser("list", help="List files on server")
    list_parser.add_argument("--verbose", "-v", action="store_true", help="Show local info")


    # Search subcommand
    search_parser = subparsers.add_parser("search", help="Search files by keywords")
    search_parser.add_argument("keywords", type=str, nargs="+", help="Keywords")

    # Info subcommand
    info_parser = subparsers.add_parser("info", help="Get file details")
    info_parser.add_argument("file_id", type=str, help="File ID")

    # Download subcommand
    download_parser = subparsers.add_parser("download", help="Download a file")
    download_parser.add_argument("file_id", type=str, help="File ID")
    download_parser.add_argument("--output", "-o", type=str, help="Output directory or file path")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        # Also configure requests logging if needed
        # logging.getLogger("requests.packages.urllib3").setLevel(logging.DEBUG)

    check_requirements()
    client = SecureFileClient(args.server)

    if args.command == "upload":
        input_path = Path(args.path)
        if input_path.is_file():
            try:
                file_id = client.upload_file(input_path, manual_keywords=args.keywords)
                print(f"File '{input_path.name}' uploaded successfully. ID: {file_id}")
            except Exception as e:
                print(f"Error uploading {input_path.name}: {e}")
        elif input_path.is_dir():
            print(f"Uploading files from directory: {input_path}")
            uploaded_files = []
            failed_files = []
            for item in input_path.iterdir():
                if item.is_file():
                    print(f"  Uploading {item.name}...")
                    try:
                        file_id = client.upload_file(item, manual_keywords=args.keywords)
                        uploaded_files.append((item.name, file_id))
                        print(f"  -> Success. ID: {file_id}")
                    except Exception as e:
                        failed_files.append(item.name)
                        print(f"  -> FAILED: {e}")
            print("\nUpload Summary:")
            print(f"  Successfully uploaded: {len(uploaded_files)}")
            for name, fid in uploaded_files: print(f"    - {name}: {fid}")
            if failed_files:
                print(f"  Failed uploads: {len(failed_files)}")
                for name in failed_files: print(f"    - {name}")
        else:
            print(f"Error: Path '{args.path}' is not a valid file or directory.")

    elif args.command == "por":
        try:
            result = client.request_por_proof(args.file_ids)
            status = "SUCCESSFUL" if result["verified"] else "FAILED"
            print(f"PoR Verification Result: {status} for files {result['file_ids']}")
            if "error" in result: print(f"  Error details: {result['error']}")
            if "message" in result: print(f"  Message: {result['message']}")
        except Exception as e:
            print(f"Error during PoR request/verification: {e}")

    elif args.command == "list":
        try:
            # Check if verbose flag was passed specifically to list command
            is_list_verbose = getattr(args, 'verbose', False) or parser.prog == 'list' and '-v' in sys.argv # Simple check
            files = client.list_files(verbose=is_list_verbose)
            print(f"Found {len(files)} files:")
            # Basic print, add formatting if needed
            for f in files:
                 print(f"  ID: {f['file_id']}, Name: {f.get('filename', 'N/A')}, Size: {f.get('file_size', 0)} bytes")
                 if is_list_verbose and 'local_info' in f:
                      print(f"    Local: Stored={f['local_info']['stored_locally']}, Uploaded={f['local_info'].get('upload_timestamp', 'N/A')}")
        except Exception as e:
            print(f"Error listing files: {e}")

    elif args.command == "search":
        try:
            results = client.search_files(args.keywords)
            print(f"Found {len(results)} files matching: {', '.join(args.keywords)}")
            for r in results: print(f"  ID: {r['file_id']}, Name: {r.get('filename', 'N/A')}, Score: {r.get('match_score', 'N/A')}") # Add more details
        except Exception as e:
            print(f"Error searching files: {e}")

    elif args.command == "info":
        try:
            info = client.get_file_info(args.file_id)
            print(json.dumps(info, indent=2)) # Pretty print details
        except Exception as e:
            print(f"Error getting file info: {e}")

    elif args.command == "download":
        try:
            output = Path(args.output) if args.output else None
            downloaded_path = client.download_file(args.file_id, output)
            print(f"File downloaded to: {downloaded_path}")
        except Exception as e:
            print(f"Error downloading file: {e}")

if __name__ == "__main__":
    import sys # Needed for verbose check in list command
    main()