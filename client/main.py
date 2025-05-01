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

# Configure logging
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

# Assume config.py defines P (large prime) and BLOCK_SIZE
import config

class SecureFileClient:
    def __init__(self, server_url: str):
        """Initialize the secure file client with Shacham-Waters parameters."""
        self.server_url = server_url
        self.p = config.P  # Large prime from config, e.g., 2**256 - 2**224 + 2**192 + 2**96 - 1
        self.alpha = randint(1, self.p - 1)  # Secret scalar
        self.k = os.urandom(32)  # PRF key (256 bits)
        self.block_size = config.BLOCK_SIZE
        self.l = 80  # Security parameter: number of blocks to challenge
        
        # Initialize keyword extractor if available
        if KEYBERT_AVAILABLE:
            self.kw_model = KeyBERT()
        
        # Initialize document converter if available
        if DOCLING_AVAILABLE:
            self.doc_converter = DocumentConverter()
        
        # Define supported formats
        self.text_formats = ['.txt', '.md', '.markdown', '.html', '.htm', '.xhtml', '.csv', '.json', '.xml', '.py', '.js', '.java', '.c', '.cpp']
        self.docling_formats = ['.pdf', '.docx', '.xlsx', '.pptx', '.adoc', '.png', '.jpg', '.jpeg', '.tiff', '.bmp']
        self.video_formats = ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv', '.m4v']
        
        # Store parameters for each file
        self._init_storage()

    def _init_storage(self):
        """Initialize storage for file parameters."""
        self.storage_file = Path("client_storage.pickle")
        if not self.storage_file.exists():
            self.file_params = {}
            self._save_storage()
        else:
            self._load_storage()

    def _save_storage(self):
        """Save file parameters to disk."""
        with open(self.storage_file, "wb") as f:
            pickle.dump(self.file_params, f)

    def _load_storage(self):
        """Load file parameters from disk."""
        try:
            with open(self.storage_file, "rb") as f:
                self.file_params = pickle.load(f)
        except Exception as e:
            logger.error(f"Error loading client storage: {str(e)}")
            self.file_params = {}

    def prf(self, i: int, key: bytes = None) -> int:
        """Pseudorandom function using HMAC-SHA256, reduced modulo p."""
        if key is None:
            key = self.k
        h = hmac.new(key, str(i).encode(), hashlib.sha256).digest()
        return int.from_bytes(h, 'big') % self.p

    def compute_tag(self, block: bytes, block_idx: int, alpha: int = None, key: bytes = None) -> int:
        """Compute Shacham-Waters tag: σ_i = f_k(i) + α * m_i mod p."""
        if alpha is None:
            alpha = self.alpha
        m = int.from_bytes(block, 'big') % self.p
        return (self.prf(block_idx, key) + alpha * m) % self.p

    def detect_file_type(self, file_path: Path) -> Dict[str, Any]:
        """
        Detect the file type and return its information.
        Returns a dict with mime_type, category, and is_binary properties.
        """
        ext = file_path.suffix.lower()
        mime_type, _ = mimetypes.guess_type(file_path)
        
        # Determine file category and binary status
        if ext in self.text_formats:
            category = "text"
            is_binary = False
        elif ext in self.docling_formats:
            category = "document"
            is_binary = True
        elif ext in self.video_formats:
            category = "video"
            is_binary = True
        else:
            # Handle unknown formats as binary
            category = "binary"
            is_binary = True
            
        if mime_type is None:
            if category == "text":
                mime_type = "text/plain"
            elif category == "document":
                mime_type = "application/octet-stream"
            elif category == "video":
                mime_type = "video/mp4"  # Default video MIME
            else:
                mime_type = "application/octet-stream"
                
        return {
            "mime_type": mime_type,
            "category": category,
            "is_binary": is_binary,
            "extension": ext
        }

    def extract_keywords_from_filename(self, filename: str) -> List[str]:
        """Extract potential keywords from the filename."""
        # Remove extension and replace separators with spaces
        name_only = Path(filename).stem
        # Replace common separators with spaces
        clean_name = re.sub(r'[_\-.]', ' ', name_only)
        # Split by spaces and filter out short words (likely not meaningful)
        words = [word.lower() for word in clean_name.split() if len(word) > 2]
        return list(set(words))  # Remove duplicates

    def extract_text_from_video(self, file_path: Path) -> str:
        """Extract subtitles/captions from video files using ffmpeg."""
        if not FFMPEG_AVAILABLE:
            logger.warning("ffmpeg-python not available. Cannot extract subtitles.")
            return ""
            
        try:
            # Create a temporary directory for extracted subtitles
            with tempfile.TemporaryDirectory() as temp_dir:
                subtitle_path = os.path.join(temp_dir, "subtitles.srt")
                
                # Try to extract subtitles using ffmpeg
                try:
                    (
                        ffmpeg
                        .input(str(file_path))
                        .output(subtitle_path, map="s")  # Map subtitles
                        .run(quiet=True, overwrite_output=True)
                    )
                except ffmpeg.Error:
                    logger.info(f"No embedded subtitles found in {file_path.name}")
                    return ""
                
                # Read the subtitles if they were extracted
                if os.path.exists(subtitle_path) and os.path.getsize(subtitle_path) > 0:
                    with open(subtitle_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    # Clean up subtitle content (remove timestamps and numbers)
                    clean_content = re.sub(r'\d+:\d+:\d+,\d+ --> \d+:\d+:\d+,\d+', '', content)
                    clean_content = re.sub(r'^\d+$', '', clean_content, flags=re.MULTILINE)
                    
                    return clean_content
                else:
                    # If no subtitles, try speech recognition (placeholder - would require additional dependencies)
                    logger.info(f"No subtitles extracted from {file_path.name}")
                    return ""
        except Exception as e:
            logger.error(f"Error extracting text from video {file_path.name}: {str(e)}")
            return ""

    def process_document_with_docling(self, file_path: Path) -> str:
        """Process document with Docling and extract text content."""
        if not DOCLING_AVAILABLE:
            logger.warning("Docling not available. Cannot process document.")
            return ""
            
        try:
            result = self.doc_converter.convert(str(file_path))
            return result.document.export_to_markdown()
        except Exception as e:
            logger.error(f"Error processing document with Docling: {str(e)}")
            return ""

    def extract_keywords(self, content: str, file_path: Path) -> List[str]:
        """Extract keywords from content using KeyBERT or fallback methods."""
        if not content.strip():
            logger.info(f"No content to extract keywords from for {file_path.name}")
            return self.extract_keywords_from_filename(file_path.name)
            
        if KEYBERT_AVAILABLE:
            try:
                keywords = self.kw_model.extract_keywords(content)
                extracted_kw = [word for word, _ in keywords]
                if extracted_kw:
                    return extracted_kw
            except Exception as e:
                logger.error(f"KeyBERT extraction error: {str(e)}")
        
        # Fallback: Basic keyword extraction from content
        words = re.findall(r'\b\w+\b', content.lower())
        # Filter common words and short words
        stopwords = {'the', 'and', 'of', 'to', 'a', 'in', 'for', 'is', 'on', 'that', 'by', 'this', 'with', 'you', 'it'}
        filtered_words = [w for w in words if w not in stopwords and len(w) > 3]
        # Count word frequency
        word_counts = {}
        for word in filtered_words:
            word_counts[word] = word_counts.get(word, 0) + 1
        # Get top words
        sorted_words = sorted(word_counts.items(), key=lambda x: x[1], reverse=True)
        return [word for word, count in sorted_words[:10]]  # Return top 10 words

    def get_content_and_keywords(self, file_path: Path) -> Tuple[Optional[bytes], List[str]]:
        """
        Process file content based on file type and extract keywords.
        Returns the file content (or None for binary files) and keywords.
        """
        file_info = self.detect_file_type(file_path)
        logger.info(f"Processing {file_path.name} detected as {file_info['category']}")
        
        # Always read the raw content
        with open(file_path, "rb") as f:
            raw_content = f.read()
        
        # For text files, extract keywords directly
        if file_info['category'] == "text":
            try:
                text_content = raw_content.decode('utf-8', errors='ignore')
                keywords = self.extract_keywords(text_content, file_path)
                return raw_content, keywords
            except Exception as e:
                logger.error(f"Error processing text file: {str(e)}")
                return raw_content, self.extract_keywords_from_filename(file_path.name)
        
        # For documents, use Docling if available
        elif file_info['category'] == "document" and DOCLING_AVAILABLE:
            try:
                text_content = self.process_document_with_docling(file_path)
                keywords = self.extract_keywords(text_content, file_path)
                return raw_content, keywords
            except Exception as e:
                logger.error(f"Error processing document: {str(e)}")
                return raw_content, self.extract_keywords_from_filename(file_path.name)
        
        # For videos, extract subtitles if possible
        elif file_info['category'] == "video":
            try:
                text_content = self.extract_text_from_video(file_path)
                if text_content:
                    keywords = self.extract_keywords(text_content, file_path)
                else:
                    keywords = self.extract_keywords_from_filename(file_path.name)
                return raw_content, keywords
            except Exception as e:
                logger.error(f"Error processing video: {str(e)}")
                return raw_content, self.extract_keywords_from_filename(file_path.name)
        
        # Default fallback for binary files
        else:
            return raw_content, self.extract_keywords_from_filename(file_path.name)

    def split_into_blocks(self, content: bytes) -> List[bytes]:
        """Split file content into fixed-size blocks."""
        logger.info(f"Splitting content into blocks (size: {len(content)} bytes)")
        blocks = []
        total_size = len(content)
        num_blocks = math.ceil(total_size / self.block_size)

        for i in range(num_blocks):
            start = i * self.block_size
            end = min(start + self.block_size, total_size)
            block = content[start:end]
            if len(block) < self.block_size:
                block = block + b'\0' * (self.block_size - len(block))
            blocks.append(block)
        return blocks

    def handle_non_text_file(self, file_path: Path, file_id: str, file_key: bytes, file_alpha: int, manual_keywords: List[str] = None) -> str:
        """
        Special handling for non-text files that preserves file integrity.
        Doesn't split the file into blocks, but calculates a single tag for verification.
        """
        logger.info(f"Processing non-text file: {file_path.name}")
        try:
            # Read full file content
            with open(file_path, "rb") as f:
                content = f.read()
            
            file_size = len(content)
            
            # Generate keywords
            if manual_keywords:
                keywords = manual_keywords
            else:
                _, auto_keywords = self.get_content_and_keywords(file_path)
                keywords = auto_keywords
            
            # Calculate single tag for verification
            # Use the entire file as a single block for tag calculation
            tag = self.compute_tag(content, 0, file_alpha, file_key)
            
            # Store file information
            file_info = self.detect_file_type(file_path)
            self.file_params[file_id] = {
                'alpha': file_alpha,
                'key': file_key,
                'filename': file_path.name,
                'file_type': file_info['mime_type'],
                'file_size': file_size,
                'is_non_text': True  # Flag for non-text file
            }
            self._save_storage()
            
            # Create metadata for server
            metadata = {
                "file_id": file_id,
                "filename": file_path.name,
                "file_type": file_info['mime_type'],
                "file_size": file_size,
                "keywords": keywords,
                "total_blocks": 1,  # Single block
                "is_non_text": True,
                "blocks": [{
                    "block_idx": 0,
                    "tag": tag.to_bytes(32, 'big').hex(),
                    "size": file_size
                }]
            }
            
            # Send metadata to server
            response = requests.post(f"{self.server_url}/create-file", json=metadata)
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
            
            # Upload file as a single block
            files = {"block": (f"{file_id}_block_0", content, "application/octet-stream")}
            data = {"file_id": file_id, "block_idx": 0, "is_non_text": True}
            response = requests.post(f"{self.server_url}/upload-block", files=files, data=data)
            
            if response.status_code != 200:
                raise Exception(f"Server error uploading file: {response.text}")
            
            logger.info(f"Successfully uploaded non-text file {file_path.name} with ID: {file_id}")
            return file_id
            
        except Exception as e:
            logger.error(f"Error handling non-text file: {str(e)}")
            raise

    def upload_file(self, file_path: Path, manual_keywords: List[str] = None, preserve_integrity: bool = True) -> str:
        """
        Upload a file with Shacham-Waters tags.
        
        Args:
            file_path: Path to the file
            manual_keywords: Optional list of manual keywords
            preserve_integrity: If True, non-text files will be handled specially
                                to preserve their integrity (default: True)
        """
        logger.info(f"Uploading file: {file_path}")
        try:
            file_id = str(uuid.uuid4())
            file_info = self.detect_file_type(file_path)
            file_size = file_path.stat().st_size
            
            # Generate new key and alpha for this file
            file_key = os.urandom(32)
            file_alpha = randint(1, self.p - 1)
            
            # For non-text files with preserve_integrity enabled, use special handling
            if preserve_integrity and (file_info['category'] in ["document", "video", "binary"] or file_info['is_binary']):
                return self.handle_non_text_file(file_path, file_id, file_key, file_alpha, manual_keywords)
            
            # For regular text files or when preserve_integrity is disabled
            # Get content and auto-extracted keywords
            content, auto_keywords = self.get_content_and_keywords(file_path)
            
            # Use manual keywords if provided, otherwise use auto-extracted
            keywords = manual_keywords if manual_keywords else auto_keywords
            
            # Store parameters for this file
            self.file_params[file_id] = {
                'alpha': file_alpha,
                'key': file_key,
                'filename': file_path.name,
                'file_type': file_info['mime_type'],
                'file_size': file_size
            }
            self._save_storage()

            # Process blocks & tags
            if file_size <= 10 * 1024 * 1024:  # 10MB threshold for small files
                blocks = self.split_into_blocks(content)
                block_data = self._process_blocks(blocks, file_alpha, file_key)
                
                # Create metadata
                metadata = {
                    "file_id": file_id,
                    "filename": file_path.name,
                    "file_type": file_info['mime_type'],
                    "file_category": file_info['category'],
                    "file_size": file_size,
                    "keywords": keywords,
                    "total_blocks": len(blocks),
                    "blocks": block_data
                }
                
                # Send metadata to server
                response = requests.post(f"{self.server_url}/create-file", json=metadata)
                if response.status_code != 200:
                    raise Exception(f"Server error: {response.text}")
                
                # Upload blocks
                self._upload_blocks(file_id, blocks)
            else:
                # For large files, process in chunks
                logger.info(f"Large file detected ({file_size} bytes). Processing in chunks...")
                
                # Calculate total blocks
                total_blocks = math.ceil(file_size / self.block_size)
                
                # Create metadata with placeholder for block data
                metadata = {
                    "file_id": file_id,
                    "filename": file_path.name,
                    "file_type": file_info['mime_type'],
                    "file_category": file_info['category'],
                    "file_size": file_size,
                    "keywords": keywords,
                    "total_blocks": total_blocks,
                    "chunked_upload": True
                }
                
                # Send metadata to server
                response = requests.post(f"{self.server_url}/create-file", json=metadata)
                if response.status_code != 200:
                    raise Exception(f"Server error: {response.text}")
                
                # Process and upload blocks in chunks
                with open(file_path, "rb") as f:
                    chunk_size = 5 * 1024 * 1024  # 5MB chunks
                    block_idx = 0
                    
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                            
                        blocks = self.split_into_blocks(chunk)
                        block_data = self._process_blocks(blocks, file_alpha, file_key, start_idx=block_idx)
                        
                        # Update server with block metadata for this chunk
                        response = requests.post(f"{self.server_url}/update-file-blocks", json={
                            "file_id": file_id,
                            "blocks": block_data
                        })
                        if response.status_code != 200:
                            raise Exception(f"Server error updating blocks: {response.text}")
                        
                        # Upload blocks
                        self._upload_blocks(file_id, blocks, start_idx=block_idx)
                        
                        block_idx += len(blocks)
                        logger.info(f"Uploaded chunk: {block_idx}/{total_blocks} blocks processed")

            logger.info(f"Successfully uploaded file {file_path.name} with ID: {file_id}")
            return file_id

        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")
            raise

    def _process_blocks(self, blocks: List[bytes], alpha: int, key: bytes, start_idx: int = 0) -> List[Dict]:
        """Process blocks and generate tags."""
        block_data = []
        for i, block in enumerate(blocks):
            block_idx = start_idx + i
            tag = self.compute_tag(block, block_idx, alpha, key)
            block_data.append({
                "block_idx": block_idx,
                "tag": tag.to_bytes(32, 'big').hex(),  # Store as hex string
                "size": len(block)
            })
        return block_data
    
    def _upload_blocks(self, file_id: str, blocks: List[bytes], start_idx: int = 0):
        """Upload blocks to the server."""
        for i, block in enumerate(blocks):
            block_idx = start_idx + i
            files = {"block": (f"{file_id}_block_{block_idx}", block, "application/octet-stream")}
            data = {"file_id": file_id, "block_idx": block_idx}
            
            # Retry logic for network issues
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    response = requests.post(f"{self.server_url}/upload-block", files=files, data=data)
                    if response.status_code == 200:
                        break
                    logger.warning(f"Error uploading block {block_idx}, attempt {attempt+1}/{max_retries}")
                    if attempt == max_retries - 1:
                        raise Exception(f"Server error uploading block {block_idx}: {response.text}")
                except requests.exceptions.RequestException as e:
                    if attempt == max_retries - 1:
                        raise Exception(f"Network error uploading block {block_idx}: {str(e)}")

    def generate_multi_file_por_challenge(self, file_ids: List[str]) -> Dict[str, List[Tuple[int, int]]]:
        """Generate a PoR challenge across multiple files."""
        challenge = {}
        total_blocks_per_file = {}

        # Fetch file info for each file
        for file_id in file_ids:
            response = requests.get(f"{self.server_url}/file-info?file_id={file_id}")
            if response.status_code != 200:
                raise Exception(f"Server error for file {file_id}: {response.text}")
            
            file_info = response.json()
            total_blocks_per_file[file_id] = file_info["total_blocks"]
            
            # Check if file is non-text (special handling)
            is_non_text = file_info.get("is_non_text", False)
            if is_non_text:
                # For non-text files, challenge the entire file as one block
                challenge[file_id] = [(0, randint(1, self.p - 1))]
                logger.info(f"Challenging non-text file {file_id} (entire file as one block)")
                continue

            # Regular challenge generation for normal files
            total_blocks = total_blocks_per_file[file_id]
            l = min(self.l, total_blocks)  # Number of blocks to challenge per file
            if total_blocks <= 8:
                indices = list(range(total_blocks))
            else:
                indices = sample(range(total_blocks), l)
            challenge[file_id] = [(i, randint(1, self.p - 1)) for i in indices]
            logger.info(f"Challenging {len(indices)} blocks for file {file_id} out of {total_blocks}")

        return challenge

    def verify_por_proof(self, file_challenges: Dict[str, List[Tuple[int, int]]], sigma: int, mu_dict: Dict[str, int]) -> bool: 
        expected_sigma = 0
        for file_id, challenge in file_challenges.items():
            if file_id not in self.file_params:
                logger.error(f"Error: No parameters found for file {file_id}")
                return False
                
            file_params = self.file_params[file_id]
            alpha = file_params['alpha']
            key = file_params['key']

            file_sigma_contribution = 0
            for i, nu in challenge:
                prf_value = self.prf(i, key)
                file_sigma_contribution = (file_sigma_contribution + nu * prf_value) % self.p
            
            expected_sigma = (expected_sigma + file_sigma_contribution) % self.p
            expected_sigma = (expected_sigma + alpha * mu_dict[file_id]) % self.p

        logger.info(f"Expected sigma: {expected_sigma}")
        logger.info(f"Received sigma: {sigma}")
        return sigma == expected_sigma
      
    def request_por_proof(self, file_ids: List[str]) -> Dict:
        """Request and verify PoR proof for a list of files."""
        try:
            file_challenges = self.generate_multi_file_por_challenge(file_ids)
            challenge_json = [{"file_id": file_id, "index": i, "coeff": nu} 
                            for file_id, challenges in file_challenges.items() 
                            for i, nu in challenges]

            response = requests.post(f"{self.server_url}/por-proof", json={
                "file_ids": file_ids,
                "challenge": challenge_json
            })

            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")

            data = response.json()
            sigma = int(data["sigma"], 16)
            mu_dict = {file_id: int(mu_hex, 16) for file_id, mu_hex in data["mu"].items()}

            verified = self.verify_por_proof(file_challenges, sigma, mu_dict)
            return {"verified": verified, "file_ids": file_ids}

        except Exception as e:
            logger.error(f"PoR proof failed: {str(e)}")
            raise

    def list_files(self, verbose: bool = False) -> List[Dict]:
        """List all files stored on the server."""
        try:
            response = requests.get(f"{self.server_url}/list-files")
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
                
            file_list = response.json()
            
            # If verbose mode, add local info
            if verbose:
                for file in file_list:
                    file_id = file["file_id"]
                    if file_id in self.file_params:
                        file["local_info"] = {
                            "stored_locally": True,
                            "filename": self.file_params[file_id]['filename'],
                            "upload_date": self.file_params[file_id].get('upload_date', 'Unknown')
                        }
                    else:
                        file["local_info"] = {"stored_locally": False}
                        
            return file_list
        except Exception as e:
            logger.error(f"Error listing files: {str(e)}")
            raise

    def search_files(self, keywords: List[str]) -> List[Dict]:
        """Search for files by keywords."""
        try:
            response = requests.get(f"{self.server_url}/search", params={"keywords": ",".join(keywords)})
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
                
            search_results = response.json()
            
            # Add local info for files we have stored
            for file in search_results:
                file_id = file["file_id"]
                if file_id in self.file_params:
                    file["stored_locally"] = True
                else:
                    file["stored_locally"] = False
                    
            return search_results
        except Exception as e:
            logger.error(f"Error searching files: {str(e)}")
            raise

    def get_file_info(self, file_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific file."""
        try:
            response = requests.get(f"{self.server_url}/file-info", params={"file_id": file_id})
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
                
            file_info = response.json()
            
            # Add local information if available
            if file_id in self.file_params:
                local_info = {
                    "stored_locally": True,
                    "filename": self.file_params[file_id]['filename'],
                    "file_type": self.file_params[file_id].get('file_type', 'Unknown'),
                    "file_size": self.file_params[file_id].get('file_size', 0),
                    "upload_date": self.file_params[file_id].get('upload_date', 'Unknown')
                }
                file_info["local_info"] = local_info
            else:
                file_info["local_info"] = {"stored_locally": False}
                
            return file_info
        except Exception as e:
            logger.error(f"Error getting file info: {str(e)}")
            raise

    def download_file(self, file_id: str, output_path: Optional[Path] = None) -> Path:
        """Download a file from the server."""
        try:
            # Get file info
            file_info = self.get_file_info(file_id)
            filename = file_info.get("filename", f"downloaded_{file_id}")
            
            # Determine output path
            if output_path is None:
                output_path = Path(filename)
            elif output_path.is_dir():
                output_path = output_path / filename
                
            # Download file
            response = requests.get(f"{self.server_url}/download", params={"file_id": file_id}, stream=True)
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
                
            # Save file
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
            logger.info(f"Downloaded file {filename} to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error downloading file: {str(e)}")
            raise

def check_requirements():
    """Check if requirements are installed and offer guidance."""
    missing = []
    
    if not KEYBERT_AVAILABLE:
        missing.append("keybert (pip install keybert)")
    
    if not FFMPEG_AVAILABLE:
        missing.append("ffmpeg-python (pip install ffmpeg-python)")
        # Also check if ffmpeg is installed on the system
        try:
            subprocess.run(["ffmpeg", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            missing.append("ffmpeg command-line tool - please install from https://ffmpeg.org/download.html")
    
    if not DOCLING_AVAILABLE:
        missing.append("docling (pip install docling)")
    
    if missing:
        print("Optional dependencies missing:")
        for dep in missing:
            print(f"  - {dep}")
        print("The client will still work, but with limited functionality.")
        print("Install the missing dependencies for full functionality.")
    
    return len(missing) == 0

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Secure File Client with Shacham-Waters PoR")
    parser.add_argument("--server", type=str, default="http://13.232.216.193:8000", help="Server URL")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute", required=True)

    # Upload subcommand
    upload_parser = subparsers.add_parser("upload", help="Upload a file")
    upload_parser.add_argument("file", type=str, help="Path to the file")
    upload_parser.add_argument("--keywords", type=str, nargs='+', help="Optional manual keywords for the file")
    upload_parser.add_argument("--split", action="store_true", help="Split even non-text files into blocks (not recommended)")

    # PoR subcommand
    por_parser = subparsers.add_parser("por", help="Request PoR proof for multiple files")
    por_parser.add_argument("file_ids", type=str, nargs="+", help="File IDs to verify")

    # List files subcommand
    list_parser = subparsers.add_parser("list", help="List all files stored on the server")
    
    # Search subcommand
    search_parser = subparsers.add_parser("search", help="Search for files by keywords")
    search_parser.add_argument("keywords", type=str, nargs="+", help="Keywords to search for")

    # Info subcommand
    info_parser = subparsers.add_parser("info", help="Get detailed information about a file")
    info_parser.add_argument("file_id", type=str, help="File ID to get information for")
    
    # Download subcommand
    download_parser = subparsers.add_parser("download", help="Download a file from the server")
    download_parser.add_argument("file_id", type=str, help="File ID to download")
    download_parser.add_argument("--output", "-o", type=str, help="Output directory or file path")

    args = parser.parse_args()
    
    # Set log level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Check requirements
    check_requirements()
    
    server_url = args.server
    client = SecureFileClient(server_url)

    if args.command == "upload":
        # For upload, check if it's a single file or a directory
        path = Path(args.file)
        
        if path.is_file():
            # Process a single file
            file_id = client.upload_file(
                path, 
                manual_keywords=args.keywords, 
                preserve_integrity=not args.split
            )
            print(f"File uploaded with ID: {file_id}")
        elif path.is_dir():
            # Process all files in the directory
            uploaded_files = []
            for file_path in path.glob("*"):
                if file_path.is_file():
                    try:
                        file_id = client.upload_file(
                            file_path, 
                            manual_keywords=args.keywords,
                            preserve_integrity=not args.split
                        )
                        uploaded_files.append((file_path.name, file_id))
                    except Exception as e:
                        print(f"Error uploading {file_path.name}: {str(e)}")
            
            # Print summary of uploaded files
            print(f"Uploaded {len(uploaded_files)} files:")
            for filename, file_id in uploaded_files:
                print(f"  - {filename}: {file_id}")
        else:
            print(f"Error: {args.file} is not a valid file or directory")

    elif args.command == "por":
        # Request PoR proof for files
        try:
            result = client.request_por_proof(args.file_ids)
            if result["verified"]:
                print(f"✅ PoR Verification SUCCESSFUL for files {result['file_ids']}")
                print("Files are stored correctly on the server.")
            else:
                print(f"❌ PoR Verification FAILED for files {result['file_ids']}")
                print("Files may have been tampered with or corrupted on the server.")
        except Exception as e:
            print(f"Error during PoR verification: {str(e)}")
            
    elif args.command == "list":
        # List all files
        try:
            files = client.list_files(verbose=True)
            print(f"Found {len(files)} files on the server:")
            
            # Print table header
            print(f"{'File ID':<36} {'Filename':<30} {'Size':<10} {'Keywords':<30}")
            print("-" * 100)
            
            # Print file information
            for file in files:
                file_id = file["file_id"]
                filename = file["filename"] if "filename" in file else "Unknown"
                size = file.get("file_size", 0)
                size_str = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f} MB"
                keywords = ", ".join(file.get("keywords", [])[:3])
                if len(file.get("keywords", [])) > 3:
                    keywords += "..."
                print(f"{file_id:<36} {filename[:30]:<30} {size_str:<10} {keywords[:30]:<30}")
                
        except Exception as e:
            print(f"Error listing files: {str(e)}")
            
    elif args.command == "search":
        # Search files by keywords
        try:
            results = client.search_files(args.keywords)
            print(f"Found {len(results)} files matching keywords: {', '.join(args.keywords)}")
            
            if not results:
                print("No matching files found.")
            else:
                # Print table header
                print(f"{'File ID':<36} {'Filename':<30} {'Match Score':<10} {'Keywords':<30}")
                print("-" * 100)
                
                # Sort by match score (if available)
                results.sort(key=lambda x: x.get("match_score", 0), reverse=True)
                
                # Print file information
                for file in results:
                    file_id = file["file_id"]
                    filename = file["filename"] if "filename" in file else "Unknown"
                    score = f"{file.get('match_score', 0):.2f}" if "match_score" in file else "N/A"
                    keywords = ", ".join(file.get("keywords", [])[:3])
                    if len(file.get("keywords", [])) > 3:
                        keywords += "..."
                    print(f"{file_id:<36} {filename[:30]:<30} {score:<10} {keywords[:30]:<30}")
                    
        except Exception as e:
            print(f"Error searching files: {str(e)}")
            
    elif args.command == "info":
        # Get detailed file information
        try:
            file_info = client.get_file_info(args.file_id)
            print(f"Information for file {args.file_id}:")
            print(f"  Filename: {file_info.get('filename', 'Unknown')}")
            print(f"  File Type: {file_info.get('file_type', 'Unknown')}")
            print(f"  File Size: {file_info.get('file_size', 0) / 1024:.1f} KB")
            print(f"  Keywords: {', '.join(file_info.get('keywords', []))}")
            print(f"  Total Blocks: {file_info.get('total_blocks', 0)}")
            print(f"  Category: {file_info.get('file_category', 'Unknown')}")
            
            # Show local information if available
            if file_info.get("local_info", {}).get("stored_locally", False):
                print("  Local Information:")
                local_info = file_info["local_info"]
                print(f"    Upload Date: {local_info.get('upload_date', 'Unknown')}")
            else:
                print("  Local Information: Not stored locally")
                
        except Exception as e:
            print(f"Error getting file information: {str(e)}")
    
    elif args.command == "download":
        # Download file
        try:
            output_path = Path(args.output) if args.output else None
            downloaded_path = client.download_file(args.file_id, output_path)
            print(f"File downloaded successfully to: {downloaded_path}")
        except Exception as e:
            print(f"Error downloading file: {str(e)}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()