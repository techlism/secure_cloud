import math
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
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
import logging
from datetime import datetime
import concurrent.futures
import time

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
        
        # Thread pool for concurrent uploads
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)

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
        logger.info(f"Attempting to extract subtitles from video: {file_path.name}")
        if not FFMPEG_AVAILABLE:
            logger.warning("ffmpeg-python not available. Cannot extract subtitles.")
            return ""
            
        try:
            # Create a temporary directory for extracted subtitles
            with tempfile.TemporaryDirectory() as temp_dir:
                subtitle_path = os.path.join(temp_dir, "subtitles.srt")
                
                # Try to extract subtitles from all available subtitle streams
                subtitle_content = ""
                try:
                    # First try with subtitle streams
                    (
                        ffmpeg
                        .input(str(file_path))
                        .output(subtitle_path, map="s")  # Map all subtitle streams
                        .run(quiet=True, overwrite_output=True)
                    )
                    
                    if os.path.exists(subtitle_path) and os.path.getsize(subtitle_path) > 0:
                        with open(subtitle_path, 'r', errors='ignore') as f:
                            subtitle_content = f.read()
                        logger.info(f"Successfully extracted subtitle stream from {file_path.name}")
                except ffmpeg.Error:
                    # If no embedded subtitles found, try extracting text from different streams
                    for i in range(5):  # Try the first 5 potential subtitle streams
                        try:
                            stream_path = os.path.join(temp_dir, f"sub_{i}.srt")
                            (
                                ffmpeg
                                .input(str(file_path))
                                .output(stream_path, map=f"0:{i}")  # Try different stream indexes
                                .run(quiet=True, overwrite_output=True)
                            )
                            
                            if os.path.exists(stream_path) and os.path.getsize(stream_path) > 0:
                                with open(stream_path, 'r', errors='ignore') as f:
                                    subtitle_content = f.read()
                                logger.info(f"Successfully extracted subtitle from stream {i} of {file_path.name}")
                                break
                        except ffmpeg.Error:
                            continue
                
                if not subtitle_content:
                    logger.info(f"No subtitles extracted from {file_path.name}")
                    return ""
                
                # Clean up subtitle content - strip all HTML tags and clean formatting
                # Strip all HTML/XML tags
                clean_content = re.sub(r'<[^>]*>', '', subtitle_content)
                
                # Remove timestamps and numbers
                clean_content = re.sub(r'\d+:\d+:\d+[,\.]\d+ --> \d+:\d+:\d+[,\.]\d+', '', clean_content)
                clean_content = re.sub(r'^\d+$', '', clean_content, flags=re.MULTILINE)
                
                # Remove special subtitle indicators like italics markup
                clean_content = re.sub(r'\\[Nh]', '', clean_content)  # WebVTT formatting
                clean_content = re.sub(r'\{[^\}]*\}', '', clean_content)  # SSA/ASS formatting
                
                # Remove excessive blank lines
                clean_content = re.sub(r'\n+', '\n', clean_content)

                logger.info(f"Extracted and cleaned {len(clean_content)} characters of subtitles from {file_path.name}")
                return clean_content.strip()
                
        except Exception as e:
            logger.error(f"Error extracting text from video {file_path.name}: {str(e)}")
            return ""

    def process_document_with_docling(self, file_path: Path) -> str:
        """Process document with Docling and extract text content."""
        logger.info(f"Processing document with Docling: {file_path.name}")
        if not DOCLING_AVAILABLE:
            logger.warning("Docling not available. Cannot process document.")
            return ""
            
        try:
            result = self.doc_converter.convert(str(file_path))
            text_content = result.document.export_to_text()
            logger.info(f"Successfully extracted {len(text_content)} characters from {file_path.name}")
            return text_content
        except Exception as e:
            logger.error(f"Error processing document with Docling: {str(e)}")
            return ""

    def extract_keywords(self, content: str, file_path: Path) -> List[str]:
        """Extract keywords from content using KeyBERT or fallback methods."""
        logger.info(f"Extracting keywords from content for {file_path.name}")
        
        if not content.strip():
            logger.info(f"No content to extract keywords from for {file_path.name}")
            keywords = self.extract_keywords_from_filename(file_path.name)
            logger.info(f"Extracted {len(keywords)} keywords from filename: {keywords}")
            return keywords
            
        if KEYBERT_AVAILABLE:
            try:
                keywords = self.kw_model.extract_keywords(content)
                extracted_kw = [word for word, _ in keywords]
                if extracted_kw:
                    logger.info(f"KeyBERT extracted keywords: {extracted_kw}")
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
        extracted_keywords = [word for word, count in sorted_words[:10]]  # Return top 10 words
        logger.info(f"Fallback method extracted keywords: {extracted_keywords}")
        return extracted_keywords

    def get_content_and_keywords(self, file_path: Path) -> Tuple[bytes, List[str]]:
        """
        Process file content based on file type and extract keywords.
        Returns the file content and keywords.
        """
        file_info = self.detect_file_type(file_path)
        logger.info(f"Processing {file_path.name} detected as {file_info['category']}")
        
        # Always read the raw content
        with open(file_path, "rb") as f:
            raw_content = f.read()
            logger.info(f"Read {len(raw_content)} bytes from {file_path.name}")
        
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
            logger.info(f"Processing binary file: {file_path.name}")
            return raw_content, self.extract_keywords_from_filename(file_path.name)

    def split_into_blocks(self, content: bytes) -> List[bytes]:
        """Split file content into fixed-size blocks."""
        total_size = len(content)
        num_blocks = math.ceil(total_size / self.block_size)
        
        blocks = []
        for i in range(num_blocks):
            start = i * self.block_size
            end = min(start + self.block_size, total_size)
            block = content[start:end]
            if len(block) < self.block_size:
                block = block + b'\0' * (self.block_size - len(block))
            blocks.append(block)
        
        logger.info(f"Split content into {len(blocks)} blocks of {self.block_size} bytes")
        return blocks

    def _process_blocks(self, blocks: List[bytes], alpha: int, key: bytes, start_idx: int = 0) -> List[Dict]:
        """Process blocks and generate tags."""
        block_data = []
        for i, block in enumerate(blocks):
            block_idx = start_idx + i
            tag = self.compute_tag(block, block_idx, alpha, key)
            block_data.append({
                "block_idx": block_idx,
                "tag": tag.to_bytes(32, 'big').hex(),
                "size": len(block)
            })
        return block_data
    
    def _upload_single_block(self, file_id: str, block: bytes, block_idx: int) -> bool:
        """Upload a single block to the server."""
        files = {"block": (f"{file_id}_block_{block_idx}", block, "application/octet-stream")}
        data = {"file_id": file_id, "block_idx": block_idx}
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = requests.post(f"{self.server_url}/upload-block", files=files, data=data)
                if response.status_code == 200:
                    return True
                time.sleep(1)  # Wait before retrying
            except requests.exceptions.RequestException:
                time.sleep(1)  # Wait before retrying
                
        return False
    
    def _upload_blocks_multithreaded(self, file_id: str, blocks: List[bytes], start_idx: int = 0):
        """Upload blocks to the server using multithreading."""
        logger.info(f"Uploading {len(blocks)} blocks using multithreading")
        
        # Submit all uploads to thread pool
        futures = []
        for i, block in enumerate(blocks):
            block_idx = start_idx + i
            future = self.thread_pool.submit(self._upload_single_block, file_id, block, block_idx)
            futures.append((future, block_idx))
        
        # Track progress
        total = len(blocks)
        completed = 0
        failed = []
        
        # Wait for all uploads to complete
        for future, block_idx in futures:
            try:
                success = future.result()
                completed += 1
                if not success:
                    failed.append(block_idx)
            except Exception:
                failed.append(block_idx)
        
        if failed:
            raise Exception(f"Failed to upload {len(failed)} blocks: {failed}")
        
        logger.info(f"Successfully uploaded all {len(blocks)} blocks")

    def upload_file(self, file_path: Path, manual_keywords: List[str] = None) -> str:
        """
        Upload a file with Shacham-Waters tags.
        
        Args:
            file_path: Path to the file
            manual_keywords: Optional list of manual keywords
        """
        logger.info(f"Starting upload for file: {file_path}")
        file_id = str(uuid.uuid4())
        
        try:
            # Step 1: Read the file content and extract keywords
            content, auto_keywords = self.get_content_and_keywords(file_path)
            keywords = list(set((manual_keywords or []) + auto_keywords))            
            # Step 2: Generate file metadata
            file_info = self.detect_file_type(file_path)
            file_size = len(content)
            file_key = os.urandom(32)
            file_alpha = randint(1, self.p - 1)
            
            # Step 3: Store client-side file parameters
            self.file_params[file_id] = {
                'alpha': file_alpha,
                'key': file_key,
                'filename': file_path.name,
                'file_type': file_info['mime_type'],
                'file_size': file_size,
                'upload_date': datetime.now().isoformat()
            }
            self._save_storage()
            
            # Step 4: Split content into blocks
            blocks = self.split_into_blocks(content)
            total_blocks = len(blocks)
            
            # Step 5: Process blocks to generate tags
            block_data = self._process_blocks(blocks, file_alpha, file_key)
            
            # Step 6: Create file metadata on server
            metadata = {
                "file_id": file_id,
                "filename": file_path.name,
                "file_type": file_info['mime_type'],
                "file_category": file_info['category'],
                "file_size": file_size,
                "keywords": keywords,
                "total_blocks": total_blocks,
                "blocks": block_data
            }
            
            logger.info(f"Sending metadata for file {file_path.name} ({file_size} bytes, {total_blocks} blocks)")
            response = requests.post(f"{self.server_url}/create-file", json=metadata)
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
            
            # Step 7: Upload blocks using multithreading
            self._upload_blocks_multithreaded(file_id, blocks)
            
            logger.info(f"Successfully uploaded file {file_path.name} with ID: {file_id}")
            return file_id
            
        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")
            raise

    def parse_audit_request(self, audit_spec: str) -> Dict[str, List[int]]:
        """
        Parse an audit specification string into a dictionary mapping file IDs to block indices.
        Format: "file_id1 file_id2 ... 1,2,4"
        The last element is a comma-separated list of block indices to audit for each file.
        """
        logger.info(f"Parsing audit request: {audit_spec}")
        parts = audit_spec.strip().split()
        if len(parts) < 2:
            raise ValueError("Audit specification must include at least one file ID and block indices")
            
        # The last part should be the block indices
        indices_str = parts[-1]
        try:
            indices = [int(idx) for idx in indices_str.split(',')]
            if not indices:
                raise ValueError("No block indices specified")
        except ValueError:
            # If the last part isn't valid indices, assume all parts are file IDs
            # and use default indices (0)
            indices = [0]
            file_ids = parts
            logger.info(f"No specific indices provided, defaulting to index 0 for all files")
        else:
            # Otherwise, all parts except the last are file IDs
            file_ids = parts[:-1]
            
        logger.info(f"Parsed {len(file_ids)} file IDs and {len(indices)} block indices")
        
        # Create a mapping of file IDs to indices
        audit_map = {file_id: indices for file_id in file_ids}
        return audit_map

    def validate_audit_request(self, audit_map: Dict[str, List[int]]) -> Dict[str, List[int]]:
        """
        Validate that all files exist and have the requested block indices.
        Returns a map of valid file IDs to their valid block indices.
        """
        logger.info(f"Validating audit request for {len(audit_map)} files")
        valid_map = {}
        
        for file_id, indices in audit_map.items():
            try:
                # Check if file exists and get its block count
                file_info = self.get_file_info(file_id)
                total_blocks = file_info.get("total_blocks", 0)
                
                if total_blocks == 0:
                    logger.warning(f"File {file_id} has no blocks")
                    continue
                    
                # Filter indices to only include valid ones
                valid_indices = [idx for idx in indices if 0 <= idx < total_blocks]
                
                if not valid_indices:
                    logger.warning(f"No valid block indices for file {file_id}. Requested: {indices}, Total blocks: {total_blocks}")
                    continue
                    
                if len(valid_indices) < len(indices):
                    missing = set(indices) - set(valid_indices)
                    logger.warning(f"File {file_id} is missing requested blocks: {missing}")
                    
                valid_map[file_id] = valid_indices
                logger.info(f"Validated file {file_id} with {len(valid_indices)} valid block indices")
                
            except Exception as e:
                logger.error(f"Error validating file {file_id}: {str(e)}")
                
        if not valid_map:
            raise ValueError("No valid file and block combinations found for auditing")
            
        return valid_map

    def generate_audit_challenge(self, audit_map: Dict[str, List[int]]) -> Dict[str, List[Tuple[int, int]]]:
        """
        Generate a PoR challenge for specific files and specific block indices.
        """
        logger.info(f"Generating audit challenge for {len(audit_map)} files")
        challenge = {}
        
        for file_id, block_indices in audit_map.items():
            challenge[file_id] = [(idx, randint(1, self.p - 1)) for idx in block_indices]
            logger.info(f"Generated challenge for file {file_id} with {len(block_indices)} blocks: {block_indices}")
            
        return challenge

    def run_audit(self, audit_spec: str) -> Dict[str, Any]:
        """
        Run an audit based on a specification string.
        Format: "file_id1 file_id2 ... 1,2,4"
        Returns audit results including verification status for each file.
        """
        logger.info(f"Starting audit with specification: {audit_spec}")
        try:
            # Parse the audit specification
            audit_map = self.parse_audit_request(audit_spec)
            
            # Validate the audit request
            valid_map = self.validate_audit_request(audit_map)
            
            if not valid_map:
                return {"success": False, "message": "No valid files and blocks to audit"}
                
            # Generate challenge for valid files and blocks
            file_challenges = self.generate_audit_challenge(valid_map)
            
            # Prepare challenge for server
            challenge_json = [{"file_id": file_id, "index": i, "coeff": nu} 
                             for file_id, challenges in file_challenges.items() 
                             for i, nu in challenges]
                             
            # Send challenge to server
            file_ids = list(valid_map.keys())
            logger.info(f"Sending challenge to server for files: {file_ids}")
            response = requests.post(f"{self.server_url}/por-proof", json={
                "file_ids": file_ids,
                "challenge": challenge_json
            })
            
            if response.status_code != 200:
                logger.error(f"Server error during audit: {response.text}")
                return {"success": False, "message": f"Server error: {response.text}"}
                
            # Process server response
            data = response.json()
            sigma = int(data["sigma"], 16)
            mu_dict = {file_id: int(mu_hex, 16) for file_id, mu_hex in data["mu"].items()}
            
            # Verify the proof
            verified = self.verify_por_proof(file_challenges, sigma, mu_dict)
            
            # Calculate results per file
            per_file_results = {}
            for file_id in file_ids:
                if file_id not in self.file_params:
                    per_file_results[file_id] = {"verified": False, "error": "No local parameters found"}
                    continue
                    
                # File specific verification would require more detailed data from server
                # For now, we'll use the global verification result
                per_file_results[file_id] = {"verified": verified, "blocks_audited": valid_map[file_id]}
            
            audit_result = {
                "success": True,
                "verified": verified,
                "file_count": len(file_ids),
                "block_count": sum(len(indices) for indices in valid_map.values()),
                "file_results": per_file_results,
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"Audit completed with result: verified={verified}")
            return audit_result
            
        except Exception as e:
            logger.error(f"Error during audit: {str(e)}")
            return {"success": False, "message": str(e)}

    def verify_por_proof(self, file_challenges: Dict[str, List[Tuple[int, int]]], sigma: int, mu_dict: Dict[str, int]) -> bool: 
        """Verify a proof of retrievability across multiple files."""
        logger.info(f"Verifying PoR proof for {len(file_challenges)} files")
        expected_sigma = 0
        
        for file_id, challenge in file_challenges.items():
            if file_id not in self.file_params:
                logger.error(f"Error: No parameters found for file {file_id}")
                return False
                
            file_params = self.file_params[file_id]
            alpha = file_params['alpha']
            key = file_params['key']
            
            logger.debug(f"Verifying file {file_id} with {len(challenge)} blocks")
            file_sigma_contribution = 0
            for i, nu in challenge:
                prf_value = self.prf(i, key)
                file_sigma_contribution = (file_sigma_contribution + nu * prf_value) % self.p
            
            expected_sigma = (expected_sigma + file_sigma_contribution) % self.p
            
            if file_id in mu_dict:
                expected_sigma = (expected_sigma + alpha * mu_dict[file_id]) % self.p
            else:
                logger.error(f"Missing mu value for file {file_id}")
                return False

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

    def generate_multi_file_por_challenge(self, file_ids: List[str]) -> Dict[str, List[Tuple[int, int]]]:
        """Generate a PoR challenge across multiple files."""
        logger.info(f"Generating multi-file PoR challenge for {len(file_ids)} files")
        challenge = {}
        total_blocks_per_file = {}

        # Fetch file info for each file
        for file_id in file_ids:
            response = requests.get(f"{self.server_url}/file-info?file_id={file_id}")
            if response.status_code != 200:
                raise Exception(f"Server error for file {file_id}: {response.text}")
            
            file_info = response.json()
            total_blocks_per_file[file_id] = file_info["total_blocks"]
            logger.debug(f"File {file_id} has {total_blocks_per_file[file_id]} blocks")

            # Regular challenge generation for all files
            total_blocks = total_blocks_per_file[file_id]
            l = min(self.l, total_blocks)  # Number of blocks to challenge per file
            if total_blocks <= 8:
                indices = list(range(total_blocks))
            else:
                indices = sample(range(total_blocks), l)
            challenge[file_id] = [(i, randint(1, self.p - 1)) for i in indices]
            logger.info(f"Challenging {len(indices)} blocks for file {file_id} out of {total_blocks}")

        return challenge

    def list_files(self, verbose: bool = False) -> List[Dict]:
        """List all files stored on the server."""
        try:
            logger.info("Listing files from server")
            response = requests.get(f"{self.server_url}/list-files")
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
                
            file_list = response.json()
            logger.info(f"Received {len(file_list)} files from server")
            
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
            logger.info(f"Searching files with keywords: {keywords}")
            response = requests.get(f"{self.server_url}/search", params={"keywords": ",".join(keywords)})
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
                
            search_results = response.json()
            logger.info(f"Found {len(search_results)} files matching keywords")
            
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
            logger.info(f"Getting file info for {file_id}")
            response = requests.get(f"{self.server_url}/file-info", params={"file_id": file_id})
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
                
            file_info = response.json()           
            return file_info
        except Exception as e:
            logger.error(f"Error getting file info: {str(e)}")
            raise

    def download_file(self, file_id: str, output_path: Optional[Path] = None) -> Path:
        """Download a file from the server."""
        try:
            # Get file info
            logger.info(f"Downloading file {file_id}")
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
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    if total_size > 0:
                        progress = min(100, int(100 * downloaded_size / total_size))
                        logger.debug(f"Download progress: {progress}% ({downloaded_size}/{total_size} bytes)")
                    
            logger.info(f"Downloaded file {filename} to {output_path} ({downloaded_size} bytes)")
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

    # Audit subcommand
    audit_parser = subparsers.add_parser("audit", help="Audit specific files and blocks")
    audit_parser.add_argument("spec", type=str, help="Audit specification in format 'file_id1 file_id2 ... 1,2,4'")

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
                manual_keywords=args.keywords
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
                            manual_keywords=args.keywords
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
            
    elif args.command == "audit":
        # Run an audit using the specified files and blocks
        try:
            result = client.run_audit(args.spec)
            if result.get("success", False):
                if result.get("verified", False):
                    print(f"✅ Audit SUCCESSFUL for {result['file_count']} files ({result['block_count']} blocks)")
                    for file_id, file_result in result["file_results"].items():
                        blocks = file_result.get("blocks_audited", [])
                        status = "✅ Verified" if file_result.get("verified", False) else "❌ Failed"
                        print(f"  - {file_id}: {status} - Audited blocks: {blocks}")
                else:
                    print(f"❌ Audit FAILED for {result['file_count']} files ({result['block_count']} blocks)")
                    for file_id, file_result in result["file_results"].items():
                        blocks = file_result.get("blocks_audited", [])
                        error = file_result.get("error", "Unknown error")
                        if "error" in file_result:
                            print(f"  - {file_id}: ERROR: {error}")
                        else:
                            status = "✅ Verified" if file_result.get("verified", False) else "❌ Failed"
                            print(f"  - {file_id}: {status} - Audited blocks: {blocks}")
            else:
                print(f"❌ Audit failed: {result.get('message', 'Unknown error')}")
        except Exception as e:
            print(f"Error during audit: {str(e)}")

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
            print(f"File ID: {args.file_id}")
            print(f"Filename: {file_info.get('filename', 'Unknown')}")
            print(f"Total blocks: {file_info.get('total_blocks', 0)}")
            print(f"Size: {file_info.get('file_size', 0)} bytes")
            print(f"Keywords: {', '.join(file_info.get('keywords', []))}")
            print(f"Upload date: {file_info.get('upload_date', 'Unknown')}")
            
            # Show local information if available
            if args.file_id in client.file_params:
                local_info = client.file_params[args.file_id]
                print("Local information:")
                print(f"  File type: {local_info.get('file_type', 'Unknown')}")
                print(f"  Upload date: {local_info.get('upload_date', 'Unknown')}")
                
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