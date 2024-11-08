# secure_storage_service.py
from pathlib import Path
import string
import boto3
from typing import Dict, List, Any, Optional
from datetime import datetime
import hashlib
import uuid 
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer
import base64

# Download required NLTK data
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
nltk.download('averaged_perceptron_tagger')
nltk.download('punkt_tab')

from database import DatabaseManager
from config import AWS_CONFIG, BLOCK_SIZE, DATABASE_PATH, KEY, LOG_FILE

class SecureStorageService:
    def __init__(self):
        # Initialize services and dependencies
        self.s3 = boto3.client('s3', region_name=AWS_CONFIG['region_name'])
        self.db = DatabaseManager(DATABASE_PATH)
        self.key = KEY  # AES-256 key
        
        logging.basicConfig(
            filename=str(LOG_FILE),
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)        
        
        # Initialize NLTK components
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        
        # Initialize TF-IDF vectorizer
        self.vectorizer = TfidfVectorizer(
            stop_words='english',
            ngram_range=(1, 2),
            max_features=10
        )        
        
    def _split_into_blocks(self, content: bytes) -> List[bytes]:
        return [content[i:i + BLOCK_SIZE] for i in range(0, len(content), BLOCK_SIZE)]
    
    def _encrypt_block(self, data: bytes) -> tuple:
        """Encrypt data using AES-CBC"""
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data, base64.b64encode(iv).decode('utf-8')

    def _decrypt_block(self, encrypted_data: bytes, iv: str) -> bytes:
        """Decrypt data using AES-CBC"""
        iv = base64.b64decode(iv.encode('utf-8'))
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return unpad(decrypted_data, AES.block_size)

    def _generate_tags(self, text: str) -> List[tuple]:
        """Generate tags with relevance scores using TF-IDF"""
        # Preprocess text
        tokens = word_tokenize(text.lower())
        tokens = [self.lemmatizer.lemmatize(token) 
                 for token in tokens 
                 if token not in self.stop_words 
                 and token not in string.punctuation]
        
        # Get TF-IDF scores
        document = [' '.join(tokens)]
        tfidf_matrix = self.vectorizer.fit_transform(document)
        feature_names = self.vectorizer.get_feature_names_out()
        
        # Get scores for each term
        scores = zip(feature_names, tfidf_matrix.toarray()[0])
        
        # Return top scored terms with type and score
        return [(term, 'tfidf', score) 
                for term, score in sorted(scores, key=lambda x: x[1], reverse=True)
                if score > 0.1]

    def upload_file(self, file_path: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            file_path = Path(file_path)
            file_id = str(uuid.uuid4())
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            blocks = self._split_into_blocks(content)
            block_urls = []

            for idx, block in enumerate(blocks):
                block_id = f"{file_id}_block_{idx}"
                
                # Generate preview and tags before encryption
                try:
                    block_text = block.decode('utf-8')
                    content_preview = block_text  # Store first 200 chars
                except:
                    content_preview = ""
                
                # Encrypt block
                encrypted_block, iv = self._encrypt_block(block)
                block_hash = hashlib.sha256(block).hexdigest()
                
                # Upload to S3
                s3_key = f"{file_id}/{idx}"
                self.s3.put_object(
                    Bucket=AWS_CONFIG['bucket_name'],
                    Key=s3_key,
                    Body=encrypted_block
                )
                
                block_urls.append(self._get_file_url(file_id, idx))
                
                # Store block info with preview and IV
                self.db.add_block(
                    block_id=block_id,
                    file_id=file_id,
                    index=idx,
                    s3_key=s3_key,
                    block_hash=block_hash,
                    size=len(block),
                    content_preview=content_preview,
                    iv=iv
                )
                
                # Generate and store tags
                if content_preview:
                    tags = self._generate_tags(content_preview)
                    self.db.add_tags(block_id=block_id, tags=tags)

            # Store file metadata
            file_metadata = {
                'original_name': file_path.name,
                'size': len(content),
                'block_count': len(blocks),
                'created_at': datetime.utcnow().isoformat(),
                'urls': block_urls
            }
            if metadata:
                file_metadata.update(metadata)

            self.db.add_file(
                file_id=file_id,
                filename=file_path.name,
                mime_type=self._get_mime_type(file_path),
                size=len(content),
                metadata=file_metadata
            )

            return {
                'file_id': file_id,
                'urls': block_urls,
                'metadata': file_metadata
            }

        except Exception as e:
            self.logger.error(f"Upload failed: {str(e)}")
            raise
    
    def _get_file_url(self, file_id: str, block_index: int = 0) -> str:
        return f"https://{AWS_CONFIG['bucket_name']}.s3.{AWS_CONFIG['region_name']}.amazonaws.com/{file_id}/{block_index}"
    
    def _get_mime_type(self, file_path: Path) -> str:
        import mimetypes
        mime_type, _ = mimetypes.guess_type(str(file_path))
        return mime_type or 'application/octet-stream'        
                    
    def search_by_keyword(self, keyword: str, min_score: float = 0.1) -> List[Dict]:
        """Search for blocks based on keyword"""
        results = self.db.search_blocks(keyword, min_score)
        
        # Format results
        formatted_results = []
        for result in results:
            formatted_results.append({
                'block_id': result['block_id'],
                'file_id': result['file_id'],
                'original_name': result['original_name'],
                'block_index': result['block_index'],
                'content_preview': result['content_preview'],
                'relevance_score': result['relevance_score'],
                'url': self._get_file_url(result['file_id'], result['block_index']),
                'tags': [tag.split(':')[0] for tag in result['tags'].split(',')]
            })
            
        return formatted_results

    # Other methods remain unchanged

    def get_file_info(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get file metadata and URLs"""
        try:
            file_info = self.db.get_file(file_id)
            if not file_info:
                return None
            
            blocks = self.db.get_file_blocks(file_id)
            urls = [self._get_file_url(file_id, b['block_index']) for b in blocks]
            
            return {
                'file_id': file_id,
                'urls': urls,
                'metadata': file_info['metadata']
            }
            
        except Exception as e:
            self.logger.error(f"Error getting file info: {str(e)}")
            raise