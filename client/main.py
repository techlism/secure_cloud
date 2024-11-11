# client.py
from pathlib import Path
from typing import Generator
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import requests
import uuid
import os
from tqdm import tqdm
import math

class SecureFileUploader:
    def __init__(self, server_url: str, block_size: int = 1024*1024):
        self.server_url = server_url
        self.block_size = block_size
        self.key = b'MySuperSecretKey12345MySuperSecretKey12345'[:32]

    def split_file(self, file_path: Path) -> Generator[bytes, None, None]:
        """Split file into blocks"""
        with open(file_path, 'rb') as f:
            while True:
                block = f.read(self.block_size)
                if not block:
                    break
                yield block

    def generate_block_id(self, block_data: bytes, file_id: str) -> str:
        """Generate unique block ID"""
        hash_input = f"{file_id}-{len(block_data)}-{uuid.uuid4()}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def generate_auth_tag(self, block_data: bytes) -> tuple[str, bytes]:
        """Generate AES-CBC-MAC authentication tag"""
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Pad the block data
        padded_data = self._pad_data(block_data)
        
        # Generate CBC-MAC
        ciphertext = cipher.encrypt(padded_data)
        auth_tag = ciphertext[-16:]  # Last block is the MAC
        
        return iv.hex() + auth_tag.hex(), auth_tag

    def _pad_data(self, data: bytes) -> bytes:
        """PKCS7 padding"""
        pad_len = 16 - (len(data) % 16)
        padding = bytes([pad_len]) * pad_len
        return data + padding

    def upload_file(self, file_path: Path) -> str:
        """Upload file in blocks"""
        file_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path)
        total_blocks = math.ceil(file_size / self.block_size)
        uploaded_blocks = []
        
        with tqdm(total=total_blocks, desc="Uploading blocks") as pbar:
            for block in self.split_file(file_path):
                block_id = self.generate_block_id(block, file_id)
                auth_tag, _ = self.generate_auth_tag(block)

                files = {
                    'file': ('block', block, 'application/octet-stream')
                }
                
                data = {
                    'block_id': block_id,
                    'file_id': file_id,
                    'auth_tag': auth_tag
                }

                try:
                    # Send as multipart form data
                    response = requests.post(
                        f"{self.server_url}/upload-block",
                        files=files,
                        data=data  # This will be sent as form fields
                    )
                    
                    if response.status_code != 200:
                        raise Exception(f"Server error: {response.text}")
                    
                    uploaded_blocks.append(response.json())
                    pbar.update(1)
                    
                except Exception as e:
                    raise Exception(f"Upload failed: {str(e)}")

        return file_id
    
    def verify_blocks(self, file_id: str, block_ids: List[str]) -> bool:
        """Verify specific blocks"""
        try:
            response = requests.post(
                f"{self.server_url}/verify-blocks",
                json={"block_ids": block_ids, "file_id": file_id}
            )
            
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
                
            data = response.json()
            content = bytes.fromhex(data['content'])
            received_auth = data['auth_tag']
            
            # Generate our own auth tag
            local_auth, _ = self.generate_auth_tag(content)
            
            # Compare tags
            return local_auth == received_auth
            
        except Exception as e:
            print(f"Verification failed: {str(e)}")
            return False
    # def verify_uploads(self, file_id: str) -> bool:
    #     """Verify all blocks were uploaded"""
    #     response = requests.get(f"{self.server_url}/blocks/{file_id}")
    #     if response.status_code != 200:
    #         return False
        
    #     blocks = response.json()['blocks']
    #     return len(blocks) > 0

# Usage example
if __name__ == "__main__":
    uploader = SecureFileUploader("http://15.206.89.160:8000")
    file_path = Path("example.txt")
    
    try:
        file_id = uploader.upload_file(file_path)
        print(f"File uploaded successfully with ID: {file_id}")
        
        # Get blocks for the file
        response = requests.get(f"{uploader.server_url}/blocks/{file_id}")
        blocks = response.json()['blocks']
        
        # Verify first two blocks if available
        block_ids = [block['block_id'] for block in blocks[:2]]
        if block_ids:
            if uploader.verify_blocks(file_id, block_ids):
                print("Blocks verified successfully")
            else:
                print("Block verification failed")
                
    except Exception as e:
        print(f"Operation failed: {e}")