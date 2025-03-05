import json
from pathlib import Path
from typing import List
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import requests
import uuid
from keybert import KeyBERT

class SecureFileUploader:
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.key = b"MySuperSecretKey12345MySuperSecretKey12345"[:32]
        self.kw_model = KeyBERT()

    def extract_keywords(self, content: bytes) -> List[str]:
        """Extract keywords from the entire file content."""
        try:
            keywords = self.kw_model.extract_keywords(content.decode())
            return [word for word, _ in keywords]
        except UnicodeDecodeError:
            return []

    def generate_auth_tag(self, content: bytes) -> tuple[str, bytes]:
        """Generate AES-CBC-MAC authentication tag for the entire file."""
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = self._pad_data(content)
        ciphertext = cipher.encrypt(padded_data)
        auth_tag = ciphertext[-16:]  # Last block is the MAC
        return iv.hex() + auth_tag.hex(), auth_tag

    def _pad_data(self, data: bytes) -> bytes:
        """PKCS7 padding."""
        pad_len = 16 - (len(data) % 16)
        padding = bytes([pad_len]) * pad_len
        return data + padding

    def upload_file(self, file_path: Path) -> str:
        """Upload the entire file."""
        file_id = str(uuid.uuid4())
        with open(file_path, "rb") as f:
            content = f.read()
        
        auth_tag, _ = self.generate_auth_tag(content)
        keywords = self.extract_keywords(content)
        
        files = {"file": (file_path.name, content, "application/octet-stream")}
        data = {
            "file_id": file_id,
            "auth_tag": auth_tag,
            "keywords": '#'.join(keywords),
        }
        
        response = requests.post(f"{self.server_url}/upload-file", files=files, data=data)
        
        if response.status_code != 200:
            raise Exception(f"Server error: {response.text}")
        
        return file_id

    def verify_file(self, file_id: str) -> bool:
        """Verify the entire file."""
        try:
            response = requests.get(f"{self.server_url}/get-file/{file_id}")
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
            
            data = response.json()
            content = bytes.fromhex(data["content"])
            received_auth = data["auth_tag"]
            
            iv = bytes.fromhex(received_auth[:32])
            expected_auth = received_auth[32:]
            
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded_data = self._pad_data(content)
            ciphertext = cipher.encrypt(padded_data)
            local_auth = ciphertext[-16:].hex()
            
            local_auth_combined = iv.hex() + local_auth
            
            if local_auth_combined == received_auth:
                return True
            else:
                print(f"Verification failed for file {file_id}")
                return False
        except Exception as e:
            print(f"Verification failed: {str(e)}")
            return False

if __name__ == "__main__":
    uploader = SecureFileUploader("http://13.232.216.193:8000")  # Fixed URL typo
    file_path = Path("example.txt")
    
    try:
        file_id = uploader.upload_file(file_path)
        print(f"File uploaded successfully with ID: {file_id}")
        
        if uploader.verify_file(file_id):
            print("File verified successfully")
        else:
            print("File verification failed")
    
    except Exception as e:
        print(f"Operation failed: {e}")