import hashlib
import requests
import uuid
import os
import math
from pathlib import Path
from typing import Generator, List
from tqdm import tqdm

# Use py_ecc for cryptographic operations
from py_ecc.bn128 import G1, G2, pairing, multiply, add, eq

class SecureFileUploader:
    def __init__(self, server_url: str, block_size: int = 1024 * 1024, key_seed: str = 'fa074028-1bb9-4d69-bdd5-b4f683e8a85a'):
        # Generate deterministic key from seed
        seed_hash = hashlib.sha256(key_seed.encode()).digest()
        self.x = int.from_bytes(seed_hash, 'big') % G1.order()
        
        # Generator point and public key
        self.P = G1.generator()
        self.Ppub = multiply(self.P, self.x)
        
        self.server_url = server_url
        self.block_size = block_size

    def hash_to_point(self, data):
        # Convert data to a hash and map to G1 point
        hash_bytes = hashlib.sha256(data).digest()
        return multiply(self.P, int.from_bytes(hash_bytes, 'big') % G1.order())

    def generate_block_tag(self, block_data: bytes) -> str:
        # ZSS-like signature generation
        H_m = self.hash_to_point(block_data)
        S = multiply(self.P, pow(int(H_m[0]) + self.x, -1, G1.order()))
        
        # Convert signature to string representation
        return f"{S[0]},{S[1]}"

    def upload_file(self, file_path: Path) -> str:
        file_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path)
        total_blocks = math.ceil(file_size / self.block_size)

        with tqdm(total=total_blocks, desc="Uploading blocks") as pbar:
            i = 0
            for block in self.split_file(file_path):
                block_id = hashlib.sha256(block).hexdigest()
                tag = self.generate_block_tag(block)

                files = {'file': ('block', block, 'application/octet-stream')}
                data = {'block_id': i, 'file_id': file_id, 'tag': tag}

                response = requests.post(
                    f"{self.server_url}/upload-block",
                    files=files,
                    data=data
                )
                if response.status_code != 200:
                    raise Exception(f"Upload failed: {response.text}")

                pbar.update(1)
                i += 1

        return file_id

    def split_file(self, file_path: Path) -> Generator[bytes, None, None]:
        with open(file_path, 'rb') as f:
            while True:
                block = f.read(self.block_size)
                if not block:
                    break
                yield block

    def verify_blocks(self, file_id: str, block_ids: List[str]) -> bool:
        try:
            response = requests.post(
                f"{self.server_url}/verify-blocks",
                json={
                    "block_ids": block_ids,
                    "file_id": file_id
                },
                headers={
                    "Content-Type": "application/json"
                }
            )
            
            if response.status_code != 200:
                print(f"Server error: {response.text}")
                return False
                
            data = response.json()['blocks'][0]
            
            # Reconstruct signature point
            tags = data['tag'].split(",")
            S = (int(tags[0]), int(tags[1]))
            
            # Convert block hash
            block_hash = data['block_hash']
            H_m = self.hash_to_point(bytes.fromhex(block_hash))
            
            # Verification equation
            left = pairing(add(H_m, self.Ppub), S)
            right = pairing(self.P, self.P)
            
            verification_result = eq(left, right)
            
            if not verification_result:
                print(f"Verification failed for block {block_ids[0]}")
                return False

            print("All blocks verified successfully.")
            return True                
                    
        except Exception as e:
            print(f"Verification failed: {str(e)}")
            return False

# Usage example
if __name__ == "__main__":
    uploader = SecureFileUploader("http://15.206.89.160:8000")
    file_path = Path("example.txt")
    
    try:
        file_id = uploader.upload_file(file_path)
        print(f"File uploaded successfully with ID: {file_id}")
    except Exception as e:
        print(f"Operation failed: {e}")