from pathlib import Path
from typing import Generator, List
import hashlib
from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa.keys import gen_keypair
import requests
import uuid
import os
from tqdm import tqdm
import math

class SecureFileUploader:
    def __init__(self, server_url: str, block_size: int = 1024 * 1024):
        self.server_url = server_url
        self.block_size = block_size
        self.private_key, self.P = gen_keypair(P256)
        self.public_key = self.private_key * self.P  # Public key

    def split_file(self, file_path: Path) -> Generator[bytes, None, None]:
        """Split file into blocks."""
        with open(file_path, 'rb') as f:
            while True:
                block = f.read(self.block_size)
                if not block:
                    break
                yield block

    def generate_block_tag(self, block_data: bytes) -> str:
        """Generate a cryptographic tag for a block."""
        # Ensure we get an integer hash
        block_hash = int.from_bytes(hashlib.sha256(block_data).digest(), byteorder="big")
        
        # Convert values to integers and perform modular arithmetic
        private_key_int = int(self.private_key) % P256.q
        inverse = pow(block_hash + private_key_int, -1, P256.q)  # Modular multiplicative inverse
        
        # Generate tag point
        tag = inverse * self.P  # Point multiplication
        
        # Convert coordinates to integers
        return f"{int(tag.x)},{int(tag.y)}"

    def upload_file(self, file_path: Path) -> str:
        """Upload file in blocks with cryptographic tags."""
        file_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path)
        total_blocks = math.ceil(file_size / self.block_size)

        with tqdm(total=total_blocks, desc="Uploading blocks") as pbar:
            for block in self.split_file(file_path):
                block_id = hashlib.sha256(block).hexdigest()
                tag = self.generate_block_tag(block)

                files = {'file': ('block', block, 'application/octet-stream')}
                data = {'block_id': block_id, 'file_id': file_id, 'tag': tag}

                response = requests.post(
                    f"{self.server_url}/upload-block",
                    files=files,
                    data=data
                )
                if response.status_code != 200:
                    raise Exception(f"Upload failed: {response.text}")

                pbar.update(1)

        return file_id
    # client/main.py
    def verify_blocks(self, file_id: str, block_ids: List[str]) -> bool:
        """Verify block authenticity using stored tags."""
        try:
            # Make verification request
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
                
            data = response.json()
            if "tags" not in data:
                print("Invalid server response - missing tags")
                return False

            # Verify each tag
            for tag_str in data["tags"]:
                try:
                    # Parse tag point coordinates
                    tag_x, tag_y = map(int, tag_str.split(","))
                    tag_point = Point(tag_x, tag_y, curve=P256)
                    
                    # Basic verification - check if point is on curve
                    if not P256.is_point_on_curve((tag_point.x, tag_point.y)):
                        print(f"Invalid point: ({tag_x}, {tag_y})")
                        return False
                        
                except ValueError as e:
                    print(f"Tag parsing error: {e}")
                    return False
                    
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
        print(f"File uploaded successfully with ID: {file_id}\n Keep this ID safe for future reference.")
        
                
    except Exception as e:
        print(f"Operation failed: {e}")