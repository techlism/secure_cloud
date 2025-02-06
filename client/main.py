# client/main.py
from py_ecc.bn128 import (
    G1,
    G2,
    pairing,
    multiply,
    add,
    eq,
    curve_order,
    FQ,
    FQ2
)
import hashlib
import requests
import uuid
import os
import math
from pathlib import Path
from typing import Generator, List
from tqdm import tqdm

class SecureFileUploader:
    def __init__(self, server_url: str, block_size: int = 1024 * 1024, key_seed: str = 'your-secure-key-seed'):
        # Generate deterministic private key from seed
        seed_hash = hashlib.sha256(key_seed.encode()).digest()
        self.x = int.from_bytes(seed_hash, 'big') % curve_order
        
        # Generators of G1 and G2
        self.P = G1
        self.Q = G2
        
        # Public key in G2
        self.Ppub = multiply(self.Q, self.x)
        
        self.server_url = server_url
        self.block_size = block_size

    def generate_block_tag(self, block_data: bytes) -> tuple[str, str]:
        """Generate a ZSS signature and hash for a block."""
        # Calculate block hash
        block_hash = hashlib.sha256(block_data).hexdigest()
        H_m = int(block_hash, 16) % curve_order
        
        # Compute (H(m) + x)^{-1} mod q
        h_plus_x = (H_m + self.x) % curve_order
        h_plus_x_inv = pow(h_plus_x, -1, curve_order)
        
        # Compute signature S = (H(m) + x)^{-1} * P
        S = multiply(self.P, h_plus_x_inv)
        x, y = S  # Unpack affine coordinates
        
        # Convert to string format
        tag = f"{x},{y}"
        
        return tag, block_hash

    def upload_file(self, file_path: Path) -> str:
        file_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path)
        total_blocks = math.ceil(file_size / self.block_size)

        with tqdm(total=total_blocks, desc="Uploading blocks") as pbar:
            for i, block in enumerate(self.split_file(file_path)):
                tag, block_hash = self.generate_block_tag(block)
                
                files = {'file': ('block', block, 'application/octet-stream')}
                data = {
                    'block_id': str(i),
                    'file_id': file_id,
                    'tag': tag,
                    'block_hash': block_hash
                }

                response = requests.post(
                    f"{self.server_url}/upload-block",
                    files=files,
                    data=data
                )
                if response.status_code != 200:
                    raise Exception(f"Upload failed: {response.text}")

                pbar.update(1)

        return file_id

    def verify_blocks(self, file_id: str, block_ids: List[str]) -> bool:
        try:
            response = requests.post(
                f"{self.server_url}/verify-blocks",
                json={"block_ids": block_ids, "file_id": file_id}
            )
            
            if response.status_code != 200:
                print(f"Server error: {response.text}")
                return False
            
            blocks = response.json()["blocks"]
            print(f"Retrieved blocks: {blocks}")
            
            for block in blocks:
                try:
                    # Convert signature point to FQ elements
                    tag_x, tag_y = map(int, block['tag'].split(","))
                    S = (FQ(tag_x), FQ(tag_y))  # Point in G1
                    print(f"Signature point S: {S}")
                    
                    # Compute H(m)
                    H_m = int(block['block_hash'], 16) % curve_order
                    print(f"H(m): {H_m}")
                    
                    # Compute V = H(m) * Q + Ppub in G2
                    HmQ = multiply(self.Q, H_m)
                    V = add(HmQ, self.Ppub)
                    print(f"Verification point V: {V}")
                    
                    # Points in G2 should have FQ2 coordinates
                    V = (FQ2(V[0]), FQ2(V[1]))
                    
                    # Perform pairing
                    lhs = pairing(S, V)
                    rhs = pairing(self.P, self.Q)
                    print(f"LHS pairing: {lhs}")
                    print(f"RHS pairing: {rhs}")
                    
                    if lhs != rhs:
                        print("Verification failed - pairings not equal")
                        return False
                        
                except Exception as e:
                    print(f"Error processing block: {str(e)}")
                    return False
                
            print("All blocks verified successfully")
            return True
        
        except Exception as e:
            print(f"Verification failed: {str(e)}")
            return False

    def split_file(self, file_path: Path) -> Generator[bytes, None, None]:
        with open(file_path, 'rb') as f:
            while True:
                block = f.read(self.block_size)
                if not block:
                    break
                yield block
if __name__ == "__main__":
    uploader = SecureFileUploader("http://15.206.89.160:8000")
    file_id = '187ebb27-c743-4a0d-9e91-2a647fa9d90b'
    block_ids = ['0']  # Adjust as needed
    result = uploader.verify_blocks(file_id, block_ids)
    print(f"Verification result: {result}")