import json
import math
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import requests
import uuid
from keybert import KeyBERT
import os
import hmac
import hashlib
from random import randint, sample
import pickle

# Assume config.py defines P (large prime) and BLOCK_SIZE
import config

class SecureFileClient:
    def __init__(self, server_url: str):
        """Initialize the secure file client with Shacham-Waters parameters."""
        self.server_url = server_url
        self.p = config.P  # Large prime from config, e.g., 2**256 - 2**224 + 2**192 + 2**96 - 1
        self.alpha = randint(1, self.p - 1)  # Secret scalar
        self.k = os.urandom(32)  # PRF key (256 bits)
        self.kw_model = KeyBERT()
        self.block_size = config.BLOCK_SIZE
        self.l = 80  # Security parameter: number of blocks to challenge
        
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
            print(f"Error loading client storage: {str(e)}")
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

    def extract_keywords(self, content: bytes) -> List[str]:
        """Extract keywords from file content."""
        try:
            print("Extracting Keywords\n")
            keywords = self.kw_model.extract_keywords(content.decode())
            return [word for word, _ in keywords]
        except Exception as e:
            print(f"Error extracting keywords: {str(e)}")
            return []

    def split_into_blocks(self, content: bytes) -> List[bytes]:
        """Split file content into fixed-size blocks."""
        print("File Splitting\n")
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

    def upload_file(self, file_path: Path) -> str:
        """Upload a file with Shacham-Waters tags for each block."""
        print("Uploading File\n")
        try:
            file_id = str(uuid.uuid4())
            with open(file_path, "rb") as f:
                content = f.read()

            # Generate new key and alpha for this file
            file_key = os.urandom(32)
            file_alpha = randint(1, self.p - 1)
            
            # Store parameters for this file
            self.file_params[file_id] = {
                'alpha': file_alpha,
                'key': file_key,
                'filename': file_path.name
            }
            self._save_storage()

            keywords = self.extract_keywords(content)
            blocks = self.split_into_blocks(content)
            
            block_data = []
            for i, block in enumerate(blocks):
                tag = self.compute_tag(block, i, file_alpha, file_key)
                block_data.append({
                    "block_idx": i,
                    "tag": tag.to_bytes(32, 'big').hex(),  # Store as hex string
                    "size": len(block)
                })

            metadata = {
                "file_id": file_id,
                "filename": file_path.name,
                "keywords": keywords,
                "total_blocks": len(blocks),
                "blocks": block_data
            }

            response = requests.post(f"{self.server_url}/create-file", json=metadata)
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")

            for i, block in enumerate(blocks):
                files = {"block": (f"{file_id}_block_{i}", block, "application/octet-stream")}
                data = {"file_id": file_id, "block_idx": i}
                response = requests.post(f"{self.server_url}/upload-block", files=files, data=data)
                if response.status_code != 200:
                    raise Exception(f"Server error uploading block {i}: {response.text}")

            print(f"Successfully uploaded file {file_path.name} with ID: {file_id}")
            return file_id

        except Exception as e:
            print(f"Upload failed: {str(e)}")
            raise

    def generate_por_challenge(self, file_id: str, total_blocks: int) -> List[Tuple[int, int]]:
        """Generate a PoR challenge for a file."""
        # Ensure we don't try to sample more blocks than exist
        l = min(self.l, total_blocks)
        # If there are very few blocks, we might need to challenge all of them
        if total_blocks <= 8:
            indices = list(range(total_blocks))
        else:
            indices = sample(range(total_blocks), l)
        
        print(f"Challenging {len(indices)} blocks out of {total_blocks} total blocks")
        
        # Generate random coefficients for each challenged block
        challenge = [(i, randint(1, self.p - 1)) for i in indices]
        return challenge

    def verify_por_proof(self, file_id: str, challenge: List[Tuple[int, int]], sigma: int, mu: int) -> bool:
        """Verify the PoR proof from the server."""
        try:
            if file_id not in self.file_params:
                print(f"Error: No parameters found for file {file_id}")
                return False
                
            # Get the stored parameters for this file
            file_params = self.file_params[file_id]
            alpha = file_params['alpha']
            key = file_params['key']
            
            # Calculate expected sigma based on the parameters and the server's mu
            expected_sigma = 0
            
            # Sum the PRF values times challenge coefficients
            for i, nu in challenge:
                prf_value = self.prf(i, key)
                expected_sigma = (expected_sigma + nu * prf_value) % self.p
            
            # Add alpha * mu
            expected_sigma = (expected_sigma + alpha * mu) % self.p
            
            # Debug output
            print(f"Expected sigma: {expected_sigma}")
            print(f"Received sigma: {sigma}")
            
            return sigma == expected_sigma
            
        except Exception as e:
            print(f"Verification error: {str(e)}")
            return False

    def request_por_proof(self, file_id: str) -> Dict:
        """Request and verify a PoR proof for a file."""
        try:
            # Check if we have parameters for this file
            if file_id not in self.file_params:
                print(f"No parameters found for file {file_id}. Cannot verify.")
                return {"verified": False, "file_id": file_id, "error": "No client parameters"}

            # Get total blocks for the file
            with requests.get(f"{self.server_url}/file-info?file_id={file_id}") as response:
                if response.status_code != 200:
                    raise Exception(f"Server error: {response.text}")
                total_blocks = response.json()["total_blocks"]    

            challenge = self.generate_por_challenge(file_id, total_blocks)
            print(f"Generated challenge with {len(challenge)} blocks")
            
            # Convert challenge to the format expected by the server
            challenge_json = [{"index": i, "coeff": nu} for i, nu in challenge]
            
            response = requests.post(f"{self.server_url}/por-proof", json={
                "file_id": file_id,
                "challenge": challenge_json
            })
            
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")

            data = response.json()
            print(f"Received proof: {data}")
            
            # Parse the proof components from hex
            sigma = int(data["sigma"], 16)
            mu = int(data["mu"], 16)
            
            # Verify the proof
            verified = self.verify_por_proof(file_id, challenge, sigma, mu)
            return {"verified": verified, "file_id": file_id}

        except Exception as e:
            print(f"PoR proof failed: {str(e)}")
            raise

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Secure File Client with Shacham-Waters PoR")
    parser.add_argument("--server", type=str, default="http://13.232.216.193:8000", help="Server URL")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    upload_parser = subparsers.add_parser("upload", help="Upload a file")
    upload_parser.add_argument("file", type=str, help="Path to the file")

    por_parser = subparsers.add_parser("por", help="Request PoR proof")
    por_parser.add_argument("file_id", type=str, help="File ID to verify")

    args = parser.parse_args()
    server_url = args.server
    client = SecureFileClient(server_url)

    if args.command == "upload":
        file_id = client.upload_file(Path(args.file))
        print(f"File uploaded with ID: {file_id}")

    elif args.command == "por":
        result = client.request_por_proof(args.file_id)
        print(f"PoR Verification result: {'Successful' if result['verified'] else 'Failed'} for file {result['file_id']}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()