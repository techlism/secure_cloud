from pathlib import Path
from typing import Generator
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
        block_hash = int.from_bytes(hashlib.sha256(block_data).digest(), byteorder="big")
        tag = (block_hash + self.private_key) ** -1 * self.P
        return f"{tag.x},{tag.y}"  # Tag stored as string for metadata

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
