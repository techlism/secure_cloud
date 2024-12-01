# client/verify_blocks.py
from pathlib import Path
from typing import List
from main import SecureFileUploader
from fastecdsa.curve import P256
from fastecdsa.point import Point
import sys
import requests
import hashlib

def verify_specific_blocks():
    # Hardcoded values for testing
    SERVER_URL = "http://15.206.89.160:8000"
    FILE_ID = "a805d69b-9281-4881-91d9-193446b7725d"
    BLOCK_IDS = [
        "ebe9909db14e26a2",
        "86ae935a03b0d61f"
    ]

    try:
        uploader = SecureFileUploader(SERVER_URL)
        print(f"Verifying blocks for file: {FILE_ID}")
        print(f"Block IDs: {', '.join(BLOCK_IDS)}")
        
        # Get tags and hashes from server
        response = requests.post(
            f"{SERVER_URL}/verify-blocks",
            json={"block_ids": BLOCK_IDS, "file_id": FILE_ID}
        )
        
        if response.status_code != 200:
            raise Exception(f"Server error: {response.text}")
            
        data = response.json()
        tags = data["tags"]
        block_hashes = data["block_hashes"]
        
        for tag_str, block_hash in zip(tags, block_hashes):
            # Parse tag point
            tag_x, tag_y = map(int, tag_str.split(","))
            tag = Point(tag_x, tag_y, curve=P256)
            
            # Convert block hash to integer
            h = int(block_hash, 16)
            
            # Verify tag using public key
            # (h + private_key)^-1 * P = tag
            # Therefore: (h + private_key) * tag = P
            verify_point = (h * uploader.P + uploader.public_key)
            if verify_point != tag:
                print(f"❌ Block verification failed!")
                return False
                
        print("✅ All blocks verified successfully!")
        return True

    except Exception as e:
        print(f"❌ Verification failed: {str(e)}")
        return False

if __name__ == "__main__":
    verify_specific_blocks()