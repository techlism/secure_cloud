# verify_blocks.py - Complete file
from pathlib import Path
from typing import List
from main import SecureFileUploader
import sys

def verify_specific_blocks():
    # Hardcoded values for testing
    SERVER_URL = "http://15.206.89.160:8000"
    FILE_ID = "97cb28f2-7066-4e2e-bbc4-0f2c7a388055"
    BLOCK_IDS = [
        "e1cca550de61814a"
    ]

    try:
        uploader = SecureFileUploader(SERVER_URL)
        print(f"Verifying blocks for file: {FILE_ID}")
        print(f"Block IDs: {', '.join(BLOCK_IDS)}")
        
        if uploader.verify_blocks(FILE_ID, BLOCK_IDS):
            print("✅ Blocks verified successfully")
        else:
            print("❌ Block verification failed")
            
    except Exception as e:
        print(f"❌ Verification failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    verify_specific_blocks()