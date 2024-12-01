# verify_blocks.py - Complete file
from pathlib import Path
from typing import List
from main import SecureFileUploader  # Ensure SecureFileUploader is in client.py
import sys

def verify_specific_blocks():
    # Hardcoded values for testing
    SERVER_URL = "http://15.206.89.160:8000"  # Replace with your actual server URL
    FILE_ID = "9fbdeee4-5121-40ce-8f46-149238aae518"  # Replace with your actual file ID
    BLOCK_IDS = [
        "418de17ba13aebdd"  # Replace with actual block IDs you want to verify                
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
