import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data'
LOG_DIR = BASE_DIR / 'logs'

# Database
DATABASE_PATH = DATA_DIR / 'secure_storage.db'

AWS_CONFIG = {
    'bucket_name': 'secure-cloud-project',
    'region_name': 'ap-south-1'
}


BLOCK_SIZE = 1024 * 1024

# Logging configuration
LOG_FILE = LOG_DIR / 'app.log'

import os

# Shacham-Waters parameters
P = 2**256 - 2**224 + 2**192 + 2**96 - 1

# Server Configuration
LOG_FILE = "server.log"
DATABASE_FILE = "server_storage.db"

# Upload Configuration
LARGE_FILE_THRESHOLD_MB = 10
S3_MULTIPART_CHUNK_SIZE_MB = 10
PRESIGNED_URL_EXPIRY_SECONDS = 3600 


# Convert MB to bytes
LARGE_FILE_THRESHOLD_BYTES = LARGE_FILE_THRESHOLD_MB * 1024 * 1024
S3_MULTIPART_CHUNK_SIZE_BYTES = S3_MULTIPART_CHUNK_SIZE_MB * 1024 * 1024

if S3_MULTIPART_CHUNK_SIZE_BYTES < 5 * 1024 * 1024:
     print("WARN: S3_MULTIPART_CHUNK_SIZE_MB must be at least 5MB. Adjusting.")
     S3_MULTIPART_CHUNK_SIZE_BYTES = 5 * 1024 * 1024
