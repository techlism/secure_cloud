import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data'
LOG_DIR = BASE_DIR / 'logs'

# Database
DATABASE_PATH = DATA_DIR / 'secure_storage.db'

# AWS Configuration
AWS_CONFIG = {
    'bucket_name': 'secure-cloud-project',
    'region_name': 'ap-south-1'
}

BLOCK_SIZE = 1024 * 1024

# Logging configuration
LOG_FILE = LOG_DIR / 'app.log'