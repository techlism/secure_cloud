# client.py
import json
import os
import hashlib
import math
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
import requests
import uuid
from keybert import KeyBERT
from crypto_utils import HomomorphicTagGenerator
import config

class SecureFileClient:
    def __init__(self, server_url: str, crypto_key: bytes = None, scalar_s: bytes = None):
        """
        Initialize the secure file client.
        
        Args:
            server_url: URL of the secure file server
            crypto_key: Optional crypto key (will be generated if None)
            scalar_s: Optional scalar value (will be generated if None)
        """
        self.server_url = server_url
        self.tag_generator = HomomorphicTagGenerator(crypto_key, scalar_s)
        self.kw_model = KeyBERT()
        self.block_size = config.BLOCK_SIZE
    
    def extract_keywords(self, content: bytes) -> List[str]:
        """
        Extract keywords from file content.
        
        Args:
            content: File content as bytes
            
        Returns:
            List of extracted keywords
        """
        try:
            text_content = content.decode('utf-8', errors='ignore')
            keywords = self.kw_model.extract_keywords(
                text_content,
                keyphrase_ngram_range=(1, 2),
                stop_words='english',
                use_mmr=True,
                diversity=0.7,
                top_n=10
            )
            return [word for word, _ in keywords]
        except Exception as e:
            print(f"Error extracting keywords: {str(e)}")
            return []
    
    def split_into_blocks(self, content: bytes) -> List[bytes]:
        """
        Split file content into fixed-size blocks.
        
        Args:
            content: File content as bytes
            
        Returns:
            List of data blocks
        """
        blocks = []
        total_size = len(content)
        num_blocks = math.ceil(total_size / self.block_size)
        
        for i in range(num_blocks):
            start = i * self.block_size
            end = min(start + self.block_size, total_size)
            block = content[start:end]
            
            # Pad the last block if necessary
            if len(block) < self.block_size:
                block = block + b'\0' * (self.block_size - len(block))
            
            blocks.append(block)
        
        return blocks
    
    def upload_file(self, file_path: Path) -> str:
        """
        Upload a file with homomorphic tags for each block.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File ID
        """
        try:
            file_id = str(uuid.uuid4())
            
            with open(file_path, "rb") as f:
                content = f.read()
            
            # Extract keywords from the entire file
            keywords = self.extract_keywords(content)
            
            # Split content into blocks
            blocks = self.split_into_blocks(content)
            
            # Compute tags for each block
            block_data = []
            for i, block in enumerate(blocks):
                tag_bytes, _, _, tag_int = self.tag_generator.compute_tag(block)
                
                block_data.append({
                    "block_idx": i,
                    "tag": tag_bytes.hex(),
                    "size": len(block)
                })
            
            # Prepare metadata
            metadata = {
                "file_id": file_id,
                "filename": file_path.name,
                "keywords": keywords,
                "total_blocks": len(blocks),
                "blocks": block_data
            }
            
            # First, upload metadata to create file record
            response = requests.post(
                f"{self.server_url}/create-file",
                json=metadata
            )
            
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
            
            # Then upload each block
            for i, block in enumerate(blocks):
                files = {"block": (f"{file_id}_block_{i}", block, "application/octet-stream")}
                data = {
                    "file_id": file_id,
                    "block_idx": i
                }
                
                response = requests.post(
                    f"{self.server_url}/upload-block",
                    files=files,
                    data=data
                )
                
                if response.status_code != 200:
                    raise Exception(f"Server error uploading block {i}: {response.text}")
            
            print(f"Successfully uploaded file {file_path.name} with ID: {file_id}")
            return file_id
        
        except Exception as e:
            print(f"Upload failed: {str(e)}")
            raise
    
    def get_blocks_by_keyword(self, keyword: str, block_indices: Optional[List[int]] = None) -> Dict:
        """
        Retrieve and verify blocks from files that contain a specific keyword.
        
        Args:
            keyword: Keyword to search for
            block_indices: Optional specific block indices to retrieve (all if None)
            
        Returns:
            Dictionary with verification results and block data
        """
        try:
            # Request blocks by keyword
            params = {"keyword": keyword}
            if block_indices:
                params["block_indices"] = ",".join(map(str, block_indices))
            
            response = requests.get(
                f"{self.server_url}/get-blocks-by-keyword",
                params=params
            )
            
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
            
            data = response.json()
            
            # Parse combined data
            combined_data = bytes.fromhex(data["combined_data"])
            combined_tag = int(data["combined_tag"], 16)
            metadata = data["metadata"]
            
            # Extract blocks based on metadata
            blocks = []
            current_pos = 0
            block_info = []
            
            for item in metadata:
                file_id = item["file_id"]
                block_idx = item["block_idx"]
                block_len = item["block_len"]
                
                block = combined_data[current_pos:current_pos + block_len]
                blocks.append(block)
                block_info.append({"file_id": file_id, "block_idx": block_idx})
                current_pos += block_len
            
            # Verify combined data
            verification_result = self.tag_generator.verify_combined_data(blocks, combined_tag)
            
            return {
                "verified": verification_result,
                "blocks": blocks,
                "block_info": block_info,
                "metadata": metadata
            }
        
        except Exception as e:
            print(f"Block retrieval failed: {str(e)}")
            raise
    
    def get_blocks_by_file_ids(self, file_blocks: Dict[str, List[int]]) -> Dict:
        """
        Retrieve and verify specific blocks from specific files.
        
        Args:
            file_blocks: Dictionary mapping file_ids to lists of block indices
            
        Returns:
            Dictionary with verification results and block data
        """
        try:
            response = requests.post(
                f"{self.server_url}/get-blocks-by-file-ids",
                json={"file_blocks": file_blocks}
            )
            
            if response.status_code != 200:
                raise Exception(f"Server error: {response.text}")
            
            data = response.json()
            
            # Parse combined data
            combined_data = bytes.fromhex(data["combined_data"])
            combined_tag = int(data["combined_tag"], 16)
            metadata = data["metadata"]
            
            # Extract blocks based on metadata
            blocks = []
            current_pos = 0
            block_info = []
            
            for item in metadata:
                file_id = item["file_id"]
                block_idx = item["block_idx"]
                block_len = item["block_len"]
                
                block = combined_data[current_pos:current_pos + block_len]
                blocks.append(block)
                block_info.append({"file_id": file_id, "block_idx": block_idx})
                current_pos += block_len
            
            # Verify combined data
            verification_result = self.tag_generator.verify_combined_data(blocks, combined_tag)
            
            return {
                "verified": verification_result,
                "blocks": blocks,
                "block_info": block_info,
                "metadata": metadata
            }
        
        except Exception as e:
            print(f"Block retrieval failed: {str(e)}")
            raise
    
    def get_crypto_params(self) -> Tuple[bytes, bytes]:
        """Get the cryptographic parameters as bytes."""
        return self.tag_generator.get_crypto_params()
    
    def save_crypto_params(self, file_path: str) -> None:
        """
        Save cryptographic parameters to a file.
        
        Args:
            file_path: Path to save the parameters
        """
        key, s = self.get_crypto_params()
        with open(file_path, "wb") as f:
            f.write(key + s)
        print(f"Cryptographic parameters saved to {file_path}")
    
    @classmethod
    def load_from_params_file(cls, server_url: str, file_path: str) -> 'SecureFileClient':
        """
        Create a client instance from saved cryptographic parameters.
        
        Args:
            server_url: Server URL
            file_path: Path to the parameters file
            
        Returns:
            SecureFileClient instance
        """
        with open(file_path, "rb") as f:
            data = f.read()
            
        key = data[:32]
        s = data[32:64]
        
        return cls(server_url, key, s)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Secure File Client")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Upload a file")
    upload_parser.add_argument("file", type=str, help="Path to the file")
    upload_parser.add_argument("--params", type=str, help="Path to crypto parameters file")
    
    # Get by keyword command
    keyword_parser = subparsers.add_parser("get-by-keyword", help="Get blocks by keyword")
    keyword_parser.add_argument("keyword", type=str, help="Keyword to search for")
    keyword_parser.add_argument("--blocks", type=str, help="Comma-separated block indices")
    keyword_parser.add_argument("--params", type=str, required=True, help="Path to crypto parameters file")
    
    # Get by file IDs command
    file_parser = subparsers.add_parser("get-by-files", help="Get blocks by file IDs")
    file_parser.add_argument("file_blocks", type=str, help="JSON string mapping file IDs to block indices")
    file_parser.add_argument("--params", type=str, required=True, help="Path to crypto parameters file")
    
    # Generate crypto params command
    gen_parser = subparsers.add_parser("generate-params", help="Generate and save crypto parameters")
    gen_parser.add_argument("output", type=str, help="Output file path")
    
    args = parser.parse_args()
    
    # Server URL
    server_url = "http://localhost:8000"
    
    if args.command == "upload":
        if args.params:
            client = SecureFileClient.load_from_params_file(server_url, args.params)
        else:
            client = SecureFileClient(server_url)
            # Save parameters for future use
            params_path = "crypto_params.bin"
            client.save_crypto_params(params_path)
            print(f"New crypto parameters generated and saved to {params_path}")
            
        file_id = client.upload_file(Path(args.file))
        print(f"File uploaded with ID: {file_id}")
    
    elif args.command == "get-by-keyword":
        client = SecureFileClient.load_from_params_file(server_url, args.params)
        block_indices = None
        if args.blocks:
            block_indices = [int(idx) for idx in args.blocks.split(",")]
            
        result = client.get_blocks_by_keyword(args.keyword, block_indices)
        print(f"Verification result: {'Successful' if result['verified'] else 'Failed'}")
        print(f"Retrieved {len(result['blocks'])} blocks")
        
        for i, (block, info) in enumerate(zip(result['blocks'], result['block_info'])):
            print(f"Block {i}: File ID {info['file_id']}, Block {info['block_idx']}, Size {len(block)} bytes")
    
    elif args.command == "get-by-files":
        client = SecureFileClient.load_from_params_file(server_url, args.params)
        file_blocks = json.loads(args.file_blocks)
        
        result = client.get_blocks_by_file_ids(file_blocks)
        print(f"Verification result: {'Successful' if result['verified'] else 'Failed'}")
        print(f"Retrieved {len(result['blocks'])} blocks")
        
        for i, (block, info) in enumerate(zip(result['blocks'], result['block_info'])):
            print(f"Block {i}: File ID {info['file_id']}, Block {info['block_idx']}, Size {len(block)} bytes")
    
    elif args.command == "generate-params":
        client = SecureFileClient(server_url)
        client.save_crypto_params(args.output)
        print(f"Crypto parameters generated and saved to {args.output}")

if __name__ == "__main__":
    main()