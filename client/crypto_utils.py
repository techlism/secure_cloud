# crypto_utils.py
import os
import hashlib
from typing import Tuple, List
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import config

class HomomorphicTagGenerator:
    def __init__(self, key: bytes = None, s: bytes = None):
        """
        Initialize the HomomorphicTagGenerator with cryptographic primitives.
        
        Args:
            key: Secret symmetric key for CBC-MAC (32 bytes)
            s: Random scalar for homomorphic property (32 bytes)
        """
        # Generate or use provided key for CBC-MAC
        self.key = key if key else get_random_bytes(32)
        
        # Generate or use provided scalar s
        s_bytes = s if s else get_random_bytes(32)
        # Convert to integer and reduce modulo p
        self.s = int.from_bytes(s_bytes, 'big') % config.P
        
        # Prime modulus p
        self.p = config.P
    
    def compute_mac(self, data: bytes) -> bytes:
        """
        Compute AES-CBC-MAC for the given data block.
        
        Args:
            data: Data block bytes
            
        Returns:
            MAC tag as bytes
        """
        # Use zero IV for CBC-MAC
        iv = bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # PKCS7 padding
        padded_data = self._pad_data(data)
        # Encrypt and take last block as MAC
        ciphertext = cipher.encrypt(padded_data)
        mac = ciphertext[-16:]
        return mac
    
    def _pad_data(self, data: bytes) -> bytes:
        """PKCS7 padding for AES block size."""
        pad_len = 16 - (len(data) % 16)
        padding = bytes([pad_len]) * pad_len
        return data + padding
    
    def compute_hash(self, data: bytes) -> int:
        """
        Hash the data block and convert to integer in the field.
        
        Args:
            data: Data block bytes
            
        Returns:
            Integer hash value modulo p
        """
        hash_bytes = hashlib.sha256(data).digest()
        hash_int = int.from_bytes(hash_bytes, 'big') % self.p
        return hash_int
    
    def compute_tag(self, data: bytes) -> Tuple[bytes, bytes, int, int]:
        """
        Compute homomorphic tag for a data block.
        
        Args:
            data: Data block bytes
            
        Returns:
            Tuple of (tag_bytes, mac_bytes, hash_int, tag_int)
        """
        # Compute MAC
        mac_bytes = self.compute_mac(data)
        mac_int = int.from_bytes(mac_bytes, 'big') % self.p
        
        # Compute hash
        hash_int = self.compute_hash(data)
        
        # Compute tag = mac + s * hash (mod p)
        tag_int = (mac_int + (self.s * hash_int) % self.p) % self.p
        
        # Convert tag to bytes (32 bytes for 256-bit)
        tag_bytes = tag_int.to_bytes(32, 'big')
        
        return tag_bytes, mac_bytes, hash_int, tag_int
    
    def combine_tags(self, tags: List[int]) -> int:
        """
        Combine multiple tags into a single tag.
        
        Args:
            tags: List of integer tag values
            
        Returns:
            Combined tag as integer
        """
        combined_tag = sum(tags) % self.p
        return combined_tag
    
    def verify_combined_data(self, blocks: List[bytes], combined_tag: int) -> bool:
        """
        Verify the integrity of multiple blocks using a combined tag.
        
        Args:
            blocks: List of data blocks
            combined_tag: Combined tag value to verify against
            
        Returns:
            True if verification succeeds, False otherwise
        """
        sum_mac = 0
        sum_hash = 0
        
        # Compute MACs and hashes for each block
        for block in blocks:
            mac_bytes = self.compute_mac(block)
            mac_int = int.from_bytes(mac_bytes, 'big') % self.p
            hash_int = self.compute_hash(block)
            
            sum_mac = (sum_mac + mac_int) % self.p
            sum_hash = (sum_hash + hash_int) % self.p
        
        # Compute expected combined tag
        expected_tag = (sum_mac + (self.s * sum_hash) % self.p) % self.p
        
        # Verify
        return expected_tag == combined_tag
    
    def get_crypto_params(self) -> Tuple[bytes, bytes]:
        """Get the cryptographic parameters as bytes."""
        s_bytes = self.s.to_bytes(32, 'big')
        return self.key, s_bytes