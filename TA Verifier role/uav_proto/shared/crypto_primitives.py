"""
crypto_primitives.py - SHA-256 for consistent cross-platform testing
"""

import hashlib
import os

# Domain-separation tags
TAG_ML_DSA = b"ML-DSA"
TAG_MERKLE_ROOT = b"MerkleRoot"
TAG_INTERVAL_SECRET = b"IntervalSecret"
TAG_RID = b"RID"
TAG_LEAF = b"leaf"
TAG_RID_AUTH = b"RID-Auth"
TAG_LIGHTWEIGHT = b"Lightweight"

def hash_bytes(data: bytes) -> bytes:
    """SHA-256 hash - consistent across all platforms."""
    return hashlib.sha256(data).digest()

def kdf(secret: bytes, *components: bytes) -> bytes:
    """Key derivation using SHA-256."""
    h = hashlib.sha256()
    h.update(secret)
    for comp in components:
        h.update(comp)
    return h.digest()

def aead_encrypt(key: bytes, nonce: bytes, ad: bytes, plaintext: bytes) -> bytes:
    """XOR encryption for testing."""
    result = bytearray(plaintext)
    for i in range(len(result)):
        result[i] ^= key[i % len(key)] ^ nonce[i % len(nonce)]
    return bytes(result)

def aead_decrypt(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes) -> bytes:
    """XOR decryption for testing."""
    result = bytearray(ciphertext)
    for i in range(len(result)):
        result[i] ^= key[i % len(key)] ^ nonce[i % len(nonce)]
    return bytes(result)
