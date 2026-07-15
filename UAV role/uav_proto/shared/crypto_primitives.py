"""
crypto_primitives.py - TEMPORARY VERSION using hashlib for testing
This replaces the broken Ascon library with SHA-256 to get Phase 4 working.
"""

import hashlib
import os
from typing import Optional

# Domain-separation tags (must match protocol_common.py)
TAG_ML_DSA = b"ML-DSA"
TAG_MERKLE_ROOT = b"MerkleRoot"
TAG_INTERVAL_SECRET = b"IntervalSecret"
TAG_RID = b"RID"
TAG_LEAF = b"leaf"
TAG_RID_AUTH = b"RID-Auth"
TAG_LIGHTWEIGHT = b"Lightweight"

def hash_bytes(data: bytes) -> bytes:
    """SHA-256 hash (temporary replacement for Ascon-Hash256)."""
    return hashlib.sha256(data).digest()

def kdf(secret: bytes, *components: bytes) -> bytes:
    """Key derivation function using SHA-256."""
    h = hashlib.sha256()
    h.update(secret)
    for comp in components:
        h.update(comp)
    return h.digest()

def aead_encrypt(key: bytes, nonce: bytes, ad: bytes, plaintext: bytes) -> bytes:
    """AEAD encryption (placeholder - returns XOR for testing)."""
    # Simple XOR for testing - NOT SECURE, only for testing!
    result = bytearray(plaintext)
    for i in range(len(result)):
        result[i] ^= key[i % len(key)] ^ nonce[i % len(nonce)]
    return bytes(result)

def aead_decrypt(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes) -> bytes:
    """AEAD decryption (placeholder - returns XOR for testing)."""
    # Simple XOR for testing - NOT SECURE, only for testing!
    result = bytearray(ciphertext)
    for i in range(len(result)):
        result[i] ^= key[i % len(key)] ^ nonce[i % len(nonce)]
    return bytes(result)
