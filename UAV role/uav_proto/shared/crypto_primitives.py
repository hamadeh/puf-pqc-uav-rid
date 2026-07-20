"""
crypto_primitives.py

H(.), KDF(.), and AEAD for the final protocol, backed by the official
Ascon reference C implementation via ctypes.

Run build_ascon_libs.sh once on each target machine.  The generated
libraries are architecture-specific and intentionally not committed.
"""

import ctypes
import os

_DIR = os.path.dirname(__file__)
_HASH_LIB_PATH = os.path.join(_DIR, "libasconhash.so")
_AEAD_LIB_PATH = os.path.join(_DIR, "libasconaead.so")

for _path in (_HASH_LIB_PATH, _AEAD_LIB_PATH):
    if not os.path.exists(_path):
        raise ImportError(
            f"{_path} not found. Run ./build_ascon_libs.sh on this machine "
            "before running the final protocol or its benchmark."
        )

_libhash = ctypes.CDLL(_HASH_LIB_PATH)
_libaead = ctypes.CDLL(_AEAD_LIB_PATH)

_HASH_LEN = 32


def hash_bytes(data: bytes) -> bytes:
    """Ascon-Hash256 (NIST SP 800-232)."""
    out = ctypes.create_string_buffer(_HASH_LEN)
    ret = _libhash.crypto_hash(out, data, ctypes.c_ulonglong(len(data)))
    if ret != 0:
        raise RuntimeError("ascon-c crypto_hash returned nonzero")
    return out.raw


def kdf(*parts: bytes) -> bytes:
    """Protocol KDF: Ascon-Hash256 over the ordered byte-string parts."""
    return hash_bytes(b"".join(parts))


def aead_encrypt(key16: bytes, nonce16: bytes, associated_data: bytes,
                 plaintext: bytes) -> bytes:
    """Ascon-AEAD128 encryption; ciphertext includes its 16-byte tag."""
    if len(key16) != 16 or len(nonce16) != 16:
        raise ValueError("Ascon-AEAD128 key and nonce must each be 16 bytes")
    clen = ctypes.c_ulonglong(0)
    ciphertext = ctypes.create_string_buffer(len(plaintext) + 16)
    ret = _libaead.crypto_aead_encrypt(
        ciphertext, ctypes.byref(clen),
        plaintext, ctypes.c_ulonglong(len(plaintext)),
        associated_data, ctypes.c_ulonglong(len(associated_data)),
        None, nonce16, key16,
    )
    if ret != 0:
        raise RuntimeError("ascon-c crypto_aead_encrypt returned nonzero")
    return ciphertext.raw[:clen.value]


def aead_decrypt(key16: bytes, nonce16: bytes, associated_data: bytes,
                 ciphertext: bytes):
    """Ascon-AEAD128 decryption, or None when authentication fails."""
    if len(key16) != 16 or len(nonce16) != 16:
        raise ValueError("Ascon-AEAD128 key and nonce must each be 16 bytes")
    mlen = ctypes.c_ulonglong(0)
    plaintext = ctypes.create_string_buffer(max(len(ciphertext), 1))
    ret = _libaead.crypto_aead_decrypt(
        plaintext, ctypes.byref(mlen), None,
        ciphertext, ctypes.c_ulonglong(len(ciphertext)),
        associated_data, ctypes.c_ulonglong(len(associated_data)),
        nonce16, key16,
    )
    if ret != 0:
        return None
    return plaintext.raw[:mlen.value]
