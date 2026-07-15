"""
tuple_hash256.py

H384(.): the 384-bit collision-sensitive tuple hash the paper specifies
for Merkle leaves, internal nodes, roots, and authentication-transcript
hashing (Table 3's notation entry: "H256(.), H384(.) 256-bit
general-purpose hash and 384-bit collision-sensitive tuple hash"; "In
the implementation, H256 is Ascon-Hash256 and H384 is TupleHash256
with a 384-bit output as specified in NIST SP 800-185. TupleHash
supplies unambiguous, length-delimited encoding of structured inputs.").

Nothing in this codebase implemented H384 before this file: crypto_
primitives.py only exposes a single 256-bit hash_bytes(). This is a
distinct primitive from H256 and deliberately does not depend on
crypto_primitives.py or its choice of Ascon vs. the temporary hashlib
backend -- H384 is TupleHash256 regardless of which H256 backend is
live.

Backed by pycryptodome's Crypto.Hash.TupleHash256, NIST SP 800-185's
own encoding (not a hand-rolled reimplementation): each positional
argument becomes one length-encoded element of the tuple, exactly the
"unambiguous, length-delimited encoding of structured inputs" property
the paper's text calls out, so a caller doesn't need to add its own
delimiters between fields the way canonical_json_bytes()'s JSON
encoding does for H256/AEAD/KDF calls elsewhere in this codebase.

Requires pycryptodome (added to requirements.txt): pip install pycryptodome
"""

from Crypto.Hash import TupleHash256

DIGEST_BYTES = 48  # 384 bits


def tuple_hash256(*parts) -> bytes:
    """
    H384(parts...) -> 48 bytes. Each part may be bytes, or an int
    (encoded as a big-endian minimal-width byte string; callers that
    need a specific fixed width, e.g. a 32-bit level or position field,
    should pass pre-encoded bytes instead, since TupleHash treats each
    argument as one opaque, length-delimited element regardless of its
    byte width).
    """
    h = TupleHash256.new(digest_bytes=DIGEST_BYTES)
    for part in parts:
        if isinstance(part, int):
            part = part.to_bytes((part.bit_length() + 7) // 8 or 1, "big")
        h.update(part)
    return h.digest()
