#!/usr/bin/env bash
# Build the NIST-standard Ascon-Hash256 and Ascon-AEAD128 reference
# implementations on macOS, verify official KATs, then install them while
# retaining timestamped backups of any existing native libraries.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_ROOT="$SCRIPT_DIR/ascon_c_src"
HASH_SRC="$SOURCE_ROOT/crypto_hash/asconhash256/ref"
AEAD_SRC="$SOURCE_ROOT/crypto_aead/asconaead128/ref"
TEST_HEADERS="$SOURCE_ROOT/tests"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ascon-verified.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: this verified rebuild script is for macOS/clang." >&2
  exit 1
fi

for required in \
  "$HASH_SRC/hash.c" "$HASH_SRC/printstate.c" \
  "$AEAD_SRC/aead.c" "$AEAD_SRC/printstate.c"; do
  if [[ ! -f "$required" ]]; then
    echo "ERROR: missing Ascon reference source: $required" >&2
    exit 1
  fi
done

echo "Building Ascon-Hash256 reference library..."
clang -O3 -dynamiclib \
  -I "$HASH_SRC" \
  -o "$TMP_DIR/libasconhash.so" \
  "$HASH_SRC/hash.c" "$HASH_SRC/printstate.c"

echo "Building Ascon-AEAD128 reference library..."
clang -O3 -dynamiclib \
  -I "$AEAD_SRC" -I "$TEST_HEADERS" \
  -o "$TMP_DIR/libasconaead.so" \
  "$AEAD_SRC/aead.c" "$AEAD_SRC/printstate.c"

echo "Checking official known-answer vectors..."
python3 - "$TMP_DIR/libasconhash.so" "$TMP_DIR/libasconaead.so" <<'PY'
import ctypes
import sys

hash_path, aead_path = sys.argv[1:]

hash_lib = ctypes.CDLL(hash_path)
hash_lib.crypto_hash.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.c_ulonglong]
hash_lib.crypto_hash.restype = ctypes.c_int
digest = ctypes.create_string_buffer(32)
if hash_lib.crypto_hash(digest, b"", 0) != 0:
    raise SystemExit("Ascon-Hash256 returned an error")
expected_hash = bytes.fromhex(
    "0b3be5850f2f6b98caf29f8fdea89b64"
    "a1fa70aa249b8f839bd53baa304d92b2"
)
if digest.raw != expected_hash:
    raise SystemExit(
        f"Ascon-Hash256 KAT failed: {digest.raw.hex()} != {expected_hash.hex()}"
    )

aead_lib = ctypes.CDLL(aead_path)
aead_lib.crypto_aead_encrypt.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.c_void_p, ctypes.c_ulonglong,
    ctypes.c_void_p, ctypes.c_ulonglong,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
]
aead_lib.crypto_aead_encrypt.restype = ctypes.c_int
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
nonce = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
ciphertext = ctypes.create_string_buffer(16)
ciphertext_len = ctypes.c_ulonglong(0)
if aead_lib.crypto_aead_encrypt(
    ciphertext, ctypes.byref(ciphertext_len),
    b"", 0, b"", 0, None, nonce, key,
) != 0:
    raise SystemExit("Ascon-AEAD128 returned an error")
expected_ciphertext = bytes.fromhex("4f9c278211bec9316bf68f46ee8b2ec6")
actual_ciphertext = ciphertext.raw[:ciphertext_len.value]
if actual_ciphertext != expected_ciphertext:
    raise SystemExit(
        f"Ascon-AEAD128 KAT failed: "
        f"{actual_ciphertext.hex()} != {expected_ciphertext.hex()}"
    )

print("Ascon-Hash256 KAT: PASS")
print("Ascon-AEAD128 KAT: PASS")
PY

stamp="$(date +%Y%m%d_%H%M%S)"
for name in libasconhash.so libasconaead.so; do
  if [[ -e "$SCRIPT_DIR/$name" ]]; then
    mv "$SCRIPT_DIR/$name" "$SCRIPT_DIR/${name}.backup_${stamp}"
    echo "Archived old $name as ${name}.backup_${stamp}"
  fi
  mv "$TMP_DIR/$name" "$SCRIPT_DIR/$name"
done

echo "Installed verified native libraries in $SCRIPT_DIR"
