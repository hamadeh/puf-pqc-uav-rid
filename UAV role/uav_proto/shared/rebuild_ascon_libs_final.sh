#!/bin/bash
# rebuild_ascon_libs_final.sh - For Ascon repository with src/ structure

set -e

cd ~/uav_proto/shared

# Clean old libraries
rm -f libasconhash.so libasconaead.so

# Navigate to Ascon source
cd ascon-c

echo "Building Ascon Hash library from src/ structure..."

# Build hash library using src/hash.c with proper includes
gcc -O3 -fPIC -shared \
    -Isrc \
    -I. \
    -DCRYPTO_NAMESPACE= \
    -DASCON_HASH=1 \
    -DASCON_HASH_RATE=8 \
    -DASCON_HASH_ROUNDS=12 \
    -o ../libasconhash.so \
    src/hash.c \
    src/printstate.c \
    src/permutations.c

echo "Building Ascon AEAD library from src/ structure..."

# Build AEAD library using src/aead.c
gcc -O3 -fPIC -shared \
    -Isrc \
    -I. \
    -DCRYPTO_NAMESPACE= \
    -DASCON_AEAD=1 \
    -DASCON_AEAD_RATE=8 \
    -DASCON_AEAD_ROUNDS=12 \
    -o ../libasconaead.so \
    src/aead.c \
    src/printstate.c \
    src/permutations.c

cd ..

echo ""
echo "Verifying symbols..."
echo ""

# Check hash symbols
echo "Hash symbols in libasconhash.so:"
nm -D libasconhash.so | grep -E "hash|HASH|crypto" || echo "  No hash/crypto symbols found!"

# Check AEAD symbols
echo ""
echo "AEAD symbols in libasconaead.so:"
nm -D libasconaead.so | grep -E "aead|AEAD|crypto" || echo "  No AEAD/crypto symbols found!"

echo ""
echo "Libraries built:"
ls -la libascon*.so

# Test if the symbols are correct
echo ""
echo "Testing library loading..."
python3 -c "
import ctypes
import sys

# Test hash library
try:
    lib = ctypes.CDLL('./libasconhash.so')
    # Try to find crypto_hash
    if hasattr(lib, 'crypto_hash'):
        print('? crypto_hash found in libasconhash.so')
    elif hasattr(lib, 'ascon_hash'):
        print('? ascon_hash found in libasconhash.so')
    else:
        # List all symbols
        print('Available symbols in libasconhash.so:')
        for name in dir(lib):
            if not name.startswith('_'):
                print(f'  {name}')
except Exception as e:
    print(f'Error loading libasconhash.so: {e}')

# Test AEAD library
try:
    lib = ctypes.CDLL('./libasconaead.so')
    if hasattr(lib, 'crypto_aead_encrypt'):
        print('? crypto_aead_encrypt found in libasconaead.so')
    elif hasattr(lib, 'ascon_aead_encrypt'):
        print('? ascon_aead_encrypt found in libasconaead.so')
    else:
        print('Available symbols in libasconaead.so:')
        for name in dir(lib):
            if not name.startswith('_'):
                print(f'  {name}')
except Exception as e:
    print(f'Error loading libasconaead.so: {e}')
"
