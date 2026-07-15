#!/bin/bash
# rebuild_ascon_libs.sh - Corrected for standard Ascon structure

set -e

cd ~/uav_proto/shared

# Clean old libraries
rm -f libasconhash.so libasconaead.so

# Clone Ascon if not present
if [ ! -d "ascon-c" ]; then
    git clone https://github.com/ascon/ascon-c.git
    cd ascon-c
    # Use the crypto_hash directory structure
else
    cd ascon-c
fi

echo "Building Ascon Hash library..."

# Find the hash implementation
HASH_SRC=""
if [ -f "crypto_hash/ascon_hash.c" ]; then
    HASH_SRC="crypto_hash/ascon_hash.c"
elif [ -f "src/crypto_hash/ascon_hash.c" ]; then
    HASH_SRC="src/crypto_hash/ascon_hash.c"
elif [ -f "hash/ascon_hash.c" ]; then
    HASH_SRC="hash/ascon_hash.c"
else
    echo "ERROR: Cannot find ascon_hash.c"
    echo "Searching for it..."
    find . -name "ascon_hash.c"
    exit 1
fi

echo "Found hash source: $HASH_SRC"

# Build with correct includes
gcc -O3 -fPIC -shared \
    -I. \
    -I$(dirname $HASH_SRC) \
    -I$(dirname $(dirname $HASH_SRC))/common \
    -DCRYPTO_NAMESPACE= \
    -DASCON_HASH=1 \
    -DASCON_HASH_RATE=8 \
    -DASCON_HASH_ROUNDS=12 \
    -o ../libasconhash.so \
    $HASH_SRC \
    common/printstate.c \
    common/word.c

echo "Building Ascon AEAD library..."

# Find the AEAD implementation
AEAD_SRC=""
if [ -f "crypto_aead/ascon_aead.c" ]; then
    AEAD_SRC="crypto_aead/ascon_aead.c"
elif [ -f "src/crypto_aead/ascon_aead.c" ]; then
    AEAD_SRC="src/crypto_aead/ascon_aead.c"
elif [ -f "aead/ascon_aead.c" ]; then
    AEAD_SRC="aead/ascon_aead.c"
else
    echo "ERROR: Cannot find ascon_aead.c"
    find . -name "ascon_aead.c"
    exit 1
fi

echo "Found AEAD source: $AEAD_SRC"

gcc -O3 -fPIC -shared \
    -I. \
    -I$(dirname $AEAD_SRC) \
    -I$(dirname $(dirname $AEAD_SRC))/common \
    -DCRYPTO_NAMESPACE= \
    -DASCON_AEAD=1 \
    -DASCON_AEAD_RATE=8 \
    -DASCON_AEAD_ROUNDS=12 \
    -o ../libasconaead.so \
    $AEAD_SRC \
    common/printstate.c \
    common/word.c

cd ..

echo "Verifying symbols..."
echo ""
echo "Hash symbols:"
nm -D libasconhash.so | grep -E "hash|HASH" || echo "  No hash symbols found!"
echo ""
echo "AEAD symbols:"
nm -D libasconaead.so | grep -E "aead|AEAD" || echo "  No AEAD symbols found!"

echo ""
echo "Done. Libraries built at:"
ls -la libascon*.so
