#!/bin/bash
# build_ascon_libs.sh
#
# Compiles the official Ascon reference C implementation (ascon-c,
# github.com/ascon/ascon-c) into two small shared libraries. Run this on
# EVERY machine separately (your Mac and the Pi), it builds a native
# binary for whichever machine runs it; a library built on one will not
# load on the other.
#
# This replaces the pure-Python `ascon` PyPI package, which measured
# ~380x slower per hash call and implements the pre-standardization
# Ascon v1.2 naming, not NIST SP 800-232. This is the actual standardized
# Ascon-Hash256 / Ascon-AEAD128 reference code.
#
# Auto-detects macOS vs Linux and uses the right compiler flags for each:
# macOS's clang needs -dynamiclib to produce a library ctypes can load,
# Linux's gcc needs -shared -fPIC instead. The output is still named
# .so on both platforms on purpose, ctypes only cares about the actual
# binary format, not the file extension, and keeping the name the same
# means crypto_primitives.py doesn't need any platform-specific logic.
#
# Needs: a C compiler (Xcode Command Line Tools on macOS, gcc on Linux;
# already required by earlier setup steps for liboqs/bchlib either way).

set -e
cd "$(dirname "$0")/ascon_c_src"

OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
  echo "Detected macOS, using clang -dynamiclib"
  CC=clang
  SHARED_FLAGS="-dynamiclib"
else
  echo "Detected Linux, using gcc -shared -fPIC"
  CC=gcc
  SHARED_FLAGS="-shared -fPIC"
fi

$CC -O3 $SHARED_FLAGS -o ../libasconhash.so \
  hash.c permutations.c -I .

$CC -O3 $SHARED_FLAGS -o ../libasconaead.so \
  aead/aead.c aead/permutations.c -I aead/

echo "Built libasconhash.so and libasconaead.so in $(dirname "$0")"
echo "Verifying they load correctly..."
cd ..
python3 -c "
import ctypes
h = ctypes.CDLL('./libasconhash.so')
a = ctypes.CDLL('./libasconaead.so')
print('Both libraries load correctly.')
"
