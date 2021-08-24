#!/bin/bash
set -e


if [ -z "$1" ] | [ -z "$2" ]; then
  echo "\$1 parameter must be the rust-secp256k1-sys depend directory"
  echo "\$2 parameter must be the rust-secp256k1-sys version code (M_m_p format)"
  echo "\$3 parameter (optional) can be the revision to check out"
  exit 1
fi

PARENT_DIR=$1
VERSIONCODE=$2
REV=$3
DIR=secp256k1
ORIGDIR=$(pwd)

while true; do
    read -r -p "$PARENT_DIR/$DIR will be deleted [yn]: " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

cd "$PARENT_DIR" || exit 1
rm -rf "$DIR"
git clone https://github.com/bitcoin-core/secp256k1.git "$DIR"
cd "$DIR"
if [ -n "$REV" ]; then
    git checkout "$REV"
fi
HEAD=$(git rev-parse HEAD)
cd ..
echo "# This file was automatically created by $0" > ./secp256k1-HEAD-revision.txt
echo "$HEAD" >> ./secp256k1-HEAD-revision.txt

# We need to make some source changes to the files.

# To support compiling for WASM, we need to remove all methods that use malloc.
# To compensate, the secp_context_create and _destroy methods are redefined in Rust.
patch "$DIR/include/secp256k1.h" "./secp256k1.h.patch"
patch "$DIR/src/secp256k1.c" "./secp256k1.c.patch"
patch "$DIR/src/scratch_impl.h" "./scratch_impl.h.patch"
patch "$DIR/src/util.h" "./util.h.patch"

# Prefix all methods with rustsecp and a version prefix
find "$DIR" -not -path '*/\.*' -type f -print0 | xargs -0 sed -i "/^#include/! s/secp256k1_/rustsecp256k1_v${VERSIONCODE}_/g"

# special rule for a method that is not prefixed in libsecp
find "$DIR" -not -path '*/\.*' -type f -print0 | xargs -0 sed -i "/^#include/! s/ecdsa_signature_parse_der_lax/rustsecp256k1_v${VERSIONCODE}_ecdsa_signature_parse_der_lax/g"

# TODO: can be removed once 496c5b43b lands in secp-zkp
find "$DIR" -not -path '*/\.*' -type f -print0 | xargs -0 sed -i 's/^const int CURVE_B/static const int CURVE_B/g'

while true; do
    read -r -p "Update Rust extern references and Cargo.toml as well? [yn]: " yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

cd "$ORIGDIR"

# Update the `links = ` in the manifest file.
sed -i -r "s/^links = \".*\"$/links = \"rustsecp256k1_v${VERSIONCODE}\"/" Cargo.toml

# Update the extern references in the Rust FFI source files.
find "./src/" -name "*.rs" -type f -print0 | xargs -0 sed -i -r "s/rustsecp256k1_v[0-9]+_[0-9]+_[0-9]+_(.*)([\"\(])/rustsecp256k1_v${VERSIONCODE}_\1\2/g"

