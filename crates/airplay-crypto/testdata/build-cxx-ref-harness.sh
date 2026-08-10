#!/bin/sh
# Rebuild the C++ reference harness and refresh its captured goldens.
# Run from the repository root. This is the AGENTS.md "differential
# validation" tool for airplay-crypto: any behavior change to the C++
# side must be reviewed against crates/airplay-crypto/testdata/cxx-ref-golden.txt
# and the Rust `cxx_reference_harness_goldens` test updated in lockstep.
set -e
HARNESS="crates/airplay-crypto/testdata/cxx-ref-harness.cpp"
g++ -std=c++20 \
  -I src -I _deps/mbedtls-src/include -I third_party/ed25519/src \
  "$HARNESS" src/airplay_crypto.cpp libairplay_crypto.a libed25519.a \
  _deps/mbedtls-build/library/libmbedcrypto.a \
  -o /tmp/cxx-ref-harness
/tmp/cxx-ref-harness > crates/airplay-crypto/testdata/cxx-ref-golden.txt
echo "golden updated: $(wc -l < crates/airplay-crypto/testdata/cxx-ref-golden.txt) lines"