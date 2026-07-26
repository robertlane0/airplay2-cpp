# airplay2-cpp

## Identity

Fork of `airplay2-sender-cpp` — focused on **AirPlay Video** (remote-URL
playback), not realtime audio. C++20. Apache-2.0.

## Build

Only the Qt-free crypto core (`airplay_crypto`) builds. The Qt-dependent
sender (`raop_sender.*`) is reference source, **not wired into CMake**.

```
cmake -B build                                                 # configure
cmake --build build --target airplay_crypto                    # build crypto core
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release             # CI-style
```

No tests, no lint, no formatter configured. Testing is interop against real
Apple TV hardware.

## Architecture

Two layers:

- **`src/airplay_crypto.*`** — Qt-free, portable C++20. Crypto (via Mbed TLS
  3.6 + vendored orlp/ed25519), SRP-6a-3072, TLV8, bplist00, RFC 2617 digest.
  Only target CMake builds.
- **`src/raop_sender.*`** — Qt-dependent sender state machine
  (QTcpSocket/QUdpSocket/QTimer). Reference implementation. Roadmap: extract a
  transport interface to make it Qt-free.

Video and RAOP share only **pairing + encrypted-request framing** — they are
unrelated wire protocols beyond that.

## Dependencies

| What | How | Notes |
|------|-----|-------|
| Mbed TLS 3.6 | `FetchContent` from GitHub | `ENABLE_PROGRAMS=OFF`, `ENABLE_TESTING=OFF` |
| orlp/ed25519 | Vendored in `third_party/ed25519/` | Compiled with `ED25519_NO_SEED` (entropy from Mbed TLS) |
| Qt5/Qt6 | System-installed | Only for `raop_sender`, not in CMake build yet |

## Protocol gotchas

- **Two pairing paths** — `pair-verify` (on-screen PIN, X25519 → 32-byte
  shared secret) vs `HAP transient` (SRP-6a → 64-byte session key **clamped
  to first 32 bytes** for the audio key).
- **Encrypted channel framing** — `[2B LE len][ChaCha20-Poly1305 cipher][16B
  tag]`, chunked at 1024 B. AAD = the 2-byte length prefix. Nonce = `[4x
  00][8B LE counter]`. Separate per-direction counters.

## Clean-room rules (from CONTRIBUTING.md)

- `src/airplay_crypto.*` is **clean-room** — written from public spec docs
  only. Do not paste code from owntone, shairport-sync, pyatv, pair_ap, etc.
  Wire formats/constants are facts, not source code.
- `src/raop_sender.cpp` is credited as a C++ port of pyatv (MIT). Extending it
  with logic from another project requires matching license + attribution.
- **Never** copy from GPL/AGPL sources.

## Style

- lowercase prose in docs/comments, plain text (no em-dashes).
- No `Co-Authored-By` AI-attribution trailers.
- Bug reports: receiver model, `sf=` feature flag, symptom.

## Current state

- Builds one static library (`airplay_crypto`).
- No binary target — there is nothing to run.
- CI: single job, ubuntu-latest, Ninja, build-only.

## Key source files

| File | Lines | Role |
|------|-------|------|
| `src/airplay_crypto.h` | — | Public API: all crypto+bplist+digest primitives |
| `src/airplay_crypto.cpp` | 781 | Implementation |
| `src/raop_sender.h` | 339 | `RaopSender` class, `State`/`PairStage` enums |
| `src/raop_sender.cpp` | 2034 | Full AP1+AP2 realtime-audio sender |
| `src/ring_buffer.h` | 87 | Lock-free SPSC ring buffer |
