# Migration Tracker — C++ → Rust 2024

Per AGENTS.md. Each component migrates in vertical slices, in dependency
order. States: `Not assessed` → `Assessed` → `Characterized` →
`Rust impl started` → `Rust impl validated` → `Shadow/differential validation`
→ `Production rollout` → `C++ removed` → `Completed`.

## Crate layout (mirrors the CMake targets)

| CMake target            | Rust crate               | Path                         | Status |
|-------------------------|--------------------------|------------------------------|--------|
| (header) `logger.h`     | `logger`                 | `crates/logger`              | Rust impl validated |
| (header) `ring_buffer.h`| `ring-buffer`            | `crates/ring-buffer`         | Rust impl validated |
| (header) `transport.h`  | `transport`              | `crates/transport`           | Rust impl validated |
| `posix_transport`       | `posix-transport`        | `crates/posix-transport`     | Rust impl validated |
| `airplay_crypto`        | `airplay-crypto`         | `crates/airplay-crypto`      | Characterized + Rust impl validated * |
| `mdns_browser`          | `mdns-browser`           | `crates/mdns-browser`        | Characterized + Rust impl validated * |
| `raop_sender`           | `raop-sender`            | `crates/raop-sender`         | Characterized + Rust impl started * |
| `airplay-send` (example)| `airplay-send`           | `crates/airplay-send`        | Not assessed |
| `mbedcrypto` + ed25519  | RustCrypto crates + dalek| (workspace dependencies)     | Not assessed |

## Global decisions (assessed)

- **No `unsafe` Rust anywhere in the workspace.** Enforced per-crate via
  workspace lints (`unsafe_code = "deny"`). Dependencies with `unsafe`
  internally (e.g. curve25519-dalek, nix) are acceptable only because their
  public APIs are safe and sound; each is listed in the supply-chain review
  below.
- **Panics instead of C++ UB.** Where the C++ has latent undefined behavior
  (e.g. calling `close()` on the socket whose `onClosed` is firing; nested
  `poll()`), the Rust translation is deterministic: documented `panic!` or a
  defined no-op. RefCell borrows are never held across user callbacks, so the
  operations RaopSender actually relies on (send/sendTo/close/every/after/
  cancel from inside callbacks) work exactly as in C++.
- **Sentinel values → `Option`/newtypes.** `Handle`/`TimerId` are newtypes;
  invalid handles are `Option<Handle>` (C++ `kInvalid == -1`).
- **Ring buffer: `&mut`-based, no atomics.** The C++ header is SPSC-safe
  (`alignas(64)` atomics) but the only caller in this repo (the `airplay-send`
  demo) feeds and drains it from the same `poll()` loop — single-threaded.
  The Rust version is a safe `&mut` ring; cross-thread use would need the
  caller to coordinate (documented, deliberate scope change). Revisit if a
  multithreaded host appears.
- **Randomness.** C++ uses CTR-DRBG seeded from the OS (Mbed TLS). The Rust
  side uses `getrandom` (OS CSPRNG) directly. This is a same-class behavior
  change: nothing in any wire format depends on the exact RNG output, and the
  C++ output was nondeterministic run-to-run too.
- **Threading model preserved:** one thread calls `poll()`; callbacks fire
  synchronously from inside `poll()`; no background threads. Rust `&self`
  method signatures + `RefCell` interiors encode "single-threaded, callbacks
  may re-enter for the supported ops".
- **Dependencies** (supply-chain review; all pure-Rust or safe-API):

  | Dep | Purpose | License | Notes |
  |-----|---------|---------|-------|
  | `sha2` | SHA-512 (SRP, hashes) | MIT/Apache-2.0 | RustCrypto, pure Rust |
  | `hmac`, `hkdf` | HMAC/HKDF-SHA512 | MIT/Apache-2.0 | RustCrypto |
  | `chacha20poly1305` | AP2 AEAD | Apache-2.0/MIT | RustCrypto |
  | `aes` + `cipher` | AES (CTR-DRBG) | MIT/Apache-2.0 | RustCrypto |
  | `md-5` | RFC 2617 digest auth | MIT/Apache-2.0 | RustCrypto |
  | `num-bigint` | SRP 3072-bit modpow | MIT/Apache-2.0 | replaces Mbed TLS bignum |
  | `x25519-dalek` | X25519 ECDH | BSD-3 | unsafe internally (`curve25519-dalek`), safe public API |
  | `ed25519-dalek` | Ed25519 (replaces vendored orlp) | BSD-3 | RFC 8032 deterministic, byte-identical signatures |
  | `getrandom` | OS CSPRNG seeding | MIT/Apache-2.0 | |
  | `subtle` | constant-time compares | BSD-3 | |
  | `nix` | poll(2)/sockets/multicast | MIT | libc-backed, safe API |

### logger / ring-buffer / transport — Rust impl validated (2026-08-10)

All three crates pass `cargo check --all-targets`, `cargo test` (4+9+3
tests incl. a 50k-op model check against `VecDeque` for the ring), `cargo
clippy -- -D warnings`, `cargo fmt --check`, and build docs. No `unsafe`
(workspace lint `unsafe_code = "deny"`).

### posix-transport — Rust impl validated (2026-08-11)

`crates/posix-transport` (845+ lines, 10 tests) passes the full gate
suite: `cargo check --all-targets`, `cargo test -p posix-transport`
(incl. deferred connected-callback, connect-failure, UDP send/receive
round-trips, timer clamp/reschedule/cancel, re-entrancy from callbacks,
and `close()` from inside a callback), `cargo clippy -- -D warnings`,
`cargo fmt --check`.

Bug fixed during validation: `tcp_connect` previously connected to
`addrs[0]` instead of the address record whose `socket()` succeeded
(C++ `used->ai_addr` parity at `src/posix_transport.cpp:86`). On an
IPv6-first resolution with IPv6 unavailable the old code returned `None`
where the C++ fell through to IPv4. Fixed by tracking the winning record;
regression test `tcp_connect_resolves_multihomed_hostname` covers the
multi-record resolution path.

## Per-component records

### logger (`src/logger.h` → `crates/logger`)

- **Scope.** Pluggable stderr log sink; `LogLevel { Info, Warn }`; default
  sink prints `[info] msg` / `[warn] msg` to stderr; `"{}"`-style formatting;
  `Log::format()` also exposed for building user-facing error strings.
- **Behavioral risks.** Formatting is "replace `{}` left to right with
  ostream output; if no placeholder, return fmt unchanged and ignore args".
  Rust `format!` panics at compile time on arity mismatch — an intentional,
  safer incompatibility (documented). Runtime `format` helper keeps the
  dynamic-string case.
- **Tests.** Default-sink output text; set_sink routing; placeholder
  replacement incl. missing-placeholder case.
- **Ownership.** Global static sink — `Mutex<Option<Sink>>` (C++ static
  function-local).

### ring-buffer (`src/ring_buffer.h` → `crates/ring-buffer`)

- **Scope.** Pow2-capacity ring, `tryPush`/`tryPop` returning bool, available
  read/write, capacity, reset. C++ requires trivially-copyable `T`; Rust
  mirrors with `T: Copy`.
- **Behavioral notes.** `nextPow2` on a requested size of 0 would wrap/UB in
  C++; Rust documents `requested_size == 0` → capacity 1 (or pushes nothing)
  — deterministic choice, to be confirmed against the caller.
- **Tests.** Full/half-empty boundaries, wrap-around, push-fail/pop-fail,
  reset, capacity rounding.
- **Owner.** conversation; **Exit criteria.** byte-identical frame stream to
  receiver in differential run.

### transport (`src/transport.h` → `crates/transport`)

- **Scope.** The `ITransport` contract: tcpConnect/udpBind/localPort/
  localAddress/peerAddress/send/sendTo/close/every/after/cancel/poll.
- **Boundary mapping.** `Handle`/`TimerId` newtypes; `Option` instead of -1;
  `DataFn(&[u8], &str /*fromHost*/, u16 /*fromPort*/)`; all methods `&self`
  with interior mutability so callbacks may re-enter with send/close/timers.
- **Tests.** Trait-level invariants via a mock transport (handle issuance,
  callback routing, re-entrancy from callbacks).

### posix-transport (assessment pending — read of `posix_transport.cpp`: done)

- 354 lines, `poll(2)` + BSD sockets, IPv4-only UDP + AF_UNSPEC TCP
  (getaddrinfo, first successful `socket()` wins), non-blocking connect with
  `connecting` flag, connected callback always deferred to `poll()`.
- `send`: bounded poll-for-writable (3000 ms) on EAGAIN; `sendTo`: IPv4-only
  (`inet_pton`), one datagram.
- Timers: `every`/`after` clamp ms (`every`: max(1,ms); `after`: max(0,ms));
  `poll` clamps its timeout to the earliest due timer; due timers rescheduled/
  erased BEFORE the callback fires (re-entrant `every()` restart pattern).
- Latent C++ UB (documented, avoided in Rust): `onData` closing its own
  socket invalidates the `onClosed` read later in the same dispatch; nested
  `poll()` from a callback. Rust: panic-free dispatch via owned `Rc` copies
  of callbacks taken before firing.
- Ports: POLLOUT|POLLERR while connecting; POLLIN|POLLHUP|POLLERR otherwise;
  `poll(nullptr, 0, t)` sleep when no sockets.
- **Deps:** `nix` (poll, sockets, multicast needs in mdns-browser).

### airplay-crypto (`src/airplay_crypto.cpp` → `crates/airplay-crypto`) — Characterized + Rust impl validated

- **Scope.** bplist/TLV8 wire formats, SRP-6a 3072/SHA-512 client,
  ChaCha20-Poly1305 (8-byte LE counter nonce + 4-zero pad), HKDF-SHA512
  (32-byte keys), X25519, Ed25519, sha512/hmacSha512, randomBytes, RFC 2617
  digest auth.
- **Differential validation (2026-08-10).** Deterministic C++ reference
  harness at `crates/airplay-crypto/testdata/cxx-ref-harness.cpp` (rebuild
  + golden refresh from the repo root: `sh crates/airplay-crypto/testdata/build-cxx-ref-harness.sh`).
  `crates/airplay-crypto/testdata/cxx-ref-golden.txt` captured 28 lines of
  ground truth (sha512/hmac/hkdf/ChaCha-Poly1305 ciphertext, X25519
  RFC 7748 §6.1 incl. clamping + low-order rejection, Ed25519 RFC 8032
  vector 1 + message signature, TLV8 incl. 384-byte fragmentation and
  truncation behavior, bplist full setup-features dict byte-exact,
  digest-auth header layout). The Rust tests mirror every value
  (`tests::cxx_reference_harness_goldens`). During validation the C++
  vendored X25519 (`third_party/ed25519/src/x25519_raw.c`) was swept
  against an independent Python Montgomery ladder (41 cases incl. the RFC
  vector): VENDORED C++ IS CORRECT — no incompatibility to document. A
  mis-typed test vector in the original Rust `hkdf_sha512_rfc5869_case4`
  golden constant was found and fixed (independent Python HKDF + C++
  agree with the implementation).
- **Behavioral notes.** `chacha20Poly1305Decrypt` returns `None` on bad
  key/tag/AAD (C++ `nullopt`); X25519 all-zero/low-order shared secret →
  `None`; SRP ephemeral `a` uses `getrandom` (C++ Mbed TLS CTR-DRBG —
  same-class OS randomness, documented decision above).
- **API parity.** `tlv`, `bplist`, `srp` exposed as `pub mod`s, matching the
  C++ header's public namespaces; `BplistValue`/`SrpClient` re-exported.

### mdns-browser (`src/mdns_browser.{h,cpp}` → `crates/mdns-browser`) — Characterized + Rust impl validated

- **Scope.** mDNS/DNS-SD receiver discovery: one UDP socket on
  `224.0.0.251:5353` (SO_REUSEADDR + SO_REUSEPORT, multicast TTL 255,
  nonblocking), two-question PTR query (`_airplay._tcp.local` +
  `_raop._tcp.local`), per-packet `PTR → SRV/TXT/A` correlation, friendly-name
  dedupe with silent host/port/txt refresh on re-announcement and a re-fire on
  AirPlay 1 → AirPlay 2 upgrade, `deriveAuth` (AP2 → HapPin; `pw` ∈
  {true,1} → Password; `am` prefix "AirPort" → AuthSetup; else None).
- **Parser semantics ported byte-for-byte from the C++ `DnsReader`** (all
  adversarial behavior unit-tested): name compression pointers must point
  strictly backward, ≤ 128 hops, ≤ 1024-byte names, reserved 01/10 label
  prefixes and truncated names are malformed, question section skipped, all
  three RR sections merged in packet order, `rdlength`-bounded rdata, TXT
  first-wins per key (C++ `emplace`/`std::map::insert` — Rust uses
  `BTreeMap::entry().or_insert()`), SRV port = rdata bytes 4–5 BE, A record
  must be `rdlength == 4` and in the same packet, cache-flush class bit
  masked, records already parsed before a malformed tail are still delivered.
- **Documented deviations.** `new() -> Result<MdnsBrowser, MdnsBrowserError>`
  instead of a half-constructed object + `ok()`; `SOCK_NONBLOCK` +
  `SOCK_CLOEXEC` passed to `socket(2)` (matching posix-transport) instead of a
  later `fcntl(O_NONBLOCK)`; `handle_packet` is public (C++ `handlePacket_`
  was private) so tests and callers can drive parsing without a socket.
- **`Auth` enum** mirrors `fxchain::RaopSender::Auth` (None, AuthSetup,
  LegacyPin, HapTransient, HapPin, Password) for `airplay-send` to consume.
- **Tests.** 25 unit tests: exact query-packet bytes, discovery + auth
  derivation, refresh-without-refire, upgrade re-fire, two devices in one
  packet in order, A-rdlength / missing-SRV skip rules, question-section
  skipping, TXT truncation soft-stop and first-wins merge, unknown
  service/instance isolation, malformed-input fuzzlets, pointer chain 128-hop
  cap, forward/self pointers, reserved prefixes, 1024-byte name cap, bounds
  checks. Live socket path (`new`/`query`/`poll`) verified on a dev box via an
  `#[ignore]`d smoke test (binds port 5353; excluded from default CI runs).
- **Owner.** conversation; **Exit criteria.** end-to-end discovery order in
  the `airplay-send` demo matches the C++ binary.

### raop-sender (`src/raop_sender.{h,cpp}` → `crates/raop-sender`) — Characterized + Rust impl started

- **Scope.** 2073-line state machine. The pure, device-free layers are
  ported and validated: `util` (NTP/RTP timeline math, hex/JSON/DMAP
  helpers, session constants), `rtsp` (response parsing `onRtspData_`,
  request builders `sendRequest_`/`sendAp2Rtsp_`/`httpPost_`/feedback,
  digest challenges, the AP2 ChaCha20-Poly1305 channel
  `writeRtsp_`/`onEventData_` incl. the encrypted-200-OK event responder,
  and the handshake payloads SDP/volume/transport/RTP-Info/DMAP
  metadata), `pairing` (pair-setup M1..M6 + pair-verify M1..M3 as
  `PairingSession`, creds-JSON), `plists` (AP2 SETUP session/stream
  payloads + reply parsing), and `stream` (RTP audio packets: AP1 BE s16
  / AP2 uncompressed-ALAC + ChaCha20-Poly1305 with trailing nonce, SYNC
  0x54, retransmit 0x55 → 0xD6, NTP timing reply 0xD3, 1024-slot
  backlog).
- **Session work (2026-08-10).** RTSP channel unit fixes: `MAX_FRAME_LEN`
  tightened 1 MiB → 32 KiB (an LE16 length prefix caps hostile frames at
  65535, making a 1 MiB ceiling unreachable; 32 KiB is the tightest
  enforceable power-of-two bound, documented deviation), `M4Outcome`
  moved to module scope, `PairingMode` derives `Default`, M1 test
  corrected against `sendPairSetupM1_` (Method=0, **State=1**,
  transient Flags=0x10), split/batched channel tests fixed (were
  replaying an already-decrypted frame — a real counter desync),
  `build_rtsp_request` refactored to an `RtspRequest` struct (clippy
  `too_many_arguments`).
- **`stream` module (2026-08-10).** 14 tests: ALAC bit-level goldens
  verified against an independent Python bit-writer (header 0x20 0x00
  0x02, samples continuous from bit 23, END tail 0x01 0xC0), RTP header
  golden (marker on first packet, seq/rtptime advance), AP1 BE-s16
  payload, AP2 AEAD roundtrip with AAD = header 4..12 and trailing LE
  nonce + counter advance, SYNC packet golden with hand-computed
  ts2ntp/rtptime fields, retransmit replay order + aged-out-slot skip,
  timing-reply golden + short-datagram rejection. Cross-checked against
  `sendAudioPacket_`/`sendSyncPacket_`/`onControlData_`/
  `onTimingData_`/`encodeAlacFrame_` (src/raop_sender.cpp:1825, 2006,
  2027, 2051, 1867).
- **`input` module (2026-08-10).** 11 tests: `Resampler` (`fillFrames_`)
  pass-through pop-and-pad, 88200 → every-other-frame, 22050 →
  interpolated midpoints with phase rebase + left-neighbour compaction,
  starvation → silence (the lerp demands its right neighbour even at
  frac = 0, per the C++ `i0 + 1 >= bufFrames` guard), `kInBufMaxFrames`
  top-up bound, 0 → 48000 mapping, no-ring silence path; and the pure
  pacer: `target_frames` boundary (352 frames need ≥ 352·10⁹/44100 ns),
  whole-block counting, cap 16. During testing a real bug was caught:
  the first `pending_packets` translation re-read the ORIGINAL
  `frames_sent` in the loop condition (C++ re-reads the growing value),
  returning 16 everywhere; fixed with the closed form
  `min(cap, (target − frames_sent)/FRAMES_PER_PACKET)`.
- **Remaining.** The `RaopSender` state machine over the `transport`
  trait (session flow, pacer token bucket, resampler, ring input),
  mock-transport integration tests, then the `airplay-send` example /
  C++ removal.
- **Owner.** conversation.

### airplay-send (`crates/airplay-send`) — pending assessment.

## CI quality gates (to be established)

1. `cargo fmt --check`
2. `cargo check --all-targets --all-features`
3. `cargo test --all-targets --all-features`
4. `cargo clippy --all-targets --all-features -- -D warnings`
5. Rust 2024 edition (workspace `edition`), `unsafe_code = "deny"` (workspace
   lints)
6. `cargo doc --no-deps` for public crate API changes
7. Dependency audit (`cargo audit` where available)

## Definition of done (workspace-level)

The C++ build remains the reference during migration; each crate lands with
unit tests + characterization tests, clippy-clean, and `deny(unsafe_code)`.
The final migration state: production path entirely Rust, C++ removed from
the build, differential/characterization evidence recorded here.