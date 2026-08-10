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
| `posix_transport`       | `posix-transport`        | `crates/posix-transport`     | Rust impl started |
| `airplay_crypto`        | `airplay-crypto`         | `crates/airplay-crypto`      | Not assessed |
| `mdns_browser`          | `mdns-browser`           | `crates/mdns-browser`        | Not assessed |
| `raop_sender`           | `raop-sender`            | `crates/raop-sender`         | Not assessed |
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

### airplay-crypto (pending: read `airplay_crypto.cpp`)

- bplist/TLV8 wire formats, SRP-6a 3072/SHA-512 client, ChaCha20-Poly1305
  (8-byte LE counter nonce + 4-zero pad), HKDF-SHA512 (32-byte keys),
  X25519, Ed25519, sha512/hmacSha512, randomBytes, RFC 2617 digest auth.

### mdns-browser / raop-sender / airplay-send — pending assessment.

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