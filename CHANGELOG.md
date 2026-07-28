# changelog

## unreleased
- **ROADMAP.md m2: the host glue is dropped.** Added `src/mdns_browser.{h,cpp}`:
  a small, dependency-free mDNS/DNS-SD browser (RFC 6762/6763, hand-parsed, no
  avahi/dns-sd/Bonjour.h) that discovers `_airplay._tcp.local` /
  `_raop._tcp.local` receivers and resolves each to a `RaopDeviceInfo` (host,
  port, deviceId, model, a starting `RaopSender::Auth` guess, and the raw TXT
  record). Bounds-checked throughout (loop-safe DNS name decompression, no
  trust placed in any length/count field from the wire), tested against a
  hand-crafted fake mDNS responder (including multi-hop name-compression and
  an `_airplay._tcp`/`_raop._tcp` upgrade-dedup case) and ~5000
  malformed/adversarial packets under ASan/UBSan with zero crashes. Builds as
  a CMake target (`mdns_browser`).
- **ROADMAP.md m1: `raop_sender` is Qt-free.** Replaced `QTcpSocket` /
  `QUdpSocket` / `QTimer` with `ITransport` (`src/transport.h`), a small
  callback-driven network+timer interface; `QObject` signals became
  `std::function` members; `QByteArray`/`QString`/`QHash`/`QList` became
  `std::string`/`std::map`/`std::vector`. `PosixTransport`
  (`src/posix_transport.{h,cpp}`) is the default adapter: plain `poll(2)` +
  BSD sockets, IPv4-only, no third-party dependency. `RaopDeviceInfo::Auth`
  (previously pulled from a host-only, not-in-this-repo `mdns_discovery.h`)
  is folded in as `RaopSender::Auth`; `common/logger.h` is replaced by a
  small pluggable `Log` sink (`src/logger.h`), both were m2 items, done
  early since m1 needed them to build standalone at all. `raop_sender` and
  `posix_transport` now build as CMake targets and have been run end-to-end
  against a fake RTSP/RAOP receiver.
- provenance made precise: the crypto/wire-format core is clean-room; the
  RAOP/AP2 transport in `raop_sender.cpp` is credited as a C++ port of pyatv
  (MIT). pyatv's MIT notice now ships in `licenses/THIRD-PARTY-NOTICES.txt`.
- added `## security` scope note (sender does not yet authenticate the receiver;
  trusted-LAN use), plus `SECURITY.md`, `CONTRIBUTING.md` (with the clean-room
  rule), an issue template, and a CI build of the crypto core.
- hardening: bplist UTF-16 length DoS-bound; pair-verify empty-shared-secret
  guard. ed25519 build now matches its SOURCE.md (drops seed.c / `ED25519_NO_SEED`).
- initial extraction from FXChainPlayer: the verified AirPlay 2 realtime sender
  + the Qt-free crypto/wire-format core.
- README carries the complete seven-step AP2 realtime recipe + the
  pair-verify-vs-transient audio-key story (the macOS 32-byte clamp).
- Apache-2.0 (explicit patent grant for the reverse-engineered protocol); vendored ed25519 (zlib); Mbed TLS (Apache-2.0) at build time.
- trademark / non-affiliation disclaimer added to README + NOTICE (Apple Inc.
  marks used nominatively; clean-room interoperability client, ships no apple
  keys/certs/firmware).
