# changelog

## unreleased
- **miniaudio: the demo plays more than wav, optionally.** New
  `ENABLE_MINIAUDIO` CMake flag (default **OFF**; full plan in
  `MINIAUDIO_PLAN.md`). The flag build fetches miniaudio 0.11.25 (FetchContent,
  pinned tag, decode-only: `MA_NO_DEVICE_IO` / `MA_NO_ENCODING` /
  `MA_NO_GENERATION`) and compiles a second reader,
  `example/miniaudio_reader.{h,cpp}` (`loadWithMiniAudio`), so `airplay-send`
  decodes mp3 / flac / ogg (vorbis) / opus as well as wav. Dispatch is
  fallback-based: the fuzz-tested `loadWavAsStereo16` runs first, miniaudio
  only when it fails, so the default build stays byte-for-byte the wav-only
  code path with zero miniaudio references. Both readers share one output
  type: `WavAudio` moved to a new `example/audio_data.h` and became
  `AudioData`. aac is a documented non-goal (miniaudio's built-in decoders
  don't cover it). README / example README carry the build instructions and
  the per-config format matrix; miniaudio's license is in
  `licenses/THIRD-PARTY-NOTICES.txt`.
- **ROADMAP.md m3: the CLI demo.** Added `airplay-send` (`example/`): browses
  for a receiver via `mdns_browser`, connects and streams a `.wav` through
  `raop_sender` + `PosixTransport`, tears down cleanly on ctrl-c or
  end-of-file. New `example/wav_reader.{h,cpp}` (RIFF/WAVE, 8/16/24/32-bit
  PCM + float32, mono/stereo, WAVE_FORMAT_EXTENSIBLE) and
  `example/creds_store.{h,cpp}` (a per-device HAP credential cache under
  `~/.cache/airplay-send/`, so a re-run skips the on-screen PIN). Verified
  end-to-end against hand-built fake devices: the zero-flags discover-and-
  play path, `--host`/`--airplay1`/`--list`/`--no-discover`, ctrl-c mid-
  stream (confirmed a real TEARDOWN reaches the receiver), and the HAP
  on-screen-PIN prompt (stdin -> `submitPin` -> SRP M3, confirmed byte-exact
  on the fake device's side). Fixed two bugs found in the process: an
  uncaught-exception crash on a non-numeric `--port`/`--volume`/
  `--browse-time`, and a credential cache that silently failed to persist on
  a machine with no pre-existing `~/.cache` (both now covered by tests). The
  wav reader was separately fuzzed with 38 malformed files under ASan/UBSan
  with zero crashes. Builds as the `airplay-send` CMake target.
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
