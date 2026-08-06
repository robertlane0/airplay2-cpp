# roadmap

**the original three milestones and the miniaudio milestones (m1-m6) are done.** what started as "lifted out of a
working player" is now a `git clone && cmake && run` standalone: Qt-free, no
host glue, a CLI that discovers a receiver and streams audio to it, with an
optional `-DENABLE_MINIAUDIO=ON` build for playing mp3 / flac / ogg / opus files.

## done

- the whole AP2 realtime recipe, verified live against a real **Apple TV 4K**, a
  **HomePod**, and a **macOS** receiver (the full story is in the README).
- `airplay_crypto`: the Qt-free crypto + wire-format core. compiles and links on
  its own today, no Qt, no app around it.
- the transient/macOS **32-byte audio-key clamp**, the last-mile fix that turned
  "macbook shows the cover and stays silent" into "macbook plays".
- **m1: the sender is Qt-free.** `raop_sender.{h,cpp}` talks to the network only
  through `ITransport` (`src/transport.h`); `PosixTransport`
  (`src/posix_transport.{h,cpp}`) is the default poll()/BSD-sockets adapter.
  `RaopDeviceInfo::Auth` is folded in as `RaopSender::Auth` and `common/logger.h`
  is now the tiny pluggable `Log` sink m2 asked for. Builds as a CMake target
  (`raop_sender`) and has been run end-to-end against a fake RTSP/RAOP receiver
  (full OPTIONS → ANNOUNCE → SETUP → RECORD → streaming handshake, correct
  packet sizes/marker bits).
- **m2: the host glue is dropped.** `src/mdns_browser.{h,cpp}`: a small,
  dependency-free mDNS/DNS-SD browser (RFC 6762/6763, hand-parsed, no
  avahi/dns-sd/Bonjour.h) that finds `_airplay._tcp.local` /
  `_raop._tcp.local` receivers and produces exactly what `RaopSender` needs,
  host, port, a stable device id, and a starting `RaopSender::Auth` guess.
  Builds as a CMake target (`mdns_browser`) and has been run against a
  hand-crafted fake mDNS responder (PTR/SRV/TXT/A with real DNS name
  compression, an `_airplay._tcp` + `_raop._tcp` upgrade-dedup case) and
  ~5000 malformed/adversarial packets under ASan/UBSan with zero crashes.
- **m3: the CLI demo.** `example/airplay_send.cpp` + `wav_reader.{h,cpp}` +
  `creds_store.{h,cpp}`: `airplay-send <file.wav>` browses for a receiver,
  connects, streams, and tears down on ctrl-c or end-of-file; `--host` skips
  discovery, `--list` just prints what's out there. Builds as the
  `airplay-send` CMake target. Run end-to-end against hand-built fake
  devices covering the paths that matter: the actual zero-flags
  discover-then-stream experience, `--host`/`--airplay1`/digest-adjacent
  flags, ctrl-c mid-stream (confirmed a real TEARDOWN reaches the receiver),
  the HAP on-screen-PIN prompt (stdin → `submitPin` → SRP M3, confirmed
  byte-exact on the fake device's side), and malformed/missing wav files.
  Caught and fixed two real bugs along the way: an uncaught-exception crash
  on a non-numeric `--port`/`--volume`, and a credential cache that silently
  failed to persist on a machine with no pre-existing `~/.cache` (both
- **m4-m6: optional miniaudio integration (mp3 / flac / ogg / opus)**. New
  `ENABLE_MINIAUDIO` CMake option (default **OFF**). Shared `AudioData` type in
  `example/audio_data.h`; `wav_reader` runs first, `miniaudio_reader`
  (`loadWithMiniAudio`) acts as fallback when `ENABLE_MINIAUDIO=ON`. Tested
  across WAV, MP3, FLAC, OGG, and malformed inputs with clean error handling and
  zero miniaudio symbols in default builds.

## the path to standalone

### m4: the shared audio type (done)

the two readers share one output type, `AudioData`:

```cpp
struct AudioData {
    std::vector<int16_t> pcm;   // interleaved stereo
    uint32_t sampleRate = 0;
    bool ok = false;
    std::string error;          // set when ok == false
    size_t frames() const { return pcm.size() / 2; }
};
```

- new `example/audio_data.h`; `WavAudio` renamed and moved there from
  `wav_reader.h` (so `miniaudio_reader` can include it without including
  `wav_reader`).
- `wav_reader.{h,cpp}`: `loadWavAsStereo16` keeps its name (it is wav-specific)
  and just returns `AudioData`; `airplay_send.cpp` gets the mechanical
  `WavAudio` → `AudioData` renames. Purely mechanical, no behavior change.

### m5: the optional miniaudio reader + flag (done)

- `CMakeLists.txt`: `option(ENABLE_MINIAUDIO ... OFF)`; inside the flag block,
  `MINIAUDIO_BUILD_EXAMPLES/TESTS OFF` + `FetchContent` miniaudio `0.11.25` +
  link `miniaudio` into `airplay-send`, define `WITH_MINIAUDIO`, and force
  decoding-only compile defs on the miniaudio target
  (`MA_NO_DEVICE_IO` / `MA_NO_ENCODING` / `MA_NO_GENERATION`) so it needs no
  platform audio libs.
- new `example/miniaudio_reader.{h,cpp}` with `loadWithMiniAudio`: whole-file
  `ma_decoder` decode (s16 stereo output config, native sample rate) to the
  same `AudioData` the wav reader produces, with the same ~1 GB size cap and
  the same "clear error beats crash" error strings. miniaudio's converter does
  mono→stereo duplication and >2ch→stereo downmix, so the feed loop is
  untouched.
- `example/airplay_send.cpp`: one guarded fallback —
  `if (!audio.ok) audio = loadWithMiniAudio(o.wavPath);` — and the usage text
  `<file.wav>` → `<file>` under the flag. flag-OFF build: byte-for-byte the
  current code path, zero miniaudio symbols.

### m6: docs, notices, and the verification pass (done)

- `README.md` / `example/README.md`: `-DENABLE_MINIAUDIO=ON` build
  instructions and the supported-format matrix per config.
- `CHANGELOG.md` entry; `licenses/THIRD-PARTY-NOTICES.txt`: a miniaudio
  BUILD-TIME entry (pinned 0.11.25, real license text — CC0/MIT-0 as shipped)
  following the Mbed TLS convention.
- the verification pass from `MINIAUDIO_PLAN.md`: both configs build clean
  under the warning-as-error settings (flag-OFF must be byte-for-byte the old
  path; confirm no miniaudio symbols via `nm`); a wav file must decode
  identically in both configs (wav reader always runs first); mp3/flac/ogg
  (and opus if ffmpeg can encode it) smoke-tested via `airplay-send
  --no-discover --host 127.0.0.1 /tmp/t.flac`, where the decode happens
  before the connect attempt; truncated/empty/random inputs error cleanly;
  grep the tree for stale "wav only" claims.

## later / maybe

- buffered stream (type 103, TCP) alongside realtime (type 96, UDP).
- AAC / Opus on receivers that advertise it (realtime is hardcoded-ALAC). this
  is about the on-wire stream codec; as input files, aac is out of scope too,
  miniaudio's built-in decoders don't cover it (see the plan above).
- multi-room / grouped output.
- IPv6 in the default transport (the interface doesn't care; `PosixTransport`
  currently only binds/sends IPv4) and in `mdns_browser` (A records only today).
- a queued-query fallback in `mdns_browser` for a receiver that splits its
  PTR/SRV/TXT/A answer across multiple response packets (none seen in testing
  do this, but it's a real possibility per RFC 6762).
- a real device run of the CLI's HAP on-screen-PIN path end to end (tested so
  far against a hand-built fake device that proves the prompt/stdin/SRP-M3
  plumbing works, see the m3 note above; a live Apple TV pairing + a stored
  reconnect is the natural next confidence check).
- streaming input for the demo (stdin / a growing file) instead of loading
  the whole file into memory upfront. once m5 lands, a chunked-read pass
  through `ma_decoder` in the feed loop is the natural first step; the wav
  reader can grow the same way.

## want to help?

the roadmap's original three milestones are done; the miniaudio milestones
(m4-m6, see `MINIAUDIO_PLAN.md`) are next and not started. issues / PRs
against any of it are welcome, open one and let's talk. otherwise: try it
against your own receiver and file a bug if something's off, that's worth
more than another feature right now.
