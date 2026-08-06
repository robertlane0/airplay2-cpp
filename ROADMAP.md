# roadmap

**the original three milestones are done.** what started as "lifted out of a
working player" is now a `git clone && cmake && run` standalone: Qt-free, no
host glue, a CLI that discovers a receiver and streams audio to it. **the new
milestones are not.** the optional miniaudio integration below (m4-m6, planned
in `MINIAUDIO_PLAN.md`) isn't built yet; until it is, the demo plays wav only.

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
  covered above by tests now). The wav reader was separately fuzzed with 38
  malformed files under ASan/UBSan.

## the path to standalone

three milestones, in order. **all three are done.**

### m1: make the sender Qt-free (done)

`raop_sender` used to do its networking with Qt (`QTcpSocket` / `QUdpSocket` /
`QTimer`). It now talks to the network only through `ITransport`:

```cpp
class ITransport {
public:
    using Handle = int;
    Handle tcpConnect(host, port, onConnected, onData, onClosed);
    Handle udpBind(port, onData);
    uint16_t    localPort(Handle) const;
    std::string localAddress(Handle) const;
    std::string peerAddress(Handle) const;     // TCP only
    bool send(Handle, data, len);              // TCP
    bool sendTo(Handle, host, port, data, len); // UDP
    void close(Handle);
    int  every(ms, fn);   // repeating timer (the pacer + keep-alives)
    int  after(ms, fn);   // one-shot timer   (handshake/PIN watchdogs)
    void cancel(timerId);
    void poll(timeoutMs); // pump: the host's whole main loop is this in a while()
};
```

Grew a bit past the original 5-method sketch (RAOP needs UDP send/receive with
per-datagram source addresses, plus one-shot timers for the handshake/PIN
watchdogs, not just the pacer) but the shape is the same: callback-driven, so it
maps cleanly onto a bare `poll()` loop *or* an existing event loop (Qt, asio,
libuv, all welcome as alternate adapters). `PosixTransport`
(`src/posix_transport.h`) is the default, plain BSD sockets + `poll(2)`,
IPv4-only, no third-party dependency. The whole host integration is now:

```cpp
PosixTransport io;
RaopSender sender(io);
while (running) io.poll(16);
```

### m2: drop the host glue (done)

- ~~`mdns_discovery.h` is only there for the `RaopDeviceInfo::Auth` enum~~, done
  as part of m1 (folded in as `RaopSender::Auth`, since the enum has nothing to
  do with discovery and the header didn't exist in this repo to begin with).
- ~~`common/logger.h` becomes a one-line `std::function<void(level, msg)>`
  sink~~, done as part of m1 (`src/logger.h`), same shape this line asked for.
- ~~ship a tiny mDNS browser for receiver discovery~~, done: `src/mdns_browser.h`.
  a plain BSD-sockets multicast query + a bounds-checked DNS message parser
  (no third-party mDNS/DNS-SD library), scoped to `_airplay._tcp.local` /
  `_raop._tcp.local`:

  ```cpp
  MdnsBrowser browser;
  browser.query([](const RaopDeviceInfo& d) {
      // d.name, d.host, d.port, d.deviceId, d.airplay2, d.auth (a starting guess)
  });
  for (int i = 0; i < 20; ++i) browser.poll(100);   // ~2 s browse window
  ```

  the `RaopSender::Auth` it produces for an AirPlay-2 device is a documented
  best-effort guess (`HapPin`), not a parsed feature-flag table, on purpose:
  see `mdns_browser.cpp`'s `deriveAuth` for why, and why `RaopSender`'s own
  403/470 auto-fallback between `HapPin`/`HapTransient` makes a wrong guess
  cost one round trip, not a failure. resolves IPv4 only, and only from
  records bundled in one response packet (every device this was tested
  against does that); both are documented, narrow, deliberate scope cuts, not
  gaps someone forgot.
- `common/ring_buffer.h` is already self-contained (it lives in `src/`).

### m3: the demo (done)

`example/airplay_send.cpp` wires `raop_sender` + `PosixTransport` +
`mdns_browser` + a small wav reader + a per-device credential cache into one
binary:

```
$ airplay-send living_room.wav
browsing for AirPlay/RAOP devices (3s)...
target: [AirPlay 2] Living Room  10.0.0.42:7000  (AppleTV14,1)
loaded 'living_room.wav': 1323000 frames @ 44100 Hz (30s)
streaming to 'Living Room'
30s / 30s queued
file fully queued, letting the tail play out...
done
```

zero flags is the whole pitch: it browses, picks a receiver (preferring
AirPlay 2), streams, and tears down cleanly on ctrl-c or end-of-file. `--host
<ip>` skips picking a device (still enriches from mDNS if that host answers,
falls back to a documented guess otherwise); `--list` just prints what's out
there; `--airplay1` / `--password` / `--volume` / `--browse-time` /
`--no-discover` round it out, see `--help`. A HAP on-screen PIN prompts on
stdin; a successful pairing is cached under `~/.cache/airplay-send/` (or
`$XDG_CACHE_HOME`) so the next run skips it.

wav support: 8/16/24/32-bit PCM integer + 32-bit float, mono or stereo (extra
channels dropped), any sample rate (`RaopSender` resamples to 44.1 kHz). Not a
general media library, on purpose: wav is built in and nothing else is — the
optional `ENABLE_MINIAUDIO` build that extends the same binary to mp3 / flac /
ogg (vorbis) / opus is the new work below, not done.

## new: the optional miniaudio integration (mp3 / flac / ogg / opus)

**not done.** the full plan lives in `MINIAUDIO_PLAN.md` (proposed
2026-08-06); this section is its roadmap form. until m4-m6 land, `airplay-send`
is wav-only and the tree has no miniaudio references. locked-in decisions:

- `ENABLE_MINIAUDIO` CMake option, default **OFF** — the default build stays
  wav-only and dependency-free.
- dispatch when ON: `loadWavAsStereo16` first, miniaudio fallback — no
  extension sniffing, so wav files decode identically in both configs.
- acquisition: FetchContent, pinned tag `0.11.25`, shallow, `SYSTEM` include —
  the same pattern as Mbed TLS.

### m4: the shared audio type (not done)

the two readers will share one output type, `AudioData`:

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

### m5: the optional miniaudio reader + flag (not done)

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

### m6: docs, notices, and the verification pass (not done)

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
