# example: airplay-send

the reference CLI for the core. `raop_sender` + `PosixTransport` +
`mdns_browser` + a wav reader + a per-device credential cache, wired into one
binary. ROADMAP.md m3, done; the optional miniaudio reader (ROADMAP.md, done)
extends it to more formats behind a CMake flag.

## build

default build, wav only:

```
cmake -B build && cmake --build build --target airplay-send
```

"everything else" (adds miniaudio, plays mp3 / flac / ogg / opus too):

```
cmake -B build -DENABLE_MINIAUDIO=ON && cmake --build build --target airplay-send
```

the binary lands at `build/airplay-send`. the default build is dependency-free
and contains zero miniaudio references; the flag build fetches miniaudio
0.11.25 (pinned tag) at configure time, like Mbed TLS.

## use

```
airplay-send living_room.wav                          # discover, pick a receiver, stream
airplay-send --host 10.0.0.42 song.mp3                 # with -DENABLE_MINIAUDIO=ON
airplay-send --host 10.0.0.42 --airplay1 song.wav      # legacy RAOP, no HAP pairing
airplay-send --host 10.0.0.42 --password secret song.wav  # pw=true legacy receivers
airplay-send --name "Party Box" living_room.wav        # override the sender name
airplay-send --list                                    # just show what's on the LAN
airplay-send --help                                    # the full flag list
```

zero flags is the intended default: it browses for ~3 s, prefers an AirPlay 2
device if one answered, connects, pairs if it needs to (a HAP on-screen PIN
prompts right there on stdin), streams the file, and tears down cleanly on
ctrl-c or when the file ends. A successful pairing is cached under
`~/.cache/airplay-send/` (or `$XDG_CACHE_HOME`) so the next run against the
same device skips the PIN.

the name that reaches the receiver (`X-Apple-Client-Name` + the AP2 SETUP
"name" field) defaults to the executable's own file name -- rename the binary
and the sender renames itself -- or is set explicitly with `--name <name>`.

## input formats

| build | formats |
|---|---|
| default | wav: 8/16/24/32-bit PCM integer + 32-bit IEEE float, mono (expanded to stereo) or stereo (extra channels dropped), any sample rate. `RaopSender` resamples to 44.1 kHz internally. |
| `-DENABLE_MINIAUDIO=ON` | all of the above, plus mp3, flac, ogg/vorbis, opus |

the decode path is a fallback, not a fork: `loadWavAsStereo16` always runs
first and the miniaudio reader (`loadWithMiniAudio`) only gets asked when the
wav reader says "not a RIFF/WAVE file", so wav files decode identically in
both configs and a misnamed file still plays if the bytes decode. aac is not
covered (miniaudio's built-in decoders don't include it). when built with the
flag the usage text says `<file>` instead of `<file.wav>`, for the obvious
reason.

this is a demo, not a general media tool: the whole file is loaded into memory
upfront, there's no playlist/queue, and errors are reported to stderr and a
non-zero exit code rather than retried.

## if you're reading the code, not just running it

`airplay_send.cpp`'s `main()` is short on purpose, discover → resolve →
`RaopSender::setAuth`/`start()` → a feed loop that tops up a `RingBuffer` from
the loaded audio → `stop()`. Everything it needs from the library is:

```cpp
fxchain::PosixTransport io;
fxchain::RaopSender sender(io);
sender.attachRing(&ring);
sender.setInputFormat(audio.sampleRate);
sender.setAuth(device.auth, device.airplay2, device.deviceId, cachedCreds, password);
sender.start(device.host, device.port, device.name);
while (running) io.poll(16);
```

the load step sits in front: `loadWavAsStereo16(path)` returns an `AudioData`
(`example/audio_data.h`, interleaved stereo int16 + native sample rate); with
the miniaudio build a failing wav load falls through to
`loadWithMiniAudio(path)`, which returns the same `AudioData`.

`../src/raop_sender.h` + the top-level README's **recipe** section are the map
for the protocol itself; this directory is just the last mile of wiring.
