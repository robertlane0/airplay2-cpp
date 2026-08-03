# example: airplay-send

the CLI demo. `raop_sender` + `PosixTransport` + `mdns_browser` + a wav reader
+ a per-device credential cache, wired into one binary. ROADMAP.md m3, done.

## build

```
cmake -B build && cmake --build build --target airplay-send
```

the binary lands at `build/airplay-send`.

## use

```
airplay-send living_room.wav                          # discover, pick a receiver, stream
airplay-send --host 10.0.0.42 song.wav                 # skip picking, target this IP
airplay-send --host 10.0.0.42 --airplay1 song.wav      # legacy RAOP, no HAP pairing
airplay-send --host 10.0.0.42 --password secret song.wav  # pw=true legacy receivers
airplay-send --list                                    # just show what's on the LAN
airplay-send --help                                    # the full flag list
```

zero flags is the intended default: it browses for ~3 s, prefers an AirPlay 2
device if one answered, connects, pairs if it needs to (a HAP on-screen PIN
prompts right there on stdin), streams the file, and tears down cleanly on
ctrl-c or when the file ends. A successful pairing is cached under
`~/.cache/airplay-send/` (or `$XDG_CACHE_HOME`) so the next run against the
same device skips the PIN.

wav support: 8/16/24/32-bit PCM integer and 32-bit IEEE float, mono (expanded
to stereo) or stereo (extra channels dropped), any sample rate, `RaopSender`
resamples to 44.1 kHz internally.

this is a demo, not a general media tool: the whole file is loaded into memory
upfront, there's no playlist/queue, and errors are reported to stderr and a
non-zero exit code rather than retried.

## if you're reading the code, not just running it

`airplay_send.cpp`'s `main()` is short on purpose, discover → resolve →
`RaopSender::setAuth`/`start()` → a feed loop that tops up a `RingBuffer` from
the loaded wav → `stop()`. Everything it needs from the library is:

```cpp
fxchain::PosixTransport io;
fxchain::RaopSender sender(io);
sender.attachRing(&ring);
sender.setInputFormat(wav.sampleRate);
sender.setAuth(device.auth, device.airplay2, device.deviceId, cachedCreds, password);
sender.start(device.host, device.port, device.name);
while (running) io.poll(16);
```

`../src/raop_sender.h` + the top-level README's **recipe** section are the map
for the protocol itself; this directory is just the last mile of wiring.
