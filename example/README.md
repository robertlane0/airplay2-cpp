# example (roadmap)

the `airplay-send <host> <file.wav>` CLI demo lands here once the demo itself
(`../ROADMAP.md` m3) is built.

**m1 (Qt-free sender) is done**, `../src/raop_sender.{h,cpp}` now talks to the
network only through `ITransport` (`../src/transport.h`), with
`../src/posix_transport.{h,cpp}` as the default `poll()`/BSD-sockets adapter.
Both build as CMake targets (`raop_sender`, `posix_transport`) today, no Qt
required. What's missing for this directory to exist for real is just the demo
itself: a wav reader + an mDNS lookup (or a `--host` flag) wired to

```cpp
fxchain::PosixTransport io;
fxchain::RaopSender sender(io);
while (running) io.poll(16);
```

until then, `../src/raop_sender.h` + the **README recipe** are the map. the
crypto core (`../src/airplay_crypto.*`) you can use today: build it with the
top-level `CMakeLists.txt` and link `airplay_crypto`.
