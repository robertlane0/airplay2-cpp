# roadmap

the crypto core already stands on its own. the goal here is to walk the rest of
the sender the last mile: from "lifted out of a working player" to a **drop-in,
Qt-free standalone library** you can `git clone && cmake && run`.

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
  packet sizes/marker bits), a real device is still the better test, that's
  what m3's CLI demo is for.
- **m2: the host glue is dropped.** `src/mdns_browser.{h,cpp}`: a small,
  dependency-free mDNS/DNS-SD browser (RFC 6762/6763, hand-parsed, no
  avahi/dns-sd/Bonjour.h) that finds `_airplay._tcp.local` /
  `_raop._tcp.local` receivers and produces exactly what `RaopSender` needs,
  host, port, a stable device id, and a starting `RaopSender::Auth` guess.
  Builds as a CMake target (`mdns_browser`) and has been run against a
  hand-crafted fake mDNS responder (PTR/SRV/TXT/A with real DNS name
  compression, an `_airplay._tcp` + `_raop._tcp` upgrade-dedup case) and
  ~5000 malformed/adversarial packets under ASan/UBSan with zero crashes.

## the path to standalone

three milestones, in order. **m1 and m2 are done**; m3 is the payoff.

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

### m3: the demo

`airplay-send <host> <file.wav>`: pair, set up, stream a wav, ctrl-c to stop. the
thing you actually clone and run to prove it on your own couch in 30 seconds.
`raop_sender`, `PosixTransport`, and `mdns_browser` are all ready for this
now, it's wiring + a wav reader (`--host` to skip discovery, or browse and
pick the first `_airplay._tcp` device found).

## later / maybe

- buffered stream (type 103, TCP) alongside realtime (type 96, UDP).
- AAC / Opus on receivers that advertise it (realtime is hardcoded-ALAC).
- multi-room / grouped output.
- IPv6 in the default transport (the interface doesn't care; `PosixTransport`
  currently only binds/sends IPv4) and in `mdns_browser` (A records only today).
- a queued-query fallback in `mdns_browser` for a receiver that splits its
  PTR/SRV/TXT/A answer across multiple response packets (none seen in testing
  do this, but it's a real possibility per RFC 6762).

## want to help?

**m3 is the one that matters now.** `raop_sender`, `PosixTransport`, and
`mdns_browser` all build and run; the highest-leverage PR left is the CLI
demo. open an issue and let's talk.
