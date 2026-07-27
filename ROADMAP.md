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
  is now the tiny pluggable `Log` sink m2 asked for (see below), so both m2 boxes
  it depended on are already checked off; what's left of m2 is just mDNS. Builds
  as a CMake target (`raop_sender`) and has been run end-to-end against a fake
  RTSP/RAOP receiver (full OPTIONS → ANNOUNCE → SETUP → RECORD → streaming
  handshake, correct packet sizes/marker bits), a real device is still the
  better test, that's what m3's CLI demo is for.

## the path to standalone

three milestones, in order. **m1 is done**; m2 is cleanup; m3 is the payoff.

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

### m2: drop the host glue

- ~~`mdns_discovery.h` is only there for the `RaopDeviceInfo::Auth` enum~~, done
  as part of m1 (folded in as `RaopSender::Auth`, since the enum has nothing to
  do with discovery and the header didn't exist in this repo to begin with).
  What's left: ship a tiny mDNS browser for receiver discovery (or let the
  caller pass an already-resolved host + the `sf` flags, which `RaopSender`
  already accepts today).
- ~~`common/logger.h` becomes a one-line `std::function<void(level, msg)>`
  sink~~, done as part of m1 (`src/logger.h`), same shape this line asked for.
- `common/ring_buffer.h` is already self-contained (it lives in `src/`).

### m3: the demo

`airplay-send <host> <file.wav>`: pair, set up, stream a wav, ctrl-c to stop. the
thing you actually clone and run to prove it on your own couch in 30 seconds.
`raop_sender` + `PosixTransport` are both ready for this now, it's wiring +
a wav reader + an mDNS lookup (or a `--host` flag to skip discovery entirely).

## later / maybe

- buffered stream (type 103, TCP) alongside realtime (type 96, UDP).
- AAC / Opus on receivers that advertise it (realtime is hardcoded-ALAC).
- multi-room / grouped output.
- IPv6 in the default transport (the interface doesn't care; `PosixTransport`
  currently only binds/sends IPv4).

## want to help?

**m3 is the one that matters now.** `raop_sender` and `PosixTransport` both
build and run; the highest-leverage PR left is the CLI demo (or an mDNS browser
for m2). open an issue and let's talk.
