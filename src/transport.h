// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// transport.h -- the Qt-free network + timer abstraction raop_sender talks to.
// ----------------------------------------------------------------------------
// ROADMAP.md m1 in one sentence: `raop_sender` used to reach into `QTcpSocket`
// / `QUdpSocket` / `QTimer` directly; now it only ever touches `ITransport`, and
// the Qt build collapses to a small adapter someone can write against Qt if
// they want to (nobody has to -- `PosixTransport`, in posix_transport.h, is the
// default, and it's plain BSD sockets + `poll(2)`).
//
// shape: everything is callback-driven (like asio / libuv, which the ROADMAP
// explicitly welcomes as alternate adapters), because that's the only shape
// that maps cleanly onto BOTH "a Qt event loop" and "a bare poll/select loop"
// without RaopSender knowing which one it's talking to. a `Handle` is an
// opaque per-socket id; TCP and UDP share the same handle type but not the
// same methods (send() is TCP, sendTo() is UDP -- calling the wrong one on a
// handle is a caller bug, not a runtime case worth modelling).
//
// the whole host integration is: construct one transport, construct
// `RaopSender(transport)`, then pump it --
//
//     PosixTransport io;
//     RaopSender sender(io);
//     while (running) io.poll(16);     // <- this line IS the event loop
//
// -- everything else (connect, read, write, the ~16 ms pacer, the 25 s
// keep-alive) happens inside RaopSender via the callbacks below.
//
// scope, honestly: the default adapter (posix_transport.*) is IPv4-only and
// single-threaded/non-reentrant, which covers every AirPlay receiver you'll
// meet on a home LAN. IPv6 / TLS-grade backends are exactly the kind of
// alternate adapter ROADMAP.md is asking for, not a gap in this interface.

#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>

namespace fxchain {

class ITransport {
public:
    using Handle = int;
    static constexpr Handle kInvalid = -1;

    // Fired once per successful read: `len` raw bytes. For a udpBind()
    // handle, `fromHost`/`fromPort` name the sender of that one datagram;
    // for a tcpConnect() handle they're always empty/0 (the peer is fixed).
    using DataFn = std::function<void(const uint8_t* data, size_t len,
                                       const std::string& fromHost,
                                       uint16_t fromPort)>;
    // TCP connect completed (the socket is writable / usable now).
    using ConnectFn = std::function<void()>;
    // TCP connection ended -- peer close, a connect()/read()/write() error,
    // or (indirectly) a timeout. `reason` is a short human string for logs,
    // empty for a plain graceful close. The handle is dead after this fires;
    // don't call close() on it too.
    using ClosedFn = std::function<void(const std::string& reason)>;
    using TimerFn  = std::function<void()>;

    virtual ~ITransport() = default;

    // Begin a TCP connection to host:port (host may be a literal IPv4/IPv6
    // address or a hostname; DNS, if needed, happens synchronously inside
    // this call). Returns kInvalid immediately on a synchronous failure
    // (bad address, out of sockets, ...) with no callback fired; otherwise
    // returns a live handle and exactly one of onConnected() / onClosed()
    // fires later from poll().
    virtual Handle tcpConnect(const std::string& host, uint16_t port,
                               ConnectFn onConnected, DataFn onData,
                               ClosedFn onClosed) = 0;

    // Bind a local UDP socket (ephemeral port if `port` == 0) that can both
    // sendTo() any destination and receive from anyone (onData per
    // datagram). Returns kInvalid on a synchronous bind failure.
    virtual Handle udpBind(uint16_t port, DataFn onData) = 0;

    // The local port/address bound for `h` -- needed to advertise our
    // control/timing ports in SETUP and to build the `rtsp://<ip>/<id>` URI
    // and SDP `o=`/`c=` lines. peerAddress() is TCP-only.
    virtual uint16_t    localPort(Handle h) const = 0;
    virtual std::string localAddress(Handle h) const = 0;
    virtual std::string peerAddress(Handle h) const = 0;

    // TCP stream write. Blocks (internally, via a bounded poll-for-writable
    // loop) until every byte is handed to the OS or a hard error/timeout
    // occurs; there is no separate flush() because there's no userspace
    // write queue to flush -- unlike QTcpSocket, bytes are in the kernel's
    // socket buffer by the time this returns true.
    virtual bool send(Handle h, const uint8_t* data, size_t len) = 0;

    // UDP: one datagram to an arbitrary destination.
    virtual bool sendTo(Handle h, const std::string& host, uint16_t port,
                        const uint8_t* data, size_t len) = 0;

    // Tear the socket down now (no linger, no goodbye packet beyond
    // whatever the last send() already delivered). Safe to call on a handle
    // whose onClosed already fired (a no-op then).
    virtual void close(Handle h) = 0;

    // Recurring timer (fires every `ms`, best-effort, from inside poll()).
    // Returns an id for cancel().
    virtual int every(int ms, TimerFn fn) = 0;
    // One-shot timer (fires once, ~`ms` from now, then forgets itself).
    virtual int after(int ms, TimerFn fn) = 0;
    // Cancel an every()/after() timer. A no-op on an id that already fired
    // (one-shot) or was already cancelled.
    virtual void cancel(int timerId) = 0;

    // Pump: wait up to `timeoutMs` (less if a timer is due sooner) for
    // socket I/O, dispatch whatever fired (connects, data, closes, timers),
    // then return. The host's entire main loop is a call to this in a
    // `while (running)` loop -- see the file header.
    virtual void poll(int timeoutMs) = 0;
};

} // namespace fxchain
