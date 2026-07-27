// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// posix_transport.h -- the default ITransport: plain BSD sockets + poll(2).
// ----------------------------------------------------------------------------
// this is the "portable poll/select adapter" ROADMAP.md m1 promises ships as
// the default. it targets Linux/macOS/BSD (anything with <poll.h> + a normal
// sockets API) and IPv4 destinations, which is every AirPlay receiver you'll
// meet on a home LAN. no Qt, no third-party dependency, ~250 lines.
//
// single-threaded, non-reentrant: construct one, call poll() from one thread,
// and don't call back into it from inside a callback it's currently firing
// EXCEPT the operations RaopSender actually relies on (send/sendTo/close/
// every/after/cancel from inside a callback are all fine -- that's the whole
// point of a re-entrant-safe pump loop, and this one is).

#include "transport.h"

#include <chrono>
#include <unordered_map>

namespace fxchain {

class PosixTransport final : public ITransport {
public:
    PosixTransport();
    ~PosixTransport() override;
    PosixTransport(const PosixTransport&) = delete;
    PosixTransport& operator=(const PosixTransport&) = delete;

    Handle tcpConnect(const std::string& host, uint16_t port,
                       ConnectFn onConnected, DataFn onData,
                       ClosedFn onClosed) override;
    Handle udpBind(uint16_t port, DataFn onData) override;

    uint16_t    localPort(Handle h) const override;
    std::string localAddress(Handle h) const override;
    std::string peerAddress(Handle h) const override;

    bool send(Handle h, const uint8_t* data, size_t len) override;
    bool sendTo(Handle h, const std::string& host, uint16_t port,
               const uint8_t* data, size_t len) override;

    void close(Handle h) override;

    int  every(int ms, TimerFn fn) override;
    int  after(int ms, TimerFn fn) override;
    void cancel(int timerId) override;

    void poll(int timeoutMs) override;

private:
    struct Socket {
        int  fd = -1;
        bool isUdp     = false;
        bool connecting = false;   // TCP only: connect() is in flight
        DataFn    onData;
        ConnectFn onConnected;
        ClosedFn  onClosed;
    };
    struct Timer {
        std::chrono::steady_clock::time_point due;
        int      intervalMs = 0;   // 0 = one-shot
        TimerFn  fn;
    };

    void closeFd_(Socket& s);
    void handleReadableTcp_(Handle h, Socket& s);
    void handleReadableUdp_(Handle h, Socket& s);
    void handleConnectResult_(Handle h, Socket& s);

    std::unordered_map<Handle, Socket> sockets_;
    Handle nextHandle_ = 1;

    std::unordered_map<int, Timer> timers_;
    int nextTimerId_ = 1;
};

} // namespace fxchain
