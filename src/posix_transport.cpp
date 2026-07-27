// SPDX-License-Identifier: Apache-2.0
//
// posix_transport.cpp -- see posix_transport.h for the shape/scope notes.

#include "posix_transport.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace fxchain {

namespace {

void setNonBlocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Stringify whatever family a sockaddr happens to be (IPv4 or IPv6).
std::string ntop(const sockaddr* sa) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (sa->sa_family == AF_INET) {
        const auto* a = reinterpret_cast<const sockaddr_in*>(sa);
        ::inet_ntop(AF_INET, &a->sin_addr, buf, sizeof(buf));
    } else if (sa->sa_family == AF_INET6) {
        const auto* a = reinterpret_cast<const sockaddr_in6*>(sa);
        ::inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof(buf));
    }
    return buf;
}

uint16_t portOf(const sockaddr* sa) {
    if (sa->sa_family == AF_INET)
        return ntohs(reinterpret_cast<const sockaddr_in*>(sa)->sin_port);
    if (sa->sa_family == AF_INET6)
        return ntohs(reinterpret_cast<const sockaddr_in6*>(sa)->sin6_port);
    return 0;
}

}  // namespace

PosixTransport::PosixTransport() = default;

PosixTransport::~PosixTransport() {
    for (auto& [h, s] : sockets_) closeFd_(s);
}

void PosixTransport::closeFd_(Socket& s) {
    if (s.fd >= 0) { ::close(s.fd); s.fd = -1; }
}

ITransport::Handle PosixTransport::tcpConnect(const std::string& host, uint16_t port,
                                              ConnectFn onConnected, DataFn onData,
                                              ClosedFn onClosed) {
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string portStr = std::to_string(port);
    if (::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res)
        return kInvalid;

    int fd = -1;
    addrinfo* used = nullptr;
    for (addrinfo* p = res; p; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd >= 0) { used = p; break; }
    }
    if (fd < 0) { ::freeaddrinfo(res); return kInvalid; }

    setNonBlocking(fd);
    const int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    const int rc = ::connect(fd, used->ai_addr, used->ai_addrlen);
    ::freeaddrinfo(res);
    if (rc < 0 && errno != EINPROGRESS) { ::close(fd); return kInvalid; }

    Socket s;
    s.fd = fd;
    s.isUdp = false;
    // Always defer the "connected" callback to poll(): even a synchronous
    // rc==0 (e.g. connecting to localhost) is picked up next poll() cycle
    // via the normal POLLOUT check below, so RaopSender never sees
    // onConnected() fire before tcpConnect() has returned its handle.
    s.connecting = true;
    s.onData = std::move(onData);
    s.onConnected = std::move(onConnected);
    s.onClosed = std::move(onClosed);
    const Handle h = nextHandle_++;
    sockets_.emplace(h, std::move(s));
    return h;
}

ITransport::Handle PosixTransport::udpBind(uint16_t port, DataFn onData) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return kInvalid;
    setNonBlocking(fd);
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return kInvalid;
    }
    Socket s;
    s.fd = fd;
    s.isUdp = true;
    s.onData = std::move(onData);
    const Handle h = nextHandle_++;
    sockets_.emplace(h, std::move(s));
    return h;
}

uint16_t PosixTransport::localPort(Handle h) const {
    const auto it = sockets_.find(h);
    if (it == sockets_.end()) return 0;
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (::getsockname(it->second.fd, reinterpret_cast<sockaddr*>(&ss), &len) < 0)
        return 0;
    return portOf(reinterpret_cast<sockaddr*>(&ss));
}

std::string PosixTransport::localAddress(Handle h) const {
    const auto it = sockets_.find(h);
    if (it == sockets_.end()) return {};
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (::getsockname(it->second.fd, reinterpret_cast<sockaddr*>(&ss), &len) < 0)
        return {};
    return ntop(reinterpret_cast<sockaddr*>(&ss));
}

std::string PosixTransport::peerAddress(Handle h) const {
    const auto it = sockets_.find(h);
    if (it == sockets_.end()) return {};
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (::getpeername(it->second.fd, reinterpret_cast<sockaddr*>(&ss), &len) < 0)
        return {};
    return ntop(reinterpret_cast<sockaddr*>(&ss));
}

bool PosixTransport::send(Handle h, const uint8_t* data, size_t len) {
    const auto it = sockets_.find(h);
    if (it == sockets_.end() || it->second.fd < 0) return false;
    const int fd = it->second.fd;
    size_t off = 0;
    while (off < len) {
        const ssize_t n = ::send(fd, data + off, len - off,
#ifdef MSG_NOSIGNAL
                                 MSG_NOSIGNAL
#else
                                 0
#endif
        );
        if (n > 0) { off += size_t(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // The kernel's send buffer is momentarily full (e.g. a large
            // SET_PARAMETER cover-art write). Wait for room; a receiver-side
            // stall of several seconds shouldn't be treated as a hard error.
            pollfd pfd{fd, POLLOUT, 0};
            const int pr = ::poll(&pfd, 1, 3000);
            if (pr > 0 && (pfd.revents & POLLOUT)) continue;
            return false;
        }
        return false;   // real error / peer gone
    }
    return true;
}

bool PosixTransport::sendTo(Handle h, const std::string& host, uint16_t port,
                            const uint8_t* data, size_t len) {
    const auto it = sockets_.find(h);
    if (it == sockets_.end() || it->second.fd < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
        return false;   // the default adapter is IPv4-only, see the header note
    const ssize_t n = ::sendto(it->second.fd, data, len, 0,
                               reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    return n == static_cast<ssize_t>(len);
}

void PosixTransport::close(Handle h) {
    const auto it = sockets_.find(h);
    if (it == sockets_.end()) return;
    closeFd_(it->second);
    sockets_.erase(it);
}

int PosixTransport::every(int ms, TimerFn fn) {
    Timer t;
    t.due = std::chrono::steady_clock::now() + std::chrono::milliseconds(std::max(1, ms));
    t.intervalMs = std::max(1, ms);
    t.fn = std::move(fn);
    const int id = nextTimerId_++;
    timers_.emplace(id, std::move(t));
    return id;
}

int PosixTransport::after(int ms, TimerFn fn) {
    Timer t;
    t.due = std::chrono::steady_clock::now() + std::chrono::milliseconds(std::max(0, ms));
    t.intervalMs = 0;
    t.fn = std::move(fn);
    const int id = nextTimerId_++;
    timers_.emplace(id, std::move(t));
    return id;
}

void PosixTransport::cancel(int timerId) {
    timers_.erase(timerId);
}

void PosixTransport::handleConnectResult_(Handle h, Socket& s) {
    int err = 0;
    socklen_t elen = sizeof(err);
    ::getsockopt(s.fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    s.connecting = false;
    if (err == 0) {
        if (s.onConnected) s.onConnected();
    } else {
        ClosedFn onClosed = std::move(s.onClosed);
        closeFd_(s);
        sockets_.erase(h);
        if (onClosed) onClosed(std::strerror(err));
    }
}

void PosixTransport::handleReadableTcp_(Handle h, Socket& s) {
    std::string buf;
    uint8_t chunk[65536];
    bool closed = false;
    std::string closeReason;
    for (;;) {
        const ssize_t n = ::recv(s.fd, chunk, sizeof(chunk), 0);
        if (n > 0) { buf.append(reinterpret_cast<const char*>(chunk), size_t(n)); continue; }
        if (n == 0) { closed = true; break; }                       // peer closed
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;         // nothing more right now
        closed = true; closeReason = std::strerror(errno); break;   // real error
    }
    if (!buf.empty() && s.onData)
        s.onData(reinterpret_cast<const uint8_t*>(buf.data()), buf.size(), "", 0);
    if (closed) {
        ClosedFn onClosed = std::move(s.onClosed);
        closeFd_(s);
        sockets_.erase(h);
        if (onClosed) onClosed(closeReason);
    }
}

void PosixTransport::handleReadableUdp_(Handle h, Socket& s) {
    uint8_t buf[65536];
    for (;;) {
        sockaddr_in from{};
        socklen_t fromLen = sizeof(from);
        const ssize_t n = ::recvfrom(s.fd, buf, sizeof(buf), 0,
                                     reinterpret_cast<sockaddr*>(&from), &fromLen);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;   // EAGAIN or a transient error: nothing more right now
        }
        if (s.onData)
            s.onData(buf, size_t(n), ntop(reinterpret_cast<sockaddr*>(&from)),
                     ntohs(from.sin_port));
        (void)h;
    }
}

void PosixTransport::poll(int timeoutMs) {
    // Clamp the wait to whatever timer is due soonest, so a caller doing
    // `while (running) transport.poll(1000);` still gets ~8 ms pacer ticks.
    int effectiveTimeout = timeoutMs;
    const auto now = std::chrono::steady_clock::now();
    for (const auto& [id, t] : timers_) {
        const auto msUntil = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  t.due - now).count();
        const int clamped = int(std::max<long long>(0, msUntil));
        effectiveTimeout = std::min(effectiveTimeout, clamped);
    }
    effectiveTimeout = std::max(0, effectiveTimeout);

    if (!sockets_.empty()) {
        std::vector<pollfd> pfds;
        std::vector<Handle>  handles;
        pfds.reserve(sockets_.size());
        handles.reserve(sockets_.size());
        for (const auto& [h, s] : sockets_) {
            pollfd pfd{};
            pfd.fd = s.fd;
            pfd.events = s.connecting ? (POLLOUT | POLLERR) : POLLIN;
            pfds.push_back(pfd);
            handles.push_back(h);
        }
        ::poll(pfds.data(), pfds.size(), effectiveTimeout);

        // Snapshot which handles fired before dispatching: a callback firing
        // for handle N may close/erase handle M later in this same list.
        for (size_t i = 0; i < pfds.size(); ++i) {
            if (pfds[i].revents == 0) continue;
            const Handle h = handles[i];
            const auto it = sockets_.find(h);
            if (it == sockets_.end()) continue;   // already closed by an earlier callback this cycle
            if (it->second.connecting) {
                if (pfds[i].revents & (POLLOUT | POLLERR | POLLHUP))
                    handleConnectResult_(h, it->second);
            } else if (pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                if (it->second.isUdp) handleReadableUdp_(h, it->second);
                else                  handleReadableTcp_(h, it->second);
            }
        }
    } else if (effectiveTimeout > 0) {
        // No sockets yet (e.g. between sessions) but a timer is armed --
        // poll(2) with no fds is a portable sleep.
        ::poll(nullptr, 0, effectiveTimeout);
    }

    // Fire due timers. Reschedule/erase BEFORE calling fn() so a callback
    // that re-enters every()/after()/cancel() (RaopSender's restart-on-tick
    // pattern) sees consistent bookkeeping, not a stale iterator.
    const auto now2 = std::chrono::steady_clock::now();
    std::vector<int> due;
    for (const auto& [id, t] : timers_)
        if (t.due <= now2) due.push_back(id);
    for (int id : due) {
        const auto it = timers_.find(id);
        if (it == timers_.end()) continue;   // cancelled earlier in this same batch
        TimerFn fn = it->second.fn;
        if (it->second.intervalMs > 0)
            it->second.due = now2 + std::chrono::milliseconds(it->second.intervalMs);
        else
            timers_.erase(it);
        if (fn) fn();
    }
}

} // namespace fxchain
