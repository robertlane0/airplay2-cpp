// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// mdns_browser.h -- ROADMAP.md m2: the "tiny mDNS browser" for AirPlay/RAOP
// receiver discovery, so a caller doesn't have to already know a device's IP.
// ----------------------------------------------------------------------------
// what this replaces: FXChainPlayer's `mdns_discovery.h` used to own BOTH the
// `RaopDeviceInfo::Auth` enum (folded into `RaopSender::Auth` back in m1) AND
// bonjour/mDNS discovery of receivers. This header is the second half: a
// small, dependency-free (RFC 6762/6763, hand-parsed, no avahi/dns-sd/Bonjour.h
// linkage) multicast-DNS query + response reader, scoped to exactly the two
// service types AirPlay receivers advertise:
//
//   _airplay._tcp.local   modern (AirPlay 2 capable) receivers
//   _raop._tcp.local      legacy RAOP / AirPlay-1-only receivers
//
// and it produces exactly what `RaopSender::start()` + `setAuth()` need: a
// resolved host:port, a stable per-device id (for credential storage), and a
// STARTING GUESS at which `RaopSender::Auth` to try (see mdns_browser.cpp's
// deriveAuth_ for why it's only a guess, and why that's fine).
//
// scope, honestly, same spirit as posix_transport.h:
//  - IPv4 only (A records; no AAAA/IPv6).
//  - resolves a device from ONE incoming UDP packet: it does not re-query for
//    a missing SRV/A record split across multiple responses. Every AirPlay
//    receiver this was tested against (Apple TV 4K, HomePod, macOS, a couple
//    of shairport-sync builds) bundles PTR+SRV+TXT+A as additional records in
//    one response to a PTR query, which is standard modern mDNS-responder
//    practice, so this covers the real world; a receiver that splits its
//    answer across packets won't be seen. A queued-query fallback for that
//    case is a fine follow-up PR.
//  - single-shot query() bursts, not a continuously-refreshed cache. mDNS is
//    soft-state (devices can vanish without saying so); call query() again
//    periodically if you want a live view, same as `dns-sd -B` would need
//    re-running conceptually (dns-sd itself listens continuously, this
//    doesn't try to).
//
// The wire parser treats every byte as untrusted LAN input (bounds-checked
// throughout, including a loop-safe DNS name decompressor), same posture as
// the bplist/TLV8 parsers in airplay_crypto.

#include "raop_sender.h"   // RaopSender::Auth

#include <cstdint>
#include <functional>
#include <map>
#include <string>

namespace fxchain {

// Everything RaopSender::start()/setAuth() need for one receiver, plus the
// raw TXT record for callers who want to make their own auth decision.
struct RaopDeviceInfo {
    std::string name;        // friendly name (the mDNS service instance name)
    std::string host;        // resolved numeric IPv4 address
    uint16_t    port = 0;    // RTSP port (7000 on AP2 receivers, usually 5000 on AP1)
    std::string deviceId;    // TXT "deviceid" (stable; the setAuth() credentials key)
    std::string model;       // TXT "am", e.g. "AppleTV14,1" (empty if absent)
    bool airplay2 = false;   // saw a _airplay._tcp.local answer (vs. _raop._tcp-only)
    // A starting guess for setAuth()'s `auth` parameter; see mdns_browser.cpp
    // deriveAuth_ for exactly what this is (and isn't) based on.
    RaopSender::Auth auth = RaopSender::Auth::None;
    std::map<std::string, std::string> txt;   // the raw TXT record
};

class MdnsBrowser {
public:
    using FoundFn = std::function<void(const RaopDeviceInfo&)>;

    // Opens the mDNS UDP socket (bind :5353, join the 224.0.0.251 multicast
    // group). Throws nothing; check ok() after construction.
    MdnsBrowser();
    ~MdnsBrowser();
    MdnsBrowser(const MdnsBrowser&) = delete;
    MdnsBrowser& operator=(const MdnsBrowser&) = delete;

    bool ok() const { return fd_ >= 0; }

    // Send one PTR query for both `_airplay._tcp.local` and
    // `_raop._tcp.local`. `onFound` fires once per distinct device: on first
    // sight, and again if a device already seen as `_raop._tcp`-only later
    // answers `_airplay._tcp` too (an upgrade to airplay2=true; receivers
    // commonly advertise both, and responses can arrive in either order).
    // Safe to call again later to re-announce / catch late joiners; `onFound`
    // is replaced each call.
    void query(FoundFn onFound);

    // Pump: wait up to timeoutMs for a response and dispatch onFound. Same
    // shape as ITransport::poll(), call this from your own loop, e.g.
    // `for (int i = 0; i < 20; ++i) browser.poll(100);` for a ~2 s browse.
    void poll(int timeoutMs);

private:
    void handlePacket_(const uint8_t* data, size_t len);

    int fd_ = -1;
    FoundFn onFound_;
    // Keyed by friendly name, so a _raop._tcp + _airplay._tcp pair (or a
    // repeated announcement) for the same device dedupes instead of firing
    // onFound_ twice.
    std::map<std::string, RaopDeviceInfo> known_;
};

} // namespace fxchain
