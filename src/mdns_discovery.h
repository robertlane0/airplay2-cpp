// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// mdns_discovery.h -- mDNS/DNS-SD browser for RAOP/AirPlay receivers.
// ----------------------------------------------------------------------------
// Discovers AirPlay receivers advertising _raop._tcp or _airplay._tcp services
// on the local network. Provides both synchronous (one-shot scan) and
// asynchronous (continuous browsing) APIs.
//
// PLATFORM SUPPORT:
//   - Linux/BSD: uses avahi-client (libavahi-client-dev)
//   - macOS:     uses DNSServiceBrowse (System.framework / dns_sd.h)
//   - Windows:   not yet implemented (could use Bonjour SDK or wsdd)
//
// USAGE (synchronous):
//   auto devices = RaopDiscovery::discover(2000);  // 2-second scan
//   for (const auto& d : devices) {
//       printf("%s at %s:%u (sf=%u)\n", d.name.c_str(), d.host.c_str(),
//              d.port, d.features);
//   }
//
// USAGE (asynchronous):
//   RaopDiscovery browser;
//   browser.onDeviceFound = [](const RaopDeviceInfo& info) { ... };
//   browser.onDeviceLost  = [](const std::string& instance) { ... };
//   browser.start();
//   // ... pump io.poll() in your main loop ...
//   browser.stop();
//

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace fxchain {

// RaopDeviceInfo carries everything RaopSender::setAuth() + start() need.
// `features` is the raw `sf` flags from the TXT record (see pyatv/ownTone
// for bit definitions); `auth` is derived from those flags + the `am`
// (authentication-mode) TXT field.
struct RaopDeviceInfo {
    std::string instance;    // unique mDNS instance name (e.g. "Living Room @ Apple TV")
    std::string name;        // friendly/service name (e.g. "Living Room")
    std::string host;        // IPv4 address (resolved at discovery time)
    uint16_t port = 0;       // RAOP service port
    uint32_t features = 0;   // raw `sf` flags from TXT record
    uint8_t airplayVersion = 1;  // 1 or 2 (from `am` / feature flags)

    // Auth method required by this receiver (derived from TXT flags).
    // Mirrors RaopSender::Auth so callers can pass it directly to setAuth().
    enum class Auth : uint8_t {
        None,          // plain RAOP/AirPlay 1, no auth at all
        AuthSetup,     // MFiSAP one-shot (AirPort Express gen 2 and similar)
        LegacyPin,     // pre-HomeKit SRP-2048 "Fruit" pairing (not implemented)
        HapTransient,  // HomePod/macOS: fixed-PIN 3939, no UI
        HapPin,        // Apple TV 4+: on-screen PIN (or stored creds)
        Password,      // RTSP digest auth (pw=true receivers)
    } auth = Auth::None;

    // Raw TXT record fields (optional, may be empty). Useful for advanced
    // scenarios (device ID, model, supported codecs, etc.).
    std::string deviceId;    // `did` or `id` field
    std::string model;       // `model` field (e.g. "AppleTV6,2")
    std::string macAddress;  // `mac` field (colon-separated hex)
};

class RaopDiscovery {
public:
    RaopDiscovery();
    ~RaopDiscovery();
    RaopDiscovery(const RaopDiscovery&) = delete;
    RaopDiscovery& operator=(const RaopDiscovery&) = delete;

    // Synchronous one-shot discovery: scan for `timeoutMs` milliseconds and
    // return all discovered devices. Blocks the calling thread.
    static std::vector<RaopDeviceInfo> discover(int timeoutMs = 2000);

    // Asynchronous browsing: start() begins watching for services; stop()
    // ends the session. While running, callbacks fire as devices appear/disappear.
    void start();
    void stop();
    bool isRunning() const { return running_; }

    // Callbacks (fire from the internal poll/loop context, not a background thread).
    std::function<void(const RaopDeviceInfo&)> onDeviceFound;
    std::function<void(const std::string& instance)> onDeviceLost;

private:
    struct Impl;
    Impl* impl_ = nullptr;
    bool running_ = false;

    static RaopDeviceInfo::Auth deriveAuth_(uint32_t features, const std::string& authMode,
                                            const std::string& model);
};

} // namespace fxchain
