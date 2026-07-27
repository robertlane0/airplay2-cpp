// SPDX-License-Identifier: Apache-2.0
//
// mdns_discovery.cpp -- mDNS/DNS-SD browser for RAOP/AirPlay receivers.
// ----------------------------------------------------------------------------

#include "mdns_discovery.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

#if defined(__APPLE__)
    #include <dns_sd.h>
#elif defined(__linux__) || defined(__FreeBSD__)
    #include <avahi-client/client.h>
    #include <avahi-client/lookup.h>
    #include <avahi-common/error.h>
    #include <avahi-common/simple-watch.h>
#else
    #warning "mDNS discovery not implemented on this platform"
#endif

namespace fxchain {

// ── Auth derivation (TXT flags → RaopSender::Auth) ────────────────────────
// Feature flag bits from pyatv/owntone (sf field):
//   0x40 = supports AirPlay 2
//   0x80 = requires authentication (am field refines this)
// am field values:
//   0 or missing = no auth
//   1 = MFiSAP (auth-setup)
//   2 = HAP transient (fixed PIN 3939)
//   3 = HAP PIN (on-screen)
//   4 = legacy SRP (not implemented)
//   pw=true in TXT = RTSP digest password
RaopDeviceInfo::Auth RaopDiscovery::deriveAuth_(uint32_t features,
                                                const std::string& authMode,
                                                const std::string& model) {
    // Check for password-based auth first (explicit in TXT)
    if (features & 0x10000) {  // pw=true flag (varies by implementation)
        return RaopDeviceInfo::Auth::Password;
    }

    // AirPlay 2 devices use the `am` field
    if (!authMode.empty()) {
        int am = std::stoi(authMode);
        switch (am) {
            case 1: return RaopDeviceInfo::Auth::AuthSetup;
            case 2: return RaopDeviceInfo::Auth::HapTransient;
            case 3: return RaopDeviceInfo::Auth::HapPin;
            case 4: return RaopDeviceInfo::Auth::LegacyPin;
            default: break;
        }
    }

    // Legacy feature-flag based detection
    if (features & 0x80) {
        // Requires auth but no am field - check model for hints
        if (model.find("AppleTV") != std::string::npos) {
            return RaopDeviceInfo::Auth::HapPin;  // Apple TV usually needs PIN
        }
        return RaopDeviceInfo::Auth::LegacyPin;
    }

    return RaopDeviceInfo::Auth::None;
}

// ── Platform-specific implementations ─────────────────────────────────────

#if defined(__APPLE__)
// ════════════════════════════════════════════════════════════════════════════
// macOS Implementation using DNSServiceBrowse
// ════════════════════════════════════════════════════════════════════════════

struct RaopDiscovery::Impl {
    DNSServiceRef browseRef = nullptr;
    std::set<std::string> seenInstances;
    std::vector<RaopDeviceInfo> devices;
    std::mutex devicesMutex;
    RaopDiscovery* parent = nullptr;

    static void DNSSD_API handleBrowse(DNSServiceRef sdRef,
                                       DNSServiceFlags flags,
                                       uint32_t interfaceIndex,
                                       DNSServiceErrorType errorCode,
                                       const char* serviceName,
                                       const char* regtype,
                                       const char* replyDomain,
                                       void* context) {
        auto* self = static_cast<Impl*>(context);
        if (errorCode != kDNSServiceErr_NoError) {
            return;
        }

        if (flags & kDNSServiceFlagsAdd) {
            // Resolve the service to get host and port
            DNSServiceRef resolveRef = nullptr;
            DNSServiceResolve(&resolveRef, 0, interfaceIndex, serviceName,
                            regtype, replyDomain,
                            [](DNNSServiceRef sdRef, DNSServiceFlags flags,
                               uint32_t interfaceIndex,
                               DNSServiceErrorType errorCode,
                               const char* fullname,
                               const char* hosttarget,
                               uint16_t port,
                               uint16_t txtLen,
                               const unsigned char* txtRecord,
                               void* context) {
                                if (errorCode != kDNSServiceErr_NoError) {
                                    DNSServiceRefDeallocate(sdRef);
                                    return;
                                }

                                auto* self = static_cast<Impl*>(context);
                                RaopDeviceInfo info;
                                info.instance = serviceName;
                                
                                // Extract name from instance (remove @ suffix)
                                std::string fullName(serviceName);
                                auto atPos = fullName.rfind('@');
                                if (atPos != std::string::npos && atPos > 0) {
                                    info.name = fullName.substr(0, atPos - 1);
                                } else {
                                    info.name = fullName;
                                }

                                info.port = ntohs(port);
                                info.host = hosttarget;

                                // Parse TXT record
                                parseTxtRecord(txtRecord, txtLen, info);

                                // Deduplicate
                                {
                                    std::lock_guard<std::mutex> lock(self->devicesMutex);
                                    if (self->seenInstances.find(info.instance) == self->seenInstances.end()) {
                                        self->seenInstances.insert(info.instance);
                                        self->devices.push_back(info);
                                        if (self->parent && self->parent->onDeviceFound) {
                                            self->parent->onDeviceFound(info);
                                        }
                                    }
                                }

                                DNSServiceRefDeallocate(sdRef);
                            }, self);
        } else {
            // Service removed
            std::string instance(serviceName);
            {
                std::lock_guard<std::mutex> lock(self->devicesMutex);
                self->seenInstances.erase(instance);
                self->devices.erase(
                    std::remove_if(self->devices.begin(), self->devices.end(),
                                   [&instance](const RaopDeviceInfo& d) {
                                       return d.instance == instance;
                                   }),
                    self->devices.end());
            }
            if (self->parent && self->parent->onDeviceLost) {
                self->parent->onDeviceLost(instance);
            }
        }
    }

    static void parseTxtRecord(const unsigned char* txt, uint16_t len,
                              RaopDeviceInfo& info) {
        std::map<std::string, std::string> txtMap;
        size_t pos = 0;
        while (pos < len) {
            uint8_t itemLen = txt[pos++];
            if (pos + itemLen > len) break;
            
            std::string item(reinterpret_cast<const char*>(&txt[pos]), itemLen);
            pos += itemLen;

            auto eqPos = item.find('=');
            if (eqPos != std::string::npos) {
                std::string key = item.substr(0, eqPos);
                std::string value = item.substr(eqPos + 1);
                txtMap[key] = value;
            }
        }

        // Extract relevant fields
        if (auto it = txtMap.find("sf"); it != txtMap.end()) {
            info.features = static_cast<uint32_t>(std::stoul(it->second));
        }
        if (auto it = txtMap.find("am"); it != txtMap.end()) {
            info.airplayVersion = (it->second == "2") ? 2 : 1;
        }
        if (auto it = txtMap.find("did"); it != txtMap.end()) {
            info.deviceId = it->second;
        }
        if (auto it = txtMap.find("model"); it != txtMap.end()) {
            info.model = it->second;
        }
        if (auto it = txtMap.find("mac"); it != txtMap.end()) {
            info.macAddress = it->second;
        }

        info.auth = RaopDiscovery::deriveAuth_(info.features,
                                               txtMap.count("am") ? txtMap["am"] : "",
                                               info.model);
    }
};

RaopDiscovery::RaopDiscovery() : impl_(new Impl()) {
    impl_->parent = this;
}

RaopDiscovery::~RaopDiscovery() {
    stop();
    delete impl_;
}

void RaopDiscovery::start() {
    if (running_) return;
    
    DNSServiceErrorType err = DNSServiceBrowse(&impl_->browseRef, 0, 0,
                                               "_raop._tcp", nullptr,
                                               Impl::handleBrowse, impl_);
    if (err == kDNSServiceErr_NoError) {
        running_ = true;
    }
}

void RaopDiscovery::stop() {
    if (!running_) return;
    
    if (impl_->browseRef) {
        DNSServiceRefDeallocate(impl_->browseRef);
        impl_->browseRef = nullptr;
    }
    running_ = false;
}

std::vector<RaopDeviceInfo> RaopDiscovery::discover(int timeoutMs) {
    std::vector<RaopDeviceInfo> results;
    std::mutex mutex;
    std::condition_variable cv;
    bool done = false;

    RaopDiscovery browser;
    browser.onDeviceFound = [&](const RaopDeviceInfo& info) {
        std::lock_guard<std::mutex> lock(mutex);
        results.push_back(info);
    };
    browser.start();

    std::this_thread::sleep_for(std::chrono::milliseconds(timeoutMs));
    browser.stop();

    return results;
}

#elif defined(__linux__) || defined(__FreeBSD__)
// ════════════════════════════════════════════════════════════════════════════
// Linux/BSD Implementation using Avahi
// ════════════════════════════════════════════════════════════════════════════

struct RaopDiscovery::Impl {
    AvahiSimplePoll* poll = nullptr;
    AvahiClient* client = nullptr;
    AvahiServiceBrowser* browser = nullptr;
    std::set<std::string> seenInstances;
    std::vector<RaopDeviceInfo> devices;
    std::mutex devicesMutex;
    RaopDiscovery* parent = nullptr;
    bool browseFailed = false;

    static void serviceCallback(AvahiServiceBrowser* b,
                                AvahiIfIndex interface,
                                AvahiProtocol protocol,
                                AvahiBrowserEvent event,
                                const char* name,
                                const char* type,
                                const char* domain,
                                AvahiLookupResultFlags flags,
                                void* userdata) {
        auto* self = static_cast<Impl*>(userdata);

        if (event == AVAHI_BROWSER_FAILURE) {
            self->browseFailed = true;
            return;
        }

        if (event == AVAHI_BROWSER_NEW) {
            // Resolve service
            avahi_service_resolver_new(self->client, interface, protocol,
                                       name, type, domain, AVAHI_PROTO_INET,
                                       (AvahiLookupFlags)0,
                                       [](AvahiServiceResolver* r,
                                          AvahiIfIndex interface,
                                          AvahiProtocol protocol,
                                          AvahiResolverEvent event,
                                          const char* name,
                                          const char* type,
                                          const char* domain,
                                          const char* host,
                                          const AvahiAddress* address,
                                          uint16_t port,
                                          AvahiStringList* txt,
                                          AvahiLookupResultFlags flags,
                                          void* userdata) {
                                           if (event == AVAHI_RESOLVER_FOUND) {
                                               auto* self = static_cast<Impl*>(userdata);
                                               RaopDeviceInfo info;
                                               info.instance = name;

                                               // Extract name from instance
                                               std::string fullName(name);
                                               auto atPos = fullName.rfind('@');
                                               if (atPos != std::string::npos && atPos > 0) {
                                                   info.name = fullName.substr(0, atPos - 1);
                                               } else {
                                                   info.name = fullName;
                                               }

                                               info.port = port;
                                               
                                               char hostStr[AVAHI_ADDRESS_STR_MAX];
                                               avahi_address_snprint(hostStr, sizeof(hostStr), address);
                                               info.host = hostStr;

                                               // Parse TXT record
                                               parseTxtRecord(txt, info);

                                               // Deduplicate
                                               {
                                                   std::lock_guard<std::mutex> lock(self->devicesMutex);
                                                   if (self->seenInstances.find(info.instance) == self->seenInstances.end()) {
                                                       self->seenInstances.insert(info.instance);
                                                       self->devices.push_back(info);
                                                       if (self->parent && self->parent->onDeviceFound) {
                                                           self->parent->onDeviceFound(info);
                                                       }
                                                   }
                                               }
                                           }
                                           avahi_service_resolver_free(r);
                                       }, self);
        } else if (event == AVAHI_BROWSER_REMOVE) {
            std::string instance(name);
            {
                std::lock_guard<std::mutex> lock(self->devicesMutex);
                self->seenInstances.erase(instance);
                self->devices.erase(
                    std::remove_if(self->devices.begin(), self->devices.end(),
                                   [&instance](const RaopDeviceInfo& d) {
                                       return d.instance == instance;
                                   }),
                    self->devices.end());
            }
            if (self->parent && self->parent->onDeviceLost) {
                self->parent->onDeviceLost(instance);
            }
        }
    }

    static void parseTxtRecord(AvahiStringList* txt, RaopDeviceInfo& info) {
        std::map<std::string, std::string> txtMap;
        
        while (txt) {
            char* str = reinterpret_cast<char*>(txt->text);
            std::string item(str);
            
            auto eqPos = item.find('=');
            if (eqPos != std::string::npos) {
                std::string key = item.substr(0, eqPos);
                std::string value = item.substr(eqPos + 1);
                txtMap[key] = value;
            }
            
            txt = txt->next;
        }

        // Extract relevant fields
        if (auto it = txtMap.find("sf"); it != txtMap.end()) {
            info.features = static_cast<uint32_t>(std::stoul(it->second));
        }
        if (auto it = txtMap.find("am"); it != txtMap.end()) {
            info.airplayVersion = (it->second == "2") ? 2 : 1;
        }
        if (auto it = txtMap.find("did"); it != txtMap.end()) {
            info.deviceId = it->second;
        }
        if (auto it = txtMap.find("model"); it != txtMap.end()) {
            info.model = it->second;
        }
        if (auto it = txtMap.find("mac"); it != txtMap.end()) {
            info.macAddress = it->second;
        }

        info.auth = RaopDiscovery::deriveAuth_(info.features,
                                               txtMap.count("am") ? txtMap["am"] : "",
                                               info.model);
    }

    static void clientCallback(AvahiClient* c, AvahiClientState state, void* userdata) {
        auto* self = static_cast<Impl*>(userdata);
        
        if (state == AVAHI_CLIENT_FAILURE) {
            self->browseFailed = true;
            return;
        }

        if (state == AVAHI_CLIENT_S_REGISTERING || 
            state == AVAHI_CLIENT_S_RUNNING ||
            state == AVAHI_CLIENT_CONNECTING) {
            
            if (!self->browser && c) {
                self->browser = avahi_service_browser_new(
                    c, AVAHI_IF_UNSPEC, AVAHI_PROTO_INET,
                    "_raop._tcp", nullptr,
                    (AvahiLookupFlags)0,
                    serviceCallback, self);
                
                if (!self->browser) {
                    self->browseFailed = true;
                }
            }
        }
    }
};

RaopDiscovery::RaopDiscovery() : impl_(new Impl()) {
    impl_->parent = this;
    impl_->poll = avahi_simple_poll_new();
    if (!impl_->poll) {
        delete impl_;
        impl_ = nullptr;
        return;
    }
    
    int error;
    impl_->client = avahi_client_new(avahi_simple_poll_get(impl_->poll),
                                     (AvahiClientFlags)0,
                                     Impl::clientCallback, impl_, &error);
    if (!impl_->client) {
        avahi_simple_poll_free(impl_->poll);
        delete impl_;
        impl_ = nullptr;
    }
}

RaopDiscovery::~RaopDiscovery() {
    stop();
    if (impl_) {
        if (impl_->client) {
            avahi_client_free(impl_->client);
        }
        if (impl_->poll) {
            avahi_simple_poll_free(impl_->poll);
        }
        delete impl_;
    }
}

void RaopDiscovery::start() {
    if (!impl_ || running_) return;
    running_ = true;
}

void RaopDiscovery::stop() {
    if (!running_ || !impl_) return;
    
    if (impl_->browser) {
        avahi_service_browser_free(impl_->browser);
        impl_->browser = nullptr;
    }
    running_ = false;
}

std::vector<RaopDeviceInfo> RaopDiscovery::discover(int timeoutMs) {
    std::vector<RaopDeviceInfo> results;
    
    RaopDiscovery browser;
    if (!browser.impl_) {
        return results;  // Avahi not available
    }
    
    browser.onDeviceFound = [&](const RaopDeviceInfo& info) {
        results.push_back(info);
    };
    browser.start();

    // Pump the Avahi event loop
    auto endTime = std::chrono::steady_clock::now() + 
                   std::chrono::milliseconds(timeoutMs);
    
    while (std::chrono::steady_clock::now() < endTime && !browser.impl_->browseFailed) {
        int timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - std::chrono::steady_clock::now()).count();
        if (timeout < 0) timeout = 0;
        
        avahi_simple_poll_iterate(browser.impl_->poll, timeout);
    }
    
    browser.stop();
    return results;
}

#else
// ════════════════════════════════════════════════════════════════════════════
// Stub Implementation for unsupported platforms
// ════════════════════════════════════════════════════════════════════════════

struct RaopDiscovery::Impl {};

RaopDiscovery::RaopDiscovery() : impl_(new Impl()) {}
RaopDiscovery::~RaopDiscovery() { delete impl_; }

void RaopDiscovery::start() { running_ = false; }
void RaopDiscovery::stop() { running_ = false; }

std::vector<RaopDeviceInfo> RaopDiscovery::discover(int timeoutMs) {
    // Return empty list on unsupported platforms
    return {};
}

#endif

} // namespace fxchain
