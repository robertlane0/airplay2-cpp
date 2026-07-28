// SPDX-License-Identifier: Apache-2.0
//
// Example: scan for RAOP/AirPlay receivers using mDNS discovery
// ----------------------------------------------------------------------------
// Build: g++ -std=c++20 -I../src mdns_scan.cpp -L../build -lmdns_discovery \
//        $(pkg-config --cflags --libs avahi-client) -lpthread -o mdns_scan
// Run:   ./mdns_scan
//

#include "mdns_discovery.h"
#include <cstdio>
#include <chrono>
#include <thread>

int main() {
    printf("Scanning for RAOP/AirPlay receivers (3 seconds)...\n\n");
    
    // Synchronous scan
    auto devices = fxchain::RaopDiscovery::discover(3000);
    
    if (devices.empty()) {
        printf("No devices found.\n");
        return 0;
    }
    
    printf("Found %zu device(s):\n\n", devices.size());
    
    for (const auto& d : devices) {
        printf("  Instance:     %s\n", d.instance.c_str());
        printf("  Name:         %s\n", d.name.c_str());
        printf("  Host:         %s:%u\n", d.host.c_str(), d.port);
        printf("  Features:     0x%08X\n", d.features);
        printf("  AirPlay Ver:  %u\n", d.airplayVersion);
        
        const char* authStr = "";
        switch (d.auth) {
            case fxchain::RaopDeviceInfo::Auth::None:         authStr = "None"; break;
            case fxchain::RaopDeviceInfo::Auth::AuthSetup:    authStr = "MFiSAP (auth-setup)"; break;
            case fxchain::RaopDeviceInfo::Auth::LegacyPin:    authStr = "Legacy PIN (not implemented)"; break;
            case fxchain::RaopDeviceInfo::Auth::HapTransient: authStr = "HAP Transient (PIN 3939)"; break;
            case fxchain::RaopDeviceInfo::Auth::HapPin:       authStr = "HAP PIN (on-screen)"; break;
            case fxchain::RaopDeviceInfo::Auth::Password:     authStr = "RTSP Password"; break;
        }
        printf("  Auth Method:  %s\n", authStr);
        
        if (!d.deviceId.empty())   printf("  Device ID:    %s\n", d.deviceId.c_str());
        if (!d.model.empty())      printf("  Model:        %s\n", d.model.c_str());
        if (!d.macAddress.empty()) printf("  MAC:          %s\n", d.macAddress.c_str());
        
        printf("\n");
    }
    
    return 0;
}
