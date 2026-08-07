// SPDX-License-Identifier: Apache-2.0
//
// airplay_send.cpp -- ROADMAP.md m3: the CLI demo. `raop_sender`,
// `PosixTransport`, and `mdns_browser` are the library; this file is just
// wiring + a wav reader + a credential cache, proving the whole thing on a
// real device in about 30 seconds:
//
//     airplay-send living_room.wav
//     airplay-send --host 10.0.0.42 --airplay1 song.wav
//     airplay-send --list
//
// See `--help` (or just run it) for the full option list. If you're reading
// this file to see how the pieces fit together rather than to use the tool,
// start at main() at the bottom; everything above it is argument parsing and
// small helpers.

#include "creds_store.h"
#include "logger.h"
#include "mdns_browser.h"
#include "posix_transport.h"
#include "raop_sender.h"
#include "ring_buffer.h"
#include "wav_reader.h"
#ifdef WITH_MINIAUDIO
#include "miniaudio_reader.h"
#endif

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using namespace fxchain;

namespace {

// Build-time default for the --headless / --interactive pair, set by the
// CMake HEADLESS_DEFAULT option: 1 = fail immediately when cached
// credentials are stale (never prompt for a PIN), 0 = prompt the user to
// re-pair with a PIN. The runtime flags override it; --version reports it.
#ifndef HEADLESS_DEFAULT
#define HEADLESS_DEFAULT 0
#endif
constexpr bool kHeadlessDefault = HEADLESS_DEFAULT != 0;

volatile std::sig_atomic_t g_stop = 0;
void onSigint(int) { g_stop = 1; }

const char* authName(RaopSender::Auth a) {
    switch (a) {
    case RaopSender::Auth::None:         return "none";
    case RaopSender::Auth::AuthSetup:    return "auth-setup";
    case RaopSender::Auth::LegacyPin:    return "legacy-pin";
    case RaopSender::Auth::HapTransient: return "hap-transient";
    case RaopSender::Auth::HapPin:       return "hap-pin";
    case RaopSender::Auth::Password:     return "password";
    }
    return "?";
}

std::string trimmed(std::string s) {
    const size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// The binary's own name minus any leading path and trailing extension -- the
// default client name, so renaming the executable renames the sender.
std::string executableBaseName(const char* argv0) {
    std::string base = argv0 ? argv0 : "";
    const size_t slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base = base.substr(slash + 1);
    const size_t dot = base.find_last_of('.');
    if (dot != std::string::npos && dot > 0) base = base.substr(0, dot);
    return base.empty() ? "airplay-send" : base;
}

// std::stoi/std::stod throw on anything that isn't a valid number, which
// would otherwise crash the program on a simple typo'd flag value; these
// return false instead so callers can print a clean usage error.
bool parseInt(const std::string& s, int& out) {
    if (s.empty()) return false;
    try {
        size_t consumed = 0;
        const int v = std::stoi(s, &consumed);
        if (consumed != s.size()) return false;
        out = v;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}
bool parseDouble(const std::string& s, double& out) {
    if (s.empty()) return false;
    try {
        size_t consumed = 0;
        const double v = std::stod(s, &consumed);
        if (consumed != s.size()) return false;
        out = v;
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

struct Options {
    std::string host;              // empty = pick a device via mDNS
    uint16_t    port = 0;          // 0 = derive from --airplay1 / discovery
    bool        airplay1 = false;  // force legacy AirPlay 1 (skip HAP)
    std::string password;          // AirPlay 1 pw=true receivers
    std::optional<double> volume;  // percent, applied once streaming starts if specified
    int         browseSeconds = 3;
    bool        noDiscover = false;
    // --headless → true, --interactive → false; last one wins. Absent =
    // build-time HEADLESS_DEFAULT (kHeadlessDefault below).
    std::optional<bool> headlessMode;
    bool        list = false;
    bool        version = false;
    bool        help = false;
    std::string wavPath;
    // Name this sender presents to the receiver (X-Apple-Client-Name). Empty
    // = the executable's own basename (renaming the binary renames it).
    std::string clientName;
};

void printUsage(const char* argv0) {
#ifdef WITH_MINIAUDIO
    const char* fileArg = "<file>";
    const char* fileDesc = "stream an audio file (wav/mp3/flac/ogg/opus) to an AirPlay / RAOP receiver.";
#else
    const char* fileArg = "<file.wav>";
    const char* fileDesc = "stream a .wav file to an AirPlay / RAOP receiver.";
#endif
    std::cout <<
        "usage: " << argv0 << " [options] " << fileArg << "\n"
        "       " << argv0 << " --list\n"
        "\n"
        << fileDesc << "\n"
        "\n"
        "options:\n"
        "  --host <ip>          connect directly to this IP; skips picking a\n"
        "                       device from mDNS discovery (discovery still runs\n"
        "                       first, to fill in the port/auth/deviceId if this\n"
        "                       IP is seen; pass --no-discover to skip that too)\n"
        "  --port <port>        RTSP port (default: 7000, or 5000 with --airplay1;\n"
        "                       overrides whatever discovery found for --host)\n"
        "  --airplay1           force legacy AirPlay 1 (no HAP pairing)\n"
        "  --password <pw>      RTSP digest password (AirPlay 1 pw=true receivers)\n"
        "  --name <name>        name presented to the receiver as the sender\n"
        "                       (default: this executable's file name, minus any\n"
        "                       extension)\n"
        "  --volume <0-100>     percent volume once streaming starts (default: leave untouched)\n"
        "  --browse-time <sec>  seconds to browse mDNS for (default: 3)\n"
        "  --no-discover        skip mDNS entirely (requires --host)\n"
        "  --list               print discovered devices and exit\n"
        "  --headless           fail immediately if cached credentials are stale,\n"
        "                       never prompt for a PIN"
        << (kHeadlessDefault ? " [default; no effect]" : " [overrides the default]") << "\n"
        "  --interactive        prompt for a PIN to re-authenticate if cached\n"
        "                       credentials are stale"
        << (kHeadlessDefault ? " [overrides the default]" : " [default; no effect]") << "\n"
        "  -v, --version        show version info and compilation flags\n"
        "  -h, --help           this\n";}

void printVersion() {
    std::cout << "airplay-send (AirPlay 2 Sender)\n"
              << "compilation flags & features:\n";
#ifdef WITH_MINIAUDIO
    std::cout << "  ENABLE_MINIAUDIO : ON (miniaudio 0.11.25, formats: wav, mp3, flac, ogg/vorbis, opus)\n";
#else
    std::cout << "  ENABLE_MINIAUDIO : OFF (built-in wav reader only)\n";
#endif
    std::cout << "  HEADLESS_DEFAULT : " << (kHeadlessDefault ? "ON" : "OFF")
              << (kHeadlessDefault
                      ? " (stale credentials fail immediately; --interactive enables PIN prompts)"
                      : " (stale credentials prompt for a PIN; --headless disables)") << "\n"
              << "  crypto backend   : Mbed TLS 3.6 + orlp/ed25519\n"
              << "  transport        : PosixTransport (poll(2) + BSD sockets)\n"
              << "  c++ standard     : C++20\n";
}

bool parseArgs(int argc, char** argv, Options& o) {
    std::vector<std::string> positional;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto need = [&](const char* flag) -> std::optional<std::string> {
            if (i + 1 >= argc) {
                std::cerr << "error: " << flag << " needs a value\n";
                return std::nullopt;
            }
            return std::string(argv[++i]);
        };
        if (a == "-h" || a == "--help") { o.help = true; }
        else if (a == "--host") { auto v = need("--host"); if (!v) return false; o.host = *v; }
        else if (a == "--port") {
            auto v = need("--port"); if (!v) return false;
            int p = 0;
            if (!parseInt(*v, p) || p < 1 || p > 65535) {
                std::cerr << "error: --port needs a number 1-65535, got '" << *v << "'\n";
                return false;
            }
            o.port = uint16_t(p);
        }
        else if (a == "--airplay1") { o.airplay1 = true; }
        else if (a == "--password") { auto v = need("--password"); if (!v) return false; o.password = *v; }
        else if (a == "--name") { auto v = need("--name"); if (!v) return false; o.clientName = *v; }
        else if (a == "--volume") {
            auto v = need("--volume"); if (!v) return false;
            double vol = 0.0;
            if (!parseDouble(*v, vol)) {
                std::cerr << "error: --volume needs a number, got '" << *v << "'\n";
                return false;
            }
            o.volume = vol;
        }
        else if (a == "--browse-time") {
            auto v = need("--browse-time"); if (!v) return false;
            if (!parseInt(*v, o.browseSeconds) || o.browseSeconds < 0) {
                std::cerr << "error: --browse-time needs a non-negative number, got '" << *v << "'\n";
                return false;
            }
        }
        else if (a == "--no-discover") { o.noDiscover = true; }
        else if (a == "--headless") { o.headlessMode = true; }
        else if (a == "--interactive") { o.headlessMode = false; }
        else if (a == "--list") { o.list = true; }
        else if (a == "-v" || a == "--version") { o.version = true; }
        else if (!a.empty() && a[0] == '-') { std::cerr << "error: unknown option '" << a << "'\n"; return false; }
        else { positional.push_back(a); }
    }
    if (o.help || o.list || o.version) return true;
    if (positional.size() != 1) {
#ifdef WITH_MINIAUDIO
        std::cerr << "error: expected exactly one <file> argument\n";
#else
        std::cerr << "error: expected exactly one <file.wav> argument\n";
#endif
        return false;
    }
    o.wavPath = positional.front();
    if (o.noDiscover && o.host.empty()) {
        std::cerr << "error: --no-discover requires --host\n";
        return false;
    }
    return true;
}

// Browse for `seconds`; every device seen is appended to `out` (in
// first-seen order, later updated in place on an mDNS "upgrade", same
// semantics as MdnsBrowser::query itself).
void browse(int seconds, std::vector<RaopDeviceInfo>& out) {
    MdnsBrowser browser;
    if (!browser.ok()) {
        std::cerr << "warning: mDNS socket setup failed, discovery unavailable "
                     "(firewall? try --host)\n";
        return;
    }
    browser.query([&](const RaopDeviceInfo& d) {
        auto it = std::find_if(out.begin(), out.end(),
                                [&](const RaopDeviceInfo& e) { return e.name == d.name; });
        if (it == out.end()) out.push_back(d);
        else *it = d;
    });
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (std::chrono::steady_clock::now() < until) browser.poll(100);
}

void printDevice(const RaopDeviceInfo& d) {
    std::cout << (d.airplay2 ? "[AirPlay 2] " : "[AirPlay 1] ") << d.name
              << "  " << d.host << ":" << d.port;
    if (!d.model.empty()) std::cout << "  (" << d.model << ")";
    std::cout << "\n";
}

// Resolve the device to actually connect to from discovery results + the
// user's flags. Returns std::nullopt if nothing usable was found.
std::optional<RaopDeviceInfo> resolveDevice(const Options& o, const std::vector<RaopDeviceInfo>& found) {
    RaopDeviceInfo device;
    if (!o.host.empty()) {
        auto it = std::find_if(found.begin(), found.end(),
                                [&](const RaopDeviceInfo& d) { return d.host == o.host; });
        if (it != found.end()) {
            device = *it;
            if (o.port) device.port = o.port;   // explicit --port overrides discovery
        } else {
            // Not seen via mDNS (or discovery was skipped): build a best
            // guess from the flags. See mdns_browser.cpp's deriveAuth for
            // why "guess HapPin, let RaopSender's own 403/470 fallback sort
            // it out" is the same honest default the browser itself uses.
            device.name = o.host;
            device.host = o.host;
            device.port = o.port ? o.port : (o.airplay1 ? 5000 : 7000);
            device.airplay2 = !o.airplay1;
            device.auth = o.airplay1
                ? (o.password.empty() ? RaopSender::Auth::None : RaopSender::Auth::Password)
                : RaopSender::Auth::HapPin;
            std::cout << "note: " << (o.noDiscover ? "discovery skipped (--no-discover)"
                                                    : (o.host + " wasn't seen via mDNS"))
                      << "; using port " << device.port
                      << (o.port ? " (given)" : " (guessed)")
                      << ", auth=" << authName(device.auth)
                      << (o.airplay1 ? " (--airplay1)" : " (guessed)") << ".\n";
        }
    } else {
        auto it = std::find_if(found.begin(), found.end(),
                                [](const RaopDeviceInfo& d) { return d.airplay2; });
        if (it == found.end()) it = found.begin();   // first AirPlay-1-only device, if any
        if (it == found.end()) return std::nullopt;
        device = *it;
    }
    // Some receivers advertise no "deviceid" TXT key; fall back to the host
    // so the credential cache still has SOMETHING stable to key on.
    if (device.deviceId.empty()) device.deviceId = device.host;
    return device;
}

// How one streaming session ended, so the caller can decide whether to
// re-pair (stale credentials) or give up.
enum class SessionResult { Ok, Stopped, Failed, StaleCreds };

// Run one full streaming session against `device`. `credsJson` carries the
// stored long-term credentials (empty = first pairing / re-pairing).
// `headless` suppresses the PIN prompt: if the receiver asks for a code the
// session is aborted instead of blocking on stdin.
SessionResult runSession(const RaopDeviceInfo& device, const AudioData& audio,
                         const Options& o, bool headless, const std::string& credsJson) {
    PosixTransport io;
    RaopSender sender(io);

    // Roughly a second of stereo audio at the file's native rate; plenty of
    // headroom for the ~8 ms pacer to pull from without the feed loop below
    // needing to be especially tight about topping it up.
    RingBuffer<int16_t> ring(size_t(std::max<uint32_t>(audio.sampleRate, 8000)) * 2);
    sender.attachRing(&ring);
    sender.setInputFormat(audio.sampleRate);

    bool launchDone = false, launchedOk = false, sessionClosed = false;
    bool pinPromptSuppressed = false;   // headless: receiver wants a PIN we won't collect

    sender.onLaunched = [&](bool ok, const std::string& err) {
        launchDone = true;
        launchedOk = ok;
        if (ok) {
            std::cout << "streaming to '" << device.name << "'\n";
            if (o.volume.has_value())
                sender.setVolume(*o.volume);
        } else {
            std::cerr << "error: " << err << "\n";
        }
    };
    sender.onClosed = [&] { sessionClosed = true; };
    sender.onPinRequired = [&](const std::string& name) {
        if (headless) {
            // A headless run can't collect a code from the user; abort the
            // session instead of blocking on stdin until the PIN watchdog.
            std::cerr << "error: '" << name << "' requires a PIN but interactive "
                         "prompts are disabled (--headless / HEADLESS_DEFAULT=ON); "
                         "run without --headless to pair.\n";
            pinPromptSuppressed = true;
            return;
        }
        // Blocks the poll loop while waiting for input, which is fine here:
        // there's nothing else useful to do concurrently in a one-shot CLI
        // tool, and RaopSender's own PIN-wait watchdog (3 min) just runs a
        // little "late" relative to wall clock, it's checked the instant
        // poll() resumes after this returns, not on a background thread.
        std::cout << "\nenter the 4-digit AirPlay code shown on '" << name << "': " << std::flush;
        std::string pin;
        std::getline(std::cin, pin);
        sender.submitPin(trimmed(pin));
    };
    sender.onCredentialsObtained = [&](const std::string& id, const std::string& json) {
        saveCachedCreds(id, json);
        std::cout << "paired; credentials cached for next time\n";
    };

    sender.setAuth(device.auth, device.airplay2, device.deviceId, credsJson, o.password);
    sender.setClientName(o.clientName);
    sender.start(device.host, device.port, device.name);

    size_t offset = 0;
    const size_t totalSamples = audio.pcm.size();
    bool fileQueued = false, draining = false;
    std::chrono::steady_clock::time_point drainDeadline{};
    auto lastProgress = std::chrono::steady_clock::now();

    while (!g_stop && !sessionClosed && !pinPromptSuppressed) {
        while (offset < totalSamples) {
            const size_t avail = ring.availableWrite();
            if (avail < 2) break;
            size_t chunk = std::min(avail, totalSamples - offset);
            chunk -= chunk % 2;   // keep stereo-frame alignment
            if (chunk == 0) break;
            if (!ring.tryPush(std::span<const int16_t>(audio.pcm.data() + offset, chunk))) break;
            offset += chunk;
        }
        if (offset >= totalSamples) fileQueued = true;

        io.poll(16);

        const auto now = std::chrono::steady_clock::now();
        if (launchDone && launchedOk && now - lastProgress >= std::chrono::milliseconds(1000)) {
            lastProgress = now;
            const double queuedSec = double(offset / 2) / double(audio.sampleRate);
            const double totalSec  = double(totalSamples / 2) / double(audio.sampleRate);
            std::cout << "\r" << queuedSec << "s / " << totalSec << "s queued   " << std::flush;
        }

        if (fileQueued && !draining && launchDone && ring.availableRead() == 0) {
            draining = true;
            // RAOP's fixed pipeline latency is ~1.5 s (see raop_sender.h);
            // give it a little extra margin so the last packets are
            // actually audible at the receiver before TEARDOWN.
            drainDeadline = now + std::chrono::milliseconds(2500);
            std::cout << "\nfile fully queued, letting the tail play out...\n";
        }
        if (draining && now >= drainDeadline) break;
    }

    std::cout << "\n";
    if (g_stop) std::cout << "stopping (ctrl-c)...\n";
    sender.stop();   // synchronous: TEARDOWN + socket close happen inline
    std::cout << "done\n";

    if (launchDone && launchedOk) return SessionResult::Ok;
    if (launchDone && !launchedOk)
        return sender.credsRejected() ? SessionResult::StaleCreds : SessionResult::Failed;
    if (g_stop) return SessionResult::Stopped;
    return SessionResult::Failed;   // aborted (headless PIN) or loop ended without a launch
}

}  // namespace

int main(int argc, char** argv) {
    Options o;
    if (!parseArgs(argc, argv, o)) { printUsage(argv[0]); return 2; }
    if (o.help) { printUsage(argv[0]); return 0; }
    if (o.version) { printVersion(); return 0; }
    if (o.clientName.empty()) o.clientName = executableBaseName(argv[0]);

    std::vector<RaopDeviceInfo> found;
    if (!o.noDiscover) {
        std::cout << "browsing for AirPlay/RAOP devices (" << o.browseSeconds << "s)...\n";
        browse(o.browseSeconds, found);
    }

    if (o.list) {
        if (found.empty()) std::cout << "no devices found.\n";
        for (const auto& d : found) printDevice(d);
        return 0;
    }

    const auto deviceOpt = resolveDevice(o, found);
    if (!deviceOpt) {
        std::cerr << "error: no AirPlay device found. Try --host <ip>, --list, or a "
                     "longer --browse-time.\n";
        return 1;
    }
    const RaopDeviceInfo device = *deviceOpt;
    std::cout << "target: "; printDevice(device);

    AudioData audio = loadWavAsStereo16(o.wavPath);
#ifdef WITH_MINIAUDIO
    if (!audio.ok) audio = loadWithMiniAudio(o.wavPath);
#endif
    if (!audio.ok) {
        std::cerr << "error: " << audio.error << "\n";
        return 1;
    }
    std::cout << "loaded '" << o.wavPath << "': " << audio.frames() << " frames @ "
              << audio.sampleRate << " Hz (" << (double(audio.frames()) / double(audio.sampleRate)) << "s)\n";

    const std::string cachedCreds = loadCachedCreds(device.deviceId);
    if (!cachedCreds.empty())
        std::cout << "using cached credentials for this device\n";

    const bool headless = o.headlessMode.value_or(kHeadlessDefault);
    std::signal(SIGINT, onSigint);

    // Stale cached credentials (the receiver reset its paired-device list):
    // in interactive mode, clear the cache and re-pair with a PIN; headless
    // mode fails immediately.
    std::string creds = cachedCreds;
    bool retriedWithoutCreds = false;
    for (;;) {
        switch (runSession(device, audio, o, headless, creds)) {
        case SessionResult::Ok:
        case SessionResult::Stopped:
            return 0;
        case SessionResult::Failed:
            return 1;
        case SessionResult::StaleCreds:
            if (headless || retriedWithoutCreds) {
                std::cerr << "error: cached credentials for '" << device.name
                          << "' were rejected by the device (it may have reset its "
                             "paired devices); "
                          << (headless ? "run without --headless"
                                       : "pair the device again and re-run")
                          << " to re-pair with a PIN.\n";
                return 1;
            }
            std::cout << "cached credentials were rejected by the device; "
                         "re-pairing with a PIN...\n";
            creds.clear();
            retriedWithoutCreds = true;
            break;   // retry once, un-paired, so the PIN prompt can re-authenticate
        }
    }
}
