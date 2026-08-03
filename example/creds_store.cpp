// SPDX-License-Identifier: Apache-2.0
//
// creds_store.cpp -- see creds_store.h for scope notes.

#include "creds_store.h"

#include <cstdlib>
#include <fstream>
#include <sstream>

#include <sys/stat.h>

namespace fxchain {

namespace {

std::string cacheDir() {
    if (const char* xdg = std::getenv("XDG_CACHE_HOME"); xdg && *xdg)
        return std::string(xdg) + "/airplay-send";
    if (const char* home = std::getenv("HOME"); home && *home)
        return std::string(home) + "/.cache/airplay-send";
    return "/tmp/airplay-send-creds";
}

// deviceId is typically a MAC ("AA:BB:CC:DD:EE:FF"); keep only characters
// that are safe in a filename on every platform we care about, mapping
// everything else (colons included) to '_'. Defends against a deviceId
// containing a path separator or similar, however that string was sourced.
std::string sanitize(const std::string& deviceId) {
    std::string s;
    s.reserve(deviceId.size());
    for (char c : deviceId) {
        const bool safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (c >= '0' && c <= '9') || c == '-' || c == '.';
        s += safe ? c : '_';
    }
    return s.empty() ? "unknown" : s;
}

std::string pathFor(const std::string& deviceId) {
    return cacheDir() + "/" + sanitize(deviceId) + ".credentials";
}

// mkdir -p: create every missing path segment, not just the final one. The
// original "cacheDir() is always one segment below an existing directory"
// assumption doesn't hold in practice, e.g. a fresh container's $HOME often
// has no .cache yet, so this walks the whole path.
void ensureDir(const std::string& dir) {
    std::string partial;
    partial.reserve(dir.size());
    size_t pos = 0;
    while (pos < dir.size()) {
        const size_t slash = dir.find('/', pos);
        const size_t end = (slash == std::string::npos) ? dir.size() : slash;
        partial.append(dir, pos, end - pos);
        if (!partial.empty()) ::mkdir(partial.c_str(), 0700);   // ignore EEXIST and other errors here
        partial += '/';
        pos = end + 1;
    }
}

}  // namespace

std::string loadCachedCreds(const std::string& deviceId) {
    if (deviceId.empty()) return {};
    std::ifstream f(pathFor(deviceId), std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void saveCachedCreds(const std::string& deviceId, const std::string& credsJson) {
    if (deviceId.empty() || credsJson.empty()) return;
    ensureDir(cacheDir());
    std::ofstream f(pathFor(deviceId), std::ios::binary | std::ios::trunc);
    if (!f) return;   // best-effort; see the header note
    f << credsJson;
}

} // namespace fxchain
