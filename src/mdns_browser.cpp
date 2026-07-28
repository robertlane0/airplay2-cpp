// SPDX-License-Identifier: Apache-2.0
//
// mdns_browser.cpp -- see mdns_browser.h for scope/shape notes.
//
// Wire format: RFC 1035 (DNS message format) + RFC 6762 (mDNS) + RFC 6763
// (DNS-SD). All three are open IETF standards, not reverse-engineered Apple
// protocol, no clean-room concerns here (unlike raop_sender.cpp's RTSP/RAOP
// layer) -- this is just "read a DNS packet".

#include "mdns_browser.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace fxchain {

namespace {

constexpr uint16_t kDnsTypeA   = 1;
constexpr uint16_t kDnsTypePTR = 12;
constexpr uint16_t kDnsTypeTXT = 16;
constexpr uint16_t kDnsTypeSRV = 33;
constexpr uint16_t kDnsClassIN = 1;
constexpr uint16_t kMdnsPort   = 5353;
constexpr const char* kMdnsGroup = "224.0.0.251";

// ── a bounds-checked reader over one whole DNS message ────────────────
// Every offset is absolute into `data` (DNS name-compression pointers are
// always relative to the start of the message, RFC 1035 §4.1.4), so this
// reads by explicit position rather than an implicit stream cursor for
// anything that can be pointed at (names); readU8/16/32 do use an implicit
// cursor for the fixed-width fields that surround them.
struct DnsReader {
    const uint8_t* data;
    size_t size;
    size_t pos = 0;

    bool readU8(uint8_t& v) {
        if (pos + 1 > size) return false;
        v = data[pos]; pos += 1; return true;
    }
    bool readU16(uint16_t& v) {
        if (pos + 2 > size) return false;
        v = uint16_t((uint16_t(data[pos]) << 8) | data[pos + 1]); pos += 2; return true;
    }
    bool readU32(uint32_t& v) {
        if (pos + 4 > size) return false;
        v = (uint32_t(data[pos]) << 24) | (uint32_t(data[pos + 1]) << 16)
          | (uint32_t(data[pos + 2]) << 8) | uint32_t(data[pos + 3]);
        pos += 4; return true;
    }

    // Decode a (possibly compressed) domain name starting at the reader's
    // CURRENT position, advancing `pos` past exactly what the OUTER read
    // consumed (2 bytes if it started with a pointer, however far the
    // pointer's target expands to otherwise). Bounds-checked; pointer chains
    // must point strictly backward from wherever they're followed, which
    // both matches RFC 1035's "prior occurrence" requirement and makes an
    // infinite/looping chain structurally impossible (each hop's target is
    // less than that hop's own position, so the chain is finite and bounded
    // by the message size regardless of the 128-hop belt-and-suspenders cap
    // below).
    bool readName(std::string& out) {
        out.clear();
        size_t cursor = pos;
        bool jumped = false;
        size_t resumeAt = 0;
        int hops = 0;
        for (;;) {
            if (cursor >= size) return false;
            const uint8_t len = data[cursor];
            if ((len & 0xC0) == 0xC0) {
                if (cursor + 1 >= size) return false;
                const size_t target = (size_t(len & 0x3F) << 8) | data[cursor + 1];
                if (!jumped) { resumeAt = cursor + 2; jumped = true; }
                if (target >= cursor) return false;   // must point strictly backward
                if (++hops > 128) return false;
                cursor = target;
                continue;
            }
            if (len & 0xC0) return false;   // reserved 01/10 label-length prefix: malformed
            if (len == 0) { cursor += 1; break; }
            if (cursor + 1 + len > size) return false;
            if (!out.empty()) out += '.';
            out.append(reinterpret_cast<const char*>(data + cursor + 1), len);
            if (out.size() > 1024) return false;   // defence in depth; see file header
            cursor += 1 + size_t(len);
        }
        pos = jumped ? resumeAt : cursor;
        return true;
    }
};

// A record's fixed header, decoded; `rdata`/`rdlength` are NOT copied (they
// point back into the caller's packet buffer, valid only as long as that is).
struct DnsRecord {
    std::string name;
    uint16_t type = 0;
    uint16_t rrClass = 0;
    const uint8_t* rdata = nullptr;
    uint16_t rdlength = 0;
    size_t rdataOffset = 0;   // absolute offset, for parsing a compressed name INSIDE rdata
};

bool readRecord(DnsReader& r, DnsRecord& out) {
    if (!r.readName(out.name)) return false;
    uint16_t type = 0, cls = 0, rdlen = 0;
    uint32_t ttl = 0;
    if (!r.readU16(type) || !r.readU16(cls) || !r.readU32(ttl) || !r.readU16(rdlen))
        return false;
    (void)ttl;   // soft-state TTL; this browser doesn't track expiry (see file header)
    out.type = type;
    out.rrClass = cls & 0x7FFF;   // mask the mDNS cache-flush bit (top bit of class)
    out.rdataOffset = r.pos;
    out.rdlength = rdlen;
    if (r.pos + rdlen > r.size) return false;
    out.rdata = r.data + r.pos;
    r.pos += rdlen;
    return true;
}

// Parse a (possibly compressed) name living at an absolute offset inside
// `full` -- used for names embedded in rdata (PTR's target, SRV's target),
// which is a separate read from the record-header walk above.
bool nameAt(const DnsReader& full, size_t offset, std::string& out) {
    if (offset > full.size) return false;
    DnsReader r{full.data, full.size, offset};
    return r.readName(out);
}

// TXT rdata: a sequence of length-prefixed strings, each "key=value" or a
// bare "key" (DNS-SD allows boolean-valued keys with no '=').
std::map<std::string, std::string> parseTxt(const uint8_t* rdata, uint16_t rdlen) {
    std::map<std::string, std::string> out;
    size_t i = 0;
    while (i < rdlen) {
        const uint8_t len = rdata[i];
        if (i + 1 + len > rdlen) break;   // truncated entry, stop (not a hard error)
        const char* p = reinterpret_cast<const char*>(rdata + i + 1);
        const std::string entry(p, len);
        const size_t eq = entry.find('=');
        if (eq == std::string::npos) out.emplace(entry, "");
        else out.emplace(entry.substr(0, eq), entry.substr(eq + 1));
        i += 1 + len;
    }
    return out;
}

// A starting guess at RaopSender::Auth from a device's mDNS advertisement.
// Deliberately conservative: AirPlay 2 (HAP) pairing has two shapes,
// HapPin (Apple TV-style on-screen code) and HapTransient (HomePod/macOS
// fixed-pin, no UI), and the two verified real devices behind this repo
// (see README) show DIFFERENT `flags`/`sf` TXT values for them -- but not
// distinctly enough, on the bits we can attribute with any confidence, to
// tell them apart reliably without risking a wrong "documented fact" here.
// RaopSender already recovers from a wrong guess on its own: a HapPin start
// that gets refused with /pair-pin-start 403 automatically retries as
// HapTransient, and a HapTransient start refused with 470 automatically
// retries as HapPin (see raop_sender.cpp's onPairingResponse_). So this just
// defaults every AP2 device to HapPin and lets that recovery do its job --
// a wrong guess costs one extra round trip, not a failure. If you have
// out-of-band knowledge for a specific device (or stored credentials, which
// RaopSender::setAuth()'s credsJson already routes straight to pair-verify
// regardless of this guess), override RaopDeviceInfo::auth before calling
// setAuth().
RaopSender::Auth deriveAuth(bool airplay2, const std::map<std::string, std::string>& txt) {
    if (airplay2)
        return RaopSender::Auth::HapPin;

    // Legacy RAOP / AirPlay 1: these TXT semantics are the original,
    // long-public AirTunes ones (shairport-sync/pyatv document them
    // identically), not the AP2/HAP guesswork above.
    const auto pw = txt.find("pw");
    if (pw != txt.end() && (pw->second == "true" || pw->second == "1"))
        return RaopSender::Auth::Password;

    // A naming heuristic, not a protocol fact: the AirPort Express units
    // that speak MFi auth-setup show up with an "AirPort" model string.
    // There's no TXT key we're aware of that states "requires auth-setup"
    // outright; override RaopDeviceInfo::auth if you know better for a
    // specific device.
    const auto am = txt.find("am");
    if (am != txt.end() && am->second.rfind("AirPort", 0) == 0)
        return RaopSender::Auth::AuthSetup;

    return RaopSender::Auth::None;
}

// Append one QNAME (dotted -> length-prefixed labels) + QTYPE + QCLASS to a
// query packet under construction.
void appendQuestion(std::string& pkt, const std::string& dotted, uint16_t qtype) {
    size_t start = 0;
    while (start <= dotted.size()) {
        const size_t dot = dotted.find('.', start);
        const size_t end = (dot == std::string::npos) ? dotted.size() : dot;
        const size_t len = end - start;
        pkt += char(uint8_t(len));
        pkt.append(dotted, start, len);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    pkt += '\0';   // root label
    pkt += char(uint8_t(qtype >> 8)); pkt += char(uint8_t(qtype & 0xFF));
    pkt += char(uint8_t(kDnsClassIN >> 8)); pkt += char(uint8_t(kDnsClassIN & 0xFF));
}

} // namespace

MdnsBrowser::MdnsBrowser() {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;

    const int reuse = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(kMdnsPort);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return;
    }

    ip_mreq mreq{};
    ::inet_pton(AF_INET, kMdnsGroup, &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (::setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        ::close(fd);
        return;
    }

    // mDNS convention (RFC 6762 §11): multicast TTL 255, so a misconfigured
    // router that decrements-but-doesn't-drop doesn't silently kill replies.
    const int ttl = 255;
    ::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    fd_ = fd;
}

MdnsBrowser::~MdnsBrowser() {
    if (fd_ >= 0) ::close(fd_);
}

void MdnsBrowser::query(FoundFn onFound) {
    onFound_ = std::move(onFound);
    if (fd_ < 0) return;

    std::string pkt;
    pkt.reserve(64);
    // Header: ID=0, flags=0 (standard query), QDCOUNT=2, AN/NS/ARCOUNT=0.
    pkt += '\0'; pkt += '\0';   // ID
    pkt += '\0'; pkt += '\0';   // flags
    pkt += '\0'; pkt += '\x02'; // QDCOUNT = 2
    pkt += '\0'; pkt += '\0';   // ANCOUNT
    pkt += '\0'; pkt += '\0';   // NSCOUNT
    pkt += '\0'; pkt += '\0';   // ARCOUNT
    appendQuestion(pkt, "_airplay._tcp.local", kDnsTypePTR);
    appendQuestion(pkt, "_raop._tcp.local", kDnsTypePTR);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(kMdnsPort);
    ::inet_pton(AF_INET, kMdnsGroup, &dst.sin_addr);
    ::sendto(fd_, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
}

void MdnsBrowser::poll(int timeoutMs) {
    if (fd_ < 0) return;
    pollfd pfd{fd_, POLLIN, 0};
    ::poll(&pfd, 1, timeoutMs);
    if (!(pfd.revents & POLLIN)) return;

    uint8_t buf[8192];
    for (;;) {
        const ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
        if (n <= 0) break;   // EAGAIN or nothing more this cycle
        handlePacket_(buf, size_t(n));
    }
}

void MdnsBrowser::handlePacket_(const uint8_t* data, size_t len) {
    DnsReader r{data, len};
    uint16_t id = 0, flags = 0, qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
    if (!r.readU16(id) || !r.readU16(flags) || !r.readU16(qdcount) || !r.readU16(ancount)
        || !r.readU16(nscount) || !r.readU16(arcount))
        return;
    (void)id; (void)flags;

    // Walk (and discard) the question section, just to advance past it correctly.
    for (uint16_t i = 0; i < qdcount; ++i) {
        std::string qname;
        uint16_t qtype = 0, qclass = 0;
        if (!r.readName(qname) || !r.readU16(qtype) || !r.readU16(qclass)) return;
    }

    // Answer + authority + additional all get the same RR format; AirPlay
    // receivers put SRV/TXT/A in "additional", so treat all three sections
    // identically rather than caring which section a record came from.
    std::vector<DnsRecord> records;
    const uint32_t total = uint32_t(ancount) + uint32_t(nscount) + uint32_t(arcount);
    records.reserve(std::min<uint32_t>(total, 64));
    for (uint32_t i = 0; i < total; ++i) {
        DnsRecord rec;
        if (!readRecord(r, rec)) return;   // malformed packet: stop, keep whatever we already found
        records.push_back(std::move(rec));
    }

    for (const DnsRecord& ptr : records) {
        if (ptr.type != kDnsTypePTR) continue;
        if (ptr.rrClass != kDnsClassIN) continue;
        const bool airplay2 = (ptr.name == "_airplay._tcp.local");
        if (!airplay2 && ptr.name != "_raop._tcp.local") continue;

        std::string instance;
        if (!nameAt(r, ptr.rdataOffset, instance)) continue;

        const DnsRecord* srv = nullptr;
        const DnsRecord* a = nullptr;
        std::map<std::string, std::string> txt;
        for (const DnsRecord& rec : records) {
            if (rec.name != instance) continue;
            if (rec.type == kDnsTypeSRV && !srv) srv = &rec;
            else if (rec.type == kDnsTypeTXT) {
                auto part = parseTxt(rec.rdata, rec.rdlength);
                txt.insert(part.begin(), part.end());
            }
        }
        if (!srv || srv->rdlength < 6) continue;   // no port/target, can't resolve this packet
        uint16_t port = uint16_t((uint16_t(srv->rdata[4]) << 8) | srv->rdata[5]);
        std::string target;
        if (!nameAt(r, srv->rdataOffset + 6, target)) continue;
        for (const DnsRecord& rec : records) {
            if (rec.type == kDnsTypeA && rec.name == target && rec.rdlength == 4) { a = &rec; break; }
        }
        if (!a) continue;   // A record not bundled in this packet; see file header scope note

        char ipbuf[INET_ADDRSTRLEN] = {};
        in_addr addr{};
        std::memcpy(&addr, a->rdata, 4);
        ::inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf));

        // Strip the known suffix (". _airplay._tcp.local" / "._raop._tcp.local")
        // to get the friendly name. RFC 6763 instance names can contain
        // escaped dots (\.); this doesn't unescape them (a minor cosmetic
        // gap for the rare device with a literal dot in its name).
        const std::string suffix = "." + ptr.name;
        std::string friendlyName = instance;
        if (friendlyName.size() > suffix.size()
            && friendlyName.compare(friendlyName.size() - suffix.size(), suffix.size(), suffix) == 0)
            friendlyName.resize(friendlyName.size() - suffix.size());

        RaopDeviceInfo info;
        info.name = friendlyName;
        info.host = ipbuf;
        info.port = port;
        info.txt = txt;
        info.deviceId = txt.count("deviceid") ? txt.at("deviceid") : "";
        info.model = txt.count("am") ? txt.at("am") : "";
        info.airplay2 = airplay2;
        info.auth = deriveAuth(airplay2, txt);

        auto it = known_.find(friendlyName);
        const bool isNew = (it == known_.end());
        const bool isUpgrade = !isNew && airplay2 && !it->second.airplay2;
        if (isNew || isUpgrade) {
            known_[friendlyName] = info;
            if (onFound_) onFound_(info);
        } else if (it != known_.end()) {
            // Refresh the non-identifying fields (host/port/txt can change
            // across announcements) without re-firing onFound_.
            it->second.host = info.host;
            it->second.port = info.port;
            it->second.txt = info.txt;
        }
    }
}

} // namespace fxchain
