// SPDX-License-Identifier: Apache-2.0
//! mDNS/DNS-SD browser for AirPlay receivers — migration of
//! `src/mdns_browser.{h,cpp}`.
//!
//! Discovers `_airplay._tcp.local` (AirPlay 2) and `_raop._tcp.local`
//! (legacy AirPlay 1) receivers on the local IPv4 LAN and reports each via
//! a callback when it is first announced or when it upgrades from AirPlay 1
//! to AirPlay 2.
//!
//! Packet handling follows the C++ implementation rule for rule:
//!
//! * one UDP socket on `224.0.0.251:5353` (`SO_REUSEADDR` +
//!   `SO_REUSEPORT`, multicast TTL 255 — the RFC 6762 §11 convention),
//!   nonblocking, driven by an application-level `poll`;
//! * `query` writes a two-question (`PTR` for both service types) packet to
//!   the multicast group;
//! * `PTR -> SRV/TXT/A` records are correlated within a single packet —
//!   SRV port, SRV target resolved through `A`, TXT keys merged first-wins
//!   — and a receiver whose `A` record is not in the same packet is
//!   skipped, exactly like the C++;
//! * receivers are deduplicated by friendly name (the `PTR` instance minus
//!   the service suffix); re-announcements silently refresh
//!   `host`/`port`/`txt`, and an AirPlay 1 → AirPlay 2 upgrade re-fires the
//!   callback.
//!
//! Deliberate deviations from the C++ (all documented):
//!
//! * `new()` returns `Result` instead of a half-constructed object with an
//!   `ok()` flag; the failed step is a typed error variant.
//! * `SOCK_NONBLOCK | SOCK_CLOEXEC` are passed to `socket(2)` directly
//!   (matching `posix-transport`) instead of `socket()` plus a later
//!   `fcntl(F_SETFL, O_NONBLOCK)` — same kernel state, no `fcntl` needed.
//! * `handle_packet` is public: it is the C++ `handlePacket_` (private
//!   there), exposed so tests and callers can drive it without a socket.
//!
//! `Auth` mirrors `fxchain::RaopSender::Auth` in `src/raop_sender.h`; the
//! final `airplay-send` will consume it from here.

mod dns;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::rc::Rc;

use dns::{Reader, TYPE_A, TYPE_IN, TYPE_PTR, TYPE_SRV, TYPE_TXT, name_at, parse_txt, read_record};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::socket::sockopt;
use nix::sys::socket::{
    AddressFamily, IpMembershipRequest, MsgFlags, SockFlag, SockType, SockaddrIn, bind, recv,
    sendto, setsockopt, socket,
};

/// mDNS group address (RFC 6762 §3).
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// mDNS UDP port (RFC 6762 §3).
const MDNS_PORT: u16 = 5353;
const RECV_BUF_SIZE: usize = 8192;

/// The authentication model a receiver is expected to use, mirroring
/// `fxchain::RaopSender::Auth` in `src/raop_sender.h` (same names, same
/// ordering).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// No pairing required.
    None,
    /// Start with RTSP `SETUP` + RSA `pair-setup` (MFi AirPort Express).
    AuthSetup,
    /// AirPlay 1 4-digit PIN (`pair-setup-encrypted`).
    LegacyPin,
    /// HAP pairing with a transient (device-side) PIN.
    HapTransient,
    /// HAP pairing presented as a PIN code (default guess for AirPlay 2).
    HapPin,
    /// HAP pairing with a password.
    Password,
}

/// What the browser knows about one discovered receiver.
#[derive(Debug, Clone)]
pub struct RaopDeviceInfo {
    /// Friendly name (`PTR` instance minus the service suffix).
    pub name: String,
    /// IPv4 address of the receiver as a dotted quad.
    pub host: String,
    /// RTSP port from the SRV record.
    pub port: u16,
    /// Full TXT record, merged first-wins across the packet.
    pub txt: BTreeMap<String, String>,
    /// `deviceid` TXT key (empty when absent).
    pub device_id: String,
    /// `am` TXT key (empty when absent).
    pub model: String,
    /// True when announced under `_airplay._tcp.local`.
    pub airplay2: bool,
    /// Starting guess for `RaopSender::Auth`, derived as in the C++
    /// `deriveAuth`: AirPlay 2 → `HapPin`; `pw` ∈ {"true", "1"} →
    /// `Password`; `am` starting with "AirPort" → `AuthSetup`; else `None`.
    pub auth: Auth,
}

/// Failed `MdnsBrowser` construction; one variant per failed step.
#[derive(Debug)]
pub enum MdnsBrowserError {
    /// `socket(2)` failed.
    CreateSocket(Errno),
    /// `setsockopt(SO_REUSEADDR)` failed.
    SetReuseAddr(Errno),
    /// `setsockopt(SO_REUSEPORT)` failed (not available on Solaris).
    SetReusePort(Errno),
    /// `bind(0.0.0.0:5353)` failed (e.g. another responder holds the port
    /// without reuse).
    Bind(Errno),
    /// `setsockopt(IP_ADD_MEMBERSHIP)` failed.
    JoinMulticastGroup(Errno),
    /// `setsockopt(IP_MULTICAST_TTL)` failed.
    SetMulticastTtl(Errno),
}

impl fmt::Display for MdnsBrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MdnsBrowserError::CreateSocket(e) => write!(f, "socket(2): {e}"),
            MdnsBrowserError::SetReuseAddr(e) => write!(f, "setsockopt(SO_REUSEADDR): {e}"),
            MdnsBrowserError::SetReusePort(e) => write!(f, "setsockopt(SO_REUSEPORT): {e}"),
            MdnsBrowserError::Bind(e) => write!(f, "bind(0.0.0.0:{MDNS_PORT}): {e}"),
            MdnsBrowserError::JoinMulticastGroup(e) => {
                write!(f, "setsockopt(IP_ADD_MEMBERSHIP): {e}")
            }
            MdnsBrowserError::SetMulticastTtl(e) => {
                write!(f, "setsockopt(IP_MULTICAST_TTL): {e}")
            }
        }
    }
}

impl std::error::Error for MdnsBrowserError {}

/// Notified with each newly discovered (or upgraded) receiver.
pub type FoundFn = Box<dyn Fn(&RaopDeviceInfo)>;

/// An active mDNS browser. Callbacks fire from `poll` (and from
/// `handle_packet`, which `poll` feeds); the browser holds no borrows across
/// user callbacks, so a re-entrant `query` from inside a callback is safe
/// (it replaces the callback for subsequent announcements, as in the C++).
pub struct MdnsBrowser {
    fd: OwnedFd,
    on_found: RefCell<Option<Rc<FoundFn>>>,
    known: RefCell<BTreeMap<String, RaopDeviceInfo>>,
}

impl MdnsBrowser {
    /// Open the multicast socket and join `224.0.0.251` (C++ constructor).
    pub fn new() -> Result<Self, MdnsBrowserError> {
        let fd = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(MdnsBrowserError::CreateSocket)?;

        setsockopt(&fd, sockopt::ReuseAddr, &true).map_err(MdnsBrowserError::SetReuseAddr)?;
        #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
        setsockopt(&fd, sockopt::ReusePort, &true).map_err(MdnsBrowserError::SetReusePort)?;

        let any = SockaddrIn::new(0, 0, 0, 0, MDNS_PORT);
        bind(fd.as_raw_fd(), &any).map_err(MdnsBrowserError::Bind)?;

        let membership = IpMembershipRequest::new(MDNS_GROUP, None);
        setsockopt(&fd, sockopt::IpAddMembership, &membership)
            .map_err(MdnsBrowserError::JoinMulticastGroup)?;

        // RFC 6762 §11: multicast TTL 255.
        setsockopt(&fd, sockopt::IpMulticastTtl, &255u8)
            .map_err(MdnsBrowserError::SetMulticastTtl)?;

        Ok(MdnsBrowser {
            fd,
            on_found: RefCell::new(None),
            known: RefCell::new(BTreeMap::new()),
        })
    }

    /// Re-arm the discovery callback and multicast the two-question query
    /// (C++ `query` — the callback is replaced *before* sending, so a
    /// receiver answering the fresh probe is reported to the new callback).
    pub fn query(&self, on_found: FoundFn) {
        *self.on_found.borrow_mut() = Some(Rc::new(on_found));
        let pkt = build_query_packet();
        let dst = SockaddrIn::new(224, 0, 0, 251, MDNS_PORT);
        let _ = sendto(self.fd.as_raw_fd(), &pkt, &dst, MsgFlags::empty());
    }

    /// Wait up to `timeout_ms` for readable datagrams and process them
    /// (C++ `poll`). `timeout_ms == 0` returns immediately.
    pub fn poll(&self, timeout_ms: i32) {
        let mut pfd = [PollFd::new(self.fd.as_fd(), PollFlags::POLLIN)];
        // Only negative values fail TryFrom; C++ hands them to poll(2)
        // unchanged (negative means infinite, < -1 is EINVAL) — both map to
        // "nothing readable this cycle".
        let Ok(timeout) = PollTimeout::try_from(timeout_ms) else {
            return;
        };
        if nix::poll::poll(&mut pfd, timeout).is_err() {
            return;
        }
        if !pfd[0]
            .revents()
            .is_some_and(|r| r.contains(PollFlags::POLLIN))
        {
            return;
        }
        let mut buf = [0u8; RECV_BUF_SIZE];
        loop {
            match recv(self.fd.as_raw_fd(), &mut buf, MsgFlags::empty()) {
                Ok(0) | Err(_) => break, // EAGAIN or nothing more this cycle
                Ok(n) => self.handle_packet(&buf[..n]),
            }
        }
    }

    /// Process one received datagram (C++ `handlePacket_`). Malformed
    /// input is dropped; already-parsed records from a truncated packet are
    /// still delivered (C++ "keep whatever we already found").
    pub fn handle_packet(&self, data: &[u8]) {
        let mut r = Reader::new(data);
        // Header: ID, flags, QD/AN/NS/AR counts — all six read to validate
        // the 12-byte header; `id`/`flags` are then ignored, as in the C++.
        let (Some(_id), Some(_flags), Some(qdcount), Some(ancount), Some(nscount), Some(arcount)) = (
            r.read_u16(),
            r.read_u16(),
            r.read_u16(),
            r.read_u16(),
            r.read_u16(),
            r.read_u16(),
        ) else {
            return;
        };
        // Walk (and discard) the question section, advancing past it just
        // like the C++ (a QTYPE/QCLASS pair follows each QNAME).
        for _ in 0..qdcount {
            if r.read_name().is_none() || r.read_u16().is_none() || r.read_u16().is_none() {
                return;
            }
        }
        // Answer + authority + additional all carry the same RR format;
        // AirPlay receivers put SRV/TXT/A in "additional", so the sections
        // are treated identically (C++: merged, in packet order).
        let mut records = Vec::new();
        let total = u32::from(ancount) + u32::from(nscount) + u32::from(arcount);
        for _ in 0..total {
            let Some(rec) = read_record(&mut r) else {
                return; // malformed packet: stop, keep whatever we already found
            };
            records.push(rec);
        }

        for ptr in &records {
            if ptr.rtype != TYPE_PTR || ptr.rr_class != TYPE_IN {
                continue;
            }
            let airplay2 = ptr.name == "_airplay._tcp.local";
            if !airplay2 && ptr.name != "_raop._tcp.local" {
                continue;
            }

            let Some(instance) = name_at(data, ptr.rdata_offset) else {
                continue;
            };

            let mut srv = None;
            let mut txt = BTreeMap::new();
            for rec in &records {
                if rec.name != instance {
                    continue;
                }
                if rec.rtype == TYPE_SRV && srv.is_none() {
                    srv = Some(rec);
                } else if rec.rtype == TYPE_TXT {
                    // `std::map::insert` semantics: existing keys keep the
                    // first value seen in packet order.
                    let part = parse_txt(
                        &data[rec.rdata_offset..rec.rdata_offset + rec.rdlength as usize],
                    );
                    for (k, v) in part {
                        txt.entry(k).or_insert(v);
                    }
                }
            }
            let Some(srv) = srv else {
                continue; // no SRV: can't resolve this packet
            };
            if srv.rdlength < 6 {
                continue; // no port/target
            }
            let rdata = &data[srv.rdata_offset..srv.rdata_offset + srv.rdlength as usize];
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let Some(target) = name_at(data, srv.rdata_offset + 6) else {
                continue;
            };
            let mut a = None;
            for rec in &records {
                if rec.rtype == TYPE_A && rec.name == target && rec.rdlength == 4 {
                    a = Some(rec);
                    break;
                }
            }
            let Some(a) = a else {
                continue; // A record not bundled in this packet (C++ scope note)
            };
            let ip = Ipv4Addr::new(
                data[a.rdata_offset],
                data[a.rdata_offset + 1],
                data[a.rdata_offset + 2],
                data[a.rdata_offset + 3],
            )
            .to_string();

            // Strip the service suffix to get the friendly name. RFC 6763
            // instance names may contain escaped dots (\.); like the C++,
            // they are not unescaped.
            let suffix = format!(".{}", ptr.name);
            let mut friendly_name = instance;
            if friendly_name.len() > suffix.len() && friendly_name.ends_with(&suffix) {
                friendly_name.truncate(friendly_name.len() - suffix.len());
            }

            let info = RaopDeviceInfo {
                name: friendly_name,
                host: ip,
                port,
                txt: txt.clone(),
                device_id: txt.get("deviceid").cloned().unwrap_or_default(),
                model: txt.get("am").cloned().unwrap_or_default(),
                airplay2,
                auth: derive_auth(airplay2, &txt),
            };

            // Decide what to do, but never hold the `known` borrow across
            // the user callback fired below.
            let fire = {
                let mut known = self.known.borrow_mut();
                match known.get(&info.name) {
                    None => {
                        known.insert(info.name.clone(), info.clone());
                        true
                    }
                    Some(existing) if airplay2 && !existing.airplay2 => {
                        // AirPlay 1 -> AirPlay 2 upgrade: replace, re-fire.
                        known.insert(info.name.clone(), info.clone());
                        true
                    }
                    Some(_) => {
                        // Refresh the non-identifying fields (host/port/txt
                        // can change across announcements) without firing.
                        if let Some(slot) = known.get_mut(&info.name) {
                            slot.host = info.host.clone();
                            slot.port = info.port;
                            slot.txt = info.txt.clone();
                        }
                        false
                    }
                }
            };
            if fire {
                self.fire(info);
            }
        }
    }

    fn fire(&self, info: RaopDeviceInfo) {
        // Read the callback *at fire time* (C++ `onFound_` semantics), so a
        // re-entrant `query` from an earlier callback takes effect here.
        let cb = self.on_found.borrow().clone();
        if let Some(cb) = cb {
            cb(&info);
        }
    }

    /// Number of receivers currently known (test/diagnostic hook).
    pub fn known_count(&self) -> usize {
        self.known.borrow().len()
    }
}

/// `Auth` guess from a device's advertisement (C++ `deriveAuth`).
pub(crate) fn derive_auth(airplay2: bool, txt: &BTreeMap<String, String>) -> Auth {
    if airplay2 {
        // HAP pairing has two shapes (HapPin / HapTransient) that the TXT
        // bits don't distinguish reliably; HapPin is the conservative
        // default and RaopSender's pairing-response recovery covers a wrong
        // guess (see the comment in src/mdns_browser.cpp).
        return Auth::HapPin;
    }
    if let Some(pw) = txt.get("pw") {
        if pw == "true" || pw == "1" {
            return Auth::Password;
        }
    }
    if txt.get("am").is_some_and(|am| am.starts_with("AirPort")) {
        return Auth::AuthSetup;
    }
    Auth::None
}

/// The two-question mDNS query packet (C++ `query` body): header
/// `ID=0, flags=0, QDCOUNT=2`, then a `PTR` question for each service.
pub(crate) fn build_query_packet() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0]);
    append_question(&mut pkt, "_airplay._tcp.local", TYPE_PTR);
    append_question(&mut pkt, "_raop._tcp.local", TYPE_PTR);
    pkt
}

fn append_question(pkt: &mut Vec<u8>, dotted: &str, qtype: u16) {
    for label in dotted.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&TYPE_IN.to_be_bytes());
}
#[cfg(test)]
mod tests {
    use super::*;

    // ── synthetic response builder ────────────────────────────────────
    // Records are appended contiguously after the header; the reader walks
    // them in order, so nothing may sit between them. Names on first use
    // are written inline (raw labels) and *registered at their true
    // offset*; later uses become compression pointers, which by
    // construction always point strictly backward (RFC 1035 §4.1.4 + the
    // C++ reader's requirement).

    #[derive(Clone, Copy)]
    enum Section {
        Answer,
        Additional,
    }

    struct PktBuilder {
        bytes: Vec<u8>,
        names: BTreeMap<String, usize>,
    }

    impl PktBuilder {
        /// Header with QR set; section counts grow as records are added.
        fn new() -> Self {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&[0, 0, 0x84, 0x00]); // ID=0, flags=QR
            bytes.extend_from_slice(&0u16.to_be_bytes()); // qdcount
            bytes.extend_from_slice(&0u16.to_be_bytes()); // ancount
            bytes.extend_from_slice(&0u16.to_be_bytes()); // nscount
            bytes.extend_from_slice(&0u16.to_be_bytes()); // arcount
            PktBuilder {
                bytes,
                names: BTreeMap::new(),
            }
        }

        fn anc(&self) -> u16 {
            u16::from_be_bytes([self.bytes[6], self.bytes[7]])
        }

        fn arc(&self) -> u16 {
            u16::from_be_bytes([self.bytes[10], self.bytes[11]])
        }

        /// A name for a record header: raw labels on first use, then a
        /// pointer to the earlier occurrence.
        fn write_name(&mut self, name: &str) {
            if let Some(&off) = self.names.get(name) {
                self.bytes
                    .extend_from_slice(&(0xC000 | off as u16).to_be_bytes());
                return;
            }
            let off = self.bytes.len();
            for label in name.split('.') {
                self.bytes.push(label.len() as u8);
                self.bytes.extend_from_slice(label.as_bytes());
            }
            self.bytes.push(0);
            self.names.insert(name.to_string(), off);
        }

        /// One RR. The rdata closure appends the rdata bytes directly (so
        /// any name it embeds is registered at its true offset); the length
        /// is backfilled after it runs.
        fn rr(&mut self, section: Section, name: &str, rtype: u16, rdata: impl FnOnce(&mut Self)) {
            match section {
                Section::Answer => {
                    let n = self.anc() + 1;
                    self.bytes[6..8].copy_from_slice(&n.to_be_bytes());
                }
                Section::Additional => {
                    let n = self.arc() + 1;
                    self.bytes[10..12].copy_from_slice(&n.to_be_bytes());
                }
            }
            self.write_name(name);
            self.bytes.extend_from_slice(&rtype.to_be_bytes());
            // IN with the cache-flush bit set, exercising the masking.
            self.bytes.extend_from_slice(&0x8001u16.to_be_bytes());
            self.bytes.extend_from_slice(&120u32.to_be_bytes());
            let rdlen_at = self.bytes.len();
            self.bytes.extend_from_slice(&0u16.to_be_bytes());
            rdata(self);
            let rdlen = self.bytes.len() - rdlen_at - 2;
            self.bytes[rdlen_at..rdlen_at + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
        }

        /// A name embedded in rdata: same inline-once-then-pointer rules.
        fn rd_name(&mut self, name: &str) {
            self.write_name(name);
        }

        fn rd_srv(&mut self, port: u16, target: &str) {
            self.bytes.extend_from_slice(&0u16.to_be_bytes()); // priority
            self.bytes.extend_from_slice(&0u16.to_be_bytes()); // weight
            self.bytes.extend_from_slice(&port.to_be_bytes());
            self.rd_name(target);
        }

        fn rd_txt<'a>(entries: &'a [&'a str]) -> impl FnOnce(&mut Self) + 'a {
            // TXT entries are plain length-prefixed strings; never names.
            move |p: &mut Self| {
                for e in entries {
                    p.bytes.push(e.len() as u8);
                    p.bytes.extend_from_slice(e.as_bytes());
                }
            }
        }

        fn rd_a(ip: [u8; 4]) -> impl FnOnce(&mut Self) {
            move |p: &mut Self| p.bytes.extend_from_slice(&ip)
        }

        fn ptr_rdata(instance: &str) -> impl FnOnce(&mut Self) + '_ {
            move |p: &mut Self| p.rd_name(instance)
        }

        fn build(self) -> Vec<u8> {
            self.bytes
        }
    }

    /// Records for one `_airplay` device: PTR (in Answer, rdata carries the
    /// instance name) + SRV/TXT/A (in Additional, like real responders).
    /// Later records reference the instance/host names already embedded by
    /// the PTR and SRV rdata via compression pointers.
    fn airplay_device(
        instance: &str,
        host: &str,
        port: u16,
        ip: [u8; 4],
        entries: &[&str],
    ) -> Vec<u8> {
        let mut p = PktBuilder::new();
        p.rr(
            Section::Answer,
            "_airplay._tcp.local",
            TYPE_PTR,
            PktBuilder::ptr_rdata(instance),
        );
        p.rr(Section::Additional, instance, TYPE_SRV, {
            move |q: &mut PktBuilder| q.rd_srv(port, host)
        });
        p.rr(
            Section::Additional,
            instance,
            TYPE_TXT,
            PktBuilder::rd_txt(entries),
        );
        p.rr(Section::Additional, host, TYPE_A, PktBuilder::rd_a(ip));
        p.build()
    }

    fn raop_device(
        instance: &str,
        host: &str,
        port: u16,
        ip: [u8; 4],
        entries: &[&str],
    ) -> Vec<u8> {
        let mut p = PktBuilder::new();
        p.rr(
            Section::Answer,
            "_raop._tcp.local",
            TYPE_PTR,
            PktBuilder::ptr_rdata(instance),
        );
        p.rr(Section::Additional, instance, TYPE_SRV, {
            move |q: &mut PktBuilder| q.rd_srv(port, host)
        });
        p.rr(
            Section::Additional,
            instance,
            TYPE_TXT,
            PktBuilder::rd_txt(entries),
        );
        p.rr(Section::Additional, host, TYPE_A, PktBuilder::rd_a(ip));
        p.build()
    }

    fn available_cb() -> (Rc<RefCell<Vec<RaopDeviceInfo>>>, FoundFn) {
        let fired = Rc::new(RefCell::new(Vec::new()));
        let fired2 = Rc::clone(&fired);
        (
            fired,
            Box::new(move |info| fired2.borrow_mut().push(info.clone())),
        )
    }

    #[test]
    fn query_packet_is_exactly_the_cxx_packet() {
        let pkt = build_query_packet();
        let mut expect = Vec::new();
        expect.extend_from_slice(&[0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0]);
        for n in ["_airplay._tcp.local", "_raop._tcp.local"] {
            for label in n.split('.') {
                expect.push(label.len() as u8);
                expect.extend_from_slice(label.as_bytes());
            }
            expect.push(0);
            expect.extend_from_slice(&[0, TYPE_PTR as u8, 0, TYPE_IN as u8]);
        }
        assert_eq!(pkt, expect);
    }

    #[test]
    fn discovers_airplay2_device_and_derives_happin() {
        let (fired, cb) = available_cb();
        let b = MdnsBrowser::new().unwrap();
        b.query(cb);
        b.handle_packet(&airplay_device(
            "Alice._airplay._tcp.local",
            "alice.local",
            7000,
            [10, 0, 1, 5],
            &[
                "deviceid=AA:BB:CC:DD:EE:FF",
                "am=AppleTV5,3",
                "flags=0x44",
                "sf",
                "pw=false",
            ],
        ));
        let fired = fired.borrow();
        assert_eq!(fired.len(), 1);
        let info = &fired[0];
        assert_eq!(info.name, "Alice");
        assert_eq!(info.host, "10.0.1.5");
        assert_eq!(info.port, 7000);
        assert_eq!(info.device_id, "AA:BB:CC:DD:EE:FF");
        assert_eq!(info.model, "AppleTV5,3");
        assert!(info.airplay2);
        assert_eq!(info.auth, Auth::HapPin);
        assert_eq!(info.txt.get("sf"), Some(&String::new()));
        assert_eq!(info.txt.get("flags"), Some(&"0x44".to_string()));
        assert_eq!(b.known_count(), 1);
    }

    #[test]
    fn reannouncement_refreshes_without_refiring() {
        let (fired, cb) = available_cb();
        let b = MdnsBrowser::new().unwrap();
        b.query(cb);
        b.handle_packet(&airplay_device(
            "Alice._airplay._tcp.local",
            "alice.local",
            7000,
            [10, 0, 1, 5],
            &["deviceid=AA:BB:CC:DD:EE:FF", "am=AppleTV5,3"],
        ));
        assert_eq!(fired.borrow().len(), 1);
        b.handle_packet(&airplay_device(
            "Alice._airplay._tcp.local",
            "alice.local",
            7100,
            [10, 0, 1, 6],
            &["deviceid=DIFFERENT", "am=iOS"],
        ));
        assert_eq!(fired.borrow().len(), 1, "re-announcement must not re-fire");
        // host/port/txt are refreshed; name/deviceId/model are not (they
        // identify the receiver and come from the first announcement).
        let known = b.known.borrow();
        let info = known.get("Alice").unwrap();
        assert_eq!(info.host, "10.0.1.6");
        assert_eq!(info.port, 7100);
        assert_eq!(info.txt.get("am"), Some(&"iOS".to_string()));
        assert_eq!(info.device_id, "AA:BB:CC:DD:EE:FF");
        assert_eq!(info.model, "AppleTV5,3");
    }

    #[test]
    fn raop_then_airplay_upgrade_refires_with_auth_change() {
        let (fired, cb) = available_cb();
        let b = MdnsBrowser::new().unwrap();
        b.query(cb);
        // Legacy RAOP with pw=true -> Password.
        b.handle_packet(&raop_device(
            "Bob._raop._tcp.local",
            "bobhost.local",
            5000,
            [10, 0, 1, 6],
            &["pw=true", "am=AirPort4,2"],
        ));
        assert_eq!(fired.borrow().len(), 1);
        assert_eq!(fired.borrow()[0].auth, Auth::Password);
        assert!(!fired.borrow()[0].airplay2);

        // Same instance now advertised under _airplay -> upgrade re-fire.
        b.handle_packet(&airplay_device(
            "Bob._airplay._tcp.local",
            "bobhost.local",
            7000,
            [10, 0, 1, 6],
            &["pw=true"],
        ));
        let fired = fired.borrow();
        assert_eq!(fired.len(), 2);
        assert!(fired[1].airplay2);
        assert_eq!(fired[1].auth, Auth::HapPin);
        assert_eq!(fired[1].port, 7000);
        assert_eq!(b.known_count(), 1);
    }

    #[test]
    fn two_devices_in_one_packet_both_fire_in_order() {
        let (fired, cb) = available_cb();
        let b = MdnsBrowser::new().unwrap();
        b.query(cb);
        let mut p = PktBuilder::new();
        p.rr(
            Section::Answer,
            "_airplay._tcp.local",
            TYPE_PTR,
            PktBuilder::ptr_rdata("A._airplay._tcp.local"),
        );
        // Second PTR: same owner name -> must come out as a compression
        // pointer to the first one (exercises the pointer path).
        p.rr(
            Section::Answer,
            "_airplay._tcp.local",
            TYPE_PTR,
            PktBuilder::ptr_rdata("B._airplay._tcp.local"),
        );
        p.rr(Section::Additional, "A._airplay._tcp.local", TYPE_SRV, {
            |q| q.rd_srv(7000, "a.local")
        });
        p.rr(
            Section::Additional,
            "A._airplay._tcp.local",
            TYPE_TXT,
            PktBuilder::rd_txt(&["deviceid=11"]),
        );
        p.rr(
            Section::Additional,
            "a.local",
            TYPE_A,
            PktBuilder::rd_a([10, 0, 0, 1]),
        );
        p.rr(Section::Additional, "B._airplay._tcp.local", TYPE_SRV, {
            |q| q.rd_srv(7001, "b.local")
        });
        p.rr(
            Section::Additional,
            "B._airplay._tcp.local",
            TYPE_TXT,
            PktBuilder::rd_txt(&["deviceid=22"]),
        );
        p.rr(
            Section::Additional,
            "b.local",
            TYPE_A,
            PktBuilder::rd_a([10, 0, 0, 2]),
        );
        b.handle_packet(&p.build());
        let fired = fired.borrow();
        assert_eq!(fired.len(), 2);
        assert_eq!(fired[0].name, "A");
        assert_eq!(fired[0].device_id, "11");
        assert_eq!(fired[1].name, "B");
        assert_eq!(fired[1].device_id, "22");
    }

    #[test]
    fn a_record_with_wrong_rdlength_is_skipped() {
        let (fired, cb) = available_cb();
        let b = MdnsBrowser::new().unwrap();
        b.query(cb);
        let mut p = PktBuilder::new();
        p.rr(
            Section::Answer,
            "_airplay._tcp.local",
            TYPE_PTR,
            PktBuilder::ptr_rdata("A._airplay._tcp.local"),
        );
        p.rr(Section::Additional, "A._airplay._tcp.local", TYPE_SRV, {
            |q| q.rd_srv(7000, "a.local")
        });
        p.rr(
            Section::Additional,
            "a.local",
            TYPE_A,
            PktBuilder::rd_a([10, 0, 0, 1]),
        );
        // Corrupt the A record's rdlength from 4 to 3 (its two bytes sit
        // directly before the 4 rdata bytes at the end of the packet).
        let mut bytes = p.build();
        let n = bytes.len();
        bytes[n - 6] = 0;
        bytes[n - 5] = 3;
        b.handle_packet(&bytes);
        assert_eq!(
            fired.borrow().len(),
            0,
            "rdlength 3 A record must be skipped"
        );
    }

    #[test]
    fn question_section_is_skipped_past() {
        let (fired, cb) = available_cb();
        let b = MdnsBrowser::new().unwrap();
        b.query(cb);
        // A probe-response shape: 1 question + the records (responders echo
        // both their own query and the answers).
        let mut p = PktBuilder::new();
        p.bytes[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount = 1
        for label in "_airplay._tcp.local".split('.') {
            p.bytes.push(label.len() as u8);
            p.bytes.extend_from_slice(label.as_bytes());
        }
        p.bytes.push(0);
        p.bytes.extend_from_slice(&TYPE_PTR.to_be_bytes());
        p.bytes.extend_from_slice(&TYPE_IN.to_be_bytes());
        p.rr(
            Section::Answer,
            "_airplay._tcp.local",
            TYPE_PTR,
            PktBuilder::ptr_rdata("Q._airplay._tcp.local"),
        );
        p.rr(Section::Additional, "Q._airplay._tcp.local", TYPE_SRV, {
            |q| q.rd_srv(7000, "q.local")
        });
        p.rr(
            Section::Additional,
            "q.local",
            TYPE_A,
            PktBuilder::rd_a([10, 0, 0, 9]),
        );
        b.handle_packet(&p.build());
        assert_eq!(fired.borrow().len(), 1);
        assert_eq!(fired.borrow()[0].name, "Q");
    }

    #[test]
    fn malformed_packets_are_dropped_without_panic() {
        let (fired, cb) = available_cb();
        let b = MdnsBrowser::new().unwrap();
        b.query(cb);
        for junk in [
            vec![],                                                  // no header
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],                // empty header
            vec![0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0xC0],          // pointer truncated
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, b'a', b'b'], // name past end
        ] {
            b.handle_packet(&junk);
        }
        assert_eq!(fired.borrow().len(), 0);
    }

    #[test]
    fn truncated_txt_entry_is_a_soft_stop() {
        // "1=X" then a truncated entry (claims 5 bytes, only 2 follow).
        let rdata = [3, b'1', b'=', b'X', 5, b'a', b'b'];
        let txt = parse_txt(&rdata);
        assert_eq!(txt.len(), 1, "truncated entry stops the walk, keeps prior");
        assert_eq!(txt.get("1"), Some(&"X".to_string()));
    }

    #[test]
    fn txt_keys_merge_first_wins() {
        // Within one record and across records, the first value for a key
        // wins (C++ `emplace` / `std::map::insert` semantics).
        let a = parse_txt(&[
            4, b'a', b'=', b'1', b'x', 3, b'a', b'=', b'2', 2, b's', b'f',
        ]);
        let b = parse_txt(&[3, b'a', b'=', b'9', 1, b'k']);
        let mut merged = a.clone();
        for (k, v) in b {
            merged.entry(k).or_insert(v);
        }
        assert_eq!(
            merged.get("a"),
            Some(&"1x".to_string()),
            "first wins across records"
        );
        assert_eq!(merged.get("sf"), Some(&String::new()));
        assert_eq!(merged.get("k"), Some(&String::new()));
    }

    #[test]
    fn unknown_service_or_class_is_ignored() {
        let (fired, cb) = available_cb();
        let b = MdnsBrowser::new().unwrap();
        b.query(cb);
        let mut p = PktBuilder::new();
        // PTR for an unknown service.
        p.rr(
            Section::Answer,
            "_http._tcp.local",
            TYPE_PTR,
            PktBuilder::ptr_rdata("web._http._tcp.local"),
        );
        p.rr(Section::Additional, "web._http._tcp.local", TYPE_SRV, {
            |q| q.rd_srv(80, "w.local")
        });
        p.rr(
            Section::Additional,
            "w.local",
            TYPE_A,
            PktBuilder::rd_a([10, 0, 0, 3]),
        );
        b.handle_packet(&p.build());
        assert_eq!(fired.borrow().len(), 0);
    }

    #[test]
    fn srv_missing_from_packet_skips_device() {
        let (fired, cb) = available_cb();
        let b = MdnsBrowser::new().unwrap();
        b.query(cb);
        let mut p = PktBuilder::new();
        p.rr(
            Section::Answer,
            "_airplay._tcp.local",
            TYPE_PTR,
            PktBuilder::ptr_rdata("N._airplay._tcp.local"),
        );
        p.rr(
            Section::Additional,
            "N._airplay._tcp.local",
            TYPE_TXT,
            PktBuilder::rd_txt(&["deviceid=1"]),
        );
        p.rr(
            Section::Additional,
            "n.local",
            TYPE_A,
            PktBuilder::rd_a([10, 0, 0, 4]),
        );
        b.handle_packet(&p.build());
        assert_eq!(fired.borrow().len(), 0, "no SRV -> skip (C++ semantics)");
    }

    #[test]
    fn txt_only_for_other_instances_is_ignored() {
        let (fired, cb) = available_cb();
        let b = MdnsBrowser::new().unwrap();
        b.query(cb);
        let mut p = PktBuilder::new();
        p.rr(
            Section::Answer,
            "_airplay._tcp.local",
            TYPE_PTR,
            PktBuilder::ptr_rdata("Mine._airplay._tcp.local"),
        );
        p.rr(Section::Additional, "Mine._airplay._tcp.local", TYPE_SRV, {
            |q| q.rd_srv(7000, "m.local")
        });
        p.rr(
            Section::Additional,
            "Other._airplay._tcp.local",
            TYPE_TXT,
            PktBuilder::rd_txt(&["deviceid=EVIL"]),
        );
        p.rr(
            Section::Additional,
            "m.local",
            TYPE_A,
            PktBuilder::rd_a([10, 0, 0, 7]),
        );
        b.handle_packet(&p.build());
        let fired = fired.borrow();
        assert_eq!(fired.len(), 1);
        assert_eq!(
            fired[0].device_id, "",
            "TXT from another instance must not leak in"
        );
    }

    #[test]
    fn derive_auth_mapping() {
        let mut txt = BTreeMap::new();
        assert_eq!(derive_auth(false, &txt), Auth::None);
        assert_eq!(derive_auth(true, &txt), Auth::HapPin);
        txt.insert("pw".into(), "false".into());
        assert_eq!(derive_auth(false, &txt), Auth::None);
        txt.insert("pw".into(), "true".into());
        assert_eq!(derive_auth(false, &txt), Auth::Password);
        txt.insert("pw".into(), "1".into());
        assert_eq!(derive_auth(false, &txt), Auth::Password);
        txt.insert("pw".into(), "2".into());
        txt.insert("am".into(), "AirPort4,2".into());
        assert_eq!(derive_auth(false, &txt), Auth::AuthSetup);
        txt.insert("am".into(), "SomethingElse".into());
        assert_eq!(derive_auth(false, &txt), Auth::None);
        // AirPlay 2 wins over pw (C++ checks airplay2 first).
        txt.insert("pw".into(), "1".into());
        assert_eq!(derive_auth(true, &txt), Auth::HapPin);
    }

    /// Live smoke test of the real socket path (bind 0.0.0.0:5353, join the
    /// multicast group, TTL 255, nonblocking, poll/recv loop). Kept
    /// `#[ignore]` for CI because port 5353 may be held by another
    /// responder; run with `cargo test -- --ignored` on a dev box.
    #[test]
    #[ignore]
    fn live_socket_round_trip() {
        let b = MdnsBrowser::new().expect("socket, bind and join must succeed");
        assert_eq!(b.known_count(), 0);
        let (fired, cb) = available_cb();
        // Feed a synthetic announcement straight into the packet handler
        // while poll() drains the (empty) socket.
        b.query(cb);
        b.handle_packet(&airplay_device(
            "Live._airplay._tcp.local",
            "live.local",
            7000,
            [10, 0, 0, 50],
            &["deviceid=AA:BB:CC:DD:EE:FF"],
        ));
        b.poll(0);
        assert_eq!(fired.borrow().len(), 1);
        assert_eq!(b.known_count(), 1);
    }
}
