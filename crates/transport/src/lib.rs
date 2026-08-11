// SPDX-License-Identifier: Apache-2.0
#![deny(unsafe_code)]
//! The network + timer abstraction a RAOP sender talks to.
//!
//! Rust 2024 migration of [`src/transport.h`](../../src/transport.h), the
//! `ITransport` interface. Everything is callback-driven (asio/libuv shape),
//! so it maps onto a bare `poll()` loop or any event loop. The whole host
//! integration is:
//!
//! ```no_run
//! use transport::Transport;
//! # fn demo<T: Transport>(io: &T, running: &std::sync::atomic::AtomicBool) {
//! while running.load(std::sync::atomic::Ordering::Relaxed) {
//!     io.poll(16); // <- this line IS the event loop
//! }
//! # }
//! ```
//!
//! # Contract
//!
//! * `Handle`s and `TimerId`s are opaque ids allocated by the transport.
//!   The C++ `kInvalid == -1` sentinel is replaced by `Option` (an explicit,
//!   safer translation of the same contract).
//! * All callbacks fire synchronously from inside [`Transport::poll`],
//!   never from a background thread.
//! * For a connected TCP socket, exactly one of the `on_connected` /
//!   `on_closed` callbacks fires (from `poll()`), and never before
//!   `tcp_connect` has returned its handle.
//! * After `on_closed` fires, the handle is dead; `close` on it is a no-op.
//! * Re-entrancy: a callback may call `send` / `send_to` / `close` /
//!   `every` / `after` / `cancel` on the same transport while `poll()` is
//!   dispatching it — the operations the sender actually relies on. The
//!   C++ header documents the same set; what was undefined behavior in C++
//!   (e.g. calling `poll()` nested, or `close()` on the socket whose
//!   `on_closed` is currently firing while `poll()` is still dispatching
//!   that socket) panics or is a defined no-op here.
//! * Single-threaded, non-reentrant-by-design: construct one transport,
//!   call `poll()` from one thread. All methods take `&self` and the
//!   implementations use interior mutability so that re-entrant calls from
//!   callbacks are safe Rust.
//!
//! Scope (inherited from the C++ header): the default adapter is IPv4-only
//! for UDP and single-threaded; that covers every AirPlay receiver on a
//! home LAN.

use std::fmt;

/// Opaque per-socket id (C++ `ITransport::Handle`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Handle(u32);

impl Handle {
    /// Create a handle from its raw id. Transports allocate ids internally.
    pub fn from_raw(raw: u32) -> Handle {
        Handle(raw)
    }

    /// The raw id.
    pub fn as_raw(self) -> u32 {
        self.0
    }
}

/// Opaque timer id, returned by [`Transport::every`] / [`Transport::after`]
/// for [`Transport::cancel`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TimerId(u32);

impl TimerId {
    /// Create a timer id from its raw id.
    pub fn from_raw(raw: u32) -> TimerId {
        TimerId(raw)
    }

    /// The raw id.
    pub fn as_raw(self) -> u32 {
        self.0
    }
}

/// TCP connect completed (the socket is usable now).
pub type ConnectFn = Box<dyn Fn()>;

/// Fired once per successful read: `data` holds the bytes. For a
/// `udp_bind` handle, `from_host`/`from_port` name the sender of that one
/// datagram; for a `tcp_connect` handle they are always `""`/`0` (the peer
/// is fixed). (C++ `DataFn`.)
pub type DataFn = Box<dyn Fn(&[u8], &str, u16)>;

/// TCP connection ended — peer close, a connect()/read()/write() error, or
/// (indirectly) a timeout. `reason` is a short human string for logs,
/// empty for a plain graceful close. The handle is dead after this fires.
/// (C++ `ClosedFn`.)
pub type ClosedFn = Box<dyn Fn(&str)>;

/// A repeating or one-shot timer callback. (C++ `TimerFn`.)
pub type TimerFn = Box<dyn Fn()>;

/// The callback-driven network + timer abstraction (C++ `ITransport`).
///
/// See the module docs for the full contract (callback timing, handle
/// lifetime, re-entrancy).
pub trait Transport {
    /// Begin a TCP connection to `host`:`port` (`host` may be a literal
    /// IPv4/IPv6 address or a hostname; DNS, if needed, happens
    /// synchronously inside this call). Returns `None` immediately on a
    /// synchronous failure (bad address, out of sockets, ...) with no
    /// callback fired; otherwise returns a live handle and exactly one of
    /// `on_connected` / `on_closed` fires later from `poll()`.
    ///
    /// Note: even a connection that completes synchronously (e.g. to
    /// localhost) reports itself through `on_connected` on a later
    /// `poll()`, never before this call returns (C++ parity).
    fn tcp_connect(
        &self,
        host: &str,
        port: u16,
        on_connected: ConnectFn,
        on_data: DataFn,
        on_closed: ClosedFn,
    ) -> Option<Handle>;

    /// Bind a local UDP socket (ephemeral port if `port == 0`) that can
    /// both `send_to` any destination and receive from anyone (`on_data`
    /// per datagram). Returns `None` on a synchronous bind failure.
    fn udp_bind(&self, port: u16, on_data: DataFn) -> Option<Handle>;

    /// The local port bound for `h` (needed to advertise control/timing
    /// ports in SETUP). `None` if the handle is unknown or the query
    /// failed (C++ returned 0/`""` — the `Option` is an explicit mapping).
    fn local_port(&self, h: Handle) -> Option<u16>;

    /// The local address bound for `h`. `None` if unknown/failed.
    fn local_address(&self, h: Handle) -> Option<String>;

    /// The peer address for a TCP handle. `None` for unknown handles or
    /// connections without a peer (C++ returned `""`).
    fn peer_address(&self, h: Handle) -> Option<String>;

    /// TCP stream write. Blocks (internally, via a bounded poll-for-
    /// writable loop) until every byte is handed to the OS or a hard
    /// error/timeout occurs. Returns `false` on failure. Bytes are in the
    /// kernel's socket buffer by the time it returns `true`.
    fn send(&self, h: Handle, data: &[u8]) -> bool;

    /// UDP: one datagram to an arbitrary destination. Returns `false` on a
    /// hard failure (unknown handle, unparseable/unreachable address).
    fn send_to(&self, h: Handle, host: &str, port: u16, data: &[u8]) -> bool;

    /// Tear the socket down now (no linger, no goodbye packet beyond
    /// whatever the last `send` already delivered). Safe to call on a
    /// handle whose `on_closed` already fired (a no-op then).
    fn close(&self, h: Handle);

    /// Recurring timer (fires every `ms`, best-effort, from inside
    /// `poll()`). Returns an id for `cancel`.
    fn every(&self, ms: u32, f: TimerFn) -> TimerId;

    /// One-shot timer (fires once, ~`ms` from now, then forgets itself).
    fn after(&self, ms: u32, f: TimerFn) -> TimerId;

    /// Cancel an `every`/`after` timer. A no-op on an id that already
    /// fired (one-shot) or was already cancelled.
    fn cancel(&self, id: TimerId);

    /// Pump: wait up to `timeout_ms` (less if a timer is due sooner) for
    /// socket I/O, dispatch whatever fired (connects, data, closes,
    /// timers), then return. The host's entire main loop is a call to this
    /// in a loop.
    fn poll(&self, timeout_ms: i32);
}

/// A no-op transport recording every call, for tests and fakes.
///
/// Every operation succeeds trivially (handles are allocated, sends are
/// "delivered"), and no callback is ever fired — behave deterministically.
/// Use it anywhere a `Transport` must exist but no I/O should happen.
#[derive(Default)]
pub struct NullTransport {
    next: std::cell::Cell<u32>,
}

impl Transport for NullTransport {
    fn tcp_connect(
        &self,
        _host: &str,
        _port: u16,
        _on_connected: ConnectFn,
        _on_data: DataFn,
        _on_closed: ClosedFn,
    ) -> Option<Handle> {
        self.alloc()
    }

    fn udp_bind(&self, _port: u16, _on_data: DataFn) -> Option<Handle> {
        self.alloc()
    }

    fn local_port(&self, h: Handle) -> Option<u16> {
        Some((h.as_raw() % 65535) as u16)
    }

    fn local_address(&self, h: Handle) -> Option<String> {
        Some(format!("127.0.0.{}", (h.as_raw() % 254) + 1))
    }

    fn peer_address(&self, h: Handle) -> Option<String> {
        Some(format!("192.168.0.{}", (h.as_raw() % 254) + 1))
    }

    fn send(&self, _h: Handle, _data: &[u8]) -> bool {
        true
    }

    fn send_to(&self, _h: Handle, _host: &str, _port: u16, _data: &[u8]) -> bool {
        true
    }

    fn close(&self, _h: Handle) {}

    fn every(&self, _ms: u32, _f: TimerFn) -> TimerId {
        TimerId::from_raw(0)
    }

    fn after(&self, _ms: u32, _f: TimerFn) -> TimerId {
        TimerId::from_raw(0)
    }

    fn cancel(&self, _id: TimerId) {}

    fn poll(&self, _timeout_ms: i32) {}
}

impl NullTransport {
    fn alloc(&self) -> Option<Handle> {
        let n = self.next.get();
        self.next.set(n + 1);
        Some(Handle::from_raw(n + 1))
    }
}

impl fmt::Debug for NullTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NullTransport")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_transport_allocates_handles_and_accepts_callbacks() {
        let t = NullTransport::default();
        let h = t.tcp_connect(
            "127.0.0.1",
            7000,
            Box::new(|| {}),
            Box::new(|_, _, _| {}),
            Box::new(|_| {}),
        );
        assert!(h.is_some());
        assert_eq!(t.local_address(h.unwrap()), Some("127.0.0.2".into()));
    }

    #[test]
    fn callbacks_can_reenter_the_transport() {
        // The re-entrancy contract: a DataFn may call send/close/... on the
        // same transport. With an `&self`-method trait this compiles and
        // runs without borrow conflicts.
        let t = NullTransport::default();
        let h = t
            .udp_bind(0, Box::new(|_, _, _| {}))
            .expect("bind succeeds");
        let data: Vec<u8> = vec![1, 2, 3];
        let ok = t.send_to(h, "127.0.0.1", 7000, &data);
        assert!(ok);
        t.close(h);
    }

    #[test]
    fn ids_are_opaque_newtypes() {
        let a = Handle::from_raw(7);
        let b = Handle::from_raw(7);
        assert_eq!(a, b);
        assert_eq!(a.as_raw(), 7);
        assert_ne!(a, Handle::from_raw(8));
        assert_eq!(TimerId::from_raw(3), TimerId::from_raw(3));
    }
}
