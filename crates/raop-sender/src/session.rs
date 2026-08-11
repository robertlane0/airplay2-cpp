// SPDX-License-Identifier: Apache-2.0
//! The `RaopSender` state machine over the [`Transport`] trait — the
//! session slice of the [`src/raop_sender.cpp`](../../src/raop_sender.cpp)
//! migration.
//!
//! Everything here is the C++ class translated ownership-for-ownership:
//!
//! * `Session` is a handle (an `Rc<RefCell<SessionInner>>`); every public
//!   method runs one short borrow of the inner state, and the four host
//!   callbacks ([`Callbacks`]) fire only after the borrow is released, so
//!   a callback that re-enters the session (e.g. `stop()` from
//!   `on_closed`) can never deadlock or double-borrow.
//! * Transport callbacks and timers capture a `Weak` clone of the inner
//!   state (never a reference cycle).
//! * API and behavior mirror the C++ method-for-method: `start` /
//!   `stop`, the UDP trio bind then `tcp_connect`, `beginAuthChain_`
//!   (plain / password / auth-setup / legacy-PIN / HAP transient / HAP
//!   PIN), the `handleResponse_` dispatcher (digest 401 retry, non-fatal
//!   streaming-time RECORD/FLUSH failures), the pairing TLV dispatcher
//!   (`onPairingResponse_` incl. the 470 transient→PIN and 403
//!   pin-start→transient fallbacks), the AP2 flow (`GET /info` →
//!   session SETUP → event channel + RECORD → stream SETUP →
//!   streaming), `startStreaming_` (timeline anchor, 1 s sync, 8 ms
//!   pacer, 2 s AP2 / 25 s AP1 feedback, 0 dB AP2 default volume), the
//!   encrypted control + event channels, volume/metadata push, and the
//!   retransmit/timing UDP responders.
//!
//! ### Documented deviations from the C++
//!
//! * The ring buffer is attached as `Rc<RefCell<RingBuffer<i16>>>`
//!   (shared with the host) instead of a raw pointer; there is no null
//!   ring, the host passes the shared handle or leaves it unattached
//!   (silence).
//! * `Auth::NoAuth` is the C++ `Auth::None` (keyword).
//! * Random-number generation reports failure instead of producing
//!   indeterminate bytes: `start` fails with "Random-number failure
//!   starting a new session".
//! * `stop()` cancels the handshake watchdog *again* after the TEARDOWN
//!   send (a C++ zombie timer armed by a mid-pairing TEARDOWN could
//!   otherwise fire into the *next* session).
//! * No logging (the rest of the crate is also quiet); all
//!   observability-relevant outcomes surface through `Callbacks`.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::{Rc, Weak};
use std::time::Instant;

use transport::{Handle, TimerId, Transport};

use crate::input::{Resampler, target_frames};
use crate::pairing::{PairingError, PairingMode, PairingSession, TRANSIENT_PIN};
use crate::plists;
use crate::rtsp::{
    Ap2Channel, FrameError, RtspRequest, StatusKind, build_announce_sdp, build_ap2_feedback,
    build_ap2_rtsp, build_dmap_metadata, build_event_200_ok, build_http_post, build_rtp_info,
    build_rtsp_request, build_setup_transport, next_event_request, parse_digest_challenge,
    parse_response, parse_setup_transport_reply,
};
use crate::stream::{AudioStream, build_timing_reply};
use crate::util::{
    CHANNELS, FRAMES_PER_PACKET, HANDSHAKE_TIMEOUT_MS, LATENCY_FRAMES, MAX_PACKETS_PER_TICK,
    NO_VOLUME, PACER_MS, PIN_WAIT_TIMEOUT_MS, RAOP_RATE, encode_creds, fixed6, header_value,
    hex_upper_no_pad, ntp_now, ntp2ts, pct_to_dbfs, rand_u16, rand_u32, rand_u64, to_hex,
};

/// Which authentication the session uses (C++ `RaopSender::Auth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Auth {
    /// Plain (Phase-1) receiver, no auth (C++ `Auth::None`).
    #[default]
    NoAuth,
    /// RTSP digest (reactive: the first 401 arms the `Authorization`
    /// header).
    Password,
    /// MFiSAP one-shot `/auth-setup`.
    AuthSetup,
    /// Pre-HomeKit "Fruit" pairing (fails fast, unsupported).
    LegacyPin,
    /// HomePod / AP2, fixed-PIN 3939 transient pairing.
    HapTransient,
    /// Apple TV 4+, on-screen PIN (or stored credentials).
    HapPin,
}

/// Lifecycle state of a session (C++ `RaopSender::State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionState {
    #[default]
    Idle,
    Connecting,
    Pairing,
    Handshake,
    Streaming,
}

/// Exactly where the auth/pairing/AP2 handshake is (C++ `PairStage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PairStage {
    #[default]
    None,
    AuthSetup,
    PinStart,
    SetupM2,
    SetupM4,
    SetupM6,
    VerifyM2,
    VerifyDone,
    Ap2Info,
    Ap2Session,
    Ap2Record,
    Ap2Stream,
    /// Auth is done; only used transiently (the C++ uses `Done`).
    Done,
}

pub type LaunchedFn = Box<dyn Fn(bool, &str)>;
pub type CredentialsFn = Box<dyn Fn(&str, &str)>;

/// The host-facing event hooks (C++ `RaopSender::callbacks`). All fire
/// synchronously from inside [`Transport::poll`]-driven callbacks /
/// timers, never from a background thread, and never while the session's
/// inner state is borrowed.
pub struct Callbacks {
    /// `ok == true` with an empty error once streaming starts; `ok ==
    /// false` with a reason when the handshake or stream setup fails.
    pub on_launched: LaunchedFn,
    /// The session ended (after `fail_` or a graceful close). Fires on
    /// every terminal event, including the fail of a never-started
    /// session.
    pub on_closed: Box<dyn Fn()>,
    /// HAP PIN pairing needs the on-screen code (`deviceName`).
    pub on_pin_required: Box<dyn Fn(&str)>,
    /// HAP pairing completed; `deviceId` + credentials JSON to persist
    /// (`{"ltsk":…,"ltpk":…,"atvId":…,"clientId":…}`).
    pub on_credentials_obtained: CredentialsFn,
}

/// The session handle. Cheap to clone (an `Rc` around the inner state).
#[derive(Clone)]
pub struct Session {
    inner: Rc<RefCell<SessionInner>>,
}

/// The `auth-setup` request body: mode byte + a static Curve25519 public
/// key, exactly the C++ `kCurve25519Pub`.
pub const AUTH_SETUP_BODY: [u8; 33] = [
    0x01, 0x59, 0x02, 0xed, 0xe9, 0x0d, 0x4e, 0xf2, 0xbd, 0x4c, 0xb6, 0x8a, 0x63, 0x30, 0x03, 0x82,
    0x07, 0xa9, 0x4d, 0xbd, 0x50, 0xd8, 0xaa, 0x46, 0x5b, 0x5d, 0x8c, 0x01, 0x2a, 0x0c, 0x7e, 0x1d,
    0x4e,
];

/// User callbacks deferred until the session's inner borrow is released
/// (re-entrancy safety).
enum Deferred {
    Launched(bool, String),
    Closed,
    PinRequired(String),
    CredentialsObtained(String, String),
}

/// The AP2 half of a session (C++ `RaopAp2State`).
struct Ap2State {
    session: PairingSession,
    /// Session-level SETUP uuid (C++ `sessionUuid`; the stream
    /// `streamConnectionID` is our numeric RTSP session id).
    session_uuid: String,
}

struct SessionInner {
    transport: Rc<dyn Transport>,
    callbacks: Callbacks,
    /// Back-reference for timers/transport callbacks (never a cycle).
    me: Weak<RefCell<SessionInner>>,

    host: String,
    name: String,

    session_id: u32,
    dacp_id: String,
    active_remote: u32,
    cseq: u32,

    auth_method: Auth,
    airplay2: bool,
    device_id: String,
    creds_json: String,
    digest_password: String,
    digest_realm: String,
    digest_nonce: String,
    digest_retried: bool,

    state: SessionState,
    pair_stage: PairStage,
    waiting_for_pin: bool,
    tried_transient_after_pin403: bool,

    rtsp: Option<Handle>,
    rtsp_connected: bool,
    audio: Option<Handle>,
    control: Option<Handle>,
    timing: Option<Handle>,
    event: Option<Handle>,

    pacer_timer: Option<TimerId>,
    sync_timer: Option<TimerId>,
    handshake_timer: Option<TimerId>,
    pin_timer: Option<TimerId>,
    feedback_timer: Option<TimerId>,

    rx_buf: Vec<u8>,
    pending_methods: VecDeque<String>,
    pending_is_http: VecDeque<bool>,
    control_channel: Ap2Channel,
    event_channel: Ap2Channel,
    event_plain_buf: Vec<u8>,

    rtsp_session: String,
    server_port: u16,
    control_port: u16,
    timing_port: u16,
    event_port: u16,

    ring: Option<Rc<RefCell<ring_buffer::RingBuffer<i16>>>>,
    resampler: Resampler,
    stream: AudioStream,
    clock_start: Option<Instant>,

    pending_volume_db: f64,

    np_title: String,
    np_artist: String,
    np_album: String,
    np_cover: Vec<u8>,
    np_cover_mime: String,

    ap2: Option<Ap2State>,
}

impl Session {
    /// A fresh idle session bound to `transport`.
    pub fn new(transport: Rc<dyn Transport>, callbacks: Callbacks) -> Session {
        let inner = Rc::new(RefCell::new(SessionInner::new(transport, callbacks)));
        inner.borrow_mut().me = Rc::downgrade(&inner);
        Session { inner }
    }

    /// Attach the input ring the pacer pulls PCM from (C++
    /// `attachRing`). The host writes interleaved s16 into the same
    /// `Rc`; unattached sessions stream silence.
    pub fn attach_ring(&self, ring: Rc<RefCell<ring_buffer::RingBuffer<i16>>>) {
        self.with_inner(|g| {
            g.ring = Some(ring);
            vec![]
        });
    }

    /// Device input rate (C++ `setInputFormat`): 0 = no device open
    /// yet, which resamples as 48000 like the WASAPI default.
    pub fn set_input_format(&self, sample_rate: u32) {
        self.with_inner(|g| {
            g.resampler.set_input_format(sample_rate);
            vec![]
        });
    }

    /// Configure the session's auth (C++ `setAuth`).
    pub fn set_auth(
        &self,
        auth: Auth,
        airplay2: bool,
        device_id: &str,
        creds_json: &str,
        password: &str,
    ) {
        self.with_inner(|g| {
            g.auth_method = auth;
            g.airplay2 = airplay2;
            g.device_id = device_id.to_string();
            g.creds_json = creds_json.to_string();
            g.digest_password = password.to_string();
            vec![]
        });
    }

    /// Connect + handshake + stream (C++ `start`). One session at a
    /// time; `host` must be a numeric IP (used for the TCP control
    /// connection and every UDP `send_to`).
    pub fn start(&self, host: &str, port: u16, name: &str) {
        self.with_inner(|g| g.start(host, port, name));
    }

    /// End the session: TEARDOWN, close, timers cancelled (C++ `stop`).
    pub fn stop(&self) {
        self.with_inner(|g| {
            g.stop();
            vec![]
        });
    }

    /// Whether a session is currently up (C++ `active`).
    pub fn active(&self) -> bool {
        self.inner.borrow().state != SessionState::Idle
    }

    /// Whether the session is waiting for the user to enter the
    /// on-screen PIN (C++ `waitingForPin`).
    pub fn waiting_for_pin(&self) -> bool {
        self.inner.borrow().waiting_for_pin
    }

    /// Supply the on-screen PIN the user typed (C++ `submitPin`).
    pub fn submit_pin(&self, code: &str) {
        self.with_inner(|g| g.submit_pin(code));
    }

    /// Receiver volume 0..100 % → dBFS (C++ `setVolume`). Stored when
    /// not streaming and pushed at RECORD / stream start.
    pub fn set_volume(&self, pct: f64) {
        self.with_inner(|g| {
            let pct = pct.clamp(0.0, 100.0);
            let db = pct_to_dbfs(pct);
            g.pending_volume_db = db;
            if g.state == SessionState::Streaming {
                g.send_volume();
            }
            vec![]
        });
    }

    /// Now-playing metadata (C++ `setNowPlaying`); pushed immediately
    /// while streaming, stored and pushed at RECORD otherwise. `cover`
    /// is raw image bytes (empty = none), `cover_mime` defaults to
    /// `image/jpeg` when `cover` is non-empty.
    pub fn set_now_playing(
        &self,
        title: &str,
        artist: &str,
        album: &str,
        cover: &[u8],
        cover_mime: &str,
    ) {
        self.with_inner(|g| {
            let changed = title != g.np_title
                || artist != g.np_artist
                || album != g.np_album
                || cover != g.np_cover
                || cover_mime != g.np_cover_mime;
            g.np_title = title.to_string();
            g.np_artist = artist.to_string();
            g.np_album = album.to_string();
            g.np_cover = cover.to_vec();
            g.np_cover_mime = cover_mime.to_string();
            if g.state == SessionState::Streaming && changed {
                g.send_metadata();
            }
            vec![]
        });
    }

    #[cfg(test)]
    pub(crate) fn state_for_test(&self) -> SessionState {
        self.inner.borrow().state
    }

    /// The derived control-channel keys (test hook: lets tests speak the
    /// encrypted channel the machine is actually using).
    #[cfg(test)]
    pub(crate) fn control_keys_for_test(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let g = self.inner.borrow();
        let a = g.ap2.as_ref()?;
        Some((a.session.control_in.clone(), a.session.control_out.clone()))
    }

    /// Rewind the streaming clock so the next pacer/sync tick is
    /// deterministic in tests (the timers never fire by themselves).
    #[cfg(test)]
    pub(crate) fn backdate_clock_for_test(&self, back: std::time::Duration) {
        let mut g = self.inner.borrow_mut();
        let base = g.clock_start.get_or_insert(std::time::Instant::now());
        *base = base.checked_sub(back).unwrap_or(*base);
    }

    fn with_inner<F>(&self, f: F)
    where
        F: FnOnce(&mut SessionInner) -> Vec<Deferred>,
    {
        let evs = {
            let mut g = self.inner.borrow_mut();
            f(&mut g)
        };
        self.fire(evs);
    }

    fn fire(&self, evs: Vec<Deferred>) {
        if evs.is_empty() {
            return;
        }
        // Callbacks may re-enter ANY public `Session` method (the C++
        // demo blocks inside `on_pin_required` and calls `submit_pin`),
        // so they must run with no `inner` borrow held at all. Swap the
        // callbacks out for no-ops under one short borrow, run, swap
        // back.
        let cbs = {
            let mut g = self.inner.borrow_mut();
            std::mem::replace(&mut g.callbacks, Callbacks::default())
        };
        cbs.fire_one(evs);
        let mut g = self.inner.borrow_mut();
        g.callbacks = cbs;
    }
}

impl Default for Callbacks {
    /// No-op hooks; used while the real callbacks are swapped out during
    /// [`Session::fire`] and the `dispatch` helper (and as a placeholder
    /// default).
    fn default() -> Self {
        Callbacks {
            on_launched: Box::new(|_, _| {}),
            on_closed: Box::new(|| {}),
            on_pin_required: Box::new(|_| {}),
            on_credentials_obtained: Box::new(|_, _| {}),
        }
    }
}

impl Callbacks {
    fn fire_one(&self, evs: Vec<Deferred>) {
        for e in evs {
            match e {
                Deferred::Launched(ok, why) => (self.on_launched)(ok, &why),
                Deferred::Closed => (self.on_closed)(),
                Deferred::PinRequired(name) => (self.on_pin_required)(&name),
                Deferred::CredentialsObtained(id, creds) => {
                    (self.on_credentials_obtained)(&id, &creds)
                }
            }
        }
    }
}

/// Run `f` on the inner state guarded by the `RefCell` (no-op once the
/// session is dropped) and fire any deferred callbacks after the borrow.
/// Cancel a session timer (a free function so calls like
/// `stop_timer(&*self.transport, &mut self.pacer_timer)` don't double-borrow
/// `self`).
fn stop_timer(transport: &dyn Transport, id: &mut Option<TimerId>) {
    if let Some(t) = id.take() {
        transport.cancel(t);
    }
}

fn dispatch(me: &Weak<RefCell<SessionInner>>, f: impl FnOnce(&mut SessionInner) -> Vec<Deferred>) {
    let Some(s) = me.upgrade() else { return };
    let evs = {
        let mut g = s.borrow_mut();
        f(&mut g)
    };
    if evs.is_empty() {
        return;
    }
    let mut g = s.borrow_mut();
    let cbs = std::mem::replace(&mut g.callbacks, Callbacks::default());
    drop(g);
    cbs.fire_one(evs);
    let mut g = s.borrow_mut();
    g.callbacks = cbs;
}

impl SessionInner {
    fn new(transport: Rc<dyn Transport>, callbacks: Callbacks) -> Self {
        SessionInner {
            transport,
            callbacks,
            me: Weak::new(),
            host: String::new(),
            name: String::new(),
            session_id: 0,
            dacp_id: String::new(),
            active_remote: 0,
            cseq: 0,
            auth_method: Auth::NoAuth,
            airplay2: false,
            device_id: String::new(),
            creds_json: String::new(),
            digest_password: String::new(),
            digest_realm: String::new(),
            digest_nonce: String::new(),
            digest_retried: false,
            state: SessionState::Idle,
            pair_stage: PairStage::None,
            waiting_for_pin: false,
            tried_transient_after_pin403: false,
            rtsp: None,
            rtsp_connected: false,
            audio: None,
            control: None,
            timing: None,
            event: None,
            pacer_timer: None,
            sync_timer: None,
            handshake_timer: None,
            pin_timer: None,
            feedback_timer: None,
            rx_buf: Vec::new(),
            pending_methods: VecDeque::new(),
            pending_is_http: VecDeque::new(),
            control_channel: Ap2Channel::plain(),
            event_channel: Ap2Channel::plain(),
            event_plain_buf: Vec::new(),
            rtsp_session: String::new(),
            server_port: 0,
            control_port: 0,
            timing_port: 0,
            event_port: 0,
            ring: None,
            resampler: Resampler::new(),
            stream: AudioStream::new(0, 0),
            clock_start: None,
            pending_volume_db: NO_VOLUME,
            np_title: String::new(),
            np_artist: String::new(),
            np_album: String::new(),
            np_cover: Vec::new(),
            np_cover_mime: String::new(),
            ap2: None,
        }
    }

    // ── session lifecycle ──────────────────────────────────────────────

    fn start(&mut self, host: &str, port: u16, name: &str) -> Vec<Deferred> {
        self.stop();
        self.host = host.to_string();
        self.name = name.to_string();

        // Fresh session identity (C++ start(): random session id used as
        // the RTSP URI path AND the RTP SSRC; DACP-ID / Active-Remote
        // identify us to remote-control-capable receivers).
        let (Ok(session_id), Ok(dacp_rand), Ok(active_remote), Ok(seq)) =
            (rand_u32(), rand_u64(), rand_u32(), rand_u16())
        else {
            return self.fail_("Random-number failure starting a new session");
        };
        self.session_id = session_id;
        self.dacp_id = hex_upper_no_pad(dacp_rand);
        self.active_remote = active_remote;
        self.cseq = 0;
        self.stream = AudioStream::new(session_id, seq);
        self.rx_buf.clear();
        self.control_channel = Ap2Channel::plain();
        self.event_channel = Ap2Channel::plain();
        self.event_plain_buf.clear();
        self.pending_methods.clear();
        self.pending_is_http.clear();
        self.rtsp_session.clear();
        self.resampler = Resampler::new();
        self.pending_volume_db = NO_VOLUME; // never carry volume between devices

        self.ap2 = None;
        self.pair_stage = PairStage::None;
        self.waiting_for_pin = false;
        self.tried_transient_after_pin403 = false;
        self.digest_realm.clear();
        self.digest_nonce.clear();
        self.digest_retried = false;
        self.event_port = 0;
        self.server_port = 0;
        self.control_port = 0;
        self.timing_port = 0;
        self.clock_start = None;

        // Bind the UDP trio BEFORE SETUP: the SETUP request advertises our
        // control/timing ports so the receiver can reach them (ephemeral
        // ports, bound to all interfaces).
        let me = self.me.clone();
        self.timing = self.transport.udp_bind(
            0,
            Box::new(move |d: &[u8], h: &str, p: u16| {
                dispatch(&me, |g| g.on_timing_data(d, h, p));
            }),
        );
        let me = self.me.clone();
        self.control = self.transport.udp_bind(
            0,
            Box::new(move |d: &[u8], h: &str, p: u16| {
                dispatch(&me, |g| g.on_control_data(d, h, p));
            }),
        );
        // Send-only audio socket (C++ passes nullptr for its data hook).
        self.audio = self.transport.udp_bind(0, Box::new(|_, _, _| {}));
        if self.timing.is_none() || self.control.is_none() || self.audio.is_none() {
            for h in [self.timing.take(), self.control.take(), self.audio.take()]
                .into_iter()
                .flatten()
            {
                self.transport.close(h);
            }
            return vec![Deferred::Launched(
                false,
                "Could not bind UDP sockets".to_string(),
            )];
        }

        self.state = SessionState::Connecting;
        self.start_handshake_timeout();
        self.rtsp = self.tcp_rtsp_connect(host, port);
        if self.rtsp.is_none() {
            return self.fail_("Could not start connecting to the device");
        }
        vec![]
    }

    fn tcp_rtsp_connect(&mut self, host: &str, port: u16) -> Option<Handle> {
        let me = self.me.clone();
        let connected = Box::new(move || dispatch(&me, Self::on_rtsp_connected));
        let me = self.me.clone();
        let data = Box::new(move |d: &[u8], _: &str, _: u16| dispatch(&me, |g| g.on_rtsp_data(d)));
        let me = self.me.clone();
        let closed = Box::new(move |r: &str| dispatch(&me, |g| g.on_rtsp_closed(r)));
        self.transport
            .tcp_connect(host, port, connected, data, closed)
    }

    fn on_rtsp_connected(&mut self) -> Vec<Deferred> {
        if self.state != SessionState::Connecting {
            return vec![];
        }
        self.rtsp_connected = true;
        self.begin_auth_chain()
    }

    fn on_rtsp_closed(&mut self, reason: &str) -> Vec<Deferred> {
        self.rtsp_connected = false;
        self.rtsp = None; // the transport already tore it down
        if self.state == SessionState::Idle {
            return vec![]; // our own stop(), quiet
        }
        if !reason.is_empty() {
            return self.fail_(reason);
        }
        // Graceful close from the far end.
        let was_starting = self.state != SessionState::Streaming;
        self.state = SessionState::Idle;
        self.stop_all_timers();
        let mut evs = Vec::new();
        if was_starting {
            evs.push(Deferred::Launched(
                false,
                "Connection closed by the device".to_string(),
            ));
        }
        evs.push(Deferred::Closed);
        evs
    }

    fn stop(&mut self) {
        if self.state == SessionState::Idle {
            return;
        }
        self.stop_all_timers();
        if self.rtsp_connected && (!self.rtsp_session.is_empty() || self.airplay2) {
            let mut extra = Vec::new();
            if !self.rtsp_session.is_empty() {
                extra.push(("Session".to_string(), self.rtsp_session.clone()));
            }
            let uri = self.rtsp_uri();
            self.send_request("TEARDOWN", uri, None, Vec::new(), extra);
            // A TEARDOWN sent mid-pairing re-armed the handshake watchdog
            // (C++ zombie): kill it too or it would fire into a later
            // session.
            stop_timer(&*self.transport, &mut self.handshake_timer);
        }
        self.state = SessionState::Idle; // BEFORE closing → on_rtsp_closed stays quiet
        if let Some(h) = self.rtsp.take() {
            self.transport.close(h);
        }
        self.rtsp_connected = false;
        for h in [
            self.audio.take(),
            self.control.take(),
            self.timing.take(),
            self.event.take(),
        ]
        .into_iter()
        .flatten()
        {
            self.transport.close(h);
        }
    }

    fn fail_(&mut self, why: &str) -> Vec<Deferred> {
        self.state = SessionState::Idle;
        self.stop_all_timers();
        if let Some(h) = self.rtsp.take() {
            self.transport.close(h);
        }
        self.rtsp_connected = false;
        for h in [
            self.audio.take(),
            self.control.take(),
            self.timing.take(),
            self.event.take(),
        ]
        .into_iter()
        .flatten()
        {
            self.transport.close(h);
        }
        let evs = vec![Deferred::Launched(false, why.to_string()), Deferred::Closed];
        evs
    }

    // ── timers ─────────────────────────────────────────────────────────

    fn every(&mut self, ms: u32, tick: fn(&mut Self) -> Vec<Deferred>) -> TimerId {
        let me = self.me.clone();
        self.transport
            .every(ms, Box::new(move || dispatch(&me, tick)))
    }

    fn after(&mut self, ms: u32, tick: fn(&mut Self) -> Vec<Deferred>) -> TimerId {
        let me = self.me.clone();
        self.transport
            .after(ms, Box::new(move || dispatch(&me, tick)))
    }

    fn stop_all_timers(&mut self) {
        stop_timer(&*self.transport, &mut self.pacer_timer);
        stop_timer(&*self.transport, &mut self.sync_timer);
        stop_timer(&*self.transport, &mut self.handshake_timer);
        stop_timer(&*self.transport, &mut self.pin_timer);
        stop_timer(&*self.transport, &mut self.feedback_timer);
    }

    fn start_handshake_timeout(&mut self) {
        // Replace, don't stack: every request re-arms the watchdog, and
        // the C++ accumulates zombie timers it then leaks into later
        // sessions. Each fire is guarded, so this is strictly cleaner.
        stop_timer(&*self.transport, &mut self.handshake_timer);
        let id = self.after(HANDSHAKE_TIMEOUT_MS as u32, Self::on_handshake_timeout);
        self.handshake_timer = Some(id);
    }

    fn on_handshake_timeout(&mut self) -> Vec<Deferred> {
        self.handshake_timer = None; // one-shot: the transport already forgot it
        if self.waiting_for_pin {
            return vec![]; // a PIN wait is user-driven; pin_timer guards it
        }
        if matches!(
            self.state,
            SessionState::Connecting | SessionState::Pairing | SessionState::Handshake
        ) {
            self.fail_("Timed out waiting for the device")
        } else {
            vec![]
        }
    }

    fn on_pin_wait_timeout(&mut self) -> Vec<Deferred> {
        self.pin_timer = None;
        if !self.waiting_for_pin {
            return vec![];
        }
        self.waiting_for_pin = false;
        self.fail_(&format!(
            "No PIN was entered. Switch {} on and make sure its screen \
             shows the AirPlay code, then try again.",
            self.name
        ))
    }

    // ── RTSP plumbing ──────────────────────────────────────────────────

    fn rtsp_uri(&self) -> String {
        let ip = self
            .rtsp
            .and_then(|h| self.transport.local_address(h))
            .unwrap_or_default();
        format!("rtsp://{}/{}", ip, self.session_id)
    }

    /// `sendRequest_`: RTSP control request with the identity headers,
    /// the digest `Authorization` once a 401 armed it, and the method
    /// FIFO bookkeeping. `method` is a literal (never host input).
    fn send_request(
        &mut self,
        method: &'static str,
        uri: String,
        content_type: Option<String>,
        body: Vec<u8>,
        extra: Vec<(String, String)>,
    ) {
        let dacp = self.dacp_id.clone();
        let active_remote = self.active_remote;
        let cseq = self.cseq;
        self.cseq = self.cseq.wrapping_add(1);
        let digest = if !self.digest_nonce.is_empty() && !self.digest_password.is_empty() {
            Some((
                self.digest_realm.clone(),
                self.digest_nonce.clone(),
                self.digest_password.clone(),
            ))
        } else {
            None
        };
        let extra_refs: Vec<(&str, &str)> = extra
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let digest_refs: Option<(&str, &str, &str)> = digest
            .as_ref()
            .map(|(r, n, p)| (r.as_str(), n.as_str(), p.as_str()));
        let req = build_rtsp_request(&RtspRequest {
            method,
            uri: &uri,
            cseq,
            dacp_id: &dacp,
            active_remote,
            extra: &extra_refs,
            content_type: content_type.as_deref(),
            body: &body,
            digest: digest_refs,
        });
        self.pending_methods.push_back(method.to_string());
        self.pending_is_http.push_back(false); // RTSP reply
        self.write_rtsp(&req);
        if matches!(self.state, SessionState::Handshake | SessionState::Pairing) {
            self.start_handshake_timeout(); // fresh window per handshake step
        }
    }

    /// `httpPost_`: an HTTP POST over the same TCP socket (pairing / AP2
    /// plists), routed back via `pending_is_http`.
    fn http_post(&mut self, uri: &str, content_type: Option<&str>, body: Vec<u8>) {
        let hkp = if self.auth_method == Auth::HapTransient {
            4
        } else {
            3
        };
        let dacp = self.dacp_id.clone();
        let cseq = self.cseq;
        self.cseq = self.cseq.wrapping_add(1);
        let req = build_http_post(
            uri,
            cseq,
            &dacp,
            self.active_remote,
            hkp,
            content_type,
            &body,
        );
        self.pending_methods.push_back("POST".to_string());
        self.pending_is_http.push_back(true);
        self.write_rtsp(&req);
        if !self.waiting_for_pin {
            self.start_handshake_timeout();
        }
    }

    /// `sendAp2Rtsp_`: AP2 binary-plist methods on the control channel
    /// (adds `X-Apple-StreamID: 1` on SETUP; replies carry a plist body
    /// → the pairing dispatcher).
    fn send_ap2_rtsp(
        &mut self,
        method: &str,
        uri: &str,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) {
        let dacp = self.dacp_id.clone();
        let cseq = self.cseq;
        self.cseq = self.cseq.wrapping_add(1);
        let req = build_ap2_rtsp(
            method,
            uri,
            cseq,
            &dacp,
            self.active_remote,
            content_type,
            &body,
        );
        self.pending_methods.push_back(method.to_string());
        self.pending_is_http.push_back(true); // reply has a plist body
        self.write_rtsp(&req);
        self.start_handshake_timeout();
    }

    /// `writeRtsp_`: plaintext on the control socket until the control
    /// channel keys up (post pair-verify), then 1024-byte ChaCha20 frames.
    fn write_rtsp(&mut self, plain: &[u8]) {
        let out = self.control_channel.frame_out(plain);
        if let Some(h) = self.rtsp {
            self.transport.send(h, &out);
        }
    }

    // ── control-plane receive ──────────────────────────────────────────

    /// `onRtspData_`: decrypt the control channel (post pair-verify),
    /// bound the plaintext buffer, and dispatch complete responses
    /// through the method FIFO.
    fn on_rtsp_data(&mut self, data: &[u8]) -> Vec<Deferred> {
        match self.control_channel.feed_in(data) {
            Err(FrameError::AuthFailed) => {
                return self.fail_("Encrypted control channel authentication failed");
            }
            // Hardening (no such cap in the C++): a hostile frame length
            // could otherwise grow the accumulator unboundedly.
            Err(FrameError::OversizedFrame) => {
                return self.fail_("The receiver sent an oversized control-channel frame");
            }
            Ok(plain) => self.rx_buf.extend_from_slice(&plain),
        }
        if self.rx_buf.len() > 4 * 1024 * 1024 {
            return self.fail_("Oversized RTSP response from the receiver");
        }
        let mut evs = Vec::new();
        while let Some((resp, used)) = parse_response(&self.rx_buf) {
            self.rx_buf.drain(..used);
            if resp.kind == StatusKind::ServerRequest {
                continue; // a server→client request; we act on none
            }
            let Some(method) = self.pending_methods.pop_front() else {
                continue; // unexpected response
            };
            let is_http = self.pending_is_http.pop_front().unwrap_or(false);
            if is_http {
                evs.extend(self.on_pairing_response(resp.code, &resp.headers, &resp.body));
            } else {
                evs.extend(self.handle_response(&method, resp.code, &resp.headers));
            }
            if self.state == SessionState::Idle {
                break; // fail_ during dispatch
            }
        }
        evs
    }

    fn handle_response(
        &mut self,
        method: &str,
        code: u32,
        headers: &BTreeMap<String, String>,
    ) -> Vec<Deferred> {
        // Streaming-time auxiliaries first, failures are non-fatal there.
        if method == "SET_PARAMETER" {
            return vec![]; // a non-200 here is warn-only in the C++
        }
        if method == "POST" {
            // /feedback keep-alive probe (AP1).
            if code == 200 {
                if self.feedback_timer.is_none() {
                    let id = self.every(25_000, Self::on_feedback_tick);
                    self.feedback_timer = Some(id);
                }
            } else {
                stop_timer(&*self.transport, &mut self.feedback_timer); // keep-alive disabled
            }
            return vec![];
        }
        if method == "FEEDBACK" || method == "TEARDOWN" {
            return vec![]; // AP2 keep-alive / our own teardown, ignored
        }

        // RTSP digest auth for pw=true receivers (RFC 2617 MD5).
        if code == 401 {
            if self.digest_password.is_empty() {
                return self.fail_("The device requires a password");
            }
            if self.digest_retried {
                return self.fail_("The password was not accepted by the device");
            }
            let wa = header_value(headers, "www-authenticate", "");
            let (realm, nonce) = parse_digest_challenge(wa);
            let Some(nonce) = nonce else {
                return self.fail_("The device password challenge could not be parsed");
            };
            self.digest_realm = realm.unwrap_or_default();
            self.digest_nonce = nonce;
            self.digest_retried = true;
            // Re-issue the request that was rejected; send_request now
            // attaches the Authorization header.
            return match method {
                "OPTIONS" => {
                    self.send_options();
                    vec![]
                }
                "ANNOUNCE" => {
                    self.send_announce();
                    vec![]
                }
                "SETUP" => {
                    self.send_setup();
                    vec![]
                }
                "RECORD" => {
                    self.send_record();
                    vec![]
                }
                _ => self.fail_("The device password was required at an unexpected step"),
            };
        }
        if !(200..300).contains(&code) {
            // AP2 sends RECORD + FLUSH fire-and-forget AFTER streaming has
            // begun; a rejection there is NON-fatal.
            if self.state == SessionState::Streaming && (method == "RECORD" || method == "FLUSH") {
                return vec![];
            }
            return self.fail_(&format!("Device refused {} ({})", method, code));
        }

        match method {
            "OPTIONS" => self.send_announce(),
            "ANNOUNCE" => self.send_setup(),
            "SETUP" => {
                let transport = header_value(headers, "transport", "");
                let (server_port, control_port, timing_port) =
                    parse_setup_transport_reply(transport);
                self.server_port = server_port;
                self.control_port = control_port;
                self.timing_port = timing_port;
                self.rtsp_session = header_value(headers, "session", "").to_string();
                if self.rtsp_session.is_empty() {
                    self.rtsp_session = "1".to_string();
                }
                if self.server_port == 0 {
                    return self.fail_("SETUP reply carried no server_port");
                }
                self.send_record();
            }
            "RECORD" => {
                // The receiver may report its buffer depth; informational
                // only, we keep the fixed latency model.
                let _lat = header_value(headers, "audio-latency", "");
                // AP1: RECORD's reply begins streaming. AP2: RECORD was
                // sent fire-and-forget from within start_streaming (already
                // Streaming), a late reply must NOT re-init the stream.
                if self.state != SessionState::Streaming {
                    return self.start_streaming();
                }
            }
            "FLUSH" => {} // AP2 timeline anchor, reply informational
            _ => {}
        }
        vec![]
    }

    // ── handshake steps ────────────────────────────────────────────────

    fn send_options(&mut self) {
        self.send_request("OPTIONS", "*".to_string(), None, Vec::new(), Vec::new());
    }

    fn send_announce(&mut self) {
        let local = self
            .rtsp
            .and_then(|h| self.transport.local_address(h))
            .unwrap_or_default();
        let remote = self
            .rtsp
            .and_then(|h| self.transport.peer_address(h))
            .unwrap_or_default();
        let sdp = build_announce_sdp(self.session_id, &local, &remote);
        let uri = self.rtsp_uri();
        self.send_request(
            "ANNOUNCE",
            uri,
            Some("application/sdp".to_string()),
            sdp,
            Vec::new(),
        );
    }

    fn send_setup(&mut self) {
        let control_port = self
            .control
            .and_then(|h| self.transport.local_port(h))
            .unwrap_or(0);
        let timing_port = self
            .timing
            .and_then(|h| self.transport.local_port(h))
            .unwrap_or(0);
        let transport = build_setup_transport(control_port, timing_port);
        let uri = self.rtsp_uri();
        self.send_request(
            "SETUP",
            uri,
            None,
            Vec::new(),
            vec![("Transport".to_string(), transport)],
        );
    }

    fn send_record(&mut self) {
        let rtp_info = build_rtp_info(self.stream.seq(), self.stream.rtptime32());
        let mut headers = vec![("Range".to_string(), "npt=0-".to_string())];
        headers.push(("RTP-Info".to_string(), rtp_info));
        // AP1 carries the RTSP Session id; AP2 has none (it keys off the
        // rtsp://host/sessionId URI), so only send it when we got one.
        if !self.rtsp_session.is_empty() {
            headers.push(("Session".to_string(), self.rtsp_session.clone()));
        }
        let uri = self.rtsp_uri();
        self.send_request("RECORD", uri, None, Vec::new(), headers);
    }

    fn send_volume(&mut self) {
        let body = format!("volume: {}", fixed6(self.pending_volume_db));
        let mut extra = Vec::new();
        if !self.rtsp_session.is_empty() {
            extra.push(("Session".to_string(), self.rtsp_session.clone()));
        }
        let uri = self.rtsp_uri();
        self.send_request(
            "SET_PARAMETER",
            uri,
            Some("text/parameters".to_string()),
            body.into_bytes(),
            extra,
        );
    }

    fn send_metadata(&mut self) {
        if self.state != SessionState::Streaming {
            return;
        }
        if self.np_title.is_empty()
            && self.np_artist.is_empty()
            && self.np_album.is_empty()
            && self.np_cover.is_empty()
        {
            return;
        }
        let rtp_info = build_rtp_info(self.stream.seq(), self.stream.rtptime32());
        let mut extra = Vec::new();
        if !self.rtsp_session.is_empty() {
            extra.push(("Session".to_string(), self.rtsp_session.clone()));
        }
        extra.push(("RTP-Info".to_string(), rtp_info));
        let body = build_dmap_metadata(&self.np_title, &self.np_artist, &self.np_album);
        if !body.is_empty() {
            let uri = self.rtsp_uri();
            self.send_request(
                "SET_PARAMETER",
                uri,
                Some("application/x-dmap-tagged".to_string()),
                body,
                extra.clone(),
            );
        }
        if !self.np_cover.is_empty() && self.np_cover.len() <= 8 * 1024 * 1024 {
            let mime = if self.np_cover_mime.is_empty() {
                "image/jpeg".to_string()
            } else {
                self.np_cover_mime.clone()
            };
            let uri = self.rtsp_uri();
            self.send_request(
                "SET_PARAMETER",
                uri,
                Some(mime),
                self.np_cover.clone(),
                extra,
            );
        }
    }

    fn start_streaming(&mut self) -> Vec<Deferred> {
        self.state = SessionState::Streaming;
        stop_timer(&*self.transport, &mut self.handshake_timer);
        // Anchor the timeline on wall-clock NTP so sync-packet NTP values
        // and our timing-server replies share one epoch.
        let start_ts = ntp2ts(ntp_now(), RAOP_RATE);
        self.stream.begin_timeline(start_ts, LATENCY_FRAMES);
        self.clock_start = Some(Instant::now());
        self.send_sync_packet(true); // first sync carries the marker bit
        let id = self.every(1000, Self::on_sync_tick);
        self.sync_timer = Some(id);
        // An AP2 receiver can sit at its own (possibly muted) default until
        // told otherwise; if the user never set a volume, push 0 dB so
        // audio is audible by default.
        if self.airplay2 && self.pending_volume_db <= NO_VOLUME + 1.0 {
            self.pending_volume_db = 0.0;
        }
        if self.pending_volume_db > NO_VOLUME + 1.0 {
            self.send_volume();
        }
        // Audio RTP loop starts LAST.
        let id = self.every(PACER_MS as u32, Self::on_pacer_tick);
        self.pacer_timer = Some(id);
        if self.airplay2 {
            // AP2 keep-alive: POST /feedback every 2 s.
            let id = self.every(2000, Self::on_feedback_tick);
            self.feedback_timer = Some(id);
        } else {
            // AP1 keep-alive probe: one POST /feedback; a 200 arms the
            // 25 s timer, anything else disables it for good (handled in
            // handle_response POST).
            self.send_request(
                "POST",
                "/feedback".to_string(),
                None,
                Vec::new(),
                Vec::new(),
            );
        }
        self.send_metadata();
        vec![Deferred::Launched(true, String::new())]
    }

    // ── auth / pairing / AP2 ───────────────────────────────────────────

    fn begin_auth_chain(&mut self) -> Vec<Deferred> {
        self.state = SessionState::Pairing;
        match self.auth_method {
            Auth::NoAuth | Auth::Password => {
                // Plain Phase-1 receiver (or digest, which is reactive):
                // straight to the RTSP handshake.
                self.state = SessionState::Handshake;
                self.send_options();
                vec![]
            }
            Auth::AuthSetup => {
                self.send_auth_setup();
                vec![]
            }
            Auth::LegacyPin => self.fail_(&format!(
                "{} uses an older AirPlay pairing that isn't supported yet. \
                 Update the device's software, or use an AirPlay-2 receiver \
                 (HomePod, Apple TV 4K, or a modern AirPlay speaker).",
                self.name
            )),
            Auth::HapTransient => {
                if let Some(err) = self.new_ap2() {
                    return self.fail_(&err);
                }
                self.send_pair_setup_m1();
                vec![]
            }
            Auth::HapPin => {
                if let Some(err) = self.new_ap2() {
                    return self.fail_(&err);
                }
                if !self.creds_json.is_empty() {
                    let creds = self.creds_json.clone();
                    let ready = self
                        .ap2
                        .as_mut()
                        .is_some_and(|a| a.session.try_load_creds(&creds));
                    if ready {
                        self.send_pair_verify_m1();
                        return vec![];
                    }
                }
                self.send_pair_pin_start();
                vec![]
            }
        }
    }

    fn new_ap2(&mut self) -> Option<String> {
        let Ok((uuid, _stream_connection)) = PairingSession::generate_session_id_parts() else {
            return Some("Random-number failure starting pairing".to_string());
        };
        let mode = if self.auth_method == Auth::HapTransient {
            PairingMode::Transient
        } else {
            PairingMode::Pin
        };
        let session = PairingSession::new(mode);
        self.ap2 = Some(Ap2State {
            session,
            session_uuid: uuid,
        });
        None
    }

    fn send_auth_setup(&mut self) {
        self.pair_stage = PairStage::AuthSetup;
        self.http_post(
            "/auth-setup",
            Some("application/octet-stream"),
            AUTH_SETUP_BODY.to_vec(),
        );
    }

    fn send_pair_pin_start(&mut self) {
        // The tvOS Apple TV only RENDERS its code when it receives POST
        // /pair-pin-start; send it BEFORE M1 for normal HomeKit pairing.
        self.pair_stage = PairStage::PinStart;
        self.http_post(
            "/pair-pin-start",
            Some("application/octet-stream"),
            Vec::new(),
        );
    }

    fn send_pair_setup_m1(&mut self) {
        let body = self
            .ap2
            .as_ref()
            .map(|a| a.session.pair_setup_m1())
            .unwrap_or_default();
        self.pair_stage = PairStage::SetupM2;
        self.http_post("/pair-setup", Some("application/octet-stream"), body);
    }

    fn send_pair_setup_m3(&mut self, pin: &str) -> Vec<Deferred> {
        let Some(ap2) = self.ap2.as_mut() else {
            return vec![];
        };
        let m3 = match ap2.session.pair_setup_m3(pin) {
            Ok(m3) => m3,
            Err(_) => return self.fail_("Pairing rejected the device's parameters"),
        };
        self.pair_stage = PairStage::SetupM4;
        self.http_post("/pair-setup", Some("application/octet-stream"), m3);
        vec![]
    }

    fn send_pair_setup_m5(&mut self) -> Vec<Deferred> {
        let Some(ap2) = self.ap2.as_mut() else {
            return vec![];
        };
        let m5 = match ap2.session.pair_setup_m5() {
            Ok(m5) => m5,
            Err(_) => return self.fail_("Pairing M5 could not be built"),
        };
        self.pair_stage = PairStage::SetupM6;
        self.http_post("/pair-setup", Some("application/octet-stream"), m5);
        vec![]
    }

    fn send_pair_verify_m1(&mut self) -> Vec<Deferred> {
        let Some(ap2) = self.ap2.as_mut() else {
            return vec![];
        };
        let m1 = match ap2.session.pair_verify_m1() {
            Ok(m1) => m1,
            Err(_) => return self.fail_("Pair-verify could not be started"),
        };
        self.pair_stage = PairStage::VerifyM2;
        self.http_post("/pair-verify", Some("application/octet-stream"), m1);
        vec![]
    }

    fn handle_pair_setup_m2(&mut self, body: &[u8]) -> Vec<Deferred> {
        let Some(ap2) = self.ap2.as_mut() else {
            return vec![];
        };
        let res = ap2.session.handle_pair_setup_m2(body);
        match res {
            Err(PairingError::AccessoryRejected(n)) => {
                return self.fail_(&format!("The device rejected pairing (error {n})"));
            }
            Err(PairingError::Incomplete) => {
                return self.fail_("Pairing setup response was incomplete");
            }
            Err(_) => return self.fail_("Pairing setup failed"),
            Ok(()) => {}
        }
        if self.auth_method == Auth::HapTransient {
            return self.send_pair_setup_m3(TRANSIENT_PIN);
        }
        // Normal HAP PIN: ask the caller for the on-screen code.
        self.waiting_for_pin = true;
        stop_timer(&*self.transport, &mut self.handshake_timer);
        let id = self.after(PIN_WAIT_TIMEOUT_MS as u32, Self::on_pin_wait_timeout);
        self.pin_timer = Some(id);
        vec![Deferred::PinRequired(self.name.clone())]
    }

    fn handle_pair_setup_m4(&mut self, body: &[u8]) -> Vec<Deferred> {
        let outcome = match self.ap2.as_mut() {
            Some(ap2) => ap2.session.handle_pair_setup_m4(body),
            None => return vec![],
        };
        match outcome {
            Err(PairingError::AccessoryRejected(n)) => {
                return self.fail_(&format!("Pairing PIN was not accepted (error {n})"));
            }
            Err(_) => return self.fail_("Pairing did not complete"),
            Ok((crate::pairing::M4Outcome::TransientKeysDerived, _)) => {
                // Transient pairing stops at M4: derive the audio/control
                // key from the SRP shared secret and go straight to AP2
                // SETUP.
                self.pair_stage = PairStage::Done;
                return self.after_auth_ok();
            }
            Ok((crate::pairing::M4Outcome::SendM5, _)) => {}
        }
        self.send_pair_setup_m5()
    }

    fn handle_pair_setup_m6(&mut self, body: &[u8]) -> Vec<Deferred> {
        let Some(ap2) = self.ap2.as_mut() else {
            return vec![];
        };
        let res = ap2.session.handle_pair_setup_m6(body);
        match res {
            Err(PairingError::AccessoryRejected(n)) => {
                return self.fail_(&format!("Pairing finalisation failed (error {n})"));
            }
            Err(PairingError::Incomplete) => {
                return self.fail_("Pairing M6 response was incomplete");
            }
            Err(PairingError::DecryptFailed) => {
                return self.fail_("Pairing M6 could not be decrypted");
            }
            Err(_) => return self.fail_("Pairing could not be finalised"),
            Ok(_) => {}
        }
        let Some(ap2) = self.ap2.as_mut() else {
            return vec![];
        };
        // Persist the long-term credentials so later connects skip the PIN.
        let client_id = String::from_utf8_lossy(&ap2.session.pairing_id).into_owned();
        let creds = encode_creds(
            &to_hex(&ap2.session.lt_seed),
            &to_hex(&ap2.session.accessory_ltpk),
            &to_hex(&ap2.session.accessory_id),
            &client_id,
        );
        let mut evs = vec![Deferred::CredentialsObtained(self.device_id.clone(), creds)];
        // Now run pair-verify to derive the live session keys.
        evs.extend(self.send_pair_verify_m1());
        evs
    }

    fn handle_pair_verify_m2(&mut self, body: &[u8]) -> Vec<Deferred> {
        let Some(ap2) = self.ap2.as_mut() else {
            return vec![];
        };
        let m3 = match ap2.session.handle_pair_verify_m2(body) {
            Ok((m3, _)) => m3,
            Err(PairingError::AccessoryRejected(n)) => {
                return self.fail_(&format!("Pair-verify rejected (error {n})"));
            }
            Err(PairingError::Incomplete) => return self.fail_("Pair-verify response incomplete"),
            Err(_) => return self.fail_("Pair-verify failed"),
        };
        // The receiver pushes encrypted requests on the event channel from
        // now on (auto-answered in on_event_data).
        if let Some(ap2) = self.ap2.as_ref() {
            self.event_channel
                .install_keys(&ap2.session.event_in, &ap2.session.event_out);
        }
        self.pair_stage = PairStage::VerifyDone;
        self.http_post("/pair-verify", Some("application/octet-stream"), m3);
        vec![]
    }

    fn after_auth_ok(&mut self) -> Vec<Deferred> {
        self.digest_retried = false; // reset for the handshake's own auth
        if self.airplay2 {
            // Pair-verify is done; from here the RTSP control channel is
            // ChaCha20-Poly1305 encrypted (Control-Read/Write keys). The
            // very next request (/setup) is already encrypted, and an
            // Apple TV REQUIRES this.
            if let Some(ap2) = self.ap2.as_ref() {
                if ap2.session.control_out.len() == 32 && ap2.session.control_in.len() == 32 {
                    self.control_channel
                        .install_keys(&ap2.session.control_in, &ap2.session.control_out);
                }
            }
            self.state = SessionState::Handshake;
            self.send_ap2_info();
        } else {
            self.state = SessionState::Handshake;
            self.send_options();
        }
        vec![]
    }

    fn on_pairing_response(
        &mut self,
        code: u32,
        _headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Vec<Deferred> {
        if self.state == SessionState::Idle {
            return vec![];
        }
        // Once we're streaming the handshake is done; a late/duplicate
        // pairing-stage reply must NOT be re-parsed as a SETUP plist and
        // tear down the live stream.
        if self.state == SessionState::Streaming {
            return vec![];
        }
        // auth-setup: the response is ignored (pyatv does exactly this).
        if self.auth_method == Auth::AuthSetup
            && self.ap2.is_none()
            && self.pair_stage == PairStage::AuthSetup
        {
            self.pair_stage = PairStage::Done;
            return self.after_auth_ok();
        }
        // The RECORD reply (between session + stream SETUP): proceed to the
        // stream SETUP even on a rejection so the stream is at least
        // established.
        if self.pair_stage == PairStage::Ap2Record {
            self.send_ap2_setup_stream();
            return vec![];
        }

        if !(200..300).contains(&code) {
            // HTTP 470 on transient pair-setup means the receiver wants
            // real pairing: switch to HapPin and run /pair-pin-start then
            // M1. One-shot, gated on the transient M1 stage so it can't
            // loop.
            if code == 470
                && self.auth_method == Auth::HapTransient
                && self.pair_stage == PairStage::SetupM2
            {
                self.auth_method = Auth::HapPin;
                if let Some(err) = self.new_ap2() {
                    return self.fail_(&err);
                }
                self.send_pair_pin_start();
                return vec![];
            }
            // A 403 to /pair-pin-start is the Mac case (no on-screen PIN,
            // but the receiver still accepts PIN-less transient pairing
            // when access is open): try transient once.
            if code == 403
                && self.pair_stage == PairStage::PinStart
                && !self.tried_transient_after_pin403
            {
                self.tried_transient_after_pin403 = true;
                self.auth_method = Auth::HapTransient;
                if let Some(err) = self.new_ap2() {
                    return self.fail_(&err);
                }
                self.send_pair_setup_m1();
                return vec![];
            }
            let msg = if code == 403 {
                format!(
                    "{} refused pairing. On a Mac, set System Settings → \
                     AirDrop & Handoff → AirPlay Receiver → \"Allow AirPlay \
                     for: Everyone\" and turn off Require Password, though a \
                     Mac may only accept Apple devices. An Apple TV or \
                     HomePod (Allow Access → \"Anyone on the Same Network\") \
                     is the reliable target.",
                    self.name
                )
            } else if code == 470 {
                format!(
                    "{} needs to be paired with a PIN, but it didn't show \
                     one. On the Apple TV / Mac set AirPlay access to \
                     \"Anyone on the Same Network\" and try again.",
                    self.name
                )
            } else {
                format!("Pairing with {} failed (HTTP {})", self.name, code)
            };
            return self.fail_(&msg);
        }

        match self.pair_stage {
            PairStage::PinStart => {
                self.send_pair_setup_m1();
                vec![]
            }
            PairStage::SetupM2 => self.handle_pair_setup_m2(body),
            PairStage::SetupM4 => self.handle_pair_setup_m4(body),
            PairStage::SetupM6 => self.handle_pair_setup_m6(body),
            PairStage::VerifyM2 => self.handle_pair_verify_m2(body),
            PairStage::VerifyDone => {
                self.pair_stage = PairStage::Done;
                self.after_auth_ok()
            }
            PairStage::Ap2Info => {
                self.send_ap2_setup_session();
                vec![]
            }
            PairStage::Ap2Session => self.handle_ap2_setup_session(body),
            PairStage::Ap2Record => {
                self.send_ap2_setup_stream();
                vec![]
            }
            PairStage::Ap2Stream => self.handle_ap2_setup_stream(body),
            _ => vec![], // unexpected stage
        }
    }

    // ── AirPlay 2 ──────────────────────────────────────────────────────

    fn send_ap2_info(&mut self) {
        self.pair_stage = PairStage::Ap2Info;
        self.send_ap2_rtsp("GET", "/info", None, Vec::new());
    }

    fn send_ap2_setup_session(&mut self) {
        let Some(ap2) = self.ap2.as_ref() else {
            return;
        };
        let uuid = ap2.session_uuid.clone();
        let timing_port = self
            .timing
            .and_then(|h| self.transport.local_port(h))
            .unwrap_or(0);
        let body = plists::build_setup_session(&uuid, timing_port);
        self.pair_stage = PairStage::Ap2Session;
        let uri = self.rtsp_uri();
        self.send_ap2_rtsp(
            "SETUP",
            &uri,
            Some("application/x-apple-binary-plist"),
            body,
        );
    }

    fn handle_ap2_setup_session(&mut self, body: &[u8]) -> Vec<Deferred> {
        self.event_port = plists::parse_setup_session_reply(body);
        // A modern Apple TV needs the event-channel TCP connection OPEN and
        // RECORD accepted BEFORE the stream SETUP.
        if self.event_port != 0 {
            if let Some(h) = self.event.take() {
                self.transport.close(h);
            }
            self.event = self.event_connect(self.event_port);
        }
        self.send_ap2_record();
        vec![]
    }

    fn send_ap2_record(&mut self) {
        self.pair_stage = PairStage::Ap2Record;
        let uri = self.rtsp_uri();
        self.send_ap2_rtsp("RECORD", &uri, None, Vec::new());
    }

    fn send_ap2_setup_stream(&mut self) {
        let Some(ap2) = self.ap2.as_mut() else {
            return;
        };
        // Audio key = the FIRST 32 bytes of the shared secret, used
        // DIRECTLY as the ChaCha20-Poly1305 key (owntone: `shk` AND the
        // cipher key with no HKDF). SRP K is 64 bytes for transient
        // pairing; only 32 are used for audio.
        ap2.session.derive_audio_key();
        let key = ap2.session.audio_key.clone();
        let Some(key32) = key.get(..32).and_then(|k| <[u8; 32]>::try_from(k).ok()) else {
            return; // cannot happen post-pairing (the key is 32 or 64 B)
        };
        self.stream.install_audio_key(key32);
        let control_port = self
            .control
            .and_then(|h| self.transport.local_port(h))
            .unwrap_or(0);
        let body = plists::build_setup_stream(control_port, &key32, self.session_id);
        self.pair_stage = PairStage::Ap2Stream;
        let uri = self.rtsp_uri();
        self.send_ap2_rtsp(
            "SETUP",
            &uri,
            Some("application/x-apple-binary-plist"),
            body,
        );
    }

    fn handle_ap2_setup_stream(&mut self, body: &[u8]) -> Vec<Deferred> {
        let (data_port, mut control_port) = plists::parse_setup_stream_reply(body);
        self.server_port = data_port;
        if self.server_port == 0 {
            return self.fail_("AirPlay 2 stream SETUP returned no data port");
        }
        // AP2 has no separate sync 'control_port' in the AP1 sense; reuse
        // the data path for sync if the receiver didn't give one.
        if control_port == 0 {
            control_port = data_port;
        }
        self.control_port = control_port;
        self.timing_port = data_port; // NTP timing rides the same host
        // AP2 realtime does NOT use RTSP RECORD (the Apple TV never replies
        // to it); go straight to streaming — start_streaming pushes the
        // initial volume + sync + RTP.
        self.start_streaming()
    }

    fn event_connect(&mut self, port: u16) -> Option<Handle> {
        let me = self.me.clone();
        let data = Box::new(move |d: &[u8], _: &str, _: u16| dispatch(&me, |g| g.on_event_data(d)));
        let me = self.me.clone();
        let closed = Box::new(move |_: &str| {
            if let Some(s) = me.upgrade() {
                s.borrow_mut().event = None;
            }
        });
        self.transport
            .tcp_connect(&self.host, port, Box::new(|| {}), data, closed)
    }

    /// `onEventData_`: decrypt the receiver's pushed RTSP requests on the
    /// event channel and answer each with an encrypted bare 200 OK (or the
    /// Apple TV tears the session down at ~25 s).
    fn on_event_data(&mut self, data: &[u8]) -> Vec<Deferred> {
        if self.state == SessionState::Idle {
            return vec![]; // dead session, don't auto-answer
        }
        if !self.event_channel.encrypted() {
            return vec![]; // not keyed yet
        }
        let Ok(plain) = self.event_channel.feed_in(data) else {
            return vec![]; // decrypt failed, dropping (channel cleared)
        };
        self.event_plain_buf.extend_from_slice(&plain);
        while let Some(req) = next_event_request(&self.event_plain_buf) {
            self.event_plain_buf.drain(..req.total);
            let resp = build_event_200_ok(req.cseq.as_deref());
            let out = self.event_channel.frame_out(&resp);
            if let Some(h) = self.event {
                self.transport.send(h, &out);
            }
        }
        vec![]
    }

    // ── streaming ──────────────────────────────────────────────────────

    fn on_sync_tick(&mut self) -> Vec<Deferred> {
        self.send_sync_packet(false);
        vec![]
    }

    fn send_sync_packet(&mut self, first: bool) {
        if self.server_port == 0 || self.control_port == 0 {
            return;
        }
        let pkt = self.stream.build_sync_packet(first);
        if let Some(h) = self.control {
            self.transport
                .send_to(h, &self.host, self.control_port, &pkt);
        }
    }

    /// `onPacerTick_`'s loop: written packets must track wall clock at
    /// 44100 frames/s; a stall is repaid in bursts, capped so we never
    /// flood the LAN.
    fn on_pacer_tick(&mut self) -> Vec<Deferred> {
        let elapsed_ns = self
            .clock_start
            .map(|c| c.elapsed().as_nanos() as u64)
            .unwrap_or(0);
        let target = target_frames(elapsed_ns);
        let mut sent = 0;
        while self.stream.frames_sent() + FRAMES_PER_PACKET as u64 <= target
            && sent < MAX_PACKETS_PER_TICK
        {
            self.send_audio_packet();
            sent += 1;
        }
        vec![]
    }

    fn send_audio_packet(&mut self) {
        let mut pcm = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        let mut ring = self.ring.as_ref().map(|r| r.borrow_mut());
        self.resampler
            .fill(&mut pcm, FRAMES_PER_PACKET, ring.as_deref_mut());
        let pkt = self.stream.build_audio_packet(&pcm);
        if let Some(h) = self.audio {
            self.transport
                .send_to(h, &self.host, self.server_port, &pkt);
        }
    }

    fn on_control_data(&mut self, data: &[u8], from_host: &str, from_port: u16) -> Vec<Deferred> {
        let Some(responses) = self.stream.retransmit_responses(data) else {
            return vec![];
        };
        if let Some(h) = self.control {
            for resp in responses {
                self.transport.send_to(h, from_host, from_port, &resp);
            }
        }
        vec![]
    }

    fn on_timing_data(&mut self, data: &[u8], from_host: &str, from_port: u16) -> Vec<Deferred> {
        let Some(resp) = build_timing_reply(data, ntp_now()) else {
            return vec![];
        };
        if let Some(h) = self.timing {
            self.transport.send_to(h, from_host, from_port, &resp);
        }
        vec![]
    }

    // ── public setters (C++ parity) ────────────────────────────────────

    fn submit_pin(&mut self, code: &str) -> Vec<Deferred> {
        if !self.waiting_for_pin {
            return vec![];
        }
        self.waiting_for_pin = false;
        stop_timer(&*self.transport, &mut self.pin_timer);
        self.start_handshake_timeout(); // re-arm the handshake watchdog
        self.send_pair_setup_m3(code)
    }

    fn on_feedback_tick(&mut self) -> Vec<Deferred> {
        if self.state != SessionState::Streaming {
            return vec![];
        }
        if self.airplay2 {
            // AP2 keep-alive: POST /feedback RTSP/1.0 — an HTTP/1.1 line is
            // silently ignored by the receiver's RTSP parser, so its
            // liveness timer never resets and it drops at 30 s.
            let cseq = self.cseq;
            self.cseq = self.cseq.wrapping_add(1);
            let req = build_ap2_feedback(cseq, &self.dacp_id, self.active_remote);
            self.pending_methods.push_back("FEEDBACK".to_string());
            self.pending_is_http.push_back(false);
            self.write_rtsp(&req);
        } else {
            self.send_request(
                "POST",
                "/feedback".to_string(),
                None,
                Vec::new(),
                Vec::new(),
            );
        }
vec![]
    }
}
// ── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::time::Duration;
    use transport::{ClosedFn, ConnectFn, DataFn, TimerFn};

    use airplay_crypto::bplist::{self, Value};
    use airplay_crypto::tlv as hap_tlv;
    use ring_buffer::RingBuffer;

    /// Everything the transport sent, in order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Tx {
        Tcp(Vec<u8>),
        Udp {
            dest_host: String,
            dest_port: u16,
            data: Vec<u8>,
        },
    }

    type MockTimer = (u32, u32, Option<TimerFn>, bool);
    type MockTcpCallbacks = (
        Rc<RefCell<Option<ConnectFn>>>,
        Rc<RefCell<Option<DataFn>>>,
        Rc<RefCell<Option<ClosedFn>>>,
    );
    type MockDataCallback = Rc<RefCell<Option<DataFn>>>;

    /// A scriptable in-process `Transport`: tests register callbacks via
    /// `fire_*`, inspect the wire via `tx`, and script addresses.
    struct MockTransport {
        next_handle: Cell<u32>,
        next_timer: Cell<u32>,
        local_ips: RefCell<HashMap<u32, String>>,
        local_ports: RefCell<HashMap<u32, u16>>,
        peer_ips: RefCell<HashMap<u32, String>>,
        tcp: RefCell<HashMap<u32, MockTcpCallbacks>>,
        udp: RefCell<HashMap<u32, MockDataCallback>>,
        timers: RefCell<Vec<MockTimer>>, // (id, ms, f, repeating)
        tx: RefCell<Vec<Tx>>,
    }

    impl Default for MockTransport {
        fn default() -> Self {
            MockTransport {
                next_handle: Cell::new(0),
                next_timer: Cell::new(0),
                local_ips: RefCell::new(HashMap::new()),
                local_ports: RefCell::new(HashMap::new()),
                peer_ips: RefCell::new(HashMap::new()),
                tcp: RefCell::new(HashMap::new()),
                udp: RefCell::new(HashMap::new()),
                timers: RefCell::new(Vec::new()),
                tx: RefCell::new(Vec::new()),
            }
        }
    }

    impl MockTransport {
        fn alloc_handle(&self) -> Handle {
            let n = self.next_handle.get() + 1;
            self.next_handle.set(n);
            Handle::from_raw(n)
        }

        fn set_local_ip(&self, h: Handle, ip: &str) {
            self.local_ips
                .borrow_mut()
                .insert(h.as_raw(), ip.to_string());
        }

        fn set_local_port(&self, h: Handle, p: u16) {
            self.local_ports.borrow_mut().insert(h.as_raw(), p);
        }

        fn set_peer_ip(&self, h: Handle, ip: &str) {
            self.peer_ips
                .borrow_mut()
                .insert(h.as_raw(), ip.to_string());
        }

        fn tcp_handles(&self) -> Vec<Handle> {
            self.tcp
                .borrow()
                .keys()
                .map(|&r| Handle::from_raw(r))
                .collect()
        }

        fn udp_handles_for_test(&self) -> Vec<Handle> {
            self.udp
                .borrow()
                .keys()
                .map(|&r| Handle::from_raw(r))
                .collect()
        }

        fn fire_connect(&self, h: Handle) {
            let cb = {
                let t = self.tcp.borrow();
                t.get(&h.as_raw())
                    .map(|(c, _, _)| c.clone())
                    .and_then(|c| c.borrow_mut().take())
            };
            if let Some(cb) = cb {
                cb();
            }
        }

        fn fire_data(&self, h: Handle, data: &[u8]) {
            let cb = {
                let t = self.tcp.borrow();
                t.get(&h.as_raw())
                    .map(|(_, d, _)| d.clone())
                    .and_then(|d| d.borrow_mut().take())
            };
            if let Some(cb) = cb {
                cb(data, "", 0);
                if let Some(t) = self.tcp.borrow().get(&h.as_raw()) {
                    *t.1.borrow_mut() = Some(cb);
                }
            }
        }

        fn fire_udp_data(&self, h: Handle, data: &[u8], from: &str, port: u16) {
            let cb = {
                let u = self.udp.borrow();
                u.get(&h.as_raw())
                    .cloned()
                    .and_then(|d| d.borrow_mut().take())
            };
            if let Some(cb) = cb {
                cb(data, from, port);
                if let Some(u) = self.udp.borrow().get(&h.as_raw()) {
                    *u.borrow_mut() = Some(cb);
                }
            }
        }

        fn fire_close(&self, h: Handle, reason: &str) {
            let cb = {
                let t = self.tcp.borrow();
                t.get(&h.as_raw())
                    .map(|(_, _, c)| c.clone())
                    .and_then(|c| c.borrow_mut().take())
            };
            if let Some(cb) = cb {
                cb(reason);
            }
        }

        fn fire_timer(&self, id: u32) {
            // TimerFn is Box<dyn Fn()> (not Clone): move the (id, ms, f,
            // repeating) tuple out, run f, and put a repeating timer back.
            let (ms, f, repeating) = {
                let mut ts = self.timers.borrow_mut();
                let Some(idx) = ts.iter().position(|(i, ..)| *i == id) else {
                    return;
                };
                let (_, ms, f, repeating) = ts.remove(idx);
                (ms, f, repeating)
            };
            if let Some(f) = f {
                f();
                if repeating {
                    self.timers.borrow_mut().push((id, ms, Some(f), true));
                }
            }
        }

        fn fire_only_repeating_timer(&self) {
            let ids: Vec<u32> = self
                .timers
                .borrow()
                .iter()
                .filter(|(_, _, _, rep)| *rep)
                .map(|(id, ..)| *id)
                .collect();
            for id in ids {
                self.fire_timer(id);
            }
        }

        fn timer_ids(&self) -> Vec<u32> {
            self.timers.borrow().iter().map(|(id, ..)| *id).collect()
        }

        fn has_timer_with_period(&self, ms: u32) -> bool {
            self.timers.borrow().iter().any(|(_, m, ..)| *m == ms)
        }

        fn tcp_tx(&self) -> Vec<Vec<u8>> {
            self.tx
                .borrow()
                .iter()
                .filter_map(|t| match t {
                    Tx::Tcp(data) => Some(data.clone()),
                    _ => None,
                })
                .collect()
        }

        fn last_tcp(&self) -> Vec<u8> {
            self.tcp_tx().pop().unwrap_or_default()
        }

        fn tcp_tx_count(&self) -> usize {
            self.tcp_tx().len()
        }

        fn udp_tx(&self, dest_port: u16) -> Vec<Vec<u8>> {
            self.tx
                .borrow()
                .iter()
                .filter_map(|t| match t {
                    Tx::Udp {
                        dest_port: p, data, ..
                    } if *p == dest_port => Some(data.clone()),
                    _ => None,
                })
                .collect()
        }

        fn all_tx(&self) -> Vec<Tx> {
            self.tx.borrow().clone()
        }
    }

    impl Transport for MockTransport {
        fn tcp_connect(
            &self,
            _host: &str,
            _port: u16,
            on_connected: ConnectFn,
            on_data: DataFn,
            on_closed: ClosedFn,
        ) -> Option<Handle> {
            let h = self.alloc_handle();
            self.tcp.borrow_mut().insert(
                h.as_raw(),
                (
                    Rc::new(RefCell::new(Some(on_connected))),
                    Rc::new(RefCell::new(Some(on_data))),
                    Rc::new(RefCell::new(Some(on_closed))),
                ),
            );
            Some(h)
        }

        fn udp_bind(&self, _port: u16, on_data: DataFn) -> Option<Handle> {
            let h = self.alloc_handle();
            self.udp
                .borrow_mut()
                .insert(h.as_raw(), Rc::new(RefCell::new(Some(on_data))));
            Some(h)
        }

        fn local_port(&self, h: Handle) -> Option<u16> {
            self.local_ports.borrow().get(&h.as_raw()).copied()
        }

        fn local_address(&self, h: Handle) -> Option<String> {
            self.local_ips.borrow().get(&h.as_raw()).cloned()
        }

        fn peer_address(&self, h: Handle) -> Option<String> {
            self.peer_ips.borrow().get(&h.as_raw()).cloned()
        }

        fn send(&self, h: Handle, data: &[u8]) -> bool {
            if !self.tcp.borrow().contains_key(&h.as_raw()) {
                return false;
            }
            self.tx.borrow_mut().push(Tx::Tcp(data.to_vec()));
            true
        }

        fn send_to(&self, h: Handle, host: &str, port: u16, data: &[u8]) -> bool {
            if !self.udp.borrow().contains_key(&h.as_raw()) {
                return false;
            }
            self.tx.borrow_mut().push(Tx::Udp {
                dest_host: host.to_string(),
                dest_port: port,
                data: data.to_vec(),
            });
            true
        }

        fn close(&self, h: Handle) {
            self.tcp.borrow_mut().remove(&h.as_raw());
            self.udp.borrow_mut().remove(&h.as_raw());
        }

        fn every(&self, ms: u32, f: TimerFn) -> TimerId {
            self.alloc_timer(ms, f, true)
        }

        fn after(&self, ms: u32, f: TimerFn) -> TimerId {
            self.alloc_timer(ms, f, false)
        }

        fn cancel(&self, id: TimerId) {
            self.timers.borrow_mut().retain(|(i, ..)| *i != id.as_raw());
        }

        fn poll(&self, _timeout_ms: i32) {}
    }

    impl MockTransport {
        fn alloc_timer(&self, ms: u32, f: TimerFn, repeating: bool) -> TimerId {
            let n = self.next_timer.get() + 1;
            self.next_timer.set(n);
            self.timers.borrow_mut().push((n, ms, Some(f), repeating));
            TimerId::from_raw(n)
        }
    }

    // ── helpers ────────────────────────────────────────────────────────

    fn harness() -> (Rc<MockTransport>, Session, Rc<RefCell<Vec<String>>>) {
        let m = Rc::new(MockTransport::default());
        let events: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let ev = events.clone();
        let s = Session::new(
            m.clone(),
            Callbacks {
                on_launched: Box::new(move |ok, why| {
                    ev.borrow_mut().push(format!("launched {ok} {why}"))
                }),
                on_closed: Box::new({
                    let ev = events.clone();
                    move || ev.borrow_mut().push("closed".to_string())
                }),
                on_pin_required: Box::new({
                    let ev = events.clone();
                    move |n| ev.borrow_mut().push(format!("pin {n}"))
                }),
                on_credentials_obtained: Box::new({
                    let ev = events.clone();
                    move |id, c| ev.borrow_mut().push(format!("creds {id} {c}"))
                }),
            },
        );
        (m, s, events)
    }

    fn start_ap1(m: &Rc<MockTransport>, s: &Session) -> Handle {
        s.set_auth(Auth::NoAuth, false, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        assert!(s.active());
        // UDP trio bound (audio last, send-only), one TCP connect pending.
        assert_eq!(m.udp.borrow().len(), 3);
        assert_eq!(m.tcp.borrow().len(), 1);
        let rtsp = m.tcp_handles()[0];
        m.set_local_ip(rtsp, "192.0.2.77");
        m.set_peer_ip(rtsp, "192.0.2.1");
        for h in m.udp_handles_for_test() {
            let raw = h.as_raw();
            m.set_local_port(h, (51000 + raw % 1000) as u16);
        }
        m.fire_connect(rtsp);
        rtsp
    }

    /// Drive OPTIONS → ANNOUNCE → SETUP → RECORD against `rtsp` and
    /// return after the RECORD 200 (streaming has started).
    fn ap1_handshake_to_streaming(m: &Rc<MockTransport>, _s: &Session, rtsp: Handle) {
        let opts = m.last_tcp();
        assert!(String::from_utf8_lossy(&opts).starts_with("OPTIONS * RTSP/1.0\r\n"));
        m.fire_data(rtsp, b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n");

        let ann = m.last_tcp();
        let ann = String::from_utf8_lossy(&ann);
        assert!(ann.starts_with("ANNOUNCE rtsp://192.0.2.77/"), "got {ann}");
        assert!(ann.contains("Content-Type: application/sdp\r\n"));
        assert!(ann.contains("a=rtpmap:96 L16/44100/2\r\n"));
        m.fire_data(rtsp, b"RTSP/1.0 200 OK\r\n\r\n");

        let setup = m.last_tcp();
        let setup = String::from_utf8_lossy(&setup);
        assert!(setup.starts_with("SETUP rtsp://192.0.2.77/"));
        assert!(
            setup.contains(
                "Transport: RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=51"
            ),
            "got {setup}"
        );
        m.fire_data(
            rtsp,
            b"RTSP/1.0 200 OK\r\nTransport: RTP/AVP/UDP;unicast;mode=record;server_port=5001;control_port=6001;timing_port=7001\r\nSession: 42\r\n\r\n",
        );

        let rec = m.last_tcp();
        let rec = String::from_utf8_lossy(&rec);
        assert!(rec.starts_with("RECORD rtsp://192.0.2.77/"));
        assert!(rec.contains("Range: npt=0-\r\n"));
        assert!(rec.contains("RTP-Info: seq="));
        assert!(rec.contains("Session: 42\r\n"));
        m.fire_data(rtsp, b"RTSP/1.0 200 OK\r\nAudio-Latency: 22050\r\n\r\n");
    }

    fn assert_launched(events: &Rc<RefCell<Vec<String>>>, ok: bool, why: &str) {
        // fail_ fires launched(false, why) then closed, so the launched
        // event may not be the last one.
        let evs = events.borrow();
        let want = format!("launched {ok} {why}");
        assert!(evs.iter().any(|e| e == &want), "events: {evs:?}");
    }

    fn audio_seq(m: &Rc<MockTransport>, port: u16) -> u16 {
        let pkts = m.udp_tx(port);
        let first = pkts.first().expect("an audio packet was sent");
        u16::from_be_bytes([first[2], first[3]])
    }

    // ── AP1 ────────────────────────────────────────────────────────────

    #[test]
    fn ap1_full_flow_streams_syncs_and_paces() {
        let (m, s, events) = harness();
        let rtsp = start_ap1(&m, &s);

        // Ring with one full 352-frame packet worth of PCM.
        let ring = Rc::new(RefCell::new(RingBuffer::new(8192)));
        let samples: Vec<i16> = (0..FRAMES_PER_PACKET * CHANNELS)
            .map(|i| (i as i16).wrapping_mul(7))
            .collect();
        assert!(ring.borrow_mut().try_push(&samples));
        s.attach_ring(ring);
        s.set_input_format(44100); // passthrough, like the C++ frontend

        ap1_handshake_to_streaming(&m, &s, rtsp);

        assert_launched(&events, true, "");
        assert_eq!(s.state_for_test(), SessionState::Streaming);

        // First sync (marker) went to control_port=6001 BEFORE the pacer
        // started.
        let syncs = m.udp_tx(6001);
        assert!(!syncs.is_empty());
        assert_eq!(syncs[0][0], 0x90);
        assert_eq!(syncs[0][1], 0xD4);
        assert_eq!(u16::from_be_bytes([syncs[0][2], syncs[0][3]]), 0x0007);

        // Audio arrives on the first pacer tick. Backdate the clock 100 ms
        // so the burst is deterministic: 12 packets (4410 target frames,
        // 352 per packet, under the 16-per-tick cap).
        s.backdate_clock_for_test(Duration::from_millis(100));
        m.fire_only_repeating_timer(); // sync + pacer
        let audio = m.udp_tx(5001);
        assert_eq!(audio.len(), 12);
        assert_eq!(audio[0][0], 0x80);
        assert_eq!(audio[0][1], 0xE0); // marker on the first packet
        // AP1 payload: big-endian s16 of the ring samples.
        assert_eq!(audio[0].len(), 12 + FRAMES_PER_PACKET * CHANNELS * 2);
        for i in 0..4 {
            let v = (i as i16).wrapping_mul(7) as u16;
            assert_eq!(audio[0][12 + 2 * i..12 + 2 * i + 2], v.to_be_bytes());
        }

        // The ring drained; the next tick still advances the timeline.
        let n0 = m.udp_tx(5001).len();
        s.backdate_clock_for_test(Duration::from_millis(100)); // 200 ms total
        m.fire_only_repeating_timer();
        assert!(m.udp_tx(5001).len() > n0);
        let syncs2 = m.udp_tx(6001);
        assert_eq!(syncs2.last().unwrap()[0], 0x80); // no marker after the first

        // AP1 keep-alive probe: one POST /feedback, and its 200 arms the
        // 25 s timer.
        let posts: Vec<Vec<u8>> = m
            .tcp_tx()
            .into_iter()
            .filter(|b| String::from_utf8_lossy(b).starts_with("POST /feedback"))
            .collect();
        assert_eq!(posts.len(), 1);
        assert!(!m.has_timer_with_period(25_000));
        m.fire_data(rtsp, b"RTSP/1.0 200 OK\r\nCSeq: 4\r\n\r\n");
        assert!(m.has_timer_with_period(25_000));

        // TEARDOWN on stop; second start works and binds a fresh trio.
        let tcp_before = m.tcp_tx_count();
        s.stop();
        assert!(!s.active());
        let tcp_tx = m.tcp_tx();
        let teardown = tcp_tx[tcp_before..]
            .iter()
            .find(|b| String::from_utf8_lossy(b).starts_with("TEARDOWN rtsp://192.0.2.77/"))
            .expect("TEARDOWN sent");
        assert!(String::from_utf8_lossy(teardown).contains("Session: 42\r\n"));
        assert_eq!(m.tcp.borrow().len(), 0);
        assert_eq!(m.udp.borrow().len(), 0);
        assert!(
            m.timer_ids().is_empty(),
            "all timers cancelled on stop: {:?}",
            m.timers
                .borrow()
                .iter()
                .map(|(i, ms, _, r)| (*i, *ms, *r))
                .collect::<Vec<_>>()
        );

        s.start("192.0.2.1", 7000, "test-device");
        assert_eq!(m.tcp.borrow().len(), 1);
        assert_eq!(m.udp.borrow().len(), 3);
    }

    #[test]
    fn ap1_retransmit_and_timing_responders() {
        let (m, s, _events) = harness();
        let rtsp = start_ap1(&m, &s);
        ap1_handshake_to_streaming(&m, &s, rtsp);

        // Get audio on the wire first (the pacer only runs on timer ticks).
        s.backdate_clock_for_test(Duration::from_millis(100));
        m.fire_only_repeating_timer();

        let first_seq = audio_seq(&m, 5001);
        // Retransmit request 0x55 for that seq (lost_count 1).
        let mut req = vec![0x80u8, 0x55, 0, 0, 0, 0, 0, 1];
        req[4..6].copy_from_slice(&first_seq.to_be_bytes());
        let before = m.udp_tx(6001).len();
        for h in m.udp_handles_for_test() {
            if m.local_ports.borrow().get(&h.as_raw()).is_some() {
                m.fire_udp_data(h, &req, "192.0.2.1", 6001);
            }
        }
        let resp = m.udp_tx(6001);
        let replay = resp.last().unwrap();
        assert_eq!(replay[0], 0x80);
        assert_eq!(replay[1], 0xD6);
        assert_eq!(u16::from_be_bytes([replay[2], replay[3]]), first_seq);
        // The response carries the full original packet.
        let original = m.udp_tx(5001).first().unwrap().clone();
        assert_eq!(replay[4..], original[..]);
        assert!(
            resp.len() > before,
            "response was sent on the control socket"
        );

        // Timing request (32 bytes) → 0xD3 reply echoing the sendtime.
        let mut timing = vec![0u8; 32];
        timing[0] = 0x11;
        timing[24..32].copy_from_slice(&0xDEAD_BEEFu64.to_be_bytes());
        for h in m.udp_handles_for_test() {
            m.fire_udp_data(h, &timing, "192.0.2.1", 7001);
        }
        let replies: Vec<Vec<u8>> = m
            .all_tx()
            .into_iter()
            .filter_map(|t| match t {
                Tx::Udp { data, .. } if data.len() == 32 && data[1] == 0xD3 => Some(data),
                _ => None,
            })
            .collect();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0][0], 0x11); // proto byte echoed
        assert_eq!(&replies[0][8..16], &0xDEAD_BEEFu64.to_be_bytes()); // reftime = sendtime
    }

    #[test]
    fn ap1_digest_401_retries_then_fails() {
        let (m, s, events) = harness();
        s.set_auth(Auth::Password, false, "dev-1", "", "s3cret");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);

        let opts = m.last_tcp();
        assert!(String::from_utf8_lossy(&opts).starts_with("OPTIONS * RTSP/1.0\r\n"));
        assert!(!String::from_utf8_lossy(&opts).contains("Authorization:"));
        m.fire_data(
            rtsp,
            b"RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"AirPlay\", nonce=\"deadbeefcafe\"\r\n\r\n",
        );

        // Re-issued with the digest Authorization header.
        let retry = m.last_tcp();
        let retry = String::from_utf8_lossy(&retry);
        assert!(retry.starts_with("OPTIONS * RTSP/1.0\r\n"));
        assert!(retry.contains(
            "Authorization: Digest username=\"iTunes\", realm=\"AirPlay\", nonce=\"deadbeefcafe\""
        ));
        assert!(retry.contains("response="));

        // A second 401 is fatal.
        m.fire_data(rtsp, b"RTSP/1.0 401 Unauthorized\r\n\r\n");
        assert!(!s.active());
        assert_launched(
            &events,
            false,
            "The password was not accepted by the device",
        );
        assert!(events.borrow().last() == Some(&"closed".to_string()));
    }

    #[test]
    fn ap1_requires_password_when_challenged() {
        let (m, s, events) = harness();
        s.set_auth(Auth::Password, false, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);
        m.fire_data(rtsp, b"RTSP/1.0 401 Unauthorized\r\n\r\n");
        assert_launched(&events, false, "The device requires a password");
    }

    #[test]
    fn callbacks_may_reenter_session_methods() {
        // The CLI demo blocks inside `on_pin_required` and calls
        // `submit_pin` (C++ `submitPin` from the callback). Callbacks must
        // therefore run with NO inner borrow held: the fire/dispatch paths
        // swap the callbacks out, invoke with zero borrows, and swap back.
        let m = Rc::new(MockTransport::default());
        let events: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let ev = events.clone();
        let holder: Rc<RefCell<Option<Session>>> = Rc::new(RefCell::new(None));
        let h2 = holder.clone();
        let s = Session::new(
            m.clone(),
            Callbacks {
                on_launched: Box::new(|_, _| {}),
                on_closed: Box::new(|| {}),
                on_pin_required: Box::new(move |_n: &str| {
                    // Re-entrant: the demo pattern (submit_pin from inside
                    // the callback) must not panic on the RefCell.
                    h2.borrow().as_ref().expect("holder set").submit_pin("1234");
                    ev.borrow_mut().push("pin-callback-ran".to_string());
                }),
                on_credentials_obtained: Box::new(|_, _| {}),
            },
        );
        *holder.borrow_mut() = Some(s.clone());
        s.set_auth(Auth::HapPin, true, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);
        m.fire_data(rtsp, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"); // pin-start 200
        let mut m2 = tlv(0x02, b"fake-salt");
        m2.extend(tlv(0x03, &[0xCDu8; 64]));
        let mut rep = b"HTTP/1.1 200 OK\r\nContent-Length: 77\r\n\r\n".to_vec();
        rep.extend_from_slice(&m2);
        m.fire_data(rtsp, &rep); // M2 desires a PIN → on_pin_required
        assert!(events.borrow().contains(&"pin-callback-ran".to_string()));
        assert_eq!(
            events.borrow().iter().filter(|e| *e == "pin-callback-ran").count(),
            1,
            "callback ran exactly once"
        );
        // The submit_pin from inside the callback actually took: the
        // machine is replying to M2 with the PIN-derived M3 (transient =
        // not waiting any more).
        assert!(!s.waiting_for_pin());
    }

    #[test]
    fn ap1_handshake_timeout_and_graceful_close() {
        // Timeout: the receiver never replies.
        let (m, s, events) = harness();
        start_ap1(&m, &s);
        let ids = m.timer_ids();
        let hst = *ids.first().expect("handshake timeout armed");
        m.fire_timer(hst);
        assert!(!s.active());
        assert_launched(&events, false, "Timed out waiting for the device");
        assert_eq!(events.borrow().last(), Some(&"closed".to_string()));

        // Graceful close: OPTIONS answered (Handshake), then close("").
        let (m, s, events) = harness();
        let rtsp = start_ap1(&m, &s);
        m.fire_data(rtsp, b"RTSP/1.0 200 OK\r\n\r\n"); // OPTIONS 200
        m.fire_close(rtsp, "");
        assert!(!s.active());
        assert_launched(&events, false, "Connection closed by the device");
        assert_eq!(events.borrow().last(), Some(&"closed".to_string()));

        // Non-empty close reason is a hard failure with that reason.
        let (m, s, events) = harness();
        let rtsp = start_ap1(&m, &s);
        m.fire_close(rtsp, "connection reset by peer");
        assert_launched(&events, false, "connection reset by peer");
    }

    #[test]
    fn ap1_volume_stored_then_pushed_and_live_updates() {
        let (m, s, events) = harness();
        s.set_auth(Auth::NoAuth, false, "dev-1", "", "");
        // Volume set BEFORE start() is deliberately discarded (C++:
        // "never carry volume between devices").
        s.set_volume(50.0);
        s.start("192.0.2.1", 7000, "test-device");
        // Volume set while the handshake runs is stored and pushed at
        // RECORD.
        s.set_volume(50.0);
        let rtsp = m.tcp_handles()[0];
        m.set_local_ip(rtsp, "192.0.2.77");
        m.fire_connect(rtsp);
        assert_eq!(m.tcp_tx_count(), 1, "only OPTIONS so far");
        m.fire_data(rtsp, b"RTSP/1.0 200 OK\r\n\r\n"); // OPTIONS
        m.fire_data(rtsp, b"RTSP/1.0 200 OK\r\n\r\n"); // ANNOUNCE
        m.fire_data(
            rtsp,
            b"RTSP/1.0 200 OK\r\nTransport: RTP/AVP/UDP;unicast;mode=record;server_port=5001;control_port=6001;timing_port=7001\r\nSession: 42\r\n\r\n",
        );
        let params: Vec<Vec<u8>> = m
            .tcp_tx()
            .into_iter()
            .filter(|b| String::from_utf8_lossy(b).starts_with("SET_PARAMETER"))
            .collect();
        assert_eq!(params.len(), 0, "still nothing pushed before RECORD");
        m.fire_data(rtsp, b"RTSP/1.0 200 OK\r\n\r\n"); // RECORD
        assert_launched(&events, true, "");

        let volume: Vec<Vec<u8>> = m
            .tcp_tx()
            .into_iter()
            .filter(|b| String::from_utf8_lossy(b).starts_with("SET_PARAMETER"))
            .collect();
        assert_eq!(volume.len(), 1, "the pending volume rides the RECORD reply");
        let v = String::from_utf8_lossy(&volume[0]);
        assert!(v.contains("Content-Type: text/parameters\r\n"));
        assert!(v.ends_with("volume: -15.000000"));
        assert!(v.contains("Session: 42\r\n"));

        // Live volume changes push immediately; 0 % is the mute sentinel.
        s.set_volume(0.0);
        let last = m.last_tcp();
        assert!(String::from_utf8_lossy(&last).ends_with("volume: -144.000000"));
        s.set_volume(25.0);
        assert!(String::from_utf8_lossy(&m.last_tcp()).ends_with("volume: -22.500000"));
    }

    #[test]
    fn ap1_metadata_pushes_and_change_dedup() {
        let (m, s, _events) = harness();
        let rtsp = start_ap1(&m, &s);
        ap1_handshake_to_streaming(&m, &s, rtsp);

        s.set_now_playing("Title", "Artist", "Album", &[1, 2, 3], "");
        let params: Vec<Vec<u8>> = m
            .tcp_tx()
            .into_iter()
            .filter(|b| String::from_utf8_lossy(b).starts_with("SET_PARAMETER"))
            .collect();
        assert_eq!(params.len(), 2);
        let dmap = String::from_utf8_lossy(&params[0]);
        assert!(dmap.contains("Content-Type: application/x-dmap-tagged\r\n"));
        assert!(dmap.contains("RTP-Info: seq="));
        let body = &params[0][dmap.find("\r\n\r\n").unwrap() + 4..];
        assert!(body.windows(4).any(|w| w == b"minm"));
        assert!(body.windows(4).any(|w| w == b"asal"));
        assert!(body.windows(4).any(|w| w == b"asar"));
        let cover = String::from_utf8_lossy(&params[1]);
        assert!(cover.contains("Content-Type: image/jpeg\r\n"));
        assert_eq!(
            &params[1][cover.find("\r\n\r\n").unwrap() + 4..],
            &[1, 2, 3]
        );

        // Unchanged metadata is not re-pushed.
        let n = m.tcp_tx_count();
        s.set_now_playing("Title", "Artist", "Album", &[1, 2, 3], "");
        assert_eq!(m.tcp_tx_count(), n);
        // A change is.
        s.set_now_playing("Title2", "Artist", "Album", &[1, 2, 3], "");
        assert_eq!(m.tcp_tx_count(), n + 2);
    }

    #[test]
    fn ap1_stray_reply_ignored_and_refused_request_fatal() {
        // A stray 500 while streaming (empty method FIFO) is ignored: the
        // live stream must not be torn down by a late/duplicate reply.
        let (m, s, events) = harness();
        let rtsp = start_ap1(&m, &s);
        ap1_handshake_to_streaming(&m, &s, rtsp);
        m.fire_data(rtsp, b"RTSP/1.0 500 Internal Server Error\r\n\r\n");
        assert!(s.active());
        assert_launched(&events, true, "");

        // A pre-streaming refusal IS fatal.
        let (m, s, events) = harness();
        s.set_auth(Auth::NoAuth, false, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);
        m.fire_data(rtsp, b"RTSP/1.0 500 Boom\r\n\r\n"); // OPTIONS refused
        assert!(!s.active());
        assert_launched(&events, false, "Device refused OPTIONS (500)");
    }

    // ── AP2 ────────────────────────────────────────────────────────────

    /// ChaCha20-Poly1305 AP2 frame, exactly `Ap2Channel::frame_out`.
    fn enc_frame(key: &[u8], ctr: u64, plain: &[u8]) -> Vec<u8> {
        let nonce = ctr.to_le_bytes();
        let len = plain.len();
        let aad = [len as u8, (len >> 8) as u8];
        let ct = airplay_crypto::chacha20_poly1305_encrypt(key, &nonce, plain, &aad)
            .expect("32-byte key");
        let mut out = aad.to_vec();
        out.extend_from_slice(&ct);
        out
    }

    fn dec_frame(key: &[u8], ctr: u64, framed: &[u8]) -> Vec<u8> {
        let len = u16::from_le_bytes([framed[0], framed[1]]) as usize;
        let nonce = ctr.to_le_bytes();
        airplay_crypto::chacha20_poly1305_decrypt(
            key,
            &nonce,
            &framed[2..2 + len + 16],
            &framed[0..2],
        )
        .expect("decrypt")
    }

    fn tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, payload.len() as u8];
        v.extend_from_slice(payload);
        v
    }

    fn assert_http_post(body: &[u8], uri: &str) {
        let s = String::from_utf8_lossy(body);
        assert!(
            s.starts_with(&format!("POST {uri} HTTP/1.1\r\n")),
            "got {s}"
        );
        assert!(s.contains("Connection: keep-alive\r\n"));
    }

    #[test]
    fn ap2_transient_full_flow_to_streaming() {
        let (m, s, events) = harness();
        s.set_auth(Auth::HapTransient, true, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.set_local_ip(rtsp, "192.0.2.77");
        m.fire_connect(rtsp);

        // M1: transient flag 0x10, X-Apple-HKP: 4.
        let m1 = m.last_tcp();
        assert_http_post(&m1, "/pair-setup");
        assert!(String::from_utf8_lossy(&m1).contains("X-Apple-HKP: 4\r\n"));
        let m1body = &m1[m1.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
        assert!(m1body.windows(3).any(|w| w == [0x00, 0x01, 0x00])); // Method
        assert!(m1body.windows(3).any(|w| w == [0x06, 0x01, 0x01])); // State
        assert!(m1body.windows(3).any(|w| w == [0x13, 0x01, 0x10])); // Flags 0x10

        // M2: salt + server B.
        let mut m2 = tlv(0x02, b"fake-salt");
        m2.extend(tlv(0x03, &[0xCDu8; 64]));
        let mut reply = b"HTTP/1.1 200 OK\r\nContent-Length: ".to_vec();
        reply.extend_from_slice(m2.len().to_string().as_bytes());
        reply.extend_from_slice(b"\r\n\r\n");
        reply.extend_from_slice(&m2);
        m.fire_data(rtsp, &reply);

        // Transient: M3 with the fixed PIN follows without user input.
        let m3 = m.last_tcp();
        assert_http_post(&m3, "/pair-setup");
        let m3body = &m3[m3.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
        assert!(m3body.windows(3).any(|w| w == [0x06, 0x01, 0x03])); // State 3
        // SRP 3072 A is a natural-length mpint (383/384 bytes), so decode
        // rather than match raw length bytes.
        let m3map = hap_tlv::decode(m3body);
        assert!(
            hap_tlv::get(&m3map, hap_tlv::PUBLIC_KEY).is_some(),
            "PublicKey TLV"
        );
        assert!(hap_tlv::get(&m3map, hap_tlv::PROOF).is_some(), "Proof TLV");
        assert_eq!(
            hap_tlv::get(&m3map, hap_tlv::STATE).map(|v| v.as_slice()),
            Some(&[0x03][..])
        );
        assert!(!s.waiting_for_pin());

        // M4: server proof (bogus → mismatch is warn-only) → keys derived.
        let m4 = tlv(0x04, &[0xABu8; 64]);
        reply = b"HTTP/1.1 200 OK\r\nContent-Length: 66\r\n\r\n".to_vec();
        reply.extend_from_slice(&m4);
        m.fire_data(rtsp, &reply);

        // The control channel is now encrypted: GET /info is framed.
        let (recv, send) = s.control_keys_for_test().expect("keys derived");
        assert_eq!(recv.len(), 32);
        assert_eq!(send.len(), 32);
        let mut ctr = 0u64;
        let info = m.last_tcp();
        let info_len = u16::from_le_bytes([info[0], info[1]]) as usize;
        assert!(info.len() >= 2 + info_len + 16, "framed: {}", info.len());
        let info_plain = dec_frame(&send, ctr, &info);
        assert_eq!(
            info_plain.len(),
            info_len,
            "length prefix matches plaintext"
        );
        assert!(info_plain.starts_with(b"GET /info RTSP/1.0\r\n"));
        ctr += 1;

        // Encrypted /info 200 → session SETUP. The /info reply advances
        // only the RECEIVE counter; the SETUP write is still send nonce 1.
        let body = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();
        m.fire_data(rtsp, &enc_frame(&recv, 0, &body));
        let session = m.last_tcp();
        let session_plain = dec_frame(&send, ctr, &session);
        ctr += 1;
        assert!(session_plain.starts_with(b"SETUP rtsp://192.0.2.77/"));
        assert!(
            session_plain
                .windows(46)
                .any(|w| w == b"Content-Type: application/x-apple-binary-plist"),
            "got {session_plain:?}"
        );

        // Session SETUP reply: eventPort → event channel opens + RECORD.
        let plist = bplist::encode(&Value::Dict(vec![(
            "eventPort".to_string(),
            Value::Int(12345),
        )]));
        let mut rep = b"HTTP/1.1 200 OK\r\nContent-Length: ".to_vec();
        rep.extend_from_slice(plist.len().to_string().as_bytes());
        rep.extend_from_slice(b"\r\n\r\n");
        rep.extend_from_slice(&plist);
        m.fire_data(rtsp, &enc_frame(&recv, 1, &rep));
        assert_eq!(m.tcp.borrow().len(), 2, "event channel connected");
        let record = m.last_tcp();
        let record_plain = dec_frame(&send, ctr, &record);
        ctr += 1;
        assert!(record_plain.starts_with(b"RECORD rtsp://192.0.2.77/"));

        // RECORD reply (rejected: 500) → still proceeds to stream SETUP.
        m.fire_data(
            rtsp,
            &enc_frame(&recv, 2, b"HTTP/1.1 500 Err\r\nContent-Length: 0\r\n\r\n"),
        );
        let stream = m.last_tcp();
        let stream_plain = dec_frame(&send, ctr, &stream);
        ctr += 1;
        assert!(stream_plain.starts_with(b"SETUP rtsp://192.0.2.77/"));
        assert!(
            stream_plain
                .windows(19)
                .any(|w| w == b"X-Apple-StreamID: 1")
        );
        assert!(stream_plain.windows(3).any(|w| w == b"shk"));

        // Stream SETUP reply: dataPort + controlPort → streaming.
        let streams = vec![
            ("dataPort".to_string(), Value::Int(6000)),
            ("controlPort".to_string(), Value::Int(6100)),
        ];
        let plist = bplist::encode(&Value::Dict(vec![(
            "streams".to_string(),
            Value::Arr(vec![Value::Dict(streams)]),
        )]));
        let mut rep = b"HTTP/1.1 200 OK\r\nContent-Length: ".to_vec();
        rep.extend_from_slice(plist.len().to_string().as_bytes());
        rep.extend_from_slice(b"\r\n\r\n");
        rep.extend_from_slice(&plist);
        m.fire_data(rtsp, &enc_frame(&recv, 3, &rep));

        assert_launched(&events, true, "");
        assert_eq!(s.state_for_test(), SessionState::Streaming);

        // AP2 default volume: 0 dB pushed once streaming (frame ctr 4).
        let vol = m.last_tcp();
        let vol_plain = dec_frame(&send, ctr, &vol);
        assert!(String::from_utf8_lossy(&vol_plain).ends_with("volume: 0.000000"));

        // Audio: encrypted ALAC (12 header + 1412 ALAC + 16 tag + 8
        // nonce) to the data port; sync to the control port. Audio flows
        // on the first pacer tick; backdate the clock for that, which
        // also fires the 2 s feedback timer once (its POST is the final
        // TCP send → frame ctr+1).
        assert!(m.has_timer_with_period(2000), "AP2 feedback timer armed");
        s.backdate_clock_for_test(Duration::from_millis(100));
        m.fire_only_repeating_timer(); // sync + pacer + feedback
        let audio = m.udp_tx(6000);
        assert!(!audio.is_empty());
        assert_eq!(audio[0].len(), 12 + 1412 + 16 + 8, "encrypted ALAC payload");
        assert_eq!(audio[0][1], 0xE0, "marker on the first audio packet");
        let syncs = m.udp_tx(6100);
        assert_eq!(syncs[0][1], 0xD4);

        // AP2 feedback: POST /feedback RTSP/1.0.
        let last = m.last_tcp();
        let plain = dec_frame(&send, ctr + 1, &last);
        assert!(
            plain.starts_with(b"POST /feedback RTSP/1.0\r\nCSeq:".as_slice()),
            "RTSP feedback, got {plain:?}"
        );
        assert!(plain.windows(21).any(|w| w == b"Content-Length: 0\r\n\r\n"));
    }

    #[test]
    fn ap2_transient_470_falls_back_to_pin() {
        let (m, s, _events) = harness();
        s.set_auth(Auth::HapTransient, true, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);
        m.fire_data(
            rtsp,
            b"HTTP/1.1 470 RTSP_CONNECTION_AUTH_REQUIRED\r\nContent-Length: 0\r\n\r\n",
        );
        // Fresh HapPin: /pair-pin-start with HKP 3.
        let pin_start = m.last_tcp();
        assert_http_post(&pin_start, "/pair-pin-start");
        assert!(String::from_utf8_lossy(&pin_start).contains("X-Apple-HKP: 3\r\n"));
        // And the stage advanced: a 200 there goes to M1.
        m.fire_data(rtsp, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m1 = m.last_tcp();
        assert_http_post(&m1, "/pair-setup");
        let body = &m1[m1.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
        assert!(
            !body.windows(3).any(|w| w == [0x13, 0x01, 0x10]),
            "no transient flag now"
        );
    }

    #[test]
    fn ap2_403_on_pin_start_tries_transient_once() {
        let (m, s, _events) = harness();
        s.set_auth(Auth::HapPin, true, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);
        let pin_start = m.last_tcp();
        assert_http_post(&pin_start, "/pair-pin-start");
        m.fire_data(rtsp, b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        // Mac-style: retried as transient M1 (HKP 4 + flags).
        let m1 = m.last_tcp();
        assert_http_post(&m1, "/pair-setup");
        assert!(String::from_utf8_lossy(&m1).contains("X-Apple-HKP: 4\r\n"));
        let body = &m1[m1.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
        assert!(body.windows(3).any(|w| w == [0x13, 0x01, 0x10]));
        // The retry is one-shot: another 403 on the M2 reply is fatal.
        m.fire_data(rtsp, b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        assert!(!s.active());
    }

    #[test]
    fn ap2_pin_flow_pin_required_submit_and_m6_failure() {
        let (m, s, events) = harness();
        s.set_auth(Auth::HapPin, true, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);
        m.fire_data(rtsp, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"); // pin-start
        // (No reply to M1: the M2 body below IS its reply.)

        // M2: the receiver wants a PIN.
        let mut m2 = tlv(0x02, b"fake-salt");
        m2.extend(tlv(0x03, &[0xCDu8; 64]));
        let mut rep = b"HTTP/1.1 200 OK\r\nContent-Length: 77\r\n\r\n".to_vec();
        rep.extend_from_slice(&m2);
        m.fire_data(rtsp, &rep);
        assert!(s.waiting_for_pin());
        assert_eq!(events.borrow().last(), Some(&"pin test-device".to_string()));

        // The handshake watchdog is parked during the PIN wait: the M2
        // handler stopped it, so only the 180 s pin timer is armed; a
        // 10 s handshake timeout would be wrong here.
        assert_eq!(
            m.timer_ids().len(),
            1,
            "timers: {:?}",
            m.timers
                .borrow()
                .iter()
                .map(|(i, ms, _, r)| (*i, *ms, *r))
                .collect::<Vec<_>>()
        );
        assert!(!m.has_timer_with_period(10_000));
        assert!(m.has_timer_with_period(180_000));

        s.submit_pin("1234");
        assert!(!s.waiting_for_pin());
        let m3 = m.last_tcp();
        assert_http_post(&m3, "/pair-setup");
        let m3body = &m3[m3.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
        assert!(m3body.windows(3).any(|w| w == [0x06, 0x01, 0x03]));

        // M4 without a proof → proceed to M5 (long-term key exchange).
        let m4 = tlv(0x02, b"");
        rep = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".to_vec();
        rep.extend_from_slice(&m4);
        m.fire_data(rtsp, &rep);
        let m5 = m.last_tcp();
        assert_http_post(&m5, "/pair-setup");
        let m5body = &m5[m5.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
        assert!(m5body.windows(3).any(|w| w == [0x06, 0x01, 0x05])); // State 5

        // M6 with an error TLV → the documented failure.
        let m6 = tlv(0x07, &[0x06]);
        rep = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n".to_vec();
        rep.extend_from_slice(&m6);
        m.fire_data(rtsp, &rep);
        assert!(!s.active());
        assert_launched(&events, false, "Pairing finalisation failed (error 6)");
    }

    #[test]
    fn ap2_stored_creds_skip_to_pair_verify() {
        let (m, s, events) = harness();
        let creds = r#"{"ltsk":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899","ltpk":"11223344556677889900112233445566778899aabbccddeeff00112233445566","atvId":"aabbccddeeff0011aabbccddeeff0011","clientId":"my-client"}"#;
        s.set_auth(Auth::HapPin, true, "dev-1", creds, "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);
        let verify = m.last_tcp();
        assert_http_post(&verify, "/pair-verify");
        assert!(!s.waiting_for_pin(), "stored creds skip the PIN");
        // An M2 without the required fields is an incomplete response.
        m.fire_data(
            rtsp,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\x01\x01",
        );
        assert!(!s.active());
        assert_launched(&events, false, "Pair-verify response incomplete");
    }

    #[test]
    fn ap2_setup_stream_requires_data_port() {
        let (m, s, events) = harness();
        s.set_auth(Auth::HapTransient, true, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);
        // M1 → M2 → M3 → M4 (keys), /info, session SETUP, RECORD.
        let mut m2 = tlv(0x02, b"fake-salt");
        m2.extend(tlv(0x03, &[0xCDu8; 64]));
        let mut rep = b"HTTP/1.1 200 OK\r\nContent-Length: 77\r\n\r\n".to_vec();
        rep.extend_from_slice(&m2);
        m.fire_data(rtsp, &rep);
        rep = b"HTTP/1.1 200 OK\r\nContent-Length: 66\r\n\r\n".to_vec();
        rep.extend_from_slice(&tlv(0x04, &[0xABu8; 64]));
        m.fire_data(rtsp, &rep);
        let (recv, send) = s.control_keys_for_test().unwrap();
        m.fire_data(
            rtsp,
            &enc_frame(&recv, 0, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        );
        m.fire_data(
            rtsp,
            &enc_frame(&recv, 1, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        );
        m.fire_data(
            rtsp,
            &enc_frame(&recv, 2, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        );
        // Stream SETUP reply without a data port → hard failure.
        m.fire_data(
            rtsp,
            &enc_frame(&recv, 3, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        );
        assert!(!s.active());
        assert_launched(
            &events,
            false,
            "AirPlay 2 stream SETUP returned no data port",
        );
        let _ = send;
    }

    #[test]
    fn auth_setup_flow() {
        let (m, s, events) = harness();
        s.set_auth(Auth::AuthSetup, false, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);

        let post = m.last_tcp();
        assert_http_post(&post, "/auth-setup");
        let body = &post[post.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
        assert_eq!(body.len(), 33);
        assert_eq!(body[0], 0x01); // mode = unencrypted

        // The reply is ignored entirely, then the classic handshake runs.
        m.fire_data(rtsp, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let opts = m.last_tcp();
        assert!(String::from_utf8_lossy(&opts).starts_with("OPTIONS * RTSP/1.0\r\n"));
        m.fire_data(rtsp, b"RTSP/1.0 200 OK\r\n\r\n");
        m.fire_data(rtsp, b"RTSP/1.0 200 OK\r\n\r\n");
        m.fire_data(
            rtsp,
            b"RTSP/1.0 200 OK\r\nTransport: RTP/AVP/UDP;unicast;mode=record;server_port=5001;control_port=6001;timing_port=7001\r\n\r\n",
        );
        m.fire_data(rtsp, b"RTSP/1.0 200 OK\r\n\r\n");
        assert_launched(&events, true, "");
    }

    #[test]
    fn legacy_pin_fails_fast() {
        let (m, s, events) = harness();
        s.set_auth(Auth::LegacyPin, false, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);
        assert!(!s.active());
        let evs = events.borrow();
        assert!(
            evs.iter()
                .any(|e| e.contains("older AirPlay pairing that isn't supported yet"))
        );
        assert_eq!(evs.last(), Some(&"closed".to_string()));
        let _ = m;
        let _ = rtsp;
    }

    #[test]
    fn pin_wait_timeout_fails_with_actionable_message() {
        let (m, s, events) = harness();
        s.set_auth(Auth::HapPin, true, "dev-1", "", "");
        s.start("192.0.2.1", 7000, "test-device");
        let rtsp = m.tcp_handles()[0];
        m.fire_connect(rtsp);
        m.fire_data(rtsp, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"); // pin-start
        // (No reply to M1: the M2 body below IS its reply.)
        let mut m2 = tlv(0x02, b"fake-salt");
        m2.extend(tlv(0x03, &[0xCDu8; 64]));
        let mut rep = b"HTTP/1.1 200 OK\r\nContent-Length: 77\r\n\r\n".to_vec();
        rep.extend_from_slice(&m2);
        m.fire_data(rtsp, &rep);
        assert!(s.waiting_for_pin());

        let pin_timer = m
            .timers
            .borrow()
            .iter()
            .find(|(_, ms, _, rep)| !*rep && *ms == 180_000)
            .map(|(id, ..)| *id)
            .expect("180 s pin watchdog armed");
        m.fire_timer(pin_timer);
        assert!(!s.active());
        assert_launched(
            &events,
            false,
            "No PIN was entered. Switch test-device on and make sure its screen shows the AirPlay code, then try again.",
        );
    }
}
