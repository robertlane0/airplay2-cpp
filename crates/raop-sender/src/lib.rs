// SPDX-License-Identifier: Apache-2.0
//! The pure protocol layer of the AirPlay RAOP sender — the first slice
//! of the [`src/raop_sender.{h,cpp}`](https://github.com/fxchain/cast/raw/…) migration.
//!
//! `src/raop_sender.cpp` is a 2073-line state machine. This crate ports
//! the parts that are pure and device-free today:
//!
//! * [`util`] — NTP/RTP timeline math, string/hex/JSON helpers, DMAP
//!   tagging, session constants;
//! * [`rtsp`] — the RTSP/HTTP control-plane wire: response parsing
//!   (`onRtspData_`), request builders (`sendRequest_` / `sendAp2Rtsp_` /
//!   `httpPost_` / AP2 feedback), the AP2 ChaCha20-Poly1305 channel
//!   framing (`writeRtsp_` / `onRtspData_` / `onEventData_`), the event
//!   channel's encrypted-200-OK responder, digest-challenge parsing, and
//!   the pure handshake payloads (SDP, volume, transport, RTP-Info,
//!   DMAP metadata);
//! * [`pairing`] — HAP pair-setup M1..M6 + pair-verify M1..M3 as a pure
//!   state container (`PairingSession`), creds-JSON handling;
//! * [`plists`] — the AP2 binary-plist session/stream SETUP payloads and
//!   reply parsing;
//! * [`stream`] — the RAOP UDP packet layer: RTP audio packets (AP1
//!   big-endian s16 / AP2 uncompressed-ALAC + ChaCha20-Poly1305), the
//!   SYNC packet (0x54), retransmit handling (0x55 → 0xD6) and the NTP
//!   timing reply (0xD3);
//! * [`input`] — the input pipeline (`fillFrames_`): pass-through and
//!   linear-interpolation resampler with bounded staging + compaction,
//!   and the pure pacer token bucket (`onPacerTick_`);
//! * [`session`] — the `RaopSender` state machine over the `transport`
//!   trait: `start`/`stop`, the auth/pairing chain, the AP2 flow (info →
//!   session SETUP → event channel + RECORD → stream SETUP), digest,
//!   streaming (sync/pacer/feedback, encrypted control + event
//!   channels, volume/metadata), and the retransmit/timing UDP
//!   responders.
//!
//! The remaining slice is the host-side audio path (`airplay-send`: the
//! `PcmStreamServer` + `RtspSession` hosts over `posix-transport`) and
//! then C++ removal.
//!
//! ### Behavior notes vs the C++ (all documented deviations)
//!
//! * Errors are `Result`-typed; the C++ fails the session with a message.
//!   Each error variant maps back to exactly one C++ `fail_` string so
//!   the state machine can reproduce the diagnostics.
//! * The inbound AP2 frame-length is capped at 32 KiB
//!   ([`rtsp::FrameError::OversizedFrame`]); the C++ has no such cap and
//!   would grow its encrypted accumulator unboundedly against a hostile
//!   length prefix (an LE16-encoded length can reach at most 65535, so
//!   32 KiB is the tightest power-of-two ceiling that keeps the cap
//!   reachable in practice).
//! * RNG failures (`util::rand_*`, `make_uuid`) propagate as
//!   `Result` instead of panicking.
//! * Some panic-free hardening where the C++ relies on
//!   fixed-length crypto inputs (checked `try_into` conversions).

pub mod input;
pub mod pairing;
pub mod plists;
pub mod rtsp;
pub mod session;
pub mod stream;
pub mod util;

pub use pairing::{PairingError, PairingMode, PairingSession, StoredCreds};
pub use rtsp::{Ap2Channel, FrameError, Response, StatusKind};
