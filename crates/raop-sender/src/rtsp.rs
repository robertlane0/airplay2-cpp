// SPDX-License-Identifier: Apache-2.0
//! The RTSP/HTTP control-plane wire layer of the AirPlay sender, ported
//! from [`src/raop_sender.cpp`](../../src/raop_sender.cpp).
//!
//! Everything here is pure (byte slices in, requests/responses out) and
//! mirrors the C++ byte-for-byte:
//!
//! * response parsing exactly as `onRtspData_` (lower-cased header keys,
//!   strict `content-length`, body capture, RTSP/HTTP/server-request
//!   classification);
//! * request builders exactly as `sendRequest_` / `sendAp2Rtsp_` /
//!   `httpPost_` (header order is observable wire behavior);
//! * the AP2 ChaCha20-Poly1305 control/event channel framing
//!   (`writeRtsp_` / `onRtspData_` / `onEventData_`): `[2-byte LE
//!   len][cipher][16-byte tag]`, chunked at 1024 B, an 8-byte LE counter
//!   per direction, AAD = the 2 length bytes;
//! * the event-channel "answer every pushed request with an encrypted
//!   200 OK" responder (owntone's bare `Server`-only 200);
//! * digest-challenge parsing and the pure handshake payloads (SDP,
//!   volume, transport, RTP-Info, DMAP metadata).
//!
//! The `Response` type is `[{ satisfies Eq }]` so tests can assert on
//! parsed structure directly.

use std::collections::BTreeMap;

use crate::util::{dmap_tag, fixed6, split_str, to_int_or_0, to_uint_or_0, trimmed};
use airplay_crypto::digest_auth_response;

// ── byte-level parsing helpers (the C++ works on raw bytes) ────────────

/// Trim `" \t\r\n"` from both ends of a byte slice (raw `trimmed`).
fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|&c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|&c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        .map_or(start, |i| i + 1);
    &b[start..end]
}

/// ASCII-lowercase a byte slice in place of the returned Vec (`toLowerStr`
/// on raw bytes).
fn lower_ascii_bytes(b: &[u8]) -> Vec<u8> {
    b.iter().map(|&c| c.to_ascii_lowercase()).collect()
}

/// ASCII digits to u32, 0 when anything else is present (`toIntOr0` on a
/// raw byte slice).
fn ascii_to_u32(b: &[u8]) -> u32 {
    if b.is_empty() || !b.iter().all(|c| c.is_ascii_digit()) {
        return 0;
    }
    std::str::from_utf8(b).map_or(0, |s| s.parse::<u32>().unwrap_or(0))
}

// ── response parsing (onRtspData_ head/body loop) ──────────────────────

/// How a received message line classifies (`isRtsp` / `isHttp` / a
/// server→client request that we consume and ignore).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Rtsp,
    Http,
    ServerRequest,
}

/// One complete received control-plane message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub kind: StatusKind,
    pub code: u32,
    /// Lower-cased header keys, trimmed values (duplicates: last wins, as
    /// in the C++ map).
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Parse the next complete message out of `buf`, exactly like the
/// `onRtspData_` loop: find the `\r\n\r\n` head, parse status line +
/// headers, honor `content-length` (strict: a missing/bad/negative header
/// reads as 0) and only hand the message back when the whole body has
/// arrived.
///
/// Returns `(response, consumed)`; `None` when more bytes are needed.
pub fn parse_response(buf: &[u8]) -> Option<(Response, usize)> {
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = &buf[..head_end];

    // Headers: every line after the status line (split on '\n'; the '\r'
    // falls off via trim_bytes).
    let mut headers = BTreeMap::new();
    let mut lines: Vec<&[u8]> = head.split(|&b| b == b'\n').collect();
    if lines.is_empty() {
        lines.push(&[]); // unreachable: loops below rely on a first line
    }
    for line in &lines[1..] {
        let line = trim_bytes(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        if colon == 0 {
            continue; // C++: colon == npos || colon == 0 → skip
        }
        headers.insert(
            String::from_utf8_lossy(&lower_ascii_bytes(trim_bytes(&line[..colon]))).into_owned(),
            String::from_utf8_lossy(trim_bytes(&line[colon + 1..])).into_owned(),
        );
    }

    // content-length: strict parse, bad/negative → 0 (audit fix in C++).
    let content_len = match headers.get("content-length").map(String::as_str) {
        Some(v) => crate::util::to_int_checked(v)
            .filter(|n| *n >= 0)
            .map(|n| n as usize)
            .unwrap_or(0),
        None => 0,
    };
    let total = head_end + 4 + content_len;
    if buf.len() < total {
        return None; // body still arriving
    }

    // Status line: first head line.
    let status_line = trim_bytes(lines[0]);
    let (kind, code) = classify(status_line);

    Some((
        Response {
            kind,
            code,
            headers,
            body: buf[head_end + 4..total].to_vec(),
        },
        total,
    ))
}

/// Classify a status line and extract the numeric code (`parts[1]` as
/// decimal, 0 when missing/malformed).
pub fn classify(status_line: &[u8]) -> (StatusKind, u32) {
    let kind = if status_line.starts_with(b"RTSP/") {
        StatusKind::Rtsp
    } else if status_line.starts_with(b"HTTP/") {
        StatusKind::Http
    } else {
        StatusKind::ServerRequest
    };
    let parts: Vec<&[u8]> = status_line.split(|&b| b == b' ').collect();
    let code = parts.get(1).map_or(0, |p| ascii_to_u32(p));
    (kind, code)
}

// ── request builders (sendRequest_ / sendAp2Rtsp_ / httpPost_) ─────────

/// Build a plain RTSP request exactly as `sendRequest_`: status line,
/// One RTSP request (mirrors the C++ `sendRequest_` argument bundle):
/// identity headers (CSeq, User-Agent, DACP-ID, Active-Remote,
/// Client-Instance, X-Apple-Client-Name), optional `Authorization`
/// (RTSP digest, RFC 2617), extras, and Content-Type/Content-Length only
/// when non-empty. `digest` is `(realm, nonce, password)`; the username
/// is fixed `"iTunes"` like the C++.
pub struct RtspRequest<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub cseq: u32,
    pub dacp_id: &'a str,
    pub active_remote: u32,
    pub extra: &'a [(&'a str, &'a str)],
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
    pub digest: Option<(&'a str, &'a str, &'a str)>,
}

/// Render `req` exactly as `sendRequest_` does: request line, identity
/// headers, digest when given, extras, Content-Type/Length when the body
/// is non-empty, blank line, body.
pub fn build_rtsp_request(req: &RtspRequest<'_>) -> Vec<u8> {
    let mut s = format!("{} {} RTSP/1.0\r\n", req.method, req.uri);
    s.push_str(&format!("CSeq: {}\r\n", req.cseq));
    s.push_str("User-Agent: AirPlay/550.10\r\n");
    s.push_str(&format!("DACP-ID: {}\r\n", req.dacp_id));
    s.push_str(&format!("Active-Remote: {}\r\n", req.active_remote));
    s.push_str(&format!("Client-Instance: {}\r\n", req.dacp_id));
    s.push_str("X-Apple-Client-Name: FXChainPlayer\r\n");
    if let Some((realm, nonce, password)) = req.digest {
        let ah = digest_auth_response(req.method, req.uri, "iTunes", realm, password, nonce);
        s.push_str(&format!("Authorization: {ah}\r\n"));
    }
    for (k, v) in req.extra {
        s.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(ct) = req.content_type {
        s.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    if !req.body.is_empty() {
        s.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    }
    s.push_str("\r\n");
    let mut out = s.into_bytes();
    out.extend_from_slice(req.body);
    out
}

/// Build an encrypted-channel RTSP request exactly as `sendAp2Rtsp_
///` (AP2 plist methods): same identity header set as `sendRequest_`, plus
/// `X-Apple-StreamID: 1` on `SETUP` (owntone/pyatv parity), and no digest
/// (AP2 control is post-pairing).
pub fn build_ap2_rtsp(
    method: &str,
    uri: &str,
    cseq: u32,
    dacp_id: &str,
    active_remote: u32,
    content_type: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let mut req = format!("{method} {uri} RTSP/1.0\r\n");
    req.push_str(&format!("CSeq: {cseq}\r\n"));
    req.push_str("User-Agent: AirPlay/550.10\r\n");
    req.push_str(&format!("DACP-ID: {dacp_id}\r\n"));
    req.push_str(&format!("Active-Remote: {active_remote}\r\n"));
    req.push_str(&format!("Client-Instance: {dacp_id}\r\n"));
    req.push_str("X-Apple-Client-Name: FXChainPlayer\r\n");
    if method == "SETUP" {
        req.push_str("X-Apple-StreamID: 1\r\n");
    }
    if let Some(ct) = content_type {
        req.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Build an HTTP POST over the RTSP socket exactly as `httpPost_`
/// (pairing + AP2 plists): `X-Apple-HKP` (3 for PIN pairing, 4 for
/// transient), `Connection: keep-alive`, always a Content-Length (even
/// 0), and the owntone identity headers.
pub fn build_http_post(
    uri: &str,
    cseq: u32,
    dacp_id: &str,
    active_remote: u32,
    hkp: u8,
    content_type: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let mut req = format!("POST {uri} HTTP/1.1\r\n");
    req.push_str(&format!("CSeq: {cseq}\r\n"));
    req.push_str("User-Agent: AirPlay/550.10\r\n");
    req.push_str("Connection: keep-alive\r\n");
    req.push_str(&format!("X-Apple-HKP: {hkp}\r\n"));
    req.push_str(&format!("DACP-ID: {dacp_id}\r\n"));
    req.push_str(&format!("Active-Remote: {active_remote}\r\n"));
    req.push_str(&format!("Client-Instance: {dacp_id}\r\n"));
    req.push_str("X-Apple-Client-Name: FXChainPlayer\r\n");
    if let Some(ct) = content_type {
        req.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Build the AP2 keep-alive: `POST /feedback RTSP/1.0` with the standard
/// RTSP identity headers and `Content-Length: 0`. An `HTTP/1.1` line is
/// silently ignored by the receiver's RTSP parser, so this must stay an
/// RTSP request line (`onFeedbackTick_`).
pub fn build_ap2_feedback(cseq: u32, dacp_id: &str, active_remote: u32) -> Vec<u8> {
    let mut req = "POST /feedback RTSP/1.0\r\n".to_string();
    req.push_str(&format!("CSeq: {cseq}\r\n"));
    req.push_str("User-Agent: AirPlay/550.10\r\n");
    req.push_str(&format!("DACP-ID: {dacp_id}\r\n"));
    req.push_str(&format!("Active-Remote: {active_remote}\r\n"));
    req.push_str(&format!("Client-Instance: {dacp_id}\r\n"));
    req.push_str("Content-Length: 0\r\n\r\n");
    req.into_bytes()
}

// ── digest challenge parsing (401 handling) ────────────────────────────

/// The value between the first two quotes after `key` in a header value
/// (`extractQuoted`); `None` when the key or a closed quote pair is
/// missing.
pub fn extract_quoted(header: &str, key: &str) -> Option<String> {
    let k = header.find(key)?;
    let rest = &header[k..];
    let q1 = rest.find('"')? + k;
    let rest2 = &header[q1 + 1..];
    let q2 = rest2.find('"')? + q1 + 1;
    Some(header[q1 + 1..q2].to_string())
}

/// `(realm, nonce)` from a `WWW-Authenticate: Digest …` header; `nonce`
/// must be present (`handleResponse_` fails the session otherwise).
pub fn parse_digest_challenge(www_authenticate: &str) -> (Option<String>, Option<String>) {
    (
        extract_quoted(www_authenticate, "realm="),
        extract_quoted(www_authenticate, "nonce="),
    )
}

// ── AP2 encrypted channel framing (writeRtsp_ / onRtspData_) ───────────

/// A directional ChaCha20-Poly1305 framed channel, as used for the AP2
/// control connection AND the event channel (the event channel is a
/// reverse connection: its decrypt key is the receiver's write key and
/// vice versa — the caller just installs them swapped).
///
/// Wire format per frame: `[2-byte LE length][ciphertext][16-byte
/// tag]`, AAD = the 2 length bytes, nonce = the 8-byte little-endian
/// counter (`counter_nonce8`), incrementing once per frame per direction.
/// Outbound plaintext is chunked at 1024 bytes.
///
/// With no keys installed the channel is identity (plaintext AP1 mode).
#[derive(Debug, Default)]
pub struct Ap2Channel {
    /// Decrypt key (controlIn / eventIn). Empty = plaintext mode.
    recv_key: Vec<u8>,
    /// Encrypt key (controlOut / eventOut). Empty = plaintext mode.
    send_key: Vec<u8>,
    recv_ctr: u64,
    send_ctr: u64,
    /// Raw (still-encrypted) accumulator.
    recv_buf: Vec<u8>,
}

/// Why an inbound frame could not be consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Frame length prefix is unreasonable (hardening: no such cap exists
    /// in the C++; a hostile length would otherwise grow `recv_buf`
    /// unboundedly while waiting for the body).
    OversizedFrame,
    /// The tag did not verify (bad key, wrong counter, or tampering).
    AuthFailed,
}

/// The largest inbound frame length accepted. Control-plane messages are
/// tiny (requests are bounded by the 1-kiB chunk size), so 32 KiB is a
/// generous ceiling; the cap is also what makes the LE16 frame prefix
/// (max 65535) actually enforceable.
const MAX_FRAME_LEN: usize = 32 * 1024;

impl Ap2Channel {
    /// A plaintext (identity) channel.
    pub fn plain() -> Self {
        Self::default()
    }

    /// Install 32-byte decrypt + encrypt keys; resets counters and the
    /// inbound accumulator, flipping the channel into encrypted mode
    /// (mirrors `afterAuthOk_` resetting `ctrlSendCtr_`/`ctrlRecvCtr_`
    /// when the control channel keys up).
    pub fn install_keys(&mut self, recv_key: &[u8], send_key: &[u8]) {
        debug_assert_eq!(recv_key.len(), 32);
        debug_assert_eq!(send_key.len(), 32);
        self.recv_key = recv_key.to_vec();
        self.send_key = send_key.to_vec();
        self.recv_ctr = 0;
        self.send_ctr = 0;
        self.recv_buf.clear();
    }

    pub fn encrypted(&self) -> bool {
        !self.recv_key.is_empty()
    }

    /// Frame outbound plaintext: identity passthrough when plaintext
    /// mode, else `[len][cipher][tag]` chunks at 1024 B (`writeRtsp_`).
    pub fn frame_out(&mut self, plain: &[u8]) -> Vec<u8> {
        if !self.encrypted() {
            return plain.to_vec();
        }
        let mut out = Vec::with_capacity(plain.len() + plain.len() / 1024 * 18 + 18);
        let mut off = 0;
        while off < plain.len() {
            let len = 1024.min(plain.len() - off);
            let nonce8 = self.send_ctr.to_le_bytes();
            self.send_ctr = self.send_ctr.wrapping_add(1);
            let ct = airplay_crypto::chacha20_poly1305_encrypt(
                &self.send_key,
                &nonce8,
                &plain[off..off + len],
                &[len as u8, (len >> 8) as u8],
            )
            .expect("32-byte send key and 8-byte nonce; encryption cannot fail");
            out.push(len as u8);
            out.push((len >> 8) as u8);
            out.extend_from_slice(&ct);
            off += len;
        }
        out
    }

    /// Feed inbound bytes; returns the decrypted plaintext produced
    /// (empty when a frame boundary is pending), or a framing error. On
    /// `AuthFailed`/`OversizedFrame` the accumulator is dropped (matches
    /// the event-channel "decrypt failed, dropping" path; the control
    /// channel treats the same failure as fatal at the caller level).
    /// Identity passthrough in plaintext mode.
    pub fn feed_in(&mut self, data: &[u8]) -> Result<Vec<u8>, FrameError> {
        if !self.encrypted() {
            return Ok(data.to_vec());
        }
        self.recv_buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if self.recv_buf.len() < 2 {
                break;
            }
            let len = u16::from_le_bytes([self.recv_buf[0], self.recv_buf[1]]) as usize;
            if len > MAX_FRAME_LEN {
                self.recv_buf.clear();
                return Err(FrameError::OversizedFrame);
            }
            let need = 2 + len + 16;
            if self.recv_buf.len() < need {
                break; // frame still arriving
            }
            let nonce8 = self.recv_ctr.to_le_bytes();
            self.recv_ctr = self.recv_ctr.wrapping_add(1);
            let Some(dec) = airplay_crypto::chacha20_poly1305_decrypt(
                &self.recv_key,
                &nonce8,
                &self.recv_buf[2..need],
                &[self.recv_buf[0], self.recv_buf[1]],
            ) else {
                self.recv_buf.clear();
                return Err(FrameError::AuthFailed);
            };
            out.extend_from_slice(&dec);
            self.recv_buf.drain(..need);
        }
        Ok(out)
    }
}

// ── event channel responder (onEventData_) ─────────────────────────────

/// A complete RTSP request extracted from the decrypted event stream:
/// CSeq header value and the total bytes (head + body) it occupies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRequest {
    pub cseq: Option<String>,
    pub total: usize,
}

/// Find the next complete request (`\r\n\r\n` head + `content-length`
/// body) in the plaintext event stream; `None` until it has fully
/// arrived. `content-length` uses the lenient parse here (`toIntOr0`),
/// exactly like `onEventData_`.
pub fn next_event_request(buf: &[u8]) -> Option<EventRequest> {
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let mut content_len = 0usize;
    let mut cseq = None;
    for line in buf[..head_end].split(|&b| b == b'\n').skip(1) {
        let line = trim_bytes(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        if colon == 0 {
            continue;
        }
        let k = lower_ascii_bytes(trim_bytes(&line[..colon]));
        let v = trim_bytes(&line[colon + 1..]);
        if k == b"content-length" {
            content_len = ascii_lenient(to_int_or_0(&String::from_utf8_lossy(v)));
        } else if k == b"cseq" {
            cseq = Some(String::from_utf8_lossy(v).into_owned());
        }
    }
    let total = head_end + 4 + content_len;
    if buf.len() < total {
        return None;
    }
    Some(EventRequest { cseq, total })
}

/// `toIntOr0` result to a non-negative usize (lenient path).
fn ascii_lenient(v: i64) -> usize {
    v.max(0) as usize
}

/// The bare 200 OK for one pushed event (owntone's `respond()`: `Server`
/// only, no Content-Length/Audio-Latency which corrupt the receiver's
/// timeline); echoes CSeq when the request carried one.
pub fn build_event_200_ok(cseq: Option<&str>) -> Vec<u8> {
    let mut resp = String::from("RTSP/1.0 200 OK\r\n");
    resp.push_str("Server: AirTunes/550.10\r\n");
    if let Some(cseq) = cseq {
        resp.push_str(&format!("CSeq: {cseq}\r\n"));
    }
    resp.push_str("\r\n");
    resp.into_bytes()
}

// ── pure handshake payloads ────────────────────────────────────────────

/// The `text/parameters` volume body: `volume: <dBFS>` (`fixed6`).
pub fn build_volume_body(dbfs: f64) -> Vec<u8> {
    format!("volume: {}", fixed6(dbfs)).into_bytes()
}

/// DMAP-tagged now-playing metadata: `mlit{minm asal asar}` (pyatv tag
/// order), empty fields omitted entirely, exactly like `sendMetadata_`.
pub fn build_dmap_metadata(title: &str, artist: &str, album: &str) -> Vec<u8> {
    let mut inner = Vec::new();
    if !title.is_empty() {
        inner.extend_from_slice(&dmap_tag("minm", title.as_bytes()));
    }
    if !album.is_empty() {
        inner.extend_from_slice(&dmap_tag("asal", album.as_bytes()));
    }
    if !artist.is_empty() {
        inner.extend_from_slice(&dmap_tag("asar", artist.as_bytes()));
    }
    if inner.is_empty() {
        return Vec::new();
    }
    dmap_tag("mlit", &inner)
}

/// The `RTP-Info` header value: `seq=<seq>;rtptime=<rtptime>`.
pub fn build_rtp_info(seq: u16, rtptime: u32) -> String {
    format!("seq={seq};rtptime={rtptime}")
}

/// The `Transport` header value for the SETUP request:
/// `RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=N;
/// timing_port=N`.
pub fn build_setup_transport(control_port: u16, timing_port: u16) -> String {
    format!(
        "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port={control_port};timing_port={timing_port}"
    )
}

/// The ANNOUNCE SDP body (raw PCM L16 with the classic fmtp list),
/// exactly as `sendAnnounce_`.
pub fn build_announce_sdp(session_id: u32, local_ip: &str, remote_ip: &str) -> Vec<u8> {
    let mut sdp = String::new();
    sdp.push_str("v=0\r\n");
    sdp.push_str(&format!("o=iTunes {session_id} 0 IN IP4 {local_ip}\r\n"));
    sdp.push_str("s=iTunes\r\n");
    sdp.push_str(&format!("c=IN IP4 {remote_ip}\r\n"));
    sdp.push_str("t=0 0\r\n");
    sdp.push_str("m=audio 0 RTP/AVP 96\r\n");
    sdp.push_str("a=rtpmap:96 L16/44100/2\r\n");
    sdp.push_str("a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100\r\n");
    sdp.into_bytes()
}

/// Parse the `Transport` reply header into (server_port, control_port,
/// timing_port), 0 for anything absent (`handleResponse_` SETUP arm).
pub fn parse_setup_transport_reply(transport: &str) -> (u16, u16, u16) {
    let mut server = 0u16;
    let mut control = 0u16;
    let mut timing = 0u16;
    for opt in split_str(transport, ';') {
        let opt = trimmed(&opt);
        let Some(eq) = opt.find('=') else { continue };
        if eq == 0 {
            continue;
        }
        let key = trimmed(&opt[..eq]);
        let val = to_uint_or_0(trimmed(&opt[eq + 1..])) as u16;
        match key {
            "server_port" => server = val,
            "control_port" => control = val,
            "timing_port" => timing = val,
            _ => {}
        }
    }
    (server, control, timing)
}

// ── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn str_response(buf: &[u8]) -> String {
        String::from_utf8_lossy(buf).into_owned()
    }

    const RTSP_200_HEAD: &str = "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: AirTunes/550.10\r\n\r\n";

    #[test]
    fn parse_simple_200() {
        let (r, consumed) = parse_response(RTSP_200_HEAD.as_bytes()).expect("complete");
        assert_eq!(consumed, RTSP_200_HEAD.len());
        assert_eq!(r.kind, StatusKind::Rtsp);
        assert_eq!(r.code, 200);
        assert_eq!(r.headers.get("cseq").map(String::as_str), Some("1"));
        assert_eq!(
            r.headers.get("server").map(String::as_str),
            Some("AirTunes/550.10")
        );
        assert!(r.body.is_empty());
    }

    #[test]
    fn parse_needs_more_bytes() {
        let full = RTSP_200_HEAD.as_bytes();
        assert!(parse_response(&full[..full.len() - 3]).is_none());
    }

    #[test]
    fn parse_header_keys_lowercased_values_trimmed() {
        let buf = b"RTSP/1.0 200 OK\r\nX-CaMeL:  v1  \r\nDup: a\r\nDup: b\r\n\r\n";
        let (r, _) = parse_response(buf).expect("complete");
        assert_eq!(r.headers.get("x-camel").map(String::as_str), Some("v1"));
        // Duplicate header: last wins (C++ map assignment).
        assert_eq!(r.headers.get("dup").map(String::as_str), Some("b"));
    }

    #[test]
    fn parse_body_by_content_length() {
        let body = b"hello world";
        let mut buf =
            format!("RTSP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        buf.extend_from_slice(body);
        // Feed hits: head complete but body missing → None.
        assert!(parse_response(&buf[..buf.len() - 2]).is_none());
        let (r, consumed) = parse_response(&buf).expect("complete");
        assert_eq!(r.body, body);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_bad_content_length_treated_as_zero() {
        for bad in ["abc", "-1", "12x"] {
            let buf = format!("RTSP/1.0 200 OK\r\nContent-Length: {bad}\r\n\r\n").into_bytes();
            let (r, consumed) = parse_response(&buf).expect("complete");
            assert!(r.body.is_empty(), "len={bad}");
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn parse_multiple_messages_in_one_buffer() {
        let mut buf = RTSP_200_HEAD.as_bytes().to_vec();
        let second = b"HTTP/1.1 470 Bad\r\nCSeq: 2\r\nContent-Length: 3\r\n\r\nABC";
        buf.extend_from_slice(second);
        let (r1, c1) = parse_response(&buf).expect("first");
        assert_eq!(r1.kind, StatusKind::Rtsp);
        let (r2, c2) = parse_response(&buf[c1..]).expect("second");
        assert_eq!(r2.kind, StatusKind::Http);
        assert_eq!(r2.code, 470);
        assert_eq!(r2.body, b"ABC");
        assert_eq!(c1 + c2, buf.len());
    }

    #[test]
    fn parse_server_request_classified_and_consumed() {
        let buf = b"ANNOUNCE rtsp://1.2.3.4/5 RTSP/1.0\r\nCSeq: 9\r\n\r\n";
        let (r, consumed) = parse_response(buf).expect("complete");
        assert_eq!(r.kind, StatusKind::ServerRequest);
        assert_eq!(r.code, 0); // parts[1] is not a number
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn classify_edge_lines() {
        assert_eq!(
            classify(b"RTSP/1.0 401 Unauthorized"),
            (StatusKind::Rtsp, 401)
        );
        assert_eq!(classify(b"HTTP/1.1 200 OK"), (StatusKind::Http, 200));
        assert_eq!(classify(b"RTSP/1.0 200"), (StatusKind::Rtsp, 200));
        assert_eq!(classify(b"RTSP/1.0 OK"), (StatusKind::Rtsp, 0));
        assert_eq!(classify(b"junk"), (StatusKind::ServerRequest, 0));
        assert_eq!(classify(b"RTSP/1.0 12x"), (StatusKind::Rtsp, 0));
    }

    #[test]
    fn build_plain_rtsp_request_golden() {
        let req = build_rtsp_request(&RtspRequest {
            method: "OPTIONS",
            uri: "*",
            cseq: 0,
            dacp_id: "DACPID1",
            active_remote: 42,
            extra: &[],
            content_type: None,
            body: b"",
            digest: None,
        });
        assert_eq!(
            str_response(&req),
            "OPTIONS * RTSP/1.0\r\n\
             CSeq: 0\r\n\
             User-Agent: AirPlay/550.10\r\n\
             DACP-ID: DACPID1\r\n\
             Active-Remote: 42\r\n\
             Client-Instance: DACPID1\r\n\
             X-Apple-Client-Name: FXChainPlayer\r\n\
             \r\n"
        );
    }

    #[test]
    fn build_rtsp_request_with_body_extras_type_and_digest() {
        let req = build_rtsp_request(&RtspRequest {
            method: "SET_PARAMETER",
            uri: "rtsp://1.2.3.4/7",
            cseq: 3,
            dacp_id: "D",
            active_remote: 1,
            extra: &[("Session", "AB12")],
            content_type: Some("text/parameters"),
            body: b"volume: -15.000000",
            digest: Some(("AirPlay", "nonce123", "sekrit")),
        });
        let s = str_response(&req);
        assert!(s.starts_with("SET_PARAMETER rtsp://1.2.3.4/7 RTSP/1.0\r\n"));
        assert!(s.contains("CSeq: 3\r\n"));
        assert!(s.contains("Session: AB12\r\n"));
        assert!(s.contains("Content-Type: text/parameters\r\n"));
        assert!(s.contains("Content-Length: 18\r\n\r\n"));
        assert!(s.ends_with("volume: -15.000000"));
        // RFC 2617 MD5 Authorization, username fixed to iTunes.
        assert!(
            s.contains("Authorization: Digest username=\"iTunes\", realm=\"AirPlay\", nonce=\"nonce123\", uri=\"rtsp://1.2.3.4/7\", response=\"")
        );
    }

    #[test]
    fn build_ap2_rtsp_stream_id_only_on_setup() {
        let setup = build_ap2_rtsp("SETUP", "rtsp://h/1", 1, "D", 2, Some("ct"), b"plist");
        let s = str_response(&setup);
        assert!(s.contains("X-Apple-StreamID: 1\r\n"));
        assert!(s.starts_with("SETUP rtsp://h/1 RTSP/1.0\r\n"));
        let record = build_ap2_rtsp("RECORD", "rtsp://h/1", 2, "D", 2, None, b"");
        let s2 = str_response(&record);
        assert!(!s2.contains("X-Apple-StreamID"));
        assert!(s2.starts_with("RECORD rtsp://h/1 RTSP/1.0\r\n"));
    }

    #[test]
    fn build_http_post_golden() {
        let req = build_http_post(
            "/pair-setup",
            4,
            "D",
            7,
            3,
            Some("application/octet-stream"),
            b"\x06\x01",
        );
        let s = str_response(&req);
        assert!(s.starts_with("POST /pair-setup HTTP/1.1\r\n"));
        assert!(s.contains("CSeq: 4\r\n"));
        assert!(s.contains("Connection: keep-alive\r\n"));
        assert!(s.contains("X-Apple-HKP: 3\r\n"));
        assert!(s.contains("Content-Type: application/octet-stream\r\n"));
        assert!(s.contains("Content-Length: 2\r\n\r\n"));
        assert!(s.ends_with("\x06\x01"));
        // Empty body still carries Content-Length: 0 (httpPost_ does).
        let empty = str_response(&build_http_post("/pair-pin-start", 5, "D", 7, 3, None, b""));
        assert!(empty.contains("Content-Length: 0\r\n\r\n"));
    }

    #[test]
    fn build_ap2_feedback_uses_rtsp_line() {
        let s = str_response(&build_ap2_feedback(9, "D", 3));
        assert!(s.starts_with("POST /feedback RTSP/1.0\r\n"));
        assert!(s.contains("CSeq: 9\r\n"));
        assert!(s.contains("Client-Instance: D\r\n"));
        assert!(s.ends_with("Content-Length: 0\r\n\r\n"));
    }

    #[test]
    fn extract_quoted_and_challenge() {
        let hdr = r#"Digest realm="AirPlay", nonce="abc123""#;
        assert_eq!(extract_quoted(hdr, "realm=").as_deref(), Some("AirPlay"));
        assert_eq!(extract_quoted(hdr, "nonce=").as_deref(), Some("abc123"));
        assert_eq!(extract_quoted(hdr, "qop="), None);
        assert_eq!(extract_quoted("no key here", "realm="), None);
        let (realm, nonce) = parse_digest_challenge(hdr);
        assert_eq!(realm.as_deref(), Some("AirPlay"));
        assert_eq!(nonce.as_deref(), Some("abc123"));
    }

    #[test]
    fn channel_plaintext_identity() {
        let mut ch = Ap2Channel::plain();
        assert!(!ch.encrypted());
        let framed = ch.frame_out(b"RTSP/1.0 200 OK\r\n\r\n");
        assert_eq!(framed, b"RTSP/1.0 200 OK\r\n\r\n");
        let dec = ch.feed_in(b"more").unwrap();
        assert_eq!(dec, b"more");
    }

    #[test]
    fn channel_encrypt_roundtrip_single() {
        let mut key = [0u8; 32];
        // Distinct key halves to catch swapped keys.
        key.fill(7);
        let mut a = Ap2Channel::plain();
        let mut b = Ap2Channel::plain();
        a.install_keys(&key, &key);
        b.install_keys(&key, &key);
        let msg = b"GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        let framed = a.frame_out(msg);
        // [len LE][ct+tag]; message under 1024 → exactly one frame.
        assert_eq!(framed.len(), 2 + msg.len() + 16);
        assert_eq!(
            u16::from_le_bytes([framed[0], framed[1]]) as usize,
            msg.len()
        );
        let dec = b.feed_in(&framed).unwrap();
        assert_eq!(dec, msg);
        // Counters must line up across separate feeds of one frame.
        let dec2 = b.feed_in(&[]).unwrap();
        assert!(dec2.is_empty());
    }

    #[test]
    fn channel_chunking_at_1024() {
        let keys = [3u8; 32];
        let mut a = Ap2Channel::plain();
        let mut b = Ap2Channel::plain();
        a.install_keys(&keys, &keys);
        b.install_keys(&keys, &keys);
        let msg: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let framed = a.frame_out(&msg);
        // 1024 + 1024 + 952 chunks → 3 frames.
        let mut off = 0;
        let mut lens = Vec::new();
        while off < framed.len() {
            let len = u16::from_le_bytes([framed[off], framed[off + 1]]) as usize;
            assert!(len <= 1024);
            lens.push(len);
            off += 2 + len + 16;
        }
        assert_eq!(off, framed.len());
        assert_eq!(lens, vec![1024, 1024, 952]);
        // Straight-line feed decrypts everything in order.
        let dec = b.feed_in(&framed).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn channel_handles_split_and_batched_frames() {
        let key = [9u8; 32];
        // Split arrival: 1-byte dribbles produce nothing until the frame
        // is complete.
        let mut a = Ap2Channel::plain();
        let mut b = Ap2Channel::plain();
        a.install_keys(&key, &key);
        b.install_keys(&key, &key);
        let msg = b"RTSP/1.0 200 OK\r\n\r\n";
        let framed = a.frame_out(msg);
        for i in 0..framed.len() - 1 {
            let dec = b.feed_in(&framed[i..i + 1]).unwrap();
            assert!(dec.is_empty(), "byte {i}");
        }
        let dec = b.feed_in(&framed[framed.len() - 1..]).unwrap();
        assert_eq!(dec, msg);

        // Batched arrival: two frames in a single feed decrypt in order.
        let mut batched = a.frame_out(b"first");
        batched.extend_from_slice(&a.frame_out(b"second"));
        let dec = b.feed_in(&batched).unwrap();
        assert_eq!(dec, b"firstsecond" as &[u8]);
    }

    #[test]
    fn channel_keys_swap_detected() {
        let in_key = [1u8; 32];
        let other = [2u8; 32];
        let mut a = Ap2Channel::plain();
        let mut b = Ap2Channel::plain();
        a.install_keys(&in_key, &in_key);
        b.install_keys(&other, &other); // wrong key
        let framed = a.frame_out(b"hi");
        assert_eq!(b.feed_in(&framed), Err(FrameError::AuthFailed));
        // Accumulator dropped after the failure (event-path semantics).
        let dec = b.feed_in(&framed);
        assert!(matches!(dec, Err(FrameError::AuthFailed)));
    }

    #[test]
    fn channel_counter_desync_detected() {
        let key = [5u8; 32];
        let mut a = Ap2Channel::plain();
        let mut b = Ap2Channel::plain();
        a.install_keys(&key, &key);
        b.install_keys(&key, &key);
        let framed = a.frame_out(b"one");
        // b already consumed a frame at counter 0; next frame at counter 1
        // arrives before b has seen counter 0 → tag mismatch.
        let dec = b.feed_in(&framed).unwrap();
        assert_eq!(dec, b"one");
        // Feed the SAME frame again: b now uses counter 1 → auth fail.
        assert_eq!(b.feed_in(&framed), Err(FrameError::AuthFailed));
    }

    #[test]
    fn channel_oversized_frame_rejected() {
        let key = [1u8; 32];
        let mut a = Ap2Channel::plain();
        let mut b = Ap2Channel::plain();
        a.install_keys(&key, &key);
        b.install_keys(&key, &key);
        let mut hostile = vec![0xFF, 0xFF, 0x00]; // len = 65535
        hostile.extend_from_slice(&[0u8; 200]); // not even a full frame
        assert_eq!(b.feed_in(&hostile), Err(FrameError::OversizedFrame));
    }

    #[test]
    fn channel_install_keys_resets_state() {
        let mut ch = Ap2Channel::plain();
        let key = [4u8; 32];
        ch.install_keys(&key, &key);
        assert!(ch.encrypted());
        // A second install must restart counters (afterAuthOk_ resets
        // ctrl counters to 0).
        ch.install_keys(&key, &key);
        let mut peer = Ap2Channel::plain();
        peer.install_keys(&key, &key);
        let framed = ch.frame_out(b"x");
        let dec = peer.feed_in(&framed).unwrap();
        assert_eq!(dec, b"x");
    }

    #[test]
    fn event_request_extraction() {
        let req = b"POST /command updateInfo HTTP/1.1\r\nCSeq: 12\r\nContent-Length: 4\r\n\r\nbody";
        let e = next_event_request(req).expect("complete");
        assert_eq!(e.cseq.as_deref(), Some("12"));
        assert_eq!(e.total, req.len());
        // Truncated body → pending.
        assert!(next_event_request(&req[..req.len() - 2]).is_none());
        // Two requests back to back.
        let mut two = req.to_vec();
        let req2 = b"POST /command x HTTP/1.1\r\nCSeq: 13\r\n\r\n";
        two.extend_from_slice(req2);
        let e1 = next_event_request(&two).unwrap();
        assert_eq!(e1.cseq.as_deref(), Some("12"));
        let e2 = next_event_request(&two[e1.total..]).unwrap();
        assert_eq!(e2.cseq.as_deref(), Some("13"));
        assert_eq!(e2.total, req2.len());
    }

    #[test]
    fn event_200_ok_shapes() {
        assert_eq!(
            str_response(&build_event_200_ok(None)),
            "RTSP/1.0 200 OK\r\nServer: AirTunes/550.10\r\n\r\n"
        );
        let with_cseq = str_response(&build_event_200_ok(Some("12")));
        assert!(with_cseq.contains("CSeq: 12\r\n"));
        assert!(!with_cseq.contains("Content-Length"));
    }

    #[test]
    fn handshake_payloads_golden() {
        assert_eq!(build_volume_body(-15.0), b"volume: -15.000000");
        assert_eq!(build_volume_body(-144.0), b"volume: -144.000000");

        let meta = build_dmap_metadata("T", "A", "L");
        let s = str_response(&meta);
        assert!(s.starts_with("mlit"));
        assert!(s.contains("minm"));
        assert!(s.contains("asar"));
        assert!(s.contains("asal"));
        // Omitted fields are omitted entirely.
        assert_eq!(build_dmap_metadata("", "", ""), b"");
        let only_title = build_dmap_metadata("T", "", "");
        assert!(!str_response(&only_title).contains("asal"));

        assert_eq!(build_rtp_info(0x1234, 66150), "seq=4660;rtptime=66150");
        assert_eq!(
            str_response(&build_setup_transport(50000, 50001).into_bytes()),
            "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=50000;timing_port=50001"
        );

        let sdp = str_response(&build_announce_sdp(7, "10.0.0.1", "10.0.0.2"));
        assert_eq!(
            sdp,
            "v=0\r\no=iTunes 7 0 IN IP4 10.0.0.1\r\ns=iTunes\r\nc=IN IP4 10.0.0.2\r\n\
             t=0 0\r\nm=audio 0 RTP/AVP 96\r\na=rtpmap:96 L16/44100/2\r\n\
             a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100\r\n"
        );
    }

    #[test]
    fn setup_transport_reply_parse() {
        assert_eq!(
            parse_setup_transport_reply(
                "RTP/AVP/UDP;unicast;mode=record;server_port=5000;control_port=5001;timing_port=5002"
            ),
            (5000, 5001, 5002)
        );
        // Missing / malformed pieces default to 0 (lenient port parse).
        assert_eq!(
            parse_setup_transport_reply("server_port=5x;control_port=abc;timing_port=7"),
            (5, 0, 7)
        );
        assert_eq!(parse_setup_transport_reply("junk"), (0, 0, 0));
    }
}
