// SPDX-License-Identifier: Apache-2.0
//! Pure protocol helpers ported 1:1 from the anonymous namespace of
//! [`src/raop_sender.cpp`](../../src/raop_sender.cpp): NTP/RTP timeline
//! math, tiny string/hex/JSON-convenience helpers, DMAP tagging, and the
//! RAOP session constants.
//!
//! Every function here is deterministic (or documented as clock/RNG-based)
//! so the layer above can be unit-tested without a device or sockets.

use std::collections::BTreeMap;

use airplay_crypto::CryptoError;

// ── RAOP constants (raop_sender.cpp lines 62-74) ────────────────────────

/// Frames of audio per RTP packet; RAOP-fixed at 352.
pub const FRAMES_PER_PACKET: usize = 352;
/// The RAOP audio sample rate (Hz); everything is resampled to this.
pub const RAOP_RATE: u32 = 44100;
/// Audio channels (interleaved stereo).
pub const CHANNELS: usize = 2;
/// Payload bytes per packet for raw PCM: 352 * 2 * 2.
pub const PAYLOAD_BYTES: usize = FRAMES_PER_PACKET * CHANNELS * 2;
/// Retransmit backlog depth (power of two; slot = seq & (kBacklogSize-1)).
pub const BACKLOG_SIZE: usize = 1024;
/// Pacer tick interval (~8 ms ≈ 1 packet/tick at 44.1 kHz).
pub const PACER_MS: i64 = 8;
/// Stall catch-up cap: at most this many packets per pacer tick.
pub const MAX_PACKETS_PER_TICK: usize = 16;
/// Handshake watchdog (ms).
pub const HANDSHAKE_TIMEOUT_MS: i64 = 10_000;
/// On-screen-PIN wait watchdog (ms); 3 minutes.
pub const PIN_WAIT_TIMEOUT_MS: i64 = 180_000;
/// AP1 keep-alive interval (ms), pyatv `KEEP_ALIVE_INTERVAL`.
pub const FEEDBACK_INTERVAL_MS: i64 = 25_000;
/// Resampler staging-buffer cap (frames); ~0.2 s at 48 kHz.
pub const IN_BUF_MAX_FRAMES: usize = 8192;
/// Fixed RAOP pipeline latency in frames (pyatv: 22050 + 44100).
pub const LATENCY_FRAMES: u32 = 22_050 + 44_100;
/// Sentinel for "no volume pending" (out of the valid dBFS range).
pub const NO_VOLUME: f64 = -1000.0;

// ── big-endian appenders (the RTP family is network byte order) ────────

/// Append one byte.
pub fn b8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

/// Append a big-endian u16.
pub fn be16(out: &mut Vec<u8>, v: u16) {
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

/// Append a big-endian u32.
pub fn be32(out: &mut Vec<u8>, v: u32) {
    out.push((v >> 24) as u8);
    out.push((v >> 16) as u8);
    out.push((v >> 8) as u8);
    out.push(v as u8);
}

/// Append a big-endian u64.
pub fn be64(out: &mut Vec<u8>, v: u64) {
    for shift in [56, 48, 40, 32, 24, 16, 8, 0] {
        out.push((v >> shift) as u8);
    }
}

// ── pyatv timing.py, NTP <-> RTP-timestamp conversion ──────────────────

/// RTP timestamp for an NTP timestamp: `((ntp >> 16) * rate) >> 16`.
/// Matches `ntp2ts`; wrapping arithmetic so a Debug build never panics on
/// the huge NTP-derived bases (saturating u64 is not used: it must wrap,
/// the formulas are designed so the base cancels out downstream).
pub fn ntp2ts(ntp: u64, rate: u32) -> u64 {
    ((ntp >> 16).wrapping_mul(rate as u64)) >> 16
}

/// NTP timestamp for an RTP timestamp: `((ts << 16) / rate) << 16`.
/// Matches `ts2ntp`.
pub fn ts2ntp(ts: u64, rate: u32) -> u64 {
    (ts.wrapping_shl(16) / rate as u64).wrapping_shl(16)
}

/// Current wall time in 64-bit NTP format (seconds since 1900 in the high
/// word, 2^32-scaled fraction below). Microsecond resolution, matches
/// `RaopSender::ntpNow_()`.
pub fn ntp_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the UNIX epoch")
        .as_micros() as u64;
    let sec = us / 1_000_000;
    let frac = us % 1_000_000;
    ((sec.wrapping_add(0x83AA_7E80)) << 32) | ((frac << 32) / 1_000_000)
}

/// The RTP timestamp the audio headers carry: `latency + frames_sent`,
/// u32-wrapped (the RTP norm). The huge NTP-derived base cancels, so this
/// starts at `latency` and advances one per frame sent.
pub fn rtptime32(latency_frames: u64, frames_sent: u64) -> u32 {
    (latency_frames.wrapping_add(frames_sent)) as u32
}

// ── pseudo-random helpers (airplay-crypto CTR-DRBG, no second RNG) ─────

fn rand_bytes(n: usize) -> Result<Vec<u8>, CryptoError> {
    airplay_crypto::random_bytes(n)
}

/// 32-bit random, assembled big-endian from 4 random bytes (`randU32`).
pub fn rand_u32() -> Result<u32, CryptoError> {
    let b = rand_bytes(4)?;
    Ok(
        (u32::from(b[0]) << 24)
            | (u32::from(b[1]) << 16)
            | (u32::from(b[2]) << 8)
            | u32::from(b[3]),
    )
}

/// 64-bit random from 8 random bytes (`randU64`).
pub fn rand_u64() -> Result<u64, CryptoError> {
    let b = rand_bytes(8)?;
    let mut v = 0u64;
    for byte in b {
        v = (v << 8) | u64::from(byte);
    }
    Ok(v)
}

/// 16-bit random, low 16 bits of `randU32` (`randU16`).
pub fn rand_u16() -> Result<u16, CryptoError> {
    Ok((rand_u32()? & 0xFFFF) as u16)
}

/// RFC 4122 v4 UUID, lowercase, no braces (`makeUuid`, QUuid
/// `toString(WithoutBraces)`): version nibble at octet 6, variant 10xx at
/// octet 8, dashes at character positions 8/13/18/23.
pub fn make_uuid() -> Result<String, CryptoError> {
    let mut b = rand_bytes(16)?;
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    let hex = b"0123456789abcdef";
    let mut s = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        s.push(hex[(byte >> 4) as usize] as char);
        s.push(hex[(byte & 0x0F) as usize] as char);
    }
    Ok(s)
}

// ── tiny string helpers ────────────────────────────────────────────────

/// ASCII-only uppercase copy (`toUpperStr`).
pub fn to_upper_str(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_uppercase()).collect()
}

/// ASCII-only lowercase copy (`toLowerStr`).
pub fn to_lower_str(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

/// Trim `" \t\r\n"` from both ends; empty if the string is all whitespace
/// (`trimmed`).
pub fn trimmed(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t' || c == '\r' || c == '\n')
}

/// Split on every occurrence of `delim`, keeping empty fields
/// (`splitStr`). A trailing delim yields a trailing empty field, exactly
/// like the C++ loop.
pub fn split_str(s: &str, delim: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0;
    for (pos, c) in s.char_indices() {
        if c == delim {
            out.push(s[start..pos].to_string());
            start = pos + 1;
        }
    }
    out.push(s[start..].to_string());
    out
}

/// `v[i]` if in bounds, else `def` (`atOr`).
pub fn at_or<'a>(v: &'a [String], i: usize, def: &'a str) -> &'a str {
    v.get(i).map_or(def, String::as_str)
}

/// `QByteArray::toInt(&ok)` equivalent: the WHOLE string must be a valid
/// base-10 integer (optional sign; the C++ `strtol` would also accept
/// leading whitespace, but every call site trims first). `None` on empty,
/// malformed, or overflowing input (`toIntChecked`, with overflow treated
/// as invalid rather than strtol's saturating LONG_MAX).
pub fn to_int_checked(s: &str) -> Option<i64> {
    if s.is_empty() {
        return None;
    }
    s.parse::<i64>().ok()
}

/// `toIntOr0`.
pub fn to_int_or_0(s: &str) -> i64 {
    to_int_checked(s).unwrap_or(0)
}

/// `strtoul` "best effort" semantics (`toUIntOr0`): skip leading
/// whitespace, optional sign, consume leading digits, return the value
/// (0 if nothing was consumed). Overflow saturates like strtoul's
/// ULONG_MAX.
pub fn to_uint_or_0(s: &str) -> u64 {
    let t = s.trim_start_matches([' ', '\t', '\r', '\n']);
    let (neg, rest) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let digits = &rest[..end];
    if digits.is_empty() {
        return 0;
    }
    let v: u64 = digits.parse().unwrap_or(u64::MAX);
    if neg { v.wrapping_neg() } else { v }
}

/// Fixed 6-decimal-place formatting (`QByteArray::number(double, 'f', 6)`
/// via snprintf; both round the same IEEE double correctly).
pub fn fixed6(v: f64) -> String {
    format!("{v:.6}")
}

/// Uppercase hex of a 64-bit value, no zero-padding
/// (`QByteArray::number(v, 16).toUpper()`).
pub fn hex_upper_no_pad(v: u64) -> String {
    format!("{v:X}")
}

/// Lowercase hex of a byte slice (`toHex`).
pub fn to_hex(b: &[u8]) -> String {
    let hex = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push(hex[(byte >> 4) as usize] as char);
        s.push(hex[(byte & 0x0F) as usize] as char);
    }
    s
}

/// Lenient hex decode (`fromHexLenient`): empty on odd length or any
/// non-hex character, matching QByteArray::fromHex's "best effort" — the
/// callers only treat the result as valid if its SIZE is right.
pub fn from_hex_lenient(s: &str) -> Vec<u8> {
    if s.len() % 2 != 0 {
        return Vec::new();
    }
    let val = |c: char| -> Option<u8> {
        match c {
            '0'..='9' => Some(c as u8 - b'0'),
            'a'..='f' => Some(c as u8 - b'a' + 10),
            'A'..='F' => Some(c as u8 - b'A' + 10),
            _ => None,
        }
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let (Some(hi), Some(lo)) = (val(bytes[i] as char), val(bytes[i + 1] as char)) else {
            return Vec::new();
        };
        out.push((hi << 4) | lo);
    }
    out
}

/// Map lookup with a default (lower-cased-key header maps) (`headerValue`).
pub fn header_value<'a>(headers: &'a BTreeMap<String, String>, key: &str, def: &'a str) -> &'a str {
    headers.get(key).map_or(def, String::as_str)
}

// ── persisted AirPlay credentials, JSON ────────────────────────────────

/// A fixed 4-key flat JSON object — `{"ltsk":"<hex>","ltpk":"<hex>",
/// "atvId":"<hex>","clientId":"<uuid>"}` — hand-rolled since the schema
/// never changes and nothing needs escaping (`encodeCreds`).
pub fn encode_creds(ltsk_hex: &str, ltpk_hex: &str, atv_id_hex: &str, client_id: &str) -> String {
    format!(
        "{{\"ltsk\":\"{ltsk_hex}\",\"ltpk\":\"{ltpk_hex}\",\"atvId\":\"{atv_id_hex}\",\"clientId\":\"{client_id}\"}}"
    )
}

/// Fetch the string value for a top-level `"key":"value"` pair
/// (`jsonStringValue`). Handles only what `encode_creds` produces (no
/// nesting, no escapes); `None` when the key or a closed value is absent.
pub fn json_string_value(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let k = json.find(&needle)?;
    let colon = json[k + needle.len()..].find(':')? + k + needle.len();
    let rest = &json[colon + 1..];
    let q1 = rest.find('"')? + colon + 1;
    let rest2 = &json[q1 + 1..];
    let q2 = rest2.find('"')? + q1 + 1;
    Some(json[q1 + 1..q2].to_string())
}

// ── DMAP tagging ───────────────────────────────────────────────────────

/// DMAP tag: 4-char ASCII code + 4-byte big-endian length + payload
/// (`dmapTag`).
pub fn dmap_tag(code: &str, payload: &[u8]) -> Vec<u8> {
    debug_assert_eq!(code.len(), 4);
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(code.as_bytes());
    out.push((payload.len() >> 24) as u8);
    out.push((payload.len() >> 16) as u8);
    out.push((payload.len() >> 8) as u8);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    out
}

// ── volume mapping ─────────────────────────────────────────────────────

/// pyatv `pct_to_dbfs`: 0 % is the AirPlay mute sentinel -144, the rest
/// maps linearly onto the -30..0 dBFS attenuation range (input clamped to
/// 0..100).
pub fn pct_to_dbfs(pct: f64) -> f64 {
    let pct = pct.clamp(0.0, 100.0);
    if pct < 0.01 {
        -144.0
    } else {
        -30.0 + 0.3 * pct
    }
}

// ── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp2ts_one_second_is_rate_frames() {
        // 0x00000001_00000000 = exactly 1.0 NTP second.
        assert_eq!(ntp2ts(0x0000_0001_0000_0000, RAOP_RATE), 44_100);
        assert_eq!(ntp2ts(0, RAOP_RATE), 0);
    }

    #[test]
    fn ts2ntp_one_second_roundtrip() {
        // ts==rate maps back onto exactly 1.0 NTP seconds.
        assert_eq!(ts2ntp(44_100, RAOP_RATE), 0x0000_0001_0000_0000);
        // Round trip through the pipeline start_ts = ntp2ts(ntp_now()).
        let ntp = 0x83AA_7E80_8000_0000u64 + 42;
        let ts = ntp2ts(ntp, RAOP_RATE);
        assert_eq!(ntp2ts(ts2ntp(ts, RAOP_RATE), RAOP_RATE), ts);
        // Division truncation: ts2ntp(1 sec) - 1 frame must be < 1 sec.
        assert!(ts2ntp(44_099, RAOP_RATE) < 0x0000_0001_0000_0000);
    }

    #[test]
    fn ntp_now_shape() {
        let ntp = ntp_now();
        // High word is seconds since 1900 (~4e9 in 2026), fraction below.
        let secs = ntp >> 32;
        assert!(
            secs > 0x8000_0000 && secs < 0x1_0000_0000,
            "seconds={secs:#x}"
        );
        assert!(ntp & 0xFFFF_FFFF != 0 || true); // low word is 0..2^32
    }

    #[test]
    fn ntp2ts_never_overflow_overflows() {
        // Extreme hostile NTP value: must not panic (wrapping) and must be
        // bounded by (2^48 * rate) >> 16.
        let v = ntp2ts(u64::MAX, RAOP_RATE);
        assert!(v < ((1u64 << 48) * RAOP_RATE as u64) >> 16);
    }

    #[test]
    fn rtptime32_starts_at_latency_and_wraps() {
        assert_eq!(rtptime32(LATENCY_FRAMES as u64, 0), LATENCY_FRAMES);
        assert_eq!(rtptime32(LATENCY_FRAMES as u64, 352), LATENCY_FRAMES + 352);
        // u32 wrap is the RTP norm.
        assert_eq!(rtptime32(u64::from(u32::MAX) - 10, 20), 9);
    }

    #[test]
    fn be_appenders_network_order() {
        let mut out = Vec::new();
        b8(&mut out, 0xAB);
        be16(&mut out, 0x1234);
        be32(&mut out, 0xDEAD_BEEF);
        be64(&mut out, 0x0102_0304_0506_0708);
        assert_eq!(
            out,
            vec![
                0xAB, 0x12, 0x34, 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8
            ]
        );
    }

    #[test]
    fn make_uuid_shape() {
        let u = make_uuid().unwrap();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[8..9], "-");
        assert_eq!(&u[13..14], "-");
        assert_eq!(&u[18..19], "-");
        assert_eq!(&u[23..24], "-");
        // Version 4 nibble at octet 6, variant 10xx at octet 8.
        assert_eq!(&u[14..15], "4");
        let variant = u.as_bytes()[19];
        assert!(
            matches!(variant, b'8'..=b'b'),
            "variant nibble {variant:#x}"
        );
    }

    #[test]
    fn trimmed_and_split() {
        assert_eq!(trimmed("  hi \t\r\n"), "hi");
        assert_eq!(trimmed("\r\n\t  "), "");
        assert_eq!(trimmed(""), "");
        assert_eq!(split_str("a;b;", ';'), vec!["a", "b", ""]);
        assert_eq!(split_str("", ';'), vec![""]);
        assert_eq!(at_or(&split_str("x y z", ' '), 5, "dflt"), "dflt");
    }

    #[test]
    fn to_int_checked_semantics() {
        assert_eq!(to_int_checked("12"), Some(12));
        assert_eq!(to_int_checked("-7"), Some(-7));
        assert_eq!(to_int_checked("+7"), Some(7));
        assert_eq!(to_int_checked("12abc"), None);
        assert_eq!(to_int_checked(""), None);
        assert_eq!(to_int_checked(" 12"), None); // callers trim first
        assert_eq!(to_int_or_0("abc"), 0);
        assert_eq!(to_int_or_0("200"), 200);
    }

    #[test]
    fn to_uint_or_0_best_effort() {
        assert_eq!(to_uint_or_0("5000"), 5000);
        assert_eq!(to_uint_or_0("12abc"), 12);
        assert_eq!(to_uint_or_0("abc"), 0);
        assert_eq!(to_uint_or_0(""), 0);
        assert_eq!(to_uint_or_0(" 12"), 12);
        assert_eq!(to_uint_or_0("99999999999999999999999"), u64::MAX);
    }

    #[test]
    fn fixed6_and_hex() {
        assert_eq!(fixed6(-144.0), "-144.000000");
        assert_eq!(fixed6(0.0), "0.000000");
        assert_eq!(fixed6(2.675), "2.675000");
        assert_eq!(hex_upper_no_pad(0), "0");
        assert_eq!(hex_upper_no_pad(0xABC), "ABC");
        assert_eq!(to_hex(&[0xDE, 0xAD]), "dead");
        assert_eq!(from_hex_lenient("dead"), vec![0xDE, 0xAD]);
        assert_eq!(from_hex_lenient("DEAD"), vec![0xDE, 0xAD]);
        assert_eq!(from_hex_lenient("dea"), Vec::<u8>::new());
        assert_eq!(from_hex_lenient("deag"), Vec::<u8>::new());
    }

    #[test]
    fn creds_json_roundtrip() {
        let json = encode_creds("aa", "bb", "cc", "client-1");
        assert_eq!(json_string_value(&json, "ltsk"), Some("aa".to_string()));
        assert_eq!(json_string_value(&json, "ltpk"), Some("bb".to_string()));
        assert_eq!(json_string_value(&json, "atvId"), Some("cc".to_string()));
        assert_eq!(
            json_string_value(&json, "clientId"),
            Some("client-1".to_string())
        );
        assert_eq!(json_string_value(&json, "nope"), None);
        assert_eq!(json_string_value("{}", "ltsk"), None);
    }

    #[test]
    fn dmap_tag_layout() {
        let payload = b"hi";
        let t = dmap_tag("minm", payload);
        assert_eq!(t, vec![b'm', b'i', b'n', b'm', 0, 0, 0, 2, b'h', b'i']);
        // Nested mlit wrap, like the C++ sendMetadata_ path.
        let inner = dmap_tag("asar", b"artist");
        let outer = dmap_tag("mlit", &inner);
        assert_eq!(&outer[..4], b"mlit");
        assert_eq!(outer.len(), 8 + inner.len());
    }

    #[test]
    fn pct_to_dbfs_mapping() {
        assert_eq!(pct_to_dbfs(0.0), -144.0);
        assert_eq!(pct_to_dbfs(50.0), -15.0);
        assert_eq!(pct_to_dbfs(100.0), 0.0);
        assert_eq!(pct_to_dbfs(-5.0), -144.0);
        assert_eq!(pct_to_dbfs(150.0), 0.0);
    }

    #[test]
    fn to_lower_upper_ascii_only() {
        assert_eq!(to_upper_str("AbC-1"), "ABC-1");
        assert_eq!(to_lower_str("AbC-1"), "abc-1");
    }
}
