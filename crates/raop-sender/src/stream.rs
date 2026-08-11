// SPDX-License-Identifier: Apache-2.0
//! The RAOP UDP packet layer — the payload side of the streaming
//! half of [`src/raop_sender.cpp`](https://github.com/fxchain/cast/raw/…):
//!
//! * audio RTP packets ([`AudioStream::build_audio_packet`], mirroring
//!   `sendAudioPacket_`): 12-byte BE RTP header (SSRC = session id),
//!   AP1 payload = big-endian s16 PCM, AP2 payload = an uncompressed
//!   ALAC frame ([`encode_alac_frame`]) ChaCha20-Poly1305 encrypted
//!   (AAD = header bytes 4..12, trailing 8-byte LE nonce), plus the
//!   1024-slot retransmit backlog;
//! * the SYNC packet ([`AudioStream::build_sync_packet`], type 0x54):
//!   the latency-shifted RTP time, the NTP time of the frame just
//!   written, and the play-now RTP time;
//! * retransmit-request handling ([`AudioStream::retransmit_responses`],
//!   0x55 → 0xD6), mirroring `onControlData_`;
//! * the NTP timing reply ([`build_timing_reply`], type 0xD3), mirroring
//!   `onTimingData_`.
//!
//! The network send, the pacer token bucket (`onPacerTick_`) and the
//! resampler stay with the state machine slice; this module is the pure,
//! byte-level core.

use airplay_crypto::{chacha20_poly1305_encrypt, counter_nonce8};

use crate::util::{self, BACKLOG_SIZE, CHANNELS, FRAMES_PER_PACKET, RAOP_RATE};

/// RTP payload type of audio packets (second header byte low 7 bits).
pub const RTP_AUDIO_TYPE: u8 = 0x60;
/// Marker bit set on the first audio packet after (re)start.
pub const FIRST_PACKET_BYTE: u8 = 0xE0;
/// SYNC packet type (`0x54 | 0x80`).
pub const SYNC_TYPE: u8 = 0xD4;
/// Retransmit request type (`0x55 | 0x80` mask 0x7F → 0x55).
pub const RETRANSMIT_REQUEST_TYPE: u8 = 0x55;
/// Retransmit response type (`0x56 | 0x80`, pyatv `0xD6`).
pub const RETRANSMIT_RESPONSE_TYPE: u8 = 0xD6;
/// Timing reply type (`0x53 | 0x80`, pyatv `0xD3`).
pub const TIMING_REPLY_TYPE: u8 = 0xD3;
/// Fixed `line` field carried by both 0x54 sync and 0x53 timing packets.
pub const SYNC_LINE_FIELD: u16 = 0x0007;

/// Size of the RTP header the audio packets carry (and the sync packet's
/// 20-byte total derives from: 4 fixed + 4 + 4 + 4 + 4).
pub const RTP_HEADER_LEN: usize = 12;

/// Encode one frame of interleaved s16 stereo PCM as an UNCOMPRESSED ALAC
/// frame, which is what a modern Apple TV's realtime path (hardcoded ALAC,
/// frameLength 352 / 16-bit / 2ch) decodes. The ALAC bitstream is read
/// MSB-first by the receiver (shairport-sync alac.c). Per-frame element
/// layout (the `#90` comment in `sendAudioPacket_`):
///
/// ```text
/// 3b channel tag = 1 (stereo CPE) · 4b unused=0 · 12b unknown=0 ·
/// 1b hasSize=0 (use cookie's default 352) · 2b wastedBytes=0 ·
/// 1b isNotCompressed=1 · then nFrames×{L16,R16} samples MSB-first ·
/// 3b end tag = 7 · zero-pad to a byte boundary.
/// ```
///
/// `frames` must hold `FRAMES_PER_PACKET * CHANNELS` samples (the C++
/// always encodes a full 352-frame packet).
pub fn encode_alac_frame(frames: &[i16]) -> Vec<u8> {
    assert_eq!(
        frames.len(),
        FRAMES_PER_PACKET * CHANNELS,
        "audio frames must be exactly FRAMES_PER_PACKET * CHANNELS samples"
    );
    let mut out = Vec::with_capacity(frames.len() + 8);
    let mut cur: u8 = 0;
    let mut filled: u32 = 0;
    let put = |value: u32, bits: u32, out: &mut Vec<u8>, cur: &mut u8, filled: &mut u32| {
        for i in (0..bits).rev() {
            *cur = (*cur << 1) | (((value >> i) & 1u32) as u8);
            *filled += 1;
            if *filled == 8 {
                out.push(*cur);
                *cur = 0;
                *filled = 0;
            }
        }
    };
    put(1, 3, &mut out, &mut cur, &mut filled); // stereo channel-pair element
    put(0, 4, &mut out, &mut cur, &mut filled); // unused
    put(0, 12, &mut out, &mut cur, &mut filled); // unknown
    put(0, 1, &mut out, &mut cur, &mut filled); // hasSize = 0
    put(0, 2, &mut out, &mut cur, &mut filled); // wastedBytes = 0
    put(1, 1, &mut out, &mut cur, &mut filled); // isNotCompressed = 1
    for &s in frames {
        put(s as u16 as u32, 16, &mut out, &mut cur, &mut filled); // MSB-first
    }
    put(7, 3, &mut out, &mut cur, &mut filled); // END element tag
    if filled > 0 {
        out.push(cur << (8 - filled));
    }
    out
}

/// Encrypt an AP2 audio payload exactly as `encryptAudioPayload_`:
/// ChaCha20-Poly1305 with the 8-byte LE counter nonce, AAD = the RTP
/// header bytes 4..12, and the 8-byte nonce appended AFTER the
/// ciphertext+tag. `key` is `None` on the AP1 identity path (payload
/// returned untouched). The nonce counter is incremented after use.
pub fn encrypt_audio_payload(
    key: Option<&[u8; 32]>,
    nonce: &mut u64,
    rtp_header_aad: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let Some(key) = key else {
        return payload.to_vec();
    };
    let nonce8 = counter_nonce8(*nonce);
    let ct = chacha20_poly1305_encrypt(key, &nonce8, payload, rtp_header_aad)
        .expect("32-byte key and 8-byte nonce are always valid");
    *nonce = nonce.wrapping_add(1);
    let mut out = ct;
    out.extend_from_slice(&nonce8);
    out
}

/// One slot of the retransmit backlog (mirrors the parallel `backlog_` /
/// `backlogSeq_` arrays; `None` = `-1` "aged out" sentinel).
type BacklogSlot = Option<(u16, Vec<u8>)>;

/// The pure streaming-half state: sequence number, timeline, audio
/// encryption key/nonce, and the retransmit backlog. Mirrors the members
/// of `RaopSender` used by `sendAudioPacket_` / `sendSyncPacket_` /
/// `onControlData_`.
pub struct AudioStream {
    /// Next RTP sequence number (seeded `randU16()` per session in C++).
    seq: u16,
    /// Marker bit goes on the first packet after (re)start.
    first_audio: bool,
    /// Frames written so far this session (u64, drives `rtptime32`).
    frames_sent: u64,
    /// RTP SSRC (C++ `sessionId_`, also the RTSP URI path segment).
    session_id: u32,
    /// RTP time of the first frame this session (C++ `startTs_`).
    start_ts: u64,
    /// Latency in frames added to every RTP timestamp.
    latency: u32,
    /// AP2 audio key; `None` = AP1 identity (raw L16 payload).
    audio_key: Option<[u8; 32]>,
    /// ChaCha20-Poly1305 counter for audio packets (C++ `audioNonce`).
    audio_nonce: u64,
    /// 1024-slot retransmit backlog, indexed by `seq & (BACKLOG_SIZE-1)`.
    backlog: Vec<BacklogSlot>,
}

impl AudioStream {
    /// A fresh stream (mirrors the session reset in `start()`):
    /// `frames_sent = 0`, `first_audio = true`, empty backlog.
    pub fn new(session_id: u32, seq: u16) -> Self {
        AudioStream {
            seq,
            first_audio: true,
            frames_sent: 0,
            session_id,
            start_ts: 0,
            latency: 0,
            audio_key: None,
            audio_nonce: 0,
            backlog: vec![None; BACKLOG_SIZE],
        }
    }

    /// The timestamp the audio headers carry: `latency + frames_sent`,
    /// u32-wrapped (the RTP norm; see `util::rtptime32`).
    pub fn rtptime32(&self) -> u32 {
        util::rtptime32(u64::from(self.latency), self.frames_sent)
    }

    /// Frames written so far this session.
    pub fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    /// Current outbound sequence number.
    pub fn seq(&self) -> u16 {
        self.seq
    }

    /// Begin the streaming timeline: `start_ts` is the NTP-derived RTP
    /// base of the first frame (C++ `startTs_` from `sendAnnounce_`),
    /// `latency` the receiver latency in frames. Resets `first_audio`.
    pub fn begin_timeline(&mut self, start_ts: u64, latency: u32) {
        self.start_ts = start_ts;
        self.latency = latency;
        self.first_audio = true;
    }

    /// Install the AP2 audio key (switches the payload to encrypted
    /// uncompressed ALAC) and reset the audio nonce, mirroring the
    /// `ap2_->encryptAudio` flip after pair-verify.
    pub fn install_audio_key(&mut self, key: [u8; 32]) {
        self.audio_key = Some(key);
        self.audio_nonce = 0;
    }

    /// Build one audio packet from a full 352-frame PCM buffer (`len()`
    /// must be `FRAMES_PER_PACKET * CHANNELS`), store it in the
    /// retransmit backlog, and advance seq/frames_sent exactly like
    /// `sendAudioPacket_`. The marker bit is set only on the first
    /// packet after (re)start.
    pub fn build_audio_packet(&mut self, pcm: &[i16]) -> Vec<u8> {
        let mut header = Vec::with_capacity(RTP_HEADER_LEN);
        util::b8(&mut header, 0x80);
        util::b8(
            &mut header,
            if self.first_audio {
                FIRST_PACKET_BYTE
            } else {
                RTP_AUDIO_TYPE
            },
        );
        util::be16(&mut header, self.seq);
        util::be32(&mut header, self.rtptime32());
        util::be32(&mut header, self.session_id);

        let payload = match self.audio_key {
            Some(_) => encode_alac_frame(pcm),
            None => {
                let mut p = Vec::with_capacity(pcm.len() * 2);
                for &s in pcm {
                    util::be16(&mut p, s as u16);
                }
                p
            }
        };
        let wire = encrypt_audio_payload(
            self.audio_key.as_ref(),
            &mut self.audio_nonce,
            &header[4..12],
            &payload,
        );

        let mut pkt = header;
        pkt.extend_from_slice(&wire);

        let slot = usize::from(self.seq) & (BACKLOG_SIZE - 1);
        self.backlog[slot] = Some((self.seq, pkt.clone()));

        self.first_audio = false;
        self.seq = self.seq.wrapping_add(1);
        self.frames_sent = self.frames_sent.wrapping_add(FRAMES_PER_PACKET as u64);
        pkt
    }

    /// Build the 20-byte SYNC packet mirroring `sendSyncPacket_`:
    /// the latency-shifted RTP time `now - latency`, the NTP time of the
    /// frame just written, and the play-now RTP time `now`. The marker
    /// bit is set when `first` (the first sync after (re)start).
    pub fn build_sync_packet(&self, first: bool) -> Vec<u8> {
        let cur_ntp = util::ts2ntp(self.start_ts.wrapping_add(self.frames_sent), RAOP_RATE);
        let now = self.rtptime32();
        let mut pkt = Vec::with_capacity(20);
        util::b8(&mut pkt, if first { 0x90 } else { 0x80 });
        util::b8(&mut pkt, SYNC_TYPE);
        util::be16(&mut pkt, SYNC_LINE_FIELD);
        util::be32(&mut pkt, now.wrapping_sub(self.latency));
        util::be32(&mut pkt, (cur_ntp >> 32) as u32);
        util::be32(&mut pkt, cur_ntp as u32);
        util::be32(&mut pkt, now);
        pkt
    }

    /// Handle a control-port datagram mirroring `onControlData_`:
    /// `None` when it isn't a retransmit request (`data[1] & 0x7F !=
    /// 0x55` or shorter than 8 bytes); otherwise one 0xD6 response per
    /// still-cached lost sequence number (aged-out slots are skipped),
    /// in request order.
    pub fn retransmit_responses(&self, data: &[u8]) -> Option<Vec<Vec<u8>>> {
        if data.len() < 8 {
            return None;
        }
        let ty = data[1] & 0x7F;
        if ty != RETRANSMIT_REQUEST_TYPE {
            return None;
        }
        let lost_seq = u16::from_be_bytes([data[4], data[5]]);
        let lost_count = u16::from_be_bytes([data[6], data[7]]);
        let mut out = Vec::new();
        for i in 0..lost_count {
            let s = lost_seq.wrapping_add(i);
            let slot = usize::from(s) & (BACKLOG_SIZE - 1);
            match &self.backlog[slot] {
                Some((cached_seq, packet)) if *cached_seq == s => {
                    let mut resp = Vec::with_capacity(4 + packet.len());
                    util::b8(&mut resp, 0x80);
                    util::b8(&mut resp, RETRANSMIT_RESPONSE_TYPE);
                    util::be16(&mut resp, s);
                    resp.extend_from_slice(packet);
                    out.push(resp);
                }
                _ => {} // aged out of backlog
            }
        }
        Some(out)
    }
}

/// Build the 32-byte NTP timing reply mirroring `onTimingData_`: the
/// request's proto byte echoed, type 0xD3, the fixed line field, 4 bytes
/// of padding, the request's sendtime echoed as our reftime, and the
/// receive + send times both = `now` (one wall-clock read at this
/// precision). `None` when the request is shorter than 32 bytes.
pub fn build_timing_reply(req: &[u8], now: u64) -> Option<Vec<u8>> {
    if req.len() < 32 {
        return None;
    }
    let mut resp = Vec::with_capacity(32);
    resp.push(req[0]); // proto byte echoed
    util::b8(&mut resp, TIMING_REPLY_TYPE);
    util::be16(&mut resp, SYNC_LINE_FIELD);
    util::be32(&mut resp, 0); // padding
    resp.extend_from_slice(&req[24..32]); // reftime = request sendtime
    util::be32(&mut resp, (now >> 32) as u32);
    util::be32(&mut resp, now as u32);
    util::be32(&mut resp, (now >> 32) as u32);
    util::be32(&mut resp, now as u32);
    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use airplay_crypto::{chacha20_poly1305_decrypt, counter_nonce8};

    fn stream(session_id: u32, seq: u16) -> AudioStream {
        AudioStream::new(session_id, seq)
    }

    #[test]
    fn alac_silence_frame_golden() {
        // Header bits 0..22 → 0x20 0x00 0x02 (isNotCompressed=1 is bit 22,
        // the penultimate bit of byte 2); 11264 zero sample bits; END tag
        // 111 spans bytes 1410/1411 → tail 0x01 0xC0. Verified against an
        // independent bit-writer and the C++ bit layout comment.
        let frames = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        let enc = encode_alac_frame(&frames);
        assert_eq!(enc.len(), 1412);
        assert_eq!(&enc[..3], &[0x20, 0x00, 0x02]);
        assert!(enc[3..1410].iter().all(|&b| b == 0));
        assert_eq!(&enc[1410..], &[0x01, 0xC0]);
    }

    #[test]
    fn alac_nonzero_and_negative_samples_golden() {
        // Samples are a continuous bitstream starting at bit 23, so the
        // first sample's bits 2..9 land in byte 3 (0x1234 ≙ 0x24 0x68).
        let mut frames = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        frames[0] = 0x1234;
        frames[1] = 0;
        let enc = encode_alac_frame(&frames);
        assert_eq!(&enc[..7], &[0x20, 0x00, 0x02, 0x24, 0x68, 0x00, 0x00]);
        assert_eq!(&enc[1410..], &[0x01, 0xC0]);
        // -1 reinterprets as u16 0xFFFF (C++ uint16_t cast): bits 1..9
        // are 1111 1111 1 → byte 2 = 0x03, then 0xFF 0xFE.
        let mut frames = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        frames[0] = -1;
        let enc = encode_alac_frame(&frames);
        assert_eq!(&enc[..7], &[0x20, 0x00, 0x03, 0xFF, 0xFE, 0x00, 0x00]);
        assert_eq!(&enc[1410..], &[0x01, 0xC0]);
    }

    #[test]
    fn alac_packet_length_is_exactly_1412_bytes() {
        let frames = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        // 23 header bits + 704×16 sample bits + 3 END bits → 1412 bytes.
        let enc = encode_alac_frame(&frames);
        assert_eq!(enc.len(), 1412);
        assert_eq!(enc[1410], 0x01);
        assert_eq!(enc[1411], 0xC0);
    }

    #[test]
    fn audio_packet_header_golden_ap1() {
        // Manually fixed state: seq 0x1234, rtptime 0x89ABCDEF,
        // SSRC 0xDEADBEEF, first packet → marker byte 0xE0.
        let mut s = stream(0xDEADBEEF, 0x1234);
        s.begin_timeline(0, 0x89ABCDEF);
        let pcm = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        let pkt = s.build_audio_packet(&pcm);
        assert_eq!(
            &pkt[..12],
            &[
                0x80, 0xE0, 0x12, 0x34, 0x89, 0xAB, 0xCD, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF
            ]
        );
        assert_eq!(pkt.len(), 12 + FRAMES_PER_PACKET * CHANNELS * 2);
    }

    #[test]
    fn ap1_payload_is_be_s16_and_marker_only_first() {
        let mut s = stream(1, 0);
        s.begin_timeline(0, 0);
        let mut pcm = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        pcm[0] = 0x1234;
        pcm[1] = -2;
        let first = s.build_audio_packet(&pcm);
        assert_eq!(first[1], 0xE0);
        assert_eq!(&first[12..16], &[0x12, 0x34, 0xFF, 0xFE]);
        let second = s.build_audio_packet(&pcm);
        assert_eq!(second[1], 0x60);
        assert_eq!(second[2], 0x00);
        assert_eq!(second[3], 0x01); // seq advanced
        // rtptime started at 0 (latency 0) and advanced one frame.
        assert_eq!(u32::from_be_bytes(second[4..8].try_into().unwrap()), 352);
    }

    #[test]
    fn ap2_encrypt_roundtrip_trailing_nonce_aad() {
        let mut s = stream(7, 100);
        s.begin_timeline(0, 0);
        s.install_audio_key([0x42u8; 32]);
        let mut pcm = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        pcm[0] = 12;
        let pkt = s.build_audio_packet(&pcm);
        // trailing 8-byte nonce is the LE counter 0 on the first packet
        assert_eq!(&pkt[pkt.len() - 8..], &counter_nonce8(0)[..]);
        let ct_end = pkt.len() - 8;
        let plain = chacha20_poly1305_decrypt(
            &[0x42u8; 32],
            &counter_nonce8(0),
            &pkt[12..ct_end],
            &pkt[4..12],
        )
        .expect("decrypt with header AAD + leading nonce");
        assert_eq!(plain, encode_alac_frame(&pcm));

        // Second packet uses counter 1; the wire carries it.
        let pkt2 = s.build_audio_packet(&pcm);
        assert_eq!(&pkt2[pkt2.len() - 8..], &counter_nonce8(1)[..]);
        let plain2 = chacha20_poly1305_decrypt(
            &[0x42u8; 32],
            &counter_nonce8(1),
            &pkt2[12..pkt2.len() - 8],
            &pkt2[4..12],
        )
        .expect("second packet decrypts at counter 1");
        assert_eq!(plain2, encode_alac_frame(&pcm));
    }

    #[test]
    fn sync_packet_golden() {
        // start_ts = 0, frames_sent = 0x200 → ts2ntp(0x200, 44100)
        // = ((0x200 << 16) / 44100) << 16 = 0x02F80000; now =
        // latency + frames_sent = 0x100 + 0x200 = 0x300.
        let s = AudioStream {
            seq: 0,
            first_audio: false,
            frames_sent: 0x200,
            session_id: 0xDEADBEEF,
            start_ts: 0,
            latency: 0x100,
            audio_key: None,
            audio_nonce: 0,
            backlog: vec![None; BACKLOG_SIZE],
        };
        assert_eq!(
            s.build_sync_packet(false),
            vec![
                0x80, 0xD4, 0x00, 0x07, // marker off, type, line
                0x00, 0x00, 0x02, 0x00, // now - latency
                0x00, 0x00, 0x00, 0x00, // curNtp hi
                0x02, 0xF8, 0x00, 0x00, // curNtp lo
                0x00, 0x00, 0x03, 0x00, // now
            ]
        );
        // Same timeline, first → byte 0x90.
        assert_eq!(s.build_sync_packet(true)[0], 0x90);
    }

    #[test]
    fn sync_packet_after_packets_tracks_timeline() {
        let mut s = stream(1, 0);
        s.begin_timeline(0, 0x100);
        let pcm = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        s.build_audio_packet(&pcm);
        let sync = s.build_sync_packet(true);
        // now = 0x100 + 352 = 0x260; now - latency = 0x160.
        assert_eq!(u32::from_be_bytes(sync[4..8].try_into().unwrap()), 0x160);
        assert_eq!(u32::from_be_bytes(sync[16..20].try_into().unwrap()), 0x260);
    }

    #[test]
    fn retransmit_replays_stored_packets_in_order() {
        let mut s = stream(9, 1000);
        s.begin_timeline(0, 0);
        let pcm = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        let p1 = s.build_audio_packet(&pcm);
        let p2 = s.build_audio_packet(&pcm);
        // Request both lost seqs: 1000, 1001.
        let req = [0x80, 0x55, 0x00, 0x07, 0x03, 0xE8, 0x00, 0x02];
        let resps = s.retransmit_responses(&req).expect("type 0x55");
        assert_eq!(resps.len(), 2);
        let mut want1 = vec![0x80, 0xD6, 0x03, 0xE8];
        want1.extend_from_slice(&p1);
        let mut want2 = vec![0x80, 0xD6, 0x03, 0xE9];
        want2.extend_from_slice(&p2);
        assert_eq!(resps[0], want1);
        assert_eq!(resps[1], want2);
    }

    #[test]
    fn retransmit_skips_aged_out_slots() {
        let mut s = stream(3, 5);
        s.begin_timeline(0, 0);
        let pcm = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        s.build_audio_packet(&pcm); // seq 5 → slot 5
        // seq 5 + 1024 lands in the same slot, evicting seq 5.
        s.seq = 5 + 1024;
        s.build_audio_packet(&pcm);
        let req = [0x80, 0x55, 0x00, 0x07, 0x00, 0x05, 0x00, 0x01]; // seq 5
        assert_eq!(
            s.retransmit_responses(&req).expect("type 0x55"),
            Vec::<Vec<u8>>::new()
        );
    }

    #[test]
    fn retransmit_ignores_other_types_and_short_datagrams() {
        let s = stream(1, 0);
        assert_eq!(
            s.retransmit_responses(&[0x80, 0x54, 0, 0, 0, 0, 0, 0]),
            None
        );
        assert_eq!(s.retransmit_responses(&[0x80, 0x55, 0, 0]), None);
    }

    #[test]
    fn timing_reply_golden() {
        let mut req = vec![0u8; 32];
        req[0] = 0x07; // proto byte
        req[24..32].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]); // sendtime
        let now: u64 = 0x1122_3344_5566_7788;
        assert_eq!(
            build_timing_reply(&req, now),
            Some(vec![
                0x07, 0xD3, 0x00, 0x07, // proto echoed, type, line
                0x00, 0x00, 0x00, 0x00, // padding
                0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, // reftime
                0x11, 0x22, 0x33, 0x44, // recvtime hi
                0x55, 0x66, 0x77, 0x88, // recvtime lo
                0x11, 0x22, 0x33, 0x44, // sendtime hi
                0x55, 0x66, 0x77, 0x88, // sendtime lo
            ])
        );
    }

    #[test]
    fn timing_reply_short_rejected() {
        assert_eq!(build_timing_reply(&[0u8; 31], 0), None);
    }

    #[test]
    fn seq_frames_and_rtptime_advance_consistently() {
        let mut s = stream(0x0A0B, 400);
        s.begin_timeline(0, 0x100);
        let pcm = vec![0i16; FRAMES_PER_PACKET * CHANNELS];
        for _ in 0..3 {
            s.build_audio_packet(&pcm);
        }
        assert_eq!(s.seq(), 403);
        assert_eq!(s.frames_sent(), 3 * FRAMES_PER_PACKET as u64);
        assert_eq!(s.rtptime32(), 0x100 + 3 * FRAMES_PER_PACKET as u32);
    }
}
