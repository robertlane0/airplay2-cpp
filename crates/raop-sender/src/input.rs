// SPDX-License-Identifier: Apache-2.0
//! The input side of the streaming half of
//! [`src/raop_sender.cpp`](https://github.com/fxchain/cast/raw/…):
//!
//! * [`Resampler`] — `fillFrames_`'s device→44100 pipeline: pass-through
//!   when the device is already 44100, otherwise a deliberately simple
//!   two-point linear interpolation with a bounded staging buffer
//!   (`kInBufMaxFrames`), fractional phase tracking, and compaction that
//!   keeps only the lerp's left neighbour (the documented Phase-2
//!   refinement would be windowed-sinc);
//! * [`target_frames`] / [`pending_packets`] — the `onPacerTick_` token
//!   bucket made pure: frames-on-the-wire must track wall clock at
//!   44100/s, a stall is repaid in capped bursts so a halted player can
//!   catch up without flooding the LAN.
//!
//! The ring itself, the pacing timer and the RTP send stay with the
//! state-machine slice; `pacing` only decides the counts.

use ring_buffer::RingBuffer;

use crate::util::{
    CHANNELS, FRAMES_PER_PACKET, IN_BUF_MAX_FRAMES, MAX_PACKETS_PER_TICK, RAOP_RATE,
};

/// Device→44100 resampling state mirroring `fillFrames_`'s non-trivial
/// branch: the staging buffer, the fractional read phase and the device
/// rate. The C++ `inReadFrames_` member was dropped: it is written and
/// reset but never read anywhere.
pub struct Resampler {
    input_rate: u32,
    phase: f64,
    in_buf: Vec<i16>,
}

impl Resampler {
    /// A resampler with no device rate configured yet (behaves as 0 —
    /// the C++ `setInputFormat` maps 0 to 48000, mirroring the WASAPI
    /// default).
    pub fn new() -> Self {
        Resampler {
            input_rate: 0,
            phase: 0.0,
            in_buf: Vec::new(),
        }
    }

    /// `setInputFormat`: 0 = no device open yet, assume 48000.
    pub fn set_input_format(&mut self, sample_rate: u32) {
        self.input_rate = if sample_rate > 0 { sample_rate } else { 48000 };
    }

    /// The device rate in effect (after any 0 → 48000 mapping).
    pub fn input_rate(&self) -> u32 {
        self.input_rate
    }

    /// Fill `dst` (exactly `want` frames, i.e. `want * CHANNELS`
    /// samples) exactly like `fillFrames_`. `ring` is `None` when no
    /// input device is open (all silence). Returns the number of frames
    /// produced from real input; the rest of `dst` is silence, because
    /// the timeline must keep running or the receiver declares the
    /// stream dead.
    pub fn fill(
        &mut self,
        dst: &mut [i16],
        want: usize,
        ring: Option<&mut RingBuffer<i16>>,
    ) -> usize {
        assert_eq!(
            dst.len(),
            want * CHANNELS,
            "dst must hold exactly want * CHANNELS samples"
        );
        let want_samples = want * CHANNELS;
        let Some(ring) = ring else {
            dst.fill(0);
            return 0;
        };

        if self.input_rate == RAOP_RATE {
            // Pass-through: pop what's there, pad the rest with silence.
            let take = (ring.available_read()).min(want_samples);
            if take > 0 {
                let _ = ring.try_pop(&mut dst[..take]);
            }
            dst[take..want_samples].fill(0);
            return take / CHANNELS;
        }

        // Linear-interpolation resample deviceRate → 44100 (two-point
        // lerp; allocation-light, quality fine for the cast path).
        let step = f64::from(self.input_rate) / f64::from(RAOP_RATE);

        // Top up the staging buffer from the ring (bounded working set).
        let mut buf_frames = self.in_buf.len() / CHANNELS;
        let room = IN_BUF_MAX_FRAMES.saturating_sub(buf_frames);
        let ring_frames = ring.available_read() / CHANNELS;
        let pull = room.min(ring_frames);
        if pull > 0 {
            let old = self.in_buf.len();
            self.in_buf.resize(old + pull * CHANNELS, 0);
            let _ = ring.try_pop(&mut self.in_buf[old..]);
            buf_frames += pull;
        }

        let mut produced = 0;
        while produced < want {
            let i0 = self.phase.floor() as usize;
            if i0 + 1 >= buf_frames {
                break; // need i0 and i0+1, starved
            }
            let frac = self.phase - i0 as f64;
            let a = &self.in_buf[i0 * CHANNELS..(i0 + 1) * CHANNELS];
            let b = &self.in_buf[(i0 + 1) * CHANNELS..(i0 + 2) * CHANNELS];
            for ch in 0..CHANNELS {
                dst[produced * CHANNELS + ch] =
                    (f64::from(a[ch]) + (f64::from(b[ch]) - f64::from(a[ch])) * frac) as i16;
            }
            self.phase += step;
            produced += 1;
        }
        if produced < want {
            dst[produced * CHANNELS..want_samples].fill(0);
        }

        // Compact: drop fully consumed frames (keep the one at
        // floor(phase), the lerp's left neighbour) and rebase the phase.
        let keep_from = self.phase.floor() as usize;
        if keep_from > 0 {
            let drop = keep_from.min(buf_frames);
            self.in_buf.drain(..drop * CHANNELS);
            self.phase -= drop as f64;
        }
        produced
    }
}

impl Default for Resampler {
    fn default() -> Self {
        Self::new()
    }
}

/// `onPacerTick_`'s token-bucket target: the frames that should be on
/// the wire after `elapsed_ns` of steady wall clock at 44100/s.
pub fn target_frames(elapsed_ns: u64) -> u64 {
    elapsed_ns * u64::from(RAOP_RATE) / 1_000_000_000
}

/// How many packets one pacer tick may send: every full
/// `FRAMES_PER_PACKET` block up to `target` is due, capped at
/// `MAX_PACKETS_PER_TICK` (the stall catch-up cap — the receiver
/// buffers ~2 s, so a capped catch-up is inaudible). Mirrors the
/// `onPacerTick_` loop, whose condition re-reads the (growing)
/// `framesSent_` each iteration — the equivalent closed form is
/// `min(cap, (target - frames_sent) / FRAMES_PER_PACKET)`.
pub fn pending_packets(frames_sent: u64, target: u64) -> usize {
    let due = target.saturating_sub(frames_sent) / FRAMES_PER_PACKET as u64;
    (due as usize).min(MAX_PACKETS_PER_TICK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_with(samples: &[i16]) -> RingBuffer<i16> {
        let mut r = RingBuffer::new(samples.len().next_power_of_two());
        assert!(r.try_push(samples));
        r
    }

    fn frames_to_samples(frames: &[(i16, i16)]) -> Vec<i16> {
        frames.iter().flat_map(|&(l, r)| [l, r]).collect()
    }

    #[test]
    fn no_ring_is_all_silence_and_counts_zero() {
        let mut rs = Resampler::new();
        rs.set_input_format(44100);
        let mut dst = [9i16; 704];
        assert_eq!(rs.fill(&mut dst, FRAMES_PER_PACKET, None), 0);
        assert!(dst.iter().all(|&s| s == 0));
    }

    #[test]
    fn passthrough_pops_whats_there_and_pads() {
        let mut rs = Resampler::new();
        rs.set_input_format(44100);
        let mut ring = ring_with(&frames_to_samples(&[(10, 20), (30, 40)]));
        let mut dst = [9i16; 704];
        assert_eq!(rs.fill(&mut dst, FRAMES_PER_PACKET, Some(&mut ring)), 2);
        assert_eq!(&dst[..4], &[10, 20, 30, 40]);
        assert!(dst[4..].iter().all(|&s| s == 0));
        assert_eq!(ring.available_read(), 0);
    }

    #[test]
    fn passthrough_fully_starved_is_silence() {
        let mut rs = Resampler::new();
        rs.set_input_format(44100);
        let mut ring = RingBuffer::new(16);
        let mut dst = [7i16; 704];
        assert_eq!(rs.fill(&mut dst, FRAMES_PER_PACKET, Some(&mut ring)), 0);
        assert!(dst.iter().all(|&s| s == 0));
    }

    #[test]
    fn resample_88200_takes_every_other_frame() {
        // step = 2.0: frames 0 and 2 are sampled verbatim (frac = 0),
        // then the right neighbour runs out → silence pad.
        let mut rs = Resampler::new();
        rs.set_input_format(88200);
        let mut ring = ring_with(&frames_to_samples(&[
            (10, 20),
            (30, 40),
            (50, 60),
            (70, 80),
        ]));
        let mut dst = [0i16; 8];
        assert_eq!(rs.fill(&mut dst, 4, Some(&mut ring)), 2);
        assert_eq!(&dst, &[10, 20, 50, 60, 0, 0, 0, 0]);
        // Both remaining frames were consumed (floor(phase)=4 ≥ 4).
        assert_eq!(rs.in_buf.len(), 0);
    }

    #[test]
    fn resample_22050_interpolates_midpoints() {
        // step = 0.5: frame 1 is the exact midpoint of frames 0 and 1.
        // The lerp demands its RIGHT neighbour even when frac = 0, so
        // with 2 frames only outputs 0 and 0.5 are producible — frame
        // (100, 4000) waits for more input (C++ `i0 + 1 >= bufFrames`).
        let mut rs = Resampler::new();
        rs.set_input_format(22050);
        let mut ring = ring_with(&frames_to_samples(&[(0, 2000), (100, 4000)]));
        let mut dst = [0i16; 8];
        assert_eq!(rs.fill(&mut dst, 4, Some(&mut ring)), 2);
        assert_eq!(&dst, &[0, 2000, 50, 3000, 0, 0, 0, 0]);
        // Compaction keeps the lerp's left neighbour (frame 1) and
        // rebases the phase to 0.
        assert_eq!(rs.in_buf, vec![100, 4000]);
        assert_eq!(rs.phase, 0.0);

        // A follow-up fill is starved: nothing new arrives, the left
        // neighbour alone cannot interpolate → silence.
        let mut dst = [1i16; 4];
        assert_eq!(rs.fill(&mut dst, 2, Some(&mut ring)), 0);
        assert_eq!(&dst, &[0, 0, 0, 0]);
        assert_eq!(rs.in_buf, vec![100, 4000]);
    }

    #[test]
    fn resample_single_frame_cannot_interpolate() {
        // A lone frame has no right neighbour → starved from the first
        // output, the whole fill is silence (C++ `i0 + 1 >= bufFrames`).
        let mut rs = Resampler::new();
        rs.set_input_format(22050);
        let mut ring = ring_with(&[5, -5]);
        let mut dst = [0i16; 8];
        assert_eq!(rs.fill(&mut dst, 4, Some(&mut ring)), 0);
        assert!(dst.iter().all(|&s| s == 0));
    }

    #[test]
    fn resample_topup_bounded_by_k_in_buf_max_frames() {
        let mut rs = Resampler::new();
        rs.set_input_format(22050);
        let big: Vec<i16> = (0..20_000).map(|i| (i % 1000) as i16).collect();
        let mut ring = ring_with(&big);
        let mut dst = [0i16; 8];
        // One fill pulls only up to 8192 frames into the staging buffer;
        // the 4 outputs advance phase by 2.0 so compaction drops 2.
        assert_eq!(rs.fill(&mut dst, 4, Some(&mut ring)), 4);
        assert_eq!(rs.in_buf.len(), (IN_BUF_MAX_FRAMES - 2) * CHANNELS);
        let left_in_ring = 20_000 - 8192 * CHANNELS;
        assert_eq!(ring.available_read(), left_in_ring);
    }

    #[test]
    fn set_input_format_zero_maps_to_48000() {
        let mut rs = Resampler::new();
        rs.set_input_format(0);
        assert_eq!(rs.input_rate(), 48000);
    }

    #[test]
    fn pacer_target_linear_in_elapsed() {
        assert_eq!(target_frames(0), 0);
        assert_eq!(target_frames(1_000_000_000), 44_100);
        assert_eq!(target_frames(8_000_000), 352); // one packet tick
        // 352 frames need ≥ 352·10⁹/44100 = 7,981,860 ns.
        assert_eq!(target_frames(7_981_859), 351);
        assert_eq!(target_frames(7_981_860), 352);
    }

    #[test]
    fn pacer_sends_due_blocks_up_to_cap() {
        // Debt-free: exactly 10 blocks due.
        assert_eq!(pending_packets(0, 352 * 10), 10);
        // Partially through a block: only whole blocks count.
        assert_eq!(pending_packets(352 * 9 + 100, 352 * 10), 0);
        assert_eq!(pending_packets(352 * 9 + 100, 352 * 11), 1);
        // A stall is repaid in bursts... capped at the tick cap.
        assert_eq!(pending_packets(0, u64::MAX), MAX_PACKETS_PER_TICK);
    }

    #[test]
    fn pacer_threshold_off_by_one() {
        // The boundary is frames_sent + 352 <= target.
        assert_eq!(pending_packets(352, 351), 0);
        assert_eq!(pending_packets(352, 352), 0);
        assert_eq!(pending_packets(352, 703), 0);
        assert_eq!(pending_packets(352, 704), 1);
    }
}
