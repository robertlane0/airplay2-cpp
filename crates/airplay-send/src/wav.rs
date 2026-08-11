// SPDX-License-Identifier: Apache-2.0
//!
//! WAV → interleaved stereo s16 PCM (port of `example/wav_reader.cpp`).
//!
//! Demo-scoped, not a general media library: loads the whole file into
//! memory (fine for the short clips this demo targets; a real app would
//! stream from disk instead), and only handles the RIFF/WAVE chunk layout
//! every encoder in practice produces (`fmt ` + `data`, in either order,
//! with or without a `WAVE_FORMAT_EXTENSIBLE` fmt chunk). No
//! RIFF64/BWF/ADPCM support.
//!
//! Bounds-checked against a truncated/malformed file (this is a
//! user-supplied file, not untrusted network input, but "corrupt wav →
//! clear error" beats "corrupt wav → crash" for a CLI tool either way).

/// A file this large is almost certainly a mistake (or not actually a
/// short demo clip); fail with a clear message rather than trying to load
/// it all into memory. ~1 GB is generous headroom for anything reasonable.
const MAX_FILE_BYTES: usize = 1024 * 1024 * 1024;

/// Decoded audio: interleaved stereo s16 at the file's native rate (the
/// session resamples to 44.1 kHz internally; this does NOT resample).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WavAudio {
    /// Interleaved stereo (frame = `pcm[i * 2]`, `pcm[i * 2 + 1]`).
    pub pcm: Vec<i16>,
    pub sample_rate: u32,
}

impl WavAudio {
    pub fn frames(&self) -> usize {
        self.pcm.len() / 2
    }
}

fn rd_u16(p: &[u8]) -> u16 {
    u16::from_le_bytes([p[0], p[1]])
}

fn rd_u32(p: &[u8]) -> u32 {
    u32::from_le_bytes([p[0], p[1], p[2], p[3]])
}

/// Decode one sample (at `p`, `bytes_per_sample` wide) to i16, given the
/// wav's format tag (1 = PCM integer, 3 = IEEE float).
fn decode_sample(p: &[u8], bytes_per_sample: usize, format_tag: u16) -> i16 {
    if format_tag == 3 && bytes_per_sample == 4 {
        let f = f32::from_le_bytes([p[0], p[1], p[2], p[3]]).clamp(-1.0, 1.0);
        // `as` truncates toward zero and saturates at the bounds, matching
        // the C++ float→int16 cast on the clamped input.
        return (f * 32767.0) as i16;
    }
    match bytes_per_sample {
        1 => {
            // WAV 8-bit PCM is unsigned, centered at 128.
            let v = i32::from(p[0]) - 128;
            (v * 256) as i16
        }
        2 => i16::from_le_bytes([p[0], p[1]]),
        3 => {
            let mut u = u32::from(p[0]) | (u32::from(p[1]) << 8) | (u32::from(p[2]) << 16);
            if u & 0x0080_0000 != 0 {
                u |= 0xFF00_0000; // sign-extend 24 → 32 bits
            }
            (u as i32 >> 8) as i16
        }
        4 => (i32::from_le_bytes([p[0], p[1], p[2], p[3]]) >> 16) as i16,
        _ => 0,
    }
}

/// Parse a complete RIFF/WAVE file from memory (pure; the CLI wraps it in
/// the file-loading `load_wav`). Errors carry the C++ message text.
pub fn parse_wav(bytes: &[u8]) -> Result<WavAudio, String> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err("file is implausibly large, refusing to load".to_string());
    }
    if bytes.len() < 44 {
        return Err("file is too small to be a wav".to_string());
    }
    if &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return Err("not a RIFF/WAVE file (missing 'RIFF'/'WAVE' magic)".to_string());
    }

    let (mut format_tag, mut num_channels, mut sample_rate, mut block_align, mut bits_per_sample) =
        (0u16, 0u16, 0u32, 0u16, 0u16);
    let mut have_fmt = false;
    let (mut data_ptr, mut data_len) = (0usize, 0usize);

    let mut pos = 12; // past "RIFF"+size+"WAVE"
    while pos + 8 <= bytes.len() {
        let chunk_id = &bytes[pos..pos + 4];
        let chunk_size = rd_u32(&bytes[pos + 4..pos + 8]) as usize;
        let chunk_data_off = pos + 8;
        if chunk_data_off + chunk_size > bytes.len() {
            // A truncated/malformed final chunk; stop, use whatever chunks
            // were already fully parsed (matches how most players are
            // forgiving of a slightly-broken trailing chunk).
            break;
        }
        let p = &bytes[chunk_data_off..chunk_data_off + chunk_size];
        if chunk_id == b"fmt " && chunk_size >= 16 {
            format_tag = rd_u16(&p[0..2]);
            num_channels = rd_u16(&p[2..4]);
            sample_rate = rd_u32(&p[4..8]);
            block_align = rd_u16(&p[12..14]);
            bits_per_sample = rd_u16(&p[14..16]);
            // WAVE_FORMAT_EXTENSIBLE (0xFFFE): the base WAVEFORMATEX fields
            // are the first 16 bytes, followed by cbSize(2) +
            // wValidBitsPerSample(2) + dwChannelMask(4), and only THEN the
            // 16-byte SubFormat GUID, whose first 2 bytes are the real
            // format tag. 16 + 2 + 2 + 4 = byte offset 24.
            if format_tag == 0xFFFE && chunk_size >= 24 + 16 {
                format_tag = rd_u16(&p[24..26]);
            }
            have_fmt = true;
        } else if chunk_id == b"data" {
            data_ptr = chunk_data_off;
            data_len = chunk_size;
        }
        // Chunks are word-aligned: an odd chunkSize has one pad byte after
        // it.
        pos = chunk_data_off + chunk_size + (chunk_size & 1);
    }

    if !have_fmt {
        return Err("no 'fmt ' chunk found".to_string());
    }
    if data_len == 0 {
        return Err("no 'data' chunk found".to_string());
    }
    if format_tag != 1 && format_tag != 3 {
        return Err(format!(
            "unsupported wav format tag {format_tag} (only PCM integer and IEEE float are supported)"
        ));
    }
    if num_channels == 0 {
        return Err("wav declares 0 channels".to_string());
    }
    if bits_per_sample != 8
        && bits_per_sample != 16
        && bits_per_sample != 24
        && bits_per_sample != 32
    {
        return Err(format!("unsupported bits-per-sample {bits_per_sample}"));
    }
    let bytes_per_sample = usize::from(bits_per_sample / 8);
    if block_align == 0 {
        block_align = (bytes_per_sample * usize::from(num_channels)) as u16;
    }
    if usize::from(block_align) < bytes_per_sample * usize::from(num_channels) {
        return Err("wav 'fmt ' chunk has an inconsistent blockAlign".to_string());
    }

    let frame_count = data_len / usize::from(block_align);
    let mut pcm = Vec::with_capacity(frame_count * 2);
    for i in 0..frame_count {
        let frame = &bytes[data_ptr + i * usize::from(block_align)..];
        let l = decode_sample(frame, bytes_per_sample, format_tag);
        let r = if num_channels >= 2 {
            decode_sample(&frame[bytes_per_sample..], bytes_per_sample, format_tag)
        } else {
            l // mono → duplicate to both channels
        };
        pcm.push(l);
        pcm.push(r);
    }

    Ok(WavAudio { pcm, sample_rate })
}

/// Read `path` and decode it (C++ `loadWavAsStereo16`).
pub fn load_wav(path: &str) -> Result<WavAudio, String> {
    let bytes = std::fs::read(path).map_err(|_| format!("could not open '{path}'"))?;
    if bytes.is_empty() {
        return Err("file is too small to be a wav".to_string());
    }
    parse_wav(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wav(fmt: &[u8], fmt_size: u32, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"RIFF");
        let total = 4 + 8 + fmt_size + 8 + data.len() as u32;
        b.extend_from_slice(&total.to_le_bytes());
        b.extend_from_slice(b"WAVE");
        b.extend_from_slice(b"fmt ");
        b.extend_from_slice(&fmt_size.to_le_bytes());
        b.extend_from_slice(fmt);
        b.extend_from_slice(b"data");
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(data);
        b
    }

    /// Standard 16-bit stereo fmt chunk.
    fn fmt16(rate: u32, channels: u16) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&1u16.to_le_bytes()); // PCM
        f.extend_from_slice(&channels.to_le_bytes());
        f.extend_from_slice(&rate.to_le_bytes());
        f.extend_from_slice(&(rate * 2 * u32::from(channels)).to_le_bytes());
        f.extend_from_slice(&(2u16 * channels).to_le_bytes()); // blockAlign
        f.extend_from_slice(&16u16.to_le_bytes());
        f
    }

    /// Any 1/3-tagged fmt with a custom bits-per-sample (8, 24, 32).
    fn fmt_bits(rate: u32, channels: u16, bits: u16, tag: u16) -> Vec<u8> {
        let bps = u32::from(bits / 8);
        let mut f = Vec::new();
        f.extend_from_slice(&tag.to_le_bytes());
        f.extend_from_slice(&channels.to_le_bytes());
        f.extend_from_slice(&rate.to_le_bytes());
        f.extend_from_slice(&(rate * bps * u32::from(channels)).to_le_bytes());
        f.extend_from_slice(&((bps * u32::from(channels)) as u16).to_le_bytes());
        f.extend_from_slice(&bits.to_le_bytes());
        f
    }

    fn stereo16(rate: u32, samples: &[i16]) -> Vec<u8> {
        let mut d = Vec::new();
        for s in samples {
            d.extend_from_slice(&s.to_le_bytes());
        }
        wav(&fmt16(rate, 2), 16, &d)
    }

    #[test]
    fn sixteen_bit_stereo_roundtrip() {
        let w = stereo16(44100, &[1, -2, 300, -300, 32767, -32768]);
        let a = parse_wav(&w).unwrap();
        assert_eq!(a.sample_rate, 44100);
        assert_eq!(a.frames(), 3);
        assert_eq!(a.pcm, vec![1, -2, 300, -300, 32767, -32768]);
    }

    #[test]
    fn mono_is_duplicated() {
        let w = wav(
            &fmt16(22050, 1),
            16,
            &[42i16, -42]
                .iter()
                .flat_map(|&s| s.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let a = parse_wav(&w).unwrap();
        assert_eq!(a.pcm, vec![42, 42, -42, -42]);
        assert_eq!(a.sample_rate, 22050);
    }

    #[test]
    fn eight_bit_unsigned_centered_at_128() {
        let w = wav(&fmt_bits(8000, 2, 8, 1), 16, &[0u8, 128, 255, 129]);
        let a = parse_wav(&w).unwrap();
        assert_eq!(a.pcm, vec![-32768, 0, 32512, 256]);
    }

    #[test]
    fn twenty_four_bit_sign_extended() {
        // Stereo frames of 3-byte samples: (-1, +1) then (32767, 0). The
        // reader takes the TOP 16 bits of each 24-bit sample (>>8), so
        // 0x000100 — not 0x000001 — is the smallest +1.
        let w = wav(
            &fmt_bits(48000, 2, 24, 1),
            16,
            &[
                0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x00, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00,
            ],
        );
        let a = parse_wav(&w).unwrap();
        assert_eq!(a.pcm, vec![-1, 1, 32767, 0]);
    }

    #[test]
    fn thirty_two_bit_integer_takes_top_bits() {
        // >>16 keeps the signed top half: -131072 (0xFFFE0000) -> -2.
        let minus_two = (-131072i32).to_le_bytes();
        let big = 0x0001_0000i32.to_le_bytes();
        let w = wav(&fmt_bits(48000, 2, 32, 1), 16, &[minus_two, big].concat());
        let a = parse_wav(&w).unwrap();
        assert_eq!(a.pcm, vec![-2, 1]); // >> 16
    }

    #[test]
    fn float32_clamps_and_scales() {
        let f = |v: f32| v.to_le_bytes();
        let w = wav(
            &fmt_bits(48000, 2, 32, 3),
            16,
            &[f(0.5), f(1.5), f(-2.0), f(0.0)].concat(),
        );
        let a = parse_wav(&w).unwrap();
        // +1.5 clamps to 1.0 → 32767; -2.0 clamps to -1.0 → -32767 (the
        // C++ clamps BEFORE scaling, so the negative bound is -32767).
        assert_eq!(a.pcm, vec![16383, 32767, -32767, 0]); // truncation toward zero
    }

    #[test]
    fn float_needs_four_byte_samples() {
        // Tag 3 with 2-byte samples: falls through to the int paths.
        let mut fmt = fmt16(48000, 2);
        fmt[0..2].copy_from_slice(&3u16.to_le_bytes());
        let d = [7i16, -7]
            .iter()
            .flat_map(|s| s.to_le_bytes())
            .collect::<Vec<_>>();
        let a = parse_wav(&wav(&fmt, 16, &d)).unwrap();
        assert_eq!(a.pcm, vec![7, -7]);
    }

    #[test]
    fn wave_format_extensible_resolves_subformat_guid() {
        // 24-bit PCM in a WAVE_FORMAT_EXTENSIBLE fmt chunk (the Bandcamp /
        // DAW export shape): the REAL tag (PCM 1) is 2 bytes into the
        // 16-byte SubFormat GUID at offset 24.
        let ext_base = fmt16(48000, 2);
        let mut ext = ext_base.clone();
        ext[0..2].copy_from_slice(&0xFFFEu16.to_le_bytes()); // base tag → extensible
        ext.extend_from_slice(&22u16.to_le_bytes()); // cbSize: 2+2+4+16 = 22
        ext.extend_from_slice(&24u16.to_le_bytes()); // wValidBitsPerSample
        ext.extend_from_slice(&0x0000_0003u32.to_le_bytes()); // channel mask
        let mut guid = [0u8; 16];
        guid[0..2].copy_from_slice(&1u16.to_le_bytes()); // KSDATAFORMAT_SUBTYPE_PCM
        ext.extend_from_slice(&guid);
        ext[14..16].copy_from_slice(&24u16.to_le_bytes()); // bits/sample
        ext[12..14].copy_from_slice(&6u16.to_le_bytes()); // blockAlign: 3 bytes × 2ch
        let d = [0xFFu8, 0xFF, 0xFF, 0x00, 0x01, 0x00];
        let a = parse_wav(&wav(&ext, 40, &d)).unwrap();
        assert_eq!(a.pcm, vec![-1, 1]);
    }

    #[test]
    fn data_chunk_before_fmt_chunk() {
        let mut b = Vec::new();
        b.extend_from_slice(b"RIFF");
        b.extend_from_slice(&36u32.to_le_bytes());
        b.extend_from_slice(b"WAVE");
        b.extend_from_slice(b"data");
        b.extend_from_slice(&4u32.to_le_bytes());
        b.extend_from_slice(
            &[1i16, 2]
                .iter()
                .flat_map(|s| s.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        b.extend_from_slice(b"fmt ");
        b.extend_from_slice(&16u32.to_le_bytes());
        b.extend_from_slice(&fmt16(44100, 2));
        let a = parse_wav(&b).unwrap();
        assert_eq!(a.pcm, vec![1, 2]);
    }

    #[test]
    fn odd_chunk_size_gets_pad_byte() {
        // A "cue " chunk with an odd size (1 byte) between fmt and data.
        let data = [9i16, -9]
            .iter()
            .flat_map(|s| s.to_le_bytes())
            .collect::<Vec<_>>();
        let mut b = Vec::new();
        b.extend_from_slice(b"RIFF");
        b.extend_from_slice(&51u32.to_le_bytes());
        b.extend_from_slice(b"WAVE");
        b.extend_from_slice(b"fmt ");
        b.extend_from_slice(&16u32.to_le_bytes());
        b.extend_from_slice(&fmt16(44100, 2));
        b.extend_from_slice(b"cue ");
        b.extend_from_slice(&1u32.to_le_bytes());
        b.push(0xAA);
        b.push(0x00); // pad
        b.extend_from_slice(b"data");
        b.extend_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(&data);
        let a = parse_wav(&b).unwrap();
        assert_eq!(a.pcm, vec![9, -9]);
    }

    #[test]
    fn truncated_trailing_chunk_is_forgiven() {
        let w = stereo16(44100, &[5, 6]);
        let mut t = w.clone();
        t.extend_from_slice(b"LIST");
        t.extend_from_slice(&999u32.to_le_bytes()); // claims 999 bytes, has none
        let a = parse_wav(&t).unwrap(); // fmt+data already parsed
        assert_eq!(a.pcm, vec![5, 6]);
    }

    #[test]
    fn truncated_pcm_is_cut_to_complete_frames() {
        // 5 samples = 10 bytes declared as stereo-16 data: the header size
        // drives decoding, so only 10/4 = 2 complete frames come out.
        let w = stereo16(44100, &[1, 2, 3, 4, 5]);
        let a = parse_wav(&w).unwrap();
        assert_eq!(a.pcm, vec![1, 2, 3, 4]);
        // Physically cutting the file mid-chunk instead makes the trailing
        // chunk unreadable, and the reader drops it wholesale (same as the
        // C++): no data survives, with the usual clear error.
        let mut cut = w;
        cut.truncate(cut.len() - 1);
        assert_eq!(parse_wav(&cut).unwrap_err(), "no 'data' chunk found");
    }

    #[test]
    fn too_small_for_a_wav() {
        assert_eq!(
            parse_wav(&[0u8; 43]).unwrap_err(),
            "file is too small to be a wav"
        );
    }

    #[test]
    fn bad_magic() {
        assert_eq!(
            parse_wav(&[0u8; 44]).unwrap_err(),
            "not a RIFF/WAVE file (missing 'RIFF'/'WAVE' magic)"
        );
        let mut b = b"RIFF\x24\x00\x00\x00FAKE".to_vec();
        b.resize(44, 0);
        assert_eq!(
            parse_wav(&b).unwrap_err(),
            "not a RIFF/WAVE file (missing 'RIFF'/'WAVE' magic)"
        );
    }

    #[test]
    fn missing_fmt_or_data_chunks() {
        assert_eq!(
            parse_wav(&wav(&fmt16(44100, 2), 16, &[])).unwrap_err(),
            "no 'data' chunk found"
        );
        // A plausible RIFF/WAVE without any fmt chunk (padded past the
        // 44-byte minimum so the "no 'fmt '" check is what fires).
        let mut no_fmt = Vec::new();
        no_fmt.extend_from_slice(b"RIFF");
        no_fmt.extend_from_slice(&44u32.to_le_bytes());
        no_fmt.extend_from_slice(b"WAVE");
        no_fmt.extend_from_slice(b"data");
        no_fmt.extend_from_slice(&4u32.to_le_bytes());
        no_fmt.extend_from_slice(&[0u8; 4]);
        no_fmt.extend_from_slice(&[0u8; 24]); // filler for the size floor
        assert_eq!(parse_wav(&no_fmt).unwrap_err(), "no 'fmt ' chunk found");
    }

    #[test]
    fn unsupported_format_tag() {
        let mut fmt = fmt16(44100, 2);
        fmt[0..2].copy_from_slice(&2u16.to_le_bytes()); // ADPCM
        assert_eq!(
            parse_wav(&wav(&fmt, 16, &[0u8; 4])).unwrap_err(),
            "unsupported wav format tag 2 (only PCM integer and IEEE float are supported)"
        );
    }

    #[test]
    fn unsupported_bits_per_sample() {
        let mut fmt = fmt16(44100, 2);
        fmt[14..16].copy_from_slice(&12u16.to_le_bytes());
        assert_eq!(
            parse_wav(&wav(&fmt, 16, &[0u8; 4])).unwrap_err(),
            "unsupported bits-per-sample 12"
        );
    }

    #[test]
    fn zero_channels_rejected() {
        let fmt = fmt16(44100, 0);
        assert_eq!(
            parse_wav(&wav(&fmt, 16, &[0u8; 4])).unwrap_err(),
            "wav declares 0 channels"
        );
    }

    #[test]
    fn block_align_zero_falls_back_and_inconsistency_rejected() {
        let mut fmt = fmt16(44100, 2);
        fmt[12..14].copy_from_slice(&0u16.to_le_bytes());
        let a = parse_wav(&wav(
            &fmt,
            16,
            &[1i16, 2]
                .iter()
                .flat_map(|s| s.to_le_bytes())
                .collect::<Vec<_>>(),
        ))
        .unwrap();
        assert_eq!(a.pcm, vec![1, 2]);

        let mut bad = fmt16(44100, 2);
        bad[12..14].copy_from_slice(&1u16.to_le_bytes()); // < 2*2
        assert_eq!(
            parse_wav(&wav(&bad, 16, &[0u8; 4])).unwrap_err(),
            "wav 'fmt ' chunk has an inconsistent blockAlign"
        );
    }

    #[test]
    fn sample_rate_zero_passthrough() {
        // A rate of 0 is not rejected by the reader (matches the C++); the
        // session treats it as "no device format" at attach time.
        let w = stereo16(0, &[1, 2]);
        let a = parse_wav(&w).unwrap();
        assert_eq!(a.sample_rate, 0);
    }

    #[test]
    fn load_wav_missing_file_message() {
        assert_eq!(
            load_wav("/nonexistent/airplay-send-test.wav").unwrap_err(),
            "could not open '/nonexistent/airplay-send-test.wav'"
        );
    }
}
