// SPDX-License-Identifier: Apache-2.0
//! HomeKit TLV8 (type-length-value, 255-byte fragmenting).
//!
//! One level only (HAP never nests). A repeated tag whose value exceeds
//! 255 bytes is split into consecutive same-tag chunks on write and
//! re-joined on read — required for the 384-byte SRP PublicKey. Port of
//! the `tlv` namespace in [`src/airplay_crypto.cpp`](../../src/airplay_crypto.cpp).

/// The HAP TLV8 tag values AirPlay 2 SETUP uses.
pub const METHOD: u8 = 0x00;
pub const IDENTIFIER: u8 = 0x01;
pub const SALT: u8 = 0x02;
pub const PUBLIC_KEY: u8 = 0x03;
pub const PROOF: u8 = 0x04;
pub const ENCRYPTED_DATA: u8 = 0x05;
pub const STATE: u8 = 0x06;
pub const ERROR: u8 = 0x07;
pub const SIGNATURE: u8 = 0x0A;
pub const PERMISSIONS: u8 = 0x0B;
pub const NAME: u8 = 0x11;
pub const FLAGS: u8 = 0x13;

/// Insertion-ordered tag/value sequence (HAP cares about order for some
/// receivers). Mirrors the C++ `tlv::Map`.
pub type Map = Vec<(u8, Vec<u8>)>;

/// Encode items, fragmenting values > 255 bytes into consecutive
/// same-tag chunks. An empty value still emits one zero-length record
/// (HAP `State`/`Method` etc.). Matches `tlv::encode`.
pub fn encode(items: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (tag, value) in items {
        let mut pos = 0usize;
        loop {
            let chunk = 255.min(value.len() - pos);
            out.push(*tag);
            out.push(chunk as u8);
            out.extend_from_slice(&value[pos..pos + chunk]);
            pos += chunk;
            if pos >= value.len() {
                break;
            }
        }
    }
    out
}

/// Decode, re-joining a repeated tag that immediately follows (a
/// fragmented value). Malformed trailing records (a length running past
/// the end) are dropped, exactly like the C++.
pub fn decode(data: &[u8]) -> Map {
    let mut out: Map = Vec::new();
    let mut i = 0usize;
    while i + 2 <= data.len() {
        let tag = data[i];
        let len = data[i + 1] as usize;
        if i + 2 + len > data.len() {
            break;
        }
        let chunk = data[i + 2..i + 2 + len].to_vec();
        match out.last_mut() {
            Some((last_tag, last_value)) if *last_tag == tag => {
                last_value.extend_from_slice(&chunk)
            }
            _ => out.push((tag, chunk)),
        }
        i += 2 + len;
    }
    out
}

/// Fetch the (joined) value for a tag — the first occurrence wins,
/// matching `tlv::get`.
pub fn get(map: &Map, tag: u8) -> Option<&Vec<u8>> {
    map.iter().find(|(t, _)| *t == tag).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_simple() {
        let m = vec![
            (METHOD, vec![0x00]),
            (STATE, vec![0x01]),
            (NAME, b"test-device".to_vec()),
        ];
        let enc = encode(&m);
        assert_eq!(decode(&enc), m);
    }

    #[test]
    fn fragmentation_over_255() {
        // A 384-byte value (SRP PublicKey) fragments into 255+129 chunks
        // and re-joins to the exact original.
        let big: Vec<u8> = (0..384).map(|i| (i % 251) as u8).collect();
        let enc = encode(&[(PUBLIC_KEY, big.clone())]);
        assert!(enc.len() > big.len());
        assert_eq!(decode(&enc), vec![(PUBLIC_KEY, big)]);
    }

    #[test]
    fn empty_value_emits_one_record() {
        let enc = encode(&[(STATE, vec![])]);
        assert_eq!(enc, vec![STATE, 0]);
        assert_eq!(decode(&enc), vec![(STATE, vec![])]);
    }

    #[test]
    fn insertion_order_preserved() {
        let m = vec![
            (NAME, b"a".to_vec()),
            (SALT, b"b".to_vec()),
            (NAME, b"c".to_vec()),
        ];
        let dec = decode(&encode(&m));
        assert_eq!(dec.len(), 3);
        assert_eq!(dec[0], (NAME, b"a".to_vec()));
        assert_eq!(dec[1], (SALT, b"b".to_vec()));
        assert_eq!(dec[2], (NAME, b"c".to_vec()));
    }

    #[test]
    fn get_returns_first_match() {
        let m = vec![(NAME, b"x".to_vec()), (NAME, b"y".to_vec())];
        assert_eq!(get(&m, NAME), Some(&b"x".to_vec()));
        assert_eq!(get(&m, SALT), None);
    }

    #[test]
    fn truncated_record_dropped() {
        // Length claims 10 bytes but only 3 exist -> record dropped, the
        // earlier complete record survives.
        let data = vec![STATE, 1, 0x01, SALT, 10, 1, 2];
        let dec = decode(&data);
        assert_eq!(dec, vec![(STATE, vec![0x01])]);
    }

    #[test]
    fn exact_255_boundary() {
        let v: Vec<u8> = vec![7; 255];
        let enc = encode(&[(PROOF, v.clone())]);
        assert_eq!(enc.len(), 2 + 255);
        assert_eq!(decode(&enc), vec![(PROOF, v)]);
    }
}
