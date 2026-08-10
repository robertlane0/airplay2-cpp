// SPDX-License-Identifier: Apache-2.0
//! Apple binary property list (`bplist00`), minimal encoder/decoder.
//!
//! Enough of the bplist grammar to round-trip the AirPlay 2 SETUP
//! request/response dictionaries (dict / array / string / data / int /
//! bool / real). NOT a general libplist replacement. Port of the `bplist`
//! namespace in [`src/airplay_crypto.cpp`](../../src/airplay_crypto.cpp),
//! including every malformed-input bound the C++ applies (offset-table and
//! recursion bounds, count vs. file-size guards, wrapping-safe arithmetic).

use crate::Bytes;

/// A bplist value (C++ `Value` tagged union).
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Real(f64),
    Str(String),
    Data(Vec<u8>),
    Arr(Vec<Value>),
    /// Insertion-ordered, exactly like the C++ `Dict`.
    Dict(Vec<(String, Value)>),
}

impl Value {
    /// Lookup helper for decoded dicts (`None` if absent / wrong type).
    pub fn find(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Integer value, `def` if not an Int (C++ `asInt`).
    pub fn as_int(&self, def: i64) -> i64 {
        match self {
            Value::Int(v) => *v,
            _ => def,
        }
    }

    /// String value, `def` if not a Str (C++ `asStr`).
    pub fn as_str<'a>(&'a self, def: &'static str) -> &'a str {
        match self {
            Value::Str(s) => s,
            _ => def,
        }
    }
}

// ── encoder ───────────────────────────────────────────────────────────

/// Object-table encoder. Every distinct object lands in a flat table; a
/// fixed 4-byte object-reference size is used (simpler, always valid for
/// the small dictionaries AirPlay SETUP uses). Exact C++ layout: header
/// `bplist00`, object table, offset table, 32-byte trailer.
struct Encoder {
    objects: Vec<Vec<u8>>,
}

impl Encoder {
    fn new() -> Self {
        Encoder {
            objects: Vec::new(),
        }
    }

    /// Recursively flatten `v` into the object table, returning its index.
    /// Children of arrays/dicts are added BEFORE the parent's marker is
    /// emitted, exactly as in the C++, so the table order (and thus the
    /// encoded bytes) is identical.
    fn add(&mut self, v: &Value) -> usize {
        let idx = self.objects.len();
        self.objects.push(Vec::new()); // reserve slot (recursion-safe)
        let mut obj = Vec::new();
        match v {
            Value::Bool(b) => obj.push(if *b { 0x09 } else { 0x08 }),
            Value::Int(i) => Self::encode_int(&mut obj, *i),
            Value::Real(r) => {
                obj.push(0x23); // double (8-byte)
                obj.extend_from_slice(&r.to_bits().to_be_bytes());
            }
            Value::Str(s) => Self::encode_string(&mut obj, s),
            Value::Data(data) => {
                Self::encode_marker_len(&mut obj, 0x40, data.len());
                obj.extend_from_slice(data);
            }
            Value::Arr(items) => {
                let refs: Vec<usize> = items.iter().map(|c| self.add(c)).collect();
                Self::encode_marker_len(&mut obj, 0xA0, refs.len());
                for r in refs {
                    Self::append_ref(&mut obj, r);
                }
            }
            Value::Dict(entries) => {
                let mut krefs = Vec::with_capacity(entries.len());
                let mut vrefs = Vec::with_capacity(entries.len());
                for (k, val) in entries {
                    krefs.push(self.add(&Value::Str(k.clone())));
                    vrefs.push(self.add(val));
                }
                Self::encode_marker_len(&mut obj, 0xD0, entries.len());
                for r in krefs {
                    Self::append_ref(&mut obj, r);
                }
                for r in vrefs {
                    Self::append_ref(&mut obj, r);
                }
            }
        }
        self.objects[idx] = obj;
        idx
    }

    fn append_ref(obj: &mut Vec<u8>, r: usize) {
        obj.extend_from_slice(&(r as u32).to_be_bytes());
    }

    fn encode_marker_len(obj: &mut Vec<u8>, marker: u8, len: usize) {
        if len < 15 {
            obj.push(marker | len as u8);
        } else {
            obj.push(marker | 0x0F);
            Self::encode_int(obj, len as i64); // length follows as an int object inline
        }
    }

    fn encode_string(obj: &mut Vec<u8>, s: &str) {
        // ASCII string (0x5x). AirPlay SETUP keys/values are all ASCII.
        Self::encode_marker_len(obj, 0x50, s.len());
        obj.extend_from_slice(s.as_bytes());
    }

    fn encode_int(obj: &mut Vec<u8>, value: i64) {
        // Smallest power-of-two width that holds the value; negatives use
        // 8 bytes (two's complement), exactly like the C++ branches.
        if (0..=0xFF).contains(&value) {
            obj.push(0x10);
            obj.push(value as u8);
        } else if (0..=0xFFFF).contains(&value) {
            obj.push(0x11);
            obj.extend_from_slice(&(value as u16).to_be_bytes());
        } else if (0..=0xFFFF_FFFF).contains(&value) {
            obj.push(0x12);
            obj.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            obj.push(0x13);
            obj.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// Encode a value tree as a `bplist00` document (C++ `bplist::encode`).
pub fn encode(root: &Value) -> Bytes {
    let mut enc = Encoder::new();
    enc.add(root); // root is object 0

    let mut out = Bytes::new();
    out.extend_from_slice(b"bplist00");

    // Object table, recording each object's byte offset.
    let mut offsets: Vec<u64> = Vec::with_capacity(enc.objects.len());
    for o in &enc.objects {
        offsets.push(out.len() as u64);
        out.extend_from_slice(o);
    }

    // Offset table (4-byte offsets, generous for our small payloads).
    let offset_table_start = out.len() as u64;
    for off in &offsets {
        out.extend_from_slice(&(*off as u32).to_be_bytes());
    }

    // Trailer: 6 unused bytes, offsetIntSize, objectRefSize, numObjects(8),
    // topObject(8), offsetTableOffset(8).
    let mut trailer = [0u8; 32];
    trailer[6] = 4; // offset size
    trailer[7] = 4; // object ref size (matches append_ref)
    trailer[8..16].copy_from_slice(&(enc.objects.len() as u64).to_be_bytes());
    trailer[16..24].copy_from_slice(&0u64.to_be_bytes()); // top object index
    trailer[24..32].copy_from_slice(&offset_table_start.to_be_bytes());
    out.extend_from_slice(&trailer);
    out
}

// ── decoder ───────────────────────────────────────────────────────────

struct Decoder<'a> {
    d: &'a [u8],
    offset_size: u8,
    ref_size: u8,
    num_objects: u64,
    offset_table_start: u64,
    offsets: Vec<u64>,
    ok: bool,
}

/// Big-endian read of `n` bytes at `at`, wrapping on overflow exactly like
/// the C++ (crafted size fields only need in-bounds reads, not sane
/// values). Sets `ok = false` on an out-of-bounds read.
fn read_be(d: &[u8], at: u64, n: usize, ok: &mut bool) -> u64 {
    let mut v = 0u64;
    for i in 0..n {
        let Some(&b) = d.get((at as usize).wrapping_add(i)) else {
            *ok = false;
            return 0;
        };
        v = v.wrapping_shl(8) | u64::from(b);
    }
    v
}

/// Count is the low nibble of the marker, or an inline int object when
/// the nibble is 0x0F (exactly the C++ `readCount`).
fn read_count(dec: &mut Decoder, pos: &mut u64, lo: usize) -> u64 {
    if lo != 0x0F {
        return lo as u64;
    }
    if *pos >= dec.d.len() as u64 {
        dec.ok = false;
        return 0;
    }
    let im = dec.d[*pos as usize];
    *pos += 1;
    let n = 1usize << (im & 0x0F);
    let c = read_be(dec.d, *pos, n, &mut dec.ok);
    *pos += n as u64;
    c
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Decoder {
            d: data,
            offset_size: 0,
            ref_size: 0,
            num_objects: 0,
            offset_table_start: 0,
            offsets: Vec::new(),
            ok: true,
        }
    }

    fn parse_trailer(&mut self) -> bool {
        if self.d.len() < 8 + 32 {
            return false;
        }
        if &self.d[..8] != b"bplist00" {
            return false;
        }
        let tr = self.d.len() as u64 - 32;
        self.offset_size = self.d[tr as usize + 6];
        self.ref_size = self.d[tr as usize + 7];
        self.num_objects = read_be(self.d, tr + 8, 8, &mut self.ok);
        self.offset_table_start = read_be(self.d, tr + 24, 8, &mut self.ok);
        if !self.ok {
            return false;
        }
        // Validate the size fields ∈ {1,2,4,8} and bound numObjects against
        // the file (each object needs ≥ 1 byte) BEFORE any multiply, so a
        // crafted huge numObjects can't wrap the bounds check.
        let valid_size = |s: u8| matches!(s, 1 | 2 | 4 | 8);
        if !valid_size(self.offset_size) || !valid_size(self.ref_size) {
            return false;
        }
        if self.offset_table_start > self.d.len() as u64 {
            return false;
        }
        if self.num_objects > self.d.len() as u64 {
            return false;
        }
        if self.num_objects
            > (self.d.len() as u64 - self.offset_table_start) / self.offset_size as u64
        {
            return false;
        }
        self.offsets.reserve(self.num_objects as usize);
        for i in 0..self.num_objects {
            let at = self.offset_table_start + i * self.offset_size as u64;
            self.offsets
                .push(read_be(self.d, at, self.offset_size as usize, &mut self.ok));
        }
        self.ok
    }

    /// Decode the object at table index `ref`. Bounded recursion via depth.
    fn object(&mut self, r: u64, depth: usize) -> Option<Value> {
        if depth > 32 || r >= self.num_objects {
            return None;
        }
        let mut pos = self.offsets[r as usize];
        if pos >= self.d.len() as u64 {
            return None;
        }
        let marker = self.d[pos as usize];
        pos += 1;
        let hi = marker & 0xF0;
        let lo = (marker & 0x0F) as usize;

        match hi {
            0x00 => {
                // bool / null / fill: only 0x09 is true; everything else in
                // this nibble range decodes as false (C++ parity).
                Some(Value::Bool(marker == 0x09))
            }
            0x10 => {
                // int: n bytes big-endian, cast to i64 with the same
                // wraparound semantics as the C++ (only the low 8 bytes are
                // significant for n > 8).
                let n = 1usize << lo;
                let v = read_be(self.d, pos, n, &mut self.ok) as i64;
                Some(Value::Int(v))
            }
            0x20 => {
                // real: 4- or 8-byte IEEE; any other width decodes as 0.0.
                let n = 1usize << lo;
                let bits = read_be(self.d, pos, n, &mut self.ok);
                let r = match n {
                    8 => f64::from_bits(bits),
                    4 => f64::from(f32::from_bits(bits as u32)),
                    _ => 0.0,
                };
                Some(Value::Real(r))
            }
            0x40 => {
                // data
                let cnt = read_count(self, &mut pos, lo);
                // Bound cnt FIRST: pos+cnt must not wrap for a crafted
                // near-2^64 count (the array/dict cases are already guarded
                // via cnt > numObjects).
                if cnt
                    .checked_add(pos)
                    .is_none_or(|end| end > self.d.len() as u64 || cnt > self.d.len() as u64)
                {
                    return None;
                }
                let start = pos as usize;
                Some(Value::Data(self.d[start..start + cnt as usize].to_vec()))
            }
            0x50 => {
                // ASCII string
                let cnt = read_count(self, &mut pos, lo);
                if cnt
                    .checked_add(pos)
                    .is_none_or(|end| end > self.d.len() as u64 || cnt > self.d.len() as u64)
                {
                    return None;
                }
                let start = pos as usize;
                let raw = &self.d[start..start + cnt as usize];
                // C++ stores raw bytes in std::string; lossy is the safe
                // equivalent (only differs on invalid UTF-8, which AirPlay
                // never sends).
                Some(Value::Str(String::from_utf8_lossy(raw).into_owned()))
            }
            0x60 => {
                // UTF-16 string: keep the low byte of each BE unit (the
                // ASCII subset), matching the C++ helper.
                let cnt = read_count(self, &mut pos, lo);
                if cnt > self.d.len() as u64 {
                    return None; // DoS-bound, matches the C++.
                }
                let mut s = String::new();
                for i in 0..cnt {
                    let at = pos + i * 2;
                    let Some(&b) = self.d.get(at as usize + 1) else {
                        break;
                    };
                    s.push(b as char);
                }
                Some(Value::Str(s))
            }
            0xA0 => {
                // array
                let cnt = read_count(self, &mut pos, lo);
                let table_end = pos.checked_add(cnt.saturating_mul(self.ref_size as u64));
                // An array can't reference more objects than exist, and its
                // ref table must fit (bounds a crafted huge cnt).
                if !self.ok
                    || cnt > self.num_objects
                    || table_end.is_none_or(|end| end > self.d.len() as u64)
                {
                    return None;
                }
                let mut arr = Vec::with_capacity(cnt as usize);
                for i in 0..cnt {
                    let r = read_be(
                        self.d,
                        pos + i * self.ref_size as u64,
                        self.ref_size as usize,
                        &mut self.ok,
                    );
                    arr.push(self.object(r, depth + 1)?);
                }
                Some(Value::Arr(arr))
            }
            0xD0 => {
                // dict
                let cnt = read_count(self, &mut pos, lo);
                let table_end = pos.checked_add(cnt.saturating_mul(2 * self.ref_size as u64));
                if !self.ok
                    || cnt > self.num_objects
                    || table_end.is_none_or(|end| end > self.d.len() as u64)
                {
                    return None;
                }
                let mut dd = Vec::with_capacity(cnt as usize);
                for i in 0..cnt {
                    let kr = read_be(
                        self.d,
                        pos + i * self.ref_size as u64,
                        self.ref_size as usize,
                        &mut self.ok,
                    );
                    let vr = read_be(
                        self.d,
                        pos + (cnt + i) * self.ref_size as u64,
                        self.ref_size as usize,
                        &mut self.ok,
                    );
                    let k = self.object(kr, depth + 1)?;
                    let val = self.object(vr, depth + 1)?;
                    let key = match &k {
                        Value::Str(s) => s.clone(),
                        _ => String::new(), // C++ asStr() default
                    };
                    dd.push((key, val));
                }
                Some(Value::Dict(dd))
            }
            _ => None,
        }
    }
}

/// Decode a `bplist00` document; `None` on anything malformed (C++
/// `bplist::decode`).
pub fn decode(data: &[u8]) -> Option<Value> {
    let mut dec = Decoder::new(data);
    if !dec.parse_trailer() {
        return None;
    }
    dec.object(0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_decode_roundtrip(v: &Value) {
        let bytes = encode(v);
        let decoded = decode(&bytes).expect("round-trip decodes");
        assert_eq!(&decoded, v);
    }

    #[test]
    fn scalars_roundtrip() {
        enc_decode_roundtrip(&Value::Bool(true));
        enc_decode_roundtrip(&Value::Bool(false));
        for i in [
            0i64,
            1,
            127,
            128,
            255,
            256,
            65535,
            65536,
            1 << 32,
            i64::MAX,
            -1,
            -129,
        ] {
            enc_decode_roundtrip(&Value::Int(i));
        }
        for r in [0.0f64, 1.5, -3.25, f64::MAX, f64::MIN_POSITIVE] {
            enc_decode_roundtrip(&Value::Real(r));
        }
        enc_decode_roundtrip(&Value::Str("pair-setup".into()));
        enc_decode_roundtrip(&Value::Str("".into()));
        enc_decode_roundtrip(&Value::Data(vec![0, 1, 2, 255]));
        enc_decode_roundtrip(&Value::Data(vec![]));
    }

    #[test]
    fn nested_container_roundtrip() {
        // The SETUP request shape: an array of dicts with mixed values
        // inside a top dict.
        let v = Value::Dict(vec![
            ("txTxtv".to_string(), Value::Int(1)),
            ("pw".to_string(), Value::Bool(true)),
            ("vv".to_string(), Value::Int(2)),
            (
                "vs".to_string(),
                Value::Arr(vec![
                    Value::Dict(vec![
                        ("cn".to_string(), Value::Int(0)),
                        ("sc".to_string(), Value::Int(1)),
                        ("sv".to_string(), Value::Str("130.14".into())),
                    ]),
                    Value::Dict(vec![
                        ("cn".to_string(), Value::Int(2)),
                        ("sc".to_string(), Value::Int(3)),
                        ("sv".to_string(), Value::Str("8".into())),
                    ]),
                ]),
            ),
            ("ft".to_string(), Value::Str("0x4F,0x0B".into())),
            ("et".to_string(), Value::Data(vec![0x00, 0x05, 0x06])),
            ("sf".to_string(), Value::Bool(false)),
            (
                "ek".to_string(),
                Value::Dict(vec![
                    ("ty".to_string(), Value::Int(64)),
                    ("k".to_string(), Value::Data(vec![7; 16])),
                ]),
            ),
        ]);
        enc_decode_roundtrip(&v);
    }

    #[test]
    fn find_and_as_helpers() {
        let v = Value::Dict(vec![
            ("status".to_string(), Value::Int(200)),
            ("name".to_string(), Value::Str("kitchen".into())),
        ]);
        assert_eq!(v.find("status").map(|x| x.as_int(-1)), Some(200));
        assert_eq!(v.find("name").map(|x| x.as_str("")), Some("kitchen"));
        assert_eq!(v.find("missing"), None);
        // Wrong-type lookups fall back to defaults.
        assert_eq!(v.find("name").map(|x| x.as_int(-1)), Some(-1));
        assert_eq!(v.find("status").map(|x| x.as_str("")), Some(""));
        // find on a non-dict.
        assert_eq!(Value::Int(1).find("status"), None);
    }

    #[test]
    fn trailer_layout_is_exact() {
        let v = Value::Dict(vec![("a".to_string(), Value::Int(1))]);
        let b = encode(&v);
        assert_eq!(&b[..8], b"bplist00");
        // Trailer: offsetIntSize=4, objectRefSize=4, numObjects=3
        // (dict, key str, int), topObject=0, offsetTableOffset.
        let tr = b.len() - 32;
        assert_eq!(b[tr + 6], 4);
        assert_eq!(b[tr + 7], 4);
        let n = u64::from_be_bytes(b[tr + 8..tr + 16].try_into().unwrap());
        assert_eq!(n, 3);
        let ot = u64::from_be_bytes(b[tr + 24..tr + 32].try_into().unwrap());
        assert_eq!(ot as usize, tr - 3 * 4);
    }

    #[test]
    fn rejects_garbage_and_crafted_trailers() {
        assert!(decode(b"").is_none());
        assert!(decode(b"bplist").is_none());
        assert!(decode(b"xplist00").is_none());
        // Valid header + junk trailer.
        let mut d = b"bplist00".to_vec();
        d.extend_from_slice(&[0u8; 32]);
        assert!(decode(&d).is_none());
        // Bounds: numObjects bigger than the file.
        let mut d = b"bplist00".to_vec();
        d.extend_from_slice(&[0u8; 32]);
        d[8 + 8..8 + 16].copy_from_slice(&100u64.to_be_bytes()); // numObjects=100
        assert!(decode(&d).is_none());
        // Invalid offset/ref sizes.
        let mut d = b"bplist00".to_vec();
        d.extend_from_slice(&[0u8; 32]);
        d[8 + 6] = 3; // offsetIntSize=3 not in {1,2,4,8}
        assert!(decode(&d).is_none());
        // numObjects zero: allowed (empty object table) but object(0) None.
        let mut d = b"bplist00".to_vec();
        d.extend_from_slice(&[0u8; 32]);
        d[8 + 8..8 + 16].copy_from_slice(&0u64.to_be_bytes());
        assert!(decode(&d).is_none());
    }

    #[test]
    fn rejects_wrapped_lengths() {
        // A data object whose count is huge (near 2^64) must be rejected,
        // not wrap pos+cnt into an OOB slice. Build a 0x4F marker (data
        // with inline int count) whose inline int is 2^64-1.
        let mut d = b"bplist00".to_vec();
        d.push(0x4F);
        d.push(0x13); // inline int, 8 bytes
        d.extend_from_slice(&u64::MAX.to_be_bytes()); // count = 2^64-1
        let offset_start = d.len() as u64; // offset table begins after the object
        d.push(8); // offset table: object 0 starts at offset 8
        let mut trailer = [0u8; 32];
        trailer[6] = 1;
        trailer[7] = 4;
        trailer[8..16].copy_from_slice(&1u64.to_be_bytes());
        trailer[24..32].copy_from_slice(&offset_start.to_be_bytes());
        d.extend_from_slice(&trailer);
        assert!(decode(&d).is_none());
    }

    #[test]
    fn utf16_low_bytes_only() {
        // 0x60 string "Hi" as UTF-16BE -> "Hi" (low bytes kept).
        let mut d = b"bplist00".to_vec();
        d.push(0x62); // UTF-16, count 2
        d.extend_from_slice(&[0x00, b'H', 0x00, b'i']);
        let offset_start = d.len() as u64; // offset table begins after the object
        d.push(8); // offset table entry: object 0 starts at offset 8
        let mut trailer = [0u8; 32];
        trailer[6] = 1;
        trailer[7] = 4;
        trailer[8..16].copy_from_slice(&1u64.to_be_bytes());
        trailer[24..32].copy_from_slice(&offset_start.to_be_bytes());
        d.extend_from_slice(&trailer);
        assert_eq!(decode(&d), Some(Value::Str("Hi".into())));
    }

    #[test]
    fn depth_bomb_limited() {
        // A deeply nested array (depth > 32) decodes to None instead of
        // recursing forever.
        let mut v = Value::Bool(true);
        for _ in 0..40 {
            v = Value::Arr(vec![v]);
        }
        let b = encode(&v);
        // The encoder is fine with it; the decoder's depth bound kicks in.
        assert!(decode(&b).is_none());
    }
}
