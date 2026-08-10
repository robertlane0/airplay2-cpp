// SPDX-License-Identifier: Apache-2.0
//! RFC 1035/6762/6763 packet reading, as in `MdnsBrowser::handlePacket_`
//! (`src/mdns_browser.cpp`). Every byte is untrusted LAN input; all reads
//! are bounds-checked and the DNS name decompressor is loop-safe by
//! construction (pointers must point strictly backward, hop cap 128, name
//! cap 1024 bytes — the exact C++ rules).

use std::collections::BTreeMap;

/// DNS record types this browser cares about (RFC 1035 §3.2.2).
pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_PTR: u16 = 12;
pub(crate) const TYPE_TXT: u16 = 16;
pub(crate) const TYPE_SRV: u16 = 33;
/// Internet class (RFC 1035 §3.2.4).
pub(crate) const TYPE_IN: u16 = 1;

/// `readName`'s defence-in-depth caps, identical to the C++.
const NAME_MAX_HOPS: u32 = 128;
const NAME_MAX_BYTES: usize = 1024;

/// A bounds-checked reader over one whole DNS message (C++ `DnsReader`).
///
/// Fixed-width fields advance an implicit cursor (`read_u16` etc.); names
/// are read at absolute offsets because compression pointers are relative
/// to the start of the message (RFC 1035 §4.1.4).
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// A reader positioned at an absolute offset, for names embedded in
    /// rdata (PTR/SRV targets).
    pub(crate) fn at(data: &'a [u8], offset: usize) -> Option<Self> {
        (offset <= data.len()).then_some(Reader { data, pos: offset })
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn data(&self) -> &'a [u8] {
        self.data
    }

    pub(crate) fn read_u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.data.len() {
            return None;
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }

    pub(crate) fn read_u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }

    /// Decode a (possibly compressed) domain name starting at the current
    /// position. `pos` advances past exactly what the outer read consumed
    /// (2 bytes if it started with a pointer, the full label sequence
    /// otherwise). `None` on any malformed input, mirroring the C++.
    pub(crate) fn read_name(&mut self) -> Option<String> {
        let mut out = String::new();
        let mut cursor = self.pos;
        let mut jumped = false;
        let mut resume_at = 0usize;
        let mut hops = 0u32;
        loop {
            if cursor >= self.data.len() {
                return None;
            }
            let len = self.data[cursor];
            if len & 0xC0 == 0xC0 {
                // Compression pointer (RFC 1035 §4.1.4).
                if cursor + 1 >= self.data.len() {
                    return None;
                }
                let target = ((len & 0x3F) as usize) << 8 | self.data[cursor + 1] as usize;
                if !jumped {
                    resume_at = cursor + 2;
                    jumped = true;
                }
                if target >= cursor {
                    return None; // must point strictly backward
                }
                hops += 1;
                if hops > NAME_MAX_HOPS {
                    return None;
                }
                cursor = target;
                continue;
            }
            if len & 0xC0 != 0 {
                return None; // reserved 01/10 label-length prefix: malformed
            }
            if len == 0 {
                cursor += 1;
                break; // root label
            }
            if cursor + 1 + len as usize > self.data.len() {
                return None;
            }
            if !out.is_empty() {
                out.push('.');
            }
            let label = &self.data[cursor + 1..cursor + 1 + len as usize];
            out.push_str(&String::from_utf8_lossy(label));
            if out.len() > NAME_MAX_BYTES {
                return None;
            }
            cursor += 1 + len as usize;
        }
        self.pos = if jumped { resume_at } else { cursor };
        Some(out)
    }
}

/// A record's decoded fixed header. The rdata itself is referenced by
/// offset+length into the message rather than copied (C++ `DnsRecord`).
#[derive(Debug, Clone)]
pub(crate) struct Record {
    pub(crate) name: String,
    pub(crate) rtype: u16,
    /// Class with the mDNS cache-flush bit (top bit) masked off.
    pub(crate) rr_class: u16,
    pub(crate) rdata_offset: usize,
    pub(crate) rdlength: u16,
}

/// Read one RR from the current position (name + fixed header + bounds the
/// rdata window). `None` when the record does not fit the message.
pub(crate) fn read_record(r: &mut Reader<'_>) -> Option<Record> {
    let name = r.read_name()?;
    let rtype = r.read_u16()?;
    let rr_class = r.read_u16()? & 0x7FFF; // mDNS cache-flush bit
    let _ttl = r.read_u32()?; // soft-state TTL; this browser does not track expiry
    let rdlength = r.read_u16()?;
    let rdata_offset = r.pos();
    if r.pos() + rdlength as usize > r.data().len() {
        return None;
    }
    r.pos += rdlength as usize;
    Some(Record {
        name,
        rtype,
        rr_class,
        rdata_offset,
        rdlength,
    })
}

/// Parse a (possibly compressed) name at an absolute offset into the whole
/// message — used for names embedded in rdata (C++ `nameAt`).
pub(crate) fn name_at(data: &[u8], offset: usize) -> Option<String> {
    let mut r = Reader::at(data, offset)?;
    r.read_name()
}

/// TXT rdata: a sequence of length-prefixed strings, each "key=value" or a
/// bare "key" (DNS-SD boolean keys). First occurrence of a key wins, exactly
/// like the C++ `std::map::emplace`. A truncated trailing entry stops the
/// walk without failing the whole record.
pub(crate) fn parse_txt(rdata: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut i = 0usize;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        if i + 1 + len > rdata.len() {
            break;
        }
        let entry = &rdata[i + 1..i + 1 + len];
        match memchr_eq(entry) {
            Some(eq) => {
                out.entry(String::from_utf8_lossy(&entry[..eq]).into_owned())
                    .or_insert_with(|| String::from_utf8_lossy(&entry[eq + 1..]).into_owned());
            }
            None => {
                out.entry(String::from_utf8_lossy(entry).into_owned())
                    .or_insert_with(String::new);
            }
        }
        i += 1 + len;
    }
    out
}

fn memchr_eq(s: &[u8]) -> Option<usize> {
    s.iter().position(|&b| b == b'=')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_name_at(data: &[u8], offset: usize) -> Option<String> {
        let mut r = Reader::at(data, offset)?;
        r.read_name()
    }

    /// Labels + root for a plain name (no compression).
    fn plain(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for label in name.split('.') {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v
    }

    #[test]
    fn reads_plain_and_compressed_names() {
        let mut data = Vec::new();
        data.extend_from_slice(&plain("alice._airplay._tcp.local"));
        let alice = 0usize;
        let ptr_at = data.len();
        data.extend_from_slice(&[0xC0, (alice & 0xFF) as u8]);
        data.extend_from_slice(&plain("bob.local")); // caches other labels? no: root-terminated
        assert_eq!(
            read_name_at(&data, alice),
            Some("alice._airplay._tcp.local".into())
        );
        let mut r = Reader::at(&data, ptr_at).unwrap();
        assert_eq!(r.read_name(), Some("alice._airplay._tcp.local".into()));
        // pos advanced past the 2 pointer bytes only.
        assert_eq!(r.pos(), ptr_at + 2);
    }

    #[test]
    fn pointer_chain_follows_and_caps_at_128_hops() {
        // "x" root at bytes 0..3 (len byte at 0, 'x' at 1, root at 2).
        // Pointers P_0..P_{N-1} at offsets 3,5,7,...; P_0 targets the label
        // at offset 0 and P_k targets P_{k-1}, all strictly backward.
        fn chain(n: usize) -> Vec<u8> {
            let mut data = vec![1, b'x', 0];
            for k in 0..n {
                let target = if k == 0 { 0 } else { 3 + 2 * (k - 1) };
                data.push(0xC0 | ((target >> 8) as u8 & 0x3F));
                data.push((target & 0xFF) as u8);
            }
            data
        }
        // 129 pointers -> 129 hops > 128 -> rejected.
        let data = chain(129);
        assert_eq!(
            read_name_at(&data, data.len() - 2),
            None,
            "129 hops rejected"
        );
        // 128 pointers -> 128 hops, then the label: allowed.
        let ok = chain(128);
        assert_eq!(read_name_at(&ok, ok.len() - 2), Some("x".into()));
    }

    #[test]
    fn forward_pointers_are_rejected() {
        // Pointer at offset 1 targeting offset 3 (>= cursor 1).
        let data = [0xC0, 0x03, 1, b'x', 0];
        assert_eq!(read_name_at(&data, 1), None);
        // Self-pointer at offset 1 -> target 1.
        let data = [0xC0, 0x01, 0];
        assert_eq!(read_name_at(&data, 1), None);
    }

    #[test]
    fn reserved_label_prefixes_are_malformed() {
        for prefix in [0x40u8, 0x80u8] {
            let data = [prefix, b'x', 0];
            assert_eq!(
                read_name_at(&data, 0),
                None,
                "prefix {prefix:#04x} rejected"
            );
        }
    }

    #[test]
    fn names_that_run_off_the_message_are_rejected() {
        // Label claims 5 bytes, only 2 follow.
        assert_eq!(read_name_at(&[3, b'a', b'b'], 0), None);
        // Truncated pointer (only one byte of it present).
        assert_eq!(read_name_at(&[0xC0], 0), None);
        // Root-only message.
        assert_eq!(read_name_at(&[0], 0), Some(String::new()));
    }

    #[test]
    fn name_length_cap_is_1024_bytes() {
        // 17 labels x 63 bytes: 1071 chars + 16 dots = 1087 > 1024.
        let mut too_big = Vec::new();
        for _ in 0..17 {
            too_big.push(63);
            too_big.extend(std::iter::repeat_n(b'a', 63));
        }
        too_big.push(0);
        assert_eq!(read_name_at(&too_big, 0), None);

        // 16 labels x 63 bytes: 1008 + 15 dots = 1023 <= 1024, allowed.
        let mut ok = Vec::new();
        for _ in 0..16 {
            ok.push(63);
            ok.extend(std::iter::repeat_n(b'a', 63));
        }
        ok.push(0);
        assert!(read_name_at(&ok, 0).is_some());
    }

    #[test]
    fn read_u16_u32_are_bounds_checked() {
        let mut r = Reader::new(&[0, 1, 2, 3]);
        assert_eq!(r.read_u16(), Some(0x0001));
        // 2 + 4 > 4: rejected; pos stays at 2 (C++ leaves its cursor too).
        assert_eq!(r.read_u32(), None);
        assert_eq!(r.pos(), 2);
        // Two bytes remain, so a follow-up u16 read still succeeds.
        assert_eq!(r.read_u16(), Some(0x0203));
        assert_eq!(r.read_u16(), None);
        assert_eq!(r.pos(), 4);
    }

    #[test]
    fn read_record_requires_full_fixed_header_and_rdata() {
        let mut ok = Vec::new();
        ok.extend_from_slice(&plain("x.local"));
        ok.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 1]);
        let mut r = Reader::new(&ok);
        let rec = read_record(&mut r).unwrap();
        assert_eq!(rec.name, "x.local");
        assert_eq!(rec.rtype, TYPE_A);
        assert_eq!(rec.rr_class, 1);
        assert_eq!(rec.rdlength, 4);
        assert_eq!(rec.rdata_offset, ok.len() - 4);

        // One byte short of the rdata window.
        let mut r = Reader::new(&ok[..ok.len() - 1]);
        assert!(read_record(&mut r).is_none());
        // Truncated header.
        let mut r = Reader::new(&ok[..ok.len() - 10]);
        assert!(read_record(&mut r).is_none());
    }

    #[test]
    fn cache_flush_bit_is_masked_out_of_class() {
        let mut data = Vec::new();
        data.extend_from_slice(&plain("x.local"));
        data.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 1, 0]);
        let mut r = Reader::new(&data);
        assert_eq!(read_record(&mut r).unwrap().rr_class, 1);
    }

    #[test]
    fn parse_txt_basic_forms() {
        let rdata = [3, b'a', b'=', b'1', 2, b's', b'f', 1, b'k'];
        let txt = parse_txt(&rdata);
        assert_eq!(txt.len(), 3);
        assert_eq!(txt.get("a"), Some(&"1".to_string()));
        assert_eq!(txt.get("sf"), Some(&String::new()));
        assert_eq!(txt.get("k"), Some(&String::new()));
    }
}
