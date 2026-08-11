// SPDX-License-Identifier: Apache-2.0
#![deny(unsafe_code)]
//! The crypto + wire-format bytes AirPlay 2 pairing needs.
//!
//! Rust 2024 migration of [`src/airplay_crypto.{h,cpp}`](../../src/airplay_crypto.h).
//! Same scope: SRP-6a 3072/SHA-512 (HAP pair-setup), X25519 + Ed25519
//! (pair-verify), ChaCha20-Poly1305 (encrypted control/event/audio), the
//! HomeKit TLV8 and `bplist00` wire formats, and RFC 2617 digest auth.
//!
//! Behavior contract preserved from the C++:
//!
//! * HAP ChaCha20-Poly1305 uses an 8-byte little-endian counter nonce with
//!   a 4-zero-byte pad in front ([`counter_nonce8`] builds the 8-byte
//!   counter; the pad is added internally).
//! * SRP padding conventions match pyatv's `hap_srp` / `pair_ap`'s
//!   `H_nn_pad`: `k` and `u` hash both operands zero-padded to the full
//!   384-byte N length; `H(N)`, `H(g)`, `salt`, `A`, `B`, `S` are hashed at
//!   natural byte length; username is always `Pair-Setup`.
//! * X25519 privates are stored clamped (RFC 7748) exactly like the C++
//!   (which clamps the stored copy *and* clamps inside the scalar ladder).
//! * Ed25519 is RFC 8032 deterministic (SHA-512), expected byte-identical
//!   to the vendored orlp implementation.
//! * TLV8 fragments values > 255 bytes into consecutive same-tag chunks on
//!   write and re-joins them on read; insertion order is preserved.
//! * bplist is the minimal Apple `bplist00` subset (dict/array/string/
//!   data/int/bool/real) with the same malformed-input bounds checks.
//! * `digestAuthResponse` produces the exact `Authorization` header value
//!   the C++ does (no field escaping, same quoting).
//!
//! Deliberate, documented differences:
//!
//! * Randomness comes straight from the OS CSPRNG (`getrandom`) instead of
//!   Mbed TLS CTR-DRBG — same-class behavior, nothing on the wire depends
//!   on the exact RNG output.
//! * Fixed-size key types ([`X25519KeyPair`], [`x25519_shared_secret`],
//!   [`ed25519_sign`]...) make the C++ length-error cases unrepresentable;
//!   callers must convert explicitly at the wire boundary.
//! * Functions the C++ made fallible by *throwing* return [`Result`] where
//!   a caller could plausibly recover (RNG failure, bad key length) and
//!   return `Option` where the C++ used an empty/sentinel value
//!   ([`chacha20_poly1305_decrypt`], [`x25519_shared_secret`]).
//!
//! Clean-room provenance is unchanged from the C++ header: the byte
//! sequences (SRP padding, HKDF strings, TLV8 labels, pair-verify layout)
//! were specified from pyatv + pair_ap documentation, not copied code.

// Same public surface as the C++ `airplay_crypto.h`: the tlv, bplist and
// srp namespaces are part of that library API, so these modules are public
// here too (their pair-verify consumers land with the raop-sender slice,
// MIGRATION.md).
pub mod bplist;
pub mod srp;
pub mod tlv;

pub use bplist::Value as BplistValue;
pub use srp::SrpClient;

/// A byte buffer (C++ `std::vector<uint8_t>`).
pub type Bytes = Vec<u8>;

/// Failures a caller may want to handle. The C++ side threw
/// `std::runtime_error` for the same cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The OS CSPRNG failed (C++: CTR-DRBG seed/read failure).
    Rng,
    /// A 32-byte key was required.
    BadKeyLength,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Rng => write!(f, "airplay crypto: OS CSPRNG failure"),
            CryptoError::BadKeyLength => write!(f, "airplay crypto: 32-byte key required"),
        }
    }
}

impl std::error::Error for CryptoError {}

// ── basic hashing / KDF ───────────────────────────────────────────────

/// SHA-512 (64 bytes). C++ `sha512`.
pub fn sha512(data: &[u8]) -> Bytes {
    use sha2::{Digest, Sha512};
    Sha512::digest(data).to_vec()
}

/// HMAC-SHA512 (64 bytes). C++ `hmacSha512`.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Bytes {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 5869 HKDF-SHA512, defaulting to 32-byte keys as HAP always uses.
/// C++ `hkdfSha512` takes `std::string` salt/info (raw bytes); the Rust
/// version takes slices (string literals via `.as_bytes()`).
pub fn hkdf_sha512(salt: &[u8], info: &[u8], ikm: &[u8], length: usize) -> Bytes {
    use hkdf::Hkdf;
    let hk = Hkdf::<sha2::Sha512>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .expect("HKDF expand only fails for absurd lengths");
    okm
}

/// Cryptographically-secure random bytes. C++ `randomBytes` (CTR-DRBG).
pub fn random_bytes(n: usize) -> Result<Bytes, CryptoError> {
    let mut out = vec![0u8; n];
    getrandom::getrandom(&mut out).map_err(|_| CryptoError::Rng)?;
    Ok(out)
}

// ── ChaCha20-Poly1305 AEAD ────────────────────────────────────────────

/// The 8-byte little-endian counter nonce HAP uses for the audio and
/// control channels (the 4-byte zero pad is added internally). Matches
/// `counterNonce8` and pyatv's `hap_encrypted_counter` / `_asn1_counter`.
pub fn counter_nonce8(counter: u64) -> Bytes {
    counter.to_le_bytes().to_vec()
}

/// HAP nonce: 4 zero bytes in front of the 8-byte counter.
fn pad12(nonce8: &[u8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    let take = nonce8.len().min(8);
    n[4..4 + take].copy_from_slice(&nonce8[..take]);
    n
}

/// ChaCha20-Poly1305 encrypt, returning `ciphertext||tag(16)`.
/// C++ `chacha20Poly1305Encrypt`.
pub fn chacha20_poly1305_encrypt(
    key: &[u8],
    nonce8: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Bytes, CryptoError> {
    use chacha20poly1305::KeyInit;
    use chacha20poly1305::aead::Aead;
    if key.len() != 32 {
        return Err(CryptoError::BadKeyLength); // C++ threw for the same case
    }
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
    let nonce = chacha20poly1305::Nonce::from(pad12(nonce8));
    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad,
    };
    let ct = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| CryptoError::Rng)?; // unreachable for valid inputs
    Ok(ct)
}

/// ChaCha20-Poly1305 decrypt of `ciphertextAndTag`; `None` on a bad tag
/// (or invalid key length, exactly like the C++ `std::nullopt` path).
pub fn chacha20_poly1305_decrypt(
    key: &[u8],
    nonce8: &[u8],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Option<Bytes> {
    use chacha20poly1305::KeyInit;
    use chacha20poly1305::aead::Aead;
    if ciphertext_and_tag.len() < 16 || key.len() != 32 {
        return None;
    }
    let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce = chacha20poly1305::Nonce::from(pad12(nonce8));
    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext_and_tag,
        aad,
    };
    cipher.decrypt(&nonce, payload).ok()
}

// ── X25519 ECDH ───────────────────────────────────────────────────────

/// An X25519 key pair, 32 bytes each (C++ `X25519KeyPair`).
pub struct X25519KeyPair {
    /// 32-byte public key.
    pub public: Bytes,
    /// 32-byte private key, stored RFC 7748-clamped (C++ parity).
    pub private: Bytes,
}

/// RFC 7748 clamping, applied to the stored private exactly as the C++
/// does (the scalar ladder clamps internally too; both together are
/// idempotent).
fn clamp_private(priv32: &mut [u8; 32]) {
    priv32[0] &= 248;
    priv32[31] &= 127;
    priv32[31] |= 64;
}

/// Generate an X25519 key pair from OS CSPRNG bytes. C++ `x25519Generate`.
pub fn x25519_generate() -> Result<X25519KeyPair, CryptoError> {
    let mut private: [u8; 32] = random_bytes(32)?.try_into().expect("32 bytes");
    clamp_private(&mut private);
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES).to_vec();
    Ok(X25519KeyPair {
        public,
        private: private.to_vec(),
    })
}

/// X25519 shared secret. `None` for an all-zero result (a low-order peer
/// key; a legitimate receiver never yields one). C++ `x25519SharedSecret`.
pub fn x25519_shared_secret(our_priv32: &[u8; 32], their_pub32: &[u8; 32]) -> Option<Bytes> {
    let out = x25519_dalek::x25519(*our_priv32, *their_pub32);
    if out.iter().all(|b| *b == 0) {
        return None;
    }
    Some(out.to_vec())
}

// ── Ed25519 sign / verify (RFC 8032, deterministic) ───────────────────

/// The public key for a 32-byte long-term seed (`ltsk` -> `ltpk`).
/// C++ `ed25519PublicFromSeed`.
pub fn ed25519_public_from_seed(seed32: &[u8; 32]) -> Bytes {
    let sk = ed25519_dalek::SigningKey::from_bytes(seed32);
    sk.verifying_key().to_bytes().to_vec()
}

/// Sign `msg` with a 32-byte seed. Byte-identical to the vendored orlp
/// implementation (both are RFC 8032 deterministic). C++ `ed25519Sign`.
pub fn ed25519_sign(seed32: &[u8; 32], msg: &[u8]) -> Bytes {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(seed32);
    sk.sign(msg).to_bytes().to_vec()
}

/// Verify a 64-byte signature. Same verification as the C++ (the
/// cofactorless RFC 8032 equation; no strict low-order rejection).
/// C++ `ed25519Verify`.
pub fn ed25519_verify(pub32: &[u8; 32], msg: &[u8], sig64: &[u8; 64]) -> bool {
    use ed25519_dalek::Verifier;
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pub32) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(sig64);
    vk.verify(msg, &sig).is_ok()
}

// ── RFC 2617 MD5 digest auth ──────────────────────────────────────────

fn md5_hex(s: &[u8]) -> String {
    use md5::{Digest, Md5};
    let out = Md5::digest(s);
    let mut r = String::with_capacity(32);
    for b in out {
        r.push_str(&format!("{:02x}", b));
    }
    r
}

/// The `Authorization` header value for RFC 2617 digest auth
/// (pw=true receivers). Exact string layout as the C++ — no escaping of
/// the fields beyond the fixed quotes.
pub fn digest_auth_response(
    method: &str,
    uri: &str,
    username: &str,
    realm: &str,
    password: &str,
    nonce: &str,
) -> String {
    let ha1 = md5_hex(format!("{username}:{realm}:{password}").as_bytes());
    let ha2 = md5_hex(format!("{method}:{uri}").as_bytes());
    let resp = md5_hex(format!("{ha1}:{nonce}:{ha2}").as_bytes());
    format!(
        "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", \
response=\"{resp}\""
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_known_vector() {
        // SHA-512 of the empty string.
        let want: Bytes = hex(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );
        assert_eq!(sha512(b""), want);
    }

    #[test]
    fn hmac_sha512_rfc4231_case2() {
        // RFC 4231 test case 2: key = 0x0b x 20, data = "Hi There".
        let key = [0x0bu8; 20];
        let want: Bytes = hex(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        );
        assert_eq!(hmac_sha512(&key, b"Hi There"), want);
    }

    #[test]
    fn hkdf_sha512_rfc5869_case4() {
        // RFC 5869 Appendix A.4 (SHA-512): IKM = 0x0b x 11, salt =
        // 0x00..0x0c, info = 0xf0..0xf9, L = 42.
        let ikm = [0x0bu8; 11];
        let salt: Vec<u8> = (0..=0x0cu8).collect();
        let info: Vec<u8> = (0xf0..=0xf9u8).collect();
        let okm = hkdf_sha512(&salt, &info, &ikm, 42);
        // Verified independently: Python hkdf and the C++ airplay_crypto
        // both produce 7413e899... for these inputs (the constant in the
        // original test was a bogus 56-byte value).
        let want: Bytes = hex(
            "7413e8997e020610fbf6823f2ce14bff01875db1ca55f68cfcf3954dc8aff\
53559bd5e3028b080f7c068",
        );
        assert_eq!(okm, want);
    }

    #[test]
    fn counter_nonce8_is_little_endian() {
        assert_eq!(counter_nonce8(0), vec![0; 8]);
        assert_eq!(counter_nonce8(1), vec![1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            counter_nonce8(0x0102030405060708),
            vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn chacha_round_trip_and_tamper_rejection() {
        let key = vec![0x42u8; 32];
        let plaintext = b"the quick brown fox";
        let aad = b"rtsp headers";
        let ct = chacha20_poly1305_encrypt(&key, &counter_nonce8(7), plaintext, aad).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 16);
        // Round-trip.
        let pt = chacha20_poly1305_decrypt(&key, &counter_nonce8(7), &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
        // Wrong counter -> auth failure.
        assert!(chacha20_poly1305_decrypt(&key, &counter_nonce8(8), &ct, aad).is_none());
        // Wrong AAD -> auth failure.
        assert!(chacha20_poly1305_decrypt(&key, &counter_nonce8(7), &ct, b"x").is_none());
        // Tampered ciphertext byte -> auth failure.
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(chacha20_poly1305_decrypt(&key, &counter_nonce8(7), &bad, aad).is_none());
        // Too short / bad key -> None (C++ parity).
        assert!(chacha20_poly1305_decrypt(&key, &counter_nonce8(7), &ct[..10], aad).is_none());
        assert!(chacha20_poly1305_decrypt(&[0u8; 16], &counter_nonce8(7), &ct, aad).is_none());
        assert_eq!(
            chacha20_poly1305_encrypt(&[0u8; 16], &counter_nonce8(0), b"x", &[]),
            Err(CryptoError::BadKeyLength)
        );
    }

    #[test]
    fn chacha_zero_length_plaintext() {
        // Empty plaintext -> 16-byte tag only; decrypts back to empty.
        let ct = chacha20_poly1305_encrypt(&[1u8; 32], &counter_nonce8(1), b"", b"").unwrap();
        assert_eq!(ct.len(), 16);
        assert_eq!(
            chacha20_poly1305_decrypt(&[1u8; 32], &counter_nonce8(1), &ct, b""),
            Some(vec![])
        );
    }

    #[test]
    fn x25519_rfc7748_vector_with_clamped_keys() {
        // RFC 7748 section 6.1: Alice and Bob's unclamped private keys and
        // the expected shared secret. Clamping is applied first, exactly as
        // both the C++ (stored copy + ladder) and this crate do.
        let mut alice = hex_arr("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let mut bob = hex_arr("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        clamp_private(&mut alice);
        clamp_private(&mut bob);
        let alice_pub = x25519_dalek::x25519(alice, x25519_dalek::X25519_BASEPOINT_BYTES);
        let bob_pub = x25519_dalek::x25519(bob, x25519_dalek::X25519_BASEPOINT_BYTES);
        assert_eq!(
            alice_pub,
            hex_arr("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob_pub,
            hex_arr("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        assert_eq!(
            x25519_shared_secret(&alice, &bob_pub),
            Some(hex(
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
            ))
        );
        assert_eq!(
            x25519_shared_secret(&bob, &alice_pub),
            Some(hex(
                "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
            ))
        );
    }

    #[test]
    fn x25519_low_order_peer_rejected() {
        // An all-zero public key yields an all-zero shared secret (low-order
        // point) -> None, the same safety check the C++ performs.
        let mut priv32 = [7u8; 32];
        clamp_private(&mut priv32);
        assert!(x25519_shared_secret(&priv32, &[0u8; 32]).is_none());
    }

    #[test]
    fn ed25519_sign_verify_roundtrip_and_det() {
        let seed = hex_arr("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let msg = b"apple pair-verify payload";
        let sig = ed25519_sign(&seed, msg);
        assert_eq!(sig.len(), 64);
        let pubk = ed25519_public_from_seed(&seed);
        assert!(ed25519_verify(
            &pubk.clone().try_into().unwrap(),
            msg,
            &sig.clone().try_into().unwrap()
        ));
        // Wrong message -> false.
        assert!(!ed25519_verify(
            &pubk.try_into().unwrap(),
            b"other",
            &sig.try_into().unwrap()
        ));
    }

    #[test]
    fn ed25519_rfc8032_vector() {
        // RFC 8032 test vector 1: secret key 9d61..., message empty,
        // signature as published. Exercises the exact [u8;64] path.
        let seed = hex_arr("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let want = hex_arr(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert_eq!(ed25519_sign(&seed, b""), want.clone());
        assert!(ed25519_verify(
            &hex_arr("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            b"",
            &want
        ));
    }

    #[test]
    fn digest_auth_layout() {
        let r = digest_auth_response(
            "SETUP",
            "rtsp://1.2.3.4/0",
            "airplay",
            "realm-x",
            "1234",
            "nonce-y",
        );
        assert_eq!(
            r,
            "Digest username=\"airplay\", realm=\"realm-x\", nonce=\"nonce-y\", \
uri=\"rtsp://1.2.3.4/0\", response=\"5724dd00924cfaded5b7f1ba2a5cbb81\""
        );
    }

    #[test]
    fn hkdf_32_byte_default_deterministic() {
        let key = hkdf_sha512(b"Control-Salt", b"Control-Write-Encryption-Key", b"ikm", 32);
        assert_eq!(key.len(), 32);
        let again = hkdf_sha512(b"Control-Salt", b"Control-Write-Encryption-Key", b"ikm", 32);
        assert_eq!(key, again);
    }

    /// Goldens captured from the C++ reference harness
    /// (/tmp/opencode/ref_harness.cpp, git 67b0ce6, 2026-08-10) so that any
    /// divergence between the Rust port and the C++ implementation is
    /// caught byte-for-byte. Vectors chosen for the C++ harness use the
    /// same inputs as the RFC tests above where applicable.
    #[test]
    fn cxx_reference_harness_goldens() {
        let k32 = vec![0x42u8; 32];
        // C++: hmacSha512(k32, "the quick brown fox")
        assert_eq!(
            hmac_sha512(&k32, b"the quick brown fox"),
            hex(
                "cc5ad4a0cdcd8e3ebe2fd58dc981bbaaa79df7212b2f580f77818a1412745248\
cc55c93d4b0f3823cc1d77049c5e217fb0c259efde1c40d1fd681e94ec5bca32"
            )
        );
        // C++: hkdfSha512("Control-Salt", "Control-Write-Encryption-Key", k32, 32)
        assert_eq!(
            hkdf_sha512(b"Control-Salt", b"Control-Write-Encryption-Key", &k32, 32),
            hex("f8ecb70d25a656211a68a7988f2681b819d4e0577ce9963c6639a1bb33184354")
        );
        // C++: chacha20Poly1305Encrypt(k32, counterNonce8(7), pt, aad)
        let ct = chacha20_poly1305_encrypt(
            &k32,
            &counter_nonce8(7),
            b"the quick brown fox",
            b"rtsp headers",
        )
        .unwrap();
        assert_eq!(
            ct,
            hex("7d11d3effe057cab543050d83409c7d9bb152b49e0c1373cf28701b911019ca207898d")
        );
        // C++: ed25519Sign(seed 9d61..., "apple pair-verify payload")
        let seed = hex_arr("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        assert_eq!(
            ed25519_sign(&seed, b"apple pair-verify payload"),
            hex(
                "0d376cadb1eb5b4259f6c3b5858c4a0f1a1c2c61084dd34172f9443e839b857a\
5a44944045ffd2119b15868143ea93e7847404a722320ea8596382db39ad900c"
            )
        );
        // C++: tlv::encode({{0x13,{0x10}}, {0x02,{1,2,3}}})
        assert_eq!(
            tlv::encode(&[(0x13, vec![0x10]), (0x02, vec![1, 2, 3])]),
            hex("1301100203010203")
        );
        // C++: 384-byte value fragmented into 0xff + 0x81 chunks by the encoder.
        let big: Vec<u8> = (0u16..384).map(|i| (i % 251) as u8).collect();
        let enc = tlv::encode(&[(0x03, big.clone())]);
        assert_eq!(enc.len(), 2 + 255 + 2 + 129);
        assert_eq!(
            enc,
            hex(
                "03ff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f\
505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa0001020303810405060708090a0b0c0d0e0f101112\
131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142\
434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172\
737475767778797a7b7c7d7e7f8081828384"
            )
        );
        let decoded = tlv::decode(&enc);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].1, big);
        // C++: tlv::decode of a truncated buffer keeps only intact records.
        assert_eq!(tlv::decode(&enc[..enc.len() - 3]).len(), 1);
        // C++: bplist::encode of {{"key" -> 42}}
        assert_eq!(
            bplist::encode(&BplistValue::Dict(vec![(
                "key".to_string(),
                BplistValue::Int(42)
            )])),
            hex(
                "62706c6973743030d10000000100000002536b6579102a000000080000001100000015\
0000000000000404000000000000000300000000000000000000000000000017"
            )
        );
        // C++: full setup-features dict (layout + offsets table parity).
        assert_eq!(
            bplist::encode(&setup_plist_for_golden()),
            hex(
                "62706c6973743030d8000000010000000300000005000000070000001700000019\
0000001b0000001d00000002000000040000000600000008000000180000001a0000001c0000001e\
567478547874761001527077095276761002527673a20000000900000010d30000000a0000000c\
0000000e0000000b0000000d0000000f52636e10005273631001527376563133302e3134d300000011\
000000130000001500000012000000140000001652636e10025273631003527376513852667459\
307834462c30783042526574430005065273660852656bd20000001f0000002100000020000000\
225274791040516b4f101007070707070707070707070707070707000000080000004900000050\
000000520000005500000056000000590000005b0000005e000000670000008000000083000000\
85000000880000008a0000008d00000094000000ad000000b0000000b2000000b5000000b70000\
00ba000000bc000000bf000000c9000000cc000000d0000000d3000000d4000000d7000000e800\
0000eb000000ed000000ef00000000000004040000000000000023000000000000000000000000\
00000102"
            )
        );
    }

    fn setup_plist_for_golden() -> BplistValue {
        use BplistValue::{Arr, Bool, Data, Dict, Int, Str};
        Dict(vec![
            ("txTxtv".to_string(), Int(1)),
            ("pw".to_string(), Bool(true)),
            ("vv".to_string(), Int(2)),
            (
                "vs".to_string(),
                Arr(vec![
                    Dict(vec![
                        ("cn".to_string(), Int(0)),
                        ("sc".to_string(), Int(1)),
                        ("sv".to_string(), Str("130.14".to_string())),
                    ]),
                    Dict(vec![
                        ("cn".to_string(), Int(2)),
                        ("sc".to_string(), Int(3)),
                        ("sv".to_string(), Str("8".to_string())),
                    ]),
                ]),
            ),
            ("ft".to_string(), Str("0x4F,0x0B".to_string())),
            ("et".to_string(), Data(vec![0x00, 0x05, 0x06])),
            ("sf".to_string(), Bool(false)),
            (
                "ek".to_string(),
                Dict(vec![
                    ("ty".to_string(), Int(64)),
                    ("k".to_string(), Data(vec![7u8; 16])),
                ]),
            ),
        ])
    }

    fn hex(s: &str) -> Bytes {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().expect("hex length matches N")
    }
}
