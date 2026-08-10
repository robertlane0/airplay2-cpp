// SPDX-License-Identifier: Apache-2.0
//! SRP-6a, 3072-bit, SHA-512 — client side (HAP pair-setup).
//!
//! Port of the `SrpClient` class in
//! [`src/airplay_crypto.cpp`](../../src/airplay_crypto.cpp). HomeKit uses
//! RFC 5054 group 3072 (g = 5) with SHA-512; the username is always
//! `Pair-Setup`, the password is the PIN. The padding conventions (k and u
//! hashed over N-length zero-padded big-endian operands; salt/N/g and
//! A/B/S hashed at natural length) match pyatv's `hap_srp` and pair_ap's
//! `H_nn_pad`.

use crate::{Bytes, CryptoError, random_bytes, sha512};
use num_bigint::BigUint;
use num_traits::Zero;

/// RFC 5054 group 3072, g = 5 (big-endian hex, as in the C++).
const SRP_N_3072_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183\
995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A\
85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7A\
BF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D\
87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E20\
8E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

const SRP_N_BYTES: usize = 384;

/// The SRP username, always `Pair-Setup` for HAP.
pub const SRP_USERNAME: &str = "Pair-Setup";

/// Fixed "3939" PIN for transient HomePod pairing (Apple TV uses an
/// on-screen 4-digit code instead).
pub const TRANSIENT_PIN: &str = "3939";

fn n_modulus() -> BigUint {
    BigUint::parse_bytes(SRP_N_3072_HEX.as_bytes(), 16).expect("static SRP modulus parses")
}

/// Big-endian bytes with no leading zeros; a zero value is one zero byte
/// (mbedtls `mpi_write_binary` parity: `mpi_size(0) == 0` but a 1-byte
/// buffer is still written).
fn mpi_bytes(v: &BigUint) -> Vec<u8> {
    let b = v.to_bytes_be();
    if b.is_empty() { vec![0] } else { b }
}

/// Big-endian bytes zero-extended to exactly `len` bytes on the left
/// (mbedtls `mpi_write_binary` with a fixed-length buffer).
fn mpi_bytes_padded(v: &BigUint, len: usize) -> Vec<u8> {
    let mut b = v.to_bytes_be();
    if b.len() > len {
        // Values are all < N (384 bytes) in practice; anything larger is a
        // programming error, not a wire case.
        panic!("SRP operand exceeds its {len}-byte pad length");
    }
    let mut out = vec![0u8; len - b.len()];
    out.append(&mut b);
    out
}

/// SHA-512 over two N-byte-padded big-integers (HAP k and u). Mirrors
/// pair_ap `H_nn_pad`: both operands zero-extended to 384 bytes.
fn hash_two_padded(a: &BigUint, b: &BigUint) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 * SRP_N_BYTES);
    buf.extend_from_slice(&mpi_bytes_padded(a, SRP_N_BYTES));
    buf.extend_from_slice(&mpi_bytes_padded(b, SRP_N_BYTES));
    sha512(&buf)
}

/// SRP-6a 3072/SHA-512 client for HAP pair-setup (C++ `SrpClient`).
#[derive(Default)]
pub struct SrpClient {
    n: BigUint,
    g: BigUint,
    a: BigUint,
    a_pub: BigUint,
    b_pub: BigUint,
    k: BigUint,
    u: BigUint,
    x: BigUint,
    s: BigUint,
    salt: Vec<u8>,
    k_session: Vec<u8>,
    m1: Vec<u8>,
    password: String,
    processed: bool,
}

impl SrpClient {
    /// New client with RFC 5054 group 3072, g = 5.
    pub fn new() -> Self {
        SrpClient {
            n: n_modulus(),
            g: BigUint::from(5u32),
            ..Default::default()
        }
    }

    /// Choose the password (PIN). Generates the ephemeral secret `a` and
    /// public `A = g^a mod N`. C++ `start` (which could throw).
    pub fn start(&mut self, password: &str) -> Result<(), CryptoError> {
        self.password = password.to_owned();
        // Ephemeral secret a (256 bits, like pair_ap's bnum_random(a, 256)).
        let a_bytes = random_bytes(32)?;
        self.a = BigUint::from_bytes_be(&a_bytes);
        self.a_pub = self.g.modpow(&self.a, &self.n);
        Ok(())
    }

    /// Public client value A (big-endian, natural length — the wire form
    /// HAP TLV8 PublicKey carries). C++ `publicA`.
    pub fn public_a(&self) -> Bytes {
        mpi_bytes(&self.a_pub)
    }

    /// Process the server's salt + public B. Computes the shared session
    /// key K = SHA-512(S) and the client proof M1. Returns `false` if
    /// B ≡ 0 (mod N) — a malicious/garbled server value. C++ `process`.
    pub fn process(&mut self, salt: &[u8], server_b: &[u8]) -> bool {
        self.salt = salt.to_vec();
        self.b_pub = BigUint::from_bytes_be(server_b);

        // Reject B ≡ 0 (mod N) (RFC 5054 safety check).
        if (&self.b_pub % &self.n).is_zero() {
            return false;
        }

        // k = H(N | g), u = H(A | B) — both operands N-padded.
        self.k = BigUint::from_bytes_be(&hash_two_padded(&self.n, &self.g));
        self.u = BigUint::from_bytes_be(&hash_two_padded(&self.a_pub, &self.b_pub));

        // x = H(salt | H("Pair-Setup:" + password)).
        let inner = format!("{SRP_USERNAME}:{}", self.password);
        let inner_hash = sha512(inner.as_bytes());
        let mut salt_and_hash = self.salt.clone();
        salt_and_hash.extend_from_slice(&inner_hash);
        self.x = BigUint::from_bytes_be(&sha512(&salt_and_hash));

        // S = (B - k * g^x) ^ (a + u * x) mod N. Negative intermediates are
        // kept positive mod N, exactly like the C++ `mod_mpi` calls.
        let gx = self.g.modpow(&self.x, &self.n);
        let kgx = (&self.k * &gx) % &self.n;
        let base = if self.b_pub >= kgx {
            &self.b_pub - &kgx
        } else {
            &self.n + &self.b_pub - &kgx
        };
        let ux = &self.u * &self.x;
        let exp = &self.a + ux;
        self.s = base.modpow(&exp, &self.n);

        // K = SHA-512(S) at natural byte length.
        self.k_session = sha512(&mpi_bytes(&self.s));

        // M1 = H( H(N) XOR H(g) | H(I) | salt | A | B | K ).
        let h_n = sha512(&mpi_bytes(&self.n));
        let h_g = sha512(&mpi_bytes(&self.g));
        let h_xor: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(x, y)| x ^ y).collect();
        let h_i = sha512(SRP_USERNAME.as_bytes());
        let mut m1_in = Vec::new();
        m1_in.extend_from_slice(&h_xor);
        m1_in.extend_from_slice(&h_i);
        m1_in.extend_from_slice(&self.salt);
        m1_in.extend_from_slice(&mpi_bytes(&self.a_pub));
        m1_in.extend_from_slice(&mpi_bytes(&self.b_pub));
        m1_in.extend_from_slice(&self.k_session);
        self.m1 = sha512(&m1_in);

        self.processed = true;
        true
    }

    /// Client proof M1 (64 bytes). C++ `proofM1`.
    pub fn proof_m1(&self) -> Bytes {
        self.m1.clone()
    }

    /// Shared session key K (64 bytes, the HKDF ikm). C++ `sessionKey`.
    pub fn session_key(&self) -> Bytes {
        self.k_session.clone()
    }

    /// Verify the server's proof M2 = H(A | M1 | K), constant-time.
    /// C++ `verifyServerProof`.
    pub fn verify_server_proof(&self, server_m2: &[u8]) -> bool {
        if !self.processed {
            return false;
        }
        let mut in_buf = Vec::new();
        in_buf.extend_from_slice(&mpi_bytes(&self.a_pub));
        in_buf.extend_from_slice(&self.m1);
        in_buf.extend_from_slice(&self.k_session);
        let m2 = sha512(&in_buf);
        if m2.len() != server_m2.len() {
            return false;
        }
        // Constant-time compare (a proof compared against a network value).
        let diff = m2
            .iter()
            .zip(server_m2.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic checks with fixed inputs: k/u/x conventions must run
    /// without error and produce the fixed-size outputs. (The `a` ephemeral
    /// is random, so no byte-for-byte vector is asserted here.)
    #[test]
    fn deterministic_flow_with_fixed_inputs() {
        let salt = vec![0xABu8; 16];
        let server_b = vec![0xCDu8; 64];
        let mut client = SrpClient::new();
        assert!(client.process(&salt, &server_b));
        assert_eq!(client.proof_m1().len(), 64);
        assert_eq!(client.session_key().len(), 64);
    }

    #[test]
    fn rejects_zero_b() {
        let mut client = SrpClient::new();
        assert!(!client.process(b"salt", &[0u8]));
        // verifyServerProof on an unprocessed client -> false.
        assert!(!client.verify_server_proof(&[0u8; 64]));
    }

    /// Full client/server consistency: a mock server using the same SRP
    /// conventions verifies M1 and produces an M2 the client accepts, and
    /// both sides agree on the session key.
    #[test]
    fn client_and_mock_server_agree() {
        let mut client = SrpClient::new();
        client.start("1234").unwrap();
        let a = client.public_a();

        // Mock server (same conventions as the repo's fake devices):
        // b random-ish, v = g^x, B = (k*v + g^b) mod N, u, S, K, M1-check,
        // M2. x is derived exactly like the client's.
        let b = BigUint::from_bytes_be(&[0x5Au8; 32]);
        // x = H(salt || H("Pair-Setup:" + password)), exactly as the client.
        let x = {
            let inner = sha512(b"Pair-Setup:1234");
            let mut salt_and_hash = b"mock-salt".to_vec();
            salt_and_hash.extend_from_slice(&inner);
            BigUint::from_bytes_be(&sha512(&salt_and_hash))
        };
        let v = BigUint::from(5u32).modpow(&x, &n_modulus());
        let k = BigUint::from_bytes_be(&hash_two_padded(&n_modulus(), &BigUint::from(5u32)));
        let gb = BigUint::from(5u32).modpow(&b, &n_modulus());
        let b_pub = (k * &v + gb) % &n_modulus();
        let u = BigUint::from_bytes_be(&hash_two_padded(&BigUint::from_bytes_be(&a), &b_pub));
        // SRP-6a server secret: S = (A * v^u)^b mod N, identical to the
        // client's (g^b)^(a + u*x).
        let s_server =
            (&BigUint::from_bytes_be(&a) * v.modpow(&u, &n_modulus())).modpow(&b, &n_modulus());
        let k_server = sha512(&mpi_bytes(&s_server));
        let salt = b"mock-salt";

        let ok = client.process(salt, &mpi_bytes(&b_pub));
        assert!(ok);

        // Server verifies M1 = H(H(N)^H(g) | H(I) | salt | A | B | K).
        let h_n = sha512(&mpi_bytes(&n_modulus()));
        let h_g = sha512(&mpi_bytes(&BigUint::from(5u32)));
        let h_xor: Vec<u8> = h_n.iter().zip(h_g.iter()).map(|(x, y)| x ^ y).collect();
        let mut m1_in = Vec::new();
        m1_in.extend_from_slice(&h_xor);
        m1_in.extend_from_slice(&sha512(SRP_USERNAME.as_bytes()));
        m1_in.extend_from_slice(salt);
        m1_in.extend_from_slice(&a);
        m1_in.extend_from_slice(&mpi_bytes(&b_pub));
        m1_in.extend_from_slice(&k_server);
        assert_eq!(client.proof_m1(), sha512(&m1_in));

        // Client verifies M2 = H(A | M1 | K).
        assert_eq!(client.session_key(), k_server);
        let mut m2_in = Vec::new();
        m2_in.extend_from_slice(&a);
        m2_in.extend_from_slice(&client.proof_m1());
        m2_in.extend_from_slice(&k_server);
        let m2 = sha512(&m2_in);
        assert!(client.verify_server_proof(&m2));

        // Tampered M2 is rejected.
        let mut bad = m2.clone();
        bad[0] ^= 1;
        assert!(!client.verify_server_proof(&bad));
    }

    #[test]
    fn public_a_is_384_bits_or_less() {
        let mut client = SrpClient::new();
        client.start("3939").unwrap();
        let a = client.public_a();
        assert!(!a.is_empty());
        assert!(a.len() <= 384);
        // The wire form carries no leading zero bytes.
        assert_ne!(a[0], 0);
    }
}
