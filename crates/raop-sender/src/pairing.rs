// SPDX-License-Identifier: Apache-2.0
//! HAP pairing (pair-setup M1..M6 + pair-verify M1..M3) as a pure state
//! container, ported from [`src/raop_sender.cpp`](../../src/raop_sender.cpp)
//! (`sendPairSetupM1_` … `handlePairVerifyM2_`, `RaopAp2State`, and the
//! creds-JSON handling in `beginAuthChain_`).
//!
//! The C++ splits each handshake step between `send*` (build a POST body
//! and fire it) and `handle*` (digest the reply) with the pairing state
//! spread across `RaopSender` fields. Here the state lives in
//! [`PairingSession`] and every step is a pure function of
//! `(&mut PairingSession, reply bytes)` — the transport, the RTSP
//! routing, the stages, and the timers stay in the sender state machine
//! that lands in a later slice.
//!
//! Round-trip tests drive pair-setup M5/M6 and pair-verify end to end
//! against a scripted fake accessory implemented with the same
//! airplay-crypto primitives, so message nonces, HKDF labels and TLV
//! layouts are validated without a device.

use airplay_crypto::{
    self, CryptoError, SrpClient, X25519KeyPair, ed25519_public_from_seed, ed25519_sign,
    ed25519_verify, hkdf_sha512, random_bytes, tlv, x25519_generate, x25519_shared_secret,
};

use crate::util::{
    encode_creds, from_hex_lenient, json_string_value, make_uuid, to_hex, to_upper_str,
};

/// The pairing fast-path selection, mirroring the C++ `authMethod_` split
/// (`HapTransient` vs `HapPin`-style on-screen PIN). Selects the fixed
/// transient PIN, the `Flags=0x10` M1 bit, and the `X-Apple-HKP` value
/// (4 transient / 3 PIN).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PairingMode {
    Transient,
    #[default]
    Pin,
}

/// The one-shot pairing failure categories, mapped from the `fail_`
/// messages of the C++ pairing handlers (the sender machine renders them
/// into its own session-failure text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    /// TLV `Error` tag present; value = first byte (0 when empty).
    AccessoryRejected(u8),
    /// A required TLV field was missing.
    Incomplete,
    /// ChaCha20-Poly1305 tag check failed on pair-setup M6 / pair-verify M2.
    DecryptFailed,
    /// SRP `process` rejected the server salt/B.
    SrpParamsRejected,
    /// X25519 shared-secret derivation failed (low-order or malformed key).
    SharedSecretFailed,
    /// A required key material field was missing/invalid (e.g. no SRP
    /// session yet, no long-term seed).
    MissingKey,
    /// RNG/primitive failure from airplay-crypto.
    Crypto(CryptoError),
}

impl From<CryptoError> for PairingError {
    fn from(e: CryptoError) -> Self {
        PairingError::Crypto(e)
    }
}

/// The accessory identity learned at the end of pair-setup M6, plus the
/// credentials JSON to persist (`onCredentialsObtained` payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessoryIdentity {
    pub accessory_id: Vec<u8>,
    pub accessory_ltpk: Vec<u8>,
    pub creds_json: String,
}

/// Stored long-term credentials parsed from the persisted JSON
/// (`credsJson`); mirrors the four `jsonStringValue` lookups in
/// `beginAuthChain_`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCreds {
    pub ltsk: Vec<u8>,
    pub ltpk: Vec<u8>,
    pub atv_id: Vec<u8>,
    pub client_id: String,
}

/// Parse the persisted creds JSON; `None` when any of the four fields is
/// unreadable or the hex values don't decode (lenient).
pub fn parse_stored_creds(creds_json: &str) -> Option<StoredCreds> {
    let ltsk = json_string_value(creds_json, "ltsk").map(|s| from_hex_lenient(&s))?;
    let ltpk = json_string_value(creds_json, "ltpk").map(|s| from_hex_lenient(&s))?;
    let atv_id = json_string_value(creds_json, "atvId").map(|s| from_hex_lenient(&s))?;
    let client_id = json_string_value(creds_json, "clientId")?;
    Some(StoredCreds {
        ltsk,
        ltpk,
        atv_id,
        client_id,
    })
}

/// The fixed transient pairing PIN.
pub const TRANSIENT_PIN: &str = "3939";

/// What M4 leaves the session to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M4Outcome {
    /// Transient path: keys derived from the SRP shared secret, done.
    TransientKeysDerived,
    /// Normal path: proceed to M5 (long-term key exchange).
    SendM5,
}

/// Pair-setup/verify handshake state (the C++ `RaopAp2State` + the SRP
/// scratch in `RaopSender`).
#[derive(Default)]
pub struct PairingSession {
    pub mode: PairingMode,
    /// SRP client; started at M3 (`ap2_->srp`).
    pub srp: Option<SrpClient>,
    /// Server SALT + B captured at M2 for M3 (`srpSalt_`, `srpServerB_`).
    pub srp_salt: Option<Vec<u8>>,
    pub srp_server_b: Option<Vec<u8>>,
    /// Controller long-term identity (persisted as credentials).
    pub lt_seed: Vec<u8>,
    pub lt_pub: Vec<u8>,
    /// Stable pairing id (uuid string bytes); `make_uuid` at M5 if unset.
    pub pairing_id: Vec<u8>,
    /// Accessory identity learned at M6 / loaded from stored creds.
    pub accessory_id: Vec<u8>,
    pub accessory_ltpk: Vec<u8>,
    /// Pair-verify ephemeral X25519.
    pub verify_keys: Option<X25519KeyPair>,
    /// Shared secret: X25519 ECDH (pair-verify) or SRP K (transient).
    pub shared_secret: Vec<u8>,
    /// Control-channel keys (HKDF over the shared secret).
    pub control_out: Vec<u8>,
    pub control_in: Vec<u8>,
    /// Event-channel keys — reverse connection, so `event_in` decrypts
    /// the receiver's pushes and `event_out` encrypts our 200 OKs.
    pub event_in: Vec<u8>,
    pub event_out: Vec<u8>,
    /// Audio key = first 32 bytes of the shared secret (AP2 stream SETUP).
    pub audio_key: Vec<u8>,
    /// Pair-setup M5 session key, stashed to decrypt M6
    /// (`pairSetupSessionKey_`).
    pub pair_setup_session_key: Vec<u8>,
}

impl PairingSession {
    pub fn new(mode: PairingMode) -> Self {
        Self {
            mode,
            ..Self::default()
        }
    }

    /// The `X-Apple-HKP` header value: 4 transient, 3 PIN.
    pub fn hkp(&self) -> u8 {
        match self.mode {
            PairingMode::Transient => 4,
            PairingMode::Pin => 3,
        }
    }

    /// Apply stored long-term credentials (HapPin reconnect path):
    /// ltsk → seed, atvId/ltpk → accessory identity, clientId → pairing
    /// id. Recomputes `lt_pub` when a full 32-byte seed was loaded —
    /// exactly the field-by-field assignment in `beginAuthChain_`.
    pub fn apply_stored_creds(&mut self, creds: &StoredCreds) {
        if !creds.ltsk.is_empty() {
            self.lt_seed = creds.ltsk.clone();
            if self.lt_seed.len() == 32 {
                self.lt_pub =
                    ed25519_public_from_seed(&self.lt_seed.clone().try_into().expect("32"));
            }
        }
        if !creds.client_id.is_empty() {
            self.pairing_id = creds.client_id.as_bytes().to_vec();
        }
        if !creds.atv_id.is_empty() {
            self.accessory_id = creds.atv_id.clone();
        }
        if !creds.ltpk.is_empty() {
            self.accessory_ltpk = creds.ltpk.clone();
        }
    }

    /// Whether stored creds qualify for a straight pair-verify (the
    /// `sendPairVerifyM1_` condition in `beginAuthChain_`).
    pub fn ready_for_pair_verify(&self) -> bool {
        self.lt_seed.len() == 32 && !self.accessory_ltpk.is_empty()
    }

    /// Load the persisted creds JSON (HapPin reconnect path); returns
    /// whether the session is now ready for a straight pair-verify.
    pub fn try_load_creds(&mut self, creds_json: &str) -> bool {
        if let Some(creds) = parse_stored_creds(creds_json) {
            self.apply_stored_creds(&creds);
        }
        self.ready_for_pair_verify()
    }

    /// The transient pairing's session-UUID/stream-connection helpers
    /// (the `RaopAp2State` ctor): uppercase UUID + decimal u64.
    pub fn generate_session_id_parts() -> Result<(String, String), CryptoError> {
        let uuid = to_upper_str(&make_uuid()?);
        let stream_conn = crate::util::rand_u64()?.to_string();
        Ok((uuid, stream_conn))
    }

    // ── pair-setup M1 ────────────────────────────────────────────────

    /// M1: `{Method:0x00, State:0x01}` (+ `Flags:0x10` when transient).
    pub fn pair_setup_m1(&self) -> Vec<u8> {
        let mut m = vec![(tlv::METHOD, vec![0x00]), (tlv::STATE, vec![0x01])];
        if self.mode == PairingMode::Transient {
            m.push((tlv::FLAGS, vec![0x10])); // kPairingFlag_Transient
        }
        tlv::encode(&m)
    }

    // ── pair-setup M2 handling ───────────────────────────────────────

    /// Handle M2: decode the reply, check the TLV Error tag, capture
    /// SALT + PublicKey (server B). Err on rejection/incompleteness; on
    /// Ok the caller proceeds to M3 (transient: immediately with the
    /// fixed PIN, PIN mode: ask the user).
    pub fn handle_pair_setup_m2(&mut self, body: &[u8]) -> Result<(), PairingError> {
        let m = tlv::decode(body);
        if let Some(err) = tlv::get(&m, tlv::ERROR) {
            return Err(PairingError::AccessoryRejected(
                err.first().copied().unwrap_or(0),
            ));
        }
        let (Some(salt), Some(pub_b)) = (tlv::get(&m, tlv::SALT), tlv::get(&m, tlv::PUBLIC_KEY))
        else {
            return Err(PairingError::Incomplete);
        };
        self.srp_salt = Some(salt.clone());
        self.srp_server_b = Some(pub_b.clone());
        Ok(())
    }

    // ── pair-setup M3 ────────────────────────────────────────────────

    /// M3: SRP step1 (pin) + step2 (salt, B); body =
    /// `{State:0x03, PublicKey: A, Proof: M1}`. Err when the device's
    /// SRP parameters are rejected (`Pairing rejected the device's
    /// parameters`).
    pub fn pair_setup_m3(&mut self, pin: &str) -> Result<Vec<u8>, PairingError> {
        let (Some(salt), Some(server_b)) = (self.srp_salt.clone(), self.srp_server_b.clone())
        else {
            return Err(PairingError::Incomplete);
        };
        let mut srp = SrpClient::new();
        srp.start(pin)?;
        if !srp.process(&salt, &server_b) {
            return Err(PairingError::SrpParamsRejected);
        }
        let m = vec![
            (tlv::STATE, vec![0x03]),
            (tlv::PUBLIC_KEY, srp.public_a()),
            (tlv::PROOF, srp.proof_m1()),
        ];
        self.srp = Some(srp);
        Ok(tlv::encode(&m))
    }

    // ── pair-setup M4 handling ───────────────────────────────────────

    /// Handle M4: verify the server proof (warn-only in C++), then either
    /// derive the transient control keys (shared secret = SRP K, HKDF
    /// `Control-Salt`) or continue to M5. Returns
    /// `(outcome, server_proof_mismatch)`.
    pub fn handle_pair_setup_m4(&mut self, body: &[u8]) -> Result<(M4Outcome, bool), PairingError> {
        let m = tlv::decode(body);
        if let Some(err) = tlv::get(&m, tlv::ERROR) {
            return Err(PairingError::AccessoryRejected(
                err.first().copied().unwrap_or(0),
            ));
        }
        let mut proof_mismatch = false;
        let srp = self.srp.as_ref().ok_or(PairingError::MissingKey)?;
        if let Some(proof) = tlv::get(&m, tlv::PROOF) {
            if !srp.verify_server_proof(proof) {
                proof_mismatch = true; // C++ logs a warning and continues
            }
        }
        if self.mode == PairingMode::Transient {
            self.shared_secret = srp.session_key();
            self.derive_control_keys();
            return Ok((M4Outcome::TransientKeysDerived, proof_mismatch));
        }
        Ok((M4Outcome::SendM5, proof_mismatch))
    }

    // ── pair-setup M5 ────────────────────────────────────────────────

    /// M5: build the controller's signed identity. Generates the
    /// long-term Ed25519 seed + pairing id on first pairing; encrypts
    /// `{Identifier, PublicKey, Signature}` under the Pair-Setup-Encrypt
    /// session key with the string-label nonce `PS-Msg05`. Stashes the
    /// session key for M6, exactly like `sendPairSetupM5_`.
    pub fn pair_setup_m5(&mut self) -> Result<Vec<u8>, PairingError> {
        if self.lt_seed.is_empty() {
            self.lt_seed = random_bytes(32)?;
        }
        self.lt_pub = ed25519_public_from_seed(&self.lt_seed.clone().try_into().expect("32"));
        if self.pairing_id.is_empty() {
            self.pairing_id = make_uuid()?.into_bytes();
        }
        let srp = self.srp.as_ref().ok_or(PairingError::MissingKey)?;
        let k = srp.session_key();
        let session_key = hkdf_sha512(
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
            &k,
            32,
        );
        let ios_device_x = hkdf_sha512(
            b"Pair-Setup-Controller-Sign-Salt",
            b"Pair-Setup-Controller-Sign-Info",
            &k,
            32,
        );
        let mut device_info = ios_device_x;
        device_info.extend_from_slice(&self.pairing_id);
        device_info.extend_from_slice(&self.lt_pub);
        let sig = ed25519_sign(&self.lt_seed.clone().try_into().expect("32"), &device_info);

        let inner = vec![
            (tlv::IDENTIFIER, self.pairing_id.clone()),
            (tlv::PUBLIC_KEY, self.lt_pub.clone()),
            (tlv::SIGNATURE, sig),
        ];
        let enc = airplay_crypto::chacha20_poly1305_encrypt(
            &session_key,
            b"PS-Msg05",
            &tlv::encode(&inner),
            b"",
        )?;
        self.pair_setup_session_key = session_key;
        let outer = vec![(tlv::STATE, vec![0x05]), (tlv::ENCRYPTED_DATA, enc)];
        Ok(tlv::encode(&outer))
    }

    // ── pair-setup M6 handling ───────────────────────────────────────

    /// M6: decrypt the accessory's long-term identity with the stashed
    /// session key + `PS-Msg06`; the persist-ready creds are returned
    /// (the `onCredentialsObtained` payload). Mirrors
    /// `handlePairSetupM6_`.
    pub fn handle_pair_setup_m6(&mut self, body: &[u8]) -> Result<AccessoryIdentity, PairingError> {
        let m = tlv::decode(body);
        if let Some(err) = tlv::get(&m, tlv::ERROR) {
            return Err(PairingError::AccessoryRejected(
                err.first().copied().unwrap_or(0),
            ));
        }
        let encrypted = tlv::get(&m, tlv::ENCRYPTED_DATA).ok_or(PairingError::Incomplete)?;
        let session_key = self.pair_setup_session_key.clone();
        let Some(dec) =
            airplay_crypto::chacha20_poly1305_decrypt(&session_key, b"PS-Msg06", encrypted, b"")
        else {
            return Err(PairingError::DecryptFailed);
        };
        let sub = tlv::decode(&dec);
        let (Some(atv_id), Some(atv_ltpk)) = (
            tlv::get(&sub, tlv::IDENTIFIER),
            tlv::get(&sub, tlv::PUBLIC_KEY),
        ) else {
            return Err(PairingError::Incomplete);
        };
        self.accessory_id = atv_id.clone();
        self.accessory_ltpk = atv_ltpk.clone();
        let creds_json = encode_creds(
            &to_hex(&self.lt_seed),
            &to_hex(atv_ltpk),
            &to_hex(atv_id),
            &String::from_utf8_lossy(&self.pairing_id),
        );
        self.pair_setup_session_key.clear(); // C++ clears it after M6
        Ok(AccessoryIdentity {
            accessory_id: atv_id.clone(),
            accessory_ltpk: atv_ltpk.clone(),
            creds_json,
        })
    }

    // ── pair-verify M1 ───────────────────────────────────────────────

    /// M1: generate the ephemeral X25519 pair; body =
    /// `{State:0x01, PublicKey}`.
    pub fn pair_verify_m1(&mut self) -> Result<Vec<u8>, PairingError> {
        self.verify_keys = Some(x25519_generate()?);
        let m = vec![
            (tlv::STATE, vec![0x01]),
            (
                tlv::PUBLIC_KEY,
                self.verify_keys
                    .as_ref()
                    .expect("just generated")
                    .public
                    .clone(),
            ),
        ];
        Ok(tlv::encode(&m))
    }

    // ── pair-verify M2 handling ──────────────────────────────────────

    /// Handle M2 of pair-verify: derive the X25519 shared secret + verify
    /// session key (`Pair-Verify-Encrypt`), decrypt the accessory's
    /// `{Identifier, Signature}`, verify its signature over
    /// `sessionPub||atvId||ourPub` (warn-only), sign our half over
    /// `ourPub||pairingId||sessionPub`, derive the control/event keys,
    /// and return the M3 request body + `accessory_signature_mismatch`.
    ///
    /// Calling this installs the channel keys (control read/write + the
    /// swapped event read/write) exactly like `handlePairVerifyM2_`.
    pub fn handle_pair_verify_m2(&mut self, body: &[u8]) -> Result<(Vec<u8>, bool), PairingError> {
        let m = tlv::decode(body);
        if let Some(err) = tlv::get(&m, tlv::ERROR) {
            return Err(PairingError::AccessoryRejected(
                err.first().copied().unwrap_or(0),
            ));
        }
        let (Some(session_pub), Some(encrypted)) = (
            tlv::get(&m, tlv::PUBLIC_KEY),
            tlv::get(&m, tlv::ENCRYPTED_DATA),
        ) else {
            return Err(PairingError::Incomplete);
        };
        let verify_keys = self.verify_keys.as_ref().ok_or(PairingError::MissingKey)?;
        let our_pub = verify_keys.public.clone();
        let our_priv: &[u8; 32] = verify_keys
            .private
            .as_slice()
            .try_into()
            .map_err(|_| PairingError::SharedSecretFailed)?;
        let session_pub32: &[u8; 32] = session_pub
            .as_slice()
            .try_into()
            .map_err(|_| PairingError::SharedSecretFailed)?;
        let Some(shared) = x25519_shared_secret(our_priv, session_pub32) else {
            return Err(PairingError::SharedSecretFailed); // low-order sessionPub
        };
        self.shared_secret = shared;
        let verify_key = hkdf_sha512(
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
            &self.shared_secret,
            32,
        );
        let Some(dec) =
            airplay_crypto::chacha20_poly1305_decrypt(&verify_key, b"PV-Msg02", encrypted, b"")
        else {
            return Err(PairingError::DecryptFailed);
        };
        let sub = tlv::decode(&dec);
        let (Some(atv_id), Some(atv_sig)) = (
            tlv::get(&sub, tlv::IDENTIFIER),
            tlv::get(&sub, tlv::SIGNATURE),
        ) else {
            return Err(PairingError::Incomplete);
        };

        // Verify the accessory signature (warn-only: the C++ continues on
        // mismatch; a missing/odd-length ltpk also counts as mismatch —
        // the C++ would read past a short buffer there).
        let mut sig_mismatch = false;
        if !self.accessory_ltpk.is_empty() {
            let mut info = session_pub.clone();
            info.extend_from_slice(atv_id);
            info.extend_from_slice(&our_pub);
            let ok = match (
                <[u8; 32]>::try_from(self.accessory_ltpk.as_slice()),
                <[u8; 64]>::try_from(atv_sig.as_slice()),
            ) {
                (Ok(pk), Ok(sig)) => ed25519_verify(&pk, &info, &sig),
                _ => false,
            };
            if !ok {
                sig_mismatch = true;
            }
        }

        // Sign our half: ourPub || pairingId || sessionPub.
        let mut device_info = our_pub.clone();
        device_info.extend_from_slice(&self.pairing_id);
        device_info.extend_from_slice(session_pub);
        let sig = ed25519_sign(&self.lt_seed.clone().try_into().expect("32"), &device_info);
        let inner = vec![
            (tlv::IDENTIFIER, self.pairing_id.clone()),
            (tlv::SIGNATURE, sig),
        ];
        let enc = airplay_crypto::chacha20_poly1305_encrypt(
            &verify_key,
            b"PV-Msg03",
            &tlv::encode(&inner),
            b"",
        )?;
        let outer = vec![(tlv::STATE, vec![0x03]), (tlv::ENCRYPTED_DATA, enc)];

        // Derive control + event channel keys (the event keys swap
        // read/write: a reverse connection).
        self.derive_control_keys();
        self.event_in = hkdf_sha512(
            b"Events-Salt",
            b"Events-Write-Encryption-Key",
            &self.shared_secret,
            32,
        );
        self.event_out = hkdf_sha512(
            b"Events-Salt",
            b"Events-Read-Encryption-Key",
            &self.shared_secret,
            32,
        );
        Ok((tlv::encode(&outer), sig_mismatch))
    }

    // ── key derivation ───────────────────────────────────────────────

    /// Derive the Control-Write/Read keys over the shared secret
    /// (transient: SRP K; pair-verify: the ECDH secret of
    /// [`Self::handle_pair_verify_m2`]). `Control-Salt` +
    /// `Control-Write/Read-Encryption-Key`, exactly as both pairing
    /// paths do it.
    pub fn derive_control_keys(&mut self) {
        self.control_out = hkdf_sha512(
            b"Control-Salt",
            b"Control-Write-Encryption-Key",
            &self.shared_secret,
            32,
        );
        self.control_in = hkdf_sha512(
            b"Control-Salt",
            b"Control-Read-Encryption-Key",
            &self.shared_secret,
            32,
        );
    }

    /// The AP2 audio key: the shared secret clamped to 32 bytes (the
    /// pair-verify X25519 secret is already 32; the transient SRP K is
    /// SHA-512 = 64 bytes, only the first 32 are used). Matches the
    /// `sendAp2SetupStream_` clamp.
    pub fn derive_audio_key(&mut self) {
        self.audio_key = self.shared_secret.clone();
        self.audio_key.truncate(32);
    }
}

// ── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-consistent SRP server params: airplay-crypto's own tests
    /// accept any non-zero B (the only server check is B ≢ 0 mod N), so a
    /// fixed filler works for driving the client machine.
    fn srp_pair() -> (Vec<u8>, Vec<u8>) {
        (b"fake-salt".to_vec(), vec![0xCDu8; 64])
    }

    /// Drive a PIN-mode session through M2/M3 (with the fixed SRP params),
    /// leaving it ready for M4.
    fn session_at_m4() -> PairingSession {
        let mut s = PairingSession::new(PairingMode::Pin);
        let (salt, b) = srp_pair();
        s.handle_pair_setup_m2(&tlv::encode(&[
            (tlv::STATE, vec![0x02]),
            (tlv::SALT, salt.clone()),
            (tlv::PUBLIC_KEY, b.clone()),
        ]))
        .unwrap();
        s.pair_setup_m3("1234").unwrap();
        s
    }

    #[test]
    fn m1_shapes() {
        let pin = PairingSession::new(PairingMode::Pin);
        assert_eq!(
            pin.pair_setup_m1(),
            vec![0x00, 0x01, 0x00, 0x06, 0x01, 0x01]
        );
        let transient = PairingSession::new(PairingMode::Transient);
        assert_eq!(
            transient.pair_setup_m1(),
            vec![0x00, 0x01, 0x00, 0x06, 0x01, 0x01, 0x13, 0x01, 0x10]
        );
        assert_eq!(pin.hkp(), 3);
        assert_eq!(transient.hkp(), 4);
    }

    #[test]
    fn m2_error_and_incomplete_paths() {
        let mut s = PairingSession::new(PairingMode::Pin);
        // TLV Error tag → AccessoryRejected with first byte.
        let err = tlv::encode(&[(tlv::ERROR, vec![0x05])]);
        assert_eq!(
            s.handle_pair_setup_m2(&err),
            Err(PairingError::AccessoryRejected(0x05))
        );
        // Empty error value → 0.
        let err0 = tlv::encode(&[(tlv::ERROR, Vec::new())]);
        assert_eq!(
            s.handle_pair_setup_m2(&err0),
            Err(PairingError::AccessoryRejected(0))
        );
        // Missing salt/pub → Incomplete.
        assert_eq!(
            s.handle_pair_setup_m2(&tlv::encode(&[(tlv::STATE, vec![0x02])])),
            Err(PairingError::Incomplete)
        );
        // Valid M2 body → salt+B captured.
        let ok = tlv::encode(&[
            (tlv::STATE, vec![0x02]),
            (tlv::SALT, b"salt".to_vec()),
            (tlv::PUBLIC_KEY, vec![1, 2, 3, 4]),
        ]);
        s.handle_pair_setup_m2(&ok).unwrap();
        assert_eq!(s.srp_salt.as_deref(), Some(b"salt".as_slice()));
        assert_eq!(s.srp_server_b.as_deref(), Some([1, 2, 3, 4].as_slice()));
    }

    #[test]
    fn m3_requires_captured_params() {
        let mut s = PairingSession::new(PairingMode::Pin);
        assert_eq!(s.pair_setup_m3("1234"), Err(PairingError::Incomplete));
        // Captured params but zero B → SrpParamsRejected.
        s.handle_pair_setup_m2(&tlv::encode(&[
            (tlv::STATE, vec![0x02]),
            (tlv::SALT, b"s".to_vec()),
            (tlv::PUBLIC_KEY, vec![0u8; 32]),
        ]))
        .unwrap();
        assert_eq!(
            s.pair_setup_m3("1234"),
            Err(PairingError::SrpParamsRejected)
        );
    }

    #[test]
    fn m4_error_paths() {
        let mut s = PairingSession::new(PairingMode::Pin);
        let err = tlv::encode(&[(tlv::ERROR, vec![0x07])]);
        assert_eq!(
            s.handle_pair_setup_m4(&err),
            Err(PairingError::AccessoryRejected(0x07))
        );
        // No SRP started yet (no M3) → MissingKey.
        assert_eq!(
            s.handle_pair_setup_m4(&tlv::encode(&[(tlv::STATE, vec![0x04])])),
            Err(PairingError::MissingKey)
        );
    }

    #[test]
    fn m4_without_proof_continues_to_m5() {
        // Pin mode after M3: M4 without a Proof tag must continue to M5.
        let mut s = session_at_m4();
        let (outcome, mismatch) = s
            .handle_pair_setup_m4(&tlv::encode(&[(tlv::STATE, vec![0x04])]))
            .unwrap();
        assert_eq!(outcome, M4Outcome::SendM5);
        assert!(!mismatch);
        // A bogus Proof fails verification but must NOT error the session.
        let (outcome2, mismatch2) = s
            .handle_pair_setup_m4(&tlv::encode(&[
                (tlv::STATE, vec![0x04]),
                (tlv::PROOF, vec![1, 2]),
            ]))
            .unwrap();
        assert_eq!(outcome2, M4Outcome::SendM5);
        assert!(mismatch2);
    }

    #[test]
    fn transient_m4_derives_keys() {
        let mut s = PairingSession::new(PairingMode::Transient);
        let (salt, b) = srp_pair();
        s.handle_pair_setup_m2(&tlv::encode(&[
            (tlv::STATE, vec![0x02]),
            (tlv::SALT, salt),
            (tlv::PUBLIC_KEY, b),
        ]))
        .unwrap();
        s.pair_setup_m3(TRANSIENT_PIN).unwrap();
        let (outcome, mismatch) = s
            .handle_pair_setup_m4(&tlv::encode(&[(tlv::STATE, vec![0x04])]))
            .unwrap();
        assert_eq!(outcome, M4Outcome::TransientKeysDerived);
        assert!(!mismatch);
        // Control keys derived over the SRP K (64 bytes); audio key = K[:32].
        assert_eq!(s.control_out.len(), 32);
        assert_eq!(s.control_in.len(), 32);
        assert_ne!(s.control_out, s.control_in);
        assert_eq!(s.shared_secret.len(), 64);
        s.derive_audio_key();
        assert_eq!(s.audio_key, s.shared_secret[..32]);
    }

    #[test]
    fn m5_builds_and_m6_roundtrips() {
        // Pair-setup M5/M6 end to end with a scripted accessory: it
        // decrypts our M5 with the same session-key derivation (from the
        // SRP K it shares) and verifies our signature; we decrypt its M6.
        let mut s = session_at_m4();
        s.handle_pair_setup_m4(&tlv::encode(&[(tlv::STATE, vec![0x04])]))
            .unwrap();

        let k = s.srp.as_ref().unwrap().session_key();
        let session_key = hkdf_sha512(
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
            &k,
            32,
        );

        let m5 = s.pair_setup_m5().unwrap();
        let m5_map = tlv::decode(&m5);
        assert_eq!(
            tlv::get(&m5_map, tlv::STATE).map(|v| v.as_slice()),
            Some([0x05].as_slice())
        );
        assert!(!s.lt_seed.is_empty() && s.lt_seed.len() == 32);
        let enc = tlv::get(&m5_map, tlv::ENCRYPTED_DATA).unwrap();
        let dec = airplay_crypto::chacha20_poly1305_decrypt(&session_key, b"PS-Msg05", enc, b"")
            .expect("M5 decrypts with the shared session key");
        let inner = tlv::decode(&dec);
        let their_id = tlv::get(&inner, tlv::IDENTIFIER).unwrap().clone();
        let their_pub = tlv::get(&inner, tlv::PUBLIC_KEY).unwrap().clone();
        let their_sig = tlv::get(&inner, tlv::SIGNATURE).unwrap();

        // Verify the signed material: X || pairingId || ltPub.
        let ios_x = hkdf_sha512(
            b"Pair-Setup-Controller-Sign-Salt",
            b"Pair-Setup-Controller-Sign-Info",
            &k,
            32,
        );
        let mut signed = ios_x;
        signed.extend_from_slice(&their_id);
        signed.extend_from_slice(&their_pub);
        assert_eq!(their_id, s.pairing_id);
        assert_eq!(their_pub, s.lt_pub);
        assert!(ed25519_verify(
            their_pub.as_slice().try_into().unwrap(),
            &signed,
            their_sig.as_slice().try_into().unwrap(),
        ));

        // Accessory M6: its own long-term identity, encrypted with PS-Msg06.
        let atv_seed: [u8; 32] = vec![0xAB; 32].try_into().unwrap();
        let atv_pub = ed25519_public_from_seed(&atv_seed);
        let atv_id = b"Accessory-UUID-1".to_vec();
        let inner6 = tlv::encode(&[
            (tlv::IDENTIFIER, atv_id.clone()),
            (tlv::PUBLIC_KEY, atv_pub.clone()),
        ]);
        let enc6 =
            airplay_crypto::chacha20_poly1305_encrypt(&session_key, b"PS-Msg06", &inner6, b"")
                .unwrap();
        let m6 = tlv::encode(&[(tlv::STATE, vec![0x06]), (tlv::ENCRYPTED_DATA, enc6)]);

        let identity = s.handle_pair_setup_m6(&m6).unwrap();
        assert_eq!(identity.accessory_id, atv_id.clone());
        assert_eq!(identity.accessory_ltpk, atv_pub.clone());
        assert_eq!(s.accessory_id, atv_id.clone());
        assert_eq!(s.accessory_ltpk, atv_pub.clone());
        // Creds JSON round-trips back into the session.
        let parsed = parse_stored_creds(&identity.creds_json).expect("parseable");
        assert_eq!(parsed.ltsk, s.lt_seed);
        assert_eq!(parsed.ltpk, atv_pub);
        assert_eq!(parsed.atv_id, atv_id);
        assert_eq!(parsed.client_id, String::from_utf8_lossy(&s.pairing_id));
        // Stash cleared after M6.
        assert!(s.pair_setup_session_key.is_empty());
    }

    #[test]
    fn m6_error_paths() {
        let mut s = PairingSession::new(PairingMode::Pin);
        assert_eq!(
            s.handle_pair_setup_m6(&tlv::encode(&[(tlv::ERROR, vec![0x01])])),
            Err(PairingError::AccessoryRejected(0x01))
        );
        assert_eq!(
            s.handle_pair_setup_m6(&tlv::encode(&[(tlv::STATE, vec![0x06])])),
            Err(PairingError::Incomplete)
        );
        // Stash a junk key so the decrypt step runs and fails.
        s.pair_setup_session_key = vec![0u8; 32];
        let junk = tlv::encode(&[(tlv::STATE, vec![0x06]), (tlv::ENCRYPTED_DATA, vec![0; 20])]);
        assert_eq!(
            s.handle_pair_setup_m6(&junk),
            Err(PairingError::DecryptFailed)
        );
        // Decrypt succeeds but the inner TLV lacks keys.
        let enc = airplay_crypto::chacha20_poly1305_encrypt(
            &s.pair_setup_session_key,
            b"PS-Msg06",
            &tlv::encode(&[(tlv::STATE, vec![0x06])]),
            b"",
        )
        .unwrap();
        let m6 = tlv::encode(&[(tlv::STATE, vec![0x06]), (tlv::ENCRYPTED_DATA, enc)]);
        assert_eq!(s.handle_pair_setup_m6(&m6), Err(PairingError::Incomplete));
    }

    #[test]
    fn pair_verify_full_roundtrip() {
        // Pair-verify M1/M2/M3 end to end: two X25519 endpoints, both
        // Ed25519 sides sign and verify, keys agree.
        let mut client = PairingSession::new(PairingMode::Pin);
        client.lt_seed = vec![0x11; 32];
        client.lt_pub = ed25519_public_from_seed(&vec![0x11; 32].try_into().unwrap());
        client.pairing_id = b"client-pairing-id".to_vec();
        let atv_lt_seed: [u8; 32] = vec![0x22; 32].try_into().unwrap();
        let atv_pub = ed25519_public_from_seed(&atv_lt_seed);
        client.accessory_ltpk = atv_pub.clone();

        // M1 (client → accessory).
        let m1 = client.pair_verify_m1().unwrap();
        let m1_map = tlv::decode(&m1);
        let client_pub = tlv::get(&m1_map, tlv::PUBLIC_KEY).unwrap().clone();
        assert_eq!(
            tlv::get(&m1_map, tlv::STATE).map(|v| v.as_slice()),
            Some([0x01].as_slice())
        );

        // Accessory side: its own X25519 pair + shared secret + verify key.
        let server = x25519_generate().unwrap();
        let server_pub = server.public.clone();
        let shared = x25519_shared_secret(
            server.private.as_slice().try_into().unwrap(),
            client_pub.as_slice().try_into().unwrap(),
        )
        .expect("shared secret");
        let verify_key = hkdf_sha512(
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
            &shared,
            32,
        );

        // Accessory M2 inner: {atvId, sig over sessionPub||atvId||clientPub}.
        let atv_id = b"Accessory-2".to_vec();
        let mut info = server_pub.clone();
        info.extend_from_slice(&atv_id);
        info.extend_from_slice(&client_pub);
        let atv_sig = ed25519_sign(&atv_lt_seed, &info);
        let inner2 = tlv::encode(&[(tlv::IDENTIFIER, atv_id.clone()), (tlv::SIGNATURE, atv_sig)]);
        let enc2 =
            airplay_crypto::chacha20_poly1305_encrypt(&verify_key, b"PV-Msg02", &inner2, b"")
                .unwrap();
        let m2 = tlv::encode(&[
            (tlv::STATE, vec![0x02]),
            (tlv::PUBLIC_KEY, server_pub.clone()),
            (tlv::ENCRYPTED_DATA, enc2),
        ]);

        // Client handles M2 → M3 body + no signature mismatch.
        let (m3, mismatch) = client.handle_pair_verify_m2(&m2).unwrap();
        assert!(!mismatch, "accessory signature must verify");
        let m3_map = tlv::decode(&m3);
        assert_eq!(
            tlv::get(&m3_map, tlv::STATE).map(|v| v.as_slice()),
            Some([0x03].as_slice())
        );
        let enc3 = tlv::get(&m3_map, tlv::ENCRYPTED_DATA).unwrap();

        // Accessory decrypts M3 and verifies our signature over
        // clientPub||pairingId||serverPub.
        let dec3 = airplay_crypto::chacha20_poly1305_decrypt(&verify_key, b"PV-Msg03", enc3, b"")
            .expect("M3 decrypts");
        let inner3 = tlv::decode(&dec3);
        let their_id = tlv::get(&inner3, tlv::IDENTIFIER).unwrap();
        let their_sig = tlv::get(&inner3, tlv::SIGNATURE).unwrap();
        assert_eq!(their_id, &client.pairing_id);
        let mut signed = client_pub.clone();
        signed.extend_from_slice(&client.pairing_id);
        signed.extend_from_slice(&server_pub);
        assert!(ed25519_verify(
            client.lt_pub.as_slice().try_into().unwrap(),
            &signed,
            their_sig.as_slice().try_into().unwrap(),
        ));

        // Keys: control + event (swapped) derived on both ends.
        assert_eq!(client.control_out.len(), 32);
        assert_eq!(client.control_in.len(), 32);
        assert_eq!(client.event_in.len(), 32);
        assert_eq!(client.event_out.len(), 32);
        let want_out = hkdf_sha512(
            b"Control-Salt",
            b"Control-Write-Encryption-Key",
            &shared,
            32,
        );
        let want_in = hkdf_sha512(b"Control-Salt", b"Control-Read-Encryption-Key", &shared, 32);
        assert_eq!(client.control_out, want_out);
        assert_eq!(client.control_in, want_in);
        let want_ev_in = hkdf_sha512(b"Events-Salt", b"Events-Write-Encryption-Key", &shared, 32);
        let want_ev_out = hkdf_sha512(b"Events-Salt", b"Events-Read-Encryption-Key", &shared, 32);
        assert_eq!(client.event_in, want_ev_in);
        assert_eq!(client.event_out, want_ev_out);
        // In a reverse connection the event keys are NOT the control keys.
        assert_ne!(client.event_in, client.control_in);
        // Audio key = first 32 of the shared secret (32 already, no clamp).
        client.derive_audio_key();
        assert_eq!(client.audio_key, shared[..32]);
    }

    #[test]
    fn pair_verify_error_paths() {
        let mut client = PairingSession::new(PairingMode::Pin);
        assert_eq!(
            client.handle_pair_verify_m2(&tlv::encode(&[(tlv::ERROR, vec![0x03])])),
            Err(PairingError::AccessoryRejected(0x03))
        );
        assert_eq!(
            client.handle_pair_verify_m2(&tlv::encode(&[(tlv::STATE, vec![0x02])])),
            Err(PairingError::Incomplete)
        );
        // No verify keys yet → MissingKey at shared-secret time.
        let m2 = tlv::encode(&[
            (tlv::STATE, vec![0x02]),
            (tlv::PUBLIC_KEY, vec![0u8; 32]),
            (tlv::ENCRYPTED_DATA, vec![0u8; 20]),
        ]);
        assert_eq!(
            client.handle_pair_verify_m2(&m2),
            Err(PairingError::MissingKey)
        );
    }

    #[test]
    fn pair_verify_bad_accessory_signature_warns_not_fails() {
        let mut client = PairingSession::new(PairingMode::Pin);
        client.lt_seed = vec![0x11; 32];
        client.lt_pub = ed25519_public_from_seed(&vec![0x11; 32].try_into().unwrap());
        client.pairing_id = b"id".to_vec();
        client.accessory_ltpk = ed25519_public_from_seed(&vec![0x22; 32].try_into().unwrap());
        client.pair_verify_m1().unwrap();

        let server = x25519_generate().unwrap();
        let shared = x25519_shared_secret(
            server.private.as_slice().try_into().unwrap(),
            client
                .verify_keys
                .as_ref()
                .unwrap()
                .public
                .as_slice()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let verify_key = hkdf_sha512(
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
            &shared,
            32,
        );
        // Signature over the WRONG material.
        let bad_sig = ed25519_sign(&vec![0x22; 32].try_into().unwrap(), b"wrong");
        let inner = tlv::encode(&[
            (tlv::IDENTIFIER, b"atv".to_vec()),
            (tlv::SIGNATURE, bad_sig),
        ]);
        let enc = airplay_crypto::chacha20_poly1305_encrypt(&verify_key, b"PV-Msg02", &inner, b"")
            .unwrap();
        let m2 = tlv::encode(&[
            (tlv::STATE, vec![0x02]),
            (tlv::PUBLIC_KEY, server.public),
            (tlv::ENCRYPTED_DATA, enc),
        ]);
        let (_m3, mismatch) = client.handle_pair_verify_m2(&m2).unwrap();
        assert!(mismatch, "bad signature must warn");
        // Keys still derive (the C++ continues on mismatch).
        assert_eq!(client.control_out.len(), 32);
    }

    #[test]
    fn stored_creds_roundtrip_and_load() {
        let mut s = PairingSession::new(PairingMode::Pin);
        let json = encode_creds(
            &to_hex(&[7u8; 32]),
            &to_hex(&[8u8; 32]),
            "deadbeef",
            "client-uuid",
        );
        assert!(s.try_load_creds(&json));
        assert_eq!(s.lt_seed, vec![7u8; 32]);
        assert_eq!(s.accessory_ltpk, vec![8u8; 32]);
        assert_eq!(s.accessory_id, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(s.pairing_id, b"client-uuid");
        assert_eq!(
            s.lt_pub,
            ed25519_public_from_seed(&vec![7u8; 32].try_into().unwrap())
        );
        assert!(s.ready_for_pair_verify());

        // Garbage JSON → nothing loaded, not verify-ready.
        let mut s2 = PairingSession::new(PairingMode::Pin);
        assert!(!s2.try_load_creds("{}"));
        assert!(!s2.ready_for_pair_verify());
        assert!(s2.lt_seed.is_empty());
        assert!(parse_stored_creds("not json").is_none());
    }
}
