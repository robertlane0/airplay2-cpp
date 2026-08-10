// SPDX-License-Identifier: Apache-2.0
//! AirPlay 2 binary-plist SETUP payloads and reply parsing, ported from
//! [`src/raop_sender.cpp`](../../src/raop_sender.cpp)
//! (`sendAp2SetupSession_` / `handleAp2SetupSession_` /
//! `sendAp2SetupStream_` / `handleAp2SetupStream_`).
//!
//! All four are pure: dictionaries in (fixed build order — insertion
//! order is observable wire behavior), reply plists out.

use airplay_crypto::bplist::Value;

/// Session-level SETUP plist, exactly the field order of
/// `sendAp2SetupSession_`. `device_id`/`mac_address` are the hardcoded
/// placeholders the C++ sends; `name` is the constant client name.
pub fn build_setup_session(session_uuid: &str, timing_port: u16) -> Vec<u8> {
    let d = vec![
        ("deviceID", Value::Str("AA:BB:CC:DD:EE:FF".to_string())),
        ("sessionUUID", Value::Str(session_uuid.to_string())),
        ("timingPort", Value::Int(i64::from(timing_port))),
        ("timingProtocol", Value::Str("NTP".to_string())),
        ("isMultiSelectAirPlay", Value::Bool(true)),
        ("groupContainsGroupLeader", Value::Bool(false)),
        ("macAddress", Value::Str("AA:BB:CC:DD:EE:FF".to_string())),
        ("model", Value::Str("iPhone14,3".to_string())),
        ("name", Value::Str("FXChainPlayer".to_string())),
        ("osBuildVersion", Value::Str("20F66".to_string())),
        ("osName", Value::Str("iPhone OS".to_string())),
        ("osVersion", Value::Str("16.5".to_string())),
        ("senderSupportsRelay", Value::Bool(false)),
        ("sourceVersion", Value::Str("690.7.1".to_string())),
        ("statsCollectionEnabled", Value::Bool(false)),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    airplay_crypto::bplist::encode(&Value::Dict(d))
}

/// Stream-level SETUP plist (the payload of the stream `SETUP`),
/// exactly the field order of `sendAp2SetupStream_`: the `streams` array
/// wraps a single stream dict. `audio_key` is the clamped shared secret
/// (`shk`); the C++ takes the FIRST 32 bytes on the wire.
pub fn build_setup_stream(control_port: u16, audio_key: &[u8], session_id: u32) -> Vec<u8> {
    let stream = vec![
        ("audioFormat", Value::Int(0x40000)), // ALAC/44100/16/2
        ("audioMode", Value::Str("default".to_string())),
        ("controlPort", Value::Int(i64::from(control_port))),
        ("ct", Value::Int(2)), // ALAC
        ("isMedia", Value::Bool(true)),
        ("latencyMax", Value::Int(88200)),
        ("latencyMin", Value::Int(11025)),
        ("shk", Value::Data(audio_key.to_vec())),
        ("spf", Value::Int(352)), // samples per frame
        ("sr", Value::Int(44100)),
        ("type", Value::Int(0x60)), // realtime
        ("supportsDynamicStreamID", Value::Bool(false)),
        ("streamConnectionID", Value::Int(i64::from(session_id))),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let d = vec![("streams", Value::Arr(vec![Value::Dict(stream)]))]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    airplay_crypto::bplist::encode(&Value::Dict(d))
}

/// Reply of the session SETUP: `eventPort` (0 when absent/not an int).
pub fn parse_setup_session_reply(body: &[u8]) -> u16 {
    let Some(root) = airplay_crypto::bplist::decode(body) else {
        return 0;
    };
    match root.find("eventPort") {
        Some(v) => v.as_int(0) as u16,
        None => 0,
    }
}

/// Reply of the stream SETUP: `(dataPort, controlPort)` from the first
/// entry of the `streams` array (0 when absent) — mirrors the C++
/// `type == Arr && !arr.empty()` guard and the per-field `find`.
pub fn parse_setup_stream_reply(body: &[u8]) -> (u16, u16) {
    let Some(root) = airplay_crypto::bplist::decode(body) else {
        return (0, 0);
    };
    let Some(streams) = root.find("streams") else {
        return (0, 0);
    };
    let Value::Arr(arr) = streams else {
        return (0, 0);
    };
    let Some(s0) = arr.first() else {
        return (0, 0);
    };
    let data_port = match s0.find("dataPort") {
        Some(v) => v.as_int(0) as u16,
        None => 0,
    };
    let control_port = match s0.find("controlPort") {
        Some(v) => v.as_int(0) as u16,
        None => 0,
    };
    (data_port, control_port)
}

// ── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_plist_roundtrip_and_event_port() {
        let body = build_setup_session("UUID-1", 50001);
        // Decodable + presence of the key fields.
        let root = airplay_crypto::bplist::decode(&body).expect("decodes");
        assert_eq!(root.find("sessionUUID").unwrap().as_str(""), "UUID-1");
        assert_eq!(root.find("timingPort").unwrap().as_int(-1), 50001);
        assert_eq!(root.find("timingProtocol").unwrap().as_str(""), "NTP");
        assert_eq!(root.find("isMultiSelectAirPlay").unwrap().as_int(-1), -1); // bools: not ints
        // eventPort absent → 0.
        assert_eq!(parse_setup_session_reply(&body), 0);
        // Hostile/unparseable body → 0.
        assert_eq!(parse_setup_session_reply(b"junk"), 0);

        // A crafted reply with an eventPort parses back.
        let reply = airplay_crypto::bplist::encode(&Value::Dict(vec![
            ("eventPort".to_string(), Value::Int(6000)),
            ("other".to_string(), Value::Str("x".to_string())),
        ]));
        assert_eq!(parse_setup_session_reply(&reply), 6000);
    }

    #[test]
    fn stream_plist_roundtrip_and_ports() {
        let key = vec![0x42u8; 32];
        let body = build_setup_stream(50002, &key, 7);
        let root = airplay_crypto::bplist::decode(&body).expect("decodes");
        let streams = root.find("streams").unwrap();
        let Value::Arr(arr) = streams else {
            panic!("streams is an array")
        };
        let s0 = arr.first().unwrap();
        assert_eq!(s0.find("shk").unwrap().as_str(""), ""); // Data not Str
        assert_eq!(s0.find("spf").unwrap().as_int(0), 352);
        assert_eq!(s0.find("streamConnectionID").unwrap().as_int(0), 7);
        assert_eq!(s0.find("type").unwrap().as_int(0), 0x60);

        // Reply parsing: happy path.
        let reply = airplay_crypto::bplist::encode(&Value::Dict(vec![(
            "streams".to_string(),
            Value::Arr(vec![Value::Dict(vec![
                ("dataPort".to_string(), Value::Int(5001)),
                ("controlPort".to_string(), Value::Int(5002)),
            ])]),
        )]));
        assert_eq!(parse_setup_stream_reply(&reply), (5001, 5002));

        // Missing controlPort → 0; empty array → (0, 0); junk → (0, 0).
        let no_ctl = airplay_crypto::bplist::encode(&Value::Dict(vec![(
            "streams".to_string(),
            Value::Arr(vec![Value::Dict(vec![(
                "dataPort".to_string(),
                Value::Int(5001),
            )])]),
        )]));
        assert_eq!(parse_setup_stream_reply(&no_ctl), (5001, 0));
        let empty = airplay_crypto::bplist::encode(&Value::Dict(vec![(
            "streams".to_string(),
            Value::Arr(vec![]),
        )]));
        assert_eq!(parse_setup_stream_reply(&empty), (0, 0));
        assert_eq!(parse_setup_stream_reply(b"junk"), (0, 0));
        let no_streams =
            airplay_crypto::bplist::encode(&Value::Dict(vec![("x".to_string(), Value::Int(1))]));
        assert_eq!(parse_setup_stream_reply(&no_streams), (0, 0));
    }
}
