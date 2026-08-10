// Reference harness: dumps ground-truth bytes from the C++ airplay_crypto
// for differential testing against the Rust migration. Deterministic
// inputs only (no SRP: its ephemeral `a` is random; SRP is covered by the
// mock-server test in Rust).
#include "airplay_crypto.h"
extern "C" {
#include "x25519_raw.h"
}
#include <cstdio>
#include <string>
#include <vector>

using namespace fxchain::airplay;

static std::string hex(const Bytes& b) {
    static const char* hx = "0123456789abcdef";
    std::string r; r.reserve(b.size()*2);
    for (unsigned char c : b) { r.push_back(hx[c >> 4]); r.push_back(hx[c & 0xF]); }
    return r;
}

static void dump(const std::string& name, const Bytes& b) {
    printf("%s=%s\n", name.c_str(), hex(b).c_str());
}

int main() {
    const Bytes fixedKey(32, 0x42);
    const Bytes fixedNonce = counterNonce8(7);
    const Bytes aad("rtsp headers", "rtsp headers" + 12);
    const Bytes pt("the quick brown fox", "the quick brown fox" + 19);

    dump("sha512_empty", sha512(Bytes()));
    dump("sha512_abc", sha512(Bytes("abc", "abc" + 3)));
    dump("hmac512", hmacSha512(fixedKey, pt));
    dump("hkdf32", hkdfSha512("Control-Salt", "Control-Write-Encryption-Key", fixedKey, 32));
    {
        std::string saltStr, infoStr;
        for (int i = 0; i <= 12; ++i) saltStr.push_back(char(i));
        for (int i = 0xf0; i <= 0xf9; ++i) infoStr.push_back(char(i));
        dump("hkdf_salt012_info_f0f9", hkdfSha512(saltStr, infoStr, Bytes(11, 0x0b), 42));
    }
    const Bytes ct = chacha20Poly1305Encrypt(fixedKey, fixedNonce, pt, aad);
    dump("chacha_ct", ct);
    auto dec = chacha20Poly1305Decrypt(fixedKey, fixedNonce, ct, aad);
    printf("chacha_rt=%d\n", (int)(dec.has_value() && *dec == pt));
    auto badTag = chacha20Poly1305Decrypt(fixedKey, fixedNonce, ct, Bytes("x", "x" + 1));
    printf("chacha_bad_aad=%s\n", badTag ? "DECRYPTED" : "nullopt");

    {
        const unsigned char a_[32] = {0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a};
        const unsigned char b_[32] = {0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb};
        Bytes alice(a_, a_+32), bob(b_, b_+32);
        alice[0] &= 248; alice[31] &= 127; alice[31] |= 64;
        bob[0]   &= 248; bob[31]   &= 127; bob[31]   |= 64;
        Bytes apub(32), bpub(32);
        x25519_base(apub.data(), alice.data());
        x25519_base(bpub.data(), bob.data());
        dump("x25519_alice_pub", apub);
        dump("x25519_bob_pub", bpub);
        dump("x25519_shared", x25519SharedSecret(alice, bpub));
        printf("x25519_zero_reject=%d\n", (int)x25519SharedSecret(alice, Bytes(32, 0)).empty());
    }
    {
        const unsigned char seed_[32] = {0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0xc4,0x44,0x49,0xc5,0x69,0x7b,0x32,0x69,0x19,0x70,0x3b,0xac,0x03,0x1c,0xae,0x7f,0x60};
        Bytes seed(seed_, seed_+32);
        dump("ed_pub", ed25519PublicFromSeed(seed));
        dump("ed_sig_empty", ed25519Sign(seed, Bytes()));
        dump("ed_sig_msg", ed25519Sign(seed, Bytes("apple pair-verify payload", "apple pair-verify payload" + 25)));
        printf("ed_verify_ok=%d ed_verify_bad=%d\n",
               (int)ed25519Verify(ed25519PublicFromSeed(seed), Bytes("apple pair-verify payload", "apple pair-verify payload" + 25), ed25519Sign(seed, Bytes("apple pair-verify payload", "apple pair-verify payload" + 25))),
               (int)ed25519Verify(ed25519PublicFromSeed(seed), Bytes("other", "other" + 5), ed25519Sign(seed, Bytes("apple pair-verify payload", "apple pair-verify payload" + 25))));
    }
    {
        tlv::Map m = {{tlv::Flags, {0x10}}, {tlv::Salt, {1,2,3}}};
        dump("tlv_enc", tlv::encode(m));
        Bytes big; for (int i = 0; i < 384; ++i) big.push_back((unsigned char)(i % 251));
        tlv::Map m2 = {{tlv::PublicKey, big}};
        dump("tlv_enc_384", tlv::encode(m2));
        auto dec = tlv::decode(tlv::encode(m2));
        printf("tlv_rt_384=%d\n", (int)(dec.size()==1 && dec[0].second==big));
        Bytes trunc = tlv::encode(m2);
        trunc.resize(trunc.size() - 3);
        printf("tlv_truncated=%zu\n", tlv::decode(trunc).size());
        printf("tlv_get=%zu\n", tlv::get(dec, tlv::PublicKey).has_value());
    }
    {
        using namespace fxchain::airplay::bplist;
        Dict e = {{"key", Value::integer(42)}};
        dump("bplist_dict_int", encode(Value::object(e)));
        Dict full = {
            {"txTxtv", Value::integer(1)},
            {"pw", Value::boolean(true)},
            {"vv", Value::integer(2)},
            {"vs", Value::array({Value::object({{"cn", Value::integer(0)}, {"sc", Value::integer(1)}, {"sv", Value::str("130.14")}}),
                                 Value::object({{"cn", Value::integer(2)}, {"sc", Value::integer(3)}, {"sv", Value::str("8")}})
                                })},
            {"ft", Value::str("0x4F,0x0B")},
            {"et", Value::bytes(Bytes({0x00, 0x05, 0x06}))},
            {"sf", Value::boolean(false)},
            {"ek", Value::object({{"ty", Value::integer(64)}, {"k", Value::bytes(Bytes(16, 7))}})},
        };
        dump("bplist_setup", encode(Value::object(full)));
        auto dec = decode(encode(Value::object(full)));
        printf("bplist_rt=%d\n", (int)dec.has_value());
        printf("bplist_empty=%d bplist_junk=%d\n", (int)decode(Bytes()).has_value(), (int)decode(Bytes("hello world", "hello world" + 11)).has_value());
        auto di = decode(encode(Value::object(e)));
        printf("bplist_find=%lld str=%s\n", (long long)(di ? di->find("key")->asInt(-1) : -999), di ? di->find("key")->asStr("x").c_str() : "nf");
        // reals: exact double round trip
        auto real = decode(encode(Value::real(1.5)));
        printf("bplist_real_rt=%d\n", (int)(real.has_value() && real->type == Value::Type::Real && real->r == 1.5));
    }
    printf("digest=%s\n", digestAuthResponse("SETUP", "rtsp://1.2.3.4/0", "airplay", "realm-x", "1234", "nonce-y").c_str());
    return 0;
}