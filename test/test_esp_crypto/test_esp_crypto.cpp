#include <Arduino.h>
#include <ESPCrypto.h>
#include <unity.h>
#include <cstring>
#include <vector>

void test_teardown_preinit_and_idempotent() {
    ESPCrypto::deinit();
    TEST_ASSERT_FALSE(ESPCrypto::isInitialized());

    ESPCrypto::deinit();
    TEST_ASSERT_FALSE(ESPCrypto::isInitialized());
}

void test_teardown_reinit_lifecycle() {
    ESPCrypto::deinit();
    TEST_ASSERT_FALSE(ESPCrypto::isInitialized());

    CryptoPolicy customPolicy = ESPCrypto::policy();
    customPolicy.minPbkdf2Iterations = 4096;
    ESPCrypto::setPolicy(customPolicy);
    TEST_ASSERT_TRUE(ESPCrypto::isInitialized());
    TEST_ASSERT_EQUAL_UINT32(4096, ESPCrypto::policy().minPbkdf2Iterations);

    ESPCrypto::deinit();
    TEST_ASSERT_FALSE(ESPCrypto::isInitialized());
    TEST_ASSERT_EQUAL_UINT32(1024, ESPCrypto::policy().minPbkdf2Iterations);

    std::vector<uint8_t> key(16, 0x5A);
    std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};
    auto enc = ESPCrypto::aesGcmEncryptAuto(key, plaintext);
    TEST_ASSERT_TRUE_MESSAGE(enc.ok(), enc.status.message.c_str());
    TEST_ASSERT_TRUE(ESPCrypto::isInitialized());

    ESPCrypto::deinit();
    TEST_ASSERT_FALSE(ESPCrypto::isInitialized());
}

void test_sha_hex_matches_known_value() {
    const char *data = "hello world";
    String digest = ESPCrypto::shaHex(reinterpret_cast<const uint8_t *>(data), strlen(data));
    TEST_ASSERT_EQUAL_STRING("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                            digest.c_str());
}

void test_password_hash_roundtrip() {
    String hashed = ESPCrypto::hashString("hunter2");
    TEST_ASSERT_TRUE(hashed.length() > 0);
    TEST_ASSERT_TRUE(ESPCrypto::verifyString("hunter2", hashed));
    TEST_ASSERT_FALSE(ESPCrypto::verifyString("badpass", hashed));
}

void test_sha_known_vectors() {
    ShaOptions opts;
    opts.variant = ShaVariant::SHA256;
    String sha256 = ESPCrypto::shaHex(reinterpret_cast<const uint8_t *>("abc"), 3, opts);
    TEST_ASSERT_EQUAL_STRING("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                             sha256.c_str());
    opts.variant = ShaVariant::SHA384;
    String sha384 = ESPCrypto::shaHex(reinterpret_cast<const uint8_t *>("abc"), 3, opts);
    TEST_ASSERT_EQUAL_STRING("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
                             sha384.c_str());
    opts.variant = ShaVariant::SHA512;
    String sha512 = ESPCrypto::shaHex(reinterpret_cast<const uint8_t *>("abc"), 3, opts);
    TEST_ASSERT_EQUAL_STRING("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                             sha512.c_str());
}

void test_aes_gcm_known_vector() {
    std::vector<uint8_t> key(16, 0x00);
    std::vector<uint8_t> iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::vector<uint8_t> plaintext(16, 0x00);
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
    TEST_ASSERT_TRUE(ESPCrypto::aesGcmEncrypt(key, iv, plaintext, ciphertext, tag));
    const uint8_t expectedCipher[] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                      0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
    const uint8_t expectedTag[] = {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                   0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(ciphertext, std::vector<uint8_t>(expectedCipher, expectedCipher + sizeof(expectedCipher))));
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(tag, std::vector<uint8_t>(expectedTag, expectedTag + sizeof(expectedTag))));

    auto decrypted = ESPCrypto::aesGcmDecrypt(key, iv, ciphertext, tag);
    TEST_ASSERT_TRUE_MESSAGE(decrypted.ok(), decrypted.status.message.c_str());
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(plaintext, decrypted.value));
}

void test_aes_gcm_auto_iv_roundtrip() {
    std::vector<uint8_t> key(16, 0x01);
    std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto enc = ESPCrypto::aesGcmEncryptAuto(key, plaintext);
    TEST_ASSERT_TRUE_MESSAGE(enc.ok(), enc.status.message.c_str());
    TEST_ASSERT_EQUAL_UINT32(12, enc.value.iv.size());
    auto dec = ESPCrypto::aesGcmDecrypt(key, enc.value.iv, enc.value.ciphertext, enc.value.tag);
    TEST_ASSERT_TRUE_MESSAGE(dec.ok(), dec.status.message.c_str());
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(plaintext, dec.value));
}

void test_hkdf_rfc5869_case1() {
    std::vector<uint8_t> ikm(22, 0x0b);
    std::vector<uint8_t> salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    std::vector<uint8_t> info = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    auto okm = ESPCrypto::hkdf(ShaVariant::SHA256, CryptoSpan<const uint8_t>(salt), CryptoSpan<const uint8_t>(ikm), CryptoSpan<const uint8_t>(info), 42);
    TEST_ASSERT_TRUE_MESSAGE(okm.ok(), okm.status.message.c_str());
    const uint8_t expected[] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
    TEST_ASSERT_EQUAL(sizeof(expected), okm.value.size());
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(okm.value, std::vector<uint8_t>(expected, expected + sizeof(expected))));
}

void test_pbkdf2_vector() {
    std::vector<uint8_t> salt = {'s', 'a', 'l', 't'};
    auto derived = ESPCrypto::pbkdf2("password", CryptoSpan<const uint8_t>(salt), 1024, 32);
    TEST_ASSERT_TRUE_MESSAGE(derived.ok(), derived.status.message.c_str());
    const uint8_t expected[] = {0x23, 0x1a, 0xfb, 0x7d, 0xcd, 0x2e, 0x86, 0x0c, 0xfd, 0x58, 0xab, 0x13, 0x37, 0x2b, 0xd1, 0x2c,
                                0x92, 0x30, 0x76, 0xc3, 0x59, 0x8a, 0x12, 0x19, 0x60, 0x32, 0x0f, 0x6f, 0xec, 0x8a, 0x56, 0x98};
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(derived.value, std::vector<uint8_t>(expected, expected + sizeof(expected))));
}

void test_jwt_roundtrip_hs256() {
    JsonDocument claims;
    claims["scope"] = "demo";
    JwtSignOptions signOptions;
    signOptions.algorithm = JwtAlgorithm::HS256;
    signOptions.issuer = "unity";
    signOptions.expiresInSeconds = 15;
    String token = ESPCrypto::createJwt(claims, "secret", signOptions);
    TEST_ASSERT_TRUE(token.length() > 0);

    JsonDocument decoded;
    String error;
    JwtVerifyOptions verifyOptions;
    verifyOptions.algorithm = JwtAlgorithm::HS256;
    verifyOptions.issuer = "unity";
    TEST_ASSERT_TRUE_MESSAGE(ESPCrypto::verifyJwt(token, "secret", decoded, error, verifyOptions), error.c_str());
    TEST_ASSERT_EQUAL_STRING("demo", decoded["scope"].as<const char *>());
}

void test_sha_ctx_streaming() {
    ShaCtx ctx;
    TEST_ASSERT_TRUE(ctx.begin(ShaVariant::SHA256).ok());
    const char *chunk1 = "ab";
    const char *chunk2 = "c";
    TEST_ASSERT_TRUE(ctx.update(CryptoSpan<const uint8_t>(reinterpret_cast<const uint8_t *>(chunk1), 2)).ok());
    TEST_ASSERT_TRUE(ctx.update(CryptoSpan<const uint8_t>(reinterpret_cast<const uint8_t *>(chunk2), 1)).ok());
    std::vector<uint8_t> out(32, 0);
    TEST_ASSERT_TRUE(ctx.finish(CryptoSpan<uint8_t>(out)).ok());
    const uint8_t expected[] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(out, std::vector<uint8_t>(expected, expected + sizeof(expected))));
}

void test_sha_ctx_rebegin_reuses_context() {
    ShaCtx ctx;
    const char *input = "abc";

    std::vector<uint8_t> sha256(32, 0);
    TEST_ASSERT_TRUE(ctx.begin(ShaVariant::SHA256).ok());
    TEST_ASSERT_TRUE(ctx.update(CryptoSpan<const uint8_t>(reinterpret_cast<const uint8_t *>(input), 3)).ok());
    TEST_ASSERT_TRUE(ctx.finish(CryptoSpan<uint8_t>(sha256)).ok());

    std::vector<uint8_t> sha512(64, 0);
    TEST_ASSERT_TRUE(ctx.begin(ShaVariant::SHA512).ok());
    TEST_ASSERT_TRUE(ctx.update(CryptoSpan<const uint8_t>(reinterpret_cast<const uint8_t *>(input), 3)).ok());
    TEST_ASSERT_TRUE(ctx.finish(CryptoSpan<uint8_t>(sha512)).ok());

    const uint8_t expectedSha256[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    const uint8_t expectedSha512[] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(sha256, std::vector<uint8_t>(expectedSha256, expectedSha256 + sizeof(expectedSha256))));
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(sha512, std::vector<uint8_t>(expectedSha512, expectedSha512 + sizeof(expectedSha512))));
}

void test_hmac_ctx_rebegin_reuses_context() {
    HmacCtx ctx;
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> msg = {'a', 'b', 'c'};

    std::vector<uint8_t> out1(32, 0);
    TEST_ASSERT_TRUE(ctx.begin(ShaVariant::SHA256, CryptoSpan<const uint8_t>(key)).ok());
    TEST_ASSERT_TRUE(ctx.update(CryptoSpan<const uint8_t>(msg)).ok());
    TEST_ASSERT_TRUE(ctx.finish(CryptoSpan<uint8_t>(out1)).ok());

    std::vector<uint8_t> out2(32, 0);
    TEST_ASSERT_TRUE(ctx.begin(ShaVariant::SHA256, CryptoSpan<const uint8_t>(key)).ok());
    TEST_ASSERT_TRUE(ctx.update(CryptoSpan<const uint8_t>(msg)).ok());
    TEST_ASSERT_TRUE(ctx.finish(CryptoSpan<uint8_t>(out2)).ok());

    auto oneShot = ESPCrypto::hmac(ShaVariant::SHA256, CryptoSpan<const uint8_t>(key), CryptoSpan<const uint8_t>(msg));
    TEST_ASSERT_TRUE(oneShot.ok());
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(out1, oneShot.value));
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(out2, oneShot.value));
}

void test_aes_ctr_stream_roundtrip() {
    std::vector<uint8_t> key(16, 0x00);
    std::vector<uint8_t> nonce(16, 0x01);
    std::vector<uint8_t> plaintext = {0x10, 0x20, 0x30, 0x40};
    std::vector<uint8_t> ciphertext(plaintext.size(), 0);
    std::vector<uint8_t> decrypted(plaintext.size(), 0);

    AesCtrStream enc;
    TEST_ASSERT_TRUE(enc.begin(key, CryptoSpan<const uint8_t>(nonce)).ok());
    TEST_ASSERT_TRUE(enc.update(CryptoSpan<const uint8_t>(plaintext), CryptoSpan<uint8_t>(ciphertext)).ok());

    AesCtrStream dec;
    TEST_ASSERT_TRUE(dec.begin(key, CryptoSpan<const uint8_t>(nonce)).ok());
    TEST_ASSERT_TRUE(dec.update(CryptoSpan<const uint8_t>(ciphertext), CryptoSpan<uint8_t>(decrypted)).ok());
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(plaintext, decrypted));
}

void test_aes_gcm_ctx_roundtrip() {
    std::vector<uint8_t> key(16, 0x33);
    std::vector<uint8_t> iv(12, 0x44);
    std::vector<uint8_t> aad = {0x01, 0x02};
    std::vector<uint8_t> plaintext = {0x0A, 0x0B, 0x0C, 0x0D};
    std::vector<uint8_t> ciphertext(plaintext.size(), 0);
    std::vector<uint8_t> tag(16, 0);

    AesGcmCtx enc;
    TEST_ASSERT_TRUE(enc.beginEncrypt(key, CryptoSpan<const uint8_t>(iv), CryptoSpan<const uint8_t>(aad)).ok());
    TEST_ASSERT_TRUE(enc.update(CryptoSpan<const uint8_t>(plaintext), CryptoSpan<uint8_t>(ciphertext)).ok());
    TEST_ASSERT_TRUE(enc.finish(CryptoSpan<uint8_t>(tag)).ok());

    std::vector<uint8_t> decrypted(plaintext.size(), 0);
    AesGcmCtx dec;
    TEST_ASSERT_TRUE(dec.beginDecrypt(key, CryptoSpan<const uint8_t>(iv), CryptoSpan<const uint8_t>(aad), CryptoSpan<const uint8_t>(tag)).ok());
    TEST_ASSERT_TRUE(dec.update(CryptoSpan<const uint8_t>(ciphertext), CryptoSpan<uint8_t>(decrypted)).ok());
    TEST_ASSERT_TRUE(dec.finish(CryptoSpan<uint8_t>(tag)).ok());
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(plaintext, decrypted));
}

void test_gcm_nonce_strategy_counter() {
    std::vector<uint8_t> key(16, 0x55);
    std::vector<uint8_t> plaintext = {0xAA, 0xBB};
    GcmNonceOptions opts;
    opts.strategy = GcmNonceStrategy::Counter64_Random32;
    auto first = ESPCrypto::aesGcmEncryptAuto(key, plaintext, {}, 12, opts);
    auto second = ESPCrypto::aesGcmEncryptAuto(key, plaintext, {}, 12, opts);
    TEST_ASSERT_TRUE(first.ok());
    TEST_ASSERT_TRUE(second.ok());
    TEST_ASSERT_EQUAL_UINT32(12, first.value.iv.size());
    TEST_ASSERT_EQUAL_UINT32(12, second.value.iv.size());
    TEST_ASSERT_FALSE(ESPCrypto::constantTimeEq(first.value.iv, second.value.iv));
}

void test_chacha20poly1305_roundtrip() {
    std::vector<uint8_t> key(32, 0x01);
    std::vector<uint8_t> nonce(12, 0x02);
    std::vector<uint8_t> aad = {0x03, 0x04};
    std::vector<uint8_t> plaintext = {0x10, 0x20, 0x30};
    auto enc = ESPCrypto::chacha20Poly1305Encrypt(CryptoSpan<const uint8_t>(key),
                                                  CryptoSpan<const uint8_t>(nonce),
                                                  CryptoSpan<const uint8_t>(aad),
                                                  CryptoSpan<const uint8_t>(plaintext));
    TEST_ASSERT_TRUE_MESSAGE(enc.ok(), enc.status.message.c_str());
    auto dec = ESPCrypto::chacha20Poly1305Decrypt(CryptoSpan<const uint8_t>(key),
                                                  CryptoSpan<const uint8_t>(nonce),
                                                  CryptoSpan<const uint8_t>(aad),
                                                  CryptoSpan<const uint8_t>(enc.value));
    TEST_ASSERT_TRUE_MESSAGE(dec.ok(), dec.status.message.c_str());
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(plaintext, dec.value));
}

void test_ecdsa_raw_der_roundtrip() {
    std::vector<uint8_t> raw(64, 0);
    for (size_t i = 0; i < raw.size(); ++i) raw[i] = static_cast<uint8_t>(i + 1);
    auto der = ESPCrypto::ecdsaRawToDer(CryptoSpan<const uint8_t>(raw));
    TEST_ASSERT_TRUE_MESSAGE(der.ok(), der.status.message.c_str());
    auto rawBack = ESPCrypto::ecdsaDerToRaw(CryptoSpan<const uint8_t>(der.value));
    TEST_ASSERT_TRUE_MESSAGE(rawBack.ok(), rawBack.status.message.c_str());
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(raw, rawBack.value));
}

void test_aes_gcm_span_roundtrip() {
    std::vector<uint8_t> key(16, 0x11);
    std::vector<uint8_t> iv(12, 0x22);
    std::vector<uint8_t> plaintext = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<uint8_t> ciphertext(plaintext.size(), 0);
    std::vector<uint8_t> tag(16, 0);

    auto enc = ESPCrypto::aesGcmEncrypt(key,
                                        CryptoSpan<const uint8_t>(iv),
                                        CryptoSpan<const uint8_t>(plaintext),
                                        CryptoSpan<uint8_t>(ciphertext),
                                        CryptoSpan<uint8_t>(tag));
    TEST_ASSERT_TRUE_MESSAGE(enc.ok(), enc.status.message.c_str());

    std::vector<uint8_t> decrypted(plaintext.size(), 0);
    auto dec = ESPCrypto::aesGcmDecrypt(key,
                                        CryptoSpan<const uint8_t>(iv),
                                        CryptoSpan<const uint8_t>(ciphertext),
                                        CryptoSpan<const uint8_t>(tag),
                                        CryptoSpan<uint8_t>(decrypted));
    TEST_ASSERT_TRUE_MESSAGE(dec.ok(), dec.status.message.c_str());
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(plaintext, decrypted));
}

void test_device_key_is_stable() {
    auto first = ESPCrypto::deriveDeviceKey("unity-device-key", CryptoSpan<const uint8_t>(), 32);
    auto second = ESPCrypto::deriveDeviceKey("unity-device-key", CryptoSpan<const uint8_t>(), 32);
    TEST_ASSERT_TRUE_MESSAGE(first.ok(), first.status.message.c_str());
    TEST_ASSERT_TRUE_MESSAGE(second.ok(), second.status.message.c_str());
    TEST_ASSERT_EQUAL_UINT32(32, first.value.size());
    TEST_ASSERT_TRUE(ESPCrypto::constantTimeEq(first.value, second.value));
}

void test_jwt_and_envelope_fuzz() {
    const char *badTokens[] = {"", "abc", "a.b", "a.b.c", "e30=.e30=.@@@@", "eyJhbGciOiJIUzI1NiJ9.e30.bad"};
    JsonDocument out;
    String err;
    JwtVerifyOptions opts;
    opts.algorithm = JwtAlgorithm::HS256;
    for (auto t : badTokens) {
        TEST_ASSERT_FALSE(ESPCrypto::verifyJwt(String(t), "secret", out, err, opts));
    }
    TEST_ASSERT_FALSE(ESPCrypto::verifyString("pw", "$esphash$v1$bad$bad$bad"));
}

void test_jwks_verification() {
    // Build HS256 token and JWKS with oct key
    JsonDocument claims;
    claims["iss"] = "jwks";
    JwtSignOptions signOpts;
    signOpts.algorithm = JwtAlgorithm::HS256;
    signOpts.expiresInSeconds = 60;
    signOpts.keyId = "k1";
    String token = ESPCrypto::createJwt(claims, "supersecret", signOpts);
    JsonDocument jwks;
    JsonArray keys = jwks["keys"].to<JsonArray>();
    JsonObject k = keys.add<JsonObject>();
    k["kty"] = "oct";
    k["kid"] = "k1";
    k["k"] = "c3VwZXJzZWNyZXQ"; // base64url("supersecret")
    JsonDocument decoded;
    auto res = ESPCrypto::verifyJwtWithJwks(token, jwks, decoded);
    TEST_ASSERT_TRUE_MESSAGE(res.ok(), res.status.message.c_str());
    TEST_ASSERT_EQUAL_STRING("jwks", decoded["iss"].as<const char *>());
}
void setUp() {}
void tearDown() {}

void setup() {
    delay(2000);
    UNITY_BEGIN();
    RUN_TEST(test_teardown_preinit_and_idempotent);
    RUN_TEST(test_teardown_reinit_lifecycle);
    RUN_TEST(test_sha_hex_matches_known_value);
    RUN_TEST(test_sha_known_vectors);
    RUN_TEST(test_sha_ctx_streaming);
    RUN_TEST(test_sha_ctx_rebegin_reuses_context);
    RUN_TEST(test_hmac_ctx_rebegin_reuses_context);
    RUN_TEST(test_password_hash_roundtrip);
    RUN_TEST(test_aes_gcm_known_vector);
    RUN_TEST(test_aes_gcm_auto_iv_roundtrip);
    RUN_TEST(test_aes_gcm_span_roundtrip);
    RUN_TEST(test_aes_ctr_stream_roundtrip);
    RUN_TEST(test_aes_gcm_ctx_roundtrip);
    RUN_TEST(test_gcm_nonce_strategy_counter);
    RUN_TEST(test_chacha20poly1305_roundtrip);
    RUN_TEST(test_ecdsa_raw_der_roundtrip);
    RUN_TEST(test_hkdf_rfc5869_case1);
    RUN_TEST(test_pbkdf2_vector);
    RUN_TEST(test_jwt_roundtrip_hs256);
    RUN_TEST(test_jwt_and_envelope_fuzz);
    RUN_TEST(test_device_key_is_stable);
    UNITY_END();
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}
