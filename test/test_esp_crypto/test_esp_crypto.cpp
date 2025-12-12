#include <Arduino.h>
#include <ESPCrypto.h>
#include <unity.h>
#include <cstring>
#include <vector>

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

void setUp() {}
void tearDown() {}

void setup() {
    delay(2000);
    UNITY_BEGIN();
    RUN_TEST(test_sha_hex_matches_known_value);
    RUN_TEST(test_sha_known_vectors);
    RUN_TEST(test_password_hash_roundtrip);
    RUN_TEST(test_aes_gcm_known_vector);
    RUN_TEST(test_aes_gcm_auto_iv_roundtrip);
    RUN_TEST(test_hkdf_rfc5869_case1);
    RUN_TEST(test_pbkdf2_vector);
    RUN_TEST(test_jwt_roundtrip_hs256);
    UNITY_END();
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}
