#include <Arduino.h>
#include <ESPCrypto.h>
#include <unity.h>
#include <cstring>

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
    RUN_TEST(test_password_hash_roundtrip);
    RUN_TEST(test_jwt_roundtrip_hs256);
    UNITY_END();
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}
