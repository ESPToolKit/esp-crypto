#include <Arduino.h>
#include <ESPCrypto.h>
#include <cstring>
#include <string>
#include <unity.h>
#include <vector>

namespace {
const char *statusMessage(const CryptoStatusDetail &status) {
	return status.message.empty() ? toString(status.code) : status.message.c_str();
}

void test_runtime_lifecycle_and_policy_reset() {
	espcrypto::runtime::deinit();
	TEST_ASSERT_FALSE(espcrypto::runtime::isInitialized());

	CryptoPolicy policy = espcrypto::policy::get();
	policy.minPbkdf2Iterations = 1024;
	espcrypto::policy::set(policy);
	TEST_ASSERT_TRUE(espcrypto::runtime::isInitialized());
	TEST_ASSERT_EQUAL_UINT32(1024, espcrypto::policy::get().minPbkdf2Iterations);

	espcrypto::runtime::deinit();
	TEST_ASSERT_FALSE(espcrypto::runtime::isInitialized());
	TEST_ASSERT_EQUAL_UINT32(100000, espcrypto::policy::get().minPbkdf2Iterations);
}

void test_sha_hex_matches_known_value() {
	auto digest = espcrypto::hash::shaHex("hello world");
	TEST_ASSERT_EQUAL_STRING(
	    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
	    digest.c_str()
	);
}

void test_password_hash_roundtrip_v2() {
	auto hashed = espcrypto::password::hash("hunter2");
	TEST_ASSERT_TRUE_MESSAGE(hashed.ok(), statusMessage(hashed.status));
	TEST_ASSERT_TRUE_MESSAGE(
	    espcrypto::password::verify("hunter2", hashed.value).ok(),
	    "expected password verify success"
	);
	auto rejected = espcrypto::password::verify("badpass", hashed.value);
	TEST_ASSERT_FALSE(rejected.ok());
	TEST_ASSERT_EQUAL_INT(
	    static_cast<int>(CryptoStatus::VerifyFailed),
	    static_cast<int>(rejected.status.code)
	);
}

void test_password_legacy_envelopes_require_explicit_compat() {
	std::string legacy = "$esphash$v1$10$AQ==$AQ==";
	auto rejected = espcrypto::password::verify("pw", legacy);
	TEST_ASSERT_FALSE(rejected.ok());
	TEST_ASSERT_EQUAL_INT(
	    static_cast<int>(CryptoStatus::PolicyViolation),
	    static_cast<int>(rejected.status.code)
	);

	PasswordVerifyOptions compat;
	compat.allowLegacy = true;
	auto compatRes = espcrypto::password::verify("pw", legacy, compat);
	TEST_ASSERT_FALSE(compatRes.ok());
	TEST_ASSERT_NOT_EQUAL(
	    static_cast<int>(CryptoStatus::PolicyViolation),
	    static_cast<int>(compatRes.status.code)
	);
}

void test_aes_gcm_known_vector() {
	std::vector<uint8_t> key(16, 0x00);
	std::vector<uint8_t> iv(12, 0x00);
	std::vector<uint8_t> plaintext(16, 0x00);
	std::vector<uint8_t> ciphertext(plaintext.size(), 0);
	std::vector<uint8_t> tag(16, 0);

	auto enc = espcrypto::symmetric::aesGcmEncrypt(
	    key,
	    CryptoSpan<const uint8_t>(iv),
	    CryptoSpan<const uint8_t>(plaintext),
	    CryptoSpan<uint8_t>(ciphertext),
	    CryptoSpan<uint8_t>(tag)
	);
	TEST_ASSERT_TRUE_MESSAGE(enc.ok(), statusMessage(enc.status));

	const uint8_t expectedCipher[] = {
	    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
	    0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
	};
	const uint8_t expectedTag[] = {
	    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
	    0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
	};
	TEST_ASSERT_TRUE(
	    espcrypto::runtime::constantTimeEq(
	        ciphertext,
	        std::vector<uint8_t>(expectedCipher, expectedCipher + sizeof(expectedCipher))
	    )
	);
	TEST_ASSERT_TRUE(
	    espcrypto::runtime::constantTimeEq(
	        tag,
	        std::vector<uint8_t>(expectedTag, expectedTag + sizeof(expectedTag))
	    )
	);

	auto dec = espcrypto::symmetric::aesGcmDecrypt(key, iv, ciphertext, tag);
	TEST_ASSERT_TRUE_MESSAGE(dec.ok(), statusMessage(dec.status));
	TEST_ASSERT_TRUE(espcrypto::runtime::constantTimeEq(plaintext, dec.value));
}

void test_hkdf_and_pbkdf2() {
	CryptoPolicy policy = espcrypto::policy::get();
	policy.minPbkdf2Iterations = 1024;
	espcrypto::policy::set(policy);

	std::vector<uint8_t> ikm(22, 0x0b);
	std::vector<uint8_t> salt =
	    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
	std::vector<uint8_t> info = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
	auto hkdf = espcrypto::kdf::hkdf(
	    ShaVariant::SHA256,
	    CryptoSpan<const uint8_t>(salt),
	    CryptoSpan<const uint8_t>(ikm),
	    CryptoSpan<const uint8_t>(info),
	    42
	);
	TEST_ASSERT_TRUE_MESSAGE(hkdf.ok(), statusMessage(hkdf.status));
	TEST_ASSERT_EQUAL_UINT32(42, hkdf.value.size());

	std::vector<uint8_t> pbkdfSalt = {'s', 'a', 'l', 't'};
	auto pbkdf2 =
	    espcrypto::kdf::pbkdf2("password", CryptoSpan<const uint8_t>(pbkdfSalt), 1024, 32);
	TEST_ASSERT_TRUE_MESSAGE(pbkdf2.ok(), statusMessage(pbkdf2.status));
	TEST_ASSERT_EQUAL_UINT32(32, pbkdf2.value.size());
}

void test_jwt_roundtrip_hs256() {
	JsonDocument claims;
	claims["scope"] = "demo";

	JwtSignOptions signOptions;
	signOptions.algorithm = JwtAlgorithm::HS256;
	signOptions.issuer = "unity";
	signOptions.expiresInSeconds = 15;

	auto token = espcrypto::jwt::create(claims, "secret", signOptions);
	TEST_ASSERT_TRUE_MESSAGE(token.ok(), statusMessage(token.status));

	JsonDocument decoded;
	JwtVerifyOptions verifyOptions;
	verifyOptions.algorithm = JwtAlgorithm::HS256;
	verifyOptions.issuer = "unity";

	auto verified = espcrypto::jwt::verify(token.value, "secret", decoded, verifyOptions);
	TEST_ASSERT_TRUE_MESSAGE(verified.ok(), statusMessage(verified.status));
	TEST_ASSERT_EQUAL_STRING("demo", decoded["scope"].as<const char *>());
}

void test_jwks_verification() {
	JsonDocument claims;
	claims["scope"] = "rotation";

	JwtSignOptions signOptions;
	signOptions.algorithm = JwtAlgorithm::HS256;
	signOptions.keyId = "primary";
	signOptions.issuer = "jwks";

	auto token = espcrypto::jwt::create(claims, "supersecret", signOptions);
	TEST_ASSERT_TRUE_MESSAGE(token.ok(), statusMessage(token.status));

	JsonDocument jwks;
	JsonArray keys = jwks["keys"].to<JsonArray>();
	JsonObject key = keys.add<JsonObject>();
	key["kid"] = "primary";
	key["kty"] = "oct";
	key["alg"] = "HS256";
	key["k"] = "c3VwZXJzZWNyZXQ";

	JsonDocument decoded;
	JwtVerifyOptions verifyOptions;
	verifyOptions.algorithm = JwtAlgorithm::HS256;
	verifyOptions.issuer = "jwks";

	auto verified = espcrypto::jwt::verifyWithJwks(token.value, jwks, decoded, verifyOptions);
	TEST_ASSERT_TRUE_MESSAGE(verified.ok(), statusMessage(verified.status));
	TEST_ASSERT_EQUAL_STRING("rotation", decoded["scope"].as<const char *>());
}

void test_streaming_and_device_key_helpers() {
	const char *chunk1 = "ab";
	const char *chunk2 = "c";
	uint8_t digest[32] = {0};
	ShaCtx sha;
	TEST_ASSERT_TRUE(sha.begin(ShaVariant::SHA256).ok());
	TEST_ASSERT_TRUE(
	    sha.update(
	           CryptoSpan<const uint8_t>(
	               reinterpret_cast<const uint8_t *>(chunk1),
	               strlen(chunk1)
	           )
	       )
	        .ok()
	);
	TEST_ASSERT_TRUE(
	    sha.update(
	           CryptoSpan<const uint8_t>(
	               reinterpret_cast<const uint8_t *>(chunk2),
	               strlen(chunk2)
	           )
	       )
	        .ok()
	);
	TEST_ASSERT_TRUE(sha.finish(CryptoSpan<uint8_t>(digest, sizeof(digest))).ok());

	std::vector<uint8_t> key(16, 0x33);
	std::vector<uint8_t> counter(16, 0x00);
	std::vector<uint8_t> input = {'s', 't', 'r', 'e', 'a', 'm'};
	std::vector<uint8_t> encrypted(input.size(), 0);
	std::vector<uint8_t> decrypted(input.size(), 0);
	AesCtrStream enc;
	AesCtrStream dec;
	TEST_ASSERT_TRUE(enc.begin(key, CryptoSpan<const uint8_t>(counter)).ok());
	TEST_ASSERT_TRUE(dec.begin(key, CryptoSpan<const uint8_t>(counter)).ok());
	TEST_ASSERT_TRUE(
	    enc.update(
	           CryptoSpan<const uint8_t>(input),
	           CryptoSpan<uint8_t>(encrypted)
	       )
	        .ok()
	);
	TEST_ASSERT_TRUE(
	    dec.update(
	           CryptoSpan<const uint8_t>(encrypted),
	           CryptoSpan<uint8_t>(decrypted)
	       )
	        .ok()
	);
	TEST_ASSERT_TRUE(espcrypto::runtime::constantTimeEq(input, decrypted));

	auto first = espcrypto::device::deriveKey("unity-device-key", CryptoSpan<const uint8_t>(), 32);
	auto second = espcrypto::device::deriveKey("unity-device-key", CryptoSpan<const uint8_t>(), 32);
	TEST_ASSERT_TRUE_MESSAGE(first.ok(), statusMessage(first.status));
	TEST_ASSERT_TRUE_MESSAGE(second.ok(), statusMessage(second.status));
	TEST_ASSERT_TRUE(espcrypto::runtime::constantTimeEq(first.value, second.value));
}
} // namespace

void setup() {
	delay(1000);
	UNITY_BEGIN();
	RUN_TEST(test_runtime_lifecycle_and_policy_reset);
	RUN_TEST(test_sha_hex_matches_known_value);
	RUN_TEST(test_password_hash_roundtrip_v2);
	RUN_TEST(test_password_legacy_envelopes_require_explicit_compat);
	RUN_TEST(test_aes_gcm_known_vector);
	RUN_TEST(test_hkdf_and_pbkdf2);
	RUN_TEST(test_jwt_roundtrip_hs256);
	RUN_TEST(test_jwks_verification);
	RUN_TEST(test_streaming_and_device_key_helpers);
	UNITY_END();
}

void loop() {
}
