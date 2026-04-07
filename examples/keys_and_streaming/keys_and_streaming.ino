#include <Arduino.h>
#include <ESPCrypto.h>

#include <string>
#include <vector>

namespace {
const char *statusText(const CryptoStatusDetail &status) {
	return status.message.empty() ? toString(status.code) : status.message.c_str();
}
} // namespace

void setup() {
	Serial.begin(115200);
	delay(1000);

	MemoryKeyStore memoryStore;
	KeyHandle handle{"demo-key", 1};
	std::vector<uint8_t> rawKey(32, 0x44);

	auto stored = espcrypto::keystore::store(
	    memoryStore,
	    handle,
	    CryptoSpan<const uint8_t>(rawKey)
	);
	Serial.printf("store key: %s\n", stored.ok() ? "ok" : statusText(stored.status));

	auto loaded = espcrypto::keystore::load(memoryStore, handle, KeyFormat::Raw, KeyKind::Symmetric);
	Serial.printf("load key: %s\n", loaded.ok() ? "ok" : statusText(loaded.status));

	ShaCtx sha;
	uint8_t digest[32] = {0};
	sha.begin(ShaVariant::SHA256);
	sha.update(CryptoSpan<const uint8_t>(reinterpret_cast<const uint8_t *>("hello"), 5));
	sha.update(CryptoSpan<const uint8_t>(reinterpret_cast<const uint8_t *>(" world"), 6));
	sha.finish(CryptoSpan<uint8_t>(digest, sizeof(digest)));
	Serial.println("streaming sha complete");

	std::vector<uint8_t> aesKey(16, 0x33);
	std::vector<uint8_t> iv(12, 0x11);
	std::vector<uint8_t> aad = {'a', 'a', 'd'};
	std::vector<uint8_t> plaintext = {'c', 'h', 'u', 'n', 'k'};
	std::vector<uint8_t> ciphertext(plaintext.size(), 0);
	std::vector<uint8_t> tag(16, 0);
	std::vector<uint8_t> decrypted(plaintext.size(), 0);

	AesGcmCtx enc;
	AesGcmCtx dec;
	auto encStart = enc.beginEncrypt(aesKey, CryptoSpan<const uint8_t>(iv), CryptoSpan<const uint8_t>(aad));
	auto encUpdate = enc.update(CryptoSpan<const uint8_t>(plaintext), CryptoSpan<uint8_t>(ciphertext));
	auto encFinish = enc.finish(CryptoSpan<uint8_t>(tag));
	auto decStart = dec.beginDecrypt(
	    aesKey,
	    CryptoSpan<const uint8_t>(iv),
	    CryptoSpan<const uint8_t>(aad),
	    CryptoSpan<const uint8_t>(tag)
	);
	auto decUpdate = dec.update(CryptoSpan<const uint8_t>(ciphertext), CryptoSpan<uint8_t>(decrypted));
	auto decFinish = dec.finish(CryptoSpan<uint8_t>(tag));

	Serial.printf(
	    "streaming gcm: %s\n",
	    (encStart.ok() && encUpdate.ok() && encFinish.ok() && decStart.ok() && decUpdate.ok() &&
	     decFinish.ok() && espcrypto::runtime::constantTimeEq(plaintext, decrypted))
	        ? "ok"
	        : "failed"
	);

	GcmNonceOptions nonceOptions;
	nonceOptions.strategy = GcmNonceStrategy::Counter64_Random32;
	auto message = espcrypto::symmetric::aesGcmEncryptAuto(aesKey, plaintext, {}, 12, nonceOptions);
	Serial.printf("auto nonce encrypt: %s\n", message.ok() ? "ok" : statusText(message.status));

	auto deviceKey = espcrypto::device::deriveKey("example", CryptoSpan<const uint8_t>(), 32);
	Serial.printf("device key: %s\n", deviceKey.ok() ? "ok" : statusText(deviceKey.status));
}

void loop() {
}
