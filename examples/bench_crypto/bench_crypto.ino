#include <Arduino.h>
#include <ESPCrypto.h>

#include <vector>

void setup() {
	Serial.begin(115200);
	delay(1000);

	std::vector<uint8_t> data(256, 0x5A);
	uint8_t digest[32] = {0};
	uint32_t started = millis();
	for (int i = 0; i < 100; ++i) {
		espcrypto::hash::sha(CryptoSpan<const uint8_t>(data), CryptoSpan<uint8_t>(digest, sizeof(digest)));
	}
	Serial.printf("100 sha rounds: %lu ms\n", static_cast<unsigned long>(millis() - started));

	std::vector<uint8_t> key(16, 0x11);
	std::vector<uint8_t> iv(12, 0x22);
	std::vector<uint8_t> ciphertext(data.size(), 0);
	std::vector<uint8_t> tag(16, 0);
	started = millis();
	for (int i = 0; i < 50; ++i) {
		espcrypto::symmetric::aesGcmEncrypt(
		    key,
		    CryptoSpan<const uint8_t>(iv),
		    CryptoSpan<const uint8_t>(data),
		    CryptoSpan<uint8_t>(ciphertext),
		    CryptoSpan<uint8_t>(tag)
		);
	}
	Serial.printf("50 aes-gcm rounds: %lu ms\n", static_cast<unsigned long>(millis() - started));
}

void loop() {
}
