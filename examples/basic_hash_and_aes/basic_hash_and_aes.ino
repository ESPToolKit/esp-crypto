#include <Arduino.h>
#include <ESPCrypto.h>

#include <string>
#include <vector>

namespace {
std::string bytesToHex(const std::vector<uint8_t> &bytes) {
	static const char *hexDigits = "0123456789abcdef";
	std::string out;
	out.reserve(bytes.size() * 2);
	for (uint8_t b : bytes) {
		out.push_back(hexDigits[(b >> 4) & 0x0F]);
		out.push_back(hexDigits[b & 0x0F]);
	}
	return out;
}
} // namespace

void setup() {
	Serial.begin(115200);
	delay(1000);

	std::string message = "ESPCrypto";
	std::string digest = espcrypto::hash::shaHex(message);
	Serial.printf("SHA-256(%s) = %s\n", message.c_str(), digest.c_str());

	std::vector<uint8_t> key(32, 0x11);
	std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};
	auto encrypted = espcrypto::symmetric::aesGcmEncryptAuto(key, plaintext);
	if (!encrypted.ok()) {
		Serial.printf("encrypt failed: %s\n", encrypted.status.message.c_str());
		espcrypto::runtime::deinit();
		return;
	}

	Serial.printf("IV  : %s\n", bytesToHex(encrypted.value.iv).c_str());
	Serial.printf("TAG : %s\n", bytesToHex(encrypted.value.tag).c_str());

	auto decrypted = espcrypto::symmetric::aesGcmDecrypt(
	    key,
	    encrypted.value.iv,
	    encrypted.value.ciphertext,
	    encrypted.value.tag
	);
	if (!decrypted.ok()) {
		Serial.printf("decrypt failed: %s\n", decrypted.status.message.c_str());
		espcrypto::runtime::deinit();
		return;
	}

	std::string clear(reinterpret_cast<const char *>(decrypted.value.data()), decrypted.value.size());
	Serial.printf("Plaintext recovered: %s\n", clear.c_str());
	espcrypto::runtime::deinit();
}

void loop() {
}
