#include <Arduino.h>
#include <ESPCrypto.h>

#include <string>
#include <vector>

namespace {
std::string bytesToHex(const std::vector<uint8_t> &bytes) {
	static const char *HEX = "0123456789abcdef";
	std::string out;
	out.reserve(bytes.size() * 2);
	for (uint8_t b : bytes) {
		out.push_back(HEX[(b >> 4) & 0x0F]);
		out.push_back(HEX[b & 0x0F]);
	}
	return out;
}

const char *statusText(const CryptoStatusDetail &status) {
	return status.message.empty() ? toString(status.code) : status.message.c_str();
}
} // namespace

void setup() {
	Serial.begin(115200);
	delay(1000);

	CryptoCaps caps = espcrypto::runtime::caps();
	Serial.printf("caps: sha=%d aes=%d gcm=%d\n", caps.shaAccel, caps.aesAccel, caps.aesGcmAccel);

	CryptoPolicy policy = espcrypto::policy::get();
	policy.minPbkdf2Iterations = 100000;
	espcrypto::policy::set(policy);

	std::vector<uint8_t> key = {0x6b, 0x65, 0x79};
	std::vector<uint8_t> msg = {'d', 'a', 't', 'a'};
	auto hmac = espcrypto::kdf::hmac(
	    ShaVariant::SHA256,
	    CryptoSpan<const uint8_t>(key),
	    CryptoSpan<const uint8_t>(msg)
	);
	Serial.printf("hmac: %s\n", hmac.ok() ? bytesToHex(hmac.value).c_str() : statusText(hmac.status));

	auto hkdf = espcrypto::kdf::hkdf(
	    ShaVariant::SHA256,
	    CryptoSpan<const uint8_t>(key),
	    CryptoSpan<const uint8_t>(msg),
	    CryptoSpan<const uint8_t>(),
	    32
	);
	Serial.printf("hkdf: %s\n", hkdf.ok() ? bytesToHex(hkdf.value).c_str() : statusText(hkdf.status));

	auto calibrated = espcrypto::password::calibrateIterations();
	Serial.printf(
	    "calibrated iterations: %lu\n",
	    calibrated.ok() ? static_cast<unsigned long>(calibrated.value) : 0UL
	);

	SecureText secret("top-secret");
	Serial.printf("secure text size: %u\n", static_cast<unsigned>(secret.size()));

	std::vector<uint8_t> ctrKey(16, 0x22);
	std::vector<uint8_t> counter(16, 0x00);
	std::vector<uint8_t> streamInput = {'s', 't', 'r', 'e', 'a', 'm'};
	auto ctrOut = espcrypto::symmetric::aesCtrCrypt(ctrKey, counter, streamInput);
	if (!ctrOut.ok()) {
		Serial.printf("ctr encrypt failed: %s\n", statusText(ctrOut.status));
		return;
	}
	auto ctrPlain = espcrypto::symmetric::aesCtrCrypt(ctrKey, counter, ctrOut.value);
	if (!ctrPlain.ok()) {
		Serial.printf("ctr decrypt failed: %s\n", statusText(ctrPlain.status));
		return;
	}
	std::string recovered(reinterpret_cast<const char *>(ctrPlain.value.data()), ctrPlain.value.size());
	Serial.printf("ctr recovered: %s\n", recovered.c_str());
}

void loop() {
}
