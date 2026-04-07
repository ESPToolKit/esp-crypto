#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESPCrypto.h>
#include <esp_crypto/jwt.h>

#include <string>

namespace {
const char *statusText(const CryptoStatusDetail &status) {
	return status.message.empty() ? toString(status.code) : status.message.c_str();
}
} // namespace

void setup() {
	Serial.begin(115200);
	delay(1000);

	JsonDocument claims;
	claims["device"] = "esp32";
	claims["scope"] = "demo";

	JwtSignOptions sign;
	sign.algorithm = JwtAlgorithm::HS256;
	sign.issuer = "example";
	sign.expiresInSeconds = 60;

	auto token = espcrypto::jwt::create(claims, "super-secret", sign);
	if (!token.ok()) {
		Serial.printf("token create failed: %s\n", statusText(token.status));
		return;
	}
	Serial.printf("token: %s\n", token.value.c_str());

	JsonDocument decoded;
	JwtVerifyOptions verify;
	verify.algorithm = JwtAlgorithm::HS256;
	verify.issuer = "example";

	auto verified = espcrypto::jwt::verify(token.value, "super-secret", decoded, verify);
	Serial.printf(
	    "jwt verify: %s\n",
	    verified.ok() ? "ok" : statusText(verified.status)
	);

	auto hashed = espcrypto::password::hash("hunter2");
	if (!hashed.ok()) {
		Serial.printf("hash failed: %s\n", statusText(hashed.status));
		return;
	}
	Serial.printf("password hash: %s\n", hashed.value.c_str());

	auto ok = espcrypto::password::verify("hunter2", hashed.value);
	Serial.printf("password verify: %s\n", ok.ok() ? "ok" : statusText(ok.status));
}

void loop() {
}
