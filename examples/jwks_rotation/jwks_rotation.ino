#include <Arduino.h>
#include <ESPCrypto.h>

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
	claims["scope"] = "rotation";

	JwtSignOptions sign;
	sign.algorithm = JwtAlgorithm::HS256;
	sign.keyId = "current";
	sign.issuer = "jwks";

	auto token = espcrypto::jwt::create(claims, "moresecret", sign);
	if (!token.ok()) {
		Serial.printf("create failed: %s\n", statusText(token.status));
		return;
	}

	JsonDocument jwks;
	JsonArray keys = jwks["keys"].to<JsonArray>();
	JsonObject current = keys.add<JsonObject>();
	current["kid"] = "current";
	current["kty"] = "oct";
	current["alg"] = "HS256";
	current["k"] = "bW9yZXNlY3JldA";

	JsonDocument decoded;
	JwtVerifyOptions verify;
	verify.algorithm = JwtAlgorithm::HS256;
	verify.issuer = "jwks";

	auto res = espcrypto::jwt::verifyWithJwks(token.value, jwks, decoded, verify);
	Serial.printf("jwks verify: %s\n", res.ok() ? "ok" : statusText(res.status));
}

void loop() {
}
