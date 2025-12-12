#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESPCrypto.h>

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("JWKS rotation demo");

    // Build a JWKS with two keys; rotate by switching kid
    JsonDocument jwks;
    JsonArray keys = jwks["keys"].to<JsonArray>();
    JsonObject k1 = keys.add<JsonObject>();
    k1["kty"] = "oct";
    k1["kid"] = "k1";
    k1["alg"] = "HS256";
    k1["k"] = "c3VwZXJzZWNyZXQ"; // "supersecret"

    JsonObject k2 = keys.add<JsonObject>();
    k2["kty"] = "oct";
    k2["kid"] = "k2";
    k2["alg"] = "HS256";
    k2["k"] = "bW9yZXNlY3JldA"; // "moresecret"

    // Issue token with kid=k2
    JsonDocument claims;
    claims["iss"] = "jwks-demo";
    JwtSignOptions sign;
    sign.algorithm = JwtAlgorithm::HS256;
    sign.keyId = "k2";
    String token = ESPCrypto::createJwt(claims, "moresecret", sign);

    JsonDocument decoded;
    auto res = ESPCrypto::verifyJwtWithJwks(token, jwks, decoded);
    Serial.printf("JWKS verify with rotation (kid=k2) ok? %s\n", res.ok() ? "yes" : "no");
}

void loop() {}
