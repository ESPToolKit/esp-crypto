#include <Arduino.h>
#include <ESPCrypto.h>

String toFriendly(const CryptoStatusDetail &status) {
    if (status.ok()) {
        return "ok";
    }
    if (status.message.length() > 0) {
        return status.message;
    }
    return String(toString(status.code));
}

void setup() {
    Serial.begin(115200);
    delay(200);

    // JWT creation/verification (HS256)
    JsonDocument claims;
    claims["role"] = "admin";
    JwtSignOptions sign;
    sign.algorithm = JwtAlgorithm::HS256;
    sign.issuer = "esp32";
    sign.expiresInSeconds = 60;

    auto tokenResult = ESPCrypto::createJwtResult(claims, "super-secret", sign);
    if (!tokenResult.ok()) {
        Serial.printf("JWT create failed: %s\n", toFriendly(tokenResult.status).c_str());
        return;
    }
    Serial.printf("JWT: %s\n", tokenResult.value.c_str());

    JsonDocument decoded;
    JwtVerifyOptions verify;
    verify.algorithm = JwtAlgorithm::HS256;
    verify.issuer = "esp32";
    auto verifyResult = ESPCrypto::verifyJwtResult(tokenResult.value, "super-secret", decoded, verify);
    if (!verifyResult.ok()) {
        Serial.printf("JWT verify failed: %s\n", toFriendly(verifyResult.status).c_str());
    } else {
        Serial.printf("JWT role claim: %s\n", decoded["role"].as<const char *>());
    }

    // Password hashing + verification
    String hashed = ESPCrypto::hashString("hunter2");
    Serial.printf("Hashed password: %s\n", hashed.c_str());
    bool ok = ESPCrypto::verifyString("hunter2", hashed);
    Serial.printf("Password matches: %s\n", ok ? "true" : "false");
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}
