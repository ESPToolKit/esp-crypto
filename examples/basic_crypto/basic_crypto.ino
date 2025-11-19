#include <Arduino.h>
#include <ESPCrypto.h>

#include <vector>

String bytesToHex(const std::vector<uint8_t> &bytes) {
    static const char *HEX_DIGITS = "0123456789ABCDEF";
    String out;
    for (uint8_t b : bytes) {
        out += HEX_DIGITS[(b >> 4) & 0x0F];
        out += HEX_DIGITS[b & 0x0F];
    }
    return out;
}

void setup() {
    Serial.begin(115200);
    delay(200);

    String message = "ESPCrypto";
    String digest = ESPCrypto::shaHex(reinterpret_cast<const uint8_t *>(message.c_str()), message.length());
    Serial.printf("SHA256('%s') = %s\n", message.c_str(), digest.c_str());

    std::vector<uint8_t> key = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                                0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                                0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                                0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    std::vector<uint8_t> iv = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03,
                               0x04, 0x05, 0x06, 0x07};
    std::vector<uint8_t> aad = {'E', 'S', 'P'};
    std::vector<uint8_t> plaintext = {'s', 'e', 'c', 'r', 'e', 't'};
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
    if (ESPCrypto::aesGcmEncrypt(key, iv, plaintext, ciphertext, tag, aad)) {
        Serial.printf("AES-GCM ciphertext: %s\n", bytesToHex(ciphertext).c_str());
        std::vector<uint8_t> decrypted;
        if (ESPCrypto::aesGcmDecrypt(key, iv, ciphertext, tag, decrypted, aad)) {
            Serial.printf("AES-GCM decrypted: %s\n", String(reinterpret_cast<const char *>(decrypted.data()), decrypted.size()).c_str());
        }
    }

    JsonDocument claims;
    claims["role"] = "admin";
    JwtSignOptions signOptions;
    signOptions.algorithm = JwtAlgorithm::HS256;
    signOptions.issuer = "esp32";
    signOptions.expiresInSeconds = 120;
    String jwt = ESPCrypto::createJwt(claims, "super-secret", signOptions);
    Serial.printf("JWT: %s\n", jwt.c_str());

    JsonDocument decoded;
    String error;
    JwtVerifyOptions verifyOptions;
    verifyOptions.algorithm = JwtAlgorithm::HS256;
    verifyOptions.issuer = "esp32";
    if (ESPCrypto::verifyJwt(jwt, "super-secret", decoded, error, verifyOptions)) {
        Serial.printf("JWT payload role: %s\n", decoded["role"].as<const char *>());
    } else {
        Serial.printf("JWT verify failed: %s\n", error.c_str());
    }

    String hashed = ESPCrypto::hashString("hunter2");
    Serial.printf("Hashed password: %s\n", hashed.c_str());
    Serial.printf("Password matches: %s\n", ESPCrypto::verifyString("hunter2", hashed) ? "true" : "false");
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}
