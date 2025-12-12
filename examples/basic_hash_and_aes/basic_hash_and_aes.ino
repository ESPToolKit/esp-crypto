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

    // Basic SHA helper
    String message = "ESPCrypto";
    String digest = ESPCrypto::shaHex(reinterpret_cast<const uint8_t *>(message.c_str()), message.length());
    Serial.printf("SHA256('%s') = %s\n", message.c_str(), digest.c_str());

    // Basic AES-GCM with auto IV/tag handling
    std::vector<uint8_t> key(32, 0x01);  // 256-bit key
    std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};
    auto encrypted = ESPCrypto::aesGcmEncryptAuto(key, plaintext);
    if (!encrypted.ok()) {
        Serial.printf("GCM encrypt failed: %s\n", toString(encrypted.status.code));
        return;
    }
    Serial.printf("GCM IV: %s\n", bytesToHex(encrypted.value.iv).c_str());
    Serial.printf("GCM ciphertext: %s\n", bytesToHex(encrypted.value.ciphertext).c_str());
    Serial.printf("GCM tag: %s\n", bytesToHex(encrypted.value.tag).c_str());

    auto decrypted = ESPCrypto::aesGcmDecrypt(key, encrypted.value.iv, encrypted.value.ciphertext, encrypted.value.tag);
    if (!decrypted.ok()) {
        Serial.printf("GCM decrypt failed: %s\n", toString(decrypted.status.code));
        return;
    }
    Serial.printf("GCM plaintext recovered: %s\n",
                  String(reinterpret_cast<const char *>(decrypted.value.data()), decrypted.value.size()).c_str());
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}
