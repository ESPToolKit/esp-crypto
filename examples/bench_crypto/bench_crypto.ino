#include <Arduino.h>
#include <ESPCrypto.h>

void benchSha() {
    std::vector<uint8_t> data(1024, 0xAB);
    uint8_t out[32] = {0};
    uint32_t start = millis();
    for (int i = 0; i < 200; ++i) {
        ESPCrypto::sha(CryptoSpan<const uint8_t>(data), CryptoSpan<uint8_t>(out));
    }
    uint32_t elapsed = millis() - start;
    Serial.printf("SHA256 x200 of 1KB: %ums\n", elapsed);
}

void benchGcm() {
    std::vector<uint8_t> key(16, 0x01);
    std::vector<uint8_t> iv(12, 0x02);
    std::vector<uint8_t> plaintext(512, 0x11);
    std::vector<uint8_t> ciphertext(plaintext.size(), 0);
    std::vector<uint8_t> tag(16, 0);
    uint32_t start = millis();
    for (int i = 0; i < 50; ++i) {
        ESPCrypto::aesGcmEncrypt(key, CryptoSpan<const uint8_t>(iv), CryptoSpan<const uint8_t>(plaintext), CryptoSpan<uint8_t>(ciphertext), CryptoSpan<uint8_t>(tag));
    }
    uint32_t elapsed = millis() - start;
    Serial.printf("AES-GCM x50 of 512B: %ums\n", elapsed);
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("ESPCrypto micro-bench");
    benchSha();
    benchGcm();
}

void loop() {}
