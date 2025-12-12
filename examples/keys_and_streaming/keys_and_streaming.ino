#include <Arduino.h>
#include <ESPCrypto.h>

MemoryKeyStore memoryStore;

void demoKeystore() {
    KeyHandle handle{String("demo-key"), 1};
    const char *pem = "-----BEGIN PRIVATE KEY-----\n...replace-with-real-key...\n-----END PRIVATE KEY-----";
    ESPCrypto::storeKey(memoryStore, handle, CryptoSpan<const uint8_t>(reinterpret_cast<const uint8_t *>(pem), strlen(pem)));
    auto loaded = ESPCrypto::loadKey(memoryStore, handle, KeyFormat::Pem, KeyKind::Private);
    if (loaded.ok()) {
        auto sig = ESPCrypto::rsaSign(loaded.value,
                                      CryptoSpan<const uint8_t>(reinterpret_cast<const uint8_t *>("payload"), 7),
                                      ShaVariant::SHA256);
        Serial.printf("Loaded key and produced signature? %s\n", sig.ok() ? "yes" : "no");
    } else {
        Serial.printf("Key load failed: %s\n", loaded.status.message.c_str());
    }
}

void demoStreaming() {
    // Streaming SHA256
    ShaCtx shaCtx;
    shaCtx.begin(ShaVariant::SHA256);
    shaCtx.update(CryptoSpan<const uint8_t>(reinterpret_cast<const uint8_t *>("hello "), 6));
    shaCtx.update(CryptoSpan<const uint8_t>(reinterpret_cast<const uint8_t *>("world"), 5));
    uint8_t digest[32] = {0};
    shaCtx.finish(CryptoSpan<uint8_t>(digest));
    Serial.print("SHA256(stream) digest[0..3]: ");
    for (int i = 0; i < 4; ++i) {
        Serial.printf("%02x", digest[i]);
    }
    Serial.println();

    // AES-GCM streaming with caller buffers
    std::vector<uint8_t> key(16, 0x01);
    std::vector<uint8_t> iv(12, 0x02);
    std::vector<uint8_t> plaintext = {'E', 'S', 'P', 'C', 'r', 'y', 'p', 't', 'o'};
    std::vector<uint8_t> ciphertext(plaintext.size(), 0);
    std::vector<uint8_t> tag(16, 0);

    AesGcmCtx enc;
    enc.beginEncrypt(key, CryptoSpan<const uint8_t>(iv), CryptoSpan<const uint8_t>());
    enc.update(CryptoSpan<const uint8_t>(plaintext), CryptoSpan<uint8_t>(ciphertext));
    enc.finish(CryptoSpan<uint8_t>(tag));

    std::vector<uint8_t> decrypted(plaintext.size(), 0);
    AesGcmCtx dec;
    dec.beginDecrypt(key, CryptoSpan<const uint8_t>(iv), CryptoSpan<const uint8_t>(), CryptoSpan<const uint8_t>(tag));
    dec.update(CryptoSpan<const uint8_t>(ciphertext), CryptoSpan<uint8_t>(decrypted));
    auto decStatus = dec.finish(CryptoSpan<uint8_t>(tag));
    Serial.printf("AES-GCM streaming decrypt ok? %s\n", decStatus.ok() && ESPCrypto::constantTimeEq(plaintext, decrypted) ? "yes" : "no");
}

void demoNonceStrategies() {
    std::vector<uint8_t> key(16, 0x03);
    std::vector<uint8_t> plaintext = {0x01, 0x02};
    GcmNonceOptions opts;
    opts.strategy = GcmNonceStrategy::Counter64_Random32;
    auto msg = ESPCrypto::aesGcmEncryptAuto(key, plaintext, {}, 12, opts);
    Serial.printf("GCM iv (counter strategy) size: %u\n", msg.value.iv.size());
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("ESPCrypto keystore + streaming demo");
    demoKeystore();
    demoStreaming();
    demoNonceStrategies();
    auto deviceKey = ESPCrypto::deriveDeviceKey("example", CryptoSpan<const uint8_t>(), 32);
    Serial.printf("Device-bound key derived? %s\n", deviceKey.ok() ? "yes" : "no");
}

void loop() {}
