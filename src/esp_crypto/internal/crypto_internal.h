#pragma once

#include "../esp_crypto.h"

#if __has_include(<ArduinoJson.h>)
#include "../jwt.h"
#define ESPCRYPTO_HAS_ARDUINOJSON 1
#else
#define ESPCRYPTO_HAS_ARDUINOJSON 0
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <map>
#include <random>
#include <string>
#include <type_traits>
#include <vector>

#include "mbedtls/aes.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/base64.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/version.h"
#if defined(__has_include)
#if __has_include("mbedtls/private_access.h")
#include "mbedtls/private_access.h"
#endif
#endif

#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(member) member
#endif

#if defined(ARDUINO) && __has_include(<LittleFS.h>)
#include <LittleFS.h>
#define ESPCRYPTO_HAS_LITTLEFS 1
#else
#define ESPCRYPTO_HAS_LITTLEFS 0
#endif

#if (defined(ESP_PLATFORM) || defined(ARDUINO_ARCH_ESP32)) && __has_include("esp_system.h")
#define ESPCRYPTO_HAS_ESP_SYSTEM 1
#else
#define ESPCRYPTO_HAS_ESP_SYSTEM 0
#endif

#if (defined(ESP_PLATFORM) || defined(ARDUINO_ARCH_ESP32)) && __has_include("esp_timer.h")
#define ESPCRYPTO_HAS_ESP_TIMER 1
#else
#define ESPCRYPTO_HAS_ESP_TIMER 0
#endif

#if (defined(ESP_PLATFORM) || defined(ARDUINO_ARCH_ESP32)) && __has_include("esp_random.h")
#define ESPCRYPTO_HAS_ESP_RANDOM 1
#else
#define ESPCRYPTO_HAS_ESP_RANDOM 0
#endif

#if ESPCRYPTO_HAS_ESP_SYSTEM || ESPCRYPTO_HAS_ESP_TIMER || ESPCRYPTO_HAS_ESP_RANDOM
extern "C" {
#if ESPCRYPTO_HAS_ESP_SYSTEM
#include "esp_system.h"
#endif
#if ESPCRYPTO_HAS_ESP_TIMER
#include "esp_timer.h"
#endif
#if ESPCRYPTO_HAS_ESP_RANDOM
#include "esp_random.h"
#endif
}
#endif

#if defined(ESP_PLATFORM)
extern "C" {
#include "nvs.h"
#include "nvs_flash.h"
#if defined(__has_include)
#if __has_include("esp_mac.h")
#include "esp_mac.h"
#define ESPCRYPTO_HAS_ESP_MAC 1
#else
#define ESPCRYPTO_HAS_ESP_MAC 0
#endif
#if __has_include("esp_efuse_mac.h")
#include "esp_efuse_mac.h"
#define ESPCRYPTO_HAS_ESP_EFUSE_MAC 1
#else
#define ESPCRYPTO_HAS_ESP_EFUSE_MAC 0
#endif
#if __has_include("sha/sha_parallel_engine.h")
#include "hal/sha_types.h"
#include "sha/sha_parallel_engine.h"
#define ESPCRYPTO_SHA_ACCEL 1
#endif
#if __has_include("aes/esp_aes.h")
#include "aes/esp_aes.h"
#define ESPCRYPTO_AES_ACCEL 1
#endif
#if __has_include("aes/esp_aes_gcm.h")
#include "aes/esp_aes_gcm.h"
#define ESPCRYPTO_AES_GCM_ACCEL 1
#endif
#else
#define ESPCRYPTO_HAS_ESP_MAC 0
#define ESPCRYPTO_HAS_ESP_EFUSE_MAC 0
#endif
}
#include <sys/time.h>
#else
#define ESPCRYPTO_SHA_ACCEL 0
#define ESPCRYPTO_AES_ACCEL 0
#define ESPCRYPTO_AES_GCM_ACCEL 0
#include <ctime>
#endif

#ifndef ESPCRYPTO_SHA_ACCEL
#define ESPCRYPTO_SHA_ACCEL 0
#endif
#ifndef ESPCRYPTO_AES_ACCEL
#define ESPCRYPTO_AES_ACCEL 0
#endif
#ifndef ESPCRYPTO_AES_GCM_ACCEL
#define ESPCRYPTO_AES_GCM_ACCEL 0
#endif

#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000
#define ESPCRYPTO_MBEDTLS_V3 1
#else
#define ESPCRYPTO_MBEDTLS_V3 0
#endif

#ifndef ESPCRYPTO_NONCE_GUARD_CACHE
#define ESPCRYPTO_NONCE_GUARD_CACHE 8
#endif
#ifndef ESPCRYPTO_ENABLE_NONCE_GUARD
#define ESPCRYPTO_ENABLE_NONCE_GUARD 0
#endif

constexpr size_t AES_GCM_TAG_BYTES = 16;

enum class Base64Alphabet { Standard, Url };

struct NonceRecord {
    uint32_t keyHash = 0;
    std::array<uint8_t, 16> iv = {};
    size_t ivLen = 0;
    bool used = false;
};

struct GlobalRuntimeState {
    std::atomic<bool> initialized{false};
    std::map<std::string, bool> nvsInitMap;
#if ESPCRYPTO_ENABLE_NONCE_GUARD
    std::array<NonceRecord, ESPCRYPTO_NONCE_GUARD_CACHE> nonceCache = {};
    size_t nonceCursor = 0;
#endif
    std::atomic<uint64_t> bootCounter{0};
};

#if ESPCRYPTO_HAS_ARDUINOJSON
std::string algorithmName(JwtAlgorithm alg);
JwtAlgorithm algorithmFromName(const std::string &name);
#endif

void secureZero(void *data, size_t length);
CryptoPolicy &mutablePolicy();
CryptoStatusDetail makeStatus(CryptoStatus code, const char *message = nullptr);
GlobalRuntimeState &runtimeState();
void markRuntimeInitialized();
void resetRuntimeState();
uint32_t fingerprintKey(const std::vector<uint8_t> &key);
bool nonceReused(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv);
size_t digestLength(ShaVariant variant);
const mbedtls_md_info_t *mdInfoForVariant(ShaVariant variant);
bool softwareSha(ShaVariant variant, const uint8_t *data, size_t length, uint8_t *out);
bool tryHardwareSha(ShaVariant variant, const uint8_t *data, size_t length, uint8_t *out);
std::string base64Encode(const uint8_t *data, size_t length, Base64Alphabet alphabet);
bool base64Decode(const std::string &input, Base64Alphabet alphabet, std::vector<uint8_t> &output);
uint32_t currentTimeSeconds(uint32_t overrideValue);
uint64_t monotonicMillis();
void fillRandom(uint8_t *data, size_t length);
bool constantTimeEquals(CryptoSpan<const uint8_t> a, CryptoSpan<const uint8_t> b);
CryptoStatusDetail buildRsaPemFromJwk(
    const std::vector<uint8_t> &n, const std::vector<uint8_t> &e, std::string &outPem
);
CryptoStatusDetail buildEcPemFromJwk(
    const std::vector<uint8_t> &x,
    const std::vector<uint8_t> &y,
    const std::string &crv,
    std::string &outPem
);
#if ESPCRYPTO_HAS_ARDUINOJSON
CryptoResult<CryptoKey> jwkToKey(const JsonObjectConst &jwk);
CryptoResult<CryptoKey>
selectJwkFromSet(const JsonDocument &jwks, const std::string &kid, JwtAlgorithm algHint);
#endif
std::string handleKeyString(const KeyHandle &handle);
bool ensureNvsReady(const std::string &partition);
uint64_t loadCounterFromNvs(
    const std::string &ns,
    const std::string &partition,
    const std::string &key,
    bool &found
);
void storeCounterToNvs(
    const std::string &ns,
    const std::string &partition,
    const std::string &key,
    uint64_t value
);
bool hmacSha256(
    const std::string &key, const uint8_t *data, size_t length, std::vector<uint8_t> &out
);
bool initDrbg(mbedtls_ctr_drbg_context &ctr, mbedtls_entropy_context &entropy);
bool computeHash(
    ShaVariant variant, const uint8_t *data, size_t length, std::vector<uint8_t> &hash
);
int pbkdf2Sha256(
    const unsigned char *password,
    size_t passwordLength,
    const uint8_t *salt,
    size_t saltLength,
    uint32_t iterations,
    uint8_t *output,
    size_t outputLength
);
bool pkParsePublicOrPrivate(
    mbedtls_pk_context &pk,
    const std::string &pem,
    mbedtls_ctr_drbg_context *ctr,
    const mbedtls_entropy_context *entropy
);
bool pkPolicyAllows(mbedtls_pk_context &pk, mbedtls_pk_type_t expected);
mbedtls_pk_context &pkContext(const CryptoKey &key);
bool pkSignContext(
    mbedtls_pk_context &pk,
    mbedtls_pk_type_t expected,
    ShaVariant variant,
    const uint8_t *data,
    size_t length,
    std::vector<uint8_t> &signature
);
bool pkVerifyContext(
    mbedtls_pk_context &pk,
    mbedtls_pk_type_t expected,
    ShaVariant variant,
    const uint8_t *data,
    size_t length,
    const std::vector<uint8_t> &signature
);
bool pkSignInternal(
    const std::string &pem,
    mbedtls_pk_type_t expected,
    ShaVariant variant,
    const uint8_t *data,
    size_t length,
    std::vector<uint8_t> &signature
);
bool pkVerifyInternal(
    const std::string &pem,
    mbedtls_pk_type_t expected,
    ShaVariant variant,
    const uint8_t *data,
    size_t length,
    const std::vector<uint8_t> &signature
);
#if ESPCRYPTO_HAS_ARDUINOJSON
bool signJwt(
    JwtAlgorithm alg,
    const std::string &key,
    const uint8_t *data,
    size_t length,
    std::vector<uint8_t> &signature
);
bool verifySignature(
    JwtAlgorithm alg,
    const std::string &key,
    const uint8_t *data,
    size_t length,
    const std::vector<uint8_t> &signature
);
#endif
bool aesKeyValid(const std::vector<uint8_t> &key);
bool hardwareAesCtr(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonceCounter,
    const std::vector<uint8_t> &input,
    std::vector<uint8_t> &output
);
bool softwareAesCtr(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonceCounter,
    const std::vector<uint8_t> &input,
    std::vector<uint8_t> &output
);
bool hardwareGcmCryptSpan(
    int mode,
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> input,
    CryptoSpan<uint8_t> output,
    CryptoSpan<uint8_t> tag
);
bool hardwareGcmCrypt(
    int mode,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &input,
    std::vector<uint8_t> &output,
    std::vector<uint8_t> &tag
);
bool softwareGcmCrypt(
    int mode,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &input,
    std::vector<uint8_t> &output,
    std::vector<uint8_t> &tag
);
bool softwareGcmCrypt(
    int mode,
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> input,
    CryptoSpan<uint8_t> output,
    CryptoSpan<uint8_t> tag
);
CryptoStatusDetail aesGcmEncryptSpan(
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> plaintext,
    CryptoSpan<uint8_t> ciphertext,
    CryptoSpan<uint8_t> tag
);
CryptoStatusDetail aesGcmDecryptSpan(
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> ciphertext,
    CryptoSpan<const uint8_t> tag,
    CryptoSpan<uint8_t> plaintext
);
CryptoStatusDetail aesGcmEncryptInternal(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &plaintext,
    std::vector<uint8_t> &ciphertext,
    std::vector<uint8_t> &tag
);
CryptoStatusDetail aesGcmDecryptInternal(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &tag,
    std::vector<uint8_t> &plaintext
);
bool parsePasswordHash(
    const std::string &encoded,
    uint8_t &cost,
    std::vector<uint8_t> &salt,
    std::vector<uint8_t> &hash
);
CryptoResult<std::vector<uint8_t>> ecdsaDerToRawInternal(CryptoSpan<const uint8_t> der);
CryptoResult<std::vector<uint8_t>> ecdsaRawToDerInternal(CryptoSpan<const uint8_t> raw);
