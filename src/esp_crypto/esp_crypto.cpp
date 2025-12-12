#include "esp_crypto.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <cstdlib>
#include <random>
#include <ctime>
#include <string>
#include <vector>
#include <type_traits>

#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/version.h"

#if defined(ESP_PLATFORM)
extern "C" {
#include "esp_system.h"
#include "esp_timer.h"
#if defined(__has_include)
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

namespace {

constexpr size_t AES_GCM_TAG_BYTES = 16;
#ifndef ESPCRYPTO_NONCE_GUARD_CACHE
#define ESPCRYPTO_NONCE_GUARD_CACHE 8
#endif
#ifndef ESPCRYPTO_ENABLE_NONCE_GUARD
#define ESPCRYPTO_ENABLE_NONCE_GUARD 0
#endif

void secureZero(void *data, size_t length) {
    if (!data || length == 0) {
        return;
    }
    volatile uint8_t *p = static_cast<volatile uint8_t *>(data);
    while (length--) {
        *p++ = 0;
    }
#if defined(__GNUC__)
    __asm__ __volatile__("" : : : "memory");
#endif
}

CryptoPolicy &mutablePolicy() {
    static CryptoPolicy policy;
    return policy;
}

CryptoStatusDetail makeStatus(CryptoStatus code, const char *message = nullptr) {
    CryptoStatusDetail status;
    status.code = code;
    if (message) {
        status.message = message;
    }
    return status;
}

struct NonceRecord {
    uint32_t keyHash = 0;
    std::array<uint8_t, 16> iv = {};
    size_t ivLen = 0;
    bool used = false;
};

uint32_t fingerprintKey(const std::vector<uint8_t> &key) {
    uint32_t hash = 2166136261u;
    for (uint8_t b : key) {
        hash ^= b;
        hash *= 16777619u;
    }
    return hash;
}

bool nonceReused(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv) {
#if ESPCRYPTO_ENABLE_NONCE_GUARD
    static std::array<NonceRecord, ESPCRYPTO_NONCE_GUARD_CACHE> cache;
    static size_t cursor = 0;
    if (iv.size() > cache[0].iv.size()) {
        return false;
    }
    uint32_t keyHash = fingerprintKey(key);
    for (const auto &record : cache) {
        if (!record.used || record.ivLen != iv.size()) {
            continue;
        }
        if (record.keyHash != keyHash) {
            continue;
        }
        if (memcmp(record.iv.data(), iv.data(), iv.size()) == 0) {
            return true;
        }
    }
    NonceRecord &slot = cache[cursor % cache.size()];
    slot.used = true;
    slot.keyHash = keyHash;
    slot.ivLen = iv.size();
    memcpy(slot.iv.data(), iv.data(), iv.size());
    cursor++;
#else
    (void)key;
    (void)iv;
#endif
    return false;
}

enum class Base64Alphabet { Standard, Url };

size_t digestLength(ShaVariant variant) {
    switch (variant) {
        case ShaVariant::SHA256:
            return 32;
        case ShaVariant::SHA384:
            return 48;
        case ShaVariant::SHA512:
            return 64;
    }
    return 0;
}

const mbedtls_md_info_t *mdInfoForVariant(ShaVariant variant) {
    switch (variant) {
        case ShaVariant::SHA256:
            return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        case ShaVariant::SHA384:
            return mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
        case ShaVariant::SHA512:
            return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    }
    return nullptr;
}

bool softwareSha(ShaVariant variant, const uint8_t *data, size_t length, uint8_t *out) {
    const mbedtls_md_info_t *info = mdInfoForVariant(variant);
    if (!info) {
        return false;
    }
    return mbedtls_md(info, data, length, out) == 0;
}

bool tryHardwareSha(ShaVariant variant, const uint8_t *data, size_t length, uint8_t *out) {
#if ESPCRYPTO_SHA_ACCEL
    esp_sha_type type = SHA1;
    switch (variant) {
        case ShaVariant::SHA256:
            type = SHA2_256;
            break;
        case ShaVariant::SHA384:
#if defined(SHA2_384)
            type = SHA2_384;
            break;
#else
            return false;
#endif
        case ShaVariant::SHA512:
#if defined(SHA2_512)
            type = SHA2_512;
            break;
#else
            return false;
#endif
    }
    esp_sha(type, data, length, out);
    return true;
#else
    (void)variant;
    (void)data;
    (void)length;
    (void)out;
    return false;
#endif
}

std::string base64Encode(const uint8_t *data, size_t length, Base64Alphabet alphabet) {
    if (length == 0) {
        return std::string();
    }
    size_t encodedLen = 4 * ((length + 2) / 3);
    std::string buffer(encodedLen, '\0');
    size_t actualLen = 0;
    if (mbedtls_base64_encode(reinterpret_cast<unsigned char *>(&buffer[0]), buffer.size(), &actualLen, data, length) != 0) {
        return std::string();
    }
    buffer.resize(actualLen);
    if (alphabet == Base64Alphabet::Url) {
        for (char &c : buffer) {
            if (c == '+') {
                c = '-';
            } else if (c == '/') {
                c = '_';
            }
        }
        while (!buffer.empty() && buffer.back() == '=') {
            buffer.pop_back();
        }
    }
    return buffer;
}

bool base64Decode(const std::string &input, Base64Alphabet alphabet, std::vector<uint8_t> &output) {
    std::string transformed = input;
    if (alphabet == Base64Alphabet::Url) {
        for (char &c : transformed) {
            if (c == '-') {
                c = '+';
            } else if (c == '_') {
                c = '/';
            }
        }
        while (transformed.size() % 4 != 0) {
            transformed.push_back('=');
        }
    }
    size_t required = 0;
    int probe = mbedtls_base64_decode(nullptr, 0, &required,
                                      reinterpret_cast<const unsigned char *>(transformed.c_str()),
                                      transformed.size());
    if (probe != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && probe != 0) {
        return false;
    }
    output.assign(required, 0);
    size_t actual = 0;
    int ret = mbedtls_base64_decode(output.data(), output.size(), &actual,
                                    reinterpret_cast<const unsigned char *>(transformed.c_str()),
                                    transformed.size());
    if (ret != 0) {
        output.clear();
        return false;
    }
    output.resize(actual);
    return true;
}

uint32_t currentTimeSeconds(uint32_t overrideValue) {
    if (overrideValue != 0) {
        return overrideValue;
    }
#if defined(ESP_PLATFORM)
    struct timeval tv;
    if (gettimeofday(&tv, nullptr) == 0 && tv.tv_sec > 0) {
        return static_cast<uint32_t>(tv.tv_sec);
    }
    return static_cast<uint32_t>(esp_timer_get_time() / 1000000ULL);
#else
    return static_cast<uint32_t>(time(nullptr));
#endif
}

void fillRandom(uint8_t *data, size_t length) {
#if defined(ESP_PLATFORM)
    esp_fill_random(data, length);
#else
    std::random_device rd;
    for (size_t i = 0; i < length; ++i) {
        data[i] = static_cast<uint8_t>(rd());
    }
#endif
}

bool constantTimeEquals(CryptoSpan<const uint8_t> a, CryptoSpan<const uint8_t> b) {
    if (a.size() != b.size()) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<uint8_t>(a.data()[i] ^ b.data()[i]);
    }
    return diff == 0;
}

std::string algorithmName(JwtAlgorithm alg) {
    switch (alg) {
        case JwtAlgorithm::HS256:
            return "HS256";
        case JwtAlgorithm::RS256:
            return "RS256";
        case JwtAlgorithm::ES256:
            return "ES256";
        case JwtAlgorithm::Auto:
        default:
            return "";
    }
}

JwtAlgorithm algorithmFromName(const std::string &name) {
    if (name == "HS256") {
        return JwtAlgorithm::HS256;
    }
    if (name == "RS256") {
        return JwtAlgorithm::RS256;
    }
    if (name == "ES256") {
        return JwtAlgorithm::ES256;
    }
    return JwtAlgorithm::Auto;
}

bool hmacSha256(const std::string &key, const uint8_t *data, size_t length, std::vector<uint8_t> &out) {
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) {
        return false;
    }
    out.assign(mbedtls_md_get_size(info), 0);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int ret = mbedtls_md_setup(&ctx, info, 1);
    if (ret == 0) {
        ret = mbedtls_md_hmac_starts(&ctx, reinterpret_cast<const unsigned char *>(key.data()), key.size());
    }
    if (ret == 0) {
        ret = mbedtls_md_hmac_update(&ctx, data, length);
    }
    if (ret == 0) {
        ret = mbedtls_md_hmac_finish(&ctx, out.data());
    }
    mbedtls_md_free(&ctx);
    if (ret != 0) {
        out.clear();
        return false;
    }
    return true;
}

bool initDrbg(mbedtls_ctr_drbg_context &ctr, mbedtls_entropy_context &entropy) {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);
    static const char *pers = "espcrypto";
    int ret = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                                    reinterpret_cast<const unsigned char *>(pers), strlen(pers));
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        return false;
    }
    return true;
}

bool computeHash(ShaVariant variant, const uint8_t *data, size_t length, std::vector<uint8_t> &hash) {
    hash.assign(digestLength(variant), 0);
    if (hash.empty()) {
        return false;
    }
    static const uint8_t ZERO_BYTE = 0;
    const uint8_t *buffer = (!data && length == 0) ? &ZERO_BYTE : data;
    if (softwareSha(variant, buffer, length, hash.data())) {
        return true;
    }
    return false;
}

int pbkdf2Sha256(const unsigned char *password,
                 size_t passwordLength,
                 const uint8_t *salt,
                 size_t saltLength,
                 uint32_t iterations,
                 uint8_t *output,
                 size_t outputLength) {
#if ESPCRYPTO_MBEDTLS_V3
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                         password,
                                         passwordLength,
                                         salt,
                                         saltLength,
                                         iterations,
                                         outputLength,
                                         output);
#else
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) {
        mbedtls_md_free(&ctx);
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }
    int ret = mbedtls_md_setup(&ctx, info, 1);
    if (ret == 0) {
        ret = mbedtls_pkcs5_pbkdf2_hmac(&ctx,
                                         password,
                                         passwordLength,
                                         salt,
                                         saltLength,
                                         iterations,
                                         outputLength,
                                         output);
    }
    mbedtls_md_free(&ctx);
    return ret;
#endif
}

bool pkParsePublicOrPrivate(mbedtls_pk_context &pk,
                             const std::string &pem,
                             mbedtls_ctr_drbg_context *ctr,
                             mbedtls_entropy_context *entropy) {
    int ret = mbedtls_pk_parse_public_key(&pk,
                                          reinterpret_cast<const unsigned char *>(pem.c_str()),
                                          pem.size() + 1);
    if (ret == 0) {
        return true;
    }
    mbedtls_ctr_drbg_context localCtr;
    mbedtls_entropy_context localEntropy;
    if (!ctr || !entropy) {
        ctr = &localCtr;
        entropy = &localEntropy;
        if (!initDrbg(localCtr, localEntropy)) {
            return false;
        }
    }
#if ESPCRYPTO_MBEDTLS_V3
    ret = mbedtls_pk_parse_key(&pk,
                                reinterpret_cast<const unsigned char *>(pem.c_str()),
                                pem.size() + 1,
                                nullptr,
                                0,
                                mbedtls_ctr_drbg_random,
                                ctr);
#else
    ret = mbedtls_pk_parse_key(&pk,
                                reinterpret_cast<const unsigned char *>(pem.c_str()),
                                pem.size() + 1,
                                nullptr,
                                0);
#endif
    if (ctr == &localCtr) {
        mbedtls_ctr_drbg_free(&localCtr);
        mbedtls_entropy_free(&localEntropy);
    }
    return ret == 0;
}

bool pkSignInternal(const std::string &pem,
                    mbedtls_pk_type_t expected,
                    ShaVariant variant,
                    const uint8_t *data,
                    size_t length,
                    std::vector<uint8_t> &signature) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_ctr_drbg_context ctr;
    mbedtls_entropy_context entropy;
    if (!initDrbg(ctr, entropy)) {
        mbedtls_pk_free(&pk);
        return false;
    }
#if ESPCRYPTO_MBEDTLS_V3
    int ret = mbedtls_pk_parse_key(&pk,
                                    reinterpret_cast<const unsigned char *>(pem.c_str()),
                                    pem.size() + 1,
                                    nullptr,
                                    0,
                                    mbedtls_ctr_drbg_random,
                                    &ctr);
#else
    int ret = mbedtls_pk_parse_key(&pk,
                                    reinterpret_cast<const unsigned char *>(pem.c_str()),
                                    pem.size() + 1,
                                    nullptr,
                                    0);
#endif
    if (ret != 0 || !mbedtls_pk_can_do(&pk, expected)) {
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        mbedtls_pk_free(&pk);
        return false;
    }
    const CryptoPolicy &policy = mutablePolicy();
    size_t bitlen = mbedtls_pk_get_bitlen(&pk);
    if (!policy.allowLegacy) {
        if (expected == MBEDTLS_PK_RSA && bitlen < policy.minRsaBits) {
            mbedtls_ctr_drbg_free(&ctr);
            mbedtls_entropy_free(&entropy);
            mbedtls_pk_free(&pk);
            return false;
        }
        if (expected == MBEDTLS_PK_ECKEY && !policy.allowWeakCurves && bitlen < 256) {
            mbedtls_ctr_drbg_free(&ctr);
            mbedtls_entropy_free(&entropy);
            mbedtls_pk_free(&pk);
            return false;
        }
    }
    std::vector<uint8_t> hash;
    if (!computeHash(variant, data, length, hash)) {
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        mbedtls_pk_free(&pk);
        return false;
    }
    const mbedtls_md_info_t *info = mdInfoForVariant(variant);
    if (!info) {
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
        mbedtls_pk_free(&pk);
        return false;
    }
    size_t sigLen = mbedtls_pk_get_len(&pk);
    signature.assign(sigLen, 0);
#if ESPCRYPTO_MBEDTLS_V3
    ret = mbedtls_pk_sign(&pk,
                           mbedtls_md_get_type(info),
                           hash.data(), hash.size(),
                           signature.data(), signature.size(), &sigLen,
                           mbedtls_ctr_drbg_random,
                           &ctr);
#else
    ret = mbedtls_pk_sign(&pk,
                           mbedtls_md_get_type(info),
                           hash.data(), hash.size(),
                           signature.data(), &sigLen,
                           mbedtls_ctr_drbg_random,
                           &ctr);
#endif
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);
    if (ret != 0) {
        signature.clear();
        return false;
    }
    signature.resize(sigLen);
    return true;
}

bool pkVerifyInternal(const std::string &pem,
                       mbedtls_pk_type_t expected,
                       ShaVariant variant,
                       const uint8_t *data,
                       size_t length,
                       const std::vector<uint8_t> &signature) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    if (!pkParsePublicOrPrivate(pk, pem, nullptr, nullptr)) {
        mbedtls_pk_free(&pk);
        return false;
    }
    if (!mbedtls_pk_can_do(&pk, expected)) {
        mbedtls_pk_free(&pk);
        return false;
    }
    const CryptoPolicy &policy = mutablePolicy();
    size_t bitlen = mbedtls_pk_get_bitlen(&pk);
    if (!policy.allowLegacy) {
        if (expected == MBEDTLS_PK_RSA && bitlen < policy.minRsaBits) {
            mbedtls_pk_free(&pk);
            return false;
        }
        if (expected == MBEDTLS_PK_ECKEY && !policy.allowWeakCurves && bitlen < 256) {
            mbedtls_pk_free(&pk);
            return false;
        }
    }
    std::vector<uint8_t> hash;
    if (!computeHash(variant, data, length, hash)) {
        mbedtls_pk_free(&pk);
        return false;
    }
    const mbedtls_md_info_t *info = mdInfoForVariant(variant);
    if (!info) {
        mbedtls_pk_free(&pk);
        return false;
    }
    int ret = mbedtls_pk_verify(&pk,
                                 mbedtls_md_get_type(info),
                                 hash.data(), hash.size(),
                                 signature.data(), signature.size());
    mbedtls_pk_free(&pk);
    return ret == 0;
}

bool signJwt(JwtAlgorithm alg,
             const std::string &key,
             const uint8_t *data,
             size_t length,
             std::vector<uint8_t> &signature) {
    switch (alg) {
        case JwtAlgorithm::HS256:
            return hmacSha256(key, data, length, signature);
        case JwtAlgorithm::RS256:
            return pkSignInternal(key, MBEDTLS_PK_RSA, ShaVariant::SHA256, data, length, signature);
        case JwtAlgorithm::ES256:
            return pkSignInternal(key, MBEDTLS_PK_ECKEY, ShaVariant::SHA256, data, length, signature);
        case JwtAlgorithm::Auto:
        default:
            return false;
    }
}

bool verifySignature(JwtAlgorithm alg,
                     const std::string &key,
                     const uint8_t *data,
                     size_t length,
                     const std::vector<uint8_t> &signature) {
    switch (alg) {
        case JwtAlgorithm::HS256: {
            std::vector<uint8_t> expected;
            if (!hmacSha256(key, data, length, expected)) {
                return false;
            }
            return constantTimeEquals(expected, signature);
        }
        case JwtAlgorithm::RS256:
            return pkVerifyInternal(key, MBEDTLS_PK_RSA, ShaVariant::SHA256, data, length, signature);
        case JwtAlgorithm::ES256:
            return pkVerifyInternal(key, MBEDTLS_PK_ECKEY, ShaVariant::SHA256, data, length, signature);
        case JwtAlgorithm::Auto:
        default:
            return false;
    }
}

bool aesKeyValid(const std::vector<uint8_t> &key) {
    return key.size() == 16 || key.size() == 24 || key.size() == 32;
}

bool hardwareAesCtr(const std::vector<uint8_t> &key,
                    const std::vector<uint8_t> &nonceCounter,
                    const std::vector<uint8_t> &input,
                    std::vector<uint8_t> &output) {
#if ESPCRYPTO_AES_ACCEL
    esp_aes_context ctx;
    esp_aes_init(&ctx);
    bool ok = esp_aes_setkey(&ctx, key.data(), key.size() * 8) == 0;
    unsigned char counter[16] = {0};
    unsigned char stream[16] = {0};
    memcpy(counter, nonceCounter.data(), 16);
    size_t off = 0;
    if (ok) {
        ok = esp_aes_crypt_ctr(&ctx, input.size(), &off, counter, stream, input.data(), output.data()) == 0;
    }
    esp_aes_free(&ctx);
    return ok;
#else
    (void)key;
    (void)nonceCounter;
    (void)input;
    (void)output;
    return false;
#endif
}

bool softwareAesCtr(const std::vector<uint8_t> &key,
                     const std::vector<uint8_t> &nonceCounter,
                     const std::vector<uint8_t> &input,
                     std::vector<uint8_t> &output) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    bool ok = mbedtls_aes_setkey_enc(&ctx, key.data(), key.size() * 8) == 0;
    unsigned char counter[16] = {0};
    unsigned char stream[16] = {0};
    memcpy(counter, nonceCounter.data(), 16);
    size_t off = 0;
    if (ok) {
        ok = mbedtls_aes_crypt_ctr(&ctx, input.size(), &off, counter, stream, input.data(), output.data()) == 0;
    }
    mbedtls_aes_free(&ctx);
    return ok;
}

bool hardwareGcmCrypt(int mode,
                      const std::vector<uint8_t> &key,
                      const std::vector<uint8_t> &iv,
                      const std::vector<uint8_t> &aad,
                      const std::vector<uint8_t> &input,
                      std::vector<uint8_t> &output,
                      std::vector<uint8_t> &tag) {
#if ESPCRYPTO_AES_GCM_ACCEL
    esp_gcm_context ctx;
    esp_aes_gcm_init(&ctx);
    bool ok = esp_aes_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(), key.size() * 8) == 0;
    if (ok && mode == MBEDTLS_GCM_ENCRYPT) {
        ok = esp_aes_gcm_crypt_and_tag(&ctx, mode, input.size(),
                                       iv.data(), iv.size(),
                                       aad.empty() ? nullptr : aad.data(), aad.size(),
                                       input.data(), output.data(),
                                       tag.size(), tag.data()) == 0;
    } else if (ok && mode == MBEDTLS_GCM_DECRYPT) {
        ok = esp_aes_gcm_auth_decrypt(&ctx, input.size(),
                                      iv.data(), iv.size(),
                                      aad.empty() ? nullptr : aad.data(), aad.size(),
                                      tag.data(), tag.size(),
                                      input.data(), output.data()) == 0;
    }
    esp_aes_gcm_free(&ctx);
    return ok;
#else
    (void)mode;
    (void)key;
    (void)iv;
    (void)aad;
    (void)input;
    (void)output;
    (void)tag;
    return false;
#endif
}

bool softwareGcmCrypt(int mode,
                      const std::vector<uint8_t> &key,
                      const std::vector<uint8_t> &iv,
                      const std::vector<uint8_t> &aad,
                      const std::vector<uint8_t> &input,
                      std::vector<uint8_t> &output,
                      std::vector<uint8_t> &tag) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    bool ok = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(), key.size() * 8) == 0;
    if (ok && mode == MBEDTLS_GCM_ENCRYPT) {
        ok = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, input.size(),
                                       iv.data(), iv.size(),
                                       aad.empty() ? nullptr : aad.data(), aad.size(),
                                       input.data(), output.data(),
                                       tag.size(), tag.data()) == 0;
    } else if (ok && mode == MBEDTLS_GCM_DECRYPT) {
        ok = mbedtls_gcm_auth_decrypt(&ctx, input.size(),
                                      iv.data(), iv.size(),
                                      aad.empty() ? nullptr : aad.data(), aad.size(),
                                      tag.data(), tag.size(),
                                      input.data(), output.data()) == 0;
    }
    mbedtls_gcm_free(&ctx);
    return ok;
}

bool parsePasswordHash(const std::string &encoded,
                       uint8_t &cost,
                       std::vector<uint8_t> &salt,
                       std::vector<uint8_t> &hash) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= encoded.size()) {
        size_t pos = encoded.find('$', start);
        if (pos == std::string::npos) {
            parts.push_back(encoded.substr(start));
            break;
        }
        parts.push_back(encoded.substr(start, pos - start));
        start = pos + 1;
    }
    if (parts.size() < 6 || parts[1] != "esphash" || parts[2] != "v1") {
        return false;
    }
    cost = static_cast<uint8_t>(atoi(parts[3].c_str()));
    if (!base64Decode(parts[4], Base64Alphabet::Standard, salt)) {
        return false;
    }
    if (!base64Decode(parts[5], Base64Alphabet::Standard, hash)) {
        return false;
    }
    return true;
}

CryptoStatusDetail aesGcmEncryptInternal(const std::vector<uint8_t> &key,
                                         const std::vector<uint8_t> &iv,
                                         const std::vector<uint8_t> &aad,
                                         const std::vector<uint8_t> &plaintext,
                                         std::vector<uint8_t> &ciphertext,
                                         std::vector<uint8_t> &tag) {
    if (!aesKeyValid(key) || iv.empty()) {
        return makeStatus(CryptoStatus::InvalidInput, "invalid key or iv");
    }
    const CryptoPolicy &policy = mutablePolicy();
    if (!policy.allowLegacy && iv.size() < policy.minAesGcmIvBytes) {
        return makeStatus(CryptoStatus::PolicyViolation, "iv too short");
    }
    if (nonceReused(key, iv)) {
        return makeStatus(CryptoStatus::NonceReuse, "iv reuse");
    }
    ciphertext.assign(plaintext.size(), 0);
    tag.assign(AES_GCM_TAG_BYTES, 0);
    bool ok = hardwareGcmCrypt(MBEDTLS_GCM_ENCRYPT, key, iv, aad, plaintext, ciphertext, tag);
    if (!ok) {
        ok = softwareGcmCrypt(MBEDTLS_GCM_ENCRYPT, key, iv, aad, plaintext, ciphertext, tag);
    }
    if (!ok) {
        secureZero(ciphertext.data(), ciphertext.size());
        secureZero(tag.data(), tag.size());
        ciphertext.clear();
        tag.clear();
        return makeStatus(CryptoStatus::InternalError, "aes gcm encrypt failed");
    }
    return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail aesGcmDecryptInternal(const std::vector<uint8_t> &key,
                                         const std::vector<uint8_t> &iv,
                                         const std::vector<uint8_t> &aad,
                                         const std::vector<uint8_t> &ciphertext,
                                         const std::vector<uint8_t> &tag,
                                         std::vector<uint8_t> &plaintext) {
    if (!aesKeyValid(key) || iv.empty() || tag.size() != AES_GCM_TAG_BYTES) {
        return makeStatus(CryptoStatus::InvalidInput, "invalid key/iv/tag");
    }
    const CryptoPolicy &policy = mutablePolicy();
    if (!policy.allowLegacy && iv.size() < policy.minAesGcmIvBytes) {
        return makeStatus(CryptoStatus::PolicyViolation, "iv too short");
    }
    plaintext.assign(ciphertext.size(), 0);
    std::vector<uint8_t> tagCopy = tag;
    bool ok = hardwareGcmCrypt(MBEDTLS_GCM_DECRYPT, key, iv, aad, ciphertext, plaintext, tagCopy);
    if (!ok) {
        tagCopy = tag;
        ok = softwareGcmCrypt(MBEDTLS_GCM_DECRYPT, key, iv, aad, ciphertext, plaintext, tagCopy);
    }
    if (!ok) {
        secureZero(plaintext.data(), plaintext.size());
        plaintext.clear();
        return makeStatus(CryptoStatus::VerifyFailed, "gcm auth failed");
    }
    return makeStatus(CryptoStatus::Ok);
}

}  // namespace

const char *toString(CryptoStatus status) {
    switch (status) {
        case CryptoStatus::Ok:
            return "ok";
        case CryptoStatus::InvalidInput:
            return "invalid input";
        case CryptoStatus::RandomFailure:
            return "random source failed";
        case CryptoStatus::Unsupported:
            return "unsupported";
        case CryptoStatus::PolicyViolation:
            return "policy violation";
        case CryptoStatus::BufferTooSmall:
            return "buffer too small";
        case CryptoStatus::VerifyFailed:
            return "verification failed";
        case CryptoStatus::DecodeError:
            return "decode error";
        case CryptoStatus::JsonError:
            return "json error";
        case CryptoStatus::Expired:
            return "token expired";
        case CryptoStatus::NotYetValid:
            return "token not active";
        case CryptoStatus::AudienceMismatch:
            return "audience mismatch";
        case CryptoStatus::IssuerMismatch:
            return "issuer mismatch";
        case CryptoStatus::NonceReuse:
            return "nonce reuse detected";
        case CryptoStatus::InternalError:
        default:
            return "internal error";
    }
}

SecureBuffer::SecureBuffer(size_t bytes) {
    buffer.assign(bytes, 0);
}

SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept : buffer(std::move(other.buffer)) {
    other.wipe();
}

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept {
    if (this != &other) {
        wipe();
        buffer = std::move(other.buffer);
        other.wipe();
    }
    return *this;
}

SecureBuffer::~SecureBuffer() {
    wipe();
}

void SecureBuffer::wipe() {
    if (!buffer.empty()) {
        secureZero(buffer.data(), buffer.size());
        buffer.clear();
    }
}

void SecureBuffer::resize(size_t bytes) {
    wipe();
    buffer.assign(bytes, 0);
}

SecureString::SecureString(std::string value) : value(std::move(value)) {}

SecureString::SecureString(SecureString &&other) noexcept : value(std::move(other.value)) {
    other.wipe();
}

SecureString &SecureString::operator=(SecureString &&other) noexcept {
    if (this != &other) {
        wipe();
        value = std::move(other.value);
        other.wipe();
    }
    return *this;
}

SecureString::~SecureString() {
    wipe();
}

void SecureString::wipe() {
    if (!value.empty()) {
        secureZero(&value[0], value.size());
        value.clear();
    }
}

void ESPCrypto::setPolicy(const CryptoPolicy &policy) {
    mutablePolicy() = policy;
}

CryptoPolicy ESPCrypto::policy() {
    return mutablePolicy();
}

CryptoCaps ESPCrypto::caps() {
    CryptoCaps c;
    c.shaAccel = ESPCRYPTO_SHA_ACCEL;
    c.aesAccel = ESPCRYPTO_AES_ACCEL;
    c.aesGcmAccel = ESPCRYPTO_AES_GCM_ACCEL;
    return c;
}

bool ESPCrypto::constantTimeEq(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
    return constantTimeEquals(CryptoSpan<const uint8_t>(a), CryptoSpan<const uint8_t>(b));
}

bool ESPCrypto::constantTimeEq(CryptoSpan<const uint8_t> a, CryptoSpan<const uint8_t> b) {
    return constantTimeEquals(a, b);
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::shaResult(CryptoSpan<const uint8_t> data, const ShaOptions &options) {
    CryptoResult<std::vector<uint8_t>> result;
    if (!data.data() && data.size() > 0) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "null data");
        return result;
    }
    result.value.assign(digestLength(options.variant), 0);
    if (result.value.empty()) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "unknown sha variant");
        return result;
    }
    static const uint8_t ZERO_BYTE = 0;
    const uint8_t *buffer = data.size() == 0 ? &ZERO_BYTE : data.data();
    size_t length = data.size();
    bool hashed = false;
    if (options.preferHardware) {
        hashed = tryHardwareSha(options.variant, buffer, length, result.value.data());
    }
    if (!hashed) {
        hashed = softwareSha(options.variant, buffer, length, result.value.data());
    }
    if (!hashed) {
        secureZero(result.value.data(), result.value.size());
        result.value.clear();
        result.status = makeStatus(CryptoStatus::InternalError, "sha failed");
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

std::vector<uint8_t> ESPCrypto::sha(const uint8_t *data, size_t length, const ShaOptions &options) {
    auto result = shaResult(CryptoSpan<const uint8_t>(data, length), options);
    return result.ok() ? result.value : std::vector<uint8_t>();
}

std::vector<uint8_t> ESPCrypto::sha(const std::vector<uint8_t> &data, const ShaOptions &options) {
    return sha(data.data(), data.size(), options);
}

String ESPCrypto::shaHex(const uint8_t *data, size_t length, const ShaOptions &options) {
    auto digest = sha(data, length, options);
    if (digest.empty()) {
        return String();
    }
    static const char *HEX_DIGITS = "0123456789abcdef";
    std::string hex;
    hex.reserve(digest.size() * 2);
    for (uint8_t b : digest) {
        hex.push_back(HEX_DIGITS[(b >> 4) & 0x0F]);
        hex.push_back(HEX_DIGITS[b & 0x0F]);
    }
    return String(hex.c_str());
}

String ESPCrypto::shaHex(const String &text, const ShaOptions &options) {
    return shaHex(reinterpret_cast<const uint8_t *>(text.c_str()), text.length(), options);
}

bool ESPCrypto::aesGcmEncrypt(const std::vector<uint8_t> &key,
                              const std::vector<uint8_t> &iv,
                              const std::vector<uint8_t> &plaintext,
                              std::vector<uint8_t> &ciphertext,
                              std::vector<uint8_t> &tag,
                              const std::vector<uint8_t> &aad) {
    CryptoStatusDetail status = aesGcmEncryptInternal(key, iv, aad, plaintext, ciphertext, tag);
    if (!status.ok()) {
        secureZero(ciphertext.data(), ciphertext.size());
        secureZero(tag.data(), tag.size());
    }
    return status.ok();
}

bool ESPCrypto::aesGcmDecrypt(const std::vector<uint8_t> &key,
                              const std::vector<uint8_t> &iv,
                              const std::vector<uint8_t> &ciphertext,
                              const std::vector<uint8_t> &tag,
                              std::vector<uint8_t> &plaintext,
                              const std::vector<uint8_t> &aad) {
    CryptoStatusDetail status = aesGcmDecryptInternal(key, iv, aad, ciphertext, tag, plaintext);
    if (!status.ok()) {
        secureZero(plaintext.data(), plaintext.size());
        plaintext.clear();
    }
    return status.ok();
}

bool ESPCrypto::aesCtrCrypt(const std::vector<uint8_t> &key,
                            const std::vector<uint8_t> &nonceCounter,
                            const std::vector<uint8_t> &input,
                            std::vector<uint8_t> &output) {
    auto result = aesCtrCrypt(key, nonceCounter, input);
    if (!result.ok()) {
        output.clear();
        return false;
    }
    output = std::move(result.value);
    return true;
}

CryptoResult<GcmMessage> ESPCrypto::aesGcmEncryptAuto(const std::vector<uint8_t> &key,
                                                      const std::vector<uint8_t> &plaintext,
                                                      const std::vector<uint8_t> &aad,
                                                      size_t ivLength) {
    CryptoResult<GcmMessage> result;
    const CryptoPolicy &policy = mutablePolicy();
    if (ivLength == 0) {
        ivLength = policy.minAesGcmIvBytes;
    }
    if (!policy.allowLegacy && ivLength < policy.minAesGcmIvBytes) {
        result.status = makeStatus(CryptoStatus::PolicyViolation, "iv too short");
        return result;
    }
    result.value.iv.assign(ivLength, 0);
    fillRandom(result.value.iv.data(), result.value.iv.size());
    result.status = aesGcmEncryptInternal(key, result.value.iv, aad, plaintext, result.value.ciphertext, result.value.tag);
    if (!result.ok()) {
        result.value = {};
    }
    return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::aesGcmDecrypt(const std::vector<uint8_t> &key,
                                                            const std::vector<uint8_t> &iv,
                                                            const std::vector<uint8_t> &ciphertext,
                                                            const std::vector<uint8_t> &tag,
                                                            const std::vector<uint8_t> &aad) {
    CryptoResult<std::vector<uint8_t>> result;
    result.status = aesGcmDecryptInternal(key, iv, aad, ciphertext, tag, result.value);
    if (!result.ok()) {
        result.value.clear();
    }
    return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::aesCtrCrypt(const std::vector<uint8_t> &key,
                                                          const std::vector<uint8_t> &nonceCounter,
                                                          const std::vector<uint8_t> &input) {
    CryptoResult<std::vector<uint8_t>> result;
    if (!aesKeyValid(key) || nonceCounter.size() != 16) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "invalid key or nonce");
        return result;
    }
    result.value.assign(input.size(), 0);
    bool ok = hardwareAesCtr(key, nonceCounter, input, result.value);
    if (!ok) {
        ok = softwareAesCtr(key, nonceCounter, input, result.value);
    }
    if (!ok) {
        secureZero(result.value.data(), result.value.size());
        result.value.clear();
        result.status = makeStatus(CryptoStatus::InternalError, "aes ctr failed");
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

bool ESPCrypto::rsaSign(const std::string &privateKeyPem,
                        const uint8_t *data,
                        size_t length,
                        ShaVariant variant,
                        std::vector<uint8_t> &signature) {
    if (privateKeyPem.empty() || (!data && length > 0)) {
        return false;
    }
    return pkSignInternal(privateKeyPem, MBEDTLS_PK_RSA, variant, data, length, signature);
}

bool ESPCrypto::rsaVerify(const std::string &publicKeyPem,
                          const uint8_t *data,
                          size_t length,
                          const std::vector<uint8_t> &signature,
                          ShaVariant variant) {
    if (publicKeyPem.empty() || (!data && length > 0) || signature.empty()) {
        return false;
    }
    return pkVerifyInternal(publicKeyPem, MBEDTLS_PK_RSA, variant, data, length, signature);
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::rsaSign(const std::string &privateKeyPem,
                                                      CryptoSpan<const uint8_t> data,
                                                      ShaVariant variant) {
    CryptoResult<std::vector<uint8_t>> result;
    if (privateKeyPem.empty() || (!data.data() && data.size() > 0)) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing key or data");
        return result;
    }
    if (!pkSignInternal(privateKeyPem, MBEDTLS_PK_RSA, variant, data.data(), data.size(), result.value)) {
        result.status = makeStatus(CryptoStatus::VerifyFailed, "rsa sign failed");
        result.value.clear();
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoResult<void> ESPCrypto::rsaVerify(const std::string &publicKeyPem,
                                        CryptoSpan<const uint8_t> data,
                                        CryptoSpan<const uint8_t> signature,
                                        ShaVariant variant) {
    CryptoResult<void> result;
    if (publicKeyPem.empty() || (!data.data() && data.size() > 0) || signature.empty()) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing key/data/signature");
        return result;
    }
    if (!pkVerifyInternal(publicKeyPem, MBEDTLS_PK_RSA, variant, data.data(), data.size(), std::vector<uint8_t>(signature.data(), signature.data() + signature.size()))) {
        result.status = makeStatus(CryptoStatus::VerifyFailed, "rsa verify failed");
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

bool ESPCrypto::eccSign(const std::string &privateKeyPem,
                        const uint8_t *data,
                        size_t length,
                        ShaVariant variant,
                        std::vector<uint8_t> &signature) {
    if (privateKeyPem.empty() || (!data && length > 0)) {
        return false;
    }
    return pkSignInternal(privateKeyPem, MBEDTLS_PK_ECKEY, variant, data, length, signature);
}

bool ESPCrypto::eccVerify(const std::string &publicKeyPem,
                          const uint8_t *data,
                          size_t length,
                          const std::vector<uint8_t> &signature,
                          ShaVariant variant) {
    if (publicKeyPem.empty() || (!data && length > 0) || signature.empty()) {
        return false;
    }
    return pkVerifyInternal(publicKeyPem, MBEDTLS_PK_ECKEY, variant, data, length, signature);
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::eccSign(const std::string &privateKeyPem,
                                                      CryptoSpan<const uint8_t> data,
                                                      ShaVariant variant) {
    CryptoResult<std::vector<uint8_t>> result;
    if (privateKeyPem.empty() || (!data.data() && data.size() > 0)) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing key or data");
        return result;
    }
    if (!pkSignInternal(privateKeyPem, MBEDTLS_PK_ECKEY, variant, data.data(), data.size(), result.value)) {
        result.status = makeStatus(CryptoStatus::VerifyFailed, "ecc sign failed");
        result.value.clear();
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoResult<void> ESPCrypto::eccVerify(const std::string &publicKeyPem,
                                        CryptoSpan<const uint8_t> data,
                                        CryptoSpan<const uint8_t> signature,
                                        ShaVariant variant) {
    CryptoResult<void> result;
    if (publicKeyPem.empty() || (!data.data() && data.size() > 0) || signature.empty()) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing key/data/signature");
        return result;
    }
    if (!pkVerifyInternal(publicKeyPem, MBEDTLS_PK_ECKEY, variant, data.data(), data.size(), std::vector<uint8_t>(signature.data(), signature.data() + signature.size()))) {
        result.status = makeStatus(CryptoStatus::VerifyFailed, "ecc verify failed");
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

String ESPCrypto::createJwt(const JsonDocument &claims,
                            const std::string &key,
                            const JwtSignOptions &options) {
    auto result = createJwtResult(claims, key, options);
    return result.ok() ? result.value : String();
}

bool ESPCrypto::verifyJwt(const String &token,
                          const std::string &key,
                          JsonDocument &outClaims,
                          String &error,
                          const JwtVerifyOptions &options) {
    auto result = verifyJwtResult(token, key, outClaims, options);
    if (!result.ok()) {
        error = result.status.message.length() > 0 ? result.status.message : String(toString(result.status.code));
        return false;
    }
    error = "";
    return true;
}

CryptoResult<String> ESPCrypto::createJwtResult(const JsonDocument &claims,
                                                const std::string &key,
                                                const JwtSignOptions &options) {
    CryptoResult<String> result;
    if (key.empty()) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "key missing");
        return result;
    }
    JsonDocument header;
    std::string algName = algorithmName(options.algorithm);
    if (algName.empty()) {
        result.status = makeStatus(CryptoStatus::Unsupported, "unsupported alg");
        return result;
    }
    header["alg"] = algName.c_str();
    header["typ"] = "JWT";
    if (options.keyId.length() > 0) {
        header["kid"] = options.keyId.c_str();
    }
    JsonDocument payload;
    payload.set(claims);
    if (options.issuer.length() > 0 && payload["iss"].isNull()) {
        payload["iss"] = options.issuer.c_str();
    }
    if (options.subject.length() > 0 && payload["sub"].isNull()) {
        payload["sub"] = options.subject.c_str();
    }
    if (options.audience.length() > 0 && payload["aud"].isNull()) {
        payload["aud"] = options.audience.c_str();
    }
    uint32_t now = currentTimeSeconds(options.currentTimestamp != 0 ? options.currentTimestamp : options.issuedAt);
    if (options.issuedAt != 0) {
        payload["iat"] = options.issuedAt;
    } else {
        payload["iat"] = now;
    }
    if (options.expiresInSeconds > 0) {
        payload["exp"] = static_cast<uint32_t>(payload["iat"].as<uint32_t>() + options.expiresInSeconds);
    }
    if (options.notBefore > 0) {
        payload["nbf"] = options.notBefore;
    }

    std::string headerJson;
    if (serializeJson(header, headerJson) == 0) {
        result.status = makeStatus(CryptoStatus::JsonError, "header serialization failed");
        return result;
    }
    std::string payloadJson;
    if (serializeJson(payload, payloadJson) == 0) {
        result.status = makeStatus(CryptoStatus::JsonError, "payload serialization failed");
        return result;
    }

    std::string encodedHeader = base64Encode(reinterpret_cast<const uint8_t *>(headerJson.data()), headerJson.size(), Base64Alphabet::Url);
    std::string encodedPayload = base64Encode(reinterpret_cast<const uint8_t *>(payloadJson.data()), payloadJson.size(), Base64Alphabet::Url);
    if (encodedHeader.empty() || encodedPayload.empty()) {
        result.status = makeStatus(CryptoStatus::DecodeError, "base64 encode failed");
        return result;
    }
    std::string signingInput = encodedHeader + "." + encodedPayload;
    std::vector<uint8_t> signature;
    if (!signJwt(options.algorithm, key,
                 reinterpret_cast<const uint8_t *>(signingInput.data()), signingInput.size(), signature)) {
        result.status = makeStatus(CryptoStatus::InternalError, "sign failed");
        return result;
    }
    std::string encodedSignature = base64Encode(signature.data(), signature.size(), Base64Alphabet::Url);
    std::string token = signingInput + "." + encodedSignature;
    result.value = String(token.c_str());
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoResult<void> ESPCrypto::verifyJwtResult(const String &token,
                                              const std::string &key,
                                              JsonDocument &outClaims,
                                              const JwtVerifyOptions &options) {
    CryptoResult<void> result;
    if (token.length() == 0 || key.empty()) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "token or key missing");
        return result;
    }
    std::string tokenStd(token.c_str(), token.length());
    size_t first = tokenStd.find('.');
    size_t second = tokenStd.find('.', first == std::string::npos ? 0 : first + 1);
    if (first == std::string::npos || second == std::string::npos) {
        result.status = makeStatus(CryptoStatus::DecodeError, "invalid token structure");
        return result;
    }
    std::string headerPart = tokenStd.substr(0, first);
    std::string payloadPart = tokenStd.substr(first + 1, second - first - 1);
    std::string signaturePart = tokenStd.substr(second + 1);
    std::vector<uint8_t> headerBytes;
    std::vector<uint8_t> payloadBytes;
    std::vector<uint8_t> signatureBytes;
    if (!base64Decode(headerPart, Base64Alphabet::Url, headerBytes) ||
        !base64Decode(payloadPart, Base64Alphabet::Url, payloadBytes) ||
        !base64Decode(signaturePart, Base64Alphabet::Url, signatureBytes)) {
        result.status = makeStatus(CryptoStatus::DecodeError, "base64 decode failed");
        return result;
    }
    JsonDocument headerDoc;
    if (deserializeJson(headerDoc, headerBytes.data(), headerBytes.size()) != DeserializationError::Ok) {
        result.status = makeStatus(CryptoStatus::JsonError, "invalid header json");
        return result;
    }
    JsonDocument payloadDoc;
    if (deserializeJson(payloadDoc, payloadBytes.data(), payloadBytes.size()) != DeserializationError::Ok) {
        result.status = makeStatus(CryptoStatus::JsonError, "invalid payload json");
        return result;
    }
    const char *algStr = headerDoc["alg"].as<const char *>();
    JwtAlgorithm alg = algorithmFromName(algStr ? algStr : "");
    if (alg == JwtAlgorithm::Auto) {
        result.status = makeStatus(CryptoStatus::Unsupported, "unsupported alg");
        return result;
    }
    if (options.algorithm != JwtAlgorithm::Auto && options.algorithm != alg) {
        result.status = makeStatus(CryptoStatus::PolicyViolation, "alg mismatch");
        return result;
    }
    std::string signingInput = headerPart + "." + payloadPart;
    if (!verifySignature(alg, key,
                         reinterpret_cast<const uint8_t *>(signingInput.data()), signingInput.size(),
                         signatureBytes)) {
        result.status = makeStatus(CryptoStatus::VerifyFailed, "signature mismatch");
        return result;
    }
    uint32_t now = currentTimeSeconds(options.currentTimestamp);
    uint32_t exp = payloadDoc["exp"].as<uint32_t>();
    uint32_t nbf = payloadDoc["nbf"].as<uint32_t>();
    if (options.requireExpiration && exp == 0) {
        result.status = makeStatus(CryptoStatus::PolicyViolation, "missing exp");
        return result;
    }
    if (exp != 0 && now > exp) {
        result.status = makeStatus(CryptoStatus::Expired, "token expired");
        return result;
    }
    if (nbf != 0 && now < nbf) {
        result.status = makeStatus(CryptoStatus::NotYetValid, "token not active");
        return result;
    }
    if (options.audience.length() > 0) {
        const char *aud = payloadDoc["aud"].as<const char *>();
        if (!aud || options.audience != aud) {
            result.status = makeStatus(CryptoStatus::AudienceMismatch, "aud mismatch");
            return result;
        }
    }
    if (options.issuer.length() > 0) {
        const char *iss = payloadDoc["iss"].as<const char *>();
        if (!iss || options.issuer != iss) {
            result.status = makeStatus(CryptoStatus::IssuerMismatch, "iss mismatch");
            return result;
        }
    }
    outClaims.set(payloadDoc);
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}
String ESPCrypto::hashString(const String &input, const PasswordHashOptions &options) {
    auto result = hashStringResult(input, options);
    return result.ok() ? result.value : String();
}

bool ESPCrypto::verifyString(const String &input, const String &encoded) {
    auto result = verifyStringResult(input, encoded);
    return result.ok();
}

CryptoResult<String> ESPCrypto::hashStringResult(const String &input, const PasswordHashOptions &options) {
    CryptoResult<String> result;
    if (input.length() == 0 || options.saltBytes == 0 || options.outputBytes == 0) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing password or params");
        return result;
    }
    std::vector<uint8_t> salt(options.saltBytes, 0);
    fillRandom(salt.data(), salt.size());
    uint8_t cost = std::min<uint8_t>(options.cost, 31);
    uint32_t iterations = 1u << cost;
    const CryptoPolicy &policy = mutablePolicy();
    if (!policy.allowLegacy && iterations < policy.minPbkdf2Iterations) {
        uint8_t adjustedCost = cost;
        while ((1u << adjustedCost) < policy.minPbkdf2Iterations && adjustedCost < 31) {
            adjustedCost++;
        }
        cost = adjustedCost;
        iterations = 1u << cost;
    }
    auto derived = pbkdf2(input, CryptoSpan<const uint8_t>(salt), iterations, options.outputBytes);
    if (!derived.ok()) {
        result.status = derived.status;
        return result;
    }
    std::string saltB64 = base64Encode(salt.data(), salt.size(), Base64Alphabet::Standard);
    std::string hashB64 = base64Encode(derived.value.data(), derived.value.size(), Base64Alphabet::Standard);
    secureZero(derived.value.data(), derived.value.size());
    if (saltB64.empty() || hashB64.empty()) {
        result.status = makeStatus(CryptoStatus::InternalError, "base64 encode failed");
        return result;
    }
    std::string encoded = "$esphash$v1$" + std::to_string(cost) + "$" + saltB64 + "$" + hashB64;
    result.value = String(encoded.c_str());
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoResult<void> ESPCrypto::verifyStringResult(const String &input, const String &encoded) {
    CryptoResult<void> result;
    if (input.length() == 0 || encoded.length() == 0) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing password or encoded hash");
        return result;
    }
    uint8_t cost = 0;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> hash;
    std::string encodedStd(encoded.c_str(), encoded.length());
    if (!parsePasswordHash(encodedStd, cost, salt, hash)) {
        result.status = makeStatus(CryptoStatus::DecodeError, "invalid esphash envelope");
        return result;
    }
    if (salt.empty() || hash.empty()) {
        result.status = makeStatus(CryptoStatus::DecodeError, "invalid esphash parts");
        return result;
    }
    uint32_t iterations = 1u << cost;
    const CryptoPolicy &policy = mutablePolicy();
    if (!policy.allowLegacy && iterations < policy.minPbkdf2Iterations) {
        result.status = makeStatus(CryptoStatus::PolicyViolation, "pbkdf2 iterations below policy");
        return result;
    }
    auto derived = pbkdf2(input, CryptoSpan<const uint8_t>(salt), iterations, hash.size());
    if (!derived.ok()) {
        result.status = derived.status;
        return result;
    }
    bool match = constantTimeEquals(CryptoSpan<const uint8_t>(hash), CryptoSpan<const uint8_t>(derived.value));
    secureZero(derived.value.data(), derived.value.size());
    result.status = match ? makeStatus(CryptoStatus::Ok) : makeStatus(CryptoStatus::VerifyFailed, "hash mismatch");
    return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::hmac(ShaVariant variant,
                                                   CryptoSpan<const uint8_t> key,
                                                   CryptoSpan<const uint8_t> data) {
    CryptoResult<std::vector<uint8_t>> result;
    const mbedtls_md_info_t *info = mdInfoForVariant(variant);
    if (!info) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "invalid sha variant");
        return result;
    }
    result.value.assign(mbedtls_md_get_size(info), 0);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int ret = mbedtls_md_setup(&ctx, info, 1);
    if (ret == 0) {
        ret = mbedtls_md_hmac_starts(&ctx, reinterpret_cast<const unsigned char *>(key.data()), key.size());
    }
    if (ret == 0) {
        ret = mbedtls_md_hmac_update(&ctx, data.data(), data.size());
    }
    if (ret == 0) {
        ret = mbedtls_md_hmac_finish(&ctx, result.value.data());
    }
    mbedtls_md_free(&ctx);
    if (ret != 0) {
        secureZero(result.value.data(), result.value.size());
        result.value.clear();
        result.status = makeStatus(CryptoStatus::InternalError, "hmac failed");
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::hkdf(ShaVariant variant,
                                                   CryptoSpan<const uint8_t> salt,
                                                   CryptoSpan<const uint8_t> ikm,
                                                   CryptoSpan<const uint8_t> info,
                                                   size_t length) {
    CryptoResult<std::vector<uint8_t>> result;
    if (length == 0) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "length missing");
        return result;
    }
    const size_t hashLen = digestLength(variant);
    if (hashLen == 0) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "invalid sha variant");
        return result;
    }
    size_t blocks = (length + hashLen - 1) / hashLen;
    if (blocks > 255) {
        result.status = makeStatus(CryptoStatus::BufferTooSmall, "length too large");
        return result;
    }
    std::vector<uint8_t> actualSalt;
    if (salt.empty()) {
        actualSalt.assign(hashLen, 0);
    } else {
        actualSalt.assign(salt.data(), salt.data() + salt.size());
    }
    auto prk = hmac(variant, CryptoSpan<const uint8_t>(actualSalt), ikm);
    secureZero(actualSalt.data(), actualSalt.size());
    if (!prk.ok()) {
        result.status = prk.status;
        return result;
    }
    result.value.reserve(length);
    std::vector<uint8_t> previous;
    for (size_t i = 0; i < blocks; ++i) {
        std::vector<uint8_t> blockInput;
        blockInput.insert(blockInput.end(), previous.begin(), previous.end());
        if (!info.empty()) {
            blockInput.insert(blockInput.end(), info.data(), info.data() + info.size());
        }
        blockInput.push_back(static_cast<uint8_t>(i + 1));
        auto block = hmac(variant, CryptoSpan<const uint8_t>(prk.value), CryptoSpan<const uint8_t>(blockInput));
        secureZero(blockInput.data(), blockInput.size());
        if (!block.ok()) {
            secureZero(prk.value.data(), prk.value.size());
            result.status = block.status;
            return result;
        }
        size_t take = std::min(hashLen, length - result.value.size());
        result.value.insert(result.value.end(), block.value.begin(), block.value.begin() + take);
        previous = std::move(block.value);
    }
    secureZero(prk.value.data(), prk.value.size());
    secureZero(previous.data(), previous.size());
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::pbkdf2(const String &password,
                                                     CryptoSpan<const uint8_t> salt,
                                                     uint32_t iterations,
                                                     size_t outputLength) {
    CryptoResult<std::vector<uint8_t>> result;
    if (password.length() == 0 || salt.empty() || outputLength == 0) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing password/salt/len");
        return result;
    }
    const CryptoPolicy &policy = mutablePolicy();
    if (!policy.allowLegacy && iterations < policy.minPbkdf2Iterations) {
        result.status = makeStatus(CryptoStatus::PolicyViolation, "iterations below policy");
        return result;
    }
    result.value.assign(outputLength, 0);
    int ret = pbkdf2Sha256(reinterpret_cast<const unsigned char *>(password.c_str()),
                           password.length(),
                           salt.data(),
                           salt.size(),
                           iterations,
                           result.value.data(),
                           result.value.size());
    if (ret != 0) {
        secureZero(result.value.data(), result.value.size());
        result.value.clear();
        result.status = makeStatus(CryptoStatus::InternalError, "pbkdf2 failed");
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}
