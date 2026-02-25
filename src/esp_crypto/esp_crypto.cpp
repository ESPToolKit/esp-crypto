#include "esp_crypto.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <random>
#include <ctime>
#include <string>
#include <vector>
#include <type_traits>
#include <map>
#include <functional>
#include <atomic>

#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/version.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/ecdh.h"
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

#if defined(ESP_PLATFORM)
extern "C" {
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"
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

JwtAlgorithm algorithmFromName(const std::string &name);

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

struct GlobalRuntimeState {
    std::atomic<bool> initialized{false};
    std::map<std::string, bool> nvsInitMap;
#if ESPCRYPTO_ENABLE_NONCE_GUARD
    std::array<NonceRecord, ESPCRYPTO_NONCE_GUARD_CACHE> nonceCache = {};
    size_t nonceCursor = 0;
#endif
    std::atomic<uint64_t> bootCounter{0};
};

GlobalRuntimeState &runtimeState() {
    static GlobalRuntimeState state;
    return state;
}

void markRuntimeInitialized() {
    runtimeState().initialized.store(true, std::memory_order_release);
}

void resetRuntimeState() {
    GlobalRuntimeState &state = runtimeState();
    state.nvsInitMap.clear();
#if ESPCRYPTO_ENABLE_NONCE_GUARD
    for (auto &record : state.nonceCache) {
        record = NonceRecord{};
    }
    state.nonceCursor = 0;
#endif
    state.bootCounter.store(0, std::memory_order_release);
    mutablePolicy() = CryptoPolicy{};
    state.initialized.store(false, std::memory_order_release);
}

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
    GlobalRuntimeState &state = runtimeState();
    if (iv.empty() || iv.size() > state.nonceCache[0].iv.size()) {
        return false;
    }
    markRuntimeInitialized();
    uint32_t keyHash = fingerprintKey(key);
    for (const auto &record : state.nonceCache) {
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
    NonceRecord &slot = state.nonceCache[state.nonceCursor % state.nonceCache.size()];
    slot.used = true;
    slot.keyHash = keyHash;
    slot.ivLen = iv.size();
    memcpy(slot.iv.data(), iv.data(), iv.size());
    state.nonceCursor++;
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

CryptoResult<std::vector<uint8_t>> ecdsaDerToRawInternal(CryptoSpan<const uint8_t> der) {
    CryptoResult<std::vector<uint8_t>> result;
    unsigned char *cursor = const_cast<unsigned char *>(der.data());
    const unsigned char *end = der.data() + der.size();
    size_t len = 0;
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    do {
        if (mbedtls_asn1_get_tag(&cursor, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
            result.status = makeStatus(CryptoStatus::DecodeError, "asn1 seq");
            break;
        }
        if (mbedtls_asn1_get_mpi(&cursor, end, &r) != 0 || mbedtls_asn1_get_mpi(&cursor, end, &s) != 0) {
            result.status = makeStatus(CryptoStatus::DecodeError, "asn1 mpi");
            break;
        }
        size_t rlen = mbedtls_mpi_size(&r);
        size_t slen = mbedtls_mpi_size(&s);
        size_t part = std::max(rlen, slen);
        result.value.assign(part * 2, 0);
        mbedtls_mpi_write_binary(&r, result.value.data() + (part - rlen), rlen);
        mbedtls_mpi_write_binary(&s, result.value.data() + part + (part - slen), slen);
        result.status = makeStatus(CryptoStatus::Ok);
    } while (false);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return result;
}

CryptoResult<std::vector<uint8_t>> ecdsaRawToDerInternal(CryptoSpan<const uint8_t> raw) {
    CryptoResult<std::vector<uint8_t>> result;
    if (raw.size() % 2 != 0 || raw.empty()) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "raw len invalid");
        return result;
    }
    size_t part = raw.size() / 2;
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    do {
        if (mbedtls_mpi_read_binary(&r, raw.data(), part) != 0 || mbedtls_mpi_read_binary(&s, raw.data() + part, part) != 0) {
            result.status = makeStatus(CryptoStatus::DecodeError, "raw mpi");
            break;
        }
        unsigned char buffer[200];
        unsigned char *p = buffer + sizeof(buffer);
        size_t len = 0;
        if (mbedtls_asn1_write_mpi(&p, buffer, &s) < 0 || mbedtls_asn1_write_mpi(&p, buffer, &r) < 0) {
            result.status = makeStatus(CryptoStatus::InternalError, "asn1 mpi write");
            break;
        }
        len = static_cast<size_t>(buffer + sizeof(buffer) - p);
        if (mbedtls_asn1_write_len(&p, buffer, len) < 0 ||
            mbedtls_asn1_write_tag(&p, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) < 0) {
            result.status = makeStatus(CryptoStatus::InternalError, "asn1 len");
            break;
        }
        size_t total = static_cast<size_t>(buffer + sizeof(buffer) - p);
        result.value.assign(p, p + total);
        result.status = makeStatus(CryptoStatus::Ok);
    } while (false);
    do {
        if (mbedtls_mpi_read_binary(&r, raw.data(), part) != 0 || mbedtls_mpi_read_binary(&s, raw.data() + part, part) != 0) {
            result.status = makeStatus(CryptoStatus::DecodeError, "raw mpi");
            break;
        }
        unsigned char buffer[200];
        unsigned char *p = buffer + sizeof(buffer);
        size_t len = 0;
        if (mbedtls_asn1_write_mpi(&p, buffer, &s) < 0 || mbedtls_asn1_write_mpi(&p, buffer, &r) < 0) {
            result.status = makeStatus(CryptoStatus::InternalError, "asn1 mpi write");
            break;
        }
        len = static_cast<size_t>(buffer + sizeof(buffer) - p);
        if (mbedtls_asn1_write_len(&p, buffer, len) < 0 ||
            mbedtls_asn1_write_tag(&p, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) < 0) {
            result.status = makeStatus(CryptoStatus::InternalError, "asn1 len");
            break;
        }
        size_t total = static_cast<size_t>(buffer + sizeof(buffer) - p);
        result.value.assign(p, p + total);
        result.status = makeStatus(CryptoStatus::Ok);
    } while (false);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return result;
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

CryptoStatusDetail buildRsaPemFromJwk(const std::vector<uint8_t> &n,
                                      const std::vector<uint8_t> &e,
                                      std::string &outPem) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    CryptoStatusDetail status = makeStatus(CryptoStatus::InternalError, "rsa setup failed");
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
        mbedtls_pk_free(&pk);
        return status;
    }
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    if (mbedtls_rsa_import_raw(rsa, n.data(), n.size(), nullptr, 0, nullptr, 0, nullptr, 0, e.data(), e.size()) != 0 ||
        mbedtls_rsa_complete(rsa) != 0 ||
        mbedtls_rsa_check_pubkey(rsa) != 0) {
        mbedtls_pk_free(&pk);
        return makeStatus(CryptoStatus::DecodeError, "rsa jwk invalid");
    }
    std::vector<uint8_t> buffer(1600, 0);
    if (mbedtls_pk_write_pubkey_pem(&pk, buffer.data(), buffer.size()) != 0) {
        mbedtls_pk_free(&pk);
        return status;
    }
    outPem.assign(reinterpret_cast<const char *>(buffer.data()));
    mbedtls_pk_free(&pk);
    return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail buildEcPemFromJwk(const std::vector<uint8_t> &x,
                                     const std::vector<uint8_t> &y,
                                     const std::string &crv,
                                     std::string &outPem) {
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_ecp_keypair *ec = nullptr;
    CryptoStatusDetail status = makeStatus(CryptoStatus::Unsupported, "curve unsupported");
    mbedtls_ecp_group_id gid = MBEDTLS_ECP_DP_NONE;
    if (crv == "P-256") {
        gid = MBEDTLS_ECP_DP_SECP256R1;
    }
    if (gid == MBEDTLS_ECP_DP_NONE) {
        return status;
    }
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0) {
        mbedtls_pk_free(&pk);
        return makeStatus(CryptoStatus::InternalError, "ec setup failed");
    }
    ec = mbedtls_pk_ec(pk);
    if (!ec || mbedtls_ecp_group_load(&ec->MBEDTLS_PRIVATE(grp), gid) != 0) {
        mbedtls_pk_free(&pk);
        return status;
    }
    if (mbedtls_mpi_read_binary(&ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), x.data(), x.size()) != 0 ||
        mbedtls_mpi_read_binary(&ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), y.data(), y.size()) != 0) {
        mbedtls_pk_free(&pk);
        return makeStatus(CryptoStatus::DecodeError, "ec coord read");
    }
    if (mbedtls_mpi_lset(&ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Z), 1) != 0) {
        mbedtls_pk_free(&pk);
        return makeStatus(CryptoStatus::DecodeError, "ec coord set");
    }
    if (mbedtls_ecp_check_pubkey(&ec->MBEDTLS_PRIVATE(grp), &ec->MBEDTLS_PRIVATE(Q)) != 0) {
        mbedtls_pk_free(&pk);
        return makeStatus(CryptoStatus::DecodeError, "ec jwk invalid");
    }
    {
        std::vector<uint8_t> buffer(800, 0);
        if (mbedtls_pk_write_pubkey_pem(&pk, buffer.data(), buffer.size()) != 0) {
            mbedtls_pk_free(&pk);
            return makeStatus(CryptoStatus::InternalError, "ec pem write failed");
        }
        outPem.assign(reinterpret_cast<const char *>(buffer.data()));
    }
    mbedtls_pk_free(&pk);
    return makeStatus(CryptoStatus::Ok);
}

CryptoResult<CryptoKey> jwkToKey(const JsonObjectConst &jwk) {
    CryptoResult<CryptoKey> result;
    const char *kty = jwk["kty"].as<const char *>();
    if (!kty) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing kty");
        return result;
    }
    if (strcmp(kty, "oct") == 0) {
        std::vector<uint8_t> k;
        if (!base64Decode(jwk["k"].as<const char *>(), Base64Alphabet::Url, k)) {
            result.status = makeStatus(CryptoStatus::DecodeError, "oct decode failed");
            return result;
        }
        result.value = CryptoKey::fromRaw(k, KeyKind::Symmetric);
        result.status = makeStatus(CryptoStatus::Ok);
        return result;
    }
    if (strcmp(kty, "RSA") == 0) {
        std::vector<uint8_t> n, e;
        if (!base64Decode(jwk["n"].as<const char *>(), Base64Alphabet::Url, n) ||
            !base64Decode(jwk["e"].as<const char *>(), Base64Alphabet::Url, e)) {
            result.status = makeStatus(CryptoStatus::DecodeError, "rsa decode failed");
            return result;
        }
        std::string pem;
        auto status = buildRsaPemFromJwk(n, e, pem);
        if (!status.ok()) {
            result.status = status;
            return result;
        }
        result.value = CryptoKey::fromPem(pem, KeyKind::Public);
        result.status = makeStatus(CryptoStatus::Ok);
        return result;
    }
    if (strcmp(kty, "EC") == 0) {
        std::vector<uint8_t> x, y;
        if (!base64Decode(jwk["x"].as<const char *>(), Base64Alphabet::Url, x) ||
            !base64Decode(jwk["y"].as<const char *>(), Base64Alphabet::Url, y)) {
            result.status = makeStatus(CryptoStatus::DecodeError, "ec decode failed");
            return result;
        }
        std::string pem;
        auto status = buildEcPemFromJwk(x, y, std::string(jwk["crv"].as<const char *>() ? jwk["crv"].as<const char *>() : ""), pem);
        if (!status.ok()) {
            result.status = status;
            return result;
        }
        result.value = CryptoKey::fromPem(pem, KeyKind::Public);
        result.status = makeStatus(CryptoStatus::Ok);
        return result;
    }
    result.status = makeStatus(CryptoStatus::Unsupported, "kty unsupported");
    return result;
}

CryptoResult<CryptoKey> selectJwkFromSet(const JsonDocument &jwks, const String &kid, JwtAlgorithm algHint) {
    CryptoResult<CryptoKey> result;
    JsonArrayConst keys = jwks["keys"].as<JsonArrayConst>();
    if (keys.isNull()) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "jwks missing keys");
        return result;
    }
    for (JsonVariantConst v : keys) {
        JsonObjectConst jwk = v.as<JsonObjectConst>();
        const char *jwkKid = jwk["kid"].as<const char *>();
        if (kid.length() > 0 && (!jwkKid || kid != jwkKid)) {
            continue;
        }
        const char *algStr = jwk["alg"].as<const char *>();
        if (algStr && algHint != JwtAlgorithm::Auto && algorithmFromName(algStr) != JwtAlgorithm::Auto && algorithmFromName(algStr) != algHint) {
            continue;
        }
        auto parsed = jwkToKey(jwk);
        if (parsed.ok()) {
            return parsed;
        }
        result.status = parsed.status;
    }
    if (kid.length() > 0) {
        result.status = makeStatus(CryptoStatus::DecodeError, "kid not found");
    } else if (!result.status.ok()) {
        // Keep last parse error
    } else {
        result.status = makeStatus(CryptoStatus::DecodeError, "no jwk matched");
    }
    return result;
}

}  // namespace

bool initDrbg(mbedtls_ctr_drbg_context &ctr, mbedtls_entropy_context &entropy);
bool softwareGcmCrypt(int mode,
                      const std::vector<uint8_t> &key,
                      CryptoSpan<const uint8_t> iv,
                      CryptoSpan<const uint8_t> aad,
                      CryptoSpan<const uint8_t> input,
                      CryptoSpan<uint8_t> output,
                      CryptoSpan<uint8_t> tag);
bool aesKeyValid(const std::vector<uint8_t> &key);

ShaCtx::ShaCtx() {
    mbedtls_md_init(&ctx);
}

ShaCtx::~ShaCtx() {
    mbedtls_md_free(&ctx);
}

CryptoStatusDetail ShaCtx::begin(ShaVariant variant, bool /*preferHardware*/) {
    // Reset any prior digest allocation so repeated begin() calls do not leak.
    mbedtls_md_free(&ctx);
    mbedtls_md_init(&ctx);
    started = false;
    info = nullptr;

    info = mdInfoForVariant(variant);
    if (!info) {
        return makeStatus(CryptoStatus::InvalidInput, "invalid sha variant");
    }
    if (mbedtls_md_setup(&ctx, info, 0) != 0) {
        return makeStatus(CryptoStatus::InternalError, "md setup failed");
    }
    if (mbedtls_md_starts(&ctx) != 0) {
        return makeStatus(CryptoStatus::InternalError, "md start failed");
    }
    started = true;
    return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail ShaCtx::update(CryptoSpan<const uint8_t> data) {
    if (!started) {
        return makeStatus(CryptoStatus::InvalidInput, "sha not started");
    }
    if (data.empty()) {
        return makeStatus(CryptoStatus::Ok);
    }
    if (mbedtls_md_update(&ctx, data.data(), data.size()) != 0) {
        return makeStatus(CryptoStatus::InternalError, "md update failed");
    }
    return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail ShaCtx::finish(CryptoSpan<uint8_t> out) {
    if (!started || !info) {
        return makeStatus(CryptoStatus::InvalidInput, "sha not started");
    }
    size_t need = mbedtls_md_get_size(info);
    if (out.size() < need) {
        return makeStatus(CryptoStatus::BufferTooSmall, "digest buffer too small");
    }
    if (mbedtls_md_finish(&ctx, out.data()) != 0) {
        return makeStatus(CryptoStatus::InternalError, "md finish failed");
    }
    started = false;
    return makeStatus(CryptoStatus::Ok);
}

HmacCtx::HmacCtx() {
    mbedtls_md_init(&ctx);
}

HmacCtx::~HmacCtx() {
    mbedtls_md_free(&ctx);
}

CryptoStatusDetail HmacCtx::begin(ShaVariant variant, CryptoSpan<const uint8_t> key) {
    // Reset any prior digest/HMAC allocation so repeated begin() calls do not leak.
    mbedtls_md_free(&ctx);
    mbedtls_md_init(&ctx);
    started = false;
    info = nullptr;

    info = mdInfoForVariant(variant);
    if (!info || key.empty()) {
        return makeStatus(CryptoStatus::InvalidInput, "invalid hmac params");
    }
    if (mbedtls_md_setup(&ctx, info, 1) != 0) {
        return makeStatus(CryptoStatus::InternalError, "md setup failed");
    }
    if (mbedtls_md_hmac_starts(&ctx, key.data(), key.size()) != 0) {
        return makeStatus(CryptoStatus::InternalError, "hmac start failed");
    }
    started = true;
    return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail HmacCtx::update(CryptoSpan<const uint8_t> data) {
    if (!started) {
        return makeStatus(CryptoStatus::InvalidInput, "hmac not started");
    }
    if (data.empty()) {
        return makeStatus(CryptoStatus::Ok);
    }
    if (mbedtls_md_hmac_update(&ctx, data.data(), data.size()) != 0) {
        return makeStatus(CryptoStatus::InternalError, "hmac update failed");
    }
    return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail HmacCtx::finish(CryptoSpan<uint8_t> out) {
    if (!started || !info) {
        return makeStatus(CryptoStatus::InvalidInput, "hmac not started");
    }
    size_t need = mbedtls_md_get_size(info);
    if (out.size() < need) {
        return makeStatus(CryptoStatus::BufferTooSmall, "digest buffer too small");
    }
    if (mbedtls_md_hmac_finish(&ctx, out.data()) != 0) {
        return makeStatus(CryptoStatus::InternalError, "hmac finish failed");
    }
    started = false;
    return makeStatus(CryptoStatus::Ok);
}

AesCtrStream::AesCtrStream() {
    mbedtls_aes_init(&ctx);
    memset(counter, 0, sizeof(counter));
    memset(streamBlock, 0, sizeof(streamBlock));
}

AesCtrStream::~AesCtrStream() {
    mbedtls_aes_free(&ctx);
    mbedtls_platform_zeroize(counter, sizeof(counter));
    mbedtls_platform_zeroize(streamBlock, sizeof(streamBlock));
}

CryptoStatusDetail AesCtrStream::begin(const std::vector<uint8_t> &key, CryptoSpan<const uint8_t> nonceCounter) {
    if (!aesKeyValid(key) || nonceCounter.size() != 16) {
        return makeStatus(CryptoStatus::InvalidInput, "invalid key or nonce");
    }
    if (mbedtls_aes_setkey_enc(&ctx, key.data(), key.size() * 8) != 0) {
        return makeStatus(CryptoStatus::InternalError, "aes setkey failed");
    }
    memcpy(counter, nonceCounter.data(), 16);
    offset = 0;
    started = true;
    return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail AesCtrStream::update(CryptoSpan<const uint8_t> input, CryptoSpan<uint8_t> output) {
    if (!started) {
        return makeStatus(CryptoStatus::InvalidInput, "ctr not started");
    }
    if (output.size() < input.size()) {
        return makeStatus(CryptoStatus::BufferTooSmall, "output too small");
    }
    if (input.empty()) {
        return makeStatus(CryptoStatus::Ok);
    }
    size_t offCopy = offset;
    int ret = mbedtls_aes_crypt_ctr(&ctx, input.size(), &offCopy, counter, streamBlock, input.data(), output.data());
    offset = offCopy;
    return ret == 0 ? makeStatus(CryptoStatus::Ok) : makeStatus(CryptoStatus::InternalError, "ctr update failed");
}

static int gcmStartsCompat(mbedtls_gcm_context &ctx, int mode, CryptoSpan<const uint8_t> iv, CryptoSpan<const uint8_t> aad) {
#if ESPCRYPTO_MBEDTLS_V3
    int ret = mbedtls_gcm_starts(&ctx, mode, iv.data(), iv.size());
    if (ret != 0 || aad.empty()) {
        return ret;
    }
    return mbedtls_gcm_update_ad(&ctx, aad.data(), aad.size());
#else
    return mbedtls_gcm_starts(&ctx,
                              mode,
                              iv.data(),
                              iv.size(),
                              aad.empty() ? nullptr : aad.data(),
                              aad.size());
#endif
}

static int gcmUpdateCompat(mbedtls_gcm_context &ctx, CryptoSpan<const uint8_t> input, CryptoSpan<uint8_t> output) {
#if ESPCRYPTO_MBEDTLS_V3
    size_t outLen = 0;
    return mbedtls_gcm_update(&ctx, input.data(), input.size(), output.data(), output.size(), &outLen);
#else
    return mbedtls_gcm_update(&ctx, input.size(), input.data(), output.data());
#endif
}

static int gcmFinishCompat(mbedtls_gcm_context &ctx, CryptoSpan<uint8_t> tagOut) {
#if ESPCRYPTO_MBEDTLS_V3
    size_t outLen = 0;
    return mbedtls_gcm_finish(&ctx, nullptr, 0, &outLen, tagOut.data(), tagOut.size());
#else
    return mbedtls_gcm_finish(&ctx, tagOut.data(), tagOut.size());
#endif
}

AesGcmCtx::AesGcmCtx() {
    mbedtls_gcm_init(&ctx);
}

AesGcmCtx::~AesGcmCtx() {
    mbedtls_gcm_free(&ctx);
    mbedtls_platform_zeroize(tagVerify.data(), tagVerify.size());
}

CryptoStatusDetail AesGcmCtx::beginCommon(const std::vector<uint8_t> &key,
                                          CryptoSpan<const uint8_t> iv,
                                          CryptoSpan<const uint8_t> aad,
                                          bool decryptMode,
                                          CryptoSpan<const uint8_t> tag) {
    if (!aesKeyValid(key) || iv.empty()) {
        return makeStatus(CryptoStatus::InvalidInput, "invalid key or iv");
    }
    markRuntimeInitialized();
    const CryptoPolicy &policy = mutablePolicy();
    if (!policy.allowLegacy && iv.size() < policy.minAesGcmIvBytes) {
        return makeStatus(CryptoStatus::PolicyViolation, "iv too short");
    }
    decrypt = decryptMode;
    if (decrypt) {
        tagVerify.assign(tag.data(), tag.data() + tag.size());
    } else {
        tagVerify.clear();
    }
    if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(), key.size() * 8) != 0) {
        return makeStatus(CryptoStatus::InternalError, "gcm setkey failed");
    }
    int mode = decrypt ? MBEDTLS_GCM_DECRYPT : MBEDTLS_GCM_ENCRYPT;
    if (gcmStartsCompat(ctx, mode, iv, aad) != 0) {
        return makeStatus(CryptoStatus::InternalError, "gcm start failed");
    }
    started = true;
    return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail AesGcmCtx::beginEncrypt(const std::vector<uint8_t> &key,
                                           CryptoSpan<const uint8_t> iv,
                                           CryptoSpan<const uint8_t> aad) {
    return beginCommon(key, iv, aad, false, CryptoSpan<const uint8_t>());
}

CryptoStatusDetail AesGcmCtx::beginDecrypt(const std::vector<uint8_t> &key,
                                           CryptoSpan<const uint8_t> iv,
                                           CryptoSpan<const uint8_t> aad,
                                           CryptoSpan<const uint8_t> tag) {
    if (tag.size() != AES_GCM_TAG_BYTES) {
        return makeStatus(CryptoStatus::InvalidInput, "tag size invalid");
    }
    return beginCommon(key, iv, aad, true, tag);
}

CryptoStatusDetail AesGcmCtx::update(CryptoSpan<const uint8_t> input, CryptoSpan<uint8_t> output) {
    if (!started) {
        return makeStatus(CryptoStatus::InvalidInput, "gcm not started");
    }
    if (output.size() < input.size()) {
        return makeStatus(CryptoStatus::BufferTooSmall, "output too small");
    }
    if (input.empty()) {
        return makeStatus(CryptoStatus::Ok);
    }
    if (gcmUpdateCompat(ctx, input, output) != 0) {
        return makeStatus(CryptoStatus::InternalError, "gcm update failed");
    }
    return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail AesGcmCtx::finish(CryptoSpan<uint8_t> tagOut) {
    if (!started) {
        return makeStatus(CryptoStatus::InvalidInput, "gcm not started");
    }
    started = false;
    if (!decrypt) {
        if (tagOut.size() < AES_GCM_TAG_BYTES) {
            return makeStatus(CryptoStatus::BufferTooSmall, "tag too small");
        }
        if (gcmFinishCompat(ctx, CryptoSpan<uint8_t>(tagOut.data(), AES_GCM_TAG_BYTES)) != 0) {
            return makeStatus(CryptoStatus::InternalError, "gcm finish failed");
        }
        return makeStatus(CryptoStatus::Ok);
    }
    std::vector<uint8_t> computed(AES_GCM_TAG_BYTES, 0);
    if (gcmFinishCompat(ctx, CryptoSpan<uint8_t>(computed)) != 0) {
        return makeStatus(CryptoStatus::InternalError, "gcm finish failed");
    }
    bool ok = constantTimeEquals(CryptoSpan<const uint8_t>(tagVerify), CryptoSpan<const uint8_t>(computed));
    mbedtls_platform_zeroize(computed.data(), computed.size());
    return ok ? makeStatus(CryptoStatus::Ok) : makeStatus(CryptoStatus::VerifyFailed, "gcm tag mismatch");
}

std::string handleKeyString(const KeyHandle &handle) {
    std::string alias(handle.alias.c_str(), handle.alias.length());
    if (alias.empty()) {
        return std::string();
    }
    return alias + ":" + std::to_string(handle.version);
}

bool ensureNvsReady(const String &partition) {
#if defined(ESP_PLATFORM)
    GlobalRuntimeState &state = runtimeState();
    auto it = state.nvsInitMap.find(partition.c_str());
    if (it != state.nvsInitMap.end() && it->second) {
        markRuntimeInitialized();
        return true;
    }
    esp_err_t err = nvs_flash_init_partition(partition.c_str());
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase_partition(partition.c_str());
        err = nvs_flash_init_partition(partition.c_str());
    }
    bool ok = (err == ESP_OK);
    state.nvsInitMap[partition.c_str()] = ok;
    if (ok) {
        markRuntimeInitialized();
    }
    return ok;
#else
    (void)partition;
    return false;
#endif
}

uint64_t loadCounterFromNvs(const String &ns, const String &partition, const std::string &key, bool &found) {
    found = false;
    uint64_t value = 0;
#if defined(ESP_PLATFORM)
    if (!ensureNvsReady(partition)) {
        return value;
    }
    nvs_handle_t nvs;
    if (nvs_open_from_partition(partition.c_str(), ns.c_str(), NVS_READONLY, &nvs) != ESP_OK) {
        return value;
    }
    size_t size = sizeof(uint64_t);
    if (nvs_get_blob(nvs, key.c_str(), &value, &size) == ESP_OK && size == sizeof(uint64_t)) {
        found = true;
    }
    nvs_close(nvs);
#else
    (void)ns;
    (void)partition;
    (void)key;
#endif
    return value;
}

void storeCounterToNvs(const String &ns, const String &partition, const std::string &key, uint64_t value) {
#if defined(ESP_PLATFORM)
    if (!ensureNvsReady(partition)) {
        return;
    }
    nvs_handle_t nvs;
    if (nvs_open_from_partition(partition.c_str(), ns.c_str(), NVS_READWRITE, &nvs) != ESP_OK) {
        return;
    }
    nvs_set_blob(nvs, key.c_str(), &value, sizeof(value));
    nvs_commit(nvs);
    nvs_close(nvs);
#else
    (void)ns;
    (void)partition;
    (void)key;
    (void)value;
#endif
}

CryptoResult<std::vector<uint8_t>> MemoryKeyStore::load(const KeyHandle &handle) {
    CryptoResult<std::vector<uint8_t>> result;
    std::string key = handleKeyString(handle);
    if (key.empty()) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "alias missing");
        return result;
    }
    auto it = storage.find(key);
    if (it == storage.end()) {
        result.status = makeStatus(CryptoStatus::DecodeError, "key not found");
        return result;
    }
    result.value = it->second;
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoStatusDetail MemoryKeyStore::store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) {
    std::string k = handleKeyString(handle);
    if (k.empty() || key.empty()) {
        return makeStatus(CryptoStatus::InvalidInput, "alias/key missing");
    }
    storage[k] = std::vector<uint8_t>(key.data(), key.data() + key.size());
    return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail MemoryKeyStore::remove(const KeyHandle &handle) {
    std::string k = handleKeyString(handle);
    if (k.empty()) {
        return makeStatus(CryptoStatus::InvalidInput, "alias missing");
    }
    storage.erase(k);
    return makeStatus(CryptoStatus::Ok);
}

NvsKeyStore::NvsKeyStore(String ns, String partition) : ns(std::move(ns)), partition(std::move(partition)) {}

CryptoStatusDetail NvsKeyStore::ensureInit() const {
#if defined(ESP_PLATFORM)
    if (!ensureNvsReady(partition)) {
        return makeStatus(CryptoStatus::InternalError, "nvs init failed");
    }
    return makeStatus(CryptoStatus::Ok);
#else
    (void)partition;
    return makeStatus(CryptoStatus::Unsupported, "nvs unavailable");
#endif
}

String NvsKeyStore::makeKeyName(const KeyHandle &handle) const {
    return String(handleKeyString(handle).c_str());
}

CryptoResult<std::vector<uint8_t>> NvsKeyStore::load(const KeyHandle &handle) {
    CryptoResult<std::vector<uint8_t>> result;
#if defined(ESP_PLATFORM)
    auto initStatus = ensureInit();
    if (!initStatus.ok()) {
        result.status = initStatus;
        return result;
    }
    std::string key = handleKeyString(handle);
    if (key.empty()) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "alias missing");
        return result;
    }
    nvs_handle_t nvs;
    if (nvs_open_from_partition(partition.c_str(), ns.c_str(), NVS_READONLY, &nvs) != ESP_OK) {
        result.status = makeStatus(CryptoStatus::DecodeError, "nvs open failed");
        return result;
    }
    size_t size = 0;
    esp_err_t err = nvs_get_blob(nvs, key.c_str(), nullptr, &size);
    if (err != ESP_OK) {
        nvs_close(nvs);
        result.status = makeStatus(CryptoStatus::DecodeError, "key missing");
        return result;
    }
    result.value.assign(size, 0);
    err = nvs_get_blob(nvs, key.c_str(), result.value.data(), &size);
    nvs_close(nvs);
    if (err != ESP_OK) {
        result.value.clear();
        result.status = makeStatus(CryptoStatus::InternalError, "read failed");
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
#else
    (void)handle;
    result.status = makeStatus(CryptoStatus::Unsupported, "nvs unavailable");
    return result;
#endif
}

CryptoStatusDetail NvsKeyStore::store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) {
#if defined(ESP_PLATFORM)
    auto initStatus = ensureInit();
    if (!initStatus.ok()) {
        return initStatus;
    }
    std::string name = handleKeyString(handle);
    if (name.empty() || key.empty()) {
        return makeStatus(CryptoStatus::InvalidInput, "alias/key missing");
    }
    nvs_handle_t nvs;
    if (nvs_open_from_partition(partition.c_str(), ns.c_str(), NVS_READWRITE, &nvs) != ESP_OK) {
        return makeStatus(CryptoStatus::InternalError, "nvs open failed");
    }
    esp_err_t err = nvs_set_blob(nvs, name.c_str(), key.data(), key.size());
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (err != ESP_OK) {
        return makeStatus(CryptoStatus::InternalError, "nvs write failed");
    }
    return makeStatus(CryptoStatus::Ok);
#else
    (void)handle;
    (void)key;
    return makeStatus(CryptoStatus::Unsupported, "nvs unavailable");
#endif
}

CryptoStatusDetail NvsKeyStore::remove(const KeyHandle &handle) {
#if defined(ESP_PLATFORM)
    auto initStatus = ensureInit();
    if (!initStatus.ok()) {
        return initStatus;
    }
    std::string name = handleKeyString(handle);
    if (name.empty()) {
        return makeStatus(CryptoStatus::InvalidInput, "alias missing");
    }
    nvs_handle_t nvs;
    if (nvs_open_from_partition(partition.c_str(), ns.c_str(), NVS_READWRITE, &nvs) != ESP_OK) {
        return makeStatus(CryptoStatus::InternalError, "nvs open failed");
    }
    esp_err_t err = nvs_erase_key(nvs, name.c_str());
    if (err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND) {
        nvs_commit(nvs);
    }
    nvs_close(nvs);
    return makeStatus(CryptoStatus::Ok);
#else
    (void)handle;
    return makeStatus(CryptoStatus::Unsupported, "nvs unavailable");
#endif
}

LittleFsKeyStore::LittleFsKeyStore(String basePath) : basePath(std::move(basePath)) {}

String LittleFsKeyStore::makePath(const KeyHandle &handle) const {
    std::string name = handleKeyString(handle);
    if (name.empty()) {
        return String();
    }
    if (basePath.endsWith("/")) {
        return basePath + name.c_str();
    }
    return basePath + "/" + name.c_str();
}

CryptoResult<std::vector<uint8_t>> LittleFsKeyStore::load(const KeyHandle &handle) {
    CryptoResult<std::vector<uint8_t>> result;
#if ESPCRYPTO_HAS_LITTLEFS
    String path = makePath(handle);
    if (path.length() == 0) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "alias missing");
        return result;
    }
    if (!LittleFS.begin()) {
        result.status = makeStatus(CryptoStatus::InternalError, "littlefs mount failed");
        return result;
    }
    File f = LittleFS.open(path, "r");
    if (!f) {
        result.status = makeStatus(CryptoStatus::DecodeError, "key missing");
        return result;
    }
    result.value.assign(f.size(), 0);
    size_t read = f.read(result.value.data(), result.value.size());
    f.close();
    if (read != result.value.size()) {
        result.value.clear();
        result.status = makeStatus(CryptoStatus::InternalError, "short read");
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
#else
    (void)handle;
    result.status = makeStatus(CryptoStatus::Unsupported, "littlefs unavailable");
    return result;
#endif
}

CryptoStatusDetail LittleFsKeyStore::store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) {
#if ESPCRYPTO_HAS_LITTLEFS
    String path = makePath(handle);
    if (path.length() == 0 || key.empty()) {
        return makeStatus(CryptoStatus::InvalidInput, "alias/key missing");
    }
    if (!LittleFS.begin()) {
        return makeStatus(CryptoStatus::InternalError, "littlefs mount failed");
    }
    if (!LittleFS.exists(basePath)) {
        LittleFS.mkdir(basePath);
    }
    File f = LittleFS.open(path, "w");
    if (!f) {
        return makeStatus(CryptoStatus::InternalError, "open failed");
    }
    size_t written = f.write(key.data(), key.size());
    f.close();
    if (written != key.size()) {
        return makeStatus(CryptoStatus::InternalError, "write failed");
    }
    return makeStatus(CryptoStatus::Ok);
#else
    (void)handle;
    (void)key;
    return makeStatus(CryptoStatus::Unsupported, "littlefs unavailable");
#endif
}

CryptoStatusDetail LittleFsKeyStore::remove(const KeyHandle &handle) {
#if ESPCRYPTO_HAS_LITTLEFS
    String path = makePath(handle);
    if (path.length() == 0) {
        return makeStatus(CryptoStatus::InvalidInput, "alias missing");
    }
    if (!LittleFS.begin()) {
        return makeStatus(CryptoStatus::InternalError, "littlefs mount failed");
    }
    LittleFS.remove(path);
    return makeStatus(CryptoStatus::Ok);
#else
    (void)handle;
    return makeStatus(CryptoStatus::Unsupported, "littlefs unavailable");
#endif
}

std::vector<uint8_t> deviceFingerprint() {
    std::vector<uint8_t> fingerprint;
#if defined(ESP_PLATFORM)
    uint8_t mac[6] = {0};
    bool haveMac = false;
#if ESPCRYPTO_HAS_ESP_MAC && defined(ESP_MAC_WIFI_STA)
    if (esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK) {
        haveMac = true;
    }
#endif
#if ESPCRYPTO_HAS_ESP_EFUSE_MAC
    if (!haveMac && esp_efuse_mac_get_default(mac) == ESP_OK) {
        haveMac = true;
    }
#endif
    if (haveMac) {
        fingerprint.insert(fingerprint.end(), mac, mac + sizeof(mac));
    }
#else
    std::random_device rd;
    for (size_t i = 0; i < 8; ++i) {
        fingerprint.push_back(static_cast<uint8_t>(rd()));
    }
#endif
    if (fingerprint.empty()) {
        fingerprint.resize(8, 0xAA);
    }
    return fingerprint;
}

CryptoStatusDetail loadOrCreateSeed(std::vector<uint8_t> &seed, const DeviceKeyOptions &options) {
    if (options.seedBytes == 0) {
        return makeStatus(CryptoStatus::InvalidInput, "seed size missing");
    }
    seed.assign(options.seedBytes, 0);
#if defined(ESP_PLATFORM)
    if (options.persistSeed) {
        NvsKeyStore store(options.nvsNamespace, options.nvsPartition);
        KeyHandle handle;
        handle.alias = "device_seed";
        auto loaded = store.load(handle);
        if (loaded.ok() && loaded.value.size() == options.seedBytes) {
            seed = loaded.value;
            return makeStatus(CryptoStatus::Ok);
        }
        fillRandom(seed.data(), seed.size());
        auto writeStatus = store.store(handle, CryptoSpan<const uint8_t>(seed));
        if (!writeStatus.ok()) {
            return writeStatus;
        }
        return makeStatus(CryptoStatus::Ok);
    }
#endif
    fillRandom(seed.data(), seed.size());
    return makeStatus(CryptoStatus::Ok);
}

CryptoKey::CryptoKey() = default;

CryptoKey::CryptoKey(const CryptoKey &other) {
    data = other.data;
    format = other.format;
    keyKind = other.keyKind;
    pk = nullptr;
}

CryptoKey &CryptoKey::operator=(const CryptoKey &other) {
    if (this != &other) {
        clear();
        data = other.data;
        format = other.format;
        keyKind = other.keyKind;
    }
    return *this;
}

CryptoKey::CryptoKey(CryptoKey &&other) noexcept {
    data = std::move(other.data);
    format = other.format;
    keyKind = other.keyKind;
    pk = other.pk;
    other.pk = nullptr;
}

CryptoKey &CryptoKey::operator=(CryptoKey &&other) noexcept {
    if (this != &other) {
        clear();
        data = std::move(other.data);
        format = other.format;
        keyKind = other.keyKind;
        pk = other.pk;
        other.pk = nullptr;
    }
    return *this;
}

CryptoKey::~CryptoKey() {
    clear();
}

CryptoKey CryptoKey::fromPem(const std::string &pem, KeyKind kind) {
    CryptoKey key;
    key.data.assign(pem.begin(), pem.end());
    key.data.push_back('\0');
    key.format = KeyFormat::Pem;
    key.keyKind = kind;
    return key;
}

CryptoKey CryptoKey::fromDer(const std::vector<uint8_t> &der, KeyKind kind) {
    CryptoKey key;
    key.data = der;
    key.format = KeyFormat::Der;
    key.keyKind = kind;
    return key;
}

CryptoKey CryptoKey::fromRaw(const std::vector<uint8_t> &raw, KeyKind kind) {
    CryptoKey key;
    key.data = raw;
    key.format = KeyFormat::Raw;
    key.keyKind = kind;
    return key;
}

bool CryptoKey::valid() const {
    return !data.empty();
}

KeyKind CryptoKey::kind() const {
    return keyKind;
}

CryptoSpan<const uint8_t> CryptoKey::bytes() const {
    return CryptoSpan<const uint8_t>(data);
}

bool CryptoKey::parsed() const {
    return pk && pk->hasKey;
}

void CryptoKey::clear() {
    if (pk) {
        mbedtls_pk_free(&pk->ctx);
        delete pk;
        pk = nullptr;
    }
    if (!data.empty()) {
        secureZero(data.data(), data.size());
        data.clear();
    }
    keyKind = KeyKind::Auto;
    format = KeyFormat::Raw;
}

CryptoStatusDetail CryptoKey::ensureParsedPk(bool requirePrivate) const {
    if (format != KeyFormat::Pem && format != KeyFormat::Der) {
        return makeStatus(CryptoStatus::Unsupported, "pk parse requires pem/der");
    }
    if (pk && pk->hasKey) {
        if (requirePrivate && !pk->isPrivate) {
            return makeStatus(CryptoStatus::PolicyViolation, "private key required");
        }
        return makeStatus(CryptoStatus::Ok);
    }
    pk = new PkCache();
    mbedtls_pk_init(&pk->ctx);
    int ret = 0;
    if (format == KeyFormat::Pem) {
        ret = mbedtls_pk_parse_public_key(&pk->ctx,
                                          reinterpret_cast<const unsigned char *>(data.data()),
                                          data.size());
        if (ret == 0) {
            pk->hasKey = true;
            pk->isPrivate = false;
        }
    }
    mbedtls_ctr_drbg_context ctr;
    mbedtls_entropy_context entropy;
    bool seeded = initDrbg(ctr, entropy);
    if (!pk->hasKey && seeded) {
#if ESPCRYPTO_MBEDTLS_V3
        ret = mbedtls_pk_parse_key(&pk->ctx,
                                   reinterpret_cast<const unsigned char *>(data.data()),
                                   format == KeyFormat::Pem ? data.size() : data.size(),
                                   nullptr,
                                   0,
                                   mbedtls_ctr_drbg_random,
                                   &ctr);
#else
        ret = mbedtls_pk_parse_key(&pk->ctx,
                                   reinterpret_cast<const unsigned char *>(data.data()),
                                   format == KeyFormat::Pem ? data.size() : data.size(),
                                   nullptr,
                                   0);
#endif
        if (ret == 0) {
            pk->hasKey = true;
            pk->isPrivate = true;
        }
    }
    if (seeded) {
        mbedtls_ctr_drbg_free(&ctr);
        mbedtls_entropy_free(&entropy);
    }
    if (!pk->hasKey) {
        mbedtls_pk_free(&pk->ctx);
        delete pk;
        pk = nullptr;
        return makeStatus(CryptoStatus::DecodeError, "pk parse failed");
    }
    if (requirePrivate && !pk->isPrivate) {
        return makeStatus(CryptoStatus::PolicyViolation, "private key required");
    }
    return makeStatus(CryptoStatus::Ok);
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

bool pkPolicyAllows(mbedtls_pk_context &pk, mbedtls_pk_type_t expected) {
    if (!mbedtls_pk_can_do(&pk, expected)) {
        return false;
    }
    markRuntimeInitialized();
    const CryptoPolicy &policy = mutablePolicy();
    size_t bitlen = mbedtls_pk_get_bitlen(&pk);
    if (!policy.allowLegacy) {
        if (expected == MBEDTLS_PK_RSA && bitlen < policy.minRsaBits) {
            return false;
        }
        if (expected == MBEDTLS_PK_ECKEY && !policy.allowWeakCurves && bitlen < 256) {
            return false;
        }
    }
    return true;
}

bool pkSignContext(mbedtls_pk_context &pk,
                   mbedtls_pk_type_t expected,
                   ShaVariant variant,
                   const uint8_t *data,
                   size_t length,
                   std::vector<uint8_t> &signature) {
    if (!pkPolicyAllows(pk, expected)) {
        return false;
    }
    std::vector<uint8_t> hash;
    if (!computeHash(variant, data, length, hash)) {
        return false;
    }
    const mbedtls_md_info_t *info = mdInfoForVariant(variant);
    if (!info) {
        return false;
    }
    size_t sigLen = mbedtls_pk_get_len(&pk);
    signature.assign(sigLen, 0);
    mbedtls_ctr_drbg_context ctr;
    mbedtls_entropy_context entropy;
    if (!initDrbg(ctr, entropy)) {
        signature.clear();
        return false;
    }
#if ESPCRYPTO_MBEDTLS_V3
    int ret = mbedtls_pk_sign(&pk,
                               mbedtls_md_get_type(info),
                               hash.data(), hash.size(),
                               signature.data(), signature.size(), &sigLen,
                               mbedtls_ctr_drbg_random,
                               &ctr);
#else
    int ret = mbedtls_pk_sign(&pk,
                               mbedtls_md_get_type(info),
                               hash.data(), hash.size(),
                               signature.data(), &sigLen,
                               mbedtls_ctr_drbg_random,
                               &ctr);
#endif
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    if (ret != 0) {
        signature.clear();
        return false;
    }
    signature.resize(sigLen);
    return true;
}

bool pkVerifyContext(mbedtls_pk_context &pk,
                     mbedtls_pk_type_t expected,
                     ShaVariant variant,
                     const uint8_t *data,
                     size_t length,
                     const std::vector<uint8_t> &signature) {
    if (!pkPolicyAllows(pk, expected)) {
        return false;
    }
    std::vector<uint8_t> hash;
    if (!computeHash(variant, data, length, hash)) {
        return false;
    }
    const mbedtls_md_info_t *info = mdInfoForVariant(variant);
    if (!info) {
        return false;
    }
    int ret = mbedtls_pk_verify(&pk,
                                 mbedtls_md_get_type(info),
                                 hash.data(), hash.size(),
                                 signature.data(), signature.size());
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
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return false;
    }
    bool ok = pkSignContext(pk, expected, variant, data, length, signature);
    mbedtls_pk_free(&pk);
    return ok;
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
    bool ok = pkVerifyContext(pk, expected, variant, data, length, signature);
    mbedtls_pk_free(&pk);
    return ok;
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

bool hardwareGcmCryptSpan(int mode,
                          const std::vector<uint8_t> &key,
                          CryptoSpan<const uint8_t> iv,
                          CryptoSpan<const uint8_t> aad,
                          CryptoSpan<const uint8_t> input,
                          CryptoSpan<uint8_t> output,
                          CryptoSpan<uint8_t> tag) {
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

bool hardwareGcmCrypt(int mode,
                      const std::vector<uint8_t> &key,
                      const std::vector<uint8_t> &iv,
                      const std::vector<uint8_t> &aad,
                      const std::vector<uint8_t> &input,
                      std::vector<uint8_t> &output,
                      std::vector<uint8_t> &tag) {
    return hardwareGcmCryptSpan(mode, key,
                                CryptoSpan<const uint8_t>(iv),
                                CryptoSpan<const uint8_t>(aad),
                                CryptoSpan<const uint8_t>(input),
                                CryptoSpan<uint8_t>(output),
                                CryptoSpan<uint8_t>(tag));
}

bool softwareGcmCrypt(int mode,
                      const std::vector<uint8_t> &key,
                      const std::vector<uint8_t> &iv,
                      const std::vector<uint8_t> &aad,
                      const std::vector<uint8_t> &input,
                      std::vector<uint8_t> &output,
                      std::vector<uint8_t> &tag) {
    return softwareGcmCrypt(mode, key,
                            CryptoSpan<const uint8_t>(iv),
                            CryptoSpan<const uint8_t>(aad),
                            CryptoSpan<const uint8_t>(input),
                            CryptoSpan<uint8_t>(output),
                            CryptoSpan<uint8_t>(tag));
}

bool softwareGcmCrypt(int mode,
                      const std::vector<uint8_t> &key,
                      CryptoSpan<const uint8_t> iv,
                      CryptoSpan<const uint8_t> aad,
                      CryptoSpan<const uint8_t> input,
                      CryptoSpan<uint8_t> output,
                      CryptoSpan<uint8_t> tag) {
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

CryptoStatusDetail aesGcmEncryptSpan(const std::vector<uint8_t> &key,
                                     CryptoSpan<const uint8_t> iv,
                                     CryptoSpan<const uint8_t> aad,
                                     CryptoSpan<const uint8_t> plaintext,
                                     CryptoSpan<uint8_t> ciphertext,
                                     CryptoSpan<uint8_t> tag) {
    if (!aesKeyValid(key) || iv.empty()) {
        return makeStatus(CryptoStatus::InvalidInput, "invalid key or iv");
    }
    markRuntimeInitialized();
    const CryptoPolicy &policy = mutablePolicy();
    if (!policy.allowLegacy && iv.size() < policy.minAesGcmIvBytes) {
        return makeStatus(CryptoStatus::PolicyViolation, "iv too short");
    }
    if (ciphertext.size() < plaintext.size()) {
        return makeStatus(CryptoStatus::BufferTooSmall, "ciphertext buffer too small");
    }
    if (tag.size() < AES_GCM_TAG_BYTES) {
        return makeStatus(CryptoStatus::BufferTooSmall, "tag buffer too small");
    }
    std::vector<uint8_t> ivCopy(iv.data(), iv.data() + iv.size());
    if (nonceReused(key, ivCopy)) {
        secureZero(ivCopy.data(), ivCopy.size());
        return makeStatus(CryptoStatus::NonceReuse, "iv reuse");
    }
    secureZero(ivCopy.data(), ivCopy.size());
    CryptoSpan<uint8_t> ctSlice(ciphertext.data(), plaintext.size());
    CryptoSpan<uint8_t> tagSlice(tag.data(), AES_GCM_TAG_BYTES);
    bool ok = hardwareGcmCryptSpan(MBEDTLS_GCM_ENCRYPT, key, iv, aad, plaintext, ctSlice, tagSlice);
    if (!ok) {
        ok = softwareGcmCrypt(MBEDTLS_GCM_ENCRYPT, key, iv, aad, plaintext, ctSlice, tagSlice);
    }
    if (!ok) {
        secureZero(ctSlice.data(), ctSlice.size());
        secureZero(tagSlice.data(), tagSlice.size());
        return makeStatus(CryptoStatus::InternalError, "aes gcm encrypt failed");
    }
    return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail aesGcmDecryptSpan(const std::vector<uint8_t> &key,
                                     CryptoSpan<const uint8_t> iv,
                                     CryptoSpan<const uint8_t> aad,
                                     CryptoSpan<const uint8_t> ciphertext,
                                     CryptoSpan<const uint8_t> tag,
                                     CryptoSpan<uint8_t> plaintext) {
    if (!aesKeyValid(key) || iv.empty() || tag.size() != AES_GCM_TAG_BYTES) {
        return makeStatus(CryptoStatus::InvalidInput, "invalid key/iv/tag");
    }
    markRuntimeInitialized();
    const CryptoPolicy &policy = mutablePolicy();
    if (!policy.allowLegacy && iv.size() < policy.minAesGcmIvBytes) {
        return makeStatus(CryptoStatus::PolicyViolation, "iv too short");
    }
    if (plaintext.size() < ciphertext.size()) {
        return makeStatus(CryptoStatus::BufferTooSmall, "plaintext buffer too small");
    }
    CryptoSpan<uint8_t> ptSlice(plaintext.data(), ciphertext.size());
    std::vector<uint8_t> tagCopy(tag.data(), tag.data() + tag.size());
    bool ok = hardwareGcmCryptSpan(MBEDTLS_GCM_DECRYPT, key, iv, aad, ciphertext, ptSlice, CryptoSpan<uint8_t>(tagCopy));
    if (!ok) {
        tagCopy.assign(tag.data(), tag.data() + tag.size());
        ok = softwareGcmCrypt(MBEDTLS_GCM_DECRYPT, key, iv, aad, ciphertext, ptSlice, CryptoSpan<uint8_t>(tagCopy));
    }
    secureZero(tagCopy.data(), tagCopy.size());
    if (!ok) {
        secureZero(ptSlice.data(), ptSlice.size());
        return makeStatus(CryptoStatus::VerifyFailed, "gcm auth failed");
    }
    return makeStatus(CryptoStatus::Ok);
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
    ciphertext.assign(plaintext.size(), 0);
    tag.assign(AES_GCM_TAG_BYTES, 0);
    return aesGcmEncryptSpan(key,
                             CryptoSpan<const uint8_t>(iv),
                             CryptoSpan<const uint8_t>(aad),
                             CryptoSpan<const uint8_t>(plaintext),
                             CryptoSpan<uint8_t>(ciphertext),
                             CryptoSpan<uint8_t>(tag));
}

CryptoStatusDetail aesGcmDecryptInternal(const std::vector<uint8_t> &key,
                                         const std::vector<uint8_t> &iv,
                                         const std::vector<uint8_t> &aad,
                                         const std::vector<uint8_t> &ciphertext,
                                         const std::vector<uint8_t> &tag,
                                         std::vector<uint8_t> &plaintext) {
    plaintext.assign(ciphertext.size(), 0);
    return aesGcmDecryptSpan(key,
                             CryptoSpan<const uint8_t>(iv),
                             CryptoSpan<const uint8_t>(aad),
                             CryptoSpan<const uint8_t>(ciphertext),
                             CryptoSpan<const uint8_t>(tag),
                             CryptoSpan<uint8_t>(plaintext));
}

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
    markRuntimeInitialized();
}

CryptoPolicy ESPCrypto::policy() {
    return mutablePolicy();
}

void ESPCrypto::deinit() {
    resetRuntimeState();
}

bool ESPCrypto::isInitialized() {
    return runtimeState().initialized.load(std::memory_order_acquire);
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

CryptoResult<void> ESPCrypto::sha(CryptoSpan<const uint8_t> data, CryptoSpan<uint8_t> out, const ShaOptions &options) {
    CryptoResult<void> result;
    size_t needed = digestLength(options.variant);
    if (needed == 0) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "unknown sha variant");
        return result;
    }
    if (out.size() < needed) {
        result.status = makeStatus(CryptoStatus::BufferTooSmall, "digest buffer too small");
        return result;
    }
    auto hashed = shaResult(data, options);
    if (!hashed.ok()) {
        result.status = hashed.status;
        return result;
    }
    memcpy(out.data(), hashed.value.data(), needed);
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::deriveDeviceKey(const String &purpose,
                                                              CryptoSpan<const uint8_t> contextInfo,
                                                              size_t length,
                                                              const DeviceKeyOptions &options) {
    CryptoResult<std::vector<uint8_t>> result;
    if (purpose.length() == 0 || length == 0) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "purpose/length missing");
        return result;
    }
    auto deviceSalt = deviceFingerprint();
    std::vector<uint8_t> seed;
    auto seedStatus = loadOrCreateSeed(seed, options);
    if (!seedStatus.ok()) {
        result.status = seedStatus;
        return result;
    }
    std::vector<uint8_t> info;
    info.insert(info.end(), purpose.begin(), purpose.end());
    if (!contextInfo.empty()) {
        info.insert(info.end(), contextInfo.data(), contextInfo.data() + contextInfo.size());
    }
    auto derived = hkdf(ShaVariant::SHA256,
                        CryptoSpan<const uint8_t>(deviceSalt),
                        CryptoSpan<const uint8_t>(seed),
                        CryptoSpan<const uint8_t>(info),
                        length);
    secureZero(seed.data(), seed.size());
    secureZero(info.data(), info.size());
    if (!derived.ok()) {
        result.status = derived.status;
        return result;
    }
    result.value = std::move(derived.value);
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoResult<void> ESPCrypto::storeKey(KeyStore &store, const KeyHandle &handle, CryptoSpan<const uint8_t> keyMaterial) {
    CryptoResult<void> result;
    auto status = store.store(handle, keyMaterial);
    result.status = status;
    return result;
}

CryptoResult<CryptoKey> ESPCrypto::loadKey(KeyStore &store, const KeyHandle &handle, KeyFormat format, KeyKind kind) {
    CryptoResult<CryptoKey> result;
    auto loaded = store.load(handle);
    if (!loaded.ok()) {
        result.status = loaded.status;
        return result;
    }
    switch (format) {
        case KeyFormat::Pem:
            result.value = CryptoKey::fromPem(std::string(reinterpret_cast<const char *>(loaded.value.data()), loaded.value.size()), kind);
            break;
        case KeyFormat::Der:
            result.value = CryptoKey::fromDer(loaded.value, kind);
            break;
        case KeyFormat::Raw:
            result.value = CryptoKey::fromRaw(loaded.value, kind);
            break;
        case KeyFormat::Jwk:
            result.status = makeStatus(CryptoStatus::Unsupported, "jwk decode not implemented");
            return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoResult<void> ESPCrypto::removeKey(KeyStore &store, const KeyHandle &handle) {
    CryptoResult<void> result;
    result.status = store.remove(handle);
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
                                                      size_t ivLength,
                                                      const GcmNonceOptions &nonceOptions) {
    CryptoResult<GcmMessage> result;
    markRuntimeInitialized();
    const CryptoPolicy &policy = mutablePolicy();
    if (ivLength == 0) {
        ivLength = policy.minAesGcmIvBytes;
    }
    if (!policy.allowLegacy && ivLength < policy.minAesGcmIvBytes) {
        result.status = makeStatus(CryptoStatus::PolicyViolation, "iv too short");
        return result;
    }
    if (!aesKeyValid(key)) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "invalid key");
        return result;
    }
    result.value.iv.assign(ivLength, 0);
    GlobalRuntimeState &state = runtimeState();
    uint32_t keyHash = fingerprintKey(key);
    state.bootCounter.fetch_add(1, std::memory_order_relaxed);
    switch (nonceOptions.strategy) {
        case GcmNonceStrategy::Random96:
        default:
            fillRandom(result.value.iv.data(), result.value.iv.size());
            break;
        case GcmNonceStrategy::Counter64_Random32: {
            if (ivLength < 12) {
                result.status = makeStatus(CryptoStatus::PolicyViolation, "counter strategy needs >=12 iv bytes");
                return result;
            }
            bool found = false;
            uint64_t counter = loadCounterFromNvs(nonceOptions.nvsNamespace, nonceOptions.nvsPartition, "gcmctr_" + std::to_string(keyHash), found);
            if (!found) {
                counter = 1;
            } else {
                counter += 1;
            }
            if (nonceOptions.persistCounter) {
                storeCounterToNvs(nonceOptions.nvsNamespace, nonceOptions.nvsPartition, "gcmctr_" + std::to_string(keyHash), counter);
            }
            for (int i = 0; i < 8 && i < static_cast<int>(ivLength); ++i) {
                result.value.iv[i] = static_cast<uint8_t>((counter >> (56 - 8 * i)) & 0xFF);
            }
            std::vector<uint8_t> tail(ivLength > 8 ? ivLength - 8 : 0, 0);
            if (!tail.empty()) {
                fillRandom(tail.data(), tail.size());
                memcpy(result.value.iv.data() + 8, tail.data(), tail.size());
            }
            break;
        }
        case GcmNonceStrategy::BootCounter_Random32: {
            if (ivLength < 12) {
                result.status = makeStatus(CryptoStatus::PolicyViolation, "counter strategy needs >=12 iv bytes");
                return result;
            }
            uint64_t counter = state.bootCounter.load(std::memory_order_relaxed);
            for (int i = 0; i < 8 && i < static_cast<int>(ivLength); ++i) {
                result.value.iv[i] = static_cast<uint8_t>((counter >> (56 - 8 * i)) & 0xFF);
            }
            std::vector<uint8_t> tail(ivLength > 8 ? ivLength - 8 : 0, 0);
            if (!tail.empty()) {
                fillRandom(tail.data(), tail.size());
                memcpy(result.value.iv.data() + 8, tail.data(), tail.size());
            }
            break;
        }
    }
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

CryptoResult<void> ESPCrypto::aesGcmEncrypt(const std::vector<uint8_t> &key,
                                            CryptoSpan<const uint8_t> iv,
                                            CryptoSpan<const uint8_t> plaintext,
                                            CryptoSpan<uint8_t> ciphertextOut,
                                            CryptoSpan<uint8_t> tagOut,
                                            CryptoSpan<const uint8_t> aad) {
    CryptoResult<void> result;
    result.status = aesGcmEncryptSpan(key, iv, aad, plaintext, ciphertextOut, tagOut);
    if (!result.ok()) {
        if (!ciphertextOut.empty()) {
            secureZero(ciphertextOut.data(), std::min(ciphertextOut.size(), plaintext.size()));
        }
        if (!tagOut.empty()) {
            secureZero(tagOut.data(), std::min(tagOut.size(), static_cast<size_t>(AES_GCM_TAG_BYTES)));
        }
    }
    return result;
}

CryptoResult<void> ESPCrypto::aesGcmDecrypt(const std::vector<uint8_t> &key,
                                            CryptoSpan<const uint8_t> iv,
                                            CryptoSpan<const uint8_t> ciphertext,
                                            CryptoSpan<const uint8_t> tag,
                                            CryptoSpan<uint8_t> plaintextOut,
                                            CryptoSpan<const uint8_t> aad) {
    CryptoResult<void> result;
    result.status = aesGcmDecryptSpan(key, iv, aad, ciphertext, tag, plaintextOut);
    if (!result.ok()) {
        if (!plaintextOut.empty()) {
            secureZero(plaintextOut.data(), std::min(plaintextOut.size(), ciphertext.size()));
        }
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

CryptoResult<std::vector<uint8_t>> ESPCrypto::rsaSign(const CryptoKey &privateKey,
                                                      CryptoSpan<const uint8_t> data,
                                                      ShaVariant variant) {
    CryptoResult<std::vector<uint8_t>> result;
    if (!privateKey.valid() || (!data.data() && data.size() > 0)) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing key or data");
        return result;
    }
    auto parsed = privateKey.ensureParsedPk(true);
    if (!parsed.ok()) {
        result.status = parsed;
        return result;
    }
    if (!pkSignContext(privateKey.pk->ctx, MBEDTLS_PK_RSA, variant, data.data(), data.size(), result.value)) {
        result.status = makeStatus(CryptoStatus::VerifyFailed, "rsa sign failed");
        result.value.clear();
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoResult<void> ESPCrypto::rsaVerify(const CryptoKey &publicKey,
                                        CryptoSpan<const uint8_t> data,
                                        CryptoSpan<const uint8_t> signature,
                                        ShaVariant variant) {
    CryptoResult<void> result;
    if (!publicKey.valid() || (!data.data() && data.size() > 0) || signature.empty()) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing key/data/signature");
        return result;
    }
    auto parsed = publicKey.ensureParsedPk(false);
    if (!parsed.ok()) {
        result.status = parsed;
        return result;
    }
    std::vector<uint8_t> sigVec(signature.data(), signature.data() + signature.size());
    if (!pkVerifyContext(publicKey.pk->ctx, MBEDTLS_PK_RSA, variant, data.data(), data.size(), sigVec)) {
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

CryptoResult<std::vector<uint8_t>> ESPCrypto::eccSign(const CryptoKey &privateKey,
                                                      CryptoSpan<const uint8_t> data,
                                                      ShaVariant variant) {
    CryptoResult<std::vector<uint8_t>> result;
    if (!privateKey.valid() || (!data.data() && data.size() > 0)) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing key or data");
        return result;
    }
    auto parsed = privateKey.ensureParsedPk(true);
    if (!parsed.ok()) {
        result.status = parsed;
        return result;
    }
    if (!pkSignContext(privateKey.pk->ctx, MBEDTLS_PK_ECKEY, variant, data.data(), data.size(), result.value)) {
        result.status = makeStatus(CryptoStatus::VerifyFailed, "ecc sign failed");
        result.value.clear();
        return result;
    }
    result.status = makeStatus(CryptoStatus::Ok);
    return result;
}

CryptoResult<void> ESPCrypto::eccVerify(const CryptoKey &publicKey,
                                        CryptoSpan<const uint8_t> data,
                                        CryptoSpan<const uint8_t> signature,
                                        ShaVariant variant) {
    CryptoResult<void> result;
    if (!publicKey.valid() || (!data.data() && data.size() > 0) || signature.empty()) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "missing key/data/signature");
        return result;
    }
    auto parsed = publicKey.ensureParsedPk(false);
    if (!parsed.ok()) {
        result.status = parsed;
        return result;
    }
    std::vector<uint8_t> sigVec(signature.data(), signature.data() + signature.size());
    if (!pkVerifyContext(publicKey.pk->ctx, MBEDTLS_PK_ECKEY, variant, data.data(), data.size(), sigVec)) {
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
    const char *typHdr = headerDoc["typ"].as<const char *>();
    if (options.expectedTyp.length() > 0) {
        if (!typHdr || options.expectedTyp != typHdr) {
            result.status = makeStatus(CryptoStatus::PolicyViolation, "typ mismatch");
            return result;
        }
    }
    JsonArray crit = headerDoc["crit"].as<JsonArray>();
    if (!crit.isNull() && !options.criticalHeadersAllowed.empty()) {
        for (JsonVariant v : crit) {
            const char *name = v.as<const char *>();
            bool allowed = false;
            for (const auto &allowedName : options.criticalHeadersAllowed) {
                if (name && allowedName == name) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                result.status = makeStatus(CryptoStatus::PolicyViolation, "crit header not allowed");
                return result;
            }
        }
    } else if (!crit.isNull() && options.criticalHeadersAllowed.empty()) {
        result.status = makeStatus(CryptoStatus::PolicyViolation, "crit header not allowed");
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
    uint32_t leeway = options.leewaySeconds;
    uint32_t exp = payloadDoc["exp"].as<uint32_t>();
    uint32_t nbf = payloadDoc["nbf"].as<uint32_t>();
    if (options.requireExpiration && exp == 0) {
        result.status = makeStatus(CryptoStatus::PolicyViolation, "missing exp");
        return result;
    }
    if (exp != 0 && now > exp + leeway) {
        result.status = makeStatus(CryptoStatus::Expired, "token expired");
        return result;
    }
    if (nbf != 0 && now + leeway < nbf) {
        result.status = makeStatus(CryptoStatus::NotYetValid, "token not active");
        return result;
    }
    auto audMatch = [&](const char *aud) -> bool {
        if (!aud) {
            return false;
        }
        if (options.audience.length() > 0 && options.audience == aud) {
            return true;
        }
        for (const auto &a : options.audiences) {
            if (a == aud) {
                return true;
            }
        }
        return options.audience.length() == 0 && options.audiences.empty();
    };
    if (options.audience.length() > 0 || !options.audiences.empty()) {
        bool ok = false;
        if (payloadDoc["aud"].is<JsonArray>()) {
            JsonArray arr = payloadDoc["aud"].as<JsonArray>();
            for (JsonVariant v : arr) {
                ok = audMatch(v.as<const char *>());
                if (ok) break;
            }
        } else {
            ok = audMatch(payloadDoc["aud"].as<const char *>());
        }
        if (!ok) {
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

CryptoResult<void> ESPCrypto::verifyJwtWithJwks(const String &token,
                                                const JsonDocument &jwks,
                                                JsonDocument &outClaims,
                                                const JwtVerifyOptions &options) {
    CryptoResult<void> result;
    if (token.length() == 0) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "token missing");
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
    std::vector<uint8_t> headerBytes;
    if (!base64Decode(headerPart, Base64Alphabet::Url, headerBytes)) {
        result.status = makeStatus(CryptoStatus::DecodeError, "base64 decode failed");
        return result;
    }
    JsonDocument headerDoc;
    if (deserializeJson(headerDoc, headerBytes.data(), headerBytes.size()) != DeserializationError::Ok) {
        result.status = makeStatus(CryptoStatus::JsonError, "invalid header json");
        return result;
    }
    const char *kid = headerDoc["kid"].as<const char *>();
    JwtAlgorithm alg = algorithmFromName(headerDoc["alg"].as<const char *>() ? headerDoc["alg"].as<const char *>() : "");
    auto keyRes = selectJwkFromSet(jwks, kid ? String(kid) : String(), alg);
    if (!keyRes.ok()) {
        result.status = keyRes.status;
        return result;
    }
    auto bytes = keyRes.value.bytes();
    std::string keyStr(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    return verifyJwtResult(token, keyStr, outClaims, options);
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
    markRuntimeInitialized();
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
    markRuntimeInitialized();
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
    markRuntimeInitialized();
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

CryptoResult<std::vector<uint8_t>> ESPCrypto::ecdsaDerToRaw(CryptoSpan<const uint8_t> der) {
    return ecdsaDerToRawInternal(der);
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::ecdsaRawToDer(CryptoSpan<const uint8_t> raw) {
    return ecdsaRawToDerInternal(raw);
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::chacha20Poly1305Encrypt(CryptoSpan<const uint8_t> key,
                                                                      CryptoSpan<const uint8_t> nonce,
                                                                      CryptoSpan<const uint8_t> aad,
                                                                      CryptoSpan<const uint8_t> plaintext) {
    CryptoResult<std::vector<uint8_t>> result;
#if defined(MBEDTLS_CHACHAPOLY_C)
    if (key.size() != 32 || nonce.size() < 12) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "key/nonce invalid");
        return result;
    }
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    if (mbedtls_chachapoly_setkey(&ctx, key.data()) != 0) {
        mbedtls_chachapoly_free(&ctx);
        result.status = makeStatus(CryptoStatus::InternalError, "setkey failed");
        return result;
    }
    result.value.assign(plaintext.size() + 16, 0);
    if (mbedtls_chachapoly_encrypt_and_tag(&ctx, plaintext.size(),
                                           nonce.data(),
                                           aad.data(), aad.size(),
                                           plaintext.data(),
                                           result.value.data(),
                                           result.value.data() + plaintext.size()) != 0) {
        result.value.clear();
        result.status = makeStatus(CryptoStatus::InternalError, "chacha20poly1305 encrypt failed");
        mbedtls_chachapoly_free(&ctx);
        return result;
    }
    mbedtls_chachapoly_free(&ctx);
    result.status = makeStatus(CryptoStatus::Ok);
#else
    (void)key;
    (void)nonce;
    (void)aad;
    (void)plaintext;
    result.status = makeStatus(CryptoStatus::Unsupported, "chachapoly unavailable");
#endif
    return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::chacha20Poly1305Decrypt(CryptoSpan<const uint8_t> key,
                                                                      CryptoSpan<const uint8_t> nonce,
                                                                      CryptoSpan<const uint8_t> aad,
                                                                      CryptoSpan<const uint8_t> ciphertextAndTag) {
    CryptoResult<std::vector<uint8_t>> result;
#if defined(MBEDTLS_CHACHAPOLY_C)
    if (key.size() != 32 || nonce.size() < 12 || ciphertextAndTag.size() < 17) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "input invalid");
        return result;
    }
    size_t cipherLen = ciphertextAndTag.size() - 16;
    const uint8_t *tag = ciphertextAndTag.data() + cipherLen;
    result.value.assign(cipherLen, 0);
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    if (mbedtls_chachapoly_setkey(&ctx, key.data()) != 0) {
        mbedtls_chachapoly_free(&ctx);
        result.status = makeStatus(CryptoStatus::InternalError, "setkey failed");
        return result;
    }
    if (mbedtls_chachapoly_auth_decrypt(&ctx, cipherLen,
                                        nonce.data(),
                                        aad.data(), aad.size(),
                                        tag,
                                        ciphertextAndTag.data(),
                                        result.value.data()) != 0) {
        mbedtls_chachapoly_free(&ctx);
        secureZero(result.value.data(), result.value.size());
        result.value.clear();
        result.status = makeStatus(CryptoStatus::VerifyFailed, "auth failed");
        return result;
    }
    mbedtls_chachapoly_free(&ctx);
    result.status = makeStatus(CryptoStatus::Ok);
#else
    (void)key;
    (void)nonce;
    (void)aad;
    (void)ciphertextAndTag;
    result.status = makeStatus(CryptoStatus::Unsupported, "chachapoly unavailable");
#endif
    return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::x25519(CryptoSpan<const uint8_t> privateKey,
                                                     CryptoSpan<const uint8_t> peerPublic) {
    CryptoResult<std::vector<uint8_t>> result;
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    if (privateKey.size() != 32 || peerPublic.size() != 32) {
        result.status = makeStatus(CryptoStatus::InvalidInput, "keys must be 32 bytes");
        return result;
    }
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Qp;
    mbedtls_mpi d;
    mbedtls_mpi z;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Qp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        result.status = makeStatus(CryptoStatus::Unsupported, "curve not available");
        goto cleanup;
    }
    ret = mbedtls_mpi_read_binary(&d, privateKey.data(), privateKey.size());
    if (ret != 0) {
        result.status = makeStatus(CryptoStatus::DecodeError, "private key load failed");
        goto cleanup;
    }
    ret = mbedtls_mpi_read_binary(&Qp.MBEDTLS_PRIVATE(X), peerPublic.data(), peerPublic.size());
    if (ret != 0 || mbedtls_mpi_lset(&Qp.MBEDTLS_PRIVATE(Z), 1) != 0) {
        result.status = makeStatus(CryptoStatus::DecodeError, "key load failed");
        goto cleanup;
    }
    result.value.assign(32, 0);
    ret = mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, nullptr, nullptr);
    if (ret != 0) {
        result.value.clear();
        result.status = makeStatus(CryptoStatus::InternalError, "x25519 failed");
        goto cleanup;
    }
    ret = mbedtls_mpi_write_binary(&z, result.value.data(), result.value.size());
    if (ret != 0) {
        secureZero(result.value.data(), result.value.size());
        result.value.clear();
        result.status = makeStatus(CryptoStatus::InternalError, "x25519 write failed");
        goto cleanup;
    }
    result.status = makeStatus(CryptoStatus::Ok);
cleanup:
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Qp);
    mbedtls_ecp_group_free(&grp);
#else
    (void)privateKey;
    (void)peerPublic;
    result.status = makeStatus(CryptoStatus::Unsupported, "curve25519 unavailable");
#endif
    return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::xchacha20Poly1305Encrypt(CryptoSpan<const uint8_t> key,
                                                                       CryptoSpan<const uint8_t> nonce,
                                                                       CryptoSpan<const uint8_t> aad,
                                                                       CryptoSpan<const uint8_t> plaintext) {
    CryptoResult<std::vector<uint8_t>> result;
    (void)key;
    (void)nonce;
    (void)aad;
    (void)plaintext;
    result.status = makeStatus(CryptoStatus::Unsupported, "xchacha20poly1305 unavailable");
    return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::xchacha20Poly1305Decrypt(CryptoSpan<const uint8_t> key,
                                                                       CryptoSpan<const uint8_t> nonce,
                                                                       CryptoSpan<const uint8_t> aad,
                                                                       CryptoSpan<const uint8_t> ciphertextAndTag) {
    CryptoResult<std::vector<uint8_t>> result;
    (void)key;
    (void)nonce;
    (void)aad;
    (void)ciphertextAndTag;
    result.status = makeStatus(CryptoStatus::Unsupported, "xchacha20poly1305 unavailable");
    return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::ed25519Sign(CryptoSpan<const uint8_t> privateKey,
                                                          CryptoSpan<const uint8_t> message) {
    CryptoResult<std::vector<uint8_t>> result;
    (void)privateKey;
    (void)message;
    result.status = makeStatus(CryptoStatus::Unsupported, "ed25519 unavailable");
    return result;
}

CryptoResult<void> ESPCrypto::ed25519Verify(CryptoSpan<const uint8_t> publicKey,
                                            CryptoSpan<const uint8_t> message,
                                            CryptoSpan<const uint8_t> signature) {
    CryptoResult<void> result;
    (void)publicKey;
    (void)message;
    (void)signature;
    result.status = makeStatus(CryptoStatus::Unsupported, "ed25519 unavailable");
    return result;
}
