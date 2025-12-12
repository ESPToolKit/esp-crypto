#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>

#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <type_traits>
#include <map>
#include <memory>
#include <functional>

#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

#if __has_include(<span>)
#include <span>
#define ESPCRYPTO_HAS_STD_SPAN 1
#else
#define ESPCRYPTO_HAS_STD_SPAN 0
#endif

enum class CryptoStatus {
    Ok,
    InvalidInput,
    RandomFailure,
    Unsupported,
    PolicyViolation,
    BufferTooSmall,
    VerifyFailed,
    DecodeError,
    JsonError,
    Expired,
    NotYetValid,
    AudienceMismatch,
    IssuerMismatch,
    NonceReuse,
    InternalError
};

const char *toString(CryptoStatus status);

struct CryptoStatusDetail {
    CryptoStatus code = CryptoStatus::Ok;
    String message;

    bool ok() const { return code == CryptoStatus::Ok; }
};

template <typename T>
struct CryptoResult {
    CryptoStatusDetail status;
    T value;

    bool ok() const { return status.ok(); }
};

template <>
struct CryptoResult<void> {
    CryptoStatusDetail status;
    bool ok() const { return status.ok(); }
};

template <typename T>
struct CryptoSpan {
    using element_type = T;
    using pointer = T *;
    using const_pointer = const T *;

    CryptoSpan() : ptr(nullptr), len(0) {}
    CryptoSpan(pointer data, size_t size) : ptr(data), len(size) {}
    CryptoSpan(std::vector<typename std::remove_const<T>::type> &vec) : ptr(vec.data()), len(vec.size()) {}
    CryptoSpan(const std::vector<typename std::remove_const<T>::type> &vec) : ptr(vec.data()), len(vec.size()) {}
#if ESPCRYPTO_HAS_STD_SPAN
    CryptoSpan(std::span<T> span) : ptr(span.data()), len(span.size()) {}
#endif

    pointer data() const { return ptr; }
    size_t size() const { return len; }
    bool empty() const { return len == 0; }

   private:
    pointer ptr;
    size_t len;
};

enum class KeyFormat {
    Raw,
    Pem,
    Der,
    Jwk
};

enum class KeyKind {
    Auto,
    Public,
    Private,
    Symmetric
};

struct KeyHandle {
    String alias;
    uint32_t version = 0;
};

class CryptoKey {
   public:
    CryptoKey();
    CryptoKey(const CryptoKey &other);
    CryptoKey &operator=(const CryptoKey &other);
    CryptoKey(CryptoKey &&other) noexcept;
    CryptoKey &operator=(CryptoKey &&other) noexcept;
    ~CryptoKey();
    static CryptoKey fromPem(const std::string &pem, KeyKind kind = KeyKind::Auto);
    static CryptoKey fromDer(const std::vector<uint8_t> &der, KeyKind kind = KeyKind::Auto);
    static CryptoKey fromRaw(const std::vector<uint8_t> &raw, KeyKind kind = KeyKind::Symmetric);

    bool valid() const;
    KeyKind kind() const;
    CryptoSpan<const uint8_t> bytes() const;
    void clear();
    bool parsed() const;

   private:
    friend class ESPCrypto;
    struct PkCache;
    CryptoStatusDetail ensureParsedPk(bool requirePrivate) const;
    std::vector<uint8_t> data;
    KeyFormat format = KeyFormat::Raw;
    KeyKind keyKind = KeyKind::Auto;
    mutable PkCache *pk = nullptr;
};

class KeyStore {
   public:
    virtual ~KeyStore() = default;
    virtual CryptoResult<std::vector<uint8_t>> load(const KeyHandle &handle) = 0;
    virtual CryptoStatusDetail store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) = 0;
    virtual CryptoStatusDetail remove(const KeyHandle &handle) = 0;
};

class MemoryKeyStore : public KeyStore {
   public:
    CryptoResult<std::vector<uint8_t>> load(const KeyHandle &handle) override;
    CryptoStatusDetail store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) override;
    CryptoStatusDetail remove(const KeyHandle &handle) override;

   private:
    std::map<std::string, std::vector<uint8_t>> storage;
};

class NvsKeyStore : public KeyStore {
   public:
    NvsKeyStore(String ns = "espcrypto", String partition = "nvs");
    CryptoResult<std::vector<uint8_t>> load(const KeyHandle &handle) override;
    CryptoStatusDetail store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) override;
    CryptoStatusDetail remove(const KeyHandle &handle) override;

   private:
    String ns;
    String partition;
    CryptoStatusDetail ensureInit() const;
    String makeKeyName(const KeyHandle &handle) const;
};

class LittleFsKeyStore : public KeyStore {
   public:
    LittleFsKeyStore(String basePath = "/keys");
    CryptoResult<std::vector<uint8_t>> load(const KeyHandle &handle) override;
    CryptoStatusDetail store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) override;
    CryptoStatusDetail remove(const KeyHandle &handle) override;

   private:
    String basePath;
    String makePath(const KeyHandle &handle) const;
};

struct DeviceKeyOptions {
    bool persistSeed = true;
    String nvsNamespace = "espcrypto";
    String nvsPartition = "nvs";
    size_t seedBytes = 32;
};

enum class ShaVariant {
    SHA256,
    SHA384,
    SHA512
};

struct ShaOptions {
    ShaVariant variant = ShaVariant::SHA256;
    bool preferHardware = true;
};

enum class GcmNonceStrategy {
    Random96,
    Counter64_Random32,
    BootCounter_Random32
};

struct GcmNonceOptions {
    GcmNonceStrategy strategy = GcmNonceStrategy::Random96;
    bool persistCounter = false;
    String nvsNamespace = "espcrypto";
    String nvsPartition = "nvs";
};

class ShaCtx {
   public:
    ShaCtx();
    ~ShaCtx();
    CryptoStatusDetail begin(ShaVariant variant, bool preferHardware = true);
    CryptoStatusDetail update(CryptoSpan<const uint8_t> data);
    CryptoStatusDetail finish(CryptoSpan<uint8_t> out);

   private:
    const mbedtls_md_info_t *info = nullptr;
    mbedtls_md_context_t ctx;
    bool started = false;
};

class HmacCtx {
   public:
    HmacCtx();
    ~HmacCtx();
    CryptoStatusDetail begin(ShaVariant variant, CryptoSpan<const uint8_t> key);
    CryptoStatusDetail update(CryptoSpan<const uint8_t> data);
    CryptoStatusDetail finish(CryptoSpan<uint8_t> out);

   private:
    const mbedtls_md_info_t *info = nullptr;
    mbedtls_md_context_t ctx;
    bool started = false;
};

class AesCtrStream {
   public:
    AesCtrStream();
    ~AesCtrStream();
    CryptoStatusDetail begin(const std::vector<uint8_t> &key, CryptoSpan<const uint8_t> nonceCounter);
    CryptoStatusDetail update(CryptoSpan<const uint8_t> input, CryptoSpan<uint8_t> output);

   private:
    mbedtls_aes_context ctx;
    unsigned char counter[16];
    unsigned char streamBlock[16];
    size_t offset = 0;
    bool started = false;
};

class AesGcmCtx {
   public:
    AesGcmCtx();
    ~AesGcmCtx();
    CryptoStatusDetail beginEncrypt(const std::vector<uint8_t> &key,
                                    CryptoSpan<const uint8_t> iv,
                                    CryptoSpan<const uint8_t> aad);
    CryptoStatusDetail beginDecrypt(const std::vector<uint8_t> &key,
                                    CryptoSpan<const uint8_t> iv,
                                    CryptoSpan<const uint8_t> aad,
                                    CryptoSpan<const uint8_t> tag);
    CryptoStatusDetail update(CryptoSpan<const uint8_t> input, CryptoSpan<uint8_t> output);
    CryptoStatusDetail finish(CryptoSpan<uint8_t> tagOut);

   private:
    bool decrypt = false;
    bool started = false;
    CryptoStatusDetail beginCommon(const std::vector<uint8_t> &key,
                                   CryptoSpan<const uint8_t> iv,
                                   CryptoSpan<const uint8_t> aad,
                                   bool decryptMode,
                                   CryptoSpan<const uint8_t> tag);
    mbedtls_gcm_context ctx;
    std::vector<uint8_t> tagVerify;
};

class SecureBuffer {
   public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t bytes);
    SecureBuffer(SecureBuffer &&other) noexcept;
    SecureBuffer &operator=(SecureBuffer &&other) noexcept;
    SecureBuffer(const SecureBuffer &) = delete;
    SecureBuffer &operator=(const SecureBuffer &) = delete;
    ~SecureBuffer();

    uint8_t *data() { return buffer.data(); }
    const uint8_t *data() const { return buffer.data(); }
    size_t size() const { return buffer.size(); }
    void resize(size_t bytes);
    std::vector<uint8_t> &raw() { return buffer; }
    const std::vector<uint8_t> &raw() const { return buffer; }

   private:
    void wipe();
    std::vector<uint8_t> buffer;
};

class SecureString {
   public:
    SecureString() = default;
    explicit SecureString(std::string value);
    SecureString(SecureString &&other) noexcept;
    SecureString &operator=(SecureString &&other) noexcept;
    SecureString(const SecureString &) = delete;
    SecureString &operator=(const SecureString &) = delete;
    ~SecureString();

    const std::string &get() const { return value; }
    std::string &get() { return value; }
    const char *c_str() const { return value.c_str(); }
    size_t size() const { return value.size(); }
    bool empty() const { return value.empty(); }

   private:
    void wipe();
    std::string value;
};

enum class JwtAlgorithm {
    Auto,
    HS256,
    RS256,
    ES256
};

struct JwtSignOptions {
    JwtAlgorithm algorithm = JwtAlgorithm::HS256;
    String keyId;
    String issuer;
    String subject;
    String audience;
    uint32_t expiresInSeconds = 3600;
    uint32_t notBefore = 0;
    uint32_t issuedAt = 0;
    uint32_t currentTimestamp = 0;
};

struct JwtVerifyOptions {
    JwtAlgorithm algorithm = JwtAlgorithm::Auto;
    String audience;
    String issuer;
    uint32_t currentTimestamp = 0;
    bool requireExpiration = true;
    uint32_t leewaySeconds = 0;
    String expectedTyp;
    std::vector<String> audiences;
    std::vector<String> criticalHeadersAllowed;
};

struct PasswordHashOptions {
    uint8_t cost = 10;          // Similar to bcrypt cost factor
    size_t saltBytes = 16;
    size_t outputBytes = 32;
};

struct CryptoPolicy {
    size_t minRsaBits = 2048;
    uint32_t minPbkdf2Iterations = 1024;
    bool allowLegacy = false;
    bool allowWeakCurves = false;
    uint8_t minAesGcmIvBytes = 12;
};

struct CryptoCaps {
    bool shaAccel = false;
    bool aesAccel = false;
    bool aesGcmAccel = false;
};

struct GcmMessage {
    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
};

class ESPCrypto {
   public:
    static void setPolicy(const CryptoPolicy &policy);
    static CryptoPolicy policy();
    static CryptoCaps caps();
    static bool constantTimeEq(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b);
    static bool constantTimeEq(CryptoSpan<const uint8_t> a, CryptoSpan<const uint8_t> b);

    static std::vector<uint8_t> sha(const uint8_t *data, size_t length, const ShaOptions &options = ShaOptions{});
    static std::vector<uint8_t> sha(const std::vector<uint8_t> &data, const ShaOptions &options = ShaOptions{});
    static CryptoResult<std::vector<uint8_t>> shaResult(CryptoSpan<const uint8_t> data, const ShaOptions &options = ShaOptions{});
    static CryptoResult<void> sha(CryptoSpan<const uint8_t> data, CryptoSpan<uint8_t> out, const ShaOptions &options = ShaOptions{});

    static String shaHex(const uint8_t *data, size_t length, const ShaOptions &options = ShaOptions{});
    static String shaHex(const String &text, const ShaOptions &options = ShaOptions{});

    static bool aesGcmEncrypt(const std::vector<uint8_t> &key,
                              const std::vector<uint8_t> &iv,
                              const std::vector<uint8_t> &plaintext,
                              std::vector<uint8_t> &ciphertext,
                              std::vector<uint8_t> &tag,
                              const std::vector<uint8_t> &aad = {});
    static bool aesGcmDecrypt(const std::vector<uint8_t> &key,
                              const std::vector<uint8_t> &iv,
                              const std::vector<uint8_t> &ciphertext,
                              const std::vector<uint8_t> &tag,
                              std::vector<uint8_t> &plaintext,
                              const std::vector<uint8_t> &aad = {});
    static bool aesCtrCrypt(const std::vector<uint8_t> &key,
                            const std::vector<uint8_t> &nonceCounter,
                            const std::vector<uint8_t> &input,
                            std::vector<uint8_t> &output);

    static CryptoResult<GcmMessage> aesGcmEncryptAuto(const std::vector<uint8_t> &key,
                                                      const std::vector<uint8_t> &plaintext,
                                                      const std::vector<uint8_t> &aad = {},
                                                      size_t ivLength = 12,
                                                      const GcmNonceOptions &nonceOptions = GcmNonceOptions{});
    static CryptoResult<std::vector<uint8_t>> aesGcmDecrypt(const std::vector<uint8_t> &key,
                                                            const std::vector<uint8_t> &iv,
                                                            const std::vector<uint8_t> &ciphertext,
                                                            const std::vector<uint8_t> &tag,
                                                            const std::vector<uint8_t> &aad = {});
    static CryptoResult<void> aesGcmEncrypt(const std::vector<uint8_t> &key,
                                            CryptoSpan<const uint8_t> iv,
                                            CryptoSpan<const uint8_t> plaintext,
                                            CryptoSpan<uint8_t> ciphertextOut,
                                            CryptoSpan<uint8_t> tagOut,
                                            CryptoSpan<const uint8_t> aad = {});
    static CryptoResult<void> aesGcmDecrypt(const std::vector<uint8_t> &key,
                                            CryptoSpan<const uint8_t> iv,
                                            CryptoSpan<const uint8_t> ciphertext,
                                            CryptoSpan<const uint8_t> tag,
                                            CryptoSpan<uint8_t> plaintextOut,
                                            CryptoSpan<const uint8_t> aad = {});
    static CryptoResult<std::vector<uint8_t>> aesCtrCrypt(const std::vector<uint8_t> &key,
                                                          const std::vector<uint8_t> &nonceCounter,
                                                          const std::vector<uint8_t> &input);

    static bool rsaSign(const std::string &privateKeyPem,
                        const uint8_t *data,
                        size_t length,
                        ShaVariant variant,
                        std::vector<uint8_t> &signature);
    static bool rsaSign(const String &privateKeyPem,
                        const uint8_t *data,
                        size_t length,
                        ShaVariant variant,
                        std::vector<uint8_t> &signature) {
        return rsaSign(std::string(privateKeyPem.c_str(), privateKeyPem.length()), data, length, variant, signature);
    }
    static bool rsaVerify(const std::string &publicKeyPem,
                          const uint8_t *data,
                          size_t length,
                          const std::vector<uint8_t> &signature,
                          ShaVariant variant);
    static bool rsaVerify(const String &publicKeyPem,
                          const uint8_t *data,
                          size_t length,
                         const std::vector<uint8_t> &signature,
                         ShaVariant variant) {
        return rsaVerify(std::string(publicKeyPem.c_str(), publicKeyPem.length()), data, length, signature, variant);
    }

    static CryptoResult<std::vector<uint8_t>> rsaSign(const std::string &privateKeyPem,
                                                      CryptoSpan<const uint8_t> data,
                                                      ShaVariant variant);
    static CryptoResult<void> rsaVerify(const std::string &publicKeyPem,
                                        CryptoSpan<const uint8_t> data,
                                        CryptoSpan<const uint8_t> signature,
                                        ShaVariant variant);
    static CryptoResult<std::vector<uint8_t>> rsaSign(const CryptoKey &privateKey,
                                                      CryptoSpan<const uint8_t> data,
                                                      ShaVariant variant);
    static CryptoResult<void> rsaVerify(const CryptoKey &publicKey,
                                        CryptoSpan<const uint8_t> data,
                                        CryptoSpan<const uint8_t> signature,
                                        ShaVariant variant);

    static bool eccSign(const std::string &privateKeyPem,
                        const uint8_t *data,
                        size_t length,
                        ShaVariant variant,
                        std::vector<uint8_t> &signature);
    static bool eccSign(const String &privateKeyPem,
                        const uint8_t *data,
                        size_t length,
                        ShaVariant variant,
                        std::vector<uint8_t> &signature) {
        return eccSign(std::string(privateKeyPem.c_str(), privateKeyPem.length()), data, length, variant, signature);
    }
    static bool eccVerify(const std::string &publicKeyPem,
                          const uint8_t *data,
                          size_t length,
                          const std::vector<uint8_t> &signature,
                          ShaVariant variant);
    static bool eccVerify(const String &publicKeyPem,
                          const uint8_t *data,
                          size_t length,
                          const std::vector<uint8_t> &signature,
                          ShaVariant variant) {
        return eccVerify(std::string(publicKeyPem.c_str(), publicKeyPem.length()), data, length, signature, variant);
    }

    static CryptoResult<std::vector<uint8_t>> eccSign(const std::string &privateKeyPem,
                                                      CryptoSpan<const uint8_t> data,
                                                      ShaVariant variant);
    static CryptoResult<void> eccVerify(const std::string &publicKeyPem,
                                        CryptoSpan<const uint8_t> data,
                                        CryptoSpan<const uint8_t> signature,
                                        ShaVariant variant);
    static CryptoResult<std::vector<uint8_t>> eccSign(const CryptoKey &privateKey,
                                                      CryptoSpan<const uint8_t> data,
                                                      ShaVariant variant);
    static CryptoResult<void> eccVerify(const CryptoKey &publicKey,
                                        CryptoSpan<const uint8_t> data,
                                        CryptoSpan<const uint8_t> signature,
                                        ShaVariant variant);

    static String createJwt(const JsonDocument &claims,
                            const std::string &key,
                            const JwtSignOptions &options = JwtSignOptions{});
    static String createJwt(const JsonDocument &claims,
                            const String &key,
                            const JwtSignOptions &options = JwtSignOptions{}) {
        return createJwt(claims, std::string(key.c_str(), key.length()), options);
    }
    static String createJwt(const JsonDocument &claims,
                            const char *key,
                            const JwtSignOptions &options = JwtSignOptions{}) {
        return createJwt(claims, key ? std::string(key) : std::string(), options);
    }

    static bool verifyJwt(const String &token,
                          const std::string &key,
                          JsonDocument &outClaims,
                          String &error,
                          const JwtVerifyOptions &options = JwtVerifyOptions{});
    static bool verifyJwt(const String &token,
                          const String &key,
                          JsonDocument &outClaims,
                          String &error,
                          const JwtVerifyOptions &options = JwtVerifyOptions{}) {
        return verifyJwt(token, std::string(key.c_str(), key.length()), outClaims, error, options);
    }
    static bool verifyJwt(const String &token,
                          const char *key,
                          JsonDocument &outClaims,
                          String &error,
                          const JwtVerifyOptions &options = JwtVerifyOptions{}) {
        return verifyJwt(token, key ? std::string(key) : std::string(), outClaims, error, options);
    }
    static CryptoResult<String> createJwtResult(const JsonDocument &claims,
                                                const std::string &key,
                                                const JwtSignOptions &options = JwtSignOptions{});
    static CryptoResult<void> verifyJwtResult(const String &token,
                                              const std::string &key,
                                              JsonDocument &outClaims,
                                              const JwtVerifyOptions &options = JwtVerifyOptions{});
    static CryptoResult<void> verifyJwtWithJwks(const String &token,
                                                const JsonDocument &jwks,
                                                JsonDocument &outClaims,
                                                const JwtVerifyOptions &options = JwtVerifyOptions{});

    static String hashString(const String &input, const PasswordHashOptions &options = PasswordHashOptions{});
    static bool verifyString(const String &input, const String &encoded);

    static CryptoResult<String> hashStringResult(const String &input, const PasswordHashOptions &options = PasswordHashOptions{});
    static CryptoResult<void> verifyStringResult(const String &input, const String &encoded);

    static CryptoResult<std::vector<uint8_t>> hmac(ShaVariant variant,
                                                   CryptoSpan<const uint8_t> key,
                                                   CryptoSpan<const uint8_t> data);
    static CryptoResult<std::vector<uint8_t>> hkdf(ShaVariant variant,
                                                   CryptoSpan<const uint8_t> salt,
                                                   CryptoSpan<const uint8_t> ikm,
                                                   CryptoSpan<const uint8_t> info,
                                                   size_t length);
    static CryptoResult<std::vector<uint8_t>> pbkdf2(const String &password,
                                                     CryptoSpan<const uint8_t> salt,
                                                     uint32_t iterations,
                                                     size_t outputLength);

    static CryptoResult<std::vector<uint8_t>> deriveDeviceKey(const String &purpose,
                                                              CryptoSpan<const uint8_t> contextInfo = {},
                                                              size_t length = 32,
                                                              const DeviceKeyOptions &options = DeviceKeyOptions{});

    static CryptoResult<void> storeKey(KeyStore &store, const KeyHandle &handle, CryptoSpan<const uint8_t> keyMaterial);
    static CryptoResult<CryptoKey> loadKey(KeyStore &store, const KeyHandle &handle, KeyFormat format, KeyKind kind = KeyKind::Auto);
    static CryptoResult<void> removeKey(KeyStore &store, const KeyHandle &handle);

    static CryptoResult<std::vector<uint8_t>> ecdsaDerToRaw(CryptoSpan<const uint8_t> der);
    static CryptoResult<std::vector<uint8_t>> ecdsaRawToDer(CryptoSpan<const uint8_t> raw);

    static CryptoResult<std::vector<uint8_t>> chacha20Poly1305Encrypt(CryptoSpan<const uint8_t> key,
                                                                      CryptoSpan<const uint8_t> nonce,
                                                                      CryptoSpan<const uint8_t> aad,
                                                                      CryptoSpan<const uint8_t> plaintext);
    static CryptoResult<std::vector<uint8_t>> chacha20Poly1305Decrypt(CryptoSpan<const uint8_t> key,
                                                                      CryptoSpan<const uint8_t> nonce,
                                                                      CryptoSpan<const uint8_t> aad,
                                                                      CryptoSpan<const uint8_t> ciphertextAndTag);
    static CryptoResult<std::vector<uint8_t>> xchacha20Poly1305Encrypt(CryptoSpan<const uint8_t> key,
                                                                       CryptoSpan<const uint8_t> nonce,
                                                                       CryptoSpan<const uint8_t> aad,
                                                                       CryptoSpan<const uint8_t> plaintext);
    static CryptoResult<std::vector<uint8_t>> xchacha20Poly1305Decrypt(CryptoSpan<const uint8_t> key,
                                                                       CryptoSpan<const uint8_t> nonce,
                                                                       CryptoSpan<const uint8_t> aad,
                                                                       CryptoSpan<const uint8_t> ciphertextAndTag);

    static CryptoResult<std::vector<uint8_t>> x25519(CryptoSpan<const uint8_t> privateKey,
                                                     CryptoSpan<const uint8_t> peerPublic);

    static CryptoResult<std::vector<uint8_t>> ed25519Sign(CryptoSpan<const uint8_t> privateKey,
                                                          CryptoSpan<const uint8_t> message);
    static CryptoResult<void> ed25519Verify(CryptoSpan<const uint8_t> publicKey,
                                            CryptoSpan<const uint8_t> message,
                                            CryptoSpan<const uint8_t> signature);
};
