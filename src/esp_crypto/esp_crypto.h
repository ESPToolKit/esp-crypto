#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>

#include <string>
#include <vector>

enum class ShaVariant {
    SHA256,
    SHA384,
    SHA512
};

struct ShaOptions {
    ShaVariant variant = ShaVariant::SHA256;
    bool preferHardware = true;
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
};

struct PasswordHashOptions {
    uint8_t cost = 10;          // Similar to bcrypt cost factor
    size_t saltBytes = 16;
    size_t outputBytes = 32;
};

class ESPCrypto {
   public:
    static std::vector<uint8_t> sha(const uint8_t *data, size_t length, const ShaOptions &options = ShaOptions{});
    static std::vector<uint8_t> sha(const std::vector<uint8_t> &data, const ShaOptions &options = ShaOptions{});
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

    static String createJwt(const JsonDocument &claims,
                            const std::string &key,
                            const JwtSignOptions &options = JwtSignOptions{});
    static String createJwt(const JsonDocument &claims,
                            const String &key,
                            const JwtSignOptions &options = JwtSignOptions{}) {
        return createJwt(claims, std::string(key.c_str(), key.length()), options);
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

    static String hashString(const String &input, const PasswordHashOptions &options = PasswordHashOptions{});
    static bool verifyString(const String &input, const String &encoded);
};
