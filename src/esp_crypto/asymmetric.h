#pragma once

#include <string_view>

#include "hash.h"
#include "types.h"

namespace espcrypto::asymmetric {
CryptoResult<std::vector<uint8_t>>
rsaSign(std::string_view privateKeyPem, CryptoSpan<const uint8_t> data, ShaVariant variant);
CryptoResult<void> rsaVerify(
    std::string_view publicKeyPem,
    CryptoSpan<const uint8_t> data,
    CryptoSpan<const uint8_t> signature,
    ShaVariant variant
);
CryptoResult<std::vector<uint8_t>>
rsaSign(const CryptoKey &privateKey, CryptoSpan<const uint8_t> data, ShaVariant variant);
CryptoResult<void> rsaVerify(
    const CryptoKey &publicKey,
    CryptoSpan<const uint8_t> data,
    CryptoSpan<const uint8_t> signature,
    ShaVariant variant
);
CryptoResult<std::vector<uint8_t>>
eccSign(std::string_view privateKeyPem, CryptoSpan<const uint8_t> data, ShaVariant variant);
CryptoResult<void> eccVerify(
    std::string_view publicKeyPem,
    CryptoSpan<const uint8_t> data,
    CryptoSpan<const uint8_t> signature,
    ShaVariant variant
);
CryptoResult<std::vector<uint8_t>>
eccSign(const CryptoKey &privateKey, CryptoSpan<const uint8_t> data, ShaVariant variant);
CryptoResult<void> eccVerify(
    const CryptoKey &publicKey,
    CryptoSpan<const uint8_t> data,
    CryptoSpan<const uint8_t> signature,
    ShaVariant variant
);
CryptoResult<std::vector<uint8_t>> ecdsaDerToRaw(CryptoSpan<const uint8_t> der);
CryptoResult<std::vector<uint8_t>> ecdsaRawToDer(CryptoSpan<const uint8_t> raw);
CryptoResult<std::vector<uint8_t>>
x25519(CryptoSpan<const uint8_t> privateKey, CryptoSpan<const uint8_t> peerPublic);
} // namespace espcrypto::asymmetric
