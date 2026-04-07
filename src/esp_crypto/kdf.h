#pragma once

#include <string_view>

#include "hash.h"

namespace espcrypto::kdf {
CryptoResult<std::vector<uint8_t>>
hmac(ShaVariant variant, CryptoSpan<const uint8_t> key, CryptoSpan<const uint8_t> data);
CryptoResult<std::vector<uint8_t>> hkdf(
    ShaVariant variant,
    CryptoSpan<const uint8_t> salt,
    CryptoSpan<const uint8_t> ikm,
    CryptoSpan<const uint8_t> info,
    size_t length
);
CryptoResult<std::vector<uint8_t>> pbkdf2(
    std::string_view password,
    CryptoSpan<const uint8_t> salt,
    uint32_t iterations,
    size_t outputLength
);
} // namespace espcrypto::kdf
