#pragma once

#include <string>
#include <string_view>

#include "types.h"

enum class ShaVariant { SHA256, SHA384, SHA512 };

struct ShaOptions {
	ShaVariant variant = ShaVariant::SHA256;
	bool preferHardware = true;
};

namespace espcrypto::hash {
CryptoResult<std::vector<uint8_t>> sha(CryptoSpan<const uint8_t> data, const ShaOptions &options = ShaOptions{});
CryptoResult<void> sha(
    CryptoSpan<const uint8_t> data,
    CryptoSpan<uint8_t> out,
    const ShaOptions &options = ShaOptions{}
);
std::string shaHex(CryptoSpan<const uint8_t> data, const ShaOptions &options = ShaOptions{});
std::string shaHex(std::string_view text, const ShaOptions &options = ShaOptions{});
} // namespace espcrypto::hash
