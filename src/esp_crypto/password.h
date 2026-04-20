#pragma once

#include <string>
#include <string_view>

#include "kdf.h"

struct PasswordHashOptions {
	uint32_t iterations = 0;
	size_t saltBytes = 16;
	size_t outputBytes = 32;
	uint32_t targetMillis = 250;
	uint32_t minIterations = 100000;
};

struct PasswordVerifyOptions {
	bool allowLegacy = false;
};

namespace espcrypto::password {
CryptoResult<uint32_t> calibrateIterations(const PasswordHashOptions &options = PasswordHashOptions{});
CryptoResult<std::string> hash(
    std::string_view input,
    const PasswordHashOptions &options = PasswordHashOptions{}
);
CryptoResult<void> verify(
    std::string_view input,
    std::string_view encoded,
    const PasswordVerifyOptions &options = PasswordVerifyOptions{}
);
} // namespace espcrypto::password
