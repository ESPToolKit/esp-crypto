#pragma once

#include "policy.h"
#include "types.h"

namespace espcrypto::runtime {
void deinit();
bool isInitialized();
CryptoCaps caps();
bool constantTimeEq(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b);
bool constantTimeEq(CryptoSpan<const uint8_t> a, CryptoSpan<const uint8_t> b);
} // namespace espcrypto::runtime
