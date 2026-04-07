#pragma once

#include <cstddef>
#include <cstdint>

struct CryptoPolicy {
	size_t minRsaBits = 2048;
	uint32_t minPbkdf2Iterations = 100000;
	bool allowLegacy = false;
	bool allowWeakCurves = false;
	uint8_t minAesGcmIvBytes = 12;
};

struct CryptoCaps {
	bool shaAccel = false;
	bool aesAccel = false;
	bool aesGcmAccel = false;
};

namespace espcrypto::policy {
void set(const CryptoPolicy &policy);
CryptoPolicy get();
} // namespace espcrypto::policy
