#pragma once

#include <string_view>

#include "kdf.h"
#include "keystore.h"

struct DeviceKeyOptions {
	bool persistSeed = true;
	std::string nvsNamespace = "espcrypto";
	std::string nvsPartition = "nvs";
	size_t seedBytes = 32;
};

namespace espcrypto::device {
CryptoResult<std::vector<uint8_t>> deriveKey(
    std::string_view purpose,
    CryptoSpan<const uint8_t> contextInfo = {},
    size_t length = 32,
    const DeviceKeyOptions &options = DeviceKeyOptions{}
);
} // namespace espcrypto::device
