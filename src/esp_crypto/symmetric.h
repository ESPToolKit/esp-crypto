#pragma once

#include "policy.h"
#include "types.h"

enum class GcmNonceStrategy { Random96, Counter64_Random32, BootCounter_Random32 };

struct GcmNonceOptions {
	GcmNonceStrategy strategy = GcmNonceStrategy::Random96;
	bool persistCounter = false;
	std::string nvsNamespace = "espcrypto";
	std::string nvsPartition = "nvs";
};

struct GcmMessage {
	std::vector<uint8_t> iv;
	std::vector<uint8_t> ciphertext;
	std::vector<uint8_t> tag;
};

namespace espcrypto::symmetric {
CryptoResult<GcmMessage> aesGcmEncryptAuto(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &plaintext,
    const std::vector<uint8_t> &aad = {},
    size_t ivLength = 12,
    const GcmNonceOptions &nonceOptions = GcmNonceOptions{}
);
CryptoResult<std::vector<uint8_t>> aesGcmDecrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &tag,
    const std::vector<uint8_t> &aad = {}
);
CryptoResult<void> aesGcmEncrypt(
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> plaintext,
    CryptoSpan<uint8_t> ciphertextOut,
    CryptoSpan<uint8_t> tagOut,
    CryptoSpan<const uint8_t> aad = {}
);
CryptoResult<void> aesGcmDecrypt(
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> ciphertext,
    CryptoSpan<const uint8_t> tag,
    CryptoSpan<uint8_t> plaintextOut,
    CryptoSpan<const uint8_t> aad = {}
);
CryptoResult<std::vector<uint8_t>> aesCtrCrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonceCounter,
    const std::vector<uint8_t> &input
);
CryptoResult<std::vector<uint8_t>> chacha20Poly1305Encrypt(
    CryptoSpan<const uint8_t> key,
    CryptoSpan<const uint8_t> nonce,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> plaintext
);
CryptoResult<std::vector<uint8_t>> chacha20Poly1305Decrypt(
    CryptoSpan<const uint8_t> key,
    CryptoSpan<const uint8_t> nonce,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> ciphertextAndTag
);
CryptoResult<std::vector<uint8_t>> xchacha20Poly1305Encrypt(
    CryptoSpan<const uint8_t> key,
    CryptoSpan<const uint8_t> nonce,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> plaintext
);
CryptoResult<std::vector<uint8_t>> xchacha20Poly1305Decrypt(
    CryptoSpan<const uint8_t> key,
    CryptoSpan<const uint8_t> nonce,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> ciphertextAndTag
);
} // namespace espcrypto::symmetric
