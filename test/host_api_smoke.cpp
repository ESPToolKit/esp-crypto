#include <esp_crypto/asymmetric.h>
#include <esp_crypto/device_key.h>
#include <esp_crypto/hash.h>
#include <esp_crypto/kdf.h>
#include <esp_crypto/keystore.h>
#include <esp_crypto/password.h>
#include <esp_crypto/policy.h>
#include <esp_crypto/runtime.h>
#include <esp_crypto/stream.h>
#include <esp_crypto/symmetric.h>
#include <esp_crypto/types.h>

#include <string>
#include <type_traits>

int main() {
	static_assert(std::is_same_v<decltype(CryptoStatusDetail{}.message), std::string>);
	static_assert(std::is_same_v<decltype(KeyHandle{}.alias), std::string>);
	static_assert(std::is_same_v<decltype(PasswordHashOptions{}.iterations), uint32_t>);
	static_assert(std::is_same_v<decltype(espcrypto::hash::shaHex(std::string_view{})), std::string>);

	CryptoResult<int> result;
	result.status = CryptoStatusDetail{};
	result.value = 7;

	CryptoSpan<const uint8_t> empty;
	CryptoPolicy policy;
	policy.minPbkdf2Iterations = 100000;
	(void)empty;
	(void)policy;
	return result.value == 7 ? 0 : 1;
}
