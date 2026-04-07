#include "internal/crypto_internal.h"

size_t digestLength(ShaVariant variant) {
	switch (variant) {
	case ShaVariant::SHA256:
		return 32;
	case ShaVariant::SHA384:
		return 48;
	case ShaVariant::SHA512:
		return 64;
	}
	return 0;
}

const mbedtls_md_info_t *mdInfoForVariant(ShaVariant variant) {
	switch (variant) {
	case ShaVariant::SHA256:
		return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	case ShaVariant::SHA384:
		return mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
	case ShaVariant::SHA512:
		return mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
	}
	return nullptr;
}

bool softwareSha(ShaVariant variant, const uint8_t *data, size_t length, uint8_t *out) {
	const mbedtls_md_info_t *info = mdInfoForVariant(variant);
	if (!info) {
		return false;
	}
	return mbedtls_md(info, data, length, out) == 0;
}

bool tryHardwareSha(ShaVariant variant, const uint8_t *data, size_t length, uint8_t *out) {
#if ESPCRYPTO_SHA_ACCEL
	esp_sha_type type = SHA1;
	switch (variant) {
	case ShaVariant::SHA256:
		type = SHA2_256;
		break;
	case ShaVariant::SHA384:
#if defined(SHA2_384)
		type = SHA2_384;
		break;
#else
		return false;
#endif
	case ShaVariant::SHA512:
#if defined(SHA2_512)
		type = SHA2_512;
		break;
#else
		return false;
#endif
	}
	esp_sha(type, data, length, out);
	return true;
#else
	(void)variant;
	(void)data;
	(void)length;
	(void)out;
	return false;
#endif
}

ShaCtx::ShaCtx() {
	mbedtls_md_init(&ctx);
}

ShaCtx::~ShaCtx() {
	mbedtls_md_free(&ctx);
}

CryptoStatusDetail ShaCtx::begin(ShaVariant variant, bool /*preferHardware*/) {
	// Reset any prior digest allocation so repeated begin() calls do not leak.
	mbedtls_md_free(&ctx);
	mbedtls_md_init(&ctx);
	started = false;
	info = nullptr;

	info = mdInfoForVariant(variant);
	if (!info) {
		return makeStatus(CryptoStatus::InvalidInput, "invalid sha variant");
	}
	if (mbedtls_md_setup(&ctx, info, 0) != 0) {
		return makeStatus(CryptoStatus::InternalError, "md setup failed");
	}
	if (mbedtls_md_starts(&ctx) != 0) {
		return makeStatus(CryptoStatus::InternalError, "md start failed");
	}
	started = true;
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail ShaCtx::update(CryptoSpan<const uint8_t> data) {
	if (!started) {
		return makeStatus(CryptoStatus::InvalidInput, "sha not started");
	}
	if (data.empty()) {
		return makeStatus(CryptoStatus::Ok);
	}
	if (mbedtls_md_update(&ctx, data.data(), data.size()) != 0) {
		return makeStatus(CryptoStatus::InternalError, "md update failed");
	}
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail ShaCtx::finish(CryptoSpan<uint8_t> out) {
	if (!started || !info) {
		return makeStatus(CryptoStatus::InvalidInput, "sha not started");
	}
	size_t need = mbedtls_md_get_size(info);
	if (out.size() < need) {
		return makeStatus(CryptoStatus::BufferTooSmall, "digest buffer too small");
	}
	if (mbedtls_md_finish(&ctx, out.data()) != 0) {
		return makeStatus(CryptoStatus::InternalError, "md finish failed");
	}
	started = false;
	return makeStatus(CryptoStatus::Ok);
}

HmacCtx::HmacCtx() {
	mbedtls_md_init(&ctx);
}

HmacCtx::~HmacCtx() {
	mbedtls_md_free(&ctx);
}

CryptoStatusDetail HmacCtx::begin(ShaVariant variant, CryptoSpan<const uint8_t> key) {
	// Reset any prior digest/HMAC allocation so repeated begin() calls do not leak.
	mbedtls_md_free(&ctx);
	mbedtls_md_init(&ctx);
	started = false;
	info = nullptr;

	info = mdInfoForVariant(variant);
	if (!info || key.empty()) {
		return makeStatus(CryptoStatus::InvalidInput, "invalid hmac params");
	}
	if (mbedtls_md_setup(&ctx, info, 1) != 0) {
		return makeStatus(CryptoStatus::InternalError, "md setup failed");
	}
	if (mbedtls_md_hmac_starts(&ctx, key.data(), key.size()) != 0) {
		return makeStatus(CryptoStatus::InternalError, "hmac start failed");
	}
	started = true;
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail HmacCtx::update(CryptoSpan<const uint8_t> data) {
	if (!started) {
		return makeStatus(CryptoStatus::InvalidInput, "hmac not started");
	}
	if (data.empty()) {
		return makeStatus(CryptoStatus::Ok);
	}
	if (mbedtls_md_hmac_update(&ctx, data.data(), data.size()) != 0) {
		return makeStatus(CryptoStatus::InternalError, "hmac update failed");
	}
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail HmacCtx::finish(CryptoSpan<uint8_t> out) {
	if (!started || !info) {
		return makeStatus(CryptoStatus::InvalidInput, "hmac not started");
	}
	size_t need = mbedtls_md_get_size(info);
	if (out.size() < need) {
		return makeStatus(CryptoStatus::BufferTooSmall, "digest buffer too small");
	}
	if (mbedtls_md_hmac_finish(&ctx, out.data()) != 0) {
		return makeStatus(CryptoStatus::InternalError, "hmac finish failed");
	}
	started = false;
	return makeStatus(CryptoStatus::Ok);
}

bool hmacSha256(
    const std::string &key, const uint8_t *data, size_t length, std::vector<uint8_t> &out
) {
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!info) {
		return false;
	}
	out.assign(mbedtls_md_get_size(info), 0);
	mbedtls_md_context_t ctx;
	mbedtls_md_init(&ctx);
	int ret = mbedtls_md_setup(&ctx, info, 1);
	if (ret == 0) {
		ret = mbedtls_md_hmac_starts(
		    &ctx,
		    reinterpret_cast<const unsigned char *>(key.data()),
		    key.size()
		);
	}
	if (ret == 0) {
		ret = mbedtls_md_hmac_update(&ctx, data, length);
	}
	if (ret == 0) {
		ret = mbedtls_md_hmac_finish(&ctx, out.data());
	}
	mbedtls_md_free(&ctx);
	if (ret != 0) {
		out.clear();
		return false;
	}
	return true;
}

bool computeHash(
    ShaVariant variant, const uint8_t *data, size_t length, std::vector<uint8_t> &hash
) {
	hash.assign(digestLength(variant), 0);
	if (hash.empty()) {
		return false;
	}
	static const uint8_t ZERO_BYTE = 0;
	const uint8_t *buffer = (!data && length == 0) ? &ZERO_BYTE : data;
	if (softwareSha(variant, buffer, length, hash.data())) {
		return true;
	}
	return false;
}

int pbkdf2Sha256(
    const unsigned char *password,
    size_t passwordLength,
    const uint8_t *salt,
    size_t saltLength,
    uint32_t iterations,
    uint8_t *output,
    size_t outputLength
) {
#if ESPCRYPTO_MBEDTLS_V3
	return mbedtls_pkcs5_pbkdf2_hmac_ext(
	    MBEDTLS_MD_SHA256,
	    password,
	    passwordLength,
	    salt,
	    saltLength,
	    iterations,
	    outputLength,
	    output
	);
#else
	mbedtls_md_context_t ctx;
	mbedtls_md_init(&ctx);
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!info) {
		mbedtls_md_free(&ctx);
		return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
	}
	int ret = mbedtls_md_setup(&ctx, info, 1);
	if (ret == 0) {
		ret = mbedtls_pkcs5_pbkdf2_hmac(
		    &ctx,
		    password,
		    passwordLength,
		    salt,
		    saltLength,
		    iterations,
		    outputLength,
		    output
		);
	}
	mbedtls_md_free(&ctx);
	return ret;
#endif
}

bool parsePasswordHash(
    const std::string &encoded,
    uint8_t &cost,
    std::vector<uint8_t> &salt,
    std::vector<uint8_t> &hash
) {
	std::vector<std::string> parts;
	size_t start = 0;
	while (start <= encoded.size()) {
		size_t pos = encoded.find('$', start);
		if (pos == std::string::npos) {
			parts.push_back(encoded.substr(start));
			break;
		}
		parts.push_back(encoded.substr(start, pos - start));
		start = pos + 1;
	}
	if (parts.size() != 6 || parts[1] != "esphash" || parts[2] != "v1") {
		return false;
	}
	const std::string &costPart = parts[3];
	if (costPart.empty()) {
		return false;
	}
	uint32_t parsedCost = 0;
	for (char ch : costPart) {
		if (ch < '0' || ch > '9') {
			return false;
		}
		parsedCost = parsedCost * 10u + static_cast<uint32_t>(ch - '0');
		if (parsedCost > 31u) {
			return false;
		}
	}
	cost = static_cast<uint8_t>(parsedCost);
	if (!base64Decode(parts[4], Base64Alphabet::Standard, salt)) {
		return false;
	}
	if (!base64Decode(parts[5], Base64Alphabet::Standard, hash)) {
		return false;
	}
	return true;
}

CryptoResult<std::vector<uint8_t>>
ESPCrypto::shaResult(CryptoSpan<const uint8_t> data, const ShaOptions &options) {
	CryptoResult<std::vector<uint8_t>> result;
	if (!data.data() && data.size() > 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "null data");
		return result;
	}
	result.value.assign(digestLength(options.variant), 0);
	if (result.value.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "unknown sha variant");
		return result;
	}
	static const uint8_t ZERO_BYTE = 0;
	const uint8_t *buffer = data.size() == 0 ? &ZERO_BYTE : data.data();
	size_t length = data.size();
#if ESPCRYPTO_SHA_ACCEL
	bool hashed = false;
	if (options.preferHardware) {
		hashed = tryHardwareSha(options.variant, buffer, length, result.value.data());
	}
	if (!hashed) {
		hashed = softwareSha(options.variant, buffer, length, result.value.data());
	}
#else
	bool hashed = softwareSha(options.variant, buffer, length, result.value.data());
#endif
	if (!hashed) {
		secureZero(result.value.data(), result.value.size());
		result.value.clear();
		result.status = makeStatus(CryptoStatus::InternalError, "sha failed");
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<void>
ESPCrypto::sha(CryptoSpan<const uint8_t> data, CryptoSpan<uint8_t> out, const ShaOptions &options) {
	CryptoResult<void> result;
	size_t needed = digestLength(options.variant);
	if (needed == 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "unknown sha variant");
		return result;
	}
	if (out.size() < needed) {
		result.status = makeStatus(CryptoStatus::BufferTooSmall, "digest buffer too small");
		return result;
	}
	auto hashed = shaResult(data, options);
	if (!hashed.ok()) {
		result.status = hashed.status;
		return result;
	}
	memcpy(out.data(), hashed.value.data(), needed);
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

std::vector<uint8_t> ESPCrypto::sha(const uint8_t *data, size_t length, const ShaOptions &options) {
	auto result = shaResult(CryptoSpan<const uint8_t>(data, length), options);
	return result.ok() ? result.value : std::vector<uint8_t>();
}

std::vector<uint8_t> ESPCrypto::sha(const std::vector<uint8_t> &data, const ShaOptions &options) {
	return sha(data.data(), data.size(), options);
}

String ESPCrypto::shaHex(const uint8_t *data, size_t length, const ShaOptions &options) {
	auto digest = sha(data, length, options);
	if (digest.empty()) {
		return String();
	}
	static const char *HEX_DIGITS = "0123456789abcdef";
	std::string hex;
	hex.reserve(digest.size() * 2);
	for (uint8_t b : digest) {
		hex.push_back(HEX_DIGITS[(b >> 4) & 0x0F]);
		hex.push_back(HEX_DIGITS[b & 0x0F]);
	}
	return String(hex.c_str());
}

String ESPCrypto::shaHex(const String &text, const ShaOptions &options) {
	return shaHex(reinterpret_cast<const uint8_t *>(text.c_str()), text.length(), options);
}

String ESPCrypto::hashString(const String &input, const PasswordHashOptions &options) {
	auto result = hashStringResult(input, options);
	return result.ok() ? result.value : String();
}

bool ESPCrypto::verifyString(const String &input, const String &encoded) {
	auto result = verifyStringResult(input, encoded);
	return result.ok();
}

CryptoResult<String>
ESPCrypto::hashStringResult(const String &input, const PasswordHashOptions &options) {
	CryptoResult<String> result;
	if (input.length() == 0 || options.saltBytes == 0 || options.outputBytes == 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing password or params");
		return result;
	}
	std::vector<uint8_t> salt(options.saltBytes, 0);
	fillRandom(salt.data(), salt.size());
	uint8_t cost = std::min<uint8_t>(options.cost, 31);
	uint32_t iterations = 1u << cost;
	markRuntimeInitialized();
	const CryptoPolicy &cryptoPolicy = mutablePolicy();
	if (!cryptoPolicy.allowLegacy && iterations < cryptoPolicy.minPbkdf2Iterations) {
		uint8_t adjustedCost = cost;
		while ((1u << adjustedCost) < cryptoPolicy.minPbkdf2Iterations && adjustedCost < 31) {
			adjustedCost++;
		}
		cost = adjustedCost;
		iterations = 1u << cost;
	}
	auto derived = pbkdf2(input, CryptoSpan<const uint8_t>(salt), iterations, options.outputBytes);
	if (!derived.ok()) {
		result.status = derived.status;
		return result;
	}
	std::string saltB64 = base64Encode(salt.data(), salt.size(), Base64Alphabet::Standard);
	std::string hashB64 =
	    base64Encode(derived.value.data(), derived.value.size(), Base64Alphabet::Standard);
	secureZero(derived.value.data(), derived.value.size());
	if (saltB64.empty() || hashB64.empty()) {
		result.status = makeStatus(CryptoStatus::InternalError, "base64 encode failed");
		return result;
	}
	std::string encoded = "$esphash$v1$" + std::to_string(cost) + "$" + saltB64 + "$" + hashB64;
	result.value = String(encoded.c_str());
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<void> ESPCrypto::verifyStringResult(const String &input, const String &encoded) {
	CryptoResult<void> result;
	if (input.length() == 0 || encoded.length() == 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing password or encoded hash");
		return result;
	}
	uint8_t cost = 0;
	std::vector<uint8_t> salt;
	std::vector<uint8_t> hash;
	std::string encodedStd(encoded.c_str(), encoded.length());
	if (!parsePasswordHash(encodedStd, cost, salt, hash)) {
		result.status = makeStatus(CryptoStatus::DecodeError, "invalid esphash envelope");
		return result;
	}
	if (salt.empty() || hash.empty()) {
		result.status = makeStatus(CryptoStatus::DecodeError, "invalid esphash parts");
		return result;
	}
	if (cost > 31) {
		result.status = makeStatus(CryptoStatus::DecodeError, "invalid esphash envelope");
		return result;
	}
	uint32_t iterations = 1u << cost;
	markRuntimeInitialized();
	const CryptoPolicy &cryptoPolicy = mutablePolicy();
	if (!cryptoPolicy.allowLegacy && iterations < cryptoPolicy.minPbkdf2Iterations) {
		result.status = makeStatus(CryptoStatus::PolicyViolation, "pbkdf2 iterations below policy");
		return result;
	}
	auto derived = pbkdf2(input, CryptoSpan<const uint8_t>(salt), iterations, hash.size());
	if (!derived.ok()) {
		result.status = derived.status;
		return result;
	}
	bool match = constantTimeEquals(
	    CryptoSpan<const uint8_t>(hash),
	    CryptoSpan<const uint8_t>(derived.value)
	);
	secureZero(derived.value.data(), derived.value.size());
	result.status = match ? makeStatus(CryptoStatus::Ok)
	                      : makeStatus(CryptoStatus::VerifyFailed, "hash mismatch");
	return result;
}

CryptoResult<std::vector<uint8_t>>
ESPCrypto::hmac(ShaVariant variant, CryptoSpan<const uint8_t> key, CryptoSpan<const uint8_t> data) {
	CryptoResult<std::vector<uint8_t>> result;
	const mbedtls_md_info_t *info = mdInfoForVariant(variant);
	if (!info) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "invalid sha variant");
		return result;
	}
	result.value.assign(mbedtls_md_get_size(info), 0);
	mbedtls_md_context_t ctx;
	mbedtls_md_init(&ctx);
	int ret = mbedtls_md_setup(&ctx, info, 1);
	if (ret == 0) {
		ret = mbedtls_md_hmac_starts(
		    &ctx,
		    reinterpret_cast<const unsigned char *>(key.data()),
		    key.size()
		);
	}
	if (ret == 0) {
		ret = mbedtls_md_hmac_update(&ctx, data.data(), data.size());
	}
	if (ret == 0) {
		ret = mbedtls_md_hmac_finish(&ctx, result.value.data());
	}
	mbedtls_md_free(&ctx);
	if (ret != 0) {
		secureZero(result.value.data(), result.value.size());
		result.value.clear();
		result.status = makeStatus(CryptoStatus::InternalError, "hmac failed");
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::hkdf(
    ShaVariant variant,
    CryptoSpan<const uint8_t> salt,
    CryptoSpan<const uint8_t> ikm,
    CryptoSpan<const uint8_t> info,
    size_t length
) {
	CryptoResult<std::vector<uint8_t>> result;
	if (length == 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "length missing");
		return result;
	}
	const size_t hashLen = digestLength(variant);
	if (hashLen == 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "invalid sha variant");
		return result;
	}
	size_t blocks = (length + hashLen - 1) / hashLen;
	if (blocks > 255) {
		result.status = makeStatus(CryptoStatus::BufferTooSmall, "length too large");
		return result;
	}
	std::vector<uint8_t> actualSalt;
	if (salt.empty()) {
		actualSalt.assign(hashLen, 0);
	} else {
		actualSalt.assign(salt.data(), salt.data() + salt.size());
	}
	auto prk = hmac(variant, CryptoSpan<const uint8_t>(actualSalt), ikm);
	secureZero(actualSalt.data(), actualSalt.size());
	if (!prk.ok()) {
		result.status = prk.status;
		return result;
	}
	result.value.reserve(length);
	std::vector<uint8_t> previous;
	for (size_t i = 0; i < blocks; ++i) {
		std::vector<uint8_t> blockInput;
		blockInput.insert(blockInput.end(), previous.begin(), previous.end());
		if (!info.empty()) {
			blockInput.insert(blockInput.end(), info.data(), info.data() + info.size());
		}
		blockInput.push_back(static_cast<uint8_t>(i + 1));
		auto block = hmac(
		    variant,
		    CryptoSpan<const uint8_t>(prk.value),
		    CryptoSpan<const uint8_t>(blockInput)
		);
		secureZero(blockInput.data(), blockInput.size());
		if (!block.ok()) {
			secureZero(prk.value.data(), prk.value.size());
			result.status = block.status;
			return result;
		}
		size_t take = std::min(hashLen, length - result.value.size());
		result.value.insert(result.value.end(), block.value.begin(), block.value.begin() + take);
		previous = std::move(block.value);
	}
	secureZero(prk.value.data(), prk.value.size());
	secureZero(previous.data(), previous.size());
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::pbkdf2(
    const String &password, CryptoSpan<const uint8_t> salt, uint32_t iterations, size_t outputLength
) {
	CryptoResult<std::vector<uint8_t>> result;
	if (password.length() == 0 || salt.empty() || outputLength == 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing password/salt/len");
		return result;
	}
	markRuntimeInitialized();
	const CryptoPolicy &cryptoPolicy = mutablePolicy();
	if (!cryptoPolicy.allowLegacy && iterations < cryptoPolicy.minPbkdf2Iterations) {
		result.status = makeStatus(CryptoStatus::PolicyViolation, "iterations below policy");
		return result;
	}
	result.value.assign(outputLength, 0);
	int ret = pbkdf2Sha256(
	    reinterpret_cast<const unsigned char *>(password.c_str()),
	    password.length(),
	    salt.data(),
	    salt.size(),
	    iterations,
	    result.value.data(),
	    result.value.size()
	);
	if (ret != 0) {
		secureZero(result.value.data(), result.value.size());
		result.value.clear();
		result.status = makeStatus(CryptoStatus::InternalError, "pbkdf2 failed");
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}
