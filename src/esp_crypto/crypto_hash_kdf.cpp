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

struct ShaCtx::Impl {
	const mbedtls_md_info_t *info = nullptr;
	mbedtls_md_context_t ctx;
	bool started = false;
};

ShaCtx::ShaCtx() {
	impl = new Impl();
	mbedtls_md_init(&impl->ctx);
}

ShaCtx::~ShaCtx() {
	mbedtls_md_free(&impl->ctx);
	delete impl;
}

CryptoStatusDetail ShaCtx::begin(ShaVariant variant, bool /*preferHardware*/) {
	// Reset any prior digest allocation so repeated begin() calls do not leak.
	mbedtls_md_free(&impl->ctx);
	mbedtls_md_init(&impl->ctx);
	impl->started = false;
	impl->info = nullptr;

	impl->info = mdInfoForVariant(variant);
	if (!impl->info) {
		return makeStatus(CryptoStatus::InvalidInput, "invalid sha variant");
	}
	if (mbedtls_md_setup(&impl->ctx, impl->info, 0) != 0) {
		return makeStatus(CryptoStatus::InternalError, "md setup failed");
	}
	if (mbedtls_md_starts(&impl->ctx) != 0) {
		return makeStatus(CryptoStatus::InternalError, "md start failed");
	}
	impl->started = true;
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail ShaCtx::update(CryptoSpan<const uint8_t> data) {
	if (!impl->started) {
		return makeStatus(CryptoStatus::InvalidInput, "sha not started");
	}
	if (data.empty()) {
		return makeStatus(CryptoStatus::Ok);
	}
	if (mbedtls_md_update(&impl->ctx, data.data(), data.size()) != 0) {
		return makeStatus(CryptoStatus::InternalError, "md update failed");
	}
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail ShaCtx::finish(CryptoSpan<uint8_t> out) {
	if (!impl->started || !impl->info) {
		return makeStatus(CryptoStatus::InvalidInput, "sha not started");
	}
	size_t need = mbedtls_md_get_size(impl->info);
	if (out.size() < need) {
		return makeStatus(CryptoStatus::BufferTooSmall, "digest buffer too small");
	}
	if (mbedtls_md_finish(&impl->ctx, out.data()) != 0) {
		return makeStatus(CryptoStatus::InternalError, "md finish failed");
	}
	impl->started = false;
	return makeStatus(CryptoStatus::Ok);
}

struct HmacCtx::Impl {
	const mbedtls_md_info_t *info = nullptr;
	mbedtls_md_context_t ctx;
	bool started = false;
};

HmacCtx::HmacCtx() {
	impl = new Impl();
	mbedtls_md_init(&impl->ctx);
}

HmacCtx::~HmacCtx() {
	mbedtls_md_free(&impl->ctx);
	delete impl;
}

CryptoStatusDetail HmacCtx::begin(ShaVariant variant, CryptoSpan<const uint8_t> key) {
	// Reset any prior digest/HMAC allocation so repeated begin() calls do not leak.
	mbedtls_md_free(&impl->ctx);
	mbedtls_md_init(&impl->ctx);
	impl->started = false;
	impl->info = nullptr;

	impl->info = mdInfoForVariant(variant);
	if (!impl->info || key.empty()) {
		return makeStatus(CryptoStatus::InvalidInput, "invalid hmac params");
	}
	if (mbedtls_md_setup(&impl->ctx, impl->info, 1) != 0) {
		return makeStatus(CryptoStatus::InternalError, "md setup failed");
	}
	if (mbedtls_md_hmac_starts(&impl->ctx, key.data(), key.size()) != 0) {
		return makeStatus(CryptoStatus::InternalError, "hmac start failed");
	}
	impl->started = true;
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail HmacCtx::update(CryptoSpan<const uint8_t> data) {
	if (!impl->started) {
		return makeStatus(CryptoStatus::InvalidInput, "hmac not started");
	}
	if (data.empty()) {
		return makeStatus(CryptoStatus::Ok);
	}
	if (mbedtls_md_hmac_update(&impl->ctx, data.data(), data.size()) != 0) {
		return makeStatus(CryptoStatus::InternalError, "hmac update failed");
	}
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail HmacCtx::finish(CryptoSpan<uint8_t> out) {
	if (!impl->started || !impl->info) {
		return makeStatus(CryptoStatus::InvalidInput, "hmac not started");
	}
	size_t need = mbedtls_md_get_size(impl->info);
	if (out.size() < need) {
		return makeStatus(CryptoStatus::BufferTooSmall, "digest buffer too small");
	}
	if (mbedtls_md_hmac_finish(&impl->ctx, out.data()) != 0) {
		return makeStatus(CryptoStatus::InternalError, "hmac finish failed");
	}
	impl->started = false;
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

namespace {
struct ParsedPasswordHash {
	uint32_t version = 0;
	uint32_t iterations = 0;
	std::vector<uint8_t> salt;
	std::vector<uint8_t> hash;
};

bool parsePasswordHash(const std::string &encoded, ParsedPasswordHash &parsed) {
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
	if (parts.size() != 6 || parts[1] != "esphash") {
		return false;
	}
	const std::string &versionPart = parts[2];
	const std::string &iterationPart = parts[3];
	if (iterationPart.empty()) {
		return false;
	}
	uint32_t parsedNumber = 0;
	for (char ch : iterationPart) {
		if (ch < '0' || ch > '9') {
			return false;
		}
		parsedNumber = parsedNumber * 10u + static_cast<uint32_t>(ch - '0');
		if (parsedNumber > 1000000000u) {
			return false;
		}
	}
	if (versionPart == "v1") {
		if (parsedNumber > 31u) {
			return false;
		}
		parsed.version = 1;
		parsed.iterations = 1u << parsedNumber;
	} else if (versionPart == "v2") {
		if (parsedNumber == 0) {
			return false;
		}
		parsed.version = 2;
		parsed.iterations = parsedNumber;
	} else {
		return false;
	}
	if (!base64Decode(parts[4], Base64Alphabet::Standard, parsed.salt)) {
		return false;
	}
	if (!base64Decode(parts[5], Base64Alphabet::Standard, parsed.hash)) {
		return false;
	}
	return true;
}

uint32_t passwordIterationFloor(const PasswordHashOptions &options) {
	markRuntimeInitialized();
	const CryptoPolicy &cryptoPolicy = mutablePolicy();
	return std::max<uint32_t>(options.minIterations, cryptoPolicy.minPbkdf2Iterations);
}

CryptoResult<std::vector<uint8_t>> derivePbkdf2(
    std::string_view password,
    CryptoSpan<const uint8_t> salt,
    uint32_t iterations,
    size_t outputLength,
    bool enforcePolicy
) {
	CryptoResult<std::vector<uint8_t>> result;
	if (password.empty() || salt.empty() || outputLength == 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing password/salt/len");
		return result;
	}
	markRuntimeInitialized();
	const CryptoPolicy &cryptoPolicy = mutablePolicy();
	if (enforcePolicy && !cryptoPolicy.allowLegacy && iterations < cryptoPolicy.minPbkdf2Iterations) {
		result.status = makeStatus(CryptoStatus::PolicyViolation, "iterations below policy");
		return result;
	}
	result.value.assign(outputLength, 0);
	int ret = pbkdf2Sha256(
	    reinterpret_cast<const unsigned char *>(password.data()),
	    password.size(),
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

} // namespace

namespace espcrypto::hash {
CryptoResult<std::vector<uint8_t>> sha(CryptoSpan<const uint8_t> data, const ShaOptions &options) {
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

CryptoResult<void> sha(
    CryptoSpan<const uint8_t> data,
    CryptoSpan<uint8_t> out,
    const ShaOptions &options
) {
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
	auto hashed = sha(data, options);
	if (!hashed.ok()) {
		result.status = hashed.status;
		return result;
	}
	memcpy(out.data(), hashed.value.data(), needed);
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

std::string shaHex(CryptoSpan<const uint8_t> data, const ShaOptions &options) {
	auto digest = sha(data, options);
	if (!digest.ok()) {
		return std::string();
	}
	static const char *HEX_DIGITS = "0123456789abcdef";
	std::string hex;
	hex.reserve(digest.value.size() * 2);
	for (uint8_t b : digest.value) {
		hex.push_back(HEX_DIGITS[(b >> 4) & 0x0F]);
		hex.push_back(HEX_DIGITS[b & 0x0F]);
	}
	return hex;
}

std::string shaHex(std::string_view text, const ShaOptions &options) {
	return shaHex(
	    CryptoSpan<const uint8_t>(
	        reinterpret_cast<const uint8_t *>(text.data()),
	        text.size()
	    ),
	    options
	);
}
} // namespace espcrypto::hash

namespace espcrypto::password {
CryptoResult<uint32_t> calibrateIterations(const PasswordHashOptions &options) {
	CryptoResult<uint32_t> result;
	if (options.saltBytes == 0 || options.outputBytes == 0 || options.targetMillis == 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "invalid calibration options");
		return result;
	}
	std::vector<uint8_t> salt(options.saltBytes, 0xA5);
	std::vector<uint8_t> derived(options.outputBytes, 0);
	const std::string probePassword = "espcrypto-calibration";
	uint32_t probeIterations = 4096;
	uint64_t elapsedMs = 0;
	for (;;) {
		uint64_t startedMs = monotonicMillis();
		int ret = pbkdf2Sha256(
		    reinterpret_cast<const unsigned char *>(probePassword.data()),
		    probePassword.size(),
		    salt.data(),
		    salt.size(),
		    probeIterations,
		    derived.data(),
		    derived.size()
		);
		elapsedMs = std::max<uint64_t>(1, monotonicMillis() - startedMs);
		secureZero(derived.data(), derived.size());
		if (ret != 0) {
			result.status = makeStatus(CryptoStatus::InternalError, "pbkdf2 calibration failed");
			return result;
		}
		if (elapsedMs >= 20 || probeIterations >= (1u << 22)) {
			break;
		}
		probeIterations *= 4;
	}
	uint64_t projected =
	    (static_cast<uint64_t>(probeIterations) * static_cast<uint64_t>(options.targetMillis)) /
	    elapsedMs;
	uint32_t floorIterations = passwordIterationFloor(options);
	result.value = static_cast<uint32_t>(std::min<uint64_t>(projected, UINT32_MAX));
	result.value = std::max(result.value, floorIterations);
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<std::string> hash(std::string_view input, const PasswordHashOptions &options) {
	CryptoResult<std::string> result;
	if (input.empty() || options.saltBytes == 0 || options.outputBytes == 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing password or params");
		return result;
	}
	std::vector<uint8_t> salt(options.saltBytes, 0);
	fillRandom(salt.data(), salt.size());
	uint32_t iterations = options.iterations;
	if (iterations == 0) {
		auto calibrated = calibrateIterations(options);
		if (!calibrated.ok()) {
			result.status = calibrated.status;
			return result;
		}
		iterations = calibrated.value;
	}
	iterations = std::max(iterations, passwordIterationFloor(options));
	auto derived =
	    derivePbkdf2(input, CryptoSpan<const uint8_t>(salt), iterations, options.outputBytes, false);
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
	result.value =
	    "$esphash$v2$" + std::to_string(iterations) + "$" + saltB64 + "$" + hashB64;
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<void>
verify(std::string_view input, std::string_view encoded, const PasswordVerifyOptions &options) {
	CryptoResult<void> result;
	if (input.empty() || encoded.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing password or encoded hash");
		return result;
	}
	ParsedPasswordHash parsed;
	if (!parsePasswordHash(std::string(encoded), parsed)) {
		result.status = makeStatus(CryptoStatus::DecodeError, "invalid esphash envelope");
		return result;
	}
	if (parsed.salt.empty() || parsed.hash.empty()) {
		result.status = makeStatus(CryptoStatus::DecodeError, "invalid esphash parts");
		return result;
	}
	uint32_t floorIterations = passwordIterationFloor(PasswordHashOptions{});
	if ((parsed.version == 1 || parsed.iterations < floorIterations) && !options.allowLegacy) {
		result.status = makeStatus(
		    CryptoStatus::PolicyViolation,
		    "password hash requires explicit legacy compatibility"
		);
		return result;
	}
	auto derived = derivePbkdf2(
	    input,
	    CryptoSpan<const uint8_t>(parsed.salt),
	    parsed.iterations,
	    parsed.hash.size(),
	    false
	);
	if (!derived.ok()) {
		result.status = derived.status;
		return result;
	}
	bool match = constantTimeEquals(
	    CryptoSpan<const uint8_t>(parsed.hash),
	    CryptoSpan<const uint8_t>(derived.value)
	);
	secureZero(derived.value.data(), derived.value.size());
	result.status = match ? makeStatus(CryptoStatus::Ok)
	                      : makeStatus(CryptoStatus::VerifyFailed, "hash mismatch");
	return result;
}
} // namespace espcrypto::password

namespace espcrypto::kdf {
CryptoResult<std::vector<uint8_t>>
hmac(ShaVariant variant, CryptoSpan<const uint8_t> key, CryptoSpan<const uint8_t> data) {
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

CryptoResult<std::vector<uint8_t>> hkdf(
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
		auto block =
		    hmac(variant, CryptoSpan<const uint8_t>(prk.value), CryptoSpan<const uint8_t>(blockInput));
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

CryptoResult<std::vector<uint8_t>> pbkdf2(
    std::string_view password,
    CryptoSpan<const uint8_t> salt,
    uint32_t iterations,
    size_t outputLength
) {
	return derivePbkdf2(password, salt, iterations, outputLength, true);
}
} // namespace espcrypto::kdf
