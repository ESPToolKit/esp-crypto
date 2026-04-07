#include "internal/crypto_internal.h"

struct AesCtrStream::Impl {
	mbedtls_aes_context ctx;
	unsigned char counter[16] = {0};
	unsigned char streamBlock[16] = {0};
	size_t offset = 0;
	bool started = false;
};

AesCtrStream::AesCtrStream() {
	impl = new Impl();
	mbedtls_aes_init(&impl->ctx);
}

AesCtrStream::~AesCtrStream() {
	mbedtls_aes_free(&impl->ctx);
	mbedtls_platform_zeroize(impl->counter, sizeof(impl->counter));
	mbedtls_platform_zeroize(impl->streamBlock, sizeof(impl->streamBlock));
	delete impl;
}

CryptoStatusDetail
AesCtrStream::begin(const std::vector<uint8_t> &key, CryptoSpan<const uint8_t> nonceCounter) {
	if (!aesKeyValid(key) || nonceCounter.size() != 16) {
		return makeStatus(CryptoStatus::InvalidInput, "invalid key or nonce");
	}
	if (mbedtls_aes_setkey_enc(&impl->ctx, key.data(), key.size() * 8) != 0) {
		return makeStatus(CryptoStatus::InternalError, "aes setkey failed");
	}
	memcpy(impl->counter, nonceCounter.data(), 16);
	impl->offset = 0;
	impl->started = true;
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail
AesCtrStream::update(CryptoSpan<const uint8_t> input, CryptoSpan<uint8_t> output) {
	if (!impl->started) {
		return makeStatus(CryptoStatus::InvalidInput, "ctr not started");
	}
	if (output.size() < input.size()) {
		return makeStatus(CryptoStatus::BufferTooSmall, "output too small");
	}
	if (input.empty()) {
		return makeStatus(CryptoStatus::Ok);
	}
	size_t offCopy = impl->offset;
	int ret = mbedtls_aes_crypt_ctr(
	    &impl->ctx,
	    input.size(),
	    &offCopy,
	    impl->counter,
	    impl->streamBlock,
	    input.data(),
	    output.data()
	);
	impl->offset = offCopy;
	return ret == 0 ? makeStatus(CryptoStatus::Ok)
	                : makeStatus(CryptoStatus::InternalError, "ctr update failed");
}

static int gcmStartsCompat(
    mbedtls_gcm_context &ctx, int mode, CryptoSpan<const uint8_t> iv, CryptoSpan<const uint8_t> aad
) {
#if ESPCRYPTO_MBEDTLS_V3
	int ret = mbedtls_gcm_starts(&ctx, mode, iv.data(), iv.size());
	if (ret != 0 || aad.empty()) {
		return ret;
	}
	return mbedtls_gcm_update_ad(&ctx, aad.data(), aad.size());
#else
	return mbedtls_gcm_starts(
	    &ctx,
	    mode,
	    iv.data(),
	    iv.size(),
	    aad.empty() ? nullptr : aad.data(),
	    aad.size()
	);
#endif
}

static int gcmUpdateCompat(
    mbedtls_gcm_context &ctx, CryptoSpan<const uint8_t> input, CryptoSpan<uint8_t> output
) {
#if ESPCRYPTO_MBEDTLS_V3
	size_t outLen = 0;
	return mbedtls_gcm_update(
	    &ctx,
	    input.data(),
	    input.size(),
	    output.data(),
	    output.size(),
	    &outLen
	);
#else
	return mbedtls_gcm_update(&ctx, input.size(), input.data(), output.data());
#endif
}

static int gcmFinishCompat(mbedtls_gcm_context &ctx, CryptoSpan<uint8_t> tagOut) {
#if ESPCRYPTO_MBEDTLS_V3
	size_t outLen = 0;
	return mbedtls_gcm_finish(&ctx, nullptr, 0, &outLen, tagOut.data(), tagOut.size());
#else
	return mbedtls_gcm_finish(&ctx, tagOut.data(), tagOut.size());
#endif
}

struct AesGcmCtx::Impl {
	bool decrypt = false;
	bool started = false;
	mbedtls_gcm_context ctx;
	std::vector<uint8_t> tagVerify;
};

AesGcmCtx::AesGcmCtx() {
	impl = new Impl();
	mbedtls_gcm_init(&impl->ctx);
}

AesGcmCtx::~AesGcmCtx() {
	mbedtls_gcm_free(&impl->ctx);
	mbedtls_platform_zeroize(impl->tagVerify.data(), impl->tagVerify.size());
	delete impl;
}

CryptoStatusDetail AesGcmCtx::beginCommon(
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> aad,
    bool decryptMode,
    CryptoSpan<const uint8_t> tag
) {
	if (!aesKeyValid(key) || iv.empty()) {
		return makeStatus(CryptoStatus::InvalidInput, "invalid key or iv");
	}
	markRuntimeInitialized();
	const CryptoPolicy &policy = mutablePolicy();
	if (!policy.allowLegacy && iv.size() < policy.minAesGcmIvBytes) {
		return makeStatus(CryptoStatus::PolicyViolation, "iv too short");
	}
	impl->decrypt = decryptMode;
	if (impl->decrypt) {
		impl->tagVerify.assign(tag.data(), tag.data() + tag.size());
	} else {
		impl->tagVerify.clear();
	}
	if (mbedtls_gcm_setkey(&impl->ctx, MBEDTLS_CIPHER_ID_AES, key.data(), key.size() * 8) != 0) {
		return makeStatus(CryptoStatus::InternalError, "gcm setkey failed");
	}
	int mode = impl->decrypt ? MBEDTLS_GCM_DECRYPT : MBEDTLS_GCM_ENCRYPT;
	if (gcmStartsCompat(impl->ctx, mode, iv, aad) != 0) {
		return makeStatus(CryptoStatus::InternalError, "gcm start failed");
	}
	impl->started = true;
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail AesGcmCtx::beginEncrypt(
    const std::vector<uint8_t> &key, CryptoSpan<const uint8_t> iv, CryptoSpan<const uint8_t> aad
) {
	return beginCommon(key, iv, aad, false, CryptoSpan<const uint8_t>());
}

CryptoStatusDetail AesGcmCtx::beginDecrypt(
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> tag
) {
	if (tag.size() != AES_GCM_TAG_BYTES) {
		return makeStatus(CryptoStatus::InvalidInput, "tag size invalid");
	}
	return beginCommon(key, iv, aad, true, tag);
}

CryptoStatusDetail AesGcmCtx::update(CryptoSpan<const uint8_t> input, CryptoSpan<uint8_t> output) {
	if (!impl->started) {
		return makeStatus(CryptoStatus::InvalidInput, "gcm not started");
	}
	if (output.size() < input.size()) {
		return makeStatus(CryptoStatus::BufferTooSmall, "output too small");
	}
	if (input.empty()) {
		return makeStatus(CryptoStatus::Ok);
	}
	if (gcmUpdateCompat(impl->ctx, input, output) != 0) {
		return makeStatus(CryptoStatus::InternalError, "gcm update failed");
	}
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail AesGcmCtx::finish(CryptoSpan<uint8_t> tagOut) {
	if (!impl->started) {
		return makeStatus(CryptoStatus::InvalidInput, "gcm not started");
	}
	impl->started = false;
	if (!impl->decrypt) {
		if (tagOut.size() < AES_GCM_TAG_BYTES) {
			return makeStatus(CryptoStatus::BufferTooSmall, "tag too small");
		}
		if (gcmFinishCompat(impl->ctx, CryptoSpan<uint8_t>(tagOut.data(), AES_GCM_TAG_BYTES)) !=
		    0) {
			return makeStatus(CryptoStatus::InternalError, "gcm finish failed");
		}
		return makeStatus(CryptoStatus::Ok);
	}
	std::vector<uint8_t> computed(AES_GCM_TAG_BYTES, 0);
	if (gcmFinishCompat(impl->ctx, CryptoSpan<uint8_t>(computed)) != 0) {
		return makeStatus(CryptoStatus::InternalError, "gcm finish failed");
	}
	bool ok = constantTimeEquals(
	    CryptoSpan<const uint8_t>(impl->tagVerify),
	    CryptoSpan<const uint8_t>(computed)
	);
	mbedtls_platform_zeroize(computed.data(), computed.size());
	return ok ? makeStatus(CryptoStatus::Ok)
	          : makeStatus(CryptoStatus::VerifyFailed, "gcm tag mismatch");
}

bool aesKeyValid(const std::vector<uint8_t> &key) {
	return key.size() == 16 || key.size() == 24 || key.size() == 32;
}

bool hardwareAesCtr(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonceCounter,
    const std::vector<uint8_t> &input,
    // cppcheck-suppress constParameterReference
    std::vector<uint8_t> &output
) {
#if ESPCRYPTO_AES_ACCEL
	esp_aes_context ctx;
	esp_aes_init(&ctx);
	bool ok = esp_aes_setkey(&ctx, key.data(), key.size() * 8) == 0;
	unsigned char counter[16] = {0};
	unsigned char stream[16] = {0};
	memcpy(counter, nonceCounter.data(), 16);
	size_t off = 0;
	if (ok) {
		ok = esp_aes_crypt_ctr(
		         &ctx,
		         input.size(),
		         &off,
		         counter,
		         stream,
		         input.data(),
		         output.data()
		     ) == 0;
	}
	esp_aes_free(&ctx);
	return ok;
#else
	(void)key;
	(void)nonceCounter;
	(void)input;
	(void)output;
	return false;
#endif
}

bool softwareAesCtr(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonceCounter,
    const std::vector<uint8_t> &input,
    std::vector<uint8_t> &output
) {
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	bool ok = mbedtls_aes_setkey_enc(&ctx, key.data(), key.size() * 8) == 0;
	unsigned char counter[16] = {0};
	memcpy(counter, nonceCounter.data(), 16);
	size_t off = 0;
	if (ok) {
		unsigned char stream[16] = {0};
		ok = mbedtls_aes_crypt_ctr(
		         &ctx,
		         input.size(),
		         &off,
		         counter,
		         stream,
		         input.data(),
		         output.data()
		     ) == 0;
	}
	mbedtls_aes_free(&ctx);
	return ok;
}

bool hardwareGcmCryptSpan(
    int mode,
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> input,
    CryptoSpan<uint8_t> output,
    CryptoSpan<uint8_t> tag
) {
#if ESPCRYPTO_AES_GCM_ACCEL
	esp_gcm_context ctx;
	esp_aes_gcm_init(&ctx);
	bool ok = esp_aes_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(), key.size() * 8) == 0;
	if (ok && mode == MBEDTLS_GCM_ENCRYPT) {
		ok = esp_aes_gcm_crypt_and_tag(
		         &ctx,
		         mode,
		         input.size(),
		         iv.data(),
		         iv.size(),
		         aad.empty() ? nullptr : aad.data(),
		         aad.size(),
		         input.data(),
		         output.data(),
		         tag.size(),
		         tag.data()
		     ) == 0;
	} else if (ok && mode == MBEDTLS_GCM_DECRYPT) {
		ok = esp_aes_gcm_auth_decrypt(
		         &ctx,
		         input.size(),
		         iv.data(),
		         iv.size(),
		         aad.empty() ? nullptr : aad.data(),
		         aad.size(),
		         tag.data(),
		         tag.size(),
		         input.data(),
		         output.data()
		     ) == 0;
	}
	esp_aes_gcm_free(&ctx);
	return ok;
#else
	(void)mode;
	(void)key;
	(void)iv;
	(void)aad;
	(void)input;
	(void)output;
	(void)tag;
	return false;
#endif
}

bool hardwareGcmCrypt(
    int mode,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &input,
    // cppcheck-suppress constParameterReference
    std::vector<uint8_t> &output,
    // cppcheck-suppress constParameterReference
    std::vector<uint8_t> &tag
) {
	return hardwareGcmCryptSpan(
	    mode,
	    key,
	    CryptoSpan<const uint8_t>(iv),
	    CryptoSpan<const uint8_t>(aad),
	    CryptoSpan<const uint8_t>(input),
	    CryptoSpan<uint8_t>(output),
	    CryptoSpan<uint8_t>(tag)
	);
}

bool softwareGcmCrypt(
    int mode,
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &input,
    // cppcheck-suppress constParameterReference
    std::vector<uint8_t> &output,
    // cppcheck-suppress constParameterReference
    std::vector<uint8_t> &tag
) {
	return softwareGcmCrypt(
	    mode,
	    key,
	    CryptoSpan<const uint8_t>(iv),
	    CryptoSpan<const uint8_t>(aad),
	    CryptoSpan<const uint8_t>(input),
	    CryptoSpan<uint8_t>(output),
	    CryptoSpan<uint8_t>(tag)
	);
}

bool softwareGcmCrypt(
    int mode,
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> input,
    CryptoSpan<uint8_t> output,
    CryptoSpan<uint8_t> tag
) {
	mbedtls_gcm_context ctx;
	mbedtls_gcm_init(&ctx);
	bool ok = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(), key.size() * 8) == 0;
	if (ok && mode == MBEDTLS_GCM_ENCRYPT) {
		ok = mbedtls_gcm_crypt_and_tag(
		         &ctx,
		         MBEDTLS_GCM_ENCRYPT,
		         input.size(),
		         iv.data(),
		         iv.size(),
		         aad.empty() ? nullptr : aad.data(),
		         aad.size(),
		         input.data(),
		         output.data(),
		         tag.size(),
		         tag.data()
		     ) == 0;
	} else if (ok && mode == MBEDTLS_GCM_DECRYPT) {
		ok = mbedtls_gcm_auth_decrypt(
		         &ctx,
		         input.size(),
		         iv.data(),
		         iv.size(),
		         aad.empty() ? nullptr : aad.data(),
		         aad.size(),
		         tag.data(),
		         tag.size(),
		         input.data(),
		         output.data()
		     ) == 0;
	}
	mbedtls_gcm_free(&ctx);
	return ok;
}

CryptoStatusDetail aesGcmEncryptSpan(
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> plaintext,
    CryptoSpan<uint8_t> ciphertext,
    CryptoSpan<uint8_t> tag
) {
	if (!aesKeyValid(key) || iv.empty()) {
		return makeStatus(CryptoStatus::InvalidInput, "invalid key or iv");
	}
	markRuntimeInitialized();
	const CryptoPolicy &policy = mutablePolicy();
	if (!policy.allowLegacy && iv.size() < policy.minAesGcmIvBytes) {
		return makeStatus(CryptoStatus::PolicyViolation, "iv too short");
	}
	if (ciphertext.size() < plaintext.size()) {
		return makeStatus(CryptoStatus::BufferTooSmall, "ciphertext buffer too small");
	}
	if (tag.size() < AES_GCM_TAG_BYTES) {
		return makeStatus(CryptoStatus::BufferTooSmall, "tag buffer too small");
	}
#if ESPCRYPTO_ENABLE_NONCE_GUARD
	std::vector<uint8_t> ivCopy(iv.data(), iv.data() + iv.size());
	if (nonceReused(key, ivCopy)) {
		secureZero(ivCopy.data(), ivCopy.size());
		return makeStatus(CryptoStatus::NonceReuse, "iv reuse");
	}
	secureZero(ivCopy.data(), ivCopy.size());
#endif
	CryptoSpan<uint8_t> ctSlice(ciphertext.data(), plaintext.size());
	CryptoSpan<uint8_t> tagSlice(tag.data(), AES_GCM_TAG_BYTES);
#if ESPCRYPTO_AES_GCM_ACCEL
	bool ok = hardwareGcmCryptSpan(MBEDTLS_GCM_ENCRYPT, key, iv, aad, plaintext, ctSlice, tagSlice);
	if (!ok) {
		ok = softwareGcmCrypt(MBEDTLS_GCM_ENCRYPT, key, iv, aad, plaintext, ctSlice, tagSlice);
	}
#else
	bool ok = softwareGcmCrypt(MBEDTLS_GCM_ENCRYPT, key, iv, aad, plaintext, ctSlice, tagSlice);
#endif
	if (!ok) {
		secureZero(ctSlice.data(), ctSlice.size());
		secureZero(tagSlice.data(), tagSlice.size());
		return makeStatus(CryptoStatus::InternalError, "aes gcm encrypt failed");
	}
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail aesGcmDecryptSpan(
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> ciphertext,
    CryptoSpan<const uint8_t> tag,
    CryptoSpan<uint8_t> plaintext
) {
	if (!aesKeyValid(key) || iv.empty() || tag.size() != AES_GCM_TAG_BYTES) {
		return makeStatus(CryptoStatus::InvalidInput, "invalid key/iv/tag");
	}
	markRuntimeInitialized();
	const CryptoPolicy &policy = mutablePolicy();
	if (!policy.allowLegacy && iv.size() < policy.minAesGcmIvBytes) {
		return makeStatus(CryptoStatus::PolicyViolation, "iv too short");
	}
	if (plaintext.size() < ciphertext.size()) {
		return makeStatus(CryptoStatus::BufferTooSmall, "plaintext buffer too small");
	}
	CryptoSpan<uint8_t> ptSlice(plaintext.data(), ciphertext.size());
	std::vector<uint8_t> tagCopy(tag.data(), tag.data() + tag.size());
#if ESPCRYPTO_AES_GCM_ACCEL
	bool ok = hardwareGcmCryptSpan(
	    MBEDTLS_GCM_DECRYPT,
	    key,
	    iv,
	    aad,
	    ciphertext,
	    ptSlice,
	    CryptoSpan<uint8_t>(tagCopy)
	);
	if (!ok) {
		tagCopy.assign(tag.data(), tag.data() + tag.size());
		ok = softwareGcmCrypt(
		    MBEDTLS_GCM_DECRYPT,
		    key,
		    iv,
		    aad,
		    ciphertext,
		    ptSlice,
		    CryptoSpan<uint8_t>(tagCopy)
		);
	}
#else
	bool ok = softwareGcmCrypt(
	    MBEDTLS_GCM_DECRYPT,
	    key,
	    iv,
	    aad,
	    ciphertext,
	    ptSlice,
	    CryptoSpan<uint8_t>(tagCopy)
	);
#endif
	secureZero(tagCopy.data(), tagCopy.size());
	if (!ok) {
		secureZero(ptSlice.data(), ptSlice.size());
		return makeStatus(CryptoStatus::VerifyFailed, "gcm auth failed");
	}
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail aesGcmEncryptInternal(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &plaintext,
    std::vector<uint8_t> &ciphertext,
    std::vector<uint8_t> &tag
) {
	ciphertext.assign(plaintext.size(), 0);
	tag.assign(AES_GCM_TAG_BYTES, 0);
	return aesGcmEncryptSpan(
	    key,
	    CryptoSpan<const uint8_t>(iv),
	    CryptoSpan<const uint8_t>(aad),
	    CryptoSpan<const uint8_t>(plaintext),
	    CryptoSpan<uint8_t>(ciphertext),
	    CryptoSpan<uint8_t>(tag)
	);
}

CryptoStatusDetail aesGcmDecryptInternal(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &aad,
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &tag,
    std::vector<uint8_t> &plaintext
) {
	plaintext.assign(ciphertext.size(), 0);
	return aesGcmDecryptSpan(
	    key,
	    CryptoSpan<const uint8_t>(iv),
	    CryptoSpan<const uint8_t>(aad),
	    CryptoSpan<const uint8_t>(ciphertext),
	    CryptoSpan<const uint8_t>(tag),
	    CryptoSpan<uint8_t>(plaintext)
	);
}

namespace espcrypto::symmetric {
CryptoResult<GcmMessage> aesGcmEncryptAuto(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &plaintext,
    const std::vector<uint8_t> &aad,
    size_t ivLength,
    const GcmNonceOptions &nonceOptions
) {
	CryptoResult<GcmMessage> result;
	markRuntimeInitialized();
	const CryptoPolicy &cryptoPolicy = mutablePolicy();
	if (ivLength == 0) {
		ivLength = cryptoPolicy.minAesGcmIvBytes;
	}
	if (!cryptoPolicy.allowLegacy && ivLength < cryptoPolicy.minAesGcmIvBytes) {
		result.status = makeStatus(CryptoStatus::PolicyViolation, "iv too short");
		return result;
	}
	if (!aesKeyValid(key)) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "invalid key");
		return result;
	}
	result.value.iv.assign(ivLength, 0);
	GlobalRuntimeState &state = runtimeState();
	uint32_t keyHash = fingerprintKey(key);
	state.bootCounter.fetch_add(1, std::memory_order_relaxed);
	switch (nonceOptions.strategy) {
	case GcmNonceStrategy::Random96:
	default:
		fillRandom(result.value.iv.data(), result.value.iv.size());
		break;
	case GcmNonceStrategy::Counter64_Random32: {
		if (ivLength < 12) {
			result.status =
			    makeStatus(CryptoStatus::PolicyViolation, "counter strategy needs >=12 iv bytes");
			return result;
		}
		bool found = false;
		uint64_t counter = loadCounterFromNvs(
		    nonceOptions.nvsNamespace,
		    nonceOptions.nvsPartition,
		    "gcmctr_" + std::to_string(keyHash),
		    found
		);
		if (!found) {
			counter = 1;
		} else {
			counter += 1;
		}
		if (nonceOptions.persistCounter) {
			storeCounterToNvs(
			    nonceOptions.nvsNamespace,
			    nonceOptions.nvsPartition,
			    "gcmctr_" + std::to_string(keyHash),
			    counter
			);
		}
		for (size_t i = 0; i < 8; ++i) {
			result.value.iv[i] = static_cast<uint8_t>((counter >> (56 - 8 * i)) & 0xFF);
		}
		std::vector<uint8_t> tail(ivLength - 8, 0);
		if (!tail.empty()) {
			fillRandom(tail.data(), tail.size());
			memcpy(result.value.iv.data() + 8, tail.data(), tail.size());
		}
		break;
	}
	case GcmNonceStrategy::BootCounter_Random32: {
		if (ivLength < 12) {
			result.status =
			    makeStatus(CryptoStatus::PolicyViolation, "counter strategy needs >=12 iv bytes");
			return result;
		}
		uint64_t counter = state.bootCounter.load(std::memory_order_relaxed);
		for (size_t i = 0; i < 8; ++i) {
			result.value.iv[i] = static_cast<uint8_t>((counter >> (56 - 8 * i)) & 0xFF);
		}
		std::vector<uint8_t> tail(ivLength - 8, 0);
		if (!tail.empty()) {
			fillRandom(tail.data(), tail.size());
			memcpy(result.value.iv.data() + 8, tail.data(), tail.size());
		}
		break;
	}
	}
	result.status = aesGcmEncryptInternal(
	    key,
	    result.value.iv,
	    aad,
	    plaintext,
	    result.value.ciphertext,
	    result.value.tag
	);
	if (!result.ok()) {
		result.value = {};
	}
	return result;
}

CryptoResult<std::vector<uint8_t>> aesGcmDecrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &iv,
    const std::vector<uint8_t> &ciphertext,
    const std::vector<uint8_t> &tag,
    const std::vector<uint8_t> &aad
) {
	CryptoResult<std::vector<uint8_t>> result;
	result.status = aesGcmDecryptInternal(key, iv, aad, ciphertext, tag, result.value);
	if (!result.ok()) {
		result.value.clear();
	}
	return result;
}

CryptoResult<void> aesGcmEncrypt(
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> plaintext,
    CryptoSpan<uint8_t> ciphertextOut,
    CryptoSpan<uint8_t> tagOut,
    CryptoSpan<const uint8_t> aad
) {
	CryptoResult<void> result;
	result.status = aesGcmEncryptSpan(key, iv, aad, plaintext, ciphertextOut, tagOut);
	if (!result.ok()) {
		if (!ciphertextOut.empty()) {
			secureZero(ciphertextOut.data(), std::min(ciphertextOut.size(), plaintext.size()));
		}
		if (!tagOut.empty()) {
			secureZero(
			    tagOut.data(),
			    std::min(tagOut.size(), static_cast<size_t>(AES_GCM_TAG_BYTES))
			);
		}
	}
	return result;
}

CryptoResult<void> aesGcmDecrypt(
    const std::vector<uint8_t> &key,
    CryptoSpan<const uint8_t> iv,
    CryptoSpan<const uint8_t> ciphertext,
    CryptoSpan<const uint8_t> tag,
    CryptoSpan<uint8_t> plaintextOut,
    CryptoSpan<const uint8_t> aad
) {
	CryptoResult<void> result;
	result.status = aesGcmDecryptSpan(key, iv, aad, ciphertext, tag, plaintextOut);
	if (!result.ok()) {
		if (!plaintextOut.empty()) {
			secureZero(plaintextOut.data(), std::min(plaintextOut.size(), ciphertext.size()));
		}
	}
	return result;
}

CryptoResult<std::vector<uint8_t>> aesCtrCrypt(
    const std::vector<uint8_t> &key,
    const std::vector<uint8_t> &nonceCounter,
    const std::vector<uint8_t> &input
) {
	CryptoResult<std::vector<uint8_t>> result;
	if (!aesKeyValid(key) || nonceCounter.size() != 16) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "invalid key or nonce");
		return result;
	}
	result.value.assign(input.size(), 0);
#if ESPCRYPTO_AES_ACCEL
	bool ok = hardwareAesCtr(key, nonceCounter, input, result.value);
	if (!ok) {
		ok = softwareAesCtr(key, nonceCounter, input, result.value);
	}
#else
	bool ok = softwareAesCtr(key, nonceCounter, input, result.value);
#endif
	if (!ok) {
		secureZero(result.value.data(), result.value.size());
		result.value.clear();
		result.status = makeStatus(CryptoStatus::InternalError, "aes ctr failed");
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<std::vector<uint8_t>> chacha20Poly1305Encrypt(
    CryptoSpan<const uint8_t> key,
    CryptoSpan<const uint8_t> nonce,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> plaintext
) {
	CryptoResult<std::vector<uint8_t>> result;
#if defined(MBEDTLS_CHACHAPOLY_C)
	if (key.size() != 32 || nonce.size() < 12) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "key/nonce invalid");
		return result;
	}
	mbedtls_chachapoly_context ctx;
	mbedtls_chachapoly_init(&ctx);
	if (mbedtls_chachapoly_setkey(&ctx, key.data()) != 0) {
		mbedtls_chachapoly_free(&ctx);
		result.status = makeStatus(CryptoStatus::InternalError, "setkey failed");
		return result;
	}
	result.value.assign(plaintext.size() + 16, 0);
	if (mbedtls_chachapoly_encrypt_and_tag(
	        &ctx,
	        plaintext.size(),
	        nonce.data(),
	        aad.data(),
	        aad.size(),
	        plaintext.data(),
	        result.value.data(),
	        result.value.data() + plaintext.size()
	    ) != 0) {
		result.value.clear();
		result.status = makeStatus(CryptoStatus::InternalError, "chacha20poly1305 encrypt failed");
		mbedtls_chachapoly_free(&ctx);
		return result;
	}
	mbedtls_chachapoly_free(&ctx);
	result.status = makeStatus(CryptoStatus::Ok);
#else
	(void)key;
	(void)nonce;
	(void)aad;
	(void)plaintext;
	result.status = makeStatus(CryptoStatus::Unsupported, "chachapoly unavailable");
#endif
	return result;
}

CryptoResult<std::vector<uint8_t>> chacha20Poly1305Decrypt(
    CryptoSpan<const uint8_t> key,
    CryptoSpan<const uint8_t> nonce,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> ciphertextAndTag
) {
	CryptoResult<std::vector<uint8_t>> result;
#if defined(MBEDTLS_CHACHAPOLY_C)
	if (key.size() != 32 || nonce.size() < 12 || ciphertextAndTag.size() < 17) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "input invalid");
		return result;
	}
	size_t cipherLen = ciphertextAndTag.size() - 16;
	const uint8_t *tag = ciphertextAndTag.data() + cipherLen;
	result.value.assign(cipherLen, 0);
	mbedtls_chachapoly_context ctx;
	mbedtls_chachapoly_init(&ctx);
	if (mbedtls_chachapoly_setkey(&ctx, key.data()) != 0) {
		mbedtls_chachapoly_free(&ctx);
		result.status = makeStatus(CryptoStatus::InternalError, "setkey failed");
		return result;
	}
	if (mbedtls_chachapoly_auth_decrypt(
	        &ctx,
	        cipherLen,
	        nonce.data(),
	        aad.data(),
	        aad.size(),
	        tag,
	        ciphertextAndTag.data(),
	        result.value.data()
	    ) != 0) {
		mbedtls_chachapoly_free(&ctx);
		secureZero(result.value.data(), result.value.size());
		result.value.clear();
		result.status = makeStatus(CryptoStatus::VerifyFailed, "auth failed");
		return result;
	}
	mbedtls_chachapoly_free(&ctx);
	result.status = makeStatus(CryptoStatus::Ok);
#else
	(void)key;
	(void)nonce;
	(void)aad;
	(void)ciphertextAndTag;
	result.status = makeStatus(CryptoStatus::Unsupported, "chachapoly unavailable");
#endif
	return result;
}

CryptoResult<std::vector<uint8_t>> xchacha20Poly1305Encrypt(
    CryptoSpan<const uint8_t> key,
    CryptoSpan<const uint8_t> nonce,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> plaintext
) {
	CryptoResult<std::vector<uint8_t>> result;
	(void)key;
	(void)nonce;
	(void)aad;
	(void)plaintext;
	result.status = makeStatus(CryptoStatus::Unsupported, "xchacha20poly1305 unavailable");
	return result;
}

CryptoResult<std::vector<uint8_t>> xchacha20Poly1305Decrypt(
    CryptoSpan<const uint8_t> key,
    CryptoSpan<const uint8_t> nonce,
    CryptoSpan<const uint8_t> aad,
    CryptoSpan<const uint8_t> ciphertextAndTag
) {
	CryptoResult<std::vector<uint8_t>> result;
	(void)key;
	(void)nonce;
	(void)aad;
	(void)ciphertextAndTag;
	result.status = makeStatus(CryptoStatus::Unsupported, "xchacha20poly1305 unavailable");
	return result;
}
} // namespace espcrypto::symmetric
