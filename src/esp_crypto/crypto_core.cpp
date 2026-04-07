#include "internal/crypto_internal.h"

void secureZero(void *data, size_t length) {
	if (!data || length == 0) {
		return;
	}
	volatile uint8_t *p = static_cast<volatile uint8_t *>(data);
	while (length--) {
		*p++ = 0;
	}
#if defined(__GNUC__)
	__asm__ __volatile__("" : : : "memory");
#endif
}

CryptoPolicy &mutablePolicy() {
	static CryptoPolicy policy;
	return policy;
}

CryptoStatusDetail makeStatus(CryptoStatus code, const char *message) {
	CryptoStatusDetail status;
	status.code = code;
	if (message) {
		status.message = message;
	}
	return status;
}


GlobalRuntimeState &runtimeState() {
	static GlobalRuntimeState state;
	return state;
}

void markRuntimeInitialized() {
	runtimeState().initialized.store(true, std::memory_order_release);
}

void resetRuntimeState() {
	GlobalRuntimeState &state = runtimeState();
	state.nvsInitMap.clear();
#if ESPCRYPTO_ENABLE_NONCE_GUARD
	std::fill(state.nonceCache.begin(), state.nonceCache.end(), NonceRecord{});
	state.nonceCursor = 0;
#endif
	state.bootCounter.store(0, std::memory_order_release);
	mutablePolicy() = CryptoPolicy{};
	state.initialized.store(false, std::memory_order_release);
}

uint32_t fingerprintKey(const std::vector<uint8_t> &key) {
	uint32_t hash = 2166136261u;
	for (uint8_t b : key) {
		hash ^= b;
		hash *= 16777619u;
	}
	return hash;
}

bool nonceReused(const std::vector<uint8_t> &key, const std::vector<uint8_t> &iv) {
#if ESPCRYPTO_ENABLE_NONCE_GUARD
	GlobalRuntimeState &state = runtimeState();
	if (iv.empty() || iv.size() > state.nonceCache[0].iv.size()) {
		return false;
	}
	markRuntimeInitialized();
	uint32_t keyHash = fingerprintKey(key);
	if (std::any_of(
	        state.nonceCache.begin(),
	        state.nonceCache.end(),
	        [&](const NonceRecord &record) {
		        return record.used && record.ivLen == iv.size() && record.keyHash == keyHash &&
		               memcmp(record.iv.data(), iv.data(), iv.size()) == 0;
	        }
	    )) {
		return true;
	}
	NonceRecord &slot = state.nonceCache[state.nonceCursor % state.nonceCache.size()];
	slot.used = true;
	slot.keyHash = keyHash;
	slot.ivLen = iv.size();
	memcpy(slot.iv.data(), iv.data(), iv.size());
	state.nonceCursor++;
#else
	(void)key;
	(void)iv;
#endif
	return false;
}

uint32_t currentTimeSeconds(uint32_t overrideValue) {
	if (overrideValue != 0) {
		return overrideValue;
	}
#if defined(ESP_PLATFORM)
	struct timeval tv;
	if (gettimeofday(&tv, nullptr) == 0 && tv.tv_sec > 0) {
		return static_cast<uint32_t>(tv.tv_sec);
	}
	return static_cast<uint32_t>(esp_timer_get_time() / 1000000ULL);
#else
	return static_cast<uint32_t>(time(nullptr));
#endif
}

uint64_t monotonicMillis() {
#if defined(ESP_PLATFORM)
	return static_cast<uint64_t>(esp_timer_get_time() / 1000ULL);
#else
	return static_cast<uint64_t>(
	    std::chrono::duration_cast<std::chrono::milliseconds>(
	        std::chrono::steady_clock::now().time_since_epoch()
	    )
	        .count()
	);
#endif
}

std::string base64Encode(const uint8_t *data, size_t length, Base64Alphabet alphabet) {
	if (length == 0) {
		return std::string();
	}
	size_t encodedLen = 4 * ((length + 2) / 3);
	// mbedtls_base64_encode requires room for encoded output plus a trailing NUL.
	std::string buffer(encodedLen + 1, '\0');
	size_t actualLen = 0;
	if (mbedtls_base64_encode(
	        reinterpret_cast<unsigned char *>(&buffer[0]),
	        buffer.size(),
	        &actualLen,
	        data,
	        length
	    ) != 0) {
		return std::string();
	}
	buffer.resize(actualLen);
	if (alphabet == Base64Alphabet::Url) {
		for (char &c : buffer) {
			if (c == '+') {
				c = '-';
			} else if (c == '/') {
				c = '_';
			}
		}
		while (!buffer.empty() && buffer.back() == '=') {
			buffer.pop_back();
		}
	}
	return buffer;
}

bool base64Decode(const std::string &input, Base64Alphabet alphabet, std::vector<uint8_t> &output) {
	std::string transformed = input;
	if (alphabet == Base64Alphabet::Url) {
		for (char &c : transformed) {
			if (c == '-') {
				c = '+';
			} else if (c == '_') {
				c = '/';
			}
		}
		while (transformed.size() % 4 != 0) {
			transformed.push_back('=');
		}
	}
	size_t required = 0;
	int probe = mbedtls_base64_decode(
	    nullptr,
	    0,
	    &required,
	    reinterpret_cast<const unsigned char *>(transformed.c_str()),
	    transformed.size()
	);
	if (probe != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && probe != 0) {
		return false;
	}
	output.assign(required, 0);
	size_t actual = 0;
	int ret = mbedtls_base64_decode(
	    output.data(),
	    output.size(),
	    &actual,
	    reinterpret_cast<const unsigned char *>(transformed.c_str()),
	    transformed.size()
	);
	if (ret != 0) {
		output.clear();
		return false;
	}
	output.resize(actual);
	return true;
}

void fillRandom(uint8_t *data, size_t length) {
#if defined(ESP_PLATFORM)
	esp_fill_random(data, length);
#else
	std::random_device rd;
	for (size_t i = 0; i < length; ++i) {
		data[i] = static_cast<uint8_t>(rd());
	}
#endif
}

bool constantTimeEquals(CryptoSpan<const uint8_t> a, CryptoSpan<const uint8_t> b) {
	if (a.size() != b.size()) {
		return false;
	}
	uint8_t diff = 0;
	for (size_t i = 0; i < a.size(); ++i) {
		diff |= static_cast<uint8_t>(a.data()[i] ^ b.data()[i]);
	}
	return diff == 0;
}

struct CryptoKey::PkCache {
	mbedtls_pk_context ctx;
	bool hasKey = false;
	bool isPrivate = false;
};

CryptoKey::CryptoKey() = default;

CryptoKey::CryptoKey(const CryptoKey &other)
    : data(other.data), format(other.format), keyKind(other.keyKind), pk(nullptr) {
}

CryptoKey &CryptoKey::operator=(const CryptoKey &other) {
	if (this != &other) {
		clear();
		data = other.data;
		format = other.format;
		keyKind = other.keyKind;
	}
	return *this;
}

CryptoKey::CryptoKey(CryptoKey &&other) noexcept
    : data(std::move(other.data)), format(other.format), keyKind(other.keyKind), pk(other.pk) {
	other.pk = nullptr;
}

CryptoKey &CryptoKey::operator=(CryptoKey &&other) noexcept {
	if (this != &other) {
		clear();
		data = std::move(other.data);
		format = other.format;
		keyKind = other.keyKind;
		pk = other.pk;
		other.pk = nullptr;
	}
	return *this;
}

CryptoKey::~CryptoKey() {
	clear();
}

CryptoKey CryptoKey::fromPem(const std::string &pem, KeyKind kind) {
	CryptoKey key;
	key.data.assign(pem.begin(), pem.end());
	key.data.push_back('\0');
	key.format = KeyFormat::Pem;
	key.keyKind = kind;
	return key;
}

CryptoKey CryptoKey::fromDer(const std::vector<uint8_t> &der, KeyKind kind) {
	CryptoKey key;
	key.data = der;
	key.format = KeyFormat::Der;
	key.keyKind = kind;
	return key;
}

CryptoKey CryptoKey::fromRaw(const std::vector<uint8_t> &raw, KeyKind kind) {
	CryptoKey key;
	key.data = raw;
	key.format = KeyFormat::Raw;
	key.keyKind = kind;
	return key;
}

bool CryptoKey::valid() const {
	return !data.empty();
}

KeyKind CryptoKey::kind() const {
	return keyKind;
}

CryptoSpan<const uint8_t> CryptoKey::bytes() const {
	return CryptoSpan<const uint8_t>(data);
}

bool CryptoKey::parsed() const {
	return pk && pk->hasKey;
}

void CryptoKey::clear() {
	if (pk) {
		mbedtls_pk_free(&pk->ctx);
		delete pk;
		pk = nullptr;
	}
	if (!data.empty()) {
		secureZero(data.data(), data.size());
		data.clear();
	}
	keyKind = KeyKind::Auto;
	format = KeyFormat::Raw;
}

CryptoStatusDetail CryptoKey::ensureParsedPk(bool requirePrivate) const {
	if (format != KeyFormat::Pem && format != KeyFormat::Der) {
		return makeStatus(CryptoStatus::Unsupported, "pk parse requires pem/der");
	}
	if (pk && pk->hasKey) {
		if (requirePrivate && !pk->isPrivate) {
			return makeStatus(CryptoStatus::PolicyViolation, "private key required");
		}
		return makeStatus(CryptoStatus::Ok);
	}
	pk = new PkCache();
	mbedtls_pk_init(&pk->ctx);
	int ret;
	if (format == KeyFormat::Pem) {
		ret = mbedtls_pk_parse_public_key(
		    &pk->ctx,
		    reinterpret_cast<const unsigned char *>(data.data()),
		    data.size()
		);
		if (ret == 0) {
			pk->hasKey = true;
			pk->isPrivate = false;
		}
	}
	mbedtls_ctr_drbg_context ctr;
	mbedtls_entropy_context entropy;
	bool seeded = initDrbg(ctr, entropy);
	if (!pk->hasKey && seeded) {
#if ESPCRYPTO_MBEDTLS_V3
		ret = mbedtls_pk_parse_key(
		    &pk->ctx,
		    reinterpret_cast<const unsigned char *>(data.data()),
		    data.size(),
		    nullptr,
		    0,
		    mbedtls_ctr_drbg_random,
		    &ctr
		);
#else
		ret = mbedtls_pk_parse_key(
		    &pk->ctx,
		    reinterpret_cast<const unsigned char *>(data.data()),
		    data.size(),
		    nullptr,
		    0
		);
#endif
		if (ret == 0) {
			pk->hasKey = true;
			pk->isPrivate = true;
		}
	}
	if (seeded) {
		mbedtls_ctr_drbg_free(&ctr);
		mbedtls_entropy_free(&entropy);
	}
	if (!pk->hasKey) {
		mbedtls_pk_free(&pk->ctx);
		delete pk;
		pk = nullptr;
		return makeStatus(CryptoStatus::DecodeError, "pk parse failed");
	}
	if (requirePrivate && !pk->isPrivate) {
		return makeStatus(CryptoStatus::PolicyViolation, "private key required");
	}
	return makeStatus(CryptoStatus::Ok);
}

bool initDrbg(mbedtls_ctr_drbg_context &ctr, mbedtls_entropy_context &entropy) {
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr);
	static const char *pers = "espcrypto";
	int ret = mbedtls_ctr_drbg_seed(
	    &ctr,
	    mbedtls_entropy_func,
	    &entropy,
	    reinterpret_cast<const unsigned char *>(pers),
	    strlen(pers)
	);
	if (ret != 0) {
		mbedtls_ctr_drbg_free(&ctr);
		mbedtls_entropy_free(&entropy);
		return false;
	}
	return true;
}

const char *toString(CryptoStatus status) {
	switch (status) {
	case CryptoStatus::Ok:
		return "ok";
	case CryptoStatus::InvalidInput:
		return "invalid input";
	case CryptoStatus::RandomFailure:
		return "random source failed";
	case CryptoStatus::Unsupported:
		return "unsupported";
	case CryptoStatus::PolicyViolation:
		return "policy violation";
	case CryptoStatus::BufferTooSmall:
		return "buffer too small";
	case CryptoStatus::VerifyFailed:
		return "verification failed";
	case CryptoStatus::DecodeError:
		return "decode error";
	case CryptoStatus::JsonError:
		return "json error";
	case CryptoStatus::Expired:
		return "token expired";
	case CryptoStatus::NotYetValid:
		return "token not active";
	case CryptoStatus::AudienceMismatch:
		return "audience mismatch";
	case CryptoStatus::IssuerMismatch:
		return "issuer mismatch";
	case CryptoStatus::NonceReuse:
		return "nonce reuse detected";
	case CryptoStatus::InternalError:
	default:
		return "internal error";
	}
}

SecureBuffer::SecureBuffer(size_t bytes) {
	buffer.assign(bytes, 0);
}

SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept : buffer(std::move(other.buffer)) {
	other.wipe();
}

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept {
	if (this != &other) {
		wipe();
		buffer = std::move(other.buffer);
		other.wipe();
	}
	return *this;
}

SecureBuffer::~SecureBuffer() {
	wipe();
}

void SecureBuffer::wipe() {
	if (!buffer.empty()) {
		secureZero(buffer.data(), buffer.size());
		buffer.clear();
	}
}

void SecureBuffer::resize(size_t bytes) {
	wipe();
	buffer.assign(bytes, 0);
}

SecureText::SecureText(std::string value) : value(std::move(value)) {
}

SecureText::SecureText(SecureText &&other) noexcept : value(std::move(other.value)) {
	other.wipe();
}

SecureText &SecureText::operator=(SecureText &&other) noexcept {
	if (this != &other) {
		wipe();
		value = std::move(other.value);
		other.wipe();
	}
	return *this;
}

SecureText::~SecureText() {
	wipe();
}

void SecureText::wipe() {
	if (!value.empty()) {
		secureZero(&value[0], value.size());
		value.clear();
	}
}

namespace espcrypto::policy {
void set(const CryptoPolicy &policy) {
	mutablePolicy() = policy;
	markRuntimeInitialized();
}

CryptoPolicy get() {
	return mutablePolicy();
}
} // namespace espcrypto::policy

namespace espcrypto::runtime {
void deinit() {
	resetRuntimeState();
}

bool isInitialized() {
	return runtimeState().initialized.load(std::memory_order_acquire);
}

CryptoCaps caps() {
	CryptoCaps c;
	c.shaAccel = ESPCRYPTO_SHA_ACCEL;
	c.aesAccel = ESPCRYPTO_AES_ACCEL;
	c.aesGcmAccel = ESPCRYPTO_AES_GCM_ACCEL;
	return c;
}

bool constantTimeEq(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
	return constantTimeEquals(CryptoSpan<const uint8_t>(a), CryptoSpan<const uint8_t>(b));
}

bool constantTimeEq(CryptoSpan<const uint8_t> a, CryptoSpan<const uint8_t> b) {
	return constantTimeEquals(a, b);
}
} // namespace espcrypto::runtime
