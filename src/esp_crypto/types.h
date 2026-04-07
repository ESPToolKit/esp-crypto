#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#if __has_include(<span>)
#include <span>
#endif

#if defined(__cpp_lib_span)
#define ESPCRYPTO_HAS_STD_SPAN 1
#elif __has_include(<experimental/span>)
#include <experimental/span>
#define ESPCRYPTO_HAS_STD_SPAN 1
#define ESPCRYPTO_USE_EXPERIMENTAL_SPAN 1
#else
#define ESPCRYPTO_HAS_STD_SPAN 0
#endif

enum class CryptoStatus {
	Ok,
	InvalidInput,
	RandomFailure,
	Unsupported,
	PolicyViolation,
	BufferTooSmall,
	VerifyFailed,
	DecodeError,
	JsonError,
	Expired,
	NotYetValid,
	AudienceMismatch,
	IssuerMismatch,
	NonceReuse,
	InternalError
};

const char *toString(CryptoStatus status);

struct CryptoStatusDetail {
	CryptoStatus code = CryptoStatus::Ok;
	std::string message;

	bool ok() const {
		return code == CryptoStatus::Ok;
	}
};

template <typename T> struct CryptoResult {
	CryptoStatusDetail status;
	T value;

	bool ok() const {
		return status.ok();
	}
};

template <> struct CryptoResult<void> {
	CryptoStatusDetail status;

	bool ok() const {
		return status.ok();
	}
};

template <typename T> struct CryptoSpan {
	using element_type = T;
	using pointer = T *;

	CryptoSpan() : ptr(nullptr), len(0) {
	}

	CryptoSpan(pointer data, size_t size) : ptr(data), len(size) {
	}

	CryptoSpan(std::vector<typename std::remove_const<T>::type> &vec)
	    : ptr(vec.data()), len(vec.size()) {
	}

	CryptoSpan(const std::vector<typename std::remove_const<T>::type> &vec)
	    : ptr(vec.data()), len(vec.size()) {
	}

#if defined(__cpp_lib_array_constexpr) || __cpp_lib_array_constexpr >= 201803L
	template <
	    size_t N,
	    typename U = T,
	    typename std::enable_if<!std::is_const<U>::value, int>::type = 0>
	constexpr CryptoSpan(U (&arr)[N]) : ptr(arr), len(N) {
	}

	template <
	    size_t N,
	    typename U = T,
	    typename std::enable_if<std::is_const<U>::value, int>::type = 0>
	constexpr CryptoSpan(const typename std::remove_const<U>::type (&arr)[N]) : ptr(arr), len(N) {
	}
#else
	template <
	    size_t N,
	    typename U = T,
	    typename std::enable_if<!std::is_const<U>::value, int>::type = 0>
	CryptoSpan(U (&arr)[N]) : ptr(arr), len(N) {
	}

	template <
	    size_t N,
	    typename U = T,
	    typename std::enable_if<std::is_const<U>::value, int>::type = 0>
	CryptoSpan(const typename std::remove_const<U>::type (&arr)[N]) : ptr(arr), len(N) {
	}
#endif

#if ESPCRYPTO_HAS_STD_SPAN
#if defined(ESPCRYPTO_USE_EXPERIMENTAL_SPAN)
	CryptoSpan(std::experimental::span<T> span) : ptr(span.data()), len(span.size()) {
	}
#else
	CryptoSpan(std::span<T> span) : ptr(span.data()), len(span.size()) {
	}
#endif
#endif

	pointer data() const {
		return ptr;
	}

	size_t size() const {
		return len;
	}

	bool empty() const {
		return len == 0;
	}

  private:
	pointer ptr;
	size_t len;
};

enum class KeyFormat { Raw, Pem, Der, Jwk };

enum class KeyKind { Auto, Public, Private, Symmetric };

class CryptoKey {
  public:
	CryptoKey();
	CryptoKey(const CryptoKey &other);
	CryptoKey &operator=(const CryptoKey &other);
	CryptoKey(CryptoKey &&other) noexcept;
	CryptoKey &operator=(CryptoKey &&other) noexcept;
	~CryptoKey();

	static CryptoKey fromPem(const std::string &pem, KeyKind kind = KeyKind::Auto);
	static CryptoKey fromDer(const std::vector<uint8_t> &der, KeyKind kind = KeyKind::Auto);
	static CryptoKey fromRaw(const std::vector<uint8_t> &raw, KeyKind kind = KeyKind::Symmetric);

	bool valid() const;
	KeyKind kind() const;
	CryptoSpan<const uint8_t> bytes() const;
	bool parsed() const;
	void clear();
	struct PkCache;
	CryptoStatusDetail ensureParsedPk(bool requirePrivate) const;

	std::vector<uint8_t> data;
	KeyFormat format = KeyFormat::Raw;
	KeyKind keyKind = KeyKind::Auto;
	mutable PkCache *pk = nullptr;
};

class SecureBuffer {
  public:
	SecureBuffer() = default;
	explicit SecureBuffer(size_t bytes);
	SecureBuffer(SecureBuffer &&other) noexcept;
	SecureBuffer &operator=(SecureBuffer &&other) noexcept;
	SecureBuffer(const SecureBuffer &) = delete;
	SecureBuffer &operator=(const SecureBuffer &) = delete;
	~SecureBuffer();

	uint8_t *data() {
		return buffer.data();
	}

	const uint8_t *data() const {
		return buffer.data();
	}

	size_t size() const {
		return buffer.size();
	}

	void resize(size_t bytes);

	std::vector<uint8_t> &raw() {
		return buffer;
	}

	const std::vector<uint8_t> &raw() const {
		return buffer;
	}

  private:
	void wipe();

	std::vector<uint8_t> buffer;
};

class SecureText {
  public:
	SecureText() = default;
	explicit SecureText(std::string value);
	SecureText(SecureText &&other) noexcept;
	SecureText &operator=(SecureText &&other) noexcept;
	SecureText(const SecureText &) = delete;
	SecureText &operator=(const SecureText &) = delete;
	~SecureText();

	const std::string &get() const {
		return value;
	}

	std::string &get() {
		return value;
	}

	const char *c_str() const {
		return value.c_str();
	}

	size_t size() const {
		return value.size();
	}

	bool empty() const {
		return value.empty();
	}

  private:
	void wipe();

	std::string value;
};
