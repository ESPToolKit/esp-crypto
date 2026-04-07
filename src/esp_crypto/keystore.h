#pragma once

#include <map>
#include <string>

#include "asymmetric.h"

struct KeyHandle {
	std::string alias;
	uint32_t version = 0;
};

class KeyStore {
  public:
	virtual ~KeyStore() = default;
	virtual CryptoResult<std::vector<uint8_t>> load(const KeyHandle &handle) = 0;
	virtual CryptoStatusDetail store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) = 0;
	virtual CryptoStatusDetail remove(const KeyHandle &handle) = 0;
};

class MemoryKeyStore : public KeyStore {
  public:
	CryptoResult<std::vector<uint8_t>> load(const KeyHandle &handle) override;
	CryptoStatusDetail store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) override;
	CryptoStatusDetail remove(const KeyHandle &handle) override;

  private:
	std::map<std::string, std::vector<uint8_t>> storage;
};

class NvsKeyStore : public KeyStore {
  public:
	NvsKeyStore(std::string ns = "espcrypto", std::string partition = "nvs");
	CryptoResult<std::vector<uint8_t>> load(const KeyHandle &handle) override;
	CryptoStatusDetail store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) override;
	CryptoStatusDetail remove(const KeyHandle &handle) override;

  private:
	CryptoStatusDetail ensureInit() const;
	std::string makeKeyName(const KeyHandle &handle) const;

	std::string ns;
	std::string partition;
};

class LittleFsKeyStore : public KeyStore {
  public:
	explicit LittleFsKeyStore(std::string basePath = "/keys");
	CryptoResult<std::vector<uint8_t>> load(const KeyHandle &handle) override;
	CryptoStatusDetail store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) override;
	CryptoStatusDetail remove(const KeyHandle &handle) override;

  private:
	std::string makePath(const KeyHandle &handle) const;

	std::string basePath;
};

namespace espcrypto::keystore {
CryptoResult<void> store(KeyStore &store, const KeyHandle &handle, CryptoSpan<const uint8_t> keyMaterial);
CryptoResult<CryptoKey> load(
    KeyStore &store,
    const KeyHandle &handle,
    KeyFormat format,
    KeyKind kind = KeyKind::Auto
);
CryptoResult<void> remove(KeyStore &store, const KeyHandle &handle);
} // namespace espcrypto::keystore
