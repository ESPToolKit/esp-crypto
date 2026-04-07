#include "internal/crypto_internal.h"

std::string handleKeyString(const KeyHandle &handle) {
	std::string alias(handle.alias.c_str(), handle.alias.length());
	if (alias.empty()) {
		return std::string();
	}
	return alias + ":" + std::to_string(handle.version);
}

bool ensureNvsReady(const String &partition) {
#if defined(ESP_PLATFORM)
	GlobalRuntimeState &state = runtimeState();
	auto it = state.nvsInitMap.find(partition.c_str());
	if (it != state.nvsInitMap.end() && it->second) {
		markRuntimeInitialized();
		return true;
	}
	esp_err_t err = nvs_flash_init_partition(partition.c_str());
	if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		nvs_flash_erase_partition(partition.c_str());
		err = nvs_flash_init_partition(partition.c_str());
	}
	bool ok = (err == ESP_OK);
	state.nvsInitMap[partition.c_str()] = ok;
	if (ok) {
		markRuntimeInitialized();
	}
	return ok;
#else
	(void)partition;
	return false;
#endif
}

uint64_t
loadCounterFromNvs(const String &ns, const String &partition, const std::string &key, bool &found) {
	found = false;
	uint64_t value = 0;
#if defined(ESP_PLATFORM)
	if (!ensureNvsReady(partition)) {
		return value;
	}
	nvs_handle_t nvs;
	if (nvs_open_from_partition(partition.c_str(), ns.c_str(), NVS_READONLY, &nvs) != ESP_OK) {
		return value;
	}
	size_t size = sizeof(uint64_t);
	if (nvs_get_blob(nvs, key.c_str(), &value, &size) == ESP_OK && size == sizeof(uint64_t)) {
		found = true;
	}
	nvs_close(nvs);
#else
	(void)ns;
	(void)partition;
	(void)key;
#endif
	return value;
}

void storeCounterToNvs(
    const String &ns, const String &partition, const std::string &key, uint64_t value
) {
#if defined(ESP_PLATFORM)
	if (!ensureNvsReady(partition)) {
		return;
	}
	nvs_handle_t nvs;
	if (nvs_open_from_partition(partition.c_str(), ns.c_str(), NVS_READWRITE, &nvs) != ESP_OK) {
		return;
	}
	nvs_set_blob(nvs, key.c_str(), &value, sizeof(value));
	nvs_commit(nvs);
	nvs_close(nvs);
#else
	(void)ns;
	(void)partition;
	(void)key;
	(void)value;
#endif
}

CryptoResult<std::vector<uint8_t>> MemoryKeyStore::load(const KeyHandle &handle) {
	CryptoResult<std::vector<uint8_t>> result;
	std::string key = handleKeyString(handle);
	if (key.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "alias missing");
		return result;
	}
	auto it = storage.find(key);
	if (it == storage.end()) {
		result.status = makeStatus(CryptoStatus::DecodeError, "key not found");
		return result;
	}
	result.value = it->second;
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoStatusDetail MemoryKeyStore::store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) {
	std::string k = handleKeyString(handle);
	if (k.empty() || key.empty()) {
		return makeStatus(CryptoStatus::InvalidInput, "alias/key missing");
	}
	storage[k] = std::vector<uint8_t>(key.data(), key.data() + key.size());
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail MemoryKeyStore::remove(const KeyHandle &handle) {
	std::string k = handleKeyString(handle);
	if (k.empty()) {
		return makeStatus(CryptoStatus::InvalidInput, "alias missing");
	}
	storage.erase(k);
	return makeStatus(CryptoStatus::Ok);
}

NvsKeyStore::NvsKeyStore(String ns, String partition)
    : ns(std::move(ns)), partition(std::move(partition)) {
}

CryptoStatusDetail NvsKeyStore::ensureInit() const {
#if defined(ESP_PLATFORM)
	if (!ensureNvsReady(partition)) {
		return makeStatus(CryptoStatus::InternalError, "nvs init failed");
	}
	return makeStatus(CryptoStatus::Ok);
#else
	(void)partition;
	return makeStatus(CryptoStatus::Unsupported, "nvs unavailable");
#endif
}

String NvsKeyStore::makeKeyName(const KeyHandle &handle) const {
	return String(handleKeyString(handle).c_str());
}

CryptoResult<std::vector<uint8_t>> NvsKeyStore::load(const KeyHandle &handle) {
	CryptoResult<std::vector<uint8_t>> result;
#if defined(ESP_PLATFORM)
	auto initStatus = ensureInit();
	if (!initStatus.ok()) {
		result.status = initStatus;
		return result;
	}
	std::string key = handleKeyString(handle);
	if (key.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "alias missing");
		return result;
	}
	nvs_handle_t nvs;
	if (nvs_open_from_partition(partition.c_str(), ns.c_str(), NVS_READONLY, &nvs) != ESP_OK) {
		result.status = makeStatus(CryptoStatus::DecodeError, "nvs open failed");
		return result;
	}
	size_t size = 0;
	esp_err_t err = nvs_get_blob(nvs, key.c_str(), nullptr, &size);
	if (err != ESP_OK) {
		nvs_close(nvs);
		result.status = makeStatus(CryptoStatus::DecodeError, "key missing");
		return result;
	}
	result.value.assign(size, 0);
	err = nvs_get_blob(nvs, key.c_str(), result.value.data(), &size);
	nvs_close(nvs);
	if (err != ESP_OK) {
		result.value.clear();
		result.status = makeStatus(CryptoStatus::InternalError, "read failed");
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
#else
	(void)handle;
	result.status = makeStatus(CryptoStatus::Unsupported, "nvs unavailable");
	return result;
#endif
}

CryptoStatusDetail NvsKeyStore::store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) {
#if defined(ESP_PLATFORM)
	auto initStatus = ensureInit();
	if (!initStatus.ok()) {
		return initStatus;
	}
	std::string name = handleKeyString(handle);
	if (name.empty() || key.empty()) {
		return makeStatus(CryptoStatus::InvalidInput, "alias/key missing");
	}
	nvs_handle_t nvs;
	if (nvs_open_from_partition(partition.c_str(), ns.c_str(), NVS_READWRITE, &nvs) != ESP_OK) {
		return makeStatus(CryptoStatus::InternalError, "nvs open failed");
	}
	esp_err_t err = nvs_set_blob(nvs, name.c_str(), key.data(), key.size());
	if (err == ESP_OK) {
		err = nvs_commit(nvs);
	}
	nvs_close(nvs);
	if (err != ESP_OK) {
		return makeStatus(CryptoStatus::InternalError, "nvs write failed");
	}
	return makeStatus(CryptoStatus::Ok);
#else
	(void)handle;
	(void)key;
	return makeStatus(CryptoStatus::Unsupported, "nvs unavailable");
#endif
}

CryptoStatusDetail NvsKeyStore::remove(const KeyHandle &handle) {
#if defined(ESP_PLATFORM)
	auto initStatus = ensureInit();
	if (!initStatus.ok()) {
		return initStatus;
	}
	std::string name = handleKeyString(handle);
	if (name.empty()) {
		return makeStatus(CryptoStatus::InvalidInput, "alias missing");
	}
	nvs_handle_t nvs;
	if (nvs_open_from_partition(partition.c_str(), ns.c_str(), NVS_READWRITE, &nvs) != ESP_OK) {
		return makeStatus(CryptoStatus::InternalError, "nvs open failed");
	}
	esp_err_t err = nvs_erase_key(nvs, name.c_str());
	if (err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND) {
		nvs_commit(nvs);
	}
	nvs_close(nvs);
	return makeStatus(CryptoStatus::Ok);
#else
	(void)handle;
	return makeStatus(CryptoStatus::Unsupported, "nvs unavailable");
#endif
}

LittleFsKeyStore::LittleFsKeyStore(String basePath) : basePath(std::move(basePath)) {
}

String LittleFsKeyStore::makePath(const KeyHandle &handle) const {
	std::string name = handleKeyString(handle);
	if (name.empty()) {
		return String();
	}
	if (basePath.endsWith("/")) {
		return basePath + name.c_str();
	}
	return basePath + "/" + name.c_str();
}

CryptoResult<std::vector<uint8_t>> LittleFsKeyStore::load(const KeyHandle &handle) {
	CryptoResult<std::vector<uint8_t>> result;
#if ESPCRYPTO_HAS_LITTLEFS
	String path = makePath(handle);
	if (path.length() == 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "alias missing");
		return result;
	}
	if (!LittleFS.begin()) {
		result.status = makeStatus(CryptoStatus::InternalError, "littlefs mount failed");
		return result;
	}
	File f = LittleFS.open(path, "r");
	if (!f) {
		result.status = makeStatus(CryptoStatus::DecodeError, "key missing");
		return result;
	}
	result.value.assign(f.size(), 0);
	size_t read = f.read(result.value.data(), result.value.size());
	f.close();
	if (read != result.value.size()) {
		result.value.clear();
		result.status = makeStatus(CryptoStatus::InternalError, "short read");
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
#else
	(void)handle;
	result.status = makeStatus(CryptoStatus::Unsupported, "littlefs unavailable");
	return result;
#endif
}

CryptoStatusDetail LittleFsKeyStore::store(const KeyHandle &handle, CryptoSpan<const uint8_t> key) {
#if ESPCRYPTO_HAS_LITTLEFS
	String path = makePath(handle);
	if (path.length() == 0 || key.empty()) {
		return makeStatus(CryptoStatus::InvalidInput, "alias/key missing");
	}
	if (!LittleFS.begin()) {
		return makeStatus(CryptoStatus::InternalError, "littlefs mount failed");
	}
	if (!LittleFS.exists(basePath)) {
		LittleFS.mkdir(basePath);
	}
	File f = LittleFS.open(path, "w");
	if (!f) {
		return makeStatus(CryptoStatus::InternalError, "open failed");
	}
	size_t written = f.write(key.data(), key.size());
	f.close();
	if (written != key.size()) {
		return makeStatus(CryptoStatus::InternalError, "write failed");
	}
	return makeStatus(CryptoStatus::Ok);
#else
	(void)handle;
	(void)key;
	return makeStatus(CryptoStatus::Unsupported, "littlefs unavailable");
#endif
}

CryptoStatusDetail LittleFsKeyStore::remove(const KeyHandle &handle) {
#if ESPCRYPTO_HAS_LITTLEFS
	String path = makePath(handle);
	if (path.length() == 0) {
		return makeStatus(CryptoStatus::InvalidInput, "alias missing");
	}
	if (!LittleFS.begin()) {
		return makeStatus(CryptoStatus::InternalError, "littlefs mount failed");
	}
	LittleFS.remove(path);
	return makeStatus(CryptoStatus::Ok);
#else
	(void)handle;
	return makeStatus(CryptoStatus::Unsupported, "littlefs unavailable");
#endif
}

std::vector<uint8_t> deviceFingerprint() {
#if defined(ESP_PLATFORM)
#if ESPCRYPTO_HAS_ESP_MAC && defined(ESP_MAC_WIFI_STA)
	{
		uint8_t mac[6];
		if (esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK) {
			return std::vector<uint8_t>(mac, mac + sizeof(mac));
		}
	}
#endif
#if ESPCRYPTO_HAS_ESP_EFUSE_MAC
	{
		uint8_t mac[6];
		if (esp_efuse_mac_get_default(mac) == ESP_OK) {
			return std::vector<uint8_t>(mac, mac + sizeof(mac));
		}
	}
#endif
	return std::vector<uint8_t>(8, 0xAA);
#else
	std::vector<uint8_t> fingerprint;
	std::random_device rd;
	for (size_t i = 0; i < 8; ++i) {
		fingerprint.push_back(static_cast<uint8_t>(rd()));
	}
	return fingerprint;
#endif
}

CryptoStatusDetail loadOrCreateSeed(std::vector<uint8_t> &seed, const DeviceKeyOptions &options) {
	if (options.seedBytes == 0) {
		return makeStatus(CryptoStatus::InvalidInput, "seed size missing");
	}
	seed.assign(options.seedBytes, 0);
#if defined(ESP_PLATFORM)
	if (options.persistSeed) {
		NvsKeyStore store(options.nvsNamespace, options.nvsPartition);
		KeyHandle handle;
		handle.alias = "device_seed";
		auto loaded = store.load(handle);
		if (loaded.ok() && loaded.value.size() == options.seedBytes) {
			seed = loaded.value;
			return makeStatus(CryptoStatus::Ok);
		}
		fillRandom(seed.data(), seed.size());
		auto writeStatus = store.store(handle, CryptoSpan<const uint8_t>(seed));
		if (!writeStatus.ok()) {
			return writeStatus;
		}
		return makeStatus(CryptoStatus::Ok);
	}
#endif
	fillRandom(seed.data(), seed.size());
	return makeStatus(CryptoStatus::Ok);
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::deriveDeviceKey(
    const String &purpose,
    CryptoSpan<const uint8_t> contextInfo,
    size_t length,
    const DeviceKeyOptions &options
) {
	CryptoResult<std::vector<uint8_t>> result;
	if (purpose.length() == 0 || length == 0) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "purpose/length missing");
		return result;
	}
	auto deviceSalt = deviceFingerprint();
	std::vector<uint8_t> seed;
	auto seedStatus = loadOrCreateSeed(seed, options);
	if (!seedStatus.ok()) {
		result.status = seedStatus;
		return result;
	}
	std::vector<uint8_t> info;
	info.insert(info.end(), purpose.begin(), purpose.end());
	if (!contextInfo.empty()) {
		info.insert(info.end(), contextInfo.data(), contextInfo.data() + contextInfo.size());
	}
	auto derived = hkdf(
	    ShaVariant::SHA256,
	    CryptoSpan<const uint8_t>(deviceSalt),
	    CryptoSpan<const uint8_t>(seed),
	    CryptoSpan<const uint8_t>(info),
	    length
	);
	secureZero(seed.data(), seed.size());
	secureZero(info.data(), info.size());
	if (!derived.ok()) {
		result.status = derived.status;
		return result;
	}
	result.value = std::move(derived.value);
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<void> ESPCrypto::storeKey(
    KeyStore &store, const KeyHandle &handle, CryptoSpan<const uint8_t> keyMaterial
) {
	CryptoResult<void> result;
	auto status = store.store(handle, keyMaterial);
	result.status = status;
	return result;
}

CryptoResult<CryptoKey>
ESPCrypto::loadKey(KeyStore &store, const KeyHandle &handle, KeyFormat format, KeyKind kind) {
	CryptoResult<CryptoKey> result;
	auto loaded = store.load(handle);
	if (!loaded.ok()) {
		result.status = loaded.status;
		return result;
	}
	switch (format) {
	case KeyFormat::Pem:
		result.value = CryptoKey::fromPem(
		    std::string(reinterpret_cast<const char *>(loaded.value.data()), loaded.value.size()),
		    kind
		);
		break;
	case KeyFormat::Der:
		result.value = CryptoKey::fromDer(loaded.value, kind);
		break;
	case KeyFormat::Raw:
		result.value = CryptoKey::fromRaw(loaded.value, kind);
		break;
	case KeyFormat::Jwk:
		result.status = makeStatus(CryptoStatus::Unsupported, "jwk decode not implemented");
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<void> ESPCrypto::removeKey(KeyStore &store, const KeyHandle &handle) {
	CryptoResult<void> result;
	result.status = store.remove(handle);
	return result;
}
