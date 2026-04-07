#include <esp_log.h>

#include <esp_crypto/hash.h>

#include <string>

extern "C" void app_main(void) {
	const std::string digest = espcrypto::hash::shaHex("esp-idf");
	ESP_LOGI("espcrypto", "sha256=%s", digest.c_str());
}
