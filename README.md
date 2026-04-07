# ESPCrypto v2

ESPCrypto v2 is an ESP32-focused crypto library with a standard C++ public surface. The core API is ESP-IDF-friendly, avoids `Arduino.h` and Arduino string types, and keeps `JsonDocument` only in the optional JWT/JWKS module.

## CI / Release / License
[![CI](https://github.com/ESPToolKit/esp-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/ESPToolKit/esp-crypto/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ESPToolKit/esp-crypto?sort=semver)](https://github.com/ESPToolKit/esp-crypto/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

## Module Layout
- Core headers: `esp_crypto/types.h`, `esp_crypto/runtime.h`, `esp_crypto/policy.h`, `esp_crypto/hash.h`, `esp_crypto/kdf.h`, `esp_crypto/symmetric.h`, `esp_crypto/asymmetric.h`, `esp_crypto/stream.h`
- Optional headers: `esp_crypto/password.h`, `esp_crypto/jwt.h`, `esp_crypto/keystore.h`, `esp_crypto/device_key.h`
- Umbrella include: `ESPCrypto.h`

## Support Matrix
- Core crypto modules: ESP-IDF and Arduino
- Password module: ESP-IDF and Arduino
- JWT/JWKS module: ESP-IDF and Arduino, with `JsonDocument` from ArduinoJson v7
- NVS/device-key helpers: ESP-IDF and Arduino on ESP32 targets
- LittleFS keystore: Arduino-compatible targets where `LittleFS.h` is available

## Design Notes
- Core APIs use `CryptoResult<T>`, `CryptoSpan`, `std::string`, and `std::string_view`.
- The password module now uses explicit PBKDF2 iterations, emits `$esphash$v2$<iterations>$<salt>$<hash>`, and calibrates to a 250 ms target by default with a 100,000-iteration floor.
- Legacy `$esphash$v1$...` envelopes are rejected by default and only accepted through `PasswordVerifyOptions{.allowLegacy = true}`.
- Ed25519 placeholder headers were removed. Unsupported algorithms are not exposed as public no-op APIs.

## Quick Start

```cpp
#include <esp_crypto/hash.h>
#include <esp_crypto/runtime.h>
#include <esp_crypto/symmetric.h>
#include <string>
#include <vector>

void use_crypto() {
    std::string digest = espcrypto::hash::shaHex("esptoolkit");

    std::vector<uint8_t> key(32, 0x11);
    std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};

    auto encrypted = espcrypto::symmetric::aesGcmEncryptAuto(key, plaintext);
    if (!encrypted.ok()) {
        return;
    }

    auto decrypted = espcrypto::symmetric::aesGcmDecrypt(
        key,
        encrypted.value.iv,
        encrypted.value.ciphertext,
        encrypted.value.tag
    );
    (void)digest;
    (void)decrypted;

    espcrypto::runtime::deinit();
}
```

## API Highlights
- `espcrypto::hash::sha(...)` and `espcrypto::hash::shaHex(...)`
- `espcrypto::kdf::hmac(...)`, `espcrypto::kdf::hkdf(...)`, `espcrypto::kdf::pbkdf2(...)`
- `espcrypto::symmetric::aesGcmEncryptAuto(...)`, `espcrypto::symmetric::aesGcmDecrypt(...)`, `espcrypto::symmetric::aesCtrCrypt(...)`
- `espcrypto::asymmetric::rsaSign(...)`, `espcrypto::asymmetric::rsaVerify(...)`, `espcrypto::asymmetric::eccSign(...)`, `espcrypto::asymmetric::eccVerify(...)`
- `ShaCtx`, `HmacCtx`, `AesCtrStream`, and `AesGcmCtx` for streaming workloads
- `espcrypto::password::hash(...)`, `espcrypto::password::verify(...)`, and `espcrypto::password::calibrateIterations(...)`
- `espcrypto::jwt::create(...)`, `espcrypto::jwt::verify(...)`, and `espcrypto::jwt::verifyWithJwks(...)`
- `espcrypto::keystore::store(...)`, `espcrypto::keystore::load(...)`, and `espcrypto::device::deriveKey(...)`

## Migration From v1
- Replace every Arduino string input/output with `std::string`.
- Replace `ESPCrypto::shaHex(...)` with `espcrypto::hash::shaHex(...)`.
- Replace `ESPCrypto::createJwtResult(...)` / `verifyJwtResult(...)` with `espcrypto::jwt::create(...)` / `espcrypto::jwt::verify(...)`.
- Replace `ESPCrypto::hashString(...)` / `verifyString(...)` with `espcrypto::password::hash(...)` / `espcrypto::password::verify(...)`.
- Replace `ESPCrypto::storeKey(...)`, `loadKey(...)`, and `deriveDeviceKey(...)` with `espcrypto::keystore::store(...)`, `espcrypto::keystore::load(...)`, and `espcrypto::device::deriveKey(...)`.
- Replace `SecureString` with `SecureText`.

## Testing
- Device-side Unity coverage lives in `test/test_esp_crypto`.
- Host-side CMake coverage is limited to portable header/API smoke checks and no longer claims to run functional crypto tests.
- CI also builds the example sketches across multiple ESP32 boards.

## Examples
- `examples/basic_hash_and_aes`
- `examples/jwt_and_password`
- `examples/advanced_primitives`
- `examples/keys_and_streaming`
- `examples/bench_crypto`
- `examples/jwks_rotation`

## Formatting
- `.clang-format` is the C/C++/INO formatting source of truth.
- `.editorconfig` enforces tabs, LF endings, and final newlines.
- Run `bash scripts/format_cpp.sh` for tracked firmware sources.

## License
MIT. See [LICENSE.md](LICENSE.md).
