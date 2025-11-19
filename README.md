# ESPCrypto

ESPCrypto wraps the ESP32 hardware crypto blocks (SHA, AES-GCM/CTR, RSA/ECC) with guardrails, automatic fallbacks, and high-level helpers (JWTs, salted hashes) that work in both ESP-IDF and Arduino builds.

## CI / Release / License
[![CI](https://github.com/ESPToolKit/esp-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/ESPToolKit/esp-crypto/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ESPToolKit/esp-crypto?sort=semver)](https://github.com/ESPToolKit/esp-crypto/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

## Toolchain Compatibility
- GitHub Actions pins the ESP32 Arduino core to `2.0.17` through Espressif's board manager URL so installers don't need to download the 3.x era 500+ MiB RV32/Xtensa bundles. PlatformIO builds continue to use the matching `framework-arduinoespressif32@3.20017.0`, covering `esp32`, `esp32-s3`, and `esp32-c3` boards.
- Runtime code gates the mbedTLS 2.x (ESP-IDF 4.x) and 3.x (ESP-IDF 5.x) API differences so PlatformIO/Arduino builds succeed regardless of which ESP-IDF revision a board package ships.

## Features
- SHA256/384/512 helpers that try the ESP parallel SHA engine first and fall back to mbedTLS when the accelerator (or platform) is unavailable.
- AES-GCM and AES-CTR utilities that automatically select the hardware DMA GCM/AES units when present, with portable mbedTLS backups for host/unit tests.
- RSA/ECC signing + verification helpers (PKCS#1 v1.5 + ECDSA) that power HS256/RS256/ES256 JWT flows or stand-alone signatures.
- Full JWT builder/validator that uses ArduinoJson v7 `JsonDocument`s, fills `iat`/`exp`/`nbf` fields, enforces issuer/audience, and exposes friendly error strings.
- Salted password hashing helper that mimics bcrypt semantics (`$esphash$v1$cost$base64(salt)$base64(hash)`), supports cost factors, and constant-time verification.
- Ready-to-flash example plus Unity tests under `test/test_esp_crypto` for HS256 round-trips and password hashing regressions.

## Examples
The `examples/basic_crypto` sketch shows SHA, AES-GCM, JWT, and password hashing in one go:

```cpp
#include <Arduino.h>
#include <ESPCrypto.h>

void setup() {
    Serial.begin(115200);
    String digest = ESPCrypto::shaHex("esptoolkit");

    std::vector<uint8_t> key(32, 0x01);
    std::vector<uint8_t> iv = {0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7};
    std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> ciphertext, tag;
    ESPCrypto::aesGcmEncrypt(key, iv, plaintext, ciphertext, tag);

    JsonDocument claims;
    claims["role"] = "admin";
    JwtSignOptions sign;
    sign.algorithm = JwtAlgorithm::HS256;
    sign.issuer = "esp32";
    String jwt = ESPCrypto::createJwt(claims, "super-secret", sign);

    JsonDocument decoded;
    String error;
    JwtVerifyOptions verify;
    verify.algorithm = JwtAlgorithm::HS256;
    verify.issuer = "esp32";
    ESPCrypto::verifyJwt(jwt, "super-secret", decoded, error, verify);

    String hashed = ESPCrypto::hashString("hunter2");
    bool ok = ESPCrypto::verifyString("hunter2", hashed);
}

void loop() {}
```

Run `examples/basic_crypto` via PlatformIO/Arduino to see the full output.

## API Highlights
- `std::vector<uint8_t> sha(const uint8_t *data, size_t len, const ShaOptions &opts)` – SHA256/384/512 with optional hardware preference (default on).
- `bool aesGcmEncrypt(...)/aesGcmDecrypt(...)` – 128/192/256-bit AES-GCM with optional AAD and automatic tag handling. `aesCtrCrypt(...)` covers stream-like CTR use cases.
- `bool rsaSign/eccSign` and `rsaVerify/eccVerify` – Wrap mbedTLS PK contexts while still benefiting from ESP hardware when available.
- `String createJwt(const JsonDocument &claims, const String &key, const JwtSignOptions &options)` – Build HS256/RS256/ES256 JWTs with auto `iat`/`exp` fields. `verifyJwt` parses, validates, and returns richer errors.
- `String hashString(const String &input, const PasswordHashOptions &options)` + `bool verifyString(...)` – Salts, PBKDF2-HMAC-SHA256 (cost = `1 << options.cost`), and constant-time comparison.

## JWT Helpers
`JwtSignOptions` lets you set `issuer`, `subject`, `audience`, `expiresInSeconds`, `notBefore`, `issuedAt`, and `keyId`. `JwtVerifyOptions` can enforce issuer/audience matches, require expiration, and accept externally supplied clocks (e.g., SNTP time). Header/payload data stays as ArduinoJson v7 `JsonDocument`s, so you can merge them with `doc.set(...)` or stream them over serial for debugging.

## Password Hashing
`hashString` emits `$esphash$v1$<cost>$<salt>$<hash>` so you can persist passwords without storing secrets. Costs map to `2^cost` PBKDF2 iterations (default 10 ⇒ 1024). `verifyString` accepts any string in that envelope, decodes the salt/hash, replays PBKDF2, and compares in constant time.

## Tests
Hardware exercises run via PlatformIO Unity tests under `test/test_esp_crypto`. Host-side CMake just stubs out tests (ESP-IDF primitives are unavailable when cross-compiling for CI).

## License
MIT — see [LICENSE.md](LICENSE.md).

## ESPToolKit
- Discover other libraries: <https://github.com/orgs/ESPToolKit/repositories>
- Website: <https://esptoolkitfrontend.onrender.com/>
- Support the project: <https://ko-fi.com/esptoolkit>
