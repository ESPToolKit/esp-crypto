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
- AES-GCM and AES-CTR utilities with a safe `aesGcmEncryptAuto` that generates a random 12-byte IV, optional nonce-reuse debug guard, and capability introspection via `ESPCrypto::caps()`.
- RSA/ECC signing + verification helpers (PKCS#1 v1.5 + ECDSA) that power HS256/RS256/ES256 JWT flows or stand-alone signatures.
- HMAC/HKDF/PBKDF2 (SHA-256/384/512) building blocks with policy enforcement for PBKDF2 iteration counts; password hashing uses these primitives and constant-time verification.
- Structured `CryptoStatus` + `CryptoResult<T>` with span-friendly overloads to reduce heap churn and keep error handling uniform; `SecureBuffer`/`SecureString` zeroize sensitive data on scope exit.
- Full JWT builder/validator that uses ArduinoJson v7 `JsonDocument`s, fills `iat`/`exp`/`nbf` fields, enforces issuer/audience, and exposes both friendly errors and structured status codes.
- Ready-to-flash example plus Unity tests under `test/test_esp_crypto` with NIST/RFC vectors for SHA, AES-GCM, HKDF, PBKDF2, JWT, and password hashing regressions.

## Examples
- `examples/basic_hash_and_aes` – SHA plus AES-GCM with auto IV/tag handling and structured status.
- `examples/jwt_and_password` – HS256 JWT creation/verification and password hashing/verification.
- `examples/advanced_primitives` – Capability/policy introspection, SecureBuffer/String, HMAC/HKDF/PBKDF2, AES-CTR streaming, and RSA/ECDSA signing flows.

The basic AES example shows SHA and AES-GCM in one go:

```cpp
#include <Arduino.h>
#include <ESPCrypto.h>
#include <vector>

void setup() {
    Serial.begin(115200);
    std::vector<uint8_t> key(32, 0x01);
    std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};

    String digest = ESPCrypto::shaHex("esptoolkit");
    auto gcm = ESPCrypto::aesGcmEncryptAuto(key, plaintext);
    if (gcm.ok()) {
        auto decrypted = ESPCrypto::aesGcmDecrypt(key, gcm.value.iv, gcm.value.ciphertext, gcm.value.tag);
        (void)decrypted;
    }
}

void loop() {}
```

Run `examples/basic_hash_and_aes` via PlatformIO/Arduino to see the full output.

## API Highlights
- `CryptoResult<std::vector<uint8_t>> shaResult(...)` / `shaHex(...)` – SHA256/384/512 with optional hardware preference (default on) and structured status codes.
- `CryptoResult<GcmMessage> aesGcmEncryptAuto(...)` + `aesGcmDecrypt(...)` – 128/192/256-bit AES-GCM with random IVs, optional AAD, 16-byte tags, and policy-enforced IV length; `aesCtrCrypt(...)` covers stream-like CTR use cases.
- `CryptoResult<std::vector<uint8_t>> rsaSign/eccSign` and `rsaVerify/eccVerify` – Wrap mbedTLS PK contexts while enforcing minimum key sizes unless `allowLegacy` is enabled.
- `CryptoResult<String> createJwtResult(...)` / `verifyJwtResult(...)` – Build HS256/RS256/ES256 JWTs with auto `iat`/`exp` fields and get back structured status plus the friendly error string versions.
- `CryptoResult<std::vector<uint8_t>> hmac/hkdf/pbkdf2` and `hashString`/`verifyString` – HMAC/HKDF/PBKDF2 building blocks; password hashes stay in the `$esphash$v1$cost$salt$hash` envelope and compare in constant time.
- `CryptoCaps caps()` and `SecureBuffer`/`SecureString` – Introspect hardware acceleration availability and zeroize sensitive buffers on scope exit.

## JWT Helpers
`JwtSignOptions` lets you set `issuer`, `subject`, `audience`, `expiresInSeconds`, `notBefore`, `issuedAt`, and `keyId`. `JwtVerifyOptions` can enforce issuer/audience matches, require expiration, and accept externally supplied clocks (e.g., SNTP time). Header/payload data stays as ArduinoJson v7 `JsonDocument`s, so you can merge them with `doc.set(...)` or stream them over serial for debugging. Use `createJwt`/`verifyJwt` for friendly strings or `createJwtResult`/`verifyJwtResult` for structured status codes.

## Policy & Guardrails
- `CryptoPolicy` (default: RSA ≥ 2048 bits, PBKDF2 iterations ≥ 1024, GCM IV ≥ 12 bytes) is readable via `ESPCrypto::policy()` and adjustable with `setPolicy(...)`; set `allowLegacy = true` to opt into weaker parameters.
- AES-GCM can enable debug nonce-reuse detection via `ESPCRYPTO_ENABLE_NONCE_GUARD` (tiny LRU cache keyed by IV + key fingerprint).
- `constantTimeEq` and `SecureBuffer`/`SecureString` keep comparisons and cleanup timing-safe.

## Security Posture
- Constant-time coverage: `constantTimeEq` underpins password verification and HS256 JWT checks; other primitives lean on ESP-IDF/mbedTLS implementations and should be treated as best-effort constant-time rather than hardened side-channel countermeasures.
- Hardware acceleration: SHA, AES-CTR, and AES-GCM try the ESP hardware blocks first and fall back to mbedTLS software paths; `ESPCrypto::caps()` reports what is active at runtime. Random bytes come from `esp_fill_random` on-device and from `std::random_device` only for host builds/tests.
- Best-effort hardening: password hashes stay in a structured envelope with policy-enforced PBKDF2 costs, AES-GCM enforces IV length and offers an optional nonce-reuse guard, and sensitive buffers zeroize on scope exit or failure paths.
- Threat model: aimed at network-connected ESP32-class devices where attackers can send arbitrary inputs. It does not attempt to defend against physical capture, power/EM/fault-injection side channels, or secure element/key storage requirements; review your board’s secure boot/flash encryption story separately.

## Password Hashing
`hashString` emits `$esphash$v1$<cost>$<salt>$<hash>` so you can persist passwords without storing secrets. Costs map to `2^cost` PBKDF2 iterations (default 10 ⇒ 1024) and will auto-bump to the policy minimum iteration count unless `allowLegacy` is enabled. `verifyString` accepts any string in that envelope, decodes the salt/hash, replays PBKDF2, and compares in constant time.

## Tests
Hardware exercises run via PlatformIO Unity tests under `test/test_esp_crypto`, including KATs for SHA-2, AES-GCM (with tag checks), HKDF, PBKDF2, JWT HS256 round-trips, and password hashing. Host-side CMake just stubs out tests (ESP-IDF primitives are unavailable when cross-compiling for CI).

## License
MIT — see [LICENSE.md](LICENSE.md).

## ESPToolKit
- Discover other libraries: <https://github.com/orgs/ESPToolKit/repositories>
- Website: <https://www.esptoolkit.hu/>
- Support the project: <https://ko-fi.com/esptoolkit>
- Visit the website: <https://www.esptoolkit.hu/>
