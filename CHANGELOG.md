# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Planned curve25519 helpers once ESP-IDF exposes hardware accel hooks.
- `SecureBuffer`/`SecureString` RAII containers that zeroize sensitive material, plus `CryptoStatus`/`CryptoResult` and span-based overloads for SHA, AES, JWT, signing, and password helpers.
- AES-GCM safe helpers that auto-generate nonces, optional nonce-reuse debug guardrails, and capability reporting via `ESPCrypto::caps()`.
- HMAC/HKDF/PBKDF2 APIs (SHA-256/384/512) with policy enforcement for PBKDF2 iteration counts and RSA/ECC key sizes.
- Known-answer tests for SHA-2 variants, AES-GCM (NIST vectors), HKDF, PBKDF2, and AES-GCM auto-IV round-trips to keep regressions visible.
- Examples split into `basic_hash_and_aes`, `jwt_and_password`, and `advanced_primitives` to cover both quick-start and full-surface flows.

### Fixed
- CI now pins Arduino CLI to the ESP32 `2.0.17` core via Espressif's package index, preventing GitHub runners from timing out while downloading the 3.x toolchains and keeping PlatformIO/Arduino builds in sync.
- Addressed Arduino/PlatformIO build failures by avoiding `Print.h`'s `HEX` macro collision, adding `const char*` JWT helpers, and shimming the mbedTLS 2.x/3.x API differences for `mbedtls_pk_parse_key`, `mbedtls_pk_sign`, and PBKDF2.

### Changed
- Password hashing now enforces the minimum PBKDF2 iterations from the algorithm policy (defaults to 1024, unless `allowLegacy` is enabled).
- AES-GCM tag length locked to 16 bytes and policy now requires IVs to be at least 12 bytes unless `allowLegacy` is set.

## [1.0.0] - 2025-11-19

### Added
- Initial release of ESPCrypto with SHA256/384/512 helpers that prefer the on-die accelerator but fall back to mbedTLS.
- AES-GCM/CTR utilities that automatically switch between ESP hardware engines and portable software implementations.
- RSA/ECC signing + verification helpers powering HS256/RS256/ES256 JWT creation/verification via ArduinoJson v7 payloads.
- Password hashing helper with random salts and cost factors similar to bcrypt, plus PlatformIO example/test scaffolding.
