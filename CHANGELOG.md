# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- `CryptoKey` + `KeyHandle` abstractions with cached mbedTLS contexts and `MemoryKeyStore`/`NvsKeyStore`/`LittleFsKeyStore` helpers for alias+versioned key rotation.
- `deriveDeviceKey(...)` HKDF helper seeded from a device fingerprint and optional NVS-backed seed so symmetric keys are device-bound instead of hard-coded.
- No-allocation SHA/AES-GCM overloads that write into caller-owned spans (`CryptoSpan`) to reduce heap churn when hashing or encrypting large payloads.
- Streaming contexts (`ShaCtx`, `HmacCtx`, `AesCtrStream`, `AesGcmCtx`) for chunked hashing/HMAC and AES-CTR/GCM flows.
- AES-GCM nonce strategies (random96 default, counter+random, boot-counter+random) with optional NVS-persisted counters via `GcmNonceOptions`.
- JWK/JWKS verification helper (`verifyJwtWithJwks`) with leeway, multi-audience, typ/crit enforcement, and ECDSA DER↔raw helpers for JOSE interop.
- ChaCha20-Poly1305 encrypt/decrypt and X25519 shared-secret helper (capability-gated); XChaCha20-Poly1305 and Ed25519/EdDSA APIs are present but return `Unsupported` until a backend is available.
- New examples: keystore/streaming demo, JWKS rotation, and micro-benchmarks for SHA/AES-GCM.
- Planned curve25519 helpers once ESP-IDF exposes hardware accel hooks.
- `SecureBuffer`/`SecureString` RAII containers that zeroize sensitive material, plus `CryptoStatus`/`CryptoResult` and span-based overloads for SHA, AES, JWT, signing, and password helpers.
- AES-GCM safe helpers that auto-generate nonces, optional nonce-reuse debug guardrails, and capability reporting via `ESPCrypto::caps()`.
- HMAC/HKDF/PBKDF2 APIs (SHA-256/384/512) with policy enforcement for PBKDF2 iteration counts and RSA/ECC key sizes.
- Known-answer tests for SHA-2 variants, AES-GCM (NIST vectors), HKDF, PBKDF2, and AES-GCM auto-IV round-trips to keep regressions visible.
- Examples split into `basic_hash_and_aes`, `jwt_and_password`, and `advanced_primitives` to cover both quick-start and full-surface flows.
- Documented the security posture, threat model, and acceleration/constant-time expectations in the README.

### Fixed
- CI now builds Arduino sketches against the ESP32 `3.3.3` core via Espressif's package index, caching the toolchains to keep PlatformIO/Arduino coverage aligned across the supported boards.
- Addressed Arduino/PlatformIO build failures by avoiding `Print.h`'s `HEX` macro collision, adding `const char*` JWT helpers, and shimming the mbedTLS 2.x/3.x API differences for `mbedtls_pk_parse_key`, `mbedtls_pk_sign`, and PBKDF2.
- Fixed Arduino CLI regressions on ESP32 core 3.x by declaring the DRBG helper before use, wiring AES-GCM span overloads correctly, removing duplicate XChaCha/Ed25519 stubs, and reworking X25519 to the mbedTLS 3-compatible ECDH API.
- Updated ESP32 core 3.3.3 compatibility for JWKS iteration, ASN.1 ECDSA parsing, mbedTLS private field access (ECC/X25519), and the ESP-IDF AES-GCM alt streaming API so Arduino builds succeed again.
- Guarded MAC retrieval and mbedTLS private access headers so Arduino/PlatformIO builds keep working even when board packages omit `esp_efuse_mac.h` or `mbedtls/private_access.h`, and removed the unconditional `esp_efuse_mac.h` include that broke Arduino CLI builds on ESP32 core 3.3.x.
- Removed duplicated ASN.1/JWK helpers and stray namespace closures that slipped into `esp_crypto.cpp`, fixing Arduino CLI/PlatformIO compilation on ESP32 core 3.3.x.
- Aligned AES-GCM alt shims and helper declarations so ESP32-C3 Arduino/PlatformIO builds compile with the 3.3.x core again.
- Updated AES-GCM streaming shims to match the ESP32 Arduino 3.3.x `esp_aes_gcm_*` signatures (starts/update/finish) by routing AAD through `gcm_update_ad` and honoring the output-length parameters, avoiding Arduino CLI build failures on `advanced_primitives`.
- Handled the ESP-IDF 4.x/mbedTLS 2.x AES-GCM alt signatures (6-arg `starts`, 4-arg `update`, 3-arg `finish`) so PlatformIO Arduino builds on ESP32-C3 boards stop failing in `advanced_primitives`.
- Added array-backed `CryptoSpan` constructors so fixed-size buffers in `bench_crypto` build under PlatformIO Arduino.

### Changed
- Password hashing now enforces the minimum PBKDF2 iterations from the algorithm policy (defaults to 1024, unless `allowLegacy` is enabled).
- AES-GCM tag length locked to 16 bytes and policy now requires IVs to be at least 12 bytes unless `allowLegacy` is set.

## [1.0.0] - 2025-11-19

### Added
- Initial release of ESPCrypto with SHA256/384/512 helpers that prefer the on-die accelerator but fall back to mbedTLS.
- AES-GCM/CTR utilities that automatically switch between ESP hardware engines and portable software implementations.
- RSA/ECC signing + verification helpers powering HS256/RS256/ES256 JWT creation/verification via ArduinoJson v7 payloads.
- Password hashing helper with random salts and cost factors similar to bcrypt, plus PlatformIO example/test scaffolding.
