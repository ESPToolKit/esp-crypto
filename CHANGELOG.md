# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Planned curve25519 helpers once ESP-IDF exposes hardware accel hooks.

### Fixed
- CI now pins Arduino CLI to the ESP32 `2.0.17` core via Espressif's package index, preventing GitHub runners from timing out while downloading the 3.x toolchains and keeping PlatformIO/Arduino builds in sync.

## [1.0.0] - 2025-09-16

### Added
- Initial release of ESPCrypto with SHA256/384/512 helpers that prefer the on-die accelerator but fall back to mbedTLS.
- AES-GCM/CTR utilities that automatically switch between ESP hardware engines and portable software implementations.
- RSA/ECC signing + verification helpers powering HS256/RS256/ES256 JWT creation/verification via ArduinoJson v7 payloads.
- Password hashing helper with random salts and cost factors similar to bcrypt, plus PlatformIO example/test scaffolding.
