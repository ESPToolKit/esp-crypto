#pragma once

#include <cstddef>
#include <cstdint>

// Placeholder Ed25519 API. Current toolchain lacks Ed25519 primitives; these functions return failure.
namespace ed25519 {
inline void keypair(uint8_t *, uint8_t *, const uint8_t *) {}
inline void sign(uint8_t *, const uint8_t *, size_t, const uint8_t *) {}
inline int verify(const uint8_t *, const uint8_t *, size_t, const uint8_t *) { return -1; }
}  // namespace ed25519
