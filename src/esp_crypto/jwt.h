#pragma once

#include <ArduinoJson.h>

#include <string>
#include <vector>

#include "asymmetric.h"

enum class JwtAlgorithm { Auto, HS256, RS256, ES256 };

struct JwtSignOptions {
	JwtAlgorithm algorithm = JwtAlgorithm::HS256;
	std::string keyId;
	std::string issuer;
	std::string subject;
	std::string audience;
	uint32_t expiresInSeconds = 3600;
	uint32_t notBefore = 0;
	uint32_t issuedAt = 0;
	uint32_t currentTimestamp = 0;
};

struct JwtVerifyOptions {
	JwtAlgorithm algorithm = JwtAlgorithm::Auto;
	std::string audience;
	std::string issuer;
	uint32_t currentTimestamp = 0;
	bool requireExpiration = true;
	uint32_t leewaySeconds = 0;
	std::string expectedTyp;
	std::vector<std::string> audiences;
	std::vector<std::string> criticalHeadersAllowed;
};

namespace espcrypto::jwt {
CryptoResult<std::string> create(
    const JsonDocument &claims,
    std::string_view key,
    const JwtSignOptions &options = JwtSignOptions{}
);
CryptoResult<void> verify(
    std::string_view token,
    std::string_view key,
    JsonDocument &outClaims,
    const JwtVerifyOptions &options = JwtVerifyOptions{}
);
CryptoResult<void> verifyWithJwks(
    std::string_view token,
    const JsonDocument &jwks,
    JsonDocument &outClaims,
    const JwtVerifyOptions &options = JwtVerifyOptions{}
);
} // namespace espcrypto::jwt
