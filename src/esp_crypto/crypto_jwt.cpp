#include "internal/crypto_internal.h"

CryptoResult<CryptoKey>
selectJwkFromSet(const JsonDocument &jwks, const std::string &kid, JwtAlgorithm algHint) {
	CryptoResult<CryptoKey> result;
	JsonArrayConst keys = jwks["keys"].as<JsonArrayConst>();
	if (keys.isNull()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "jwks missing keys");
		return result;
	}
	for (JsonVariantConst v : keys) {
		JsonObjectConst jwk = v.as<JsonObjectConst>();
		const char *jwkKid = jwk["kid"].as<const char *>();
		if (!kid.empty() && (!jwkKid || kid != jwkKid)) {
			continue;
		}
		const char *algStr = jwk["alg"].as<const char *>();
		if (algStr && algHint != JwtAlgorithm::Auto &&
		    algorithmFromName(algStr) != JwtAlgorithm::Auto &&
		    algorithmFromName(algStr) != algHint) {
			continue;
		}
		auto parsed = jwkToKey(jwk);
		if (parsed.ok()) {
			return parsed;
		}
		result.status = parsed.status;
	}
	if (!kid.empty()) {
		result.status = makeStatus(CryptoStatus::DecodeError, "kid not found");
	} else if (!result.status.ok()) {
		// Keep last parse error.
	} else {
		result.status = makeStatus(CryptoStatus::DecodeError, "no jwk matched");
	}
	return result;
}

std::string algorithmName(JwtAlgorithm alg) {
	switch (alg) {
	case JwtAlgorithm::HS256:
		return "HS256";
	case JwtAlgorithm::RS256:
		return "RS256";
	case JwtAlgorithm::ES256:
		return "ES256";
	case JwtAlgorithm::Auto:
	default:
		return "";
	}
}

JwtAlgorithm algorithmFromName(const std::string &name) {
	if (name == "HS256") {
		return JwtAlgorithm::HS256;
	}
	if (name == "RS256") {
		return JwtAlgorithm::RS256;
	}
	if (name == "ES256") {
		return JwtAlgorithm::ES256;
	}
	return JwtAlgorithm::Auto;
}

bool signJwt(
    JwtAlgorithm alg,
    const std::string &key,
    const uint8_t *data,
    size_t length,
    std::vector<uint8_t> &signature
) {
	switch (alg) {
	case JwtAlgorithm::HS256:
		return hmacSha256(key, data, length, signature);
	case JwtAlgorithm::RS256:
		return pkSignInternal(key, MBEDTLS_PK_RSA, ShaVariant::SHA256, data, length, signature);
	case JwtAlgorithm::ES256:
		return pkSignInternal(key, MBEDTLS_PK_ECKEY, ShaVariant::SHA256, data, length, signature);
	case JwtAlgorithm::Auto:
	default:
		return false;
	}
}

bool verifySignature(
    JwtAlgorithm alg,
    const std::string &key,
    const uint8_t *data,
    size_t length,
    const std::vector<uint8_t> &signature
) {
	switch (alg) {
	case JwtAlgorithm::HS256: {
		std::vector<uint8_t> expected;
		if (!hmacSha256(key, data, length, expected)) {
			return false;
		}
		return constantTimeEquals(
		    CryptoSpan<const uint8_t>(expected),
		    CryptoSpan<const uint8_t>(signature)
		);
	}
	case JwtAlgorithm::RS256:
		return pkVerifyInternal(key, MBEDTLS_PK_RSA, ShaVariant::SHA256, data, length, signature);
	case JwtAlgorithm::ES256:
		return pkVerifyInternal(key, MBEDTLS_PK_ECKEY, ShaVariant::SHA256, data, length, signature);
	case JwtAlgorithm::Auto:
	default:
		return false;
	}
}

namespace espcrypto::jwt {
CryptoResult<std::string> create(
    const JsonDocument &claims,
    std::string_view key,
    const JwtSignOptions &options
) {
	CryptoResult<std::string> result;
	if (key.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "key missing");
		return result;
	}
	JsonDocument header;
	std::string algName = algorithmName(options.algorithm);
	if (algName.empty()) {
		result.status = makeStatus(CryptoStatus::Unsupported, "unsupported alg");
		return result;
	}
	header["alg"] = algName.c_str();
	header["typ"] = "JWT";
	if (!options.keyId.empty()) {
		header["kid"] = options.keyId.c_str();
	}

	JsonDocument payload;
	payload.set(claims);
	if (!options.issuer.empty() && payload["iss"].isNull()) {
		payload["iss"] = options.issuer.c_str();
	}
	if (!options.subject.empty() && payload["sub"].isNull()) {
		payload["sub"] = options.subject.c_str();
	}
	if (!options.audience.empty() && payload["aud"].isNull()) {
		payload["aud"] = options.audience.c_str();
	}

	uint32_t now = currentTimeSeconds(
	    options.currentTimestamp != 0 ? options.currentTimestamp : options.issuedAt
	);
	if (options.issuedAt != 0) {
		payload["iat"] = options.issuedAt;
	} else {
		payload["iat"] = now;
	}
	if (options.expiresInSeconds > 0) {
		payload["exp"] =
		    static_cast<uint32_t>(payload["iat"].as<uint32_t>() + options.expiresInSeconds);
	}
	if (options.notBefore > 0) {
		payload["nbf"] = options.notBefore;
	}

	std::string headerJson;
	if (serializeJson(header, headerJson) == 0) {
		result.status = makeStatus(CryptoStatus::JsonError, "header serialization failed");
		return result;
	}
	std::string payloadJson;
	if (serializeJson(payload, payloadJson) == 0) {
		result.status = makeStatus(CryptoStatus::JsonError, "payload serialization failed");
		return result;
	}

	std::string encodedHeader = base64Encode(
	    reinterpret_cast<const uint8_t *>(headerJson.data()),
	    headerJson.size(),
	    Base64Alphabet::Url
	);
	std::string encodedPayload = base64Encode(
	    reinterpret_cast<const uint8_t *>(payloadJson.data()),
	    payloadJson.size(),
	    Base64Alphabet::Url
	);
	if (encodedHeader.empty() || encodedPayload.empty()) {
		result.status = makeStatus(CryptoStatus::DecodeError, "base64 encode failed");
		return result;
	}

	std::string signingInput = encodedHeader + "." + encodedPayload;
	std::vector<uint8_t> signature;
	if (!signJwt(
	        options.algorithm,
	        std::string(key),
	        reinterpret_cast<const uint8_t *>(signingInput.data()),
	        signingInput.size(),
	        signature
	    )) {
		result.status = makeStatus(CryptoStatus::InternalError, "sign failed");
		return result;
	}

	std::string encodedSignature =
	    base64Encode(signature.data(), signature.size(), Base64Alphabet::Url);
	result.value = signingInput + "." + encodedSignature;
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<void> verify(
    std::string_view token,
    std::string_view key,
    JsonDocument &outClaims,
    const JwtVerifyOptions &options
) {
	CryptoResult<void> result;
	if (token.empty() || key.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "token or key missing");
		return result;
	}

	std::string tokenStd(token);
	size_t first = tokenStd.find('.');
	size_t second = tokenStd.find('.', first == std::string::npos ? 0 : first + 1);
	if (first == std::string::npos || second == std::string::npos) {
		result.status = makeStatus(CryptoStatus::DecodeError, "invalid token structure");
		return result;
	}

	std::string headerPart = tokenStd.substr(0, first);
	std::string payloadPart = tokenStd.substr(first + 1, second - first - 1);
	std::string signaturePart = tokenStd.substr(second + 1);
	std::vector<uint8_t> headerBytes;
	std::vector<uint8_t> payloadBytes;
	std::vector<uint8_t> signatureBytes;
	if (!base64Decode(headerPart, Base64Alphabet::Url, headerBytes) ||
	    !base64Decode(payloadPart, Base64Alphabet::Url, payloadBytes) ||
	    !base64Decode(signaturePart, Base64Alphabet::Url, signatureBytes)) {
		result.status = makeStatus(CryptoStatus::DecodeError, "base64 decode failed");
		return result;
	}

	JsonDocument headerDoc;
	if (deserializeJson(headerDoc, headerBytes.data(), headerBytes.size()) !=
	    DeserializationError::Ok) {
		result.status = makeStatus(CryptoStatus::JsonError, "invalid header json");
		return result;
	}
	JsonDocument payloadDoc;
	if (deserializeJson(payloadDoc, payloadBytes.data(), payloadBytes.size()) !=
	    DeserializationError::Ok) {
		result.status = makeStatus(CryptoStatus::JsonError, "invalid payload json");
		return result;
	}

	const char *algStr = headerDoc["alg"].as<const char *>();
	JwtAlgorithm alg = algorithmFromName(algStr ? algStr : "");
	if (alg == JwtAlgorithm::Auto) {
		result.status = makeStatus(CryptoStatus::Unsupported, "unsupported alg");
		return result;
	}
	if (options.algorithm != JwtAlgorithm::Auto && options.algorithm != alg) {
		result.status = makeStatus(CryptoStatus::PolicyViolation, "alg mismatch");
		return result;
	}

	const char *typHdr = headerDoc["typ"].as<const char *>();
	if (!options.expectedTyp.empty() && (!typHdr || options.expectedTyp != typHdr)) {
		result.status = makeStatus(CryptoStatus::PolicyViolation, "typ mismatch");
		return result;
	}

	JsonArray crit = headerDoc["crit"].as<JsonArray>();
	if (!crit.isNull() && !options.criticalHeadersAllowed.empty()) {
		for (JsonVariant v : crit) {
			const char *name = v.as<const char *>();
			bool allowed = name && std::any_of(
			                           options.criticalHeadersAllowed.begin(),
			                           options.criticalHeadersAllowed.end(),
			                           [&](const std::string &allowedName) {
				                           return allowedName == name;
			                           }
			                       );
			if (!allowed) {
				result.status =
				    makeStatus(CryptoStatus::PolicyViolation, "crit header not allowed");
				return result;
			}
		}
	} else if (!crit.isNull() && options.criticalHeadersAllowed.empty()) {
		result.status = makeStatus(CryptoStatus::PolicyViolation, "crit header not allowed");
		return result;
	}

	std::string signingInput = headerPart + "." + payloadPart;
	if (!verifySignature(
	        alg,
	        std::string(key),
	        reinterpret_cast<const uint8_t *>(signingInput.data()),
	        signingInput.size(),
	        signatureBytes
	    )) {
		result.status = makeStatus(CryptoStatus::VerifyFailed, "signature mismatch");
		return result;
	}

	uint32_t now = currentTimeSeconds(options.currentTimestamp);
	uint32_t leeway = options.leewaySeconds;
	uint32_t exp = payloadDoc["exp"].as<uint32_t>();
	uint32_t nbf = payloadDoc["nbf"].as<uint32_t>();
	if (options.requireExpiration && exp == 0) {
		result.status = makeStatus(CryptoStatus::PolicyViolation, "missing exp");
		return result;
	}
	if (exp != 0 && now > exp + leeway) {
		result.status = makeStatus(CryptoStatus::Expired, "token expired");
		return result;
	}
	if (nbf != 0 && now + leeway < nbf) {
		result.status = makeStatus(CryptoStatus::NotYetValid, "token not active");
		return result;
	}

	auto audMatch = [&](const char *aud) -> bool {
		if (!aud) {
			return false;
		}
		if (!options.audience.empty() && options.audience == aud) {
			return true;
		}
		if (std::any_of(
		        options.audiences.begin(),
		        options.audiences.end(),
		        [&](const std::string &allowedAudience) { return allowedAudience == aud; }
		    )) {
			return true;
		}
		return options.audience.empty() && options.audiences.empty();
	};

	if (!options.audience.empty() || !options.audiences.empty()) {
		bool ok = false;
		if (payloadDoc["aud"].is<JsonArray>()) {
			JsonArray arr = payloadDoc["aud"].as<JsonArray>();
			for (JsonVariant v : arr) {
				ok = audMatch(v.as<const char *>());
				if (ok) {
					break;
				}
			}
		} else {
			ok = audMatch(payloadDoc["aud"].as<const char *>());
		}
		if (!ok) {
			result.status = makeStatus(CryptoStatus::AudienceMismatch, "aud mismatch");
			return result;
		}
	}

	if (!options.issuer.empty()) {
		const char *iss = payloadDoc["iss"].as<const char *>();
		if (!iss || options.issuer != iss) {
			result.status = makeStatus(CryptoStatus::IssuerMismatch, "iss mismatch");
			return result;
		}
	}

	outClaims.set(payloadDoc);
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<void> verifyWithJwks(
    std::string_view token,
    const JsonDocument &jwks,
    JsonDocument &outClaims,
    const JwtVerifyOptions &options
) {
	CryptoResult<void> result;
	if (token.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "token missing");
		return result;
	}

	std::string tokenStd(token);
	size_t first = tokenStd.find('.');
	size_t second = tokenStd.find('.', first == std::string::npos ? 0 : first + 1);
	if (first == std::string::npos || second == std::string::npos) {
		result.status = makeStatus(CryptoStatus::DecodeError, "invalid token structure");
		return result;
	}

	std::string headerPart = tokenStd.substr(0, first);
	std::vector<uint8_t> headerBytes;
	if (!base64Decode(headerPart, Base64Alphabet::Url, headerBytes)) {
		result.status = makeStatus(CryptoStatus::DecodeError, "base64 decode failed");
		return result;
	}

	JsonDocument headerDoc;
	if (deserializeJson(headerDoc, headerBytes.data(), headerBytes.size()) !=
	    DeserializationError::Ok) {
		result.status = makeStatus(CryptoStatus::JsonError, "invalid header json");
		return result;
	}

	const char *kid = headerDoc["kid"].as<const char *>();
	JwtAlgorithm alg = algorithmFromName(
	    headerDoc["alg"].as<const char *>() ? headerDoc["alg"].as<const char *>() : ""
	);
	auto keyRes = selectJwkFromSet(jwks, kid ? std::string(kid) : std::string(), alg);
	if (!keyRes.ok()) {
		result.status = keyRes.status;
		return result;
	}

	auto bytes = keyRes.value.bytes();
	std::string keyStr(reinterpret_cast<const char *>(bytes.data()), bytes.size());
	return verify(token, keyStr, outClaims, options);
}
} // namespace espcrypto::jwt
