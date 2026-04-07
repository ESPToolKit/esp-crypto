#include "internal/crypto_internal.h"

CryptoResult<std::vector<uint8_t>> ecdsaDerToRawInternal(CryptoSpan<const uint8_t> der) {
	CryptoResult<std::vector<uint8_t>> result;
	unsigned char *cursor = const_cast<unsigned char *>(der.data());
	const unsigned char *end = der.data() + der.size();
	size_t len = 0;
	mbedtls_mpi r, s;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	do {
		if (mbedtls_asn1_get_tag(
		        &cursor,
		        end,
		        &len,
		        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE
		    ) != 0) {
			result.status = makeStatus(CryptoStatus::DecodeError, "asn1 seq");
			break;
		}
		if (mbedtls_asn1_get_mpi(&cursor, end, &r) != 0 ||
		    mbedtls_asn1_get_mpi(&cursor, end, &s) != 0) {
			result.status = makeStatus(CryptoStatus::DecodeError, "asn1 mpi");
			break;
		}
		size_t rlen = mbedtls_mpi_size(&r);
		size_t slen = mbedtls_mpi_size(&s);
		size_t part = std::max(rlen, slen);
		result.value.assign(part * 2, 0);
		mbedtls_mpi_write_binary(&r, result.value.data() + (part - rlen), rlen);
		mbedtls_mpi_write_binary(&s, result.value.data() + part + (part - slen), slen);
		result.status = makeStatus(CryptoStatus::Ok);
	} while (false);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return result;
}

CryptoResult<std::vector<uint8_t>> ecdsaRawToDerInternal(CryptoSpan<const uint8_t> raw) {
	CryptoResult<std::vector<uint8_t>> result;
	if (raw.size() % 2 != 0 || raw.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "raw len invalid");
		return result;
	}
	size_t part = raw.size() / 2;
	mbedtls_mpi r, s;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	do {
		if (mbedtls_mpi_read_binary(&r, raw.data(), part) != 0 ||
		    mbedtls_mpi_read_binary(&s, raw.data() + part, part) != 0) {
			result.status = makeStatus(CryptoStatus::DecodeError, "raw mpi");
			break;
		}
		unsigned char buffer[200];
		unsigned char *p = buffer + sizeof(buffer);
		size_t len = 0;
		if (mbedtls_asn1_write_mpi(&p, buffer, &s) < 0 ||
		    mbedtls_asn1_write_mpi(&p, buffer, &r) < 0) {
			result.status = makeStatus(CryptoStatus::InternalError, "asn1 mpi write");
			break;
		}
		len = static_cast<size_t>(buffer + sizeof(buffer) - p);
		if (mbedtls_asn1_write_len(&p, buffer, len) < 0 ||
		    mbedtls_asn1_write_tag(&p, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) <
		        0) {
			result.status = makeStatus(CryptoStatus::InternalError, "asn1 len");
			break;
		}
		size_t total = static_cast<size_t>(buffer + sizeof(buffer) - p);
		result.value.assign(p, p + total);
		result.status = makeStatus(CryptoStatus::Ok);
	} while (false);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	return result;
}

CryptoStatusDetail buildRsaPemFromJwk(
    const std::vector<uint8_t> &n, const std::vector<uint8_t> &e, std::string &outPem
) {
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	CryptoStatusDetail status = makeStatus(CryptoStatus::InternalError, "rsa setup failed");
	if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
		mbedtls_pk_free(&pk);
		return status;
	}
	mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
	if (mbedtls_rsa_import_raw(
	        rsa,
	        n.data(),
	        n.size(),
	        nullptr,
	        0,
	        nullptr,
	        0,
	        nullptr,
	        0,
	        e.data(),
	        e.size()
	    ) != 0 ||
	    mbedtls_rsa_complete(rsa) != 0 || mbedtls_rsa_check_pubkey(rsa) != 0) {
		mbedtls_pk_free(&pk);
		return makeStatus(CryptoStatus::DecodeError, "rsa jwk invalid");
	}
	std::vector<uint8_t> buffer(1600, 0);
	if (mbedtls_pk_write_pubkey_pem(&pk, buffer.data(), buffer.size()) != 0) {
		mbedtls_pk_free(&pk);
		return status;
	}
	outPem.assign(reinterpret_cast<const char *>(buffer.data()));
	mbedtls_pk_free(&pk);
	return makeStatus(CryptoStatus::Ok);
}

CryptoStatusDetail buildEcPemFromJwk(
    const std::vector<uint8_t> &x,
    const std::vector<uint8_t> &y,
    const std::string &crv,
    std::string &outPem
) {
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	mbedtls_ecp_keypair *ec = nullptr;
	CryptoStatusDetail status = makeStatus(CryptoStatus::Unsupported, "curve unsupported");
	mbedtls_ecp_group_id gid = MBEDTLS_ECP_DP_NONE;
	if (crv == "P-256") {
		gid = MBEDTLS_ECP_DP_SECP256R1;
	}
	if (gid == MBEDTLS_ECP_DP_NONE) {
		return status;
	}
	if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0) {
		mbedtls_pk_free(&pk);
		return makeStatus(CryptoStatus::InternalError, "ec setup failed");
	}
	ec = mbedtls_pk_ec(pk);
	if (!ec || mbedtls_ecp_group_load(&ec->MBEDTLS_PRIVATE(grp), gid) != 0) {
		mbedtls_pk_free(&pk);
		return status;
	}
	if (mbedtls_mpi_read_binary(&ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), x.data(), x.size()) !=
	        0 ||
	    mbedtls_mpi_read_binary(&ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), y.data(), y.size()) !=
	        0) {
		mbedtls_pk_free(&pk);
		return makeStatus(CryptoStatus::DecodeError, "ec coord read");
	}
	if (mbedtls_mpi_lset(&ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Z), 1) != 0) {
		mbedtls_pk_free(&pk);
		return makeStatus(CryptoStatus::DecodeError, "ec coord set");
	}
	if (mbedtls_ecp_check_pubkey(&ec->MBEDTLS_PRIVATE(grp), &ec->MBEDTLS_PRIVATE(Q)) != 0) {
		mbedtls_pk_free(&pk);
		return makeStatus(CryptoStatus::DecodeError, "ec jwk invalid");
	}
	{
		std::vector<uint8_t> buffer(800, 0);
		if (mbedtls_pk_write_pubkey_pem(&pk, buffer.data(), buffer.size()) != 0) {
			mbedtls_pk_free(&pk);
			return makeStatus(CryptoStatus::InternalError, "ec pem write failed");
		}
		outPem.assign(reinterpret_cast<const char *>(buffer.data()));
	}
	mbedtls_pk_free(&pk);
	return makeStatus(CryptoStatus::Ok);
}

CryptoResult<CryptoKey> jwkToKey(const JsonObjectConst &jwk) {
	CryptoResult<CryptoKey> result;
	const char *kty = jwk["kty"].as<const char *>();
	if (!kty) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing kty");
		return result;
	}
	if (strcmp(kty, "oct") == 0) {
		std::vector<uint8_t> k;
		if (!base64Decode(jwk["k"].as<const char *>(), Base64Alphabet::Url, k)) {
			result.status = makeStatus(CryptoStatus::DecodeError, "oct decode failed");
			return result;
		}
		result.value = CryptoKey::fromRaw(k, KeyKind::Symmetric);
		result.status = makeStatus(CryptoStatus::Ok);
		return result;
	}
	if (strcmp(kty, "RSA") == 0) {
		std::vector<uint8_t> n, e;
		if (!base64Decode(jwk["n"].as<const char *>(), Base64Alphabet::Url, n) ||
		    !base64Decode(jwk["e"].as<const char *>(), Base64Alphabet::Url, e)) {
			result.status = makeStatus(CryptoStatus::DecodeError, "rsa decode failed");
			return result;
		}
		std::string pem;
		auto status = buildRsaPemFromJwk(n, e, pem);
		if (!status.ok()) {
			result.status = status;
			return result;
		}
		result.value = CryptoKey::fromPem(pem, KeyKind::Public);
		result.status = makeStatus(CryptoStatus::Ok);
		return result;
	}
	if (strcmp(kty, "EC") == 0) {
		std::vector<uint8_t> x, y;
		if (!base64Decode(jwk["x"].as<const char *>(), Base64Alphabet::Url, x) ||
		    !base64Decode(jwk["y"].as<const char *>(), Base64Alphabet::Url, y)) {
			result.status = makeStatus(CryptoStatus::DecodeError, "ec decode failed");
			return result;
		}
		std::string pem;
		auto status = buildEcPemFromJwk(
		    x,
		    y,
		    std::string(jwk["crv"].as<const char *>() ? jwk["crv"].as<const char *>() : ""),
		    pem
		);
		if (!status.ok()) {
			result.status = status;
			return result;
		}
		result.value = CryptoKey::fromPem(pem, KeyKind::Public);
		result.status = makeStatus(CryptoStatus::Ok);
		return result;
	}
	result.status = makeStatus(CryptoStatus::Unsupported, "kty unsupported");
	return result;
}

bool pkParsePublicOrPrivate(
    mbedtls_pk_context &pk,
    const std::string &pem,
    mbedtls_ctr_drbg_context *ctr,
    const mbedtls_entropy_context *entropy
) {
	int ret = mbedtls_pk_parse_public_key(
	    &pk,
	    reinterpret_cast<const unsigned char *>(pem.c_str()),
	    pem.size() + 1
	);
	if (ret == 0) {
		return true;
	}
	mbedtls_ctr_drbg_context localCtr;
	mbedtls_entropy_context localEntropy;
	// cppcheck-suppress constVariablePointer
	mbedtls_ctr_drbg_context *effectiveCtr = ctr;
	if (!ctr || !entropy) {
		if (!initDrbg(localCtr, localEntropy)) {
			return false;
		}
		effectiveCtr = &localCtr;
	}
#if ESPCRYPTO_MBEDTLS_V3
	ret = mbedtls_pk_parse_key(
	    &pk,
	    reinterpret_cast<const unsigned char *>(pem.c_str()),
	    pem.size() + 1,
	    nullptr,
	    0,
	    mbedtls_ctr_drbg_random,
	    effectiveCtr
	);
#else
	ret = mbedtls_pk_parse_key(
	    &pk,
	    reinterpret_cast<const unsigned char *>(pem.c_str()),
	    pem.size() + 1,
	    nullptr,
	    0
	);
#endif
	if (effectiveCtr == &localCtr) {
		mbedtls_ctr_drbg_free(&localCtr);
		mbedtls_entropy_free(&localEntropy);
	}
	return ret == 0;
}

bool pkPolicyAllows(mbedtls_pk_context &pk, mbedtls_pk_type_t expected) {
	if (!mbedtls_pk_can_do(&pk, expected)) {
		return false;
	}
	markRuntimeInitialized();
	const CryptoPolicy &policy = mutablePolicy();
	size_t bitlen = mbedtls_pk_get_bitlen(&pk);
	if (!policy.allowLegacy) {
		if (expected == MBEDTLS_PK_RSA && bitlen < policy.minRsaBits) {
			return false;
		}
		if (expected == MBEDTLS_PK_ECKEY && !policy.allowWeakCurves && bitlen < 256) {
			return false;
		}
	}
	return true;
}

bool pkSignContext(
    mbedtls_pk_context &pk,
    mbedtls_pk_type_t expected,
    ShaVariant variant,
    const uint8_t *data,
    size_t length,
    std::vector<uint8_t> &signature
) {
	if (!pkPolicyAllows(pk, expected)) {
		return false;
	}
	std::vector<uint8_t> hash;
	if (!computeHash(variant, data, length, hash)) {
		return false;
	}
	const mbedtls_md_info_t *info = mdInfoForVariant(variant);
	if (!info) {
		return false;
	}
	size_t sigLen = mbedtls_pk_get_len(&pk);
	signature.assign(sigLen, 0);
	mbedtls_ctr_drbg_context ctr;
	mbedtls_entropy_context entropy;
	if (!initDrbg(ctr, entropy)) {
		signature.clear();
		return false;
	}
#if ESPCRYPTO_MBEDTLS_V3
	int ret = mbedtls_pk_sign(
	    &pk,
	    mbedtls_md_get_type(info),
	    hash.data(),
	    hash.size(),
	    signature.data(),
	    signature.size(),
	    &sigLen,
	    mbedtls_ctr_drbg_random,
	    &ctr
	);
#else
	int ret = mbedtls_pk_sign(
	    &pk,
	    mbedtls_md_get_type(info),
	    hash.data(),
	    hash.size(),
	    signature.data(),
	    &sigLen,
	    mbedtls_ctr_drbg_random,
	    &ctr
	);
#endif
	mbedtls_ctr_drbg_free(&ctr);
	mbedtls_entropy_free(&entropy);
	if (ret != 0) {
		signature.clear();
		return false;
	}
	signature.resize(sigLen);
	return true;
}

bool pkVerifyContext(
    mbedtls_pk_context &pk,
    mbedtls_pk_type_t expected,
    ShaVariant variant,
    const uint8_t *data,
    size_t length,
    const std::vector<uint8_t> &signature
) {
	if (!pkPolicyAllows(pk, expected)) {
		return false;
	}
	std::vector<uint8_t> hash;
	if (!computeHash(variant, data, length, hash)) {
		return false;
	}
	const mbedtls_md_info_t *info = mdInfoForVariant(variant);
	if (!info) {
		return false;
	}
	int ret = mbedtls_pk_verify(
	    &pk,
	    mbedtls_md_get_type(info),
	    hash.data(),
	    hash.size(),
	    signature.data(),
	    signature.size()
	);
	return ret == 0;
}

bool pkSignInternal(
    const std::string &pem,
    mbedtls_pk_type_t expected,
    ShaVariant variant,
    const uint8_t *data,
    size_t length,
    std::vector<uint8_t> &signature
) {
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	mbedtls_ctr_drbg_context ctr;
	mbedtls_entropy_context entropy;
	if (!initDrbg(ctr, entropy)) {
		mbedtls_pk_free(&pk);
		return false;
	}
#if ESPCRYPTO_MBEDTLS_V3
	int ret = mbedtls_pk_parse_key(
	    &pk,
	    reinterpret_cast<const unsigned char *>(pem.c_str()),
	    pem.size() + 1,
	    nullptr,
	    0,
	    mbedtls_ctr_drbg_random,
	    &ctr
	);
#else
	int ret = mbedtls_pk_parse_key(
	    &pk,
	    reinterpret_cast<const unsigned char *>(pem.c_str()),
	    pem.size() + 1,
	    nullptr,
	    0
	);
#endif
	mbedtls_ctr_drbg_free(&ctr);
	mbedtls_entropy_free(&entropy);
	if (ret != 0) {
		mbedtls_pk_free(&pk);
		return false;
	}
	bool ok = pkSignContext(pk, expected, variant, data, length, signature);
	mbedtls_pk_free(&pk);
	return ok;
}

bool pkVerifyInternal(
    const std::string &pem,
    mbedtls_pk_type_t expected,
    ShaVariant variant,
    const uint8_t *data,
    size_t length,
    const std::vector<uint8_t> &signature
) {
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	if (!pkParsePublicOrPrivate(pk, pem, nullptr, nullptr)) {
		mbedtls_pk_free(&pk);
		return false;
	}
	bool ok = pkVerifyContext(pk, expected, variant, data, length, signature);
	mbedtls_pk_free(&pk);
	return ok;
}

bool ESPCrypto::rsaSign(
    const std::string &privateKeyPem,
    const uint8_t *data,
    size_t length,
    ShaVariant variant,
    std::vector<uint8_t> &signature
) {
	if (privateKeyPem.empty() || (!data && length > 0)) {
		return false;
	}
	return pkSignInternal(privateKeyPem, MBEDTLS_PK_RSA, variant, data, length, signature);
}

bool ESPCrypto::rsaVerify(
    const std::string &publicKeyPem,
    const uint8_t *data,
    size_t length,
    const std::vector<uint8_t> &signature,
    ShaVariant variant
) {
	if (publicKeyPem.empty() || (!data && length > 0) || signature.empty()) {
		return false;
	}
	return pkVerifyInternal(publicKeyPem, MBEDTLS_PK_RSA, variant, data, length, signature);
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::rsaSign(
    const std::string &privateKeyPem, CryptoSpan<const uint8_t> data, ShaVariant variant
) {
	CryptoResult<std::vector<uint8_t>> result;
	if (privateKeyPem.empty() || (!data.data() && data.size() > 0)) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing key or data");
		return result;
	}
	if (!pkSignInternal(
	        privateKeyPem,
	        MBEDTLS_PK_RSA,
	        variant,
	        data.data(),
	        data.size(),
	        result.value
	    )) {
		result.status = makeStatus(CryptoStatus::VerifyFailed, "rsa sign failed");
		result.value.clear();
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<void> ESPCrypto::rsaVerify(
    const std::string &publicKeyPem,
    CryptoSpan<const uint8_t> data,
    CryptoSpan<const uint8_t> signature,
    ShaVariant variant
) {
	CryptoResult<void> result;
	if (publicKeyPem.empty() || (!data.data() && data.size() > 0) || signature.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing key/data/signature");
		return result;
	}
	if (!pkVerifyInternal(
	        publicKeyPem,
	        MBEDTLS_PK_RSA,
	        variant,
	        data.data(),
	        data.size(),
	        std::vector<uint8_t>(signature.data(), signature.data() + signature.size())
	    )) {
		result.status = makeStatus(CryptoStatus::VerifyFailed, "rsa verify failed");
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::rsaSign(
    const CryptoKey &privateKey, CryptoSpan<const uint8_t> data, ShaVariant variant
) {
	CryptoResult<std::vector<uint8_t>> result;
	if (!privateKey.valid() || (!data.data() && data.size() > 0)) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing key or data");
		return result;
	}
	auto parsed = privateKey.ensureParsedPk(true);
	if (!parsed.ok()) {
		result.status = parsed;
		return result;
	}
	if (!pkSignContext(
	        privateKey.pk->ctx,
	        MBEDTLS_PK_RSA,
	        variant,
	        data.data(),
	        data.size(),
	        result.value
	    )) {
		result.status = makeStatus(CryptoStatus::VerifyFailed, "rsa sign failed");
		result.value.clear();
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<void> ESPCrypto::rsaVerify(
    const CryptoKey &publicKey,
    CryptoSpan<const uint8_t> data,
    CryptoSpan<const uint8_t> signature,
    ShaVariant variant
) {
	CryptoResult<void> result;
	if (!publicKey.valid() || (!data.data() && data.size() > 0) || signature.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing key/data/signature");
		return result;
	}
	auto parsed = publicKey.ensureParsedPk(false);
	if (!parsed.ok()) {
		result.status = parsed;
		return result;
	}
	std::vector<uint8_t> sigVec(signature.data(), signature.data() + signature.size());
	if (!pkVerifyContext(
	        publicKey.pk->ctx,
	        MBEDTLS_PK_RSA,
	        variant,
	        data.data(),
	        data.size(),
	        sigVec
	    )) {
		result.status = makeStatus(CryptoStatus::VerifyFailed, "rsa verify failed");
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

bool ESPCrypto::eccSign(
    const std::string &privateKeyPem,
    const uint8_t *data,
    size_t length,
    ShaVariant variant,
    std::vector<uint8_t> &signature
) {
	if (privateKeyPem.empty() || (!data && length > 0)) {
		return false;
	}
	return pkSignInternal(privateKeyPem, MBEDTLS_PK_ECKEY, variant, data, length, signature);
}

bool ESPCrypto::eccVerify(
    const std::string &publicKeyPem,
    const uint8_t *data,
    size_t length,
    const std::vector<uint8_t> &signature,
    ShaVariant variant
) {
	if (publicKeyPem.empty() || (!data && length > 0) || signature.empty()) {
		return false;
	}
	return pkVerifyInternal(publicKeyPem, MBEDTLS_PK_ECKEY, variant, data, length, signature);
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::eccSign(
    const std::string &privateKeyPem, CryptoSpan<const uint8_t> data, ShaVariant variant
) {
	CryptoResult<std::vector<uint8_t>> result;
	if (privateKeyPem.empty() || (!data.data() && data.size() > 0)) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing key or data");
		return result;
	}
	if (!pkSignInternal(
	        privateKeyPem,
	        MBEDTLS_PK_ECKEY,
	        variant,
	        data.data(),
	        data.size(),
	        result.value
	    )) {
		result.status = makeStatus(CryptoStatus::VerifyFailed, "ecc sign failed");
		result.value.clear();
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<void> ESPCrypto::eccVerify(
    const std::string &publicKeyPem,
    CryptoSpan<const uint8_t> data,
    CryptoSpan<const uint8_t> signature,
    ShaVariant variant
) {
	CryptoResult<void> result;
	if (publicKeyPem.empty() || (!data.data() && data.size() > 0) || signature.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing key/data/signature");
		return result;
	}
	if (!pkVerifyInternal(
	        publicKeyPem,
	        MBEDTLS_PK_ECKEY,
	        variant,
	        data.data(),
	        data.size(),
	        std::vector<uint8_t>(signature.data(), signature.data() + signature.size())
	    )) {
		result.status = makeStatus(CryptoStatus::VerifyFailed, "ecc verify failed");
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::eccSign(
    const CryptoKey &privateKey, CryptoSpan<const uint8_t> data, ShaVariant variant
) {
	CryptoResult<std::vector<uint8_t>> result;
	if (!privateKey.valid() || (!data.data() && data.size() > 0)) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing key or data");
		return result;
	}
	auto parsed = privateKey.ensureParsedPk(true);
	if (!parsed.ok()) {
		result.status = parsed;
		return result;
	}
	if (!pkSignContext(
	        privateKey.pk->ctx,
	        MBEDTLS_PK_ECKEY,
	        variant,
	        data.data(),
	        data.size(),
	        result.value
	    )) {
		result.status = makeStatus(CryptoStatus::VerifyFailed, "ecc sign failed");
		result.value.clear();
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<void> ESPCrypto::eccVerify(
    const CryptoKey &publicKey,
    CryptoSpan<const uint8_t> data,
    CryptoSpan<const uint8_t> signature,
    ShaVariant variant
) {
	CryptoResult<void> result;
	if (!publicKey.valid() || (!data.data() && data.size() > 0) || signature.empty()) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "missing key/data/signature");
		return result;
	}
	auto parsed = publicKey.ensureParsedPk(false);
	if (!parsed.ok()) {
		result.status = parsed;
		return result;
	}
	std::vector<uint8_t> sigVec(signature.data(), signature.data() + signature.size());
	if (!pkVerifyContext(
	        publicKey.pk->ctx,
	        MBEDTLS_PK_ECKEY,
	        variant,
	        data.data(),
	        data.size(),
	        sigVec
	    )) {
		result.status = makeStatus(CryptoStatus::VerifyFailed, "ecc verify failed");
		return result;
	}
	result.status = makeStatus(CryptoStatus::Ok);
	return result;
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::ecdsaDerToRaw(CryptoSpan<const uint8_t> der) {
	return ecdsaDerToRawInternal(der);
}

CryptoResult<std::vector<uint8_t>> ESPCrypto::ecdsaRawToDer(CryptoSpan<const uint8_t> raw) {
	return ecdsaRawToDerInternal(raw);
}

CryptoResult<std::vector<uint8_t>>
ESPCrypto::x25519(CryptoSpan<const uint8_t> privateKey, CryptoSpan<const uint8_t> peerPublic) {
	CryptoResult<std::vector<uint8_t>> result;
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
	if (privateKey.size() != 32 || peerPublic.size() != 32) {
		result.status = makeStatus(CryptoStatus::InvalidInput, "keys must be 32 bytes");
		return result;
	}
	mbedtls_ecp_group grp;
	mbedtls_ecp_point Qp;
	mbedtls_mpi d;
	mbedtls_mpi z;
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&Qp);
	mbedtls_mpi_init(&d);
	mbedtls_mpi_init(&z);

	int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
	if (ret != 0) {
		result.status = makeStatus(CryptoStatus::Unsupported, "curve not available");
		goto cleanup;
	}
	ret = mbedtls_mpi_read_binary(&d, privateKey.data(), privateKey.size());
	if (ret != 0) {
		result.status = makeStatus(CryptoStatus::DecodeError, "private key load failed");
		goto cleanup;
	}
	ret = mbedtls_mpi_read_binary(&Qp.MBEDTLS_PRIVATE(X), peerPublic.data(), peerPublic.size());
	if (ret != 0 || mbedtls_mpi_lset(&Qp.MBEDTLS_PRIVATE(Z), 1) != 0) {
		result.status = makeStatus(CryptoStatus::DecodeError, "key load failed");
		goto cleanup;
	}
	result.value.assign(32, 0);
	ret = mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, nullptr, nullptr);
	if (ret != 0) {
		result.value.clear();
		result.status = makeStatus(CryptoStatus::InternalError, "x25519 failed");
		goto cleanup;
	}
	ret = mbedtls_mpi_write_binary(&z, result.value.data(), result.value.size());
	if (ret != 0) {
		secureZero(result.value.data(), result.value.size());
		result.value.clear();
		result.status = makeStatus(CryptoStatus::InternalError, "x25519 write failed");
		goto cleanup;
	}
	result.status = makeStatus(CryptoStatus::Ok);
cleanup:
	mbedtls_mpi_free(&z);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_point_free(&Qp);
	mbedtls_ecp_group_free(&grp);
#else
	(void)privateKey;
	(void)peerPublic;
	result.status = makeStatus(CryptoStatus::Unsupported, "curve25519 unavailable");
#endif
	return result;
}

CryptoResult<std::vector<uint8_t>>
ESPCrypto::ed25519Sign(CryptoSpan<const uint8_t> privateKey, CryptoSpan<const uint8_t> message) {
	CryptoResult<std::vector<uint8_t>> result;
	(void)privateKey;
	(void)message;
	result.status = makeStatus(CryptoStatus::Unsupported, "ed25519 unavailable");
	return result;
}

CryptoResult<void> ESPCrypto::ed25519Verify(
    CryptoSpan<const uint8_t> publicKey,
    CryptoSpan<const uint8_t> message,
    CryptoSpan<const uint8_t> signature
) {
	CryptoResult<void> result;
	(void)publicKey;
	(void)message;
	(void)signature;
	result.status = makeStatus(CryptoStatus::Unsupported, "ed25519 unavailable");
	return result;
}
