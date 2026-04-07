#pragma once

#include "hash.h"
#include "types.h"

class ShaCtx {
  public:
	ShaCtx();
	~ShaCtx();
	ShaCtx(const ShaCtx &) = delete;
	ShaCtx &operator=(const ShaCtx &) = delete;

	CryptoStatusDetail begin(ShaVariant variant, bool preferHardware = true);
	CryptoStatusDetail update(CryptoSpan<const uint8_t> data);
	CryptoStatusDetail finish(CryptoSpan<uint8_t> out);

  private:
	struct Impl;
	Impl *impl = nullptr;
};

class HmacCtx {
  public:
	HmacCtx();
	~HmacCtx();
	HmacCtx(const HmacCtx &) = delete;
	HmacCtx &operator=(const HmacCtx &) = delete;

	CryptoStatusDetail begin(ShaVariant variant, CryptoSpan<const uint8_t> key);
	CryptoStatusDetail update(CryptoSpan<const uint8_t> data);
	CryptoStatusDetail finish(CryptoSpan<uint8_t> out);

  private:
	struct Impl;
	Impl *impl = nullptr;
};

class AesCtrStream {
  public:
	AesCtrStream();
	~AesCtrStream();
	AesCtrStream(const AesCtrStream &) = delete;
	AesCtrStream &operator=(const AesCtrStream &) = delete;

	CryptoStatusDetail begin(const std::vector<uint8_t> &key, CryptoSpan<const uint8_t> nonceCounter);
	CryptoStatusDetail update(CryptoSpan<const uint8_t> input, CryptoSpan<uint8_t> output);

  private:
	struct Impl;
	Impl *impl = nullptr;
};

class AesGcmCtx {
  public:
	AesGcmCtx();
	~AesGcmCtx();
	AesGcmCtx(const AesGcmCtx &) = delete;
	AesGcmCtx &operator=(const AesGcmCtx &) = delete;

	CryptoStatusDetail beginEncrypt(
	    const std::vector<uint8_t> &key,
	    CryptoSpan<const uint8_t> iv,
	    CryptoSpan<const uint8_t> aad
	);
	CryptoStatusDetail beginDecrypt(
	    const std::vector<uint8_t> &key,
	    CryptoSpan<const uint8_t> iv,
	    CryptoSpan<const uint8_t> aad,
	    CryptoSpan<const uint8_t> tag
	);
	CryptoStatusDetail update(CryptoSpan<const uint8_t> input, CryptoSpan<uint8_t> output);
	CryptoStatusDetail finish(CryptoSpan<uint8_t> tagOut);

  private:
	CryptoStatusDetail beginCommon(
	    const std::vector<uint8_t> &key,
	    CryptoSpan<const uint8_t> iv,
	    CryptoSpan<const uint8_t> aad,
	    bool decryptMode,
	    CryptoSpan<const uint8_t> tag
	);

	struct Impl;
	Impl *impl = nullptr;
};
