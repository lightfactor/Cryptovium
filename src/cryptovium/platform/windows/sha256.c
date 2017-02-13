////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2016 Lightfactor, LLC. All rights reserved.
//
// Author:			Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified:	02/12/2017
//
////////////////////////////////////////////////////////////////////////////////

#include "sha256.h"
#include "zeroize.h"


typedef struct
{
	BLOBHEADER		hdr;
	DWORD			keyLength;
	BYTE			key[128];
} keydata_t;


////////////////////////////////////////////////////////////////////////////////
void sha256_free(sha256_context* ctx)
{
	if (ctx->hCryptProv)
	{
		CryptReleaseContext(ctx->hCryptProv, 0);
		ctx->hCryptProv = 0;
	}

	if (ctx->hHash)
	{
		CryptDestroyHash(ctx->hHash);
		ctx->hHash = 0;
	}

	if (ctx->hKey)
	{
		CryptDestroyKey(ctx->hKey);
		ctx->hKey = 0;
	}
}

////////////////////////////////////////////////////////////////////////////////
int sha256_init(sha256_context* ctx)
{
	memset(ctx, 0, sizeof(sha256_context));

	if (!CryptAcquireContext(&ctx->hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		return 0;

	if (!CryptCreateHash(ctx->hCryptProv, CALG_SHA_256, 0, 0, &ctx->hHash))
	{
		sha256_free(ctx);
		return 0;
	}

	return 1;
}

////////////////////////////////////////////////////////////////////////////////
int sha256_update(sha256_context* ctx, const uint8_t* input, size_t ilen)
{
	if (!CryptHashData(ctx->hHash, input, ilen, 0))
		return 0;

	return 1;
}

////////////////////////////////////////////////////////////////////////////////
int sha256_finish(sha256_context* ctx, uint8_t output[SHA256_HASH_SIZE])
{
	DWORD				dw;

	dw = SHA256_HASH_SIZE;
	if (!CryptGetHashParam(ctx->hHash, HP_HASHVAL, output, &dw, 0))
		return 0;

	sha256_free(ctx);

	return 1;
}

////////////////////////////////////////////////////////////////////////////////
int sha256(const uint8_t* input, size_t ilen, uint8_t output[SHA256_HASH_SIZE])
{
	sha256_context ctx;

	if (!sha256_init(&ctx)) return 0;
	if (!sha256_update(&ctx, input, ilen)) return 0;
	if (!sha256_finish(&ctx, output)) return 0;

	return 1;
}




////////////////////////////////////////////////////////////////////////////////
int sha256_hmac_init(sha256_context* ctx, const uint8_t* key, size_t keylen)
{
	keydata_t			kd;
	HMAC_INFO			hmacInfo;

	if (keylen > sizeof(kd.key)) return 0;

	memset(ctx, 0, sizeof(sha256_context));

	if (!CryptAcquireContext(&ctx->hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		return 0;

	// import the raw secret as the HMAC key
	kd.hdr.bType = PLAINTEXTKEYBLOB;
	kd.hdr.bVersion = CUR_BLOB_VERSION;
	kd.hdr.reserved = 0;
	kd.hdr.aiKeyAlg = CALG_RC2;	// ugh.  I hate crypto api. this allows importing an HMAC key.
	kd.keyLength = keylen;
	memcpy(kd.key, key, keylen);

	if (!CryptImportKey(ctx->hCryptProv, (BYTE*)&kd, sizeof(kd), 0, CRYPT_IPSEC_HMAC_KEY, &ctx->hKey))
	{
		sha256_free(ctx);
		return 0;
	}

	zeroize(&kd, sizeof(kd));

	if (!CryptCreateHash(ctx->hCryptProv, CALG_HMAC, ctx->hKey, 0, &ctx->hHash))
	{
		sha256_free(ctx);
		return 0;
	}

	memset(&hmacInfo, 0, sizeof(hmacInfo));
	hmacInfo.HashAlgid = CALG_SHA_256;

	if (!CryptSetHashParam(ctx->hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0))
	{
		sha256_free(ctx);
		return 0;
	}

	return 1;
}

////////////////////////////////////////////////////////////////////////////////
int sha256_hmac_update(sha256_context* ctx, const uint8_t* input, size_t ilen)
{
	return sha256_update(ctx, input, ilen);
}

////////////////////////////////////////////////////////////////////////////////
int sha256_hmac_finish(sha256_context* ctx, uint8_t output[SHA256_HASH_SIZE])
{
	sha256_finish(ctx, output);
	sha256_free(ctx);

	return 1;
}

////////////////////////////////////////////////////////////////////////////////
int sha256_hmac(const uint8_t* key, size_t keylen, const uint8_t* input, size_t ilen, uint8_t output[SHA256_HASH_SIZE])
{
	sha256_context ctx;

	if (!sha256_hmac_init(&ctx, key, keylen)) return 0;
	if (!sha256_update(&ctx, input, ilen)) return 0;
	if (!sha256_finish(&ctx, output)) return 0;

	return 1;
}
