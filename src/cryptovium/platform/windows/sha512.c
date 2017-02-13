////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2016 Lightfactor, LLC. All rights reserved.
//
// Author:			Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified:	02/12/2017
//
////////////////////////////////////////////////////////////////////////////////

#include "sha512.h"


////////////////////////////////////////////////////////////////////////////////
void sha512_free(sha512_context* ctx)
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
}

////////////////////////////////////////////////////////////////////////////////
int sha512_init(sha512_context* ctx)
{
	memset(ctx, 0, sizeof(sha512_context));

	if (!CryptAcquireContext(&ctx->hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		return 0;

	if (!CryptCreateHash(ctx->hCryptProv, CALG_SHA_512, 0, 0, &ctx->hHash))
	{
		sha512_free(ctx);
		return 0;
	}

	return 1;
}

////////////////////////////////////////////////////////////////////////////////
int sha512_update(sha512_context* ctx, const uint8_t* input, size_t ilen)
{
	if (!CryptHashData(ctx->hHash, input, ilen, 0))
		return 0;

	return 1;
}

////////////////////////////////////////////////////////////////////////////////
int sha512_finish(sha512_context* ctx, uint8_t output[SHA512_HASH_SIZE])
{
	DWORD				dw;

	dw = SHA512_HASH_SIZE;
	if (!CryptGetHashParam(ctx->hHash, HP_HASHVAL, output, &dw, 0))
		return 0;

	sha512_free(ctx);

	return 1;
}

////////////////////////////////////////////////////////////////////////////////
int sha512(const uint8_t* input, size_t ilen, uint8_t output[SHA512_HASH_SIZE])
{
	sha512_context ctx;

	if (!sha512_init(&ctx)) return 0;
	if (!sha512_update(&ctx, input, ilen)) return 0;
	if (!sha512_finish(&ctx, output)) return 0;

	return 1;
}
