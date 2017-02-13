////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2016 Lightfactor, LLC. All rights reserved.
//
// Author:			Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified:	02/12/2017
//
////////////////////////////////////////////////////////////////////////////////


#ifndef _SHA256_H_
#define _SHA256_H_


#define SHA256_HASH_SIZE		(32)

#include "include_windows.h"
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	HCRYPTPROV	hCryptProv;
	HCRYPTHASH	hHash;
	HCRYPTKEY	hKey;
}
sha256_context;


int sha256_init(sha256_context* ctx);
int sha256_update(sha256_context* ctx, const uint8_t* input, size_t ilen);
int sha256_finish(sha256_context* ctx, uint8_t output[SHA256_HASH_SIZE]);
int sha256(const uint8_t* input, size_t ilen, uint8_t output[SHA256_HASH_SIZE]);

int sha256_hmac_init(sha256_context* ctx, const uint8_t* key,  size_t keylen);
int sha256_hmac_update(sha256_context* ctx, const uint8_t* input, size_t ilen);
int sha256_hmac_finish(sha256_context* ctx, uint8_t output[SHA256_HASH_SIZE]);
int sha256_hmac(const uint8_t* key, size_t keylen, const uint8_t* input, size_t ilen, uint8_t output[SHA256_HASH_SIZE]);


#ifdef __cplusplus
	}
#endif

#endif // _SHA256_H_
