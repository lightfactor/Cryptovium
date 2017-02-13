////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2016 Lightfactor, LLC. All rights reserved.
//
// Author:			Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified:	02/12/2017
//
////////////////////////////////////////////////////////////////////////////////


#ifndef _SHA512_H_
#define _SHA512_H_


#define SHA512_HASH_SIZE		(64)

#include "include_windows.h"
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

	typedef struct
	{
		HCRYPTPROV	hCryptProv;
		HCRYPTHASH	hHash;
	}
	sha512_context;


	int sha512_init(sha512_context* ctx);
	int sha512_update(sha512_context* ctx, const uint8_t* input, size_t ilen);
	int sha512_finish(sha512_context* ctx, uint8_t output[SHA512_HASH_SIZE]);
	int sha512(const uint8_t* input, size_t ilen, uint8_t output[SHA512_HASH_SIZE]);


#ifdef __cplusplus
}
#endif

#endif // _SHA512_H_
