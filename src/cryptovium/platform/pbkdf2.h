////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2016 Lightfactor, LLC. All rights reserved.
//
// Author:			Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified:	02/13/2017
//
////////////////////////////////////////////////////////////////////////////////


#ifndef _PBKDF2_H_
#define _PBKDF2_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif


void pbkdf2_sha256_hmac(const uint8_t* P, const uint32_t szP, const uint8_t* S, const uint32_t szS, const uint32_t c, uint8_t* DK, const uint32_t dkLen);
bool pbkdf2_self_test(void);


#ifdef __cplusplus
	}
#endif

#endif // _PBKDF2_H_
