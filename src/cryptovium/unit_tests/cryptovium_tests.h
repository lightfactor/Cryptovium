////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017 Lightfactor, LLC. All rights reserved.
//
// Author:		  Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified: 02/10/2017
//
////////////////////////////////////////////////////////////////////////////////


#ifndef _CRYPTOVIUM_TESTS_H_
#define _CRYPTOVIUM_TESTS_H_

#include "cryptovium.h"

#ifdef __cplusplus
extern "C" {
#endif


	// EXECUTE ALL TESTS
cvm_error_t cvm_ut_all(void);


cvm_error_t _cvm_ut_dump_error(cvm_error_t err, uint8_t* buffer, uint32_t sz_buffer);

// SHA unit tests
cvm_error_t cvm_ut_sha256_v1(void);
cvm_error_t cvm_ut_sha256_v2(void);
cvm_error_t cvm_ut_sha256_v3(void);
cvm_error_t cvm_ut_sha256_v1_inc(void);
cvm_error_t cvm_ut_sha256_v2_inc(void);
cvm_error_t cvm_ut_sha256_v3_inc(void);
cvm_error_t cvm_ut_sha512_v1(void);
cvm_error_t cvm_ut_sha512_v2(void);
cvm_error_t cvm_ut_sha512_v3(void);
cvm_error_t cvm_ut_sha512_v1_inc(void);
cvm_error_t cvm_ut_sha512_v2_inc(void);
cvm_error_t cvm_ut_sha512_v3_inc(void);
cvm_error_t cvm_ut_hmac_sha256_v1(void);
cvm_error_t cvm_ut_hmac_sha256_v2(void);
cvm_error_t cvm_ut_hmac_sha256_v3(void);
cvm_error_t cvm_ut_hmac_sha256_v4(void);
cvm_error_t cvm_ut_hmac_sha256_v1_inc(void);
cvm_error_t cvm_ut_hmac_sha256_v2_inc(void);
cvm_error_t cvm_ut_hmac_sha256_v3_inc(void);
cvm_error_t cvm_ut_hmac_sha256_v4_inc(void);

// FIDO unit tests
cvm_error_t cvm_ut_fidou2f_register(void);
cvm_error_t cvm_ut_fidou2f_authenticate(void);


#ifdef __cplusplus
}
#endif

#endif // _CRYPTOVIUM_TESTS_H_
