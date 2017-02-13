////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017 Lightfactor, LLC. All rights reserved.
//
// Author:		  Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified: 02/12/2017
//
////////////////////////////////////////////////////////////////////////////////

#include "cryptovium.h"
#include "cryptovium_tests.h"
#include <stdio.h>
#include <string.h>


static uint8_t attestationCert[] =
{ 0x30, 0x82, 0x01, 0x70, 0x30, 0x82, 0x01, 0x16, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
0xd3, 0x6a, 0x68, 0xd3, 0x7d, 0x84, 0x6b, 0x0f, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
0x3d, 0x04, 0x03, 0x02, 0x30, 0x34, 0x31, 0x32, 0x30, 0x30, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
0x29, 0x4c, 0x69, 0x67, 0x68, 0x74, 0x66, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x55, 0x32, 0x46,
0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x20, 0x53, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x20,
0x32, 0x30, 0x31, 0x36, 0x30, 0x31, 0x30, 0x36, 0x30, 0x31, 0x30, 0x20, 0x17, 0x0d, 0x31, 0x36,
0x30, 0x31, 0x30, 0x36, 0x31, 0x34, 0x33, 0x34, 0x30, 0x34, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x36,
0x36, 0x30, 0x31, 0x30, 0x36, 0x31, 0x34, 0x33, 0x34, 0x30, 0x34, 0x5a, 0x30, 0x1a, 0x31, 0x18,
0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x4c, 0x69, 0x67, 0x68, 0x74, 0x66, 0x61,
0x63, 0x74, 0x6f, 0x72, 0x20, 0x55, 0x32, 0x46, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
0x42, 0x00, 0x04, 0xa4, 0x5b, 0xf6, 0x95, 0x10, 0xdd, 0xff, 0x4e, 0x9d, 0x71, 0x53, 0xdc, 0x14,
0xee, 0x52, 0x5b, 0x07, 0xee, 0x36, 0x38, 0xfa, 0xbc, 0x3d, 0x8d, 0xc7, 0x2f, 0x02, 0x77, 0xf0,
0xcd, 0xbb, 0x56, 0xe4, 0xad, 0x36, 0x1f, 0x11, 0x81, 0x1e, 0x95, 0xaf, 0xa4, 0x95, 0x0d, 0x61,
0xde, 0x3d, 0xe6, 0xdd, 0x53, 0x0a, 0xdc, 0x68, 0x99, 0xa5, 0x5b, 0xd3, 0x8f, 0x84, 0xdc, 0x03,
0x29, 0x94, 0xcc, 0xa3, 0x29, 0x30, 0x27, 0x30, 0x25, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
0x82, 0xed, 0x00, 0x01, 0x01, 0x04, 0x17, 0x04, 0x15, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31,
0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x36, 0x37, 0x32, 0x30, 0x2e, 0x31, 0x2e, 0x31, 0x30, 0x0a,
0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02,
0x21, 0x00, 0xe3, 0x56, 0x1f, 0x6a, 0xa7, 0x1e, 0x22, 0xfa, 0xcb, 0x1d, 0x8f, 0x59, 0x3c, 0xde,
0x1a, 0x92, 0xbb, 0x07, 0xc4, 0xab, 0x4d, 0xf2, 0xbf, 0xc0, 0xc2, 0xf7, 0x52, 0x3e, 0xe9, 0x03,
0xba, 0x90, 0x02, 0x20, 0x70, 0x42, 0x37, 0x36, 0x32, 0xae, 0x0f, 0x65, 0xea, 0xf9, 0xb5, 0xc4,
0xc3, 0xa8, 0xe9, 0xa5, 0x50, 0x67, 0x34, 0x81, 0x09, 0xae, 0xe4, 0x44, 0x22, 0x5e, 0xf7, 0xd2,
0xcb, 0xba, 0x31, 0xa7 };

static uint8_t stream_fido_keywrap[] =
{
	// privateKey = HMAC-SHA256((appID || nonce), wrappingKey)
	// keyHandle = nonce || HMAC-SHA256((appID || privateKey), wrappingKey)

	CVM_F_SECURE_RANDOM,		// create random nonce in A
	CVM_REG32_A,

	CVM_F_HMAC_SHA256_START,	// create private key
	CVM_EXTERNAL, 0,			// (wrappingKey)

	CVM_F_HMAC_SHA256_UPDATE,
	CVM_EXTERNAL, 1,			// (appID)

	CVM_F_HMAC_SHA256_UPDATE,	// (nonce)
	CVM_REG32_A,

	CVM_F_HMAC_SHA256_FINISH,	// privateKey in C
	CVM_REG32_C,

	CVM_F_HMAC_SHA256_START,	// create mac portion of keyHandle
	CVM_EXTERNAL, 0,			// (wrappingKey)

	CVM_F_HMAC_SHA256_UPDATE,
	CVM_EXTERNAL, 1,			// (appID)

	CVM_F_HMAC_SHA256_UPDATE,	// (privateKey)
	CVM_REG32_C,

	CVM_F_HMAC_SHA256_FINISH,	// mac in B
	CVM_REG32_B,

	CVM_F_MOVE,					// output to buffer - keyHandle
	CVM_OUTPUT_BUFFER,
	CVM_REG64_AB,

	CVM_F_ECC_SECP256R1_COMPUTE_PUBLIC,	// compute publicKey - output to buffer
	CVM_OUTPUT_BUFFER,					// dst (buffer)
	CVM_REG32_C,						// src (privateKey)

	CVM_F_ZEROIZE,				// zero privateKey
	CVM_REG32_C,

	CVM_F_ZEROIZE,				// zero nonce/mac
	CVM_REG64_AB
};

static const uint8_t stream_fido_register[] =
{
	// sign
	CVM_F_SHA256_START,

	CVM_F_SHA256_UPDATE,
	CVM_IMMEDIATE, 1, 0x00,				// U2F_RFU

	CVM_F_SHA256_UPDATE,
	CVM_EXTERNAL, 0,					// appID

	CVM_F_SHA256_UPDATE,
	CVM_EXTERNAL, 1,					// challenge

	CVM_F_SHA256_UPDATE,
	CVM_EXTERNAL, 2,					// keyHandle

	CVM_F_SHA256_UPDATE,
	CVM_EXTERNAL, 3,					// publicKey

	CVM_F_SHA256_FINISH,				// hash to C
	CVM_REG32_C,

	CVM_F_ECC_SECP256R1_SIGN,
	CVM_REG64_AB,						// signature
	CVM_EXTERNAL, 4,					// attestationKey
	CVM_REG32_C,						// hash

	CVM_F_MOVE,
	CVM_OUTPUT_BUFFER,
	CVM_IMMEDIATE, 1, 0x05,				// U2F_REGISTER_ID

	CVM_F_MOVE,
	CVM_OUTPUT_BUFFER,
	CVM_EXTERNAL, 3,					// publicKey

	CVM_F_MOVE,
	CVM_OUTPUT_BUFFER,
	CVM_IMMEDIATE, 1, 64,				// keyHandle length

	CVM_F_MOVE,
	CVM_OUTPUT_BUFFER,
	CVM_EXTERNAL, 2,					// keyHandle

	CVM_F_MOVE,
	CVM_OUTPUT_BUFFER,
	CVM_EXTERNAL, 5,					// attestationCert

	CVM_F_ECC_SECP256R1_DER_ENCODE,		// DER-encoded signature
	CVM_OUTPUT_BUFFER,
	CVM_REG64_AB,

	CVM_F_ZEROIZE,						// zero used registers
	CVM_REG128_ABCD
};

static const uint8_t stream_fido_keyunwrap[] =
{
	// nonce = keyHandle[0..31]
	// keyHandleMAC = keyHandle[32..63]
	// private_key = HMAC-SHA256((appID || nonce), wrappingKey)
	// computedMAC = HMAC-SHA256((appID || privateKey), wrappingKey)
	// if (keyHandleMAC != computedMAC) return CVM_ERR_COMPARE_FAILED

	CVM_F_MOVE,					// move keyHandle to AB
	CVM_REG64_AB,
	CVM_EXTERNAL, 0,			// keyHandle

	CVM_F_HMAC_SHA256_START,	// re-create private key
	CVM_EXTERNAL, 1,			// secret (wrappingKey)

	CVM_F_HMAC_SHA256_UPDATE,
	CVM_EXTERNAL, 2,			// appID

	CVM_F_HMAC_SHA256_UPDATE,
	CVM_REG32_A,				// nonce

	CVM_F_HMAC_SHA256_FINISH,
	CVM_REG32_C,				// privateKey in C

	CVM_F_HMAC_SHA256_START,	// compute MAC
	CVM_EXTERNAL, 1,			// secret (wrappingKey)

	CVM_F_HMAC_SHA256_UPDATE,
	CVM_EXTERNAL, 2,			// appID

	CVM_F_HMAC_SHA256_UPDATE,
	CVM_REG32_C,				// privateKey

	CVM_F_HMAC_SHA256_FINISH,
	CVM_REG32_D,				// computedMAC in D

	CVM_F_COMPARE,				// compare MAC's
	CVM_REG32_B,
	CVM_REG32_D,
};

static const uint8_t stream_fido_authenticate[] =
{
	// sign
	CVM_F_SHA256_START,

	CVM_F_SHA256_UPDATE,
	CVM_EXTERNAL, 0,					// appID

	CVM_F_SHA256_UPDATE,
	CVM_IMMEDIATE, 1, 0x01,				// U2F_AUTH_FLAG_TUP

	CVM_F_SHA256_UPDATE,
	CVM_EXTERNAL, 1,					// counter

	CVM_F_SHA256_UPDATE,
	CVM_EXTERNAL, 2,					// challenge

	CVM_F_SHA256_FINISH,				// hash to D
	CVM_REG32_D,

	CVM_F_ECC_SECP256R1_SIGN,
	CVM_REG64_AB,						// signature
	CVM_REG32_C,						// privateKey
	CVM_REG32_D,						// hash

	CVM_F_ZEROIZE,						// zero used registers
	CVM_REG64_CD,

	CVM_F_MOVE,
	CVM_OUTPUT_BUFFER,
	CVM_IMMEDIATE, 1, 0x01,				// U2F_AUTH_FLAG_TUP

	CVM_F_MOVE,
	CVM_OUTPUT_BUFFER,
	CVM_EXTERNAL, 1,					// counter

	CVM_F_ECC_SECP256R1_DER_ENCODE,		// DER-encoded signature
	CVM_OUTPUT_BUFFER,
	CVM_REG64_AB,

	CVM_F_ZEROIZE,						// zero used registers
	CVM_REG64_AB
};


static uint8_t wrappingKey[32] = { 0 };
static uint8_t appID[32] = { 0 };
static uint8_t challenge[32] = { 0 };
static uint8_t attestationKey[32] = { 0 };
static uint8_t keyHandlePublicKey[64 + 65];
static uint32_t counter = 0;


////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_fidou2f_register()
{
	const uint8_t	stream_rnd[] = { CVM_F_SECURE_RANDOM, CVM_REG32_A, CVM_F_MOVE, CVM_OUTPUT_BUFFER, CVM_REG32_A, CVM_F_ZEROIZE, CVM_REG32_A };
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// get random wrappingKey
	ret = cvm_execute_stream(stream_rnd, sizeof(stream_rnd), wrappingKey, sizeof(wrappingKey), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, wrappingKey, sz_buffer);

	// get random appID
	ret = cvm_execute_stream(stream_rnd, sizeof(stream_rnd), appID, sizeof(appID), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, appID, sz_buffer);

	// get random challenge
	ret = cvm_execute_stream(stream_rnd, sizeof(stream_rnd), challenge, sizeof(challenge), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, challenge, sz_buffer);

	// get random attestationKey
	ret = cvm_execute_stream(stream_rnd, sizeof(stream_rnd), attestationKey, sizeof(attestationKey), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, attestationKey, sz_buffer);

	// phase 1 - key wrap
	// import externals (read-only)
	ret = cvm_import_external(wrappingKey, sizeof(wrappingKey));			// index 0 (wrappingKey)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(appID, sizeof(appID));						// index 1 (appID)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	
	ret = cvm_execute_stream(stream_fido_keywrap, sizeof(stream_fido_keywrap), keyHandlePublicKey, sizeof(keyHandlePublicKey), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, keyHandlePublicKey, sz_buffer);

	// phase 2 - register
	// import externals (read-only)
	ret = cvm_import_external(appID, sizeof(appID));						// index 0 (appID)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(challenge, sizeof(challenge));				// index 1 (challenge)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(keyHandlePublicKey, 64);						// index 2 (keyHandle)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(&keyHandlePublicKey[64], 65);					// index 3 (publicKey)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(attestationKey, sizeof(attestationKey));		// index 4 (attestationKey)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(attestationCert, sizeof(attestationCert));	// index 5 (attestationCert)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_fido_register, sizeof(stream_fido_register), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_fidou2f_register()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_fidou2f_authenticate()
{
	const uint8_t	stream_rnd[] = { CVM_F_SECURE_RANDOM, CVM_REG32_A, CVM_F_MOVE, CVM_OUTPUT_BUFFER, CVM_REG32_A, CVM_F_ZEROIZE, CVM_REG32_A };
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// get random challenge
	ret = cvm_execute_stream(stream_rnd, sizeof(stream_rnd), challenge, sizeof(challenge), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, challenge, sz_buffer);

	// phase 1 - key unwrap
	// import externals (read-only)
	ret = cvm_import_external(keyHandlePublicKey, 64);						// index 0 (keyHandle)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(wrappingKey, sizeof(wrappingKey));			// index 1 (wrappingKey)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(appID, sizeof(appID));						// index 2 (appID)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_fido_keyunwrap, sizeof(stream_fido_keyunwrap), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	// phase 2 - authenticate
	counter++;

	// import externals (read-only)
	ret = cvm_import_external(appID, sizeof(appID));						// index 0 (appID)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external((uint8_t*)&counter, sizeof(counter));			// index 1 (counter)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(challenge, sizeof(challenge));				// index 2 (challenge)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_fido_authenticate, sizeof(stream_fido_authenticate), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_fidou2f_authenticate()::success\n");
	return ret;
}
