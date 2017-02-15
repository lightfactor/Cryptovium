////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017 Lightfactor, LLC. All rights reserved.
//
// Author:		  Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified: 02/15/2017
//
////////////////////////////////////////////////////////////////////////////////


#ifndef _CRYPTOVIUM_H_
#define _CRYPTOVIUM_H_

#include "conf_cryptovium.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#pragma pack(push, 1)

	typedef struct
	{
		uint8_t		a[32];
		uint8_t		b[32];
		uint8_t		c[32];
		uint8_t		d[32];
		uint8_t		e[32];
		uint8_t		f[32];
		uint8_t		g[32];
		uint8_t		h[32];
	} cvm_regs32_t;

	typedef struct
	{
		uint8_t		ab[64];
		uint8_t		cd[64];
		uint8_t		ef[64];
		uint8_t		gh[64];
	} cvm_regs64_t;

	typedef struct
	{
		uint8_t		abcd[128];
		uint8_t		efgh[128];
	} cvm_regs128_t;

	typedef union
	{
		cvm_regs32_t	regs32;
		cvm_regs64_t	regs64;
		cvm_regs128_t	regs128;
	} cvm_regs_t;

#pragma pack(pop)


typedef enum
{
	CVM_ERR_NONE,
	CVM_ERR_END_OF_STREAM,
	CVM_ERR_INVALID_REG,
	CVM_ERR_INVALID_OPERAND,
	CVM_ERR_INVALID_OPERAND_LENGTH,
	CVM_ERR_ENTROPY_SOURCE_FAILED,
	CVM_ERR_ZERO_DATA,
	CVM_ERR_NO_CONTEXT,
	CVM_ERR_NOT_IMPLEMENTED,
	CVM_ERR_BUFFER_OVERFLOW,
	CVM_ERR_COMPARE_FAILED,
	CVM_ERR_SIGNATURE_VERIFY_FAILED,
	CVM_ERR_DECODE_FAILED,
	CVM_ERR_NOT_INITIALIZED,
	CVM_ERR_IMM_EXT_OVERFLOW,
	CVM_ERR_INVALID_IMM_EXT,
	CVM_ERR_UNKNOWN
} cvm_error_t;

typedef enum
{
	CVM_F_RESERVED = 0x00,

	// intrinsics
	CVM_F_MOVE = 0x01,								// 2 operands - DST, SRC
	CVM_F_COMPARE = 0x02,							// 2 operands
	CVM_F_ZEROIZE = 0x03,							// 1 operand, DST=reg only

	// RND functions
	CVM_F_SECURE_RANDOM = 0x04,						// 1 operand, DST=reg only

	// SHA functions
	CVM_F_SHA256 = 0x10,							// 2 operands, DST, SRC
	CVM_F_SHA256_START = 0x11,						// 0 operands (initializes SHA256 context)
	CVM_F_SHA256_UPDATE = 0x12,						// 1 operand, SRC
	CVM_F_SHA256_FINISH = 0x13,						// 1 operand, DST
	CVM_F_SHA512 = 0x14,							// 2 operands, DST, SRC
	CVM_F_SHA512_START = 0x15,						// 0 operands (initializes SHA512 context)
	CVM_F_SHA512_UPDATE = 0x16,						// 1 operand, SRC
	CVM_F_SHA512_FINISH = 0x17,						// 1 operand, DST
	CVM_F_HMAC_SHA256 = 0x18,						// 3 operands, DST, SECRET, SRC
	CVM_F_HMAC_SHA256_START = 0x19,					// 1 operand, SECRET
	CVM_F_HMAC_SHA256_UPDATE = 0x1a,				// 1 operand, SRC
	CVM_F_HMAC_SHA256_FINISH = 0x1b,				// 1 operand, DST

	// ECC functions
	CVM_F_ECC_CURVE25519_CLAMP_SECRET = 0x30,		// 1 operand, KEY=reg only
	CVM_F_ECC_CURVE25519_COMPUTE_PUBLIC = 0x31,		// 2 operands, PUBLIC, SECRET
	CVM_F_ECC_CURVE25519_COMPUTE_SHARED = 0x32,		// 3 operands, SHARED, SECRET, PUBLIC
	CVM_F_ECC_CURVE25519_SIGN = 0x33,				// 3 operands, SIGNATURE, SECRET, DATA
	CVM_F_ECC_CURVE25519_VERIFY = 0x34,				// 3 operands, SIGNATURE, PUBLIC, DATA
	//CVM_F_ECC_ED25519_CLAMP_SECRET = 0x35,		// 1 operand, KEY=reg only
	//CVM_F_ECC_ED25519_COMPUTE_PUBLIC = 0x36,		// 2 operands, PUBLIC, SECRET
	//CVM_F_ECC_ED25519_SIGN = 0x37,				// 3 operands, SIGNATURE, SECRET, DATA
	//CVM_F_ECC_ED25519_VERIFY = 0x38,				// 3 operands, SIGNATURE, PUBLIC, DATA

	CVM_F_ECC_SECP256R1_COMPUTE_PUBLIC = 0x40,		// 2 operands, PUBLIC, SECRET
	CVM_F_ECC_SECP256R1_COMPUTE_SHARED = 0x41,		// 3 operands, SHARED, SECRET, PUBLIC
	CVM_F_ECC_SECP256R1_SIGN = 0x42,				// 3 operands, SIGNATURE, SECRET, HASH
	CVM_F_ECC_SECP256R1_VERIFY = 0x43,				// 3 operands, SIGNATURE, PUBLIC, HASH
	CVM_F_ECC_SECP256R1_DER_ENCODE = 0x44,			// 2 operands, SIGNATURE_DER, SIGNATURE
	CVM_F_ECC_SECP256R1_DER_DECODE = 0x45,			// 2 operands, SIGNATURE, SIGNATURE_DER

	// KDF functions
	CVM_F_HKDF = 0xf0,								// 5 operands, OUTPUT, SALT, KEY, INFO, START_OFFSET
	CVM_F_PBKDF2_SHA256_HMAC = 0xf1,				// 4 operands, DK, P, SALT, C
} cvm_func_t;


typedef enum
{
	CVM_IMM_BUF = 0x00,								// do not use CVM_IMM_BUF directly in an execution stream - use helper defines below
	CVM_REG32_A = 0x01,
	CVM_REG32_B = 0x02,
	CVM_REG32_C = 0x04,
	CVM_REG32_D = 0x08,
	CVM_REG32_E = 0x10,
	CVM_REG32_F = 0x20,
	CVM_REG32_G = 0x40,
	CVM_REG32_H = 0x80,
	CVM_REG64_AB = CVM_REG32_A | CVM_REG32_B,
	CVM_REG64_CD = CVM_REG32_C | CVM_REG32_D,
	CVM_REG64_EF = CVM_REG32_E | CVM_REG32_F,
	CVM_REG64_GH = CVM_REG32_G | CVM_REG32_H,
	CVM_REG128_ABCD = CVM_REG32_A | CVM_REG32_B | CVM_REG32_C | CVM_REG32_D,
	CVM_REG128_EFGH = CVM_REG32_E | CVM_REG32_F | CVM_REG32_G | CVM_REG32_H,
	CVM_EXTERNAL = 0xff
} cvm_operand_t;

// operand encoding helpers - use these instead of CVM_IMM_BUF directly
#define CVM_IMMEDIATE		CVM_IMM_BUF
#define CVM_OUTPUT_BUFFER	CVM_IMM_BUF, 0


typedef struct
{
	cvm_operand_t		op;
	uint32_t			sz;
	uint8_t*			ptr;
} cvm_param_t;


cvm_error_t cvm_init(void);
cvm_error_t cvm_import_external(const uint8_t* pdata, uint32_t sz_data);
cvm_error_t cvm_execute_stream(const uint8_t* pstream, uint32_t sz_stream, uint8_t* pbuffer, uint32_t sz_buffer, uint32_t* psz_out);
void cvm_zeroize(void);
cvm_regs_t* cvm_get_regs(void);	// for unit test dump

#ifdef __cplusplus
}
#endif

#endif // _CRYPTOVIUM_H_
