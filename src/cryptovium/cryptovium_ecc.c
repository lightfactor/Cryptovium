////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017 Lightfactor, LLC. All rights reserved.
//
// Author:		  Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified: 02/13/2017
//
////////////////////////////////////////////////////////////////////////////////

#include "include_windows.h"
#include "cryptovium.h"
#include "compare_ct.h"
#include "zeroize.h"
#include "curve25519.h"
#include "curve_sigs.h"
#include "uECC.h"
#include "sha256.h"
#include <stdint.h>
#include <stdbool.h>


#define ECC_SECP256R1_PRIVATE_KEY_SIZE      32
#define ECC_SECP256R1_PUBLIC_KEY_SIZE       65
#define ECC_SECP256R1_SHARED_SECRET_SIZE    32
#define ECC_SECP256R1_RAW_SIG_SIZE			64
#define ECC_SECP256R1_MIN_DER_SIG_SIZE      70
#define ECC_SECP256R1_MAX_DER_SIG_SIZE      72

#define EC_POINT_UNCOMPRESSED   (0x04)
#define ASN1_SEQUENCE			(0x30)
#define ASN1_INTEGER			(0x02)


////////////////////////////////////////////////////////////////////////////////
// forward declarations
////////////////////////////////////////////////////////////////////////////////
extern cvm_error_t _cvm_check_dst_op_size(cvm_param_t* op, uint8_t sz);
void _encode_sig_der(uint8_t signature_raw[ECC_SECP256R1_RAW_SIG_SIZE], uint8_t signature_der[ECC_SECP256R1_MAX_DER_SIG_SIZE], uint32_t* psz_signature_der);
int _decode_sig_der(uint8_t signature_der[ECC_SECP256R1_MAX_DER_SIG_SIZE], uint32_t sz_signature_der, uint8_t signature_raw[ECC_SECP256R1_RAW_SIG_SIZE]);


////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_ecc_curve25519_clamp_secret(cvm_param_t* op_secret)
{
	if ((op_secret->op == CVM_IMM_BUF) || (op_secret->op == CVM_EXTERNAL))
		return CVM_ERR_INVALID_OPERAND;

	// check secret size
	if (op_secret->sz != CURVE25519_KEY_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	curve25519_prepare_secret_key(op_secret->ptr);

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_ecc_curve25519_compute_public_key(cvm_param_t* op_public, cvm_param_t* op_secret)
{
	cvm_error_t	ret;

	// check secret size
	if (op_secret->sz != CURVE25519_KEY_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// check public size
	ret = _cvm_check_dst_op_size(op_public, CURVE25519_KEY_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	// make sure secret is not zero! (a valid C25519 point)
	if (compare_constant_time_zero(op_secret->ptr, CURVE25519_KEY_SIZE) == true)
		return CVM_ERR_ZERO_DATA;

	// compute the public key
	curve25519_scalarmult_base(op_public->ptr, op_secret->ptr);

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_ecc_curve25519_compute_shared_secret(cvm_param_t* op_shared, cvm_param_t* op_secret, cvm_param_t* op_public)
{
	cvm_error_t	ret;

	// check secret size
	if (op_secret->sz != CURVE25519_KEY_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// check public size
	if (op_public->sz != CURVE25519_KEY_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// check shared size
	ret = _cvm_check_dst_op_size(op_shared, CURVE25519_KEY_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	// make sure secret is not zero! (a valid C25519 point)
	if (compare_constant_time_zero(op_secret->ptr, CURVE25519_KEY_SIZE) == true)
		return CVM_ERR_ZERO_DATA;

	// make sure public is not zero! (a valid C25519 point)
	if (compare_constant_time_zero(op_public->ptr, CURVE25519_KEY_SIZE) == true)
		return CVM_ERR_ZERO_DATA;

	// compute the shared secret
	curve25519_scalarmult(op_shared->ptr, op_secret->ptr, op_public->ptr);

	// make sure shared secret is not zero! (a valid C25519 point)
	if (compare_constant_time_zero(op_shared->ptr, CURVE25519_KEY_SIZE) == true)
		return CVM_ERR_ZERO_DATA;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_ecc_curve25519_sign(cvm_param_t* op_signature, cvm_param_t* op_secret, cvm_param_t* op_data)
{
	cvm_error_t		ret;
	uint8_t			random[64];
	BOOL			b;
	HCRYPTPROV		hCryptProvider;

	// check secret size
	if (op_secret->sz != CURVE25519_KEY_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// make sure secret is not zero! (a valid C25519 point)
	if (compare_constant_time_zero(op_secret->ptr, CURVE25519_KEY_SIZE) == true)
		return CVM_ERR_ZERO_DATA;

	// check signature size
	ret = _cvm_check_dst_op_size(op_signature, 64);
	if (ret != CVM_ERR_NONE) return ret;

	if (!CryptAcquireContextW(&hCryptProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		return CVM_ERR_NO_CONTEXT;

	b = CryptGenRandom(hCryptProvider, sizeof(random), random);
	CryptReleaseContext(hCryptProvider, 0);
	
	if (b == FALSE)
		return CVM_ERR_ENTROPY_SOURCE_FAILED;

	if (curve25519_sign(op_signature->ptr, op_secret->ptr, op_data->ptr, op_data->sz, random) != 0)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	zeroize(random, sizeof(random));

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_ecc_curve25519_verify(cvm_param_t* op_signature, cvm_param_t* op_public, cvm_param_t* op_data)
{
	// check signature size
	if (op_signature->sz != 64)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// check public key size
	if (op_public->sz != CURVE25519_KEY_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	if (curve25519_verify(op_signature->ptr, op_public->ptr, op_data->ptr, op_data->sz) != 0)
		return CVM_ERR_SIGNATURE_VERIFY_FAILED;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_ecc_secp256r1_compute_public_key(cvm_param_t* op_public, cvm_param_t* op_secret)
{
	cvm_error_t	ret;

	// check secret size
	if (op_secret->sz != ECC_SECP256R1_PRIVATE_KEY_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// check public size
	ret = _cvm_check_dst_op_size(op_public, ECC_SECP256R1_PUBLIC_KEY_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	// make sure secret is not zero!
	if (compare_constant_time_zero(op_secret->ptr, ECC_SECP256R1_PRIVATE_KEY_SIZE) == true)
		return CVM_ERR_ZERO_DATA;

	// compute the public key
	if (!uECC_compute_public_key(op_secret->ptr, op_public->ptr, uECC_secp256r1()))
		return CVM_ERR_UNKNOWN;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_ecc_secp256r1_compute_shared_secret(cvm_param_t* op_shared, cvm_param_t* op_secret, cvm_param_t* op_public)
{
	cvm_error_t	ret;

	// check secret size
	if (op_secret->sz != ECC_SECP256R1_PRIVATE_KEY_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// check public size
	if (op_secret->sz != ECC_SECP256R1_PUBLIC_KEY_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// check shared size
	ret = _cvm_check_dst_op_size(op_shared, ECC_SECP256R1_SHARED_SECRET_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	// make sure secret is not zero!
	if (compare_constant_time_zero(op_secret->ptr, ECC_SECP256R1_PRIVATE_KEY_SIZE) == true)
		return CVM_ERR_ZERO_DATA;

	// make sure public is not zero!
	if (compare_constant_time_zero(op_public->ptr, ECC_SECP256R1_PUBLIC_KEY_SIZE) == true)
		return CVM_ERR_ZERO_DATA;

	// compute the shared secret
	if (!uECC_shared_secret(op_public->ptr, op_secret->ptr, op_shared->ptr, uECC_secp256r1()))
		return CVM_ERR_UNKNOWN;

	// make sure shared secret is not zero!
	if (compare_constant_time_zero(op_shared->ptr, ECC_SECP256R1_SHARED_SECRET_SIZE) == true)
		return CVM_ERR_ZERO_DATA;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_ecc_secp256r1_sign(cvm_param_t* op_signature, cvm_param_t* op_secret, cvm_param_t* op_hash)
{
	cvm_error_t	ret;

	// check secret size
	if (op_secret->sz != ECC_SECP256R1_PRIVATE_KEY_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// check hash size
	if (op_hash->sz != SHA256_HASH_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// make sure secret is not zero!
	if (compare_constant_time_zero(op_secret->ptr, ECC_SECP256R1_PRIVATE_KEY_SIZE) == true)
		return CVM_ERR_ZERO_DATA;

	// check signature size
	ret = _cvm_check_dst_op_size(op_signature, ECC_SECP256R1_RAW_SIG_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	if (!uECC_sign(op_secret->ptr, op_hash->ptr, op_hash->sz, op_signature->ptr, uECC_secp256r1()))
		return CVM_ERR_UNKNOWN;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_ecc_secp256r1_verify(cvm_param_t* op_signature, cvm_param_t* op_public, cvm_param_t* op_hash)
{
	// check signature size
	if (op_signature->sz != ECC_SECP256R1_RAW_SIG_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// check public key size
	if (op_public->sz != ECC_SECP256R1_PUBLIC_KEY_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// check hash size
	if (op_hash->sz != SHA256_HASH_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	if (!uECC_verify(op_public->ptr, op_hash->ptr, op_hash->sz, op_signature->ptr, uECC_secp256r1()))
		return CVM_ERR_SIGNATURE_VERIFY_FAILED;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_ecc_secp256r1_der_encode(cvm_param_t* op_signature_der, cvm_param_t* op_signature)
{
	uint8_t		der[ECC_SECP256R1_MAX_DER_SIG_SIZE];
	uint32_t	sz_der;
	cvm_error_t	ret;

	// check signature size
	if (op_signature->sz != ECC_SECP256R1_RAW_SIG_SIZE)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	_encode_sig_der(op_signature->ptr, der, &sz_der);

	// check sz_der
	ret = _cvm_check_dst_op_size(op_signature_der, sz_der);
	if (ret != CVM_ERR_NONE) return ret;

	memcpy(op_signature_der->ptr, der, sz_der);
	zeroize(der, sizeof(der));
	zeroize(&sz_der, sizeof(sz_der));

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_ecc_secp256r1_der_decode(cvm_param_t* op_signature, cvm_param_t* op_signature_der)
{
	cvm_error_t	ret;

	// check der size
	if ((op_signature_der->sz < ECC_SECP256R1_MIN_DER_SIG_SIZE) || (op_signature_der->sz > ECC_SECP256R1_MAX_DER_SIG_SIZE))
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	// check shared size
	ret = _cvm_check_dst_op_size(op_signature, ECC_SECP256R1_SHARED_SECRET_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	if (!_decode_sig_der(op_signature_der->ptr, op_signature_der->sz, op_signature->ptr))
		return CVM_ERR_DECODE_FAILED;

	return CVM_ERR_NONE;
}


////////////////////////////////////////////////////////////////////////////////
void _encode_sig_der(uint8_t signature_raw[ECC_SECP256R1_RAW_SIG_SIZE],	uint8_t signature_der[ECC_SECP256R1_MAX_DER_SIG_SIZE],	uint32_t* psz_signature_der)
{
	uint8_t		lr, ls;

	// prepare R
	signature_der[2] = ASN1_INTEGER;

	// pad R
	if (signature_raw[0] & 0x80)   // test MSB
	{
		lr = 33;
		signature_der[4] = 0x00;
		memcpy(&signature_der[5], signature_raw, 32);
	}
	else
	{
		lr = 32;
		memcpy(&signature_der[4], signature_raw, 32);
	}

	signature_der[3] = lr;

	// prepare S
	signature_der[4 + lr] = ASN1_INTEGER;

	// pad S
	if (signature_raw[32] & 0x80)   // test MSB
	{
		ls = 33;
		signature_der[4 + lr + 2] = 0x00;
		memcpy(&signature_der[4 + lr + 2 + 1], &signature_raw[32], 32);
	}
	else
	{
		ls = 32;
		memcpy(&signature_der[4 + lr + 2], &signature_raw[32], 32);
	}

	signature_der[4 + lr + 1] = ls;

	// prepare header
	signature_der[0] = ASN1_SEQUENCE;
	signature_der[1] = lr + ls + 4;

	// return sz_signature_der
	*psz_signature_der = lr + ls + 6;
}

////////////////////////////////////////////////////////////////////////////////
int _decode_sig_der(uint8_t signature_der[ECC_SECP256R1_MAX_DER_SIG_SIZE],	uint32_t sz_signature_der,	uint8_t signature_raw[ECC_SECP256R1_RAW_SIG_SIZE])
{
	uint32_t lr, ls;
	uint8_t* pr;
	uint8_t* ps;

	if ((sz_signature_der < 8) || (sz_signature_der > ECC_SECP256R1_MAX_DER_SIG_SIZE))
		return 0;

	if (signature_der[0] != ASN1_SEQUENCE)
		return 0;

	if (signature_der[1] != (sz_signature_der - 2))      // ASN1_SEQUENCE length
		return 0;

	if (signature_der[2] != ASN1_INTEGER)
		return 0;

	lr = signature_der[3];                  // ASN1_INTEGER length
	pr = (uint8_t*)&signature_der[4];

	if ((lr == 0) || (lr > 33))
		return 0;

	if (signature_der[4 + lr] != ASN1_INTEGER)
		return 0;

	ls = signature_der[4 + lr + 1];         // ASN1_INTEGER length
	ps = (uint8_t*)&signature_der[4 + lr + 2];

	if ((ls == 0) || (ls > 33))
		return 0;

	if (lr == 33)
	{
		if (pr[0] == 0x00)
		{
			pr++;
			lr--;
		}
		else
		{
			return 0;   // invalid
		}
	}

	if (ls == 33)
	{
		if (ps[0] == 0x00)
		{
			ps++;
			ls--;
		}
		else
		{
			return 0;   // invalid
		}
	}

	memset(signature_raw, 0, 64);

	memcpy(signature_raw + (32 - lr), pr, lr);
	memcpy(signature_raw + 32 + (32 - ls), ps, ls);

	return 1;
}
