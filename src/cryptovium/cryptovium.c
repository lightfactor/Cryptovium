////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017 Lightfactor, LLC. All rights reserved.
//
// Author:		  Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified: 02/12/2017
//
////////////////////////////////////////////////////////////////////////////////

#include "cryptovium.h"
#include "compare_ct.h"
#include "zeroize.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>


typedef struct  
{
	uint32_t			sz;
	uint8_t*			ptr;
} cvm_imm_ext_t;


static cvm_regs_t		_regs;
static cvm_imm_ext_t	_imm_exts[CVM_MAX_IMMEDIATE_EXTERNALS];
static uint32_t			_imm_exts_count = 0;

static bool				_initialized = false;
static uint32_t			_stream_pos = 0;
static uint8_t*			_pbuffer = NULL;
static uint32_t			_sz_buffer = 0;
static uint32_t			_buffer_pos = 0;


#define CVM_PARAMS_MAX		(6)


////////////////////////////////////////////////////////////////////////////////
// forward declarations
////////////////////////////////////////////////////////////////////////////////
cvm_error_t _tokenizer_get_byte(const uint8_t* pstream, uint32_t sz_stream, uint8_t* u8);
cvm_error_t _tokenizer_skip_bytes(const uint8_t* pstream, uint32_t sz_stream, uint32_t skip);
cvm_error_t _tokenizer_get_params(const uint8_t* pstream, uint32_t sz_stream, cvm_param_t* params, uint32_t n_params);

cvm_error_t _cvm_check_dst_op_size(cvm_param_t* op, uint32_t sz);

cvm_error_t cvm_f_move(cvm_param_t* op_dst, cvm_param_t* op_src);
cvm_error_t cvm_f_compare(cvm_param_t* op1, cvm_param_t* op2);
cvm_error_t cvm_f_zeroize(cvm_param_t* op_dst);

cvm_error_t cvm_f_secure_random(cvm_param_t* op_dst);

cvm_error_t cvm_f_sha256(cvm_param_t* op_hash, cvm_param_t* op_data);
cvm_error_t cvm_f_sha256_start(void);
cvm_error_t cvm_f_sha256_update(cvm_param_t* op_data);
cvm_error_t cvm_f_sha256_finish(cvm_param_t* op_hash);
cvm_error_t cvm_f_sha512(cvm_param_t* op_hash, cvm_param_t* op_data);
cvm_error_t cvm_f_sha512_start(void);
cvm_error_t cvm_f_sha512_update(cvm_param_t* op_data);
cvm_error_t cvm_f_sha512_finish(cvm_param_t* op_hash);
cvm_error_t cvm_f_hmac_sha256(cvm_param_t* op_hash, cvm_param_t* op_secret, cvm_param_t* op_data);
cvm_error_t cvm_f_hmac_sha256_start(cvm_param_t* op_secret);
cvm_error_t cvm_f_hmac_sha256_update(cvm_param_t* op_data);
cvm_error_t cvm_f_hmac_sha256_finish(cvm_param_t* op_hash);

cvm_error_t cvm_f_ecc_curve25519_clamp_secret(cvm_param_t* op_secret);
cvm_error_t cvm_f_ecc_curve25519_compute_public_key(cvm_param_t* op_public, cvm_param_t* op_secret);
cvm_error_t cvm_f_ecc_curve25519_compute_shared_secret(cvm_param_t* op_shared, cvm_param_t* op_secret, cvm_param_t* op_public);
cvm_error_t cvm_f_ecc_curve25519_sign(cvm_param_t* op_signature, cvm_param_t* op_secret, cvm_param_t* op_data);
cvm_error_t cvm_f_ecc_curve25519_verify(cvm_param_t* op_signature, cvm_param_t* op_public, cvm_param_t* op_data);

cvm_error_t cvm_f_ecc_secp256r1_compute_public_key(cvm_param_t* op_public, cvm_param_t* op_secret);
cvm_error_t cvm_f_ecc_secp256r1_compute_shared_secret(cvm_param_t* op_shared, cvm_param_t* op_secret, cvm_param_t* op_public);
cvm_error_t cvm_f_ecc_secp256r1_sign(cvm_param_t* op_signature, cvm_param_t* op_secret, cvm_param_t* op_hash);
cvm_error_t cvm_f_ecc_secp256r1_verify(cvm_param_t* op_signature, cvm_param_t* op_public, cvm_param_t* op_hash);
cvm_error_t cvm_f_ecc_secp256r1_der_encode(cvm_param_t* op_signature_der, cvm_param_t* op_signature);
cvm_error_t cvm_f_ecc_secp256r1_der_decode(cvm_param_t* op_signature, cvm_param_t* op_signature_der);

cvm_error_t cvm_f_kdf_hkdf(cvm_param_t* op_output, cvm_param_t* op_salt, cvm_param_t* op_key, cvm_param_t* op_info, cvm_param_t* op_start_offset);
cvm_error_t cvm_f_kdf_pbkdf2_sha256_hmac(cvm_param_t* op_dk, cvm_param_t* op_p, cvm_param_t* op_salt, cvm_param_t* op_c);



////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_init()
{
	zeroize(&_regs, sizeof(_regs));
	zeroize(&_imm_exts, sizeof(_imm_exts));
	_imm_exts_count = 0;

	_initialized = true;
	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_import_external(const uint8_t* pdata, uint32_t sz_data)
{
	if (_imm_exts_count >= CVM_MAX_IMMEDIATE_EXTERNALS)
		return CVM_ERR_IMM_EXT_OVERFLOW;

	_imm_exts[_imm_exts_count].ptr = (uint8_t*)pdata;
	_imm_exts[_imm_exts_count].sz = sz_data;
	_imm_exts_count++;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_execute_stream(const uint8_t* pstream, uint32_t sz_stream, uint8_t* pbuffer, uint32_t sz_buffer, uint32_t* psz_out)
{
	cvm_error_t		ret = CVM_ERR_UNKNOWN;
	cvm_func_t		func = CVM_F_RESERVED;
	cvm_param_t		params[CVM_PARAMS_MAX];

	if (!_initialized)
		return CVM_ERR_NOT_INITIALIZED;

	// reset execution state variables
	_stream_pos = 0;
	_pbuffer = pbuffer;
	_sz_buffer = sz_buffer;
	_buffer_pos = 0;

	// no output yet
	*psz_out = 0;

	zeroize(params, sizeof(params));

	while (_tokenizer_get_byte(pstream, sz_stream, (uint8_t*)&func) == CVM_ERR_NONE)
	{
		switch (func)
		{
		case CVM_F_MOVE:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 2);	// 2 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_move(&params[0], &params[1]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;

		case CVM_F_COMPARE:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 2);	// 2 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_compare(&params[0], &params[1]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;

		case CVM_F_ZEROIZE:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 1);	// 1 operand
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_zeroize(&params[0]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;

#if CRYPTOVIUM_SUPPORT_SECURE_RANDOM
		case CVM_F_SECURE_RANDOM:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 1);	// 1 operand
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_secure_random(&params[0]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_SHA256
		case CVM_F_SHA256:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 2);	// 2 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_sha256(&params[0], &params[1]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_SHA256_INCREMENTAL
		case CVM_F_SHA256_START:
			ret = cvm_f_sha256_start();
			if (ret != CVM_ERR_NONE) goto fin;
			break;

		case CVM_F_SHA256_UPDATE:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 1);	// 1 operand
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_sha256_update(&params[0]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;

		case CVM_F_SHA256_FINISH:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 1);	// 1 operand
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_sha256_finish(&params[0]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_SHA512
		case CVM_F_SHA512:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 2);	// 2 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_sha512(&params[0], &params[1]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_SHA512_INCREMENTAL
		case CVM_F_SHA512_START:
			ret = cvm_f_sha512_start();
			if (ret != CVM_ERR_NONE) goto fin;
			break;

		case CVM_F_SHA512_UPDATE:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 1);	// 1 operand
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_sha512_update(&params[0]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;

		case CVM_F_SHA512_FINISH:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 1);	// 1 operand
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_sha512_finish(&params[0]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_HMAC_SHA256
		case CVM_F_HMAC_SHA256:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 3);	// 3 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_hmac_sha256(&params[0], &params[1], &params[2]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_HMAC_SHA256_INCREMENTAL
		case CVM_F_HMAC_SHA256_START:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 1);	// 1 operand
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_hmac_sha256_start(&params[0]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;

		case CVM_F_HMAC_SHA256_UPDATE:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 1);	// 1 operand
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_hmac_sha256_update(&params[0]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;

		case CVM_F_HMAC_SHA256_FINISH:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 1);	// 1 operand
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_hmac_sha256_finish(&params[0]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_ECC_SECP256R1
		case CVM_F_ECC_SECP256R1_COMPUTE_PUBLIC:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 2);	// 2 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_ecc_secp256r1_compute_public_key(&params[0], &params[1]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;

		case CVM_F_ECC_SECP256R1_COMPUTE_SHARED:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 3);	// 3 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_ecc_secp256r1_compute_shared_secret(&params[0], &params[1], &params[2]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_ECC_SECP256R1_SIGN
		case CVM_F_ECC_SECP256R1_SIGN:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 3);	// 3 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_ecc_secp256r1_sign(&params[0], &params[1], &params[2]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_ECC_SECP256R1_VERIFY
		case CVM_F_ECC_SECP256R1_VERIFY:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 3);	// 3 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_ecc_secp256r1_verify(&params[0], &params[1], &params[2]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_ECC_SECP256R1_DER_ENCODE
		case CVM_F_ECC_SECP256R1_DER_ENCODE:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 2);	// 2 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_ecc_secp256r1_der_encode(&params[0], &params[1]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_ECC_SECP256R1_DER_DECODE
		case CVM_F_ECC_SECP256R1_DER_DECODE:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 2);	// 2 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_ecc_secp256r1_der_decode(&params[0], &params[1]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_ECC_CURVE25519
		case CVM_F_ECC_CURVE25519_CLAMP_SECRET:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 1);	// 1 operand
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_ecc_curve25519_clamp_secret(&params[0]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;

		case CVM_F_ECC_CURVE25519_COMPUTE_PUBLIC:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 2);	// 2 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_ecc_curve25519_compute_public_key(&params[0], &params[1]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;

		case CVM_F_ECC_CURVE25519_COMPUTE_SHARED:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 3);	// 3 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_ecc_curve25519_compute_shared_secret(&params[0], &params[1], &params[2]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_ECC_CURVE25519_SIGN
		case CVM_F_ECC_CURVE25519_SIGN:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 3);	// 3 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_ecc_curve25519_sign(&params[0], &params[1], &params[2]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_ECC_CURVE25519_VERIFY
		case CVM_F_ECC_CURVE25519_VERIFY:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 3);	// 3 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_ecc_curve25519_verify(&params[0], &params[1], &params[2]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_ECC_ED25519_SIGN
		//case ECC_ED25519_CLAMP_SECRET:
		//case ECC_ED25519_COMPUTE_PUBLIC_KEY:
		//case ECC_ED25519_SIGN:
#endif
#if CRYPTOVIUM_SUPPORT_ECC_ED25519_VERIFY
		//case ECC_ED25519_VERIFY:
#endif

#if CRYPTOVIUM_SUPPORT_KDF_HKDF
		case CVM_F_HKDF:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 5);	// 5 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_kdf_hkdf(&params[0], &params[1], &params[2], &params[3], &params[4]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
#if CRYPTOVIUM_SUPPORT_KDF_PBKDF2
		case CVM_F_PBKDF2_SHA256_HMAC:
			ret = _tokenizer_get_params(pstream, sz_stream, params, 5);	// 4 operands
			if (ret != CVM_ERR_NONE) goto fin;
			ret = cvm_f_kdf_pbkdf2_sha256_hmac(&params[0], &params[1], &params[2], &params[3]);
			if (ret != CVM_ERR_NONE) goto fin;
			break;
#endif
		default:
			return CVM_ERR_NOT_IMPLEMENTED;
		}
	}

fin:
	// return number of bytes in output buffer
	*psz_out = _buffer_pos;

	// clear execution state
	func = CVM_F_RESERVED;
	zeroize(params, sizeof(params));
	zeroize(&_imm_exts, sizeof(_imm_exts));
	_imm_exts_count = 0;

	return ret;
}




////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_move(cvm_param_t* op_dst, cvm_param_t* op_src)
{
	cvm_error_t ret;

	// check destination
	ret = _cvm_check_dst_op_size(op_dst, op_src->sz);
	if (ret != CVM_ERR_NONE) return ret;

	// make sure source and destination don't overlap
	if (op_dst->ptr == op_src->ptr)
		return CVM_ERR_INVALID_OPERAND_LENGTH;

	memcpy(op_dst->ptr, op_src->ptr, op_src->sz);
	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_compare(cvm_param_t* op1, cvm_param_t* op2)
{
	if (compare_constant_time(op1->ptr, op2->ptr, op2->sz) == false)
		return CVM_ERR_COMPARE_FAILED;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_zeroize(cvm_param_t* op_dst)
{
	if ((op_dst->op == CVM_IMM_BUF) || (op_dst->op == CVM_EXTERNAL))
		return CVM_ERR_INVALID_OPERAND;

	zeroize(op_dst->ptr, op_dst->sz);

	return CVM_ERR_NONE;
}




////////////////////////////////////////////////////////////////////////////////
cvm_error_t _tokenizer_get_byte(const uint8_t* pstream, uint32_t sz_stream, uint8_t* u8)
{
	if ((sz_stream - _stream_pos) == 0)
		return CVM_ERR_END_OF_STREAM;

	*u8 = pstream[_stream_pos++];
	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t _tokenizer_skip_bytes(const uint8_t* pstream, uint32_t sz_stream, uint32_t skip)
{
	if ((sz_stream - _stream_pos) < skip)
		return CVM_ERR_END_OF_STREAM;

	_stream_pos += skip;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t _tokenizer_get_params(const uint8_t* pstream, uint32_t sz_stream, cvm_param_t* params, uint32_t n_params)
{
	uint8_t tmp;

	for (uint32_t i = 0; i < n_params; ++i)
	{
		if (_tokenizer_get_byte(pstream, sz_stream, (uint8_t*)&params[i].op) != CVM_ERR_NONE)
			return CVM_ERR_END_OF_STREAM;

		if (params[i].op == CVM_IMM_BUF)
		{
			if (_tokenizer_get_byte(pstream, sz_stream, &tmp) != CVM_ERR_NONE)
				return CVM_ERR_END_OF_STREAM;

			params[i].sz = tmp;
			params[i].ptr = (uint8_t*)&pstream[_stream_pos];

			if (_tokenizer_skip_bytes(pstream, sz_stream, params[i].sz) != CVM_ERR_NONE)
				return CVM_ERR_END_OF_STREAM;
		}
		else if (params[i].op == CVM_EXTERNAL)
		{
			if (_tokenizer_get_byte(pstream, sz_stream, &tmp) != CVM_ERR_NONE)
				return CVM_ERR_END_OF_STREAM;

			if (tmp >= _imm_exts_count)
				return CVM_ERR_INVALID_IMM_EXT;

			params[i].ptr = _imm_exts[tmp].ptr;
			params[i].sz = _imm_exts[tmp].sz;
		}
		else
		{
			switch (params[i].op)
			{
			case CVM_REG32_A:
				params[i].ptr = _regs.regs32.a; params[i].sz = 32;
				break;
			case CVM_REG32_B:
				params[i].ptr = _regs.regs32.b; params[i].sz = 32;
				break;
			case CVM_REG32_C:
				params[i].ptr = _regs.regs32.c; params[i].sz = 32;
				break;
			case CVM_REG32_D:
				params[i].ptr = _regs.regs32.d; params[i].sz = 32;
				break;
			case CVM_REG32_E:
				params[i].ptr = _regs.regs32.e; params[i].sz = 32;
				break;
			case CVM_REG32_F:
				params[i].ptr = _regs.regs32.f; params[i].sz = 32;
				break;
			case CVM_REG32_G:
				params[i].ptr = _regs.regs32.g; params[i].sz = 32;
				break;
			case CVM_REG32_H:
				params[i].ptr = _regs.regs32.h; params[i].sz = 32;
				break;
			case CVM_REG64_AB:
				params[i].ptr = _regs.regs64.ab; params[i].sz = 64;
				break;
			case CVM_REG64_CD:
				params[i].ptr = _regs.regs64.cd; params[i].sz = 64;
				break;
			case CVM_REG64_EF:
				params[i].ptr = _regs.regs64.ef; params[i].sz = 64;
				break;
			case CVM_REG64_GH:
				params[i].ptr = _regs.regs64.gh; params[i].sz = 64;
				break;
			case CVM_REG128_ABCD:
				params[i].ptr = _regs.regs128.abcd; params[i].sz = 128;
				break;
			case CVM_REG128_EFGH:
				params[i].ptr = _regs.regs128.efgh; params[i].sz = 128;
				break;
			default:
				return CVM_ERR_INVALID_REG;
			}
		}
	}

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t _cryptovm_get_buffer(uint8_t** ppbuffer, uint32_t sz)
{
	if ((_pbuffer == NULL) || ((_sz_buffer - _buffer_pos) < sz))
		return CVM_ERR_BUFFER_OVERFLOW;

	*ppbuffer = &_pbuffer[_buffer_pos];
	_buffer_pos += sz;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t _cvm_check_dst_op_size(cvm_param_t* op, uint32_t sz)
{
	cvm_error_t	ret;

	// make sure we're not outputting to an immediate external operand
	if (op->op == CVM_EXTERNAL)
		return CVM_ERR_INVALID_OPERAND;

	// destination to buffer?
	if (op->op == CVM_IMM_BUF)
	{
		// destination size must be zero
		if (op->sz != 0)
			return CVM_ERR_INVALID_OPERAND_LENGTH;

		// check to see if there is enough buffer for this operation
		ret = _cryptovm_get_buffer(&op->ptr, sz);
		if (ret != CVM_ERR_NONE) return ret;
	}
	else
	{
		// check to see if destination is the right length
		if (op->sz != sz)
			return CVM_ERR_INVALID_OPERAND_LENGTH;
	}

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
void cvm_zeroize()
{
	zeroize(&_regs, sizeof(_regs));
	zeroize(&_imm_exts, sizeof(_imm_exts));
	_imm_exts_count = 0;

	_stream_pos = 0;
	_pbuffer = NULL;
	_sz_buffer = 0;
	_buffer_pos = 0;
}

////////////////////////////////////////////////////////////////////////////////
cvm_regs_t* cvm_get_regs()	// for unit test dump
{
	return &_regs;
}
