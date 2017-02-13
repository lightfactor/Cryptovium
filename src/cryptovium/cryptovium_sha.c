////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017 Lightfactor, LLC. All rights reserved.
//
// Author:		  Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified: 02/12/2017
//
////////////////////////////////////////////////////////////////////////////////

#include "cryptovium.h"
#include "zeroize.h"
#include "compare_ct.h"
#include "sha256.h"
#include "sha512.h"
#include <stdint.h>
#include <stdbool.h>


static sha256_context	context_sha256;
static sha512_context	context_sha512;
static sha256_context	context_hmac_sha256;

static bool				sha256_started = false;
static bool				sha512_started = false;
static bool				hmac_sha256_started = false;


////////////////////////////////////////////////////////////////////////////////
// forward declarations
////////////////////////////////////////////////////////////////////////////////
extern cvm_error_t _cvm_check_dst_op_size(cvm_param_t* op, uint8_t sz);


////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_sha256(cvm_param_t* op_hash, cvm_param_t* op_data)
{
	cvm_error_t	ret;

	// check destination size
	ret = _cvm_check_dst_op_size(op_hash, SHA256_HASH_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	sha256(op_data->ptr, op_data->sz, op_hash->ptr);

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_sha256_start()
{
	if (sha256_started)
		return CVM_ERR_NO_CONTEXT;

	sha256_init(&context_sha256);
	sha256_started = true;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_sha256_update(cvm_param_t* op_data)
{
	if (sha256_started == false)
		return CVM_ERR_NO_CONTEXT;

	sha256_update(&context_sha256, op_data->ptr, op_data->sz);

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_sha256_finish(cvm_param_t* op_hash)
{
	cvm_error_t	ret;

	if (sha256_started == false)
		return CVM_ERR_NO_CONTEXT;

	// check destination size
	ret = _cvm_check_dst_op_size(op_hash, SHA256_HASH_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	sha256_finish(&context_sha256, op_hash->ptr);

	sha256_started = false;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_sha512(cvm_param_t* op_hash, cvm_param_t* op_data)
{
	cvm_error_t	ret;

	// check destination size
	ret = _cvm_check_dst_op_size(op_hash, SHA512_HASH_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	sha512(op_data->ptr, op_data->sz, op_hash->ptr);

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_sha512_start()
{
	if (sha512_started)
		return CVM_ERR_NO_CONTEXT;

	sha512_init(&context_sha512);
	sha512_started = true;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_sha512_update(cvm_param_t* op_data)
{
	if (sha512_started == false)
		return CVM_ERR_NO_CONTEXT;

	sha512_update(&context_sha512, op_data->ptr, op_data->sz);

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_sha512_finish(cvm_param_t* op_hash)
{
	cvm_error_t	ret;

	if (sha512_started == false)
		return CVM_ERR_NO_CONTEXT;

	// check destination size
	ret = _cvm_check_dst_op_size(op_hash, SHA512_HASH_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	sha512_finish(&context_sha512, op_hash->ptr);

	sha512_started = false;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_hmac_sha256(cvm_param_t* op_hash, cvm_param_t* op_secret, cvm_param_t* op_data)
{
	cvm_error_t			ret;

	// check secret for zeros
	if (compare_constant_time_zero(op_secret->ptr, op_secret->sz))
		return CVM_ERR_ZERO_DATA;

	// check destination size
	ret = _cvm_check_dst_op_size(op_hash, SHA256_HASH_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	sha256_hmac(op_secret->ptr, op_secret->sz, op_data->ptr, op_data->sz, op_hash->ptr);

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_hmac_sha256_start(cvm_param_t* op_secret)
{
	// check secret for zeros
	if (compare_constant_time_zero(op_secret->ptr, op_secret->sz))
		return CVM_ERR_ZERO_DATA;

	if (hmac_sha256_started)
		return CVM_ERR_NO_CONTEXT;

	sha256_hmac_init(&context_hmac_sha256, op_secret->ptr, op_secret->sz);
	hmac_sha256_started = true;

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_hmac_sha256_update(cvm_param_t* op_data)
{
	if (hmac_sha256_started == false)
		return CVM_ERR_NO_CONTEXT;

	sha256_hmac_update(&context_hmac_sha256, op_data->ptr, op_data->sz);

	return CVM_ERR_NONE;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_hmac_sha256_finish(cvm_param_t* op_hash)
{
	cvm_error_t	ret;

	if (hmac_sha256_started == false)
		return CVM_ERR_NO_CONTEXT;

	// check destination size
	ret = _cvm_check_dst_op_size(op_hash, SHA256_HASH_SIZE);
	if (ret != CVM_ERR_NONE) return ret;

	sha256_hmac_finish(&context_hmac_sha256, op_hash->ptr);

	hmac_sha256_started = false;

	return CVM_ERR_NONE;
}
