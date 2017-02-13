////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017 Lightfactor, LLC. All rights reserved.
//
// Author:		  Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified: 02/12/2017
//
////////////////////////////////////////////////////////////////////////////////

#include "cryptovium.h"
#include "hkdf.h"
#include "pbkdf2.h"
#include <stdint.h>
#include <stdbool.h>


////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_kdf_hkdf(cvm_param_t* op_output, cvm_param_t* op_salt, cvm_param_t* op_key, cvm_param_t* op_info, cvm_param_t* op_start_offset)
{
	if ((op_output->op == CVM_IMM_BUF) || (op_output->op == CVM_EXTERNAL))
		return CVM_ERR_INVALID_OPERAND;

	hkdf_derive_secrets(*((uint8_t*)op_start_offset->ptr), op_salt->ptr, op_salt->sz, op_key->ptr, op_key->sz, op_info->ptr, op_info->sz, op_output->ptr, op_output->sz);

	return CVM_ERR_NONE;
}


////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_kdf_pbkdf2_sha256_hmac(cvm_param_t* op_dk, cvm_param_t* op_p, cvm_param_t* op_salt, cvm_param_t* op_c)
{
	if ((op_dk->op == CVM_IMM_BUF) || (op_dk->op == CVM_EXTERNAL))
		return CVM_ERR_INVALID_OPERAND;

	pbkdf2_sha256_hmac(op_p->ptr, op_p->sz, op_salt->ptr, op_salt->sz, *((uint8_t*)op_c->ptr), op_dk->ptr, op_dk->sz);

	return CVM_ERR_NONE;
}
