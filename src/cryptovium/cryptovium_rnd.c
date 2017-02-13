////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017 Lightfactor, LLC. All rights reserved.
//
// Author:		  Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified: 02/12/2017
//
////////////////////////////////////////////////////////////////////////////////

#include "cryptovium.h"
#include "sec_rnd.h"
#include <stdint.h>
#include <stdbool.h>


////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_f_secure_random(cvm_param_t* op_dst)
{
	if ((op_dst->op == CVM_IMM_BUF) || (op_dst->op == CVM_EXTERNAL))
		return CVM_ERR_INVALID_OPERAND;

	if (!secure_random(op_dst->ptr, op_dst->sz))
		return CVM_ERR_ENTROPY_SOURCE_FAILED;

	return CVM_ERR_NONE;
}
