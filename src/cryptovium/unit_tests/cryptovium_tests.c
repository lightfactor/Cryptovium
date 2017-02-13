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

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_all()
{
	cvm_error_t ret;

	// execute SHA unit tests
	ret = cvm_ut_sha256_v1(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_sha256_v2(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_sha256_v3(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_sha256_v1_inc(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_sha256_v2_inc(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_sha256_v3_inc(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_sha512_v1(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_sha512_v2(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_sha512_v3(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_sha512_v1_inc(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_sha512_v2_inc(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_sha512_v3_inc(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_hmac_sha256_v1(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_hmac_sha256_v2(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_hmac_sha256_v3(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_hmac_sha256_v4(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_hmac_sha256_v1_inc(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_hmac_sha256_v2_inc(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_hmac_sha256_v3_inc(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_hmac_sha256_v4_inc(); if (ret != CVM_ERR_NONE) return ret;

	// execute fidou2f unit tests
	ret = cvm_ut_fidou2f_register(); if (ret != CVM_ERR_NONE) return ret;
	ret = cvm_ut_fidou2f_authenticate(); if (ret != CVM_ERR_NONE) return ret;

	return CVM_ERR_NONE;
}



////////////////////////////////////////////////////////////////////////////////
void _dump_buffer(uint8_t* buffer, uint32_t sz_buffer)
{
	for (uint32_t i = 0; i < sz_buffer; ++i)
		printf("%02x", buffer[i]);

	printf("\n");
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t _cvm_ut_dump_error(cvm_error_t err, uint8_t* buffer, uint32_t sz_buffer)
{
	cvm_regs_t* pregs;

	switch (err)
	{
	case CVM_ERR_NONE:
		printf("OK\n");
		break;
	case CVM_ERR_END_OF_STREAM:
		printf("error: CVM_ERR_END_OF_STREAM\n");
		break;
	case CVM_ERR_INVALID_REG:
		printf("error: CVM_ERR_INVALID_REG\n");
		break;
	case CVM_ERR_INVALID_OPERAND:
		printf("error: CVM_ERR_INVALID_OPERAND\n");
		break;
	case CVM_ERR_INVALID_OPERAND_LENGTH:
		printf("error: CVM_ERR_INVALID_OPERAND_LENGTH\n");
		break;
	case CVM_ERR_ENTROPY_SOURCE_FAILED:
		printf("error: CVM_ERR_ENTROPY_SOURCE_FAILED\n");
		break;
	case CVM_ERR_ZERO_DATA:
		printf("error: CVM_ERR_ZERO_DATA\n");
		break;
	case CVM_ERR_NO_CONTEXT:
		printf("error: CVM_ERR_NO_CONTEXT\n");
		break;
	case CVM_ERR_NOT_IMPLEMENTED:
		printf("error: CVM_ERR_NOT_IMPLEMENTED\n");
		break;
	case CVM_ERR_BUFFER_OVERFLOW:
		printf("error: CVM_ERR_BUFFER_OVERFLOW\n");
		break;
	case CVM_ERR_COMPARE_FAILED:
		printf("error: CVM_ERR_EQUALS_FAILED\n");
		break;
	case CVM_ERR_SIGNATURE_VERIFY_FAILED:
		printf("error: CVM_ERR_VERIFY_SIGNATURE_FAILED\n");
		break;
	case CVM_ERR_NOT_INITIALIZED:
		printf("error: CVM_ERR_NOT_INITIALIZED\n");
		break;
	case CVM_ERR_IMM_EXT_OVERFLOW:
		printf("error: CVM_ERR_IMM_EXT_OVERFLOW\n");
		break;
	case CVM_ERR_INVALID_IMM_EXT:
		printf("error: CVM_ERR_INVALID_IMM_EXT\n");
		break;
	default:
		printf("error: ***UNKNOWN_ERROR***\n");
		break;
	}

	printf("REGS:\n");
	pregs = cvm_get_regs();
	printf("a = "); _dump_buffer(pregs->regs32.a, 32);
	printf("b = "); _dump_buffer(pregs->regs32.b, 32);
	printf("c = "); _dump_buffer(pregs->regs32.c, 32);
	printf("d = "); _dump_buffer(pregs->regs32.d, 32);
	printf("e = "); _dump_buffer(pregs->regs32.e, 32);
	printf("f = "); _dump_buffer(pregs->regs32.f, 32);
	printf("g = "); _dump_buffer(pregs->regs32.g, 32);
	printf("h = "); _dump_buffer(pregs->regs32.h, 32);
	printf("\n");

	if (sz_buffer > 0)
	{
		printf("BUFFER (size=%i):\n", sz_buffer);
		_dump_buffer(buffer, sz_buffer);
	}

	printf("\n");
	return err;
}
