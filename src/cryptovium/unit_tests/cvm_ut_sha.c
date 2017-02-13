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


// NIST vectors
static uint8_t sha_vector1[]				= "";
static uint32_t sha_vector1_size			= sizeof(sha_vector1) - 1;

static uint8_t sha256_vector1_hash[]		= { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
												0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };

static uint8_t sha512_vector1_hash[]		= { 0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 
												0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 
												0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 
												0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e };

static uint8_t sha_vector2[]				= "abc";
static uint32_t sha_vector2_size			= sizeof(sha_vector2) - 1;

static uint8_t sha256_vector2_hash[]		= { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
												0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };

static uint8_t sha512_vector2_hash[]		= { 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
												0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
												0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
												0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f };


static uint8_t sha_vector3[]				= "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static uint32_t sha_vector3_size			= sizeof(sha_vector3) - 1;

static uint8_t sha256_vector3_hash[]		= { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
												0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 };

static uint8_t sha512_vector3_hash[]		= { 0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16,
												0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
												0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
												0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45 };

// IETF vectors (because I'm lazy)
static uint8_t hmac_sha256_vector1_key[]	= { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 
												0x0b, 0x0b, 0x0b, 0x0b };
static uint8_t hmac_sha256_vector1_data[]	= { 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 };
static uint8_t hmac_sha256_vector1_hash[]	= { 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 
												0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7 };

static uint8_t hmac_sha256_vector2_key[]	= { 0x4a, 0x65, 0x66, 0x65 };
static uint8_t hmac_sha256_vector2_data[]	= { 0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20,
												0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f };
static uint8_t hmac_sha256_vector2_hash[]	= { 0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7, 
												0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43 };

static uint8_t hmac_sha256_vector3_key[]	= { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
												0xaa, 0xaa, 0xaa, 0xaa };
static uint8_t hmac_sha256_vector3_data[]	= { 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
												0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
												0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
												0xdd, 0xdd };

static uint8_t hmac_sha256_vector3_hash[]	= { 0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7, 
												0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe };

static uint8_t hmac_sha256_vector4_key[]	= { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 
												0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 };

static uint8_t hmac_sha256_vector4_data[]	= { 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
												0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
												0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
												0xcd, 0xcd };

static uint8_t hmac_sha256_vector4_hash[]	= { 0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a, 
												0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b };


static uint8_t stream_sha256[] =
{
	CVM_F_SHA256,
	CVM_REG32_A,				// output hash
	CVM_EXTERNAL, 0,			// input vector

	CVM_F_COMPARE,				// compare
	CVM_REG32_A,
	CVM_EXTERNAL, 1,
};

static uint8_t stream_sha256_inc[] =
{
	CVM_F_SHA256_START,

	CVM_F_SHA256_UPDATE,
	CVM_EXTERNAL, 0,			// input vector

	CVM_F_SHA256_FINISH,
	CVM_REG32_A,				// output hash

	CVM_F_COMPARE,				// compare
	CVM_REG32_A,
	CVM_EXTERNAL, 1,
};

static uint8_t stream_sha512[] =
{
	CVM_F_SHA512,
	CVM_REG64_AB,				// output hash
	CVM_EXTERNAL, 0,			// input vector

	CVM_F_COMPARE,				// compare
	CVM_REG64_AB,
	CVM_EXTERNAL, 1,
};

static uint8_t stream_sha512_inc[] =
{
	CVM_F_SHA512_START,

	CVM_F_SHA512_UPDATE,
	CVM_EXTERNAL, 0,			// input vector

	CVM_F_SHA512_FINISH,
	CVM_REG64_AB,				// output hash

	CVM_F_COMPARE,				// compare
	CVM_REG64_AB,
	CVM_EXTERNAL, 1,
};

static uint8_t stream_hmac_sha256[] =
{
	CVM_F_HMAC_SHA256,
	CVM_REG32_A,				// output hash
	CVM_EXTERNAL, 0,			// input key
	CVM_EXTERNAL, 1,			// input vector

	CVM_F_COMPARE,				// compare
	CVM_REG32_A,
	CVM_EXTERNAL, 2,
};

static uint8_t stream_hmac_sha256_inc[] =
{
	CVM_F_HMAC_SHA256_START,
	CVM_EXTERNAL, 0,			// input key

	CVM_F_HMAC_SHA256_UPDATE,
	CVM_EXTERNAL, 1,			// input vector

	CVM_F_HMAC_SHA256_FINISH,
	CVM_REG32_A,				// output hash

	CVM_F_COMPARE,				// compare
	CVM_REG32_A,
	CVM_EXTERNAL, 2,
};
////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha256_v1()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector1, sha_vector1_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha256_vector1_hash, sizeof(sha256_vector1_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha256, sizeof(stream_sha256), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha256_v1()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha256_v2()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector2, sha_vector2_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha256_vector2_hash, sizeof(sha256_vector2_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha256, sizeof(stream_sha256), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha256_v2()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha256_v3()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector3, sha_vector3_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha256_vector3_hash, sizeof(sha256_vector3_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha256, sizeof(stream_sha256), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha256_v3()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha256_v1_inc()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector1, sha_vector1_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha256_vector1_hash, sizeof(sha256_vector1_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha256_inc, sizeof(stream_sha256_inc), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha256_v1_inc()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha256_v2_inc()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector2, sha_vector2_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha256_vector2_hash, sizeof(sha256_vector2_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha256_inc, sizeof(stream_sha256_inc), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha256_v2_inc()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha256_v3_inc()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector3, sha_vector3_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha256_vector3_hash, sizeof(sha256_vector3_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha256_inc, sizeof(stream_sha256_inc), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha256_v3_inc()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha512_v1()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector1, sha_vector1_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha512_vector1_hash, sizeof(sha512_vector1_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha512, sizeof(stream_sha512), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha512_v1()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha512_v2()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector2, sha_vector2_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha512_vector2_hash, sizeof(sha512_vector2_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha512, sizeof(stream_sha512), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha512_v2()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha512_v3()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector3, sha_vector3_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha512_vector3_hash, sizeof(sha512_vector3_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha512, sizeof(stream_sha512), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha512_v3()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha512_v1_inc()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector1, sha_vector1_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha512_vector1_hash, sizeof(sha512_vector1_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha512_inc, sizeof(stream_sha512_inc), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha512_v1()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha512_v2_inc()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector2, sha_vector2_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha512_vector2_hash, sizeof(sha512_vector2_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha512_inc, sizeof(stream_sha512_inc), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha512_v2()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_sha512_v3_inc()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(sha_vector3, sha_vector3_size);						// index 0 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(sha512_vector3_hash, sizeof(sha512_vector3_hash));	// index 1 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_sha512_inc, sizeof(stream_sha512_inc), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_sha512_v3()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_hmac_sha256_v1()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(hmac_sha256_vector1_key, sizeof(hmac_sha256_vector1_key));	// index 0 (input key)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector1_data, sizeof(hmac_sha256_vector1_data));	// index 1 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector1_hash, sizeof(hmac_sha256_vector1_hash));	// index 2 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_hmac_sha256, sizeof(stream_hmac_sha256), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_hmac_sha256_v1()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_hmac_sha256_v2()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(hmac_sha256_vector2_key, sizeof(hmac_sha256_vector2_key));	// index 0 (input key)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector2_data, sizeof(hmac_sha256_vector2_data));	// index 1 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector2_hash, sizeof(hmac_sha256_vector2_hash));	// index 2 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_hmac_sha256, sizeof(stream_hmac_sha256), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_hmac_sha256_v2()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_hmac_sha256_v3()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(hmac_sha256_vector3_key, sizeof(hmac_sha256_vector3_key));	// index 0 (input key)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector3_data, sizeof(hmac_sha256_vector3_data));	// index 1 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector3_hash, sizeof(hmac_sha256_vector3_hash));	// index 2 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_hmac_sha256, sizeof(stream_hmac_sha256), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_hmac_sha256_v3()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_hmac_sha256_v4()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(hmac_sha256_vector4_key, sizeof(hmac_sha256_vector4_key));	// index 0 (input key)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector4_data, sizeof(hmac_sha256_vector4_data));	// index 1 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector4_hash, sizeof(hmac_sha256_vector4_hash));	// index 2 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_hmac_sha256, sizeof(stream_hmac_sha256), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_hmac_sha256_v4()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_hmac_sha256_v1_inc()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(hmac_sha256_vector1_key, sizeof(hmac_sha256_vector1_key));	// index 0 (input key)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector1_data, sizeof(hmac_sha256_vector1_data));	// index 1 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector1_hash, sizeof(hmac_sha256_vector1_hash));	// index 2 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_hmac_sha256_inc, sizeof(stream_hmac_sha256_inc), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_hmac_sha256_v1_inc()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_hmac_sha256_v2_inc()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(hmac_sha256_vector2_key, sizeof(hmac_sha256_vector2_key));	// index 0 (input key)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector2_data, sizeof(hmac_sha256_vector2_data));	// index 1 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector2_hash, sizeof(hmac_sha256_vector2_hash));	// index 2 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_hmac_sha256_inc, sizeof(stream_hmac_sha256_inc), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_hmac_sha256_v2_inc()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_hmac_sha256_v3_inc()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(hmac_sha256_vector3_key, sizeof(hmac_sha256_vector3_key));	// index 0 (input key)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector3_data, sizeof(hmac_sha256_vector3_data));	// index 1 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector3_hash, sizeof(hmac_sha256_vector3_hash));	// index 2 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_hmac_sha256_inc, sizeof(stream_hmac_sha256_inc), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_hmac_sha256_v3_inc()::success\n");
	return ret;
}

////////////////////////////////////////////////////////////////////////////////
cvm_error_t cvm_ut_hmac_sha256_v4_inc()
{
	cvm_error_t		ret;
	uint8_t			buffer[1024];
	uint32_t		sz_buffer;

	// import externals (read-only)
	ret = cvm_import_external(hmac_sha256_vector4_key, sizeof(hmac_sha256_vector4_key));	// index 0 (input key)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector4_data, sizeof(hmac_sha256_vector4_data));	// index 1 (input vector)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);
	ret = cvm_import_external(hmac_sha256_vector4_hash, sizeof(hmac_sha256_vector4_hash));	// index 2 (compare hash)
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, 0, 0);

	ret = cvm_execute_stream(stream_hmac_sha256_inc, sizeof(stream_hmac_sha256_inc), buffer, sizeof(buffer), &sz_buffer);
	if (ret != CVM_ERR_NONE) return _cvm_ut_dump_error(ret, buffer, sz_buffer);

	printf("cvm_ut_hmac_sha256_v4_inc()::success\n");
	return ret;
}

