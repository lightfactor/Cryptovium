////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2016 Lightfactor, LLC. All rights reserved.
//
// Author:			Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified:	02/13/2017
//
////////////////////////////////////////////////////////////////////////////////


#include "pbkdf2.h"
#include "sha256.h"
#include "zeroize.h"
#include "compare_ct.h"
#include <string.h>


////////////////////////////////////////////////////////////////////////////////
static inline uint32_t _BE32(const uint32_t u)
{
	uint32_t v;
	
	v = ((u << 8) & 0xFF00FF00 ) | ((u >> 8) & 0xFF00FF ); 
	return (v << 16) | (v >> 16);
}

////////////////////////////////////////////////////////////////////////////////
void pbkdf2_sha256_hmac(const uint8_t* P, const uint32_t szP, const uint8_t* S, const uint32_t szS, const uint32_t c, uint8_t* DK, const uint32_t dkLen)
{
	sha256_context	ctx;
	uint8_t					f[SHA256_HASH_SIZE];
	uint8_t					g[SHA256_HASH_SIZE];
	uint32_t				n, i, j, k;
	
	// skip dkLen check (must be <= (2^32 - 1) * HMAC_SHA256_SIZE_BYTES
		
	// compute total number of HMAC_SHA256 blocks
	n = dkLen / SHA256_HASH_SIZE;
	if (dkLen & (SHA256_HASH_SIZE - 1))
		n++;
		
	for (i = 1; i <= n; i++)
	{
		j = _BE32(i);															// convert i to big endian
		
		// compute sha256-hmac
		sha256_hmac_init(&ctx, P, szP);
		sha256_hmac_update(&ctx, S, szS);
		sha256_hmac_update(&ctx, (uint8_t*)&j, sizeof(uint32_t));
		sha256_hmac_finish(&ctx, g);
		
		memcpy(f, g, SHA256_HASH_SIZE);						// copy to f

		for (j = 1; j < c; j++)
		{
			sha256_hmac(P, szP, g, SHA256_HASH_SIZE, g);
			
			for (k = 0; k < SHA256_HASH_SIZE; k++)
				f[k] ^= g[k];
		}
		
		if (i == n && (dkLen & (SHA256_HASH_SIZE - 1)))
			memcpy(DK + SHA256_HASH_SIZE * (i - 1), f, dkLen & (SHA256_HASH_SIZE - 1));
		else
			memcpy(DK + SHA256_HASH_SIZE * (i - 1), f, SHA256_HASH_SIZE);
	}
	
	zeroize(f, sizeof(f));
	zeroize(g, sizeof(g));
}

////////////////////////////////////////////////////////////////////////////////
bool pbkdf2_self_test(void)
{
	const uint8_t p1[] = "password";
	const uint8_t s1[] = "salt";
	const uint8_t p2[] = "passwordPASSWORDpassword";
	const uint8_t s2[] = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
	const uint8_t p3[] = "pass\0word";
	const uint8_t s3[] = "sa\0lt";
	
	const uint8_t dk1[] = { 0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
													0xa8, 0x65, 0x48, 0xc9 };

	const uint8_t dk2[] = { 0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
													0x2a, 0x30, 0x3f, 0x8e };
													
	const uint8_t dk3[] = { 0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
													0x96, 0x28, 0x93, 0xa0 };
													
	//const uint8_t dk4[] = { 0xcf, 0x81, 0xc6, 0x6f, 0xe8, 0xcf, 0xc0, 0x4d, 0x1f, 0x31, 0xec, 0xb6, 0x5d, 0xab, 0x40, 0x89,
	//												0xf7, 0xf1, 0x79, 0xe8 };

	const uint8_t dk5[] = { 0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f, 0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
													0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18, 0x1c };
													
	const uint8_t dk6[] = { 0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89, 0x3c, 0x69, 0x62, 0x26, 0x65, 0x0a, 0x86, 0x87 };

	uint8_t dk[25];
	
	pbkdf2_sha256_hmac(p1, (sizeof(p1) - 1), s1, (sizeof(s1) - 1), 1, dk, 20);
	if (compare_constant_time(dk, dk1, 20) == false) return false;
	
	pbkdf2_sha256_hmac(p1, (sizeof(p1) - 1), s1, (sizeof(s1) - 1), 2, dk, 20);
	if (compare_constant_time(dk, dk2, 20) == false) return false;

	pbkdf2_sha256_hmac(p1, (sizeof(p1) - 1), s1, (sizeof(s1) - 1), 4096, dk, 20);
	if (compare_constant_time(dk, dk3, 20) == false) return false;

	//pbkdf2_sha256_hmac(p1, (sizeof(p1) - 1), s1, (sizeof(s1) - 1), 16777216, dk, 20);
	//if (compare_constant_time(dk, dk4, 20) == false) return false;

	pbkdf2_sha256_hmac(p2, (sizeof(p2) - 1), s2, (sizeof(s2) - 1), 4096, dk, 25);
	if (compare_constant_time(dk, dk5, 25) == false) return false;

	pbkdf2_sha256_hmac(p3, (sizeof(p3) - 1), s3, (sizeof(s3) - 1), 4096, dk, 16);
	if (compare_constant_time(dk, dk6, 16) == false) return false;
	
	return true;
}

