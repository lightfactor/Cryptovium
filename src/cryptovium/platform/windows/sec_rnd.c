////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2017 Lightfactor, LLC. All rights reserved.
//
// Author:		  Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified: 02/12/2017
//
////////////////////////////////////////////////////////////////////////////////

#include "include_windows.h"
#include <stdint.h>
#include <stdbool.h>


////////////////////////////////////////////////////////////////////////////////
int secure_random(uint8_t* rnd, uint32_t sz_rnd)
{
	BOOL		b;
	HCRYPTPROV	hCryptProvider;

	if (!CryptAcquireContextW(&hCryptProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		return 0;

	b = CryptGenRandom(hCryptProvider, sz_rnd, rnd);
	CryptReleaseContext(hCryptProvider, 0);

	if (b == FALSE)
		return 0;

	return 1;
}
