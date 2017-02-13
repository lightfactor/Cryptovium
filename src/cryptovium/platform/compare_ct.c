////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2016 Lightfactor, LLC. All rights reserved.
//
// Author:			Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified:	02/05/2017
//
////////////////////////////////////////////////////////////////////////////////


#include "compare_ct.h"


bool compare_constant_time(const uint8_t* a, const uint8_t* b, const uint32_t sz)
{
	uint8_t		c;
	uint32_t	i;

	c = 0;

	for (i = 0; i < sz; ++i)
		c |= (a[i] ^ b[i]);

	if (c == 0)		// match
		return true;
	else
		return false;
}

bool compare_constant_time_zero(const uint8_t* p, const uint32_t sz)
{
	uint8_t		c;
	uint32_t	i;

	c = 0;

	for (i = 0; i < sz; ++i)
		c |= (p[i] ^ 0);

	if (c == 0)		// match
		return true;
	else
		return false;
}