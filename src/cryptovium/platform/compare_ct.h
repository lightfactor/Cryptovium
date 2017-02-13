////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2016 Lightfactor, LLC. All rights reserved.
//
// Author:			Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified:	02/05/2017
//
////////////////////////////////////////////////////////////////////////////////


#ifndef _COMPARE_CT_H_
#define _COMPARE_CT_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif


bool compare_constant_time(const uint8_t* a, const uint8_t* b, const uint32_t sz);
bool compare_constant_time_zero(const uint8_t* p, const uint32_t sz);


#ifdef __cplusplus
	}
#endif

#endif // _COMPARE_CT_H_
