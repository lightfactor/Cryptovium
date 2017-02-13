////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2016 Lightfactor, LLC. All rights reserved.
//
// Author:			Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified:	01/13/2017
//
////////////////////////////////////////////////////////////////////////////////


#ifndef _ZEROIZE_H_
#define _ZEROIZE_H_

#define ZEROIZE_STACK_SIZE 1024

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


void zeroize(void *v, uint32_t n);
void zeroize_stack(void);

#ifdef __cplusplus
}
#endif

#endif // _ZEROIZE_H_
