////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2016 Lightfactor, LLC. All rights reserved.
//
// Author:			Jeff Cesnik <jcesnik@lightfactor.co>
// Last Modified:	02/13/2017
//
////////////////////////////////////////////////////////////////////////////////

#ifndef _HKDF_H_
#define _HKDF_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif


void hkdf_derive_secrets(
	size_t			n_start_offset,
	const uint8_t*	salt,
	size_t			salt_len,
	const uint8_t*	input_key_material,
	size_t			input_key_material_len,
	const uint8_t*	info,
	size_t			info_len,
	uint8_t*		output,
	size_t			output_len);

bool hkdf_self_test(void);


#ifdef __cplusplus
	}
#endif

#endif	// _HKDF_H_
