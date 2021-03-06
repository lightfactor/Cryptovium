
#ifndef __CURVE_SIGS_H__
#define __CURVE_SIGS_H__

#ifdef __cplusplus
extern "C" {
#endif
	/* returns 0 on success */
	int curve25519_sign(unsigned char* signature_out, /* 64 bytes */
		const unsigned char* curve25519_privkey, /* 32 bytes */
		const unsigned char* msg, const unsigned long msg_len, /* <= 256 bytes */
		const unsigned char* random); /* 64 bytes */

/* returns 0 on success */
	int curve25519_verify(const unsigned char* signature, /* 64 bytes */
		const unsigned char* curve25519_pubkey, /* 32 bytes */
		const unsigned char* msg, const unsigned long msg_len); /* <= 256 bytes */

#ifdef __cplusplus
}
#endif

#endif
