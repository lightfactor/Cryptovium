#ifndef CURVE25519_H
#define CURVE25519_H

#ifdef __cplusplus
extern "C" {
#endif


#define CURVE25519_KEY_SIZE     32

extern void curve25519_scalarmult(uint8_t* r, const uint8_t* s, const uint8_t* p);
extern void curve25519_scalarmult_base(uint8_t* q, const uint8_t* n);
void curve25519_prepare_secret_key(uint8_t s[32]);


#ifdef __cplusplus
}
#endif

#endif
