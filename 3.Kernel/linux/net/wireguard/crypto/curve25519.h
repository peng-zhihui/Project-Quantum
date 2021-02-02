/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef _WG_CURVE25519_H
#define _WG_CURVE25519_H

#include <linux/types.h>

enum curve25519_lengths {
	CURVE25519_POINT_SIZE = 32
};

bool __must_check curve25519(u8 mypublic[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE], const u8 basepoint[CURVE25519_POINT_SIZE]);
void curve25519_generate_secret(u8 secret[CURVE25519_POINT_SIZE]);
bool __must_check curve25519_generate_public(u8 pub[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE]);

void curve25519_fpu_init(void);

#ifdef DEBUG
bool curve25519_selftest(void);
#endif

#endif /* _WG_CURVE25519_H */
