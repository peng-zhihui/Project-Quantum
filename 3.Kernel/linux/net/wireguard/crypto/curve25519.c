/* Original author: Adam Langley <agl@imperialviolet.org>
 *
 * Copyright 2008 Google Inc. All Rights Reserved.
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "curve25519.h"

#include <linux/version.h>
#include <linux/string.h>
#include <linux/random.h>
#include <crypto/algapi.h>

#define ARCH_HAS_SEPARATE_IRQ_STACK

#if (defined(CONFIG_MIPS) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)) || defined(CONFIG_ARM)
#undef ARCH_HAS_SEPARATE_IRQ_STACK
#endif

static __always_inline void normalize_secret(u8 secret[CURVE25519_POINT_SIZE])
{
	secret[0] &= 248;
	secret[31] &= 127;
	secret[31] |= 64;
}
static const u8 null_point[CURVE25519_POINT_SIZE] = { 0 };

#if defined(CONFIG_X86_64)
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/fpu/api.h>
#include <asm/simd.h>
static bool curve25519_use_avx __read_mostly;
void curve25519_fpu_init(void)
{
	curve25519_use_avx = boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
}

typedef u64 fe[10];
typedef u64 fe51[5];
asmlinkage void curve25519_sandy2x_ladder(fe *, const u8 *);
asmlinkage void curve25519_sandy2x_ladder_base(fe *, const u8 *);
asmlinkage void curve25519_sandy2x_fe51_pack(u8 *, const fe51 *);
asmlinkage void curve25519_sandy2x_fe51_mul(fe51 *, const fe51 *, const fe51 *);
asmlinkage void curve25519_sandy2x_fe51_nsquare(fe51 *, const fe51 *, int);

static inline u32 le24_to_cpupv(const u8 *in)
{
	return le16_to_cpup((__le16 *)in) | ((u32)in[2]) << 16;
}

static inline void fe_frombytes(fe h, const u8 *s)
{
	u64 h0 = le32_to_cpup((__le32 *)s);
	u64 h1 = le24_to_cpupv(s + 4) << 6;
	u64 h2 = le24_to_cpupv(s + 7) << 5;
	u64 h3 = le24_to_cpupv(s + 10) << 3;
	u64 h4 = le24_to_cpupv(s + 13) << 2;
	u64 h5 = le32_to_cpup((__le32 *)(s + 16));
	u64 h6 = le24_to_cpupv(s + 20) << 7;
	u64 h7 = le24_to_cpupv(s + 23) << 5;
	u64 h8 = le24_to_cpupv(s + 26) << 4;
	u64 h9 = (le24_to_cpupv(s + 29) & 8388607) << 2;
	u64 carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7, carry8, carry9;

	carry9 = h9 >> 25; h0 += carry9 * 19; h9 &= 0x1FFFFFF;
	carry1 = h1 >> 25; h2 += carry1; h1 &= 0x1FFFFFF;
	carry3 = h3 >> 25; h4 += carry3; h3 &= 0x1FFFFFF;
	carry5 = h5 >> 25; h6 += carry5; h5 &= 0x1FFFFFF;
	carry7 = h7 >> 25; h8 += carry7; h7 &= 0x1FFFFFF;

	carry0 = h0 >> 26; h1 += carry0; h0 &= 0x3FFFFFF;
	carry2 = h2 >> 26; h3 += carry2; h2 &= 0x3FFFFFF;
	carry4 = h4 >> 26; h5 += carry4; h4 &= 0x3FFFFFF;
	carry6 = h6 >> 26; h7 += carry6; h6 &= 0x3FFFFFF;
	carry8 = h8 >> 26; h9 += carry8; h8 &= 0x3FFFFFF;

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}

static inline void fe51_invert(fe51 *r, const fe51 *x)
{
	fe51 z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t;

	/* 2 */ curve25519_sandy2x_fe51_nsquare(&z2, x, 1);
	/* 4 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2, 1);
	/* 8 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&t, 1);
	/* 9 */ curve25519_sandy2x_fe51_mul(&z9, (const fe51 *)&t, x);
	/* 11 */ curve25519_sandy2x_fe51_mul(&z11, (const fe51 *)&z9, (const fe51 *)&z2);
	/* 22 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z11, 1);
	/* 2^5 - 2^0 = 31 */ curve25519_sandy2x_fe51_mul(&z2_5_0, (const fe51 *)&t, (const fe51 *)&z9);

	/* 2^10 - 2^5 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2_5_0, 5);
	/* 2^10 - 2^0 */ curve25519_sandy2x_fe51_mul(&z2_10_0, (const fe51 *)&t, (const fe51 *)&z2_5_0);

	/* 2^20 - 2^10 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2_10_0, 10);
	/* 2^20 - 2^0 */ curve25519_sandy2x_fe51_mul(&z2_20_0, (const fe51 *)&t, (const fe51 *)&z2_10_0);

	/* 2^40 - 2^20 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2_20_0, 20);
	/* 2^40 - 2^0 */ curve25519_sandy2x_fe51_mul(&t, (const fe51 *)&t, (const fe51 *)&z2_20_0);

	/* 2^50 - 2^10 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&t, 10);
	/* 2^50 - 2^0 */ curve25519_sandy2x_fe51_mul(&z2_50_0, (const fe51 *)&t, (const fe51 *)&z2_10_0);

	/* 2^100 - 2^50 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2_50_0, 50);
	/* 2^100 - 2^0 */ curve25519_sandy2x_fe51_mul(&z2_100_0, (const fe51 *)&t, (const fe51 *)&z2_50_0);

	/* 2^200 - 2^100 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2_100_0, 100);
	/* 2^200 - 2^0 */ curve25519_sandy2x_fe51_mul(&t, (const fe51 *)&t, (const fe51 *)&z2_100_0);

	/* 2^250 - 2^50 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&t, 50);
	/* 2^250 - 2^0 */ curve25519_sandy2x_fe51_mul(&t, (const fe51 *)&t, (const fe51 *)&z2_50_0);

	/* 2^255 - 2^5 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&t, 5);
	/* 2^255 - 21 */ curve25519_sandy2x_fe51_mul(r, (const fe51 *)t, (const fe51 *)&z11);
}

static void curve25519_sandy2x(u8 mypublic[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE], const u8 basepoint[CURVE25519_POINT_SIZE])
{
	u8 e[32];
	fe var[3];
	fe51 x_51, z_51;

	memcpy(e, secret, 32);
	normalize_secret(e);
#define x1 var[0]
#define x2 var[1]
#define z2 var[2]
	fe_frombytes(x1, basepoint);
	curve25519_sandy2x_ladder(var, e);
	z_51[0] = (z2[1] << 26) + z2[0];
	z_51[1] = (z2[3] << 26) + z2[2];
	z_51[2] = (z2[5] << 26) + z2[4];
	z_51[3] = (z2[7] << 26) + z2[6];
	z_51[4] = (z2[9] << 26) + z2[8];
	x_51[0] = (x2[1] << 26) + x2[0];
	x_51[1] = (x2[3] << 26) + x2[2];
	x_51[2] = (x2[5] << 26) + x2[4];
	x_51[3] = (x2[7] << 26) + x2[6];
	x_51[4] = (x2[9] << 26) + x2[8];
#undef x1
#undef x2
#undef z2
	fe51_invert(&z_51, (const fe51 *)&z_51);
	curve25519_sandy2x_fe51_mul(&x_51, (const fe51 *)&x_51, (const fe51 *)&z_51);
	curve25519_sandy2x_fe51_pack(mypublic, (const fe51 *)&x_51);

	memzero_explicit(e, sizeof(e));
	memzero_explicit(var, sizeof(var));
	memzero_explicit(x_51, sizeof(x_51));
	memzero_explicit(z_51, sizeof(z_51));
}

static void curve25519_sandy2x_base(u8 pub[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE])
{
	u8 e[32];
	fe var[3];
	fe51 x_51, z_51;

	memcpy(e, secret, 32);
	normalize_secret(e);
	curve25519_sandy2x_ladder_base(var, e);
#define x2 var[0]
#define z2 var[1]
	z_51[0] = (z2[1] << 26) + z2[0];
	z_51[1] = (z2[3] << 26) + z2[2];
	z_51[2] = (z2[5] << 26) + z2[4];
	z_51[3] = (z2[7] << 26) + z2[6];
	z_51[4] = (z2[9] << 26) + z2[8];
	x_51[0] = (x2[1] << 26) + x2[0];
	x_51[1] = (x2[3] << 26) + x2[2];
	x_51[2] = (x2[5] << 26) + x2[4];
	x_51[3] = (x2[7] << 26) + x2[6];
	x_51[4] = (x2[9] << 26) + x2[8];
#undef x2
#undef z2
	fe51_invert(&z_51, (const fe51 *)&z_51);
	curve25519_sandy2x_fe51_mul(&x_51, (const fe51 *)&x_51, (const fe51 *)&z_51);
	curve25519_sandy2x_fe51_pack(pub, (const fe51 *)&x_51);

	memzero_explicit(e, sizeof(e));
	memzero_explicit(var, sizeof(var));
	memzero_explicit(x_51, sizeof(x_51));
	memzero_explicit(z_51, sizeof(z_51));
}
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && defined(CONFIG_ARM) && !defined(CONFIG_CPU_THUMBONLY)
#include <asm/hwcap.h>
#include <asm/neon.h>
#include <asm/simd.h>
asmlinkage void curve25519_asm_neon(u8 mypublic[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE], const u8 basepoint[CURVE25519_POINT_SIZE]);
static bool curve25519_use_neon __read_mostly;
void __init curve25519_fpu_init(void)
{
	curve25519_use_neon = elf_hwcap & HWCAP_NEON;
}
#else
void __init curve25519_fpu_init(void) { }
#endif

#if defined(CONFIG_ARCH_SUPPORTS_INT128) && defined(__SIZEOF_INT128__)
typedef u64 limb;
typedef limb felem[5];
typedef __uint128_t u128;

/* Sum two numbers: output += in */
static __always_inline void fsum(limb *output, const limb *in)
{
	output[0] += in[0];
	output[1] += in[1];
	output[2] += in[2];
	output[3] += in[3];
	output[4] += in[4];
}

/* Find the difference of two numbers: output = in - output
 * (note the order of the arguments!)
 *
 * Assumes that out[i] < 2**52
 * On return, out[i] < 2**55
 */
static __always_inline void fdifference_backwards(felem out, const felem in)
{
	/* 152 is 19 << 3 */
	static const limb two54m152 = (((limb)1) << 54) - 152;
	static const limb two54m8 = (((limb)1) << 54) - 8;

	out[0] = in[0] + two54m152 - out[0];
	out[1] = in[1] + two54m8 - out[1];
	out[2] = in[2] + two54m8 - out[2];
	out[3] = in[3] + two54m8 - out[3];
	out[4] = in[4] + two54m8 - out[4];
}

/* Multiply a number by a scalar: output = in * scalar */
static __always_inline void fscalar_product(felem output, const felem in, const limb scalar)
{
	u128 a;

	a = ((u128) in[0]) * scalar;
	output[0] = ((limb)a) & 0x7ffffffffffffUL;

	a = ((u128) in[1]) * scalar + ((limb) (a >> 51));
	output[1] = ((limb)a) & 0x7ffffffffffffUL;

	a = ((u128) in[2]) * scalar + ((limb) (a >> 51));
	output[2] = ((limb)a) & 0x7ffffffffffffUL;

	a = ((u128) in[3]) * scalar + ((limb) (a >> 51));
	output[3] = ((limb)a) & 0x7ffffffffffffUL;

	a = ((u128) in[4]) * scalar + ((limb) (a >> 51));
	output[4] = ((limb)a) & 0x7ffffffffffffUL;

	output[0] += (a >> 51) * 19;
}

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * Assumes that in[i] < 2**55 and likewise for in2.
 * On return, output[i] < 2**52
 */
static __always_inline void fmul(felem output, const felem in2, const felem in)
{
	u128 t[5];
	limb r0, r1, r2, r3, r4, s0, s1, s2, s3, s4, c;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];

	s0 = in2[0];
	s1 = in2[1];
	s2 = in2[2];
	s3 = in2[3];
	s4 = in2[4];

	t[0]  =  ((u128) r0) * s0;
	t[1]  =  ((u128) r0) * s1 + ((u128) r1) * s0;
	t[2]  =  ((u128) r0) * s2 + ((u128) r2) * s0 + ((u128) r1) * s1;
	t[3]  =  ((u128) r0) * s3 + ((u128) r3) * s0 + ((u128) r1) * s2 + ((u128) r2) * s1;
	t[4]  =  ((u128) r0) * s4 + ((u128) r4) * s0 + ((u128) r3) * s1 + ((u128) r1) * s3 + ((u128) r2) * s2;

	r4 *= 19;
	r1 *= 19;
	r2 *= 19;
	r3 *= 19;

	t[0] += ((u128) r4) * s1 + ((u128) r1) * s4 + ((u128) r2) * s3 + ((u128) r3) * s2;
	t[1] += ((u128) r4) * s2 + ((u128) r2) * s4 + ((u128) r3) * s3;
	t[2] += ((u128) r4) * s3 + ((u128) r3) * s4;
	t[3] += ((u128) r4) * s4;

			r0 = (limb)t[0] & 0x7ffffffffffffUL; c = (limb)(t[0] >> 51);
	t[1] += c;      r1 = (limb)t[1] & 0x7ffffffffffffUL; c = (limb)(t[1] >> 51);
	t[2] += c;      r2 = (limb)t[2] & 0x7ffffffffffffUL; c = (limb)(t[2] >> 51);
	t[3] += c;      r3 = (limb)t[3] & 0x7ffffffffffffUL; c = (limb)(t[3] >> 51);
	t[4] += c;      r4 = (limb)t[4] & 0x7ffffffffffffUL; c = (limb)(t[4] >> 51);
	r0 +=   c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffffUL;
	r1 +=   c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffffUL;
	r2 +=   c;

	output[0] = r0;
	output[1] = r1;
	output[2] = r2;
	output[3] = r3;
	output[4] = r4;
}

static __always_inline void fsquare_times(felem output, const felem in, limb count)
{
	u128 t[5];
	limb r0, r1, r2, r3, r4, c;
	limb d0, d1, d2, d4, d419;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];

	do {
		d0 = r0 * 2;
		d1 = r1 * 2;
		d2 = r2 * 2 * 19;
		d419 = r4 * 19;
		d4 = d419 * 2;

		t[0] = ((u128) r0) * r0 + ((u128) d4) * r1 + (((u128) d2) * (r3     ));
		t[1] = ((u128) d0) * r1 + ((u128) d4) * r2 + (((u128) r3) * (r3 * 19));
		t[2] = ((u128) d0) * r2 + ((u128) r1) * r1 + (((u128) d4) * (r3     ));
		t[3] = ((u128) d0) * r3 + ((u128) d1) * r2 + (((u128) r4) * (d419   ));
		t[4] = ((u128) d0) * r4 + ((u128) d1) * r3 + (((u128) r2) * (r2     ));

				r0 = (limb)t[0] & 0x7ffffffffffffUL; c = (limb)(t[0] >> 51);
		t[1] += c;      r1 = (limb)t[1] & 0x7ffffffffffffUL; c = (limb)(t[1] >> 51);
		t[2] += c;      r2 = (limb)t[2] & 0x7ffffffffffffUL; c = (limb)(t[2] >> 51);
		t[3] += c;      r3 = (limb)t[3] & 0x7ffffffffffffUL; c = (limb)(t[3] >> 51);
		t[4] += c;      r4 = (limb)t[4] & 0x7ffffffffffffUL; c = (limb)(t[4] >> 51);
		r0 +=   c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffffUL;
		r1 +=   c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffffUL;
		r2 +=   c;
	} while (--count);

	output[0] = r0;
	output[1] = r1;
	output[2] = r2;
	output[3] = r3;
	output[4] = r4;
}

/* Load a little-endian 64-bit number  */
static inline limb load_limb(const u8 *in)
{
	return le64_to_cpu(*(__le64 *)in);
}

static inline void store_limb(u8 *out, limb in)
{
	*(__le64 *)out = cpu_to_le64(in);
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static inline void fexpand(limb *output, const u8 *in)
{
	output[0] = load_limb(in) & 0x7ffffffffffffUL;
	output[1] = (load_limb(in + 6) >> 3) & 0x7ffffffffffffUL;
	output[2] = (load_limb(in + 12) >> 6) & 0x7ffffffffffffUL;
	output[3] = (load_limb(in + 19) >> 1) & 0x7ffffffffffffUL;
	output[4] = (load_limb(in + 24) >> 12) & 0x7ffffffffffffUL;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static void fcontract(u8 *output, const felem input)
{
	u128 t[5];

	t[0] = input[0];
	t[1] = input[1];
	t[2] = input[2];
	t[3] = input[3];
	t[4] = input[4];

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffffUL;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffffUL;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffffUL;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffffUL;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffffUL;

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffffUL;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffffUL;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffffUL;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffffUL;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffffUL;

	/* now t is between 0 and 2^255-1, properly carried. */
	/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

	t[0] += 19;

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffffUL;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffffUL;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffffUL;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffffUL;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffffUL;

	/* now between 19 and 2^255-1 in both cases, and offset by 19. */

	t[0] += 0x8000000000000UL - 19;
	t[1] += 0x8000000000000UL - 1;
	t[2] += 0x8000000000000UL - 1;
	t[3] += 0x8000000000000UL - 1;
	t[4] += 0x8000000000000UL - 1;

	/* now between 2^255 and 2^256-20, and offset by 2^255. */

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffffUL;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffffUL;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffffUL;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffffUL;
	t[4] &= 0x7ffffffffffffUL;

	store_limb(output,    t[0] | (t[1] << 51));
	store_limb(output+8,  (t[1] >> 13) | (t[2] << 38));
	store_limb(output+16, (t[2] >> 26) | (t[3] << 25));
	store_limb(output+24, (t[3] >> 39) | (t[4] << 12));
}

/* Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   x2 z3: long form
 *   x3 z3: long form
 *   x z: short form, destroyed
 *   xprime zprime: short form, destroyed
 *   qmqp: short form, preserved
 */
static void fmonty(limb *x2, limb *z2, /* output 2Q */
			 limb *x3, limb *z3, /* output Q + Q' */
			 limb *x, limb *z,   /* input Q */
			 limb *xprime, limb *zprime, /* input Q' */

			 const limb *qmqp /* input Q - Q' */)
{
	limb origx[5], origxprime[5], zzz[5], xx[5], zz[5], xxprime[5], zzprime[5], zzzprime[5];

	memcpy(origx, x, 5 * sizeof(limb));
	fsum(x, z);
	fdifference_backwards(z, origx);  // does x - z

	memcpy(origxprime, xprime, sizeof(limb) * 5);
	fsum(xprime, zprime);
	fdifference_backwards(zprime, origxprime);
	fmul(xxprime, xprime, z);
	fmul(zzprime, x, zprime);
	memcpy(origxprime, xxprime, sizeof(limb) * 5);
	fsum(xxprime, zzprime);
	fdifference_backwards(zzprime, origxprime);
	fsquare_times(x3, xxprime, 1);
	fsquare_times(zzzprime, zzprime, 1);
	fmul(z3, zzzprime, qmqp);

	fsquare_times(xx, x, 1);
	fsquare_times(zz, z, 1);
	fmul(x2, xx, zz);
	fdifference_backwards(zz, xx);  // does zz = xx - zz
	fscalar_product(zzz, zz, 121665);
	fsum(zzz, xx);
	fmul(z2, zz, zzz);
}

/* Maybe swap the contents of two limb arrays (@a and @b), each @len elements
 * long. Perform the swap iff @swap is non-zero.
 *
 * This function performs the swap without leaking any side-channel
 * information.
 */
static void swap_conditional(limb a[5], limb b[5], limb iswap)
{
	unsigned int i;
	const limb swap = -iswap;

	for (i = 0; i < 5; ++i) {
		const limb x = swap & (a[i] ^ b[i]);

		a[i] ^= x;
		b[i] ^= x;
	}
}

/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   resultx/resultz: the x coordinate of the resulting curve point (short form)
 *   n: a little endian, 32-byte number
 *   q: a point of the curve (short form)
 */
static void cmult(limb *resultx, limb *resultz, const u8 *n, const limb *q)
{
	limb a[5] = {0}, b[5] = {1}, c[5] = {1}, d[5] = {0};
	limb *nqpqx = a, *nqpqz = b, *nqx = c, *nqz = d, *t;
	limb e[5] = {0}, f[5] = {1}, g[5] = {0}, h[5] = {1};
	limb *nqpqx2 = e, *nqpqz2 = f, *nqx2 = g, *nqz2 = h;

	unsigned int i, j;

	memcpy(nqpqx, q, sizeof(limb) * 5);

	for (i = 0; i < 32; ++i) {
		u8 byte = n[31 - i];

		for (j = 0; j < 8; ++j) {
			const limb bit = byte >> 7;

			swap_conditional(nqx, nqpqx, bit);
			swap_conditional(nqz, nqpqz, bit);
			fmonty(nqx2, nqz2,
						 nqpqx2, nqpqz2,
						 nqx, nqz,
						 nqpqx, nqpqz,
						 q);
			swap_conditional(nqx2, nqpqx2, bit);
			swap_conditional(nqz2, nqpqz2, bit);

			t = nqx;
			nqx = nqx2;
			nqx2 = t;
			t = nqz;
			nqz = nqz2;
			nqz2 = t;
			t = nqpqx;
			nqpqx = nqpqx2;
			nqpqx2 = t;
			t = nqpqz;
			nqpqz = nqpqz2;
			nqpqz2 = t;

			byte <<= 1;
		}
	}

	memcpy(resultx, nqx, sizeof(limb) * 5);
	memcpy(resultz, nqz, sizeof(limb) * 5);
}

static void crecip(felem out, const felem z)
{
	felem a, t0, b, c;

	/* 2 */ fsquare_times(a, z, 1); // a = 2
	/* 8 */ fsquare_times(t0, a, 2);
	/* 9 */ fmul(b, t0, z); // b = 9
	/* 11 */ fmul(a, b, a); // a = 11
	/* 22 */ fsquare_times(t0, a, 1);
	/* 2^5 - 2^0 = 31 */ fmul(b, t0, b);
	/* 2^10 - 2^5 */ fsquare_times(t0, b, 5);
	/* 2^10 - 2^0 */ fmul(b, t0, b);
	/* 2^20 - 2^10 */ fsquare_times(t0, b, 10);
	/* 2^20 - 2^0 */ fmul(c, t0, b);
	/* 2^40 - 2^20 */ fsquare_times(t0, c, 20);
	/* 2^40 - 2^0 */ fmul(t0, t0, c);
	/* 2^50 - 2^10 */ fsquare_times(t0, t0, 10);
	/* 2^50 - 2^0 */ fmul(b, t0, b);
	/* 2^100 - 2^50 */ fsquare_times(t0, b, 50);
	/* 2^100 - 2^0 */ fmul(c, t0, b);
	/* 2^200 - 2^100 */ fsquare_times(t0, c, 100);
	/* 2^200 - 2^0 */ fmul(t0, t0, c);
	/* 2^250 - 2^50 */ fsquare_times(t0, t0, 50);
	/* 2^250 - 2^0 */ fmul(t0, t0, b);
	/* 2^255 - 2^5 */ fsquare_times(t0, t0, 5);
	/* 2^255 - 21 */ fmul(out, t0, a);
}

bool curve25519(u8 mypublic[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE], const u8 basepoint[CURVE25519_POINT_SIZE])
{
#ifdef CONFIG_X86_64
	if (curve25519_use_avx && irq_fpu_usable()) {
		kernel_fpu_begin();
		curve25519_sandy2x(mypublic, secret, basepoint);
		kernel_fpu_end();
	} else
#endif
	{
		limb bp[5], x[5], z[5], zmone[5];
		u8 e[32];

		memcpy(e, secret, 32);
		normalize_secret(e);

		fexpand(bp, basepoint);
		cmult(x, z, e, bp);
		crecip(zmone, z);
		fmul(z, x, zmone);
		fcontract(mypublic, z);

		memzero_explicit(e, sizeof(e));
		memzero_explicit(bp, sizeof(bp));
		memzero_explicit(x, sizeof(x));
		memzero_explicit(z, sizeof(z));
		memzero_explicit(zmone, sizeof(zmone));
	}
	return crypto_memneq(mypublic, null_point, CURVE25519_POINT_SIZE);
}

bool curve25519_generate_public(u8 pub[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE])
{
	static const u8 basepoint[CURVE25519_POINT_SIZE] __aligned(32) = { 9 };

	if (unlikely(!crypto_memneq(secret, null_point, CURVE25519_POINT_SIZE)))
		return false;

#ifdef CONFIG_X86_64
	if (curve25519_use_avx && irq_fpu_usable()) {
		kernel_fpu_begin();
		curve25519_sandy2x_base(pub, secret);
		kernel_fpu_end();
		return crypto_memneq(pub, null_point, CURVE25519_POINT_SIZE);
	}
#endif
	return curve25519(pub, secret, basepoint);
}
#else
typedef s64 limb;

/* Field element representation:
 *
 * Field elements are written as an array of signed, 64-bit limbs, least
 * significant first. The value of the field element is:
 *   x[0] + 2^26·x[1] + x^51·x[2] + 2^102·x[3] + ...
 *
 * i.e. the limbs are 26, 25, 26, 25, ... bits wide.
 */

/* Sum two numbers: output += in */
static void fsum(limb *output, const limb *in)
{
	unsigned int i;

	for (i = 0; i < 10; i += 2) {
		output[0 + i] = output[0 + i] + in[0 + i];
		output[1 + i] = output[1 + i] + in[1 + i];
	}
}

/* Find the difference of two numbers: output = in - output
 * (note the order of the arguments!).
 */
static void fdifference(limb *output, const limb *in)
{
	unsigned int i;

	for (i = 0; i < 10; ++i)
		output[i] = in[i] - output[i];
}

/* Multiply a number by a scalar: output = in * scalar */
static void fscalar_product(limb *output, const limb *in, const limb scalar)
{
	unsigned int i;

	for (i = 0; i < 10; ++i)
		output[i] = in[i] * scalar;
}

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * output[x] <= 14 * the largest product of the input limbs.
 */
static void fproduct(limb *output, const limb *in2, const limb *in)
{
	output[0] =       ((limb) ((s32) in2[0])) * ((s32) in[0]);
	output[1] =       ((limb) ((s32) in2[0])) * ((s32) in[1]) +
					    ((limb) ((s32) in2[1])) * ((s32) in[0]);
	output[2] =  2 *  ((limb) ((s32) in2[1])) * ((s32) in[1]) +
					    ((limb) ((s32) in2[0])) * ((s32) in[2]) +
					    ((limb) ((s32) in2[2])) * ((s32) in[0]);
	output[3] =       ((limb) ((s32) in2[1])) * ((s32) in[2]) +
					    ((limb) ((s32) in2[2])) * ((s32) in[1]) +
					    ((limb) ((s32) in2[0])) * ((s32) in[3]) +
					    ((limb) ((s32) in2[3])) * ((s32) in[0]);
	output[4] =       ((limb) ((s32) in2[2])) * ((s32) in[2]) +
				       2 * (((limb) ((s32) in2[1])) * ((s32) in[3]) +
					    ((limb) ((s32) in2[3])) * ((s32) in[1])) +
					    ((limb) ((s32) in2[0])) * ((s32) in[4]) +
					    ((limb) ((s32) in2[4])) * ((s32) in[0]);
	output[5] =       ((limb) ((s32) in2[2])) * ((s32) in[3]) +
					    ((limb) ((s32) in2[3])) * ((s32) in[2]) +
					    ((limb) ((s32) in2[1])) * ((s32) in[4]) +
					    ((limb) ((s32) in2[4])) * ((s32) in[1]) +
					    ((limb) ((s32) in2[0])) * ((s32) in[5]) +
					    ((limb) ((s32) in2[5])) * ((s32) in[0]);
	output[6] =  2 * (((limb) ((s32) in2[3])) * ((s32) in[3]) +
					    ((limb) ((s32) in2[1])) * ((s32) in[5]) +
					    ((limb) ((s32) in2[5])) * ((s32) in[1])) +
					    ((limb) ((s32) in2[2])) * ((s32) in[4]) +
					    ((limb) ((s32) in2[4])) * ((s32) in[2]) +
					    ((limb) ((s32) in2[0])) * ((s32) in[6]) +
					    ((limb) ((s32) in2[6])) * ((s32) in[0]);
	output[7] =       ((limb) ((s32) in2[3])) * ((s32) in[4]) +
					    ((limb) ((s32) in2[4])) * ((s32) in[3]) +
					    ((limb) ((s32) in2[2])) * ((s32) in[5]) +
					    ((limb) ((s32) in2[5])) * ((s32) in[2]) +
					    ((limb) ((s32) in2[1])) * ((s32) in[6]) +
					    ((limb) ((s32) in2[6])) * ((s32) in[1]) +
					    ((limb) ((s32) in2[0])) * ((s32) in[7]) +
					    ((limb) ((s32) in2[7])) * ((s32) in[0]);
	output[8] =       ((limb) ((s32) in2[4])) * ((s32) in[4]) +
				       2 * (((limb) ((s32) in2[3])) * ((s32) in[5]) +
					    ((limb) ((s32) in2[5])) * ((s32) in[3]) +
					    ((limb) ((s32) in2[1])) * ((s32) in[7]) +
					    ((limb) ((s32) in2[7])) * ((s32) in[1])) +
					    ((limb) ((s32) in2[2])) * ((s32) in[6]) +
					    ((limb) ((s32) in2[6])) * ((s32) in[2]) +
					    ((limb) ((s32) in2[0])) * ((s32) in[8]) +
					    ((limb) ((s32) in2[8])) * ((s32) in[0]);
	output[9] =       ((limb) ((s32) in2[4])) * ((s32) in[5]) +
					    ((limb) ((s32) in2[5])) * ((s32) in[4]) +
					    ((limb) ((s32) in2[3])) * ((s32) in[6]) +
					    ((limb) ((s32) in2[6])) * ((s32) in[3]) +
					    ((limb) ((s32) in2[2])) * ((s32) in[7]) +
					    ((limb) ((s32) in2[7])) * ((s32) in[2]) +
					    ((limb) ((s32) in2[1])) * ((s32) in[8]) +
					    ((limb) ((s32) in2[8])) * ((s32) in[1]) +
					    ((limb) ((s32) in2[0])) * ((s32) in[9]) +
					    ((limb) ((s32) in2[9])) * ((s32) in[0]);
	output[10] = 2 * (((limb) ((s32) in2[5])) * ((s32) in[5]) +
					    ((limb) ((s32) in2[3])) * ((s32) in[7]) +
					    ((limb) ((s32) in2[7])) * ((s32) in[3]) +
					    ((limb) ((s32) in2[1])) * ((s32) in[9]) +
					    ((limb) ((s32) in2[9])) * ((s32) in[1])) +
					    ((limb) ((s32) in2[4])) * ((s32) in[6]) +
					    ((limb) ((s32) in2[6])) * ((s32) in[4]) +
					    ((limb) ((s32) in2[2])) * ((s32) in[8]) +
					    ((limb) ((s32) in2[8])) * ((s32) in[2]);
	output[11] =      ((limb) ((s32) in2[5])) * ((s32) in[6]) +
					    ((limb) ((s32) in2[6])) * ((s32) in[5]) +
					    ((limb) ((s32) in2[4])) * ((s32) in[7]) +
					    ((limb) ((s32) in2[7])) * ((s32) in[4]) +
					    ((limb) ((s32) in2[3])) * ((s32) in[8]) +
					    ((limb) ((s32) in2[8])) * ((s32) in[3]) +
					    ((limb) ((s32) in2[2])) * ((s32) in[9]) +
					    ((limb) ((s32) in2[9])) * ((s32) in[2]);
	output[12] =      ((limb) ((s32) in2[6])) * ((s32) in[6]) +
				       2 * (((limb) ((s32) in2[5])) * ((s32) in[7]) +
					    ((limb) ((s32) in2[7])) * ((s32) in[5]) +
					    ((limb) ((s32) in2[3])) * ((s32) in[9]) +
					    ((limb) ((s32) in2[9])) * ((s32) in[3])) +
					    ((limb) ((s32) in2[4])) * ((s32) in[8]) +
					    ((limb) ((s32) in2[8])) * ((s32) in[4]);
	output[13] =      ((limb) ((s32) in2[6])) * ((s32) in[7]) +
					    ((limb) ((s32) in2[7])) * ((s32) in[6]) +
					    ((limb) ((s32) in2[5])) * ((s32) in[8]) +
					    ((limb) ((s32) in2[8])) * ((s32) in[5]) +
					    ((limb) ((s32) in2[4])) * ((s32) in[9]) +
					    ((limb) ((s32) in2[9])) * ((s32) in[4]);
	output[14] = 2 * (((limb) ((s32) in2[7])) * ((s32) in[7]) +
					    ((limb) ((s32) in2[5])) * ((s32) in[9]) +
					    ((limb) ((s32) in2[9])) * ((s32) in[5])) +
					    ((limb) ((s32) in2[6])) * ((s32) in[8]) +
					    ((limb) ((s32) in2[8])) * ((s32) in[6]);
	output[15] =      ((limb) ((s32) in2[7])) * ((s32) in[8]) +
					    ((limb) ((s32) in2[8])) * ((s32) in[7]) +
					    ((limb) ((s32) in2[6])) * ((s32) in[9]) +
					    ((limb) ((s32) in2[9])) * ((s32) in[6]);
	output[16] =      ((limb) ((s32) in2[8])) * ((s32) in[8]) +
				       2 * (((limb) ((s32) in2[7])) * ((s32) in[9]) +
					    ((limb) ((s32) in2[9])) * ((s32) in[7]));
	output[17] =      ((limb) ((s32) in2[8])) * ((s32) in[9]) +
					    ((limb) ((s32) in2[9])) * ((s32) in[8]);
	output[18] = 2 *  ((limb) ((s32) in2[9])) * ((s32) in[9]);
}

/* Reduce a long form to a short form by taking the input mod 2^255 - 19.
 *
 * On entry: |output[i]| < 14*2^54
 * On exit: |output[0..8]| < 280*2^54
 */
static void freduce_degree(limb *output)
{
	/* Each of these shifts and adds ends up multiplying the value by 19.
	 *
	 * For output[0..8], the absolute entry value is < 14*2^54 and we add, at
	 * most, 19*14*2^54 thus, on exit, |output[0..8]| < 280*2^54.
	 */
	output[8] += output[18] << 4;
	output[8] += output[18] << 1;
	output[8] += output[18];
	output[7] += output[17] << 4;
	output[7] += output[17] << 1;
	output[7] += output[17];
	output[6] += output[16] << 4;
	output[6] += output[16] << 1;
	output[6] += output[16];
	output[5] += output[15] << 4;
	output[5] += output[15] << 1;
	output[5] += output[15];
	output[4] += output[14] << 4;
	output[4] += output[14] << 1;
	output[4] += output[14];
	output[3] += output[13] << 4;
	output[3] += output[13] << 1;
	output[3] += output[13];
	output[2] += output[12] << 4;
	output[2] += output[12] << 1;
	output[2] += output[12];
	output[1] += output[11] << 4;
	output[1] += output[11] << 1;
	output[1] += output[11];
	output[0] += output[10] << 4;
	output[0] += output[10] << 1;
	output[0] += output[10];
}

#if (-1 & 3) != 3
#error "This code only works on a two's complement system"
#endif

/* return v / 2^26, using only shifts and adds.
 *
 * On entry: v can take any value.
 */
static inline limb div_by_2_26(const limb v)
{
	/* High word of v; no shift needed. */
	const u32 highword = (u32) (((u64) v) >> 32);
	/* Set to all 1s if v was negative; else set to 0s. */
	const s32 sign = ((s32) highword) >> 31;
	/* Set to 0x3ffffff if v was negative; else set to 0. */
	const s32 roundoff = ((u32) sign) >> 6;
	/* Should return v / (1<<26) */
	return (v + roundoff) >> 26;
}

/* return v / (2^25), using only shifts and adds.
 *
 * On entry: v can take any value.
 */
static inline limb div_by_2_25(const limb v)
{
	/* High word of v; no shift needed*/
	const u32 highword = (u32) (((u64) v) >> 32);
	/* Set to all 1s if v was negative; else set to 0s. */
	const s32 sign = ((s32) highword) >> 31;
	/* Set to 0x1ffffff if v was negative; else set to 0. */
	const s32 roundoff = ((u32) sign) >> 7;
	/* Should return v / (1<<25) */
	return (v + roundoff) >> 25;
}

/* Reduce all coefficients of the short form input so that |x| < 2^26.
 *
 * On entry: |output[i]| < 280*2^54
 */
static void freduce_coefficients(limb *output)
{
	unsigned int i;

	output[10] = 0;

	for (i = 0; i < 10; i += 2) {
		limb over = div_by_2_26(output[i]);
		/* The entry condition (that |output[i]| < 280*2^54) means that over is, at
		 * most, 280*2^28 in the first iteration of this loop. This is added to the
		 * next limb and we can approximate the resulting bound of that limb by
		 * 281*2^54.
		 */
		output[i] -= over << 26;
		output[i+1] += over;

		/* For the first iteration, |output[i+1]| < 281*2^54, thus |over| <
		 * 281*2^29. When this is added to the next limb, the resulting bound can
		 * be approximated as 281*2^54.
		 *
		 * For subsequent iterations of the loop, 281*2^54 remains a conservative
		 * bound and no overflow occurs.
		 */
		over = div_by_2_25(output[i+1]);
		output[i+1] -= over << 25;
		output[i+2] += over;
	}
	/* Now |output[10]| < 281*2^29 and all other coefficients are reduced. */
	output[0] += output[10] << 4;
	output[0] += output[10] << 1;
	output[0] += output[10];

	output[10] = 0;

	/* Now output[1..9] are reduced, and |output[0]| < 2^26 + 19*281*2^29
	 * So |over| will be no more than 2^16.
	 */
	{
		limb over = div_by_2_26(output[0]);

		output[0] -= over << 26;
		output[1] += over;
	}

	/* Now output[0,2..9] are reduced, and |output[1]| < 2^25 + 2^16 < 2^26. The
	 * bound on |output[1]| is sufficient to meet our needs.
	 */
}

/* A helpful wrapper around fproduct: output = in * in2.
 *
 * On entry: |in[i]| < 2^27 and |in2[i]| < 2^27.
 *
 * output must be distinct to both inputs. The output is reduced degree
 * (indeed, one need only provide storage for 10 limbs) and |output[i]| < 2^26.
 */
static void fmul(limb *output, const limb *in, const limb *in2)
{
	limb t[19];

	fproduct(t, in, in2);
	/* |t[i]| < 14*2^54 */
	freduce_degree(t);
	freduce_coefficients(t);
	/* |t[i]| < 2^26 */
	memcpy(output, t, sizeof(limb) * 10);
}

/* Square a number: output = in**2
 *
 * output must be distinct from the input. The inputs are reduced coefficient
 * form, the output is not.
 *
 * output[x] <= 14 * the largest product of the input limbs.
 */
static void fsquare_inner(limb *output, const limb *in)
{
	output[0] =       ((limb) ((s32) in[0])) * ((s32) in[0]);
	output[1] =  2 *  ((limb) ((s32) in[0])) * ((s32) in[1]);
	output[2] =  2 * (((limb) ((s32) in[1])) * ((s32) in[1]) +
					    ((limb) ((s32) in[0])) * ((s32) in[2]));
	output[3] =  2 * (((limb) ((s32) in[1])) * ((s32) in[2]) +
					    ((limb) ((s32) in[0])) * ((s32) in[3]));
	output[4] =       ((limb) ((s32) in[2])) * ((s32) in[2]) +
				       4 *  ((limb) ((s32) in[1])) * ((s32) in[3]) +
				       2 *  ((limb) ((s32) in[0])) * ((s32) in[4]);
	output[5] =  2 * (((limb) ((s32) in[2])) * ((s32) in[3]) +
					    ((limb) ((s32) in[1])) * ((s32) in[4]) +
					    ((limb) ((s32) in[0])) * ((s32) in[5]));
	output[6] =  2 * (((limb) ((s32) in[3])) * ((s32) in[3]) +
					    ((limb) ((s32) in[2])) * ((s32) in[4]) +
					    ((limb) ((s32) in[0])) * ((s32) in[6]) +
				       2 *  ((limb) ((s32) in[1])) * ((s32) in[5]));
	output[7] =  2 * (((limb) ((s32) in[3])) * ((s32) in[4]) +
					    ((limb) ((s32) in[2])) * ((s32) in[5]) +
					    ((limb) ((s32) in[1])) * ((s32) in[6]) +
					    ((limb) ((s32) in[0])) * ((s32) in[7]));
	output[8] =       ((limb) ((s32) in[4])) * ((s32) in[4]) +
				       2 * (((limb) ((s32) in[2])) * ((s32) in[6]) +
					    ((limb) ((s32) in[0])) * ((s32) in[8]) +
				       2 * (((limb) ((s32) in[1])) * ((s32) in[7]) +
					    ((limb) ((s32) in[3])) * ((s32) in[5])));
	output[9] =  2 * (((limb) ((s32) in[4])) * ((s32) in[5]) +
					    ((limb) ((s32) in[3])) * ((s32) in[6]) +
					    ((limb) ((s32) in[2])) * ((s32) in[7]) +
					    ((limb) ((s32) in[1])) * ((s32) in[8]) +
					    ((limb) ((s32) in[0])) * ((s32) in[9]));
	output[10] = 2 * (((limb) ((s32) in[5])) * ((s32) in[5]) +
					    ((limb) ((s32) in[4])) * ((s32) in[6]) +
					    ((limb) ((s32) in[2])) * ((s32) in[8]) +
				       2 * (((limb) ((s32) in[3])) * ((s32) in[7]) +
					    ((limb) ((s32) in[1])) * ((s32) in[9])));
	output[11] = 2 * (((limb) ((s32) in[5])) * ((s32) in[6]) +
					    ((limb) ((s32) in[4])) * ((s32) in[7]) +
					    ((limb) ((s32) in[3])) * ((s32) in[8]) +
					    ((limb) ((s32) in[2])) * ((s32) in[9]));
	output[12] =      ((limb) ((s32) in[6])) * ((s32) in[6]) +
				       2 * (((limb) ((s32) in[4])) * ((s32) in[8]) +
				       2 * (((limb) ((s32) in[5])) * ((s32) in[7]) +
					    ((limb) ((s32) in[3])) * ((s32) in[9])));
	output[13] = 2 * (((limb) ((s32) in[6])) * ((s32) in[7]) +
					    ((limb) ((s32) in[5])) * ((s32) in[8]) +
					    ((limb) ((s32) in[4])) * ((s32) in[9]));
	output[14] = 2 * (((limb) ((s32) in[7])) * ((s32) in[7]) +
					    ((limb) ((s32) in[6])) * ((s32) in[8]) +
				       2 *  ((limb) ((s32) in[5])) * ((s32) in[9]));
	output[15] = 2 * (((limb) ((s32) in[7])) * ((s32) in[8]) +
					    ((limb) ((s32) in[6])) * ((s32) in[9]));
	output[16] =      ((limb) ((s32) in[8])) * ((s32) in[8]) +
				       4 *  ((limb) ((s32) in[7])) * ((s32) in[9]);
	output[17] = 2 *  ((limb) ((s32) in[8])) * ((s32) in[9]);
	output[18] = 2 *  ((limb) ((s32) in[9])) * ((s32) in[9]);
}

/* fsquare sets output = in^2.
 *
 * On entry: The |in| argument is in reduced coefficients form and |in[i]| <
 * 2^27.
 *
 * On exit: The |output| argument is in reduced coefficients form (indeed, one
 * need only provide storage for 10 limbs) and |out[i]| < 2^26.
 */
static void fsquare(limb *output, const limb *in)
{
	limb t[19];

	fsquare_inner(t, in);
	/* |t[i]| < 14*2^54 because the largest product of two limbs will be <
	 * 2^(27+27) and fsquare_inner adds together, at most, 14 of those
	 * products.
	 */
	freduce_degree(t);
	freduce_coefficients(t);
	/* |t[i]| < 2^26 */
	memcpy(output, t, sizeof(limb) * 10);
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static inline void fexpand(limb *output, const u8 *input)
{
#define F(n, start, shift, mask) \
	output[n] = ((((limb) input[start + 0]) | \
		      ((limb) input[start + 1]) << 8 | \
		      ((limb) input[start + 2]) << 16 | \
		      ((limb) input[start + 3]) << 24) >> shift) & mask;
	F(0, 0, 0, 0x3ffffff);
	F(1, 3, 2, 0x1ffffff);
	F(2, 6, 3, 0x3ffffff);
	F(3, 9, 5, 0x1ffffff);
	F(4, 12, 6, 0x3ffffff);
	F(5, 16, 0, 0x1ffffff);
	F(6, 19, 1, 0x3ffffff);
	F(7, 22, 3, 0x1ffffff);
	F(8, 25, 4, 0x3ffffff);
	F(9, 28, 6, 0x1ffffff);
#undef F
}

#if (-32 >> 1) != -16
#error "This code only works when >> does sign-extension on negative numbers"
#endif

/* s32_eq returns 0xffffffff iff a == b and zero otherwise. */
static s32 s32_eq(s32 a, s32 b)
{
	a = ~(a ^ b);
	a &= a << 16;
	a &= a << 8;
	a &= a << 4;
	a &= a << 2;
	a &= a << 1;
	return a >> 31;
}

/* s32_gte returns 0xffffffff if a >= b and zero otherwise, where a and b are
 * both non-negative.
 */
static s32 s32_gte(s32 a, s32 b)
{
	a -= b;
	/* a >= 0 iff a >= b. */
	return ~(a >> 31);
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array.
 *
 * On entry: |input_limbs[i]| < 2^26
 */
static void fcontract(u8 *output, limb *input_limbs)
{
	int i;
	int j;
	s32 input[10];
	s32 mask;

	/* |input_limbs[i]| < 2^26, so it's valid to convert to an s32. */
	for (i = 0; i < 10; i++) {
		input[i] = input_limbs[i];
	}

	for (j = 0; j < 2; ++j) {
		for (i = 0; i < 9; ++i) {
			if ((i & 1) == 1) {
				/* This calculation is a time-invariant way to make input[i]
				 * non-negative by borrowing from the next-larger limb.
				 */
				const s32 mask = input[i] >> 31;
				const s32 carry = -((input[i] & mask) >> 25);

				input[i] = input[i] + (carry << 25);
				input[i+1] = input[i+1] - carry;
			} else {
				const s32 mask = input[i] >> 31;
				const s32 carry = -((input[i] & mask) >> 26);

				input[i] = input[i] + (carry << 26);
				input[i+1] = input[i+1] - carry;
			}
		}

		/* There's no greater limb for input[9] to borrow from, but we can multiply
		 * by 19 and borrow from input[0], which is valid mod 2^255-19.
		 */
		{
			const s32 mask = input[9] >> 31;
			const s32 carry = -((input[9] & mask) >> 25);

			input[9] = input[9] + (carry << 25);
			input[0] = input[0] - (carry * 19);
		}

		/* After the first iteration, input[1..9] are non-negative and fit within
		 * 25 or 26 bits, depending on position. However, input[0] may be
		 * negative.
		 */
	}

	/* The first borrow-propagation pass above ended with every limb
	   except (possibly) input[0] non-negative.
	   If input[0] was negative after the first pass, then it was because of a
	   carry from input[9]. On entry, input[9] < 2^26 so the carry was, at most,
	   one, since (2**26-1) >> 25 = 1. Thus input[0] >= -19.
	   In the second pass, each limb is decreased by at most one. Thus the second
	   borrow-propagation pass could only have wrapped around to decrease
	   input[0] again if the first pass left input[0] negative *and* input[1]
	   through input[9] were all zero.  In that case, input[1] is now 2^25 - 1,
	   and this last borrow-propagation step will leave input[1] non-negative. */
	{
		const s32 mask = input[0] >> 31;
		const s32 carry = -((input[0] & mask) >> 26);

		input[0] = input[0] + (carry << 26);
		input[1] = input[1] - carry;
	}

	/* All input[i] are now non-negative. However, there might be values between
	 * 2^25 and 2^26 in a limb which is, nominally, 25 bits wide.
	 */
	for (j = 0; j < 2; j++) {
		for (i = 0; i < 9; i++) {
			if ((i & 1) == 1) {
				const s32 carry = input[i] >> 25;

				input[i] &= 0x1ffffff;
				input[i+1] += carry;
			} else {
				const s32 carry = input[i] >> 26;

				input[i] &= 0x3ffffff;
				input[i+1] += carry;
			}
		}

		{
			const s32 carry = input[9] >> 25;

			input[9] &= 0x1ffffff;
			input[0] += 19*carry;
		}
	}

	/* If the first carry-chain pass, just above, ended up with a carry from
	 * input[9], and that caused input[0] to be out-of-bounds, then input[0] was
	 * < 2^26 + 2*19, because the carry was, at most, two.
	 *
	 * If the second pass carried from input[9] again then input[0] is < 2*19 and
	 * the input[9] -> input[0] carry didn't push input[0] out of bounds.
	 */

	/* It still remains the case that input might be between 2^255-19 and 2^255.
	 * In this case, input[1..9] must take their maximum value and input[0] must
	 * be >= (2^255-19) & 0x3ffffff, which is 0x3ffffed.
	 */
	mask = s32_gte(input[0], 0x3ffffed);
	for (i = 1; i < 10; i++) {
		if ((i & 1) == 1) {
			mask &= s32_eq(input[i], 0x1ffffff);
		} else {
			mask &= s32_eq(input[i], 0x3ffffff);
		}
	}

	/* mask is either 0xffffffff (if input >= 2^255-19) and zero otherwise. Thus
	 * this conditionally subtracts 2^255-19.
	 */
	input[0] -= mask & 0x3ffffed;

	for (i = 1; i < 10; i++) {
		if ((i & 1) == 1) {
			input[i] -= mask & 0x1ffffff;
		} else {
			input[i] -= mask & 0x3ffffff;
		}
	}

	input[1] <<= 2;
	input[2] <<= 3;
	input[3] <<= 5;
	input[4] <<= 6;
	input[6] <<= 1;
	input[7] <<= 3;
	input[8] <<= 4;
	input[9] <<= 6;
#define F(i, s) \
	output[s+0] |=  input[i] & 0xff; \
	output[s+1]  = (input[i] >> 8) & 0xff; \
	output[s+2]  = (input[i] >> 16) & 0xff; \
	output[s+3]  = (input[i] >> 24) & 0xff;
	output[0] = 0;
	output[16] = 0;
	F(0, 0);
	F(1, 3);
	F(2, 6);
	F(3, 9);
	F(4, 12);
	F(5, 16);
	F(6, 19);
	F(7, 22);
	F(8, 25);
	F(9, 28);
#undef F
}

/* Conditionally swap two reduced-form limb arrays if 'iswap' is 1, but leave
 * them unchanged if 'iswap' is 0.  Runs in data-invariant time to avoid
 * side-channel attacks.
 *
 * NOTE that this function requires that 'iswap' be 1 or 0; other values give
 * wrong results.  Also, the two limb arrays must be in reduced-coefficient,
 * reduced-degree form: the values in a[10..19] or b[10..19] aren't swapped,
 * and all all values in a[0..9],b[0..9] must have magnitude less than
 * INT32_MAX.
 */
static void swap_conditional(limb a[19], limb b[19], limb iswap)
{
	unsigned int i;
	const s32 swap = (s32) -iswap;

	for (i = 0; i < 10; ++i) {
		const s32 x = swap & (((s32)a[i]) ^ ((s32)b[i]));

		a[i] = ((s32)a[i]) ^ x;
		b[i] = ((s32)b[i]) ^ x;
	}
}

static void crecip(limb *out, const limb *z)
{
	limb z2[10];
	limb z9[10];
	limb z11[10];
	limb z2_5_0[10];
	limb z2_10_0[10];
	limb z2_20_0[10];
	limb z2_50_0[10];
	limb z2_100_0[10];
	limb t0[10];
	limb t1[10];
	int i;

	/* 2 */ fsquare(z2, z);
	/* 4 */ fsquare(t1, z2);
	/* 8 */ fsquare(t0, t1);
	/* 9 */ fmul(z9, t0, z);
	/* 11 */ fmul(z11, z9, z2);
	/* 22 */ fsquare(t0, z11);
	/* 2^5 - 2^0 = 31 */ fmul(z2_5_0, t0, z9);

	/* 2^6 - 2^1 */ fsquare(t0, z2_5_0);
	/* 2^7 - 2^2 */ fsquare(t1, t0);
	/* 2^8 - 2^3 */ fsquare(t0, t1);
	/* 2^9 - 2^4 */ fsquare(t1, t0);
	/* 2^10 - 2^5 */ fsquare(t0, t1);
	/* 2^10 - 2^0 */ fmul(z2_10_0, t0, z2_5_0);

	/* 2^11 - 2^1 */ fsquare(t0, z2_10_0);
	/* 2^12 - 2^2 */ fsquare(t1, t0);
	/* 2^20 - 2^10 */ for (i = 2; i < 10; i += 2) { fsquare(t0, t1); fsquare(t1, t0); }
	/* 2^20 - 2^0 */ fmul(z2_20_0, t1, z2_10_0);

	/* 2^21 - 2^1 */ fsquare(t0, z2_20_0);
	/* 2^22 - 2^2 */ fsquare(t1, t0);
	/* 2^40 - 2^20 */ for (i = 2; i < 20; i += 2) { fsquare(t0, t1); fsquare(t1, t0); }
	/* 2^40 - 2^0 */ fmul(t0, t1, z2_20_0);

	/* 2^41 - 2^1 */ fsquare(t1, t0);
	/* 2^42 - 2^2 */ fsquare(t0, t1);
	/* 2^50 - 2^10 */ for (i = 2; i < 10; i += 2) { fsquare(t1, t0); fsquare(t0, t1); }
	/* 2^50 - 2^0 */ fmul(z2_50_0, t0, z2_10_0);

	/* 2^51 - 2^1 */ fsquare(t0, z2_50_0);
	/* 2^52 - 2^2 */ fsquare(t1, t0);
	/* 2^100 - 2^50 */ for (i = 2; i < 50; i += 2) { fsquare(t0, t1); fsquare(t1, t0); }
	/* 2^100 - 2^0 */ fmul(z2_100_0, t1, z2_50_0);

	/* 2^101 - 2^1 */ fsquare(t1, z2_100_0);
	/* 2^102 - 2^2 */ fsquare(t0, t1);
	/* 2^200 - 2^100 */ for (i = 2; i < 100; i += 2) { fsquare(t1, t0); fsquare(t0, t1); }
	/* 2^200 - 2^0 */ fmul(t1, t0, z2_100_0);

	/* 2^201 - 2^1 */ fsquare(t0, t1);
	/* 2^202 - 2^2 */ fsquare(t1, t0);
	/* 2^250 - 2^50 */ for (i = 2; i < 50; i += 2) { fsquare(t0, t1); fsquare(t1, t0); }
	/* 2^250 - 2^0 */ fmul(t0, t1, z2_50_0);

	/* 2^251 - 2^1 */ fsquare(t1, t0);
	/* 2^252 - 2^2 */ fsquare(t0, t1);
	/* 2^253 - 2^3 */ fsquare(t1, t0);
	/* 2^254 - 2^4 */ fsquare(t0, t1);
	/* 2^255 - 2^5 */ fsquare(t1, t0);
	/* 2^255 - 21 */ fmul(out, t1, z11);
}


#ifdef ARCH_HAS_SEPARATE_IRQ_STACK
/* Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   x2 z3: long form
 *   x3 z3: long form
 *   x z: short form, destroyed
 *   xprime zprime: short form, destroyed
 *   qmqp: short form, preserved
 *
 * On entry and exit, the absolute value of the limbs of all inputs and outputs
 * are < 2^26.
 */
static void fmonty(limb *x2, limb *z2,  /* output 2Q */
		   limb *x3, limb *z3,  /* output Q + Q' */
		   limb *x, limb *z,    /* input Q */
		   limb *xprime, limb *zprime,  /* input Q' */

		   const limb *qmqp /* input Q - Q' */)
{
	limb origx[10], origxprime[10], zzz[19], xx[19], zz[19], xxprime[19],
				zzprime[19], zzzprime[19], xxxprime[19];

	memcpy(origx, x, 10 * sizeof(limb));
	fsum(x, z);
	/* |x[i]| < 2^27 */
	fdifference(z, origx);  /* does x - z */
	/* |z[i]| < 2^27 */

	memcpy(origxprime, xprime, sizeof(limb) * 10);
	fsum(xprime, zprime);
	/* |xprime[i]| < 2^27 */
	fdifference(zprime, origxprime);
	/* |zprime[i]| < 2^27 */
	fproduct(xxprime, xprime, z);
	/* |xxprime[i]| < 14*2^54: the largest product of two limbs will be <
	 * 2^(27+27) and fproduct adds together, at most, 14 of those products.
	 * (Approximating that to 2^58 doesn't work out.)
	 */
	fproduct(zzprime, x, zprime);
	/* |zzprime[i]| < 14*2^54 */
	freduce_degree(xxprime);
	freduce_coefficients(xxprime);
	/* |xxprime[i]| < 2^26 */
	freduce_degree(zzprime);
	freduce_coefficients(zzprime);
	/* |zzprime[i]| < 2^26 */
	memcpy(origxprime, xxprime, sizeof(limb) * 10);
	fsum(xxprime, zzprime);
	/* |xxprime[i]| < 2^27 */
	fdifference(zzprime, origxprime);
	/* |zzprime[i]| < 2^27 */
	fsquare(xxxprime, xxprime);
	/* |xxxprime[i]| < 2^26 */
	fsquare(zzzprime, zzprime);
	/* |zzzprime[i]| < 2^26 */
	fproduct(zzprime, zzzprime, qmqp);
	/* |zzprime[i]| < 14*2^52 */
	freduce_degree(zzprime);
	freduce_coefficients(zzprime);
	/* |zzprime[i]| < 2^26 */
	memcpy(x3, xxxprime, sizeof(limb) * 10);
	memcpy(z3, zzprime, sizeof(limb) * 10);

	fsquare(xx, x);
	/* |xx[i]| < 2^26 */
	fsquare(zz, z);
	/* |zz[i]| < 2^26 */
	fproduct(x2, xx, zz);
	/* |x2[i]| < 14*2^52 */
	freduce_degree(x2);
	freduce_coefficients(x2);
	/* |x2[i]| < 2^26 */
	fdifference(zz, xx);  // does zz = xx - zz
	/* |zz[i]| < 2^27 */
	memset(zzz + 10, 0, sizeof(limb) * 9);
	fscalar_product(zzz, zz, 121665);
	/* |zzz[i]| < 2^(27+17) */
	/* No need to call freduce_degree here:
		 fscalar_product doesn't increase the degree of its input. */
	freduce_coefficients(zzz);
	/* |zzz[i]| < 2^26 */
	fsum(zzz, xx);
	/* |zzz[i]| < 2^27 */
	fproduct(z2, zz, zzz);
	/* |z2[i]| < 14*2^(26+27) */
	freduce_degree(z2);
	freduce_coefficients(z2);
	/* |z2|i| < 2^26 */
}

/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   resultx/resultz: the x coordinate of the resulting curve point (short form)
 *   n: a little endian, 32-byte number
 *   q: a point of the curve (short form)
 */
static void cmult(limb *resultx, limb *resultz, const u8 *n, const limb *q)
{
	limb a[19] = {0}, b[19] = {1}, c[19] = {1}, d[19] = {0};
	limb *nqpqx = a, *nqpqz = b, *nqx = c, *nqz = d, *t;
	limb e[19] = {0}, f[19] = {1}, g[19] = {0}, h[19] = {1};
	limb *nqpqx2 = e, *nqpqz2 = f, *nqx2 = g, *nqz2 = h;

	unsigned int i, j;

	memcpy(nqpqx, q, sizeof(limb) * 10);

	for (i = 0; i < 32; ++i) {
		u8 byte = n[31 - i];

		for (j = 0; j < 8; ++j) {
			const limb bit = byte >> 7;

			swap_conditional(nqx, nqpqx, bit);
			swap_conditional(nqz, nqpqz, bit);
			fmonty(nqx2, nqz2,
			       nqpqx2, nqpqz2,
			       nqx, nqz,
			       nqpqx, nqpqz,
			       q);
			swap_conditional(nqx2, nqpqx2, bit);
			swap_conditional(nqz2, nqpqz2, bit);

			t = nqx;
			nqx = nqx2;
			nqx2 = t;
			t = nqz;
			nqz = nqz2;
			nqz2 = t;
			t = nqpqx;
			nqpqx = nqpqx2;
			nqpqx2 = t;
			t = nqpqz;
			nqpqz = nqpqz2;
			nqpqz2 = t;

			byte <<= 1;
		}
	}

	memcpy(resultx, nqx, sizeof(limb) * 10);
	memcpy(resultz, nqz, sizeof(limb) * 10);
}

bool curve25519(u8 mypublic[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE], const u8 basepoint[CURVE25519_POINT_SIZE])
{
#if IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && defined(CONFIG_ARM) && !defined(CONFIG_CPU_THUMBONLY)
	if (curve25519_use_neon && may_use_simd()) {
		kernel_neon_begin();
		curve25519_asm_neon(mypublic, secret, basepoint);
		kernel_neon_end();
	} else
#endif
	{
		limb bp[10], x[10], z[11], zmone[10];
		u8 e[32];

		memcpy(e, secret, 32);
		normalize_secret(e);

		fexpand(bp, basepoint);
		cmult(x, z, e, bp);
		crecip(zmone, z);
		fmul(z, x, zmone);
		fcontract(mypublic, z);

		memzero_explicit(e, sizeof(e));
		memzero_explicit(bp, sizeof(bp));
		memzero_explicit(x, sizeof(x));
		memzero_explicit(z, sizeof(z));
		memzero_explicit(zmone, sizeof(zmone));
	}
	return crypto_memneq(mypublic, null_point, CURVE25519_POINT_SIZE);
}
#else
struct other_stack {
	limb origx[10], origxprime[10], zzz[19], xx[19], zz[19], xxprime[19], zzprime[19], zzzprime[19], xxxprime[19];
	limb a[19], b[19], c[19], d[19], e[19], f[19], g[19], h[19];
	limb bp[10], x[10], z[11], zmone[10];
	u8 ee[32];
};

/* Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   x2 z3: long form
 *   x3 z3: long form
 *   x z: short form, destroyed
 *   xprime zprime: short form, destroyed
 *   qmqp: short form, preserved
 *
 * On entry and exit, the absolute value of the limbs of all inputs and outputs
 * are < 2^26.
 */
static void fmonty(struct other_stack *s,
		   limb *x2, limb *z2,  /* output 2Q */
		   limb *x3, limb *z3,  /* output Q + Q' */
		   limb *x, limb *z,    /* input Q */
		   limb *xprime, limb *zprime,  /* input Q' */

		   const limb *qmqp /* input Q - Q' */)
{
	memcpy(s->origx, x, 10 * sizeof(limb));
	fsum(x, z);
	/* |x[i]| < 2^27 */
	fdifference(z, s->origx);  /* does x - z */
	/* |z[i]| < 2^27 */

	memcpy(s->origxprime, xprime, sizeof(limb) * 10);
	fsum(xprime, zprime);
	/* |xprime[i]| < 2^27 */
	fdifference(zprime, s->origxprime);
	/* |zprime[i]| < 2^27 */
	fproduct(s->xxprime, xprime, z);
	/* |s->xxprime[i]| < 14*2^54: the largest product of two limbs will be <
	 * 2^(27+27) and fproduct adds together, at most, 14 of those products.
	 * (Approximating that to 2^58 doesn't work out.)
	 */
	fproduct(s->zzprime, x, zprime);
	/* |s->zzprime[i]| < 14*2^54 */
	freduce_degree(s->xxprime);
	freduce_coefficients(s->xxprime);
	/* |s->xxprime[i]| < 2^26 */
	freduce_degree(s->zzprime);
	freduce_coefficients(s->zzprime);
	/* |s->zzprime[i]| < 2^26 */
	memcpy(s->origxprime, s->xxprime, sizeof(limb) * 10);
	fsum(s->xxprime, s->zzprime);
	/* |s->xxprime[i]| < 2^27 */
	fdifference(s->zzprime, s->origxprime);
	/* |s->zzprime[i]| < 2^27 */
	fsquare(s->xxxprime, s->xxprime);
	/* |s->xxxprime[i]| < 2^26 */
	fsquare(s->zzzprime, s->zzprime);
	/* |s->zzzprime[i]| < 2^26 */
	fproduct(s->zzprime, s->zzzprime, qmqp);
	/* |s->zzprime[i]| < 14*2^52 */
	freduce_degree(s->zzprime);
	freduce_coefficients(s->zzprime);
	/* |s->zzprime[i]| < 2^26 */
	memcpy(x3, s->xxxprime, sizeof(limb) * 10);
	memcpy(z3, s->zzprime, sizeof(limb) * 10);

	fsquare(s->xx, x);
	/* |s->xx[i]| < 2^26 */
	fsquare(s->zz, z);
	/* |s->zz[i]| < 2^26 */
	fproduct(x2, s->xx, s->zz);
	/* |x2[i]| < 14*2^52 */
	freduce_degree(x2);
	freduce_coefficients(x2);
	/* |x2[i]| < 2^26 */
	fdifference(s->zz, s->xx);  // does s->zz = s->xx - s->zz
	/* |s->zz[i]| < 2^27 */
	memset(s->zzz + 10, 0, sizeof(limb) * 9);
	fscalar_product(s->zzz, s->zz, 121665);
	/* |s->zzz[i]| < 2^(27+17) */
	/* No need to call freduce_degree here:
		 fscalar_product doesn't increase the degree of its input. */
	freduce_coefficients(s->zzz);
	/* |s->zzz[i]| < 2^26 */
	fsum(s->zzz, s->xx);
	/* |s->zzz[i]| < 2^27 */
	fproduct(z2, s->zz, s->zzz);
	/* |z2[i]| < 14*2^(26+27) */
	freduce_degree(z2);
	freduce_coefficients(z2);
	/* |z2|i| < 2^26 */
}

/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   resultx/resultz: the x coordinate of the resulting curve point (short form)
 *   n: a little endian, 32-byte number
 *   q: a point of the curve (short form)
 */
static void cmult(struct other_stack *s, limb *resultx, limb *resultz, const u8 *n, const limb *q)
{
	unsigned int i, j;
	limb *nqpqx = s->a, *nqpqz = s->b, *nqx = s->c, *nqz = s->d, *t;
	limb *nqpqx2 = s->e, *nqpqz2 = s->f, *nqx2 = s->g, *nqz2 = s->h;

	*nqpqz = *nqx = *nqpqz2 = *nqz2 = 1;
	memcpy(nqpqx, q, sizeof(limb) * 10);

	for (i = 0; i < 32; ++i) {
		u8 byte = n[31 - i];

		for (j = 0; j < 8; ++j) {
			const limb bit = byte >> 7;

			swap_conditional(nqx, nqpqx, bit);
			swap_conditional(nqz, nqpqz, bit);
			fmonty(s,
			       nqx2, nqz2,
			       nqpqx2, nqpqz2,
			       nqx, nqz,
			       nqpqx, nqpqz,
			       q);
			swap_conditional(nqx2, nqpqx2, bit);
			swap_conditional(nqz2, nqpqz2, bit);

			t = nqx;
			nqx = nqx2;
			nqx2 = t;
			t = nqz;
			nqz = nqz2;
			nqz2 = t;
			t = nqpqx;
			nqpqx = nqpqx2;
			nqpqx2 = t;
			t = nqpqz;
			nqpqz = nqpqz2;
			nqpqz2 = t;

			byte <<= 1;
		}
	}

	memcpy(resultx, nqx, sizeof(limb) * 10);
	memcpy(resultz, nqz, sizeof(limb) * 10);
}

bool curve25519(u8 mypublic[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE], const u8 basepoint[CURVE25519_POINT_SIZE])
{
#if IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && defined(CONFIG_ARM) && !defined(CONFIG_CPU_THUMBONLY)
	if (curve25519_use_neon && may_use_simd()) {
		kernel_neon_begin();
		curve25519_asm_neon(mypublic, secret, basepoint);
		kernel_neon_end();
	} else
#endif
	{
		struct other_stack *s = kzalloc(sizeof(struct other_stack), GFP_KERNEL);

		if (unlikely(!s))
			return false;

		memcpy(s->ee, secret, 32);
		normalize_secret(s->ee);

		fexpand(s->bp, basepoint);
		cmult(s, s->x, s->z, s->ee, s->bp);
		crecip(s->zmone, s->z);
		fmul(s->z, s->x, s->zmone);
		fcontract(mypublic, s->z);

		kzfree(s);
	}
	return crypto_memneq(mypublic, null_point, CURVE25519_POINT_SIZE);
}
#endif
bool curve25519_generate_public(u8 pub[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE])
{
	static const u8 basepoint[CURVE25519_POINT_SIZE] __aligned(32) = { 9 };

	if (unlikely(!crypto_memneq(secret, null_point, CURVE25519_POINT_SIZE)))
		return false;

	return curve25519(pub, secret, basepoint);
}
#endif

void curve25519_generate_secret(u8 secret[CURVE25519_POINT_SIZE])
{
	get_random_bytes_wait(secret, CURVE25519_POINT_SIZE);
	normalize_secret(secret);
}

#include "../selftest/curve25519.h"
