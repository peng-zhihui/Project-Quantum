/*
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright 2015 Martin Willi.
 */

#include "chacha20poly1305.h"

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/version.h>
#include <crypto/algapi.h>
#include <crypto/scatterwalk.h>
#include <asm/unaligned.h>

#if defined(CONFIG_X86_64)
#include <asm/cpufeature.h>
#include <asm/processor.h>
#ifdef CONFIG_AS_SSSE3
asmlinkage void hchacha20_asm_ssse3(u8 *derived_key, const u8 *nonce, const u8 *key);
asmlinkage void chacha20_asm_block_xor_ssse3(u32 *state, u8 *dst, const u8 *src);
asmlinkage void chacha20_asm_4block_xor_ssse3(u32 *state, u8 *dst, const u8 *src);
#endif
#ifdef CONFIG_AS_AVX2
asmlinkage void chacha20_asm_8block_xor_avx2(u32 *state, u8 *dst, const u8 *src);
#endif
asmlinkage void poly1305_asm_block_sse2(u32 *h, const u8 *src, const u32 *r, unsigned int blocks);
asmlinkage void poly1305_asm_2block_sse2(u32 *h, const u8 *src, const u32 *r, unsigned int blocks, const u32 *u);
#ifdef CONFIG_AS_AVX2
asmlinkage void poly1305_asm_4block_avx2(u32 *h, const u8 *src, const u32 *r, unsigned int blocks, const u32 *u);
#endif
static bool chacha20poly1305_use_avx2 __read_mostly;
static bool chacha20poly1305_use_ssse3 __read_mostly;
static bool chacha20poly1305_use_sse2 __read_mostly;
void chacha20poly1305_fpu_init(void)
{
	chacha20poly1305_use_sse2 = boot_cpu_has(X86_FEATURE_XMM2);
	chacha20poly1305_use_ssse3 = boot_cpu_has(X86_FEATURE_SSSE3);
	chacha20poly1305_use_avx2 = boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
}
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON)
#include <asm/hwcap.h>
#include <asm/neon.h>
asmlinkage void chacha20_asm_block_xor_neon(u32 *state, u8 *dst, const u8 *src);
asmlinkage void chacha20_asm_4block_xor_neon(u32 *state, u8 *dst, const u8 *src);
static bool chacha20poly1305_use_neon __read_mostly;
void __init chacha20poly1305_fpu_init(void)
{
#if defined(CONFIG_ARM64)
	chacha20poly1305_use_neon = elf_hwcap & HWCAP_ASIMD;
#elif defined(CONFIG_ARM)
	chacha20poly1305_use_neon = elf_hwcap & HWCAP_NEON;
#endif
}
#else
void __init chacha20poly1305_fpu_init(void) { }
#endif

#define CHACHA20_IV_SIZE	16
#define CHACHA20_KEY_SIZE	32
#define CHACHA20_BLOCK_SIZE	64
#define POLY1305_BLOCK_SIZE	16
#define POLY1305_KEY_SIZE	32
#define POLY1305_MAC_SIZE	16

static inline u32 le32_to_cpuvp(const void *p)
{
	return le32_to_cpup(p);
}

static inline u64 le64_to_cpuvp(const void *p)
{
	return le64_to_cpup(p);
}

static inline u32 rotl32(u32 v, u8 n)
{
	return (v << n) | (v >> (sizeof(v) * 8 - n));
}

static inline u64 mlt(u64 a, u64 b)
{
	return a * b;
}

static inline u32 sr(u64 v, u_char n)
{
	return v >> n;
}

static inline u32 and(u32 v, u32 mask)
{
	return v & mask;
}

struct chacha20_ctx {
	u32 state[CHACHA20_BLOCK_SIZE / sizeof(u32)];
} __aligned(32);

static void chacha20_generic_block(struct chacha20_ctx *ctx, void *stream)
{
	u32 x[CHACHA20_BLOCK_SIZE / sizeof(u32)];
	__le32 *out = stream;
	int i;

	for (i = 0; i < ARRAY_SIZE(x); i++)
		x[i] = ctx->state[i];

	for (i = 0; i < 20; i += 2) {
		x[0]  += x[4];    x[12] = rotl32(x[12] ^ x[0],  16);
		x[1]  += x[5];    x[13] = rotl32(x[13] ^ x[1],  16);
		x[2]  += x[6];    x[14] = rotl32(x[14] ^ x[2],  16);
		x[3]  += x[7];    x[15] = rotl32(x[15] ^ x[3],  16);

		x[8]  += x[12];   x[4]  = rotl32(x[4]  ^ x[8],  12);
		x[9]  += x[13];   x[5]  = rotl32(x[5]  ^ x[9],  12);
		x[10] += x[14];   x[6]  = rotl32(x[6]  ^ x[10], 12);
		x[11] += x[15];   x[7]  = rotl32(x[7]  ^ x[11], 12);

		x[0]  += x[4];    x[12] = rotl32(x[12] ^ x[0],   8);
		x[1]  += x[5];    x[13] = rotl32(x[13] ^ x[1],   8);
		x[2]  += x[6];    x[14] = rotl32(x[14] ^ x[2],   8);
		x[3]  += x[7];    x[15] = rotl32(x[15] ^ x[3],   8);

		x[8]  += x[12];   x[4]  = rotl32(x[4]  ^ x[8],   7);
		x[9]  += x[13];   x[5]  = rotl32(x[5]  ^ x[9],   7);
		x[10] += x[14];   x[6]  = rotl32(x[6]  ^ x[10],  7);
		x[11] += x[15];   x[7]  = rotl32(x[7]  ^ x[11],  7);

		x[0]  += x[5];    x[15] = rotl32(x[15] ^ x[0],  16);
		x[1]  += x[6];    x[12] = rotl32(x[12] ^ x[1],  16);
		x[2]  += x[7];    x[13] = rotl32(x[13] ^ x[2],  16);
		x[3]  += x[4];    x[14] = rotl32(x[14] ^ x[3],  16);

		x[10] += x[15];   x[5]  = rotl32(x[5]  ^ x[10], 12);
		x[11] += x[12];   x[6]  = rotl32(x[6]  ^ x[11], 12);
		x[8]  += x[13];   x[7]  = rotl32(x[7]  ^ x[8],  12);
		x[9]  += x[14];   x[4]  = rotl32(x[4]  ^ x[9],  12);

		x[0]  += x[5];    x[15] = rotl32(x[15] ^ x[0],   8);
		x[1]  += x[6];    x[12] = rotl32(x[12] ^ x[1],   8);
		x[2]  += x[7];    x[13] = rotl32(x[13] ^ x[2],   8);
		x[3]  += x[4];    x[14] = rotl32(x[14] ^ x[3],   8);

		x[10] += x[15];   x[5]  = rotl32(x[5]  ^ x[10],  7);
		x[11] += x[12];   x[6]  = rotl32(x[6]  ^ x[11],  7);
		x[8]  += x[13];   x[7]  = rotl32(x[7]  ^ x[8],   7);
		x[9]  += x[14];   x[4]  = rotl32(x[4]  ^ x[9],   7);
	}

	for (i = 0; i < ARRAY_SIZE(x); i++)
		out[i] = cpu_to_le32(x[i] + ctx->state[i]);

	ctx->state[12]++;
}

static const char constant[16] = "expand 32-byte k";

static void hchacha20_generic(u8 derived_key[CHACHA20POLY1305_KEYLEN], const u8 nonce[16], const u8 key[CHACHA20POLY1305_KEYLEN])
{
	u32 x[CHACHA20_BLOCK_SIZE / sizeof(u32)];
	__le32 *out = (__force __le32 *)derived_key;
	int i;

	x[0]  = le32_to_cpuvp(constant +  0);
	x[1]  = le32_to_cpuvp(constant +  4);
	x[2]  = le32_to_cpuvp(constant +  8);
	x[3]  = le32_to_cpuvp(constant + 12);
	x[4]  = le32_to_cpuvp(key + 0);
	x[5]  = le32_to_cpuvp(key + 4);
	x[6]  = le32_to_cpuvp(key + 8);
	x[7]  = le32_to_cpuvp(key + 12);
	x[8]  = le32_to_cpuvp(key + 16);
	x[9]  = le32_to_cpuvp(key + 20);
	x[10] = le32_to_cpuvp(key + 24);
	x[11] = le32_to_cpuvp(key + 28);
	x[12]  = le32_to_cpuvp(nonce +  0);
	x[13]  = le32_to_cpuvp(nonce +  4);
	x[14]  = le32_to_cpuvp(nonce +  8);
	x[15]  = le32_to_cpuvp(nonce + 12);

	for (i = 0; i < 20; i += 2) {
		x[0]  += x[4];    x[12] = rotl32(x[12] ^ x[0],  16);
		x[1]  += x[5];    x[13] = rotl32(x[13] ^ x[1],  16);
		x[2]  += x[6];    x[14] = rotl32(x[14] ^ x[2],  16);
		x[3]  += x[7];    x[15] = rotl32(x[15] ^ x[3],  16);

		x[8]  += x[12];   x[4]  = rotl32(x[4]  ^ x[8],  12);
		x[9]  += x[13];   x[5]  = rotl32(x[5]  ^ x[9],  12);
		x[10] += x[14];   x[6]  = rotl32(x[6]  ^ x[10], 12);
		x[11] += x[15];   x[7]  = rotl32(x[7]  ^ x[11], 12);

		x[0]  += x[4];    x[12] = rotl32(x[12] ^ x[0],   8);
		x[1]  += x[5];    x[13] = rotl32(x[13] ^ x[1],   8);
		x[2]  += x[6];    x[14] = rotl32(x[14] ^ x[2],   8);
		x[3]  += x[7];    x[15] = rotl32(x[15] ^ x[3],   8);

		x[8]  += x[12];   x[4]  = rotl32(x[4]  ^ x[8],   7);
		x[9]  += x[13];   x[5]  = rotl32(x[5]  ^ x[9],   7);
		x[10] += x[14];   x[6]  = rotl32(x[6]  ^ x[10],  7);
		x[11] += x[15];   x[7]  = rotl32(x[7]  ^ x[11],  7);

		x[0]  += x[5];    x[15] = rotl32(x[15] ^ x[0],  16);
		x[1]  += x[6];    x[12] = rotl32(x[12] ^ x[1],  16);
		x[2]  += x[7];    x[13] = rotl32(x[13] ^ x[2],  16);
		x[3]  += x[4];    x[14] = rotl32(x[14] ^ x[3],  16);

		x[10] += x[15];   x[5]  = rotl32(x[5]  ^ x[10], 12);
		x[11] += x[12];   x[6]  = rotl32(x[6]  ^ x[11], 12);
		x[8]  += x[13];   x[7]  = rotl32(x[7]  ^ x[8],  12);
		x[9]  += x[14];   x[4]  = rotl32(x[4]  ^ x[9],  12);

		x[0]  += x[5];    x[15] = rotl32(x[15] ^ x[0],   8);
		x[1]  += x[6];    x[12] = rotl32(x[12] ^ x[1],   8);
		x[2]  += x[7];    x[13] = rotl32(x[13] ^ x[2],   8);
		x[3]  += x[4];    x[14] = rotl32(x[14] ^ x[3],   8);

		x[10] += x[15];   x[5]  = rotl32(x[5]  ^ x[10],  7);
		x[11] += x[12];   x[6]  = rotl32(x[6]  ^ x[11],  7);
		x[8]  += x[13];   x[7]  = rotl32(x[7]  ^ x[8],   7);
		x[9]  += x[14];   x[4]  = rotl32(x[4]  ^ x[9],   7);
	}

	out[0] = cpu_to_le32(x[0]);
	out[1] = cpu_to_le32(x[1]);
	out[2] = cpu_to_le32(x[2]);
	out[3] = cpu_to_le32(x[3]);
	out[4] = cpu_to_le32(x[12]);
	out[5] = cpu_to_le32(x[13]);
	out[6] = cpu_to_le32(x[14]);
	out[7] = cpu_to_le32(x[15]);
}

static inline void hchacha20(u8 derived_key[CHACHA20POLY1305_KEYLEN], const u8 nonce[16], const u8 key[CHACHA20POLY1305_KEYLEN], bool have_simd)
{
	if (!have_simd)
		goto no_simd;

#if defined(CONFIG_X86_64) && defined(CONFIG_AS_SSSE3)
	if (chacha20poly1305_use_ssse3) {
		hchacha20_asm_ssse3(derived_key, nonce, key);
		return;
	}
#endif

no_simd:
	hchacha20_generic(derived_key, nonce, key);
}

static void chacha20_keysetup(struct chacha20_ctx *ctx, const u8 key[CHACHA20_KEY_SIZE], const u8 nonce[sizeof(u64)])
{
	ctx->state[0]  = le32_to_cpuvp(constant +  0);
	ctx->state[1]  = le32_to_cpuvp(constant +  4);
	ctx->state[2]  = le32_to_cpuvp(constant +  8);
	ctx->state[3]  = le32_to_cpuvp(constant + 12);
	ctx->state[4]  = le32_to_cpuvp(key + 0);
	ctx->state[5]  = le32_to_cpuvp(key + 4);
	ctx->state[6]  = le32_to_cpuvp(key + 8);
	ctx->state[7]  = le32_to_cpuvp(key + 12);
	ctx->state[8]  = le32_to_cpuvp(key + 16);
	ctx->state[9]  = le32_to_cpuvp(key + 20);
	ctx->state[10] = le32_to_cpuvp(key + 24);
	ctx->state[11] = le32_to_cpuvp(key + 28);
	ctx->state[12] = 0;
	ctx->state[13] = 0;
	ctx->state[14] = le32_to_cpuvp(nonce + 0);
	ctx->state[15] = le32_to_cpuvp(nonce + 4);
}

static void chacha20_crypt(struct chacha20_ctx *ctx, u8 *dst, const u8 *src, unsigned int bytes, bool have_simd)
{
	u8 buf[CHACHA20_BLOCK_SIZE];

	if (!have_simd
#if defined(CONFIG_X86_64)
		|| !chacha20poly1305_use_ssse3

#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON)
		|| !chacha20poly1305_use_neon
#endif
	)
		goto no_simd;

#if defined(CONFIG_X86_64)
#ifdef CONFIG_AS_AVX2
	if (chacha20poly1305_use_avx2) {
		while (bytes >= CHACHA20_BLOCK_SIZE * 8) {
			chacha20_asm_8block_xor_avx2(ctx->state, dst, src);
			bytes -= CHACHA20_BLOCK_SIZE * 8;
			src += CHACHA20_BLOCK_SIZE * 8;
			dst += CHACHA20_BLOCK_SIZE * 8;
			ctx->state[12] += 8;
		}
	}
#endif
#ifdef CONFIG_AS_SSSE3
	while (bytes >= CHACHA20_BLOCK_SIZE * 4) {
		chacha20_asm_4block_xor_ssse3(ctx->state, dst, src);
		bytes -= CHACHA20_BLOCK_SIZE * 4;
		src += CHACHA20_BLOCK_SIZE * 4;
		dst += CHACHA20_BLOCK_SIZE * 4;
		ctx->state[12] += 4;
	}
	while (bytes >= CHACHA20_BLOCK_SIZE) {
		chacha20_asm_block_xor_ssse3(ctx->state, dst, src);
		bytes -= CHACHA20_BLOCK_SIZE;
		src += CHACHA20_BLOCK_SIZE;
		dst += CHACHA20_BLOCK_SIZE;
		ctx->state[12]++;
	}
	if (bytes) {
		memcpy(buf, src, bytes);
		chacha20_asm_block_xor_ssse3(ctx->state, buf, buf);
		memcpy(dst, buf, bytes);
	}
	return;
#endif
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON)
	while (bytes >= CHACHA20_BLOCK_SIZE * 4) {
		chacha20_asm_4block_xor_neon(ctx->state, dst, src);
		bytes -= CHACHA20_BLOCK_SIZE * 4;
		src += CHACHA20_BLOCK_SIZE * 4;
		dst += CHACHA20_BLOCK_SIZE * 4;
		ctx->state[12] += 4;
	}
	while (bytes >= CHACHA20_BLOCK_SIZE) {
		chacha20_asm_block_xor_neon(ctx->state, dst, src);
		bytes -= CHACHA20_BLOCK_SIZE;
		src += CHACHA20_BLOCK_SIZE;
		dst += CHACHA20_BLOCK_SIZE;
		ctx->state[12]++;
	}
	if (bytes) {
		memcpy(buf, src, bytes);
		chacha20_asm_block_xor_neon(ctx->state, buf, buf);
		memcpy(dst, buf, bytes);
	}
	return;
#endif

no_simd:
	if (dst != src)
		memcpy(dst, src, bytes);

	while (bytes >= CHACHA20_BLOCK_SIZE) {
		chacha20_generic_block(ctx, buf);
		crypto_xor(dst, buf, CHACHA20_BLOCK_SIZE);
		bytes -= CHACHA20_BLOCK_SIZE;
		dst += CHACHA20_BLOCK_SIZE;
	}
	if (bytes) {
		chacha20_generic_block(ctx, buf);
		crypto_xor(dst, buf, bytes);
	}
}

struct poly1305_ctx {
	/* key */
	u32 r[5];
	/* finalize key */
	u32 s[4];
	/* accumulator */
	u32 h[5];
	/* partial buffer */
	u8 buf[POLY1305_BLOCK_SIZE];
	/* bytes used in partial buffer */
	unsigned int buflen;
	/* derived key u set? */
	bool uset;
	/* derived keys r^3, r^4 set? */
	bool wset;
	/* derived Poly1305 key r^2 */
	u32 u[5];
	/* derived Poly1305 key r^3 */
	u32 r3[5];
	/* derived Poly1305 key r^4 */
	u32 r4[5];
};

static void poly1305_init(struct poly1305_ctx *ctx, const u8 key[POLY1305_KEY_SIZE])
{
	memset(ctx, 0, sizeof(struct poly1305_ctx));
	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	ctx->r[0] = (le32_to_cpuvp(key +  0) >> 0) & 0x3ffffff;
	ctx->r[1] = (get_unaligned_le32(key +  3) >> 2) & 0x3ffff03;
	ctx->r[2] = (get_unaligned_le32(key +  6) >> 4) & 0x3ffc0ff;
	ctx->r[3] = (get_unaligned_le32(key +  9) >> 6) & 0x3f03fff;
	ctx->r[4] = (le32_to_cpuvp(key + 12) >> 8) & 0x00fffff;
	ctx->s[0] = le32_to_cpuvp(key +  16);
	ctx->s[1] = le32_to_cpuvp(key +  20);
	ctx->s[2] = le32_to_cpuvp(key +  24);
	ctx->s[3] = le32_to_cpuvp(key +  28);
}

static unsigned int poly1305_generic_blocks(struct poly1305_ctx *ctx, const u8 *src, unsigned int srclen, u32 hibit)
{
	u32 r0, r1, r2, r3, r4;
	u32 s1, s2, s3, s4;
	u32 h0, h1, h2, h3, h4;
	u64 d0, d1, d2, d3, d4;

	r0 = ctx->r[0];
	r1 = ctx->r[1];
	r2 = ctx->r[2];
	r3 = ctx->r[3];
	r4 = ctx->r[4];

	s1 = r1 * 5;
	s2 = r2 * 5;
	s3 = r3 * 5;
	s4 = r4 * 5;

	h0 = ctx->h[0];
	h1 = ctx->h[1];
	h2 = ctx->h[2];
	h3 = ctx->h[3];
	h4 = ctx->h[4];

	while (likely(srclen >= POLY1305_BLOCK_SIZE)) {
		/* h += m[i] */
		h0 += (le32_to_cpuvp(src +  0) >> 0) & 0x3ffffff;
		h1 += (get_unaligned_le32(src +  3) >> 2) & 0x3ffffff;
		h2 += (get_unaligned_le32(src +  6) >> 4) & 0x3ffffff;
		h3 += (get_unaligned_le32(src +  9) >> 6) & 0x3ffffff;
		h4 += (le32_to_cpuvp(src + 12) >> 8) | hibit;

		/* h *= r */
		d0 = mlt(h0, r0) + mlt(h1, s4) + mlt(h2, s3) + mlt(h3, s2) + mlt(h4, s1);
		d1 = mlt(h0, r1) + mlt(h1, r0) + mlt(h2, s4) + mlt(h3, s3) + mlt(h4, s2);
		d2 = mlt(h0, r2) + mlt(h1, r1) + mlt(h2, r0) + mlt(h3, s4) + mlt(h4, s3);
		d3 = mlt(h0, r3) + mlt(h1, r2) + mlt(h2, r1) + mlt(h3, r0) + mlt(h4, s4);
		d4 = mlt(h0, r4) + mlt(h1, r3) + mlt(h2, r2) + mlt(h3, r1) + mlt(h4, r0);

		/* (partial) h %= p */
		d1 += sr(d0, 26);     h0 = and(d0, 0x3ffffff);
		d2 += sr(d1, 26);     h1 = and(d1, 0x3ffffff);
		d3 += sr(d2, 26);     h2 = and(d2, 0x3ffffff);
		d4 += sr(d3, 26);     h3 = and(d3, 0x3ffffff);
		h0 += sr(d4, 26) * 5; h4 = and(d4, 0x3ffffff);
		h1 += h0 >> 26;       h0 = h0 & 0x3ffffff;

		src += POLY1305_BLOCK_SIZE;
		srclen -= POLY1305_BLOCK_SIZE;
	}

	ctx->h[0] = h0;
	ctx->h[1] = h1;
	ctx->h[2] = h2;
	ctx->h[3] = h3;
	ctx->h[4] = h4;

	return srclen;
}

#ifdef CONFIG_X86_64
static void poly1305_simd_mult(u32 *a, const u32 *b)
{
	u8 m[POLY1305_BLOCK_SIZE];

	memset(m, 0, sizeof(m));
	/* The poly1305 block function adds a hi-bit to the accumulator which
	 * we don't need for key multiplication; compensate for it.
	 */
	a[4] -= 1U << 24;
	poly1305_asm_block_sse2(a, m, b, 1);
}

static unsigned int poly1305_simd_blocks(struct poly1305_ctx *ctx, const u8 *src, unsigned int srclen)
{
	unsigned int blocks;

#ifdef CONFIG_AS_AVX2
	if (chacha20poly1305_use_avx2 && srclen >= POLY1305_BLOCK_SIZE * 4) {
		if (unlikely(!ctx->wset)) {
			if (!ctx->uset) {
				memcpy(ctx->u, ctx->r, sizeof(ctx->u));
				poly1305_simd_mult(ctx->u, ctx->r);
				ctx->uset = true;
			}
			memcpy(ctx->r3, ctx->u, sizeof(ctx->u));
			poly1305_simd_mult(ctx->r3, ctx->r);
			memcpy(ctx->r4, ctx->r3, sizeof(ctx->u));
			poly1305_simd_mult(ctx->r4, ctx->r);
			ctx->wset = true;
		}
		blocks = srclen / (POLY1305_BLOCK_SIZE * 4);
		poly1305_asm_4block_avx2(ctx->h, src, ctx->r, blocks, ctx->u);
		src += POLY1305_BLOCK_SIZE * 4 * blocks;
		srclen -= POLY1305_BLOCK_SIZE * 4 * blocks;
	}
#endif
	if (likely(srclen >= POLY1305_BLOCK_SIZE * 2)) {
		if (unlikely(!ctx->uset)) {
			memcpy(ctx->u, ctx->r, sizeof(ctx->u));
			poly1305_simd_mult(ctx->u, ctx->r);
			ctx->uset = true;
		}
		blocks = srclen / (POLY1305_BLOCK_SIZE * 2);
		poly1305_asm_2block_sse2(ctx->h, src, ctx->r, blocks, ctx->u);
		src += POLY1305_BLOCK_SIZE * 2 * blocks;
		srclen -= POLY1305_BLOCK_SIZE * 2 * blocks;
	}
	if (srclen >= POLY1305_BLOCK_SIZE) {
		poly1305_asm_block_sse2(ctx->h, src, ctx->r, 1);
		srclen -= POLY1305_BLOCK_SIZE;
	}
	return srclen;
}
#endif

static void poly1305_update(struct poly1305_ctx *ctx, const u8 *src, unsigned int srclen, bool have_simd)
{
	unsigned int bytes;

	if (unlikely(ctx->buflen)) {
		bytes = min(srclen, POLY1305_BLOCK_SIZE - ctx->buflen);
		memcpy(ctx->buf + ctx->buflen, src, bytes);
		src += bytes;
		srclen -= bytes;
		ctx->buflen += bytes;

		if (ctx->buflen == POLY1305_BLOCK_SIZE) {
#ifdef CONFIG_X86_64
			if (have_simd && chacha20poly1305_use_sse2)
				poly1305_simd_blocks(ctx, ctx->buf, POLY1305_BLOCK_SIZE);
			else
#endif
				poly1305_generic_blocks(ctx, ctx->buf, POLY1305_BLOCK_SIZE, 1U << 24);
			ctx->buflen = 0;
		}
	}

	if (likely(srclen >= POLY1305_BLOCK_SIZE)) {
#ifdef CONFIG_X86_64
		if (have_simd && chacha20poly1305_use_sse2)
			bytes = poly1305_simd_blocks(ctx, src, srclen);
		else
#endif
			bytes = poly1305_generic_blocks(ctx, src, srclen, 1U << 24);
		src += srclen - bytes;
		srclen = bytes;
	}

	if (unlikely(srclen)) {
		ctx->buflen = srclen;
		memcpy(ctx->buf, src, srclen);
	}
}

static void poly1305_finish(struct poly1305_ctx *ctx, u8 *dst)
{
	__le32 *mac = (__le32 *)dst;
	u32 h0, h1, h2, h3, h4;
	u32 g0, g1, g2, g3, g4;
	u32 mask;
	u64 f = 0;

	if (unlikely(ctx->buflen)) {
		ctx->buf[ctx->buflen++] = 1;
		memset(ctx->buf + ctx->buflen, 0, POLY1305_BLOCK_SIZE - ctx->buflen);
		poly1305_generic_blocks(ctx, ctx->buf, POLY1305_BLOCK_SIZE, 0);
	}

	/* fully carry h */
	h0 = ctx->h[0];
	h1 = ctx->h[1];
	h2 = ctx->h[2];
	h3 = ctx->h[3];
	h4 = ctx->h[4];

	h2 += (h1 >> 26);     h1 = h1 & 0x3ffffff;
	h3 += (h2 >> 26);     h2 = h2 & 0x3ffffff;
	h4 += (h3 >> 26);     h3 = h3 & 0x3ffffff;
	h0 += (h4 >> 26) * 5; h4 = h4 & 0x3ffffff;
	h1 += (h0 >> 26);     h0 = h0 & 0x3ffffff;

	/* compute h + -p */
	g0 = h0 + 5;
	g1 = h1 + (g0 >> 26);              g0 &= 0x3ffffff;
	g2 = h2 + (g1 >> 26);              g1 &= 0x3ffffff;
	g3 = h3 + (g2 >> 26);              g2 &= 0x3ffffff;
	g4 = h4 + (g3 >> 26) - (1U << 26); g3 &= 0x3ffffff;

	/* select h if h < p, or h + -p if h >= p */
	mask = (g4 >> ((sizeof(u32) * 8) - 1)) - 1;
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* h = h % (2^128) */
	h0 = (h0 >>  0) | (h1 << 26);
	h1 = (h1 >>  6) | (h2 << 20);
	h2 = (h2 >> 12) | (h3 << 14);
	h3 = (h3 >> 18) | (h4 <<  8);

	/* mac = (h + s) % (2^128) */
	f = (f >> 32) + h0 + ctx->s[0]; mac[0] = cpu_to_le32(f);
	f = (f >> 32) + h1 + ctx->s[1]; mac[1] = cpu_to_le32(f);
	f = (f >> 32) + h2 + ctx->s[2]; mac[2] = cpu_to_le32(f);
	f = (f >> 32) + h3 + ctx->s[3]; mac[3] = cpu_to_le32(f);
}

static const u8 pad0[16] = { 0 };

static struct crypto_alg chacha20_alg = {
	.cra_blocksize = 1,
	.cra_alignmask = sizeof(u32) - 1
};
static struct crypto_blkcipher chacha20_cipher = {
	.base = {
		.__crt_alg = &chacha20_alg
	}
};
static struct blkcipher_desc chacha20_desc = {
	.tfm = &chacha20_cipher
};

static inline void __chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
					      const u8 *ad, const size_t ad_len,
					      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
					      bool have_simd)
{
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state;
	u8 block0[CHACHA20_BLOCK_SIZE] = { 0 };
	__le64 len;
	__le64 le_nonce = cpu_to_le64(nonce);

	chacha20_keysetup(&chacha20_state, key, (u8 *)&le_nonce);

	chacha20_crypt(&chacha20_state, block0, block0, sizeof(block0), have_simd);
	poly1305_init(&poly1305_state, block0);
	memzero_explicit(block0, sizeof(block0));

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	chacha20_crypt(&chacha20_state, dst, src, src_len, have_simd);

	poly1305_update(&poly1305_state, dst, src_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - src_len) & 0xf, have_simd);

	len = cpu_to_le64(ad_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	len = cpu_to_le64(src_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	poly1305_finish(&poly1305_state, dst + src_len);

	memzero_explicit(&poly1305_state, sizeof(poly1305_state));
	memzero_explicit(&chacha20_state, sizeof(chacha20_state));
}

void chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			      const u8 *ad, const size_t ad_len,
			      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool have_simd;

	have_simd = chacha20poly1305_init_simd();
	__chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, nonce, key, have_simd);
	chacha20poly1305_deinit_simd(have_simd);
}

bool chacha20poly1305_encrypt_sg(struct scatterlist *dst, struct scatterlist *src, const size_t src_len,
				 const u8 *ad, const size_t ad_len,
				 const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
				 bool have_simd)
{
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state;
	int ret = 0;
	struct blkcipher_walk walk;
	u8 block0[CHACHA20_BLOCK_SIZE] = { 0 };
	u8 mac[POLY1305_MAC_SIZE];
	__le64 len;
	__le64 le_nonce = cpu_to_le64(nonce);

	chacha20_keysetup(&chacha20_state, key, (u8 *)&le_nonce);

	chacha20_crypt(&chacha20_state, block0, block0, sizeof(block0), have_simd);
	poly1305_init(&poly1305_state, block0);
	memzero_explicit(block0, sizeof(block0));

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	if (likely(src_len)) {
		blkcipher_walk_init(&walk, dst, src, src_len);
		ret = blkcipher_walk_virt_block(&chacha20_desc, &walk, CHACHA20_BLOCK_SIZE);
		while (walk.nbytes >= CHACHA20_BLOCK_SIZE) {
			size_t chunk_len = rounddown(walk.nbytes, CHACHA20_BLOCK_SIZE);

			chacha20_crypt(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, chunk_len, have_simd);
			poly1305_update(&poly1305_state, walk.dst.virt.addr, chunk_len, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, walk.nbytes % CHACHA20_BLOCK_SIZE);
		}
		if (walk.nbytes) {
			chacha20_crypt(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, walk.nbytes, have_simd);
			poly1305_update(&poly1305_state, walk.dst.virt.addr, walk.nbytes, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, 0);
		}
	}
	if (unlikely(ret))
		goto err;

	poly1305_update(&poly1305_state, pad0, (0x10 - src_len) & 0xf, have_simd);

	len = cpu_to_le64(ad_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	len = cpu_to_le64(src_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	poly1305_finish(&poly1305_state, mac);
	scatterwalk_map_and_copy(mac, dst, src_len, sizeof(mac), 1);
err:
	memzero_explicit(&poly1305_state, sizeof(poly1305_state));
	memzero_explicit(&chacha20_state, sizeof(chacha20_state));
	memzero_explicit(mac, sizeof(mac));
	return !ret;
}

static inline bool __chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
					      const u8 *ad, const size_t ad_len,
					      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
					      bool have_simd)
{
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state;
	int ret;
	u8 block0[CHACHA20_BLOCK_SIZE] = { 0 };
	u8 mac[POLY1305_MAC_SIZE];
	size_t dst_len;
	__le64 len;
	__le64 le_nonce = cpu_to_le64(nonce);

	if (unlikely(src_len < POLY1305_MAC_SIZE))
		return false;

	chacha20_keysetup(&chacha20_state, key, (u8 *)&le_nonce);

	chacha20_crypt(&chacha20_state, block0, block0, sizeof(block0), have_simd);
	poly1305_init(&poly1305_state, block0);
	memzero_explicit(block0, sizeof(block0));

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	dst_len = src_len - POLY1305_MAC_SIZE;
	poly1305_update(&poly1305_state, src, dst_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - dst_len) & 0xf, have_simd);

	len = cpu_to_le64(ad_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	len = cpu_to_le64(dst_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	poly1305_finish(&poly1305_state, mac);
	memzero_explicit(&poly1305_state, sizeof(poly1305_state));

	ret = crypto_memneq(mac, src + dst_len, POLY1305_MAC_SIZE);
	memzero_explicit(mac, POLY1305_MAC_SIZE);
	if (likely(!ret))
		chacha20_crypt(&chacha20_state, dst, src, dst_len, have_simd);

	memzero_explicit(&chacha20_state, sizeof(chacha20_state));

	return !ret;
}

bool chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			      const u8 *ad, const size_t ad_len,
			      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool have_simd, ret;

	have_simd = chacha20poly1305_init_simd();
	ret = __chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, nonce, key, have_simd);
	chacha20poly1305_deinit_simd(have_simd);
	return ret;
}

bool chacha20poly1305_decrypt_sg(struct scatterlist *dst, struct scatterlist *src, const size_t src_len,
				 const u8 *ad, const size_t ad_len,
				 const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
				 bool have_simd)
{
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state;
	struct blkcipher_walk walk;
	int ret = 0;
	u8 block0[CHACHA20_BLOCK_SIZE] = { 0 };
	u8 read_mac[POLY1305_MAC_SIZE], computed_mac[POLY1305_MAC_SIZE];
	size_t dst_len;
	__le64 len;
	__le64 le_nonce = cpu_to_le64(nonce);

	if (unlikely(src_len < POLY1305_MAC_SIZE))
		return false;

	chacha20_keysetup(&chacha20_state, key, (u8 *)&le_nonce);

	chacha20_crypt(&chacha20_state, block0, block0, sizeof(block0), have_simd);
	poly1305_init(&poly1305_state, block0);
	memzero_explicit(block0, sizeof(block0));

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	dst_len = src_len - POLY1305_MAC_SIZE;
	if (likely(dst_len)) {
		blkcipher_walk_init(&walk, dst, src, dst_len);
		ret = blkcipher_walk_virt_block(&chacha20_desc, &walk, CHACHA20_BLOCK_SIZE);
		while (walk.nbytes >= CHACHA20_BLOCK_SIZE) {
			size_t chunk_len = rounddown(walk.nbytes, CHACHA20_BLOCK_SIZE);

			poly1305_update(&poly1305_state, walk.src.virt.addr, chunk_len, have_simd);
			chacha20_crypt(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, chunk_len, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, walk.nbytes % CHACHA20_BLOCK_SIZE);
		}
		if (walk.nbytes) {
			poly1305_update(&poly1305_state, walk.src.virt.addr, walk.nbytes, have_simd);
			chacha20_crypt(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, walk.nbytes, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, 0);
		}
	}
	if (unlikely(ret))
		goto err;

	poly1305_update(&poly1305_state, pad0, (0x10 - dst_len) & 0xf, have_simd);

	len = cpu_to_le64(ad_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	len = cpu_to_le64(dst_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	poly1305_finish(&poly1305_state, computed_mac);
	memzero_explicit(&poly1305_state, sizeof(poly1305_state));

	scatterwalk_map_and_copy(read_mac, src, dst_len, POLY1305_MAC_SIZE, 0);
	ret = crypto_memneq(read_mac, computed_mac, POLY1305_MAC_SIZE);
err:
	memzero_explicit(read_mac, POLY1305_MAC_SIZE);
	memzero_explicit(computed_mac, POLY1305_MAC_SIZE);
	memzero_explicit(&chacha20_state, sizeof(chacha20_state));
	return !ret;
}


void xchacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[XCHACHA20POLY1305_NONCELEN],
			       const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool have_simd = chacha20poly1305_init_simd();
	u8 derived_key[CHACHA20POLY1305_KEYLEN] __aligned(16);

	hchacha20(derived_key, nonce, key, have_simd);
	__chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, le64_to_cpuvp(nonce + 16), derived_key, have_simd);
	memzero_explicit(derived_key, CHACHA20POLY1305_KEYLEN);
	chacha20poly1305_deinit_simd(have_simd);
}

bool xchacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[XCHACHA20POLY1305_NONCELEN],
			       const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool ret, have_simd = chacha20poly1305_init_simd();
	u8 derived_key[CHACHA20POLY1305_KEYLEN] __aligned(16);

	hchacha20(derived_key, nonce, key, have_simd);
	ret = __chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, le64_to_cpuvp(nonce + 16), derived_key, have_simd);
	memzero_explicit(derived_key, CHACHA20POLY1305_KEYLEN);
	chacha20poly1305_deinit_simd(have_simd);
	return ret;
}

#include "../selftest/chacha20poly1305.h"
