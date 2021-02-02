/* Original author: Samuel Neves <sneves@dei.uc.pt>
 *
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "blake2s.h"

#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/bug.h>
#include <asm/unaligned.h>

typedef struct {
	u8 digest_length;
	u8 key_length;
	u8 fanout;
	u8 depth;
	u32 leaf_length;
	u32 node_offset;
	u16 xof_length;
	u8 node_depth;
	u8 inner_length;
	u8 salt[8];
	u8 personal[8];
} __packed blake2s_param;

static const u32 blake2s_iv[8] = {
	0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
	0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const u8 blake2s_sigma[10][16] = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

static inline u32 le32_to_cpuvp(const void *p)
{
	return le32_to_cpup(p);
}

static inline void blake2s_set_lastblock(struct blake2s_state *state)
{
	if (state->last_node)
		state->f[1] = -1;
	state->f[0] = -1;
}

static inline void blake2s_increment_counter(struct blake2s_state *state, const u32 inc)
{
	state->t[0] += inc;
	state->t[1] += (state->t[0] < inc);
}

static inline void blake2s_init_param(struct blake2s_state *state, const blake2s_param *param)
{
	const __le32 *p;
	int i;

	memset(state, 0, sizeof(struct blake2s_state));
	for (i = 0; i < 8; ++i)
		state->h[i] = blake2s_iv[i];
	p = (const __le32 *)param;
	/* IV XOR ParamBlock */
	for (i = 0; i < 8; ++i)
		state->h[i] ^= le32_to_cpu(p[i]);
}

void blake2s_init(struct blake2s_state *state, const size_t outlen)
{
	blake2s_param param __aligned(__alignof__(u32)) = {
		.digest_length = outlen,
		.fanout = 1,
		.depth = 1
	};

#ifdef DEBUG
	BUG_ON(!outlen || outlen > BLAKE2S_OUTBYTES);
#endif
	blake2s_init_param(state, &param);
}

void blake2s_init_key(struct blake2s_state *state, const size_t outlen, const void *key, const size_t keylen)
{
	blake2s_param param = {
		.digest_length = outlen,
		.key_length = keylen,
		.fanout = 1,
		.depth = 1
	};
	u8 block[BLAKE2S_BLOCKBYTES] = { 0 };

#ifdef DEBUG
	BUG_ON(!outlen || outlen > BLAKE2S_OUTBYTES || !key || !keylen || keylen > BLAKE2S_KEYBYTES);
#endif
	blake2s_init_param(state, &param);
	memcpy(block, key, keylen);
	blake2s_update(state, block, BLAKE2S_BLOCKBYTES);
	memzero_explicit(block, BLAKE2S_BLOCKBYTES);
}

#ifdef CONFIG_X86_64
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/fpu/api.h>
#include <asm/simd.h>
static bool blake2s_use_avx __read_mostly;
void __init blake2s_fpu_init(void)
{
	blake2s_use_avx = boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
}
asmlinkage void blake2s_compress_avx(struct blake2s_state *state, const u8 *block, size_t nblocks, u32 inc);
#else
void __init blake2s_fpu_init(void) { }
#endif

static inline void blake2s_compress(struct blake2s_state *state, const u8 *block, size_t nblocks, u32 inc)
{
	u32 m[16];
	u32 v[16];
	int i;

#ifdef DEBUG
	BUG_ON(nblocks > 1 && inc != BLAKE2S_BLOCKBYTES);
#endif

#ifdef CONFIG_X86_64
	if (blake2s_use_avx && irq_fpu_usable()) {
		kernel_fpu_begin();
		blake2s_compress_avx(state, block, nblocks, inc);
		kernel_fpu_end();
		return;
	}
#endif

	while (nblocks > 0) {
		blake2s_increment_counter(state, inc);

#ifdef __LITTLE_ENDIAN
		memcpy(m, block, BLAKE2S_BLOCKBYTES);
#else
		for (i = 0; i < 16; ++i)
			m[i] = get_unaligned_le32(block + i * sizeof(m[i]));
#endif
		memcpy(v, state->h, 32);
		v[ 8] = blake2s_iv[0];
		v[ 9] = blake2s_iv[1];
		v[10] = blake2s_iv[2];
		v[11] = blake2s_iv[3];
		v[12] = blake2s_iv[4] ^ state->t[0];
		v[13] = blake2s_iv[5] ^ state->t[1];
		v[14] = blake2s_iv[6] ^ state->f[0];
		v[15] = blake2s_iv[7] ^ state->f[1];

#define G(r, i, a, b, c, d) do { \
	a += b + m[blake2s_sigma[r][2 * i + 0]]; \
	d = ror32(d ^ a, 16); \
	c += d; \
	b = ror32(b ^ c, 12); \
	a += b + m[blake2s_sigma[r][2 * i + 1]]; \
	d = ror32(d ^ a, 8); \
	c += d; \
	b = ror32(b ^ c, 7); \
} while (0)

#define ROUND(r) do { \
	G(r, 0, v[0], v[ 4], v[ 8], v[12]); \
	G(r, 1, v[1], v[ 5], v[ 9], v[13]); \
	G(r, 2, v[2], v[ 6], v[10], v[14]); \
	G(r, 3, v[3], v[ 7], v[11], v[15]); \
	G(r, 4, v[0], v[ 5], v[10], v[15]); \
	G(r, 5, v[1], v[ 6], v[11], v[12]); \
	G(r, 6, v[2], v[ 7], v[ 8], v[13]); \
	G(r, 7, v[3], v[ 4], v[ 9], v[14]); \
} while (0)
		ROUND(0);
		ROUND(1);
		ROUND(2);
		ROUND(3);
		ROUND(4);
		ROUND(5);
		ROUND(6);
		ROUND(7);
		ROUND(8);
		ROUND(9);

#undef G
#undef ROUND

		for (i = 0; i < 8; ++i)
			state->h[i] ^= v[i] ^ v[i + 8];

		block += BLAKE2S_BLOCKBYTES;
		--nblocks;
	}
}

void blake2s_update(struct blake2s_state *state, const u8 *in, size_t inlen)
{
	const size_t fill = BLAKE2S_BLOCKBYTES - state->buflen;

	if (unlikely(!inlen))
		return;
	if (inlen > fill) {
		memcpy(state->buf + state->buflen, in, fill);
		blake2s_compress(state, state->buf, 1, BLAKE2S_BLOCKBYTES);
		state->buflen = 0;
		in += fill;
		inlen -= fill;
	}
	if (inlen > BLAKE2S_BLOCKBYTES) {
		const size_t nblocks = (inlen + BLAKE2S_BLOCKBYTES - 1) / BLAKE2S_BLOCKBYTES;
		/* Hash one less (full) block than strictly possible */
		blake2s_compress(state, in, nblocks - 1, BLAKE2S_BLOCKBYTES);
		in += BLAKE2S_BLOCKBYTES * (nblocks - 1);
		inlen -= BLAKE2S_BLOCKBYTES * (nblocks - 1);
	}
	memcpy(state->buf + state->buflen, in, inlen);
	state->buflen += inlen;
}

void __blake2s_final(struct blake2s_state *state)
{
	blake2s_set_lastblock(state);
	memset(state->buf + state->buflen, 0, BLAKE2S_BLOCKBYTES - state->buflen); /* Padding */
	blake2s_compress(state, state->buf, 1, state->buflen);
}

void blake2s_hmac(u8 *out, const u8 *in, const u8 *key, const size_t outlen, const size_t inlen, const size_t keylen)
{
	struct blake2s_state state;
	u8 o_key[BLAKE2S_BLOCKBYTES] __aligned(__alignof__(u32)) = { 0 };
	u8 i_key[BLAKE2S_BLOCKBYTES] __aligned(__alignof__(u32)) = { 0 };
	u8 i_hash[BLAKE2S_OUTBYTES] __aligned(__alignof__(u32));
	int i;

	if (keylen > BLAKE2S_BLOCKBYTES) {
		blake2s_init(&state, BLAKE2S_OUTBYTES);
		blake2s_update(&state, key, keylen);
		blake2s_final(&state, o_key, BLAKE2S_OUTBYTES);
		memcpy(i_key, o_key, BLAKE2S_OUTBYTES);
	} else {
		memcpy(o_key, key, keylen);
		memcpy(i_key, key, keylen);
	}

	for (i = 0; i < BLAKE2S_BLOCKBYTES; ++i) {
		o_key[i] ^= 0x5c;
		i_key[i] ^= 0x36;
	}

	blake2s_init(&state, BLAKE2S_OUTBYTES);
	blake2s_update(&state, i_key, BLAKE2S_BLOCKBYTES);
	blake2s_update(&state, in, inlen);
	blake2s_final(&state, i_hash, BLAKE2S_OUTBYTES);

	blake2s_init(&state, BLAKE2S_OUTBYTES);
	blake2s_update(&state, o_key, BLAKE2S_BLOCKBYTES);
	blake2s_update(&state, i_hash, BLAKE2S_OUTBYTES);
	blake2s_final(&state, i_hash, BLAKE2S_OUTBYTES);

	memcpy(out, i_hash, outlen);
	memzero_explicit(o_key, BLAKE2S_BLOCKBYTES);
	memzero_explicit(i_key, BLAKE2S_BLOCKBYTES);
	memzero_explicit(i_hash, BLAKE2S_OUTBYTES);
}

#include "../selftest/blake2s.h"
