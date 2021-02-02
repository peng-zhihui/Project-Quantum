/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef _WG_BLAKE2S_H
#define _WG_BLAKE2S_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <crypto/algapi.h>

enum blake2s_lengths {
	BLAKE2S_BLOCKBYTES = 64,
	BLAKE2S_OUTBYTES = 32,
	BLAKE2S_KEYBYTES = 32
};

struct blake2s_state {
	u32 h[8];
	u32 t[2];
	u32 f[2];
	u8 buf[BLAKE2S_BLOCKBYTES];
	size_t buflen;
	u8 last_node;
};

void blake2s_init(struct blake2s_state *state, const size_t outlen);
void blake2s_init_key(struct blake2s_state *state, const size_t outlen, const void *key, const size_t keylen);
void blake2s_update(struct blake2s_state *state, const u8 *in, size_t inlen);
void __blake2s_final(struct blake2s_state *state);
static inline void blake2s_final(struct blake2s_state *state, u8 *out, size_t outlen)
{
	int i;

#ifdef DEBUG
	BUG_ON(!out || !outlen || outlen > BLAKE2S_OUTBYTES);
#endif
	__blake2s_final(state);

	if (__builtin_constant_p(outlen) && !(outlen % sizeof(u32))) {
		if (IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) || IS_ALIGNED((unsigned long)out, __alignof__(u32))) {
			__le32 *outwords = (__le32 *)out;

			for (i = 0; i < outlen / sizeof(u32); ++i)
				outwords[i] = cpu_to_le32(state->h[i]);
		} else {
			__le32 buffer[BLAKE2S_OUTBYTES];

			for (i = 0; i < outlen / sizeof(u32); ++i)
				buffer[i] = cpu_to_le32(state->h[i]);
			memcpy(out, buffer, outlen);
			memzero_explicit(buffer, sizeof(buffer));
		}
	} else {
		u8 buffer[BLAKE2S_OUTBYTES] __aligned(__alignof__(u32));
		__le32 *outwords = (__le32 *)buffer;

		for (i = 0; i < 8; ++i)
			outwords[i] = cpu_to_le32(state->h[i]);
		memcpy(out, buffer, outlen);
		memzero_explicit(buffer, sizeof(buffer));
	}

	memzero_explicit(state, sizeof(struct blake2s_state));
}


static inline void blake2s(u8 *out, const u8 *in, const u8 *key, const size_t outlen, size_t inlen, const size_t keylen)
{
	struct blake2s_state state;

#ifdef DEBUG
	BUG_ON((!in && inlen > 0) || !out || !outlen || outlen > BLAKE2S_OUTBYTES || keylen > BLAKE2S_KEYBYTES || (!key && keylen));
#endif

	if (keylen)
		blake2s_init_key(&state, outlen, key, keylen);
	else
		blake2s_init(&state, outlen);

	blake2s_update(&state, in, inlen);
	blake2s_final(&state, out, outlen);
}

void blake2s_hmac(u8 *out, const u8 *in, const u8 *key, const size_t outlen, const size_t inlen, const size_t keylen);

void blake2s_fpu_init(void);

#ifdef DEBUG
bool blake2s_selftest(void);
#endif

#endif /* _WG_BLAKE2S_H */
