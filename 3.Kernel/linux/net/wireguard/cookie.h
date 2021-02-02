/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef _WG_COOKIE_H
#define _WG_COOKIE_H

#include "messages.h"
#include <linux/rwsem.h>

struct wireguard_peer;

struct cookie_checker {
	u8 secret[NOISE_HASH_LEN];
	u8 cookie_encryption_key[NOISE_SYMMETRIC_KEY_LEN];
	u8 message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
	u64 secret_birthdate;
	struct rw_semaphore secret_lock;
	struct wireguard_device *device;
};

struct cookie {
	u64 birthdate;
	bool is_valid;
	u8 cookie[COOKIE_LEN];
	bool have_sent_mac1;
	u8 last_mac1_sent[COOKIE_LEN];
	u8 cookie_decryption_key[NOISE_SYMMETRIC_KEY_LEN];
	u8 message_mac1_key[NOISE_SYMMETRIC_KEY_LEN];
	struct rw_semaphore lock;
};

enum cookie_mac_state {
	INVALID_MAC,
	VALID_MAC_BUT_NO_COOKIE,
	VALID_MAC_WITH_COOKIE_BUT_RATELIMITED,
	VALID_MAC_WITH_COOKIE
};

void cookie_checker_init(struct cookie_checker *checker, struct wireguard_device *wg);
void cookie_checker_precompute_device_keys(struct cookie_checker *checker);
void cookie_checker_precompute_peer_keys(struct wireguard_peer *peer);
void cookie_init(struct cookie *cookie);

enum cookie_mac_state cookie_validate_packet(struct cookie_checker *checker, struct sk_buff *skb, bool check_cookie);
void cookie_add_mac_to_packet(void *message, size_t len, struct wireguard_peer *peer);

void cookie_message_create(struct message_handshake_cookie *src, struct sk_buff *skb, __le32 index, struct cookie_checker *checker);
void cookie_message_consume(struct message_handshake_cookie *src, struct wireguard_device *wg);

#endif /* _WG_COOKIE_H */
