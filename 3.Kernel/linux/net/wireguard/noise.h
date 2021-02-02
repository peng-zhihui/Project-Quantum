/*
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * See doc/protocol.md and https://github.com/trevp/noise/blob/master/noise.md for more info
 */

#ifndef _WG_NOISE_H
#define _WG_NOISE_H

#include "messages.h"
#include "hashtables.h"

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <linux/kref.h>

union noise_counter {
	struct {
		u64 counter;
		unsigned long backtrack[COUNTER_BITS_TOTAL / BITS_PER_LONG];
		spinlock_t lock;
	} receive;
	atomic64_t counter;
};

struct noise_symmetric_key {
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	union noise_counter counter;
	u64 birthdate;
	bool is_valid;
};

struct noise_keypair {
	struct index_hashtable_entry entry;
	struct noise_symmetric_key sending;
	struct noise_symmetric_key receiving;
	__le32 remote_index;
	bool i_am_the_initiator;
	struct kref refcount;
	struct rcu_head rcu;
	u64 internal_id;
};

struct noise_keypairs {
	struct noise_keypair __rcu *current_keypair;
	struct noise_keypair __rcu *previous_keypair;
	struct noise_keypair __rcu *next_keypair;
	spinlock_t keypair_update_lock;
};

struct noise_static_identity {
	bool has_identity;
	u8 static_public[NOISE_PUBLIC_KEY_LEN];
	u8 static_private[NOISE_PUBLIC_KEY_LEN];
	struct rw_semaphore lock;
};

enum noise_handshake_state {
	HANDSHAKE_ZEROED,
	HANDSHAKE_CREATED_INITIATION,
	HANDSHAKE_CONSUMED_INITIATION,
	HANDSHAKE_CREATED_RESPONSE,
	HANDSHAKE_CONSUMED_RESPONSE
};

struct noise_handshake {
	struct index_hashtable_entry entry;

	enum noise_handshake_state state;
	u64 last_initiation_consumption;

	struct noise_static_identity *static_identity;

	u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	u8 remote_static[NOISE_PUBLIC_KEY_LEN];
	u8 remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 precomputed_static_static[NOISE_PUBLIC_KEY_LEN];

	u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];

	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];

	u8 latest_timestamp[NOISE_TIMESTAMP_LEN];
	__le32 remote_index;

	/* Protects all members except the immutable (after noise_handshake_init): remote_static, precomputed_static_static, static_identity */
	struct rw_semaphore lock;
};

struct wireguard_device;

void noise_init(void);
bool noise_handshake_init(struct noise_handshake *handshake, struct noise_static_identity *static_identity, const u8 peer_public_key[NOISE_PUBLIC_KEY_LEN], const u8 peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN], struct wireguard_peer *peer);
void noise_handshake_clear(struct noise_handshake *handshake);
void noise_keypair_put(struct noise_keypair *keypair);
struct noise_keypair *noise_keypair_get(struct noise_keypair *keypair);
void noise_keypairs_clear(struct noise_keypairs *keypairs);
bool noise_received_with_keypair(struct noise_keypairs *keypairs, struct noise_keypair *received_keypair);

void noise_set_static_identity_private_key(struct noise_static_identity *static_identity, const u8 private_key[NOISE_PUBLIC_KEY_LEN]);
bool noise_precompute_static_static(struct wireguard_peer *peer);

bool noise_handshake_create_initiation(struct message_handshake_initiation *dst, struct noise_handshake *handshake);
struct wireguard_peer *noise_handshake_consume_initiation(struct message_handshake_initiation *src, struct wireguard_device *wg);

bool noise_handshake_create_response(struct message_handshake_response *dst, struct noise_handshake *peer);
struct wireguard_peer *noise_handshake_consume_response(struct message_handshake_response *src, struct wireguard_device *wg);

bool noise_handshake_begin_session(struct noise_handshake *handshake, struct noise_keypairs *keypairs);

#endif /* _WG_NOISE_H */
