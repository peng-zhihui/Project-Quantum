/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef _WG_HASHTABLES_H
#define _WG_HASHTABLES_H

#include "messages.h"

#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/siphash.h>

struct wireguard_peer;

struct pubkey_hashtable {
	/* TODO: move to rhashtable */
	DECLARE_HASHTABLE(hashtable, 11);
	siphash_key_t key;
	struct mutex lock;
};

void pubkey_hashtable_init(struct pubkey_hashtable *table);
void pubkey_hashtable_add(struct pubkey_hashtable *table, struct wireguard_peer *peer);
void pubkey_hashtable_remove(struct pubkey_hashtable *table, struct wireguard_peer *peer);
struct wireguard_peer *pubkey_hashtable_lookup(struct pubkey_hashtable *table, const u8 pubkey[NOISE_PUBLIC_KEY_LEN]);

struct index_hashtable {
	/* TODO: move to rhashtable */
	DECLARE_HASHTABLE(hashtable, 13);
	spinlock_t lock;
};

enum index_hashtable_type {
	INDEX_HASHTABLE_HANDSHAKE = 1U << 0,
	INDEX_HASHTABLE_KEYPAIR = 1U << 1
};

struct index_hashtable_entry {
	struct wireguard_peer *peer;
	struct hlist_node index_hash;
	enum index_hashtable_type type;
	__le32 index;
};
void index_hashtable_init(struct index_hashtable *table);
__le32 index_hashtable_insert(struct index_hashtable *table, struct index_hashtable_entry *entry);
bool index_hashtable_replace(struct index_hashtable *table, struct index_hashtable_entry *old, struct index_hashtable_entry *new);
void index_hashtable_remove(struct index_hashtable *table, struct index_hashtable_entry *entry);
struct index_hashtable_entry *index_hashtable_lookup(struct index_hashtable *table, const enum index_hashtable_type type_mask, const __le32 index);

#endif /* _WG_HASHTABLES_H */
