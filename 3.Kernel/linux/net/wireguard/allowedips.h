/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef _WG_ALLOWEDIPS_H
#define _WG_ALLOWEDIPS_H

#include <linux/mutex.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct wireguard_peer;
struct allowedips_node;

struct allowedips {
	struct allowedips_node __rcu *root4;
	struct allowedips_node __rcu *root6;
	u64 seq;
};

struct allowedips_cursor {
	u64 seq;
	struct allowedips_node *stack[128];
	unsigned int len;
	bool second_half;
};

void allowedips_init(struct allowedips *table);
void allowedips_free(struct allowedips *table, struct mutex *mutex);
int allowedips_insert_v4(struct allowedips *table, const struct in_addr *ip, u8 cidr, struct wireguard_peer *peer, struct mutex *lock);
int allowedips_insert_v6(struct allowedips *table, const struct in6_addr *ip, u8 cidr, struct wireguard_peer *peer, struct mutex *lock);
void allowedips_remove_by_peer(struct allowedips *table, struct wireguard_peer *peer, struct mutex *lock);
int allowedips_walk_by_peer(struct allowedips *table, struct allowedips_cursor *cursor, struct wireguard_peer *peer, int (*func)(void *ctx, const u8 *ip, u8 cidr, int family), void *ctx, struct mutex *lock);

/* These return a strong reference to a peer: */
struct wireguard_peer *allowedips_lookup_dst(struct allowedips *table, struct sk_buff *skb);
struct wireguard_peer *allowedips_lookup_src(struct allowedips *table, struct sk_buff *skb);

#ifdef DEBUG
bool allowedips_selftest(void);
#endif

#endif /* _WG_ALLOWEDIPS_H */
