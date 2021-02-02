/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef _WG_SOCKET_H
#define _WG_SOCKET_H

#include <linux/netdevice.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>

int socket_init(struct wireguard_device *wg);
void socket_uninit(struct wireguard_device *wg);
int socket_send_buffer_to_peer(struct wireguard_peer *peer, void *data, size_t len, u8 ds);
int socket_send_skb_to_peer(struct wireguard_peer *peer, struct sk_buff *skb, u8 ds);
int socket_send_buffer_as_reply_to_skb(struct wireguard_device *wg, struct sk_buff *in_skb, void *out_buffer, size_t len);

int socket_endpoint_from_skb(struct endpoint *endpoint, const struct sk_buff *skb);
void socket_set_peer_endpoint(struct wireguard_peer *peer, const struct endpoint *endpoint);
void socket_set_peer_endpoint_from_skb(struct wireguard_peer *peer, const struct sk_buff *skb);
void socket_clear_peer_endpoint_src(struct wireguard_peer *peer);

#if defined(CONFIG_DYNAMIC_DEBUG) || defined(DEBUG)
#define net_dbg_skb_ratelimited(fmt, dev, skb, ...) do { \
	struct endpoint __endpoint; \
	socket_endpoint_from_skb(&__endpoint, skb); \
	net_dbg_ratelimited(fmt, dev, &__endpoint.addr, ##__VA_ARGS__); \
} while (0)
#else
#define net_dbg_skb_ratelimited(fmt, skb, ...)
#endif

#endif /* _WG_SOCKET_H */
