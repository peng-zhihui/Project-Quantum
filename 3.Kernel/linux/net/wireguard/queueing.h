/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef _WG_QUEUEING_H
#define _WG_QUEUEING_H

#include "peer.h"
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct wireguard_device;
struct wireguard_peer;
struct multicore_worker;
struct crypt_queue;
struct sk_buff;

/* queueing.c APIs: */
int packet_queue_init(struct crypt_queue *queue, work_func_t function, bool multicore, unsigned int len);
void packet_queue_free(struct crypt_queue *queue, bool multicore);
struct multicore_worker __percpu *packet_alloc_percpu_multicore_worker(work_func_t function, void *ptr);

/* receive.c APIs: */
void packet_receive(struct wireguard_device *wg, struct sk_buff *skb);
void packet_handshake_receive_worker(struct work_struct *work);
/* Workqueue workers: */
void packet_rx_worker(struct work_struct *work);
void packet_decrypt_worker(struct work_struct *work);

/* send.c APIs: */
void packet_send_queued_handshake_initiation(struct wireguard_peer *peer, bool is_retry);
void packet_send_handshake_response(struct wireguard_peer *peer);
void packet_send_handshake_cookie(struct wireguard_device *wg, struct sk_buff *initiating_skb, __le32 sender_index);
void packet_send_keepalive(struct wireguard_peer *peer);
void packet_send_staged_packets(struct wireguard_peer *peer);
/* Workqueue workers: */
void packet_handshake_send_worker(struct work_struct *work);
void packet_tx_worker(struct work_struct *work);
void packet_encrypt_worker(struct work_struct *work);

enum packet_state { PACKET_STATE_UNCRYPTED, PACKET_STATE_CRYPTED, PACKET_STATE_DEAD };
struct packet_cb {
	u64 nonce;
	struct noise_keypair *keypair;
	atomic_t state;
	u8 ds;
};
#define PACKET_PEER(skb) (((struct packet_cb *)skb->cb)->keypair->entry.peer)
#define PACKET_CB(skb) ((struct packet_cb *)skb->cb)

/* Returns either the correct skb->protocol value, or 0 if invalid. */
static inline __be16 skb_examine_untrusted_ip_hdr(struct sk_buff *skb)
{
	if (skb_network_header(skb) >= skb->head && (skb_network_header(skb) + sizeof(struct iphdr)) <= skb_tail_pointer(skb) && ip_hdr(skb)->version == 4)
		return htons(ETH_P_IP);
	if (skb_network_header(skb) >= skb->head && (skb_network_header(skb) + sizeof(struct ipv6hdr)) <= skb_tail_pointer(skb) && ipv6_hdr(skb)->version == 6)
		return htons(ETH_P_IPV6);
	return 0;
}

static inline void skb_reset(struct sk_buff *skb)
{
	skb_scrub_packet(skb, false);
	memset(&skb->headers_start, 0, offsetof(struct sk_buff, headers_end) - offsetof(struct sk_buff, headers_start));
	skb->queue_mapping = 0;
	skb->nohdr = 0;
	skb->peeked = 0;
	skb->mac_len = 0;
	skb->dev = NULL;
#ifdef CONFIG_NET_SCHED
	skb->tc_index = 0;
	skb_reset_tc(skb);
#endif
	skb->hdr_len = skb_headroom(skb);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_probe_transport_header(skb, 0);
	skb_reset_inner_headers(skb);
}

static inline int cpumask_choose_online(int *stored_cpu, unsigned int id)
{
	unsigned int cpu = *stored_cpu, cpu_index, i;

	if (unlikely(cpu == nr_cpumask_bits || !cpumask_test_cpu(cpu, cpu_online_mask))) {
		cpu_index = id % cpumask_weight(cpu_online_mask);
		cpu = cpumask_first(cpu_online_mask);
		for (i = 0; i < cpu_index; ++i)
			cpu = cpumask_next(cpu, cpu_online_mask);
		*stored_cpu = cpu;
	}
	return cpu;
}

/* This function is racy, in the sense that next is unlocked, so it could return
 * the same CPU twice. A race-free version of this would be to instead store an
 * atomic sequence number, do an increment-and-return, and then iterate through
 * every possible CPU until we get to that index -- choose_cpu. However that's
 * a bit slower, and it doesn't seem like this potential race actually introduces
 * any performance loss, so we live with it.
 */
static inline int cpumask_next_online(int *next)
{
	int cpu = *next;

	while (unlikely(!cpumask_test_cpu(cpu, cpu_online_mask)))
		cpu = cpumask_next(cpu, cpu_online_mask) % nr_cpumask_bits;
	*next = cpumask_next(cpu, cpu_online_mask) % nr_cpumask_bits;
	return cpu;
}

static inline int queue_enqueue_per_device_and_peer(struct crypt_queue *device_queue, struct crypt_queue *peer_queue, struct sk_buff *skb, struct workqueue_struct *wq, int *next_cpu)
{
	int cpu;

	atomic_set(&PACKET_CB(skb)->state, PACKET_STATE_UNCRYPTED);
	if (unlikely(ptr_ring_produce_bh(&peer_queue->ring, skb)))
		return -ENOSPC;
	cpu = cpumask_next_online(next_cpu);
	if (unlikely(ptr_ring_produce_bh(&device_queue->ring, skb)))
		return -EPIPE;
	queue_work_on(cpu, wq, &per_cpu_ptr(device_queue->worker, cpu)->work);
	return 0;
}

static inline void queue_enqueue_per_peer(struct crypt_queue *queue, struct sk_buff *skb, enum packet_state state)
{
	struct wireguard_peer *peer = peer_rcu_get(PACKET_PEER(skb));

	atomic_set(&PACKET_CB(skb)->state, state);
	queue_work_on(cpumask_choose_online(&peer->serial_work_cpu, peer->internal_id), peer->device->packet_crypt_wq, &queue->work);
	peer_put(peer);
}

#ifdef DEBUG
bool packet_counter_selftest(void);
#endif

#endif /* _WG_QUEUEING_H */
