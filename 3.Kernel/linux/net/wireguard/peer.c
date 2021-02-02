/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "peer.h"
#include "device.h"
#include "queueing.h"
#include "timers.h"
#include "hashtables.h"
#include "noise.h"

#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/rcupdate.h>
#include <linux/list.h>

static atomic64_t peer_counter = ATOMIC64_INIT(0);

struct wireguard_peer *peer_create(struct wireguard_device *wg, const u8 public_key[NOISE_PUBLIC_KEY_LEN], const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN])
{
	struct wireguard_peer *peer;

	lockdep_assert_held(&wg->device_update_lock);

	if (wg->num_peers >= MAX_PEERS_PER_DEVICE)
		return NULL;
	++wg->num_peers;

	peer = kzalloc(sizeof(struct wireguard_peer), GFP_KERNEL);
	if (!peer)
		return NULL;
	peer->device = wg;

	if (dst_cache_init(&peer->endpoint_cache, GFP_KERNEL)) {
		kfree(peer);
		return NULL;
	}

	peer->internal_id = atomic64_inc_return(&peer_counter);
	peer->serial_work_cpu = nr_cpumask_bits;
	cookie_init(&peer->latest_cookie);
	if (!noise_handshake_init(&peer->handshake, &wg->static_identity, public_key, preshared_key, peer)) {
		kfree(peer);
		return NULL;
	}
	timers_init(peer);
	cookie_checker_precompute_peer_keys(peer);
	spin_lock_init(&peer->keypairs.keypair_update_lock);
	INIT_WORK(&peer->transmit_handshake_work, packet_handshake_send_worker);
	rwlock_init(&peer->endpoint_lock);
	kref_init(&peer->refcount);
	packet_queue_init(&peer->tx_queue, packet_tx_worker, false, MAX_QUEUED_PACKETS);
	packet_queue_init(&peer->rx_queue, packet_rx_worker, false, MAX_QUEUED_PACKETS);
	skb_queue_head_init(&peer->staged_packet_queue);
	list_add_tail(&peer->peer_list, &wg->peer_list);
	pubkey_hashtable_add(&wg->peer_hashtable, peer);
	pr_debug("%s: Peer %llu created\n", wg->dev->name, peer->internal_id);
	return peer;
}

struct wireguard_peer *peer_get(struct wireguard_peer *peer)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(), "Taking peer reference without holding the RCU read lock");
	if (unlikely(!peer || !kref_get_unless_zero(&peer->refcount)))
		return NULL;
	return peer;
}

struct wireguard_peer *peer_rcu_get(struct wireguard_peer *peer)
{
	rcu_read_lock_bh();
	peer = peer_get(peer);
	rcu_read_unlock_bh();
	return peer;
}

/* We have a separate "remove" function to get rid of the final reference because
 * peer_list, clearing handshakes, and flushing all require mutexes which requires
 * sleeping, which must only be done from certain contexts.
 */
void peer_remove(struct wireguard_peer *peer)
{
	if (unlikely(!peer))
		return;
	lockdep_assert_held(&peer->device->device_update_lock);
	allowedips_remove_by_peer(&peer->device->peer_allowedips, peer, &peer->device->device_update_lock);
	pubkey_hashtable_remove(&peer->device->peer_hashtable, peer);
	skb_queue_purge(&peer->staged_packet_queue);
	noise_handshake_clear(&peer->handshake);
	noise_keypairs_clear(&peer->keypairs);
	list_del_init(&peer->peer_list);
	timers_stop(peer);
	flush_workqueue(peer->device->packet_crypt_wq); /* The first flush is for encrypt/decrypt step. */
	flush_workqueue(peer->device->packet_crypt_wq); /* The second flush is for send/receive step. */
	flush_workqueue(peer->device->handshake_send_wq);
	--peer->device->num_peers;
	peer_put(peer);
}

static void rcu_release(struct rcu_head *rcu)
{
	struct wireguard_peer *peer = container_of(rcu, struct wireguard_peer, rcu);

	pr_debug("%s: Peer %llu (%pISpfsc) destroyed\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);
	dst_cache_destroy(&peer->endpoint_cache);
	packet_queue_free(&peer->rx_queue, false);
	packet_queue_free(&peer->tx_queue, false);
	kzfree(peer);
}

static void kref_release(struct kref *refcount)
{
	struct wireguard_peer *peer = container_of(refcount, struct wireguard_peer, refcount);

	index_hashtable_remove(&peer->device->index_hashtable, &peer->handshake.entry);
	skb_queue_purge(&peer->staged_packet_queue);
	call_rcu_bh(&peer->rcu, rcu_release);
}

void peer_put(struct wireguard_peer *peer)
{
	if (unlikely(!peer))
		return;
	kref_put(&peer->refcount, kref_release);
}

void peer_remove_all(struct wireguard_device *wg)
{
	struct wireguard_peer *peer, *temp;

	lockdep_assert_held(&wg->device_update_lock);
	list_for_each_entry_safe(peer, temp, &wg->peer_list, peer_list)
		peer_remove(peer);
}
