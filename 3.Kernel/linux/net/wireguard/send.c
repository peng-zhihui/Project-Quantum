/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "queueing.h"
#include "timers.h"
#include "device.h"
#include "peer.h"
#include "socket.h"
#include "messages.h"
#include "cookie.h"

#include <linux/uio.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/jiffies.h>
#include <net/ip_tunnels.h>
#include <net/udp.h>
#include <net/sock.h>

static void packet_send_handshake_initiation(struct wireguard_peer *peer)
{
	struct message_handshake_initiation packet;

	down_write(&peer->handshake.lock);
	if (!time_is_before_jiffies64(peer->last_sent_handshake + REKEY_TIMEOUT)) {
		up_write(&peer->handshake.lock);
		return; /* This function is rate limited. */
	}
	peer->last_sent_handshake = get_jiffies_64();
	up_write(&peer->handshake.lock);

	net_dbg_ratelimited("%s: Sending handshake initiation to peer %llu (%pISpfsc)\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);

	if (noise_handshake_create_initiation(&packet, &peer->handshake)) {
		cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		timers_any_authenticated_packet_traversal(peer);
		socket_send_buffer_to_peer(peer, &packet, sizeof(struct message_handshake_initiation), HANDSHAKE_DSCP);
		timers_handshake_initiated(peer);
	}
}

void packet_handshake_send_worker(struct work_struct *work)
{
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, transmit_handshake_work);

	packet_send_handshake_initiation(peer);
	peer_put(peer);
}

void packet_send_queued_handshake_initiation(struct wireguard_peer *peer, bool is_retry)
{
	if (!is_retry)
		peer->timer_handshake_attempts = 0;

	/* First checking the timestamp here is just an optimization; it will
	 * be caught while properly locked inside the actual work queue.
	 */
	if (!time_is_before_jiffies64(peer->last_sent_handshake + REKEY_TIMEOUT))
		return;

	peer = peer_rcu_get(peer);
	/* Queues up calling packet_send_queued_handshakes(peer), where we do a peer_put(peer) after: */
	if (!queue_work(peer->device->handshake_send_wq, &peer->transmit_handshake_work))
		peer_put(peer); /* If the work was already queued, we want to drop the extra reference */
}

void packet_send_handshake_response(struct wireguard_peer *peer)
{
	struct message_handshake_response packet;

	net_dbg_ratelimited("%s: Sending handshake response to peer %llu (%pISpfsc)\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);
	peer->last_sent_handshake = get_jiffies_64();

	if (noise_handshake_create_response(&packet, &peer->handshake)) {
		cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		if (noise_handshake_begin_session(&peer->handshake, &peer->keypairs)) {
			timers_session_derived(peer);
			timers_any_authenticated_packet_traversal(peer);
			socket_send_buffer_to_peer(peer, &packet, sizeof(struct message_handshake_response), HANDSHAKE_DSCP);
		}
	}
}

void packet_send_handshake_cookie(struct wireguard_device *wg, struct sk_buff *initiating_skb, __le32 sender_index)
{
	struct message_handshake_cookie packet;

	net_dbg_skb_ratelimited("%s: Sending cookie response for denied handshake message for %pISpfsc\n", wg->dev->name, initiating_skb);
	cookie_message_create(&packet, initiating_skb, sender_index, &wg->cookie_checker);
	socket_send_buffer_as_reply_to_skb(wg, initiating_skb, &packet, sizeof(packet));
}

static inline void keep_key_fresh(struct wireguard_peer *peer)
{
	struct noise_keypair *keypair;
	bool send = false;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	if (likely(keypair && keypair->sending.is_valid) &&
	   (unlikely(atomic64_read(&keypair->sending.counter.counter) > REKEY_AFTER_MESSAGES) ||
	   (keypair->i_am_the_initiator && unlikely(time_is_before_eq_jiffies64(keypair->sending.birthdate + REKEY_AFTER_TIME)))))
		send = true;
	rcu_read_unlock_bh();

	if (send)
		packet_send_queued_handshake_initiation(peer, false);
}

static inline unsigned int skb_padding(struct sk_buff *skb)
{
	/* We do this modulo business with the MTU, just in case the networking layer
	 * gives us a packet that's bigger than the MTU. Since we support GSO, this
	 * isn't strictly neccessary, but it's better to be cautious here, especially
	 * if that code ever changes.
	 */
	unsigned int last_unit = skb->len % skb->dev->mtu;
	unsigned int padded_size = (last_unit + MESSAGE_PADDING_MULTIPLE - 1) & ~(MESSAGE_PADDING_MULTIPLE - 1);

	if (padded_size > skb->dev->mtu)
		padded_size = skb->dev->mtu;
	return padded_size - last_unit;
}

static inline bool skb_encrypt(struct sk_buff *skb, struct noise_keypair *keypair, bool have_simd)
{
	struct scatterlist sg[MAX_SKB_FRAGS * 2 + 1];
	struct message_data *header;
	unsigned int padding_len, plaintext_len, trailer_len;
	int num_frags;
	struct sk_buff *trailer;

	/* Calculate lengths */
	padding_len = skb_padding(skb);
	trailer_len = padding_len + noise_encrypted_len(0);
	plaintext_len = skb->len + padding_len;

	/* Expand data section to have room for padding and auth tag */
	num_frags = skb_cow_data(skb, trailer_len, &trailer);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	/* Set the padding to zeros, and make sure it and the auth tag are part of the skb */
	memset(skb_tail_pointer(trailer), 0, padding_len);

	/* Expand head section to have room for our header and the network stack's headers. */
	if (unlikely(skb_cow_head(skb, DATA_PACKET_HEAD_ROOM) < 0))
		return false;

	/* We have to remember to add the checksum to the innerpacket, in case the receiver forwards it. */
	if (likely(!skb_checksum_setup(skb, true)))
		skb_checksum_help(skb);

	/* Only after checksumming can we safely add on the padding at the end and the header. */
	skb_set_inner_network_header(skb, 0);
	header = (struct message_data *)skb_push(skb, sizeof(struct message_data));
	header->header.type = cpu_to_le32(MESSAGE_DATA);
	header->key_idx = keypair->remote_index;
	header->counter = cpu_to_le64(PACKET_CB(skb)->nonce);
	pskb_put(skb, trailer, trailer_len);

	/* Now we can encrypt the scattergather segments */
	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, sizeof(struct message_data), noise_encrypted_len(plaintext_len)) <= 0)
		return false;
	return chacha20poly1305_encrypt_sg(sg, sg, plaintext_len, NULL, 0, PACKET_CB(skb)->nonce, keypair->sending.key, have_simd);
}

void packet_send_keepalive(struct wireguard_peer *peer)
{
	struct sk_buff *skb;

	if (skb_queue_empty(&peer->staged_packet_queue)) {
		skb = alloc_skb(DATA_PACKET_HEAD_ROOM + MESSAGE_MINIMUM_LENGTH, GFP_ATOMIC);
		if (unlikely(!skb))
			return;
		skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
		skb->dev = peer->device->dev;
		skb_queue_tail(&peer->staged_packet_queue, skb);
		net_dbg_ratelimited("%s: Sending keepalive packet to peer %llu (%pISpfsc)\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);
	}

	packet_send_staged_packets(peer);
}

#define skb_walk_null_queue_safe(first, skb, next) for (skb = first, next = skb->next; skb; skb = next, next = skb ? skb->next : NULL)
static inline void skb_free_null_queue(struct sk_buff *first)
{
	struct sk_buff *skb, *next;

	skb_walk_null_queue_safe(first, skb, next)
		dev_kfree_skb(skb);
}

static void packet_create_data_done(struct sk_buff *first, struct wireguard_peer *peer)
{
	struct sk_buff *skb, *next;
	bool is_keepalive, data_sent = false;

	timers_any_authenticated_packet_traversal(peer);
	skb_walk_null_queue_safe(first, skb, next) {
		is_keepalive = skb->len == message_data_len(0);
		if (likely(!socket_send_skb_to_peer(peer, skb, PACKET_CB(skb)->ds) && !is_keepalive))
			data_sent = true;
	}

	if (likely(data_sent))
		timers_data_sent(peer);

	keep_key_fresh(peer);
}

void packet_tx_worker(struct work_struct *work)
{
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct wireguard_peer *peer;
	struct noise_keypair *keypair;
	struct sk_buff *first;
	enum packet_state state;

	spin_lock_bh(&queue->ring.consumer_lock);
	while ((first = __ptr_ring_peek(&queue->ring)) != NULL && (state = atomic_read(&PACKET_CB(first)->state)) != PACKET_STATE_UNCRYPTED) {
		__ptr_ring_discard_one(&queue->ring);
		peer = PACKET_PEER(first);
		keypair = PACKET_CB(first)->keypair;

		if (likely(state == PACKET_STATE_CRYPTED))
			packet_create_data_done(first, peer);
		else
			skb_free_null_queue(first);

		noise_keypair_put(keypair);
		peer_put(peer);
	}
	spin_unlock_bh(&queue->ring.consumer_lock);
}

void packet_encrypt_worker(struct work_struct *work)
{
	struct crypt_queue *queue = container_of(work, struct multicore_worker, work)->ptr;
	struct sk_buff *first, *skb, *next;
	bool have_simd = chacha20poly1305_init_simd();

	while ((first = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		enum packet_state state = PACKET_STATE_CRYPTED;

		skb_walk_null_queue_safe(first, skb, next) {
			if (likely(skb_encrypt(skb, PACKET_CB(first)->keypair, have_simd)))
				skb_reset(skb);
			else {
				state = PACKET_STATE_DEAD;
				break;
			}
		}
		queue_enqueue_per_peer(&PACKET_PEER(first)->tx_queue, first, state);
	}
	chacha20poly1305_deinit_simd(have_simd);
}

static void packet_create_data(struct sk_buff *first)
{
	struct wireguard_peer *peer = PACKET_PEER(first);
	struct wireguard_device *wg = peer->device;
	int ret;

	ret = queue_enqueue_per_device_and_peer(&wg->encrypt_queue, &peer->tx_queue, first, wg->packet_crypt_wq, &wg->encrypt_queue.last_cpu);
	if (likely(!ret))
		return; /* Successful. No need to fall through to drop references below. */

	if (ret == -EPIPE)
		queue_enqueue_per_peer(&peer->tx_queue, first, PACKET_STATE_DEAD);
	else {
		peer_put(peer);
		noise_keypair_put(PACKET_CB(first)->keypair);
		skb_free_null_queue(first);
	}
}

void packet_send_staged_packets(struct wireguard_peer *peer)
{
	struct noise_keypair *keypair;
	struct noise_symmetric_key *key;
	struct sk_buff_head packets;
	struct sk_buff *skb;

	/* Steal the current queue into our local one. */
	__skb_queue_head_init(&packets);
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice_init(&peer->staged_packet_queue, &packets);
	spin_unlock_bh(&peer->staged_packet_queue.lock);
	if (unlikely(skb_queue_empty(&packets)))
		return;

	/* First we make sure we have a valid reference to a valid key. */
	rcu_read_lock_bh();
	keypair = noise_keypair_get(rcu_dereference_bh(peer->keypairs.current_keypair));
	rcu_read_unlock_bh();
	if (unlikely(!keypair))
		goto out_nokey;
	key = &keypair->sending;
	if (unlikely(!key || !key->is_valid))
		goto out_nokey;
	if (unlikely(time_is_before_eq_jiffies64(key->birthdate + REJECT_AFTER_TIME)))
		goto out_invalid;

	/* After we know we have a somewhat valid key, we now try to assign nonces to
	 * all of the packets in the queue. If we can't assign nonces for all of them,
	 * we just consider it a failure and wait for the next handshake.
	 */
	skb_queue_walk(&packets, skb) {
		PACKET_CB(skb)->ds = ip_tunnel_ecn_encap(0 /* No outer TOS: no leak. TODO: should we use flowi->tos as outer? */, ip_hdr(skb), skb);
		PACKET_CB(skb)->nonce = atomic64_inc_return(&key->counter.counter) - 1;
		if (unlikely(PACKET_CB(skb)->nonce >= REJECT_AFTER_MESSAGES))
			goto out_invalid;
	}

	packets.prev->next = NULL;
	peer_rcu_get(keypair->entry.peer);
	PACKET_CB(packets.next)->keypair = keypair;
	packet_create_data(packets.next);
	return;

out_invalid:
	key->is_valid = false;
out_nokey:
	noise_keypair_put(keypair);

	/* We orphan the packets if we're waiting on a handshake, so that they
	 * don't block a socket's pool.
	 */
	skb_queue_walk(&packets, skb)
		skb_orphan(skb);
	/* Then we put them back on the top of the queue. We're not too concerned about
	 * accidently getting things a little out of order if packets are being added
	 * really fast, because this queue is for before packets can even be sent and
	 * it's small anyway.
	 */
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice(&packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);

	/* If we're exiting because there's something wrong with the key, it means
	 * we should initiate a new handshake.
	 */
	packet_send_queued_handshake_initiation(peer, false);
}
