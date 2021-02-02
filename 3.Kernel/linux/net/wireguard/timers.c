/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "timers.h"
#include "device.h"
#include "peer.h"
#include "queueing.h"
#include "socket.h"

/*
 * Timer for retransmitting the handshake if we don't hear back after `REKEY_TIMEOUT + jitter` ms
 * Timer for sending empty packet if we have received a packet but after have not sent one for `KEEPALIVE_TIMEOUT` ms
 * Timer for initiating new handshake if we have sent a packet but after have not received one (even empty) for `(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)` ms
 * Timer for zeroing out all ephemeral keys after `(REJECT_AFTER_TIME * 3)` ms if no new keys have been received
 * Timer for, if enabled, sending an empty authenticated packet every user-specified seconds
 */

/* This rounds the time down to the closest power of two of the closest quarter second. */
static inline unsigned long slack_time(unsigned long time)
{
	return time & ~(roundup_pow_of_two(HZ / 4) - 1);
}

#define peer_get_from_timer(timer_name) \
	struct wireguard_peer *peer = peer_rcu_get(from_timer(peer, timer, timer_name)); \
	if (unlikely(!peer)) \
		return;

static inline bool timers_active(struct wireguard_peer *peer)
{
	return netif_running(peer->device->dev) && !list_empty(&peer->peer_list);
}

static void expired_retransmit_handshake(struct timer_list *timer)
{
	peer_get_from_timer(timer_retransmit_handshake);

	if (peer->timer_handshake_attempts > MAX_TIMER_HANDSHAKES) {
		pr_debug("%s: Handshake for peer %llu (%pISpfsc) did not complete after %d attempts, giving up\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr, MAX_TIMER_HANDSHAKES + 2);

		if (likely(timers_active(peer)))
			del_timer(&peer->timer_send_keepalive);
		/* We drop all packets without a keypair and don't try again,
		 * if we try unsuccessfully for too long to make a handshake.
		 */
		skb_queue_purge(&peer->staged_packet_queue);

		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange.
		 */
		if (likely(timers_active(peer)) && !timer_pending(&peer->timer_zero_key_material))
			mod_timer(&peer->timer_zero_key_material, jiffies + (REJECT_AFTER_TIME * 3));
	} else {
		++peer->timer_handshake_attempts;
		pr_debug("%s: Handshake for peer %llu (%pISpfsc) did not complete after %d seconds, retrying (try %d)\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr, REKEY_TIMEOUT / HZ, peer->timer_handshake_attempts + 1);

		/* We clear the endpoint address src address, in case this is the cause of trouble. */
		socket_clear_peer_endpoint_src(peer);

		packet_send_queued_handshake_initiation(peer, true);
	}
	peer_put(peer);
}

static void expired_send_keepalive(struct timer_list *timer)
{
	peer_get_from_timer(timer_send_keepalive);

	packet_send_keepalive(peer);
	if (peer->timer_need_another_keepalive) {
		peer->timer_need_another_keepalive = false;
		if (likely(timers_active(peer)))
			mod_timer(&peer->timer_send_keepalive, jiffies + KEEPALIVE_TIMEOUT);
	}
	peer_put(peer);
}

static void expired_new_handshake(struct timer_list *timer)
{
	peer_get_from_timer(timer_new_handshake);

	pr_debug("%s: Retrying handshake with peer %llu (%pISpfsc) because we stopped hearing back after %d seconds\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr, (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) / HZ);
	/* We clear the endpoint address src address, in case this is the cause of trouble. */
	socket_clear_peer_endpoint_src(peer);
	packet_send_queued_handshake_initiation(peer, false);
	peer_put(peer);
}

static void expired_zero_key_material(struct timer_list *timer)
{
	peer_get_from_timer(timer_zero_key_material);

	if (!queue_work(peer->device->handshake_send_wq, &peer->clear_peer_work)) /* Takes our reference. */
		peer_put(peer); /* If the work was already on the queue, we want to drop the extra reference */
}
static void queued_expired_zero_key_material(struct work_struct *work)
{
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, clear_peer_work);

	pr_debug("%s: Zeroing out all keys for peer %llu (%pISpfsc), since we haven't received a new one in %d seconds\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr, (REJECT_AFTER_TIME * 3) / HZ);
	noise_handshake_clear(&peer->handshake);
	noise_keypairs_clear(&peer->keypairs);
	peer_put(peer);
}

static void expired_send_persistent_keepalive(struct timer_list *timer)
{
	peer_get_from_timer(timer_persistent_keepalive);

	if (likely(peer->persistent_keepalive_interval)) {
		if (likely(timers_active(peer)))
			del_timer(&peer->timer_send_keepalive);
		packet_send_keepalive(peer);
	}
	peer_put(peer);
}

/* Should be called after an authenticated data packet is sent. */
void timers_data_sent(struct wireguard_peer *peer)
{
	if (likely(timers_active(peer)))
		del_timer(&peer->timer_send_keepalive);

	if (likely(timers_active(peer)) && !timer_pending(&peer->timer_new_handshake))
		mod_timer(&peer->timer_new_handshake, jiffies + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
}

/* Should be called after an authenticated data packet is received. */
void timers_data_received(struct wireguard_peer *peer)
{
	if (likely(timers_active(peer))) {
		if (!timer_pending(&peer->timer_send_keepalive))
			mod_timer(&peer->timer_send_keepalive, jiffies + KEEPALIVE_TIMEOUT);
		else
			peer->timer_need_another_keepalive = true;
	}
}

/* Should be called after any type of authenticated packet is received -- keepalive or data. */
void timers_any_authenticated_packet_received(struct wireguard_peer *peer)
{
	if (likely(timers_active(peer)))
		del_timer(&peer->timer_new_handshake);
}

/* Should be called after a handshake initiation message is sent. */
void timers_handshake_initiated(struct wireguard_peer *peer)
{
	if (likely(timers_active(peer))) {
		del_timer(&peer->timer_send_keepalive);
		mod_timer(&peer->timer_retransmit_handshake, slack_time(jiffies + REKEY_TIMEOUT + prandom_u32_max(REKEY_TIMEOUT_JITTER_MAX)));
	}
}

/* Should be called after a handshake response message is received and processed or when getting key confirmation via the first data message. */
void timers_handshake_complete(struct wireguard_peer *peer)
{
	if (likely(timers_active(peer)))
		del_timer(&peer->timer_retransmit_handshake);
	peer->timer_handshake_attempts = 0;
	peer->sent_lastminute_handshake = false;
	do_gettimeofday(&peer->walltime_last_handshake);
}

/* Should be called after an ephemeral key is created, which is before sending a handshake response or after receiving a handshake response. */
void timers_session_derived(struct wireguard_peer *peer)
{
	if (likely(timers_active(peer)))
		mod_timer(&peer->timer_zero_key_material, jiffies + (REJECT_AFTER_TIME * 3));
}

/* Should be called before a packet with authentication -- data, keepalive, either handshake -- is sent, or after one is received. */
void timers_any_authenticated_packet_traversal(struct wireguard_peer *peer)
{
	if (peer->persistent_keepalive_interval && likely(timers_active(peer)))
		mod_timer(&peer->timer_persistent_keepalive, slack_time(jiffies + peer->persistent_keepalive_interval));
}

void timers_init(struct wireguard_peer *peer)
{
	timer_setup(&peer->timer_retransmit_handshake, expired_retransmit_handshake, 0);
	timer_setup(&peer->timer_send_keepalive, expired_send_keepalive, 0);
	timer_setup(&peer->timer_new_handshake, expired_new_handshake, 0);
	timer_setup(&peer->timer_zero_key_material, expired_zero_key_material, 0);
	timer_setup(&peer->timer_persistent_keepalive, expired_send_persistent_keepalive, 0);
	INIT_WORK(&peer->clear_peer_work, queued_expired_zero_key_material);
}

void timers_stop(struct wireguard_peer *peer)
{
	del_timer_sync(&peer->timer_retransmit_handshake);
	del_timer_sync(&peer->timer_send_keepalive);
	del_timer_sync(&peer->timer_new_handshake);
	del_timer_sync(&peer->timer_zero_key_material);
	del_timer_sync(&peer->timer_persistent_keepalive);
	flush_work(&peer->clear_peer_work);
}
