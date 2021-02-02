/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef _WG_TIMERS_H
#define _WG_TIMERS_H

struct wireguard_peer;

void timers_init(struct wireguard_peer *peer);
void timers_stop(struct wireguard_peer *peer);
void timers_data_sent(struct wireguard_peer *peer);
void timers_data_received(struct wireguard_peer *peer);
void timers_any_authenticated_packet_received(struct wireguard_peer *peer);
void timers_handshake_initiated(struct wireguard_peer *peer);
void timers_handshake_complete(struct wireguard_peer *peer);
void timers_session_derived(struct wireguard_peer *peer);
void timers_any_authenticated_packet_traversal(struct wireguard_peer *peer);

#endif /* _WG_TIMERS_H */
