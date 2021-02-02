/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "queueing.h"
#include "socket.h"
#include "timers.h"
#include "device.h"
#include "ratelimiter.h"
#include "peer.h"
#include "messages.h"

#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/suspend.h>
#include <net/icmp.h>
#include <net/rtnetlink.h>
#include <net/ip_tunnels.h>
#include <net/addrconf.h>

static LIST_HEAD(device_list);

static int open(struct net_device *dev)
{
	int ret;
	struct wireguard_peer *peer;
	struct wireguard_device *wg = netdev_priv(dev);
#ifndef COMPAT_CANNOT_USE_IN6_DEV_GET
	struct inet6_dev *dev_v6 = __in6_dev_get(dev);
#endif
	struct in_device *dev_v4 = __in_dev_get_rtnl(dev);

	if (dev_v4) {
		/* TODO: when we merge to mainline, put this check near the ip_rt_send_redirect
		 * call of ip_forward in net/ipv4/ip_forward.c, similar to the current secpath
		 * check, rather than turning it off like this. This is just a stop gap solution
		 * while we're an out of tree module.
		 */
		IN_DEV_CONF_SET(dev_v4, SEND_REDIRECTS, false);
		IPV4_DEVCONF_ALL(dev_net(dev), SEND_REDIRECTS) = false;
	}
#ifndef COMPAT_CANNOT_USE_IN6_DEV_GET
	if (dev_v6)
#ifndef COMPAT_CANNOT_USE_DEV_CNF
		dev_v6->cnf.addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#else
		dev_v6->addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#endif
#endif

	ret = socket_init(wg);
	if (ret < 0)
		return ret;
	mutex_lock(&wg->device_update_lock);
	list_for_each_entry(peer, &wg->peer_list, peer_list) {
		packet_send_staged_packets(peer);
		if (peer->persistent_keepalive_interval)
			packet_send_keepalive(peer);
	}
	mutex_unlock(&wg->device_update_lock);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int pm_notification(struct notifier_block *nb, unsigned long action, void *data)
{
	struct wireguard_device *wg;
	struct wireguard_peer *peer;

	if (action != PM_HIBERNATION_PREPARE && action != PM_SUSPEND_PREPARE)
		return 0;

	rtnl_lock();
	list_for_each_entry(wg, &device_list, device_list) {
		mutex_lock(&wg->device_update_lock);
		list_for_each_entry(peer, &wg->peer_list, peer_list) {
			noise_handshake_clear(&peer->handshake);
			noise_keypairs_clear(&peer->keypairs);
			if (peer->timers_enabled)
				del_timer(&peer->timer_zero_key_material);
		}
		mutex_unlock(&wg->device_update_lock);
	}
	rtnl_unlock();
	rcu_barrier_bh();
	return 0;
}
static struct notifier_block pm_notifier = { .notifier_call = pm_notification };
#endif

static int stop(struct net_device *dev)
{
	struct wireguard_device *wg = netdev_priv(dev);
	struct wireguard_peer *peer;

	mutex_lock(&wg->device_update_lock);
	list_for_each_entry(peer, &wg->peer_list, peer_list) {
		skb_queue_purge(&peer->staged_packet_queue);
		timers_stop(peer);
		noise_handshake_clear(&peer->handshake);
		noise_keypairs_clear(&peer->keypairs);
	}
	mutex_unlock(&wg->device_update_lock);
	skb_queue_purge(&wg->incoming_handshakes);
	socket_uninit(wg);
	return 0;
}

static netdev_tx_t xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct wireguard_device *wg = netdev_priv(dev);
	struct wireguard_peer *peer;
	struct sk_buff *next;
	struct sk_buff_head packets;
	sa_family_t family;
	int ret;

	if (unlikely(skb_examine_untrusted_ip_hdr(skb) != skb->protocol)) {
		ret = -EPROTONOSUPPORT;
		net_dbg_ratelimited("%s: Invalid IP packet\n", dev->name);
		goto err;
	}

	peer = allowedips_lookup_dst(&wg->peer_allowedips, skb);
	if (unlikely(!peer)) {
		ret = -ENOKEY;
		net_dbg_skb_ratelimited("%s: No peer is configured for %pISc\n", dev->name, skb);
		goto err;
	}

	family = READ_ONCE(peer->endpoint.addr.sa_family);
	if (unlikely(family != AF_INET && family != AF_INET6)) {
		ret = -EDESTADDRREQ;
		net_dbg_ratelimited("%s: No valid endpoint has been configured or discovered for peer %llu\n", dev->name, peer->internal_id);
		goto err_peer;
	}

	__skb_queue_head_init(&packets);
	if (!skb_is_gso(skb))
		skb->next = NULL;
	else {
		struct sk_buff *segs = skb_gso_segment(skb, 0);

		if (unlikely(IS_ERR(segs))) {
			ret = PTR_ERR(segs);
			goto err_peer;
		}
		dev_kfree_skb(skb);
		skb = segs;
	}
	do {
		next = skb->next;
		skb->next = skb->prev = NULL;

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (unlikely(!skb))
			continue;

		/* We only need to keep the original dst around for icmp,
		 * so at this point we're in a position to drop it.
		 */
		skb_dst_drop(skb);

		__skb_queue_tail(&packets, skb);
	} while ((skb = next) != NULL);

	spin_lock_bh(&peer->staged_packet_queue.lock);
	/* If the queue is getting too big, we start removing the oldest packets until it's small again.
	 * We do this before adding the new packet, so we don't remove GSO segments that are in excess.
	 */
	while (skb_queue_len(&peer->staged_packet_queue) > MAX_STAGED_PACKETS)
		dev_kfree_skb(__skb_dequeue(&peer->staged_packet_queue));
	skb_queue_splice_tail(&packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);

	packet_send_staged_packets(peer);

	peer_put(peer);
	return NETDEV_TX_OK;

err_peer:
	peer_put(peer);
err:
	++dev->stats.tx_errors;
	if (skb->protocol == htons(ETH_P_IP))
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
	else if (skb->protocol == htons(ETH_P_IPV6))
		icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH, 0);
	kfree_skb(skb);
	return ret;
}

static const struct net_device_ops netdev_ops = {
	.ndo_open		= open,
	.ndo_stop		= stop,
	.ndo_start_xmit		= xmit,
	.ndo_get_stats64	= ip_tunnel_get_stats64
};

static void destruct(struct net_device *dev)
{
	struct wireguard_device *wg = netdev_priv(dev);

	rtnl_lock();
	list_del(&wg->device_list);
	rtnl_unlock();
	mutex_lock(&wg->device_update_lock);
	peer_remove_all(wg); /* The final references are cleared in the below calls to destroy_workqueue. */
	wg->incoming_port = 0;
	destroy_workqueue(wg->handshake_receive_wq);
	destroy_workqueue(wg->handshake_send_wq);
	packet_queue_free(&wg->decrypt_queue, true);
	packet_queue_free(&wg->encrypt_queue, true);
	destroy_workqueue(wg->packet_crypt_wq);
	rcu_barrier_bh(); /* Wait for all the peers to be actually freed. */
	allowedips_free(&wg->peer_allowedips, &wg->device_update_lock);
	ratelimiter_uninit();
	memzero_explicit(&wg->static_identity, sizeof(struct noise_static_identity));
	skb_queue_purge(&wg->incoming_handshakes);
	socket_uninit(wg);
	free_percpu(dev->tstats);
	free_percpu(wg->incoming_handshakes_worker);
	if (wg->have_creating_net_ref)
		put_net(wg->creating_net);
	mutex_unlock(&wg->device_update_lock);

	pr_debug("%s: Interface deleted\n", dev->name);
	free_netdev(dev);
}

static void setup(struct net_device *dev)
{
	struct wireguard_device *wg = netdev_priv(dev);
	enum { WG_NETDEV_FEATURES = NETIF_F_HW_CSUM | NETIF_F_RXCSUM | NETIF_F_SG | NETIF_F_GSO | NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA };

	dev->netdev_ops = &netdev_ops;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->needed_headroom = DATA_PACKET_HEAD_ROOM;
	dev->needed_tailroom = noise_encrypted_len(MESSAGE_PADDING_MULTIPLE);
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
#ifndef COMPAT_CANNOT_USE_IFF_NO_QUEUE
	dev->priv_flags |= IFF_NO_QUEUE;
#else
	dev->tx_queue_len = 0;
#endif
	dev->features |= NETIF_F_LLTX;
	dev->features |= WG_NETDEV_FEATURES;
	dev->hw_features |= WG_NETDEV_FEATURES;
	dev->hw_enc_features |= WG_NETDEV_FEATURES;
	dev->mtu = ETH_DATA_LEN - MESSAGE_MINIMUM_LENGTH - sizeof(struct udphdr) - max(sizeof(struct ipv6hdr), sizeof(struct iphdr));

	/* We need to keep the dst around in case of icmp replies. */
	netif_keep_dst(dev);

	memset(wg, 0, sizeof(struct wireguard_device));
	wg->dev = dev;
}

static int newlink(struct net *src_net, struct net_device *dev, struct nlattr *tb[], struct nlattr *data[], struct netlink_ext_ack *extack)
{
	int ret = -ENOMEM;
	struct wireguard_device *wg = netdev_priv(dev);

	wg->creating_net = src_net;
	init_rwsem(&wg->static_identity.lock);
	mutex_init(&wg->socket_update_lock);
	mutex_init(&wg->device_update_lock);
	skb_queue_head_init(&wg->incoming_handshakes);
	pubkey_hashtable_init(&wg->peer_hashtable);
	index_hashtable_init(&wg->index_hashtable);
	allowedips_init(&wg->peer_allowedips);
	cookie_checker_init(&wg->cookie_checker, wg);
	INIT_LIST_HEAD(&wg->peer_list);
	wg->device_update_gen = 1;

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		goto error_1;

	wg->incoming_handshakes_worker = packet_alloc_percpu_multicore_worker(packet_handshake_receive_worker, wg);
	if (!wg->incoming_handshakes_worker)
		goto error_2;

	wg->handshake_receive_wq = alloc_workqueue("wg-kex-%s", WQ_CPU_INTENSIVE | WQ_FREEZABLE, 0, dev->name);
	if (!wg->handshake_receive_wq)
		goto error_3;

	wg->handshake_send_wq = alloc_workqueue("wg-kex-%s", WQ_UNBOUND | WQ_FREEZABLE, 0, dev->name);
	if (!wg->handshake_send_wq)
		goto error_4;

	wg->packet_crypt_wq = alloc_workqueue("wg-crypt-%s", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 0, dev->name);
	if (!wg->packet_crypt_wq)
		goto error_5;

	if (packet_queue_init(&wg->encrypt_queue, packet_encrypt_worker, true, MAX_QUEUED_PACKETS) < 0)
		goto error_6;

	if (packet_queue_init(&wg->decrypt_queue, packet_decrypt_worker, true, MAX_QUEUED_PACKETS) < 0)
		goto error_7;

	ret = ratelimiter_init();
	if (ret < 0)
		goto error_8;

	ret = register_netdevice(dev);
	if (ret < 0)
		goto error_9;

	list_add(&wg->device_list, &device_list);

	/* We wait until the end to assign priv_destructor, so that register_netdevice doesn't
	 * call it for us if it fails.
	 */
	dev->priv_destructor = destruct;

	pr_debug("%s: Interface created\n", dev->name);
	return ret;

error_9:
	ratelimiter_uninit();
error_8:
	packet_queue_free(&wg->decrypt_queue, true);
error_7:
	packet_queue_free(&wg->encrypt_queue, true);
error_6:
	destroy_workqueue(wg->packet_crypt_wq);
error_5:
	destroy_workqueue(wg->handshake_send_wq);
error_4:
	destroy_workqueue(wg->handshake_receive_wq);
error_3:
	free_percpu(wg->incoming_handshakes_worker);
error_2:
	free_percpu(dev->tstats);
error_1:
	return ret;
}

static struct rtnl_link_ops link_ops __read_mostly = {
	.kind			= KBUILD_MODNAME,
	.priv_size		= sizeof(struct wireguard_device),
	.setup			= setup,
	.newlink		= newlink,
};

static int netdevice_notification(struct notifier_block *nb, unsigned long action, void *data)
{
	struct net_device *dev = ((struct netdev_notifier_info *)data)->dev;
	struct wireguard_device *wg = netdev_priv(dev);

	ASSERT_RTNL();

	if (action != NETDEV_REGISTER || dev->netdev_ops != &netdev_ops)
		return 0;

	if (dev_net(dev) == wg->creating_net && wg->have_creating_net_ref) {
		put_net(wg->creating_net);
		wg->have_creating_net_ref = false;
	} else if (dev_net(dev) != wg->creating_net && !wg->have_creating_net_ref) {
		wg->have_creating_net_ref = true;
		get_net(wg->creating_net);
	}
	return 0;
}

static struct notifier_block netdevice_notifier = { .notifier_call = netdevice_notification };

int __init device_init(void)
{
	int ret;

#ifdef CONFIG_PM_SLEEP
	ret = register_pm_notifier(&pm_notifier);
	if (ret)
		return ret;
#endif

	ret = register_netdevice_notifier(&netdevice_notifier);
	if (ret)
		goto error_pm;

	ret = rtnl_link_register(&link_ops);
	if (ret)
		goto error_netdevice;

	return 0;

error_netdevice:
	unregister_netdevice_notifier(&netdevice_notifier);
error_pm:
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&pm_notifier);
#endif
	return ret;
}

void device_uninit(void)
{
	rtnl_link_unregister(&link_ops);
	unregister_netdevice_notifier(&netdevice_notifier);
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&pm_notifier);
#endif
	rcu_barrier_bh();
}
