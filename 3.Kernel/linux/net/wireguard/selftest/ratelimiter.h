/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifdef DEBUG

#include <linux/jiffies.h>

static const struct { bool result; unsigned int msec_to_sleep_before; } expected_results[] __initconst = {
	[0 ... PACKETS_BURSTABLE - 1] = { true, 0 },
	[PACKETS_BURSTABLE] = { false, 0 },
	[PACKETS_BURSTABLE + 1] = { true, MSEC_PER_SEC / PACKETS_PER_SECOND },
	[PACKETS_BURSTABLE + 2] = { false, 0 },
	[PACKETS_BURSTABLE + 3] = { true, (MSEC_PER_SEC / PACKETS_PER_SECOND) * 2 },
	[PACKETS_BURSTABLE + 4] = { true, 0 },
	[PACKETS_BURSTABLE + 5] = { false, 0 }
};

static __init unsigned int maximum_jiffies_at_index(int index)
{
	unsigned int total_msecs = 2 * MSEC_PER_SEC / PACKETS_PER_SECOND / 3;
	int i;

	for (i = 0; i <= index; ++i)
		total_msecs += expected_results[i].msec_to_sleep_before;
	return msecs_to_jiffies(total_msecs);
}

bool __init ratelimiter_selftest(void)
{
	struct sk_buff *skb4;
	struct iphdr *hdr4;
#if IS_ENABLED(CONFIG_IPV6)
	struct sk_buff *skb6;
	struct ipv6hdr *hdr6;
#endif
	int i, test = 0, tries = 0, ret = false;
	unsigned long loop_start_time;

	BUILD_BUG_ON(MSEC_PER_SEC % PACKETS_PER_SECOND != 0);

	if (ratelimiter_init())
		goto out;
	++test;
	if (ratelimiter_init()) {
		ratelimiter_uninit();
		goto out;
	}
	++test;
	if (ratelimiter_init()) {
		ratelimiter_uninit();
		ratelimiter_uninit();
		goto out;
	}
	++test;

	skb4 = alloc_skb(sizeof(struct iphdr), GFP_KERNEL);
	if (!skb4)
		goto err_nofree;
	skb4->protocol = htons(ETH_P_IP);
	hdr4 = (struct iphdr *)skb_put(skb4, sizeof(struct iphdr));
	hdr4->saddr = htonl(8182);
	skb_reset_network_header(skb4);
	++test;

#if IS_ENABLED(CONFIG_IPV6)
	skb6 = alloc_skb(sizeof(struct ipv6hdr), GFP_KERNEL);
	if (!skb6) {
		kfree_skb(skb4);
		goto err_nofree;
	}
	skb6->protocol = htons(ETH_P_IPV6);
	hdr6 = (struct ipv6hdr *)skb_put(skb6, sizeof(struct ipv6hdr));
	hdr6->saddr.in6_u.u6_addr32[0] = htonl(1212);
	hdr6->saddr.in6_u.u6_addr32[1] = htonl(289188);
	skb_reset_network_header(skb6);
	++test;
#endif

restart:
	loop_start_time = jiffies;
	for (i = 0; i < ARRAY_SIZE(expected_results); ++i) {
#define ensure_time do {\
		if (time_is_before_jiffies(loop_start_time + maximum_jiffies_at_index(i))) { \
			if (++tries >= 5000) \
				goto err; \
			gc_entries(NULL); \
			rcu_barrier(); \
			msleep(500); \
			goto restart; \
		}} while (0)

		if (expected_results[i].msec_to_sleep_before)
			msleep(expected_results[i].msec_to_sleep_before);

		ensure_time;
		if (ratelimiter_allow(skb4, &init_net) != expected_results[i].result)
			goto err;
		++test;
		hdr4->saddr = htonl(ntohl(hdr4->saddr) + i + 1);
		ensure_time;
		if (!ratelimiter_allow(skb4, &init_net))
			goto err;
		++test;
		hdr4->saddr = htonl(ntohl(hdr4->saddr) - i - 1);

#if IS_ENABLED(CONFIG_IPV6)
		hdr6->saddr.in6_u.u6_addr32[2] = hdr6->saddr.in6_u.u6_addr32[3] = htonl(i);
		ensure_time;
		if (ratelimiter_allow(skb6, &init_net) != expected_results[i].result)
			goto err;
		++test;
		hdr6->saddr.in6_u.u6_addr32[0] = htonl(ntohl(hdr6->saddr.in6_u.u6_addr32[0]) + i + 1);
		ensure_time;
		if (!ratelimiter_allow(skb6, &init_net))
			goto err;
		++test;
		hdr6->saddr.in6_u.u6_addr32[0] = htonl(ntohl(hdr6->saddr.in6_u.u6_addr32[0]) - i - 1);
		ensure_time;
#endif
	}

	gc_entries(NULL);
	rcu_barrier();

	if (atomic_read(&total_entries))
		goto err;
	++test;

	for (i = 0; i <= max_entries; ++i) {
		hdr4->saddr = htonl(i);
		if (ratelimiter_allow(skb4, &init_net) != (i != max_entries))
			goto err;
		++test;
	}

	ret = true;

err:
	kfree_skb(skb4);
#if IS_ENABLED(CONFIG_IPV6)
	kfree_skb(skb6);
#endif
err_nofree:
	ratelimiter_uninit();
	ratelimiter_uninit();
	ratelimiter_uninit();
out:
	if (ret)
		pr_info("ratelimiter self-tests: pass\n");
	else
		pr_info("ratelimiter self-test %d: fail\n", test);

	return ret;
}
#endif
