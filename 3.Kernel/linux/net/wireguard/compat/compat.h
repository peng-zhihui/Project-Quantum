/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef _WG_COMPAT_H
#define _WG_COMPAT_H

#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/types.h>
#include <generated/utsrelease.h>

#ifdef RHEL_MAJOR
#if RHEL_MAJOR == 7
#define ISRHEL7
#endif
#endif
#ifdef UTS_UBUNTU_RELEASE_ABI
#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 13, 11)
#define ISUBUNTU1404
#endif
#endif
#ifdef CONFIG_SUSE_KERNEL
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#define ISOPENSUSE42
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#error "WireGuard requires Linux >= 3.10"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0) && defined(CONFIG_X86_64)
#define CONFIG_AS_SSSE3
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0) && !defined(ISRHEL7)
#define headers_start data
#define headers_end data
#endif

#include <linux/cache.h>
#ifndef __ro_after_init
#define __ro_after_init __read_mostly
#endif

#ifndef READ_ONCE
#define READ_ONCE ACCESS_ONCE
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
#include "udp_tunnel/udp_tunnel_partial_compat.h"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0) && !defined(DEBUG) && defined(net_dbg_ratelimited)
#undef net_dbg_ratelimited
#define net_dbg_ratelimited(fmt, ...) do { if (0) no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__); } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
#define RCU_LOCKDEP_WARN(cond, message) rcu_lockdep_assert(!(cond), message)
#endif

#if ((LINUX_VERSION_CODE > KERNEL_VERSION(3, 19, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 6)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 12) && LINUX_VERSION_CODE > KERNEL_VERSION(3, 17, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 8) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)) || \
    LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 40)) && !defined(ISRHEL7) && !defined(ISUBUNTU1404)
#define dev_recursion_level() 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0) && !defined(ISRHEL7)
#define ipv6_dst_lookup(a, b, c, d) ipv6_dst_lookup(b, c, d)
#endif

#if (LINUX_VERSION_CODE == KERNEL_VERSION(4, 4, 0) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 5) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 17) && LINUX_VERSION_CODE > KERNEL_VERSION(3, 19, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 27) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 8) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 40) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 54))) && !defined(ISUBUNTU1404)
#include <linux/if.h>
#include <net/ip_tunnels.h>
#define IP6_ECN_set_ce(a, b) IP6_ECN_set_ce(b)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
#define time_is_before_jiffies64(a) time_after64(get_jiffies_64(), a)
#define time_is_after_jiffies64(a) time_before64(get_jiffies_64(), a)
#define time_is_before_eq_jiffies64(a) time_after_eq64(get_jiffies_64(), a)
#define time_is_after_eq_jiffies64(a) time_before_eq64(get_jiffies_64(), a)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0) && IS_ENABLED(CONFIG_IPV6) && !defined(ISRHEL7)
#include <net/ipv6.h>
struct ipv6_stub_type {
	void *udpv6_encap_enable;
	int (*ipv6_dst_lookup)(struct sock *sk, struct dst_entry **dst, struct flowi6 *fl6);
};
static const struct ipv6_stub_type ipv6_stub_impl = {
	.udpv6_encap_enable = (void *)1,
	.ipv6_dst_lookup = ip6_dst_lookup
};
static const struct ipv6_stub_type *ipv6_stub = &ipv6_stub_impl;
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0) && IS_ENABLED(CONFIG_IPV6) && !defined(ISOPENSUSE42) && !defined(ISRHEL7)
#include <net/addrconf.h>
static inline bool ipv6_mod_enabled(void)
{
	return ipv6_stub->udpv6_encap_enable != NULL;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#include <linux/skbuff.h>
static inline void skb_reset_tc(struct sk_buff *skb)
{
#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = 0;
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#include <linux/siphash.h>
static inline u32 get_random_u32(void)
{
	static siphash_key_t key;
	static u32 counter = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	static bool has_seeded = false;
	if (unlikely(!has_seeded)) {
		get_random_bytes(&key, sizeof(key));
		has_seeded = true;
	}
#else
	get_random_once(&key, sizeof(key));
#endif
	return siphash_2u32(counter++, get_random_int(), &key);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0) && !defined(ISRHEL7)
static inline void netif_keep_dst(struct net_device *dev)
{
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0) && !defined(ISRHEL7)
#include <linux/netdevice.h>
#ifndef netdev_alloc_pcpu_stats
#define pcpu_sw_netstats pcpu_tstats
#endif
#ifndef netdev_alloc_pcpu_stats
#define netdev_alloc_pcpu_stats alloc_percpu
#endif
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0) && !defined(ISRHEL7)
#include <linux/netdevice.h>
#ifndef netdev_alloc_pcpu_stats
#define netdev_alloc_pcpu_stats(type)					\
({									\
	typeof(type) __percpu *pcpu_stats = alloc_percpu(type);		\
	if (pcpu_stats)	{						\
		int __cpu;						\
		for_each_possible_cpu(__cpu) {				\
			typeof(type) *stat;				\
			stat = per_cpu_ptr(pcpu_stats, __cpu);		\
			u64_stats_init(&stat->syncp);			\
		}							\
	}								\
	pcpu_stats;							\
})
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
#include "checksum/checksum_partial_compat.h"
static inline void *our_pskb_put(struct sk_buff *skb, struct sk_buff *tail, int len)
{
	if (tail != skb) {
		skb->data_len += len;
		skb->len += len;
	}
	return skb_put(tail, len);
}
#define pskb_put our_pskb_put
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) && !defined(ISRHEL7)
#include <net/xfrm.h>
static inline void skb_scrub_packet(struct sk_buff *skb, bool xnet)
{
#ifdef CONFIG_CAVIUM_OCTEON_IPFWD_OFFLOAD
	memset(&skb->cvm_info, 0, sizeof(skb->cvm_info));
	skb->cvm_reserved = 0;
#endif
	skb->tstamp.tv64 = 0;
	skb->pkt_type = PACKET_HOST;
	skb->skb_iif = 0;
	skb_dst_drop(skb);
	secpath_reset(skb);
	nf_reset(skb);
	nf_reset_trace(skb);
	if (!xnet)
		return;
	skb_orphan(skb);
	skb->mark = 0;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0) || defined(ISUBUNTU1404)) && !defined(ISRHEL7)
#include <linux/random.h>
static inline u32 prandom_u32_max(u32 ep_ro)
{
	return (u32)(((u64) prandom_u32() * ep_ro) >> 32);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 75) && !defined(ISRHEL7)
#define U8_MAX ((u8)~0U)
#define S8_MAX ((s8)(U8_MAX >> 1))
#define S8_MIN ((s8)(-S8_MAX - 1))
#define U16_MAX ((u16)~0U)
#define S16_MAX ((s16)(U16_MAX >> 1))
#define S16_MIN ((s16)(-S16_MAX - 1))
#define U32_MAX ((u32)~0U)
#define S32_MAX ((s32)(U32_MAX >> 1))
#define S32_MIN ((s32)(-S32_MAX - 1))
#define U64_MAX ((u64)~0ULL)
#define S64_MAX ((s64)(U64_MAX >> 1))
#define S64_MIN ((s64)(-S64_MAX - 1))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 60) && !defined(ISRHEL7)
/* Making this static may very well invalidate its usefulness,
 * but so it goes with compat code. */
static inline void memzero_explicit(void *s, size_t count)
{
	memset(s, 0, count);
	barrier();
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0) && !defined(ISRHEL7)
static const struct in6_addr our_in6addr_any = IN6ADDR_ANY_INIT;
#define in6addr_any our_in6addr_any
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#include <linux/completion.h>
#include <linux/random.h>
#include <linux/errno.h>
struct rng_initializer {
	struct completion done;
	struct random_ready_callback cb;
};
static inline void rng_initialized_callback(struct random_ready_callback *cb)
{
	complete(&container_of(cb, struct rng_initializer, cb)->done);
}
static inline int wait_for_random_bytes(void)
{
	static bool rng_is_initialized = false;
	int ret;
	if (unlikely(!rng_is_initialized)) {
		struct rng_initializer rng = {
			.done = COMPLETION_INITIALIZER(rng.done),
			.cb = { .owner = THIS_MODULE, .func = rng_initialized_callback }
		};
		ret = add_random_ready_callback(&rng.cb);
		if (!ret) {
			ret = wait_for_completion_interruptible(&rng.done);
			if (ret) {
				del_random_ready_callback(&rng.cb);
				return ret;
			}
		} else if (ret != -EALREADY)
			return ret;
		rng_is_initialized = true;
	}
	return 0;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
/* This is a disaster. Without this API, we really have no way of
 * knowing if it's initialized. We just return that it has and hope
 * for the best... */
static inline int wait_for_random_bytes(void)
{
	return 0;
}
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
static inline int get_random_bytes_wait(void *buf, int nbytes)
{
	int ret = wait_for_random_bytes();
	if (unlikely(ret))
		return ret;
	get_random_bytes(buf, nbytes);
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) && !defined(ISRHEL7)
#define system_power_efficient_wq system_unbound_wq
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0) && !defined(ISRHEL7)
#include <linux/ktime.h>
static inline u64 ktime_get_ns(void)
{
	return ktime_to_ns(ktime_get());
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
#include <linux/inetdevice.h>
static inline __be32 our_confirm_addr_indev(struct in_device *in_dev, __be32 dst,  __be32 local, int scope)
{
	int same = 0;
	__be32 addr = 0;
	for_ifa(in_dev) {
		if (!addr && (local == ifa->ifa_local || !local) && ifa->ifa_scope <= scope) {
			addr = ifa->ifa_local;
			if (same)
				break;
		}
		if (!same) {
			same = (!local || inet_ifa_match(local, ifa)) && (!dst || inet_ifa_match(dst, ifa));
			if (same && addr) {
				if (local || !dst)
					break;
				if (inet_ifa_match(addr, ifa))
					break;
				if (ifa->ifa_scope <= scope) {
					addr = ifa->ifa_local;
					break;
				}
				same = 0;
			}
		}
	} endfor_ifa(in_dev);
	return same ? addr : 0;
}
static inline __be32 our_inet_confirm_addr(struct net *net, struct in_device *in_dev, __be32 dst, __be32 local, int scope)
{
	__be32 addr = 0;
	struct net_device *dev;
	if (in_dev)
		return our_confirm_addr_indev(in_dev, dst, local, scope);
	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		in_dev = __in_dev_get_rcu(dev);
		if (in_dev) {
			addr = our_confirm_addr_indev(in_dev, dst, local, scope);
			if (addr)
				break;
		}
	}
	rcu_read_unlock();
	return addr;
}
#define inet_confirm_addr our_inet_confirm_addr
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/slab.h>
static inline void *kvmalloc_ours(size_t size, gfp_t flags)
{
	gfp_t kmalloc_flags = flags;
	void *ret;
	if (size > PAGE_SIZE) {
		kmalloc_flags |= __GFP_NOWARN;
		if (!(kmalloc_flags & __GFP_REPEAT) || (size <= PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER))
			kmalloc_flags |= __GFP_NORETRY;
	}
	ret = kmalloc(size, kmalloc_flags);
	if (ret || size <= PAGE_SIZE)
		return ret;
	return __vmalloc(size, flags, PAGE_KERNEL);
}
static inline void *kvzalloc_ours(size_t size, gfp_t flags)
{
	return kvmalloc_ours(size, flags | __GFP_ZERO);
}
#define kvmalloc kvmalloc_ours
#define kvzalloc kvzalloc_ours
#endif

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)) || LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 41)) && !defined(ISUBUNTU1404)
#include <linux/vmalloc.h>
#include <linux/mm.h>
static inline void kvfree_ours(const void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}
#define kvfree kvfree_ours
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 9)
#include <linux/netdevice.h>
#define priv_destructor destructor
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#define newlink(a,b,c,d,e) newlink(a,b,c,d)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#include <net/netlink.h>
#include <net/genetlink.h>
#define nlmsg_parse(a, b, c, d, e, f) nlmsg_parse(a, b, c, d, e)
#define nla_parse_nested(a, b, c, d, e) nla_parse_nested(a, b, c, d)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
static inline struct nlattr **genl_family_attrbuf(const struct genl_family *family)
{
	return family->attrbuf;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
#define PTR_ERR_OR_ZERO(p) PTR_RET(p)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
#include <net/netlink.h>
#define nla_put_u64_64bit(a, b, c, d) nla_put_u64(a, b, c)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
#include <net/genetlink.h>
#ifndef GENL_UNS_ADMIN_PERM
#define GENL_UNS_ADMIN_PERM GENL_ADMIN_PERM
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
#include <net/genetlink.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0) && !defined(ISRHEL7)
#define genl_register_family(a) genl_register_family_with_ops(a, (struct genl_ops *)genl_ops, ARRAY_SIZE(genl_ops))
#else
#define genl_register_family(a) genl_register_family_with_ops(a, genl_ops)
#endif
#define COMPAT_CANNOT_USE_GENL_NOPS
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define get_device_dump(a, b) get_device_dump_real(a, b); \
static int get_device_dump(a, b) { \
	int ret; \
	struct wireguard_device *wg = (struct wireguard_device *)cb->args[0]; \
	if (!wg) { \
		int ret = get_device_start(cb); \
		if (ret) \
			return ret; \
	} \
	/* https://patchwork.kernel.org/patch/10046511/ */ \
	skb->end -= nlmsg_total_size(sizeof(int)); \
	ret = get_device_dump_real(skb, cb); \
	skb->end += nlmsg_total_size(sizeof(int)); \
	return ret; \
} \
static int get_device_dump_real(a, b)
#define COMPAT_CANNOT_USE_NETLINK_START
#else /* https://patchwork.kernel.org/patch/10046511/ */
#define get_device_dump(a, b) get_device_dump_real(a, b); \
static int get_device_dump(a, b) { \
	int ret; \
	skb->end -= nlmsg_total_size(sizeof(int)); \
	ret = get_device_dump_real(skb, cb); \
	skb->end += nlmsg_total_size(sizeof(int)); \
	return ret; \
} \
static int get_device_dump_real(a, b)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
#define COMPAT_CANNOT_USE_IN6_DEV_GET
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#define COMPAT_CANNOT_USE_DEV_CNF
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
#define COMPAT_CANNOT_USE_IFF_NO_QUEUE
#endif

#if defined(CONFIG_X86_64)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
#include <asm/user.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
#include <asm/xsave.h>
#include <asm/xcr.h>
static inline int cpu_has_xfeatures(u64 xfeatures_needed, const char **feature_name)
{
	return xgetbv(XCR_XFEATURE_ENABLED_MASK) & xfeatures_needed;
}
#endif
#ifndef XFEATURE_MASK_YMM
#define XFEATURE_MASK_YMM XSTATE_YMM
#endif
#ifndef XFEATURE_MASK_SSE
#define XFEATURE_MASK_SSE XSTATE_SSE
#endif
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
struct _____dummy_container { char dev; };
#define netdev_notifier_info net_device *)data); __attribute((unused)) char _____dummy = ((struct _____dummy_container
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define timer_setup(a, b, c) setup_timer(a, ((void (*)(unsigned long))b), ((unsigned long)a))
#define from_timer(var, callback_timer, timer_fieldname) container_of(callback_timer, typeof(*var), timer_fieldname)
#endif

#if defined(CONFIG_PAX_RAP) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
#error "Using RAP with WireGuard requires Linux >=4.15."
#endif

/* https://lkml.org/lkml/2017/6/23/790 */
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <net/ipv6.h>
#include <net/icmp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat_core.h>
static inline void new_icmp_send(struct sk_buff *skb_in, int type, int code, __be32 info)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb_in, &ctinfo);
	if (skb_network_header(skb_in) < skb_in->head || (skb_network_header(skb_in) + sizeof(struct iphdr)) > skb_tail_pointer(skb_in))
		return;
	if (ct)
		ip_hdr(skb_in)->saddr = ct->tuplehash[0].tuple.src.u3.ip;
	icmp_send(skb_in, type, code, info);
}
static inline void new_icmpv6_send(struct sk_buff *skb, u8 type, u8 code, __u32 info)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	if (skb_network_header(skb) < skb->head || (skb_network_header(skb) + sizeof(struct ipv6hdr)) > skb_tail_pointer(skb))
		return;
	if (ct)
		ipv6_hdr(skb)->saddr = ct->tuplehash[0].tuple.src.u3.in6;
	icmpv6_send(skb, type, code, info);
}
#define icmp_send(a,b,c,d) new_icmp_send(a,b,c,d)
#define icmpv6_send(a,b,c,d) new_icmpv6_send(a,b,c,d)
#endif

/* PaX compatibility */
#ifdef CONSTIFY_PLUGIN
#include <linux/cache.h>
#undef __read_mostly
#define __read_mostly
#endif

#endif /* _WG_COMPAT_H */
