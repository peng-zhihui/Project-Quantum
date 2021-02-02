/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifdef DEBUG

#ifdef DEBUG_PRINT_TRIE_GRAPHVIZ
#include <linux/siphash.h>
static __init void print_node(struct allowedips_node *node, u8 bits)
{
	u32 color = 0;
	char *style = "dotted";
	char *fmt_connection = KERN_DEBUG "\t\"%p/%d\" -> \"%p/%d\";\n";
	char *fmt_declaration = KERN_DEBUG "\t\"%p/%d\"[style=%s, color=\"#%06x\"];\n";
	if (bits == 32) {
		fmt_connection = KERN_DEBUG "\t\"%pI4/%d\" -> \"%pI4/%d\";\n";
		fmt_declaration = KERN_DEBUG "\t\"%pI4/%d\"[style=%s, color=\"#%06x\"];\n";
	} else if (bits == 128) {
		fmt_connection = KERN_DEBUG "\t\"%pI6/%d\" -> \"%pI6/%d\";\n";
		fmt_declaration = KERN_DEBUG "\t\"%pI6/%d\"[style=%s, color=\"#%06x\"];\n";
	}
	if (node->peer) {
		hsiphash_key_t key = { 0 };
		memcpy(&key, &node->peer, sizeof(node->peer));
		color = hsiphash_1u32(0xdeadbeef, &key) % 200 << 16 | hsiphash_1u32(0xbabecafe, &key) % 200 << 8 | hsiphash_1u32(0xabad1dea, &key) % 200;
		style = "bold";
	}
	printk(fmt_declaration, node->bits, node->cidr, style, color);
	if (node->bit[0]) {
		printk(fmt_connection, node->bits, node->cidr, node->bit[0]->bits, node->bit[0]->cidr);
		print_node(node->bit[0], bits);
	}
	if (node->bit[1]) {
		printk(fmt_connection, node->bits, node->cidr, node->bit[1]->bits, node->bit[1]->cidr);
		print_node(node->bit[1], bits);
	}
}
static __init void print_tree(struct allowedips_node *top, u8 bits)
{
	printk(KERN_DEBUG "digraph trie {\n");
	print_node(top, bits);
	printk(KERN_DEBUG "}\n");
}
#endif

#ifdef DEBUG_RANDOM_TRIE
#define NUM_PEERS 2000
#define NUM_RAND_ROUTES 400
#define NUM_MUTATED_ROUTES 100
#define NUM_QUERIES (NUM_RAND_ROUTES * NUM_MUTATED_ROUTES * 30)
#include <linux/random.h>
struct horrible_allowedips {
	struct hlist_head head;
};
struct horrible_allowedips_node {
	struct hlist_node table;
	union nf_inet_addr ip;
	union nf_inet_addr mask;
	uint8_t ip_version;
	void *value;
};
static __init void horrible_allowedips_init(struct horrible_allowedips *table)
{
	INIT_HLIST_HEAD(&table->head);
}
static __init void horrible_allowedips_free(struct horrible_allowedips *table)
{
	struct hlist_node *h;
	struct horrible_allowedips_node *node;
	hlist_for_each_entry_safe(node, h, &table->head, table) {
		hlist_del(&node->table);
		kfree(node);
	}
}
static __init inline union nf_inet_addr horrible_cidr_to_mask(uint8_t cidr)
{
	union nf_inet_addr mask;
	memset(&mask, 0x00, 128 / 8);
	memset(&mask, 0xff, cidr / 8);
	if (cidr % 32)
		mask.all[cidr / 32] = htonl((0xFFFFFFFFUL << (32 - (cidr % 32))) & 0xFFFFFFFFUL);
	return mask;
}
static __init inline uint8_t horrible_mask_to_cidr(union nf_inet_addr subnet)
{
	return hweight32(subnet.all[0])
	     + hweight32(subnet.all[1])
	     + hweight32(subnet.all[2])
	     + hweight32(subnet.all[3]);
}
static __init inline void horrible_mask_self(struct horrible_allowedips_node *node)
{
	if (node->ip_version == 4)
		node->ip.ip &= node->mask.ip;
	else if (node->ip_version == 6) {
		node->ip.ip6[0] &= node->mask.ip6[0];
		node->ip.ip6[1] &= node->mask.ip6[1];
		node->ip.ip6[2] &= node->mask.ip6[2];
		node->ip.ip6[3] &= node->mask.ip6[3];
	}
}
static __init inline bool horrible_match_v4(const struct horrible_allowedips_node *node, struct in_addr *ip)
{
	return (ip->s_addr & node->mask.ip) == node->ip.ip;
}
static __init inline bool horrible_match_v6(const struct horrible_allowedips_node *node, struct in6_addr *ip)
{
	return	(ip->in6_u.u6_addr32[0] & node->mask.ip6[0]) == node->ip.ip6[0] &&
		(ip->in6_u.u6_addr32[1] & node->mask.ip6[1]) == node->ip.ip6[1] &&
		(ip->in6_u.u6_addr32[2] & node->mask.ip6[2]) == node->ip.ip6[2] &&
		(ip->in6_u.u6_addr32[3] & node->mask.ip6[3]) == node->ip.ip6[3];
}
static __init void horrible_insert_ordered(struct horrible_allowedips *table, struct horrible_allowedips_node *node)
{
	struct horrible_allowedips_node *other = NULL, *where = NULL;
	uint8_t my_cidr = horrible_mask_to_cidr(node->mask);
	hlist_for_each_entry(other, &table->head, table) {
		if (!memcmp(&other->mask, &node->mask, sizeof(union nf_inet_addr)) &&
		    !memcmp(&other->ip, &node->ip, sizeof(union nf_inet_addr)) &&
		    other->ip_version == node->ip_version) {
			other->value = node->value;
			kfree(node);
			return;
		}
		where = other;
		if (horrible_mask_to_cidr(other->mask) <= my_cidr)
			break;
	}
	if (!other && !where)
		hlist_add_head(&node->table, &table->head);
	else if (!other)
		hlist_add_behind(&node->table, &where->table);
	else
		hlist_add_before(&node->table, &where->table);
}
static __init int horrible_allowedips_insert_v4(struct horrible_allowedips *table, struct in_addr *ip, uint8_t cidr, void *value)
{
	struct horrible_allowedips_node *node = kzalloc(sizeof(struct horrible_allowedips_node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;
	node->ip.in = *ip;
	node->mask = horrible_cidr_to_mask(cidr);
	node->ip_version = 4;
	node->value = value;
	horrible_mask_self(node);
	horrible_insert_ordered(table, node);
	return 0;
}
static __init int horrible_allowedips_insert_v6(struct horrible_allowedips *table, struct in6_addr *ip, uint8_t cidr, void *value)
{
	struct horrible_allowedips_node *node = kzalloc(sizeof(struct horrible_allowedips_node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;
	node->ip.in6 = *ip;
	node->mask = horrible_cidr_to_mask(cidr);
	node->ip_version = 6;
	node->value = value;
	horrible_mask_self(node);
	horrible_insert_ordered(table, node);
	return 0;
}
static __init void *horrible_allowedips_lookup_v4(struct horrible_allowedips *table, struct in_addr *ip)
{
	struct horrible_allowedips_node *node;
	void *ret = NULL;
	hlist_for_each_entry(node, &table->head, table) {
		if (node->ip_version != 4)
			continue;
		if (horrible_match_v4(node, ip)) {
			ret = node->value;
			break;
		}
	}
	return ret;
}
static __init void *horrible_allowedips_lookup_v6(struct horrible_allowedips *table, struct in6_addr *ip)
{
	struct horrible_allowedips_node *node;
	void *ret = NULL;
	hlist_for_each_entry(node, &table->head, table) {
		if (node->ip_version != 6)
			continue;
		if (horrible_match_v6(node, ip)) {
			ret = node->value;
			break;
		}
	}
	return ret;
}

static __init bool randomized_test(void)
{
	bool ret = false;
	unsigned int i, j, k, mutate_amount, cidr;
	struct wireguard_peer **peers, *peer;
	struct allowedips t;
	struct horrible_allowedips h;
	u8 ip[16], mutate_mask[16], mutated[16];

	allowedips_init(&t);
	horrible_allowedips_init(&h);

	peers = kcalloc(NUM_PEERS, sizeof(struct wireguard_peer *), GFP_KERNEL);
	if (!peers) {
		pr_info("allowedips random self-test: out of memory\n");
		goto free;
	}
	for (i = 0; i < NUM_PEERS; ++i) {
		peers[i] = kzalloc(sizeof(struct wireguard_peer), GFP_KERNEL);
		if (!peers[i]) {
			pr_info("allowedips random self-test: out of memory\n");
			goto free;
		}
		kref_init(&peers[i]->refcount);
	}

	for (i = 0; i < NUM_RAND_ROUTES; ++i) {
		prandom_bytes(ip, 4);
		cidr = prandom_u32_max(32) + 1;
		peer = peers[prandom_u32_max(NUM_PEERS)];
		if (allowedips_insert_v4(&t, (struct in_addr *)ip, cidr, peer) < 0) {
			pr_info("allowedips random self-test: out of memory\n");
			goto free;
		}
		if (horrible_allowedips_insert_v4(&h, (struct in_addr *)ip, cidr, peer) < 0) {
			pr_info("allowedips random self-test: out of memory\n");
			goto free;
		}
		for (j = 0; j < NUM_MUTATED_ROUTES; ++j) {
			memcpy(mutated, ip, 4);
			prandom_bytes(mutate_mask, 4);
			mutate_amount = prandom_u32_max(32);
			for (k = 0; k < mutate_amount / 8; ++k)
				mutate_mask[k] = 0xff;
			mutate_mask[k] = 0xff << ((8 - (mutate_amount % 8)) % 8);
			for (; k < 4; ++k)
				mutate_mask[k] = 0;
			for (k = 0; k < 4; ++k)
				mutated[k] = (mutated[k] & mutate_mask[k]) | (~mutate_mask[k] & prandom_u32_max(256));
			cidr = prandom_u32_max(32) + 1;
			peer = peers[prandom_u32_max(NUM_PEERS)];
			if (allowedips_insert_v4(&t, (struct in_addr *)mutated, cidr, peer) < 0) {
				pr_info("allowedips random self-test: out of memory\n");
				goto free;
			}
			if (horrible_allowedips_insert_v4(&h, (struct in_addr *)mutated, cidr, peer)) {
				pr_info("allowedips random self-test: out of memory\n");
				goto free;
			}
		}
	}

	for (i = 0; i < NUM_RAND_ROUTES; ++i) {
		prandom_bytes(ip, 16);
		cidr = prandom_u32_max(128) + 1;
		peer = peers[prandom_u32_max(NUM_PEERS)];
		if (allowedips_insert_v6(&t, (struct in6_addr *)ip, cidr, peer) < 0) {
			pr_info("allowedips random self-test: out of memory\n");
			goto free;
		}
		if (horrible_allowedips_insert_v6(&h, (struct in6_addr *)ip, cidr, peer) < 0) {
			pr_info("allowedips random self-test: out of memory\n");
			goto free;
		}
		for (j = 0; j < NUM_MUTATED_ROUTES; ++j) {
			memcpy(mutated, ip, 16);
			prandom_bytes(mutate_mask, 16);
			mutate_amount = prandom_u32_max(128);
			for (k = 0; k < mutate_amount / 8; ++k)
				mutate_mask[k] = 0xff;
			mutate_mask[k] = 0xff << ((8 - (mutate_amount % 8)) % 8);
			for (; k < 4; ++k)
				mutate_mask[k] = 0;
			for (k = 0; k < 4; ++k)
				mutated[k] = (mutated[k] & mutate_mask[k]) | (~mutate_mask[k] & prandom_u32_max(256));
			cidr = prandom_u32_max(128) + 1;
			peer = peers[prandom_u32_max(NUM_PEERS)];
			if (allowedips_insert_v6(&t, (struct in6_addr *)mutated, cidr, peer) < 0) {
				pr_info("allowedips random self-test: out of memory\n");
				goto free;
			}
			if (horrible_allowedips_insert_v6(&h, (struct in6_addr *)mutated, cidr, peer)) {
				pr_info("allowedips random self-test: out of memory\n");
				goto free;
			}
		}
	}

#ifdef DEBUG_PRINT_TRIE_GRAPHVIZ
	print_tree(t.root4, 32);
	print_tree(t.root6, 128);
#endif

	for (i = 0; i < NUM_QUERIES; ++i) {
		prandom_bytes(ip, 4);
		if (lookup(t.root4, 32, ip) != horrible_allowedips_lookup_v4(&h, (struct in_addr *)ip)) {
			pr_info("allowedips random self-test: FAIL\n");
			goto free;
		}
	}

	for (i = 0; i < NUM_QUERIES; ++i) {
		prandom_bytes(ip, 16);
		if (lookup(t.root6, 128, ip) != horrible_allowedips_lookup_v6(&h, (struct in6_addr *)ip)) {
			pr_info("allowedips random self-test: FAIL\n");
			goto free;
		}
	}
	ret = true;

free:
	allowedips_free(&t);
	horrible_allowedips_free(&h);
	if (peers) {
		for (i = 0; i < NUM_PEERS; ++i)
			kfree(peers[i]);
	}
	kfree(peers);
	return ret;
}
#endif

static __init inline struct in_addr *ip4(u8 a, u8 b, u8 c, u8 d)
{
	static struct in_addr ip;
	u8 *split = (u8 *)&ip;
	split[0] = a;
	split[1] = b;
	split[2] = c;
	split[3] = d;
	return &ip;
}
static __init inline struct in6_addr *ip6(u32 a, u32 b, u32 c, u32 d)
{
	static struct in6_addr ip;
	__be32 *split = (__be32 *)&ip;
	split[0] = cpu_to_be32(a);
	split[1] = cpu_to_be32(b);
	split[2] = cpu_to_be32(c);
	split[3] = cpu_to_be32(d);
	return &ip;
}

#define init_peer(name) do { \
	name = kzalloc(sizeof(struct wireguard_peer), GFP_KERNEL); \
	if (!name) { \
		pr_info("allowedips self-test: out of memory\n"); \
		goto free; \
	} \
	kref_init(&name->refcount); \
} while (0)

#define insert(version, mem, ipa, ipb, ipc, ipd, cidr) \
	allowedips_insert_v##version(&t, ip##version(ipa, ipb, ipc, ipd), cidr, mem, &mutex)

#define maybe_fail \
	++i; \
	if (!_s) { \
		pr_info("allowedips self-test %zu: FAIL\n", i); \
		success = false; \
	}

#define test(version, mem, ipa, ipb, ipc, ipd) do { \
	bool _s = lookup(t.root##version, version == 4 ? 32 : 128, ip##version(ipa, ipb, ipc, ipd)) == mem; \
	maybe_fail \
} while (0)

#define test_negative(version, mem, ipa, ipb, ipc, ipd) do { \
	bool _s = lookup(t.root##version, version == 4 ? 32 : 128, ip##version(ipa, ipb, ipc, ipd)) != mem; \
	maybe_fail \
} while (0)

bool __init allowedips_selftest(void)
{
	DEFINE_MUTEX(mutex);
	struct allowedips t;
	struct wireguard_peer *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *f = NULL, *g = NULL, *h = NULL;
	size_t i = 0;
	bool success = false;
	struct in6_addr ip;
	__be64 part;

	mutex_init(&mutex);

	mutex_lock(&mutex);

	allowedips_init(&t);
	init_peer(a);
	init_peer(b);
	init_peer(c);
	init_peer(d);
	init_peer(e);
	init_peer(f);
	init_peer(g);
	init_peer(h);

	insert(4, a, 192, 168, 4, 0, 24);
	insert(4, b, 192, 168, 4, 4, 32);
	insert(4, c, 192, 168, 0, 0, 16);
	insert(4, d, 192, 95, 5, 64, 27);
	insert(4, c, 192, 95, 5, 65, 27); /* replaces previous entry, and maskself is required */
	insert(6, d, 0x26075300, 0x60006b00, 0, 0xc05f0543, 128);
	insert(6, c, 0x26075300, 0x60006b00, 0, 0, 64);
	insert(4, e, 0, 0, 0, 0, 0);
	insert(6, e, 0, 0, 0, 0, 0);
	insert(6, f, 0, 0, 0, 0, 0); /* replaces previous entry */
	insert(6, g, 0x24046800, 0, 0, 0, 32);
	insert(6, h, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 64); /* maskself is required */
	insert(6, a, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 128);
	insert(6, c, 0x24446800, 0x40e40800, 0xdeaebeef, 0xdefbeef, 128);
	insert(6, b, 0x24446800, 0xf0e40800, 0xeeaebeef, 0, 98);
	insert(4, g, 64, 15, 112, 0, 20);
	insert(4, h, 64, 15, 123, 211, 25); /* maskself is required */
	insert(4, a, 10, 0, 0, 0, 25);
	insert(4, b, 10, 0, 0, 128, 25);
	insert(4, a, 10, 1, 0, 0, 30);
	insert(4, b, 10, 1, 0, 4, 30);
	insert(4, c, 10, 1, 0, 8, 29);
	insert(4, d, 10, 1, 0, 16, 29);

#ifdef DEBUG_PRINT_TRIE_GRAPHVIZ
	print_tree(t.root4, 32);
	print_tree(t.root6, 128);
#endif

	success = true;

	test(4, a, 192, 168, 4, 20);
	test(4, a, 192, 168, 4, 0);
	test(4, b, 192, 168, 4, 4);
	test(4, c, 192, 168, 200, 182);
	test(4, c, 192, 95, 5, 68);
	test(4, e, 192, 95, 5, 96);
	test(6, d, 0x26075300, 0x60006b00, 0, 0xc05f0543);
	test(6, c, 0x26075300, 0x60006b00, 0, 0xc02e01ee);
	test(6, f, 0x26075300, 0x60006b01, 0, 0);
	test(6, g, 0x24046800, 0x40040806, 0, 0x1006);
	test(6, g, 0x24046800, 0x40040806, 0x1234, 0x5678);
	test(6, f, 0x240467ff, 0x40040806, 0x1234, 0x5678);
	test(6, f, 0x24046801, 0x40040806, 0x1234, 0x5678);
	test(6, h, 0x24046800, 0x40040800, 0x1234, 0x5678);
	test(6, h, 0x24046800, 0x40040800, 0, 0);
	test(6, h, 0x24046800, 0x40040800, 0x10101010, 0x10101010);
	test(6, a, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef);
	test(4, g, 64, 15, 116, 26);
	test(4, g, 64, 15, 127, 3);
	test(4, g, 64, 15, 123, 1);
	test(4, h, 64, 15, 123, 128);
	test(4, h, 64, 15, 123, 129);
	test(4, a, 10, 0, 0, 52);
	test(4, b, 10, 0, 0, 220);
	test(4, a, 10, 1, 0, 2);
	test(4, b, 10, 1, 0, 6);
	test(4, c, 10, 1, 0, 10);
	test(4, d, 10, 1, 0, 20);

	insert(4, a, 1, 0, 0, 0, 32);
	insert(4, a, 64, 0, 0, 0, 32);
	insert(4, a, 128, 0, 0, 0, 32);
	insert(4, a, 192, 0, 0, 0, 32);
	insert(4, a, 255, 0, 0, 0, 32);
	allowedips_remove_by_peer(&t, a, &mutex);
	test_negative(4, a, 1, 0, 0, 0);
	test_negative(4, a, 64, 0, 0, 0);
	test_negative(4, a, 128, 0, 0, 0);
	test_negative(4, a, 192, 0, 0, 0);
	test_negative(4, a, 255, 0, 0, 0);

	allowedips_free(&t, &mutex);
	allowedips_init(&t);
	insert(4, a, 192, 168, 0, 0, 16);
	insert(4, a, 192, 168, 0, 0, 24);
	allowedips_remove_by_peer(&t, a, &mutex);
	test_negative(4, a, 192, 168, 0, 1);

	/* These will hit the BUG_ON(len >= 128) in free_node if something goes wrong. */
	for (i = 0; i < 128; ++i) {
		part = cpu_to_be64(~(1LLU << (i % 64)));
		memset(&ip, 0xff, 16);
		memcpy((u8 *)&ip + (i < 64) * 8, &part, 8);
		allowedips_insert_v6(&t, &ip, 128, a, &mutex);
	}

#ifdef DEBUG_RANDOM_TRIE
	if (success)
		success = randomized_test();
#endif

	if (success)
		pr_info("allowedips self-tests: pass\n");

free:
	allowedips_free(&t, &mutex);
	kfree(a);
	kfree(b);
	kfree(c);
	kfree(d);
	kfree(e);
	kfree(f);
	kfree(g);
	kfree(h);
	mutex_unlock(&mutex);

	return success;
}
#undef test_negative
#undef test
#undef remove
#undef insert
#undef init_peer

#endif
