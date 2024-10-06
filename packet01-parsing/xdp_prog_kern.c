/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

/* Assignment 2: Implemeant and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;
	if (ip6h + 1 > data_end) return -1;
	nh->pos += sizeof(*ip6h);

	*ip6hdr = ip6h;
	return ip6h->nexthdr;
}

static __always_inline int parse_ipv4(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **ipv4)
{
	struct iphdr *iph = nh->pos;
	if (iph + 1 > data_end) return -1;

	// header size + check?
	int hdrsize = iph->ihl * 4;
	if (nh->pos + hdrsize > data_end) return -1;
	nh->pos += hdrsize;

	*ipv4 = iph;

	return iph->protocol;
}

/* Assignment 3: Implement and use this */
static __always_inline int (parse_icmp6hdr)(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6 = nh->pos;
	if (icmp6 + 1 > data_end) return -1;
	nh->pos += sizeof(*icmp6);

	*icmp6hdr = icmp6;
	return icmp6->icmp6_type;
}

static __always_inline int (parse_icmp4hdr)(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmphdr **icmp4hdr)
{
	struct icmphdr *icmp4 = nh->pos;
	if (icmp4 + 1 > data_end) return -1;
	nh->pos += sizeof(*icmp4);

	*icmp4hdr = icmp4;
	return icmp4->type;
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IPV6)) { // IPv6
		int ipv6_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (ipv6_type != bpf_htons(IPPROTO_ICMPV6))
			goto out;

		int icmp_type = parse_icmp6hdr(&nh, data_end, &icmp6);
		if (icmp_type != bpf_htons(ICMPV6_ECHO_REQUEST))
			goto out;
		
		if (bpf_ntohs(icmp6->icmp6_dataun.u_echo.sequence) % 2 == 0) {
			action = XDP_DROP;
		}
	} else if (nh_type == bpf_htons(ETH_P_IP)) { // IPv4
		struct iphdr *ipv4;

		nh_type = parse_ipv4(&nh, data_end, &ipv4);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		struct icmphdr *icmpv4;
		nh_type = parse_icmp4hdr(&nh, data_end, &icmpv4);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmpv4->un.echo.sequence) % 2 == 0) {
			action = XDP_DROP;
		}
	} else {
		// Unknown protocol: do nothing
	}
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
