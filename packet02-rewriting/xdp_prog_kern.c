/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <string.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or -1 on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	/*
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;
	__be16 h_proto;
	int vlid = -1;
	*/

	/* Check if there is a vlan tag to pop */
	__be16 ethernet_contents_type = eth->h_proto;
	if (!proto_is_vlan(ethernet_contents_type)) return -1;

	/* Still need to do bounds checking */
	void *data_end = (void *)(long)ctx->data_end;
	struct vlan_hdr *vlan = (void *)((void *)eth + sizeof(*eth));
	if (vlan + 1 > data_end) return -1;

	/* Save vlan ID for returning, h_proto for updating Ethernet header */
	struct vlan_hdr vlan_copy = *vlan;

	/* Make a copy of the outer Ethernet header before we cut it off */
	struct ethhdr ethernet_header_copy;
	memcpy(&ethernet_header_copy, eth, sizeof(*eth));

	/* Actually adjust the head pointer */
	int ret_adjust = bpf_xdp_adjust_head(ctx, sizeof(struct vlan_hdr));
	if (ret_adjust != 0) return -1;

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */
	struct ethhdr *new_eth = (void *)(long)ctx->data;
	void *new_data_end = (void *)(long)ctx->data_end;
	if (new_eth + 1 > new_data_end) return -1;

	/* Copy back the old Ethernet header and update the proto type */
	memcpy(eth, &ethernet_header_copy, sizeof(ethernet_header_copy));
	eth->h_proto = vlan_copy.h_vlan_encapsulated_proto;

	return bpf_ntohs(vlan_copy.h_vlan_TCI);
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
					 struct ethhdr *eth, int vlid)
{
	return 0;
}

/* Implement assignment 1 in this section */
SEC("xdp")
int xdp_port_rewrite_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type != bpf_htons(ETH_P_IPV6)) {
		return XDP_PASS;
	}

	int ipv6_type = parse_ip6hdr(&nh, data_end, &ip6h);
	if (ipv6_type != bpf_htons(IPPROTO_ICMPV6)) {
		return XDP_PASS;
	}

	if (ipv6_type == IPPROTO_TCP) {
		struct tcphdr *tcp = nh.pos;
		if (tcp + 1 > data_end)
			return XDP_ABORTED;
		tcp->dest = bpf_htons(bpf_ntohs(tcp->dest) - 1);
	} else if (ipv6_type == IPPROTO_UDP) {
		struct udphdr *udp = nh.pos;
		if (udp + 1 > data_end)
			return XDP_ABORTED;
		udp->dest = bpf_htons(bpf_ntohs(udp->dest) - 1);
	}
	// else pass

	return XDP_PASS;
}

/* VLAN swapper; will pop outermost VLAN tag if it exists, otherwise push a new
 * one with ID 1. Use this for assignments 2 and 3.
 */
SEC("xdp")
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	/* Assignment 2 and 3 will implement these. For now they do nothing */
	if (proto_is_vlan(eth->h_proto))
		vlan_tag_pop(ctx, eth);
	else
		vlan_tag_push(ctx, eth, 1);

	return XDP_PASS;
}

/* Solution to the parsing exercise in lesson packet01. Handles VLANs and legacy
 * IP (via the helpers in parsing_helpers.h).
 */
SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		struct icmp6hdr *icmp6h;

		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

		if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
			action = XDP_DROP;

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
			action = XDP_DROP;
	}
 out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
