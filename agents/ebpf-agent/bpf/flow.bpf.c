// SPDX-License-Identifier: GPL-2.0
// flow.bpf.c — tc ingress hook that parses packets into FlowEvent and
// emits them via ringbuf to userspace. Supports VXLAN decap for
// inner+outer simultaneous parsing.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* ── maps ──────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MiB */
} events SEC(".maps");

/* ── constants ─────────────────────────────────────────────────────── */

#define ETH_P_IP     0x0800
#define ETH_P_IPV6   0x86DD
#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8  /* QinQ / 802.1ad */
#define ETH_HLEN     14
#define IPV6_HLEN  40
#define VXLAN_PORT 4789
#define VXLAN_HLEN 8   /* VXLAN header: flags(1) + reserved(3) + VNI(3) + reserved(1) */

/* ── L4 parser ─────────────────────────────────────────────────────── */

static __always_inline int parse_l4(struct __sk_buff *skb, __u32 off,
                                    __u8 proto, struct flow_event *e)
{
    e->protocol = proto;

    if (proto == 6 /* TCP */ || proto == 17 /* UDP */) {
        __be16 ports[2]; /* src, dst */
        if (bpf_skb_load_bytes(skb, off, ports, sizeof(ports)))
            return -1;
        e->src_port = bpf_ntohs(ports[0]);
        e->dst_port = bpf_ntohs(ports[1]);
    }
    /* ICMP / other: ports stay 0 */
    return 0;
}

/* ── L3 parser (reusable for outer and inner) ──────────────────────── */

/* Parse IPv4/IPv6 starting at ip_off (offset of the IP header) and fill
 * src_ip/dst_ip/ip_version/protocol into the flow_event. Returns the
 * L4 offset on success, or 0 on failure. */
static __always_inline __u32 parse_l3(struct __sk_buff *skb, __u32 ip_off,
                                       __u16 l3_proto, struct flow_event *e,
                                       __u8 *out_proto)
{
    if (l3_proto == ETH_P_IP) {
        __u8 ver_ihl;
        if (bpf_skb_load_bytes(skb, ip_off, &ver_ihl, 1))
            return 0;

        __u32 ihl = (__u32)(ver_ihl & 0x0F) * 4;
        if (ihl < 20)
            return 0;

        __u8 proto;
        if (bpf_skb_load_bytes(skb, ip_off + 9, &proto, 1))
            return 0;

        if (bpf_skb_load_bytes(skb, ip_off + 12, e->src_ip, 4))
            return 0;
        if (bpf_skb_load_bytes(skb, ip_off + 16, e->dst_ip, 4))
            return 0;

        e->ip_version = 4;
        *out_proto = proto;
        return ip_off + ihl;

    } else if (l3_proto == ETH_P_IPV6) {
        __u8 nexthdr;
        if (bpf_skb_load_bytes(skb, ip_off + 6, &nexthdr, 1))
            return 0;

        if (bpf_skb_load_bytes(skb, ip_off + 8, e->src_ip, 16))
            return 0;
        if (bpf_skb_load_bytes(skb, ip_off + 24, e->dst_ip, 16))
            return 0;

        e->ip_version = 6;
        *out_proto = nexthdr;
        return ip_off + IPV6_HLEN;
    }

    return 0;
}

/* ── VXLAN detection & inner parse ─────────────────────────────────── */

/* Check if this is a VXLAN packet (UDP dst port 4789) and if so, parse
 * the inner frame. Saves outer IPs into outer_src_ip/outer_dst_ip and
 * overwrites the primary fields with inner packet info.
 * Returns 1 if VXLAN was parsed, 0 otherwise. */
static __always_inline int try_parse_vxlan(struct __sk_buff *skb,
                                            __u32 l4_off,
                                            struct flow_event *e)
{
    /* VXLAN header starts right after the UDP header (8 bytes) */
    __u32 vxlan_off = l4_off + 8; /* skip UDP header */

    /* Read VXLAN header: 4 bytes flags+reserved, then 4 bytes VNI+reserved.
     * VNI is in bits [31:8] of the second 4 bytes (network order). */
    __u8 vxlan_hdr[VXLAN_HLEN];
    if (bpf_skb_load_bytes(skb, vxlan_off, vxlan_hdr, VXLAN_HLEN))
        return 0;

    /* Check VXLAN I-flag (bit 3 of first byte) — must be set */
    if (!(vxlan_hdr[0] & 0x08))
        return 0;

    /* Extract VNI from bytes [4..6] (24-bit, network order) */
    __u32 vni = ((__u32)vxlan_hdr[4] << 16) |
                ((__u32)vxlan_hdr[5] << 8)  |
                ((__u32)vxlan_hdr[6]);
    e->vni = vni;

    /* Save outer IPs before overwriting */
    __builtin_memcpy(e->outer_src_ip, e->src_ip, 16);
    __builtin_memcpy(e->outer_dst_ip, e->dst_ip, 16);

    /* Inner Ethernet starts after VXLAN header */
    __u32 inner_eth_off = vxlan_off + VXLAN_HLEN;

    /* Read inner ethertype */
    __be16 inner_eth_proto;
    if (bpf_skb_load_bytes(skb, inner_eth_off + 12, &inner_eth_proto, 2))
        return 0;

    __u16 inner_l3_proto = bpf_ntohs(inner_eth_proto);

    /* Zero out src/dst before inner parse overwrites them */
    __builtin_memset(e->src_ip, 0, 16);
    __builtin_memset(e->dst_ip, 0, 16);

    __u8 inner_proto = 0;
    __u32 inner_l4_off = parse_l3(skb, inner_eth_off + ETH_HLEN, inner_l3_proto, e, &inner_proto);
    if (!inner_l4_off) {
        /* Inner L3 parse failed — keep VNI + outer IPs, mark as VXLAN */
        e->protocol = 0;
        return 1;
    }

    if (parse_l4(skb, inner_l4_off, inner_proto, e)) {
        /* Inner L4 parse failed — still have inner L3 info */
    }

    return 1;
}

/* ── main program ──────────────────────────────────────────────────── */

SEC("tc")
int handle_ingress(struct __sk_buff *skb)
{
    /* Detect L3 (raw IP, e.g. tun) vs L2 (Ethernet) device.
     * L3 devices have no Ethernet header — packets start with the IP
     * header directly. We check the first byte's version nibble and
     * cross-validate with skb->protocol set by the kernel. */
    __u8 first_byte;
    if (bpf_skb_load_bytes(skb, 0, &first_byte, 1))
        return BPF_OK;

    __u16 skb_proto = bpf_ntohs(skb->protocol);
    __u8 ip_ver = first_byte >> 4;
    __u16 l3_proto;
    __u32 ip_off;     /* offset where the IP header starts */
    __u16 vlan_id = 0;

    if (ip_ver == 4 && skb_proto == ETH_P_IP) {
        /* L3 device — raw IPv4, no Ethernet header */
        l3_proto = ETH_P_IP;
        ip_off = 0;
    } else if (ip_ver == 6 && skb_proto == ETH_P_IPV6) {
        /* L3 device — raw IPv6 */
        l3_proto = ETH_P_IPV6;
        ip_off = 0;
    } else {
        /* L2 (Ethernet) — read EtherType at offset 12 */
        __be16 eth_proto;
        if (bpf_skb_load_bytes(skb, 12, &eth_proto, 2))
            return BPF_OK;

        l3_proto = bpf_ntohs(eth_proto);
        ip_off = ETH_HLEN;

        /* Handle 802.1Q / 802.1ad VLAN tag */
        if (l3_proto == ETH_P_8021Q || l3_proto == ETH_P_8021AD) {
            __be16 tci;
            if (bpf_skb_load_bytes(skb, 14, &tci, 2))
                return BPF_OK;
            vlan_id = bpf_ntohs(tci) & 0x0FFF;

            /* Read the real EtherType after the 4-byte VLAN tag */
            if (bpf_skb_load_bytes(skb, 16, &eth_proto, 2))
                return BPF_OK;
            l3_proto = bpf_ntohs(eth_proto);
            ip_off = ETH_HLEN + 4;
        }

        if (l3_proto != ETH_P_IP && l3_proto != ETH_P_IPV6)
            return BPF_OK;
    }

    struct flow_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return BPF_OK;

    __builtin_memset(e, 0, sizeof(*e));
    e->ts_unix_nano = bpf_ktime_get_ns();
    e->ifindex      = skb->ifindex;
    e->bytes        = skb->len;
    e->packets      = 1;
    e->vlan_id      = vlan_id;

    /* Parse outer L3 */
    __u8 outer_proto = 0;
    __u32 l4_off = parse_l3(skb, ip_off, l3_proto, e, &outer_proto);
    if (!l4_off)
        goto discard;

    /* Parse outer L4 */
    if (parse_l4(skb, l4_off, outer_proto, e)) {
        /* L4 parse failed — still emit L3 event */
        bpf_ringbuf_submit(e, 0);
        return BPF_OK;
    }

    /* If outer is UDP:4789, try VXLAN inner parse */
    if (outer_proto == 17 && e->dst_port == VXLAN_PORT) {
        try_parse_vxlan(skb, l4_off, e);
    }

    bpf_ringbuf_submit(e, 0);
    return BPF_OK;

discard:
    bpf_ringbuf_discard(e, 0);
    return BPF_OK;
}
