#ifndef __EBPF_AGENT_COMMON_H__
#define __EBPF_AGENT_COMMON_H__

/* flow_key identifies a unique flow (5-tuple).  44 bytes.
 * Optimised for tun (L3) devices — no VLAN or VXLAN metadata. */
struct flow_key {
    __u8  src_ip[16];   /* IPv4 in first 4 bytes; IPv6 uses all 16 */
    __u8  dst_ip[16];
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;     /* IPPROTO_TCP=6, IPPROTO_UDP=17, ... */
    __u8  ip_version;   /* 4 or 6 */
    __u8  _pad[2];      /* explicit padding — keeps ifindex 4-byte aligned */
    __u32 ifindex;
};

/* flow_metrics holds aggregated counters per flow.  32 bytes. */
struct flow_metrics {
    __u64 bytes;
    __u64 packets;
    __u64 first_seen;   /* ktime_ns of the first packet in this window */
    __u64 last_seen;    /* ktime_ns of the most recent packet */
};

#endif
