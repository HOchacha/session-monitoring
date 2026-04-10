#ifndef __EBPF_AGENT_COMMON_H__
#define __EBPF_AGENT_COMMON_H__

struct flow_event {
    __u64 ts_unix_nano;
    __u32 ifindex;
    __u8  ip_version;  /* 4 or 6 — inner IP version for VXLAN */
    __u8  protocol;    /* IPPROTO_TCP=6, IPPROTO_UDP=17, ... */
    __u8  src_ip[16];  /* inner src for VXLAN, otherwise outer */
    __u8  dst_ip[16];  /* inner dst for VXLAN, otherwise outer */
    __u16 src_port;    /* inner ports for VXLAN */
    __u16 dst_port;
    __u16 vlan_id;     /* 802.1Q VLAN ID (12-bit); 0 = untagged */
    __u32 vni;         /* VXLAN Network Identifier; 0 = non-VXLAN */
    __u8  outer_src_ip[16]; /* outer (tunnel endpoint) src; zeroed if non-VXLAN */
    __u8  outer_dst_ip[16]; /* outer (tunnel endpoint) dst */
    __u64 bytes;
    __u64 packets;
};

#endif
