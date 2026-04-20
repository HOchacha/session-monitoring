// SPDX-License-Identifier: GPL-2.0
// flow.bpf.c — tc ingress hook for tun (L3) devices.
//
// Parses raw IPv4/IPv6 packets via direct data-pointer access (no helper
// calls) and aggregates 5-tuple flow metrics into a per-CPU hash map.
// Userspace periodically drains the map instead of receiving per-packet
// ringbuf events, so the BPF hot path has zero ringbuf overhead.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* ── map ───────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct flow_key);
    __type(value, struct flow_metrics);
} flows SEC(".maps");

/* ── main program ───────────────────────────────────────────────────── */

SEC("tc")
int handle_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Need at least 1 byte to check IP version. */
    if (data + 1 > data_end)
        return BPF_OK;

    __u8 first_byte = *((__u8 *)data);
    __u8 ip_ver     = first_byte >> 4;

    struct flow_key key = {};
    key.ifindex = skb->ifindex;

    __u32 l4_off = 0;

    if (ip_ver == 4) {
        /* IPv4: minimum header is 20 bytes. */
        if (data + 20 > data_end)
            return BPF_OK;

        __u32 ihl = (__u32)(first_byte & 0x0F) * 4;
        if (ihl < 20 || data + ihl > data_end)
            return BPF_OK;

        key.ip_version = 4;
        key.protocol   = *((__u8 *)data + 9);           /* proto at offset 9  */
        __builtin_memcpy(key.src_ip, (__u8 *)data + 12, 4); /* saddr at offset 12 */
        __builtin_memcpy(key.dst_ip, (__u8 *)data + 16, 4); /* daddr at offset 16 */
        l4_off = ihl;

    } else if (ip_ver == 6) {
        /* IPv6: fixed 40-byte header, no option parsing needed for L4 offset. */
        if (data + 40 > data_end)
            return BPF_OK;

        key.ip_version = 6;
        key.protocol   = *((__u8 *)data + 6);            /* nexthdr at offset 6  */
        __builtin_memcpy(key.src_ip, (__u8 *)data + 8,  16); /* saddr at offset 8  */
        __builtin_memcpy(key.dst_ip, (__u8 *)data + 24, 16); /* daddr at offset 24 */
        l4_off = 40;

    } else {
        return BPF_OK;
    }

    /* Extract src/dst ports for TCP and UDP. */
    if (key.protocol == 6 /* TCP */ || key.protocol == 17 /* UDP */) {
        if (data + l4_off + 4 > data_end)
            goto aggregate;  /* short packet — record flow without ports */

        __be16 *ports = (__be16 *)((__u8 *)data + l4_off);
        key.src_port  = bpf_ntohs(ports[0]);
        key.dst_port  = bpf_ntohs(ports[1]);
    }

aggregate:;
    __u64 now       = bpf_ktime_get_ns();
    __u64 pkt_bytes = (__u64)skb->len;

    struct flow_metrics *val = bpf_map_lookup_elem(&flows, &key);
    if (val) {
        val->bytes   += pkt_bytes;
        val->packets += 1;
        val->last_seen = now;
    } else {
        struct flow_metrics new_val = {
            .bytes      = pkt_bytes,
            .packets    = 1,
            .first_seen = now,
            .last_seen  = now,
        };
        long ret = bpf_map_update_elem(&flows, &key, &new_val, BPF_NOEXIST);
        if (ret != 0) {
            /* Race: another CPU inserted first — retry lookup. */
            val = bpf_map_lookup_elem(&flows, &key);
            if (val) {
                val->bytes   += pkt_bytes;
                val->packets += 1;
                val->last_seen = now;
            }
        }
    }

    return BPF_OK;
}
