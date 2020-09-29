#include "bpf_helpers.h"

// Ethernet header
struct ethhdr
{
    __u8 h_dest[6];
    __u8 h_source[6];
    __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr
{
    __u8 ihl : 4;
    __u8 version : 4;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

struct icmphdr
{
    __u8 typ;
    __u8 code;
    __u16 checksum;
    __u16 id;
    __u16 seq;
    __u32 g;
    __u32 l;
};

// PerfEvent eBPF map
BPF_MAP_DEF(icmpmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(icmpmap);

// XDP program //
SEC("xdp")
int icmp_inject(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 packet_size = data_end - data;

    // L2
    struct ethhdr *ether = data;
    if (data + sizeof(*ether) > data_end)
    {
        return XDP_ABORTED;
    }

    // L3
    if (ether->h_proto != 0x08)
    { // htons(ETH_P_IP) -> 0x08
        return XDP_PASS;
    }

    data += sizeof(*ether);
    struct iphdr *ip = data;
    if (data + sizeof(*ip) > data_end)
    {
        return XDP_ABORTED;
    }

    if (ip->protocol == 0x01)
    {
        data += ip->ihl * 4;
        struct icmphdr *icmp = data;
        if (data + sizeof(*icmp) > data_end)
        {
            return XDP_ABORTED;
        }

        if (icmp->g == 0x706D6369 && icmp->l == 0x70647532)
        {
            __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
            bpf_perf_event_output(ctx, &icmpmap, flags, &packet_size, sizeof(packet_size));
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
