//go:build ignore
#include "common.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event {
    u16 sport;
    u16 dport;
    u32 saddr;
    u32 daddr;
    u32 curtime;
    u8 netproto;
    u8 netcmd;
    u8 appproto;
    u8 appcmd;
};
struct event *unused_event __attribute__((unused));

static __always_inline u16 my_htons(u16 val) {
    return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}

SEC("classifier")
int capture_outgoing_packets(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);

    // Check if there's enough space for the Ethernet header
    if ((struct ethhdr *)(eth + 1) > (struct ethhdr *)data_end) {
        return TC_ACT_OK; // Not enough space, drop packet
    }


    // Check if it's an IPv4 packet
    if ((void *)(ip + 1) <= data_end && eth->h_proto == my_htons(ETH_P_IP)) {
        // Check if there's enough space for the IP header
        if ((void *)(ip + 1) > data_end) {
            return TC_ACT_OK; // Not enough space, drop packet
        }

        // Initialize the event structure
        struct event *net_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (!net_info) {
            return TC_ACT_OK; // Ring buffer full, drop packet
        }

        // Record the source and destination IP addresses
        net_info->saddr = ip->saddr;
        net_info->daddr = ip->daddr;

        // Record the protocol
        net_info->netproto = ip->protocol;

        // Record the current time
        net_info->curtime = bpf_ktime_get_ns() / 1000000; // Convert to milliseconds

        // If it's a TCP packet, record the source and destination ports
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
            if ((void *)(tcp + 1) <= data_end) {
                net_info->sport = my_htons(tcp->source);
                net_info->dport = my_htons(tcp->dest);
            }
        } else {
            // For non-TCP packets, set ports to 0
            net_info->sport = 0;
            net_info->dport = 0;
        }

        // Submit the event to the ring buffer
        bpf_ringbuf_submit(net_info, 0);
    }

    return TC_ACT_OK;
}
