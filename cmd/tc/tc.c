//go:build ignore
#include "common.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "mqtt.h"
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

// Define event structure
struct event {
    u16 sport;
    u16 dport;
    u32 saddr;
    u32 daddr;
    u64 curtime;
    u8 netproto;
    u8 netcmd;
    u8 appproto;
    u8 appcmd;
    u8 apppkglength;
};

// MQTT control packet structure
struct mqtt_packet {
    u32 packettype;
    u32 packetlength;
};

// Define Ring Buffer for event structure
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
struct event *unused_event __attribute__((unused));

// Function to fill TCP layer information
static __always_inline void fill_tcp_info(struct event *net_info, struct iphdr *iph, struct tcphdr *tcph) {
    net_info->saddr = iph->saddr;
    net_info->daddr = iph->daddr;
    net_info->netproto = iph->protocol;
    net_info->sport = bpf_ntohs(tcph->source);
    net_info->dport = bpf_ntohs(tcph->dest);
    net_info->netcmd = tcph->syn | (tcph->ack << 1) | (tcph->fin << 2) | (tcph->rst << 3) | (tcph->psh << 4) | (tcph->urg << 5);
    net_info->curtime = bpf_ktime_get_ns();
}

// Function to parse MQTT control packets and record relevant information to Ring Buffer
static __always_inline void fill_mqtt_info(struct event *net_info, struct tcphdr *tcph, void *data_end) {
    // Set appproto to IPPROTO_MQTT for MQTT packets
    net_info->appproto = IPPROTO_MQTT;

    // Pointer to the start of MQTT payload
    u8 *mqtt_payload = (u8 *)tcph + sizeof(struct tcphdr);
    u8 *mqtt_packet_type = mqtt_payload + 1; // MQTT Control Packet Type byte

    // Check if there's enough space for at least the MQTT Control Packet Type byte
    if (mqtt_packet_type > (u8*)data_end)
        return;

    // Read MQTT Control Packet Type
    u8 packet_type = *mqtt_packet_type;
    net_info->appcmd = packet_type;

}

// Function to parse IP source address and record relevant information to Ring Buffer
static __always_inline int parse_tc(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Check if it's an IP packet
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;

    // Initialize IP header pointer
    iph = (struct iphdr *)(eth + 1);

    // Check IP header length
    if ((void *)(iph + 1) > data_end)
        return 0;

    // Check if it's a TCP packet
    if (iph->protocol != IPPROTO_TCP)
        return 0;

    // Initialize TCP header pointer
    tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);

    // Check TCP header length
    if ((void *)(tcph + 1) > data_end)
        return 0;

    // Reserve space in the Ring Buffer for event structure
    struct event *net_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!net_info)
        return 0;

    // Fill TCP layer information
    fill_tcp_info(net_info, iph, tcph);

    // Check if it's an MQTT packet
    if (tcph->dest == bpf_htons(MQTT_DEFAULT_PORT) || tcph->source == bpf_htons(MQTT_DEFAULT_PORT)){
        fill_mqtt_info(net_info, tcph, data_end);
        // Submit event to Ring Buffer
        bpf_ringbuf_submit(net_info, 0);
        return 0;
    }
    bpf_ringbuf_discard(net_info, 0);
    return 0;
}

// Entry point for tc program
SEC("tc")
int tc_prog_func(struct __sk_buff *skb) {
    parse_tc(skb);
    return TC_ACT_OK;
}
