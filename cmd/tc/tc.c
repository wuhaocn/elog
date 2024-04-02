//go:build ignore
#include "common.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "mqtt.h"
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_PAYLOAD_LOAD 5
#define SEC_TO_MSEC 1000000ULL
// TCP 头部的基本长度（不包括选项），单位是 32 位字（4 字节）

// Define event structure
struct event {
    u16 sport;
    u16 dport;
    u32 saddr;
    u32 daddr;
    u64 curtime;
    u64 srtt;
    u8 netproto;
    u8 netcmd;
    u32 netpkglength;
    u8 appproto;
    u8 appcmd;
    u32 apppkglength;
    u8 payload[MAX_PAYLOAD_LOAD];
};
struct key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};


// Define Ring Buffer for event structure
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
struct event *unused_event __attribute__((unused));

struct bpf_map_def SEC("maps") rtt_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct key),
    .value_size = sizeof(__u64),
    .max_entries = 100000, // Adjust the maximum number of entries as needed
};

// 定义 BPF Map 用于存储协议名称和端口列表
struct bpf_map_def SEC("maps") protocol_ports_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = 16,                // 假设协议名称最大长度为 16
    .value_size  = sizeof(__u16) *3,  // 假设最多存储 3 个端口
    .max_entries = 10,                // 假设最多存储 100,000 个配置项
};

// Function to construct the key for TCP packets
static __always_inline struct key construct_key(struct iphdr *iph, struct tcphdr *tcph, int is_ack) {
    struct key k = {
        .src_ip = is_ack ? iph->daddr : iph->saddr,
        .dst_ip = is_ack ? iph->saddr : iph->daddr,
        .src_port = bpf_htons(is_ack ? tcph->dest : tcph->source),
        .dst_port = bpf_htons(is_ack ? tcph->source : tcph->dest),
    };
    return k;
}


// Function to handle TCP packets and calculate RTT
static __always_inline void fill_tcp_rtt_info(struct __sk_buff *skb, struct event *net_info, struct iphdr *iph, struct tcphdr *tcph) {
    if (!skb || !net_info || !iph || !tcph) {
        // Error handling: Invalid input parameters
        return;
    }
    __u64 now = bpf_ktime_get_ns(); // Get the current timestamp in nanoseconds
    // Record the timestamp for SYN or PSH packets
    if (tcph->syn || tcph->psh) {
        struct key syn_key = construct_key(iph, tcph, 0);
        bpf_map_update_elem(&rtt_map, &syn_key, &now, BPF_ANY);
    }
    // Calculate RTT for ACK packets
    if (tcph->ack) {
        struct key ack_key = construct_key(iph, tcph, 1);
        __u64 *timestamp = bpf_map_lookup_elem(&rtt_map, &ack_key);
        if (timestamp) {
            __u64 rtt = now - *timestamp;
            net_info->srtt = rtt / 1000000;
        }
    }
    // // Check if the TCP header has the timestamp option
    // if (tcph->doff > 5) {
    //     // Calculate TCP options offset
    //     u8 tcp_options_offset =  4 + sizeof(struct ethhdr) + sizeof(struct iphdr) +  sizeof(struct tcphdr);
    //     // Extract TCP options
    //     __u32 tsval, tsecr;
    //     bpf_skb_load_bytes(skb, tcp_options_offset, &tsval, sizeof(tsval));
    //     bpf_skb_load_bytes(skb, tcp_options_offset + sizeof(tsval), &tsecr, sizeof(tsecr));
    // }

}
static __always_inline void fill_tcp_info(struct __sk_buff *skb, struct event *net_info, struct iphdr *iph, struct tcphdr *tcph) {
    net_info->saddr = iph->saddr;
    net_info->daddr = iph->daddr;
    net_info->netproto = iph->protocol;
    net_info->sport = bpf_ntohs(tcph->source);
    net_info->dport = bpf_ntohs(tcph->dest);
    net_info->netcmd = tcph->syn | (tcph->ack << 1) | (tcph->fin << 2) | (tcph->rst << 3) | (tcph->psh << 4) | (tcph->urg << 5);
    net_info->curtime = bpf_ktime_get_ns();
    fill_tcp_rtt_info(skb, net_info, iph, tcph);
}


// Function to fill MQTT information
static __always_inline void fill_mqtt_info(struct __sk_buff *skb, struct event *net_info, struct iphdr *iph, struct tcphdr *tcph) {
       // Set appproto to IPPROTO_MQTT for MQTT packets
    net_info->appproto = IPPROTO_MQTT;
    // tcp header length
    u8 tcp_header_length = tcph->doff * 4 ;
    // tcp payload offset
    u8 tcp_payload_offset = tcp_header_length + sizeof(struct ethhdr) + sizeof(struct iphdr);
    // eth + ip + tcp header length
    u8 tcp_payload_length = skb->len - tcp_payload_offset;
    net_info->netpkglength = tcp_payload_length;
    bpf_skb_load_bytes(skb, tcp_payload_offset, &net_info->appcmd, 1);
    bpf_skb_load_bytes(skb, tcp_payload_offset + 1, &net_info->apppkglength, 1);
    bpf_skb_load_bytes(skb, tcp_payload_offset, net_info->payload, 2);
}

#define PROTOCOL_MQTT "mqtt"
static __always_inline bool check_trace_mqtt(struct __sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph) {

    char protocol[16] = PROTOCOL_MQTT; 
    __u16 *ports_mqtt = bpf_map_lookup_elem(&protocol_ports_map, protocol);
    if (!ports_mqtt) {
        return false; 
    }

    int num_ports = 0;
    while (num_ports < 3 && ports_mqtt[num_ports] != 0) {
        num_ports++;
    }
    for (int i = 0; i < num_ports; i++) {
        __u16 port = ports_mqtt[i];
        if (port == 0) {
            break;
        }
        if (tcph->dest == bpf_htons(port) || tcph->source == bpf_htons(port)){
            struct event *net_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
            if (!net_info){
                return false;
            }
            fill_tcp_info(skb, net_info, iph, tcph);
            fill_mqtt_info(skb, net_info, iph, tcph);
            bpf_ringbuf_submit(net_info, 0);
            return true;
        }
    }

    return false;
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

    check_trace_mqtt(skb, iph, tcph);

    return 0;
}

// Entry point for tc program
SEC("tc")
int tc_prog_func(struct __sk_buff *skb) {
    parse_tc(skb);
    return TC_ACT_OK;
}
