//go:build ignore
#include "common.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "mqtt.h"
#include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

// 定义事件结构
struct event {
    u16 sport;
    u16 dport;
    u32 saddr;
    u32 daddr;
    u64 curtime;
    u8 netproto;
    u8 netcmd; 
    u8 netflags;
    u32 appproto;
    u32 appcmd;
    u32 apppkglength;
};

// MQTT 控制报文结构
struct mqtt_packet {
    u32 packettype;
    u32 packetlength;
};


// 定义事件结构的 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
struct event *unused_event __attribute__((unused));

// 补充IP层信息的函数
static __always_inline void fill_ip_info(struct event *net_info, struct iphdr *iph) {
    net_info->saddr = iph->saddr;
    net_info->daddr = iph->daddr;
    net_info->netproto = iph->protocol;
    net_info->curtime = bpf_ktime_get_ns();
}

// 补充TCP层信息的函数
static __always_inline void fill_tcp_info(struct event *net_info, struct tcphdr *tcph) {
    net_info->sport = bpf_ntohs(tcph->source);
    net_info->dport = bpf_ntohs(tcph->dest);
    net_info->netflags = tcph->syn | (tcph->ack << 1) | (tcph->fin << 2) | (tcph->rst << 3) | (tcph->psh << 4) | (tcph->urg << 5);
}

// 解析MQTT控制报文并记录相关信息到Ring Buffer
static __always_inline void fill_app_info(struct event *net_info, void *data, void *data_end) {
     // 确保数据包长度足够解析MQTT控制报文的固定头部
    u8 *mqtt_fixed_header = data;
    if (((void *)mqtt_fixed_header + 2) > data_end) {
        return;
    }
    
    // 解析剩余长度字段，这里简化处理，只考虑单字节剩余长度的情况
    u8 remaining_length = *mqtt_fixed_header;
    if (remaining_length & 0x80) {
        // 剩余长度是多字节的情况，这里不处理
        return;
    }
    
    // 提取控制包类型
    u8 mqtt_packet_type = *(mqtt_fixed_header + 1);
    
    // 根据控制包类型，设置appproto和appcmd
    net_info->appproto = IPPROTO_MQTT;
    net_info->appcmd = mqtt_packet_type;
    
    // 根据MQTT控制报文类型，设置appflags
    switch (mqtt_packet_type) {
        case MQTT_CONNECT:
            net_info->appcmd = MQTT_CMD_CONNECT;
            break;
        case MQTT_PUBLISH:
            net_info->appcmd = MQTT_CMD_PUBLISH;
            break;
        case MQTT_SUBSCRIBE:
            net_info->appcmd = MQTT_CMD_SUBSCRIBE;
            break;
        // 添加其他MQTT命令的处理
        default:
            net_info->appcmd = MQTT_CMD_UNKNOWN;
            break;
    }
}

// 解析 IP 源地址并记录相关信息到 Ring Buffer
static __always_inline int parse_tc(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;

    if ((void *)(eth + 1) > data_end) {
        return 0;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 0;
    }

    // 初始化 IP 头指针
    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return 0;
    }

    struct event *net_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!net_info) {
        return 0;
    }

    // 补充IP层信息
    fill_ip_info(net_info, iph);


        // 如果是 TCP 数据包，则记录源端口和目标端口，并且记录 TCP 标志
    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        if ((void *)(tcph + 1) <= data_end) {
            tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
            if (((void *)(tcph + 1)) <= data_end) {
                fill_tcp_info(net_info, tcph);
                
                // 计算TCP负载的开始位置和长度
                void *payload = (void *)((u8 *)tcph + tcph->doff * 4);
                u32 payload_len = (u32)(data_end - payload);
                
                // 检查是否为MQTT数据包
                if (tcph->dest == bpf_htons(MQTT_DEFAULT_PORT) || tcph->source == bpf_htons(MQTT_DEFAULT_PORT)) {
                    // 确保TCP负载长度足够解析MQTT控制报文的固定头部
                    if (((void *)payload + 2) <= data_end) {
                        fill_app_info(net_info, payload, data_end);
                    }
                }
            }
        }
    } else {
        // 如果不是 TCP 数据包，将端口和 TCP 标志都设置为 0
        net_info->sport = 0;
        net_info->dport = 0;
        net_info->netflags = 0;
        bpf_ringbuf_discard(net_info, 0);
        return 0;
    }
    net_info->netcmd = 0; // Outgoing
    // 提交事件到 Ring Buffer
    bpf_ringbuf_submit(net_info, 0);

    return 1;
}

// tc 程序入口
SEC("tc")
int tc_prog_func(struct __sk_buff *skb) {
    parse_tc(skb);
    return TC_ACT_OK;
}