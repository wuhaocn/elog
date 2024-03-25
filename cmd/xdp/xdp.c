//go:build ignore
#include "common.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
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
    u8 appproto;
    u8 appcmd;
};

// 定义事件结构的 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
struct event *unused_event __attribute__((unused));
// 解析 IP 源地址并记录相关信息到 Ring Buffer
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx) {
void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    // 记录 IP 地址和协议
    net_info->saddr = iph->saddr;
    net_info->daddr = iph->daddr;
    net_info->netproto = iph->protocol;

    // 记录当前时间（毫秒）
    net_info->curtime = bpf_ktime_get_ns();

    // 如果是 TCP 数据包，则记录源端口和目标端口，并且记录 TCP 标志
    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        if ((void *)(tcph + 1) <= data_end) {
            net_info->sport = bpf_ntohs(tcph->source);
            net_info->dport = bpf_ntohs(tcph->dest);
            net_info->netflags = tcph->syn | (tcph->ack << 1) | (tcph->fin << 2) | (tcph->rst << 3) | (tcph->psh << 4) | (tcph->urg << 5);
        }
    } else {
        // 如果不是 TCP 数据包，将端口和 TCP 标志都设置为 0
        net_info->sport = 0;
        net_info->dport = 0;
        net_info->netflags = 0;
    }
    net_info->netcmd = 0; // Outgoing
    // 提交事件到 Ring Buffer
    bpf_ringbuf_submit(net_info, 0);

    return 1;
}

// XDP 程序入口
SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    parse_ip_src_addr(ctx);
    return XDP_PASS;
}
