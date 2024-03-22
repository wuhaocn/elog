//go:build ignore
#include "common.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_sockops.h"
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
static __always_inline int sock_ops_proc(struct bpf_sock_ops *skops) {
    struct event *net_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!net_info) {
        return 0;
    }

    // 记录 IP 地址和协议
    if (skops->family == AF_INET) {
        net_info->saddr = skops->remote_ip4;
        net_info->daddr = skops->local_ip4;
    } else if (skops->family == AF_INET6) {
        // 如果是 IPv6，则使用远程和本地 IPv6 地址
        for (int i = 0; i < 4; ++i) {
            net_info->saddr |= skops->remote_ip6[i] << (i * 8);
            net_info->daddr |= skops->local_ip6[i] << (i * 8);
        }
    } else {
        // 非 IPv4 和 IPv6 地址，不做处理
        return 0;
    }

    net_info->sport = skops->remote_port; // 远程端口
    net_info->dport = skops->local_port;  // 本地端口

    // 记录当前时间（毫秒）
    net_info->curtime = bpf_ktime_get_ns();

    // 如果是 TCP 数据包，记录 TCP 标志
    if (skops->family == AF_INET && skops->state == BPF_TCP_ESTABLISHED) {
        net_info->netflags = skops->skb_tcp_flags;
    } else {
        net_info->netflags = 0;
    }

    net_info->netcmd = 0; // Unknown

    // 提交事件到 Ring Buffer
    bpf_ringbuf_submit(net_info, 0);

    return 1;
}

// Socket 操作的 eBPF 程序
SEC("sockops")
int bpf_sock_ops(struct bpf_sock_ops *skops) {
    sock_ops_proc(skops);
    return 1;
}