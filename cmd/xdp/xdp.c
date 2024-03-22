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

static __always_inline int parse_ip_src_addr(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;

    if ((void *)(eth + 1) > data_end) {
        return 0;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 0;
    }

    // 初始化iph指针
    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return 0;
    }

    struct event *net_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!net_info) {
        return 0;
    }

    net_info->netproto = iph->protocol;
    net_info->saddr = iph->saddr;
    net_info->daddr = iph->daddr;
    net_info->curtime =  bpf_ktime_get_ns() / 1000000; // 转换为毫秒
    // 如果是TCP包
    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end) {
            bpf_ringbuf_submit(net_info, 0);
            return 0;
        }
        net_info->sport = bpf_ntohs(tcph->source);
        net_info->dport = bpf_ntohs(tcph->dest);
        
    } else {
        // 如果不是TCP包，将端口设置为0
        net_info->sport = 0;
        net_info->dport = 0;

    }

    bpf_ringbuf_submit(net_info, 0);

    return 1;
}

SEC("xdp_md")
int xdp_prog_func(struct xdp_md *ctx) {
	if (!parse_ip_src_addr(ctx)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}


done:
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}