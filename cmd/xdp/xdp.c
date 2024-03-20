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
	u32 srtt;
	u8 protocol;
};
struct event *unused_event __attribute__((unused));

static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
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
	if ((void *)(iph + 1) > data_end) {
		return 0;
	}

	struct event *tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!tcp_info) {
		return 0;
	}
	*ip_src_addr = (__u32)(iph->saddr);
	__u32 ip_dst_addr = (__u32)(iph->saddr);
	tcp_info->protocol = iph->protocol;
	tcp_info->saddr = *ip_src_addr;
	// tcp_info->daddr = *ip_dst_addr;
    //tcp
    if (iph->protocol == IPPROTO_TCP) {
        tcph = (void *)iph + iph->ihl * 4;
        if (tcph + 1 > data_end)
            return 0;
		tcp_info->dport = ntohs(tcph->source);
		tcp_info->sport = ntohs(tcph->dest);
		tcp_info->srtt = 1000;

		bpf_ringbuf_submit(tcp_info, 0);
    } else{
		//use test
		tcp_info->dport = 0;
		tcp_info->sport = 0;
		tcp_info->srtt = 1000;
		bpf_ringbuf_submit(tcp_info, 0);
	}

	
	return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	__u32 ip;
	if (!parse_ip_src_addr(ctx, &ip)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}


done:
	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
