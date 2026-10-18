// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2026 Zhu Yanjun <yanjun.zhu@linux.dev>
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#define MAX_PKT_LEN 512

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);/* Shared by all CPUs */
} rb SEC(".maps");

SEC("netkit/primary")
int handle_netkit_ingress(struct __sk_buff *skb)
{
	/* Get the header pointer of skb */
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = data;

	/* Verify the data */
	if (data + sizeof(*eth) > data_end)
		return BPF_OK;

	/* Check if it is IP skb */
	if (eth->h_proto == htons(ETH_P_IP)) {
		struct iphdr *iph = data + sizeof(*eth);

		if ((void *)iph + sizeof(*iph) <= data_end) {
			bpf_printk("Got IP packet from netkit ingress, %d\n", skb->len);

			__u32 len = skb->len;

			/* It is a rping test, the size of packets should be
			 * less than MAX_PKT_LEN
			 */
			if (len == 0 || len > MAX_PKT_LEN) {
				bpf_printk("len is not in 0..MAX_PKT_LEN\n");
				return BPF_OK;
			}

			/* The len is fixed to MAX_PKT_LEN */
			void *reserve = bpf_ringbuf_reserve(&rb, MAX_PKT_LEN, 0);

			if (!reserve) {
				bpf_printk("bpf_ringbuf_reserve fails\n");
				return BPF_OK;
			}

			if (bpf_skb_load_bytes(skb, 0, reserve, len) < 0) {
				bpf_ringbuf_discard(reserve, 0);
				bpf_printk("bpf_skb_load_bytes fails\n");
				return BPF_OK;
			}

			bpf_ringbuf_submit(reserve, 0);
		}
	}

	/* BPF_OK:	Pass
	 * BPF_DROP:	Drop skb
	 */
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
