#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);/* Shared by all CPUs */
} rb SEC(".maps");

SEC("tcx/ingress")
int handle_netkit_ingress(struct __sk_buff *skb) {
	/* Get the header pointer of skb */
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = data;
    
	/* Verify the data */
	if (data + sizeof(*eth) > data_end)
		return BPF_OK;

	/* Check if it is IP skb */
	if (eth->h_proto == __constant_htons(ETH_P_IP)) {
		struct iphdr *iph = data + sizeof(*eth);
		if ((void *)iph + sizeof(*iph) <= data_end) {
			bpf_printk("Got IP packet from netkit ingress, %d\n", skb->len);

			__u32 len = skb->len;
			len &= 0x1FF;
			if (len == 0) {
				bpf_printk("%s +%d\n", __FILE__, __LINE__);
				return BPF_OK;
			}
			__u32 copy_len = len;

                        void *sample = bpf_ringbuf_reserve(&rb, 512, 0);
                        if (!sample) return BPF_OK;

                        if (bpf_skb_load_bytes(skb, 0, sample, copy_len) < 0) {
                          bpf_ringbuf_discard(sample, 0);
			bpf_printk("%s +%d\n", __FILE__, __LINE__);
                          return BPF_OK;
                        }

                        bpf_ringbuf_submit(sample, 0);
		}
	}

	/* BPF_OK:	Pass
	 * BPF_DROP:	Drop skb
	*/
	return BPF_OK; 
}

char _license[] SEC("license") = "GPL";
