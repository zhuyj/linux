/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <bpf/bpf_endian.h>

typedef unsigned int u32;
typedef long long s64;

/* Declare the external kfunc */
//extern int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz) __ksym;

extern int bpf_set_cqe(int cqe) __ksym;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/rxe_create_qp")
int BPF_KPROBE(rxe_create_qp, struct ib_qp *ibqp, struct ib_qp_init_attr *init) {
	const u32 src_qpn = BPF_CORE_READ(init, source_qpn);
	const int send_cqe = BPF_CORE_READ(init, send_cq, cqe);
	const int recv_cqe = BPF_CORE_READ(init, recv_cq, cqe);

	bpf_set_cqe(send_cqe * 2);
        bpf_printk("%s +%d func: %s, src_qpn: %d, send_cqe: %d, recv_cqe: %d\n",
			__FILE__, __LINE__, __func__,
			src_qpn, send_cqe, recv_cqe);

        return 0;
}

struct rxe_bth {
	__u8	opcode;
	__u8	flags;
	__be16	pkey;
	__be32	qpn;
	__be32	apsn;
};

static inline u8 __bth_opcode(void *arg) {
	struct rxe_bth *bth = arg;

	return BPF_CORE_READ(bth, opcode);
}

static inline u8 bth_opcode(struct rxe_bth *bth) {
	return __bth_opcode(bth);
}

static inline u8 bth_flags(struct rxe_bth *bth) {
	return BPF_CORE_READ(bth, flags);
}

static inline u16 __bth_pkey(void *arg) {
	struct rxe_bth *bth = arg;

	return bpf_ntohs(BPF_CORE_READ(bth, pkey));
}

static inline u16 bth_pkey(struct rxe_bth *bth) {
	return __bth_pkey(bth);
}

#define BTH_QPN_MASK	(0x00ffffff)
#define BTH_PSN_MASK	((1 << 24) - 1)

static inline u32 __bth_qpn(void *arg) {
	struct rxe_bth *bth = arg;

	return BTH_QPN_MASK & bpf_ntohl(BPF_CORE_READ(bth, qpn));
}

static inline u32 bth_qpn(struct rxe_bth *bth) {
	return __bth_qpn(bth);
}

static inline u32 __bth_psn(void *arg) {
	struct rxe_bth *bth = arg;

	return BTH_PSN_MASK & bpf_ntohl(BPF_CORE_READ(bth, apsn));
}

static inline u32 bth_psn(struct rxe_bth *bth) {
	return __bth_psn(bth);
}

static inline void print_bth(struct rxe_bth *bth) {
	bpf_printk("struct rxe_bth {");
	bpf_printk("\t__u8            opcode; 0x%x", bth_opcode(bth));
	bpf_printk("\t__u8            flags;  0x%x", bth_flags(bth));
	bpf_printk("\t__be16          pkey;   0x%x", bth_pkey(bth));
	bpf_printk("\t__be32          qpn;    0x%x", bth_qpn(bth));
	bpf_printk("\t__be32          apsn;   0x%x", bth_psn(bth));
	bpf_printk("};\n");
}

SEC("kprobe/rxe_rcv")
int BPF_KPROBE(rxe_rcv, struct sk_buff *skb) {
	u32 len = BPF_CORE_READ(skb, len);
	struct rxe_bth *bth;

	bth = (struct rxe_bth *)BPF_CORE_READ(skb, data);
	print_bth(bth);
        return 0;
}
