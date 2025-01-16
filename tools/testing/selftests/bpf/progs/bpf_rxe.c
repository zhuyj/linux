/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef unsigned int u32;
typedef long long s64;
typedef int pid_t;

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
