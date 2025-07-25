/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <bpf/bpf_endian.h>
#include <string.h>
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

enum rxe_hdr_type {
	RXE_LRH,
	RXE_GRH,
	RXE_BTH,
	RXE_RETH,
	RXE_AETH,
	RXE_ATMETH,
	RXE_ATMACK,
	RXE_IETH,
	RXE_RDETH,
	RXE_DETH,
	RXE_IMMDT,
	RXE_PAYLOAD,
	NUM_HDR_TYPES
};

struct rxe_bth {
	__u8	opcode;
	__u8	flags;
	__be16	pkey;
	__be32	qpn;
	__be32	apsn;
};

struct rxe_immdt {
	__be32	imm;
};

struct rxe_reth {
	__be64	va;
	__be32	rkey;
	__be32	len;
};

struct rxe_aeth {
	__be32	smsn;
};

/******************************************************************************
 * Atomic Ack Extended Transport Header
 ******************************************************************************/
struct rxe_atmack {
	__be64	orig;
};

/******************************************************************************
 * Invalidate Extended Transport Header
 ******************************************************************************/
struct rxe_ieth {
	__be32	rkey;
};

/******************************************************************************
 * Datagram Extended Transport Header
 ******************************************************************************/
struct rxe_deth {
	__be32	qkey;
	__be32	sqp;
};

#define IB_OPCODE(transport, op) \
	IB_OPCODE_ ## transport ## _ ## op = \
	IB_OPCODE_ ## transport + IB_OPCODE_ ## op

enum {
	/* transport types -- just used to define real constants */
	IB_OPCODE_RC                                = 0x00,
	IB_OPCODE_UC                                = 0x20,
	IB_OPCODE_RD                                = 0x40,
	IB_OPCODE_UD                                = 0x60,
	/* per IBTA 1.3 vol 1 Table 38, A10.3.2 */
	IB_OPCODE_CNP                               = 0x80,
	/* Manufacturer specific */
	IB_OPCODE_MSP                               = 0xe0,

	/* operations -- just used to define real constants */
	IB_OPCODE_SEND_FIRST                        = 0x00,
	IB_OPCODE_SEND_MIDDLE                       = 0x01,
	IB_OPCODE_SEND_LAST                         = 0x02,
	IB_OPCODE_SEND_LAST_WITH_IMMEDIATE          = 0x03,
	IB_OPCODE_SEND_ONLY                         = 0x04,
	IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE          = 0x05,
	IB_OPCODE_RDMA_WRITE_FIRST                  = 0x06,
	IB_OPCODE_RDMA_WRITE_MIDDLE                 = 0x07,
	IB_OPCODE_RDMA_WRITE_LAST                   = 0x08,
	IB_OPCODE_RDMA_WRITE_LAST_WITH_IMMEDIATE    = 0x09,
	IB_OPCODE_RDMA_WRITE_ONLY                   = 0x0a,
	IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE    = 0x0b,
	IB_OPCODE_RDMA_READ_REQUEST                 = 0x0c,
	IB_OPCODE_RDMA_READ_RESPONSE_FIRST          = 0x0d,
	IB_OPCODE_RDMA_READ_RESPONSE_MIDDLE         = 0x0e,
	IB_OPCODE_RDMA_READ_RESPONSE_LAST           = 0x0f,
	IB_OPCODE_RDMA_READ_RESPONSE_ONLY           = 0x10,
	IB_OPCODE_ACKNOWLEDGE                       = 0x11,
	IB_OPCODE_ATOMIC_ACKNOWLEDGE                = 0x12,
	IB_OPCODE_COMPARE_SWAP                      = 0x13,
	IB_OPCODE_FETCH_ADD                         = 0x14,
	/* opcode 0x15 is reserved */
	IB_OPCODE_SEND_LAST_WITH_INVALIDATE         = 0x16,
	IB_OPCODE_SEND_ONLY_WITH_INVALIDATE         = 0x17,

	/* real constants follow -- see comment about above IB_OPCODE()
	   macro for more details */
	/* RC */
	IB_OPCODE(RC, SEND_FIRST),
	IB_OPCODE(RC, SEND_MIDDLE),
	IB_OPCODE(RC, SEND_LAST),
	IB_OPCODE(RC, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RC, SEND_ONLY),
	IB_OPCODE(RC, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_WRITE_FIRST),
	IB_OPCODE(RC, RDMA_WRITE_MIDDLE),
	IB_OPCODE(RC, RDMA_WRITE_LAST),
	IB_OPCODE(RC, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_WRITE_ONLY),
	IB_OPCODE(RC, RDMA_WRITE_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_READ_REQUEST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_FIRST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_MIDDLE),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_LAST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_ONLY),
	IB_OPCODE(RC, ACKNOWLEDGE),
	IB_OPCODE(RC, ATOMIC_ACKNOWLEDGE),
	IB_OPCODE(RC, COMPARE_SWAP),
	IB_OPCODE(RC, FETCH_ADD),
	IB_OPCODE(RC, SEND_LAST_WITH_INVALIDATE),
	IB_OPCODE(RC, SEND_ONLY_WITH_INVALIDATE),

	/* UC */
	IB_OPCODE(UC, SEND_FIRST),
	IB_OPCODE(UC, SEND_MIDDLE),
	IB_OPCODE(UC, SEND_LAST),
	IB_OPCODE(UC, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(UC, SEND_ONLY),
	IB_OPCODE(UC, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(UC, RDMA_WRITE_FIRST),
	IB_OPCODE(UC, RDMA_WRITE_MIDDLE),
	IB_OPCODE(UC, RDMA_WRITE_LAST),
	IB_OPCODE(UC, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(UC, RDMA_WRITE_ONLY),
	IB_OPCODE(UC, RDMA_WRITE_ONLY_WITH_IMMEDIATE),

	/* RD */
	IB_OPCODE(RD, SEND_FIRST),
	IB_OPCODE(RD, SEND_MIDDLE),
	IB_OPCODE(RD, SEND_LAST),
	IB_OPCODE(RD, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RD, SEND_ONLY),
	IB_OPCODE(RD, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_WRITE_FIRST),
	IB_OPCODE(RD, RDMA_WRITE_MIDDLE),
	IB_OPCODE(RD, RDMA_WRITE_LAST),
	IB_OPCODE(RD, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_WRITE_ONLY),
	IB_OPCODE(RD, RDMA_WRITE_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_READ_REQUEST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_FIRST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_MIDDLE),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_LAST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_ONLY),
	IB_OPCODE(RD, ACKNOWLEDGE),
	IB_OPCODE(RD, ATOMIC_ACKNOWLEDGE),
	IB_OPCODE(RD, COMPARE_SWAP),
	IB_OPCODE(RD, FETCH_ADD),

	/* UD */
	IB_OPCODE(UD, SEND_ONLY),
	IB_OPCODE(UD, SEND_ONLY_WITH_IMMEDIATE)
};

struct rxe_opcode_info {
	char	*name;
	int	length;
	int	offset[NUM_HDR_TYPES];
};

/******************************************************************************
 * Atomic Extended Transport Header
 ******************************************************************************/
struct rxe_atmeth {
	__be64		va;
	__be32		rkey;
	__be64		swap_add;
	__be64		comp;
};

/******************************************************************************
 * Reliable Datagram Extended Transport Header
 ******************************************************************************/
struct rxe_rdeth {
	__be32		een;
};

enum rxe_hdr_length {
	RXE_BTH_BYTES       = sizeof(struct rxe_bth),
	RXE_DETH_BYTES      = sizeof(struct rxe_deth),
	RXE_IMMDT_BYTES     = sizeof(struct rxe_immdt),
	RXE_RETH_BYTES      = sizeof(struct rxe_reth),
	RXE_AETH_BYTES      = sizeof(struct rxe_aeth),
	RXE_ATMACK_BYTES    = sizeof(struct rxe_atmack),
	RXE_ATMETH_BYTES    = sizeof(struct rxe_atmeth),
	RXE_IETH_BYTES      = sizeof(struct rxe_ieth),
	RXE_RDETH_BYTES     = sizeof(struct rxe_rdeth),
};
#if 0
struct data_t {
	struct rxe_opcode_info rxe_opcode[128];
};
#endif
#define	RXE_NUM_OPCODE		128
struct data_t {
struct rxe_opcode_info rxe_opcode[RXE_NUM_OPCODE];
#if 0
    [IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY]      = {
        .name   = "IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY",
        .length = RXE_BTH_BYTES + RXE_AETH_BYTES,
        .offset = {
            [RXE_BTH]   = 0,
            [RXE_AETH]  = RXE_BTH_BYTES,
            [RXE_PAYLOAD]   = RXE_BTH_BYTES +
                      RXE_AETH_BYTES,
        }
    },
    [IB_OPCODE_RC_ACKNOWLEDGE]          = {
        .name   = "IB_OPCODE_RC_ACKNOWLEDGE",
        .length = RXE_BTH_BYTES + RXE_AETH_BYTES,
        .offset = {
            [RXE_BTH]   = 0,
            [RXE_AETH]  = RXE_BTH_BYTES,
            [RXE_PAYLOAD]   = RXE_BTH_BYTES +
                      RXE_AETH_BYTES,
        }
    },
}
#endif
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
#if 0
static inline void print_reth(struct rxe_reth *reth)
{
	bpf_printk("struct rxe_reth {\n");
	bpf_printk("\t__be64        va;\n");
	bpf_printk("\t__be32        rkey;\n");
	bpf_printk("\t__be32        len;\n");
	bpf_printk("};\n");
}

#define AETH_MSN_MASK       (0x00ffffff)

static inline u32 aeth_msn(struct rxe_aeth *aeth)
{
	return AETH_MSN_MASK & bpf_ntohl(BPF_CORE_READ(aeth, smsn));
}

static inline void print_aeth(struct rxe_aeth *aeth)
{
	bpf_printk("struct rxe_aeth {\n");
	bpf_printk("\t___be32       smsn; 0x%x\n", aeth_msn(aeth));
	bpf_printk("};\n");
}
#endif
#if 0
static inline u64 atmeth_va(struct rxe_atmeth *atmeth)
{
    return bpf_ntohl(BPF_CORE_READ(atmeth, va));
}

static inline u32 atmeth_rkey(struct rxe_atmeth *atmeth)
{
    return bpf_ntohl(BPF_CORE_READ(atmeth, rkey));
}

static inline u64 atmeth_swap_add(struct rxe_atmeth *atmeth)
{
    return bpf_ntohl(BPF_CORE_READ(atmeth, swap_add));
}

static inline u64 atmeth_comp(struct rxe_atmeth *atmeth)
{
    return bpf_ntohl(BPF_CORE_READ(atmeth, comp));
}

static inline void print_atmeth(struct rxe_atmeth *atmeth)
{
    bpf_printk("struct rxe_atmeth {\n");
    bpf_printk("\t__be64        va;       0x%llx\n", atmeth_va(atmeth));
    bpf_printk("\t__be32        rkey;     0x%x\n", atmeth_rkey(atmeth));
    bpf_printk("\t__be64        swap_add; 0x%llx\n", atmeth_swap_add(atmeth));
    bpf_printk("\t__be64        comp;     0x%llx\n", atmeth_comp(atmeth));
    bpf_printk("} __packed;\n");
}

static inline u64 atmack_orig(struct rxe_atmack *atmack)
{
    return bpf_ntohl(BPF_CORE_READ(atmack, orig));
}

static inline void print_atmack(struct rxe_atmack *atmack)
{
    bpf_printk("struct rxe_atmack {\n");
    bpf_printk("\t__be64        orig; 0x%llx\n", atmack_orig(atmack));
    bpf_printk("};\n");
}

static inline u32 ieth_rkey(struct rxe_ieth *ieth)
{
    return bpf_ntohl(BPF_CORE_READ(ieth, rkey));
}

static inline void print_ieth(struct rxe_ieth *ieth)
{
    bpf_printk("struct rxe_ieth {\n");
    bpf_printk("\t__be32        rkey; 0x%x\n", ieth_rkey(ieth));
    bpf_printk("};\n");
}

#define RDETH_EEN_MASK      (0x00ffffff)
#if 0
static inline u32 rdeth_een(struct rxe_rdeth *rdeth)
{
    return RDETH_EEN_MASK & bpf_ntohl(BPF_CORE_READ(rdeth, een));
}

static inline void print_rdeth(struct rxe_rdeth *rdeth)
{
    bpf_printk("struct rxe_rdeth {\n");
    bpf_printk("\t__be32        een; 0x%x\n", rdeth_een(rdeth));
    bpf_printk("};\n");
}
#endif
#endif
#define DETH_SQP_MASK       (0x00ffffff)
#if 0
static inline u32 deth_qkey(struct rxe_deth *deth)
{
    return bpf_ntohl(BPF_CORE_READ(deth, qkey));
}

static inline u32 deth_sqp(struct rxe_deth *deth)
{
    return DETH_SQP_MASK & bpf_ntohl(BPF_CORE_READ(deth, sqp));
}

static inline void print_deth(struct rxe_deth *deth)
{
    bpf_printk("struct rxe_deth {\n");
    bpf_printk("\t__be32    qkey; 0x%x\n", deth_qkey(deth));
    bpf_printk("\t__be32    sqp;  0x%x\n", deth_sqp(deth));
    bpf_printk("};\n");
}
#endif
#if 0
static inline __be32 immdt_imm(struct rxe_immdt *immdt)
{
    return immdt->imm;
}

static inline void print_immdt(struct rxe_immdt *immdt)
{
    bpf_printk("struct rxe_immdt {\n");
    bpf_printk("\t__be32        imm; 0x%x\n", immdt_imm(immdt));
    bpf_printk("};\n");
}
#endif
SEC("kprobe/rxe_rcv")
int BPF_KPROBE(rxe_rcv, struct sk_buff *skb) {
	struct data_t d;

	d.rxe_opcode[IB_OPCODE_RC_SEND_ONLY].name   = "IB_OPCODE_RC_SEND_ONLY";
	d.rxe_opcode[IB_OPCODE_RC_SEND_ONLY].length = RXE_BTH_BYTES;
//	d.rxe_opcode[IB_OPCODE_RC_SEND_ONLY].offset[RXE_BTH]   = 0;
//	d.rxe_opcode[IB_OPCODE_RC_SEND_ONLY].offset[RXE_PAYLOAD]   = RXE_BTH_BYTES;

	d.rxe_opcode[IB_OPCODE_RC_RDMA_WRITE_ONLY].name   = "IB_OPCODE_RC_RDMA_WRITE_ONLY";
	d.rxe_opcode[IB_OPCODE_RC_RDMA_WRITE_ONLY].length = RXE_BTH_BYTES + RXE_RETH_BYTES;
//	d.rxe_opcode[IB_OPCODE_RC_RDMA_WRITE_ONLY].offset[RXE_BTH]   = 0;
	d.rxe_opcode[IB_OPCODE_RC_RDMA_WRITE_ONLY].offset[RXE_RETH]  = RXE_BTH_BYTES;
//	d.rxe_opcode[IB_OPCODE_RC_RDMA_WRITE_ONLY].offset[RXE_PAYLOAD]   = RXE_BTH_BYTES + RXE_RETH_BYTES;

	d.rxe_opcode[IB_OPCODE_RC_RDMA_READ_REQUEST].name   = "IB_OPCODE_RC_RDMA_READ_REQUEST";
	d.rxe_opcode[IB_OPCODE_RC_RDMA_READ_REQUEST].length = RXE_BTH_BYTES + RXE_RETH_BYTES;
//	d.rxe_opcode[IB_OPCODE_RC_RDMA_READ_REQUEST].offset[RXE_BTH]   = 0;
	d.rxe_opcode[IB_OPCODE_RC_RDMA_READ_REQUEST].offset[RXE_RETH]  = RXE_BTH_BYTES;
//	d.rxe_opcode[IB_OPCODE_RC_RDMA_READ_REQUEST].offset[RXE_PAYLOAD]   = RXE_BTH_BYTES + RXE_RETH_BYTES;

	d.rxe_opcode[IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY].name   = "IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY";
	d.rxe_opcode[IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY].length = RXE_BTH_BYTES + RXE_AETH_BYTES;
//	d.rxe_opcode[IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY].offset[RXE_BTH]   = 0;
	d.rxe_opcode[IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY].offset[RXE_AETH]  = RXE_BTH_BYTES;
//	d.rxe_opcode[IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY].offset[RXE_PAYLOAD]   = RXE_BTH_BYTES + RXE_AETH_BYTES;

	d.rxe_opcode[IB_OPCODE_RC_ACKNOWLEDGE].name   = "IB_OPCODE_RC_ACKNOWLEDGE";
	d.rxe_opcode[IB_OPCODE_RC_ACKNOWLEDGE].length = RXE_BTH_BYTES + RXE_AETH_BYTES;
//	d.rxe_opcode[IB_OPCODE_RC_ACKNOWLEDGE].offset[RXE_BTH]   = 0;
	d.rxe_opcode[IB_OPCODE_RC_ACKNOWLEDGE].offset[RXE_AETH]  = RXE_BTH_BYTES;
//	d.rxe_opcode[IB_OPCODE_RC_ACKNOWLEDGE].offset[RXE_PAYLOAD]   = RXE_BTH_BYTES + RXE_AETH_BYTES;

	d.rxe_opcode[IB_OPCODE_UD_SEND_ONLY].name   = "IB_OPCODE_UD_SEND_ONLY";
	d.rxe_opcode[IB_OPCODE_UD_SEND_ONLY].length = RXE_BTH_BYTES + RXE_DETH_BYTES;
//	d.rxe_opcode[IB_OPCODE_UD_SEND_ONLY].offset[RXE_BTH]       = 0;
	d.rxe_opcode[IB_OPCODE_UD_SEND_ONLY].offset[RXE_DETH]      = RXE_BTH_BYTES;
//	d.rxe_opcode[IB_OPCODE_UD_SEND_ONLY].offset[RXE_PAYLOAD]   = RXE_BTH_BYTES + RXE_DETH_BYTES;

	struct rxe_bth *bth;

	bth = (struct rxe_bth *)BPF_CORE_READ(skb, data);
	print_bth(bth);
#if 0
	if (d.rxe_opcode[bth->opcode].offset[RXE_DETH]) {
		bpf_printk("RXE_RDETH\n");
		char *cur_p = (char *)bth + d.rxe_opcode[bth->opcode].offset[RXE_DETH];
		struct rxe_deth *deth = (struct rxe_deth *)cur_p;
		print_deth(deth);
	}
	if (d.rxe_opcode[bth->opcode].offset[RXE_AETH]) {
		bpf_printk("RXE_AETH\n");
		char *cur_p = (char *)bth + d.rxe_opcode[bth->opcode].offset[RXE_AETH];
		struct rxe_aeth *aeth = (struct rxe_aeth*)cur_p;
		print_aeth(aeth);
	}
	if (d.rxe_opcode[bth->opcode].offset[RXE_RETH]) {
		bpf_printk("RXE_RETH\n");
		char *cur_p = (char *)bth + d.rxe_opcode[bth->opcode].offset[RXE_RETH];
		struct rxe_reth *reth = (struct rxe_reth *)cur_p;
		print_reth(reth);
	}
#endif
#if 0
	for (int i=RXE_BTH+1; i<NUM_HDR_TYPES; i++) {
		int offset = d.rxe_opcode[bth->opcode].offset[i];
		if (offset) {
			char *cur_p = (char *)bth + offset;
			switch(i) {
			case    RXE_RETH:
				bpf_printk("RXE_RETH\n");
				struct rxe_reth *reth = (struct rxe_reth *)cur_p;
				print_reth(reth);
				break;

			case    RXE_AETH:
				bpf_printk("RXE_AETH\n");
				struct rxe_aeth *aeth = (struct rxe_aeth*)cur_p;
				print_aeth(aeth);
				break;
#if 0
			case    RXE_ATMETH:
				bpf_printk("RXE_ATMETH\n");
				struct rxe_atmeth *atmeth = (struct rxe_atmeth *)cur_p;
				print_atmeth(atmeth);
				break;

			case    RXE_ATMACK:
				bpf_printk("RXE_ATMACK\n");
				struct rxe_atmack *atmack = (struct rxe_atmack *)cur_p;
				print_atmack(atmack);
				break;

			case    RXE_IETH:
				bpf_printk("RXE_IETH\n");
				struct rxe_ieth *ieth = (struct rxe_ieth *)cur_p;
				print_ieth(ieth);
				break;

			case    RXE_RDETH:
				bpf_printk("RXE_RDETH\n");
				struct rxe_rdeth *rdeth = (struct rxe_rdeth *)cur_p;
				print_rdeth(rdeth);
				break;
#endif
			case    RXE_DETH:
				bpf_printk("RXE_DETH\n");
				struct rxe_deth *deth = (struct rxe_deth *)cur_p;
				print_deth(deth);
				break;
#if 0
			case    RXE_IMMDT:
				bpf_printk("RXE_IMMDT\n");
				struct rxe_immdt *immdt = (struct rxe_immdt *)cur_p;
				print_immdt(immdt);
				break;
			case    RXE_PAYLOAD:
				bpf_printk("RXE_PAYLOAD\n");
				int len = bpf_ntohs(udp_hdr->len) - d.rxe_opcode[bth->opcode].length;
				for (int j=0; j<len; j++) {
					if (isprint(cur_p[j])) {
						bpf_printk("%c", cur_p[j]);
					} else {
						bpf_printk("%02x", cur_p[j]);
					}
				}

				bpf_printk("\n");
				break;
#endif
			default:
				break;
			}
		}
	}
#endif
        return 0;
}
