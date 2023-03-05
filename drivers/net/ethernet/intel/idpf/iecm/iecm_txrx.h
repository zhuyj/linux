/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019 Intel Corporation */

#ifndef _IECM_TXRX_H_
#define _IECM_TXRX_H_

#include "virtchnl_lan_desc.h"
#ifdef HAVE_INDIRECT_CALL_WRAPPER_HEADER
#include <linux/indirect_call_wrapper.h>
#endif

#define IECM_LARGE_MAX_Q			256
#define IECM_MAX_Q				16
/* Mailbox Queue */
#define IECM_MAX_NONQ				1
#define IECM_MAX_TXQ_DESC			8160
#define IECM_MAX_RXQ_DESC			8160
#define IECM_MIN_TXQ_DESC			64
#define IECM_MIN_RXQ_DESC			64
#define IECM_MIN_TXQ_COMPLQ_DESC		64
#define IECM_REQ_DESC_MULTIPLE			32
#define IECM_MIN_TX_DESC_NEEDED (MAX_SKB_FRAGS + 6)
#define IECM_TX_WAKE_THRESH ((s16)IECM_MIN_TX_DESC_NEEDED * 2)

#define IECM_DFLT_SINGLEQ_TX_Q_GROUPS		1
#define IECM_DFLT_SINGLEQ_RX_Q_GROUPS		1
#define IECM_DFLT_SINGLEQ_TXQ_PER_GROUP		4
#define IECM_DFLT_SINGLEQ_RXQ_PER_GROUP		4

#define IECM_COMPLQ_PER_GROUP			1
#define IECM_MAX_BUFQS_PER_RXQ_GRP		2

#define IECM_DFLT_SPLITQ_TX_Q_GROUPS		4
#define IECM_DFLT_SPLITQ_RX_Q_GROUPS		4
#define IECM_DFLT_SPLITQ_TXQ_PER_GROUP		1
#define IECM_DFLT_SPLITQ_RXQ_PER_GROUP		1

/* Default vector sharing */
#define IECM_NONQ_VEC		1
#define IECM_MAX_Q_VEC		4 /* For Tx Completion queue and Rx queue */
#define IECM_MIN_Q_VEC		1
#define IECM_MAX_RDMA_VEC	2 /* To share with RDMA */
#define IECM_MIN_RDMA_VEC	1 /* Minimum vectors to be shared with RDMA */
#define IECM_MIN_VEC		3 /* One for mailbox, one for data queues, one
				   * for RDMA
				   */

#define IECM_DFLT_TX_Q_DESC_COUNT		512
#define IECM_DFLT_TX_COMPLQ_DESC_COUNT		512
#define IECM_DFLT_RX_Q_DESC_COUNT		512
/* IMPORTANT: We absolutely _cannot_ have more buffers in the system than a
 * given RX completion queue has descriptors. This includes _ALL_ buffer
 * queues. E.g.: If you have two buffer queues of 512 descriptors and buffers,
 * you have a total of 1024 buffers so your RX queue _must_ have at least that
 * many descriptors. This macro divides a given number of RX descriptors by
 * number of buffer queues to calculate how many descriptors each buffer queue
 * can have without overrunning the RX queue.
 *
 * If you give hardware more buffers than completion descriptors what will
 * happen is that if hardware gets a chance to post more than ring wrap of
 * descriptors before SW gets an interrupt and overwrites SW head, the gen bit
 * in the descriptor will be wrong. Any overwritten descriptors' buffers will
 * be gone forever and SW has no reasonable way to tell that this has happened.
 * From SW perspective, when we finally get an interrupt, it looks like we're
 * still waiting for descriptor to be done, stalling forever.
 */
#define IECM_RX_BUFQ_DESC_COUNT(RXD, NUM_BUFQ)	((RXD) / (NUM_BUFQ))

#define IECM_RX_BUFQ_WORKING_SET(R)		((R)->desc_count - 1)
#define IECM_RX_BUFQ_NON_WORKING_SET(R)		((R)->desc_count - \
						 IECM_RX_BUFQ_WORKING_SET(R))

#define IECM_RX_HDR_SIZE			256
#define IECM_RX_BUF_2048			2048
#define IECM_RX_BUF_4096			4096
#define IECM_RX_BUF_STRIDE			64
#define IECM_LOW_WATERMARK			64
#define IECM_HDR_BUF_SIZE			256
#define IECM_PACKET_HDR_PAD	\
	(ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))
#define IECM_MAX_RXBUFFER			9728
#define IECM_MAX_MTU		\
	(IECM_MAX_RXBUFFER - IECM_PACKET_HDR_PAD)
#define IECM_TX_TSO_MIN_MSS		88

#define IECM_RX_BI_BUFID_S		0
#define IECM_RX_BI_BUFID_M		MAKEMASK(0x7FFF, IECM_RX_BI_BUFID_S)
#define IECM_RX_BI_GEN_S		15
#define IECM_RX_BI_GEN_M		BIT(IECM_RX_BI_GEN_S)

#define IECM_SINGLEQ_RX_BUF_DESC(R, i)	\
	(&(((struct virtchnl2_singleq_rx_buf_desc *)((R)->desc_ring))[i]))
#define IECM_SPLITQ_RX_BUF_DESC(R, i)	\
	(&(((struct virtchnl2_splitq_rx_buf_desc *)((R)->desc_ring))[i]))
#define IECM_SPLITQ_RX_BI_DESC(R, i)	\
	(&(((u16 *)((R)->ring))[i]))

#define IECM_BASE_TX_DESC(R, i)	\
	(&(((struct iecm_base_tx_desc *)((R)->desc_ring))[i]))
#define IECM_BASE_TX_CTX_DESC(R, i) \
	(&(((struct iecm_base_tx_ctx_desc *)((R)->desc_ring))[i]))
#define IECM_SPLITQ_TX_COMPLQ_DESC(R, i)	\
	(&(((struct iecm_splitq_tx_compl_desc *)((R)->desc_ring))[i]))

#define IECM_FLEX_TX_DESC(R, i)	\
	(&(((union iecm_tx_flex_desc *)((R)->desc_ring))[i]))
#define IECM_FLEX_TX_CTX_DESC(R, i)	\
	(&(((union iecm_flex_tx_ctx_desc *)((R)->desc_ring))[i]))

#define IECM_DESC_UNUSED(R)	\
	((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->desc_count) + \
	(R)->next_to_clean - (R)->next_to_use - 1)

#define IECM_TX_BUF_UNUSED(R)	((R)->buf_stack.top)

/* The TX completion queue needs to maintain a cache line sized free space
 * to avoid potentially overwriting a cache line that hasn't been read by
 * SW yet. In this case, that is 16 entries.
 */
#define IECM_TX_COMPLQ_OVERFLOW_THRESH(R)	((R)->desc_count >> 1)
#define IECM_TX_COMPLQ_PENDING(R)	\
	(((R)->num_completions_pending >= (R)->complq->num_completions ? \
	0 : U64_MAX) + \
	(R)->num_completions_pending - (R)->complq->num_completions)

#define IECM_TXD_LAST_DESC_CMD (IECM_TX_DESC_CMD_EOP | IECM_TX_DESC_CMD_RS)

#define MAKEMASK(m, s)	((m) << (s))

#ifdef HAVE_XDP_SUPPORT
#define IECM_XDP_PASS		0
#define IECM_XDP_CONSUMED	BIT(0)
#define IECM_XDP_TX		BIT(1)
#define IECM_XDP_REDIR		BIT(2)
#endif /* HAVE_XDP_SUPPORT */

union iecm_tx_flex_desc {
	struct iecm_flex_tx_desc q; /* queue based scheduling */
	struct iecm_flex_tx_sched_desc flow; /* flow based scheudling */
};

struct iecm_tx_buf {
	struct hlist_node hlist;
	void *next_to_watch;
	union {
		struct sk_buff *skb;
#ifdef HAVE_XDP_FRAME_STRUCT
		struct xdp_frame *xdpf;
#else
		void *raw_buf;
#endif
	};
	unsigned int bytecount;
	unsigned short gso_segs;
#define IECM_TX_FLAGS_TSO			BIT(0)
#define IECM_TX_FLAGS_VLAN_TAG			BIT(1)
#define IECM_TX_FLAGS_HW_VLAN			BIT(2)
#define IECM_TX_FLAGS_HW_OUTER_SINGLE_VLAN	BIT(3)
#define IECM_TX_FLAGS_VLAN_SHIFT		16
#define IECM_TX_FLAGS_VLAN_MASK			0xFFFF0000
	u32 tx_flags;
	DEFINE_DMA_UNMAP_ADDR(dma);
	DEFINE_DMA_UNMAP_LEN(len);
	u16 compl_tag;		/* Unique identifier for buffer; used to
				 * compare with completion tag returned
				 * in buffer completion event
				 */
};

struct iecm_buf_lifo {
	u16 top;
	u16 size;
	struct iecm_tx_buf **bufs;
};

struct iecm_tx_offload_params {
	u16 td_cmd;	/* command field to be inserted into descriptor */
	u32 tso_len;	/* total length of payload to segment */
	u16 mss;
	u8 tso_hdr_len;	/* length of headers to be duplicated */

	/* Flow scheduling offload timestamp, formatting as hw expects it */
	/* timestamp = bits[0:22], overflow = bit[23] */
	u8 desc_ts[3];

	/* For legacy offloads */
	u32 hdr_offsets;
};

struct iecm_tx_splitq_params {
	/* Descriptor build function pointer */
	void (*splitq_build_ctb)(union iecm_tx_flex_desc *desc,
				 struct iecm_tx_splitq_params *params,
				 u16 td_cmd, u16 size);

	/* General descriptor info */
	enum iecm_tx_desc_dtype_value dtype;
	u16 eop_cmd;
	union {
		u16 compl_tag; /* only relevant for flow scheduling */
		u16 td_tag; /* only relevant for queue scheduling */
	};

	struct iecm_tx_offload_params offload;
};

/*
 * iecm_rx_csum_decoded
 *
 * Checksum offload bits decoded from the receive descriptor.
 */
struct iecm_rx_csum_decoded {
	u8 l3l4p : 1;
	u8 ipe : 1;
	u8 eipe : 1;
	u8 eudpe : 1;
	u8 ipv6exadd : 1;
	u8 l4e : 1;
	u8 pprs : 1;
	u8 nat : 1;
	u8 rsc : 1;
	u8 raw_csum_inv : 1;
	u16 raw_csum;
};

struct iecm_rx_extracted {
	unsigned int size;
	u16 vlan_tag;
	u16 rx_ptype;
};

#define IECM_TX_COMPLQ_CLEAN_BUDGET	256
#define IECM_TX_MIN_LEN			17
#define IECM_TX_DESCS_FOR_SKB_DATA_PTR	1
#define IECM_TX_MAX_BUF			8
#define IECM_TX_DESCS_PER_CACHE_LINE	4
#define IECM_TX_DESCS_FOR_CTX		1
/* TX descriptors needed, worst case */
#define IECM_TX_DESC_NEEDED (MAX_SKB_FRAGS + IECM_TX_DESCS_FOR_CTX + \
			     IECM_TX_DESCS_PER_CACHE_LINE + \
			     IECM_TX_DESCS_FOR_SKB_DATA_PTR)

/* The size limit for a transmit buffer in a descriptor is (16K - 1).
 * In order to align with the read requests we will align the value to
 * the nearest 4K which represents our maximum read request size.
 */
#define IECM_TX_MAX_READ_REQ_SIZE	4096
#define IECM_TX_MAX_DESC_DATA		(16 * 1024 - 1)
#define IECM_TX_MAX_DESC_DATA_ALIGNED \
	(~(IECM_TX_MAX_READ_REQ_SIZE - 1) & IECM_TX_MAX_DESC_DATA)

#define IECM_RX_DMA_ATTR \
	(DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)
#define IECM_RX_DESC(R, i)	\
	(&(((union virtchnl2_rx_desc *)((R)->desc_ring))[i]))

struct iecm_page_info {
	dma_addr_t dma;
	struct page *page;
	unsigned int page_offset;
	u16 pagecnt_bias;
};

struct iecm_rx_hdr_buf_pages {
	u32 nr_pages;
	struct iecm_page_info *pages;
};

struct iecm_rx_buf {
#define IECM_RX_BUF_MAX_PAGES 2
	struct iecm_page_info page_info[IECM_RX_BUF_MAX_PAGES];
	u8 page_indx;
	u16 buf_id;
	u16 buf_size;
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	union {
		struct sk_buff *skb;
		struct xdp_buff *xdp;
	};
#else
	struct sk_buff *skb;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
};

/* Packet type non-ip values */
enum iecm_rx_ptype_l2 {
	IECM_RX_PTYPE_L2_RESERVED	= 0,
	IECM_RX_PTYPE_L2_MAC_PAY2	= 1,
	IECM_RX_PTYPE_L2_TIMESYNC_PAY2	= 2,
	IECM_RX_PTYPE_L2_FIP_PAY2	= 3,
	IECM_RX_PTYPE_L2_OUI_PAY2	= 4,
	IECM_RX_PTYPE_L2_MACCNTRL_PAY2	= 5,
	IECM_RX_PTYPE_L2_LLDP_PAY2	= 6,
	IECM_RX_PTYPE_L2_ECP_PAY2	= 7,
	IECM_RX_PTYPE_L2_EVB_PAY2	= 8,
	IECM_RX_PTYPE_L2_QCN_PAY2	= 9,
	IECM_RX_PTYPE_L2_EAPOL_PAY2	= 10,
	IECM_RX_PTYPE_L2_ARP		= 11,
};

enum iecm_rx_ptype_outer_ip {
	IECM_RX_PTYPE_OUTER_L2	= 0,
	IECM_RX_PTYPE_OUTER_IP	= 1,
};

enum iecm_rx_ptype_outer_ip_ver {
	IECM_RX_PTYPE_OUTER_NONE	= 0,
	IECM_RX_PTYPE_OUTER_IPV4	= 1,
	IECM_RX_PTYPE_OUTER_IPV6	= 2,
};

enum iecm_rx_ptype_outer_fragmented {
	IECM_RX_PTYPE_NOT_FRAG	= 0,
	IECM_RX_PTYPE_FRAG	= 1,
};

enum iecm_rx_ptype_tunnel_type {
	IECM_RX_PTYPE_TUNNEL_NONE		= 0,
	IECM_RX_PTYPE_TUNNEL_IP_IP		= 1,
	IECM_RX_PTYPE_TUNNEL_IP_GRENAT		= 2,
	IECM_RX_PTYPE_TUNNEL_IP_GRENAT_MAC	= 3,
	IECM_RX_PTYPE_TUNNEL_IP_GRENAT_MAC_VLAN	= 4,
};

enum iecm_rx_ptype_tunnel_end_prot {
	IECM_RX_PTYPE_TUNNEL_END_NONE	= 0,
	IECM_RX_PTYPE_TUNNEL_END_IPV4	= 1,
	IECM_RX_PTYPE_TUNNEL_END_IPV6	= 2,
};

enum iecm_rx_ptype_inner_prot {
	IECM_RX_PTYPE_INNER_PROT_NONE		= 0,
	IECM_RX_PTYPE_INNER_PROT_UDP		= 1,
	IECM_RX_PTYPE_INNER_PROT_TCP		= 2,
	IECM_RX_PTYPE_INNER_PROT_SCTP		= 3,
	IECM_RX_PTYPE_INNER_PROT_ICMP		= 4,
	IECM_RX_PTYPE_INNER_PROT_TIMESYNC	= 5,
};

enum iecm_rx_ptype_payload_layer {
	IECM_RX_PTYPE_PAYLOAD_LAYER_NONE	= 0,
	IECM_RX_PTYPE_PAYLOAD_LAYER_PAY2	= 1,
	IECM_RX_PTYPE_PAYLOAD_LAYER_PAY3	= 2,
	IECM_RX_PTYPE_PAYLOAD_LAYER_PAY4	= 3,
};

struct iecm_rx_ptype_decoded {
	u32 ptype:10;
	u32 known:1;
	u32 outer_ip:1;
	u32 outer_ip_ver:2;
	u32 outer_frag:1;
	u32 tunnel_type:3;
	u32 tunnel_end_prot:2;
	u32 tunnel_end_frag:1;
	u32 inner_prot:4;
	u32 payload_layer:3;
};

enum iecm_rx_hsplit {
	IECM_RX_NO_HDR_SPLIT = 0,
	IECM_RX_HDR_SPLIT = 1,
	IECM_RX_HDR_SPLIT_PERF = 2,
};

/* The iecm_ptype_lkup table is used to convert from the 10-bit ptype in the
 * hardware to a bit-field that can be used by SW to more easily determine the
 * packet type.
 *
 * Macros are used to shorten the table lines and make this table human
 * readable.
 *
 * We store the PTYPE in the top byte of the bit field - this is just so that
 * we can check that the table doesn't have a row missing, as the index into
 * the table should be the PTYPE.
 *
 * Typical work flow:
 *
 * IF NOT iecm_ptype_lkup[ptype].known
 * THEN
 *      Packet is unknown
 * ELSE IF iecm_ptype_lkup[ptype].outer_ip == IECM_RX_PTYPE_OUTER_IP
 *      Use the rest of the fields to look at the tunnels, inner protocols, etc
 * ELSE
 *      Use the enum iecm_rx_ptype_l2 to decode the packet type
 * ENDIF
 */
/* macro to make the table lines short */
#define IECM_PTT(PTYPE, OUTER_IP, OUTER_IP_VER, OUTER_FRAG, T, TE, TEF, I, PL)\
	{	PTYPE, \
		1, \
		IECM_RX_PTYPE_OUTER_##OUTER_IP, \
		IECM_RX_PTYPE_OUTER_##OUTER_IP_VER, \
		IECM_RX_PTYPE_##OUTER_FRAG, \
		IECM_RX_PTYPE_TUNNEL_##T, \
		IECM_RX_PTYPE_TUNNEL_END_##TE, \
		IECM_RX_PTYPE_##TEF, \
		IECM_RX_PTYPE_INNER_PROT_##I, \
		IECM_RX_PTYPE_PAYLOAD_LAYER_##PL }

#define IECM_PTT_UNUSED_ENTRY(PTYPE) { PTYPE, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

/* shorter macros makes the table fit but are terse */
#define IECM_RX_PTYPE_NOF		IECM_RX_PTYPE_NOT_FRAG
#define IECM_RX_PTYPE_FRG		IECM_RX_PTYPE_FRAG
#define IECM_RX_PTYPE_INNER_PROT_TS	IECM_RX_PTYPE_INNER_PROT_TIMESYNC
#define IECM_RX_SUPP_PTYPE		18
#define IECM_RX_MAX_PTYPE		1024
#define IECM_RX_MAX_BASE_PTYPE		256

#define IECM_INT_NAME_STR_LEN	(IFNAMSIZ + 16)

/* Lookup table mapping the HW PTYPE to the bit field for decoding */
static const struct
iecm_rx_ptype_decoded iecm_ptype_lookup[IECM_RX_MAX_PTYPE] = {
	/* ptype indices are dynamic and package dependent. Indices represented
	 * in this lookup table are for reference and will be replaced by the
	 * values which CP sends. Also these values are static for older
	 * versions of virtchnl and if VIRTCHNL2_CAP_PTYPE is not set in
	 * virtchnl2_get_capabilities.
	 */
	/* L2 Packet types */
	IECM_PTT_UNUSED_ENTRY(0),
	IECM_PTT(1,  L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY2),
	IECM_PTT(2,  L2, NONE, NOF, NONE, NONE, NOF, TS,   PAY2),
	IECM_PTT(3,  L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY2),
	IECM_PTT_UNUSED_ENTRY(4),
	IECM_PTT_UNUSED_ENTRY(5),
	IECM_PTT(6,  L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY2),
	IECM_PTT(7,  L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY2),
	IECM_PTT_UNUSED_ENTRY(8),
	IECM_PTT_UNUSED_ENTRY(9),
	IECM_PTT(10, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY2),
	IECM_PTT(11, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),
	IECM_PTT(12, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(13, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(14, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(15, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(16, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(17, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(18, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(19, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(20, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(21, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY3),

	/* Non Tunneled IPv4 */
	IECM_PTT(22, IP, IPV4, FRG, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(23, IP, IPV4, NOF, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(24, IP, IPV4, NOF, NONE, NONE, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(25),
	IECM_PTT(26, IP, IPV4, NOF, NONE, NONE, NOF, TCP,  PAY4),
	IECM_PTT(27, IP, IPV4, NOF, NONE, NONE, NOF, SCTP, PAY4),
	IECM_PTT(28, IP, IPV4, NOF, NONE, NONE, NOF, ICMP, PAY4),

	/* IPv4 --> IPv4 */
	IECM_PTT(29, IP, IPV4, NOF, IP_IP, IPV4, FRG, NONE, PAY3),
	IECM_PTT(30, IP, IPV4, NOF, IP_IP, IPV4, NOF, NONE, PAY3),
	IECM_PTT(31, IP, IPV4, NOF, IP_IP, IPV4, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(32),
	IECM_PTT(33, IP, IPV4, NOF, IP_IP, IPV4, NOF, TCP,  PAY4),
	IECM_PTT(34, IP, IPV4, NOF, IP_IP, IPV4, NOF, SCTP, PAY4),
	IECM_PTT(35, IP, IPV4, NOF, IP_IP, IPV4, NOF, ICMP, PAY4),

	/* IPv4 --> IPv6 */
	IECM_PTT(36, IP, IPV4, NOF, IP_IP, IPV6, FRG, NONE, PAY3),
	IECM_PTT(37, IP, IPV4, NOF, IP_IP, IPV6, NOF, NONE, PAY3),
	IECM_PTT(38, IP, IPV4, NOF, IP_IP, IPV6, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(39),
	IECM_PTT(40, IP, IPV4, NOF, IP_IP, IPV6, NOF, TCP,  PAY4),
	IECM_PTT(41, IP, IPV4, NOF, IP_IP, IPV6, NOF, SCTP, PAY4),
	IECM_PTT(42, IP, IPV4, NOF, IP_IP, IPV6, NOF, ICMP, PAY4),

	/* IPv4 --> GRE/NAT */
	IECM_PTT(43, IP, IPV4, NOF, IP_GRENAT, NONE, NOF, NONE, PAY3),

	/* IPv4 --> GRE/NAT --> IPv4 */
	IECM_PTT(44, IP, IPV4, NOF, IP_GRENAT, IPV4, FRG, NONE, PAY3),
	IECM_PTT(45, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, NONE, PAY3),
	IECM_PTT(46, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(47),
	IECM_PTT(48, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, TCP,  PAY4),
	IECM_PTT(49, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, SCTP, PAY4),
	IECM_PTT(50, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, ICMP, PAY4),

	/* IPv4 --> GRE/NAT --> IPv6 */
	IECM_PTT(51, IP, IPV4, NOF, IP_GRENAT, IPV6, FRG, NONE, PAY3),
	IECM_PTT(52, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, NONE, PAY3),
	IECM_PTT(53, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(54),
	IECM_PTT(55, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, TCP,  PAY4),
	IECM_PTT(56, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, SCTP, PAY4),
	IECM_PTT(57, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, ICMP, PAY4),

	/* IPv4 --> GRE/NAT --> MAC */
	IECM_PTT(58, IP, IPV4, NOF, IP_GRENAT_MAC, NONE, NOF, NONE, PAY3),

	/* IPv4 --> GRE/NAT --> MAC --> IPv4 */
	IECM_PTT(59, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, FRG, NONE, PAY3),
	IECM_PTT(60, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, NONE, PAY3),
	IECM_PTT(61, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(62),
	IECM_PTT(63, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, TCP,  PAY4),
	IECM_PTT(64, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, SCTP, PAY4),
	IECM_PTT(65, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, ICMP, PAY4),

	/* IPv4 --> GRE/NAT -> MAC --> IPv6 */
	IECM_PTT(66, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, FRG, NONE, PAY3),
	IECM_PTT(67, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, NONE, PAY3),
	IECM_PTT(68, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(69),
	IECM_PTT(70, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, TCP,  PAY4),
	IECM_PTT(71, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, SCTP, PAY4),
	IECM_PTT(72, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, ICMP, PAY4),

	/* IPv4 --> GRE/NAT --> MAC/VLAN */
	IECM_PTT(73, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, NONE, NOF, NONE, PAY3),

	/* IPv4 ---> GRE/NAT -> MAC/VLAN --> IPv4 */
	IECM_PTT(74, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV4, FRG, NONE, PAY3),
	IECM_PTT(75, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV4, NOF, NONE, PAY3),
	IECM_PTT(76, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV4, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(77),
	IECM_PTT(78, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV4, NOF, TCP,  PAY4),
	IECM_PTT(79, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV4, NOF, SCTP, PAY4),
	IECM_PTT(80, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV4, NOF, ICMP, PAY4),

	/* IPv4 -> GRE/NAT -> MAC/VLAN --> IPv6 */
	IECM_PTT(81, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV6, FRG, NONE, PAY3),
	IECM_PTT(82, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV6, NOF, NONE, PAY3),
	IECM_PTT(83, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV6, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(84),
	IECM_PTT(85, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV6, NOF, TCP,  PAY4),
	IECM_PTT(86, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV6, NOF, SCTP, PAY4),
	IECM_PTT(87, IP, IPV4, NOF, IP_GRENAT_MAC_VLAN, IPV6, NOF, ICMP, PAY4),

	/* Non Tunneled IPv6 */
	IECM_PTT(88, IP, IPV6, FRG, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(89, IP, IPV6, NOF, NONE, NONE, NOF, NONE, PAY3),
	IECM_PTT(90, IP, IPV6, NOF, NONE, NONE, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(91),
	IECM_PTT(92, IP, IPV6, NOF, NONE, NONE, NOF, TCP,  PAY4),
	IECM_PTT(93, IP, IPV6, NOF, NONE, NONE, NOF, SCTP, PAY4),
	IECM_PTT(94, IP, IPV6, NOF, NONE, NONE, NOF, ICMP, PAY4),

	/* IPv6 --> IPv4 */
	IECM_PTT(95,  IP, IPV6, NOF, IP_IP, IPV4, FRG, NONE, PAY3),
	IECM_PTT(96,  IP, IPV6, NOF, IP_IP, IPV4, NOF, NONE, PAY3),
	IECM_PTT(97,  IP, IPV6, NOF, IP_IP, IPV4, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(98),
	IECM_PTT(99,  IP, IPV6, NOF, IP_IP, IPV4, NOF, TCP,  PAY4),
	IECM_PTT(100, IP, IPV6, NOF, IP_IP, IPV4, NOF, SCTP, PAY4),
	IECM_PTT(101, IP, IPV6, NOF, IP_IP, IPV4, NOF, ICMP, PAY4),

	/* IPv6 --> IPv6 */
	IECM_PTT(102, IP, IPV6, NOF, IP_IP, IPV6, FRG, NONE, PAY3),
	IECM_PTT(103, IP, IPV6, NOF, IP_IP, IPV6, NOF, NONE, PAY3),
	IECM_PTT(104, IP, IPV6, NOF, IP_IP, IPV6, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(105),
	IECM_PTT(106, IP, IPV6, NOF, IP_IP, IPV6, NOF, TCP,  PAY4),
	IECM_PTT(107, IP, IPV6, NOF, IP_IP, IPV6, NOF, SCTP, PAY4),
	IECM_PTT(108, IP, IPV6, NOF, IP_IP, IPV6, NOF, ICMP, PAY4),

	/* IPv6 --> GRE/NAT */
	IECM_PTT(109, IP, IPV6, NOF, IP_GRENAT, NONE, NOF, NONE, PAY3),

	/* IPv6 --> GRE/NAT -> IPv4 */
	IECM_PTT(110, IP, IPV6, NOF, IP_GRENAT, IPV4, FRG, NONE, PAY3),
	IECM_PTT(111, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, NONE, PAY3),
	IECM_PTT(112, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(113),
	IECM_PTT(114, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, TCP,  PAY4),
	IECM_PTT(115, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, SCTP, PAY4),
	IECM_PTT(116, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, ICMP, PAY4),

	/* IPv6 --> GRE/NAT -> IPv6 */
	IECM_PTT(117, IP, IPV6, NOF, IP_GRENAT, IPV6, FRG, NONE, PAY3),
	IECM_PTT(118, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, NONE, PAY3),
	IECM_PTT(119, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(120),
	IECM_PTT(121, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, TCP,  PAY4),
	IECM_PTT(122, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, SCTP, PAY4),
	IECM_PTT(123, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, ICMP, PAY4),

	/* IPv6 --> GRE/NAT -> MAC */
	IECM_PTT(124, IP, IPV6, NOF, IP_GRENAT_MAC, NONE, NOF, NONE, PAY3),

	/* IPv6 --> GRE/NAT -> MAC -> IPv4 */
	IECM_PTT(125, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, FRG, NONE, PAY3),
	IECM_PTT(126, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, NONE, PAY3),
	IECM_PTT(127, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(128),
	IECM_PTT(129, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, TCP,  PAY4),
	IECM_PTT(130, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, SCTP, PAY4),
	IECM_PTT(131, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, ICMP, PAY4),

	/* IPv6 --> GRE/NAT -> MAC -> IPv6 */
	IECM_PTT(132, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, FRG, NONE, PAY3),
	IECM_PTT(133, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, NONE, PAY3),
	IECM_PTT(134, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(135),
	IECM_PTT(136, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, TCP,  PAY4),
	IECM_PTT(137, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, SCTP, PAY4),
	IECM_PTT(138, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, ICMP, PAY4),

	/* IPv6 --> GRE/NAT -> MAC/VLAN */
	IECM_PTT(139, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, NONE, NOF, NONE, PAY3),

	/* IPv6 --> GRE/NAT -> MAC/VLAN --> IPv4 */
	IECM_PTT(140, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV4, FRG, NONE, PAY3),
	IECM_PTT(141, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV4, NOF, NONE, PAY3),
	IECM_PTT(142, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV4, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(143),
	IECM_PTT(144, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV4, NOF, TCP,  PAY4),
	IECM_PTT(145, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV4, NOF, SCTP, PAY4),
	IECM_PTT(146, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV4, NOF, ICMP, PAY4),

	/* IPv6 --> GRE/NAT -> MAC/VLAN --> IPv6 */
	IECM_PTT(147, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV6, FRG, NONE, PAY3),
	IECM_PTT(148, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV6, NOF, NONE, PAY3),
	IECM_PTT(149, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV6, NOF, UDP,  PAY4),
	IECM_PTT_UNUSED_ENTRY(150),
	IECM_PTT(151, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV6, NOF, TCP,  PAY4),
	IECM_PTT(152, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV6, NOF, SCTP, PAY4),
	IECM_PTT(153, IP, IPV6, NOF, IP_GRENAT_MAC_VLAN, IPV6, NOF, ICMP, PAY4),

	/* rest of the entries are unused */
};

enum iecm_queue_flags_t {
	__IECM_Q_GEN_CHK,
	__IECM_RFLQ_GEN_CHK,
	__IECM_Q_FLOW_SCH_EN,
	__IECM_Q_ETF_EN,
	__IECM_Q_SW_MARKER,
#ifdef HAVE_XDP_SUPPORT
	__IECM_Q_XDP,
#endif /* HAVE_XDP_SUPPORT */
	__IECM_ADQ_TX_WB_ON_ITR,
	__IECM_Q_VLAN_TAG_LOC_L2TAG1,
	__IECM_Q_VLAN_TAG_LOC_L2TAG2,
	__IECM_Q_FLAGS_NBITS,
};

enum iecm_vector_flags_t {
	/* ADQ busy-poll states used to keep track of various states as defined
	 * and those states are used during ADQ performance optimization
	 */
	/* This tracks current state of vector, BUSY_POLL or INTR */
	__IECM_VEC_STATE_IN_BP,
	/* This tracks prev state of vector, BUSY_POLL or INTR */
	__IECM_VEC_STATE_PREV_IN_BP,
	/* This tracks state of vector, was it ever in BUSY_POLL. This
	 * state goes to INTT if interrupt are enabled or SW interrupts
	 * are triggered from either service_task or napi_poll
	 */
	__IECM_VEC_STATE_ONCE_IN_BP,
	/* Tracks if previously - were there any data packets received
	 * on per channel enabled vector or not
	 */
	__IECM_VEC_STATE_PREV_DATA_PKT_RECV,
	/* ADQ performace enable */
	__IECM_VEC_CHNL_PERF_ENA,
	/* controls packet inspection based optimization */
	__IECM_VEC_CHNL_PKT_OPT_ENA,
	/* This must be last */
	__IECM_VEC_FLAGS_NBITS,
};

struct iecm_vector_ch_stats {
	/* following are used as part of managing driver internal
	 * state machine. Only to be used for perf debugging.
	 */
	u64 in_bp;
	u64 in_intr;
	u64 intr_to_bp;
	u64 bp_to_intr;
	u64 intr_to_intr;
	u64 bp_to_bp;

	/* This counter is used to track real transition of vector from
	 * BUSY_POLL to INTERRUPT based on enhanced logic (using state
	 * machine and control packets).
	 */
	u64 unlikely_cb_to_bp;
	/* Tracking "unlikely_cb_bp and once_in_bp is true" */
	u64 ucb_once_in_bp_true;
	/* This is used to keep track of enabling interrupt from napi_poll
	 * when state machine condition indicated once_in_bp is false
	 */
	u64 intr_once_bp_false;
	u64 bp_stop_need_resched;
	u64 bp_stop_timeout;

	u64 cleaned_any_data_pkt;
	/* busy_poll stop, need_resched is set and did not clean
	 * any data packet during this previous invocation of napi_poll
	 */
	u64 need_resched_no_data_pkt;
	/* busy_poll stop, need_resched is not set: hence it is inferred as
	 * possible timeout and did not clean any data packet during this
	 * previous invocation of napi_poll
	 */
	u64 timeout_no_data_pkt;
	u64 sw_intr_timeout; /* track SW INTR from napi_poll */
	u64 sw_intr_serv_task; /* track SW INTR from service_task */
	/* This keeps track of how many times, bailout when once_in_bp is set,
	 * unlikely_cb_to_bp is set, but pkt based interrupt optimization
	 * is OFF
	 */
	u64 no_sw_intr_opt_off;
	/* tracking, how many times WB_ON_ITR is set */
	u64 wb_on_itr_set;
	/* keeps track of SW triggered interrupt due to not clean_complete */
	u64 intr_en_not_clean_complete;
};

struct iecm_vec_regs {
	u32 dyn_ctl_reg;
	u32 itrn_reg;
};

struct iecm_intr_reg {
	u32 dyn_ctl;
	u32 dyn_ctl_intena_m;
	u32 dyn_ctl_clrpba_m;
	u32 dyn_ctl_itridx_s;
	u32 dyn_ctl_itridx_m;
	u32 dyn_ctl_intrvl_s;
	u32 rx_itr;
	u32 tx_itr;
	u32 dyn_ctl_wb_on_itr_m;
	u32 dyn_ctl_swint_trig_m;
	u32 dyn_ctl_sw_itridx_ena_m;
	u32 icr_ena;
	u32 icr_ena_ctlq_m;
};

struct iecm_q_vector {
	struct iecm_vport *vport;
	cpumask_t affinity_mask;
	struct napi_struct napi;
	u16 v_idx;		/* index in the vport->q_vector array */
	struct iecm_intr_reg intr_reg;

	int num_txq;
	struct iecm_queue **tx;
	struct dim tx_dim;	/* data for net_dim algorithm */
	u16 tx_itr_value;
	bool tx_intr_mode;
	u32 tx_itr_idx;

	int num_rxq;
	struct iecm_queue **rx;
	struct dim rx_dim;	/* data for net_dim algorithm */
	u16 rx_itr_value;
	bool rx_intr_mode;
	u32 rx_itr_idx;

	int num_bufq;
	struct iecm_queue **bufq;

	u16 total_events;       /* net_dim(): number of interrupts processed */
	char name[IECM_INT_NAME_STR_LEN];
	bool wb_ena;

	/* ADQ related flags */
	DECLARE_BITMAP(flags, __IECM_VEC_FLAGS_NBITS);
	/* Used in logic to determine if SW inter is needed or not.
	 * This is used only for channel enabled vector
	 */
	u64 jiffy;

	struct iecm_channel_ex *ch;
	struct iecm_vector_ch_stats ch_stats;
};

struct iecm_rx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 rsc_pkts;
};

struct iecm_tx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 lso_pkts;
};

struct iecm_ch_tx_q_stats {
};

struct iecm_ch_rx_q_stats {
	u64 tcp_ctrl_pkts;
	u64 only_ctrl_pkts;
	u64 bp_no_data_pkt;
	u64 tcp_fin_recv;
	u64 tcp_rst_recv;
	u64 tcp_syn_recv;
};

struct iecm_ch_q_poll_stats {
	/* general packet counters for busy_poll versus napi_poll */
	u64 pkt_busy_poll;
	u64 pkt_not_busy_poll;
};

struct iecm_ch_q_stats {
	struct iecm_ch_q_poll_stats poll;
	union {
		struct iecm_ch_tx_q_stats tx;
		struct iecm_ch_rx_q_stats rx;
	};
};

union iecm_queue_stats {
	struct iecm_rx_queue_stats rx;
	struct iecm_tx_queue_stats tx;
};

#define IECM_ITR_DYNAMIC	1
#define IECM_ITR_MAX		0x1FE0
#define IECM_ITR_20K		0x0032
#define IECM_ITR_GRAN_S		1	/* Assume ITR granularity is 2us */
#define IECM_ITR_MASK		0x1FFE	/* ITR register value alignment mask */
#define ITR_REG_ALIGN(setting)	((setting) & IECM_ITR_MASK)
#define IECM_ITR_IS_DYNAMIC(itr_mode) (itr_mode)
#define IECM_ITR_TX_DEF		IECM_ITR_20K
#define IECM_ITR_RX_DEF		IECM_ITR_20K

/* queue associated with a vport */
struct iecm_queue {
	struct device *dev;		/* Used for DMA mapping */
	struct iecm_vport *vport;	/* Backreference to associated vport */
	union {
		struct iecm_txq_group *txq_grp;
		struct iecm_rxq_group *rxq_grp;
	};
	/* bufq: Used as group id, either 0 or 1, on clean Buf Q uses this
	 *       index to determine which group of refill queues to clean.
	 *       Bufqs are use in splitq only.
	 * txq: Index to map between Tx Q group and hot path Tx ptrs stored in
	 *      vport.  Used in both single Q/split Q
	 * rxq: Index to total rxq across groups, used for skb reporting
	 */
	u16 idx;
	/* Used for both Q models single and split. In split Q model relevant
	 * only to Tx Q and Rx Q
	 */
	u8 __iomem *tail;
	/* Used in both single and split Q.  In single Q, Tx Q uses tx_buf and
	 * Rx Q uses rx_buf.  In split Q, Tx Q uses tx_buf, Rx Q uses skb, and
	 * Buf Q uses rx_buf.
	 */
	union {
		struct iecm_tx_buf *tx_buf;
		struct {
			struct iecm_rx_buf *buf;
			struct iecm_dma_mem **hdr_buf;
		} rx_buf;
		struct sk_buff *skb;
	};
	u16 q_type;
	/* Queue id(Tx/Tx compl/Rx/Bufq) */
	u32 q_id;
	u16 desc_count;		/* Number of descriptors */

	/* Relevant in both split & single Tx Q & Buf Q*/
	u16 next_to_use;
	/* In split q model only relevant for Tx Compl Q and Rx Q */
	u16 next_to_clean;	/* used in interrupt processing */
	/* Used only for Rx. In split Q model only relevant to Rx Q */
	u16 next_to_alloc;
	/* Generation bit check stored, as HW flips the bit at Queue end */
	DECLARE_BITMAP(flags, __IECM_Q_FLAGS_NBITS);

	union iecm_queue_stats q_stats;
	struct u64_stats_sync stats_sync;
	struct iecm_ch_q_stats ch_q_stats;
	struct iecm_channel_ex *ch;

	bool rx_hsplit_en;

	u16 rx_hbuf_size;	/* Header buffer size */
	u16 rx_buf_size;
	u16 rx_max_pkt_size;
	u16 rx_buf_stride;
	u8 rx_buffer_low_watermark;
	u64 rxdids;
	/* Used for both Q models single and split. In split Q model relavant
	 * only to Tx compl Q and Rx compl Q
	 */
	struct iecm_q_vector *q_vector;	/* Backreference to associated vector */
	unsigned int size;		/* length of descriptor ring in bytes */
	dma_addr_t dma;			/* physical address of ring */
	void *desc_ring;		/* Descriptor ring memory */

	struct bpf_prog *xdp_prog;	/* Used only for Rx compl Q */
#ifdef HAVE_XDP_BUFF_RXQ
	struct xdp_rxq_info xdp_rxq;	/* Used for XDP memory model setting */
#endif /* HAVE_XDP_BUFF_RXQ */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	struct xsk_buff_pool *xsk_pool;
	u16 xdp_tx_active;
	u16 xdp_next_rs_idx;		/* Used to track the next descriptor which
					 * has RS bit set.
					 * This is a performance optimization for
					 * singleq mode to reduce the number of descriptor
					 * writebacks with XDP transmits.
					 */
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

	u64 num_completions;		/* Only relevant for tx completion
					 * queue; tracks the number of
					 * completions received to compare
					 * against the number of completions
					 * pending, as accumulated by the TXQs
					 */

	struct iecm_buf_lifo buf_stack; /* Stack of empty buffers to store
					 * buffer info for out of order
					 * buffer completions
					 */
	u16 tx_buf_key;			/* 16 bit unique "identifier" (index)
					 * to be used as the completion tag when
					 * queue is using flow based scheduling
					 */
	u16 tx_max_bufs;		/* Max buffers that can be transmitted
					 * with scatter-gather
					 */
	DECLARE_HASHTABLE(sched_buf_hash, 12);

	struct iecm_rx_hdr_buf_pages hbuf_pages;
} ____cacheline_internodealigned_in_smp;

/* Software queues are used in splitq mode to manage buffers between rxq
 * producer and the bufq consumer.  These are required in order to maintain a
 * lockless buffer management system and are strictly software only constructs.
 */
struct iecm_sw_queue {
	u16 next_to_clean ____cacheline_aligned_in_smp;
	u16 next_to_alloc ____cacheline_aligned_in_smp;
	u16 next_to_use ____cacheline_aligned_in_smp;
	DECLARE_BITMAP(flags, __IECM_Q_FLAGS_NBITS)
		____cacheline_aligned_in_smp;
	u16 *ring ____cacheline_aligned_in_smp;
	u16 desc_count;
	u16 buf_size;
	struct device *dev;
} ____cacheline_internodealigned_in_smp;

/* Splitq only.  iecm_rxq_set associates an rxq with at an array of refillqs.
 * Each rxq needs a refillq to return used buffers back to the respective bufq.
 * Bufqs then clean these refillqs for buffers to give to hardware.
 */
struct iecm_rxq_set {
	struct iecm_queue rxq;
	/* refillqs assoc with bufqX mapped to this rxq */
	struct iecm_sw_queue *refillq0;
	struct iecm_sw_queue *refillq1;
};

/* Splitq only.  iecm_bufq_set associates a bufq to an array of refillqs.
 * In this bufq_set, there will be one refillq for each rxq in this rxq_group.
 * Used buffers received by rxqs will be put on refillqs which bufqs will
 * clean to return new buffers back to hardware.
 *
 * Buffers needed by some number of rxqs associated in this rxq_group are
 * managed by at most two bufqs (depending on performance configuration).
 */
struct iecm_bufq_set {
	struct iecm_queue bufq;
	/* This is always equal to num_rxq_sets in iecm_rxq_group */
	int num_refillqs;
	struct iecm_sw_queue *refillqs;
};

/* In singleq mode, an rxq_group is simply an array of rxqs.  In splitq, a
 * rxq_group contains all the rxqs, bufqs and refillqs needed to
 * manage buffers in splitq mode.
 */
struct iecm_rxq_group {
	struct iecm_vport *vport; /* back pointer */

	union {
		struct {
			int num_rxq;
			/* store queue pointers */
			struct iecm_queue *rxqs[IECM_LARGE_MAX_Q];
		} singleq;
		struct {
			int num_rxq_sets;
			/* store queue pointers */
			struct iecm_rxq_set *rxq_sets[IECM_LARGE_MAX_Q];
			struct iecm_bufq_set *bufq_sets;
		} splitq;
	};
};

/* Between singleq and splitq, a txq_group is largely the same except for the
 * complq.  In splitq a single complq is responsible for handling completions
 * for some number of txqs associated in this txq_group.
 */
struct iecm_txq_group {
	struct iecm_vport *vport; /* back pointer */

	int num_txq;
	/* store queue pointers */
	struct iecm_queue *txqs[IECM_LARGE_MAX_Q];

	/* splitq only */
	struct iecm_queue *complq;

	/* Total number of completions pending for the completion queue,
	 * acculumated for all txqs associated with that completion queue
	 */
	u64 num_completions_pending;
};

struct iecm_adapter;

/**
 * iecm_is_queue_ch_ena - Checks if queue channel is enabled
 * @queue: Tx/Rx queue pointer
 *
 */
/**
 * iecm_is_vec_pkt_inspect_opt_ena - Checks if packet optimizations is enabled
 * @q_vector: Pointer to the q_vector structure
 *
 */
static inline bool
iecm_is_vec_pkt_inspect_opt_ena(struct iecm_q_vector *q_vector)
{
	return test_bit(__IECM_VEC_CHNL_PKT_OPT_ENA, q_vector->flags);
}

/**
 * iecm_is_vec_ch_ena - checks if vector channel is enabled
 * @q_vector: pointer to the q_vector structure
 *
 */
static inline bool iecm_is_vec_ch_ena(struct iecm_q_vector *qv)
{
	return !!qv->ch;
}

/**
 * iecm_is_vec_ch_perf_ena - checks if vector channel performance is enabled
 * @q_vector: pointer to the q_vector structure
 *
 */
static inline bool iecm_is_vec_ch_perf_ena(struct iecm_q_vector *qv)
{
	return test_bit(__IECM_VEC_CHNL_PERF_ENA, qv->flags);
}

/**
 * iecm_is_vec_busypoll_to_intr - To check vector state
 * @qv: pointer to q_vector
 *
 * This function returns true if vector is transitioning from BUSY_POLL
 * to INTERRUPT based on current and previous state of vector
 */
static inline bool iecm_is_vec_busypoll_to_intr(struct iecm_q_vector *qv)
{
	return test_bit(__IECM_VEC_STATE_PREV_IN_BP, qv->flags) &&
		!test_bit(__IECM_VEC_STATE_IN_BP, qv->flags);
}

/**
 * iecm_is_vec_ever_in_busypoll - To check vector state ever in busypoll
 * @qv: pointer to q_vector
 *
 * This function returns true if vectors current OR previous state
 * is BUSY_POLL
 */
static inline bool iecm_is_vec_ever_in_busypoll(struct iecm_q_vector *qv)
{
	return test_bit(__IECM_VEC_STATE_PREV_IN_BP, qv->flags) ||
		test_bit(__IECM_VEC_STATE_IN_BP, qv->flags);
}

/**
 * iecm_is_vec_intr_to_busypoll - To check vector state
 * @qv: pointer to q_vector
 *
 * This function returns true if vector is transitioning from INTERRUPT
 * to BUSY_POLL based on current and previous state of vector
 */
static inline bool iecm_is_vec_intr_to_busypoll(struct iecm_q_vector *qv)
{
	return !test_bit(__IECM_VEC_STATE_PREV_IN_BP, qv->flags) &&
		test_bit(__IECM_VEC_STATE_IN_BP, qv->flags);
}

/**
 * iecm_inc_napi_sw_intr_counter - Increment SW interrupt counter
 * @q_vector: pointer to q_vector
 *
 * Track software interrupt from napi_poll codeflow.  Caller of this
 * expected to call iecm_adq_force_wb to actually trigger SW intr.
 */
static inline void
iecm_inc_napi_sw_intr_counter(struct iecm_q_vector *q_vector)
{
	q_vector->ch_stats.sw_intr_timeout++;
}

/**
 * iecm_inc_serv_task_sw_intr_counter - Increment service task SW interrupt
 * counter
 * @q_vector: pointer to q_vector
 *
 * Track software interrupt from service task codeflow.  Caller of this
 * expected to call iecm_adq_force_wb to actually trigger SW intr.
 */
static inline void
iecm_inc_serv_task_sw_intr_counter(struct iecm_q_vector *q_vector)
{
	q_vector->ch_stats.sw_intr_serv_task++;
}

/**
 * iecm_tx_singleq_build_ctob - populate command tag offset and size
 * @td_cmd: Command to be filled in desc
 * @td_offset: Offset to be filled in desc
 * @size: Size of the buffer
 * @td_tag: vlan tag to be filled
 *
 * Returns the 64 bit value populated with the input parameters
 */
static inline __le64
iecm_tx_singleq_build_ctob(u64 td_cmd, u64 td_offset, unsigned int size,
			   u64 td_tag)
{
	return cpu_to_le64(IECM_TX_DESC_DTYPE_DATA |
			   (td_cmd    << IECM_TXD_QW1_CMD_S) |
			   (td_offset << IECM_TXD_QW1_OFFSET_S) |
			   ((u64)size << IECM_TXD_QW1_TX_BUF_SZ_S) |
			   (td_tag    << IECM_TXD_QW1_L2TAG1_S));
}

void iecm_tx_splitq_build_ctb(union iecm_tx_flex_desc *desc,
			      struct iecm_tx_splitq_params *parms,
			      u16 td_cmd, u16 size);
void iecm_tx_splitq_build_flow_desc(union iecm_tx_flex_desc *desc,
				    struct iecm_tx_splitq_params *parms,
				    u16 td_cmd, u16 size);
int iecm_vport_singleq_napi_poll(struct napi_struct *napi, int budget);
void iecm_vport_init_num_qs(struct iecm_vport *vport,
			    struct virtchnl2_create_vport *vport_msg);
void iecm_vport_calc_num_q_desc(struct iecm_vport *vport);
void iecm_vport_calc_total_qs(struct iecm_adapter *adapter,
			      struct virtchnl2_create_vport *vport_msg);
void iecm_vport_calc_num_q_groups(struct iecm_vport *vport);
int iecm_vport_queues_alloc(struct iecm_vport *vport);
void iecm_rx_post_buf_refill(struct iecm_sw_queue *refillq, u16 buf_id);
void iecm_vport_queues_rel(struct iecm_vport *vport);
void iecm_vport_calc_num_q_vec(struct iecm_vport *vport);
void iecm_vport_intr_dis_irq_all(struct iecm_vport *vport);
void iecm_vport_intr_clear_dflt_itr(struct iecm_vport *vport);
void iecm_vport_intr_update_itr_ena_irq(struct iecm_q_vector *q_vector);
void iecm_vport_intr_deinit(struct iecm_vport *vport);
int iecm_vport_intr_init(struct iecm_vport *vport);
irqreturn_t
iecm_vport_intr_clean_queues(int __always_unused irq, void *data);
void iecm_vport_intr_ena_irq_all(struct iecm_vport *vport);
enum
pkt_hash_types iecm_ptype_to_htype(struct iecm_rx_ptype_decoded *decoded);
int iecm_config_rss(struct iecm_vport *vport);
void iecm_fill_dflt_rss_lut(struct iecm_vport *vport);
int iecm_init_rss(struct iecm_vport *vport);
void iecm_deinit_rss(struct iecm_vport *vport);
int iecm_config_rss(struct iecm_vport *vport);
bool iecm_rx_can_reuse_page(struct iecm_rx_buf *rx_buf);
void iecm_rx_buf_adjust_pg(struct iecm_rx_buf *rx_buf, unsigned int size);
void iecm_rx_add_frag(struct iecm_rx_buf *rx_buf, struct sk_buff *skb,
		      unsigned int size);
struct sk_buff *iecm_rx_construct_skb(struct iecm_queue *rxq,
				      struct iecm_rx_buf *rx_buf,
				      unsigned int size);
void iecm_rx_skb(struct iecm_queue *rxq, struct sk_buff *skb, u16 vlan_tag);
bool iecm_init_rx_buf_hw_alloc(struct iecm_queue *rxq, struct iecm_rx_buf *buf);
void iecm_rx_buf_hw_update(struct iecm_queue *rxq, u32 val);
void iecm_tx_buf_hw_update(struct iecm_queue *tx_q, u32 val,
			   bool xmit_more);
void iecm_rx_splitq_put_bufs(struct iecm_queue *rx_bufq,
			     struct iecm_rx_buf *hdr_buf,
			     struct iecm_rx_buf *rx_buf);
bool iecm_rx_splitq_test_staterr(u8 stat_err_field, const u8 stat_err_bits);
bool iecm_rx_singleq_test_staterr(union virtchnl2_rx_desc *rx_desc,
				  const u64 stat_err_bits);
int iecm_rx_process_skb_fields(struct iecm_queue *rxq, struct sk_buff *skb,
			       struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc);
void iecm_rx_singleq_process_skb_fields(struct iecm_queue *rx_q, struct sk_buff *skb,
					union virtchnl2_rx_desc *rx_desc, u16 ptype);
void iecm_rx_singleq_extract_fields(struct iecm_queue *rx_q,
				    union virtchnl2_rx_desc *rx_desc,
				    struct iecm_rx_extracted *fields);
void iecm_rx_singleq_bump_ntc(struct iecm_queue *q);
bool iecm_rx_singleq_is_non_eop(struct iecm_queue *rxq,
				union virtchnl2_rx_desc *rx_desc,
				struct sk_buff *skb);
#ifdef HAVE_XDP_FRAME_STRUCT
int iecm_xmit_xdpq(struct xdp_frame *xdp, struct iecm_queue *xdpq);
#else
int iecm_xmit_xdpq(struct xdp_buff *xdp, struct iecm_queue *xdpq);
#endif /* HAVE_XDP_FRAME_STRUCT */
bool iecm_rx_splitq_extract_vlan_tag(struct virtchnl2_rx_flex_desc_adv_nic_3 *desc,
				     struct iecm_queue *rxq, u16 *vlan_tag);
void iecm_rx_bump_ntc(struct iecm_queue *q);
void iecm_tx_buf_rel(struct iecm_queue *tx_q, struct iecm_tx_buf *tx_buf);
unsigned int iecm_size_to_txd_count(unsigned int size);
unsigned int iecm_tx_desc_count_required(struct sk_buff *skb);
bool iecm_chk_linearize(struct sk_buff *skb, unsigned int max_bufs,
			unsigned int count);
int iecm_tx_maybe_stop_common(struct iecm_queue *tx_q, unsigned int size);
#ifdef HAVE_TX_TIMEOUT_TXQUEUE
void iecm_tx_timeout(struct net_device *netdev,
		     unsigned int __always_unused txqueue);
#else
void iecm_tx_timeout(struct net_device *netdev);
#endif /* HAVE_TX_TIMEOUT_TXQUEUE */
netdev_tx_t iecm_tx_splitq_start(struct sk_buff *skb,
				 struct net_device *netdev);
netdev_tx_t iecm_tx_singleq_start(struct sk_buff *skb,
				  struct net_device *netdev);
#ifdef IECM_ADD_PROBES
void iecm_tx_extra_counters(struct iecm_queue *txq, struct iecm_tx_buf *first);
void iecm_rx_extra_counters(struct iecm_queue *rxq, u32 inner_prot,
			    bool ipv4, struct iecm_rx_csum_decoded *csum_bits,
			    bool splitq);
#endif /* IECM_ADD_PROBES */
bool iecm_rx_singleq_buf_hw_alloc_all(struct iecm_queue *rxq,
				      u16 cleaned_count);
#ifdef HAVE_VOID_NDO_GET_STATS64
void iecm_get_stats64(struct net_device *netdev,
		      struct rtnl_link_stats64 *stats);
#else /* HAVE_VOID_NDO_GET_STATS64 */
struct rtnl_link_stats64 *iecm_get_stats64(struct net_device *netdev,
					   struct rtnl_link_stats64 *stats);
#endif /* HAVE_VOID_NDO_GET_STATS64 */
#ifdef HAVE_XDP_SUPPORT
int iecm_rx_xdp(struct iecm_queue *rxq, struct iecm_queue *xdpq,
		struct iecm_rx_buf *rx_buf, unsigned int size);
INDIRECT_CALLABLE_DECLARE(void *iecm_prepare_xdp_tx_splitq_desc(struct iecm_queue *xdpq,
								dma_addr_t dma, u16 idx,
								u32 size));

INDIRECT_CALLABLE_DECLARE(void *iecm_prepare_xdp_tx_singleq_desc(struct iecm_queue *xdpq,
								 dma_addr_t dma, u16 idx,
								 u32 size));
#endif /* HAVE_XDP_SUPPORT */
int iecm_tso(struct iecm_tx_buf *first, struct iecm_tx_offload_params *off);
void iecm_tx_prepare_vlan_flags(struct iecm_queue *tx_q,
				struct iecm_tx_buf *first,
				struct sk_buff *skb);
void iecm_adq_force_wb(struct iecm_q_vector *q_vector);

#ifdef HAVE_XDP_SUPPORT
/**
 * iecm_xdpq_update_tail - Updates the XDP Tx queue tail register
 * @xdpq: XDP Tx queue
 *
 * This function updates the XDP Tx queue tail register.
 */
static inline void iecm_xdpq_update_tail(struct iecm_queue *xdpq)
{
	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.
	 */
	wmb();
	writel_relaxed(xdpq->next_to_use, xdpq->tail);
}

/**
 * iecm_finalize_xdp_rx - Bump XDP Tx tail and/or flush redirect map
 * @xdpq: XDP Tx queue
 * @xdp_res: Result of the receive batch
 *
 * This function bumps XDP Tx tail and/or flush redirect map, and
 * should be called when a batch of packets has been processed in the
 * napi loop.
 */
static inline void iecm_finalize_xdp_rx(struct iecm_queue *xdpq, unsigned int xdp_res)
{
	if (xdp_res & IECM_XDP_REDIR)
		xdp_do_flush_map();

	if (xdp_res & IECM_XDP_TX)
		iecm_xdpq_update_tail(xdpq);
}
#endif /* HAVE_XDP_SUPPORT */
#endif /* !_IECM_TXRX_H_ */
