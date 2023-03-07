/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2022 Intel Corporation */

#ifndef _IDPF_TXRX_H_
#define _IDPF_TXRX_H_

#include "virtchnl2_lan_desc.h"
#ifdef HAVE_INDIRECT_CALL_WRAPPER_HEADER
#include <linux/indirect_call_wrapper.h>
#endif

#define IDPF_LARGE_MAX_Q			256
#define IDPF_MAX_Q				16
#define IDPF_MIN_Q				2
/* Mailbox Queue */
#define IDPF_MAX_NONQ				1
#define IDPF_MAX_DYNAMIC_VPORT			450
#define IDPF_MIN_TXQ_DESC			64
#define IDPF_MIN_RXQ_DESC			64
#define IDPF_MIN_TXQ_COMPLQ_DESC		256
/* Number of descriptors in a queue should be a multiple of 32. RX queue
 * descriptors alone should be a multiple of (IDPF_MAX_BUFQS_PER_RXQ_GRP * 32)
 * to achieve BufQ descriptors aligned to 32
 */
#define IDPF_REQ_DESC_MULTIPLE			32
#define IDPF_REQ_RXQ_DESC_MULTIPLE (IDPF_MAX_BUFQS_PER_RXQ_GRP * 32)
#define IDPF_MIN_TX_DESC_NEEDED (MAX_SKB_FRAGS + 6)
#define IDPF_TX_WAKE_THRESH ((s16)IDPF_MIN_TX_DESC_NEEDED * 2)

#define IDPF_MAX_DESCS				8160
#define IDPF_MAX_TXQ_DESC ALIGN_DOWN(IDPF_MAX_DESCS, IDPF_REQ_DESC_MULTIPLE)
#define IDPF_MAX_RXQ_DESC ALIGN_DOWN(IDPF_MAX_DESCS, IDPF_REQ_RXQ_DESC_MULTIPLE)

#define IDPF_DFLT_SINGLEQ_TX_Q_GROUPS		1
#define IDPF_DFLT_SINGLEQ_RX_Q_GROUPS		1
#define IDPF_DFLT_SINGLEQ_TXQ_PER_GROUP		4
#define IDPF_DFLT_SINGLEQ_RXQ_PER_GROUP		4

#define IDPF_COMPLQ_PER_GROUP			1
#define IDPF_SINGLE_BUFQ_PER_RXQ_GRP		1
#define IDPF_MAX_BUFQS_PER_RXQ_GRP		2
#define IDPF_BUFQ2_ENA				1

#define IDPF_DFLT_SPLITQ_TXQ_PER_GROUP         1
#define IDPF_DFLT_SPLITQ_RXQ_PER_GROUP         1

/* Default vector sharing */
#define IDPF_MAX_ADI_NUM	6 /* max number of ADIs we support */
#define IDPF_MBX_Q_VEC		1
#define IDPF_MAX_Q_VEC		4 /* For Tx Completion queue and Rx queue */
#define IDPF_MIN_Q_VEC		1
#define IDPF_MAX_RDMA_VEC	2 /* To share with RDMA */
#define IDPF_MIN_RDMA_VEC	1 /* Minimum vectors to be shared with RDMA */

#define IDPF_DFLT_TX_Q_DESC_COUNT		512
#define IDPF_DFLT_TX_COMPLQ_DESC_COUNT		512
#define IDPF_DFLT_RX_Q_DESC_COUNT		512
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
#define IDPF_RX_BUFQ_DESC_COUNT(RXD, NUM_BUFQ)	((RXD) / (NUM_BUFQ))

#define IDPF_RX_BUFQ_WORKING_SET(R)		((R)->desc_count - 1)
#define IDPF_RX_BUFQ_NON_WORKING_SET(R)		((R)->desc_count - \
						 IDPF_RX_BUFQ_WORKING_SET(R))

#define IDPF_RX_HDR_SIZE			256
#define IDPF_RX_BUF_2048			2048
#define IDPF_RX_BUF_4096			4096
#define IDPF_RX_BUF_STRIDE			32
#define IDPF_RX_BUF_POST_STRIDE			16
#define IDPF_LOW_WATERMARK			64
#define IDPF_HDR_BUF_SIZE			256
#define IDPF_PACKET_HDR_PAD	\
	(ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))
#define IDPF_MAX_RXBUFFER			9216
#define IDPF_MAX_MTU		\
	(IDPF_MAX_RXBUFFER - IDPF_PACKET_HDR_PAD)
#define IDPF_TX_TSO_MIN_MSS		88

/* Minimum number of descriptors between 2 descriptors with the RE bit set;
 * only relevant in flow scheduling mode
 */
#define IDPF_TX_SPLITQ_RE_MIN_GAP	64

#define IDPF_RX_BI_BUFID_S		0
#define IDPF_RX_BI_BUFID_M		GENMASK(14, 0)
#define IDPF_RX_BI_GEN_S		15
#define IDPF_RX_BI_GEN_M		BIT(IDPF_RX_BI_GEN_S)
#define IDPF_RXD_EOF_SPLITQ		BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_EOF_S)
#define IDPF_RXD_EOF_SINGLEQ		BIT(VIRTCHNL2_RX_BASE_DESC_STATUS_EOF_S)

#define IDPF_SINGLEQ_RX_BUF_DESC(R, i)	\
	(&(((struct virtchnl2_singleq_rx_buf_desc *)((R)->desc_ring))[i]))
#define IDPF_SPLITQ_RX_BUF_DESC(R, i)	\
	(&(((struct virtchnl2_splitq_rx_buf_desc *)((R)->desc_ring))[i]))
#define IDPF_SPLITQ_RX_BI_DESC(R, i)	\
	(&(((u16 *)((R)->ring))[i]))

#define IDPF_BASE_TX_DESC(R, i)	\
	(&(((struct idpf_base_tx_desc *)((R)->desc_ring))[i]))
#define IDPF_BASE_TX_CTX_DESC(R, i) \
	(&(((struct idpf_base_tx_ctx_desc *)((R)->desc_ring))[i]))
#define IDPF_SPLITQ_TX_COMPLQ_DESC(R, i)	\
	(&(((struct idpf_splitq_tx_compl_desc *)((R)->desc_ring))[i]))

#define IDPF_FLEX_TX_DESC(R, i)	\
	(&(((union idpf_tx_flex_desc *)((R)->desc_ring))[i]))
#define IDPF_FLEX_TX_CTX_DESC(R, i)	\
	(&(((union idpf_flex_tx_ctx_desc *)((R)->desc_ring))[i]))

#define IDPF_DESC_UNUSED(R)	\
	((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->desc_count) + \
	(R)->next_to_clean - (R)->next_to_use - 1)

#define IDPF_TX_BUF_UNUSED(R)	((R)->buf_stack.top)

/* The TX completion queue needs to maintain a cache line sized free space
 * to avoid potentially overwriting a cache line that hasn't been read by
 * SW yet. In this case, that is 16 entries.
 */
#define IDPF_TX_COMPLQ_OVERFLOW_THRESH(R)	((R)->desc_count >> 1)
#define IDPF_TX_COMPLQ_PENDING(R)	\
	(((R)->num_completions_pending >= (R)->complq->num_completions ? \
	0 : U64_MAX) + \
	(R)->num_completions_pending - (R)->complq->num_completions)

#define IDPF_TX_SPLITQ_COMPL_TAG_WIDTH	16
#define IDPF_TX_ADJ_COMPL_TAG_GEN(R) \
	((++(R)->compl_tag_cur_gen) >= (R)->compl_tag_gen_max ? \
	0 : (R)->compl_tag_cur_gen)

#define IDPF_TXD_LAST_DESC_CMD (IDPF_TX_DESC_CMD_EOP | IDPF_TX_DESC_CMD_RS)

#ifdef HAVE_XDP_SUPPORT
#define IDPF_XDP_PASS		0
#define IDPF_XDP_CONSUMED	BIT(0)
#define IDPF_XDP_TX		BIT(1)
#define IDPF_XDP_REDIR		BIT(2)

#define IDPF_XDP_MAX_MTU        3046
#endif /* HAVE_XDP_SUPPORT */

union idpf_tx_flex_desc {
	struct idpf_flex_tx_desc q; /* queue based scheduling */
	struct idpf_flex_tx_sched_desc flow; /* flow based scheduling */
};

struct idpf_tx_buf {
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
	DEFINE_DMA_UNMAP_ADDR(dma);
	DEFINE_DMA_UNMAP_LEN(len);

	union {
		/* Splitq only: Unique identifier for a buffer; used to compare
		 * with completion tag returned in buffer completion event.
		 * Because the completion tag is expected to be the same in all
		 * data descriptors for a given packet, and a single packet can
		 * span multiple buffers, we need this field to track all
		 * buffers associated with this completion tag independently of
		 * the buf_id. The tag consists of a N bit buf_id and M upper
		 * order "generation bits". See compl_tag_bufid_m and
		 * compl_tag_gen_s in struct idpf_queue.
		 */
		u16 compl_tag;

		/* Legacy queue only: used to indicate the corresponding entry
		 * in the descriptor ring was used for a context descriptor and
		 * this buffer entry should be skipped.
		 */
		bool ctx_entry;
	};

};

struct idpf_tx_stash {
	struct hlist_node hlist;
	struct timer_list reinject_timer;
	struct idpf_tx_buf buf;
	struct idpf_queue *txq;
	/* Keep track of whether this packet was sent on the exception path
	 * either because the driver received a miss completion and is waiting
	 * on a reinject completion or because the driver received a reinject
	 * completion and is waiting on a follow up completion.
	 */
	bool miss_pkt;
};

struct idpf_buf_lifo {
	u16 top;
	u16 size;
	struct idpf_tx_stash **bufs;
};

struct idpf_tx_offload_params {
	u16 td_cmd;	/* command field to be inserted into descriptor */

#define IDPF_TX_FLAGS_TSO			BIT(0)
#define IDPF_TX_FLAGS_IPV4			BIT(1)
#define IDPF_TX_FLAGS_IPV6			BIT(2)
#define IDPF_TX_FLAGS_TUNNEL			BIT(3)
	u32 tx_flags;

	u32 tso_len;	/* total length of payload to segment */
	u16 mss;
	u8 tso_hdr_len;	/* length of headers to be duplicated */
	u16 tso_segs;   /* Number of segments to be sent */

	/* Flow scheduling offload timestamp, formatting as hw expects it */
	/* timestamp = bits[0:22], overflow = bit[23] */
	u8 desc_ts[3];

	/* For legacy offloads */
	u32 hdr_offsets;
	u32 cd_tunneling;
};

struct idpf_tx_splitq_params {
	/* Descriptor build function pointer */
	void (*splitq_build_ctb)(union idpf_tx_flex_desc *desc,
				 struct idpf_tx_splitq_params *params,
				 u16 td_cmd, u16 size);

	/* General descriptor info */
	enum idpf_tx_desc_dtype_value dtype;
	u16 eop_cmd;
	union {
		u16 compl_tag; /* only relevant for flow scheduling */
		u16 td_tag; /* only relevant for queue scheduling */
	};

	struct idpf_tx_offload_params offload;
};

enum idpf_tx_ctx_desc_eipt_offload {
	IDPF_TX_CTX_EXT_IP_NONE         = 0x0,
	IDPF_TX_CTX_EXT_IP_IPV6         = 0x1,
	IDPF_TX_CTX_EXT_IP_IPV4_NO_CSUM = 0x2,
	IDPF_TX_CTX_EXT_IP_IPV4         = 0x3
};

/* Checksum offload bits decoded from the receive descriptor. */
struct idpf_rx_csum_decoded {
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

struct idpf_rx_extracted {
	unsigned int size;
	u16 rx_ptype;
};

#define IDPF_TX_COMPLQ_CLEAN_BUDGET	256
#define IDPF_TX_MIN_LEN			17
#define IDPF_TX_DESCS_FOR_SKB_DATA_PTR	1
#define IDPF_TX_MAX_BUF			8
#define IDPF_TX_DESCS_PER_CACHE_LINE	4
#define IDPF_TX_DESCS_FOR_CTX		1
/* TX descriptors needed, worst case */
#define IDPF_TX_DESC_NEEDED (MAX_SKB_FRAGS + IDPF_TX_DESCS_FOR_CTX + \
			     IDPF_TX_DESCS_PER_CACHE_LINE + \
			     IDPF_TX_DESCS_FOR_SKB_DATA_PTR)

/* The size limit for a transmit buffer in a descriptor is (16K - 1).
 * In order to align with the read requests we will align the value to
 * the nearest 4K which represents our maximum read request size.
 */
#define IDPF_TX_MAX_READ_REQ_SIZE	SZ_4K
#define IDPF_TX_MAX_DESC_DATA		(SZ_16K - 1)
#define IDPF_TX_MAX_DESC_DATA_ALIGNED \
	ALIGN_DOWN(IDPF_TX_MAX_DESC_DATA, IDPF_TX_MAX_READ_REQ_SIZE)

#define IDPF_RX_DMA_ATTR \
	(DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)
#define IDPF_RX_DESC(R, i)	\
	(&(((union virtchnl2_rx_desc *)((R)->desc_ring))[i]))

struct idpf_page_info {
	dma_addr_t dma;
	struct page *page;
	unsigned int page_offset;
	u16 pagecnt_bias;
};

struct idpf_rx_hdr_buf_pages {
	u32 nr_pages;
	struct idpf_page_info *pages;
};

struct idpf_rx_buf {
#define IDPF_RX_BUF_MAX_PAGES 2
	struct idpf_page_info page_info[IDPF_RX_BUF_MAX_PAGES];
	u8 page_indx;
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
enum idpf_rx_ptype_l2 {
	IDPF_RX_PTYPE_L2_RESERVED	= 0,
	IDPF_RX_PTYPE_L2_MAC_PAY2	= 1,
	IDPF_RX_PTYPE_L2_TIMESYNC_PAY2	= 2,
	IDPF_RX_PTYPE_L2_FIP_PAY2	= 3,
	IDPF_RX_PTYPE_L2_OUI_PAY2	= 4,
	IDPF_RX_PTYPE_L2_MACCNTRL_PAY2	= 5,
	IDPF_RX_PTYPE_L2_LLDP_PAY2	= 6,
	IDPF_RX_PTYPE_L2_ECP_PAY2	= 7,
	IDPF_RX_PTYPE_L2_EVB_PAY2	= 8,
	IDPF_RX_PTYPE_L2_QCN_PAY2	= 9,
	IDPF_RX_PTYPE_L2_EAPOL_PAY2	= 10,
	IDPF_RX_PTYPE_L2_ARP		= 11,
};

enum idpf_rx_ptype_outer_ip {
	IDPF_RX_PTYPE_OUTER_L2	= 0,
	IDPF_RX_PTYPE_OUTER_IP	= 1,
};

enum idpf_rx_ptype_outer_ip_ver {
	IDPF_RX_PTYPE_OUTER_NONE	= 0,
	IDPF_RX_PTYPE_OUTER_IPV4	= 1,
	IDPF_RX_PTYPE_OUTER_IPV6	= 2,
};

enum idpf_rx_ptype_outer_fragmented {
	IDPF_RX_PTYPE_NOT_FRAG	= 0,
	IDPF_RX_PTYPE_FRAG	= 1,
};

enum idpf_rx_ptype_tunnel_type {
	IDPF_RX_PTYPE_TUNNEL_NONE		= 0,
	IDPF_RX_PTYPE_TUNNEL_IP_IP		= 1,
	IDPF_RX_PTYPE_TUNNEL_IP_GRENAT		= 2,
	IDPF_RX_PTYPE_TUNNEL_IP_GRENAT_MAC	= 3,
	IDPF_RX_PTYPE_TUNNEL_IP_GRENAT_MAC_VLAN	= 4,
};

enum idpf_rx_ptype_tunnel_end_prot {
	IDPF_RX_PTYPE_TUNNEL_END_NONE	= 0,
	IDPF_RX_PTYPE_TUNNEL_END_IPV4	= 1,
	IDPF_RX_PTYPE_TUNNEL_END_IPV6	= 2,
};

enum idpf_rx_ptype_inner_prot {
	IDPF_RX_PTYPE_INNER_PROT_NONE		= 0,
	IDPF_RX_PTYPE_INNER_PROT_UDP		= 1,
	IDPF_RX_PTYPE_INNER_PROT_TCP		= 2,
	IDPF_RX_PTYPE_INNER_PROT_SCTP		= 3,
	IDPF_RX_PTYPE_INNER_PROT_ICMP		= 4,
	IDPF_RX_PTYPE_INNER_PROT_TIMESYNC	= 5,
};

enum idpf_rx_ptype_payload_layer {
	IDPF_RX_PTYPE_PAYLOAD_LAYER_NONE	= 0,
	IDPF_RX_PTYPE_PAYLOAD_LAYER_PAY2	= 1,
	IDPF_RX_PTYPE_PAYLOAD_LAYER_PAY3	= 2,
	IDPF_RX_PTYPE_PAYLOAD_LAYER_PAY4	= 3,
};

struct idpf_rx_ptype_decoded {
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

enum idpf_rx_hsplit {
	IDPF_RX_NO_HDR_SPLIT = 0,
	IDPF_RX_HDR_SPLIT = 1,
};

/* The idpf_ptype_lkup table is used to convert from the 10-bit ptype in the
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
 * IF NOT idpf_ptype_lkup[ptype].known
 * THEN
 *      Packet is unknown
 * ELSE IF idpf_ptype_lkup[ptype].outer_ip == IDPF_RX_PTYPE_OUTER_IP
 *      Use the rest of the fields to look at the tunnels, inner protocols, etc
 * ELSE
 *      Use the enum idpf_rx_ptype_l2 to decode the packet type
 * ENDIF
 */
#define IDPF_RX_MAX_PTYPE	1024
#define IDPF_RX_MAX_BASE_PTYPE	256
#define IDPF_INT_NAME_STR_LEN	(IFNAMSIZ + 16)

/* Lookup table mapping the HW PTYPE to the bit field for decoding */

enum idpf_queue_flags_t {
	__IDPF_Q_GEN_CHK,
	__IDPF_RFLQ_GEN_CHK,
	__IDPF_Q_FLOW_SCH_EN,
	__IDPF_Q_ETF_EN,
	__IDPF_Q_SW_MARKER,
	__IDPF_Q_POLL_MODE,
#ifdef HAVE_XDP_SUPPORT
	__IDPF_Q_XDP,
#endif /* HAVE_XDP_SUPPORT */
	__IDPF_Q_FLAGS_NBITS,
};

struct idpf_vec_regs {
	u32 dyn_ctl_reg;
	u32 itrn_reg;
	u32 itrn_index_spacing;
};

struct idpf_intr_reg {
	u8 __iomem *dyn_ctl;
	u32 dyn_ctl_intena_m;
	u32 dyn_ctl_clrpba_m;
	u32 dyn_ctl_itridx_s;
	u32 dyn_ctl_itridx_m;
	u32 dyn_ctl_intrvl_s;
	u8 __iomem *rx_itr;
	u8 __iomem *tx_itr;
	u32 dyn_ctl_swint_trig_m;
	u32 dyn_ctl_sw_itridx_ena_m;
	u32 dyn_ctl_wb_on_itr_m;
	u8 __iomem *icr_ena;
	u32 icr_ena_ctlq_m;
};

struct idpf_q_vector {
	struct idpf_vport *vport;
	cpumask_t affinity_mask;
	struct napi_struct napi;
	u16 v_idx;		/* index in the vport->q_vector array */
	struct idpf_intr_reg intr_reg;

	int num_txq;
	struct idpf_queue **tx;
	struct dim tx_dim;	/* data for net_dim algorithm */
	u16 tx_itr_value;
	bool tx_intr_mode;
	u32 tx_itr_idx;

	int num_rxq;
	struct idpf_queue **rx;
	struct dim rx_dim;	/* data for net_dim algorithm */
	u16 rx_itr_value;
	bool rx_intr_mode;
	u32 rx_itr_idx;

	int num_bufq;
	struct idpf_queue **bufq;

	u16 total_events;       /* net_dim(): number of interrupts processed */
	char name[IDPF_INT_NAME_STR_LEN];
};

struct idpf_rx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 rsc_pkts;
	u64 hw_csum_err;
	u64 hsplit_pkts;
	u64 hsplit_buf_ovf;
	u64 bad_descs;
};

struct idpf_tx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 lso_pkts;
	u64 linearize;
	u64 q_busy;
	u64 skb_drops;
	u64 dma_errs;
};

union idpf_queue_stats {
	struct idpf_rx_queue_stats rx;
	struct idpf_tx_queue_stats tx;
};

#define IDPF_ITR_DYNAMIC	1
#define IDPF_ITR_MAX		0x1FE0
#define IDPF_ITR_20K		0x0032
#define IDPF_ITR_GRAN_S		1	/* Assume ITR granularity is 2us */
#define IDPF_ITR_MASK		0x1FFE	/* ITR register value alignment mask */
#define ITR_REG_ALIGN(setting)	((setting) & IDPF_ITR_MASK)
#define IDPF_ITR_IS_DYNAMIC(itr_mode) (itr_mode)
#define IDPF_ITR_TX_DEF		IDPF_ITR_20K
#define IDPF_ITR_RX_DEF		IDPF_ITR_20K
#define IDPF_NO_ITR_UPDATE_IDX	3
#define IDPF_ITR_IDX_SPACING(spacing, dflt)	(spacing ? spacing : dflt)

/* queue associated with a vport */
struct idpf_queue {
	struct device *dev;		/* Used for DMA mapping */
	struct idpf_vport *vport;	/* Backreference to associated vport */
	union {
		struct idpf_txq_group *txq_grp;
		struct idpf_rxq_group *rxq_grp;
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
		struct idpf_tx_buf *tx_buf;
		struct {
			struct idpf_rx_buf *buf;
			struct idpf_dma_mem **hdr_buf;
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
	DECLARE_BITMAP(flags, __IDPF_Q_FLAGS_NBITS);

	union idpf_queue_stats q_stats;
	struct u64_stats_sync stats_sync;

	/* Splitq only, TXQ only: When a TX completion is received on the TX
	 * completion queue, it can be for any TXQ associated with that
	 * completion queue. This means we can clean up to N TXQs during a
	 * single call to clean the completion queue. cleaned_bytes|pkts tracks
	 * the clean stats per TXQ during that single call to clean the
	 * completion queue. By doing so, we can update BQL with aggregate
	 * cleaned stats for each TXQ only once at the end of the cleaning
	 * routine.
	 */
	u32 cleaned_bytes;
	u16 cleaned_pkts;

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
	struct idpf_q_vector *q_vector;	/* Backreference to associated vector */
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

	u16 tx_max_bufs;		/* Max buffers that can be transmitted
					 * with scatter-gather
					 */
	u8 tx_min_pkt_len;		/* Min supported packet length */

	u64 num_completions;		/* Only relevant for tx completion
					 * queue; tracks the number of
					 * completions received to compare
					 * against the number of completions
					 * pending, as accumulated by the TXQs
					 */

	/* Flow based scheduling related fields only */
	struct idpf_buf_lifo buf_stack; /* Stack of empty buffers to store
					 * buffer info for out of order
					 * buffer completions
					 */

	/* The format of the completion tag will change based on the TXQ
	 * descriptor ring size so that we can maintain roughly the same level
	 * of "uniqueness" across all descriptor sizes. For example, if the
	 * TXQ descriptor ring size is 64 (the minimum size supported), the
	 * completion tag will be formatted as below:
	 * 15                 6 5         0
	 * --------------------------------
	 * |    GEN=0-1023     |IDX = 0-63|
	 * --------------------------------
	 *
	 * This gives us 64*1024 = 65536 possible unique values. Similarly, if
	 * the TXQ descriptor ring size is 8160 (the maximum size supported),
	 * the completion tag will be formatted as below:
	 * 15 13 12                       0
	 * --------------------------------
	 * |GEN |       IDX = 0-8159      |
	 * --------------------------------
	 *
	 * This gives us 8*8160 = 65280 possible unique values. However,
	 * because we are using 0xFFFF to represent an invalid tag, we lose one
	 * generation.
	 */
	u16 compl_tag_bufid_m;
	u16 compl_tag_gen_s;
#define IDPF_SPLITQ_TX_INVAL_COMPL_TAG 0xFFFF

	/* compl_tag_cur_gen keeps track of the current completion tag generation,
	 * whereas compl_tag_gen_max determines when compl_tag_cur_gen should be
	 * reset.
	 */
	u16 compl_tag_cur_gen;
	u16 compl_tag_gen_max;

	DECLARE_HASHTABLE(sched_buf_hash, 12);

	struct idpf_rx_hdr_buf_pages hbuf_pages;
} ____cacheline_internodealigned_in_smp;

/* Software queues are used in splitq mode to manage buffers between rxq
 * producer and the bufq consumer.  These are required in order to maintain a
 * lockless buffer management system and are strictly software only constructs.
 */
struct idpf_sw_queue {
	u16 next_to_clean ____cacheline_aligned_in_smp;
	u16 next_to_alloc ____cacheline_aligned_in_smp;
	u16 next_to_use ____cacheline_aligned_in_smp;
	DECLARE_BITMAP(flags, __IDPF_Q_FLAGS_NBITS)
		____cacheline_aligned_in_smp;
	u16 *ring ____cacheline_aligned_in_smp;
	u16 desc_count;
	u16 buf_size;
	struct device *dev;
} ____cacheline_internodealigned_in_smp;

/* Splitq only.  idpf_rxq_set associates an rxq with at an array of refillqs.
 * Each rxq needs a refillq to return used buffers back to the respective bufq.
 * Bufqs then clean these refillqs for buffers to give to hardware.
 */
struct idpf_rxq_set {
	struct idpf_queue rxq;
	/* refillqs assoc with bufqX mapped to this rxq */
	struct idpf_sw_queue *refillq0;
	struct idpf_sw_queue *refillq1;
};

/* Splitq only.  idpf_bufq_set associates a bufq to an array of refillqs.
 * In this bufq_set, there will be one refillq for each rxq in this rxq_group.
 * Used buffers received by rxqs will be put on refillqs which bufqs will
 * clean to return new buffers back to hardware.
 *
 * Buffers needed by some number of rxqs associated in this rxq_group are
 * managed by at most two bufqs (depending on performance configuration).
 */
struct idpf_bufq_set {
	struct idpf_queue bufq;
	/* This is always equal to num_rxq_sets in idpf_rxq_group */
	int num_refillqs;
	struct idpf_sw_queue *refillqs;
};

/* In singleq mode, an rxq_group is simply an array of rxqs.  In splitq, a
 * rxq_group contains all the rxqs, bufqs and refillqs needed to
 * manage buffers in splitq mode.
 */
struct idpf_rxq_group {
	struct idpf_vport *vport; /* back pointer */

	union {
		struct {
			int num_rxq;
			/* store queue pointers */
			struct idpf_queue *rxqs[IDPF_LARGE_MAX_Q];
		} singleq;
		struct {
			int num_rxq_sets;
			/* store queue pointers */
			struct idpf_rxq_set *rxq_sets[IDPF_LARGE_MAX_Q];
			struct idpf_bufq_set *bufq_sets;
		} splitq;
	};
};

/* Between singleq and splitq, a txq_group is largely the same except for the
 * complq.  In splitq a single complq is responsible for handling completions
 * for some number of txqs associated in this txq_group.
 */
struct idpf_txq_group {
	struct idpf_vport *vport; /* back pointer */

	int num_txq;
	/* store queue pointers */
	struct idpf_queue *txqs[IDPF_LARGE_MAX_Q];

	/* splitq only */
	struct idpf_queue *complq;

	/* Total number of completions pending for the completion queue,
	 * acculumated for all txqs associated with that completion queue
	 */
	u64 num_completions_pending;
};

/**
 * idpf_size_to_txd_count - Get the number of descriptors needed for Tx
 * @size: transmit request size in bytes
 *
 * Due to hardware alignment restrictions (4K alignment), we need to assume
 * that we can have no more than 12K of data per descriptor, even though each
 * descriptor can take up to 16K - 1 bytes of aligned memory.
 */
static inline unsigned int idpf_size_to_txd_count(unsigned int size)
{
	return DIV_ROUND_UP(size, IDPF_TX_MAX_DESC_DATA_ALIGNED);
}


/**
 * idpf_tx_singleq_build_ctob - populate command tag offset and size
 * @td_cmd: Command to be filled in desc
 * @td_offset: Offset to be filled in desc
 * @size: Size of the buffer
 * @td_tag: td tag to be filled
 *
 * Returns the 64 bit value populated with the input parameters
 */
static inline __le64
idpf_tx_singleq_build_ctob(u64 td_cmd, u64 td_offset, unsigned int size,
			   u64 td_tag)
{
	return cpu_to_le64(IDPF_TX_DESC_DTYPE_DATA |
			   (td_cmd    << IDPF_TXD_QW1_CMD_S) |
			   (td_offset << IDPF_TXD_QW1_OFFSET_S) |
			   ((u64)size << IDPF_TXD_QW1_TX_BUF_SZ_S) |
			   (td_tag    << IDPF_TXD_QW1_L2TAG1_S));
}

void idpf_tx_splitq_build_ctb(union idpf_tx_flex_desc *desc,
			      struct idpf_tx_splitq_params *parms,
			      u16 td_cmd, u16 size);
void idpf_tx_splitq_build_flow_desc(union idpf_tx_flex_desc *desc,
				    struct idpf_tx_splitq_params *parms,
				    u16 td_cmd, u16 size);
int idpf_vport_singleq_napi_poll(struct napi_struct *napi, int budget);
void idpf_vport_init_num_qs(struct idpf_vport *vport,
			    struct virtchnl2_create_vport *vport_msg);
void idpf_vport_calc_num_q_desc(struct idpf_vport *vport);
int idpf_vport_calc_total_qs(struct idpf_adapter *adapter, u16 vport_index,
			     struct virtchnl2_create_vport *vport_msg,
			     struct idpf_vport_max_q *max_q);
void idpf_vport_calc_num_q_groups(struct idpf_vport *vport);
int idpf_vport_queues_alloc(struct idpf_vport *vport);
void idpf_rx_post_buf_refill(struct idpf_sw_queue *refillq, u16 buf_id);
void idpf_vport_queues_rel(struct idpf_vport *vport);
void idpf_vport_calc_q_vec_base(struct idpf_adapter *adapter,
				struct idpf_vport *vport);
void idpf_vport_intr_rel(struct idpf_vport *vport);
int idpf_vport_intr_alloc(struct idpf_vport *vport);
void idpf_vport_intr_dis_irq_all(struct idpf_vport *vport);
void idpf_vport_intr_clear_dflt_itr(struct idpf_vport *vport);
void idpf_vport_intr_update_itr_ena_irq(struct idpf_q_vector *q_vector);
void idpf_vport_intr_deinit(struct idpf_vport *vport);
int idpf_vport_intr_init(struct idpf_vport *vport);
irqreturn_t
idpf_vport_intr_clean_queues(int __always_unused irq, void *data);
void idpf_vport_intr_ena_irq_all(struct idpf_vport *vport);
enum
pkt_hash_types idpf_ptype_to_htype(struct idpf_rx_ptype_decoded *decoded);
int idpf_config_rss(struct idpf_vport *vport);
void idpf_fill_dflt_rss_lut(struct idpf_vport *vport);
int idpf_init_rss(struct idpf_vport *vport);
void idpf_deinit_rss(struct idpf_vport *vport);
bool idpf_rx_can_reuse_page(struct idpf_rx_buf *rx_buf);
void idpf_rx_buf_adjust_pg(struct idpf_rx_buf *rx_buf, unsigned int size);
void idpf_rx_add_frag(struct idpf_rx_buf *rx_buf, struct sk_buff *skb,
		      unsigned int size);
struct sk_buff *idpf_rx_construct_skb(struct idpf_queue *rxq,
				      struct idpf_rx_buf *rx_buf,
				      unsigned int size);
bool idpf_init_rx_buf_hw_alloc(struct idpf_queue *rxq, struct idpf_rx_buf *buf);
void idpf_rx_buf_hw_update(struct idpf_queue *rxq, u32 val);
void idpf_tx_buf_hw_update(struct idpf_queue *tx_q, u32 val,
			   bool xmit_more);
void idpf_rx_splitq_put_bufs(struct idpf_queue *rx_bufq,
			     struct idpf_rx_buf *hdr_buf,
			     struct idpf_rx_buf *rx_buf);
bool idpf_rx_splitq_test_staterr(u8 stat_err_field, const u8 stat_err_bits);
bool idpf_rx_singleq_test_staterr(union virtchnl2_rx_desc *rx_desc,
				  const u64 stat_err_bits);
int idpf_rx_process_skb_fields(struct idpf_queue *rxq, struct sk_buff *skb,
			       struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc);
void idpf_rx_singleq_process_skb_fields(struct idpf_queue *rx_q, struct sk_buff *skb,
					union virtchnl2_rx_desc *rx_desc, u16 ptype);
void idpf_rx_singleq_extract_fields(struct idpf_queue *rx_q,
				    union virtchnl2_rx_desc *rx_desc,
				    struct idpf_rx_extracted *fields);
void idpf_rx_singleq_bump_ntc(struct idpf_queue *q);
bool idpf_rx_singleq_is_non_eop(struct idpf_queue *rxq,
				union virtchnl2_rx_desc *rx_desc,
				struct sk_buff *skb);
#ifdef HAVE_XDP_FRAME_STRUCT
int idpf_xmit_xdpq(struct xdp_frame *xdp, struct idpf_queue *xdpq);
#else
int idpf_xmit_xdpq(struct xdp_buff *xdp, struct idpf_queue *xdpq);
#endif /* HAVE_XDP_FRAME_STRUCT */
void idpf_rx_bump_ntc(struct idpf_queue *q);
void idpf_tx_buf_rel(struct idpf_queue *tx_q, struct idpf_tx_buf *tx_buf);
unsigned int idpf_size_to_txd_count(unsigned int size);
netdev_tx_t idpf_tx_drop_skb(struct idpf_queue *tx_q, struct sk_buff *skb);
void idpf_tx_dma_map_error(struct idpf_queue *txq, struct sk_buff *skb,
			   struct idpf_tx_buf *first, u16 ring_idx);
unsigned int idpf_tx_desc_count_required(struct sk_buff *skb);
bool idpf_chk_linearize(struct sk_buff *skb, unsigned int max_bufs,
			unsigned int count);
int idpf_tx_maybe_stop_common(struct idpf_queue *tx_q, unsigned int size);
#ifdef HAVE_TX_TIMEOUT_TXQUEUE
void idpf_tx_timeout(struct net_device *netdev,
		     unsigned int __always_unused txqueue);
#else
void idpf_tx_timeout(struct net_device *netdev);
#endif /* HAVE_TX_TIMEOUT_TXQUEUE */
netdev_tx_t idpf_tx_splitq_start(struct sk_buff *skb,
				 struct net_device *netdev);
netdev_tx_t idpf_tx_singleq_start(struct sk_buff *skb,
				  struct net_device *netdev);
#ifdef IDPF_ADD_PROBES
void idpf_tx_extra_counters(struct idpf_queue *txq, struct idpf_tx_buf *skb,
			    struct idpf_tx_offload_params *off);
void idpf_rx_extra_counters(struct idpf_queue *rxq, u32 inner_prot,
			    bool ipv4, struct idpf_rx_csum_decoded *csum_bits,
			    bool splitq);
#endif /* IDPF_ADD_PROBES */
bool idpf_rx_singleq_buf_hw_alloc_all(struct idpf_queue *rxq,
				      u16 cleaned_count);
#ifdef HAVE_VOID_NDO_GET_STATS64
void idpf_get_stats64(struct net_device *netdev,
		      struct rtnl_link_stats64 *stats);
#else /* HAVE_VOID_NDO_GET_STATS64 */
struct rtnl_link_stats64 *idpf_get_stats64(struct net_device *netdev,
					   struct rtnl_link_stats64 *stats);
#endif /* HAVE_VOID_NDO_GET_STATS64 */
#ifdef HAVE_XDP_SUPPORT
int idpf_rx_xdp(struct idpf_queue *rxq, struct idpf_queue *xdpq,
		struct idpf_rx_buf *rx_buf, unsigned int size);
INDIRECT_CALLABLE_DECLARE(void *idpf_prepare_xdp_tx_splitq_desc(struct idpf_queue *xdpq,
								dma_addr_t dma, u16 idx,
								u32 size));
void *idpf_prepare_xdp_tx_splitq_desc(struct idpf_queue *xdpq, dma_addr_t dma,
				      u16 idx, u32 size);

INDIRECT_CALLABLE_DECLARE(void *idpf_prepare_xdp_tx_singleq_desc(struct idpf_queue *xdpq,
								 dma_addr_t dma, u16 idx,
								 u32 size));
void *idpf_prepare_xdp_tx_singleq_desc(struct idpf_queue *xdpq, dma_addr_t dma,
				       u16 idx, u32 size);
int idpf_xdp_rxq_init(struct idpf_queue *q);
#endif /* HAVE_XDP_SUPPORT */
int idpf_tso(struct sk_buff *skb, struct idpf_tx_offload_params *off);

#ifdef HAVE_XDP_SUPPORT
/**
 * idpf_xdpq_update_tail - Updates the XDP Tx queue tail register
 * @xdpq: XDP Tx queue
 *
 * This function updates the XDP Tx queue tail register.
 */
static inline void idpf_xdpq_update_tail(struct idpf_queue *xdpq)
{
	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.
	 */
	wmb();
	writel_relaxed(xdpq->next_to_use, xdpq->tail);
}

/**
 * idpf_finalize_xdp_rx - Bump XDP Tx tail and/or flush redirect map
 * @xdpq: XDP Tx queue
 * @xdp_res: Result of the receive batch
 *
 * This function bumps XDP Tx tail and/or flush redirect map, and
 * should be called when a batch of packets has been processed in the
 * napi loop.
 */
static inline void idpf_finalize_xdp_rx(struct idpf_queue *xdpq, unsigned int xdp_res)
{
	if (xdp_res & IDPF_XDP_REDIR)
		xdp_do_flush_map();

	if (xdp_res & IDPF_XDP_TX)
		idpf_xdpq_update_tail(xdpq);
}
#endif /* HAVE_XDP_SUPPORT */
#endif /* !_IDPF_TXRX_H_ */
