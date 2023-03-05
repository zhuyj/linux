/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019 Intel Corporation */

#ifndef _IECM_H_
#define _IECM_H_

#include "kcompat.h"
#include <net/pkt_sched.h>
#ifdef __TC_MQPRIO_MODE_MAX
#include <net/pkt_cls.h>
#endif /* __TC_MQPRIO_MODE_MAX */
#include <linux/aer.h>
#include <linux/pci.h>
#include <linux/sctp.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <net/tcp.h>
#include <net/ip6_checksum.h>
#include <net/ipv6.h>
#include <net/sch_generic.h>

#include <net/gro.h>

#ifdef HAVE_XDP_SUPPORT
#include <linux/bpf_trace.h>
#endif /* HAVE_XDP_SUPPORT */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
#include <net/xdp_sock_drv.h>
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

#ifdef HAVE_VXLAN_RX_OFFLOAD
#if IS_ENABLED(CONFIG_VXLAN)
#include <net/vxlan.h>
#endif
#endif /* HAVE_VXLAN_RX_OFFLOAD */
#ifdef HAVE_GRE_ENCAP_OFFLOAD
#include <net/gre.h>
#endif /* HAVE_GRE_ENCAP_OFFLOAD */
#ifdef HAVE_GENEVE_RX_OFFLOAD
#if IS_ENABLED(CONFIG_GENEVE)
#include <net/geneve.h>
#endif
#endif /* HAVE_GENEVE_RX_OFFLOAD */
#ifdef HAVE_UDP_ENC_RX_OFFLOAD
#include <net/udp_tunnel.h>
#endif
#ifdef HAVE_XDP_SUPPORT
#include <linux/filter.h>
#include <linux/bpf.h>
#endif /* HAVE_XDP_SUPPORT */

#include "kcompat.h"
#ifdef HAVE_CONFIG_DIMLIB
#include <linux/dim.h>
#else
#include "kcompat_dim.h"
#endif /* HAVE_CONFIG_DIMLIB */

#include "iecm_lan_txrx.h"

#include "virtchnl_2.h"
#include "iecm_txrx.h"
#include "iecm_controlq.h"
#ifdef HAVE_NETDEV_BPF_XSK_POOL
#include "iecm_xsk.h"
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

#define IECM_BAR0			0
#define IECM_NO_FREE_SLOT		0xffff

/* Default Mailbox settings */
#define IECM_DFLT_MBX_BUF_SIZE		(4 * 1024)
#define IECM_NUM_QCTX_PER_MSG		3
#define IECM_NUM_FILTERS_PER_MSG	20
#define IECM_VLANS_PER_MSG \
	((IECM_DFLT_MBX_BUF_SIZE - sizeof(struct virtchnl_vlan_filter_list)) \
	 / sizeof(u16))
#define IECM_DFLT_MBX_Q_LEN		64
#define IECM_DFLT_MBX_ID		-1
/* maximum number of times to try before resetting mailbox */
#define IECM_MB_MAX_ERR			20
#define IECM_NUM_CHUNKS_PER_MSG(a, b)	((IECM_DFLT_MBX_BUF_SIZE - (a)) / (b))

/* 2K is the real maximum, but the driver should not be using more than the
 * below limit
 */
#define IECM_MAX_VECIDS			256

#define IECM_MAX_NUM_VPORTS		1

/* available message levels */
#define IECM_AVAIL_NETIF_M (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)

#define IECM_MBPS_DIVISOR		125000 /* divisor to convert to Mbps */

#define IECM_VIRTCHNL_VERSION_MAJOR VIRTCHNL_VERSION_MAJOR_2
#define IECM_VIRTCHNL_VERSION_MINOR VIRTCHNL_VERSION_MINOR_0

/* Forward declaration */
struct iecm_adapter;

struct iecm_mac_filter {
	struct list_head list;
	u8 macaddr[ETH_ALEN];
	bool remove;		/* filter needs to be removed */
	bool add;		/* filter needs to be added */
};

#define IECM_VLAN(vid, tpid) ((struct iecm_vlan){ vid, tpid })

struct iecm_vlan {
	u16 vid;
	u16 tpid;
};

struct iecm_vlan_filter {
	struct list_head list;
	struct iecm_vlan vlan;
	bool remove;		/* filter needs to be removed */
	bool add;		/* filter needs to be added */
};

enum iecm_state {
	__IECM_STARTUP,
	__IECM_VER_CHECK,
	__IECM_GET_CAPS,
	__IECM_GET_DFLT_VPORT_PARAMS,
	__IECM_INIT_SW,
	__IECM_DOWN,
	__IECM_UP,
	__IECM_STATE_LAST /* this member MUST be last */
};

enum iecm_flags {
	/* Soft reset causes */
	__IECM_SR_Q_CHANGE, /* Soft reset to do queue change */
	__IECM_SR_Q_DESC_CHANGE,
	__IECM_SR_Q_SCH_CHANGE, /* Scheduling mode change in queue context */
	__IECM_SR_MTU_CHANGE,
	__IECM_SR_TC_CHANGE,
	__IECM_SR_RSC_CHANGE,
	__IECM_SR_HSPLIT_CHANGE,
	/* Hard reset causes */
	__IECM_HR_FUNC_RESET, /* Hard reset when txrx timeout */
	__IECM_HR_CORE_RESET, /* when reset event is received on virtchannel */
	__IECM_HR_DRV_LOAD, /* Set on driver load for a clean HW */
	/* Reset in progress */
	__IECM_HR_RESET_IN_PROG,
	/* Resources release in progress*/
	__IECM_REL_RES_IN_PROG,
	/* Generic bits to share a message */
	__IECM_DEL_QUEUES,
	__IECM_UP_REQUESTED, /* Set if open to be called explicitly by driver */
	/* Mailbox interrupt event */
	__IECM_MB_INTR_MODE,
	__IECM_MB_INTR_TRIGGER,
	/* Stats message pending on mailbox */
	__IECM_MB_STATS_PENDING,
	/* Device specific bits */
	/* Request split queue model when creating vport */
	__IECM_REQ_TX_SPLITQ,
	__IECM_REQ_RX_SPLITQ,
	/* Asynchronous add/del ether address in flight */
	__IECM_ADD_ETH_REQ,
	__IECM_DEL_ETH_REQ,
	/* Virtchnl message buffer received needs to be processed */
	__IECM_VC_MSG_PENDING,
	/* To process software marker packets */
	__IECM_SW_MARKER,
	/* Do not schedule service task if bit is set */
	__IECM_CANCEL_SERVICE_TASK,
	/* Do not schedule stats task if bit is set */
	__IECM_CANCEL_STATS_TASK,
	/* Driver remove in progress */
	__IECM_REMOVE_IN_PROG,
	/* Add queues is initiated */
	__IECM_ADD_QUEUES,
	/* must be last */
	__IECM_FLAGS_NBITS,
};

/* enum used to distinquish which capability field to check */
enum iecm_cap_field {
	IECM_BASE_CAPS		= -1,
	IECM_CSUM_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   csum_caps),
	IECM_SEG_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   seg_caps),
	IECM_RSS_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   rss_caps),
	IECM_HSPLIT_CAPS	= offsetof(struct virtchnl2_get_capabilities,
					   hsplit_caps),
	IECM_RSC_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   rsc_caps),
	IECM_OTHER_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   other_caps),
	IECM_CAP_FIELD_LAST,
};

struct iecm_netdev_priv {
	struct iecm_vport *vport;
};

struct iecm_reset_reg {
	u32 rstat;
	u32 rstat_m;
};

/* product specific register API */
struct iecm_reg_ops {
	void (*ctlq_reg_init)(struct iecm_ctlq_create_info *cq);
	int (*intr_reg_init)(struct iecm_vport *vport);
	void (*mb_intr_reg_init)(struct iecm_adapter *adapter);
	void (*reset_reg_init)(struct iecm_reset_reg *reset_reg);
	void (*trigger_reset)(struct iecm_adapter *adapter,
			      enum iecm_flags trig_cause);
	u64 (*read_master_time)(struct iecm_hw *hw);
};

struct iecm_virtchnl_ops {
	int (*core_init)(struct iecm_adapter *adapter, int *vport_id);
	void (*vport_init)(struct iecm_vport *vport, int vport_id);
	int (*vport_queue_ids_init)(struct iecm_vport *vport);
	int (*get_caps)(struct iecm_adapter *adapter);
	int (*config_queues)(struct iecm_vport *vport);
	int (*enable_queues)(struct iecm_vport *vport);
	int (*disable_queues)(struct iecm_vport *vport);
	int (*add_queues)(struct iecm_vport *vport, u16 num_tx_q,
			  u16 num_complq, u16 num_rx_q,
			  u16 num_rx_bufq);
	int (*delete_queues)(struct iecm_vport *vport);
	int (*irq_map_unmap)(struct iecm_vport *vport, bool map);
	int (*enable_vport)(struct iecm_vport *vport);
	int (*disable_vport)(struct iecm_vport *vport);
	int (*destroy_vport)(struct iecm_vport *vport);
	int (*get_ptype)(struct iecm_vport *vport);
	int (*get_set_rss_key)(struct iecm_vport *vport, bool get);
	int (*get_set_rss_lut)(struct iecm_vport *vport, bool get);
	int (*get_set_rss_hash)(struct iecm_vport *vport, bool get);
	void (*adjust_qs)(struct iecm_vport *vport);
	int (*recv_mbx_msg)(struct iecm_adapter *adapter,
			    void *msg, int msg_size,
			    struct iecm_ctlq_msg *ctlq_msg, bool *work_done);
	bool (*is_cap_ena)(struct iecm_adapter *adapter, bool all,
			   enum iecm_cap_field field, u64 flag);
	u16 (*get_reserved_vecs)(struct iecm_adapter *adapter);
	void (*add_del_vlans)(struct iecm_vport *vport, bool add);
	int (*strip_vlan_msg)(struct iecm_vport *vport, bool ena);
	int (*insert_vlan_msg)(struct iecm_vport *vport, bool ena);
	void (*init_max_queues)(struct iecm_adapter *adapter);
	unsigned int (*get_max_tx_bufs)(struct iecm_adapter *adapter);
	int (*vportq_reg_init)(struct iecm_vport *vport);
	int (*alloc_vectors)(struct iecm_adapter *adapter, u16 num_vectors);
	int (*dealloc_vectors)(struct iecm_adapter *adapter);
	int (*get_supported_desc_ids)(struct iecm_vport *vport);
	int (*get_stats_msg)(struct iecm_vport *vport);
};

struct iecm_dev_ops {
	void (*reg_ops_init)(struct iecm_adapter *adapter);
	void (*vc_ops_init)(struct iecm_adapter *adapter);
	void (*crc_enable)(u64 *td_cmd);
	struct iecm_reg_ops reg_ops;
	struct iecm_virtchnl_ops vc_ops;
};

/* These macros allow us to generate an enum and a matching char * array of
 * stringified enums that are always in sync. Checkpatch issues a bogus warning
 * about this being a complex macro; but it's wrong, these are never used as a
 * statement and instead only used to define the enum and array.
 */
#define IECM_FOREACH_VPORT_VC_STATE(STATE)	\
	STATE(IECM_VC_ENA_VPORT)		\
	STATE(IECM_VC_ENA_VPORT_ERR)		\
	STATE(IECM_VC_DIS_VPORT)		\
	STATE(IECM_VC_DIS_VPORT_ERR)		\
	STATE(IECM_VC_DESTROY_VPORT)		\
	STATE(IECM_VC_DESTROY_VPORT_ERR)	\
	STATE(IECM_VC_CONFIG_TXQ)		\
	STATE(IECM_VC_CONFIG_TXQ_ERR)		\
	STATE(IECM_VC_CONFIG_RXQ)		\
	STATE(IECM_VC_CONFIG_RXQ_ERR)		\
	STATE(IECM_VC_CONFIG_Q)			\
	STATE(IECM_VC_CONFIG_Q_ERR)		\
	STATE(IECM_VC_ENA_QUEUES)		\
	STATE(IECM_VC_ENA_QUEUES_ERR)		\
	STATE(IECM_VC_DIS_QUEUES)		\
	STATE(IECM_VC_DIS_QUEUES_ERR)		\
	STATE(IECM_VC_ENA_CHANNELS)		\
	STATE(IECM_VC_ENA_CHANNELS_ERR)		\
	STATE(IECM_VC_DIS_CHANNELS)		\
	STATE(IECM_VC_DIS_CHANNELS_ERR)		\
	STATE(IECM_VC_MAP_IRQ)			\
	STATE(IECM_VC_MAP_IRQ_ERR)		\
	STATE(IECM_VC_UNMAP_IRQ)		\
	STATE(IECM_VC_UNMAP_IRQ_ERR)		\
	STATE(IECM_VC_ADD_QUEUES)		\
	STATE(IECM_VC_ADD_QUEUES_ERR)		\
	STATE(IECM_VC_DEL_QUEUES)		\
	STATE(IECM_VC_REQUEST_QUEUES)		\
	STATE(IECM_VC_REQUEST_QUEUES_ERR)	\
	STATE(IECM_VC_DEL_QUEUES_ERR)		\
	STATE(IECM_VC_ALLOC_VECTORS)		\
	STATE(IECM_VC_ALLOC_VECTORS_ERR)	\
	STATE(IECM_VC_DEALLOC_VECTORS)		\
	STATE(IECM_VC_DEALLOC_VECTORS_ERR)	\
	STATE(IECM_VC_SET_SRIOV_VFS)		\
	STATE(IECM_VC_SET_SRIOV_VFS_ERR)	\
	STATE(IECM_VC_GET_RSS_HASH)		\
	STATE(IECM_VC_GET_RSS_HASH_ERR)		\
	STATE(IECM_VC_SET_RSS_HASH)		\
	STATE(IECM_VC_SET_RSS_HASH_ERR)		\
	STATE(IECM_VC_GET_RSS_LUT)		\
	STATE(IECM_VC_GET_RSS_LUT_ERR)		\
	STATE(IECM_VC_SET_RSS_LUT)		\
	STATE(IECM_VC_SET_RSS_LUT_ERR)		\
	STATE(IECM_VC_GET_RSS_KEY)		\
	STATE(IECM_VC_GET_RSS_KEY_ERR)		\
	STATE(IECM_VC_SET_RSS_KEY)		\
	STATE(IECM_VC_SET_RSS_KEY_ERR)		\
	STATE(IECM_VC_GET_STATS)		\
	STATE(IECM_VC_GET_STATS_ERR)		\
	STATE(IECM_VC_ENA_STRIP_VLAN_TAG)	\
	STATE(IECM_VC_ENA_STRIP_VLAN_TAG_ERR)	\
	STATE(IECM_VC_DIS_STRIP_VLAN_TAG)	\
	STATE(IECM_VC_DIS_STRIP_VLAN_TAG_ERR)	\
	STATE(IECM_VC_IWARP_IRQ_MAP_UNMAP)	\
	STATE(IECM_VC_IWARP_IRQ_MAP_UNMAP_ERR)	\
	STATE(IECM_VC_IWARP_SEND_SYNC)		\
	STATE(IECM_VC_IWARP_SEND_SYNC_ERR)	\
	STATE(IECM_VC_ADD_ETH_ADDR)		\
	STATE(IECM_VC_ADD_ETH_ADDR_ERR)		\
	STATE(IECM_VC_DEL_ETH_ADDR)		\
	STATE(IECM_VC_DEL_ETH_ADDR_ERR)		\
	STATE(IECM_VC_PROMISC)			\
	STATE(IECM_VC_ADD_CLOUD_FILTER)		\
	STATE(IECM_VC_ADD_CLOUD_FILTER_ERR)	\
	STATE(IECM_VC_DEL_CLOUD_FILTER)		\
	STATE(IECM_VC_DEL_CLOUD_FILTER_ERR)	\
	STATE(IECM_VC_ADD_RSS_CFG)		\
	STATE(IECM_VC_ADD_RSS_CFG_ERR)		\
	STATE(IECM_VC_DEL_RSS_CFG)		\
	STATE(IECM_VC_DEL_RSS_CFG_ERR)		\
	STATE(IECM_VC_ADD_FDIR_FILTER)		\
	STATE(IECM_VC_ADD_FDIR_FILTER_ERR)	\
	STATE(IECM_VC_DEL_FDIR_FILTER)		\
	STATE(IECM_VC_DEL_FDIR_FILTER_ERR)	\
	STATE(IECM_VC_OFFLOAD_VLAN_V2_CAPS)	\
	STATE(IECM_VC_OFFLOAD_VLAN_V2_CAPS_ERR)	\
	STATE(IECM_VC_INSERTION_ENA_VLAN_V2)	\
	STATE(IECM_VC_INSERTION_ENA_VLAN_V2_ERR)\
	STATE(IECM_VC_INSERTION_DIS_VLAN_V2)	\
	STATE(IECM_VC_INSERTION_DIS_VLAN_V2_ERR)\
	STATE(IECM_VC_STRIPPING_ENA_VLAN_V2)	\
	STATE(IECM_VC_STRIPPING_ENA_VLAN_V2_ERR)\
	STATE(IECM_VC_STRIPPING_DIS_VLAN_V2)	\
	STATE(IECM_VC_STRIPPING_DIS_VLAN_V2_ERR)\
	STATE(IECM_VC_GET_SUPPORTED_RXDIDS)	\
	STATE(IECM_VC_GET_SUPPORTED_RXDIDS_ERR)	\
	STATE(IECM_VC_GET_PTYPE_INFO)		\
	STATE(IECM_VC_GET_PTYPE_INFO_ERR)	\
	STATE(IECM_VC_NBITS)

#define IECM_GEN_ENUM(ENUM) ENUM,
#define IECM_GEN_STRING(STRING) #STRING,

enum iecm_vport_vc_state {
	IECM_FOREACH_VPORT_VC_STATE(IECM_GEN_ENUM)
};

extern const char * const iecm_vport_vc_state_str[];

enum iecm_vport_flags {
	/* To control packet inspection based optimization */
	__IECM_VPORT_ADQ_CHNL_PKT_OPT_ENA,
	__IECM_VPORT_FLAGS_NBITS,
};

enum iecm_tw_tstamp_granularity {
	IECM_TW_TIME_STAMP_GRAN_512_DIV_S = 9,
	IECM_TW_TIME_STAMP_GRAN_1024_DIV_S = 10,
	IECM_TW_TIME_STAMP_GRAN_2048_DIV_S = 11,
	IECM_TW_TIME_STAMP_GRAN_4096_DIV_S = 12,
};

/* Horizon value in nanoseconds (MS * 1024 * 1024)*/
enum iecm_tw_horizon {
	IECM_TW_HORIZON_32MS = 32 << 20,
	IECM_TW_HORIZON_128MS = 128 << 20,
	IECM_TW_HORIZON_512MS = 512 << 20,
};

#ifdef IECM_ADD_PROBES
struct iecm_extra_stats {
	u64 tx_tcp_segs;
	u64 tx_udp_segs;
	u64 tx_tcp_cso;
	u64 tx_udp_cso;
	u64 tx_sctp_cso;
	u64 tx_ip4_cso;
	u64 tx_vlano;
	u64 rx_tcp_cso;
	u64 rx_udp_cso;
	u64 rx_sctp_cso;
	u64 rx_ip4_cso;
	u64 rx_vlano;
	u64 rx_tcp_cso_err;
	u64 rx_udp_cso_err;
	u64 rx_sctp_cso_err;
	u64 rx_ip4_cso_err;
};

#endif /* IECM_ADD_PROBES */
struct iecm_port_stats {
	struct u64_stats_sync stats_sync;
	u64 rx_hw_csum_err;
	u64 rx_hsplit;
	u64 rx_hsplit_hbo;
	u64 tx_linearize;
	u64 rx_bad_descs;
	struct virtchnl2_vport_stats vport_stats;
	struct virtchnl_eth_stats eth_stats;
#ifdef IECM_ADD_PROBES
	struct iecm_extra_stats extra_stats;
#endif /* IECM_ADD_PROBES */
};

struct iecm_vport {
	/* TX */
	int num_txq;
	int num_complq;
	/* It makes more sense for descriptor count to be part of only idpf
	 * queue structure. But when user changes the count via ethtool, driver
	 * has to store that value somewhere other than queue structure as the
	 * queues will be freed and allocated again.
	 */
	int txq_desc_count;
	int complq_desc_count;
	int compln_clean_budget;
	int num_txq_grp;
	struct iecm_txq_group *txq_grps;
	u32 txq_model;
	/* Used only in hotpath to get to the right queue very fast */
	struct iecm_queue **txqs;
	DECLARE_BITMAP(flags, __IECM_VPORT_FLAGS_NBITS);
	/* TX Timing Wheel parameters */
	enum iecm_tw_tstamp_granularity ts_gran;
	enum iecm_tw_horizon tw_horizon;

#ifdef HAVE_XDP_SUPPORT
	/* XDP TX */
	int num_xdp_txq;
	int num_xdp_rxq;
	int num_xdp_complq;
	int xdp_txq_offset;
	int xdp_rxq_offset;
	int xdp_complq_offset;
	void *(*xdp_prepare_tx_desc)(struct iecm_queue *xdpq, dma_addr_t dma,
				     u16 idx, u32 size);
#endif /* HAVE_XDP_SUPPORT */

	/* RX */
	int num_rxq;
	int num_bufq;
	int rxq_desc_count;
	u8 num_bufqs_per_qgrp;
	int bufq_desc_count[IECM_MAX_BUFQS_PER_RXQ_GRP];
	u32 bufq_size[IECM_MAX_BUFQS_PER_RXQ_GRP];
	int num_rxq_grp;
	struct iecm_rxq_group *rxq_grps;
	u32 rxq_model;
	struct iecm_rx_ptype_decoded rx_ptype_lkup[IECM_RX_MAX_PTYPE];

	struct iecm_adapter *adapter;
	struct net_device *netdev;
	u16 vport_type;
	u16 vport_id;
	u16 idx;		 /* software index in adapter vports struct */
	bool base_rxd;

	/* handler for hard interrupt */
	irqreturn_t (*irq_q_handler)(int irq, void *data);
	struct iecm_q_vector *q_vectors;	/* q vector array */
	u16 num_q_vectors;
	u16 q_vector_base;
	u16 max_mtu;
	u8 default_mac_addr[ETH_ALEN];
	u16 qset_handle;
	/* ITR profiles for the DIM algorithm */
#define IECM_DIM_PROFILE_SLOTS	5
	u16 rx_itr_profile[IECM_DIM_PROFILE_SLOTS];
	u16 tx_itr_profile[IECM_DIM_PROFILE_SLOTS];
	struct rtnl_link_stats64 netstats;
	struct iecm_port_stats port_stats;

	/* lock to protect against multiple stop threads, which can happen when
	 * the driver is in a namespace in a system that is being shutdown
	 */
	struct mutex stop_mutex;
};

enum iecm_user_flags {
	__IECM_PRIV_FLAGS_HDR_SPLIT = 0,
	__IECM_PROMISC_UC = 32,
	__IECM_PROMISC_MC,
	__IECM_USER_FLAGS_NBITS,
};

struct iecm_channel_ex {
	u16 num_rxq;
	u16 base_q;
	/* number of filter specific to this channel (aka ADQ TC) */
	u32 num_fltr;
};

#define IECM_CLOUD_FIELD_OMAC		BIT(0)
#define IECM_CLOUD_FIELD_IMAC		BIT(1)
#define IECM_CLOUD_FIELD_IVLAN		BIT(2)
#define IECM_CLOUD_FIELD_TEN_ID		BIT(3)
#define IECM_CLOUD_FIELD_IIP		BIT(4)

#define IECM_START_CHNL_TC		1

struct iecm_cloud_filter {
	struct list_head list;
	struct virtchnl_filter f;
	unsigned long cookie;
	bool remove;		/* filter needs to be deleted */
	bool add;		/* filter needs to be added */
	struct iecm_channel_ex *ch;
};

struct iecm_cloud_filter_config {
	struct list_head block_cb_list;		/* need to pass this to stack */
	struct list_head cloud_filter_list;
	u16 num_cloud_filters;
};

struct iecm_channel_config {
	struct virtchnl_channel_info ch_info[VIRTCHNL_MAX_ADQ_V2_CHANNELS];
	struct iecm_channel_ex ch_ex_info[VIRTCHNL_MAX_ADQ_V2_CHANNELS];
	bool tc_running;
	u8 total_qs;
	u8 num_tc;
};

enum iecm_adv_rss_flow_seg_hdr {
	IECM_ADV_RSS_FLOW_SEG_HDR_NONE	= 0x00000000,
	IECM_ADV_RSS_FLOW_SEG_HDR_IPV4	= 0x00000001,
	IECM_ADV_RSS_FLOW_SEG_HDR_IPV6	= 0x00000002,
	IECM_ADV_RSS_FLOW_SEG_HDR_TCP	= 0x00000004,
	IECM_ADV_RSS_FLOW_SEG_HDR_UDP	= 0x00000008,
	IECM_ADV_RSS_FLOW_SEG_HDR_SCTP	= 0x00000010,
};

#define IECM_ADV_RSS_FLOW_SEG_HDR_L3		\
	(IECM_ADV_RSS_FLOW_SEG_HDR_IPV4	|	\
	 IECM_ADV_RSS_FLOW_SEG_HDR_IPV6)

#define IECM_ADV_RSS_FLOW_SEG_HDR_L4		\
	(IECM_ADV_RSS_FLOW_SEG_HDR_TCP |	\
	 IECM_ADV_RSS_FLOW_SEG_HDR_UDP |	\
	 IECM_ADV_RSS_FLOW_SEG_HDR_SCTP)

enum iecm_adv_rss_flow_field {
	/* L3 */
	IECM_ADV_RSS_FLOW_FIELD_IDX_IPV4_SA,
	IECM_ADV_RSS_FLOW_FIELD_IDX_IPV4_DA,
	IECM_ADV_RSS_FLOW_FIELD_IDX_IPV6_SA,
	IECM_ADV_RSS_FLOW_FIELD_IDX_IPV6_DA,
	/* L4 */
	IECM_ADV_RSS_FLOW_FIELD_IDX_TCP_SRC_PORT,
	IECM_ADV_RSS_FLOW_FIELD_IDX_TCP_DST_PORT,
	IECM_ADV_RSS_FLOW_FIELD_IDX_UDP_SRC_PORT,
	IECM_ADV_RSS_FLOW_FIELD_IDX_UDP_DST_PORT,
	IECM_ADV_RSS_FLOW_FIELD_IDX_SCTP_SRC_PORT,
	IECM_ADV_RSS_FLOW_FIELD_IDX_SCTP_DST_PORT,

	/* The total number of enums must not exceed 64 */
	IECM_ADV_RSS_FLOW_FIELD_IDX_MAX
};

#define IECM_ADV_RSS_HASH_INVALID	0
#define IECM_ADV_RSS_HASH_FLD_IPV4_SA	\
	BIT_ULL(IECM_ADV_RSS_FLOW_FIELD_IDX_IPV4_SA)
#define IECM_ADV_RSS_HASH_FLD_IPV6_SA	\
	BIT_ULL(IECM_ADV_RSS_FLOW_FIELD_IDX_IPV6_SA)
#define IECM_ADV_RSS_HASH_FLD_IPV4_DA	\
	BIT_ULL(IECM_ADV_RSS_FLOW_FIELD_IDX_IPV4_DA)
#define IECM_ADV_RSS_HASH_FLD_IPV6_DA	\
	BIT_ULL(IECM_ADV_RSS_FLOW_FIELD_IDX_IPV6_DA)
#define IECM_ADV_RSS_HASH_FLD_TCP_SRC_PORT	\
	BIT_ULL(IECM_ADV_RSS_FLOW_FIELD_IDX_TCP_SRC_PORT)
#define IECM_ADV_RSS_HASH_FLD_TCP_DST_PORT	\
	BIT_ULL(IECM_ADV_RSS_FLOW_FIELD_IDX_TCP_DST_PORT)
#define IECM_ADV_RSS_HASH_FLD_UDP_SRC_PORT	\
	BIT_ULL(IECM_ADV_RSS_FLOW_FIELD_IDX_UDP_SRC_PORT)
#define IECM_ADV_RSS_HASH_FLD_UDP_DST_PORT	\
	BIT_ULL(IECM_ADV_RSS_FLOW_FIELD_IDX_UDP_DST_PORT)
#define IECM_ADV_RSS_HASH_FLD_SCTP_SRC_PORT	\
	BIT_ULL(IECM_ADV_RSS_FLOW_FIELD_IDX_SCTP_SRC_PORT)
#define IECM_ADV_RSS_HASH_FLD_SCTP_DST_PORT	\
	BIT_ULL(IECM_ADV_RSS_FLOW_FIELD_IDX_SCTP_DST_PORT)

/* bookkeeping of advanced RSS configuration */
struct iecm_adv_rss {
	struct list_head list;
	u32 packet_hdrs;
	u64 hash_flds;
	struct virtchnl_rss_cfg cfg_msg;
	bool remove;	/* RSS filter needs to be deleted */
	bool add;	/* RSS filter needs to be added */
};

enum iecm_fdir_flow_type {
	/* NONE - used for undef/error */
	IECM_FDIR_FLOW_NONE = 0,
	IECM_FDIR_FLOW_IPV4_TCP,
	IECM_FDIR_FLOW_IPV4_UDP,
	IECM_FDIR_FLOW_IPV4_SCTP,
	IECM_FDIR_FLOW_IPV4_AH,
	IECM_FDIR_FLOW_IPV4_ESP,
	IECM_FDIR_FLOW_IPV4_OTHER,
	IECM_FDIR_FLOW_IPV6_TCP,
	IECM_FDIR_FLOW_IPV6_UDP,
	IECM_FDIR_FLOW_IPV6_SCTP,
	IECM_FDIR_FLOW_IPV6_AH,
	IECM_FDIR_FLOW_IPV6_ESP,
	IECM_FDIR_FLOW_IPV6_OTHER,
	IECM_FDIR_FLOW_NON_IP_L2,
	/* MAX - this must be last and add anything new just above it */
	IECM_FDIR_FLOW_PTYPE_MAX,
};

/* Must not exceed the array element number of '__be32 data[2]' in the ethtool
 * 'struct ethtool_rx_flow_spec.m_ext.data[2]' to express the flex-byte (word).
 */
#define IECM_FLEX_WORD_NUM	2

struct iecm_flex_word {
	u16 offset;
	u16 word;
};

struct iecm_ipv4_addrs {
	__be32 src_ip;
	__be32 dst_ip;
};

struct iecm_ipv6_addrs {
	struct in6_addr src_ip;
	struct in6_addr dst_ip;
};

struct iecm_fdir_eth {
	__be16 etype;
};

struct iecm_fdir_ip {
	union {
		struct iecm_ipv4_addrs v4_addrs;
		struct iecm_ipv6_addrs v6_addrs;
	};
	__be16 src_port;
	__be16 dst_port;
	__be32 l4_header;	/* first 4 bytes of the layer 4 header */
	__be32 spi;		/* security parameter index for AH/ESP */
	union {
		u8 tos;
		u8 tclass;
	};
	u8 proto;
};

struct iecm_fdir_extra {
	u32 usr_def[IECM_FLEX_WORD_NUM];
};

/* bookkeeping of Flow Director filters */
struct iecm_fdir_fltr {
	struct list_head list;

	enum iecm_fdir_flow_type flow_type;

	struct iecm_fdir_eth eth_data;
	struct iecm_fdir_eth eth_mask;

	struct iecm_fdir_ip ip_data;
	struct iecm_fdir_ip ip_mask;

	struct iecm_fdir_extra ext_data;
	struct iecm_fdir_extra ext_mask;

	enum virtchnl_action action;

	/* flex byte filter data */
	u8 ip_ver; /* used to adjust the flex offset, 4 : IPv4, 6 : IPv6 */
	u8 flex_cnt;
	struct iecm_flex_word flex_words[IECM_FLEX_WORD_NUM];

	u32 flow_id;

	u32 loc;	/* Rule location inside the flow table */
	u32 q_index;

	struct virtchnl_fdir_add vc_add_msg;
	bool remove;	/* Flow Director filter needs to be deleted */
	bool add;	/* Flow Director filter needs to be added */
};

struct iecm_fdir_fltr_config {
	struct list_head fdir_fltr_list;
#define IECM_MAX_FDIR_FILTERS	128	/* max allowed Flow Director filters */
	u16 num_active_filters;
};

#define IECM_GET_PTYPE_SIZE(p) \
	(sizeof(struct virtchnl2_ptype) + \
	(((p)->proto_id_count ? ((p)->proto_id_count - 1) : 0) * sizeof(u16)))

#define IECM_TUN_IP_GRE (\
	IECM_PTYPE_TUNNEL_IP |\
	IECM_PTYPE_TUNNEL_IP_GRENAT)

#define IECM_TUN_IP_GRE_MAC (\
	IECM_TUN_IP_GRE |\
	IECM_PTYPE_TUNNEL_IP_GRENAT_MAC)

enum iecm_tunnel_state {
	IECM_PTYPE_TUNNEL_IP                    = BIT(0),
	IECM_PTYPE_TUNNEL_IP_GRENAT             = BIT(1),
	IECM_PTYPE_TUNNEL_IP_GRENAT_MAC         = BIT(2),
	IECM_PTYPE_TUNNEL_IP_GRENAT_MAC_VLAN    = BIT(3),
};

struct iecm_ptype_state {
	bool outer_ip;
	bool outer_frag;
	u8 tunnel_state;
};

/* User defined configuration values */
struct iecm_user_config_data {
	u32 num_req_tx_qs; /* user requested TX queues through ethtool */
	u32 num_req_rx_qs; /* user requested RX queues through ethtool */
	u32 num_req_txq_desc;
	u32 num_req_rxq_desc;
	u16 vlan_ethertype;
	/* used to store user set ctag VLANs */
	unsigned long active_cvlans[BITS_TO_LONGS(VLAN_N_VID)];
	/* used to store user set stag VLANs */
	unsigned long active_svlans[BITS_TO_LONGS(VLAN_N_VID)];
	void *req_qs_chunks;
#ifdef HAVE_XDP_SUPPORT
	/* Duplicated in queue structure for performance reasons */
	struct bpf_prog *xdp_prog;
#endif /* HAVE_XDP_SUPPORT */
	DECLARE_BITMAP(user_flags, __IECM_USER_FLAGS_NBITS);
	DECLARE_BITMAP(etf_qenable, IECM_LARGE_MAX_Q);
	struct list_head mac_filter_list;
	struct list_head vlan_filter_list;
	struct list_head adv_rss_list;
	struct iecm_fdir_fltr_config fdir_config;
	struct iecm_cloud_filter_config cf_config;
	struct iecm_channel_config ch_config;
};

struct iecm_rss_data {
	u64 rss_hash;
	u16 rss_key_size;
	u8 *rss_key;
	u16 rss_lut_size;
	u32 *rss_lut;
};

struct iecm_adapter {
	struct pci_dev *pdev;
	const char *drv_name;
	const char *drv_ver;
	u32 virt_ver_maj;
	u32 virt_ver_min;

	u32 tx_timeout_count;
	u32 msg_enable;
	enum iecm_state state;
	DECLARE_BITMAP(flags, __IECM_FLAGS_NBITS);
	struct mutex reset_lock; /* lock to protect reset flows */
	struct iecm_reset_reg reset_reg;
	struct iecm_hw hw;

	u16 num_req_msix;
	u16 num_msix_entries;
	struct msix_entry *msix_entries;
	struct virtchnl2_alloc_vectors *req_vec_chunks;
	struct iecm_q_vector mb_vector;
	/* handler for hard interrupt for mailbox*/
	irqreturn_t (*irq_mb_handler)(int irq, void *data);

	/* vport structs */
	struct iecm_vport **vports;	/* vports created by the driver */
	struct net_device **netdevs;	/* associated vport netdevs */
	u16 num_alloc_vport;
	u16 next_vport;		/* Next free slot in pf->vport[] - 0-based! */

	u16 max_queue_limit;	/* Max number of queues user can request */

	struct delayed_work init_task; /* delayed init task */
	struct workqueue_struct *init_wq;
	u32 mb_wait_count;
	struct delayed_work serv_task; /* delayed service task */
	struct workqueue_struct *serv_wq;
	struct delayed_work stats_task; /* delayed statistics task */
	struct workqueue_struct *stats_wq;
	struct delayed_work vc_event_task; /* delayed virtchannel event task */
	struct workqueue_struct *vc_event_wq;
	/* Store the resources data received from control plane */
	void **vport_params_reqd;
	void **vport_params_recvd;
	/* User set parameters */
	struct iecm_user_config_data config_data;
	void *caps;
	struct virtchnl_vlan_caps *vlan_caps;

	wait_queue_head_t vchnl_wq;
	wait_queue_head_t sw_marker_wq;
	DECLARE_BITMAP(vc_state, IECM_VC_NBITS);
	char vc_msg[IECM_DFLT_MBX_BUF_SIZE];
	struct iecm_rss_data rss_data;
	struct iecm_dev_ops dev_ops;
	s32 link_speed;
	/* This is only populated if the VIRTCHNL_VF_CAP_ADV_LINK_SPEED is set
	 * in vf_res->vf_cap_flags. This field should be used going forward and
	 * the enum virtchnl_link_speed above should be considered the legacy
	 * way of storing/communicating link speeds.
	 */
	u32 link_speed_mbps;
	bool link_up;
	int num_vfs;
	int debug_msk; /* netif messaging level */

	struct mutex sw_mutex;		/* lock to protect vport alloc flow */
	/* lock to protect cloud filters*/
	spinlock_t cloud_filter_list_lock;
	/* lock to protect mac filters */
	spinlock_t mac_filter_list_lock;
	/* lock to protect vlan filters */
	spinlock_t vlan_list_lock;
	/* lock to protect advanced RSS filters */
	spinlock_t adv_rss_list_lock;
	/* lock to protect the Flow Director filters */
	spinlock_t fdir_fltr_list_lock;
};

/**
 * iecm_is_queue_model_split - check if queue model is split
 * @q_model: queue model single or split
 *
 * Returns true if queue model is split else false
 */
static inline int iecm_is_queue_model_split(u16 q_model)
{
	return (q_model == VIRTCHNL2_QUEUE_MODEL_SPLIT);
}

#ifdef HAVE_XDP_SUPPORT
/**
 * iecm_xdp_is_prog_ena - check if there is an XDP program on adapter
 * @vport: vport to check
 */
static inline bool iecm_xdp_is_prog_ena(struct iecm_vport *vport)
{
	if (!vport->adapter)
		return false;

	return !!vport->adapter->config_data.xdp_prog;
}

/**
 * iecm_get_related_xdp_queue - Get corresponding XDP Tx queue for Rx queue
 * @rxq: Rx queue
 *
 * Returns a pointer to XDP Tx queue linked to a given Rx queue.
 */
static inline struct iecm_queue *iecm_get_related_xdp_queue(struct iecm_queue *rxq)
{
		return rxq->vport->txqs[rxq->idx + rxq->vport->xdp_txq_offset];
}

#endif /* HAVE_XDP_SUPPORT */

#define iecm_is_cap_ena(adapter, field, flag) \
	__iecm_is_cap_ena(adapter, false, field, flag)
#define iecm_is_cap_ena_all(adapter, field, flag) \
	__iecm_is_cap_ena(adapter, true, field, flag)
/**
 * __iecm_is_cap_ena - Determine if HW capability is supported
 * @adapter: private data struct
 * @all: all or one flag
 * @field: cap field to check
 * @flag: Feature flag to check
 *
 * iecm_is_cap_ena_all is used to check if all the capability bits are set
 * ('AND' operation) where as iecm_is_cap_ena is used to check if
 * any one of the capability bits is set ('OR' operation)
 */
static inline bool __iecm_is_cap_ena(struct iecm_adapter *adapter, bool all,
				     enum iecm_cap_field field, u64 flag)
{
	return adapter->dev_ops.vc_ops.is_cap_ena &&
		adapter->dev_ops.vc_ops.is_cap_ena(adapter, all, field, flag);
}

/**
 * iecm_is_rdma_cap_ena - Determine if RDMA is supported
 * @adapter: private data struct
 */
static inline bool iecm_is_rdma_cap_ena(struct iecm_adapter *adapter)
{
	return iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_RDMA);
}

/* enum used to distinguish vlan capabilities */
enum iecm_vlan_caps {
	IECM_CAP_VLAN_CTAG_INSERT,
	IECM_CAP_VLAN_STAG_INSERT,
	IECM_CAP_VLAN_CTAG_STRIP,
	IECM_CAP_VLAN_STAG_STRIP,
	IECM_CAP_VLAN_CTAG_ADD_DEL,
	IECM_CAP_VLAN_STAG_ADD_DEL,
	IECM_CAP_VLAN_LAST,
};

#define IECM_VLAN_8100 (VIRTCHNL_VLAN_TOGGLE | VIRTCHNL_VLAN_ETHERTYPE_8100)
#define IECM_VLAN_88A8 (VIRTCHNL_VLAN_TOGGLE | VIRTCHNL_VLAN_ETHERTYPE_88A8)

#ifdef NETIF_F_HW_VLAN_CTAG_TX
#define IECM_F_HW_VLAN_CTAG_TX NETIF_F_HW_VLAN_CTAG_TX
#else
#define IECM_F_HW_VLAN_CTAG_TX NETIF_F_HW_VLAN_TX
#endif /* NETIF_F_HW_VLAN_CTAG_TX */

#ifdef NETIF_F_HW_VLAN_CTAG_RX
#define IECM_F_HW_VLAN_CTAG_RX NETIF_F_HW_VLAN_CTAG_RX
#else
#define IECM_F_HW_VLAN_CTAG_RX NETIF_F_HW_VLAN_RX
#endif /* NETIF_F_HW_VLAN_CTAG_RX */

#ifdef NETIF_F_HW_VLAN_CTAG_FILTER
#define IECM_F_HW_VLAN_CTAG_FILTER NETIF_F_HW_VLAN_CTAG_FILTER
#else
#define IECM_F_HW_VLAN_CTAG_FILTER NETIF_F_HW_VLAN_FILTER
#endif /* NETIF_F_HW_VLAN_CTAG_FILTER */

#define IECM_CAP_RSS (\
	VIRTCHNL2_CAP_RSS_IPV4_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV4_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV4_UDP	|\
	VIRTCHNL2_CAP_RSS_IPV4_SCTP	|\
	VIRTCHNL2_CAP_RSS_IPV4_OTHER	|\
	VIRTCHNL2_CAP_RSS_IPV4_AH	|\
	VIRTCHNL2_CAP_RSS_IPV4_ESP	|\
	VIRTCHNL2_CAP_RSS_IPV4_AH_ESP	|\
	VIRTCHNL2_CAP_RSS_IPV6_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV6_TCP	|\
	VIRTCHNL2_CAP_RSS_IPV6_UDP	|\
	VIRTCHNL2_CAP_RSS_IPV6_SCTP	|\
	VIRTCHNL2_CAP_RSS_IPV6_OTHER	|\
	VIRTCHNL2_CAP_RSS_IPV6_AH	|\
	VIRTCHNL2_CAP_RSS_IPV6_ESP	|\
	VIRTCHNL2_CAP_RSS_IPV6_AH_ESP)

#define IECM_CAP_RSC (\
	VIRTCHNL2_CAP_RSC_IPV4_TCP	|\
	VIRTCHNL2_CAP_RSC_IPV4_SCTP	|\
	VIRTCHNL2_CAP_RSC_IPV6_TCP	|\
	VIRTCHNL2_CAP_RSC_IPV6_SCTP)

#define IECM_CAP_HSPLIT	(\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L2	|\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L3	|\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V4	|\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V6)

#define IECM_CAP_RX_CSUM_L4V4 (\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP)

#define IECM_CAP_RX_CSUM_L4V6 (\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP)

#define IECM_CAP_RX_CSUM (\
	VIRTCHNL2_CAP_RX_CSUM_L3_IPV4		|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP)

#define IECM_CAP_SCTP_CSUM (\
	VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_SCTP	|\
	VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_SCTP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP)

/**
 * iecm_restore_features - Restore feature configs
 * @adapter: driver specific private structure
 * @flag: User settings flag to check
 */
static inline bool iecm_is_user_flag_ena(struct iecm_adapter *adapter,
					 enum iecm_user_flags flag)
{
	return test_bit(flag, adapter->config_data.user_flags);
}

/**
 * iecm_get_reserved_vecs - Get reserved vectors
 * @adapter: private data struct
 */
static inline u16 iecm_get_reserved_vecs(struct iecm_adapter *adapter)
{
	return adapter->dev_ops.vc_ops.get_reserved_vecs(adapter);
}

/**
 * iecm_is_reset_detected - check if we were reset at some point
 * @adapter: driver specific private structure
 *
 * Returns true if we are either in reset currently or were previously reset.
 */
static inline bool iecm_is_reset_detected(struct iecm_adapter *adapter)
{
	/* Simics/CP isn't clearing the enable bit, just the length which isn't
	 * how it works in legacy iavf.
	 */
	return !(rd32(&adapter->hw, adapter->hw.arq->reg.len) &
		 adapter->hw.arq->reg.len_mask);
}

/**
 * iecm_is_reset_in_prog - check if reset is in progress
 * @adapter: driver specific private structure
 *
 * Returns true if hard reset is in progress, false otherwise
 */
static inline bool iecm_is_reset_in_prog(struct iecm_adapter *adapter)
{
	return (test_bit(__IECM_HR_RESET_IN_PROG, adapter->flags) ||
		test_bit(__IECM_HR_FUNC_RESET, adapter->flags) ||
		test_bit(__IECM_HR_CORE_RESET, adapter->flags) ||
		test_bit(__IECM_HR_DRV_LOAD, adapter->flags));
}

/**
 * iecm_is_netdev_vlan_feature_allowed - check if vlan feature is allowed
 * @requested_features: VLAN features requested by the stack
 * @allowed_features: VLAN features allowed by the HW
 * @feature_bit: VLAN feature bit to check
 *
 * Return true if VLAN feature is allowed, false otherwise
 */
static inline bool
iecm_is_netdev_vlan_feature_allowed(netdev_features_t requested_features,
				    netdev_features_t allowed_features,
				    netdev_features_t feature_bit)
{
	return !(((requested_features) & (feature_bit)) &&
		 !((allowed_features) & (feature_bit)));
}

/**
 * iecm_rx_offset - Return expected offset into page to access data
 * @rx_q: queue we are requesting offset of
 *
 * Returns the offset value for queue into the data buffer.
 */
static inline unsigned int
iecm_rx_offset(struct iecm_queue __maybe_unused *rx_q)
{
#ifdef HAVE_XDP_SUPPORT
	return iecm_xdp_is_prog_ena(rx_q->vport) ? XDP_PACKET_HEADROOM : 0;
#endif /* HAVE_XDP_SUPPORT */
	return 0;
}

int iecm_probe(struct pci_dev *pdev,
	       const struct pci_device_id __always_unused *ent,
	       struct iecm_adapter *adapter);
void iecm_remove(struct pci_dev *pdev);
void iecm_vport_adjust_qs(struct iecm_vport *vport);
int iecm_ctlq_reg_init(struct iecm_ctlq_create_info *cq, int num_q);
int iecm_init_dflt_mbx(struct iecm_adapter *adapter);
void iecm_deinit_dflt_mbx(struct iecm_adapter *adapter);
void iecm_vc_ops_init(struct iecm_adapter *adapter);
int iecm_vc_core_init(struct iecm_adapter *adapter, int *vport_id);
int iecm_get_reg_intr_vecs(struct iecm_vport *vport,
			   struct iecm_vec_regs *reg_vals, int num_vecs);
int iecm_wait_for_event(struct iecm_adapter *adapter,
			enum iecm_vport_vc_state state,
			enum iecm_vport_vc_state err_check);
int iecm_min_wait_for_event(struct iecm_adapter *adapter,
			    enum iecm_vport_vc_state state,
			    enum iecm_vport_vc_state err_check);
int iecm_msec_wait_for_event(struct iecm_adapter *adapter,
			     enum iecm_vport_vc_state state,
			     enum iecm_vport_vc_state err_check,
			     int timeout);
#ifdef HAVE_NDO_FEATURES_CHECK
u16 iecm_get_max_tx_hdr_size(struct iecm_adapter *adapter);
#endif /* HAVE_NDO_FEATURES_CHECK */
int iecm_send_get_caps_msg(struct iecm_adapter *adapter);
int iecm_send_delete_queues_msg(struct iecm_vport *vport);
int iecm_send_add_queues_msg(struct iecm_vport *vport, u16 num_tx_q,
			     u16 num_complq, u16 num_rx_q, u16 num_rx_bufq);
int iecm_send_vlan_v2_caps_msg(struct iecm_adapter *adapter);
int iecm_initiate_soft_reset(struct iecm_vport *vport,
			     enum iecm_flags reset_cause);
int iecm_send_config_tx_queues_msg(struct iecm_vport *vport);
int iecm_send_config_rx_queues_msg(struct iecm_vport *vport);
int iecm_send_enable_vport_msg(struct iecm_vport *vport);
int iecm_send_disable_vport_msg(struct iecm_vport *vport);
int iecm_send_destroy_vport_msg(struct iecm_vport *vport);
int iecm_send_get_rx_ptype_msg(struct iecm_vport *vport);
int iecm_send_get_set_rss_key_msg(struct iecm_vport *vport, bool get);
int iecm_send_get_set_rss_lut_msg(struct iecm_vport *vport, bool get);
int iecm_send_get_set_rss_hash_msg(struct iecm_vport *vport, bool get);
int iecm_send_dealloc_vectors_msg(struct iecm_adapter *adapter);
int iecm_send_alloc_vectors_msg(struct iecm_adapter *adapter, u16 num_vectors);
int iecm_vport_params_buf_alloc(struct iecm_adapter *adapter);
void iecm_vport_params_buf_rel(struct iecm_adapter *adapter);
struct iecm_vport *iecm_netdev_to_vport(struct net_device *netdev);
struct iecm_adapter *iecm_netdev_to_adapter(struct net_device *netdev);
int iecm_send_get_stats_msg(struct iecm_vport *vport);
int iecm_get_vec_ids(struct iecm_adapter *adapter,
		     u16 *vecids, int num_vecids,
		     struct virtchnl2_vector_chunks *chunks);
int iecm_recv_mb_msg(struct iecm_adapter *adapter, enum virtchnl_ops op,
		     void *msg, int msg_size);
int iecm_send_mb_msg(struct iecm_adapter *adapter, enum virtchnl_ops op,
		     u16 msg_size, u8 *msg);
void iecm_set_ethtool_ops(struct net_device *netdev);
void iecm_vport_set_hsplit(struct iecm_vport *vport, bool ena);
void iecm_vport_intr_rel(struct iecm_vport *vport);
int iecm_vport_intr_alloc(struct iecm_vport *vport);
int iecm_add_del_ether_addrs(struct iecm_vport *vport, bool add, bool async);
int iecm_set_promiscuous(struct iecm_adapter *adapter);
int iecm_send_add_del_cloud_filter_msg(struct iecm_vport *vport, bool add);
int iecm_send_add_del_adv_rss_cfg_msg(struct iecm_vport *vport, bool add);
int iecm_set_adv_rss_hash_opt(struct iecm_vport *vport,
			      struct ethtool_rxnfc *cmd);
int iecm_get_adv_rss_hash_opt(struct iecm_vport *vport,
			      struct ethtool_rxnfc *cmd);
int iecm_send_add_fdir_filter_msg(struct iecm_vport *vport);
int iecm_send_del_fdir_filter_msg(struct iecm_vport *vport);
int iecm_get_fdir_fltr_entry(struct iecm_vport *vport,
			     struct ethtool_rxnfc *cmd);
int iecm_get_fdir_fltr_ids(struct iecm_vport *vport, struct ethtool_rxnfc *cmd,
			   u32 *rule_locs);
int iecm_add_fdir_fltr(struct iecm_vport *vport, struct ethtool_rxnfc *cmd);
int iecm_del_fdir_fltr(struct iecm_vport *vport, struct ethtool_rxnfc *cmd);
int iecm_send_enable_channels_msg(struct iecm_vport *vport);
int iecm_send_disable_channels_msg(struct iecm_vport *vport);
bool iecm_is_feature_ena(struct iecm_vport *vport, netdev_features_t feature);
int iecm_check_descs(struct iecm_vport *vport, u64 rx_desc_ids,
		     u64 tx_desc_ids, u16 rxq_model, u16 txq_model);
int iecm_set_msg_pending(struct iecm_adapter *adapter,
			 struct iecm_ctlq_msg *ctlq_msg,
			 enum iecm_vport_vc_state err_enum);
void iecm_adq_chnl_detect_recover(struct iecm_vport *vport);
void iecm_vport_intr_write_itr(struct iecm_q_vector *q_vector,
			       u16 itr, bool tx);
int iecm_send_map_unmap_queue_vector_msg(struct iecm_vport *vport, bool map);
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_XDP_FRAME_STRUCT
int iecm_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
		  u32 flags);
#else
int iecm_xdp_xmit(struct net_device *dev, struct xdp_buff *xdp);
#endif /* HAVE_XDP_FRAME_STRUCT */
#ifndef NO_NDO_XDP_FLUSH
void iecm_xdp_flush(struct net_device *dev);
#endif /* NO_NDO_XDP_FLUSH */
#endif /* HAVE_XDP_SUPPORT */
int iecm_get_max_vfs(struct iecm_adapter *adapter);
int iecm_send_set_sriov_vfs_msg(struct iecm_adapter *adapter, u16 num_vfs);
int iecm_sriov_configure(struct pci_dev *pdev, int num_vfs);
#endif /* !_IECM_H_ */
