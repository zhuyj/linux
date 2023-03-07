/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2022 Intel Corporation */

#ifndef _IDPF_H_
#define _IDPF_H_

/* Forward declaration */
struct idpf_adapter;
struct idpf_vport;
struct idpf_queue;
struct idpf_vport_max_q;

#include "kcompat.h"
#include <net/pkt_sched.h>
#ifdef __TC_MQPRIO_MODE_MAX
#include <net/pkt_cls.h>
#endif /* __TC_MQPRIO_MODE_MAX */
#include <linux/aer.h>
#include <linux/bitfield.h>
#include <linux/pci.h>
#include <linux/sctp.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#ifdef HAVE_GRO_HEADER
#include <net/gro.h>
#endif /* HAVE_GRO_HEADER */
#include <net/tcp.h>
#include <net/ip6_checksum.h>
#include <net/ipv6.h>
#include <net/sch_generic.h>
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
#define IDPF_DRV_NAME "idpf"
#define IDPF_DRV_VER "0.0.704"
#include "kcompat.h"
#ifdef HAVE_CONFIG_DIMLIB
#include <linux/dim.h>
#else
#include "kcompat_dim.h"
#endif /* HAVE_CONFIG_DIMLIB */

#include "idpf_lan_txrx.h"

#include "iidc.h"
#include <linux/idr.h>
#include "virtchnl2.h"
#include "idpf_txrx.h"
#include "idpf_controlq.h"
#ifdef HAVE_XDP_SUPPORT
#include <linux/bpf_trace.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#endif /* HAVE_XDP_SUPPORT */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
#include "idpf_xsk.h"
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#ifdef DEVLINK_ENABLED
#include "idpf_devlink.h"
#endif /* DEVLINK_ENABLED */

#define IDPF_M(m, s)	((m) << (s))
#define GETMAXVAL(num_bits)	((1 << (num_bits)) - 1)

#define IDPF_BAR0			0
#define IDPF_NO_FREE_SLOT		0xffff

/* Default Mailbox settings */
#define IDPF_DFLT_MBX_BUF_SIZE		(4 * 1024)
#define IDPF_NUM_QCTX_PER_MSG		3
#define IDPF_NUM_FILTERS_PER_MSG	20
#define IDPF_DFLT_MBX_Q_LEN		64
#define IDPF_DFLT_MBX_ID		-1
/* maximum number of times to try before resetting mailbox */
#define IDPF_MB_MAX_ERR			20
#define IDPF_NUM_CHUNKS_PER_MSG(a, b)	((IDPF_DFLT_MBX_BUF_SIZE - (a)) / (b))
#define IDPF_WAIT_FOR_EVENT_TIMEO_MIN	2000
#define IDPF_WAIT_FOR_EVENT_TIMEO	60000
#define IDPF_MAX_CLOUD_ADQ_FILTERS	128

#define IDPF_GTPU_HDR_TEID_OFFS0	4
#define IDPF_GTPU_HDR_TEID_OFFS1	6
#define IDPF_GTPU_HDR_N_PDU_AND_NEXT_EXTHDR_OFFS	10
#define IDPF_GTPU_HDR_NEXT_EXTHDR_TYPE_MASK		0x00FF /* skip N_PDU */
/* PDU Session Container Extension Header (PSC) */
#define IDPF_GTPU_PSC_EXTHDR_TYPE			0x85
#define IDPF_GTPU_HDR_PSC_PDU_TYPE_AND_QFI_OFFS		13
#define IDPF_GTPU_HDR_PSC_PDU_QFI_MASK			0x3F /* skip Type */
#define IDPF_GTPU_EH_QFI_IDX				1

#define IDPF_PFCP_HDR_SFIELD_AND_MSG_TYPE_OFFS	0

#define IDPF_NAT_T_ESP_SPI_OFFS0	0
#define IDPF_NAT_T_ESP_SPI_OFFS1	2

#define IDPF_GTPU_PORT		2152
#define IDPF_NAT_T_ESP_PORT	4500
#define IDPF_PFCP_PORT		8805

#define IDPF_USERDEF_FLEX_WORD_M	GENMASK(15, 0)
#define IDPF_USERDEF_FLEX_OFFS_S	16
#define IDPF_USERDEF_FLEX_OFFS_M	GENMASK(31, IDPF_USERDEF_FLEX_OFFS_S)
#define IDPF_USERDEF_FLEX_FLTR_M	GENMASK(31, 0)

#define IDPF_USERDEF_FLEX_MAX_OFFS_VAL 504

/* available message levels */
#define IDPF_AVAIL_NETIF_M (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)

#define IDPF_MBPS_DIVISOR		125000 /* divisor to convert to Mbps */

#if IS_ENABLED(CONFIG_ARM64) && defined(ENABLE_ACC_PASID_WA)
/* override PASID for ARM, when compiling for SIOV on ACC and IMC */
#ifndef HAVE_PASID_SUPPORT
#define HAVE_PASID_SUPPORT
#endif /* !HAVE_PASID_SUPPORT */
#endif /* CONFIG_ARM64 && ENABLE_ACC_PASID_WA */
#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
#include "idpf_vdcm.h"
#define IDPF_RESET_DONE 1
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */

#define IDPF_VIRTCHNL_VERSION_MAJOR VIRTCHNL2_VERSION_MAJOR_2
#define IDPF_VIRTCHNL_VERSION_MINOR VIRTCHNL2_VERSION_MINOR_0

struct idpf_mac_filter {
	struct list_head list;
	u8 macaddr[ETH_ALEN];
	bool remove;		/* filter needs to be removed */
	bool add;		/* filter needs to be added */
};

struct idpf_rdma_data {
	struct iidc_core_dev_info *cdev_info;
	int aux_idx;
	u16 num_vecs;
	bool vc_send_sync_pending;
};

enum idpf_state {
	__IDPF_STARTUP,
	__IDPF_VER_CHECK,
	__IDPF_GET_CAPS,
	__IDPF_INIT_SW,
	__IDPF_STATE_LAST /* this member MUST be last */
};

enum idpf_flags {
	/* Hard reset causes */
	__IDPF_HR_FUNC_RESET, /* Hard reset when txrx timeout */
	__IDPF_HR_CORE_RESET, /* when reset event is received on virtchannel */
	__IDPF_HR_DRV_LOAD, /* Set on driver load for a clean HW */
	/* Reset in progress */
	__IDPF_HR_RESET_IN_PROG,
	/* Resources release in progress*/
	__IDPF_REL_RES_IN_PROG,
	/* Generic bits to share a message */
	__IDPF_UP_REQUESTED, /* Set if open to be called explicitly by driver */
	/* Mailbox interrupt event */
	__IDPF_MB_INTR_MODE,
	__IDPF_MB_INTR_TRIGGER,
	/* Device specific bits */
	/* Request split queue model when creating vport */
	__IDPF_REQ_TX_SPLITQ,
	__IDPF_REQ_RX_SPLITQ,
	/* Asynchronous add/del ether address in flight */
	__IDPF_ADD_MAC_REQ,
	__IDPF_DEL_MAC_REQ,
	/* Virtchnl message buffer received needs to be processed */
	__IDPF_VC_MSG_PENDING,
	/* Do not schedule service task if bit is set */
	__IDPF_CANCEL_SERVICE_TASK,
	/* Do not schedule stats task if bit is set */
	__IDPF_CANCEL_STATS_TASK,
	/* Driver remove in progress */
	__IDPF_REMOVE_IN_PROG,
	/* Add queues is initiated */
	__IDPF_ADD_QUEUES,
	/* must be last */
	__IDPF_FLAGS_NBITS,
};

/* enum used to distinquish which capability field to check */
enum idpf_cap_field {
	IDPF_BASE_CAPS		= -1,
	IDPF_CSUM_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   csum_caps),
	IDPF_SEG_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   seg_caps),
	IDPF_RSS_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   rss_caps),
	IDPF_HSPLIT_CAPS	= offsetof(struct virtchnl2_get_capabilities,
					   hsplit_caps),
	IDPF_RSC_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   rsc_caps),
	IDPF_OTHER_CAPS		= offsetof(struct virtchnl2_get_capabilities,
					   other_caps),
	IDPF_CAP_FIELD_LAST,
};

struct idpf_netdev_priv {
	struct idpf_vport *vport;
};

struct idpf_reset_reg {
	u8 __iomem *rstat;
	u32 rstat_m;
};

/* Max queues on a vport */
struct idpf_vport_max_q {
	u16 max_rxq;
	u16 max_txq;
	u16 max_bufq;
	u16 max_complq;
};

/* product specific register API */
struct idpf_reg_ops {
	void (*ctlq_reg_init)(struct idpf_ctlq_create_info *cq);
	int (*intr_reg_init)(struct idpf_vport *vport);
	void (*mb_intr_reg_init)(struct idpf_adapter *adapter);
	void (*reset_reg_init)(struct idpf_adapter *adapter);
	void (*trigger_reset)(struct idpf_adapter *adapter,
			      enum idpf_flags trig_cause);
	u64 (*read_master_time)(struct idpf_hw *hw);
};

struct idpf_idc_ops {
	int (*idc_init)(struct idpf_adapter *adapter);
	void (*idc_deinit)(struct idpf_adapter *adapter);
};

struct idpf_dev_ops {
#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
	int (*vdcm_init)(struct pci_dev *pdev);
	void (*vdcm_deinit)(struct pci_dev *pdev);
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */
	void (*crc_enable)(u64 *td_cmd);
	struct idpf_reg_ops reg_ops;
	struct idpf_idc_ops idc_ops;

	u64 bar0_region1_size;	/* non-cached BAR0 region 1 size */
	u64 bar0_region2_start;	/* non-cached BAR0 region 2 start address */
};

/* These macros allow us to generate an enum and a matching char * array of
 * stringified enums that are always in sync. Checkpatch issues a bogus warning
 * about this being a complex macro; but it's wrong, these are never used as a
 * statement and instead only used to define the enum and array.
 */
#define IDPF_FOREACH_VPORT_VC_STATE(STATE)	\
	STATE(IDPF_VC_CREATE_VPORT)		\
	STATE(IDPF_VC_CREATE_VPORT_ERR)		\
	STATE(IDPF_VC_ENA_VPORT)		\
	STATE(IDPF_VC_ENA_VPORT_ERR)		\
	STATE(IDPF_VC_DIS_VPORT)		\
	STATE(IDPF_VC_DIS_VPORT_ERR)		\
	STATE(IDPF_VC_DESTROY_VPORT)		\
	STATE(IDPF_VC_DESTROY_VPORT_ERR)	\
	STATE(IDPF_VC_CONFIG_TXQ)		\
	STATE(IDPF_VC_CONFIG_TXQ_ERR)		\
	STATE(IDPF_VC_CONFIG_RXQ)		\
	STATE(IDPF_VC_CONFIG_RXQ_ERR)		\
	STATE(IDPF_VC_CONFIG_Q)			\
	STATE(IDPF_VC_CONFIG_Q_ERR)		\
	STATE(IDPF_VC_ENA_QUEUES)		\
	STATE(IDPF_VC_ENA_QUEUES_ERR)		\
	STATE(IDPF_VC_DIS_QUEUES)		\
	STATE(IDPF_VC_DIS_QUEUES_ERR)		\
	STATE(IDPF_VC_ENA_CHANNELS)		\
	STATE(IDPF_VC_ENA_CHANNELS_ERR)		\
	STATE(IDPF_VC_DIS_CHANNELS)		\
	STATE(IDPF_VC_DIS_CHANNELS_ERR)		\
	STATE(IDPF_VC_MAP_IRQ)			\
	STATE(IDPF_VC_MAP_IRQ_ERR)		\
	STATE(IDPF_VC_UNMAP_IRQ)		\
	STATE(IDPF_VC_UNMAP_IRQ_ERR)		\
	STATE(IDPF_VC_ADD_QUEUES)		\
	STATE(IDPF_VC_ADD_QUEUES_ERR)		\
	STATE(IDPF_VC_DEL_QUEUES)		\
	STATE(IDPF_VC_REQUEST_QUEUES)		\
	STATE(IDPF_VC_REQUEST_QUEUES_ERR)	\
	STATE(IDPF_VC_DEL_QUEUES_ERR)		\
	STATE(IDPF_VC_ALLOC_VECTORS)		\
	STATE(IDPF_VC_ALLOC_VECTORS_ERR)	\
	STATE(IDPF_VC_DEALLOC_VECTORS)		\
	STATE(IDPF_VC_DEALLOC_VECTORS_ERR)	\
	STATE(IDPF_VC_SET_SRIOV_VFS)		\
	STATE(IDPF_VC_SET_SRIOV_VFS_ERR)	\
	STATE(IDPF_VC_GET_RSS_HASH)		\
	STATE(IDPF_VC_GET_RSS_HASH_ERR)		\
	STATE(IDPF_VC_SET_RSS_HASH)		\
	STATE(IDPF_VC_SET_RSS_HASH_ERR)		\
	STATE(IDPF_VC_GET_RSS_LUT)		\
	STATE(IDPF_VC_GET_RSS_LUT_ERR)		\
	STATE(IDPF_VC_SET_RSS_LUT)		\
	STATE(IDPF_VC_SET_RSS_LUT_ERR)		\
	STATE(IDPF_VC_GET_RSS_KEY)		\
	STATE(IDPF_VC_GET_RSS_KEY_ERR)		\
	STATE(IDPF_VC_SET_RSS_KEY)		\
	STATE(IDPF_VC_SET_RSS_KEY_ERR)		\
	STATE(IDPF_VC_GET_STATS)		\
	STATE(IDPF_VC_GET_STATS_ERR)		\
	STATE(IDPF_VC_ENA_STRIP_VLAN_TAG)	\
	STATE(IDPF_VC_ENA_STRIP_VLAN_TAG_ERR)	\
	STATE(IDPF_VC_DIS_STRIP_VLAN_TAG)	\
	STATE(IDPF_VC_DIS_STRIP_VLAN_TAG_ERR)	\
	STATE(IDPF_VC_IWARP_IRQ_MAP_UNMAP)	\
	STATE(IDPF_VC_IWARP_IRQ_MAP_UNMAP_ERR)	\
	STATE(IDPF_VC_IWARP_SEND_SYNC)		\
	STATE(IDPF_VC_IWARP_SEND_SYNC_ERR)	\
	STATE(IDPF_VC_ADD_MAC_ADDR)		\
	STATE(IDPF_VC_ADD_MAC_ADDR_ERR)		\
	STATE(IDPF_VC_DEL_MAC_ADDR)		\
	STATE(IDPF_VC_DEL_MAC_ADDR_ERR)		\
	STATE(IDPF_VC_PROMISC)			\
	STATE(IDPF_VC_ADD_CLOUD_FILTER)		\
	STATE(IDPF_VC_ADD_CLOUD_FILTER_ERR)	\
	STATE(IDPF_VC_DEL_CLOUD_FILTER)		\
	STATE(IDPF_VC_DEL_CLOUD_FILTER_ERR)	\
	STATE(IDPF_VC_OFFLOAD_VLAN_V2_CAPS)	\
	STATE(IDPF_VC_OFFLOAD_VLAN_V2_CAPS_ERR)	\
	STATE(IDPF_VC_INSERTION_ENA_VLAN_V2)	\
	STATE(IDPF_VC_INSERTION_ENA_VLAN_V2_ERR)\
	STATE(IDPF_VC_INSERTION_DIS_VLAN_V2)	\
	STATE(IDPF_VC_INSERTION_DIS_VLAN_V2_ERR)\
	STATE(IDPF_VC_STRIPPING_ENA_VLAN_V2)	\
	STATE(IDPF_VC_STRIPPING_ENA_VLAN_V2_ERR)\
	STATE(IDPF_VC_STRIPPING_DIS_VLAN_V2)	\
	STATE(IDPF_VC_STRIPPING_DIS_VLAN_V2_ERR)\
	STATE(IDPF_VC_GET_SUPPORTED_RXDIDS)	\
	STATE(IDPF_VC_GET_SUPPORTED_RXDIDS_ERR)	\
	STATE(IDPF_VC_GET_PTYPE_INFO)		\
	STATE(IDPF_VC_GET_PTYPE_INFO_ERR)	\
	STATE(IDPF_VC_LOOPBACK_STATE)		\
	STATE(IDPF_VC_LOOPBACK_STATE_ERR)	\
	STATE(IDPF_VC_CREATE_ADI)		\
	STATE(IDPF_VC_CREATE_ADI_ERR)		\
	STATE(IDPF_VC_DESTROY_ADI)		\
	STATE(IDPF_VC_DESTROY_ADI_ERR)		\
	STATE(IDPF_VC_NBITS)

#define IDPF_GEN_ENUM(ENUM) ENUM,
#define IDPF_GEN_STRING(STRING) #STRING,

enum idpf_vport_vc_state {
	IDPF_FOREACH_VPORT_VC_STATE(IDPF_GEN_ENUM)
};

extern const char * const idpf_vport_vc_state_str[];

enum idpf_vport_flags {
	/* Soft reset causes */
	__IDPF_SR_Q_CHANGE, /* Soft reset to do queue change */
	__IDPF_SR_Q_DESC_CHANGE,
	__IDPF_SR_Q_SCH_CHANGE, /* Scheduling mode change in queue context */
	__IDPF_SR_MTU_CHANGE,
	__IDPF_SR_TC_CHANGE,
	__IDPF_SR_RSC_CHANGE,
	__IDPF_SR_HSPLIT_CHANGE,
	/* To send delete queues message */
	__IDPF_VPORT_DEL_QUEUES,
	/* Virtchnl message buffer received needs to be processed */
	__IDPF_VPORT_VC_MSG_PENDING,
	/* To process software marker packets */
	__IDPF_VPORT_SW_MARKER,
	__IDPF_VPORT_FLAGS_NBITS,
};

enum idpf_tw_tstamp_granularity {
	IDPF_TW_TIME_STAMP_GRAN_512_DIV_S = 9,
	IDPF_TW_TIME_STAMP_GRAN_1024_DIV_S = 10,
	IDPF_TW_TIME_STAMP_GRAN_2048_DIV_S = 11,
	IDPF_TW_TIME_STAMP_GRAN_4096_DIV_S = 12,
};

/* Horizon value in nanoseconds (MS * 1024 * 1024)*/
enum idpf_tw_horizon {
	IDPF_TW_HORIZON_32MS = 32 << 20,
	IDPF_TW_HORIZON_128MS = 128 << 20,
	IDPF_TW_HORIZON_512MS = 512 << 20,
};

#ifdef IDPF_ADD_PROBES
struct idpf_extra_stats {
	u64 tx_tcp_segs;
	u64 tx_udp_segs;
	u64 tx_tcp_cso;
	u64 tx_udp_cso;
	u64 tx_sctp_cso;
	u64 tx_ip4_cso;
	u64 rx_tcp_cso;
	u64 rx_udp_cso;
	u64 rx_sctp_cso;
	u64 rx_ip4_cso;
	u64 rx_tcp_cso_err;
	u64 rx_udp_cso_err;
	u64 rx_sctp_cso_err;
	u64 rx_ip4_cso_err;
	u64 rx_csum_complete;
	u64 rx_csum_unnecessary;
};

#endif /* IDPF_ADD_PROBES */
struct idpf_port_stats {
	struct u64_stats_sync stats_sync;
	u64 rx_hw_csum_err;
	u64 rx_hsplit;
	u64 rx_hsplit_hbo;
	u64 rx_bad_descs;
	u64 tx_linearize;
	u64 tx_busy;
	u64 tx_drops;
	u64 tx_dma_errs;
	u64 tx_reinjection_timeouts;
	struct virtchnl2_vport_stats vport_stats;
#ifdef IDPF_ADD_PROBES
	struct idpf_extra_stats extra_stats;
#endif /* IDPF_ADD_PROBES */
};

enum idpf_vport_state {
	__IDPF_VPORT_DOWN,
	__IDPF_VPORT_UP,
	__IDPF_VPORT_STATE_LAST, /* this member MUST be last */
};

struct idpf_vport {
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
	struct idpf_txq_group *txq_grps;
	u32 txq_model;
	/* Used only in hotpath to get to the right queue very fast */
	struct idpf_queue **txqs;
	DECLARE_BITMAP(flags, __IDPF_VPORT_FLAGS_NBITS);
	/* TX Timing Wheel parameters */
	enum idpf_tw_tstamp_granularity ts_gran;
	enum idpf_tw_horizon tw_horizon;

#ifdef HAVE_XDP_SUPPORT
	/* XDP TX */
	int num_xdp_txq;
	int num_xdp_rxq;
	int num_xdp_complq;
	int xdp_txq_offset;
	int xdp_rxq_offset;
	int xdp_complq_offset;
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	bool xsk_changing;
	unsigned long *af_xdp_zc_qps;
#endif
	void *(*xdp_prepare_tx_desc)(struct idpf_queue *xdpq, dma_addr_t dma,
				     u16 idx, u32 size);
#endif /* HAVE_XDP_SUPPORT */

	/* RX */
	int num_rxq;
	int num_bufq;
	int rxq_desc_count;
	u8 num_bufqs_per_qgrp;
	int bufq_desc_count[IDPF_MAX_BUFQS_PER_RXQ_GRP];
	u32 bufq_size[IDPF_MAX_BUFQS_PER_RXQ_GRP];
	int num_rxq_grp;
	struct idpf_rxq_group *rxq_grps;
	u32 rxq_model;
	struct idpf_rx_ptype_decoded rx_ptype_lkup[IDPF_RX_MAX_PTYPE];

	struct idpf_adapter *adapter;
	struct net_device *netdev;
	u16 vport_type;
	u32 vport_id;
	u16 idx;		 /* software index in adapter vports struct */
	bool default_vport;
	bool base_rxd;

	u16 num_q_vectors;
	struct idpf_q_vector *q_vectors;	/* q vector array */
	u16 *q_vector_idxs;			/* q vector index array */
	u16 max_mtu;
	u8 default_mac_addr[ETH_ALEN];
	u16 qset_handle;
	/* ITR profiles for the DIM algorithm */
#define IDPF_DIM_PROFILE_SLOTS	5
	u16 rx_itr_profile[IDPF_DIM_PROFILE_SLOTS];
	u16 tx_itr_profile[IDPF_DIM_PROFILE_SLOTS];
	struct rtnl_link_stats64 netstats;
	struct idpf_port_stats port_stats;

	bool link_up;
	s32 link_speed;
	/* This is only populated if the advance link speed is set in the
	 * capabilities. This field should be used going forward and
	 * the enum virtchnl_link_speed above should be considered the legacy
	 * way of storing/communicating link speeds.
	 */
	u32 link_speed_mbps;

	char vc_msg[IDPF_DFLT_MBX_BUF_SIZE];
	/* Everything below this will NOT be copied during soft reset */
	enum idpf_vport_state state;
	DECLARE_BITMAP(vc_state, IDPF_VC_NBITS);
	wait_queue_head_t vchnl_wq;
	wait_queue_head_t sw_marker_wq;
	/* lock to protect against multiple stop threads, which can happen when
	 * the driver is in a namespace in a system that is being shutdown
	 */
	struct mutex stop_mutex;
	/* lock to protect soft reset flow */
	struct mutex soft_reset_lock;

	/* lock to protect mac filters */
	spinlock_t mac_filter_list_lock;
};

enum idpf_user_flags {
	__IDPF_PRIV_FLAGS_HDR_SPLIT = 0,
	__IDPF_PROMISC_UC = 32,
	__IDPF_PROMISC_MC,
	__IDPF_USER_FLAGS_NBITS,
};

#define IDPF_GET_PTYPE_SIZE(p) \
	(sizeof(struct virtchnl2_ptype) + \
	(((p)->proto_id_count ? ((p)->proto_id_count - 1) : 0) * sizeof(u16)))

#define IDPF_TUN_IP_GRE (\
	IDPF_PTYPE_TUNNEL_IP |\
	IDPF_PTYPE_TUNNEL_IP_GRENAT)

#define IDPF_TUN_IP_GRE_MAC (\
	IDPF_TUN_IP_GRE |\
	IDPF_PTYPE_TUNNEL_IP_GRENAT_MAC)

enum idpf_tunnel_state {
	IDPF_PTYPE_TUNNEL_IP                    = BIT(0),
	IDPF_PTYPE_TUNNEL_IP_GRENAT             = BIT(1),
	IDPF_PTYPE_TUNNEL_IP_GRENAT_MAC         = BIT(2),
};

struct idpf_ptype_state {
	bool outer_ip;
	bool outer_frag;
	u8 tunnel_state;
};

struct idpf_rss_data {
	u64 rss_hash;
	u16 rss_key_size;
	u8 *rss_key;
	u16 rss_lut_size;
	u32 *rss_lut;
	u32 *cached_lut;
};

/* User defined configuration values for each vport */
struct idpf_vport_user_config_data {
	struct idpf_rss_data rss_data;
	u32 num_req_tx_qs; /* user requested TX queues through ethtool */
	u32 num_req_rx_qs; /* user requested RX queues through ethtool */
	u32 num_req_txq_desc; /* user requested TX queue descriptors through ethtool */
	u32 num_req_rxq_desc; /* user requested RX queue descriptors through ethtool */
#ifdef HAVE_XDP_SUPPORT
	/* Duplicated in queue structure for performance reasons */
	struct bpf_prog *xdp_prog;
#endif /* HAVE_XDP_SUPPORT */
	DECLARE_BITMAP(user_flags, __IDPF_USER_FLAGS_NBITS);
	DECLARE_BITMAP(etf_qenable, IDPF_LARGE_MAX_Q);
	struct list_head mac_filter_list;
};

enum idpf_vport_config_flags {
	/* Register netdev */
	__IDPF_VPORT_REG_NETDEV,
	/* set if interface up is requested on core reset */
	__IDPF_VPORT_UP_REQUESTED,
	__IDPF_VPORT_CONFIG_FLAGS_NBITS
};

/* Maintain total queues available after allocating max queues to each vport.
 * To start with, initialize the max queue limits from the
 * virtchnl2_get_capabilities.
 */
struct idpf_avail_queue_info {
	u16 avail_rxq;
	u16 avail_txq;
	u16 avail_bufq;
	u16 avail_complq;
};

/* Utility structure to pass function arguments as a structure */
struct idpf_vector_info {
	/* Vectors required based on the number of queues updated by the user
	 * via ethtool
	 */
	u16 num_req_vecs;
	u16 num_curr_vecs;	/* Vectors previously allocated */
	u16 index;		/* Vport relative index */
	bool default_vport;
};

/* Stack to maintain vector indexes used for 'vector distribution' algorithm */
struct idpf_vector_lifo {
	/* Vector stack maintains all the relative vector indexes at the
	 * *adapter* level. This stack is divided into 2 parts, first one is
	 * called as 'default pool' and other one is called 'free pool'.
	 * Vector distribution algorithm gives priority to default vports in
	 * a way that at least IDPF_MIN_Q_VEC vectors are allocated per
	 * default vport and the relative vector indexes for those are
	 * maintained in default pool. Free pool contains all the unallocated
	 * vector indexes which can be allocated on-demand basis.
	 * Mailbox vector index is maitained in the default pool of the stack
	 * and also the RDMA vectors.
	 */
	u16 top;	/* Points to stack top i.e. next available vector index */
	u16 base;	/* Always points to start of the 'free pool' */
	u16 size;	/* Total size of the vector stack */
	u16 *vec_idx;	/* Array to store all the vector indexes */
};

/* vport configuration data */
struct idpf_vport_config {
	struct idpf_vport_user_config_data user_config;
	struct idpf_vport_max_q max_q;
	void *req_qs_chunks;
	DECLARE_BITMAP(flags, __IDPF_VPORT_CONFIG_FLAGS_NBITS);
};

struct idpf_adapter {
	struct pci_dev *pdev;
	const char *drv_name;
	const char *drv_ver;
	u32 virt_ver_maj;
	u32 virt_ver_min;

	u32 msg_enable;
	enum idpf_state state;
	DECLARE_BITMAP(flags, __IDPF_FLAGS_NBITS);
	struct mutex reset_lock; /* lock to protect reset flows */
	struct idpf_reset_reg reset_reg;
	struct idpf_hw hw;
	bool  adi_ena[IDPF_MAX_ADI_NUM];
	u16 num_req_msix;
	u16 num_avail_msix;
	u16 num_msix_entries;
	struct msix_entry *msix_entries;
	struct virtchnl2_alloc_vectors *req_vec_chunks;
	struct idpf_q_vector mb_vector;
	/* Stack to store the msix vector indexes */
	struct idpf_vector_lifo vector_stack;
	/* handler for hard interrupt for mailbox*/
	irqreturn_t (*irq_mb_handler)(int irq, void *data);

	/* vport structs */
	u32 tx_timeout_count;
	u16 vectors_per_vport;
	struct idpf_avail_queue_info avail_queues;
	/* array to store vports created by the driver */
	struct idpf_vport **vports;
	struct net_device **netdevs;	/* associated vport netdevs */
	/* Store the resources data received from control plane */
	void **vport_params_reqd;
	void **vport_params_recvd;
	u32 *vport_ids;

	/* vport parameters */
	struct idpf_vport_config **vport_config;
	/* maximum number of vports that can be created by the driver */
	u16 max_vports;
	/* current number of vports created by the driver */
	u16 num_alloc_vports;
	u16 next_vport;		/* Next free slot in pf->vport[] - 0-based! */

	struct delayed_work init_task; /* delayed init task */
	struct workqueue_struct *init_wq;
	u32 mb_wait_count;
	struct delayed_work serv_task; /* delayed service task */
	struct workqueue_struct *serv_wq;
	struct delayed_work vc_event_task; /* delayed virtchannel event task */
	struct workqueue_struct *vc_event_wq;
	struct delayed_work stats_task; /* delayed statistics task */
	struct workqueue_struct *stats_wq;
	struct virtchnl2_get_capabilities caps;

	wait_queue_head_t vchnl_wq;
	DECLARE_BITMAP(vc_state, IDPF_VC_NBITS);
	char vc_msg[IDPF_DFLT_MBX_BUF_SIZE];
	struct idpf_dev_ops dev_ops;
	struct idpf_rdma_data rdma_data;
	int num_vfs;

	struct mutex sw_mutex;		/* lock to protect vport alloc flow */
	struct mutex vector_lock;	/* lock to protect vector distribution */
	struct mutex queue_lock;	/* lock to protect queue distribution */
#ifdef DEVLINK_ENABLED
	struct list_head sf_list;
	unsigned short sf_id;
	unsigned short sf_cnt;
#endif /* DEVLINK_ENABLED */
};

#define idpf_adapter_to_dev(pf) (&((pf)->pdev->dev))

/**
 * idpf_is_queue_model_split - check if queue model is split
 * @q_model: queue model single or split
 *
 * Returns true if queue model is split else false
 */
static inline int idpf_is_queue_model_split(u16 q_model)
{
	return (q_model == VIRTCHNL2_QUEUE_MODEL_SPLIT);
}

#ifdef HAVE_XDP_SUPPORT
/**
 * idpf_xdp_is_prog_ena - check if there is an XDP program on adapter
 * @vport: vport to check
 */
static inline bool idpf_xdp_is_prog_ena(struct idpf_vport *vport)
{
	if (!vport->adapter)
		return false;

	return !!vport->adapter->vport_config[vport->idx]->user_config.xdp_prog;
}

/**
 * idpf_get_related_xdp_queue - Get corresponding XDP Tx queue for Rx queue
 * @rxq: Rx queue
 *
 * Returns a pointer to XDP Tx queue linked to a given Rx queue.
 */
static inline struct idpf_queue *idpf_get_related_xdp_queue(struct idpf_queue *rxq)
{
		return rxq->vport->txqs[rxq->idx + rxq->vport->xdp_txq_offset];
}

#endif /* HAVE_XDP_SUPPORT */

#define idpf_is_cap_ena(adapter, field, flag) \
	idpf_is_capability_ena(adapter, false, field, flag)
#define idpf_is_cap_ena_all(adapter, field, flag) \
	idpf_is_capability_ena(adapter, true, field, flag)

bool idpf_is_capability_ena(struct idpf_adapter *adapter, bool all,
			    enum idpf_cap_field field, u64 flag);

/**
 * idpf_is_rdma_cap_ena - Determine if RDMA is supported
 * @adapter: private data struct
 */
static inline bool idpf_is_rdma_cap_ena(struct idpf_adapter *adapter)
{
	return idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_RDMA);
}

#define IDPF_CAP_RSS (\
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

#define IDPF_CAP_RSC (\
	VIRTCHNL2_CAP_RSC_IPV4_TCP	|\
	VIRTCHNL2_CAP_RSC_IPV4_SCTP	|\
	VIRTCHNL2_CAP_RSC_IPV6_TCP	|\
	VIRTCHNL2_CAP_RSC_IPV6_SCTP)

#define IDPF_CAP_HSPLIT	(\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L2	|\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L3	|\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V4	|\
	VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V6)

#define IDPF_CAP_RX_CSUM_L4V4 (\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP)

#define IDPF_CAP_RX_CSUM_L4V6 (\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP)

#define IDPF_CAP_RX_CSUM (\
	VIRTCHNL2_CAP_RX_CSUM_L3_IPV4		|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP)

#define IDPF_CAP_SCTP_CSUM (\
	VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_SCTP	|\
	VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_SCTP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP)

#define IDPF_CAP_TUNNEL_TX_CSUM (\
	VIRTCHNL2_CAP_TX_CSUM_L3_SINGLE_TUNNEL	|\
	VIRTCHNL2_CAP_TX_CSUM_L3_DOUBLE_TUNNEL	|\
	VIRTCHNL2_CAP_TX_CSUM_L4_SINGLE_TUNNEL	|\
	VIRTCHNL2_CAP_TX_CSUM_L4_DOUBLE_TUNNEL)

#define IDPF_CAP_TUNNEL_RX_CSUM (\
	VIRTCHNL2_CAP_RX_CSUM_L3_SINGLE_TUNNEL	|\
	VIRTCHNL2_CAP_RX_CSUM_L3_DOUBLE_TUNNEL	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_SINGLE_TUNNEL	|\
	VIRTCHNL2_CAP_RX_CSUM_L4_DOUBLE_TUNNEL)

#define IDPF_CAP_TUNNEL (\
	VIRTCHNL2_CAP_SEG_TX_SINGLE_TUNNEL |\
	VIRTCHNL2_CAP_SEG_TX_DOUBLE_TUNNEL)

/**
 * idpf_get_reserved_vecs - Get reserved vectors
 * @adapter: private data struct
 */
static inline u16 idpf_get_reserved_vecs(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.num_allocated_vectors);
}

/**
 * idpf_get_default_vports - Get default number of vports
 * @adapter: private data struct
 */
static inline u16 idpf_get_default_vports(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.default_num_vports);
}

/**
 * idpf_get_max_vports - Get max number of vports
 * @adapter: private data struct
 */
static inline u16 idpf_get_max_vports(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.max_vports);
}

/**
 * idpf_get_max_tx_bufs - Get max scatter-gather buffers supported by the device
 * @adapter: private data struct
 */
static inline unsigned int idpf_get_max_tx_bufs(struct idpf_adapter *adapter)
{
	return adapter->caps.max_sg_bufs_per_tx_pkt;
}

/**
 * idpf_get_min_tx_pkt_len - Get min packet length supported by the device
 * @adapter: private data struct
 */
static inline u8 idpf_get_min_tx_pkt_len(struct idpf_adapter *adapter)
{
	u8 pkt_len = adapter->caps.min_sso_packet_len;

	return pkt_len ? pkt_len : IDPF_TX_MIN_LEN;
}

/**
 * idpf_get_reg_addr - Get BAR0 register address
 * @adapter: private data struct
 * @reg_offset: register offset value
 *
 * Based on the register offset, return the actual BAR0 register address
 */
static inline u8 __iomem *idpf_get_reg_addr(struct idpf_adapter *adapter, u32 reg_offset)
{
	struct idpf_hw *hw = &adapter->hw;

	if (reg_offset < adapter->dev_ops.bar0_region1_size)
		return (u8 __iomem *)(hw->hw_addr + reg_offset);
	else
		return (u8 __iomem *)(hw->hw_addr_region2 + reg_offset -
				      adapter->dev_ops.bar0_region2_start);
}

/**
 * idpf_is_reset_detected - check if we were reset at some point
 * @adapter: driver specific private structure
 *
 * Returns true if we are either in reset currently or were previously reset.
 */
static inline bool idpf_is_reset_detected(struct idpf_adapter *adapter)
{
	if (!adapter->hw.arq)
		return true;

	/* Simics/CP isn't clearing the enable bit, just the length which isn't
	 * how it works in legacy iavf.
	 */
	return !(readl(idpf_get_reg_addr(adapter, adapter->hw.arq->reg.len)) &
			adapter->hw.arq->reg.len_mask);
}

/**
 * idpf_is_reset_in_prog - check if reset is in progress
 * @adapter: driver specific private structure
 *
 * Returns true if hard reset is in progress, false otherwise
 */
static inline bool idpf_is_reset_in_prog(struct idpf_adapter *adapter)
{
	return (test_bit(__IDPF_HR_RESET_IN_PROG, adapter->flags) ||
		test_bit(__IDPF_HR_FUNC_RESET, adapter->flags) ||
		test_bit(__IDPF_HR_CORE_RESET, adapter->flags) ||
		test_bit(__IDPF_HR_DRV_LOAD, adapter->flags));
}

/**
 * idpf_rx_offset - Return expected offset into page to access data
 * @rx_q: queue we are requesting offset of
 *
 * Returns the offset value for queue into the data buffer.
 */
static inline unsigned int
idpf_rx_offset(struct idpf_queue __maybe_unused *rx_q)
{
#ifdef HAVE_XDP_SUPPORT
	return idpf_xdp_is_prog_ena(rx_q->vport) ? XDP_PACKET_HEADROOM : 0;
#else
	return 0;
#endif /* HAVE_XDP_SUPPORT */
}

int idpf_vport_adjust_qs(struct idpf_vport *vport);
int idpf_pf_probe(struct pci_dev *pdev, struct idpf_adapter *adapter);
int idpf_vf_probe(struct pci_dev *pdev, struct idpf_adapter *adapter);
int idpf_probe_common(struct pci_dev *pdev, struct idpf_adapter *adapter);
void idpf_remove_common(struct pci_dev *pdev);
int idpf_init_dflt_mbx(struct idpf_adapter *adapter);
void idpf_deinit_dflt_mbx(struct idpf_adapter *adapter);
int idpf_vc_core_init(struct idpf_adapter *adapter);
int idpf_intr_req(struct idpf_adapter *adapter);
void idpf_intr_rel(struct idpf_adapter *adapter);
int idpf_get_reg_intr_vecs(struct idpf_vport *vport,
			   struct idpf_vec_regs *reg_vals);
int idpf_wait_for_event(struct idpf_adapter *adapter,
			struct idpf_vport *vport,
			enum idpf_vport_vc_state state,
			enum idpf_vport_vc_state err_check);
int idpf_min_wait_for_event(struct idpf_adapter *adapter,
			    struct idpf_vport *vport,
			    enum idpf_vport_vc_state state,
			    enum idpf_vport_vc_state err_check);
int idpf_msec_wait_for_event(struct idpf_adapter *adapter,
			     struct idpf_vport *vport,
			     enum idpf_vport_vc_state state,
			     enum idpf_vport_vc_state err_check,
			     int timeout);
#ifdef HAVE_NDO_FEATURES_CHECK
u16 idpf_get_max_tx_hdr_size(struct idpf_adapter *adapter);
#endif /* HAVE_NDO_FEATURES_CHECK */
int idpf_send_ver_msg(struct idpf_adapter *adapter);
int idpf_recv_ver_msg(struct idpf_adapter *adapter);
int idpf_send_get_caps_msg(struct idpf_adapter *adapter);
int idpf_recv_get_caps_msg(struct idpf_adapter *adapter);
int idpf_send_delete_queues_msg(struct idpf_vport *vport);
int idpf_send_add_queues_msg(const struct idpf_vport *vport, u16 num_tx_q,
			     u16 num_complq, u16 num_rx_q, u16 num_rx_bufq);
int idpf_initiate_soft_reset(struct idpf_vport *vport,
			     enum idpf_vport_flags reset_cause);
int idpf_send_config_tx_queues_msg(struct idpf_vport *vport);
int idpf_send_config_rx_queues_msg(struct idpf_vport *vport);
int idpf_send_enable_vport_msg(struct idpf_vport *vport);
int idpf_send_disable_vport_msg(struct idpf_vport *vport);
int idpf_send_destroy_vport_msg(struct idpf_vport *vport);
int idpf_send_get_rx_ptype_msg(struct idpf_vport *vport);
int idpf_send_ena_dis_loopback_msg(struct idpf_vport *vport);
int idpf_send_get_set_rss_key_msg(struct idpf_vport *vport, bool get);
int idpf_send_get_set_rss_lut_msg(struct idpf_vport *vport, bool get);
int idpf_send_get_set_rss_hash_msg(struct idpf_vport *vport, bool get);
int idpf_send_dealloc_vectors_msg(struct idpf_adapter *adapter);
int idpf_send_alloc_vectors_msg(struct idpf_adapter *adapter, u16 num_vectors);
void idpf_init_task(struct work_struct *work);
void idpf_deinit_task(struct idpf_adapter *adapter);
int idpf_init_vector_stack(struct idpf_adapter *adapter);
void idpf_deinit_vector_stack(struct idpf_adapter *adapter);
int idpf_req_rel_vector_indexes(struct idpf_adapter *adapter,
				u16 *q_vector_idxs,
				struct idpf_vector_info *vec_info);
int idpf_vport_alloc_vec_indexes(struct idpf_vport *vport);
void idpf_vc_core_deinit(struct idpf_adapter *adapter);
void idpf_vport_params_buf_rel(struct idpf_adapter *adapter);
struct idpf_vport *idpf_netdev_to_vport(struct net_device *netdev);
int idpf_send_get_stats_msg(struct idpf_vport *vport);
int idpf_get_vec_ids(struct idpf_adapter *adapter,
		     u16 *vecids, int num_vecids,
		     struct virtchnl2_vector_chunks *chunks);
int idpf_recv_mb_msg(struct idpf_adapter *adapter, u32 op,
		     void *msg, int msg_size);
int idpf_send_mb_msg(struct idpf_adapter *adapter, u32 op,
		     u16 msg_size, u8 *msg);
void idpf_set_ethtool_ops(struct net_device *netdev);
void idpf_vport_set_hsplit(struct idpf_vport *vport, bool ena);
void idpf_vport_dealloc(struct idpf_vport *vport);
int idpf_vport_alloc_max_qs(struct idpf_adapter *adapter,
			    struct idpf_vport_max_q *max_q);
void idpf_vport_dealloc_max_qs(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q);
int idpf_add_del_mac_filters(struct idpf_vport *vport, bool add, bool async);
int idpf_set_promiscuous(struct idpf_vport *vport);
int idpf_send_disable_queues_msg(struct idpf_vport *vport);
void idpf_vport_init(struct idpf_vport *vport, struct idpf_vport_max_q *max_q);
u32 idpf_get_vport_id(struct idpf_vport *vport);
int idpf_vport_queue_ids_init(struct idpf_vport *vport);
int idpf_queue_reg_init(struct idpf_vport *vport);
int idpf_send_config_queues_msg(struct idpf_vport *vport);
int idpf_send_enable_queues_msg(struct idpf_vport *vport);
int idpf_send_create_vport_msg(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q);
int idpf_check_supported_desc_ids(struct idpf_vport *vport);
bool idpf_is_feature_ena(struct idpf_vport *vport, netdev_features_t feature);
int idpf_set_msg_pending(struct idpf_adapter *adapter,
			 struct idpf_vport *vport,
			 struct idpf_ctlq_msg *ctlq_msg,
			 enum idpf_vport_vc_state err_enum);
int idpf_send_create_adi_msg(struct idpf_adapter *adapter,
			     struct virtchnl2_create_adi *vchnl_adi);
int idpf_send_destroy_adi_msg(struct idpf_adapter *adapter,
			      struct virtchnl2_destroy_adi *vchnl_adi);
void idpf_vport_intr_write_itr(struct idpf_q_vector *q_vector,
			       u16 itr, bool tx);
int idpf_send_map_unmap_queue_vector_msg(struct idpf_vport *vport, bool map);
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_XDP_FRAME_STRUCT
int idpf_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
		  u32 flags);
#else
int idpf_xdp_xmit(struct net_device *dev, struct xdp_buff *xdp);
#endif /* HAVE_XDP_FRAME_STRUCT */
#ifndef NO_NDO_XDP_FLUSH
void idpf_xdp_flush(struct net_device *dev);
#endif /* NO_NDO_XDP_FLUSH */
#endif /* HAVE_XDP_SUPPORT */
int idpf_get_max_vfs(struct idpf_adapter *adapter);
int idpf_send_set_sriov_vfs_msg(struct idpf_adapter *adapter, u16 num_vfs);
int idpf_sriov_configure(struct pci_dev *pdev, int num_vfs);
int idpf_idc_init(struct idpf_adapter *adapter);
void idpf_idc_deinit(struct idpf_adapter *adapter);
int
idpf_idc_init_aux_device(struct idpf_adapter *adapter,
			 enum iidc_function_type ftype);
void idpf_idc_deinit_aux_device(struct idpf_adapter *adapter);
int idpf_idc_vc_receive(struct idpf_adapter *adapter, u32 f_id, u8 *msg,
			u16 msg_size);
void idpf_idc_event(struct idpf_adapter *adapter, enum idpf_vport_flags reason,
		    bool pre_event);

#endif /* !_IDPF_H_ */
