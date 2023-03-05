/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2019 Intel Corporation */
#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include "kcompat_gcc.h"
#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/if_link.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/mii.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/vmalloc.h>

#ifndef GCC_VERSION
#define GCC_VERSION (__GNUC__ * 10000		\
		     + __GNUC_MINOR__ * 100	\
		     + __GNUC_PATCHLEVEL__)
#endif /* GCC_VERSION */

#ifndef IEEE_8021QAZ_APP_SEL_DSCP
#define IEEE_8021QAZ_APP_SEL_DSCP	5
#endif

#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC 1000000L
#endif
#include <net/ipv6.h>
/* UTS_RELEASE is in a different header starting in kernel 2.6.18 */
#ifndef UTS_RELEASE
/* utsrelease.h changed locations in 2.6.33 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33) )
#include <linux/utsrelease.h>
#else
#include <generated/utsrelease.h>
#endif
#endif

/* NAPI enable/disable flags here */

/* and finally set defines so that the code sees the changes */
#ifdef NAPI
#else
#endif /* NAPI */

/* Dynamic LTR and deeper C-State support disable/enable */

/* packet split disable/enable */
#ifdef DISABLE_PACKET_SPLIT
#endif /* DISABLE_PACKET_SPLIT */

/* MSI compatibility code for all kernels and drivers */
#ifdef DISABLE_PCI_MSI
#undef CONFIG_PCI_MSI
#endif
#ifndef CONFIG_PCI_MSI
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8) )
struct msix_entry {
	u16 vector; /* kernel uses to write allocated vector */
	u16 entry;  /* driver uses to specify entry, OS writes */
};
#endif
#undef pci_enable_msi
#define pci_enable_msi(a) -ENOTSUPP
#undef pci_disable_msi
#define pci_disable_msi(a) do {} while (0)
#undef pci_enable_msix
#define pci_enable_msix(a, b, c) -ENOTSUPP
#undef pci_disable_msix
#define pci_disable_msix(a) do {} while (0)
#define msi_remove_pci_irq_vectors(a) do {} while (0)
#endif /* CONFIG_PCI_MSI */
#ifdef DISABLE_PM
#undef CONFIG_PM
#endif

#ifdef DISABLE_NET_POLL_CONTROLLER
#undef CONFIG_NET_POLL_CONTROLLER
#endif

#ifndef PMSG_SUSPEND
#define PMSG_SUSPEND 3
#endif

/* generic boolean compatibility */
#undef TRUE
#undef FALSE
#define TRUE true
#define FALSE false
#ifdef GCC_VERSION
#if ( GCC_VERSION < 3000 )
#define _Bool char
#endif
#else
#define _Bool char
#endif

#ifndef BIT
#define BIT(nr)         (1UL << (nr))
#endif

#undef __always_unused
#define __always_unused __attribute__((__unused__))

#undef __maybe_unused
#define __maybe_unused __attribute__((__unused__))

/* kernels less than 2.4.14 don't have this */
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef module_param
#define module_param(v,t,p) MODULE_PARM(v, "i");
#endif

#ifndef DMA_64BIT_MASK
#define DMA_64BIT_MASK  0xffffffffffffffffULL
#endif

#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK  0x00000000ffffffffULL
#endif

#ifndef PCI_CAP_ID_EXP
#define PCI_CAP_ID_EXP 0x10
#endif

#ifndef uninitialized_var
#define uninitialized_var(x) x = x
#endif

#ifndef PCIE_LINK_STATE_L0S
#define PCIE_LINK_STATE_L0S 1
#endif
#ifndef PCIE_LINK_STATE_L1
#define PCIE_LINK_STATE_L1 2
#endif

#ifndef SET_NETDEV_DEV
#define SET_NETDEV_DEV(net, pdev)
#endif

#if !defined(HAVE_FREE_NETDEV) && ( LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0) )
#define free_netdev(x)	kfree(x)
#endif

#ifdef HAVE_POLL_CONTROLLER
#define CONFIG_NET_POLL_CONTROLLER
#endif

#ifndef SKB_DATAREF_SHIFT
/* if we do not have the infrastructure to detect if skb_header is cloned
   just return false in all cases */
#define skb_header_cloned(x) 0
#endif

#ifndef NETIF_F_GSO
#define gso_size tso_size
#define gso_segs tso_segs
#endif

#ifndef NETIF_F_GRO
#define vlan_gro_receive(_napi, _vlgrp, _vlan, _skb) \
		vlan_hwaccel_receive_skb(_skb, _vlgrp, _vlan)
#define napi_gro_receive(_napi, _skb) netif_receive_skb(_skb)
#endif

#ifndef NETIF_F_SCTP_CSUM
#define NETIF_F_SCTP_CSUM 0
#endif

#ifndef NETIF_F_LRO
#define NETIF_F_LRO BIT(15)
#endif

#ifndef NETIF_F_NTUPLE
#define NETIF_F_NTUPLE BIT(27)
#endif

#ifndef NETIF_F_ALL_FCOE
#define NETIF_F_ALL_FCOE	(NETIF_F_FCOE_CRC | NETIF_F_FCOE_MTU | \
				 NETIF_F_FSO)
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE 136
#endif

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

#ifndef __read_mostly
#define __read_mostly
#endif

#ifndef MII_RESV1
#define MII_RESV1		0x17		/* Reserved...		*/
#endif

#ifndef unlikely
#define unlikely(_x) _x
#define likely(_x) _x
#endif

#ifndef WARN_ON
#define WARN_ON(x) ({0;})
#endif

#ifndef PCI_DEVICE
#define PCI_DEVICE(vend,dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#endif

#ifndef node_online
#define node_online(node) ((node) == 0)
#endif

#ifndef _LINUX_RANDOM_H
#include <linux/random.h>
#endif

#ifndef BITS_PER_TYPE
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#endif

#ifndef BITS_TO_LONGS
#define BITS_TO_LONGS(bits) (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#endif

#ifndef DECLARE_BITMAP
#define DECLARE_BITMAP(name,bits) long name[BITS_TO_LONGS(bits)]
#endif

#ifndef VLAN_HLEN
#define VLAN_HLEN 4
#endif

#ifndef VLAN_ETH_HLEN
#define VLAN_ETH_HLEN 18
#endif

#ifndef VLAN_ETH_FRAME_LEN
#define VLAN_ETH_FRAME_LEN 1518
#endif

#ifndef DCA_GET_TAG_TWO_ARGS
#define dca3_get_tag(a,b) dca_get_tag(b)
#endif

#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#if defined(__i386__) || defined(__x86_64__)
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#endif
#endif

/* taken from 2.6.24 definition in linux/kernel.h */
#ifndef IS_ALIGNED
#define IS_ALIGNED(x,a)         (((x) % ((typeof(x))(a))) == 0)
#endif

#ifdef IS_ENABLED
#undef IS_ENABLED
#undef __ARG_PLACEHOLDER_1
#undef config_enabled
#undef _config_enabled
#undef __config_enabled
#undef ___config_enabled
#endif

#define __ARG_PLACEHOLDER_1 0,
#define config_enabled(cfg) _config_enabled(cfg)
#ifdef __CHECKER__
/* cppcheck-suppress preprocessorErrorDirective */
#endif /* __CHECKER__ */
#define _config_enabled(value) __config_enabled(__ARG_PLACEHOLDER_##value)
#define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)
#define ___config_enabled(__ignored, val, ...) val

#define IS_ENABLED(option) \
	(config_enabled(option) || config_enabled(option##_MODULE))

#if !defined(NETIF_F_HW_VLAN_TX) && !defined(NETIF_F_HW_VLAN_CTAG_TX)
struct _kc_vlan_ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_vlan_proto;
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
};
#define vlan_ethhdr _kc_vlan_ethhdr
struct _kc_vlan_hdr {
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
};
#define vlan_hdr _kc_vlan_hdr
#define vlan_tx_tag_present(_skb) 0
#define vlan_tx_tag_get(_skb) 0
#endif /* NETIF_F_HW_VLAN_TX && NETIF_F_HW_VLAN_CTAG_TX */

#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT 13
#endif

#ifndef PCI_EXP_LNKSTA_CLS_2_5GB
#define PCI_EXP_LNKSTA_CLS_2_5GB 0x0001
#endif

#ifndef PCI_EXP_LNKSTA_CLS_5_0GB
#define PCI_EXP_LNKSTA_CLS_5_0GB 0x0002
#endif

#ifndef PCI_EXP_LNKSTA_CLS_8_0GB
#define PCI_EXP_LNKSTA_CLS_8_0GB 0x0003
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X1
#define PCI_EXP_LNKSTA_NLW_X1 0x0010
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X2
#define PCI_EXP_LNKSTA_NLW_X2 0x0020
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X4
#define PCI_EXP_LNKSTA_NLW_X4 0x0040
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X8
#define PCI_EXP_LNKSTA_NLW_X8 0x0080
#endif

#ifndef __GFP_COLD
#define __GFP_COLD 0
#endif

#ifndef __GFP_COMP
#define __GFP_COMP 0
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF /* "Fragment Offset" part */
#endif

/*****************************************************************************/
/* Installations with ethtool version without eeprom, adapter id, or statistics
 * support */

#ifndef ETH_GSTRING_LEN
#define ETH_GSTRING_LEN 32
#endif

#ifndef ETHTOOL_GSTATS
#define ETHTOOL_GSTATS 0x1d
#undef ethtool_drvinfo
#define ethtool_drvinfo k_ethtool_drvinfo
struct k_ethtool_drvinfo {
	u32 cmd;
	char driver[32];
	char version[32];
	char fw_version[32];
	char bus_info[32];
	char reserved1[32];
	char reserved2[16];
	u32 n_stats;
	u32 testinfo_len;
	u32 eedump_len;
	u32 regdump_len;
};

struct ethtool_stats {
	u32 cmd;
	u32 n_stats;
	u64 data[0];
};
#endif /* ETHTOOL_GSTATS */

#ifndef ETHTOOL_PHYS_ID
#define ETHTOOL_PHYS_ID 0x1c
#endif /* ETHTOOL_PHYS_ID */

#ifndef ETHTOOL_GSTRINGS
#define ETHTOOL_GSTRINGS 0x1b
enum ethtool_stringset {
	ETH_SS_TEST             = 0,
	ETH_SS_STATS,
};
struct ethtool_gstrings {
	u32 cmd;            /* ETHTOOL_GSTRINGS */
	u32 string_set;     /* string set id e.c. ETH_SS_TEST, etc*/
	u32 len;            /* number of strings in the string set */
	u8 data[0];
};
#endif /* ETHTOOL_GSTRINGS */

#ifndef ETHTOOL_TEST
#define ETHTOOL_TEST 0x1a
enum ethtool_test_flags {
	ETH_TEST_FL_OFFLINE	= BIT(0),
	ETH_TEST_FL_FAILED	= BIT(1),
};
struct ethtool_test {
	u32 cmd;
	u32 flags;
	u32 reserved;
	u32 len;
	u64 data[0];
};
#endif /* ETHTOOL_TEST */

#ifndef ETHTOOL_GEEPROM
#define ETHTOOL_GEEPROM 0xb
#undef ETHTOOL_GREGS
struct ethtool_eeprom {
	u32 cmd;
	u32 magic;
	u32 offset;
	u32 len;
	u8 data[0];
};

struct ethtool_value {
	u32 cmd;
	u32 data;
};
#endif /* ETHTOOL_GEEPROM */

#ifndef ETHTOOL_GLINK
#define ETHTOOL_GLINK 0xa
#endif /* ETHTOOL_GLINK */

#ifndef ETHTOOL_GWOL
#define ETHTOOL_GWOL 0x5
#define ETHTOOL_SWOL 0x6
#define SOPASS_MAX      6
struct ethtool_wolinfo {
	u32 cmd;
	u32 supported;
	u32 wolopts;
	u8 sopass[SOPASS_MAX]; /* SecureOn(tm) password */
};
#endif /* ETHTOOL_GWOL */

#ifndef ETHTOOL_GREGS
#define ETHTOOL_GREGS		0x00000004 /* Get NIC registers */
#define ethtool_regs _kc_ethtool_regs
/* for passing big chunks of data */
struct _kc_ethtool_regs {
	u32 cmd;
	u32 version; /* driver-specific, indicates different chips/revs */
	u32 len; /* bytes */
	u8 data[0];
};
#endif /* ETHTOOL_GREGS */

#ifndef ETHTOOL_GMSGLVL
#define ETHTOOL_GMSGLVL		0x00000007 /* Get driver message level */
#endif
#ifndef ETHTOOL_SMSGLVL
#define ETHTOOL_SMSGLVL		0x00000008 /* Set driver msg level, priv. */
#endif
#ifndef ETHTOOL_NWAY_RST
#define ETHTOOL_NWAY_RST	0x00000009 /* Restart autonegotiation, priv */
#endif
#ifndef ETHTOOL_GLINK
#define ETHTOOL_GLINK		0x0000000a /* Get link status */
#endif
#ifndef ETHTOOL_GEEPROM
#define ETHTOOL_GEEPROM		0x0000000b /* Get EEPROM data */
#endif
#ifndef ETHTOOL_SEEPROM
#define ETHTOOL_SEEPROM		0x0000000c /* Set EEPROM data */
#endif
#ifndef ETHTOOL_GCOALESCE
#define ETHTOOL_GCOALESCE	0x0000000e /* Get coalesce config */
/* for configuring coalescing parameters of chip */
#define ethtool_coalesce _kc_ethtool_coalesce
struct _kc_ethtool_coalesce {
	u32	cmd;	/* ETHTOOL_{G,S}COALESCE */

	/* How many usecs to delay an RX interrupt after
	 * a packet arrives.  If 0, only rx_max_coalesced_frames
	 * is used.
	 */
	u32	rx_coalesce_usecs;

	/* How many packets to delay an RX interrupt after
	 * a packet arrives.  If 0, only rx_coalesce_usecs is
	 * used.  It is illegal to set both usecs and max frames
	 * to zero as this would cause RX interrupts to never be
	 * generated.
	 */
	u32	rx_max_coalesced_frames;

	/* Same as above two parameters, except that these values
	 * apply while an IRQ is being serviced by the host.  Not
	 * all cards support this feature and the values are ignored
	 * in that case.
	 */
	u32	rx_coalesce_usecs_irq;
	u32	rx_max_coalesced_frames_irq;

	/* How many usecs to delay a TX interrupt after
	 * a packet is sent.  If 0, only tx_max_coalesced_frames
	 * is used.
	 */
	u32	tx_coalesce_usecs;

	/* How many packets to delay a TX interrupt after
	 * a packet is sent.  If 0, only tx_coalesce_usecs is
	 * used.  It is illegal to set both usecs and max frames
	 * to zero as this would cause TX interrupts to never be
	 * generated.
	 */
	u32	tx_max_coalesced_frames;

	/* Same as above two parameters, except that these values
	 * apply while an IRQ is being serviced by the host.  Not
	 * all cards support this feature and the values are ignored
	 * in that case.
	 */
	u32	tx_coalesce_usecs_irq;
	u32	tx_max_coalesced_frames_irq;

	/* How many usecs to delay in-memory statistics
	 * block updates.  Some drivers do not have an in-memory
	 * statistic block, and in such cases this value is ignored.
	 * This value must not be zero.
	 */
	u32	stats_block_coalesce_usecs;

	/* Adaptive RX/TX coalescing is an algorithm implemented by
	 * some drivers to improve latency under low packet rates and
	 * improve throughput under high packet rates.  Some drivers
	 * only implement one of RX or TX adaptive coalescing.  Anything
	 * not implemented by the driver causes these values to be
	 * silently ignored.
	 */
	u32	use_adaptive_rx_coalesce;
	u32	use_adaptive_tx_coalesce;

	/* When the packet rate (measured in packets per second)
	 * is below pkt_rate_low, the {rx,tx}_*_low parameters are
	 * used.
	 */
	u32	pkt_rate_low;
	u32	rx_coalesce_usecs_low;
	u32	rx_max_coalesced_frames_low;
	u32	tx_coalesce_usecs_low;
	u32	tx_max_coalesced_frames_low;

	/* When the packet rate is below pkt_rate_high but above
	 * pkt_rate_low (both measured in packets per second) the
	 * normal {rx,tx}_* coalescing parameters are used.
	 */

	/* When the packet rate is (measured in packets per second)
	 * is above pkt_rate_high, the {rx,tx}_*_high parameters are
	 * used.
	 */
	u32	pkt_rate_high;
	u32	rx_coalesce_usecs_high;
	u32	rx_max_coalesced_frames_high;
	u32	tx_coalesce_usecs_high;
	u32	tx_max_coalesced_frames_high;

	/* How often to do adaptive coalescing packet rate sampling,
	 * measured in seconds.  Must not be zero.
	 */
	u32	rate_sample_interval;
};
#endif /* ETHTOOL_GCOALESCE */

#ifndef ETHTOOL_SCOALESCE
#define ETHTOOL_SCOALESCE	0x0000000f /* Set coalesce config. */
#endif
#ifndef ETHTOOL_GRINGPARAM
#define ETHTOOL_GRINGPARAM	0x00000010 /* Get ring parameters */
/* for configuring RX/TX ring parameters */
#define ethtool_ringparam _kc_ethtool_ringparam
struct _kc_ethtool_ringparam {
	u32	cmd;	/* ETHTOOL_{G,S}RINGPARAM */

	/* Read only attributes.  These indicate the maximum number
	 * of pending RX/TX ring entries the driver will allow the
	 * user to set.
	 */
	u32	rx_max_pending;
	u32	rx_mini_max_pending;
	u32	rx_jumbo_max_pending;
	u32	tx_max_pending;

	/* Values changeable by the user.  The valid values are
	 * in the range 1 to the "*_max_pending" counterpart above.
	 */
	u32	rx_pending;
	u32	rx_mini_pending;
	u32	rx_jumbo_pending;
	u32	tx_pending;
};
#endif /* ETHTOOL_GRINGPARAM */

#ifndef ETHTOOL_SRINGPARAM
#define ETHTOOL_SRINGPARAM	0x00000011 /* Set ring parameters, priv. */
#endif
#ifndef ETHTOOL_GPAUSEPARAM
#define ETHTOOL_GPAUSEPARAM	0x00000012 /* Get pause parameters */
/* for configuring link flow control parameters */
#define ethtool_pauseparam _kc_ethtool_pauseparam
struct _kc_ethtool_pauseparam {
	u32	cmd;	/* ETHTOOL_{G,S}PAUSEPARAM */

	/* If the link is being auto-negotiated (via ethtool_cmd.autoneg
	 * being true) the user may set 'autoneg' here non-zero to have the
	 * pause parameters be auto-negotiated too.  In such a case, the
	 * {rx,tx}_pause values below determine what capabilities are
	 * advertised.
	 *
	 * If 'autoneg' is zero or the link is not being auto-negotiated,
	 * then {rx,tx}_pause force the driver to use/not-use pause
	 * flow control.
	 */
	u32	autoneg;
	u32	rx_pause;
	u32	tx_pause;
};
#endif /* ETHTOOL_GPAUSEPARAM */

#ifndef ETHTOOL_SPAUSEPARAM
#define ETHTOOL_SPAUSEPARAM	0x00000013 /* Set pause parameters. */
#endif
#ifndef ETHTOOL_GRXCSUM
#define ETHTOOL_GRXCSUM		0x00000014 /* Get RX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_SRXCSUM
#define ETHTOOL_SRXCSUM		0x00000015 /* Set RX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_GTXCSUM
#define ETHTOOL_GTXCSUM		0x00000016 /* Get TX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_STXCSUM
#define ETHTOOL_STXCSUM		0x00000017 /* Set TX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_GSG
#define ETHTOOL_GSG		0x00000018 /* Get scatter-gather enable
					    * (ethtool_value) */
#endif
#ifndef ETHTOOL_SSG
#define ETHTOOL_SSG		0x00000019 /* Set scatter-gather enable
					    * (ethtool_value). */
#endif
#ifndef ETHTOOL_TEST
#define ETHTOOL_TEST		0x0000001a /* execute NIC self-test, priv. */
#endif
#ifndef ETHTOOL_GSTRINGS
#define ETHTOOL_GSTRINGS	0x0000001b /* get specified string set */
#endif
#ifndef ETHTOOL_PHYS_ID
#define ETHTOOL_PHYS_ID		0x0000001c /* identify the NIC */
#endif
#ifndef ETHTOOL_GSTATS
#define ETHTOOL_GSTATS		0x0000001d /* get NIC-specific statistics */
#endif
#ifndef ETHTOOL_GTSO
#define ETHTOOL_GTSO		0x0000001e /* Get TSO enable (ethtool_value) */
#endif
#ifndef ETHTOOL_STSO
#define ETHTOOL_STSO		0x0000001f /* Set TSO enable (ethtool_value) */
#endif

#ifndef ETHTOOL_BUSINFO_LEN
#define ETHTOOL_BUSINFO_LEN	32
#endif

#ifndef WAKE_FILTER
#define WAKE_FILTER	BIT(7)
#endif

#ifndef SPEED_2500
#define SPEED_2500 2500
#endif
#ifndef SPEED_5000
#define SPEED_5000 5000
#endif
#ifndef SPEED_14000
#define SPEED_14000 14000
#endif
#ifndef SPEED_25000
#define SPEED_25000 25000
#endif
#ifndef SPEED_50000
#define SPEED_50000 50000
#endif
#ifndef SPEED_56000
#define SPEED_56000 56000
#endif
#ifndef SPEED_100000
#define SPEED_100000 100000
#endif
#ifndef SPEED_200000
#define SPEED_200000 200000
#endif

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a,b) (((a) << 8) + (b))
#endif
#ifndef AX_RELEASE_VERSION
#define AX_RELEASE_VERSION(a,b) (((a) << 8) + (b))
#endif

#ifndef AX_RELEASE_CODE
#define AX_RELEASE_CODE 0
#endif

#if (AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3,0))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5,0)
#elif (AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3,1))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5,1)
#elif (AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3,2))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5,3)
#endif

#ifndef RHEL_RELEASE_CODE
/* NOTE: RHEL_RELEASE_* introduced in RHEL4.5 */
#define RHEL_RELEASE_CODE 0
#endif

/* RHEL 7 didn't backport the parameter change in
 * create_singlethread_workqueue.
 * If/when RH corrects this we will want to tighten up the version check.
 */
#if (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,0))
#undef create_singlethread_workqueue
#define create_singlethread_workqueue(name)	\
	alloc_ordered_workqueue("%s", WQ_MEM_RECLAIM, name)
#endif

/* Ubuntu Release ABI is the 4th digit of their kernel version. You can find
 * it in /usr/src/linux/$(uname -r)/include/generated/utsrelease.h for new
 * enough versions of Ubuntu. Otherwise you can simply see it in the output of
 * uname as the 4th digit of the kernel. The UTS_UBUNTU_RELEASE_ABI is not in
 * the linux-source package, but in the linux-headers package. It begins to
 * appear in later releases of 14.04 and 14.10.
 *
 * Ex:
 * <Ubuntu 14.04.1>
 *  $uname -r
 *  3.13.0-45-generic
 * ABI is 45
 *
 * <Ubuntu 14.10>
 *  $uname -r
 *  3.16.0-23-generic
 * ABI is 23
 */
#ifndef UTS_UBUNTU_RELEASE_ABI
#define UTS_UBUNTU_RELEASE_ABI 0
#define UBUNTU_VERSION_CODE 0
#else
/* Ubuntu does not provide actual release version macro, so we use the kernel
 * version plus the ABI to generate a unique version code specific to Ubuntu.
 * In addition, we mask the lower 8 bits of LINUX_VERSION_CODE in order to
 * ignore differences in sublevel which are not important since we have the
 * ABI value. Otherwise, it becomes impossible to correlate ABI to version for
 * ordering checks.
 *
 * This also lets us store an ABI value up to 65535, since it can take the
 * space that would use the lower byte of the Linux version code.
 */
#define UBUNTU_VERSION_CODE (((~0xFF & LINUX_VERSION_CODE) << 8) + \
			     UTS_UBUNTU_RELEASE_ABI)

#if UTS_UBUNTU_RELEASE_ABI > 65535
#error UTS_UBUNTU_RELEASE_ABI is larger than 65535...
#endif /* UTS_UBUNTU_RELEASE_ABI > 65535 */

#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(3,0,0) )
/* Our version code scheme does not make sense for non 3.x or newer kernels,
 * and we have no support in kcompat for this scenario. Thus, treat this as a
 * non-Ubuntu kernel. Possibly might be better to error here.
 */
#define UTS_UBUNTU_RELEASE_ABI 0
#define UBUNTU_VERSION_CODE 0
#endif /* <= 3.0.0 */
#endif /* !UTS_UBUNTU_RELEASE_ABI */

/* We ignore the 3rd digit since we want to give precedence to the additional
 * ABI value provided by Ubuntu.
 */
#define UBUNTU_VERSION(a,b,c,d) (((a) << 24) + ((b) << 16) + (d))

/* SLE_VERSION is used to generate a 3-digit encoding that can order SLE
 * kernels based on their major release, service pack, and a possible
 * maintenance release.
 */
#define SLE_VERSION(a,b,c)	(((a) << 16) + ((b) << 8) + (c))

/* The SLE_LOCALVERSION_CODE comes from a 3-digit code added as part of the
 * Linux kernel version. It is extracted by the driver Makefile. This macro is
 * used to generate codes for making comparisons below.
 */
#define SLE_LOCALVERSION(a,b,c)	(((a) << 16) + ((b) << 8) + (c))

#ifdef CONFIG_SUSE_KERNEL
/* Starting since at least SLE 12sp4 and SLE 15, the SUSE kernels have
 * provided CONFIG_SUSE_VERSION, CONFIG_SUSE_PATCHLEVEL and
 * CONFIG_SUSE_AUXRELEASE. Use these to generate SLE_VERSION if available.
 * Only fall back to the manual table otherwise. We expect all future versions
 * of SLE kernels to include these values, so the table will remain only for
 * the older releases.
 */
#ifdef CONFIG_SUSE_VERSION
#ifndef CONFIG_SUSE_PATCHLEVEL
#error "CONFIG_SUSE_VERSION exists but CONFIG_SUSE_PATCHLEVEL is missing"
#endif
#ifndef CONFIG_SUSE_AUXRELEASE
#error "CONFIG_SUSE_VERSION exists but CONFIG_SUSE_AUXRELEASE is missing"
#endif
#define SLE_VERSION_CODE SLE_VERSION(CONFIG_SUSE_VERSION, CONFIG_SUSE_PATCHLEVEL, CONFIG_SUSE_AUXRELEASE)
#else
/* If we do not have the CONFIG_SUSE_VERSION configuration values, fall back
 * to the following table for older releases.
 */
#if ( LINUX_VERSION_CODE == KERNEL_VERSION(2,6,27) )
/* SLES11 GA is 2.6.27 based */
#define SLE_VERSION_CODE SLE_VERSION(11,0,0)
#elif ( LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32) )
/* SLES11 SP1 is 2.6.32 based */
#define SLE_VERSION_CODE SLE_VERSION(11,1,0)
#elif ( LINUX_VERSION_CODE == KERNEL_VERSION(3,0,13) )
/* SLES11 SP2 GA is 3.0.13-0.27 */
#define SLE_VERSION_CODE SLE_VERSION(11,2,0)
#elif ((LINUX_VERSION_CODE == KERNEL_VERSION(3,0,76)))
/* SLES11 SP3 GA is 3.0.76-0.11 */
#define SLE_VERSION_CODE SLE_VERSION(11,3,0)
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(3,0,101))
  #if (SLE_LOCALVERSION_CODE < SLE_LOCALVERSION(0,8,0))
  /* some SLES11sp2 update kernels up to 3.0.101-0.7.x */
  #define SLE_VERSION_CODE SLE_VERSION(11,2,0)
  #elif (SLE_LOCALVERSION_CODE < SLE_LOCALVERSION(63,0,0))
  /* most SLES11sp3 update kernels */
  #define SLE_VERSION_CODE SLE_VERSION(11,3,0)
  #else
  /* SLES11 SP4 GA (3.0.101-63) and update kernels 3.0.101-63+ */
  #define SLE_VERSION_CODE SLE_VERSION(11,4,0)
  #endif
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(3,12,28))
/* SLES12 GA is 3.12.28-4
 * kernel updates 3.12.xx-<33 through 52>[.yy] */
#define SLE_VERSION_CODE SLE_VERSION(12,0,0)
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(3,12,49))
/* SLES12 SP1 GA is 3.12.49-11
 * updates 3.12.xx-60.yy where xx={51..} */
#define SLE_VERSION_CODE SLE_VERSION(12,1,0)
#elif ((LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,21) && \
       (LINUX_VERSION_CODE <= KERNEL_VERSION(4,4,59))) || \
       (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,74) && \
        LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0) && \
        SLE_LOCALVERSION_CODE >= KERNEL_VERSION(92,0,0) && \
        SLE_LOCALVERSION_CODE <  KERNEL_VERSION(93,0,0)))
/* SLES12 SP2 GA is 4.4.21-69.
 * SLES12 SP2 updates before SLES12 SP3 are: 4.4.{21,38,49,59}
 * SLES12 SP2 updates after SLES12 SP3 are: 4.4.{74,90,103,114,120}
 * but they all use a SLE_LOCALVERSION_CODE matching 92.nn.y */
#define SLE_VERSION_CODE SLE_VERSION(12,2,0)
#elif ((LINUX_VERSION_CODE == KERNEL_VERSION(4,4,73) || \
        LINUX_VERSION_CODE == KERNEL_VERSION(4,4,82) || \
        LINUX_VERSION_CODE == KERNEL_VERSION(4,4,92)) || \
       (LINUX_VERSION_CODE == KERNEL_VERSION(4,4,103) && \
       (SLE_LOCALVERSION_CODE == KERNEL_VERSION(6,33,0) || \
        SLE_LOCALVERSION_CODE == KERNEL_VERSION(6,38,0))) || \
       (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,114) && \
        LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0) && \
        SLE_LOCALVERSION_CODE >= KERNEL_VERSION(94,0,0) && \
        SLE_LOCALVERSION_CODE <  KERNEL_VERSION(95,0,0)) )
/* SLES12 SP3 GM is 4.4.73-5 and update kernels are 4.4.82-6.3.
 * SLES12 SP3 updates not conflicting with SP2 are: 4.4.{82,92}
 * SLES12 SP3 updates conflicting with SP2 are:
 *   - 4.4.103-6.33.1, 4.4.103-6.38.1
 *   - 4.4.{114,120}-94.nn.y */
#define SLE_VERSION_CODE SLE_VERSION(12,3,0)
#else
#error "This looks like a SUSE kernel, but it has an unrecognized local version code."
#endif /* LINUX_VERSION_CODE == KERNEL_VERSION(x,y,z) */
#endif /* !CONFIG_SUSE_VERSION */
#endif /* CONFIG_SUSE_KERNEL */
#ifndef SLE_VERSION_CODE
#define SLE_VERSION_CODE 0
#endif /* SLE_VERSION_CODE */
#ifndef SLE_LOCALVERSION_CODE
#define SLE_LOCALVERSION_CODE 0
#endif /* SLE_LOCALVERSION_CODE */

/* Include definitions from the new kcompat layout */
#include "kcompat_defs.h"

/*
 * ADQ depends on __TC_MQPRIO_MODE_MAX and related kernel code
 * added around 4.15. Some distributions (e.g. Oracle Linux 7.7)
 * have done a partial back-port of that to their kernels based
 * on older mainline kernels that did not include all the necessary
 * kernel enablement to support ADQ.
 * Undefine __TC_MQPRIO_MODE_MAX for all OSV distributions with
 * kernels based on mainline kernels older than 4.15 except for
 * RHEL, SLES and Ubuntu which are known to have good back-ports.
 */
#if (!RHEL_RELEASE_CODE && !SLE_VERSION_CODE && !UBUNTU_VERSION_CODE)
  #if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
  #undef __TC_MQPRIO_MODE_MAX
  #endif /*  LINUX_VERSION_CODE == KERNEL_VERSION(4,15,0) */
#endif /* if (NOT RHEL && NOT SLES && NOT UBUNTU) */


#ifdef __KLOCWORK__
 */
#ifdef ARRAY_SIZE
#undef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define memcpy(dest, src, len)	memcpy_s(dest, len, src, len)
#define memset(dest, ch, len)	memset_s(dest, len, ch, len)

static inline int _kc_test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;
	unsigned long flags = 0;

	_atomic_spin_lock_irqsave(p, flags);
	old = *p;
	*p = old & ~mask;
	_atomic_spin_unlock_irqrestore(p, flags);

	return (old & mask) != 0;
}
#define test_and_clear_bit(nr, addr) _kc_test_and_clear_bit(nr, addr)

static inline int _kc_test_and_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;
	unsigned long flags = 0;

	_atomic_spin_lock_irqsave(p, flags);
	old = *p;
	*p = old | mask;
	_atomic_spin_unlock_irqrestore(p, flags);

	return (old & mask) != 0;
}
#define test_and_set_bit(nr, addr) _kc_test_and_set_bit(nr, addr)

#ifdef CONFIG_DYNAMIC_DEBUG
#undef dev_dbg
#define dev_dbg(dev, format, arg...) dev_printk(KERN_DEBUG, dev, format, ##arg)
#undef pr_debug
#define pr_debug(format, arg...) printk(KERN_DEBUG format, ##arg)
#endif /* CONFIG_DYNAMIC_DEBUG */

#undef hlist_for_each_entry_safe
#define hlist_for_each_entry_safe(pos, n, head, member)			     \
	for (n = NULL, pos = hlist_entry_safe((head)->first, typeof(*(pos)), \
					      member);			     \
	     pos;							     \
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#ifdef uninitialized_var
#undef uninitialized_var
#define uninitialized_var(x) x = *(&(x))
#endif

#ifdef WRITE_ONCE
#undef WRITE_ONCE
#define WRITE_ONCE(x, val)	((x) = (val))
#endif /* WRITE_ONCE */

#ifdef wait_event_interruptible_timeout
#undef wait_event_interruptible_timeout
#define wait_event_interruptible_timeout(wq_head, condition, timeout) ({	\
	long ret;								\
	if ((condition))							\
		ret = timeout;							\
	else									\
		ret = 0;							\
	ret;									\
})
#endif /* wait_event_interruptible_timeout */

#ifdef max_t
#undef max_t
#define max_t(type, x, y) ({							\
type __x = (x);								\
type __y = (y);								\
__x > __y ? __x : __y;							\
})
#endif /* max_t */

#ifdef min_t
#undef min_t
#define min_t(type, x, y) ({							\
type __x = (x);								\
type __y = (y);								\
__x < __y ? __x : __y;							\
})
#endif /* min_t */
#endif /* __KLOCWORK__ */

/*
 * Load the implementations file which actually defines kcompat backports.
 * Legacy backports still exist in this file, but all new backports must be
 * implemented using kcompat_*defs.h and kcompat_impl.h
 */
#include "kcompat_impl.h"

#endif /* _KCOMPAT_H_ */
