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

/* Backport macros for controlling GCC diagnostics */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0) )

/* Compilers before gcc-4.6 do not understand "#pragma GCC diagnostic push" */
#if GCC_VERSION >= 40600
#define __diag_str1(s)		#s
#define __diag_str(s)		__diag_str1(s)
#define __diag(s)		_Pragma(__diag_str(GCC diagnostic s))
#else
#define __diag(s)
#endif /* GCC_VERSION >= 4.6 */
#define __diag_push()	__diag(push)
#define __diag_pop()	__diag(pop)
#endif /* LINUX_VERSION < 4.18.0 */

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

/* Older versions of GCC will trigger -Wformat-nonliteral warnings for const
 * char * strings. Unfortunately, the implementation of do_trace_printk does
 * this, in order to add a storage attribute to the memory. This was fixed in
 * GCC 5.1, but we still use older distributions built with GCC 4.x.
 *
 * The string pointer is only passed as a const char * to the __trace_bprintk
 * function. Since that function has the __printf attribute, it will trigger
 * the warnings. We can't remove the attribute, so instead we'll use the
 * __diag macro to disable -Wformat-nonliteral around the call to
 * __trace_bprintk.
 */
#if GCC_VERSION < 50100
#define __trace_bprintk(ip, fmt, args...) ({		\
	int err;					\
	__diag_push();					\
	__diag(ignored "-Wformat-nonliteral");		\
	err = __trace_bprintk(ip, fmt, ##args);		\
	__diag_pop();					\
	err;						\
})
#endif /* GCC_VERSION < 5.1.0 */

/* Newer kernels removed <linux/pci-aspm.h> */
#if ((LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)) && \
     (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8,3)) && \
     !(SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(15,3,0)))))
#define HAVE_PCI_ASPM_H
#endif

/*****************************************************************************/
/* 2.4.3 => 2.4.0 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,3) )

/**************************************/
/* PCI DRIVER API */

#ifndef pci_set_dma_mask
#define pci_set_dma_mask _kc_pci_set_dma_mask
int _kc_pci_set_dma_mask(struct pci_dev *dev, dma_addr_t mask);
#endif

#ifndef pci_request_regions
#define pci_request_regions _kc_pci_request_regions
int _kc_pci_request_regions(struct pci_dev *pdev, char *res_name);
#endif

#ifndef pci_release_regions
#define pci_release_regions _kc_pci_release_regions
void _kc_pci_release_regions(struct pci_dev *pdev);
#endif

/**************************************/
/* NETWORK DRIVER API */

#ifndef alloc_etherdev
#define alloc_etherdev _kc_alloc_etherdev
struct net_device * _kc_alloc_etherdev(int sizeof_priv);
#endif

#ifndef is_valid_ether_addr
#define is_valid_ether_addr _kc_is_valid_ether_addr
int _kc_is_valid_ether_addr(u8 *addr);
#endif

/**************************************/
/* MISCELLANEOUS */

#ifndef INIT_TQUEUE
#define INIT_TQUEUE(_tq, _routine, _data)		\
	do {						\
		INIT_LIST_HEAD(&(_tq)->list);		\
		(_tq)->sync = 0;			\
		(_tq)->routine = _routine;		\
		(_tq)->data = _data;			\
	} while (0)
#endif

#endif /* 2.4.3 => 2.4.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,5) )
/* Generic MII registers. */
#define MII_BMCR            0x00        /* Basic mode control register */
#define MII_BMSR            0x01        /* Basic mode status register  */
#define MII_PHYSID1         0x02        /* PHYS ID 1                   */
#define MII_PHYSID2         0x03        /* PHYS ID 2                   */
#define MII_ADVERTISE       0x04        /* Advertisement control reg   */
#define MII_LPA             0x05        /* Link partner ability reg    */
#define MII_EXPANSION       0x06        /* Expansion register          */
/* Basic mode control register. */
#define BMCR_FULLDPLX           0x0100  /* Full duplex                 */
#define BMCR_ANENABLE           0x1000  /* Enable auto negotiation     */
/* Basic mode status register. */
#define BMSR_ERCAP              0x0001  /* Ext-reg capability          */
#define BMSR_ANEGCAPABLE        0x0008  /* Able to do auto-negotiation */
#define BMSR_10HALF             0x0800  /* Can do 10mbps, half-duplex  */
#define BMSR_10FULL             0x1000  /* Can do 10mbps, full-duplex  */
#define BMSR_100HALF            0x2000  /* Can do 100mbps, half-duplex */
#define BMSR_100FULL            0x4000  /* Can do 100mbps, full-duplex */
/* Advertisement control register. */
#define ADVERTISE_CSMA          0x0001  /* Only selector supported     */
#define ADVERTISE_10HALF        0x0020  /* Try for 10mbps half-duplex  */
#define ADVERTISE_10FULL        0x0040  /* Try for 10mbps full-duplex  */
#define ADVERTISE_100HALF       0x0080  /* Try for 100mbps half-duplex */
#define ADVERTISE_100FULL       0x0100  /* Try for 100mbps full-duplex */
#define ADVERTISE_ALL (ADVERTISE_10HALF | ADVERTISE_10FULL | \
                       ADVERTISE_100HALF | ADVERTISE_100FULL)
/* Expansion register for auto-negotiation. */
#define EXPANSION_ENABLENPAGE   0x0004  /* This enables npage words    */
#endif

/*****************************************************************************/
/* 2.4.6 => 2.4.3 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,6) )

#ifndef pci_set_power_state
#define pci_set_power_state _kc_pci_set_power_state
int _kc_pci_set_power_state(struct pci_dev *dev, int state);
#endif

#ifndef pci_enable_wake
#define pci_enable_wake _kc_pci_enable_wake
int _kc_pci_enable_wake(struct pci_dev *pdev, u32 state, int enable);
#endif

#ifndef pci_disable_device
#define pci_disable_device _kc_pci_disable_device
void _kc_pci_disable_device(struct pci_dev *pdev);
#endif

/* PCI PM entry point syntax changed, so don't support suspend/resume */
#undef CONFIG_PM

#endif /* 2.4.6 => 2.4.3 */

#ifndef HAVE_PCI_SET_MWI
#define pci_set_mwi(X) pci_write_config_word(X, \
			       PCI_COMMAND, adapter->hw.bus.pci_cmd_word | \
			       PCI_COMMAND_INVALIDATE);
#define pci_clear_mwi(X) pci_write_config_word(X, \
			       PCI_COMMAND, adapter->hw.bus.pci_cmd_word & \
			       ~PCI_COMMAND_INVALIDATE);
#endif

/*****************************************************************************/
/* 2.4.10 => 2.4.9 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10) )

/**************************************/
/* MODULE API */

#ifndef MODULE_LICENSE
	#define MODULE_LICENSE(X)
#endif

/**************************************/
/* OTHER */

#undef min
#define min(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#undef max
#define max(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

#define min_t(type,x,y) ({ \
	type _x = (x); \
	type _y = (y); \
	_x < _y ? _x : _y; })

#define max_t(type,x,y) ({ \
	type _x = (x); \
	type _y = (y); \
	_x > _y ? _x : _y; })

#ifndef list_for_each_safe
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
#endif

#ifndef ____cacheline_aligned_in_smp
#ifdef CONFIG_SMP
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#else
#define ____cacheline_aligned_in_smp
#endif /* CONFIG_SMP */
#endif

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,8) )
int _kc_snprintf(char * buf, size_t size, const char *fmt, ...);
#define snprintf(buf, size, fmt, args...) _kc_snprintf(buf, size, fmt, ##args)
int _kc_vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
#define vsnprintf(buf, size, fmt, args) _kc_vsnprintf(buf, size, fmt, args)
#else /* 2.4.8 => 2.4.9 */
int snprintf(char * buf, size_t size, const char *fmt, ...);
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
#endif
#endif /* 2.4.10 -> 2.4.6 */


/*****************************************************************************/
/* 2.4.12 => 2.4.10 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,12) )
#ifndef HAVE_NETIF_MSG
#define HAVE_NETIF_MSG 1
enum {
	NETIF_MSG_DRV		= 0x0001,
	NETIF_MSG_PROBE		= 0x0002,
	NETIF_MSG_LINK		= 0x0004,
	NETIF_MSG_TIMER		= 0x0008,
	NETIF_MSG_IFDOWN	= 0x0010,
	NETIF_MSG_IFUP		= 0x0020,
	NETIF_MSG_RX_ERR	= 0x0040,
	NETIF_MSG_TX_ERR	= 0x0080,
	NETIF_MSG_TX_QUEUED	= 0x0100,
	NETIF_MSG_INTR		= 0x0200,
	NETIF_MSG_TX_DONE	= 0x0400,
	NETIF_MSG_RX_STATUS	= 0x0800,
	NETIF_MSG_PKTDATA	= 0x1000,
	NETIF_MSG_HW		= 0x2000,
	NETIF_MSG_WOL		= 0x4000,
};

#define netif_msg_drv(p)	((p)->msg_enable & NETIF_MSG_DRV)
#define netif_msg_probe(p)	((p)->msg_enable & NETIF_MSG_PROBE)
#define netif_msg_link(p)	((p)->msg_enable & NETIF_MSG_LINK)
#define netif_msg_timer(p)	((p)->msg_enable & NETIF_MSG_TIMER)
#define netif_msg_ifdown(p)	((p)->msg_enable & NETIF_MSG_IFDOWN)
#define netif_msg_ifup(p)	((p)->msg_enable & NETIF_MSG_IFUP)
#define netif_msg_rx_err(p)	((p)->msg_enable & NETIF_MSG_RX_ERR)
#define netif_msg_tx_err(p)	((p)->msg_enable & NETIF_MSG_TX_ERR)
#define netif_msg_tx_queued(p)	((p)->msg_enable & NETIF_MSG_TX_QUEUED)
#define netif_msg_intr(p)	((p)->msg_enable & NETIF_MSG_INTR)
#define netif_msg_tx_done(p)	((p)->msg_enable & NETIF_MSG_TX_DONE)
#define netif_msg_rx_status(p)	((p)->msg_enable & NETIF_MSG_RX_STATUS)
#define netif_msg_pktdata(p)	((p)->msg_enable & NETIF_MSG_PKTDATA)
#endif /* !HAVE_NETIF_MSG */
#endif /* 2.4.12 => 2.4.10 */

/*****************************************************************************/
/* 2.4.13 => 2.4.12 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,13) )

/**************************************/
/* PCI DMA MAPPING */

#ifndef virt_to_page
	#define virt_to_page(v) (mem_map + (virt_to_phys(v) >> PAGE_SHIFT))
#endif

#ifndef pci_map_page
#define pci_map_page _kc_pci_map_page
u64 _kc_pci_map_page(struct pci_dev *dev, struct page *page, unsigned long offset, size_t size, int direction);
#endif

#ifndef pci_unmap_page
#define pci_unmap_page _kc_pci_unmap_page
void _kc_pci_unmap_page(struct pci_dev *dev, u64 dma_addr, size_t size, int direction);
#endif

/* pci_set_dma_mask takes dma_addr_t, which is only 32-bits prior to 2.4.13 */

#undef DMA_32BIT_MASK
#define DMA_32BIT_MASK	0xffffffff
#undef DMA_64BIT_MASK
#define DMA_64BIT_MASK	0xffffffff

/**************************************/
/* OTHER */

#ifndef cpu_relax
#define cpu_relax()	rep_nop()
#endif

struct vlan_ethhdr {
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	unsigned short h_vlan_proto;
	unsigned short h_vlan_TCI;
	unsigned short h_vlan_encapsulated_proto;
};
#endif /* 2.4.13 => 2.4.12 */

/*****************************************************************************/
/* 2.4.17 => 2.4.12 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,17) )

#ifndef __devexit_p
	#define __devexit_p(x) &(x)
#endif

#endif /* 2.4.17 => 2.4.13 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,18) )
#define NETIF_MSG_HW	0x2000
#define NETIF_MSG_WOL	0x4000

#ifndef netif_msg_hw
#define netif_msg_hw(p)		((p)->msg_enable & NETIF_MSG_HW)
#endif
#ifndef netif_msg_wol
#define netif_msg_wol(p)	((p)->msg_enable & NETIF_MSG_WOL)
#endif
#endif /* 2.4.18 */

/*****************************************************************************/

/*****************************************************************************/
/* 2.4.20 => 2.4.19 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20) )

/* we won't support NAPI on less than 2.4.20 */
#ifdef NAPI
#undef NAPI
#endif

#endif /* 2.4.20 => 2.4.19 */

/*****************************************************************************/
/* 2.4.22 => 2.4.17 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,22) )
#define pci_name(x)	((x)->slot_name)
#define cpu_online(cpuid) test_bit((cpuid), &cpu_online_map)

#ifndef SUPPORTED_10000baseT_Full
#define SUPPORTED_10000baseT_Full	BIT(12)
#endif
#ifndef ADVERTISED_10000baseT_Full
#define ADVERTISED_10000baseT_Full	BIT(12)
#endif
#endif

/*****************************************************************************/
/*****************************************************************************/
/* 2.4.23 => 2.4.22 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,23) )
/*****************************************************************************/
#ifdef NAPI
#ifndef netif_poll_disable
#define netif_poll_disable(x) _kc_netif_poll_disable(x)
static inline void _kc_netif_poll_disable(struct net_device *netdev)
{
	while (test_and_set_bit(__LINK_STATE_RX_SCHED, &netdev->state)) {
		/* No hurry */
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(1);
	}
}
#endif
#ifndef netif_poll_enable
#define netif_poll_enable(x) _kc_netif_poll_enable(x)
static inline void _kc_netif_poll_enable(struct net_device *netdev)
{
	clear_bit(__LINK_STATE_RX_SCHED, &netdev->state);
}
#endif
#endif /* NAPI */
#ifndef netif_tx_disable
#define netif_tx_disable(x) _kc_netif_tx_disable(x)
static inline void _kc_netif_tx_disable(struct net_device *dev)
{
	spin_lock_bh(&dev->xmit_lock);
	netif_stop_queue(dev);
	spin_unlock_bh(&dev->xmit_lock);
}
#endif
#else /* 2.4.23 => 2.4.22 */
#define HAVE_SCTP
#endif /* 2.4.23 => 2.4.22 */

/*****************************************************************************/
/* 2.6.4 => 2.6.0 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,25) || \
    ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) && \
      LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4) ) )
#define ETHTOOL_OPS_COMPAT
#endif /* 2.6.4 => 2.6.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,27) )
#define __user
#endif /* < 2.4.27 */

/*****************************************************************************/
/* 2.5.71 => 2.4.x */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,5,71) )
#define sk_protocol protocol
#define pci_get_device pci_find_device
#endif /* 2.5.70 => 2.4.x */

/*****************************************************************************/
/* < 2.4.27 or 2.6.0 <= 2.6.5 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,27) || \
    ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) && \
      LINUX_VERSION_CODE < KERNEL_VERSION(2,6,5) ) )

#ifndef netif_msg_init
#define netif_msg_init _kc_netif_msg_init
static inline u32 _kc_netif_msg_init(int debug_value, int default_msg_enable_bits)
{
	/* use default */
	if (debug_value < 0 || debug_value >= (sizeof(u32) * 8))
		return default_msg_enable_bits;
	if (debug_value == 0) /* no output */
		return 0;
	/* set low N bits */
	return (1 << debug_value) -1;
}
#endif

#endif /* < 2.4.27 or 2.6.0 <= 2.6.5 */
/*****************************************************************************/
#if (( LINUX_VERSION_CODE < KERNEL_VERSION(2,4,27) ) || \
     (( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) ) && \
      ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,3) )))
#define netdev_priv(x) x->priv
#endif

/*****************************************************************************/
/* <= 2.5.0 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0) )
#include <linux/rtnetlink.h>
#undef pci_register_driver
#define pci_register_driver pci_module_init

/*
 * Most of the dma compat code is copied/modifed from the 2.4.37
 * /include/linux/libata-compat.h header file
 */
/* These definitions mirror those in pci.h, so they can be used
 * interchangeably with their PCI_ counterparts */
enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

struct device {
	struct pci_dev pdev;
};

static inline struct pci_dev *to_pci_dev (struct device *dev)
{
	return (struct pci_dev *) dev;
}
static inline struct device *pci_dev_to_dev(struct pci_dev *pdev)
{
	return (struct device *) pdev;
}
#define pdev_printk(lvl, pdev, fmt, args...) 	\
	printk("%s %s: " fmt, lvl, pci_name(pdev), ## args)
#define dev_err(dev, fmt, args...)            \
	pdev_printk(KERN_ERR, to_pci_dev(dev), fmt, ## args)
#define dev_info(dev, fmt, args...)            \
	pdev_printk(KERN_INFO, to_pci_dev(dev), fmt, ## args)
#define dev_warn(dev, fmt, args...)            \
	pdev_printk(KERN_WARNING, to_pci_dev(dev), fmt, ## args)
#define dev_notice(dev, fmt, args...)            \
	pdev_printk(KERN_NOTICE, to_pci_dev(dev), fmt, ## args)
#define dev_dbg(dev, fmt, args...) \
	pdev_printk(KERN_DEBUG, to_pci_dev(dev), fmt, ## args)

/* NOTE: dangerous! we ignore the 'gfp' argument */
#define dma_alloc_coherent(dev,sz,dma,gfp) \
	pci_alloc_consistent(to_pci_dev(dev),(sz),(dma))
#define dma_free_coherent(dev,sz,addr,dma_addr) \
	pci_free_consistent(to_pci_dev(dev),(sz),(addr),(dma_addr))

#define dma_map_page(dev,a,b,c,d) \
	pci_map_page(to_pci_dev(dev),(a),(b),(c),(d))
#define dma_unmap_page(dev,a,b,c) \
	pci_unmap_page(to_pci_dev(dev),(a),(b),(c))

#define dma_map_single(dev,a,b,c) \
	pci_map_single(to_pci_dev(dev),(a),(b),(c))
#define dma_unmap_single(dev,a,b,c) \
	pci_unmap_single(to_pci_dev(dev),(a),(b),(c))

#define dma_map_sg(dev, sg, nents, dir) \
	pci_map_sg(to_pci_dev(dev), (sg), (nents), (dir)
#define dma_unmap_sg(dev, sg, nents, dir) \
	pci_unmap_sg(to_pci_dev(dev), (sg), (nents), (dir)

#define dma_sync_single(dev,a,b,c) \
	pci_dma_sync_single(to_pci_dev(dev),(a),(b),(c))

/* for range just sync everything, that's all the pci API can do */
#define dma_sync_single_range(dev,addr,off,sz,dir) \
	pci_dma_sync_single(to_pci_dev(dev),(addr),(off)+(sz),(dir))

#define dma_set_mask(dev,mask) \
	pci_set_dma_mask(to_pci_dev(dev),(mask))

/* hlist_* code - double linked lists */
struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;
	*pprev = next;
	if (next)
	next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = NULL;
	n->pprev = NULL;
}

static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

static inline int hlist_empty(const struct hlist_head *h)
{
	return !h->first;
}
#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

#ifndef might_sleep
#define might_sleep()
#endif
#else
static inline struct device *pci_dev_to_dev(struct pci_dev *pdev)
{
	return &pdev->dev;
}
#endif /* <= 2.5.0 */

/*****************************************************************************/
/* 2.5.28 => 2.4.23 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,5,28) )

#include <linux/tqueue.h>
#define work_struct tq_struct
#undef INIT_WORK
#define INIT_WORK(a,b) INIT_TQUEUE(a,(void (*)(void *))b,a)
#undef container_of
#define container_of list_entry
#define schedule_work schedule_task
#define flush_scheduled_work flush_scheduled_tasks
#define cancel_work_sync(x) flush_scheduled_work()

#endif /* 2.5.28 => 2.4.17 */

/*****************************************************************************/
/* 2.6.0 => 2.5.28 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) )
#ifndef read_barrier_depends
#define read_barrier_depends() rmb()
#endif

#ifndef rcu_head
struct __kc_callback_head {
	struct __kc_callback_head *next;
	void (*func)(struct callback_head *head);
};
#define rcu_head __kc_callback_head
#endif

#undef get_cpu
#define get_cpu() smp_processor_id()
#undef put_cpu
#define put_cpu() do { } while(0)
#define MODULE_INFO(version, _version)
#ifndef CONFIG_E1000_DISABLE_PACKET_SPLIT
#define CONFIG_E1000_DISABLE_PACKET_SPLIT 1
#endif
#ifndef CONFIG_IGB_DISABLE_PACKET_SPLIT
#define CONFIG_IGB_DISABLE_PACKET_SPLIT 1
#endif
#ifndef CONFIG_IGC_DISABLE_PACKET_SPLIT
#define CONFIG_IGC_DISABLE_PACKET_SPLIT 1
#endif

#define dma_set_coherent_mask(dev,mask) 1

#undef dev_put
#define dev_put(dev) __dev_put(dev)

#ifndef skb_fill_page_desc
#define skb_fill_page_desc _kc_skb_fill_page_desc
void _kc_skb_fill_page_desc(struct sk_buff *skb, int i, struct page *page, int off, int size);
#endif

#undef ALIGN
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

#ifndef page_count
#define page_count(p) atomic_read(&(p)->count)
#endif

#ifdef MAX_NUMNODES
#undef MAX_NUMNODES
#endif
#define MAX_NUMNODES 1

/* find_first_bit and find_next bit are not defined for most
 * 2.4 kernels (except for the redhat 2.4.21 kernels
 */
#include <linux/bitops.h>
#define BITOP_WORD(nr)          ((nr) / BITS_PER_LONG)
#undef find_next_bit
#define find_next_bit _kc_find_next_bit
unsigned long _kc_find_next_bit(const unsigned long *addr, unsigned long size,
				unsigned long offset);
#define find_first_bit(addr, size) find_next_bit((addr), (size), 0)

#ifndef netdev_name
static inline const char *_kc_netdev_name(const struct net_device *dev)
{
	if (strchr(dev->name, '%'))
		return "(unregistered net_device)";
	return dev->name;
}
#define netdev_name(netdev)	_kc_netdev_name(netdev)
#endif /* netdev_name */

#ifndef strlcpy
#define strlcpy _kc_strlcpy
size_t _kc_strlcpy(char *dest, const char *src, size_t size);
#endif /* strlcpy */

#ifndef do_div
#if BITS_PER_LONG == 64
# define do_div(n,base) ({					\
	uint32_t __base = (base);				\
	uint32_t __rem;						\
	__rem = ((uint64_t)(n)) % __base;			\
	(n) = ((uint64_t)(n)) / __base;				\
	__rem;							\
 })
#elif BITS_PER_LONG == 32
uint32_t _kc__div64_32(uint64_t *dividend, uint32_t divisor);
# define do_div(n,base) ({				\
	uint32_t __base = (base);			\
	uint32_t __rem;					\
	if (likely(((n) >> 32) == 0)) {			\
		__rem = (uint32_t)(n) % __base;		\
		(n) = (uint32_t)(n) / __base;		\
	} else 						\
		__rem = _kc__div64_32(&(n), __base);	\
	__rem;						\
 })
#else /* BITS_PER_LONG == ?? */
# error do_div() does not yet support the C64
#endif /* BITS_PER_LONG */
#endif /* do_div */

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC	1000000000L
#endif

#undef HAVE_I2C_SUPPORT
#else /* 2.6.0 */

#endif /* 2.6.0 => 2.5.28 */
/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,3) )
#define dma_pool pci_pool
#define dma_pool_destroy pci_pool_destroy
#define dma_pool_alloc pci_pool_alloc
#define dma_pool_free pci_pool_free

#define dma_pool_create(name,dev,size,align,allocation) \
       pci_pool_create((name),to_pci_dev(dev),(size),(align),(allocation))
#endif /* < 2.6.3 */

/*****************************************************************************/
/* 2.6.4 => 2.6.0 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4) )
#define MODULE_VERSION(_version) MODULE_INFO(version, _version)
#endif /* 2.6.4 => 2.6.0 */

/*****************************************************************************/
/* 2.6.5 => 2.6.0 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,5) )
#define dma_sync_single_for_cpu		dma_sync_single
#define dma_sync_single_for_device	dma_sync_single
#define dma_sync_single_range_for_cpu		dma_sync_single_range
#define dma_sync_single_range_for_device	dma_sync_single_range
#ifndef pci_dma_mapping_error
#define pci_dma_mapping_error _kc_pci_dma_mapping_error
static inline int _kc_pci_dma_mapping_error(dma_addr_t dma_addr)
{
	return dma_addr == 0;
}
#endif
#endif /* 2.6.5 => 2.6.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4) )
int _kc_scnprintf(char * buf, size_t size, const char *fmt, ...);
#define scnprintf(buf, size, fmt, args...) _kc_scnprintf(buf, size, fmt, ##args)
#endif /* < 2.6.4 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,6) )
/* taken from 2.6 include/linux/bitmap.h */
#undef bitmap_zero
#define bitmap_zero _kc_bitmap_zero
static inline void _kc_bitmap_zero(unsigned long *dst, int nbits)
{
        if (nbits <= BITS_PER_LONG)
                *dst = 0UL;
        else {
                int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
                memset(dst, 0, len);
        }
}
#define page_to_nid(x) 0

#endif /* < 2.6.6 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7) )
#undef if_mii
#define if_mii _kc_if_mii
static inline struct mii_ioctl_data *_kc_if_mii(struct ifreq *rq)
{
	return (struct mii_ioctl_data *) &rq->ifr_ifru;
}

#ifndef __force
#define __force
#endif
#endif /* < 2.6.7 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8) )
#ifndef PCI_EXP_DEVCTL
#define PCI_EXP_DEVCTL 8
#endif
#ifndef PCI_EXP_DEVCTL_CERE
#define PCI_EXP_DEVCTL_CERE 0x0001
#endif
#define PCI_EXP_FLAGS		2	/* Capabilities register */
#define PCI_EXP_FLAGS_VERS	0x000f	/* Capability version */
#define PCI_EXP_FLAGS_TYPE	0x00f0	/* Device/Port type */
#define  PCI_EXP_TYPE_ENDPOINT	0x0	/* Express Endpoint */
#define  PCI_EXP_TYPE_LEG_END	0x1	/* Legacy Endpoint */
#define  PCI_EXP_TYPE_ROOT_PORT 0x4	/* Root Port */
#define  PCI_EXP_TYPE_DOWNSTREAM 0x6	/* Downstream Port */
#define PCI_EXP_FLAGS_SLOT	0x0100	/* Slot implemented */
#define PCI_EXP_DEVCAP		4	/* Device capabilities */
#define PCI_EXP_DEVSTA		10	/* Device Status */
#define msleep(x)	do { set_current_state(TASK_UNINTERRUPTIBLE); \
				schedule_timeout((x * HZ)/1000 + 2); \
			} while (0)

#endif /* < 2.6.8 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9))
#include <net/dsfield.h>
#define __iomem

#ifndef kcalloc
#define kcalloc(n, size, flags) _kc_kzalloc(((n) * (size)), flags)
void *_kc_kzalloc(size_t size, int flags);
#endif
#define MSEC_PER_SEC    1000L
static inline unsigned int _kc_jiffies_to_msecs(const unsigned long j)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
	return (j * MSEC_PER_SEC) / HZ;
#endif
}
static inline unsigned long _kc_msecs_to_jiffies(const unsigned int m)
{
	if (m > _kc_jiffies_to_msecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	return m * (HZ / MSEC_PER_SEC);
#else
	return (m * HZ + MSEC_PER_SEC - 1) / MSEC_PER_SEC;
#endif
}

#define msleep_interruptible _kc_msleep_interruptible
static inline unsigned long _kc_msleep_interruptible(unsigned int msecs)
{
	unsigned long timeout = _kc_msecs_to_jiffies(msecs) + 1;

	while (timeout && !signal_pending(current)) {
		__set_current_state(TASK_INTERRUPTIBLE);
		timeout = schedule_timeout(timeout);
	}
	return _kc_jiffies_to_msecs(timeout);
}

/* Basic mode control register. */
#define BMCR_SPEED1000		0x0040  /* MSB of Speed (1000)         */

#ifndef __le16
#define __le16 u16
#endif
#ifndef __le32
#define __le32 u32
#endif
#ifndef __le64
#define __le64 u64
#endif
#ifndef __be16
#define __be16 u16
#endif
#ifndef __be32
#define __be32 u32
#endif
#ifndef __be64
#define __be64 u64
#endif

static inline struct vlan_ethhdr *vlan_eth_hdr(const struct sk_buff *skb)
{
	return (struct vlan_ethhdr *)skb->mac.raw;
}

/* Wake-On-Lan options. */
#define WAKE_PHY		BIT(0)
#define WAKE_UCAST		BIT(1)
#define WAKE_MCAST		BIT(2)
#define WAKE_BCAST		BIT(3)
#define WAKE_ARP		BIT(4)
#define WAKE_MAGIC		BIT(5)
#define WAKE_MAGICSECURE	BIT(6) /* only meaningful if WAKE_MAGIC */

#define skb_header_pointer _kc_skb_header_pointer
static inline void *_kc_skb_header_pointer(const struct sk_buff *skb,
					    int offset, int len, void *buffer)
{
	int hlen = skb_headlen(skb);

	if (hlen - offset >= len)
		return skb->data + offset;

#ifdef MAX_SKB_FRAGS
	if (skb_copy_bits(skb, offset, buffer, len) < 0)
		return NULL;

	return buffer;
#else
	return NULL;
#endif

#ifndef NETDEV_TX_OK
#define NETDEV_TX_OK 0
#endif
#ifndef NETDEV_TX_BUSY
#define NETDEV_TX_BUSY 1
#endif
#ifndef NETDEV_TX_LOCKED
#define NETDEV_TX_LOCKED -1
#endif
}

#ifndef __bitwise
#define __bitwise
#endif
#endif /* < 2.6.9 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10) )
#ifdef module_param_array_named
#undef module_param_array_named
#define module_param_array_named(name, array, type, nump, perm)          \
	static struct kparam_array __param_arr_##name                    \
	= { ARRAY_SIZE(array), nump, param_set_##type, param_get_##type, \
	    sizeof(array[0]), array };                                   \
	module_param_call(name, param_array_set, param_array_get,        \
			  &__param_arr_##name, perm)
#endif /* module_param_array_named */
/*
 * num_online is broken for all < 2.6.10 kernels.  This is needed to support
 * Node module parameter of ixgbe.
 */
#undef num_online_nodes
#define num_online_nodes(n) 1
extern DECLARE_BITMAP(_kcompat_node_online_map, MAX_NUMNODES);
#undef node_online_map
#define node_online_map _kcompat_node_online_map
#define pci_get_class pci_find_class
#endif /* < 2.6.10 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11) )
#define PCI_D0      0
#define PCI_D1      1
#define PCI_D2      2
#define PCI_D3hot   3
#define PCI_D3cold  4
typedef int pci_power_t;
#define pci_choose_state(pdev,state) state
#define PMSG_SUSPEND 3
#define PCI_EXP_LNKCTL	16

#undef NETIF_F_LLTX

#ifndef ARCH_HAS_PREFETCH
#define prefetch(X)
#endif

#ifndef NET_IP_ALIGN
#define NET_IP_ALIGN 2
#endif

#define KC_USEC_PER_SEC	1000000L
#define usecs_to_jiffies _kc_usecs_to_jiffies
static inline unsigned int _kc_jiffies_to_usecs(const unsigned long j)
{
#if HZ <= KC_USEC_PER_SEC && !(KC_USEC_PER_SEC % HZ)
	return (KC_USEC_PER_SEC / HZ) * j;
#elif HZ > KC_USEC_PER_SEC && !(HZ % KC_USEC_PER_SEC)
	return (j + (HZ / KC_USEC_PER_SEC) - 1)/(HZ / KC_USEC_PER_SEC);
#else
	return (j * KC_USEC_PER_SEC) / HZ;
#endif
}
static inline unsigned long _kc_usecs_to_jiffies(const unsigned int m)
{
	if (m > _kc_jiffies_to_usecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;
#if HZ <= KC_USEC_PER_SEC && !(KC_USEC_PER_SEC % HZ)
	return (m + (KC_USEC_PER_SEC / HZ) - 1) / (KC_USEC_PER_SEC / HZ);
#elif HZ > KC_USEC_PER_SEC && !(HZ % KC_USEC_PER_SEC)
	return m * (HZ / KC_USEC_PER_SEC);
#else
	return (m * HZ + KC_USEC_PER_SEC - 1) / KC_USEC_PER_SEC;
#endif
}

#define PCI_EXP_LNKCAP		12	/* Link Capabilities */
#define PCI_EXP_LNKSTA		18	/* Link Status */
#define PCI_EXP_SLTCAP		20	/* Slot Capabilities */
#define PCI_EXP_SLTCTL		24	/* Slot Control */
#define PCI_EXP_SLTSTA		26	/* Slot Status */
#define PCI_EXP_RTCTL		28	/* Root Control */
#define PCI_EXP_RTCAP		30	/* Root Capabilities */
#define PCI_EXP_RTSTA		32	/* Root Status */
#endif /* < 2.6.11 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12) )
#include <linux/reboot.h>
#define USE_REBOOT_NOTIFIER

/* Generic MII registers. */
#define MII_CTRL1000        0x09        /* 1000BASE-T control          */
#define MII_STAT1000        0x0a        /* 1000BASE-T status           */
/* Advertisement control register. */
#define ADVERTISE_PAUSE_CAP     0x0400  /* Try for pause               */
#define ADVERTISE_PAUSE_ASYM    0x0800  /* Try for asymmetric pause     */
/* Link partner ability register. */
#define LPA_PAUSE_CAP		0x0400	/* Can pause                   */
#define LPA_PAUSE_ASYM		0x0800	/* Can pause asymetrically     */
/* 1000BASE-T Control register */
#define ADVERTISE_1000FULL      0x0200  /* Advertise 1000BASE-T full duplex */
#define ADVERTISE_1000HALF	0x0100  /* Advertise 1000BASE-T half duplex */
/* 1000BASE-T Status register */
#define LPA_1000LOCALRXOK	0x2000	/* Link partner local receiver status */
#define LPA_1000REMRXOK		0x1000	/* Link partner remote receiver status */

#ifndef is_zero_ether_addr
#define is_zero_ether_addr _kc_is_zero_ether_addr
static inline int _kc_is_zero_ether_addr(const u8 *addr)
{
	return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
}
#endif /* is_zero_ether_addr */
#ifndef is_multicast_ether_addr
#define is_multicast_ether_addr _kc_is_multicast_ether_addr
static inline int _kc_is_multicast_ether_addr(const u8 *addr)
{
	return addr[0] & 0x01;
}
#endif /* is_multicast_ether_addr */
#endif /* < 2.6.12 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13) )
#ifndef kstrdup
#define kstrdup _kc_kstrdup
char *_kc_kstrdup(const char *s, unsigned int gfp);
#endif
#endif /* < 2.6.13 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14) )
#define pm_message_t u32
#ifndef kzalloc
#define kzalloc _kc_kzalloc
void *_kc_kzalloc(size_t size, int flags);
#endif

/* Generic MII registers. */
#define MII_ESTATUS	    0x0f	/* Extended Status */
/* Basic mode status register. */
#define BMSR_ESTATEN		0x0100	/* Extended Status in R15 */
/* Extended status register. */
#define ESTATUS_1000_TFULL	0x2000	/* Can do 1000BT Full */
#define ESTATUS_1000_THALF	0x1000	/* Can do 1000BT Half */

#define SUPPORTED_Pause	        BIT(13)
#define SUPPORTED_Asym_Pause	BIT(14)
#define ADVERTISED_Pause	BIT(13)
#define ADVERTISED_Asym_Pause	BIT(14)

#if (!(RHEL_RELEASE_CODE && \
       (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(4,3)) && \
       (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(5,0))))
#if ((LINUX_VERSION_CODE == KERNEL_VERSION(2,6,9)) && !defined(gfp_t))
#define gfp_t unsigned
#else
typedef unsigned gfp_t;
#endif
#endif /* !RHEL4.3->RHEL5.0 */

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9) )
#ifdef CONFIG_X86_64
#define dma_sync_single_range_for_cpu(dev, addr, off, sz, dir)       \
	dma_sync_single_for_cpu((dev), (addr), (off) + (sz), (dir))
#define dma_sync_single_range_for_device(dev, addr, off, sz, dir)    \
	dma_sync_single_for_device((dev), (addr), (off) + (sz), (dir))
#endif
#endif
#endif /* < 2.6.14 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15) )
#ifndef kfree_rcu
/* this is placed here due to a lack of rcu_barrier in previous kernels */
#define kfree_rcu(_ptr, _offset) kfree(_ptr)
#endif /* kfree_rcu */
#ifndef vmalloc_node
#define vmalloc_node(a,b) vmalloc(a)
#endif /* vmalloc_node*/

#define setup_timer(_timer, _function, _data) \
do { \
	(_timer)->function = _function; \
	(_timer)->data = _data; \
	init_timer(_timer); \
} while (0)
#ifndef device_can_wakeup
#define device_can_wakeup(dev)	(1)
#endif
#ifndef device_set_wakeup_enable
#define device_set_wakeup_enable(dev, val)	do{}while(0)
#endif
#ifndef device_init_wakeup
#define device_init_wakeup(dev,val) do {} while (0)
#endif
static inline unsigned _kc_compare_ether_addr(const u8 *addr1, const u8 *addr2)
{
	const u16 *a = (const u16 *) addr1;
	const u16 *b = (const u16 *) addr2;

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}
#undef compare_ether_addr
#define compare_ether_addr(addr1, addr2) _kc_compare_ether_addr(addr1, addr2)
#endif /* < 2.6.15 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16) )
#undef DEFINE_MUTEX
#define DEFINE_MUTEX(x)	DECLARE_MUTEX(x)
#define mutex_lock(x)	down_interruptible(x)
#define mutex_unlock(x)	up(x)

#ifndef ____cacheline_internodealigned_in_smp
#ifdef CONFIG_SMP
#define ____cacheline_internodealigned_in_smp ____cacheline_aligned_in_smp
#else
#define ____cacheline_internodealigned_in_smp
#endif /* CONFIG_SMP */
#endif /* ____cacheline_internodealigned_in_smp */
#undef HAVE_PCI_ERS
#else /* 2.6.16 and above */
#undef HAVE_PCI_ERS
#define HAVE_PCI_ERS
#if ( SLE_VERSION_CODE && SLE_VERSION_CODE == SLE_VERSION(10,4,0) )
#ifdef device_can_wakeup
#undef device_can_wakeup
#endif /* device_can_wakeup */
#define device_can_wakeup(dev) 1
#endif /* SLE_VERSION(10,4,0) */
#endif /* < 2.6.16 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17) )
#ifndef dev_notice
#define dev_notice(dev, fmt, args...)            \
	dev_printk(KERN_NOTICE, dev, fmt, ## args)
#endif

#ifndef first_online_node
#define first_online_node 0
#endif
#ifndef NET_SKB_PAD
#define NET_SKB_PAD 16
#endif
#endif /* < 2.6.17 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18) )

#ifndef IRQ_HANDLED
#define irqreturn_t void
#define IRQ_HANDLED
#define IRQ_NONE
#endif

#ifndef IRQF_PROBE_SHARED
#ifdef SA_PROBEIRQ
#define IRQF_PROBE_SHARED SA_PROBEIRQ
#else
#define IRQF_PROBE_SHARED 0
#endif
#endif

#ifndef IRQF_SHARED
#define IRQF_SHARED SA_SHIRQ
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef skb_is_gso
#ifdef NETIF_F_TSO
#define skb_is_gso _kc_skb_is_gso
static inline int _kc_skb_is_gso(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_size;
}
#else
#define skb_is_gso(a) 0
#endif
#endif

#ifndef resource_size_t
#define resource_size_t unsigned long
#endif

#ifdef skb_pad
#undef skb_pad
#endif
#define skb_pad(x,y) _kc_skb_pad(x, y)
int _kc_skb_pad(struct sk_buff *skb, int pad);
#ifdef skb_padto
#undef skb_padto
#endif
#define skb_padto(x,y) _kc_skb_padto(x, y)
static inline int _kc_skb_padto(struct sk_buff *skb, unsigned int len)
{
	unsigned int size = skb->len;
	if(likely(size >= len))
		return 0;
	return _kc_skb_pad(skb, len - size);
}

#ifndef DECLARE_PCI_UNMAP_ADDR
#define DECLARE_PCI_UNMAP_ADDR(ADDR_NAME) \
	dma_addr_t ADDR_NAME
#define DECLARE_PCI_UNMAP_LEN(LEN_NAME) \
	u32 LEN_NAME
#define pci_unmap_addr(PTR, ADDR_NAME) \
	((PTR)->ADDR_NAME)
#define pci_unmap_addr_set(PTR, ADDR_NAME, VAL) \
	(((PTR)->ADDR_NAME) = (VAL))
#define pci_unmap_len(PTR, LEN_NAME) \
	((PTR)->LEN_NAME)
#define pci_unmap_len_set(PTR, LEN_NAME, VAL) \
	(((PTR)->LEN_NAME) = (VAL))
#endif /* DECLARE_PCI_UNMAP_ADDR */
#endif /* < 2.6.18 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19) )
enum pcie_link_width {
	PCIE_LNK_WIDTH_RESRV    = 0x00,
	PCIE_LNK_X1             = 0x01,
	PCIE_LNK_X2             = 0x02,
	PCIE_LNK_X4             = 0x04,
	PCIE_LNK_X8             = 0x08,
	PCIE_LNK_X12            = 0x0C,
	PCIE_LNK_X16            = 0x10,
	PCIE_LNK_X32            = 0x20,
	PCIE_LNK_WIDTH_UNKNOWN  = 0xFF,
};

#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,0)))
#define i_private u.generic_ip
#endif /* >= RHEL 5.0 */

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif
#ifndef __ALIGN_MASK
#define __ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#endif
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0) )
#if (!((RHEL_RELEASE_CODE && \
        ((RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(4,4) && \
          RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(5,0)) || \
         (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(5,0))))))
typedef irqreturn_t (*irq_handler_t)(int, void*, struct pt_regs *);
#endif
#if (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,0))
#undef CONFIG_INET_LRO
#undef CONFIG_INET_LRO_MODULE
#endif
typedef irqreturn_t (*new_handler_t)(int, void*);
static inline irqreturn_t _kc_request_irq(unsigned int irq, new_handler_t handler, unsigned long flags, const char *devname, void *dev_id)
#else /* 2.4.x */
typedef void (*irq_handler_t)(int, void*, struct pt_regs *);
typedef void (*new_handler_t)(int, void*);
static inline int _kc_request_irq(unsigned int irq, new_handler_t handler, unsigned long flags, const char *devname, void *dev_id)
#endif /* >= 2.5.x */
{
	irq_handler_t new_handler = (irq_handler_t) handler;
	return request_irq(irq, new_handler, flags, devname, dev_id);
}

#undef request_irq
#define request_irq(irq, handler, flags, devname, dev_id) _kc_request_irq((irq), (handler), (flags), (devname), (dev_id))

#define irq_handler_t new_handler_t

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11) )
#ifndef skb_checksum_help
static inline int __kc_skb_checksum_help(struct sk_buff *skb)
{
	return skb_checksum_help(skb, 0);
}
#define skb_checksum_help(skb) __kc_skb_checksum_help((skb))
#endif
#endif /* < 2.6.19 && >= 2.6.11 */

/* pci_restore_state and pci_save_state handles MSI/PCIE from 2.6.19 */
#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,4)))
#define PCIE_CONFIG_SPACE_LEN 256
#define PCI_CONFIG_SPACE_LEN 64
#define PCIE_LINK_STATUS 0x12
#define pci_config_space_ich8lan() do {} while(0)
#undef pci_save_state
int _kc_pci_save_state(struct pci_dev *);
#define pci_save_state(pdev) _kc_pci_save_state(pdev)
#undef pci_restore_state
void _kc_pci_restore_state(struct pci_dev *);
#define pci_restore_state(pdev) _kc_pci_restore_state(pdev)
#endif /* !(RHEL_RELEASE_CODE >= RHEL 5.4) */

#ifdef HAVE_PCI_ERS
#undef free_netdev
void _kc_free_netdev(struct net_device *);
#define free_netdev(netdev) _kc_free_netdev(netdev)
#endif
static inline int pci_enable_pcie_error_reporting(struct pci_dev __always_unused *dev)
{
	return 0;
}
#define pci_disable_pcie_error_reporting(dev) do {} while (0)
#define pci_cleanup_aer_uncorrect_error_status(dev) do {} while (0)

void *_kc_kmemdup(const void *src, size_t len, unsigned gfp);
#define kmemdup(src, len, gfp) _kc_kmemdup(src, len, gfp)
#ifndef bool
#define bool _Bool
#define true 1
#define false 0
#endif
#else /* 2.6.19 */
#include <linux/aer.h>
#include <linux/pci_hotplug.h>

#define NEW_SKB_CSUM_HELP
#endif /* < 2.6.19 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20) )
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,28) )
#undef INIT_WORK
#define INIT_WORK(_work, _func) \
do { \
	INIT_LIST_HEAD(&(_work)->entry); \
	(_work)->pending = 0; \
	(_work)->func = (void (*)(void *))_func; \
	(_work)->data = _work; \
	init_timer(&(_work)->timer); \
} while (0)
#endif

#ifndef PCI_VDEVICE
#define PCI_VDEVICE(ven, dev)        \
	PCI_VENDOR_ID_##ven, (dev),  \
	PCI_ANY_ID, PCI_ANY_ID, 0, 0
#endif

#ifndef PCI_VENDOR_ID_INTEL
#define PCI_VENDOR_ID_INTEL 0x8086
#endif

#ifndef round_jiffies
#define round_jiffies(x) x
#endif

#define csum_offset csum

#define HAVE_EARLY_VMALLOC_NODE
#define dev_to_node(dev) -1
#undef set_dev_node
/* remove compiler warning with b=b, for unused variable */
#define set_dev_node(a, b) do { (b) = (b); } while(0)

#if (!(RHEL_RELEASE_CODE && \
       (((RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(4,7)) && \
         (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(5,0))) || \
        (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,6)))) && \
     !(SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(10,2,0)))
typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;
#endif

#if (!(RHEL_RELEASE_CODE && \
       (((RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(4,7)) && \
         (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(5,0))) || \
        (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,4)))) && \
     !(SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(10,2,0)))
static inline __wsum csum_unfold(__sum16 n)
{
	return (__force __wsum)n;
}
#endif

#else /* < 2.6.20 */
#define HAVE_DEVICE_NUMA_NODE
#endif /* < 2.6.20 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21) )
#define to_net_dev(class) container_of(class, struct net_device, class_dev)
#define NETDEV_CLASS_DEV
#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(5,5)))
#define vlan_group_get_device(vg, id) (vg->vlan_devices[id])
#define vlan_group_set_device(vg, id, dev)		\
	do {						\
		if (vg) vg->vlan_devices[id] = dev;	\
	} while (0)
#endif /* !(RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(5,5)) */
#define pci_channel_offline(pdev) (pdev->error_state && \
	pdev->error_state != pci_channel_io_normal)
#define pci_request_selected_regions(pdev, bars, name) \
        pci_request_regions(pdev, name)
#define pci_release_selected_regions(pdev, bars) pci_release_regions(pdev);

#ifndef __aligned
#define __aligned(x)			__attribute__((aligned(x)))
#endif

struct pci_dev *_kc_netdev_to_pdev(struct net_device *netdev);
#define netdev_to_dev(netdev)	\
	pci_dev_to_dev(_kc_netdev_to_pdev(netdev))
#define devm_kzalloc(dev, size, flags) kzalloc(size, flags)
#define devm_kfree(dev, p) kfree(p)
#else /* 2.6.21 */
static inline struct device *netdev_to_dev(struct net_device *netdev)
{
	return &netdev->dev;
}

#endif /* < 2.6.21 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) )
#define tcp_hdr(skb) (skb->h.th)
#define tcp_hdrlen(skb) (skb->h.th->doff << 2)
#define skb_transport_offset(skb) (skb->h.raw - skb->data)
#define skb_transport_header(skb) (skb->h.raw)
#define ipv6_hdr(skb) (skb->nh.ipv6h)
#define ip_hdr(skb) (skb->nh.iph)
#define skb_network_offset(skb) (skb->nh.raw - skb->data)
#define skb_network_header(skb) (skb->nh.raw)
#define skb_tail_pointer(skb) skb->tail
#define skb_reset_tail_pointer(skb) \
	do { \
		skb->tail = skb->data; \
	} while (0)
#define skb_set_tail_pointer(skb, offset) \
	do { \
		skb->tail = skb->data + offset; \
	} while (0)
#define skb_copy_to_linear_data(skb, from, len) \
				memcpy(skb->data, from, len)
#define skb_copy_to_linear_data_offset(skb, offset, from, len) \
				memcpy(skb->data + offset, from, len)
#define skb_network_header_len(skb) (skb->h.raw - skb->nh.raw)
#define pci_register_driver pci_module_init
#define skb_mac_header(skb) skb->mac.raw

#ifdef NETIF_F_MULTI_QUEUE
#ifndef alloc_etherdev_mq
#define alloc_etherdev_mq(_a, _b) alloc_etherdev(_a)
#endif
#endif /* NETIF_F_MULTI_QUEUE */

#ifndef ETH_FCS_LEN
#define ETH_FCS_LEN 4
#endif
#define cancel_work_sync(x) flush_scheduled_work()
#ifndef udp_hdr
#define udp_hdr _udp_hdr
static inline struct udphdr *_udp_hdr(const struct sk_buff *skb)
{
	return (struct udphdr *)skb_transport_header(skb);
}
#endif

#ifdef cpu_to_be16
#undef cpu_to_be16
#endif
#define cpu_to_be16(x) __constant_htons(x)

#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(5,1)))
enum {
	DUMP_PREFIX_NONE,
	DUMP_PREFIX_ADDRESS,
	DUMP_PREFIX_OFFSET
};
#endif /* !(RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(5,1)) */
#ifndef hex_asc
#define hex_asc(x)	"0123456789abcdef"[x]
#endif
#include <linux/ctype.h>
void _kc_print_hex_dump(const char *level, const char *prefix_str,
			int prefix_type, int rowsize, int groupsize,
			const void *buf, size_t len, bool ascii);
#define print_hex_dump(lvl, s, t, r, g, b, l, a) \
		_kc_print_hex_dump(lvl, s, t, r, g, b, l, a)
#ifndef ADVERTISED_2500baseX_Full
#define ADVERTISED_2500baseX_Full BIT(15)
#endif
#ifndef SUPPORTED_2500baseX_Full
#define SUPPORTED_2500baseX_Full BIT(15)
#endif

#ifndef ETH_P_PAUSE
#define ETH_P_PAUSE 0x8808
#endif

static inline int compound_order(struct page *page)
{
	return 0;
}

#define __must_be_array(a) 0

#ifndef SKB_WITH_OVERHEAD
#define SKB_WITH_OVERHEAD(X) \
	((X) - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
#endif
#else /* 2.6.22 */
#define ETH_TYPE_TRANS_SETS_DEV
#define HAVE_NETDEV_STATS_IN_NETDEV
#endif /* < 2.6.22 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE > KERNEL_VERSION(2,6,22) )
#undef SET_MODULE_OWNER
#define SET_MODULE_OWNER(dev) do { } while (0)
#endif /* > 2.6.22 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23) )
#define netif_subqueue_stopped(_a, _b) 0
#ifndef PTR_ALIGN
#define PTR_ALIGN(p, a)         ((typeof(p))ALIGN((unsigned long)(p), (a)))
#endif

#ifndef CONFIG_PM_SLEEP
#define CONFIG_PM_SLEEP	CONFIG_PM
#endif

#if ( LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13) )
#define HAVE_ETHTOOL_GET_PERM_ADDR
#endif /* 2.6.14 through 2.6.22 */

static inline int __kc_skb_cow_head(struct sk_buff *skb, unsigned int headroom)
{
	int delta = 0;

	if (headroom > (skb->data - skb->head))
		delta = headroom - (skb->data - skb->head);

	if (delta || skb_header_cloned(skb))
		return pskb_expand_head(skb, ALIGN(delta, NET_SKB_PAD), 0,
					GFP_ATOMIC);
	return 0;
}
#define skb_cow_head(s, h) __kc_skb_cow_head((s), (h))
#endif /* < 2.6.23 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24) )
#ifndef ETH_FLAG_LRO
#define ETH_FLAG_LRO NETIF_F_LRO
#endif

#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

/* if GRO is supported then the napi struct must already exist */
#ifndef NETIF_F_GRO
/* NAPI API changes in 2.6.24 break everything */
struct napi_struct {
	/* used to look up the real NAPI polling routine */
	int (*poll)(struct napi_struct *, int);
	struct net_device *dev;
	int weight;
};
#endif

#ifdef NAPI
int __kc_adapter_clean(struct net_device *, int *);
/* The following defines only provide limited support for NAPI calls and
 * should only be used by drivers which are not multi-queue enabled.
 */

#define napi_to_poll_dev(_napi) (_napi)->dev

static inline void __kc_netif_napi_add(struct net_device *dev, struct napi_struct *napi,
				  int (*poll)(struct napi_struct *, int), int weight)
{
	dev->poll = __kc_adapter_clean;
	dev->weight = weight;
	napi->poll = poll;
	napi->dev = dev;
}
#define netif_napi_add __kc_netif_napi_add

#define netif_napi_del(_a) do {} while (0)
#define napi_schedule_prep(_napi) netif_rx_schedule_prep((_napi)->dev)
#define napi_schedule(_napi) netif_rx_schedule((_napi)->dev)
#define napi_enable(_napi) netif_poll_enable(napi_to_poll_dev(_napi))
#define napi_disable(_napi) netif_poll_disable(napi_to_poll_dev(_napi))
#ifdef CONFIG_SMP
static inline void napi_synchronize(const struct napi_struct *n)
{
	struct net_device *dev = napi_to_poll_dev(n);

	while (test_bit(__LINK_STATE_RX_SCHED, &dev->state)) {
		/* No hurry. */
		msleep(1);
	}
}
#else
#define napi_synchronize(n)	barrier()
#endif /* CONFIG_SMP */
#define __napi_schedule(_napi) __netif_rx_schedule(napi_to_poll_dev(_napi))
static inline void _kc_napi_complete(struct napi_struct *napi)
{
#ifdef NETIF_F_GRO
	napi_gro_flush(napi);
#endif
	netif_rx_complete(napi_to_poll_dev(napi));
}
#define napi_complete _kc_napi_complete
#else /* NAPI */

/* The following definitions are only used if we don't support NAPI at all. */

static inline __kc_netif_napi_add(struct net_device *dev, struct napi_struct *napi,
				  int (*poll)(struct napi_struct *, int), int weight)
{
	dev->poll = poll;
	dev->weight = weight;
	napi->poll = poll;
	napi->weight = weight;
	napi->dev = dev;
}
#define netif_napi_del(_a) do {} while (0)
#endif /* NAPI */

#undef dev_get_by_name
#define dev_get_by_name(_a, _b) dev_get_by_name(_b)
#define __netif_subqueue_stopped(_a, _b) netif_subqueue_stopped(_a, _b)
#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n)	(((n) == 64) ? DMA_64BIT_MASK : ((1ULL<<(n))-1))
#endif

#ifdef NETIF_F_TSO6
#define skb_is_gso_v6 _kc_skb_is_gso_v6
static inline int _kc_skb_is_gso_v6(const struct sk_buff *skb)
{
	return skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6;
}
#endif /* NETIF_F_TSO6 */

#ifndef KERN_CONT
#define KERN_CONT	""
#endif
#ifndef pr_err
#define pr_err(fmt, arg...) \
	printk(KERN_ERR fmt, ##arg)
#endif

#ifndef rounddown_pow_of_two
#define rounddown_pow_of_two(n) \
	__builtin_constant_p(n) ? ( \
		(n == 1) ? 0 : \
		(1UL << ilog2(n))) : \
		(1UL << (fls_long(n) - 1))
#endif

#else /* < 2.6.24 */
#define HAVE_ETHTOOL_GET_SSET_COUNT
#define HAVE_NETDEV_NAPI_LIST
#endif /* < 2.6.24 */

#endif /* _KCOMPAT_H_ */
