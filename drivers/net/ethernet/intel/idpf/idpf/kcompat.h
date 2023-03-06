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

/*
 * Load the implementations file which actually defines kcompat backports.
 * Legacy backports still exist in this file, but all new backports must be
 * implemented using kcompat_*defs.h and kcompat_impl.h
 */
#include "kcompat_impl.h"

#endif /* _KCOMPAT_H_ */
