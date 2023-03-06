// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2010 - 2019 Intel Corporation */
/*
 * net/core/ethtool.c - Ethtool ioctl handler
 * Copyright (c) 2003 Matthew Wilcox <matthew@wil.cx>
 *
 * This file is where we call all the ethtool_ops commands to get
 * the information ethtool needs.  We fall back to calling do_ioctl()
 * for drivers which haven't been converted to ethtool_ops yet.
 *
 * It's GPL, stupid.
 *
 * Modification by sfeldma@pobox.com to work as backward compat
 * solution for pre-ethtool_ops kernels.
 * 	- copied struct ethtool_ops from ethtool.h
 * 	- defined SET_ETHTOOL_OPS
 * 	- put in some #ifndef NETIF_F_xxx wrappers
 * 	- changes refs to dev->ethtool_ops to ethtool_ops
 * 	- changed dev_ethtool to ethtool_ioctl
 *      - remove EXPORT_SYMBOL()s
 *      - added _kc_ prefix in built-in ethtool_op_xxx ops.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <asm/uaccess.h>

#include "kcompat.h"

#undef SUPPORTED_10000baseT_Full
#define SUPPORTED_10000baseT_Full	(1 << 12)
#undef ADVERTISED_10000baseT_Full
#define ADVERTISED_10000baseT_Full	(1 << 12)
#undef SPEED_10000
#define SPEED_10000		10000

#undef ethtool_ops
#define ethtool_ops _kc_ethtool_ops

struct _kc_ethtool_ops {
	int  (*get_settings)(struct net_device *, struct ethtool_cmd *);
	int  (*set_settings)(struct net_device *, struct ethtool_cmd *);
	void (*get_drvinfo)(struct net_device *, struct ethtool_drvinfo *);
	int  (*get_regs_len)(struct net_device *);
	void (*get_regs)(struct net_device *, struct ethtool_regs *, void *);
	void (*get_wol)(struct net_device *, struct ethtool_wolinfo *);
	int  (*set_wol)(struct net_device *, struct ethtool_wolinfo *);
	u32  (*get_msglevel)(struct net_device *);
	void (*set_msglevel)(struct net_device *, u32);
	int  (*nway_reset)(struct net_device *);
	u32  (*get_link)(struct net_device *);
	int  (*get_eeprom_len)(struct net_device *);
	int  (*get_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int  (*set_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int  (*get_coalesce)(struct net_device *, struct ethtool_coalesce *);
	int  (*set_coalesce)(struct net_device *, struct ethtool_coalesce *);
	void (*get_ringparam)(struct net_device *, struct ethtool_ringparam *);
	int  (*set_ringparam)(struct net_device *, struct ethtool_ringparam *);
	void (*get_pauseparam)(struct net_device *,
	                       struct ethtool_pauseparam*);
	int  (*set_pauseparam)(struct net_device *,
	                       struct ethtool_pauseparam*);
	u32  (*get_rx_csum)(struct net_device *);
	int  (*set_rx_csum)(struct net_device *, u32);
	u32  (*get_tx_csum)(struct net_device *);
	int  (*set_tx_csum)(struct net_device *, u32);
	u32  (*get_sg)(struct net_device *);
	int  (*set_sg)(struct net_device *, u32);
	u32  (*get_tso)(struct net_device *);
	int  (*set_tso)(struct net_device *, u32);
	int  (*self_test_count)(struct net_device *);
	void (*self_test)(struct net_device *, struct ethtool_test *, u64 *);
	void (*get_strings)(struct net_device *, u32 stringset, u8 *);
	int  (*phys_id)(struct net_device *, u32);
	int  (*get_stats_count)(struct net_device *);
	void (*get_ethtool_stats)(struct net_device *, struct ethtool_stats *,
	                          u64 *);
} *ethtool_ops = NULL;

#undef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev, ops) (ethtool_ops = (ops))

/*
 * Some useful ethtool_ops methods that are device independent. If we find that
 * all drivers want to do the same thing here, we can turn these into dev_()
 * function calls.
 */

#undef ethtool_op_get_link
#define ethtool_op_get_link _kc_ethtool_op_get_link
u32 _kc_ethtool_op_get_link(struct net_device *dev)
{
	return netif_carrier_ok(dev) ? 1 : 0;
}

#undef ethtool_op_get_tx_csum
#define ethtool_op_get_tx_csum _kc_ethtool_op_get_tx_csum
u32 _kc_ethtool_op_get_tx_csum(struct net_device *dev)
{
#ifdef NETIF_F_IP_CSUM
	return (dev->features & NETIF_F_IP_CSUM) != 0;
#else
	return 0;
#endif
}

#undef ethtool_op_set_tx_csum
#define ethtool_op_set_tx_csum _kc_ethtool_op_set_tx_csum
int _kc_ethtool_op_set_tx_csum(struct net_device *dev, u32 data)
{
#ifdef NETIF_F_IP_CSUM
	if (data)
#ifdef NETIF_F_IPV6_CSUM
		dev->features |= (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);
	else
		dev->features &= ~(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);
#else
		dev->features |= NETIF_F_IP_CSUM;
	else
		dev->features &= ~NETIF_F_IP_CSUM;
#endif
#endif

	return 0;
}

#undef ethtool_op_get_sg
#define ethtool_op_get_sg _kc_ethtool_op_get_sg
u32 _kc_ethtool_op_get_sg(struct net_device *dev)
{
#ifdef NETIF_F_SG
	return (dev->features & NETIF_F_SG) != 0;
#else
	return 0;
#endif
}

#undef ethtool_op_set_sg
#define ethtool_op_set_sg _kc_ethtool_op_set_sg
int _kc_ethtool_op_set_sg(struct net_device *dev, u32 data)
{
#ifdef NETIF_F_SG
	if (data)
		dev->features |= NETIF_F_SG;
	else
		dev->features &= ~NETIF_F_SG;
#endif

	return 0;
}

#undef ethtool_op_get_tso
#define ethtool_op_get_tso _kc_ethtool_op_get_tso
u32 _kc_ethtool_op_get_tso(struct net_device *dev)
{
#ifdef NETIF_F_TSO
	return (dev->features & NETIF_F_TSO) != 0;
#else
	return 0;
#endif
}

#undef ethtool_op_set_tso
#define ethtool_op_set_tso _kc_ethtool_op_set_tso
int _kc_ethtool_op_set_tso(struct net_device *dev, u32 data)
{
#ifdef NETIF_F_TSO
	if (data)
		dev->features |= NETIF_F_TSO;
	else
		dev->features &= ~NETIF_F_TSO;
#endif

	return 0;
}
