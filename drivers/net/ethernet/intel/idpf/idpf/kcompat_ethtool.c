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

