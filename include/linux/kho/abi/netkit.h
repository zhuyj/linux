/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Zhu Yanjun <yanjun.zhu@linux.dev>
 */
#ifndef _LINUX_KHO_ABI_NETKIT_H
#define _LINUX_KHO_ABI_NETKIT_H

#include <linux/types.h>

/*
 * NETKIT Live Update ABI
 *
 * This header defines the ABI for preserving netkit state across kexec.
 *
 * The state is serialized into a packed structure `struct netkit_luo_ser`
 * which is handed over to the next kernel via the KHO mechanism.
 */

/**
 * struct netkit_luo_ser - Serialized state of an eventfd
 * @cnt: The number of netkit dev
 * @netkit_name: netkit device name
 * @base_dev: the net device under netkit device
 *
 * This structure contains the minimal state needed to restore a netkit
 * after kexec. The cnt represents the current value of the event counter,
 * and flags represent the file creation flags.
 */
struct netkit_luo_ser {
	__u64 cnt;
	char netkit_name[16][16];
	char net_mode[16][16];
} __packed;

/* The compatibility string for eventfd file handler */
#define NETKIT_LUO_FH_COMPATIBLE	"netkit-v1"

#endif /* _LINUX_KHO_ABI_NETKIT_H */

