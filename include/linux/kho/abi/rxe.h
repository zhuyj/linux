/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Zhu Yanjun <yanjun.zhu@linux.dev>
 */
#ifndef _LINUX_KHO_ABI_RXE_H
#define _LINUX_KHO_ABI_RXE_H

#include <linux/types.h>

/*
 * RXE Live Update ABI
 *
 * This header defines the ABI for preserving rxe state across kexec.
 *
 * The state is serialized into a packed structure `struct rxe_luo_ser`
 * which is handed over to the next kernel via the KHO mechanism.
 */

/**
 * struct rxe_luo_ser - Serialized state of an eventfd
 * @cnt: The number of rxe dev
 * @rxe_name: rxe device name
 * @base_dev: the net device under rxe device
 *
 * This structure contains the minimal state needed to restore a rxe 
 * after kexec. The cnt represents the current value of the event counter,
 * and flags represent the file creation flags.
 */
struct eventfd_luo_ser {
	__u64 cnt;
	char rxe_name[16];
	char base_dev[16];
} __packed;

/* The compatibility string for eventfd file handler */
#define RXE_LUO_FH_COMPATIBLE	"rxe-v1"

#endif /* _LINUX_KHO_ABI_RXE_H */
