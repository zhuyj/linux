/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2026, Zhu Yanjun <yanjun.zhu@linux.dev>
 */

#ifndef _LINUX_LIVEUPDATE_ABI_DMABUF_H
#define _LINUX_LIVEUPDATE_ABI_DMABUF_H

#include <linux/types.h>

/**
 * DOC: DMABUF Live Update ABI
 *
 * DMABUF uses the ABI defined below for preserving device files across a kexec
 * reboot using LUO.
 *
 * Device metadata is serialized into memory which is then handed to the next
 * kernel via KHO.
 *
 * This interface is a contract. Any modification to any of the serialization
 * structs defined here constitutes a breaking change. Such changes require
 * incrementing the version number in the DMABUF_LUO_FH_COMPATIBLE string.
 */

#define DMABUF_LUO_FH_COMPATIBLE "dmabuf-v1"

/**
 * struct dmabuf_ser - Serialized state of a single dmabuf PCI
 * device.
 *
 * @domain: The device's PCI domain number (segment).
 * @bdf: The device's PCI bus, device, and function number.
 */
struct dmabuf_ser {
	u32 domain;
	u16 bdf;
} __packed;

#endif /* _LINUX_LIVEUPDATE_ABI_DMABUF_H */
