// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, Google LLC.
 * Zhu Yanjun <yanjun.zhu@linux.dev>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

//#include <linux/kho/abi/vfio_pci.h>
#include <linux/liveupdate.h>
#include <linux/errno.h>

#include "rxe_liveupdate.h"

static bool rxe_liveupdate_can_preserve(struct liveupdate_file_handler *handler,
					     struct file *file)
{
	pr_err("%s +%d %s\n", __FILE__, __LINE__, __func__);
	return false;
}

static int rxe_liveupdate_preserve(struct liveupdate_file_op_args *args)
{
	pr_err("%s +%d %s\n", __FILE__, __LINE__, __func__);
	return -EOPNOTSUPP;
}

static void rxe_liveupdate_unpreserve(struct liveupdate_file_op_args *args)
{
	pr_err("%s +%d %s\n", __FILE__, __LINE__, __func__);
}

static int rxe_liveupdate_retrieve(struct liveupdate_file_op_args *args)
{
	pr_err("%s +%d %s\n", __FILE__, __LINE__, __func__);
	return -EOPNOTSUPP;
}

static void rxe_liveupdate_finish(struct liveupdate_file_op_args *args)
{
	pr_err("%s +%d %s\n", __FILE__, __LINE__, __func__);
}

static const struct liveupdate_file_ops rxe_liveupdate_file_ops = {
	.can_preserve = rxe_liveupdate_can_preserve,
	.preserve = rxe_liveupdate_preserve,
	.unpreserve = rxe_liveupdate_unpreserve,
	.retrieve = rxe_liveupdate_retrieve,
	.finish = rxe_liveupdate_finish,
	.owner = THIS_MODULE,
};

#define VFIO_PCI_LUO_FH_COMPATIBLE "rxe-liveupdate-v1"
static struct liveupdate_file_handler rxe_liveupdate_fh = {
	.ops = &rxe_liveupdate_file_ops,
	.compatible = VFIO_PCI_LUO_FH_COMPATIBLE,
};

int __init rxe_liveupdate_init(void)
{
	if (!liveupdate_enabled())
		return 0;

	return liveupdate_register_file_handler(&rxe_liveupdate_fh);
}

void rxe_liveupdate_cleanup(void)
{
	if (!liveupdate_enabled())
		return;

	liveupdate_unregister_file_handler(&rxe_liveupdate_fh);
}
