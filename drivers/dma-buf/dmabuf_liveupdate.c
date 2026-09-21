// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, Zhu Yanjun <yanjun.zhu@linux.dev>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/errno.h>
#include <linux/kho/abi/dmabuf.h>
#include <linux/liveupdate.h>
#include <linux/pci_liveupdate.h>
#include <linux/module.h>

#include "dmabuf_liveupdate.h"

static bool dmabuf_liveupdate_can_preserve(struct liveupdate_file_handler *handler,
					     struct file *file)
{
	return false;
}

static int dmabuf_liveupdate_preserve(struct liveupdate_file_op_args *args)
{
	return -EOPNOTSUPP;
}

static void dmabuf_liveupdate_unpreserve(struct liveupdate_file_op_args *args)
{
}

static int dmabuf_liveupdate_retrieve(struct liveupdate_file_op_args *args)
{
	return -EOPNOTSUPP;
}

static void dmabuf_liveupdate_finish(struct liveupdate_file_op_args *args)
{
}

static const struct liveupdate_file_ops dmabuf_liveupdate_file_ops = {
	.can_preserve = dmabuf_liveupdate_can_preserve,
	.preserve = dmabuf_liveupdate_preserve,
	.unpreserve = dmabuf_liveupdate_unpreserve,
	.retrieve = dmabuf_liveupdate_retrieve,
	.finish = dmabuf_liveupdate_finish,
	.owner = THIS_MODULE,
};

static struct liveupdate_file_handler dmabuf_liveupdate_fh = {
	.ops = &dmabuf_liveupdate_file_ops,
	.compatible = DMABUF_LUO_FH_COMPATIBLE,
};

int __init dmabuf_liveupdate_init(void)
{
	int ret;

	ret = liveupdate_register_file_handler(&dmabuf_liveupdate_fh);
	if (ret)
		goto err_return;

	ret = pci_liveupdate_register_flb(&dmabuf_liveupdate_fh);
	if (ret)
		goto err_unregister;

	return 0;

err_unregister:
	liveupdate_unregister_file_handler(&dmabuf_liveupdate_fh);
err_return:
	return (ret == -EOPNOTSUPP) ? 0 : ret;
}

void dmabuf_liveupdate_cleanup(void)
{
	pci_liveupdate_unregister_flb(&dmabuf_liveupdate_fh);
	liveupdate_unregister_file_handler(&dmabuf_liveupdate_fh);
}
