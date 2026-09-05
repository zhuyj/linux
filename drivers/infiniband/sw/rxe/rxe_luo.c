// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Zhu Yanjun <yanjun.zhu@linux.dev>
 */
#include <linux/err.h>
#include <linux/file.h>
#include <linux/io.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/rxe.h>
#include <linux/liveupdate.h>
#include <linux/module.h>
#include <linux/eventfd.h>
#include <linux/anon_inodes.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/fdtable.h>

#include <linux/kho/abi/rxe.h>
#include "rxe_luo.h"

extern struct xarray rxe_luo_xa;

static int rxe_luo_preserve(struct liveupdate_file_op_args *args)
{
	struct rxe_luo_info *entry;
	struct rxe_luo_ser *ser;
	int err = 0, pos = 0;
	unsigned long index;

	rcu_read_lock();
	/* Only one rdma link is recorded now */
	xa_for_each(&rxe_luo_xa, index, entry) {
		ser = kho_alloc_preserve(sizeof(*ser));
		if (IS_ERR(ser)) {
			err = PTR_ERR(ser);
			pr_err("Failed to allocate preserve memory: %d\n", err);
			return err;
		}

		strscpy(ser->rxe_name[pos], entry->rxe_name, 64);
		strscpy(ser->base_dev[pos++], entry->ndev_name, 16);
	}
	rcu_read_unlock();

	/* Return physical address of serialization structure */
	args->serialized_data = virt_to_phys(ser);
	return 0;
}

static int rxe_luo_freeze(struct liveupdate_file_op_args *args)
{
	struct rxe_luo_ser *ser;
	unsigned long index;
	struct rxe_luo_info *entry;
	char rxe_name[64] = {};

	if (WARN_ON_ONCE(!args->serialized_data)) {
		return -EINVAL;
	}

	ser = phys_to_virt(args->serialized_data);
	rcu_read_lock();
	xa_for_each(&rxe_luo_xa, index, entry) {
		strscpy(rxe_name, entry->rxe_name, 64);
	}
	rcu_read_unlock();

	if (strncmp(rxe_name, ser->rxe_name[0], 64) != 0) {
		pr_warn("WARNING: Count changed during preserve->freeze! %s : %s\n",
			 rxe_name, ser->rxe_name[0]);
	}

	strscpy(ser->rxe_name[0], rxe_name, 64);

	return 0;
}

static void rxe_luo_unpreserve(struct liveupdate_file_op_args *args)
{
	struct rxe_luo_ser *ser;

	if (WARN_ON_ONCE(!args->serialized_data)) {
		return;
	}

	ser = phys_to_virt(args->serialized_data);
	kho_unpreserve_free(ser);
}

static int rxe_luo_retrieve(struct liveupdate_file_op_args *args)
{
	struct rxe_luo_ser *ser;

	ser = phys_to_virt(args->serialized_data);
	if (!ser) {
		pr_err("err is NULL\n");
		return -EINVAL;
	}
	pr_info("rxe_name: %s\n", ser->rxe_name[0]);
	return 0;
}

static void rxe_luo_finish(struct liveupdate_file_op_args *args)
{
	struct rxe_luo_ser *ser;

	if (args->retrieve_status) {
		return;
	}

	if (!args->serialized_data) {
		return;
	}

	ser = phys_to_virt(args->serialized_data);
	if (!ser) {
		return;
	}

	kho_restore_free(ser);
}

static bool rxe_luo_can_preserve(struct liveupdate_file_handler *handler,
				 struct file *file)
{
	if (!file->f_op) {
		return false;
	}

	/* Try to get rxe links - this will fail if no rxe links */
	if (xa_empty(&rxe_luo_xa)) {
		pr_warn("rxe_luo_xa is empty, no context exists.\n");
		return false;
	}

	pr_info("rxe_luo_xa contains active context(s).\n");
	return true;
}

static const struct liveupdate_file_ops rxe_luo_file_ops = {
	.preserve = rxe_luo_preserve,
	.unpreserve = rxe_luo_unpreserve,
	.freeze = rxe_luo_freeze,
	.retrieve = rxe_luo_retrieve,
	.finish = rxe_luo_finish,
	.can_preserve = rxe_luo_can_preserve,
	.owner = THIS_MODULE,
};

static struct liveupdate_file_handler rxe_luo_handler = {
	.ops = &rxe_luo_file_ops,
	.compatible = RXE_LUO_FH_COMPATIBLE,
};

int rxe_luo_init(void)
{
	int err = liveupdate_register_file_handler(&rxe_luo_handler);

	if (err && err != -EOPNOTSUPP) {
		pr_err("Could not register eventfd LUO handler: %pe\n",
		       ERR_PTR(err));
		return err;
	}

	return 0;
}

void rxe_luo_exit(void)
{
	liveupdate_unregister_file_handler(&rxe_luo_handler);
}
