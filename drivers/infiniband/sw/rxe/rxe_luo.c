// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Zhu Yanjun <yanjun.zhu@linux.dev>
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

#include "rxe_luo.h"

static int rxe_luo_preserve(struct liveupdate_file_op_args *args)
{
	pr_info("%s +%d \n", __func__, __FILE__, __LINE__);
#if 0
	struct eventfd_luo_ser *ser;
	u64 count;
	unsigned int flags;
	int err = 0;

	/* Get eventfd state safely */
	err = eventfd_luo_get_state(args->file, &count, &flags);
	if (err) {
		pr_err("Failed to get eventfd state: %d\n", err);
		return err;
	}

	ser = kho_alloc_preserve(sizeof(*ser));
	if (IS_ERR(ser)) {
		err = PTR_ERR(ser);
		pr_err("Failed to allocate preserve memory: %d\n", err);
		return err;
	}

	/* Save eventfd state */
	ser->count = count;
	ser->flags = flags;

	pr_debug("Preserved eventfd: count=%llu, flags=0x%x\n",
		ser->count, ser->flags);

	/* Return physical address of serialization structure */
	args->serialized_data = virt_to_phys(ser);
#endif
	return 0;
}

static int rxe_luo_freeze(struct liveupdate_file_op_args *args)
{
	pr_info("%s +%d \n", __func__, __FILE__, __LINE__);
#if 0	
	struct eventfd_luo_ser *ser;
	u64 count;
	unsigned int flags;
	int err;

	if (WARN_ON_ONCE(!args->serialized_data))
		return -EINVAL;

	ser = phys_to_virt(args->serialized_data);

	/* Get current state and update if changed */
	err = eventfd_luo_get_state(args->file, &count, &flags);
	if (err)
		return err;

	if (ser->count != count) {
		pr_debug("WARNING: Count changed during preserve->freeze! old=%llu, new=%llu\n",
			 ser->count, count);
	}

	ser->count = count;
#endif
	return 0;
}

static void rxe_luo_unpreserve(struct liveupdate_file_op_args *args)
{
	pr_info("%s +%d \n", __func__, __FILE__, __LINE__);
#if 0
	struct eventfd_luo_ser *ser;

	if (WARN_ON_ONCE(!args->serialized_data))
		return;

	ser = phys_to_virt(args->serialized_data);
	kho_unpreserve_free(ser);
#endif	
}

static int rxe_luo_retrieve(struct liveupdate_file_op_args *args)
{
	pr_info("%s +%d \n", __func__, __FILE__, __LINE__);
#if 0	
	struct eventfd_luo_ser *ser;
	struct eventfd_ctx *ctx;
	struct file *file = NULL;
	int eventfd;

	ser = phys_to_virt(args->serialized_data);
	if (!ser)
		return -EINVAL;

	/* Create a new eventfd with the preserved count and flags */
	eventfd = eventfd_create(ser->count, ser->flags);
	if (eventfd < 0) {
		pr_err("Failed to create eventfd: %d\n", eventfd);
		return eventfd;
	}

	file = fget(eventfd);
	if (!file) {
		pr_err("Failed to get file from fd\n");
		close_fd(eventfd);
		return -EBADF;
	}

	close_fd(eventfd);

	/* Verify the created file has correct internal state */
	ctx = eventfd_ctx_fileget(file);
	if (IS_ERR(ctx)) {
		pr_err("Failed to get context from file\n");
		fput(file);
		return PTR_ERR(ctx);
	}

	eventfd_ctx_put(ctx);

	args->file = file;
#endif	
	return 0;
}

static void rxe_luo_finish(struct liveupdate_file_op_args *args)
{
	pr_info("%s +%d \n", __func__, __FILE__, __LINE__);
#if 0	
	struct eventfd_luo_ser *ser;

	if (args->retrieve_status)
		return;

	if (!args->serialized_data)
		return;

	ser = phys_to_virt(args->serialized_data);
	if (!ser)
		return;

	kho_restore_free(ser);
#endif	
}

static bool rxe_luo_can_preserve(struct liveupdate_file_handler *handler,
				 struct file *file)
{
	pr_info("%s +%d \n", __func__, __FILE__, __LINE__);
#if 0
	struct eventfd_ctx *ctx;

	if (!file->f_op)
		return false;

	/* Try to get eventfd context - this will fail if not an eventfd */
	ctx = eventfd_ctx_fileget(file);
	if (IS_ERR(ctx))
		return false;

	eventfd_ctx_put(ctx);
#endif	
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

int __init rxe_luo_init(void)
{
	int err = liveupdate_register_file_handler(&rxe_luo_handler);

	if (err && err != -EOPNOTSUPP) {
		pr_err("Could not register eventfd LUO handler: %pe\n",
		       ERR_PTR(err));
		return err;
	}

	return 0;
}
late_initcall(rxe_luo_init);

void __exit rxe_luo_exit(void)
{
	liveupdate_unregister_file_handler(&rxe_luo_handler);
}
