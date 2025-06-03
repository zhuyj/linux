// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RDMA Network Block Driver
 *
 * Copyright (c) 2014 - 2018 ProfitBricks GmbH. All rights reserved.
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Copyright (c) 2019 - 2025 1&1 IONOS SE. All rights reserved.
 */
#include "rnbd-srv-dev.h"

static struct workqueue_struct *fileio_wq;
#define RNBD_DEV_MAX_FILEIO_ACTIVE_WORKERS	0

int rnbd_dev_init(void)
{
	fileio_wq = alloc_workqueue("%s", WQ_UNBOUND | WQ_HIGHPRI | WQ_MEM_RECLAIM,
				    RNBD_DEV_MAX_FILEIO_ACTIVE_WORKERS,
				    "rnbd_server_fileio_wq");
	if (!fileio_wq) {
		pr_warn("func: %s, fileio_wq NULL\n", __func__);
		return -ENOMEM;
	}

	return 0;
}

void rnbd_dev_destroy(void)
{
	destroy_workqueue(fileio_wq);
}

static int rnbd_dev_vfs_open(struct rnbd_dev *dev, const char *path, fmode_t flags)
{
	int oflags = O_DSYNC; /* enable write-through */

	if (flags & FMODE_WRITE)
		oflags |= O_RDWR;
	else if (flags & FMODE_READ)
		oflags |= O_RDONLY;
	else
		return -EINVAL;

	dev->file = filp_open(path, oflags, 0);
	return PTR_ERR_OR_ZERO(dev->file);
}

void rnbd_dev_close(struct rnbd_dev *dev)
{
	fput(dev->bdev_file);
	if (dev->io_mode == RNBD_FILEIO) {
		flush_workqueue(fileio_wq);
		if (dev->file)
			filp_close(dev->file, dev->file);
	}
	kfree(dev);
}

struct rnbd_dev *rnbd_dev_open(const char *path, fmode_t flags,
				enum rnbd_io_mode mode, rnbd_dev_io_fn io_cb)
{
	struct rnbd_dev *dev;
	int ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	if (mode == RNBD_FILEIO) {
		dev->bdev_file = bdev_file_open_by_path(path, FMODE_READ, THIS_MODULE, NULL);
		if (IS_ERR(dev->bdev_file)) {
			pr_err("bdev error, error: %pe", dev->bdev_file);
			goto err;
		}

		ret = rnbd_dev_vfs_open(dev, path, flags);
		if (ret)
			goto blk_put;

		dev->io_cb	= io_cb;
	} else if (mode == RNBD_BLOCKIO) {
		dev->bdev_file = bdev_file_open_by_path(path, flags, THIS_MODULE, NULL);
		if (IS_ERR(dev->bdev_file)) {
			ret = PTR_ERR(dev->bdev_file);
			pr_err("Opening device '%s' failed, err: %pe\n",
				path, dev->bdev_file);
			goto err;
		}
	}

	dev->blk_open_flags	= flags;
	dev->io_mode		= mode;

	return dev;

blk_put:
	fput(dev->bdev_file);
err:
	kfree(dev);
	return ERR_PTR(ret);
}

static int rnbd_dev_file_handle_flush(struct rnbd_dev_file_io_work *w,
				       loff_t start)
{
	int ret;
	loff_t end;
	int len = w->bi_size;

	if (len)
		end = start + len - 1;
	else
		end = LLONG_MAX;

	ret = vfs_fsync_range(w->dev->file, start, end, 1);
	if (unlikely(ret))
		pr_info_ratelimited("I/O FLUSH failed on %pg, vfs_sync err: %d\n",
				    file_bdev(w->dev->bdev_file), ret);
	return ret;
}

static int rnbd_dev_file_handle_fua(struct rnbd_dev_file_io_work *w,
				    loff_t start)
{
	int ret;
	loff_t end;
	int len = w->bi_size;

	if (len)
		end = start + len - 1;
	else
		end = LLONG_MAX;

	ret = vfs_fsync_range(w->dev->file, start, end, 1);
	if (unlikely(ret))
		pr_info_ratelimited("I/O FUA failed on %pg, vfs_sync err: %d\n",
				    file_bdev(w->dev->bdev_file), ret);
	return ret;
}

static void rnbd_dev_file_submit_io_worker(struct work_struct *w)
{
	struct rnbd_dev_file_io_work *dev_work;
	struct file *f;
	loff_t off;
	int ret;

	dev_work = container_of(w, struct rnbd_dev_file_io_work, work);
	off = dev_work->sector * rnbd_dev_get_logical_bsize(dev_work->dev);
	f = dev_work->dev->file;

	if (rnbd_op(dev_work->flags) == RNBD_OP_FLUSH) {
		ret = rnbd_dev_file_handle_flush(dev_work, off);
		if (unlikely(ret))
			goto out;
	}

	/* TODO Implement support for DIRECT */
	if (dev_work->bi_size) {
		loff_t off_tmp = off;

		if (rnbd_op(dev_work->flags) == RNBD_OP_WRITE)
			ret = kernel_write(f, dev_work->data, dev_work->bi_size,
					   &off_tmp);
		else
			ret = kernel_read(f, dev_work->data, dev_work->bi_size,
					  &off_tmp);

		if (unlikely(ret < 0)) {
			goto out;
		} else if (unlikely(ret != dev_work->bi_size)) {
			/* TODO implement support for partial completions */
			if (ret < dev_work->bi_size) {
				/* When ret < dev_work->bi_size, it indicates that
				 * the file pointer reaches the end of the opened file.
				 * It is not an error. Set the len to the actually
				 * read/write bytes.
				 */
				pr_warn_ratelimited("partial completions ret: %d, bi_size: %zu\n",
						ret, dev_work->bi_size);
				dev_work->len = ret;
			} else {
				ret = -EIO;
				filp_close(dev_work->dev->file, dev_work->dev->file);
				dev_work->dev->file = NULL;
				goto out;
			}
		} else {
			ret = 0;
		}
	}

	if (dev_work->flags & RNBD_F_FUA)
		ret = rnbd_dev_file_handle_fua(dev_work, off);
out:
	dev_work->dev->io_cb(dev_work->priv, ret);
	kfree(dev_work);
}

int rnbd_dev_file_submit_io(struct rnbd_dev *dev, sector_t sector,
				    void *data, size_t len, size_t bi_size,
				    enum rnbd_io_flags flags, void *priv)
{
	struct rnbd_dev_file_io_work *w;

	if (!rnbd_flags_supported(flags)) {
		pr_info_ratelimited("Unsupported I/O flags: 0x%x on device %pg\n",
				    flags, file_bdev(dev->bdev_file));
		return -ENOTSUPP;
	}

	w = kzalloc(sizeof(*w), GFP_KERNEL);
	if (!w)
		return -ENOMEM;

	w->dev		= dev;
	w->priv		= priv;
	w->sector	= sector;
	w->data		= data;
	w->len		= len;
	w->bi_size	= bi_size;
	w->flags	= flags;
	INIT_WORK(&w->work, rnbd_dev_file_submit_io_worker);

	if (unlikely(!queue_work(fileio_wq, &w->work))) {
		kfree(w);
		return -EEXIST;
	}

	return 0;
}

/* In this function, if reqest block size is different from the actual block size,
 * the io_mode should be fileio.
 */
int rnbd_get_block_size(const struct rnbd_msg_open *msg, char *path,
			enum rnbd_io_mode *io_mode)
{
	struct file *bdev_file;
	unsigned int logical_bs, physical_bs;

	bdev_file = bdev_file_open_by_path(path, FMODE_READ, THIS_MODULE, NULL);
	if (IS_ERR(bdev_file)) {
		pr_err("bdev error, error: %pe", bdev_file);
		return PTR_ERR(bdev_file);
	}

	logical_bs	= bdev_logical_block_size(file_bdev(bdev_file));
	physical_bs	= bdev_physical_block_size(file_bdev(bdev_file));

	pr_warn("%s +%d logical bs: %u, physical bs: %u, designate_bs: %u\n",
		__FILE__, __LINE__, logical_bs, physical_bs, msg->designate_bs);
	fput(bdev_file);

	return 0;
}

static int rnbd_get_actual_block_size(char *path)
{
	unsigned int logical_bs;
	struct file *bdev_file;

	bdev_file = bdev_file_open_by_path(path, FMODE_READ, THIS_MODULE, NULL);
	if (IS_ERR(bdev_file)) {
		pr_err("bdev error, error: %pe", file_bdev(bdev_file));
		return PTR_ERR(bdev_file);
	}

	logical_bs = bdev_logical_block_size(file_bdev(bdev_file));

	fput(bdev_file);

	/* logical_bs should be: 512, 1024, 2048 and 4096.
	 * Use int is enough
	 */
	return (int)logical_bs;
}

/* In this function, if request block size is less than the actual block size,
 * the io_mode should be fileio.
 */
static int rnbd_decision_io_mode_bs(u8 io_mode_bs, char *path, enum rnbd_io_mode *io_mode)
{
	int requested_bs;
	int logical_bs;

	/* 1. If not set block size, return.
	 *
	 * For example, the following command will use fileio.
	 * echo "sessname=bla path=ip:x.x.x.x io_mode=fileio device_path=/dev/nullb0" >
	 * /sys/devices/virtual/rnbd-client/ctl/map_device
	 */
	if (rnbd_check_bs_not_set(io_mode_bs))
		return 0;

	requested_bs = rnbd_get_bs(io_mode_bs);

	logical_bs = rnbd_get_actual_block_size(path);
	if (logical_bs < 0)
		return logical_bs;

	pr_info("func: %s: logical bs: %d, requested_bs: %d\n", __func__,
		logical_bs, requested_bs);

	/* 2. If requested block_size < actual logical block size, use fileio io mode.
	 *
	 * For example, the following command will use fileio if the actual block size if 4096.
	 * echo "sessname=bla path=ip:x.x.x.x requested_bs=512 device_path=/dev/nullb0" >
	 * /sys/devices/virtual/rnbd-client/ctl/map_device
	 */
	if (requested_bs < logical_bs) {
		*io_mode = RNBD_FILEIO;
		return 0;
	}

	/* 3. If block_size == actual logical block size, use the io mode requested by clt.
	 * If io mode is not set by client, use blockio.
	 * The examples to the above are as below.
	 */
	if (requested_bs == logical_bs) {
		/* If io_mode is fileio, use fileio.
		 *
		 * For example, the following command will use fileio as io_mode if actual
		 * block size is 512.
		 * echo "sessname=bla path=ip:x.x.x.x io_mode=fileio requested_bs=512
		 *  device_path=/dev/nullb0" > /sys/devices/virtual/rnbd-client/ctl/map_device
		 */
		if (*io_mode == RNBD_FILEIO)
			return 0;

		/* If io_mode not set, use blockio.
		 *
		 * For example, the following command will use blockio as io_mode if actual
		 * block size is 512.
		 * echo "sessname=bla path=ip:x.x.x.x requested_bs=512 device_path=/dev/nullb0" >
		 * /sys/devices/virtual/rnbd-client/ctl/map_device
		 *
		 * If io_mode is blockio, return.
		 *
		 * For example, the following command will use blockio as io_mode if actual
		 * block size is 512.
		 * echo "sessname=bla path=ip:x.x.x.x io_mode=blockio requested_bs=512
		 *  device_path=/dev/nullb0" > /sys/devices/virtual/rnbd-client/ctl/map_device
		 */
		*io_mode = RNBD_BLOCKIO;
		return 0;
	}

	/* 4. default settings:
	 * - if desired logical-block-size not set then: desired = actual.
	 * - if file-IO was not explicitly asked for then: IO-mode = block-IO.
	 *
	 * with the above:
	 * - if desired >= actual and IO-mode == block-IO: use block-IO
	 * - else use file-IO
	 * The examples are as below.
	 */
	if (requested_bs > logical_bs) {
		/* If requested block size > actual block size in srv, and io_mode = blockio,
		 * use blockio.
		 *
		 * For example, the following command will use blockio as io_mode if actual
		 * block size is 512.
		 * echo "sessname=bla path=ip:x.x.x.x io_mode=blockio requested_bs=4096
		 *  device_path=/dev/nullb0" > /sys/devices/virtual/rnbd-client/ctl/map_device
		 */
		if (*io_mode == RNBD_BLOCKIO)
			return 0;

		/* If requested block size > actual block size in srv, and io_mode not set or
		 * io_mode set to fileio, use fileio.
		 *
		 * 1). io_mode not set
		 *
		 * For example, the following command will use fileio as io_mode if actual
		 * block size is 512.
		 * echo "sessname=bla path=ip:x.x.x.x requested_bs=4096 device_path=/dev/nullb0" >
		 * /sys/devices/virtual/rnbd-client/ctl/map_device
		 *
		 * 2). io_mode set to fileio
		 *
		 * For example, the following command will use fileio as io_mode if actual
		 * block size is 512.
		 * echo "sessname=bla path=ip:x.x.x.x io_mode=fileio requested_bs=4096
		 * device_path=/dev/nullb0" > /sys/devices/virtual/rnbd-client/ctl/map_device
		 */
		*io_mode = RNBD_FILEIO;
		return 0;
	}

	return 0;
}

static void rnbd_io_mode_set(u8 io_mode_bs, enum rnbd_io_mode *io_mode, int def_io_mode)
{
	if ((io_mode_bs & MASK_FOR_IO_MODE) == IO_MODE_BLOCKIO)
		/* 6. if blockio is set explicitly, block size is not set,
		 * use blockio.
		 *
		 * For example, the following command will use blockio.
		 * echo "sessname=bla path=ip:x.x.x.x io_mode=blockio device_path=/dev/nullb0" >
		 * /sys/devices/virtual/rnbd-client/ctl/map_device
		 */
		*io_mode = RNBD_BLOCKIO;
	else if ((io_mode_bs & MASK_FOR_IO_MODE) == IO_MODE_FILEIO)
		/* 5. if fileio is set explicitly, block size is not set,
		 * use fileio.
		 *
		 * For example, the following command will use fileio.
		 * echo "sessname=bla path=ip:x.x.x.x io_mode=fileio device_path=/dev/nullb0" >
		 * /sys/devices/virtual/rnbd-client/ctl/map_device
		 */
		*io_mode = RNBD_FILEIO;
	else
		*io_mode = def_io_mode;
}

int rnbd_handle_io_mode(u8 io_mode_bs, int def_io_mode, char *path, enum rnbd_io_mode *io_mode)
{
	int ret;

	/* 0. if io_mode and block size are not set, use blockio.
	 *
	 * For example, the following command will use blockio as io_mode.
	 * echo "sessname=bla path=ip:x.x.x.x device_path=/dev/nullb0" >
	 * /sys/devices/virtual/rnbd-client/ctl/map_device
	 */
	if (rnbd_check_set_io_mode_bs(io_mode_bs)) {
		/* Based on msg io_mode part, set io_mode */
		rnbd_io_mode_set(io_mode_bs, io_mode, def_io_mode);

		/* Based on actual and desired block size, decide io mode */
		ret = rnbd_decision_io_mode_bs(io_mode_bs, path, io_mode);
		if (ret)
			return ret; /* No resource is allocated */
	} else {
		*io_mode = def_io_mode;
	}

	return 0;
}

void rnbd_io_mode_set_msg(const struct rnbd_msg_open *open_msg, enum rnbd_io_mode *io_mode,
			int def_io_mode)
{
	if (open_msg->io_mode == RNBD_BLOCKIO)
		*io_mode = RNBD_BLOCKIO;
	else if (open_msg->io_mode == RNBD_FILEIO)
		*io_mode = RNBD_FILEIO;
	else
		*io_mode = def_io_mode;
}
