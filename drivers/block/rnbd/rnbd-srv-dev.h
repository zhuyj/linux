/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * RDMA Network Block Driver
 *
 * Copyright (c) 2014 - 2018 ProfitBricks GmbH. All rights reserved.
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Copyright (c) 2019 - 2025 1&1 IONOS SE. All rights reserved.
 */

#ifndef RNBD_SRV_DEV_H
#define RNBD_SRV_DEV_H

#include "rnbd-proto.h"

typedef void rnbd_dev_io_fn(void *priv, int error);

struct rnbd_dev {
	struct file		*bdev_file;
	struct file		*file;
	fmode_t			blk_open_flags;
	enum rnbd_io_mode	io_mode;
	rnbd_dev_io_fn		*io_cb;
};

struct rnbd_dev_file_io_work {
	struct rnbd_dev		*dev;
	void			*priv;

	sector_t		sector;
	void			*data;
	size_t			len;
	size_t			bi_size;
	enum rnbd_io_flags	flags;

	struct work_struct	work;
};

struct ibnbd_io_private {
	struct rtrs_srv_op		*id;
	struct rnbd_srv_sess_dev	*sess_dev;
};

#define RNBD_CLT_BS	512

static inline int rnbd_dev_get_logical_bsize(const struct rnbd_dev *dev)
{
	int bsize = bdev_logical_block_size(file_bdev(dev->bdev_file));

	if (bsize != RNBD_CLT_BS)
		return RNBD_CLT_BS;
	return bsize;
}

void rnbd_dev_close(struct rnbd_dev *dev);

struct rnbd_dev *rnbd_dev_open(const char *path, fmode_t flags,
				enum rnbd_io_mode mode, rnbd_dev_io_fn io_cb);
int rnbd_dev_file_submit_io(struct rnbd_dev *dev, sector_t sector,
			    void *data, size_t len, size_t bi_size,
			    enum rnbd_io_flags flags, void *priv);

int rnbd_dev_init(void);
void rnbd_dev_destroy(void);

void rnbd_set_io_mode_bs(u8 *msg_io_mode, enum rnbd_io_mode io_mode,
			 u32 requested_bs);
void rnbd_get_io_mode_bs(u8 msg_io_mode, enum rnbd_io_mode *io_mode,
			 u32 *requested_bs);

int rnbd_handle_io_mode(u8 io_mode_bs, int def_io_mode, char *path,
			enum rnbd_io_mode *io_mode);

int rnbd_get_block_size(const struct rnbd_msg_open *msg, char *path,
			enum rnbd_io_mode *io_mode);
void rnbd_io_mode_set_msg(const struct rnbd_msg_open *open_msg, enum rnbd_io_mode *io_mode,
		      int def_io_mode);
#endif /* RNBD_SRV_DEV_H */
