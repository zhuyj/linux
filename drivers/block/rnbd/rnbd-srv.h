/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * RDMA Network Block Driver
 *
 * Copyright (c) 2014 - 2018 ProfitBricks GmbH. All rights reserved.
 * Copyright (c) 2018 - 2019 1&1 IONOS Cloud GmbH. All rights reserved.
 * Copyright (c) 2019 - 2020 1&1 IONOS SE. All rights reserved.
 */
#ifndef RNBD_SRV_H
#define RNBD_SRV_H

#include <linux/types.h>
#include <linux/idr.h>
#include <linux/kref.h>

#include <rtrs.h>
#include "rnbd-proto.h"
#include "rnbd-log.h"

struct rnbd_srv_session {
	/* Entry inside global sess_list */
	struct list_head        list;
	struct rtrs_srv_sess	*rtrs;
	char			sessname[NAME_MAX];
	int			queue_depth;

	struct xarray		index_idr;
	struct mutex		lock;
	u8			ver;
};

struct rnbd_srv_dev {
	/* Entry inside global dev_list */
	struct list_head                list;
	struct kobject                  dev_kobj;
	struct kobject                  *dev_sessions_kobj;
	struct kref                     kref;
	char				id[NAME_MAX];
	/* List of rnbd_srv_sess_dev structs */
	struct list_head		sess_dev_list;
	struct mutex			lock;
	int				open_write_cnt;
	enum rnbd_io_mode		mode;
	struct file			*file;
	struct block_device		*bdev;
};

struct rnbd_dev {
	struct block_device	*bdev;
	struct bio_set		*ibd_bio_set;
	struct file		*file;
	fmode_t			blk_open_flags;
	enum rnbd_io_mode	mode;
	char			name[BDEVNAME_SIZE];
//	rnbd_dev_io_fn		*io_cb;  /* Handle this later */
};

/* Structure which binds N devices and N sessions */
struct rnbd_srv_sess_dev {
	/* Entry inside rnbd_srv_dev struct */
	struct list_head		dev_list;
	struct rnbd_dev			*rnbd_dev;
	struct file			*bdev_file;
	struct rnbd_srv_session		*sess;
	struct rnbd_srv_dev		*dev;
	struct kobject                  kobj;
	u32                             device_id;
	bool				keep_id;
	bool				readonly;
	struct kref			kref;
	struct completion               *destroy_comp;
	char				pathname[NAME_MAX];
	enum rnbd_io_mode		mode;
	enum rnbd_access_mode		access_mode;
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

void rnbd_srv_sess_dev_force_close(struct rnbd_srv_sess_dev *sess_dev,
				   struct kobj_attribute *attr);
/* rnbd-srv-sysfs.c */

int rnbd_srv_create_dev_sysfs(struct rnbd_srv_dev *dev,
			      struct block_device *bdev);
void rnbd_srv_destroy_dev_sysfs(struct rnbd_srv_dev *dev);
int rnbd_srv_create_dev_session_sysfs(struct rnbd_srv_sess_dev *sess_dev);
void rnbd_srv_destroy_dev_session_sysfs(struct rnbd_srv_sess_dev *sess_dev);
int rnbd_srv_create_sysfs_files(void);
void rnbd_srv_destroy_sysfs_files(void);
void rnbd_destroy_sess_dev(struct rnbd_srv_sess_dev *sess_dev, bool keep_id);

static inline int rnbd_dev_get_logical_bsize(const struct rnbd_dev *dev)
{
	return bdev_logical_block_size(dev->bdev);
}

static inline int rnbd_dev_get_phys_bsize(const struct rnbd_dev *dev)
{
	return bdev_physical_block_size(dev->bdev);
}

static inline int rnbd_dev_get_max_segs(const struct rnbd_dev *dev)
{
	return queue_max_segments(bdev_get_queue(dev->bdev));
}

static inline int rnbd_dev_get_max_hw_sects(const struct rnbd_dev *dev)
{
	return queue_max_hw_sectors(bdev_get_queue(dev->bdev));
}

static inline int rnbd_dev_get_max_discard_sects(const struct rnbd_dev *dev)
{
#if 0
	if (!blk_queue_discard(bdev_get_queue(dev->bdev)))
		return 0;

	if (dev->mode == RNBD_BLOCKIO)
		return blk_queue_get_max_sectors(bdev_get_queue(dev->bdev),
						 REQ_OP_DISCARD);
#endif
	return 0;
}

static inline int rnbd_dev_get_discard_granularity(const struct rnbd_dev *dev)
{
	if (dev->mode == RNBD_BLOCKIO)
		return bdev_get_queue(dev->bdev)->limits.discard_granularity;
	return 0;
}

static inline int rnbd_dev_get_discard_alignment(const struct rnbd_dev *dev)
{
	if (dev->mode == RNBD_BLOCKIO)
		return bdev_get_queue(dev->bdev)->limits.discard_alignment;
	return 0;
}

static inline int rnbd_dev_get_secure_discard(const struct rnbd_dev *dev)
{
#if 0
	if (dev->mode == RNBD_BLOCKIO)
		return blk_queue_secure_erase(bdev_get_queue(dev->bdev));
#endif
	return 0;
}

#endif /* RNBD_SRV_H */
