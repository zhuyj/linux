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
#include <linux/dma-buf.h>
#include <linux/vfio_pci_core.h>
#include <linux/dma-resv.h>

#include "dmabuf_liveupdate.h"

static bool dmabuf_liveupdate_can_preserve(struct liveupdate_file_handler *handler,
                                           struct file *file)
{
	struct dma_buf *dmabuf;
	struct device *dev;

	if (!file || !is_dma_buf_file(file))
		return false;

	dmabuf = file->private_data;
	if (!dmabuf)
		return false;

	/* Retrieve device via exporter's private data */
	if (dmabuf->priv) {
		/*
		 * Replace 'struct vfio_pci_core_device' with your exporter's private structure type.
		 * Alternatively, if dmabuf->priv points directly to struct device:
		 * dev = dmabuf->priv;
		 */
		struct vfio_pci_core_device *vdev = dmabuf->priv;
		dev = &vdev->pdev->dev; /* or &vdev->pdev->dev */
	} else {
		return false;
	}

	/* 1. PCI Core Check */
	if (dev_is_pci(dev)) {
		struct pci_dev *pdev = to_pci_dev(dev);
		if (pdev->current_state != PCI_D0 || pci_channel_offline(pdev))
			return false;
	}

	/* 2. VFIO / IOMMU Check wait for the interface */
//	if (iommu_liveupdate_has_pending_faults(dev))
//		return false;

	/* wait for the interface */
//	if (!vfio_liveupdate_can_preserve_file(file))
//		return false;

	return true;
}

static int dmabuf_prepare_live_update(struct dma_buf *dmabuf,
                               bool (*is_preserved_dev)(struct device *dev));

static int dmabuf_liveupdate_preserve(struct liveupdate_file_op_args *args)
{
	int ret;

	ret = dmabuf_prepare_live_update(NULL, NULL);
	if (ret)
		return ret;

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

/**
 * my_dmabuf_prepare_live_update - Prepare for Live Update: wait for Fence signals and suspend writes
 * @dmabuf: Pointer to the target dma-buf
 * @is_preserved_dev: Function pointer to determine if an accessing device is a preserved device during Live Update
 */
static int dmabuf_prepare_live_update(struct dma_buf *dmabuf,
			       bool (*is_preserved_dev)(struct device *dev))
{
	struct dma_resv *resv = dmabuf->resv;
	struct dma_resv_iter cursor;
	struct dma_fence *fence;
	long timeout;

	if (!dmabuf || !resv)
		return -EINVAL;

	/* =========================================================================
	 * 1) Clear Pending Fences: Wait for all pending dma_fences to transition to Signaled state
	 * ========================================================================= */

	/* Lock the dma_resv object */
	dma_resv_lock(resv, NULL);

	/* Iterate through all fences in dma_resv (including both READ and WRITE fences) */
	dma_resv_iter_begin(&cursor, resv, DMA_RESV_USAGE_BOOKKEEP);
	dma_resv_for_each_fence_unlocked(&cursor, fence) {
		if (!fence)
			continue;

		/* Check if the fence is already signaled; wait if it is still pending */
		if (!dma_fence_is_signaled(fence)) {
			/* Set wait timeout (e.g., 5000ms) and wait for the task to complete */
			timeout = dma_fence_wait_timeout(fence, true, msecs_to_jiffies(5000));
			if (timeout <= 0) {
				pr_err("LiveUpdate: Fence wait timeout/interrupted! fence_id=%llu\n",
				       fence->seqno);
				dma_resv_iter_end(&cursor);
				dma_resv_unlock(resv);
				return (timeout == 0) ? -ETIMEDOUT : timeout;
			}
		}
	}
	dma_resv_iter_end(&cursor);

	dma_resv_unlock(resv);

	/* =========================================================================
	 * 2) Suspend Writes from Non-Preserved Devices: Pause write operations from non-preserved devices
	 * ========================================================================= */

	/*
	 * Step A: Stop DMA write operations on non-preserved hardware devices (driver-specific logic).
	 * Notify non-preserved hardware drivers to stop their DMA command queues here.
	 */
	/* stop_non_preserved_dma_hardware(dmabuf); */

	/*
	 * Step B: Set/check flag bits in custom dma_buf_ops to reject subsequent write requests.
	 */
	/* Set global or private live update suspension flag */
	// dmabuf_priv->is_suspended = true;

	pr_info("LiveUpdate: dma-buf (id/ptr=%p) fences cleared and writes suspended successfully.\n", dmabuf);

	return 0;
}

/**
 * CPU/Device access interception in driver's dma_buf_ops
 */
static int dmabuf_liveupdate_begin_cpu_access(struct dma_buf *dmabuf, enum dma_data_direction dir)
{
//	struct my_buffer_priv *priv = dmabuf->priv;

	/* Reject access if live update preparation is ongoing and the request involves write access */
//	if (priv->is_live_update_preparing && (dir == DMA_TO_DEVICE || dir == DMA_BIDIRECTIONAL)) {
//		pr_warn("LiveUpdate: Rejecting write access during live update preparation!\n");
//		return -EBUSY; /* Return -EBUSY to suspend write requests */
//	}

	/* Normal CPU access handling logic... */
	return 0;
}

static const struct dma_buf_ops dmabuf_liveupdate_ops = {
	.begin_cpu_access = dmabuf_liveupdate_begin_cpu_access,
	.attach = NULL,
	.detach = NULL,
	.map_dma_buf = NULL,
	.unmap_dma_buf = NULL,
	.end_cpu_access = NULL,
	.mmap = NULL,
	.vmap = NULL,
	.vunmap = NULL,
	.release = NULL,
};
