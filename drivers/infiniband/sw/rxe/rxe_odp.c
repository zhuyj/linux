// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

#include <rdma/ib_umem.h>
#include <rdma/ib_umem_odp.h>
#include <linux/kernel.h>
#include <linux/dma-buf.h>
#include <linux/dma-resv.h>

#include "rxe.h"

static bool rxe_ib_invalidate_range(struct mmu_interval_notifier *mni,
                                     const struct mmu_notifier_range *range,
                                     unsigned long cur_seq)
{
        struct ib_umem_odp *umem_odp =
                container_of(mni, struct ib_umem_odp, notifier);
//        struct mlx5_ib_mr *mr;
//        const u64 umr_block_mask = (MLX5_UMR_MTT_ALIGNMENT /
//                                    sizeof(struct mlx5_mtt)) - 1;
	struct rxe_mr *mr;
        u64 idx = 0, blk_start_idx = 0;
        u64 invalidations = 0;
        unsigned long start = 0;
        unsigned long end = 0;
        int in_block = 0;
        u64 addr = 0;

        if (!mmu_notifier_range_blockable(range))
                return false;
	pr_info("file: %s +%d, npages:%d, caller:%pS\n", __FILE__, __LINE__, umem_odp->npages, __builtin_return_address(0));
#if 0

        mutex_lock(&umem_odp->umem_mutex);
        mmu_interval_set_seq(mni, cur_seq);
        /*
         * If npages is zero then umem_odp->private may not be setup yet. This
         * does not complete until after the first page is mapped for DMA.
         */
        if (!umem_odp->npages)
                goto out;
        mr = umem_odp->private;

        start = max_t(u64, ib_umem_start(umem_odp), range->start);
        end = min_t(u64, ib_umem_end(umem_odp), range->end);

        /*
         * Iteration one - zap the HW's MTTs. The notifiers_count ensures that
         * while we are doing the invalidation, no page fault will attempt to
         * overwrite the same MTTs.  Concurent invalidations might race us,
         * but they will write 0s as well, so no difference in the end result.
         */
        for (addr = start; addr < end; addr += BIT(umem_odp->page_shift)) {
                idx = (addr - ib_umem_start(umem_odp)) >> umem_odp->page_shift;
                /*
                 * Strive to write the MTTs in chunks, but avoid overwriting
                 * non-existing MTTs. The huristic here can be improved to
                 * estimate the cost of another UMR vs. the cost of bigger
                 * UMR.
                 */
                if (umem_odp->dma_list[idx] &
                    (ODP_READ_ALLOWED_BIT | ODP_WRITE_ALLOWED_BIT)) {
                        if (!in_block) {
                                blk_start_idx = idx;
                                in_block = 1;
                        }

                        /* Count page invalidations */
                        invalidations += idx - blk_start_idx + 1;
                } else {
                        u64 umr_offset = idx & umr_block_mask;

                        if (in_block && umr_offset == 0) {
                                mlx5_ib_update_xlt(mr, blk_start_idx,
                                                   idx - blk_start_idx, 0,
                                                   MLX5_IB_UPD_XLT_ZAP |
                                                   MLX5_IB_UPD_XLT_ATOMIC);
                                in_block = 0;
                        }
                }
        }
        if (in_block)
                mlx5_ib_update_xlt(mr, blk_start_idx,
                                   idx - blk_start_idx + 1, 0,
                                   MLX5_IB_UPD_XLT_ZAP |
                                   MLX5_IB_UPD_XLT_ATOMIC);

        mlx5_update_odp_stats(mr, invalidations, invalidations);

        /*
         * We are now sure that the device will not access the
         * memory. We can safely unmap it, and mark it as dirty if
         * needed.
         */

        ib_umem_odp_unmap_dma_pages(umem_odp, start, end);

        if (unlikely(!umem_odp->npages && mr->parent))
                destroy_unused_implicit_child_mr(mr);
out:
        mutex_unlock(&umem_odp->umem_mutex);
#endif
	pr_info("file: %s +%d, caller:%pS\n", __FILE__, __LINE__, __builtin_return_address(0));
        return true;
}

const struct mmu_interval_notifier_ops rxe_mn_ops = {
        .invalidate = rxe_ib_invalidate_range,
};

void rxe_internal_fill_odp_caps(struct rxe_dev *dev)
{
	struct ib_odp_caps *caps = &dev->attr.odp_caps;

	memset(caps, 0, sizeof(*caps));
	caps->general_caps = IB_ODP_SUPPORT;

	caps->per_transport_caps.ud_odp_caps |= IB_ODP_SUPPORT_SEND;
	caps->per_transport_caps.ud_odp_caps |= IB_ODP_SUPPORT_SRQ_RECV;
	caps->per_transport_caps.rc_odp_caps |= IB_ODP_SUPPORT_SEND;
	caps->per_transport_caps.rc_odp_caps |= IB_ODP_SUPPORT_RECV;
	caps->per_transport_caps.rc_odp_caps |= IB_ODP_SUPPORT_WRITE;
	caps->per_transport_caps.rc_odp_caps |= IB_ODP_SUPPORT_READ;
	caps->per_transport_caps.rc_odp_caps |= IB_ODP_SUPPORT_ATOMIC;
	caps->per_transport_caps.rc_odp_caps |= IB_ODP_SUPPORT_SRQ_RECV;
}
