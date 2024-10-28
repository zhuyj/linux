// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2022-2023 Fujitsu Ltd. All rights reserved.
 */

#include <linux/hmm.h>

#include <rdma/ib_umem_odp.h>

#include "rxe.h"

#define RXE_ODP_WRITABLE_BIT    1UL

static void rxe_mr_unset_xarray(struct rxe_mr *mr, unsigned long start,
				unsigned long end)
{
	unsigned long upper = rxe_mr_iova_to_index(mr, end - 1);
	unsigned long lower = rxe_mr_iova_to_index(mr, start);
	void *entry;

	XA_STATE(xas, &mr->page_list, lower);

	/* make elements in xarray NULL */
	xas_lock(&xas);
	xas_for_each(&xas, entry, upper)
		xas_store(&xas, NULL);
	xas_unlock(&xas);
}

static void rxe_mr_set_xarray(struct rxe_mr *mr, unsigned long start,
			      unsigned long end, unsigned long *pfn_list)
{
	unsigned long upper = rxe_mr_iova_to_index(mr, end - 1);
	unsigned long lower = rxe_mr_iova_to_index(mr, start);
	void *page, *entry;

	XA_STATE(xas, &mr->page_list, lower);

	xas_lock(&xas);
	while (xas.xa_index <= upper) {
		if (pfn_list[xas.xa_index] & HMM_PFN_WRITE) {
			page = xa_tag_pointer(hmm_pfn_to_page(pfn_list[xas.xa_index]),
					      RXE_ODP_WRITABLE_BIT);
		} else
			page = hmm_pfn_to_page(pfn_list[xas.xa_index]);

		xas_store(&xas, page);
		entry = xas_next(&xas);
	}
	xas_unlock(&xas);
}

static bool rxe_ib_invalidate_range(struct mmu_interval_notifier *mni,
				    const struct mmu_notifier_range *range,
				    unsigned long cur_seq)
{
	struct ib_umem_odp *umem_odp =
		container_of(mni, struct ib_umem_odp, notifier);
	struct rxe_mr *mr = umem_odp->private;
	unsigned long start, end;

	if (!mmu_notifier_range_blockable(range))
		return false;

	mutex_lock(&umem_odp->umem_mutex);
	mmu_interval_set_seq(mni, cur_seq);

	start = max_t(u64, ib_umem_start(umem_odp), range->start);
	end = min_t(u64, ib_umem_end(umem_odp), range->end);

	rxe_mr_unset_xarray(mr, start, end);

	/* update umem_odp->dma_list */
	ib_umem_odp_unmap_dma_pages(umem_odp, start, end);

	mutex_unlock(&umem_odp->umem_mutex);
	return true;
}

const struct mmu_interval_notifier_ops rxe_mn_ops = {
	.invalidate = rxe_ib_invalidate_range,
};

#define RXE_PAGEFAULT_RDONLY BIT(1)
#define RXE_PAGEFAULT_SNAPSHOT BIT(2)
static int rxe_odp_do_pagefault_and_lock(struct rxe_mr *mr, u64 user_va, int bcnt, u32 flags)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	bool fault = !(flags & RXE_PAGEFAULT_SNAPSHOT);
	u64 access_mask;
	int np;

	access_mask = ODP_READ_ALLOWED_BIT;
	if (umem_odp->umem.writable && !(flags & RXE_PAGEFAULT_RDONLY))
		access_mask |= ODP_WRITE_ALLOWED_BIT;

	/*
	 * ib_umem_odp_map_dma_and_lock() locks umem_mutex on success.
	 * Callers must release the lock later to let invalidation handler
	 * do its work again.
	 */
	np = ib_umem_odp_map_dma_and_lock(umem_odp, user_va, bcnt,
					  access_mask, fault);
	if (np < 0)
		return np;

	/*
	 * umem_mutex is still locked here, so we can use hmm_pfn_to_page()
	 * safely to fetch pages in the range.
	 */
	rxe_mr_set_xarray(mr, user_va, user_va + bcnt, umem_odp->pfn_list);

	return np;
}

static int rxe_odp_init_pages(struct rxe_mr *mr)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	int ret;

	ret = rxe_odp_do_pagefault_and_lock(mr, mr->umem->address,
					    mr->umem->length,
					    RXE_PAGEFAULT_SNAPSHOT);

	if (ret >= 0)
		mutex_unlock(&umem_odp->umem_mutex);

	return ret >= 0 ? 0 : ret;
}

int rxe_odp_mr_init_user(struct rxe_dev *rxe, u64 start, u64 length,
			 u64 iova, int access_flags, struct rxe_mr *mr)
{
	struct ib_umem_odp *umem_odp;
	int err;

	if (!IS_ENABLED(CONFIG_INFINIBAND_ON_DEMAND_PAGING))
		return -EOPNOTSUPP;

	rxe_mr_init(access_flags, mr);

	xa_init(&mr->page_list);

	if (!start && length == U64_MAX) {
		if (iova != 0)
			return -EINVAL;
		if (!(rxe->attr.odp_caps.general_caps & IB_ODP_SUPPORT_IMPLICIT))
			return -EINVAL;

		/* Never reach here, for implicit ODP is not implemented. */
	}

	umem_odp = ib_umem_odp_get(&rxe->ib_dev, start, length, access_flags,
				   &rxe_mn_ops);
	if (IS_ERR(umem_odp)) {
		rxe_dbg_mr(mr, "Unable to create umem_odp err = %d\n",
			   (int)PTR_ERR(umem_odp));
		return PTR_ERR(umem_odp);
	}

	umem_odp->private = mr;

	mr->umem = &umem_odp->umem;
	mr->access = access_flags;
	mr->ibmr.length = length;
	mr->ibmr.iova = iova;
	mr->page_offset = ib_umem_offset(&umem_odp->umem);

	err = rxe_odp_init_pages(mr);
	if (err) {
		ib_umem_odp_release(umem_odp);
		return err;
	}

	mr->state = RXE_MR_STATE_VALID;
	mr->ibmr.type = IB_MR_TYPE_USER;

	return err;
}

/* Take xarray spinlock before entry */
static inline bool rxe_odp_check_pages(struct rxe_mr *mr, u64 iova,
				       int length, u32 flags)
{
	unsigned long upper = rxe_mr_iova_to_index(mr, iova + length - 1);
	unsigned long lower = rxe_mr_iova_to_index(mr, iova);
	bool need_fault = false;
	void *page, *entry;
	size_t perm = 0;

	if (!(flags & RXE_PAGEFAULT_RDONLY))
		perm = RXE_ODP_WRITABLE_BIT;

	XA_STATE(xas, &mr->page_list, lower);

	while (xas.xa_index <= upper) {
		page = xas_load(&xas);

		/* Check page presence and write permission */
		if (!page || (perm && !(xa_pointer_tag(page) & perm))) {
			need_fault = true;
			break;
		}
		entry = xas_next(&xas);
	}

	return need_fault;
}

int rxe_odp_mr_copy(struct rxe_mr *mr, u64 iova, void *addr, int length,
		    enum rxe_mr_copy_dir dir)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	u32 flags = 0;
	int err;

	if (unlikely(!mr->umem->is_odp))
		return -EOPNOTSUPP;

	switch (dir) {
	case RXE_TO_MR_OBJ:
		break;

	case RXE_FROM_MR_OBJ:
		flags = RXE_PAGEFAULT_RDONLY;
		break;

	default:
		return -EINVAL;
	}

	spin_lock(&mr->page_list.xa_lock);

	if (rxe_odp_check_pages(mr, iova, length, flags)) {
		spin_unlock(&mr->page_list.xa_lock);

		/* umem_mutex is locked on success */
		err = rxe_odp_do_pagefault_and_lock(mr, iova, length, flags);
		if (err < 0)
			return err;

		/* spinlock to prevent page invalidation */
		spin_lock(&mr->page_list.xa_lock);
		mutex_unlock(&umem_odp->umem_mutex);
	}

	err =  rxe_mr_copy_xarray(mr, iova, addr, length, dir);

	spin_unlock(&mr->page_list.xa_lock);

	return err;
}

int rxe_odp_mr_atomic_op(struct rxe_mr *mr, u64 iova, int opcode,
			 u64 compare, u64 swap_add, u64 *orig_val)
{
	struct ib_umem_odp *umem_odp = to_ib_umem_odp(mr->umem);
	int err;

	spin_lock(&mr->page_list.xa_lock);

	/* Atomic operations manipulate a single char. */
	if (rxe_odp_check_pages(mr, iova, sizeof(char), 0)) {
		spin_unlock(&mr->page_list.xa_lock);

		/* umem_mutex is locked on success */
		err = rxe_odp_do_pagefault_and_lock(mr, iova, sizeof(char), 0);
		if (err < 0)
			return err;

		/* spinlock to prevent page invalidation */
		spin_lock(&mr->page_list.xa_lock);
		mutex_unlock(&umem_odp->umem_mutex);
	}

	err = rxe_mr_do_atomic_op(mr, iova, opcode, compare,
				  swap_add, orig_val);

	spin_unlock(&mr->page_list.xa_lock);

	return err;
}
