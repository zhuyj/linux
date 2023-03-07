// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Intel Corporation */
#include "idpf.h"

#define VFIO_PCI_OFFSET_SHIFT   40
#define VFIO_PCI_OFFSET_TO_INDEX(off)   ((off) >> VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_INDEX_TO_OFFSET(index) ((u64)(index) << VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_OFFSET_MASK    (BIT_ULL(VFIO_PCI_OFFSET_SHIFT) - 1)

#ifdef ENABLE_ACC_PASID_WA

void *mdev_get_iommu_domain(struct device *dev);

static inline void *__mdev_get_iommu_domain(struct device *dev)
{
	void *(*fn)(struct device *dev);
	void *ret;

	fn = symbol_get(mdev_get_iommu_domain);
	if (fn) {
		ret = fn(dev);
		symbol_put(mdev_get_iommu_domain);

		return ret;
	}

	return NULL;
}
#endif /* ENABLE_ACC_PASID_WA */
/**
 * idpf_vdcm_vfio_device_get_info - get VFIO device info
 * @ivdm: pointer to VDCM
 * @arg: IOCTL command arguments
 *
 * Return 0 for success, negative for failure.
 */
static long
idpf_vdcm_vfio_device_get_info(struct idpf_vdcm *ivdm, unsigned long arg)
{
	struct vfio_device_info info;
	unsigned long minsz;

	minsz = offsetofend(struct vfio_device_info, num_irqs);

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz)
		return -EINVAL;

	info.flags = VFIO_DEVICE_FLAGS_PCI | VFIO_DEVICE_FLAGS_RESET;
	info.num_regions = VFIO_PCI_NUM_REGIONS;
	info.num_irqs = VFIO_PCI_NUM_IRQS;

	return copy_to_user((void __user *)arg, &info, minsz) ? -EFAULT : 0;
}

/**
 * idpf_vdcm_sparse_mmap_cap - prepare sparse memory for memory map
 * @caps: pointer to vfio region info capabilities
 * @adi: pointer to assignable device interface
 *
 * Return 0 if success, negative for failure.
 */
static int idpf_vdcm_sparse_mmap_cap(struct vfio_info_cap *caps,
				     struct idpf_adi *adi)
{
	struct vfio_region_info_cap_sparse_mmap *sparse;
	u32 nr_areas = 0;
	int ret = 0;
	size_t size;
	u32 i = 0;

	if (!caps)
		return -EINVAL;

	nr_areas = adi->get_sparse_mmap_num(adi);

	size = sizeof(*sparse) + (nr_areas * sizeof(*sparse->areas));

	sparse = kzalloc(size, GFP_KERNEL);
	if (!sparse)
		return -ENOMEM;

	sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
	sparse->header.version = 1;
	sparse->nr_areas = nr_areas;

	for (i = 0; i < nr_areas; i++) {
		ret = adi->get_sparse_mmap_area(adi, i,
						&sparse->areas[i].offset,
						&sparse->areas[i].size);
		if (ret < 0) {
			kfree(sparse);
			return ret;
		}
	}

	ret = vfio_info_add_capability(caps, &sparse->header, size);
	kfree(sparse);

	return ret;
}

/**
 * idpf_vdcm_mmap_open - open callback for VMA
 * @vma: pointer to VMA
 *
 * Zap mmaps on open so that we can fault them in on access and therefore
 * our vma_list only tracks mappings accessed since last zap.
 *
 * For the VMA created by QEMU/DPDK calling mmap() with vfio device fd, it is
 * not called. If necessary, driver should explicitly call this function in the
 * mmap() callback to do initialization.
 *
 * This callback is typically called after calling mmap() and later forking a
 * child process without VM_DONTCOPY vm_flags for multi-process situation.
 *
 * For QEMU/KVM, QEMU will set MADV_DONTFORK by madvise() when adding ram block,
 * this will mark this VMA with VM_DONTCOPY. So forking a child process in QEMU
 * will not trigger this callback. Refer to ram_add_block() for more details.
 *
 * For DPDK, MADV_DONTFORK is not set by default, so forking a child process
 * will trigger this callback.
 */
static void idpf_vdcm_mmap_open(struct vm_area_struct *vma)
{
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
}

/**
 * idpf_vdcm_mmap_close - close callback for VMA
 * @vma: pointer to VMA
 *
 * This function is typically called when the process is exiting and this VMA
 * has close callback registered.
 */
static void idpf_vdcm_mmap_close(struct vm_area_struct *vma)
{
	struct idpf_vdcm *ivdm = (struct idpf_vdcm *)vma->vm_private_data;
	struct idpf_vdcm_mmap_vma *mmap_vma;

	mutex_lock(&ivdm->vma_lock);
	list_for_each_entry(mmap_vma, &ivdm->vma_list, vma_next) {
		if (mmap_vma->vma == vma) {
			list_del(&mmap_vma->vma_next);
			kfree(mmap_vma);
			break;
		}
	}
	mutex_unlock(&ivdm->vma_lock);
}

/**
 * idpf_vdcm_mmap_fault - page fault callback for VMA
 * @vmf: pointer to vm fault context
 */
static vm_fault_t idpf_vdcm_mmap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct idpf_vdcm_mmap_vma *mmap_vma;
	struct idpf_vdcm *ivdm;
	unsigned int index;
	u64 addr, pg_off;
	int err;

	ivdm = (struct idpf_vdcm *)vma->vm_private_data;
	mutex_lock(&ivdm->vma_lock);

	mmap_vma = kzalloc(sizeof(*mmap_vma), GFP_KERNEL);
	if (!mmap_vma) {
		mutex_unlock(&ivdm->vma_lock);
		return VM_FAULT_OOM;
	}

	mmap_vma->vma = vma;
	list_add(&mmap_vma->vma_next, &ivdm->vma_list);

	mutex_unlock(&ivdm->vma_lock);

	index = vma->vm_pgoff >> (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);
	pg_off = vma->vm_pgoff &
		 ((1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	err = ivdm->adi->get_sparse_mmap_hpa(ivdm->adi, index, pg_off, &addr);
	if (err < 0) {
		dev_err(ivdm->dev,
			"failed to get HPA for memory map, err: %d.\n", err);
		return VM_FAULT_SIGBUS;
	}

	dev_dbg(ivdm->dev, "fault address GPA:0x%lx HPA:0x%llx HVA:0x%lx",
		vma->vm_pgoff << PAGE_SHIFT, addr, vma->vm_start);

	if (io_remap_pfn_range(vma, vma->vm_start, PHYS_PFN(addr),
			       vma->vm_end - vma->vm_start, vma->vm_page_prot))
		return VM_FAULT_SIGBUS;

	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct idpf_vdcm_mmap_ops = {
	.open = idpf_vdcm_mmap_open,
	.close = idpf_vdcm_mmap_close,
	.fault = idpf_vdcm_mmap_fault,
};

/**
 * idpf_vdcm_mmap - map device memory to user space
 * @mdev: pointer to the mdev device
 * @vma: pointer to the vm where device memory will be mapped
 *
 * Return 0 if succeed, negative for failure.
 */
static int idpf_vdcm_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);
	u64 index;

	index = vma->vm_pgoff >> (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);

	if (index >= VFIO_PCI_NUM_REGIONS ||
	    vma->vm_end < vma->vm_start ||
	    (vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;

	vma->vm_private_data = ivdm;
	/* Set this page's cache policy as UC(Uncachable) memory type in x86 */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops = &idpf_vdcm_mmap_ops;

	return 0;
}

/**
 * idpf_vdcm_vfio_device_get_region_info - get VFIO device region info
 * @ivdm: pointer to VDCM
 * @arg: IOCTL command arguments
 *
 * Return 0 for success, negative for failure.
 */
static long
idpf_vdcm_vfio_device_get_region_info(struct idpf_vdcm *ivdm, unsigned long arg)
{
	struct vfio_info_cap caps = { .buf = NULL, .size = 0 };
	struct vfio_region_info info;
	unsigned long minsz;
	int ret;

	minsz = offsetofend(struct vfio_region_info, offset);

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz)
		return -EINVAL;

	switch (info.index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
		info.size = IDPF_VDCM_CFG_SIZE;
		info.flags = VFIO_REGION_INFO_FLAG_READ |
				VFIO_REGION_INFO_FLAG_WRITE;
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
		info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
		info.size = IDPF_VDCM_BAR0_SIZE;
		info.flags = VFIO_REGION_INFO_FLAG_READ |
			     VFIO_REGION_INFO_FLAG_WRITE |
			     VFIO_REGION_INFO_FLAG_MMAP;
		ret = idpf_vdcm_sparse_mmap_cap(&caps, ivdm->adi);
		if (ret)
			return ret;
		break;
	case VFIO_PCI_BAR3_REGION_INDEX:
		info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
		info.size = IDPF_VDCM_BAR3_SIZE;
		info.flags = VFIO_REGION_INFO_FLAG_READ |
				VFIO_REGION_INFO_FLAG_WRITE;
		break;
	case VFIO_PCI_BAR1_REGION_INDEX:
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
	case VFIO_PCI_VGA_REGION_INDEX:
	case VFIO_PCI_ROM_REGION_INDEX:
		info.offset = 0;
		info.size = 0;
		info.flags = 0;
		break;
	default:
		return -EINVAL;
	}

	if (caps.size) {
		info.flags |= VFIO_REGION_INFO_FLAG_CAPS;
		if (info.argsz < sizeof(info) + caps.size) {
			info.argsz = sizeof(info) + caps.size;
			info.cap_offset = 0;
		} else {
			vfio_info_cap_shift(&caps, sizeof(info));
			if (copy_to_user((void __user *)(arg +
					 sizeof(info)), caps.buf,
					 caps.size)) {
				kfree(caps.buf);
				return -EFAULT;
			}
			info.cap_offset = sizeof(info);
		}

		kfree(caps.buf);
	}

	return copy_to_user((void __user *)arg, &info, minsz) ? -EFAULT : 0;
}

/**
 * idpf_vdcm_msix_handler - VDCM MSIX interrupt handler
 * @irq: OS IRQ number
 * @arg: IRQ data
 *
 * Return 0 or positive for success, negative for failure.
 */
static irqreturn_t idpf_vdcm_msix_handler(int irq, void *arg)
{
	struct idpf_vdcm_irq_ctx *ctx = (struct idpf_vdcm_irq_ctx *)arg;

	eventfd_signal(ctx->trigger, 1);
	return IRQ_HANDLED;
}

/**
 * idpf_vdcm_set_vector_signal - set single signal notification for vector
 * @ivdm: pointer to VDCM
 * @vector: vector number
 * @fd: eventfd descriptor
 *
 * This function is used to register a signal notification trigger associated
 * with this vector number when fd is 0 or positive. If fd is negative, the
 * signal notification trigger associated with this vector number will be
 * unregistered.
 *
 * Return 0 for success, negative for failure.
 */
static int
idpf_vdcm_set_vector_signal(struct idpf_vdcm *ivdm, int vector, int fd)
{
	struct eventfd_ctx *trigger;
	int irq, err;
	char *name;

	irq = ivdm->adi->get_irq_num(ivdm->adi, vector);
	if (irq < 0)
		return irq;

	if (ivdm->ctx[vector].trigger) {
		free_irq(irq, &ivdm->ctx[vector]);
		kfree(ivdm->ctx[vector].name);
		eventfd_ctx_put(ivdm->ctx[vector].trigger);
		ivdm->ctx[vector].trigger = NULL;
	}

	if (fd < 0)
		return 0;

	name = kasprintf(GFP_KERNEL, "idpf_vdcm-msix[%d](%s)",
			 vector, dev_name(ivdm->dev));
	if (!name)
		return -ENOMEM;

	trigger = eventfd_ctx_fdget(fd);
	if (IS_ERR(trigger)) {
		err = PTR_ERR(trigger);
		goto trigger_err;
	}
	ivdm->ctx[vector].name = name;
	ivdm->ctx[vector].trigger = trigger;
	err = request_irq(irq, idpf_vdcm_msix_handler, 0, name,
			  &ivdm->ctx[vector]);
	if (err < 0)
		goto irq_err;

	return 0;

irq_err:
	eventfd_ctx_put(trigger);
	ivdm->ctx[vector].trigger = NULL;
trigger_err:
	kfree(name);

	return err;
}

/**
 * idpf_vdcm_set_vector_signals - set signal notification for vector set
 * @ivdm: pointer to VDCM
 * @start: vector start
 * @count: vector number
 * @fds: array to store eventfd descriptor
 *
 * Return 0 for success, negative for failure.
 */
static int
idpf_vdcm_set_vector_signals(struct idpf_vdcm *ivdm, u32 start, u32 count,
			     int *fds)
{
	int i, j, err = 0;

	if (start >= ivdm->num_ctx || start + count > ivdm->num_ctx)
		return -EINVAL;

	for (i = 0, j = start; i < (int)count; i++, j++) {
		int fd = fds ? fds[i] : -1;

		err = idpf_vdcm_set_vector_signal(ivdm, j, fd);
		if (err)
			break;
	}

	if (err) {
		for (; j >= (int)start; j--)
			idpf_vdcm_set_vector_signal(ivdm, j, -1);
	}

	return err;
}

/**
 * idpf_vdcm_msix_enable - enable MSIX interrupt
 * @ivdm: pointer to VDCM
 * @nvec: vector numbers
 *
 * Return 0 for success, negative for failure.
 */
static int idpf_vdcm_msix_enable(struct idpf_vdcm *ivdm, int nvec)
{
	if (nvec < 1)
		return -EINVAL;

	ivdm->ctx = kcalloc(nvec, sizeof(ivdm->ctx[0]), GFP_KERNEL);
	if (!ivdm->ctx)
		return -ENOMEM;

	ivdm->irq_type = VFIO_PCI_MSIX_IRQ_INDEX;
	ivdm->num_ctx = nvec;

	return 0;
}

/**
 * idpf_vdcm_msix_disable - disable MSIX interrupt
 * @ivdm: pointer to VDCM
 */
static void idpf_vdcm_msix_disable(struct idpf_vdcm *ivdm)
{
	idpf_vdcm_set_vector_signals(ivdm, 0, ivdm->num_ctx, NULL);

	ivdm->irq_type = VFIO_PCI_NUM_IRQS;
	ivdm->num_ctx = 0;
	kfree(ivdm->ctx);
	ivdm->ctx = NULL;
}

/**
 * idpf_vdcm_set_msix_trigger - set MSIX trigger
 * @ivdm: pointer to VDCM
 * @hdr: vfio_irq_set header
 * @data: vfio_irq_set appended data
 *
 * Return 0 for success, negative for failure.
 */
static long
idpf_vdcm_set_msix_trigger(struct idpf_vdcm *ivdm, struct vfio_irq_set *hdr,
			   void *data)
{
	/* Checking ivdm->irq_type == hdr->index is used to skip the
	 * unnecessary idpf_vdcm_msix_disable() calling.
	 * For example, when hypervisor starts, it will release all the
	 * IRQ context by sending VFIO_DEVICE_SET_IRQS UAPI. If the IRQ
	 * context is not setup before, ivdm->irq_type is VFIO_PCI_NUM_IRQS
	 * by default and nothing should be done here.
	 */
	if (ivdm->irq_type == hdr->index && !hdr->count &&
	    (hdr->flags & VFIO_IRQ_SET_DATA_NONE)) {
		idpf_vdcm_msix_disable(ivdm);
		return 0;
	}

	if (hdr->flags & VFIO_IRQ_SET_DATA_EVENTFD) {
		int *fds = (int *)data;
		int err;

		if (ivdm->irq_type == hdr->index)
			return idpf_vdcm_set_vector_signals(ivdm, hdr->start,
							    hdr->count, fds);

		err = idpf_vdcm_msix_enable(ivdm, hdr->start + hdr->count);
		if (err)
			return err;

		err = idpf_vdcm_set_vector_signals(ivdm, hdr->start,
						   hdr->count, fds);
		if (err)
			idpf_vdcm_msix_disable(ivdm);

		return err;
	}

	return 0;
}

/**
 * idpf_vdcm_vfio_device_set_irqs - Set VFIO device IRQs
 * @ivdm: pointer to VDCM
 * @arg: IOCTL command arguments
 *
 * Return 0 for success, negative for failure.
 */
static long
idpf_vdcm_vfio_device_set_irqs(struct idpf_vdcm *ivdm, unsigned long arg)
{
	struct vfio_irq_set hdr;
	size_t data_size = 0;
	unsigned long minsz;
	u8 *data = NULL;
	int total_vecs;
	int err;

	minsz = offsetofend(struct vfio_irq_set, count);

	if (copy_from_user(&hdr, (void __user *)arg, minsz))
		return -EFAULT;

	if (hdr.argsz < minsz)
		return -EFAULT;

	total_vecs = ivdm->adi->get_num_of_vectors(ivdm->adi);
	if (total_vecs <= 0)
		return -EFAULT;

	err = vfio_set_irqs_validate_and_prepare(&hdr, total_vecs,
						 VFIO_PCI_NUM_IRQS,
						 &data_size);
	if (err)
		return -EINVAL;

	if (data_size) {
		data = memdup_user((void __user *)(arg + minsz), data_size);
		if (IS_ERR(data))
			return PTR_ERR(data);
	}

	switch (hdr.index) {
	case VFIO_PCI_MSIX_IRQ_INDEX:
		switch (hdr.flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			err = idpf_vdcm_set_msix_trigger(ivdm, &hdr, data);
			break;
		default:
			err = -ENOTTY;
			break;
		}
		break;
	default:
		err = -ENOTTY;
		break;
	}

	kfree(data);

	return err;
}

/**
 * idpf_vdcm_vfio_device_get_irq_info - get VFIO device IRQ info
 * @ivdm: pointer to VDCM
 * @arg: IOCTL command arguments
 *
 * Return 0 for success, negative for failure.
 */
static long
idpf_vdcm_vfio_device_get_irq_info(struct idpf_vdcm *ivdm, unsigned long arg)
{
	struct vfio_irq_info info;
	unsigned long minsz;
	int vector_count;

	minsz = offsetofend(struct vfio_irq_info, count);

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz || info.index >= VFIO_PCI_NUM_IRQS)
		return -EINVAL;

	/* Only MSI-X interrupts are supported */
	if (info.index != VFIO_PCI_MSIX_IRQ_INDEX)
		return -EINVAL;

	vector_count = ivdm->adi->get_num_of_vectors(ivdm->adi);
	if (vector_count <= 0)
		return -EINVAL;

	info.flags = VFIO_IRQ_INFO_EVENTFD | VFIO_IRQ_INFO_NORESIZE;
	info.count = vector_count;

	return copy_to_user((void __user *)arg, &info, minsz) ? -EFAULT : 0;
}

/**
 * idpf_vdcm_zap - remove all the previously setup VMA mmap
 * @token: pointer to VDCM
 *
 * Return 0 for success, negative for failure.
 */
int idpf_vdcm_zap(void *token)
{
	struct idpf_vdcm *ivdm = (struct idpf_vdcm *)token;
	struct idpf_vdcm_mmap_vma *mmap_vma, *tmp;

	if (!ivdm)
		return -EINVAL;

	/* There are two loops inside while(1) loop in order to gurantee the
	 * locking order: locking mm first then vma_lock. Because when page
	 * fault happens, kernel will lock the mm first and then call the
	 * page fault handler registered, in the ice_vdcm_mmap_fault callback,
	 * vma_lock is acquired to protect the vma_list. So locking the vma_lock
	 * after the mm must be followed in the driver to prevent deadlock.
	 *
	 * The first loop is to fetch the first valid mm_struct in preparation
	 * for the next loop mmap_read_lock usage, which must be called before
	 * vma_lock is acquired. Since VDCM may record VMAs from multi process,
	 * this behavior will delete the VMAs belonging to the same process one
	 * by one.
	 */
	while (1) {
		struct mm_struct *mm = NULL;

		mutex_lock(&ivdm->vma_lock);
		while (!list_empty(&ivdm->vma_list)) {
			mmap_vma = list_first_entry(&ivdm->vma_list,
						    struct idpf_vdcm_mmap_vma,
						    vma_next);
			/* Fetch the first task memory context*/
			mm = mmap_vma->vma->vm_mm;
			if (mmget_not_zero(mm))
				break;

			/* If there are no lightweight processes sharing the
			 * mm_struct data structure, delete the list node.
			 */
			list_del(&mmap_vma->vma_next);
			kfree(mmap_vma);
			mm = NULL;
		}
		/* Return when vma_list is empty */
		if (!mm) {
			mutex_unlock(&ivdm->vma_lock);
			return 0;
		}
		mutex_unlock(&ivdm->vma_lock);

		mmap_read_lock(mm);
		mutex_lock(&ivdm->vma_lock);
		list_for_each_entry_safe(mmap_vma, tmp,
					 &ivdm->vma_list, vma_next) {
			struct vm_area_struct *vma = mmap_vma->vma;

			/* Skip all the VMAs which don't belong to this task
			 * memory context. We'll zap the VMAs sharing the same
			 * mm_struct which means they belong the same process.
			 */
			if (vma->vm_mm != mm)
				continue;

			list_del(&mmap_vma->vma_next);
			kfree(mmap_vma);

			zap_vma_ptes(vma, vma->vm_start,
				     vma->vm_end - vma->vm_start);
			dev_dbg(ivdm->dev, "zap start HVA:0x%lx GPA:0x%lx size:0x%lx",
				vma->vm_start, vma->vm_pgoff << PAGE_SHIFT,
				vma->vm_end - vma->vm_start);
		}
		mutex_unlock(&ivdm->vma_lock);
		mmap_read_unlock(mm);
		mmput(mm);
	}
}

/**
 * idpf_vdcm_vfio_device_reset - VFIO device reset
 * @ivdm: pointer to VDCM
 *
 * Return 0 for success, negative for failure.
 */
static long idpf_vdcm_vfio_device_reset(struct idpf_vdcm *ivdm)
{
	idpf_vdcm_zap(ivdm);
	return ivdm->adi->reset(ivdm->adi);
}

/**
 * idpf_vdcm_pci_config_space_init - Initialize VDCM PCI configuration space
 * @ivdm: pointer to VDCM
 *
 * Return 0 for success, non 0 for failure.
 */
static int idpf_vdcm_pci_config_space_init(struct idpf_vdcm *ivdm)
{
	static u64 idpf_vdcm_pci_config[] = {
		0x001000000dd58086ULL, /* 0x00-0x40: PCI config header */
		0x0000000002000000ULL,
		0x000000000000000cULL,
		0x0000000c00000000ULL,
		0x0000000000000000ULL,
		0x0000808600000000ULL,
		0x0000004000000000ULL,
		0x0000000000000000ULL,
		0x0000000300040011ULL, /* 0x40-0x4C: MSI-X capability */
		0x0000000000002003ULL,
		0x0000000000920010ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0070001000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
	};
	int num_vectors;

	num_vectors = ivdm->adi->get_num_of_vectors(ivdm->adi);
	if (num_vectors <= 0)
		return -EINVAL;

	memcpy(ivdm->pci_cfg_space, idpf_vdcm_pci_config,
	       sizeof(idpf_vdcm_pci_config));

	/* Set MSI-X table size using N-1 encoding */
	ivdm->pci_cfg_space[IDPF_VDCM_MSIX_CTRL_OFFS] = num_vectors - 1;

	return 0;
}

/**
 * idpf_vdcm_create - create an emulated device
 * @kobj: kernel object
 * @mdev: emulated device instance pointer
 *
 * This function is called when VFIO consumer (like QEMU) wants to create a
 * emulated device, typically by echo some uuid to the SYSFS.
 * Return 0 for success, non 0 for failure.
 */
#ifdef HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE
static int idpf_vdcm_create(struct kobject *kobj, struct mdev_device *mdev)
#else
static int idpf_vdcm_create(struct mdev_device *mdev)
#endif
{
	struct device *parent_dev = mdev_parent_dev(mdev);
	struct idpf_vdcm *ivdm;
	int err;

	ivdm = kzalloc(sizeof(*ivdm), GFP_KERNEL);
	if (!ivdm)
		return -ENOMEM;

	ivdm->adi = idpf_vdcm_alloc_adi(parent_dev);
	if (!ivdm->adi) {
		err = -ENOMEM;
		goto alloc_adi_err;
	}

	ivdm->irq_type = VFIO_PCI_NUM_IRQS;
	ivdm->dev = mdev_dev(mdev);
	ivdm->parent_dev = parent_dev;
	mdev_set_drvdata(mdev, ivdm);
	mutex_init(&ivdm->vma_lock);
	INIT_LIST_HEAD(&ivdm->vma_list);
	mutex_init(&ivdm->ref_lock);
	err = idpf_vdcm_pci_config_space_init(ivdm);
	if (err)
		goto vdcm_pci_cfg_space_init_err;

#ifdef HAVE_DEV_IN_MDEV_API
	mdev_set_iommu_device(mdev_dev(mdev), parent_dev);
#else
	mdev_set_iommu_device(mdev, parent_dev);
#endif /* HAVE_DEV_IN_MDEV_API */

	return 0;

vdcm_pci_cfg_space_init_err:
	idpf_vdcm_free_adi(ivdm->adi);
alloc_adi_err:
	kfree(ivdm);

	return err;
}

/**
 * idpf_vdcm_cfg_read - read PCI configuration space
 * @ivdm: pointer to VDCM
 * @pos: read offset
 * @buf: buf stores read content
 * @count: read length
 *
 * Return 0 for success, negative value for failure.
 */
static int
idpf_vdcm_cfg_read(struct idpf_vdcm *ivdm, unsigned int pos, char *buf,
		   unsigned int count)
{
	if (pos + count > IDPF_VDCM_CFG_SIZE)
		return -EINVAL;

	memcpy(buf, &ivdm->pci_cfg_space[pos], count);
	return 0;
}

/**
 * idpf_vdcm_cfg_write_mask - write PCI configuration space with mask
 * @ivdm: pointer to VDCM
 * @off: write offset
 * @buf: buf stores write content
 * @bytes: write length
 *
 * Return 0 for success, negative value for failure.
 */
static int
idpf_vdcm_cfg_write_mask(struct idpf_vdcm *ivdm, unsigned int off, u8 *buf,
			 unsigned int bytes)
{
	u8 *cfg_base = ivdm->pci_cfg_space;
	u8 mask, newval, oldval;
	unsigned int i = 0;

	/* Bitmap for writable bits (RW or RW1C bits, but cannot co-exist
	 * in one byte) byte by byte in standard PCI configuration space.
	 * (not the full 256 bytes.)
	 */
	static const u8 idpf_vdcm_csr_rw_bmp[] = {
		0x00, 0x00, 0x00, 0x00, 0xff, 0x07, 0x00, 0xf9,
		0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00,
		0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff,
		0xf0, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00,
	};

	for (; i < bytes && (off + i < sizeof(idpf_vdcm_csr_rw_bmp)); i++) {
		mask = idpf_vdcm_csr_rw_bmp[off + i];
		oldval = cfg_base[off + i];
		newval = buf[i] & mask;

		/* The PCI_STATUS high byte has RW1C bits, here
		 * emulates clear by writing 1 for these bits.
		 * Writing a 0b to RW1C bits has no effect.
		 */
		if (off + i == PCI_STATUS + 1)
			newval = (~newval & oldval) & mask;

		cfg_base[off + i] = (oldval & ~mask) | newval;
	}

	/* For other configuration space directly copy as it is. */
	if (i < bytes)
		memcpy(cfg_base + off + i, buf + i, bytes - i);

	return 0;
}

/**
 * idpf_vdcm_cfg_write_bar - write PCI configuration space BAR registers
 * @ivdm: pointer to VDCM
 * @offset: write offset
 * @buf: buf stores write content
 * @bytes: write length
 *
 * Return 0 for success, negative value for failure.
 */
static int
idpf_vdcm_cfg_write_bar(struct idpf_vdcm *ivdm, unsigned int offset, char *buf,
			unsigned int bytes)
{
	u32 val = *(u32 *)(buf);
	int err;

	switch (offset) {
	case PCI_BASE_ADDRESS_0:
		val &= ~(IDPF_VDCM_BAR0_SIZE - 1);
		err = idpf_vdcm_cfg_write_mask(ivdm, offset, (u8 *)&val, bytes);
		break;
	case PCI_BASE_ADDRESS_1:
		val &= ~(u64)(IDPF_VDCM_BAR0_SIZE - 1) >> 32;
		err = idpf_vdcm_cfg_write_mask(ivdm, offset, (u8 *)&val, bytes);
		break;
	case PCI_BASE_ADDRESS_3:
		val &= ~(IDPF_VDCM_BAR3_SIZE - 1);
		err = idpf_vdcm_cfg_write_mask(ivdm, offset, (u8 *)&val, bytes);
		break;
	case PCI_BASE_ADDRESS_4:
		val &= ~(u64)(IDPF_VDCM_BAR3_SIZE - 1) >> 32;
		err = idpf_vdcm_cfg_write_mask(ivdm, offset, (u8 *)&val, bytes);
		break;
	case PCI_BASE_ADDRESS_5:
	case PCI_BASE_ADDRESS_2:
		err = 0;
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

/**
 * idpf_vdcm_cfg_write - write PCI configuration space
 * @ivdm: pointer to VDCM
 * @pos: write offset
 * @buf: buf stores write content
 * @count: write length
 *
 * Return 0 for success, negative value for failure.
 */
static int
idpf_vdcm_cfg_write(struct idpf_vdcm *ivdm, unsigned int pos, char *buf,
		    unsigned int count)
{
	int err;

	if (pos + count > IDPF_VDCM_CFG_SIZE)
		return -EINVAL;

	switch (pos) {
	case PCI_BASE_ADDRESS_0 ... PCI_BASE_ADDRESS_5:
		if (!IS_ALIGNED(pos, 4))
			return -EINVAL;
		err = idpf_vdcm_cfg_write_bar(ivdm, pos, buf, count);
		break;
	default:
		err = idpf_vdcm_cfg_write_mask(ivdm, pos, (u8 *)buf, count);
		break;
	}

	return err;
}

/**
 * idpf_vdcm_bar0_read - read PCI BAR0 region
 * @ivdm: pointer to VDCM
 * @pos: read offset
 * @buf: buf stores read content
 * @count: read length
 *
 * Return 0 for success, negative value for failure.
 */
static int
idpf_vdcm_bar0_read(struct idpf_vdcm *ivdm, unsigned int pos, char *buf,
		    unsigned int count)
{
	u32 val;

	if (pos + count > IDPF_VDCM_BAR0_SIZE)
		return -EINVAL;

	val = ivdm->adi->read_reg32(ivdm->adi, pos);
	memcpy(buf, &val, count);

	return 0;
}

/**
 * idpf_vdcm_bar0_write - write PCI BAR0 region
 * @ivdm: pointer to VDCM
 * @pos: write offset
 * @buf: buf stores write content
 * @count: write length
 *
 * Return 0 for success, negative value for failure.
 */
static int
idpf_vdcm_bar0_write(struct idpf_vdcm *ivdm, unsigned int pos, char *buf,
		     unsigned int count)
{
	u32 val;

	if ((pos + count > IDPF_VDCM_BAR0_SIZE) || !IS_ALIGNED(pos, 4))
		return -EINVAL;

	val = *(u32 *)(buf);
	ivdm->adi->write_reg32(ivdm->adi, pos, val);

	return 0;
}

/**
 * idpf_vdcm_rw - read/write function entry
 * @mdev: emulated device instance pointer
 * @buf: buf stores read/write content
 * @count: read/write length
 * @ppos: read/write offset
 * @is_write: is write operatoin
 *
 * Return the number of read/write bytes for success, other value for failure.
 */
static ssize_t
idpf_vdcm_rw(struct mdev_device *mdev, char *buf, size_t count,
	     const loff_t *ppos, bool is_write)
{
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	int err = -EINVAL;

	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		if (is_write)
			err = idpf_vdcm_cfg_write(ivdm, pos, buf, count);
		else
			err = idpf_vdcm_cfg_read(ivdm, pos, buf, count);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
		if (is_write)
			err = idpf_vdcm_bar0_write(ivdm, pos, buf, count);
		else
			err = idpf_vdcm_bar0_read(ivdm, pos, buf, count);
		break;
	default:
		break;
	}

	return err ? err : count;
}

/**
 * idpf_vdcm_remove - delete an emulated device
 * @mdev: emulated device instance pointer
 *
 * This function is called when VFIO consumer(like QEMU) wants to delete
 * emulated device.
 * Return 0 for success, negative for failure.
 */
static int idpf_vdcm_remove(struct mdev_device *mdev)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);

	idpf_vdcm_free_adi(ivdm->adi);
	ivdm->adi = NULL;

	kfree(ivdm);
	ivdm = NULL;

	return 0;
}

/**
 * idpf_vdcm_read - read function entry
 * @mdev: emulated device instance pointer
 * @buf: buf stores read content
 * @count: read length
 * @ppos: read offset
 *
 * This function is called when VFIO consumer (like QEMU) wants to read
 * emulated device with any device specific information for register access
 * Return the number of read bytes.
 */
static ssize_t
idpf_vdcm_read(struct mdev_device *mdev, char __user *buf, size_t count,
	       loff_t *ppos)
{
	unsigned int done = 0;
	int err;

	while (count) {
		size_t filled;

		if (count >= 4 && IS_ALIGNED(*ppos, 4)) {
			u32 val;

			err = idpf_vdcm_rw(mdev, (char *)&val, sizeof(val),
					   ppos, false);
			if (err <= 0)
				return -EFAULT;

			if (copy_to_user(buf, &val, sizeof(val)))
				return -EFAULT;

			filled = sizeof(val);
		} else if (count >= 2 && IS_ALIGNED(*ppos, 2)) {
			u16 val;

			err = idpf_vdcm_rw(mdev, (char *)&val, sizeof(val),
					   ppos, false);
			if (err <= 0)
				return -EFAULT;

			if (copy_to_user(buf, &val, sizeof(val)))
				return -EFAULT;

			filled = sizeof(val);
		} else {
			u8 val;

			err = idpf_vdcm_rw(mdev, (char *)&val, sizeof(val),
					   ppos, false);
			if (err <= 0)
				return -EFAULT;

			if (copy_to_user(buf, &val, sizeof(val)))
				return -EFAULT;

			filled = sizeof(val);
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	return done;
}

/**
 * idpf_vdcm_write - write function entry
 * @mdev: emulated device instance pointer
 * @buf: buf stores content to be written
 * @count: write length
 * @ppos: write offset
 *
 * This function is called when VFIO consumer (like QEMU) wants to write
 * emulated device with any device specific information like register access
 * Return the number of written bytes.
 */
static ssize_t
idpf_vdcm_write(struct mdev_device *mdev, const char __user *buf, size_t count,
		loff_t *ppos)
{
	unsigned int done = 0;
	int err;

	while (count) {
		size_t filled;

		if (count >= 4 && IS_ALIGNED(*ppos, 4)) {
			u32 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				return -EFAULT;

			err = idpf_vdcm_rw(mdev, (char *)&val, sizeof(val),
					   ppos, true);
			if (err <= 0)
				return -EFAULT;

			filled = sizeof(val);
		} else if (count >= 2 && IS_ALIGNED(*ppos, 2)) {
			u16 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				return -EFAULT;

			err = idpf_vdcm_rw(mdev, (char *)&val, sizeof(val),
					   ppos, true);
			if (err <= 0)
				return -EFAULT;

			filled = sizeof(val);
		} else {
			u8 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				return -EFAULT;

			err = idpf_vdcm_rw(mdev, (char *)&val, sizeof(val),
					   ppos, true);
			if (err <= 0)
				return -EFAULT;

			filled = sizeof(val);
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	return done;
}

/**
 * idpf_vdcm_ioctl - IOCTL function entry
 * @mdev: emulated device instance pointer
 * @cmd: pre defined ioctls
 * @arg: cmd arguments
 *
 * This function is called when VFIO consumer (like QEMU) wants to config
 * emulated device.
 * Return 0 for success, negative for failure.
 */
static long
idpf_vdcm_ioctl(struct mdev_device *mdev, unsigned int cmd, unsigned long arg)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);

	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
		return idpf_vdcm_vfio_device_get_info(ivdm, arg);
	case VFIO_DEVICE_GET_REGION_INFO:
		return idpf_vdcm_vfio_device_get_region_info(ivdm, arg);
	case VFIO_DEVICE_GET_IRQ_INFO:
		return idpf_vdcm_vfio_device_get_irq_info(ivdm, arg);
	case VFIO_DEVICE_SET_IRQS:
		return idpf_vdcm_vfio_device_set_irqs(ivdm, arg);
	case VFIO_DEVICE_RESET:
		return idpf_vdcm_vfio_device_reset(ivdm);
	default:
		break;
	}

	return -ENOTTY;
}

/**
 * idpf_vdcm_get_pasid - Get PASID value
 * @ivdm: pointer to VDCM
 *
 * Return valid PASID value on success, negative for failure.
 */
static int idpf_vdcm_get_pasid(struct idpf_vdcm *ivdm)
{
	struct device *dev = ivdm->dev;
	struct vfio_group *vfio_group;
	struct iommu_domain *domain;
	int pasid;

	/**
	 * vfio_group_get_external_user_from_dev() will increase kobj ref
	 * counter, so vfio_group should be cached to be passed to
	 * vfio_group_put_external_user() to decrease kobj ref counter.
	 */
	vfio_group = vfio_group_get_external_user_from_dev(dev);
	if (IS_ERR_OR_NULL(vfio_group))
		return -EFAULT;

#ifdef ENABLE_ACC_PASID_WA
	domain = __mdev_get_iommu_domain(dev);
#else
	domain = vfio_group_iommu_domain(vfio_group);
	if (IS_ERR_OR_NULL(domain)) {
		vfio_group_put_external_user(vfio_group);
		return -EFAULT;
	}
#endif /* ENABLE_ACC_PASID_WA */
	pasid = iommu_aux_get_pasid(domain, ivdm->parent_dev);
	if (pasid < 0) {
		vfio_group_put_external_user(vfio_group);
		return -EFAULT;
	}

	ivdm->vfio_group = vfio_group;

	return pasid;
}

/**
 * idpf_vdcm_open - open emulated device
 * @mdev: emulated device instance pointer
 *
 * This function is called when VFIO consumer (like QEMU) wants to open
 * emulated device.
 * Return 0 for success, negative for failure.
 */
static int idpf_vdcm_open(struct mdev_device *mdev)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);
	int pasid;
	int ret;

	mutex_lock(&ivdm->ref_lock);

	if (!ivdm->refcnt) {
		pasid = idpf_vdcm_get_pasid(ivdm);
		if (pasid < 0) {
			ret = pasid;
			goto err_get_pasid;
		}

		ret = ivdm->adi->config(ivdm->adi, pasid, true);
		if (ret)
			goto err_config_adi;
	}

	mutex_unlock(&ivdm->ref_lock);
	ivdm->refcnt++;

	return 0;

err_config_adi:
	vfio_group_put_external_user(ivdm->vfio_group);
err_get_pasid:
	mutex_unlock(&ivdm->ref_lock);
	return ret;
}

/**
 * idpf_vdcm_close - close a mediated device
 * @mdev: emulated device instance pointer
 *
 * This function is called when VFIO consumer (like QEMU) wants to close
 * emulated device.
 */
static void idpf_vdcm_close(struct mdev_device *mdev)
{
	struct idpf_vdcm *ivdm = mdev_get_drvdata(mdev);

	mutex_lock(&ivdm->ref_lock);

	if (!(--ivdm->refcnt)) {
		if (ivdm->irq_type < VFIO_PCI_NUM_IRQS)
			idpf_vdcm_msix_disable(ivdm);
		ivdm->adi->config(ivdm->adi, 0, false);
		vfio_group_put_external_user(ivdm->vfio_group);
	}

	mutex_unlock(&ivdm->ref_lock);
}

/**
 * name_show - SYSFS show function
 * @kobj: kernel object
 * @dev: linux device pointer
 * @buf: return buffer
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of read bytes.
 */
static ssize_t
#ifdef HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE
name_show(struct kobject *kobj, struct device *dev, char *buf)
#else
name_show(struct mdev_type *mtype,
	  struct mdev_type_attribute *attr, char *buf)
#endif
{
#ifndef HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE
	struct device *dev = mtype_get_parent_dev(mtype);
#endif /* !HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE */
	return sprintf(buf, "%s\n", dev_name(dev));
}
static MDEV_TYPE_ATTR_RO(name);

/**
 * available_instances_show - SYSFS show function
 * @kobj: kernel object
 * @dev: device pointer
 * @buf: return buffer
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of read bytes.
 */
static ssize_t
#ifdef HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
#else
available_instances_show(struct mdev_type *mtype,
			 struct mdev_type_attribute *attr, char *buf)
#endif
{
	return sprintf(buf, "ivdcm\n");
}
static MDEV_TYPE_ATTR_RO(available_instances);

/**
 * device_api_show - SYSFS show function
 * @kobj: kernel object
 * @dev: device pointer
 * @buf: return buffer
 *
 * This function is called when SYSFS file entry is read by user
 * Return number of read bytes.
 */
static ssize_t
#ifdef HAVE_KOBJ_IN_MDEV_PARENT_OPS_CREATE
device_api_show(struct kobject *kobj, struct device *dev, char *buf)
#else
device_api_show(struct mdev_type *mtype,
		struct mdev_type_attribute *attr, char *buf)
#endif
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}
static MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *idpf_vdcm_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};

static struct attribute_group idpf_vdcm_type_group0 = {
	.name  = "vdcm",
	.attrs = idpf_vdcm_types_attrs,
};

static struct attribute_group *idpf_vdcm_type_groups[] = {
	&idpf_vdcm_type_group0,
	NULL,
};

static const struct mdev_parent_ops idpf_vdcm_parent_ops = {
	.supported_type_groups	= idpf_vdcm_type_groups,
	.create			= idpf_vdcm_create,
	.remove			= idpf_vdcm_remove,
#ifdef HAVE_DEVICE_IN_MDEV_PARENT_OPS
	.open_device		= idpf_vdcm_open,
	.close_device		= idpf_vdcm_close,
#else
	.open			= idpf_vdcm_open,
	.release		= idpf_vdcm_close,
#endif /* HAVE_DEVICE_IN_MDEV_PARENT_OPS */
	.read			= idpf_vdcm_read,
	.write			= idpf_vdcm_write,
	.ioctl			= idpf_vdcm_ioctl,
	.mmap			= idpf_vdcm_mmap,
};

/*
 * idpf_vdcm_init - VDCM initialization routine
 * @pdev: the parent pci device
 *
 * Return 0 for success, negative for failure.
 */
int idpf_vdcm_init(struct pci_dev *pdev)
{
	int err;

	err = iommu_dev_enable_feature(&pdev->dev, IOMMU_DEV_FEAT_AUX);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable aux-domain: %d", err);
		return err;
	}

	pr_info("file: %s +%d, caller:%ps\n", __FILE__, __LINE__, __builtin_return_address(0));
	err = mdev_register_device(&pdev->dev, &idpf_vdcm_parent_ops);
	if (err) {
		dev_err(&pdev->dev, "S-IOV device register failed, err %d",
			err);
		iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_AUX);
		return err;
	}

	return 0;
}

/*
 * idpf_vdcm_deinit - VDCM deinitialization routine
 * @pdev: the parent pci device
 */
void idpf_vdcm_deinit(struct pci_dev *pdev)
{
	mdev_unregister_device(&pdev->dev);
	iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_AUX);
}
