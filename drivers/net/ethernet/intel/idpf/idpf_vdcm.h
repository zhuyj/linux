/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2022 Intel Corporation */
#ifndef _IDPF_VDCM_H_
#define _IDPF_VDCM_H_

#include <linux/uuid.h>
#include <linux/mdev.h>
#include <linux/vfio.h>
#include <linux/sched/mm.h>

#define IDPF_VDCM_BAR0_SIZE SZ_64M
#define IDPF_VDCM_BAR3_SIZE SZ_16K
#define IDPF_VDCM_CFG_SIZE 256
/* According to PCI Express Base Specification 4.0r1.0 section 7.5.1.2
 * Type 0 Configuration Space Header, the device specific capabilities
 * start at offset 0x40.
 */
#define IDPF_VDCM_MSIX_CTRL_OFFS (0x40 + PCI_MSIX_FLAGS)

/**
 * struct idpf_vdcm_irq_ctx - IRQ Context information for VDCM
 *
 * @trigger:		Eventfd context
 * @name:		Name for the IRQ context
 */
struct idpf_vdcm_irq_ctx {
	struct eventfd_ctx *trigger;
	char *name;
};

struct idpf_vdcm_mmap_vma {
	struct vm_area_struct *vma;
	struct list_head vma_next;
};

/**
 * struct idpf_vdcm - Abstraction for VDCM
 *
 * @dev:		Linux device for this VDCM
 * @parent_dev:		Linux parent device for this VDCM
 * @vfio_group:		VFIO group for this device
 * @pci_cfg_space:	PCI configuration space buffer
 * @ref_lock:		lock to protect refcnt
 * @refcnt:		device reference count
 * @ctx:		IRQ context
 * @num_ctx:		number of requested iRQ context
 * @irq_type:		IRQ type
 * @adi:		ADI attribute
 */
struct idpf_vdcm {
	/* Common attribute */
	struct device *dev;
	struct device *parent_dev;
	struct vfio_group *vfio_group;
	u8 pci_cfg_space[IDPF_VDCM_CFG_SIZE];
	struct mutex vma_lock;		/* protects access to vma_list */
	struct list_head vma_list;

	struct mutex ref_lock; /* lock to protect refcnt */
	int refcnt;

	/* IRQ context */
	struct idpf_vdcm_irq_ctx *ctx;
	unsigned int num_ctx;
	unsigned int irq_type;

	/* Device Specific */
	struct idpf_adi *adi;
};

/**
 * struct idpf_adi - Assignable Device Interface attribute
 * This structure defines the device specific resource and callbacks
 * @config:
 *     This function is called when VDCM want to config ADI's pasid
 * @reset: This function is called when VDCM wants to reset ADI
 * @read_reg32: This function is called when VDCM wants to read ADI register
 * @write_reg32: This function is called when VDCM wants to write ADI register
 * @get_num_of_vectors: get number of vectors assigned to this ADI
 * @get_irq_num: get OS IRQ number per vector
 * @get_sparse_mmap_hpa: This function is called when VDCM wants to get ADI HPA
 * @get_sparse_mmap_num: This function is called when VDCM wants to get
 *                       the number of sparse memory areas
 * @get_sparse_mmap_area: This function is called when VDCM wants to get
 *                        layout of sparse memory
 */
struct idpf_adi {
	int irq_count;
	int (*config)(struct idpf_adi *adi, u32 pasid, bool ena);
	int (*reset)(struct idpf_adi *adi);
	u32 (*read_reg32)(struct idpf_adi *adi, size_t offs);
	void (*write_reg32)(struct idpf_adi *adi, size_t offs, u32 val);
	int (*get_num_of_vectors)(struct idpf_adi *adi);
	int (*get_irq_num)(struct idpf_adi *adi, u32 vector);
	int (*get_sparse_mmap_num)(struct idpf_adi *adi);
	int (*get_sparse_mmap_area)(struct idpf_adi *adi, u64 index,
				    u64 *offset, u64 *size);
	int (*get_sparse_mmap_hpa)(struct idpf_adi *adi, u32 index, u64 pg_off,
				   u64 *addr);
};

struct idpf_adi *idpf_vdcm_alloc_adi(struct device *dev);
void idpf_vdcm_free_adi(struct idpf_adi *adi);
int idpf_vdcm_init(struct pci_dev *pdev);
void idpf_vdcm_deinit(struct pci_dev *pdev);

/* Below definitions are used by idpf_siov.c */

/* ADI vectors */
#define IDPF_MAX_ADI_VEC	5 /* max vectors per ADI - 4 data, 1 mbx */
#define IDPF_MAX_ADI_VECS	(IDPF_MAX_ADI_NUM * IDPF_MAX_ADI_VEC)

struct idpf_adi_vec_info {
	u16	num_vectors;
	u16	vec_indexes[IDPF_MAX_ADI_VEC];
	int	mbx_vec_id;
#define IDPF_MAX_VECS  16
	int	data_q_vec_ids[IDPF_MAX_VECS];
};

struct idpf_adi_q {
	int qid;
	u64 tail_reg;
};

struct idpf_adi_queue_info {
	int	num_txqs;
	int	num_complqs;
	int	num_rxqs;
	int	num_bufqs;
#define IDPF_MAX_QS  16
	struct idpf_adi_q txq[IDPF_MAX_QS];
	struct idpf_adi_q complq[IDPF_MAX_QS];
	struct idpf_adi_q rxq[IDPF_MAX_QS];
	struct idpf_adi_q bufq[IDPF_MAX_QS];
};

struct idpf_adi_priv {
	struct idpf_adi adi;
	struct idpf_adapter *adapter;
	struct idpf_adi_vec_info vec_info;
	struct idpf_adi_queue_info qinfo;
	int	mbx_id;
	/*
	 * adi_idx is the index used to get the offset
	 * of MSIX entry from the base of non ADI MSIX entry
	 * which is set to IDPF_MAX_NON_ADI_VECS - this is
	 * location from where ADI starts
	 */
	int	adi_idx;
	/* ADI id used by HMA which is sent as part of destroy ADI */
	int	adi_id;
};

#endif /* !_IDPF_VDCM_H_ */
