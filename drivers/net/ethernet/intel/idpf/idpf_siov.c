// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Intel Corporation */
#include "idpf.h"
#include "idpf_lan_pf_regs.h"
#include "idpf_lan_vf_regs.h"
#include "siov_regs.h"

#define USE_HW_MBX_ID 1 /* mailbox ID set in CREATE_ADI message */

struct idpf_adi_sparse_mmap_info {
	u64 start;
	u64 end;
	u64 cnt;
	u64 phy_addr;
};

enum idpf_adi_sparse_mmap_type {
	IDPF_ADI_SPARSE_MBX = 0,
	IDPF_ADI_SPARSE_RXQ,
	IDPF_ADI_SPARSE_RX_BUFQ,
	IDPF_ADI_SPARSE_TXQ,
	IDPF_ADI_SPARSE_DYN_CTL01,
	IDPF_ADI_SPARSE_DYN_CTL,
	IDPF_ADI_SPARSE_MAX,
};

/**
 * idpf_adi_reset - reset ADI
 * @adi: ADI pointer
 *
 * Return 0 for success, negative for failure
 */
static int idpf_adi_reset(struct idpf_adi *adi)
{
	return -EFAULT;
}

/**
 * idpf_get_adi_priv - Obtain ADI private structure
 * @adi: ADI pointer
 *
 * Return ADI private structure
 */
static void *idpf_get_adi_priv(const struct idpf_adi *adi)
{
	return (struct idpf_adi_priv *)
		container_of(adi, struct idpf_adi_priv, adi);
}

/**
 * __idpf_adi_qid_reg_init - Fill out queue id and reg info for ADI
 * @q: Data queue information
 * @num_qids: number of queue ids
 * @q_type: queue model
 * @chunks: queue ids received over mailbox
 *
 * Initialize queue ids and register info for each ADI
 * Returns number of ids filled
 */
static int
__idpf_adi_qid_reg_init(struct idpf_adi_q *q, int num_qids, u16 q_type,
			struct virtchnl2_queue_reg_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_chunks);
	struct virtchnl2_queue_reg_chunk *chunk;
	u32 start_q_id, num_q, reg_spacing;
	u32 q_id_filled = 0, i, c;
	u64 reg_val;

	for (c = 0; c < num_chunks; c++) {
		chunk = &chunks->chunks[c];
		if (le32_to_cpu(chunk->type) == q_type) {
			num_q = le32_to_cpu(chunk->num_queues);
			start_q_id = le32_to_cpu(chunk->start_queue_id);
			reg_val = le64_to_cpu(chunk->qtail_reg_start);
			reg_spacing = le32_to_cpu(chunk->qtail_reg_spacing);
			for (i = 0; i < num_q; i++) {
				if ((q_id_filled + i) < num_qids) {
					q[q_id_filled + i].qid = start_q_id;
					q[q_id_filled + i].tail_reg = reg_val;
					reg_val += reg_spacing;
					start_q_id++;
				} else {
					break;
				}
			}
			q_id_filled = q_id_filled + i;
		}
	}

	return q_id_filled;
}

/**
 * idpf_adi_qid_reg_init - Populate Q ids and registers for each queue type
 * @adi: ADI pointer
 * @vc_cadi: Create ADI Virtchannel structure
 *
 * Will initialize all queue ids with ids received as mailbox parameters.
 * Returns 0 on success, negative if all the queues are not initialized.
 */
static int idpf_adi_qid_reg_init(struct idpf_adi *adi,
				 struct virtchnl2_create_adi *vc_cadi)
{
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);
	struct virtchnl2_queue_reg_chunks *chunks;
	/* We may never deal with more than 16 same type of queues */
#define IDPF_MAX_QIDS	16
	u16 q_type;

	chunks = &vc_cadi->chunks;

	q_type = VIRTCHNL2_QUEUE_TYPE_TX;

	priv->qinfo.num_txqs = __idpf_adi_qid_reg_init(priv->qinfo.txq,
						       IDPF_MAX_QIDS,
						       q_type, chunks);

	q_type = VIRTCHNL2_QUEUE_TYPE_RX;
	priv->qinfo.num_rxqs = __idpf_adi_qid_reg_init(priv->qinfo.rxq,
						       IDPF_MAX_QIDS,
						       q_type, chunks);

	q_type = VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
	priv->qinfo.num_complqs =
			__idpf_adi_qid_reg_init(priv->qinfo.complq,
						IDPF_MAX_QIDS,
						q_type, chunks);

	q_type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
	priv->qinfo.num_bufqs = __idpf_adi_qid_reg_init(priv->qinfo.bufq,
							IDPF_MAX_QIDS,
							q_type, chunks);

	return 0;
}

/**
 * idpf_adi_prep_vec_chunks - Prepare vector chunks which needs to be sent
 * @adi: ADI pointer
 * @vc_cadi: Pointer to virtchannel create ADI
 *
 * Prepare vector chunks which will be sent as part of Create ADI
 * Returns 0 on success, negative if all the vectors are not initialized.
 */
static int idpf_adi_prep_vec_chunks(struct idpf_adi *adi,
				    struct virtchnl2_create_adi *vc_cadi)
{
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);
	int num_vecs = priv->vec_info.num_vectors;
	int vecid_filled = 0, vec_index = 0;
	int i = 0, j = 0;

	/* Take out vector_index and num_vecs for mailbox in ADI */
	vec_index++;
	num_vecs--;
	while (vecid_filled < num_vecs) {
		int index, each_chunk_vectors = 1;
		int next_phys_vec, phys_vec;

		/* Start for data queues */
		index = priv->vec_info.vec_indexes[vec_index + vecid_filled];
		phys_vec = priv->adapter->msix_entries[index].entry;
		vc_cadi->vchunks.vchunks[j].start_vector_id =
			cpu_to_le16(phys_vec);

		/* Set the relative EVVID to be used by VDEV.  It is set to 1
		 * as the mailbox is starting at zero.
		 */
		if (!j)
			vc_cadi->vchunks.vchunks[j].start_evv_id =
				cpu_to_le16(1);
		priv->vec_info.data_q_vec_ids[i] = phys_vec;
		while (1) {
			phys_vec++;
			vecid_filled++;
			index = priv->vec_info.vec_indexes[vec_index +
							   vecid_filled];
			next_phys_vec =
				priv->adapter->msix_entries[index].entry;
			if (vecid_filled != num_vecs &&
			    phys_vec == next_phys_vec) {
				each_chunk_vectors++;
				i++;
				priv->vec_info.data_q_vec_ids[i] = phys_vec;
				continue;
			}
			break;
		}
		vc_cadi->vchunks.vchunks[j].num_vectors =
			cpu_to_le16(each_chunk_vectors);
		if (vecid_filled < num_vecs)
			j++;
	}
	vc_cadi->vchunks.num_vchunks = cpu_to_le16(++j);

	return 0;
}

/**
 * idpf_adi_create - send create ADI message
 * @adi: ADI pointer
 * @pasid: pasid value
 *
 * Return 0 for success, negative for failure
 */
static int idpf_adi_create(struct idpf_adi *adi, u32 pasid)
{
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);
	struct virtchnl2_create_adi *vchnl_adi;
	int err = 0;

	vchnl_adi = kzalloc(IDPF_DFLT_MBX_BUF_SIZE, GFP_KERNEL);
	if (!vchnl_adi)
		return -ENOMEM;

	/* prepare mbx message */
	vchnl_adi->mbx_vec_id = cpu_to_le16(priv->vec_info.mbx_vec_id);
	vchnl_adi->mbx_id = cpu_to_le16(USE_HW_MBX_ID);
	vchnl_adi->pasid = cpu_to_le32(pasid);
	idpf_adi_prep_vec_chunks(adi, vchnl_adi);

	err = idpf_send_create_adi_msg(priv->adapter, vchnl_adi);
	if (err) {
		struct device *dev = &priv->adapter->pdev->dev;
		dev_err(dev, "CREATE_ADI message failed: %d\n", err);
		goto out;
	}

	/* current implementation may return -1 on error */
	if (le16_to_cpu(vchnl_adi->mbx_id) < 0) {
		err = -ENODEV;
		goto out;
	}

	priv->mbx_id = le16_to_cpu(vchnl_adi->mbx_id);
	priv->adi_id = le16_to_cpu(vchnl_adi->adi_id);
	idpf_adi_qid_reg_init(adi, vchnl_adi);

out:
	kfree(vchnl_adi);
	return err;
}

/**
 * idpf_adi_destroy - send destroy ADI message
 * @adi: ADI pointer
 *
 * Return 0 for success, negative for failure
 */
static int idpf_adi_destroy(struct idpf_adi *adi)
{
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);
	struct virtchnl2_destroy_adi vchnl_adi;
	struct idpf_vector_info vec_info;
	int num_vec_indx;

	vchnl_adi.adi_id = cpu_to_le16(priv->adi_id);

	vec_info.num_req_vecs = 0;
	vec_info.num_curr_vecs = IDPF_MAX_ADI_VEC;
	vec_info.index = 0;
	vec_info.default_vport = false;
	num_vec_indx = idpf_req_rel_vector_indexes(priv->adapter,
						   priv->vec_info.vec_indexes,
						   &vec_info);

	if (num_vec_indx <= 0) {
		dev_err(&priv->adapter->pdev->dev,
			"Could not release vectors for ADI\n");
	}

	return idpf_send_destroy_adi_msg(priv->adapter, &vchnl_adi);
}

/**
 * idpf_adi_config - Configure ADI
 * @adi: ADI pointer
 * @pasid: pasid value
 * @ena: enable or disable bool
 *
 * Return 0 for success, negative for failure
 */
static int idpf_adi_config(struct idpf_adi *adi, u32 pasid, bool ena)
{
	if (ena)
		return idpf_adi_create(adi, pasid);
	else
		return idpf_adi_destroy(adi);
}

/**
 * idpf_adi_read_reg32 - read ADI register
 * @adi: ADI pointer
 * @offs: register offset
 *
 * Return register value at the offset
 */
static u32 idpf_adi_read_reg32(struct idpf_adi *adi, size_t offs)
{
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);
	struct idpf_adapter *adapter;
	struct idpf_hw *hw;

	adapter = priv->adapter;
	hw = &adapter->hw;
	switch (offs) {
	case VFGEN_RSTAT:
		return IDPF_RESET_DONE;
	case VF_ATQBAL:
		return readl(idpf_get_reg_addr(adapter, PF_MBX_ATQBAL(priv->mbx_id)));
	case VF_ATQBAH:
		return readl(idpf_get_reg_addr(adapter, PF_MBX_ATQBAH(priv->mbx_id)));
	case VF_ATQLEN:
		return readl(idpf_get_reg_addr(adapter, PF_MBX_ATQLEN(priv->mbx_id)));
	case VF_ATQH:
		return readl(idpf_get_reg_addr(adapter, PF_MBX_ATQH(priv->mbx_id)));
	case VF_ATQT:
		return readl(idpf_get_reg_addr(adapter, PF_MBX_ATQT(priv->mbx_id)));
	case VF_ARQBAL:
		return readl(idpf_get_reg_addr(adapter, PF_MBX_ARQBAL(priv->mbx_id)));
	case VF_ARQBAH:
		return readl(idpf_get_reg_addr(adapter, PF_MBX_ARQBAH(priv->mbx_id)));
	case VF_ARQLEN:
		return readl(idpf_get_reg_addr(adapter, PF_MBX_ARQLEN(priv->mbx_id)));
	case VF_ARQH:
		return readl(idpf_get_reg_addr(adapter, PF_MBX_ARQH(priv->mbx_id)));
	case VF_ARQT:
		return readl(idpf_get_reg_addr(adapter, PF_MBX_ARQT(priv->mbx_id)));
	default:
		return 0xdeadbeef;
	}
}

/**
 * idpf_adi_write_reg32 - write ADI register
 * @adi: ADI pointer
 * @offs: register offset
 * @data: register value
 */
static void idpf_adi_write_reg32(struct idpf_adi *adi, size_t offs, u32 data)
{
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);
	struct idpf_adapter *adapter;
	struct idpf_hw *hw;
	int index;

	adapter = priv->adapter;
	hw = &adapter->hw;
	switch (offs) {
	case VF_ATQBAL:
		writel(data, idpf_get_reg_addr(adapter, PF_MBX_ATQBAL(priv->mbx_id)));
		break;
	case VF_ATQBAH:
		writel(data, idpf_get_reg_addr(adapter, PF_MBX_ATQBAH(priv->mbx_id)));
		break;
	case VF_ATQLEN:
		writel(data, idpf_get_reg_addr(adapter, PF_MBX_ATQLEN(priv->mbx_id)));
		break;
	case VF_ATQH:
		writel(data, idpf_get_reg_addr(adapter, PF_MBX_ATQH(priv->mbx_id)));
		break;
	case VF_ATQT:
		writel(data, idpf_get_reg_addr(adapter, PF_MBX_ATQT(priv->mbx_id)));
		break;
	case VF_ARQBAL:
		writel(data, idpf_get_reg_addr(adapter, PF_MBX_ARQBAL(priv->mbx_id)));
		break;
	case VF_ARQBAH:
		writel(data, idpf_get_reg_addr(adapter, PF_MBX_ARQBAH(priv->mbx_id)));
		break;
	case VF_ARQLEN:
		writel(data, idpf_get_reg_addr(adapter, PF_MBX_ARQLEN(priv->mbx_id)));
		break;
	case VF_ARQH:
		writel(data, idpf_get_reg_addr(adapter, PF_MBX_ARQH(priv->mbx_id)));
		break;
	case VF_ARQT:
		writel(data, idpf_get_reg_addr(adapter, PF_MBX_ARQT(priv->mbx_id)));
		break;
	case VF_INT_DYN_CTL0:
		writel(data, idpf_get_reg_addr(adapter,
					       PF_GLINT_DYN_CTL(priv->vec_info.mbx_vec_id)));
		break;
	case VF_QRX_TAIL_EXT(0) ... VF_QRX_TAIL_EXT(255):
		index = (offs - VF_QRX_TAIL_EXT(0)) / 4;
		if (index > priv->qinfo.num_rxqs)
			goto err;
		index = priv->qinfo.rxq[index].qid;
		writel(data, idpf_get_reg_addr(adapter, PF_QRX_TAIL(index)));
		break;
	case VF_QRXB_TAIL(0) ... VF_QRXB_TAIL(255):
		index = (offs - VF_QRXB_TAIL(0)) / 4;
		if (index > priv->qinfo.num_bufqs)
			goto err;
		index = priv->qinfo.bufq[index].qid;
		writel(data, idpf_get_reg_addr(adapter, PF_QRX_BUFFQ_TAIL(index)));
		break;
	case VF_QTX_TAIL_EXT(0) ... VF_QTX_TAIL_EXT(255):
		index = (offs - VF_QTX_TAIL_EXT(0)) / 4;
		if (index > priv->qinfo.num_txqs)
			goto err;
		index = priv->qinfo.txq[index].qid;
		writel(data, idpf_get_reg_addr(adapter, PF_QTX_COMM_DBELL(index)));
		break;
	case VF_INT_DYN_CTLN(0) ... VF_INT_DYN_CTLN(255):
		index = (offs - VF_INT_DYN_CTLN(0)) / 4;
		index = priv->vec_info.data_q_vec_ids[index];
		writel(data, idpf_get_reg_addr(adapter, PF_GLINT_DYN_CTL(index)));
		break;
	default:
		break;
	}
	return;
err:
	dev_err(&adapter->pdev->dev,
		"Invalid resource access by ADI at 0x%lx\n", offs);
}

/**
 * idpf_adi_get_num_of_vectors - get number of vectors assigned to this ADI
 * @adi: ADI pointer
 *
 * Return 0 or postive for success, negative for failure
 */
static int idpf_adi_get_num_of_vectors(struct idpf_adi *adi)
{
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);

	return priv->vec_info.num_vectors;
}

/**
 * idpf_adi_get_irq_num - get OS IRQ number per vector
 * @adi: ADI pointer
 * @vector: IRQ vector index
 *
 * Return 0 or postive for success, negative for failure
 */
static int idpf_adi_get_irq_num(struct idpf_adi *adi, u32 vector)
{
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);
	struct msix_entry *entry;
	int vec;

	if (vector >= priv->vec_info.num_vectors)
		return -EINVAL;

	vec = priv->vec_info.vec_indexes[vector];
	entry = &priv->adapter->msix_entries[vec];

	return entry->vector;
}

/**
 * idpf_adi_init_resources - Check resources if they are available
 * @adapter: pointer to adapter structure
 *
 * Return allocated ADI structure
 */
static struct idpf_adi *idpf_adi_init_resources(struct idpf_adapter *adapter)
{
	struct idpf_vector_info vec_info;
	struct idpf_adi_priv *priv;
	int filled_slots = 0;
	int i = 0, j = 0;
	int num_vec_indx;

	/* Check how many ADIs are free to use */
	while (j < IDPF_MAX_ADI_NUM) {
		if (adapter->adi_ena[j])
			filled_slots++;
		j++;
	}

	/* Max number of ADIs reached */
	if (filled_slots == IDPF_MAX_ADI_NUM) {
		dev_err(&adapter->pdev->dev,
			"Maximum number of ADIs (%d) have been reached\n",
			filled_slots);
		return NULL;
	}

	/* Factor in for the current ADI being created */
	filled_slots++;

	/* Get the next free slot to get index */
	while (i < IDPF_MAX_ADI_NUM) {
		if (!adapter->adi_ena[i])
			break;
		i++;
	}
	adapter->adi_ena[i] = true;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->adapter = adapter;
	priv->adi_idx = i;

	vec_info.num_req_vecs = IDPF_MAX_ADI_VEC;
	vec_info.num_curr_vecs = priv->vec_info.num_vectors;
	vec_info.index = 0;
	vec_info.default_vport = false;
	num_vec_indx = idpf_req_rel_vector_indexes(adapter,
						   priv->vec_info.vec_indexes,
						   &vec_info);
	/* As long as we have 1 vector for mailbox we are ok to go ahead */
	if (num_vec_indx <= 0) {
		dev_err(&adapter->pdev->dev,
			"Could not get requested number of vectors\n");
		kfree(priv);
		return NULL;
	}

	/* configure the ADI IRQ parameters */
	priv->vec_info.num_vectors = num_vec_indx;
	priv->vec_info.mbx_vec_id =
		adapter->msix_entries[priv->vec_info.vec_indexes[0]].entry;

	return &priv->adi;
}

/**
 * idpf_adi_get_sparse_mmap_num - get number of sparse memory
 * @adi: pointer to assignable device interface
 *
 * Return number of sparse memory areas.
 */
static int idpf_adi_get_sparse_mmap_num(struct idpf_adi *adi)
{
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);

	return priv->qinfo.num_txqs + priv->qinfo.num_rxqs +
	       priv->qinfo.num_bufqs + priv->vec_info.num_vectors +
	       IDPF_MBX_Q_VEC;
}

/**
 * ice_adi_get_sparse_mmap_area - get sparse memory layout for mmap
 * @adi: pointer to assignable device interface
 * @index: index of sparse memory
 * @offset: pointer to sparse memory areas offset
 * @size: pointer to sparse memory areas size
 *
 * Return 0 if success, negative for failure.
 */
static int
idpf_adi_get_sparse_mmap_area(struct idpf_adi *adi, u64 index,
			      u64 *offset, u64 *size)
{
	struct idpf_adi_sparse_mmap_info pattern[IDPF_ADI_SPARSE_MAX];
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);
	int nr_areas;
	u32 i;

	nr_areas = idpf_adi_get_sparse_mmap_num(adi);

	if (nr_areas <= 0 || index > nr_areas - 1)
		return -EINVAL;

	i = IDPF_ADI_SPARSE_MBX;
	pattern[i].start = 0;
	pattern[i].cnt = 1;
	pattern[i].end = pattern[i].start + pattern[i].cnt;
	pattern[i].phy_addr = VDEV_MBX_START;

	i = IDPF_ADI_SPARSE_RXQ;
	pattern[i].start = pattern[i - 1].end;
	pattern[i].cnt = priv->qinfo.num_rxqs;
	pattern[i].end = pattern[i].start + pattern[i].cnt;
	pattern[i].phy_addr = VDEV_QRX_TAIL_START;

	i = IDPF_ADI_SPARSE_RX_BUFQ;
	pattern[i].start = pattern[i - 1].end;
	pattern[i].cnt = priv->qinfo.num_bufqs;
	pattern[i].end = pattern[i].start + pattern[i].cnt;
	pattern[i].phy_addr = VDEV_QRX_BUFQ_TAIL_START;

	i = IDPF_ADI_SPARSE_TXQ;
	pattern[i].start = pattern[i - 1].end;
	pattern[i].cnt = priv->qinfo.num_txqs;
	pattern[i].end = pattern[i].start + pattern[i].cnt;
	pattern[i].phy_addr = VDEV_QTX_TAIL_START;

	i = IDPF_ADI_SPARSE_DYN_CTL01;
	pattern[i].start = pattern[i - 1].end;
	if (priv->vec_info.num_vectors >= IDPF_MBX_Q_VEC)
		pattern[i].cnt = IDPF_MBX_Q_VEC;
	else
		pattern[i].cnt = 0;
	pattern[i].end = pattern[i].start + pattern[i].cnt;
	pattern[i].phy_addr = VDEV_INT_DYN_CTL01;

	i = IDPF_ADI_SPARSE_DYN_CTL;
	pattern[i].start = pattern[i - 1].end;
	if (priv->vec_info.num_vectors > IDPF_MBX_Q_VEC)
		pattern[i].cnt = priv->vec_info.num_vectors - IDPF_MBX_Q_VEC;
	else
		pattern[i].cnt = 0;
	pattern[i].end = pattern[i].start + pattern[i].cnt;
	pattern[i].phy_addr = VDEV_INT_DYN_CTL(0);

	for (i = 0; i < IDPF_ADI_SPARSE_MAX; i++) {
		if (pattern[i].cnt &&
		    index >= pattern[i].start &&
		    index < pattern[i].end) {
			*offset = pattern[i].phy_addr +
					PAGE_SIZE * (index - pattern[i].start);
			*size   = PAGE_SIZE;
			break;
		}
	}

	return (i == IDPF_ADI_SPARSE_MAX) ? -EINVAL : 0;
}

/**
 * idpf_adi_get_sparse_mmap_hpa - get page aligned register's HPA
 * @adi: pointer to assignable device interface
 * @index: VFIO BAR index
 * @vm_pgoff: page offset of virtual memory area
 * @addr: VDEV address
 *
 * Return 0 if success, negative for failure.
 */
static int
idpf_adi_get_sparse_mmap_hpa(struct idpf_adi *adi, u32 index, u64 vm_pgoff,
			     u64 *addr)
{
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);
	u64 reg_off;
	u32 idx;

	if (!addr || index != VFIO_PCI_BAR0_REGION_INDEX)
		return -EINVAL;

	switch (vm_pgoff) {
	case PHYS_PFN(VDEV_MBX_START):
		/* MBX Registers */
		reg_off = PF_MBX_ARQBAL(priv->mbx_id);
		break;
	case PHYS_PFN(VDEV_QRX_TAIL_START) ...
				(PHYS_PFN(VDEV_QRX_BUFQ_TAIL_START) - 1):
		/* RX tail register */
		idx = vm_pgoff - PHYS_PFN(VDEV_QRX_TAIL_START);
		if (idx >= priv->qinfo.num_rxqs)
			return -EINVAL;
		reg_off = PF_QRX_BUFFQ_TAIL(priv->qinfo.rxq[idx].qid);
		break;
	case PHYS_PFN(VDEV_QRX_BUFQ_TAIL_START) ...
					(PHYS_PFN(VDEV_QTX_TAIL_START) - 1):
		/* RX BUFQ tail register */
		idx = vm_pgoff - PHYS_PFN(VDEV_QRX_BUFQ_TAIL_START);
		if (idx >= priv->qinfo.num_bufqs)
			return -EINVAL;
		reg_off = PF_QRX_BUFFQ_TAIL(priv->qinfo.bufq[idx].qid);
		break;
	case PHYS_PFN(VDEV_QTX_TAIL_START) ...
				(PHYS_PFN(VDEV_QTX_COMPL_TAIL_START) - 1):
		/* TX COMPL tail register */
		idx = vm_pgoff - PHYS_PFN(VDEV_QTX_TAIL_START);
		if (idx >= priv->qinfo.num_txqs)
			return -EINVAL;
		reg_off = PF_QTX_COMM_DBELL(priv->qinfo.txq[idx].qid);
		break;
	case PHYS_PFN(VDEV_INT_DYN_CTL01):
		/* INT DYN CTL01, ITR0/1/2 */
		if (priv->vec_info.num_vectors == 0)
			return -EINVAL;
		reg_off = PF_GLINT_DYN_CTL(priv->vec_info.mbx_vec_id);
		break;
	case PHYS_PFN(VDEV_INT_DYN_CTL(0)) ...
					(PHYS_PFN(IDPF_VDCM_BAR0_SIZE) - 1):
		/* INT DYN CTL, ITR0/1/2
		 * the first several vectors in q_vectors[] is for mailbox,
		 * mailbox vector's number is defined with IDPF_MBX_Q_VEC
		 */
		idx = vm_pgoff - PHYS_PFN(VDEV_INT_DYN_CTL(0));
		if (idx + IDPF_MBX_Q_VEC >= priv->vec_info.num_vectors)
			return -EINVAL;
		reg_off = PF_GLINT_DYN_CTL(priv->vec_info.data_q_vec_ids[idx]);
		break;
	default:
		return -EFAULT;
	}

	/* add BAR0 start address */
	*addr = pci_resource_start(priv->adapter->pdev, 0) + reg_off;
	return 0;
}

/**
 * idpf_vdcm_alloc_adi - alloc one ADI
 * @dev: linux device associated with ADI
 *
 * Return Non zero pointer for success, NULL for failure
 */
struct idpf_adi *idpf_vdcm_alloc_adi(struct device *dev)
{
	struct idpf_adapter *adapter;
	struct idpf_adi *adi;

	adapter = pci_get_drvdata(to_pci_dev(dev));

	adi = idpf_adi_init_resources(adapter);
	if (!adi)
		return NULL;

	adi->config = idpf_adi_config;
	adi->reset = idpf_adi_reset;
	adi->read_reg32 = idpf_adi_read_reg32;
	adi->write_reg32 = idpf_adi_write_reg32;
	adi->get_num_of_vectors = idpf_adi_get_num_of_vectors;
	adi->get_irq_num = idpf_adi_get_irq_num;
	adi->get_sparse_mmap_num = idpf_adi_get_sparse_mmap_num;
	adi->get_sparse_mmap_area = idpf_adi_get_sparse_mmap_area;
	adi->get_sparse_mmap_hpa = idpf_adi_get_sparse_mmap_hpa;

	return adi;
}

/**
 * idpf_vdcm_free_adi - free ADI
 * @adi: ADI pointer
 */
void idpf_vdcm_free_adi(struct idpf_adi *adi)
{
	struct idpf_adi_priv *priv = idpf_get_adi_priv(adi);

	priv->adapter->adi_ena[priv->adi_idx] = false;
	kfree(priv);
}
