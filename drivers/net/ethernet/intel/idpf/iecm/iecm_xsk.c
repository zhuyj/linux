// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2021 Intel Corporation */

#include "iecm.h"
#ifdef HAVE_NETDEV_BPF_XSK_POOL

/**
 * iecm_xsk_pool_disable - disables a BUFF POOL region
 * @vport: vport to allocate the buffer pool on
 * @qid: queue id
 *
 * Returns 0 on success, negative on error
 */
static int iecm_xsk_pool_disable(struct iecm_vport *vport, u16 qid)
{
	struct xsk_buff_pool *pool;

	if (!vport->rxq_grps)
		return -EINVAL;

	pool = xsk_get_pool_from_qid(vport->netdev, qid);
	if (!pool)
		return -EINVAL;

	xsk_pool_dma_unmap(pool, IECM_RX_DMA_ATTR);

	return 0;
}

/**
 * iecm_xsk_pool_enable - enables a BUFF POOL region
 * @vport: vport to allocate the buffer pool on
 * @pool: pointer to a requested BUFF POOL region
 * @qid: queue id
 *
 * Returns 0 on success, negative on error
 */
static int iecm_xsk_pool_enable(struct iecm_vport *vport, struct xsk_buff_pool *pool, u16 qid)
{
	if (qid >= vport->netdev->real_num_rx_queues ||
	    qid >= vport->netdev->real_num_tx_queues)
		return -EINVAL;

	return xsk_pool_dma_map(pool, &vport->adapter->pdev->dev, IECM_RX_DMA_ATTR);
}

/**
 * iecm_xsk_pool_setup - enable/disable a BUFF POOL region
 * @vport: current vport of interest
 * @pool: pointer to a requested BUFF POOL region
 * @qid: queue id
 *
 * Returns 0 on success, negative on failure
 */
int iecm_xsk_pool_setup(struct iecm_vport *vport, struct xsk_buff_pool *pool, u16 qid)
{
	bool pool_present = !!pool;
	int pool_failure = 0;

	if (!vport)
		return -EINVAL;

	pool_failure = pool_present ? iecm_xsk_pool_enable(vport, pool, qid) :
				      iecm_xsk_pool_disable(vport, qid);

	if (pool_failure) {
		netdev_err(vport->netdev, "Could not %sable BUFF POOL, error = %d\n",
			   pool_present ? "en" : "dis", pool_failure);
		return pool_failure;
	}

	if (!iecm_xdp_is_prog_ena(vport))
		netdev_warn(vport->netdev, "RSS may schedule pkts to q occupied by AF XDP\n");

	return iecm_initiate_soft_reset(vport, __IECM_SR_Q_CHANGE);
}

/**
 * iecm_xmit_splitq_zc - Sends AF_XDP entries, and cleans XDP entries
 * @xdpq: XDP Tx queue
 * @budget: max number of frames to xmit
 *
 * Returns true if the given budget is not fully exhausted, so there are
 * no more frames to be sent, false otherwise, what means that napi_schedule
 * shall be requested because some frames have not been transmitted yet.
 */
static bool
iecm_xmit_splitq_zc(struct iecm_queue *xdpq, int budget)
{
	struct iecm_tx_splitq_params tx_parms = {
		NULL, (enum iecm_tx_desc_dtype_value)0, 0, {0}, {0}
	};
	union iecm_tx_flex_desc *tx_desc = NULL;
	u16 ntu = xdpq->next_to_use;
	struct xdp_desc desc;
	dma_addr_t dma;

	while (likely(budget-- > 0)) {
		struct iecm_tx_buf *tx_buf;

		tx_buf = &xdpq->tx_buf[ntu];

		if (!xsk_tx_peek_desc(xdpq->xsk_pool, &desc))
			break;

		dma = xsk_buff_raw_get_dma(xdpq->xsk_pool, desc.addr);
		xsk_buff_raw_dma_sync_for_device(xdpq->xsk_pool, dma,
						 desc.len);
		tx_buf->bytecount = desc.len;

		tx_parms.compl_tag = xdpq->tx_buf_key;

		tx_desc = IECM_FLEX_TX_DESC(xdpq, ntu);
		tx_desc->q.buf_addr = cpu_to_le64(dma);

		tx_parms.dtype = IECM_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2;
		tx_parms.splitq_build_ctb = iecm_tx_splitq_build_ctb;
		tx_parms.eop_cmd = IECM_TX_DESC_CMD_EOP;

		tx_parms.splitq_build_ctb(tx_desc, &tx_parms, tx_parms.eop_cmd |
					  tx_parms.offload.td_cmd, desc.len);

		ntu++;
		if (ntu == xdpq->desc_count)
			ntu = 0;

		tx_buf->compl_tag = tx_parms.compl_tag++;
		xdpq->tx_buf_key = tx_parms.compl_tag;
	}

	if (likely(tx_desc)) {
		xdpq->next_to_use = ntu;

		/* Set RS bit for the last frame and bump tail ptr */
		tx_parms.eop_cmd |= IECM_TX_DESC_CMD_RS;
		tx_parms.splitq_build_ctb(tx_desc, &tx_parms,
					  tx_parms.eop_cmd | tx_parms.offload.td_cmd, desc.len);

		iecm_xdpq_update_tail(xdpq);
		xsk_tx_release(xdpq->xsk_pool);
	}

	return budget > 0;
}

/**
 * iecm_xmit_singleq_zc - Sends AF_XDP entries, and cleans XDP entries
 * @xdpq: XDP Tx queue
 * @budget: max number of frames to xmit
 *
 * Returns true if the given budget is not fully exhausted, so there are
 * no more frames to be sent, false otherwise, what means that napi_schedule
 * shall be requested because some frames have not been transmitted yet.
 */
static bool
iecm_xmit_singleq_zc(struct iecm_queue *xdpq, int budget)
{
	struct iecm_base_tx_desc *tx_desc = NULL;
	u16 ntu = xdpq->next_to_use;
	struct xdp_desc desc;
	dma_addr_t dma;
	u64 td_cmd;

	while (likely(budget-- > 0)) {
		struct iecm_tx_buf *tx_buf;

		tx_buf = &xdpq->tx_buf[ntu];

		if (!xsk_tx_peek_desc(xdpq->xsk_pool, &desc))
			break;

		dma = xsk_buff_raw_get_dma(xdpq->xsk_pool, desc.addr);
		xsk_buff_raw_dma_sync_for_device(xdpq->xsk_pool, dma,
						 desc.len);
		tx_buf->bytecount = desc.len;

		tx_desc = IECM_BASE_TX_DESC(xdpq, ntu);
		tx_desc->buf_addr = cpu_to_le64(dma);

		td_cmd = IECM_TX_DESC_CMD_EOP;
		tx_desc->qw1 = iecm_tx_singleq_build_ctob(td_cmd, 0x0, desc.len, 0);

		xdpq->xdp_next_rs_idx = ntu;
		ntu++;
		if (ntu == xdpq->desc_count)
			ntu = 0;
	}

	if (likely(tx_desc)) {
		xdpq->next_to_use = ntu;

		/* Set RS bit for the last frame and bump tail ptr */
		td_cmd |= IECM_TX_DESC_CMD_RS;
		tx_desc->qw1 = iecm_tx_singleq_build_ctob(td_cmd, 0x0, desc.len, 0);

		iecm_xdpq_update_tail(xdpq);
		xsk_tx_release(xdpq->xsk_pool);
	}

	return budget > 0;
}

/**
 * iecm_clean_xdp_tx_buf - Free and unmap XDP Tx buffer
 * @xdpq: XDP Tx queue
 * @tx_buf: Tx buffer to clean
 */
static void
iecm_clean_xdp_tx_buf(struct iecm_queue *xdpq, struct iecm_tx_buf *tx_buf)
{
#ifdef HAVE_XDP_FRAME_STRUCT
	xdp_return_frame(tx_buf->xdpf);
#else
	xdp_return_frame((struct xdp_frame *)tx_buf->raw_buf);
#endif
	xdpq->xdp_tx_active--;
	dma_unmap_single(xdpq->dev, dma_unmap_addr(tx_buf, dma),
			 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
	dma_unmap_len_set(tx_buf, len, 0);
}

/**
 * iecm_tx_clean_zc - Completes AF_XDP entries, and cleans XDP entries
 *		      (implementation of common part for singleq and splitq modes).
 * @xdpq: AF XDP Tx queue to clean
 * @ntc: Index of the next Tx buffer that shall be cleaned.
 * @clean_count: number of ready Tx frames that should be cleaned.
 *
 * Returns the structure containing the number of bytes and packets cleaned.
 */
static struct iecm_tx_queue_stats
iecm_tx_clean_zc(struct iecm_queue *xdpq, u16 ntc, u16 clean_count)
{
	struct iecm_tx_queue_stats cleaned_stats = {0};
	struct iecm_tx_buf *tx_buf;
	u32 xsk_frames = 0;
	u16 i;

	if (!clean_count)
		goto out;

	if (likely(!xdpq->xdp_tx_active)) {
		xsk_frames = clean_count;
		goto skip;
	}

	for (i = 0; i < clean_count; i++) {
		tx_buf = &xdpq->tx_buf[ntc];

#ifdef HAVE_XDP_FRAME_STRUCT
		if (tx_buf->xdpf) {
#else
		if (tx_buf->raw_buf) {
#endif
			iecm_clean_xdp_tx_buf(xdpq, tx_buf);
#ifdef HAVE_XDP_FRAME_STRUCT
			tx_buf->xdpf = NULL;
#else
			tx_buf->raw_buf = NULL;
#endif
			cleaned_stats.bytes += tx_buf->bytecount;
		} else {
			xsk_frames++;
		}

		++ntc;
		if (unlikely(ntc >= xdpq->desc_count))
			ntc = 0;
	}
skip:
	xdpq->next_to_clean += clean_count;
	if (unlikely(xdpq->next_to_clean >= xdpq->desc_count))
		xdpq->next_to_clean -= xdpq->desc_count;

	if (xsk_frames) {
		xsk_tx_completed(xdpq->xsk_pool, xsk_frames);
		cleaned_stats.bytes += (xsk_frames * xdpq->xsk_pool->frame_len);
	}

	cleaned_stats.packets += clean_count;
out:
	return cleaned_stats;
}

/**
 * iecm_prepare_for_xmit_zc - Prepare XSK pool to perform AF_XDP Tx action
 *			      including computing the Tx budget.
 * @xdpq: AF XDP Tx queue used to xmit
 *
 * Returns the AF_XDP Tx budget.
 */
static u16
iecm_prepare_for_xmit_zc(struct iecm_queue *xdpq)
{
	u16 send_budget;
#ifdef HAVE_NDO_XSK_WAKEUP
	if (xsk_uses_need_wakeup(xdpq->xsk_pool))
		xsk_set_tx_need_wakeup(xdpq->xsk_pool);
#endif /* HAVE_NDO_XSK_WAKEUP */

	send_budget = min_t(u16, IECM_DESC_UNUSED(xdpq), xdpq->desc_count / 4);
	return send_budget;
}

/**
 * iecm_tx_splitq_clean_zc - Completes AF_XDP entries, and cleans XDP entries
 *			     in split queue mode
 * @xdpq: AF XDP Tx queue to clean
 * @end: queue index until which it should be cleaned
 *
 * Returns the structure containing the number of bytes and packets cleaned.
 */
struct iecm_tx_queue_stats
iecm_tx_splitq_clean_zc(struct iecm_queue *xdpq, u16 end)
{
	u16 ntc = xdpq->next_to_clean;
	u16 frames_ready = 0;

	if (end >= ntc)
		frames_ready = end - ntc;
	else
		frames_ready = end + xdpq->desc_count - ntc;

	return iecm_tx_clean_zc(xdpq, ntc, frames_ready);
}

/**
 * iecm_tx_singleq_clean_zc - Completes AF_XDP entries, and cleans XDP entries
 *			      in single queue mode
 * @xdpq: AF XDP Tx queue to clean
 *
 * Returns true if all AF_XDP frames have been successfully sent, false otherwise.
 */
bool
iecm_tx_singleq_clean_zc(struct iecm_queue *xdpq)
{
	u16 next_rs_idx = xdpq->xdp_next_rs_idx;
	struct iecm_base_tx_desc *next_rs_desc;
	u16 send_budget, frames_ready = 0;
	s16 ntc = xdpq->next_to_clean;

	next_rs_desc = IECM_BASE_TX_DESC(xdpq, next_rs_idx);
	if (next_rs_desc->qw1 &
	    cpu_to_le64(IECM_TX_DESC_DTYPE_DESC_DONE)) {
		if (next_rs_idx >= ntc)
			frames_ready = next_rs_idx - ntc;
		else
			frames_ready = next_rs_idx + xdpq->desc_count - ntc;
	}

	iecm_tx_clean_zc(xdpq, ntc, frames_ready);

	send_budget = iecm_prepare_for_xmit_zc(xdpq);
	return iecm_xmit_singleq_zc(xdpq, send_budget);
}

/**
 * iecm_tx_splitq_xmit_zc - Sends all unsent data in XDP ZC queue
 * @xdpq: AF XDP Tx queue to clean
 *
 * Returns true if transmission is done.
 */
bool
iecm_tx_splitq_xmit_zc(struct iecm_queue *xdpq)
{
	u16 send_budget = iecm_prepare_for_xmit_zc(xdpq);

	return iecm_xmit_splitq_zc(xdpq, send_budget);
}

/**
 * iecm_trigger_sw_intr - trigger a software interrupt
 * @hw: pointer to the HW structure
 * @q_vector: interrupt vector to trigger the software interrupt for
 */
static void
iecm_trigger_sw_intr(struct iecm_hw *hw, struct iecm_q_vector *q_vector)
{
	struct iecm_intr_reg *intr = &q_vector->intr_reg;
	u32 val;

	val = (VIRTCHNL2_ITR_IDX_NO_ITR << intr->dyn_ctl_itridx_s) |
	      intr->dyn_ctl_swint_trig_m | intr->dyn_ctl_intena_m;
	wr32(hw, intr->dyn_ctl, val);
}

/**
 * iecm_xsk_check_xmit_params - Implements ndo_xsk_wakeup for split queue
 * @vport: current vport of interest
 * @xdpq_idx: index of XDP Tx queue
 *
 * Returns negative error code on error, zero otherwise.
 */
static int
iecm_xsk_check_xmit_params(struct iecm_vport *vport, u32 xdpq_idx)
{
	if (unlikely(vport->adapter->state == __IECM_DOWN))
		return -ENETDOWN;

	if (unlikely(!iecm_xdp_is_prog_ena(vport)))
		return -ENXIO;

	if (unlikely(xdpq_idx >= vport->num_txq))
		return -ENXIO;

	if (unlikely(!vport->txqs[xdpq_idx]->xsk_pool))
		return -ENXIO;

	return 0;
}

/**
 * iecm_xsk_schedule_napi_for_xmit - Schedule SW interrupt for AF_XDP xmit
 * @vport: vport of intrest
 * @q_vector: interrupt vector to trigger the software interrupt for
 *
 */
static void
iecm_xsk_schedule_napi_for_xmit(struct iecm_vport *vport, struct iecm_q_vector *q_vector)
{
	/* The idea here is that if NAPI is running, mark a miss, so
	 * it will run again. If not, trigger an interrupt and
	 * schedule the NAPI from interrupt context. If NAPI would be
	 * scheduled here, the interrupt affinity would not be
	 * honored.
	 */
	if (!napi_if_scheduled_mark_missed(&q_vector->napi))
		iecm_trigger_sw_intr(&vport->adapter->hw, q_vector);
}

#ifdef HAVE_NDO_XSK_WAKEUP
/**
 * iecm_xsk_splitq_wakeup - Implements ndo_xsk_wakeup for split queue mode
 * @netdev: net_device
 * @q_id: queue to wake up
 * @flags: ignored in our case, since we have Rx and Tx in the same NAPI
 *
 * Returns negative value on error, zero otherwise.
 */
int
iecm_xsk_splitq_wakeup(struct net_device *netdev, u32 q_id,
		       u32 __always_unused flags)
#else
/**
 * iecm_xsk_splitq_async_xmit - Implements ndo_xsk_async_xmit for split queue mode
 * @netdev: net_device
 * @q_id: queue to wake up
 *
 * Returns negative value on error, zero otherwise.
 */
int iecm_xsk_splitq_async_xmit(struct net_device *netdev, u32 q_id)
#endif /* HAVE_NDO_XSK_WAKEUP */
{
	struct iecm_netdev_priv *np = netdev_priv(netdev);
	struct iecm_vport *vport = np->vport;
	struct iecm_q_vector *q_vector;
	struct iecm_queue *q;
	u32 idx;
	int ret;

	idx = q_id + vport->xdp_txq_offset;

	ret = iecm_xsk_check_xmit_params(vport, idx);
	if (unlikely(ret))
		goto exit;

	q = vport->txqs[idx];
	q_vector = q->txq_grp->complq->q_vector;

	iecm_xsk_schedule_napi_for_xmit(vport, q_vector);
exit:
	return ret;
}

#ifdef HAVE_NDO_XSK_WAKEUP
/**
 * iecm_xsk_singleq_wakeup - Implements ndo_xsk_wakeup for single queue mode
 * @netdev: net_device
 * @q_id: queue to wake up
 * @flags: ignored in our case, since we have Rx and Tx in the same NAPI
 *
 * Returns negative value on error, zero otherwise.
 */
int
iecm_xsk_singleq_wakeup(struct net_device *netdev, u32 q_id,
			u32 __always_unused flags)
#else
/**
 * iecm_xsk_singleq_async_xmit - Implements ndo_xsk_async_xmit for single queue mode
 * @netdev: net_device
 * @q_id: queue to wake up
 *
 * Returns negative value on error, zero otherwise.
 */
int iecm_xsk_singleq_async_xmit(struct net_device *netdev, u32 q_id)
#endif /* HAVE_NDO_XSK_WAKEUP */
{
	struct iecm_netdev_priv *np = netdev_priv(netdev);
	struct iecm_vport *vport = np->vport;
	struct iecm_q_vector *q_vector;
	struct iecm_queue *q;
	u32 idx;
	int ret;

	idx = q_id + vport->xdp_txq_offset;

	ret = iecm_xsk_check_xmit_params(vport, idx);
	if (unlikely(ret))
		goto exit;

	q = vport->txqs[idx];
	q_vector = q->q_vector;

	iecm_xsk_schedule_napi_for_xmit(vport, q_vector);
exit:
	return ret;
}

/**
 * iecm_xsk_cleanup_xdpq - remove Tx and Completion descriptors related to the XDP queue
 * @xdpq: pointer to XDP Tx queue
 */
void iecm_xsk_cleanup_xdpq(struct iecm_queue *xdpq)
{
	u16 ntc = xdpq->next_to_clean, ntu = xdpq->next_to_use;
	u32 xsk_frames = 0;

	while (ntc != ntu) {
		struct iecm_tx_buf *tx_buf = &xdpq->tx_buf[ntc];

#ifdef HAVE_XDP_FRAME_STRUCT
		if (tx_buf->xdpf)
#else
		if (tx_buf->raw_buf)
#endif
			iecm_clean_xdp_tx_buf(xdpq, tx_buf);
		else
			xsk_frames++;

#ifdef HAVE_XDP_FRAME_STRUCT
		tx_buf->xdpf = NULL;
#else
		tx_buf->raw_buf = NULL;
#endif

		ntc++;
		if (ntc >= xdpq->desc_count)
			ntc = 0;
	}

	if (xsk_frames)
		xsk_tx_completed(xdpq->xsk_pool, xsk_frames);
}

/**
 * iecm_rx_buf_hw_alloc_zc - allocate a single Rx buffer
 * @buf: receive buffer to allocate
 * @xsk_pool: pointer to AF_XDP pool
 *
 * Returns false if the allocation was successful, true if it failed.
 */
static bool iecm_rx_buf_hw_alloc_zc(struct iecm_rx_buf *buf, struct xsk_buff_pool *xsk_pool)
{
	buf->xdp = xsk_buff_alloc(xsk_pool);
	if (!buf->xdp)
		return true;

	buf->page_info[buf->page_indx].page_offset = 0;
	buf->page_info[buf->page_indx].dma = xsk_buff_xdp_get_dma(buf->xdp);

	return false;
}

/**
 * iecm_rx_splitq_buf_hw_alloc_zc_all - allocate a number of Rx buffers
 * @rx_bufq: receive buffer queue
 * @count: The number of buffers to allocate
 *
 * Returns false if all allocations were successful, true if any fail.
 */
bool iecm_rx_splitq_buf_hw_alloc_zc_all(struct iecm_queue *rx_bufq, u16 count)
{
	struct xsk_buff_pool *xsk_pool = rx_bufq->xsk_pool;
	u16 nta = rx_bufq->next_to_alloc;
	struct iecm_rx_buf *buf;
	bool ret = false;

	if (!count)
		return false;

	buf = &rx_bufq->rx_buf.buf[nta];

	do {
		ret = iecm_rx_buf_hw_alloc_zc(buf, xsk_pool);
		if (ret)
			break;

		buf++;
		nta++;

		if (unlikely(nta == rx_bufq->desc_count)) {
			buf = rx_bufq->rx_buf.buf;
			nta = 0;
		}

		count--;

	} while (count);

	return ret;
}

/**
 * iecm_rx_singleq_buf_hw_alloc_zc_all - allocate a number of Rx buffers
 * @rxq: receive queue
 * @count: The number of buffers to allocate
 *
 * Returns false if all allocations were successful, true if any fail.
 */
bool iecm_rx_singleq_buf_hw_alloc_zc_all(struct iecm_queue *rxq, u16 count)
{
	struct virtchnl2_singleq_rx_buf_desc *singleq_rx_desc = NULL;
	struct xsk_buff_pool *xsk_pool = rxq->xsk_pool;
	u16 nta = rxq->next_to_alloc;
	struct iecm_rx_buf *buf;

	/* do nothing if no valid netdev defined */
	if (!rxq->vport->netdev || !count)
		return false;

	singleq_rx_desc = IECM_SINGLEQ_RX_BUF_DESC(rxq, nta);
	buf = &rxq->rx_buf.buf[nta];

	do {
		if (iecm_rx_buf_hw_alloc_zc(buf, xsk_pool))
			break;

		/* Refresh the desc even if buffer_addrs didn't change
		 * because each write-back erases this info.
		 */
		singleq_rx_desc->pkt_addr = cpu_to_le64(buf->page_info[buf->page_indx].dma);
		singleq_rx_desc->hdr_addr = 0;
		singleq_rx_desc++;

		buf++;
		nta++;
		if (unlikely(nta == rxq->desc_count)) {
			singleq_rx_desc = IECM_SINGLEQ_RX_BUF_DESC(rxq, 0);
			buf = rxq->rx_buf.buf;
			nta = 0;
		}

		count--;
	} while (count);

	if (rxq->next_to_alloc != nta) {
		iecm_rx_buf_hw_update(rxq, nta);
		rxq->next_to_alloc = nta;
	}

	return !!count;
}

/**
 * iecm_rx_buf_rel_zc - Free AF_XDP Rx buffer
 * @buf: receive buffer to be released
 */
void iecm_rx_buf_rel_zc(struct iecm_rx_buf *buf)
{
	if (!buf->xdp)
		return;

	xsk_buff_free(buf->xdp);
	buf->xdp = NULL;
}

/**
 * iecm_run_xdp_zc - Executes an XDP program on initialized xdp_buff
 * @rxq: Rx queue
 * @xdpq: XDP Tx queue
 * @xdp: xdp_buff used as input to the XDP program
 *
 * Returns IECM_XDP_PASS for packets to be sent up the stack, IECM_XDP_CONSUMED
 * otherwise.
 */
static int
iecm_run_xdp_zc(struct iecm_queue *rxq, struct iecm_queue *xdpq, struct xdp_buff *xdp)
{
	int err, result = IECM_XDP_PASS;
	struct bpf_prog *xdp_prog;
	u32 act;

	/* ZC path is enabled only when XDP program is set, no need to check for NULL */
	xdp_prog = READ_ONCE(rxq->xdp_prog);
	act = bpf_prog_run_xdp(xdp_prog, xdp);

	if (likely(act == XDP_REDIRECT)) {
		err = xdp_do_redirect(rxq->vport->netdev, xdp, xdp_prog);
		if (err)
			goto out_failure;
		return IECM_XDP_REDIR;
	}

	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
		result = iecm_xmit_xdpq(xdp_convert_buff_to_frame(xdp), xdpq);
		if (result == IECM_XDP_CONSUMED)
			goto out_failure;
		break;
	default:
		bpf_warn_invalid_xdp_action(rxq->vport->netdev, xdp_prog, act);
		fallthrough; /* not supported action */
	case XDP_ABORTED:
out_failure:
		trace_xdp_exception(rxq->vport->netdev, xdp_prog, act);
		fallthrough; /* handle aborts by dropping frame */
	case XDP_DROP:
		return IECM_XDP_CONSUMED;
	}

	return result;
}

/**
 * iecm_rx_construct_skb_zc - Create an skb from zero-copy buffer
 * @rxq: Rx descriptor queue
 * @rx_buf: Rx buffer to pull data from
 * @size: the length of the packet
 *
 * This function allocates a new skb from a zero-copy Rx buffer.
 *
 * Returns the skb on success, NULL on failure.
 */
static struct sk_buff *
iecm_rx_construct_skb_zc(struct iecm_queue *rxq, struct iecm_rx_buf *rx_buf,
			 unsigned int size)
{
	unsigned int datasize = (u8 *)rx_buf->xdp->data_end - (u8 *)rx_buf->xdp->data_meta;
	unsigned int metasize = (u8 *)rx_buf->xdp->data - (u8 *)rx_buf->xdp->data_meta;
	unsigned int datasize_hard = (u8 *)rx_buf->xdp->data_end -
				     (u8 *)rx_buf->xdp->data_hard_start;
	struct sk_buff *skb;

	skb = __napi_alloc_skb(&rxq->q_vector->napi, datasize_hard,
			       GFP_ATOMIC | __GFP_NOWARN);

	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, (u8 *)rx_buf->xdp->data_meta - (u8 *)rx_buf->xdp->data_hard_start);
	memcpy(__skb_put(skb, datasize), (u8 *)rx_buf->xdp->data_meta, datasize);

	if (metasize) {
		__skb_pull(skb, metasize);
		skb_metadata_set(skb, metasize);
	}

	xsk_buff_free(rx_buf->xdp);
	rx_buf->xdp = NULL;
	return skb;
}

/**
 * iecm_rx_splitq_clean_zc - consumes packets from the hardware queue
 * @rxq: AF_XDP receive queue
 * @budget: NAPI budget
 *
 * Returns number of processed packets on success, remaining budget on failure.
 */
int iecm_rx_splitq_clean_zc(struct iecm_queue *rxq, int budget)
{
	struct iecm_queue *xdpq = iecm_get_related_xdp_queue(rxq);
	unsigned int total_rx_bytes = 0, total_rx_pkts = 0;
	struct iecm_queue *rx_bufq = NULL;
	struct sk_buff *skb = rxq->skb;
	unsigned int xdp_xmit = 0;
	bool failure = false;

	rcu_read_lock();
	while (likely(total_rx_pkts < (unsigned int)budget)) {
		struct virtchnl2_rx_flex_desc_adv_nic_3 *splitq_flex_rx_desc;
		struct iecm_sw_queue *refillq = NULL;
		unsigned int xdp_res = IECM_XDP_PASS;
		struct iecm_rxq_set *rxq_set = NULL;
		struct iecm_rx_buf *rx_buf = NULL;
		union virtchnl2_rx_desc *rx_desc;
		u16 vlan_tag, gen_id, buf_id;
		unsigned int pkt_len = 0;
		int bufq_id;

		/* get the Rx desc from Rx queue based on 'next_to_clean' */
		rx_desc = IECM_RX_DESC(rxq, rxq->next_to_clean);
		splitq_flex_rx_desc = (struct virtchnl2_rx_flex_desc_adv_nic_3 *)rx_desc;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc
		 */
		dma_rmb();

		/* if the descriptor isn't done, no work yet to do */
		gen_id = le16_to_cpu(splitq_flex_rx_desc->pktlen_gen_bufq_id);
		gen_id = (gen_id & VIRTCHNL2_RX_FLEX_DESC_ADV_GEN_M) >>
			 VIRTCHNL2_RX_FLEX_DESC_ADV_GEN_S;
		if (test_bit(__IECM_Q_GEN_CHK, rxq->flags) != gen_id)
			break;

		pkt_len = le16_to_cpu(splitq_flex_rx_desc->pktlen_gen_bufq_id) &
				      VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_PBUF_M;
		if (!pkt_len)
			break;

		bufq_id = le16_to_cpu(splitq_flex_rx_desc->pktlen_gen_bufq_id);
		bufq_id = (bufq_id & VIRTCHNL2_RX_FLEX_DESC_ADV_BUFQ_ID_M) >>
			  VIRTCHNL2_RX_FLEX_DESC_ADV_BUFQ_ID_S;

		rxq_set = container_of(rxq, struct iecm_rxq_set, rxq);
		if (!bufq_id)
			refillq = rxq_set->refillq0;
		else
			refillq = rxq_set->refillq1;

		/* retrieve buffer from the rxq */
		rx_bufq = &rxq->rxq_grp->splitq.bufq_sets[bufq_id].bufq;
		buf_id = le16_to_cpu(splitq_flex_rx_desc->buf_id);
		rx_buf = &rx_bufq->rx_buf.buf[buf_id];

		if (!rx_buf->xdp)
			break;

		rx_buf->xdp->data_end = (u8 *)rx_buf->xdp->data + pkt_len;
		xsk_buff_dma_sync_for_cpu(rx_buf->xdp, rxq->xsk_pool);

		xdp_res = iecm_run_xdp_zc(rxq, xdpq, rx_buf->xdp);

		if (xdp_res) {
			if (xdp_res & (IECM_XDP_TX | IECM_XDP_REDIR))
				xdp_xmit |= xdp_res;
			else
				xsk_buff_free(rx_buf->xdp);

			rx_buf->xdp = NULL;
			total_rx_bytes += pkt_len;
			total_rx_pkts++;
			failure |= iecm_rx_buf_hw_alloc_zc(rx_buf, rxq->xsk_pool);
			iecm_rx_post_buf_refill(refillq, rx_buf->buf_id);
			iecm_rx_bump_ntc(rxq);
			continue;
		}

		/* XDP_PASS path */
		skb = iecm_rx_construct_skb_zc(rxq, rx_buf, pkt_len);
		if (!skb) {
			/* If we fetched a buffer, but didn't use it
			 * undo pagecnt_bias decrement
			 */
			if (rx_buf) {
				int page_indx = rx_buf->page_indx;

				rx_buf->page_info[page_indx].pagecnt_bias++;
			}
			break;
		}
		failure |= iecm_rx_buf_hw_alloc_zc(rx_buf, rxq->xsk_pool);
		iecm_rx_post_buf_refill(refillq, buf_id);
		iecm_rx_bump_ntc(rxq);

		/* pad skb if needed (to make valid ethernet frame) */
		if (eth_skb_pad(skb)) {
			skb = NULL;
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* protocol */
		if (unlikely(iecm_rx_process_skb_fields(rxq, skb,
							splitq_flex_rx_desc))) {
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		/* extract vlan tag from the descriptor */
		if (unlikely(iecm_rx_splitq_extract_vlan_tag(splitq_flex_rx_desc,
							     rxq, &vlan_tag))) {
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		/* send completed skb up the stack */
		iecm_rx_skb(rxq, skb, vlan_tag);
		skb = NULL;

		/* Update budget accounting */
		total_rx_pkts++;
	}

	iecm_finalize_xdp_rx(xdpq, xdp_xmit);
	rcu_read_unlock();

	u64_stats_update_begin(&rxq->stats_sync);
	rxq->q_stats.rx.packets += total_rx_pkts;
	rxq->q_stats.rx.bytes += total_rx_bytes;
	u64_stats_update_end(&rxq->stats_sync);

	if (xsk_uses_need_wakeup(rxq->xsk_pool)) {
		if (failure || rxq->next_to_clean == rxq->next_to_use)
			xsk_set_rx_need_wakeup(rxq->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rxq->xsk_pool);

		return (int)total_rx_pkts;
	}

	/* guarantee a trip back through this routine if there was a failure */
	return failure ? budget : (int)total_rx_pkts;
}

/**
 * iecm_rx_singleq_clean_zc - consumes packets from the hardware queue
 * @rxq: AF_XDP receive queue
 * @budget: NAPI budget
 *
 * Returns number of processed packets on success, remaining budget on failure.
 */
int iecm_rx_singleq_clean_zc(struct iecm_queue *rxq, int budget)
{
	struct iecm_queue *xdpq = iecm_get_related_xdp_queue(rxq);
	unsigned int total_rx_bytes = 0, total_rx_pkts = 0;
	struct sk_buff *skb = rxq->skb;
	unsigned int xdp_xmit = 0;
	u16 cleaned_count = 0;
	bool failure = false;

	rcu_read_lock();
	while (likely(total_rx_pkts < (unsigned int)budget)) {
		struct iecm_rx_extracted fields = {};
		unsigned int xdp_res = IECM_XDP_PASS;
		struct iecm_rx_buf *rx_buf = NULL;
		union virtchnl2_rx_desc *rx_desc;
		unsigned int pkt_len = 0;

		rx_desc = IECM_RX_DESC(rxq, rxq->next_to_clean);

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc
		 */
		dma_rmb();

		/* status_error_ptype_len will always be zero for unused
		 * descriptors because it's cleared in cleanup, and overlaps
		 * with hdr_addr which is always zero because packet split
		 * isn't used, if the hardware wrote DD then the length will be
		 * non-zero
		 */
#define IECM_RXD_DD BIT(VIRTCHNL2_RX_BASE_DESC_STATUS_DD_S)
		if (!iecm_rx_singleq_test_staterr(rx_desc, IECM_RXD_DD))
			break;
		iecm_rx_singleq_extract_fields(rxq, rx_desc, &fields);
		pkt_len = fields.size;

		if (!pkt_len)
			break;

		rx_buf = &rxq->rx_buf.buf[rxq->next_to_clean];
		if (!rx_buf->xdp)
			break;

		rx_buf->xdp->data_end = (u8 *)rx_buf->xdp->data + pkt_len;
		xsk_buff_dma_sync_for_cpu(rx_buf->xdp, rxq->xsk_pool);

		xdp_res = iecm_run_xdp_zc(rxq, xdpq, rx_buf->xdp);
		if (xdp_res) {
			if (xdp_res & (IECM_XDP_TX | IECM_XDP_REDIR))
				xdp_xmit |= xdp_res;
			else
				xsk_buff_free(rx_buf->xdp);

			rx_buf->xdp = NULL;
			total_rx_bytes += pkt_len;
			total_rx_pkts++;
			cleaned_count++;

			iecm_rx_singleq_bump_ntc(rxq);
			continue;
		}

		/* XDP_PASS path */
		skb = iecm_rx_construct_skb_zc(rxq, rx_buf, pkt_len);

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			/* If we fetched a buffer, but didn't use it
			 * undo pagecnt_bias decrement
			 */
			if (rx_buf) {
				int page_indx = rx_buf->page_indx;

				rx_buf->page_info[page_indx].pagecnt_bias++;
			}
			break;
		}

		iecm_rx_singleq_bump_ntc(rxq);

		cleaned_count++;

		/* skip if it is non EOP desc */
		if (iecm_rx_singleq_is_non_eop(rxq, rx_desc, skb))
			continue;

#define IECM_RXD_ERR_S BIT(VIRTCHNL2_RX_BASE_DESC_QW1_ERROR_S)
		if (unlikely(iecm_rx_singleq_test_staterr(rx_desc, IECM_RXD_ERR_S))) {
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		/* pad skb if needed (to make valid ethernet frame) */
		if (eth_skb_pad(skb)) {
			skb = NULL;
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* protocol */
		iecm_rx_singleq_process_skb_fields(rxq, skb, rx_desc, fields.rx_ptype);

		/* send completed skb up the stack */
		iecm_rx_skb(rxq, skb, fields.vlan_tag);

		/* update budget accounting */
		total_rx_pkts++;
	}

	if (cleaned_count)
		failure = iecm_rx_singleq_buf_hw_alloc_zc_all(rxq, cleaned_count);

	iecm_finalize_xdp_rx(xdpq, xdp_xmit);

	u64_stats_update_begin(&rxq->stats_sync);
	rxq->q_stats.rx.packets += total_rx_pkts;
	rxq->q_stats.rx.bytes += total_rx_bytes;
	u64_stats_update_end(&rxq->stats_sync);

	if (xsk_uses_need_wakeup(rxq->xsk_pool)) {
		if (failure || rxq->next_to_clean == rxq->next_to_use)
			xsk_set_rx_need_wakeup(rxq->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rxq->xsk_pool);

		return (int)total_rx_pkts;
	}

	/* guarantee a trip back through this routine if there was a failure */
	return failure ? budget : (int)total_rx_pkts;
}
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
