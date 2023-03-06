// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2019 Intel Corporation */

#include "iecm.h"

/**
 * iecm_buf_lifo_push - push a buffer pointer onto stack
 * @stack: pointer to stack struct
 * @buf: pointer to buf to push
 *
 * Returns 0 on success, negative on failure
 **/
static int iecm_buf_lifo_push(struct iecm_buf_lifo *stack,
			      struct iecm_tx_buf *buf)
{
	if (stack->top == stack->size)
		return -ENOSPC;

	stack->bufs[stack->top++] = buf;

	return 0;
}

/**
 * iecm_buf_lifo_pop - pop a buffer pointer from stack
 * @stack: pointer to stack struct
 **/
static struct iecm_tx_buf *iecm_buf_lifo_pop(struct iecm_buf_lifo *stack)
{
	if (!stack->top)
		return NULL;

	return stack->bufs[--stack->top];
}

/**
 * iecm_get_stats64 - get statistics for network device structure
 * @netdev: network interface device structure
 * @stats: main device statistics structure
 */
#ifdef HAVE_VOID_NDO_GET_STATS64
void iecm_get_stats64(struct net_device *netdev,
		      struct rtnl_link_stats64 *stats)
#else /* HAVE_VOID_NDO_GET_STATS64 */
struct rtnl_link_stats64 *iecm_get_stats64(struct net_device *netdev,
					   struct rtnl_link_stats64 *stats)
#endif /* !HAVE_VOID_NDO_GET_STATS64 */
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);

	set_bit(__IECM_MB_STATS_PENDING, vport->adapter->flags);

	*stats = vport->netstats;
#ifndef HAVE_VOID_NDO_GET_STATS64
	return stats;
#endif
}

/**
 * iecm_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 * @txqueue: TX queue
 */
#ifdef HAVE_TX_TIMEOUT_TXQUEUE
void iecm_tx_timeout(struct net_device *netdev,
		     unsigned int txqueue)
#else
void iecm_tx_timeout(struct net_device *netdev)
#endif /* HAVE_TX_TIMEOUT_TXQUEUE */
{
	struct iecm_adapter *adapter = iecm_netdev_to_adapter(netdev);

	adapter->tx_timeout_count++;

#ifdef HAVE_TX_TIMEOUT_TXQUEUE
	netdev_err(netdev, "Detected Tx timeout: %d Queue: %d\n",
		   adapter->tx_timeout_count, txqueue);
#else
	netdev_err(netdev, "Detected Tx timeout: %d\n",
		   adapter->tx_timeout_count);
#endif /* HAVE_TX_TIMEOUT_TXQUEUE */
	if (!iecm_is_reset_in_prog(adapter)) {
		set_bit(__IECM_HR_FUNC_RESET, adapter->flags);
		queue_delayed_work(adapter->vc_event_wq,
				   &adapter->vc_event_task,
				   msecs_to_jiffies(10));
	}
}

/**
 * iecm_tx_buf_rel - Release a Tx buffer
 * @tx_q: the queue that owns the buffer
 * @tx_buf: the buffer to free
 */
void iecm_tx_buf_rel(struct iecm_queue *tx_q, struct iecm_tx_buf *tx_buf)
{
	if (tx_buf->skb) {
		if (dma_unmap_len(tx_buf, len))
			dma_unmap_single(tx_q->dev,
					 dma_unmap_addr(tx_buf, dma),
					 dma_unmap_len(tx_buf, len),
					 DMA_TO_DEVICE);
		dev_kfree_skb_any(tx_buf->skb);
	} else if (dma_unmap_len(tx_buf, len)) {
		dma_unmap_page(tx_q->dev,
			       dma_unmap_addr(tx_buf, dma),
			       dma_unmap_len(tx_buf, len),
			       DMA_TO_DEVICE);
	}

	tx_buf->next_to_watch = NULL;
	tx_buf->skb = NULL;
	dma_unmap_len_set(tx_buf, len, 0);
}

/**
 * iecm_tx_buf_rel all - Free any empty Tx buffers
 * @txq: queue to be cleaned
 */
static void iecm_tx_buf_rel_all(struct iecm_queue *txq)
{
	u16 i;

#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	if (test_bit(__IECM_Q_XDP, txq->flags) && txq->xsk_pool) {
		iecm_xsk_cleanup_xdpq(txq);
		return;
	}
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */

	/* Buffers already cleared, nothing to do */
	if (!txq->tx_buf)
		return;

	/* Free all the Tx buffer sk_buffs */
	for (i = 0; i < txq->desc_count; i++)
		iecm_tx_buf_rel(txq, &txq->tx_buf[i]);

	kfree(txq->tx_buf);
	txq->tx_buf = NULL;

	if (txq->buf_stack.bufs) {
		for (i = 0; i < txq->buf_stack.size; i++) {
			iecm_tx_buf_rel(txq, txq->buf_stack.bufs[i]);
			kfree(txq->buf_stack.bufs[i]);
		}
		kfree(txq->buf_stack.bufs);
	}
}

/**
 * iecm_tx_desc_rel - Free Tx resources per queue
 * @txq: Tx descriptor ring for a specific queue
 * @bufq: buffer q or completion q
 *
 * Free all transmit software resources
 */
static void iecm_tx_desc_rel(struct iecm_queue *txq, bool bufq)
{
	if (bufq) {
		iecm_tx_buf_rel_all(txq);
		netdev_tx_reset_queue(netdev_get_tx_queue(txq->vport->netdev,
							  txq->idx));
	}

	if (txq->desc_ring) {
		dmam_free_coherent(txq->dev, txq->size,
				   txq->desc_ring, txq->dma);
		txq->desc_ring = NULL;
		txq->next_to_alloc = 0;
		txq->next_to_use = 0;
		txq->next_to_clean = 0;
	}
}

/**
 * iecm_tx_desc_rel_all - Free Tx Resources for All Queues
 * @vport: virtual port structure
 *
 * Free all transmit software resources
 */
static void iecm_tx_desc_rel_all(struct iecm_vport *vport)
{
	int i, j;

	if (!vport->txq_grps)
		return;

	for (i = 0; i < vport->num_txq_grp; i++) {
		struct iecm_txq_group *txq_grp = &vport->txq_grps[i];

		for (j = 0; j < txq_grp->num_txq; j++)
			iecm_tx_desc_rel(txq_grp->txqs[j], true);
		if (iecm_is_queue_model_split(vport->txq_model))
			iecm_tx_desc_rel(txq_grp->complq, false);
	}
}

/**
 * iecm_tx_buf_alloc_all - Allocate memory for all buffer resources
 * @tx_q: queue for which the buffers are allocated
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_tx_buf_alloc_all(struct iecm_queue *tx_q)
{
	int buf_size;
	int i = 0;

	/* Allocate book keeping buffers only. Buffers to be supplied to HW
	 * are allocated by kernel network stack and received as part of skb
	 */
	buf_size = sizeof(struct iecm_tx_buf) * tx_q->desc_count;
	tx_q->tx_buf = kzalloc(buf_size, GFP_KERNEL);
	if (!tx_q->tx_buf)
		return -ENOMEM;

	/* Initialize tx buf stack for out-of-order completions if
	 * flow scheduling offload is enabled
	 */
	tx_q->buf_stack.bufs =
		kcalloc(tx_q->desc_count, sizeof(struct iecm_tx_buf *),
			GFP_KERNEL);
	if (!tx_q->buf_stack.bufs)
		return -ENOMEM;

	for (i = 0; i < tx_q->desc_count; i++) {
		tx_q->buf_stack.bufs[i] = kzalloc(sizeof(*tx_q->buf_stack.bufs[i]),
						  GFP_KERNEL);
		if (!tx_q->buf_stack.bufs[i])
			return -ENOMEM;
	}

	tx_q->buf_stack.size = tx_q->desc_count;
	tx_q->buf_stack.top = tx_q->desc_count;

	return 0;
}

/**
 * iecm_tx_desc_alloc - Allocate the Tx descriptors
 * @tx_q: the tx ring to set up
 * @bufq: buffer or completion queue
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_tx_desc_alloc(struct iecm_queue *tx_q, bool bufq)
{
	struct device *dev = tx_q->dev;
	int err = 0;

	if (bufq) {
		err = iecm_tx_buf_alloc_all(tx_q);
		if (err)
			goto err_alloc;
		tx_q->size = tx_q->desc_count *
				sizeof(struct iecm_base_tx_desc);
	} else {
		tx_q->size = tx_q->desc_count *
				sizeof(struct iecm_splitq_tx_compl_desc);
	}

	/* Allocate descriptors also round up to nearest 4K */
	tx_q->size = ALIGN(tx_q->size, 4096);
	tx_q->desc_ring = dmam_alloc_coherent(dev, tx_q->size, &tx_q->dma,
					      GFP_KERNEL);
	if (!tx_q->desc_ring) {
		dev_info(dev, "Unable to allocate memory for the Tx descriptor ring, size=%d\n",
			 tx_q->size);
		err = -ENOMEM;
		goto err_alloc;
	}

	tx_q->next_to_alloc = 0;
	tx_q->next_to_use = 0;
	tx_q->next_to_clean = 0;
	set_bit(__IECM_Q_GEN_CHK, tx_q->flags);

err_alloc:
	if (err)
		iecm_tx_desc_rel(tx_q, bufq);
	return err;
}

/**
 * iecm_tx_desc_alloc_all - allocate all queues Tx resources
 * @vport: virtual port private structure
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_tx_desc_alloc_all(struct iecm_vport *vport)
{
	struct pci_dev *pdev = vport->adapter->pdev;
	int err = 0;
	int i, j;

	/* Setup buffer queues. In single queue model buffer queues and
	 * completion queues will be same
	 */
	for (i = 0; i < vport->num_txq_grp; i++) {
		for (j = 0; j < vport->txq_grps[i].num_txq; j++) {
			err = iecm_tx_desc_alloc(vport->txq_grps[i].txqs[j],
						 true);
			if (err) {
				dev_err(&pdev->dev,
					"Allocation for Tx Queue %u failed\n",
					i);
				goto err_out;
			}
		}

		if (iecm_is_queue_model_split(vport->txq_model)) {
			/* Setup completion queues */
			err = iecm_tx_desc_alloc(vport->txq_grps[i].complq,
						 false);
			if (err) {
				dev_err(&pdev->dev,
					"Allocation for Tx Completion Queue %u failed\n",
					i);
				goto err_out;
			}
		}
	}
err_out:
	if (err)
		iecm_tx_desc_rel_all(vport);
	return err;
}

/**
 * iecm_rx_page_rel - Release an rx buffer page
 * @rxq: the queue that owns the buffer
 * @page_info: pointer to page metadata of page to be freed
 */
static void iecm_rx_page_rel(struct iecm_queue *rxq,
			     struct iecm_page_info *page_info)
{
	if (!page_info->page)
		return;

	/* free resources associated with mapping */
#ifndef HAVE_STRUCT_DMA_ATTRS
	dma_unmap_page_attrs(rxq->dev, page_info->dma, PAGE_SIZE,
			     DMA_FROM_DEVICE, IECM_RX_DMA_ATTR);
#else
	dma_unmap_page(rxq->dev, page_info->dma, PAGE_SIZE,
		       DMA_FROM_DEVICE);
#endif /* !HAVE_STRUCT_DMA_ATTRS */

	__page_frag_cache_drain(page_info->page, page_info->pagecnt_bias);

	page_info->page = NULL;
	page_info->page_offset = 0;
}

/**
 * iecm_rx_buf_rel - Release a rx buffer
 * @rxq: the queue that owns the buffer
 * @rx_buf: the buffer to free
 */
static void iecm_rx_buf_rel(struct iecm_queue *rxq,
			    struct iecm_rx_buf *rx_buf)
{
	iecm_rx_page_rel(rxq, &rx_buf->page_info[0]);
#if (PAGE_SIZE < 8192)
	if (rx_buf->buf_size > IECM_RX_BUF_2048)
		iecm_rx_page_rel(rxq, &rx_buf->page_info[1]);

#endif
	if (rx_buf->skb) {
		dev_kfree_skb_any(rx_buf->skb);
		rx_buf->skb = NULL;
	}

}

/**
 * iecm_rx_hdr_buf_rel_all - Release header buffer memory
 * @rxq: queue to use
 */
static void iecm_rx_hdr_buf_rel_all(struct iecm_queue *rxq)
{
	struct iecm_hw *hw = &rxq->vport->adapter->hw;
	struct iecm_dma_mem *hbuf;
	int i;

	if (!rxq)
		return;

	if (rxq->rx_buf.hdr_buf) {
		for (i = 0; i < rxq->desc_count; i++) {
			hbuf = rxq->rx_buf.hdr_buf[i];
			if (hbuf) {
				iecm_free_dma_mem(hw, hbuf);
				kfree(hbuf);
			}
			rxq->rx_buf.hdr_buf[i] = NULL;
		}
		kfree(rxq->rx_buf.hdr_buf);
		rxq->rx_buf.hdr_buf = NULL;
	}

	for (i = 0; i < rxq->hbuf_pages.nr_pages; i++)
		iecm_rx_page_rel(rxq, &rxq->hbuf_pages.pages[i]);

	kfree(rxq->hbuf_pages.pages);
}

/**
 * iecm_rx_buf_rel_all - Free all Rx buffer resources for a queue
 * @rxq: queue to be cleaned
 */
static void iecm_rx_buf_rel_all(struct iecm_queue *rxq)
{
	u16 i;

	/* queue already cleared, nothing to do */
	if (!rxq->rx_buf.buf)
		return;

	/* Free all the bufs allocated and given to hw on Rx queue */
	for (i = 0; i < rxq->desc_count; i++)
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		if (rxq->xsk_pool)
			iecm_rx_buf_rel_zc(&rxq->rx_buf.buf[i]);
		else
			iecm_rx_buf_rel(rxq, &rxq->rx_buf.buf[i]);
#else
		iecm_rx_buf_rel(rxq, &rxq->rx_buf.buf[i]);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	if (rxq->rx_hsplit_en)
		iecm_rx_hdr_buf_rel_all(rxq);

	kfree(rxq->rx_buf.buf);
	rxq->rx_buf.buf = NULL;
	kfree(rxq->rx_buf.hdr_buf);
	rxq->rx_buf.hdr_buf = NULL;
}

/**
 * iecm_rx_desc_rel - Free a specific Rx q resources
 * @rxq: queue to clean the resources from
 * @bufq: buffer q or completion q
 * @q_model: single or split q model
 *
 * Free a specific rx queue resources
 */
static void iecm_rx_desc_rel(struct iecm_queue *rxq, bool bufq, s32 q_model)
{
	if (!rxq)
		return;

	if (!bufq && iecm_is_queue_model_split(q_model) && rxq->skb) {
		dev_kfree_skb_any(rxq->skb);
		rxq->skb = NULL;
	}

	if (bufq || !iecm_is_queue_model_split(q_model))
		iecm_rx_buf_rel_all(rxq);

	if (rxq->desc_ring) {
		dmam_free_coherent(rxq->dev, rxq->size,
				   rxq->desc_ring, rxq->dma);
		rxq->desc_ring = NULL;
		rxq->next_to_alloc = 0;
		rxq->next_to_clean = 0;
		rxq->next_to_use = 0;
	}
}

/**
 * iecm_rx_desc_rel_all - Free Rx Resources for All Queues
 * @vport: virtual port structure
 *
 * Free all rx queues resources
 */
static void iecm_rx_desc_rel_all(struct iecm_vport *vport)
{
	struct iecm_rxq_group *rx_qgrp;
	struct iecm_queue *q;
	int i, j, num_rxq;

	if (!vport->rxq_grps)
		return;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		rx_qgrp = &vport->rxq_grps[i];

		if (iecm_is_queue_model_split(vport->rxq_model)) {
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
			for (j = 0; j < num_rxq; j++) {
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
				iecm_rx_desc_rel(q, false,
						 vport->rxq_model);
			}

			if (!rx_qgrp->splitq.bufq_sets)
				continue;
			for (j = 0; j < vport->num_bufqs_per_qgrp; j++) {
				struct iecm_bufq_set *bufq_set =
					&rx_qgrp->splitq.bufq_sets[j];

				q = &bufq_set->bufq;
				iecm_rx_desc_rel(q, true, vport->rxq_model);
			}
		} else {
			for (j = 0; j < rx_qgrp->singleq.num_rxq; j++) {
				q = rx_qgrp->singleq.rxqs[j];
				iecm_rx_desc_rel(q, false,
						 vport->rxq_model);
			}
		}
	}
}

/**
 * iecm_rx_buf_hw_update - Store the new tail and head values
 * @rxq: queue to bump
 * @val: new head index
 */
void iecm_rx_buf_hw_update(struct iecm_queue *rxq, u32 val)
{
	rxq->next_to_use = val;

	if (unlikely(!rxq->tail))
		return;
	/* writel has an implicit memory barrier */
	writel(val, rxq->tail);
}

/**
 * iecm_alloc_page - allocate page to back RX buffer
 * @rxbufq: pointer to queue to struct; equivalent to rxq when operating
 * in singleq mode
 * @page_inf: pointer to page metadata struct
 */
static int
iecm_alloc_page(struct iecm_queue *rxbufq, struct iecm_page_info *page_info)
{

	/* alloc new page for storage */
	page_info->page = alloc_page(GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!page_info->page))
		return -ENOMEM;

	/* map page for use */
#ifndef HAVE_STRUCT_DMA_ATTRS
	page_info->dma = dma_map_page_attrs(rxbufq->dev, page_info->page,
					    0, PAGE_SIZE, DMA_FROM_DEVICE,
					    IECM_RX_DMA_ATTR);
#else
	page_info->dma = dma_map_page(rxbufq->dev, page_info->page, 0, PAGE_SIZE,
				      DMA_FROM_DEVICE);
#endif /* !HAVE_STRUCT_DMA_ATTRS */

	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rxbufq->dev, page_info->dma)) {
		__free_pages(page_info->page, 0);
		return -ENOMEM;
	}

	page_info->page_offset = iecm_rx_offset(rxbufq);

	/* initialize pagecnt_bias to claim we fully own page */
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	page_ref_add(page_info->page, USHRT_MAX - 1);
	page_info->pagecnt_bias = USHRT_MAX;
#else
	page_info->pagecnt_bias = 1;
#endif /* HAVE_PAGE_COUNT_BULK_UPDATE */

	return 0;
}

/**
 * iecm_init_rx_buf_hw_alloc - allocate initial RX buffer pages
 * @rxbufq: ring to use; equivalent to rxq when operating in singleq mode
 * @buf: rx_buffer struct to modify
 *
 * Returns true if the page was successfully allocated or
 * reused.
 */
bool iecm_init_rx_buf_hw_alloc(struct iecm_queue *rxbufq, struct iecm_rx_buf *buf)
{
	if (iecm_alloc_page(rxbufq, &buf->page_info[0]))
		return false;

#if (PAGE_SIZE < 8192)
	if (rxbufq->rx_buf_size > IECM_RX_BUF_2048)
		if (iecm_alloc_page(rxbufq, &buf->page_info[1]))
			return false;
#endif

	buf->page_indx = 0;
	buf->buf_size = rxbufq->rx_buf_size;

	return true;
}

/**
 * iecm_rx_hdr_buf_alloc_all - Allocate memory for header buffers
 * @rxq: ring to use
 *
 * Returns 0 on success, negative on failure.
 */
static int iecm_rx_hdr_buf_alloc_all(struct iecm_queue *rxq)
{
	struct iecm_page_info *page_info;
	int nr_pages, offset;
	int i, j = 0;

	rxq->rx_buf.hdr_buf = kcalloc(rxq->desc_count,
				      sizeof(struct iecm_dma_mem *),
				      GFP_KERNEL);
	if (!rxq->rx_buf.hdr_buf)
		return -ENOMEM;

	for (i = 0; i < rxq->desc_count; i++) {

		rxq->rx_buf.hdr_buf[i] = kcalloc(1,
						 sizeof(struct iecm_dma_mem),
						 GFP_KERNEL);
		if (!rxq->rx_buf.hdr_buf[i])
			goto unroll_buf_alloc;
	}

	/* Determine the number of pages necessary to back the total number of header buffers */
	nr_pages = (rxq->desc_count * rxq->rx_hbuf_size) / PAGE_SIZE;
	rxq->hbuf_pages.pages = kcalloc(nr_pages,
					sizeof(struct iecm_page_info),
					GFP_KERNEL);
	if (!rxq->hbuf_pages.pages)
		goto unroll_buf_alloc;

	rxq->hbuf_pages.nr_pages = nr_pages;
	for (i = 0; i < nr_pages; i++) {
		if (iecm_alloc_page(rxq, &rxq->hbuf_pages.pages[i]))
			goto unroll_buf_alloc;
	}

	page_info = &rxq->hbuf_pages.pages[0];
	for (i = 0, offset = 0; i < rxq->desc_count; i++, offset += rxq->rx_hbuf_size) {
		struct iecm_dma_mem *hbuf = rxq->rx_buf.hdr_buf[i];

		/* Move to next page */
		if (offset >= PAGE_SIZE) {
			offset = 0;
			page_info = &rxq->hbuf_pages.pages[++j];
		}

		hbuf->va = page_address(page_info->page) + offset;
		hbuf->pa = page_info->dma + offset;
		hbuf->size = rxq->rx_hbuf_size;
	}

	return 0;
unroll_buf_alloc:
	iecm_rx_hdr_buf_rel_all(rxq);
	return -ENOMEM;
}

/**
 * iecm_rx_buf_hw_alloc_all - Allocate receive buffers
 * @rxbufq: queue for which the hw buffers are allocated; equivalent to rxq
 * when operating in singleq mode
 * @alloc_count: number of buffers to allocate
 *
 * Returns false if all allocations were successful, true if any fail
 */
static bool
iecm_rx_buf_hw_alloc_all(struct iecm_queue *rxbufq, u16 alloc_count)
{
	u16 nta = rxbufq->next_to_alloc;
	struct iecm_rx_buf *buf;

	if (!alloc_count)
		return false;

	buf = &rxbufq->rx_buf.buf[nta];

	do {
		if (!iecm_init_rx_buf_hw_alloc(rxbufq, buf))
			break;

		buf++;
		nta++;
		if (unlikely(nta == rxbufq->desc_count)) {
			buf = rxbufq->rx_buf.buf;
			nta = 0;
		}

		alloc_count--;
	} while (alloc_count);

	return !!alloc_count;
}

/**
 * iecm_rx_post_buf_refill - Post buffer id to refill queue
 * @refillq: refill queue to post to
 * @buf_id: buffer id to post
 */
void iecm_rx_post_buf_refill(struct iecm_sw_queue *refillq, u16 buf_id)
{
	u16 nta = refillq->next_to_alloc;
	u16 *bi;

	bi = IECM_SPLITQ_RX_BI_DESC(refillq, nta);
	/* store the buffer ID and the SW maintained GEN bit to the refillq */
	*bi = ((buf_id << IECM_RX_BI_BUFID_S) & IECM_RX_BI_BUFID_M) |
	      (!!(test_bit(__IECM_Q_GEN_CHK, refillq->flags)) <<
	       IECM_RX_BI_GEN_S);

	nta++;
	if (unlikely(nta == refillq->desc_count)) {
		nta = 0;
		change_bit(__IECM_Q_GEN_CHK, refillq->flags);
	}
	refillq->next_to_alloc = nta;
}

/**
 * iecm_rx_post_buf_desc - Post buffer to bufq descriptor ring
 * @bufq: buffer queue to post to
 * @buf_id: buffer id to post
 */
static void iecm_rx_post_buf_desc(struct iecm_queue *bufq, u16 buf_id)
{
	struct virtchnl2_splitq_rx_buf_desc *splitq_rx_desc = NULL;
	struct iecm_page_info *page_info;
	u16 nta = bufq->next_to_alloc;
	struct iecm_dma_mem *hdr_buf;
	struct iecm_rx_buf *buf;

	splitq_rx_desc = IECM_SPLITQ_RX_BUF_DESC(bufq, nta);
	buf = &bufq->rx_buf.buf[buf_id];
	page_info = &buf->page_info[buf->page_indx];
	if (bufq->rx_hsplit_en) {
		hdr_buf = bufq->rx_buf.hdr_buf[buf_id];
		splitq_rx_desc->hdr_addr =
			cpu_to_le64(hdr_buf->pa);
	}
	dma_sync_single_range_for_device(bufq->dev, page_info->dma,
					 page_info->page_offset,
					 bufq->rx_buf_size,
					 DMA_FROM_DEVICE);
	splitq_rx_desc->pkt_addr = cpu_to_le64(page_info->dma +
					       page_info->page_offset);
	splitq_rx_desc->qword0.buf_id = cpu_to_le16(buf_id);

	nta++;
	if (unlikely(nta == bufq->desc_count))
		nta = 0;
	bufq->next_to_alloc = nta;
}

/**
 * iecm_rx_post_init_bufs - Post initial buffers to bufq
 * @bufq: buffer queue to post working set to
 * @working_set: number of buffers to put in working set
 */
static void iecm_rx_post_init_bufs(struct iecm_queue *bufq,
				   u16 working_set)
{
	int i;

	for (i = 0; i < working_set; i++)
		iecm_rx_post_buf_desc(bufq, i);

	iecm_rx_buf_hw_update(bufq, bufq->next_to_alloc & ~(bufq->rx_buf_stride - 1));
}

/**
 * iecm_rx_buf_alloc_all - Allocate memory for all buffer resources
 * @rxbufq: queue for which the buffers are allocated; equivalent to
 * rxq when operating in singleq mode
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_rx_buf_alloc_all(struct iecm_queue *rxbufq)
{
	int err = 0;

	/* Allocate book keeping buffers */
	rxbufq->rx_buf.buf = kcalloc(rxbufq->desc_count,
				     sizeof(struct iecm_rx_buf), GFP_KERNEL);
	if (!rxbufq->rx_buf.buf) {
		err = -ENOMEM;
		goto rx_buf_alloc_all_out;
	}

	if (rxbufq->rx_hsplit_en) {
		err = iecm_rx_hdr_buf_alloc_all(rxbufq);
		if (err)
			goto rx_buf_alloc_all_out;
	}

	/* Allocate buffers to be given to HW.	 */
	if (iecm_is_queue_model_split(rxbufq->vport->rxq_model)) {
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		if (rxbufq->xsk_pool) {
			if (iecm_rx_splitq_buf_hw_alloc_zc_all(rxbufq, rxbufq->desc_count - 1))
				dev_info(rxbufq->dev, "Failed to allocate some buffers on UMEM enabled rxbufq %d\n",
					 rxbufq->q_id);
		} else {
			if (iecm_rx_buf_hw_alloc_all(rxbufq, rxbufq->desc_count - 1))
				err = -ENOMEM;
		}
#else
		if (iecm_rx_buf_hw_alloc_all(rxbufq, rxbufq->desc_count - 1))
			err = -ENOMEM;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	} else {
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		if (rxbufq->xsk_pool) {
			if (iecm_rx_singleq_buf_hw_alloc_zc_all(rxbufq, rxbufq->desc_count - 1))
				dev_info(rxbufq->dev, "Failed to allocate some buffers on UMEM enabled RxQ %d\n",
					 rxbufq->q_id);
		} else {
			if (iecm_rx_singleq_buf_hw_alloc_all(rxbufq, rxbufq->desc_count - 1))
				err = -ENOMEM;
		}
#else
		if (iecm_rx_singleq_buf_hw_alloc_all(rxbufq, rxbufq->desc_count - 1))
			err = -ENOMEM;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	}

rx_buf_alloc_all_out:
	if (err)
		iecm_rx_buf_rel_all(rxbufq);
	return err;
}

/**
 * iecm_rx_desc_alloc - Allocate queue Rx resources
 * @rxq: Rx queue for which the resources are setup
 * @bufq: buffer or completion queue
 * @q_model: single or split queue model
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_rx_desc_alloc(struct iecm_queue *rxq, bool bufq, s32 q_model)
{
	struct device *dev = rxq->dev;

	/* As both single and split descriptors are 32 byte, memory size
	 * will be same for all three singleq_base rx, buf., splitq_base
	 * rx. So pick anyone of them for size
	 */
	if (bufq) {
		rxq->size = rxq->desc_count *
			sizeof(struct virtchnl2_splitq_rx_buf_desc);
	} else {
		rxq->size = rxq->desc_count *
			sizeof(union virtchnl2_rx_desc);
	}

	/* Allocate descriptors and also round up to nearest 4K */
	rxq->size = ALIGN(rxq->size, 4096);
	rxq->desc_ring = dmam_alloc_coherent(dev, rxq->size,
					     &rxq->dma, GFP_KERNEL);
	if (!rxq->desc_ring) {
		dev_info(dev, "Unable to allocate memory for the Rx descriptor ring, size=%d\n",
			 rxq->size);
		return -ENOMEM;
	}

	rxq->next_to_alloc = 0;
	rxq->next_to_clean = 0;
	rxq->next_to_use = 0;
	set_bit(__IECM_Q_GEN_CHK, rxq->flags);

	/* Allocate buffers for a rx queue if the q_model is single OR if it
	 * is a buffer queue in split queue model
	 */
	if (bufq || !iecm_is_queue_model_split(q_model)) {
		int err = 0;

		err = iecm_rx_buf_alloc_all(rxq);
		if (err) {
			iecm_rx_desc_rel(rxq, bufq, q_model);
			return err;
		}
	}
	return 0;
}

/**
 * iecm_rx_desc_alloc_all - allocate all RX queues resources
 * @vport: virtual port structure
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_rx_desc_alloc_all(struct iecm_vport *vport)
{
	struct device *dev = &vport->adapter->pdev->dev;
	struct iecm_rxq_group *rx_qgrp;
	int i, j, num_rxq, working_set;
	struct iecm_queue *q;
	int err = 0;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		rx_qgrp = &vport->rxq_grps[i];
		if (iecm_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++) {
			if (iecm_is_queue_model_split(vport->rxq_model))
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				q = rx_qgrp->singleq.rxqs[j];
			err = iecm_rx_desc_alloc(q, false, vport->rxq_model);
			if (err) {
				dev_err(dev, "Memory allocation for Rx Queue %u failed\n",
					i);
				goto err_out;
			}
		}

		if (iecm_is_queue_model_split(vport->rxq_model)) {
			for (j = 0; j < vport->num_bufqs_per_qgrp; j++) {
				q = &rx_qgrp->splitq.bufq_sets[j].bufq;
				err = iecm_rx_desc_alloc(q, true,
							 vport->rxq_model);
				if (err) {
					dev_err(dev, "Memory allocation for Rx Buffer Queue %u failed\n",
						i);
					goto err_out;
				}

				working_set = IECM_RX_BUFQ_WORKING_SET(q);
				iecm_rx_post_init_bufs(q, working_set);
			}
		}
	}
err_out:
	if (err)
		iecm_rx_desc_rel_all(vport);
	return err;
}

/**
 * iecm_txq_group_rel - Release all resources for txq groups
 * @vport: vport to release txq groups on
 */
static void iecm_txq_group_rel(struct iecm_vport *vport)
{
	struct iecm_txq_group *txq_grp;
	int i, j, num_txq;

	if (vport->txq_grps) {
		for (i = 0; i < vport->num_txq_grp; i++) {
			txq_grp = &vport->txq_grps[i];
			num_txq = txq_grp->num_txq;

			for (j = 0; j < num_txq; j++) {
				kfree(txq_grp->txqs[j]);
				txq_grp->txqs[j] = NULL;
			}
			kfree(txq_grp->complq);
			txq_grp->complq = NULL;
		}
		kfree(vport->txq_grps);
		vport->txq_grps = NULL;
	}
}

/**
 * iecm_rxq_sw_queue_rel - Release software queue resources
 * @rx_qgrp: rx queue group with software queues
 */
static void iecm_rxq_sw_queue_rel(struct iecm_rxq_group *rx_qgrp)
{
	int i, j;

	for (i = 0; i < rx_qgrp->vport->num_bufqs_per_qgrp; i++) {
		struct iecm_bufq_set *bufq_set = &rx_qgrp->splitq.bufq_sets[i];

		for (j = 0; j < bufq_set->num_refillqs; j++) {
			kfree(bufq_set->refillqs[j].ring);
			bufq_set->refillqs[j].ring = NULL;
		}
		kfree(bufq_set->refillqs);
		bufq_set->refillqs = NULL;
	}
}

/**
 * iecm_rxq_group_rel - Release all resources for rxq groups
 * @vport: vport to release rxq groups on
 */
static void iecm_rxq_group_rel(struct iecm_vport *vport)
{
	if (vport->rxq_grps) {
		int i;

		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct iecm_rxq_group *rx_qgrp = &vport->rxq_grps[i];
#ifdef HAVE_XDP_BUFF_RXQ
			struct iecm_queue *q;
#endif /* HAVE_XDP_BUFF_RXQ */
			int j, num_rxq;

			if (iecm_is_queue_model_split(vport->rxq_model)) {
				num_rxq = rx_qgrp->splitq.num_rxq_sets;
				for (j = 0; j < num_rxq; j++) {
#ifdef HAVE_XDP_BUFF_RXQ
					q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
					if (xdp_rxq_info_is_reg(&q->xdp_rxq))
						xdp_rxq_info_unreg(&q->xdp_rxq);
#endif /* HAVE_XDP_BUFF_RXQ */
					kfree(rx_qgrp->splitq.rxq_sets[j]);
					rx_qgrp->splitq.rxq_sets[j] = NULL;
				}
				iecm_rxq_sw_queue_rel(rx_qgrp);
				kfree(rx_qgrp->splitq.bufq_sets);
				rx_qgrp->splitq.bufq_sets = NULL;
			} else {
				num_rxq = rx_qgrp->singleq.num_rxq;
				for (j = 0; j < num_rxq; j++) {
#ifdef HAVE_XDP_BUFF_RXQ
					q = rx_qgrp->singleq.rxqs[j];
					if (xdp_rxq_info_is_reg(&q->xdp_rxq))
						xdp_rxq_info_unreg(&q->xdp_rxq);
#endif /* HAVE_XDP_BUFF_RXQ */
					kfree(rx_qgrp->singleq.rxqs[j]);
					rx_qgrp->singleq.rxqs[j] = NULL;
				}
			}
		}
		kfree(vport->rxq_grps);
		vport->rxq_grps = NULL;
	}
}

/**
 * iecm_vport_queue_grp_rel_all - Release all queue groups
 * @vport: vport to release queue groups for
 */
static void iecm_vport_queue_grp_rel_all(struct iecm_vport *vport)
{
	iecm_txq_group_rel(vport);
	iecm_rxq_group_rel(vport);
}

/**
 * iecm_vport_queues_rel - Free memory for all queues
 * @vport: virtual port
 *
 * Free the memory allocated for queues associated to a vport
 */
void iecm_vport_queues_rel(struct iecm_vport *vport)
{
	iecm_tx_desc_rel_all(vport);
	iecm_rx_desc_rel_all(vport);
	iecm_vport_queue_grp_rel_all(vport);

	kfree(vport->txqs);
	vport->txqs = NULL;
}

/**
 * iecm_vport_init_fast_path_txqs - Initialize fast path txq array
 * @vport: vport to init txqs on
 *
 * We get a queue index from skb->queue_mapping and we need a fast way to
 * dereference the queue from queue groups.  This allows us to quickly pull a
 * txq based on a queue index.
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_vport_init_fast_path_txqs(struct iecm_vport *vport)
{
	int i, j, k = 0;

	vport->txqs = kcalloc(vport->num_txq, sizeof(struct iecm_queue *),
			      GFP_KERNEL);

	if (!vport->txqs)
		return -ENOMEM;

	for (i = 0; i < vport->num_txq_grp; i++) {
		struct iecm_txq_group *tx_grp = &vport->txq_grps[i];

		for (j = 0; j < tx_grp->num_txq; j++, k++) {
			vport->txqs[k] = tx_grp->txqs[j];
			vport->txqs[k]->idx = k;
		}
	}
	return 0;
}

/**
 * iecm_vport_init_num_qs - Initialize number of queues
 * @vport: vport to initialize queues
 * @vport_msg: data to be filled into vport
 */
void iecm_vport_init_num_qs(struct iecm_vport *vport, struct virtchnl2_create_vport *vport_msg)
{
	vport->num_txq = le16_to_cpu(vport_msg->num_tx_q);
	vport->num_rxq = le16_to_cpu(vport_msg->num_rx_q);
	/* number of txqs and rxqs in config data will be zeros only in the
	 * driver load path and we dont update them there after
	 */
	if (!vport->adapter->config_data.num_req_tx_qs &&
	    !vport->adapter->config_data.num_req_rx_qs) {
		vport->adapter->config_data.num_req_tx_qs =
					le16_to_cpu(vport_msg->num_tx_q);
		vport->adapter->config_data.num_req_rx_qs =
					le16_to_cpu(vport_msg->num_rx_q);
	}

	if (iecm_is_queue_model_split(vport->txq_model))
		vport->num_complq = le16_to_cpu(vport_msg->num_tx_complq);
	if (iecm_is_queue_model_split(vport->rxq_model))
		vport->num_bufq = le16_to_cpu(vport_msg->num_rx_bufq);
#ifdef HAVE_XDP_SUPPORT

	if (iecm_xdp_is_prog_ena(vport)) {
		/* Do not create dummy Rx queues by default */
		vport->num_xdp_rxq = 0;
		vport->xdp_rxq_offset = 0;
		vport->num_xdp_txq = le16_to_cpu(vport_msg->num_rx_q);
		vport->xdp_txq_offset = le16_to_cpu(vport_msg->num_tx_q) -
					le16_to_cpu(vport_msg->num_rx_q);

		if (iecm_is_queue_model_split(vport->txq_model)) {
			vport->num_xdp_complq = vport->num_xdp_txq;
			vport->xdp_complq_offset = vport->xdp_txq_offset;
		}
	} else {
		vport->num_xdp_txq = 0;
		vport->num_xdp_rxq = 0;
		vport->xdp_txq_offset = 0;
		vport->xdp_rxq_offset = 0;
	}
#endif /* HAVE_XDP_SUPPORT */
}

/**
 * iecm_vport_calc_num_q_desc - Calculate number of queue groups
 * @vport: vport to calculate q groups for
 */
void iecm_vport_calc_num_q_desc(struct iecm_vport *vport)
{
	int num_req_txq_desc = vport->adapter->config_data.num_req_txq_desc;
	int num_req_rxq_desc = vport->adapter->config_data.num_req_rxq_desc;
	int num_bufqs = vport->num_bufqs_per_qgrp;
	int i = 0;

	vport->complq_desc_count = 0;
	if (num_req_txq_desc) {
		vport->txq_desc_count = num_req_txq_desc;
		if (iecm_is_queue_model_split(vport->txq_model)) {
			vport->complq_desc_count = num_req_txq_desc;
			if (vport->complq_desc_count < IECM_MIN_TXQ_COMPLQ_DESC)
				vport->complq_desc_count =
					IECM_MIN_TXQ_COMPLQ_DESC;
		}
	} else {
		vport->txq_desc_count =
			IECM_DFLT_TX_Q_DESC_COUNT;
		if (iecm_is_queue_model_split(vport->txq_model)) {
			vport->complq_desc_count =
				IECM_DFLT_TX_COMPLQ_DESC_COUNT;
		}
	}

	if (num_req_rxq_desc)
		vport->rxq_desc_count = num_req_rxq_desc;
	else
		vport->rxq_desc_count = IECM_DFLT_RX_Q_DESC_COUNT;

	for (i = 0; i < num_bufqs; i++) {
		if (!vport->bufq_desc_count[i])
			vport->bufq_desc_count[i] =
				IECM_RX_BUFQ_DESC_COUNT(vport->rxq_desc_count,
							num_bufqs);
	}
}
EXPORT_SYMBOL(iecm_vport_calc_num_q_desc);

/**
 * iecm_vport_calc_total_qs - Calculate total number of queues
 * @adapter: private data struct
 * @vport_msg: message to fill with data
 */
void iecm_vport_calc_total_qs(struct iecm_adapter *adapter,
			      struct virtchnl2_create_vport *vport_msg)
{
	unsigned int num_req_tx_qs = adapter->config_data.num_req_tx_qs;
	unsigned int num_req_rx_qs = adapter->config_data.num_req_rx_qs;
	int dflt_splitq_txq_grps, dflt_singleq_txqs;
	int dflt_splitq_rxq_grps, dflt_singleq_rxqs;
	int num_txq_grps, num_rxq_grps;
	int num_cpus;
	u16 max_q;

	/* Restrict num of queues to cpus online as a default configuration to
	 * give best performance. User can always override to a max number
	 * of queues via ethtool.
	 */
	num_cpus = num_online_cpus();
	max_q = adapter->max_queue_limit;

	dflt_splitq_txq_grps = min_t(int, max_q, num_cpus);
	dflt_singleq_txqs = min_t(int, max_q, num_cpus);
	dflt_splitq_rxq_grps = min_t(int, max_q, num_cpus);
	dflt_singleq_rxqs = min_t(int, max_q, num_cpus);

	if (iecm_is_queue_model_split(le16_to_cpu(vport_msg->txq_model))) {
		num_txq_grps = num_req_tx_qs ? num_req_tx_qs : dflt_splitq_txq_grps;
		vport_msg->num_tx_complq = cpu_to_le16(num_txq_grps *
						       IECM_COMPLQ_PER_GROUP);
		vport_msg->num_tx_q = cpu_to_le16(num_txq_grps *
						  IECM_DFLT_SPLITQ_TXQ_PER_GROUP);
	} else {
		num_txq_grps = IECM_DFLT_SINGLEQ_TX_Q_GROUPS;
		vport_msg->num_tx_q =
				cpu_to_le16(num_txq_grps *
					    (num_req_tx_qs ? num_req_tx_qs :
					    dflt_singleq_txqs));
		vport_msg->num_tx_complq = 0;
	}
	if (iecm_is_queue_model_split(le16_to_cpu(vport_msg->rxq_model))) {
		num_rxq_grps = num_req_rx_qs ? num_req_rx_qs : dflt_splitq_rxq_grps;
		vport_msg->num_rx_bufq =
					cpu_to_le16(num_rxq_grps *
						    IECM_MAX_BUFQS_PER_RXQ_GRP);

		vport_msg->num_rx_q = cpu_to_le16(num_rxq_grps *
						  IECM_DFLT_SPLITQ_RXQ_PER_GROUP);
	} else {
		num_rxq_grps = IECM_DFLT_SINGLEQ_RX_Q_GROUPS;
		vport_msg->num_rx_bufq = 0;
		vport_msg->num_rx_q =
				cpu_to_le16(num_rxq_grps *
					    (num_req_rx_qs ? num_req_rx_qs :
					    dflt_singleq_rxqs));
	}
#ifdef HAVE_XDP_SUPPORT

	/* As we now know new number of Rx and Tx queues,
	 * we can request additional Tx queues for XDP
	 */
	if (adapter->config_data.xdp_prog) {
		/* For each Rx queue request additional Tx queue for XDP use */
		vport_msg->num_tx_q =
				cpu_to_le16(le16_to_cpu(vport_msg->num_tx_q) +
					    le16_to_cpu(vport_msg->num_rx_q));
		if (iecm_is_queue_model_split(le16_to_cpu(vport_msg->txq_model)))
			vport_msg->num_tx_complq = vport_msg->num_tx_q;
	}
#endif /* HAVE_XDP_SUPPORT */
}

/**
 * iecm_vport_calc_num_q_groups - Calculate number of queue groups
 * @vport: vport to calculate q groups for
 */
void iecm_vport_calc_num_q_groups(struct iecm_vport *vport)
{
	if (iecm_is_queue_model_split(vport->txq_model))
		vport->num_txq_grp = vport->num_txq;
	else
		vport->num_txq_grp = IECM_DFLT_SINGLEQ_TX_Q_GROUPS;

	if (iecm_is_queue_model_split(vport->rxq_model))
		vport->num_rxq_grp = vport->num_rxq;
	else
		vport->num_rxq_grp = IECM_DFLT_SINGLEQ_RX_Q_GROUPS;
}
EXPORT_SYMBOL(iecm_vport_calc_num_q_groups);

/**
 * iecm_vport_calc_numq_per_grp - Calculate number of queues per group
 * @vport: vport to calculate queues for
 * @num_txq: int return parameter
 * @num_rxq: int return parameter
 */
static void iecm_vport_calc_numq_per_grp(struct iecm_vport *vport,
					 int *num_txq, int *num_rxq)
{
	if (iecm_is_queue_model_split(vport->txq_model))
		*num_txq = IECM_DFLT_SPLITQ_TXQ_PER_GROUP;
	else
		*num_txq = vport->num_txq;

	if (iecm_is_queue_model_split(vport->rxq_model))
		*num_rxq = IECM_DFLT_SPLITQ_RXQ_PER_GROUP;
	else
		*num_rxq = vport->num_rxq;
}

/**
 * iecm_vport_calc_num_q_vec - Calculate total number of vectors required for
 * this vport
 * @vport: virtual port
 *
 */
void iecm_vport_calc_num_q_vec(struct iecm_vport *vport)
{
	if (iecm_is_queue_model_split(vport->txq_model))
		vport->num_q_vectors = vport->num_txq_grp;
	else
		vport->num_q_vectors = vport->num_txq;
}
EXPORT_SYMBOL(iecm_vport_calc_num_q_vec);

/**
 * iecm_rxq_set_descids - set the descids supported by this queue
 * @vport: virtual port data structure
 * @q: rx queue for which descids are set
 *
 */
static void iecm_rxq_set_descids(struct iecm_vport *vport, struct iecm_queue *q)
{
	if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT) {
		q->rxdids = VIRTCHNL2_RXDID_1_FLEX_SPLITQ_M;
	} else {
		if (vport->base_rxd)
			q->rxdids = VIRTCHNL2_RXDID_1_32B_BASE_M;
		else
			q->rxdids = VIRTCHNL2_RXDID_2_FLEX_SQ_NIC_M;
	}
}

/**
 * iecm_set_vlan_tag_loc - set the tag location for a tx/rx queue
 * @adapter: adapter structure
 * @q: tx/rx queue to set tag location for
 *
 */
static void iecm_set_vlan_tag_loc(struct iecm_adapter *adapter,
				  struct iecm_queue *q)
{
	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_VLAN)) {
		struct virtchnl_vlan_supported_caps *insertion_support;

		insertion_support =
				&adapter->vlan_caps->offloads.insertion_support;
		if (insertion_support->outer) {
			if (insertion_support->outer &
			    VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1)
				set_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG1,
					q->flags);
			else if (insertion_support->outer &
				 VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2)
				set_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG2,
					q->flags);
		} else if (insertion_support->inner) {
			if (insertion_support->inner &
			    VIRTCHNL_VLAN_TAG_LOCATION_L2TAG1)
				set_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG1,
					q->flags);
			else if (insertion_support->inner &
				 VIRTCHNL_VLAN_TAG_LOCATION_L2TAG2)
				set_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG2,
					q->flags);
		}
	} else if (iecm_is_cap_ena(adapter, IECM_BASE_CAPS,
				   VIRTCHNL2_CAP_VLAN)) {
		set_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG1, q->flags);
	}
}

/**
 * iecm_txq_group_alloc - Allocate all txq group resources
 * @vport: vport to allocate txq groups for
 * @num_txq: number of txqs to allocate for each group
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_txq_group_alloc(struct iecm_vport *vport, int num_txq)
{
	int err = 0, i;

	vport->txq_grps = kcalloc(vport->num_txq_grp,
				  sizeof(*vport->txq_grps), GFP_KERNEL);
	if (!vport->txq_grps)
		return -ENOMEM;

	for (i = 0; i < vport->num_txq_grp; i++) {
		struct iecm_txq_group *tx_qgrp = &vport->txq_grps[i];
		int j;

		tx_qgrp->vport = vport;
		tx_qgrp->num_txq = num_txq;

		for (j = 0; j < tx_qgrp->num_txq; j++) {
			tx_qgrp->txqs[j] = kzalloc(sizeof(*tx_qgrp->txqs[j]),
						   GFP_KERNEL);
			if (!tx_qgrp->txqs[j]) {
				err = -ENOMEM;
				goto err_alloc;
			}
		}

		for (j = 0; j < tx_qgrp->num_txq; j++) {
			struct iecm_queue *q = tx_qgrp->txqs[j];

			q->dev = &vport->adapter->pdev->dev;
			q->desc_count = vport->txq_desc_count;
			q->tx_max_bufs =
				vport->adapter->dev_ops.vc_ops.get_max_tx_bufs(vport->adapter);
			q->vport = vport;
			q->txq_grp = tx_qgrp;
			hash_init(q->sched_buf_hash);

			if (!iecm_is_cap_ena(vport->adapter,
					     IECM_OTHER_CAPS,
					     VIRTCHNL2_CAP_SPLITQ_QSCHED))
				set_bit(__IECM_Q_FLOW_SCH_EN, q->flags);

			if (iecm_is_cap_ena(vport->adapter,
					    IECM_OTHER_CAPS,
					    VIRTCHNL2_CAP_WB_ON_ITR))
				set_bit(__IECM_ADQ_TX_WB_ON_ITR, q->flags);
			iecm_set_vlan_tag_loc(vport->adapter, q);
		}

		if (!iecm_is_queue_model_split(vport->txq_model))
			continue;

		tx_qgrp->complq = kcalloc(IECM_COMPLQ_PER_GROUP,
					  sizeof(*tx_qgrp->complq),
					  GFP_KERNEL);
		if (!tx_qgrp->complq) {
			err = -ENOMEM;
			goto err_alloc;
		}

		tx_qgrp->complq->dev = &vport->adapter->pdev->dev;
		tx_qgrp->complq->desc_count = vport->complq_desc_count;
		tx_qgrp->complq->vport = vport;
		tx_qgrp->complq->txq_grp = tx_qgrp;
	}

err_alloc:
	if (err)
		iecm_txq_group_rel(vport);
	return err;
}

#ifdef HAVE_NETDEV_BPF_XSK_POOL
/**
 * iecm_get_xsk_pool - get xsk_pool pointer from netdev
 * @q: queue to use
 * @xdp_txq: true if queue pointed by q parameter represents XDP Tx queue, false otherwise
 *
 * Assigns pointer to xsk_pool field in queue struct if it is supported in
 * netdev, NULL otherwise.
 */
static void iecm_get_xsk_pool(struct iecm_queue *q, bool xdp_txq)
{
	int qid;

	if (!iecm_xdp_is_prog_ena(q->vport)) {
		q->xsk_pool = NULL;
		return;
	}

	qid = xdp_txq ? q->idx - q->vport->xdp_txq_offset : q->idx;
	q->xsk_pool = xsk_get_pool_from_qid(q->vport->netdev, qid);
}
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

/**
 * iecm_rxq_group_alloc - Allocate all rxq group resources
 * @vport: vport to allocate rxq groups for
 * @num_rxq: number of rxqs to allocate for each group
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_rxq_group_alloc(struct iecm_vport *vport, int num_rxq)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_queue *q;
	int i, k, err = 0;

	vport->rxq_grps = kcalloc(vport->num_rxq_grp,
				  sizeof(struct iecm_rxq_group), GFP_KERNEL);
	if (!vport->rxq_grps)
		return -ENOMEM;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct iecm_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		int j;

		rx_qgrp->vport = vport;
		if (iecm_is_queue_model_split(vport->rxq_model)) {
			rx_qgrp->splitq.num_rxq_sets = num_rxq;

			for (j = 0; j < num_rxq; j++) {
				rx_qgrp->splitq.rxq_sets[j] =
					kzalloc(sizeof(struct iecm_rxq_set),
						GFP_KERNEL);
				if (!rx_qgrp->splitq.rxq_sets[j]) {
					err = -ENOMEM;
					goto err_alloc;
				}
			}

			rx_qgrp->splitq.bufq_sets = kcalloc(vport->num_bufqs_per_qgrp,
							    sizeof(struct iecm_bufq_set),
							    GFP_KERNEL);
			if (!rx_qgrp->splitq.bufq_sets) {
				err = -ENOMEM;
				goto err_alloc;
			}

			for (j = 0; j < vport->num_bufqs_per_qgrp; j++) {
				struct iecm_bufq_set *bufq_set =
					&rx_qgrp->splitq.bufq_sets[j];
				int swq_size = sizeof(struct iecm_sw_queue);

				q = &rx_qgrp->splitq.bufq_sets[j].bufq;
				q->dev = &adapter->pdev->dev;
				q->desc_count = vport->bufq_desc_count[j];
				q->vport = vport;
				q->rxq_grp = rx_qgrp;
				q->idx = j;
				q->rx_buf_size = vport->bufq_size[j];
				q->rx_buffer_low_watermark = IECM_LOW_WATERMARK;
				q->rx_buf_stride = IECM_RX_BUF_STRIDE;

				if (test_bit(__IECM_PRIV_FLAGS_HDR_SPLIT,
					     adapter->config_data.user_flags)) {
					q->rx_hsplit_en = true;
					q->rx_hbuf_size = IECM_HDR_BUF_SIZE;
				}

				bufq_set->num_refillqs = num_rxq;
				bufq_set->refillqs = kcalloc(num_rxq,
							     swq_size,
							     GFP_KERNEL);
				if (!bufq_set->refillqs) {
					err = -ENOMEM;
					goto err_alloc;
				}
				for (k = 0; k < bufq_set->num_refillqs; k++) {
					struct iecm_sw_queue *refillq =
						&bufq_set->refillqs[k];

					refillq->dev =
						&vport->adapter->pdev->dev;
					refillq->buf_size = q->rx_buf_size;
					refillq->desc_count =
						vport->bufq_desc_count[j];
					set_bit(__IECM_Q_GEN_CHK,
						refillq->flags);
					set_bit(__IECM_RFLQ_GEN_CHK,
						refillq->flags);
					refillq->ring = kcalloc(refillq->desc_count,
								sizeof(u16),
								GFP_KERNEL);
					if (!refillq->ring) {
						err = -ENOMEM;
						goto err_alloc;
					}
				}
			}
		} else {
			rx_qgrp->singleq.num_rxq = num_rxq;
			for (j = 0; j < num_rxq; j++) {
				rx_qgrp->singleq.rxqs[j] = kzalloc(sizeof(struct iecm_queue),
								   GFP_KERNEL);
				if (!rx_qgrp->singleq.rxqs[j]) {
					err = -ENOMEM;
					goto err_alloc;
				}
			}
		}

		for (j = 0; j < num_rxq; j++) {
			if (iecm_is_queue_model_split(vport->rxq_model)) {
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
				rx_qgrp->splitq.rxq_sets[j]->refillq0 =
				      &rx_qgrp->splitq.bufq_sets[0].refillqs[j];
				rx_qgrp->splitq.rxq_sets[j]->refillq1 =
				      &rx_qgrp->splitq.bufq_sets[1].refillqs[j];

				if (test_bit(__IECM_PRIV_FLAGS_HDR_SPLIT,
					     adapter->config_data.user_flags)) {
					q->rx_hsplit_en = true;
					q->rx_hbuf_size = IECM_HDR_BUF_SIZE;
				}
			} else {
				q = rx_qgrp->singleq.rxqs[j];
			}
			q->dev = &adapter->pdev->dev;
			q->desc_count = vport->rxq_desc_count;
			q->vport = vport;
			q->rxq_grp = rx_qgrp;
			q->idx = (i * num_rxq) + j;
			/* In splitq mode, RXQ buffer size should be
			 * set to that of the first buffer queue
			 * associated with this RXQ
			 */
			q->rx_buf_size = vport->bufq_size[0];
			q->rx_buffer_low_watermark = IECM_LOW_WATERMARK;
			q->rx_max_pkt_size = vport->netdev->mtu +
							IECM_PACKET_HDR_PAD;
			iecm_rxq_set_descids(vport, q);
			iecm_set_vlan_tag_loc(adapter, q);
#ifdef HAVE_XDP_SUPPORT
			WRITE_ONCE(q->xdp_prog, adapter->config_data.xdp_prog);
#ifdef HAVE_XDP_BUFF_RXQ
			if (!xdp_rxq_info_is_reg(&q->xdp_rxq))
				xdp_rxq_info_reg(&q->xdp_rxq, q->vport->netdev,
						 q->idx, 0);

#ifdef HAVE_NETDEV_BPF_XSK_POOL
			/* For AF_XDP we are assuming that the queue id received from
			 * the user space is mapped to the pair of queues:
			 *  - Rx queue where queue id is mapped to the queue index (q->idx)
			 *  - XDP Tx queue where queue id is mapped to the queue index,
			 *    considering the XDP offset (q->idx + vport->xdp_txq_offset).
			 */
			iecm_get_xsk_pool(q, false);

			/* Store xsk_pool pointer also in both bufqs in the rxq_group to identify
			 * xsk path while allocating buffers
			 */
			if (iecm_is_queue_model_split(vport->rxq_model))
				for (k = 0; k < IECM_MAX_BUFQS_PER_RXQ_GRP; k++)
					rx_qgrp->splitq.bufq_sets[k].bufq.xsk_pool = q->xsk_pool;

			if (q->xsk_pool) {
				xdp_rxq_info_unreg_mem_model(&q->xdp_rxq);

				q->rx_buf_size = xsk_pool_get_rx_frame_size(q->xsk_pool);
				err = xdp_rxq_info_reg_mem_model(&q->xdp_rxq,
								 MEM_TYPE_XSK_BUFF_POOL, NULL);

				if (err)
					goto err_alloc;
				xsk_pool_set_rxq_info(q->xsk_pool, &q->xdp_rxq);
			} else {
				err = xdp_rxq_info_reg_mem_model(&q->xdp_rxq,
								 MEM_TYPE_PAGE_SHARED, NULL);
				if (err)
					goto err_alloc;
			}
#else
			err = xdp_rxq_info_reg_mem_model(&q->xdp_rxq,
							 MEM_TYPE_PAGE_SHARED, NULL);
			if (err)
				goto err_alloc;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_BUFF_RXQ */
#endif /* HAVE_XDP_SUPPORT */
		}
	}
err_alloc:
	if (err)
		iecm_rxq_group_rel(vport);
	return err;
}

/**
 * iecm_vport_queue_grp_alloc_all - Allocate all queue groups/resources
 * @vport: vport with qgrps to allocate
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_vport_queue_grp_alloc_all(struct iecm_vport *vport)
{
	int num_txq, num_rxq;
	int err;

	iecm_vport_calc_numq_per_grp(vport, &num_txq, &num_rxq);

	err = iecm_txq_group_alloc(vport, num_txq);
	if (err)
		goto err_out;

	err = iecm_rxq_group_alloc(vport, num_rxq);
err_out:
	if (err)
		iecm_vport_queue_grp_rel_all(vport);
	return err;
}

/**
 * iecm_vport_queues_alloc - Allocate memory for all queues
 * @vport: virtual port
 *
 * Allocate memory for queues associated with a vport.  Returns 0 on success,
 * negative on failure.
 */
int iecm_vport_queues_alloc(struct iecm_vport *vport)
{
	int err;
#ifdef HAVE_ETF_SUPPORT
	int i;
#endif

	err = iecm_vport_queue_grp_alloc_all(vport);
	if (err)
		goto err_out;

	err = iecm_tx_desc_alloc_all(vport);
	if (err)
		goto err_out;

	err = iecm_rx_desc_alloc_all(vport);
	if (err)
		goto err_out;

	err = iecm_vport_init_fast_path_txqs(vport);
	if (err)
		goto err_out;

#ifdef HAVE_ETF_SUPPORT
	/* Initialize flow scheduling for queues that were requested
	 * before the interface was brought up
	 */
	for (i = 0; i < vport->num_txq; i++) {
		if (test_bit(i, vport->adapter->config_data.etf_qenable)) {
			set_bit(__IECM_Q_FLOW_SCH_EN, vport->txqs[i]->flags);
			set_bit(__IECM_Q_ETF_EN, vport->txqs[i]->flags);
		}
	}

#endif /* HAVE_ETF_SUPPORT */
#ifdef HAVE_XDP_SUPPORT
	if (iecm_xdp_is_prog_ena(vport)) {
		int j;

		for (j = vport->xdp_txq_offset; j < vport->num_txq; j++) {
			set_bit(__IECM_Q_XDP, vport->txqs[j]->flags);
#ifdef HAVE_NETDEV_BPF_XSK_POOL
			/* For AF_XDP we are assuming that the queue id received from
			 * the user space is mapped to the pair of queues:
			 *  - Rx queue where queue id is mapped to the queue index (q->idx)
			 *  - XDP Tx queue where queue id is mapped to the queue index,
			 *    considering the XDP offset (q->idx + vport->xdp_txq_offset).
			 */
			iecm_get_xsk_pool(vport->txqs[j], true);
#endif
		}
	}

#endif /* HAVE_XDP_SUPPORT */
	return 0;
err_out:
	iecm_vport_queues_rel(vport);
	return err;
}

/**
 * iecm_tx_find_q - Find the tx q based on q id
 * @vport: the vport we care about
 * @q_id: Id of the queue
 *
 * Returns queue ptr if found else returns NULL
 */
static struct iecm_queue *
iecm_tx_find_q(struct iecm_vport *vport, int q_id)
{
	int i;

	for (i = 0; i < vport->num_txq; i++) {
		struct iecm_queue *tx_q = vport->txqs[i];

		if (tx_q->q_id == q_id)
			return tx_q;
	}

	return NULL;
}

/**
 * iecm_tx_handle_sw_marker - Handle queue marker packet
 * @tx_q: tx queue to handle software marker
 */
static void iecm_tx_handle_sw_marker(struct iecm_queue *tx_q)
{
	struct iecm_vport *vport = tx_q->vport;
	bool drain_complete = true;
	int i;

	clear_bit(__IECM_Q_SW_MARKER, tx_q->flags);
	/* Hardware must write marker packets to all queues associated with
	 * completion queues. So check if all queues received marker packets
	 */
	for (i = 0; i < vport->num_txq; i++) {
		if (test_bit(__IECM_Q_SW_MARKER, vport->txqs[i]->flags))
			drain_complete = false;
	}
	if (drain_complete) {
		set_bit(__IECM_SW_MARKER, vport->adapter->flags);
		wake_up(&vport->adapter->sw_marker_wq);
	}
}

/**
 * iecm_tx_splitq_clean_buf - Clean TX buffer resources
 * @tx_q: tx queue to clean buffer from
 * @tx_buf: buffer to be cleaned
 * @napi_budget: Used to determine if we are in netpoll
 */
static void
iecm_tx_splitq_clean_buf(struct iecm_queue *tx_q, struct iecm_tx_buf *tx_buf,
			 int napi_budget)
{
#ifdef HAVE_XDP_SUPPORT
	if (test_bit(__IECM_Q_XDP, tx_q->flags))
#ifdef HAVE_XDP_FRAME_STRUCT
		xdp_return_frame(tx_buf->xdpf);
#else
		page_frag_free(tx_buf->raw_buf);
#endif
	else
		/* free the skb */
		napi_consume_skb(tx_buf->skb, napi_budget);
#else
	napi_consume_skb(tx_buf->skb, napi_budget);
#endif /* HAVE_XDP_SUPPORT */

	/* unmap skb header data */
	dma_unmap_single(tx_q->dev,
			 dma_unmap_addr(tx_buf, dma),
			 dma_unmap_len(tx_buf, len),
			 DMA_TO_DEVICE);

	/* clear tx_buf data */
	tx_buf->skb = NULL;
	dma_unmap_len_set(tx_buf, len, 0);
}

/**
 * iecm_stash_flow_sch_buffers - store buffere parameter info to be freed at a
 * later time (only relevant for flow scheduling mode)
 * @txq: Tx queue to clean
 * @tx_buf: buffer to store
 */
static int
iecm_stash_flow_sch_buffers(struct iecm_queue *txq, struct iecm_tx_buf *tx_buf)
{
	struct iecm_adapter *adapter = txq->vport->adapter;
	struct iecm_tx_buf *shadow_buf;

	shadow_buf = iecm_buf_lifo_pop(&txq->buf_stack);
	if (!shadow_buf) {
		dev_err(&adapter->pdev->dev,
			"No out-of-order TX buffers left!\n");
		return -ENOMEM;
	}

	/* Store buffer params in shadow buffer */
	shadow_buf->skb = tx_buf->skb;
	shadow_buf->bytecount = tx_buf->bytecount;
	shadow_buf->gso_segs = tx_buf->gso_segs;
	dma_unmap_addr_set(shadow_buf, dma, dma_unmap_addr(tx_buf, dma));
	dma_unmap_len_set(shadow_buf, len, dma_unmap_len(tx_buf, len));
	shadow_buf->compl_tag = tx_buf->compl_tag;

	/* Add buffer to buf_hash table to be freed
	 * later
	 */
	hash_add(txq->sched_buf_hash, &shadow_buf->hlist,
		 shadow_buf->compl_tag);

	memset(tx_buf, 0, sizeof(struct iecm_tx_buf));

	return 0;
}

/**
 * iecm_tx_splitq_clean - Reclaim resources from buffer queue
 * @tx_q: Tx queue to clean
 * @end: queue index until which it should be cleaned
 * @napi_budget: Used to determine if we are in netpoll
 * @descs_only: true if queue is using flow-based scheduling and should
 * not clean buffers at this time
 *
 * Cleans the queue descriptor ring. If the queue is using queue-based
 * scheduling, the buffers will be cleaned as well and this function will
 * return the number of bytes/packets cleaned. If the queue is using flow-based
 * scheduling, only the descriptors are cleaned at this time. Separate packet
 * completion events will be reported on the completion queue, and the the
 * buffers will be cleaned separately. The stats returned from this function
 * when using flow-based scheduling are irrelevant.
 */
static struct iecm_tx_queue_stats
iecm_tx_splitq_clean(struct iecm_queue *tx_q, u16 end, int napi_budget,
		     bool descs_only)
{
	union iecm_tx_flex_desc *next_pending_desc = NULL;
	struct iecm_tx_queue_stats cleaned_stats = {0};
	union iecm_tx_flex_desc *tx_desc;
	s16 ntc = tx_q->next_to_clean;
	struct iecm_tx_buf *tx_buf;
	unsigned short gso_segs = 0;
	unsigned int bytecount = 0;
	struct netdev_queue *nq;

	tx_desc = IECM_FLEX_TX_DESC(tx_q, ntc);
	next_pending_desc = IECM_FLEX_TX_DESC(tx_q, end);
	tx_buf = &tx_q->tx_buf[ntc];
	ntc -= tx_q->desc_count;

	while (tx_desc != next_pending_desc) {
		union iecm_tx_flex_desc *eop_desc =
			(union iecm_tx_flex_desc *)tx_buf->next_to_watch;

		/* clear next_to_watch to prevent false hangs */
		tx_buf->next_to_watch = NULL;

		bytecount += tx_buf->bytecount;
		gso_segs += tx_buf->gso_segs;

		if (descs_only) {
			if (iecm_stash_flow_sch_buffers(tx_q, tx_buf))
				goto tx_splitq_clean_out;

			while (tx_desc != eop_desc) {
				tx_buf++;
				tx_desc++;
				ntc++;
				if (unlikely(!ntc)) {
					ntc -= tx_q->desc_count;
					tx_buf = tx_q->tx_buf;
					tx_desc = IECM_FLEX_TX_DESC(tx_q, 0);
				}

				if (dma_unmap_len(tx_buf, len)) {
					if (iecm_stash_flow_sch_buffers(tx_q,
									tx_buf))
						goto tx_splitq_clean_out;
				}
			}
		} else {
			/* update the statistics for this packet */
			cleaned_stats.bytes += tx_buf->bytecount;
			cleaned_stats.packets += tx_buf->gso_segs;

			iecm_tx_splitq_clean_buf(tx_q, tx_buf, napi_budget);

			/* unmap remaining buffers */
			while (tx_desc != eop_desc) {
				tx_buf++;
				tx_desc++;
				ntc++;
				if (unlikely(!ntc)) {
					ntc -= tx_q->desc_count;
					tx_buf = tx_q->tx_buf;
					tx_desc = IECM_FLEX_TX_DESC(tx_q, 0);
				}

				/* unmap any remaining paged data */
				if (dma_unmap_len(tx_buf, len)) {
					dma_unmap_page(tx_q->dev,
						       dma_unmap_addr(tx_buf, dma),
						       dma_unmap_len(tx_buf, len),
						       DMA_TO_DEVICE);
					dma_unmap_len_set(tx_buf, len, 0);
				}
			}
		}

		tx_buf++;
		tx_desc++;
		ntc++;
		if (unlikely(!ntc)) {
			ntc -= tx_q->desc_count;
			tx_buf = tx_q->tx_buf;
			tx_desc = IECM_FLEX_TX_DESC(tx_q, 0);
		}
	}

tx_splitq_clean_out:
	ntc += tx_q->desc_count;
	tx_q->next_to_clean = ntc;

#ifdef HAVE_XDP_SUPPORT
	if (test_bit(__IECM_Q_XDP, tx_q->flags))
		return cleaned_stats;
#endif /* HAVE_XDP_SUPPORT*/

	nq = netdev_get_tx_queue(tx_q->vport->netdev, tx_q->idx);
	netdev_tx_completed_queue(nq, gso_segs, bytecount);

	return cleaned_stats;
}

/**
 * iecm_tx_hw_tstamp - report hw timestamp from completion desc to stack
 * @skb: original skb
 * @desc_ts: pointer to 3 byte timestamp from descriptor
 */
static void iecm_tx_hw_tstamp(struct sk_buff *skb, u8 *desc_ts)
{
	struct skb_shared_hwtstamps hwtstamps;
	u64 tstamp;

	/* Only report timestamp to stack if requested */
	if (!likely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP))
		return;

	tstamp = (desc_ts[0] | (desc_ts[1] << 8) | (desc_ts[2] << 16));
	hwtstamps.hwtstamp =
		ns_to_ktime(tstamp << IECM_TW_TIME_STAMP_GRAN_512_DIV_S);

	skb_tstamp_tx(skb, &hwtstamps);
}

/**
 * iecm_tx_clean_flow_sch_bufs - clean bufs that were stored for
 * out of order completions
 * @txq: queue to clean
 * @compl_tag: completion tag of packet to clean (from completion descriptor)
 * @desc_ts: pointer to 3 byte timestamp from descriptor
 * @budget: Used to determine if we are in netpoll
 */
static struct iecm_tx_queue_stats
iecm_tx_clean_flow_sch_bufs(struct iecm_queue *txq, u16 compl_tag,
			    u8 *desc_ts,
			    int budget)
{
	struct iecm_tx_queue_stats cleaned_stats = {0};
	struct hlist_node *tmp_buf = NULL;
	struct iecm_tx_buf *tx_buf = NULL;

	/* Buffer completion */
	hash_for_each_possible_safe(txq->sched_buf_hash, tx_buf, tmp_buf,
				    hlist, compl_tag) {
		if (tx_buf->compl_tag != compl_tag)
			continue;

#ifdef HAVE_XDP_SUPPORT
		if (test_bit(__IECM_Q_XDP, txq->flags)) {
			iecm_tx_splitq_clean_buf(txq, tx_buf, budget);
			goto stack;
		}
#endif /* HAVE_XDP_SUPPORT */
		if (likely(tx_buf->skb)) {
			/* fetch timestamp from completion
			 * descriptor to report to stack
			 */
			iecm_tx_hw_tstamp(tx_buf->skb, desc_ts);

			/* update the statistics for this packet */
			cleaned_stats.bytes += tx_buf->bytecount;
			cleaned_stats.packets += tx_buf->gso_segs;

			iecm_tx_splitq_clean_buf(txq, tx_buf, budget);
		} else if (dma_unmap_len(tx_buf, len)) {
			dma_unmap_page(txq->dev,
				       dma_unmap_addr(tx_buf, dma),
				       dma_unmap_len(tx_buf, len),
				       DMA_TO_DEVICE);
			dma_unmap_len_set(tx_buf, len, 0);
		}
#ifdef HAVE_XDP_SUPPORT
stack:
#endif /* HAVE_XDP_SUPPORT */
		/* Push shadow buf back onto stack */
		iecm_buf_lifo_push(&txq->buf_stack, tx_buf);

		hash_del(&tx_buf->hlist);
	}

	return cleaned_stats;
}

/**
 * iecm_tx_clean_complq - Reclaim resources on completion queue
 * @complq: Tx ring to clean
 * @budget: Used to determine if we are in netpoll
 *
 * Returns true if there's any budget left (e.g. the clean is finished)
 */
static bool
iecm_tx_clean_complq(struct iecm_queue *complq, int budget)
{
	struct iecm_splitq_tx_compl_desc *tx_desc;
	struct iecm_vport *vport = complq->vport;
	s16 ntc = complq->next_to_clean;
	bool clean_completed = false;
	unsigned int complq_budget;
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	bool xsk_completed = true;
	int i;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */

	complq_budget = vport->compln_clean_budget;
	tx_desc = IECM_SPLITQ_TX_COMPLQ_DESC(complq, ntc);
	ntc -= complq->desc_count;

	do {
		struct iecm_tx_queue_stats cleaned_stats = {0};
		struct iecm_queue *tx_q;
		u16 compl_tag, hw_head;
		int tx_qid;
		u8 ctype;	/* completion type */
		u16 gen;

		/* if the descriptor isn't done, no work yet to do */
		gen = (le16_to_cpu(tx_desc->qid_comptype_gen) &
		      IECM_TXD_COMPLQ_GEN_M) >> IECM_TXD_COMPLQ_GEN_S;
		if (test_bit(__IECM_Q_GEN_CHK, complq->flags) != gen)
			break;

		/* Find necessary info of TX queue to clean buffers */
		tx_qid = (le16_to_cpu(tx_desc->qid_comptype_gen) &
			 IECM_TXD_COMPLQ_QID_M) >> IECM_TXD_COMPLQ_QID_S;
		tx_q = iecm_tx_find_q(vport, tx_qid);
		if (!tx_q) {
			dev_err(&complq->vport->adapter->pdev->dev,
				"TxQ #%d not found\n", tx_qid);
			goto fetch_next_desc;
		}

		/* Determine completion type */
		ctype = (le16_to_cpu(tx_desc->qid_comptype_gen) &
			IECM_TXD_COMPLQ_COMPL_TYPE_M) >>
			IECM_TXD_COMPLQ_COMPL_TYPE_S;
		switch (ctype) {
		case IECM_TXD_COMPLT_RE:
			hw_head = le16_to_cpu(tx_desc->q_head_compl_tag.q_head);

			cleaned_stats = iecm_tx_splitq_clean(tx_q, hw_head,
							     budget, true);
			break;
		case IECM_TXD_COMPLT_RS:
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL
			if (tx_q->xsk_pool) {
				hw_head = le16_to_cpu(tx_desc->q_head_compl_tag.q_head);
				cleaned_stats = iecm_tx_splitq_clean_zc(tx_q, hw_head);

				break;
			}
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */
			if (test_bit(__IECM_Q_FLOW_SCH_EN, tx_q->flags)) {
				compl_tag =
				le16_to_cpu(tx_desc->q_head_compl_tag.compl_tag);

				cleaned_stats =
					iecm_tx_clean_flow_sch_bufs(tx_q,
								    compl_tag,
								    tx_desc->ts,
								    budget);
			} else {
				hw_head =
				le16_to_cpu(tx_desc->q_head_compl_tag.q_head);

				cleaned_stats = iecm_tx_splitq_clean(tx_q,
								     hw_head,
								     budget,
								     false);
			}

			break;
		case IECM_TXD_COMPLT_SW_MARKER:
			iecm_tx_handle_sw_marker(tx_q);
			break;
		default:
			dev_err(&tx_q->vport->adapter->pdev->dev,
				"Unknown TX completion type: %d\n",
				ctype);
			goto fetch_next_desc;
		}

		u64_stats_update_begin(&tx_q->stats_sync);
		tx_q->q_stats.tx.packets += cleaned_stats.packets;
		tx_q->q_stats.tx.bytes += cleaned_stats.bytes;
		complq->num_completions++;
		u64_stats_update_end(&tx_q->stats_sync);

#ifdef HAVE_XDP_SUPPORT
		if (test_bit(__IECM_Q_XDP, tx_q->flags))
			goto fetch_next_desc;
#endif /* HAVE_XDP_SUPPORT */
		if (unlikely(cleaned_stats.packets &&
			     netif_carrier_ok(tx_q->vport->netdev) &&
			     (IECM_DESC_UNUSED(tx_q) >= IECM_TX_WAKE_THRESH) &&
			     (IECM_TX_BUF_UNUSED(tx_q) >= tx_q->desc_count >> 2) &&
			     (IECM_TX_COMPLQ_PENDING(tx_q->txq_grp) <
			      IECM_TX_COMPLQ_OVERFLOW_THRESH(complq)))) {
			/* Make sure any other threads stopping queue after
			 * this see new next_to_clean.
			 */
			smp_mb();
			if (tx_q->vport->adapter->state == __IECM_UP &&
			    __netif_subqueue_stopped(tx_q->vport->netdev,
						     tx_q->idx)) {
				netif_wake_subqueue(tx_q->vport->netdev,
						    tx_q->idx);
			}
		}

fetch_next_desc:
		tx_desc++;
		ntc++;
		if (unlikely(!ntc)) {
			ntc -= complq->desc_count;
			tx_desc = IECM_SPLITQ_TX_COMPLQ_DESC(complq, 0);
			change_bit(__IECM_Q_GEN_CHK, complq->flags);
		}

		prefetch(tx_desc);

		/* update budget accounting */
		complq_budget--;
	} while (likely(complq_budget));

#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	/* In splitq implementation we do not track Tx descriptors.
	 * Instead, we know the Tx completion status from the completion queue
	 * only. Moreover, for AF_XDP we support asynchronous Tx by waking up
	 * the NAPI context and performing descriptor cleaning.
	 * In such a scenario, we have to explicitly trigger an 'xmit' action
	 * from here for all AF_XDP queues. Otherwise, no packet would be xmitted
	 * (because we look at the completion queue first).
	 */
	for (i = 0; i < complq->txq_grp->num_txq; ++i) {
		struct iecm_queue *xdp_q = complq->txq_grp->txqs[i];

		if (xdp_q->xsk_pool)
			xsk_completed = xsk_completed && iecm_tx_splitq_xmit_zc(xdp_q);
	}
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */

	ntc += complq->desc_count;
	complq->next_to_clean = ntc;

	clean_completed = !!complq_budget;

#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	clean_completed = clean_completed && xsk_completed;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */

	return clean_completed;
}

/**
 * iecm_tx_splitq_build_ctb - populate command tag and size for queue
 * based scheduling descriptors
 * @desc: descriptor to populate
 * @parms: pointer to tx params struct
 * @td_cmd: command to be filled in desc
 * @size: size of buffer
 */
void
iecm_tx_splitq_build_ctb(union iecm_tx_flex_desc *desc,
			 struct iecm_tx_splitq_params *parms,
			 u16 td_cmd, u16 size)
{
	desc->q.qw1.cmd_dtype =
		cpu_to_le16(parms->dtype & IECM_FLEX_TXD_QW1_DTYPE_M);
	desc->q.qw1.cmd_dtype |=
		cpu_to_le16((td_cmd << IECM_FLEX_TXD_QW1_CMD_S) &
			    IECM_FLEX_TXD_QW1_CMD_M);
	desc->q.qw1.buf_size = cpu_to_le16((u16)size);
	desc->q.qw1.flex.l2tags.l2tag1 = cpu_to_le16(parms->td_tag);
}

/**
 * iecm_tx_splitq_build_flow_desc - populate command tag and size for flow
 * scheduling descriptors
 * @desc: descriptor to populate
 * @parms: pointer to tx params struct
 * @td_cmd: command to be filled in desc
 * @size: size of buffer
 */
void
iecm_tx_splitq_build_flow_desc(union iecm_tx_flex_desc *desc,
			       struct iecm_tx_splitq_params *parms,
			       u16 td_cmd, u16 size)
{
	desc->flow.qw1.cmd_dtype = (u16)parms->dtype | td_cmd;
	desc->flow.qw1.rxr_bufsize = cpu_to_le16((u16)size);
	desc->flow.qw1.compl_tag = cpu_to_le16(parms->compl_tag);

	desc->flow.qw1.ts[0] = parms->offload.desc_ts[0];
	desc->flow.qw1.ts[1] = parms->offload.desc_ts[1];
	desc->flow.qw1.ts[2] = parms->offload.desc_ts[2];
}

/**
 * __iecm_tx_maybe_stop_common - 2nd level check for common Tx stop conditions
 * @tx_q: the queue to be checked
 * @size: the size buffer we want to assure is available
 *
 * Returns -EBUSY if a stop is needed, else 0
 */
static int
__iecm_tx_maybe_stop_common(struct iecm_queue *tx_q, unsigned int size)
{
	netif_stop_subqueue(tx_q->vport->netdev, tx_q->idx);

	/* Memory barrier before checking head and tail */
	smp_mb();

	/* Check again in a case another CPU has just made room available. */
	if (likely(IECM_DESC_UNUSED(tx_q) < size))
		return -EBUSY;

	/* A reprieve! - use start_subqueue because it doesn't call schedule */
	netif_start_subqueue(tx_q->vport->netdev, tx_q->idx);

	return 0;
}

/**
 * iecm_tx_maybe_stop_common - 1st level check for common Tx stop conditions
 * @tx_q: the queue to be checked
 * @size: number of descriptors we want to assure is available
 *
 * Returns 0 if stop is not needed
 */
int iecm_tx_maybe_stop_common(struct iecm_queue *tx_q, unsigned int size)
{
	if (likely(IECM_DESC_UNUSED(tx_q) >= size))
		return 0;

	return __iecm_tx_maybe_stop_common(tx_q, size);
}

/**
 * iecm_tx_maybe_stop_splitq - 1st level check for Tx splitq stop conditions
 * @tx_q: the queue to be checked
 *
 * Returns 0 if stop is not needed
 */
static int iecm_tx_maybe_stop_splitq(struct iecm_queue *tx_q)
{
	/* If there are too many outstanding completions expected on the
	 * completion queue, stop the TX queue to give the device some time to
	 * catch up
	 */
	if (unlikely(IECM_TX_COMPLQ_PENDING(tx_q->txq_grp) >
		     IECM_TX_COMPLQ_OVERFLOW_THRESH(tx_q->txq_grp->complq)))
		goto splitq_stop;

	/* Also check for available book keeping buffers; if we have less than
	 * a quarter of the total desc_count left stop the queue to wait for
	 * more completions
	 */
	if (unlikely(IECM_TX_BUF_UNUSED(tx_q) < tx_q->desc_count >> 2))
		goto splitq_stop;

	return 0;

splitq_stop:
	netif_stop_subqueue(tx_q->vport->netdev, tx_q->idx);
	return -EBUSY;
}

/**
 * iecm_tx_buf_hw_update - Store the new tail and head values
 * @tx_q: queue to bump
 * @val: new head index
 * @xmit_more: more skb's pending
 */
void iecm_tx_buf_hw_update(struct iecm_queue *tx_q, u32 val,
			   bool xmit_more)
{
	struct netdev_queue *nq;

	nq = netdev_get_tx_queue(tx_q->vport->netdev, tx_q->idx);
	tx_q->next_to_use = val;

	iecm_tx_maybe_stop_common(tx_q, IECM_TX_DESC_NEEDED);

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64).
	 */
	wmb();

	/* notify HW of packet */
	if (netif_xmit_stopped(nq) || !xmit_more) {
		writel(val, tx_q->tail);
#ifndef SPIN_UNLOCK_IMPLIES_MMIOWB

		/* we need this if more than one processor can write to our tail
		 * at a time, it synchronizes IO on IA64/Altix systems
		 */
		mmiowb();
#endif /* !SPIN_UNLOCK_IMPLIES_MMIOWB */
	}
}

/**
 * __iecm_tx_desc_count required - Get the number of descriptors needed for Tx
 * @size: transmit request size in bytes
 *
 * Due to hardware alignment restrictions (4K alignment), we need to
 * assume that we can have no more than 12K of data per descriptor, even
 * though each descriptor can take up to 16K - 1 bytes of aligned memory.
 * Thus, we need to divide by 12K. But division is slow! Instead,
 * we decompose the operation into shifts and one relatively cheap
 * multiply operation.
 *
 * To divide by 12K, we first divide by 4K, then divide by 3:
 *     To divide by 4K, shift right by 12 bits
 *     To divide by 3, multiply by 85, then divide by 256
 *     (Divide by 256 is done by shifting right by 8 bits)
 * Finally, we add one to round up. Because 256 isn't an exact multiple of
 * 3, we'll underestimate near each multiple of 12K. This is actually more
 * accurate as we have 4K - 1 of wiggle room that we can fit into the last
 * segment. For our purposes this is accurate out to 1M which is orders of
 * magnitude greater than our largest possible GSO size.
 *
 * This would then be implemented as:
 *     return (((size >> 12) * 85) >> 8) + IECM_TX_DESCS_FOR_SKB_DATA_PTR;
 *
 * Since multiplication and division are commutative, we can reorder
 * operations into:
 *     return ((size * 85) >> 20) + IECM_TX_DESCS_FOR_SKB_DATA_PTR;
 */
unsigned int iecm_size_to_txd_count(unsigned int size)
{
	return ((size * 85) >> 20) + IECM_TX_DESCS_FOR_SKB_DATA_PTR;
}

/**
 * iecm_tx_desc_count_required - calculate number of Tx descriptors needed
 * @skb: send buffer
 *
 * Returns number of data descriptors needed for this skb.
 */
unsigned int iecm_tx_desc_count_required(struct sk_buff *skb)
{
	const skb_frag_t *frag = &skb_shinfo(skb)->frags[0];
	unsigned int nr_frags = skb_shinfo(skb)->nr_frags;
	unsigned int count = 0, size = skb_headlen(skb);

	for (;;) {
		count += iecm_size_to_txd_count(size);

		if (!nr_frags--)
			break;

		size = skb_frag_size(frag++);
	}

	return count;
}

/**
 * iecm_tx_splitq_map - Build the Tx flex descriptor
 * @tx_q: queue to send buffer on
 * @parms: pointer to splitq params struct
 * @first: first buffer info buffer to use
 *
 * This function loops over the skb data pointed to by *first
 * and gets a physical address for each memory location and programs
 * it and the length into the transmit flex descriptor.
 */
static void
iecm_tx_splitq_map(struct iecm_queue *tx_q,
		   struct iecm_tx_splitq_params *parms,
		   struct iecm_tx_buf *first)
{
	union iecm_tx_flex_desc *tx_desc;
	unsigned int data_len, size;
	struct iecm_tx_buf *tx_buf;
	u16 i = tx_q->next_to_use;
	struct netdev_queue *nq;
	struct sk_buff *skb;
	skb_frag_t *frag;
	u16 td_cmd = 0;
	dma_addr_t dma;

	skb = first->skb;

	td_cmd = parms->offload.td_cmd;
	parms->compl_tag = tx_q->tx_buf_key;

	data_len = skb->data_len;
	size = skb_headlen(skb);

	tx_desc = IECM_FLEX_TX_DESC(tx_q, i);

	dma = dma_map_single(tx_q->dev, skb->data, size, DMA_TO_DEVICE);

	tx_buf = first;

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		unsigned int max_data = IECM_TX_MAX_DESC_DATA_ALIGNED;

		if (dma_mapping_error(tx_q->dev, dma))
			goto dma_error;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buf, len, size);
		dma_unmap_addr_set(tx_buf, dma, dma);

		/* align size to end of page */
		max_data += -dma & (IECM_TX_MAX_READ_REQ_SIZE - 1);

		/* buf_addr is in same location for both desc types */
		tx_desc->q.buf_addr = cpu_to_le64(dma);

		/* account for data chunks larger than the hardware
		 * can handle
		 */
		while (unlikely(size > IECM_TX_MAX_DESC_DATA)) {
			parms->splitq_build_ctb(tx_desc, parms, td_cmd,
						max_data);

			tx_desc++;
			i++;

			if (i == tx_q->desc_count) {
				tx_desc = IECM_FLEX_TX_DESC(tx_q, 0);
				i = 0;
			}

			dma += max_data;
			size -= max_data;

			max_data = IECM_TX_MAX_DESC_DATA_ALIGNED;
			/* buf_addr is in same location for both desc types */
			tx_desc->q.buf_addr = cpu_to_le64(dma);
		}

		if (likely(!data_len))
			break;
		parms->splitq_build_ctb(tx_desc, parms, td_cmd, size);
		tx_desc++;
		i++;

		if (i == tx_q->desc_count) {
			tx_desc = IECM_FLEX_TX_DESC(tx_q, 0);
			i = 0;
		}

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_q->dev, frag, 0, size,
				       DMA_TO_DEVICE);

		tx_buf->compl_tag = parms->compl_tag;
		tx_buf = &tx_q->tx_buf[i];
	}

	/* record bytecount for BQL */
	nq = netdev_get_tx_queue(tx_q->vport->netdev, tx_q->idx);
	netdev_tx_sent_queue(nq, first->bytecount);

	/* record SW timestamp if HW timestamp is not available */
	skb_tx_timestamp(first->skb);

	/* write last descriptor with RS and EOP bits */
	td_cmd |= parms->eop_cmd;
	parms->splitq_build_ctb(tx_desc, parms, td_cmd, size);
	i++;
	if (i == tx_q->desc_count)
		i = 0;

	/* set next_to_watch value indicating a packet is present */
	first->next_to_watch = tx_desc;
	tx_buf->compl_tag = parms->compl_tag++;

	tx_q->txq_grp->num_completions_pending++;

	iecm_tx_buf_hw_update(tx_q, i, netdev_xmit_more());

	/* Update TXQ Completion Tag key for next buffer */
	tx_q->tx_buf_key = parms->compl_tag;

	return;

dma_error:
	/* clear dma mappings for failed tx_buf map */
	for (;;) {
		tx_buf = &tx_q->tx_buf[i];
		iecm_tx_buf_rel(tx_q, tx_buf);
		if (tx_buf == first)
			break;
		if (i == 0)
			i = tx_q->desc_count;
		i--;
	}

	tx_q->next_to_use = i;
}

/**
 * iecm_tx_prepare_vlan_flags - prepare generic vlan tagging for HW
 * @tx_q: txq to find the tag location
 * @first: pointer to struct iecm_tx_buf
 * @skb: skb being xmitted
 */
void iecm_tx_prepare_vlan_flags(struct iecm_queue *tx_q,
				struct iecm_tx_buf *first,
				struct sk_buff *skb)
{
	struct iecm_vport *vport = tx_q->vport;
	u32 tx_flags = 0;

	/* Stack sets protocol to 8021q when offload is disabled so SW can take
	 * any necessary steps to handle it.  We don't need to do anything,
	 * just set protocol to encapsulated type.
	 */
	if (skb->protocol == htons(ETH_P_8021Q) &&
#ifdef NETIF_F_HW_VLAN_CTAG_RX
	    !iecm_is_feature_ena(vport, NETIF_F_HW_VLAN_CTAG_RX)) {
#else
	    !iecm_is_feature_ena(vport, NETIF_F_HW_VLAN_RX)) {
#endif /* NETIF_F_HW_VLAN_CTAG_RX */
		skb->protocol = vlan_get_protocol(skb);
		return;
	}

	if (!skb_vlan_tag_present(skb))
		return;

	tx_flags |= skb_vlan_tag_get(skb) << IECM_TX_FLAGS_VLAN_SHIFT;
	tx_flags |= IECM_TX_FLAGS_VLAN_TAG;
	if (test_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG2, tx_q->flags))
		tx_flags |= IECM_TX_FLAGS_HW_OUTER_SINGLE_VLAN;
	else if (test_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG1, tx_q->flags))
		tx_flags |= IECM_TX_FLAGS_HW_VLAN;
	else
		dev_dbg(&vport->adapter->pdev->dev, "Unsupported Tx VLAN tag location requested\n");
#ifdef IECM_ADD_PROBES
	vport->port_stats.extra_stats.tx_vlano++;
#endif /* IECM_ADD_PROBES */

	first->tx_flags |= tx_flags;
}

/**
 * iecm_tso - computes mss and TSO length to prepare for TSO
 * @first: pointer to struct iecm_tx_buf
 * @off: pointer to struct that holds offload parameters
 *
 * Returns error (negative) if TSO doesn't apply to the given skb,
 * 0 otherwise.
 *
 * Note: this function can be used in the splitq and singleq paths
 */
int iecm_tso(struct iecm_tx_buf *first, struct iecm_tx_offload_params *off)
{
	struct sk_buff *skb = first->skb;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		unsigned char *hdr;
	} l4;
	u32 paylen, l4_start;
	int err;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (!skb_is_gso(skb))
		return 0;

	err = skb_cow_head(skb, 0);
	if (err < 0)
		return err;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	/* initialize outer IP header fields */
	if (ip.v4->version == 4) {
		ip.v4->tot_len = 0;
		ip.v4->check = 0;
	} else {
		ip.v6->payload_len = 0;
	}

	/* determine offset of transport header */
	l4_start = l4.hdr - skb->data;

	/* remove payload length from checksum */
	paylen = skb->len - l4_start;

	switch (skb_shinfo(skb)->gso_type) {
	case SKB_GSO_TCPV4:
	case SKB_GSO_TCPV6:
		csum_replace_by_diff(&l4.tcp->check,
				     (__force __wsum)htonl(paylen));

		/* compute length of segmentation header */
		off->tso_hdr_len = (l4.tcp->doff * 4) + l4_start;
		break;
#ifdef NETIF_F_GSO_UDP_L4
	case SKB_GSO_UDP_L4:
		csum_replace_by_diff(&l4.udp->check,
				     (__force __wsum)htonl(paylen));
		/* compute length of segmentation header */
		off->tso_hdr_len = sizeof(struct udphdr) + l4_start;
		l4.udp->len =
			htons(skb_shinfo(skb)->gso_size +
			      sizeof(struct udphdr));
		break;
#endif /* NETIF_F_GSO_UDP_L4 */
	default:
		return -EINVAL;
	}

	off->tso_len = skb->len - off->tso_hdr_len;
	off->mss = skb_shinfo(skb)->gso_size;

	/* update gso_segs and bytecount */
	first->gso_segs = skb_shinfo(skb)->gso_segs;
	first->bytecount += (first->gso_segs - 1) * off->tso_hdr_len;

	first->tx_flags |= IECM_TX_FLAGS_TSO;

	return 0;
}

/**
 * iecm_get_flow_sche_tstamp - fetch timestamp from SKB for
 * flow scheduling offload
 * @skb: send buffer to extract timestamp from
 * @txq: pointer to txq
 * @offload: pointer to offload parameters struct
 */
static void
iecm_get_flow_sche_tstamp(struct sk_buff *skb, struct iecm_queue *txq,
			  struct iecm_tx_offload_params *offload)
{
	struct iecm_adapter *adapter = txq->vport->adapter;
#ifdef HAVE_ETF_SUPPORT
	/* skb timestamp field changed around same time ETF support was added */
	u64 ts_ns = skb->skb_mstamp_ns;
#else
	u64 ts_ns = ktime_to_ns(skb->tstamp);
#endif /* HAVE_ETF_SUPPORT */
	u64 cur_time = 0;

	/* TODO: revisit how to sync device time with OS time */
	if (unlikely(adapter->dev_ops.reg_ops.read_master_time))
		cur_time =
			adapter->dev_ops.reg_ops.read_master_time(&adapter->hw);
	else
		/* When PTM support is enabled host time will be synced with
		 * master timer.
		 */
		cur_time = ktime_get_real_ns();

	/* The format of the timestamp is the 23 least significant bits of
	 * absolute time in units of X ns. Bit 23 indicates overflow if the
	 * given timestamp is beyond current horizon. Zero means no timestamp,
	 * so if the 23 lsb and overflow bit are zero, the timestamp should be
	 * written as 1.
	 */
	if (ts_ns <= cur_time) {
		/* When timestamp is before horizon, use current time
		 * to fill in desc_ts.
		 */
		ts_ns = cur_time >> txq->vport->ts_gran;
		offload->desc_ts[0] = ts_ns & 0xff;
		offload->desc_ts[1] = (ts_ns >> 8) & 0xff;
		offload->desc_ts[2] = ((ts_ns >> 16) & 0x7f);
	} else if (ts_ns <= cur_time + txq->vport->tw_horizon) {
		ts_ns = ts_ns >> txq->vport->ts_gran;

		offload->desc_ts[0] = ts_ns & 0xff;
		offload->desc_ts[1] = (ts_ns >> 8) & 0xff;
		offload->desc_ts[2] = ((ts_ns >> 16) & 0x7f);
	} else {
		/* Set only the SW overflow bit for the whole timestamp field */
		offload->desc_ts[2] = IECM_TXD_FLOW_SCH_HORIZON_OVERFLOW_M;
	}

	/* If the timestamp is zero, set it to 1, as discussed in the comment above. */
	if (!offload->desc_ts[0] && !offload->desc_ts[1] &&
	    !offload->desc_ts[2])
		offload->desc_ts[0] = 0x1;
}

/**
 * __iecm_chk_linearize - Check skb is not using too many buffers
 * @skb: send buffer
 * @max_bufs: maximum number of buffers
 *
 * For TSO we need to count the TSO header and segment payload separately.  As
 * such we need to check cases where we have max_bufs-1 fragments or more as we
 * can potentially require max_bufs+1 DMA transactions, 1 for the TSO header, 1
 * for the segment payload in the first descriptor, and another max_buf-1 for
 * the fragments.
 */
static bool __iecm_chk_linearize(struct sk_buff *skb, unsigned int max_bufs)
{
	const skb_frag_t *frag, *stale;
	int nr_frags, sum;

	/* no need to check if number of frags is less than max_bufs - 1 */
	nr_frags = skb_shinfo(skb)->nr_frags;
	if (nr_frags < (max_bufs - 1))
		return false;

	/* We need to walk through the list and validate that each group
	 * of max_bufs-2 fragments totals at least gso_size.
	 */
	nr_frags -= max_bufs - 2;
	frag = &skb_shinfo(skb)->frags[0];

	/* Initialize size to the negative value of gso_size minus 1.  We use
	 * this as the worst case scenerio in which the frag ahead of us only
	 * provides one byte which is why we are limited to max_bufs-2
	 * descriptors for a single transmit as the header and previous
	 * fragment are already consuming 2 descriptors.
	 */
	sum = 1 - skb_shinfo(skb)->gso_size;

	/* Add size of frags 0 through 4 to create our initial sum */
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);

	/* Walk through fragments adding latest fragment, testing it, and
	 * then removing stale fragments from the sum.
	 */
	for (stale = &skb_shinfo(skb)->frags[0];; stale++) {
		int stale_size = skb_frag_size(stale);

		sum += skb_frag_size(frag++);

		/* The stale fragment may present us with a smaller
		 * descriptor than the actual fragment size. To account
		 * for that we need to remove all the data on the front and
		 * figure out what the remainder would be in the last
		 * descriptor associated with the fragment.
		 */
		if (stale_size > IECM_TX_MAX_DESC_DATA) {
			int align_pad = -(skb_frag_off(stale)) &
					(IECM_TX_MAX_READ_REQ_SIZE - 1);

			sum -= align_pad;
			stale_size -= align_pad;

			do {
				sum -= IECM_TX_MAX_DESC_DATA_ALIGNED;
				stale_size -= IECM_TX_MAX_DESC_DATA_ALIGNED;
			} while (stale_size > IECM_TX_MAX_DESC_DATA);
		}

		/* if sum is negative we failed to make sufficient progress */
		if (sum < 0)
			return true;

		if (!nr_frags--)
			break;

		sum -= stale_size;
	}

	return false;
}

/**
 * iecm_chk_linearize - Check if skb exceeds max descriptors per packet
 * @skb: send buffer
 * @max_bufs: maximum scatter gather buffers for single packet
 * @count: number of buffers this packet needs
 *
 * Make sure we don't exceed maximum scatter gather buffers for a single
 * packet. We have to do some special checking around the boundary (max_bufs-1)
 * if TSO is on since we need count the TSO header and payload separately.
 * E.g.: a packet with 7 fragments can require 9 DMA transactions; 1 for TSO
 * header, 1 for segment payload, and then 7 for the fragments.
 */
bool iecm_chk_linearize(struct sk_buff *skb, unsigned int max_bufs,
			unsigned int count)
{
	if (likely(count < max_bufs))
		return false;
	if (skb_is_gso(skb))
		return __iecm_chk_linearize(skb, max_bufs);

	return count != max_bufs;
}

#ifdef IECM_ADD_PROBES
/**
 * iecm_tx_extra_counters - Add more tx queue stats
 * @txq: transmit queue
 * @first: transmit buffer
 *
 * Increments additional offload counters
 */
void iecm_tx_extra_counters(struct iecm_queue *txq, struct iecm_tx_buf *first)
{
	struct sk_buff *skb = first->skb;
	u8 l4_proto = 0;
	__be16 protocol;

	protocol = vlan_get_protocol(skb);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (protocol == htons(ETH_P_IP)) {
			struct iphdr *v4 =
				(struct iphdr *)skb_network_header(skb);

			txq->vport->port_stats.extra_stats.tx_ip4_cso++;
			l4_proto = v4->protocol;
		} else if (protocol == htons(ETH_P_IPV6)) {
			struct ipv6hdr *v6 =
				(struct ipv6hdr *)skb_network_header(skb);

			l4_proto = v6->nexthdr;
		}

		switch (l4_proto) {
		case IPPROTO_UDP:
			txq->vport->port_stats.extra_stats.tx_udp_cso++;
			break;
		case IPPROTO_TCP:
			txq->vport->port_stats.extra_stats.tx_tcp_cso++;
			break;
		case IPPROTO_SCTP:
			txq->vport->port_stats.extra_stats.tx_sctp_cso++;
		default:
			break;
		}
	}

	if (first->tx_flags & IECM_TX_FLAGS_TSO) {
#ifdef NETIF_F_GSO_UDP_L4
		if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4)
			txq->vport->port_stats.extra_stats.tx_udp_segs += first->gso_segs;
		else
#endif /* NETIF_F_GSO_UDP_L4 */
			txq->vport->port_stats.extra_stats.tx_tcp_segs += first->gso_segs;
	}
}

#endif /* IECM_ADD_PROBES */
/**
 * iecm_tx_splitq_frame - Sends buffer on Tx ring using flex descriptors
 * @skb: send buffer
 * @tx_q: queue to send buffer on
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
static netdev_tx_t
iecm_tx_splitq_frame(struct sk_buff *skb, struct iecm_queue *tx_q)
{
	struct iecm_tx_splitq_params tx_parms = {
		NULL, (enum iecm_tx_desc_dtype_value)0, 0, {0}, {0}
	};
	struct iecm_tx_buf *first;
	unsigned int count;

	count = iecm_tx_desc_count_required(skb);
	if (iecm_chk_linearize(skb, tx_q->tx_max_bufs, count)) {
		if (__skb_linearize(skb)) {
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
		count = iecm_size_to_txd_count(skb->len);
		tx_q->vport->port_stats.tx_linearize++;
	}

	/* Check for basic TX resources */
	if (iecm_tx_maybe_stop_common(tx_q,
				      count + IECM_TX_DESCS_PER_CACHE_LINE +
				      IECM_TX_DESCS_FOR_CTX))
		return NETDEV_TX_BUSY;

	/* Check for splitq specific TX resources */
	if (iecm_tx_maybe_stop_splitq(tx_q))
		return NETDEV_TX_BUSY;

	/* record the location of the first descriptor for this packet */
	first = &tx_q->tx_buf[tx_q->next_to_use];
	first->skb = skb;
	first->bytecount = max_t(unsigned int, skb->len, ETH_ZLEN);
	first->gso_segs = 1;
	first->tx_flags = 0;

	iecm_tx_prepare_vlan_flags(tx_q, first, skb);

	if (iecm_tso(first, &tx_parms.offload) < 0) {
		/* If tso returns an error, drop the packet */
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (first->tx_flags & IECM_TX_FLAGS_TSO) {
		/* If tso is needed, set up context desc */
		union iecm_flex_tx_ctx_desc *ctx_desc;
		int i = tx_q->next_to_use;

		/* grab the next descriptor */
		ctx_desc = IECM_FLEX_TX_CTX_DESC(tx_q, i);
		i++;
		tx_q->next_to_use = (i < tx_q->desc_count) ? i : 0;

		ctx_desc->tso.qw1.cmd_dtype =
				cpu_to_le16(IECM_TX_DESC_DTYPE_FLEX_TSO_CTX |
					    IECM_TX_FLEX_CTX_DESC_CMD_TSO);
		ctx_desc->tso.qw0.flex_tlen =
				cpu_to_le32(tx_parms.offload.tso_len &
					    IECM_TXD_FLEX_CTX_TLEN_M);
		ctx_desc->tso.qw0.mss_rt =
				cpu_to_le16(tx_parms.offload.mss &
					    IECM_TXD_FLEX_CTX_MSS_RT_M);
		ctx_desc->tso.qw0.hdr_len = tx_parms.offload.tso_hdr_len;

		u64_stats_update_begin(&tx_q->stats_sync);
		tx_q->q_stats.tx.lso_pkts++;
		u64_stats_update_end(&tx_q->stats_sync);
	}

#ifdef IECM_ADD_PROBES
	iecm_tx_extra_counters(tx_q, first);

#endif /* IECM_ADD_PROBES */
	if (test_bit(__IECM_Q_FLOW_SCH_EN, tx_q->flags)) {
		if (unlikely(test_bit(__IECM_Q_ETF_EN, tx_q->flags)))
			iecm_get_flow_sche_tstamp(skb, tx_q, &tx_parms.offload);

		tx_parms.dtype = IECM_TX_DESC_DTYPE_FLEX_FLOW_SCHE;
		tx_parms.splitq_build_ctb = iecm_tx_splitq_build_flow_desc;
		tx_parms.eop_cmd =
			IECM_TXD_FLEX_FLOW_CMD_EOP | IECM_TXD_FLEX_FLOW_CMD_RE;

		tx_q->txq_grp->num_completions_pending++;

		if (skb->ip_summed == CHECKSUM_PARTIAL)
			tx_parms.offload.td_cmd |= IECM_TXD_FLEX_FLOW_CMD_CS_EN;

	} else {
		tx_parms.dtype = IECM_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2;
		tx_parms.splitq_build_ctb = iecm_tx_splitq_build_ctb;
		tx_parms.eop_cmd = IECM_TXD_LAST_DESC_CMD;

		if (skb->ip_summed == CHECKSUM_PARTIAL)
			tx_parms.offload.td_cmd |= IECM_TX_FLEX_DESC_CMD_CS_EN;

		/* VLAN Offload can only be used with queue based scheduling */
		if (first->tx_flags & IECM_TX_FLAGS_VLAN_TAG) {
			tx_parms.offload.td_cmd |= (u64)IECM_TX_FLEX_DESC_CMD_IL2TAG1;
			tx_parms.td_tag = (first->tx_flags & IECM_TX_FLAGS_VLAN_MASK) >>
					  IECM_TX_FLAGS_VLAN_SHIFT;
		}
	}

	iecm_tx_splitq_map(tx_q, &tx_parms, first);

	return NETDEV_TX_OK;
}

/**
 * iecm_tx_splitq_start - Selects the right Tx queue to send buffer
 * @skb: send buffer
 * @netdev: network interface device structure
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
netdev_tx_t iecm_tx_splitq_start(struct sk_buff *skb,
				 struct net_device *netdev)
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);
	struct iecm_queue *tx_q;

	tx_q = vport->txqs[skb->queue_mapping];

	/* hardware can't handle really short frames, hardware padding works
	 * beyond this point
	 */
	if (skb_put_padto(skb, IECM_TX_MIN_LEN))
		return NETDEV_TX_OK;

	return iecm_tx_splitq_frame(skb, tx_q);
}

/**
 * iecm_ptype_to_htype - get a hash type
 * @decoded: Decoded Rx packet type related fields
 *
 * Returns appropriate hash type (such as PKT_HASH_TYPE_L2/L3/L4) to be used by
 * skb_set_hash based on PTYPE as parsed by HW Rx pipeline and is part of
 * Rx desc.
 */
enum
pkt_hash_types iecm_ptype_to_htype(struct iecm_rx_ptype_decoded *decoded)
{
	if (!decoded->known)
		return PKT_HASH_TYPE_NONE;
	if (decoded->payload_layer == IECM_RX_PTYPE_PAYLOAD_LAYER_PAY2 &&
	    decoded->inner_prot)
		return PKT_HASH_TYPE_L4;
	if (decoded->payload_layer == IECM_RX_PTYPE_PAYLOAD_LAYER_PAY2 &&
	    decoded->outer_ip)
		return PKT_HASH_TYPE_L3;
	if (decoded->outer_ip == IECM_RX_PTYPE_OUTER_L2)
		return PKT_HASH_TYPE_L2;

	return PKT_HASH_TYPE_NONE;
}

/**
 * iecm_rx_hash - set the hash value in the skb
 * @rxq: Rx descriptor ring packet is being transacted on
 * @skb: pointer to current skb being populated
 * @rx_desc: Receive descriptor
 * @decoded: Decoded Rx packet type related fields
 */
static void
iecm_rx_hash(struct iecm_queue *rxq, struct sk_buff *skb,
	     struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc,
	     struct iecm_rx_ptype_decoded *decoded)
{
	u32 hash;

	if (!iecm_is_feature_ena(rxq->vport, NETIF_F_RXHASH))
		return;

	hash = le16_to_cpu(rx_desc->hash1) |
	       (rx_desc->ff2_mirrid_hash2.hash2 << 16) |
	       (rx_desc->hash3 << 24);

	skb_set_hash(skb, hash, iecm_ptype_to_htype(decoded));
}

#ifdef IECM_ADD_PROBES
/**
 * iecm_rx_extra_counters - Add more stats counters
 * @rxq: receive queue
 * @inner_prot: packet inner protocol
 * @ipv4: is ipv4
 * @csum_bits: checksum fields extracted from the descriptor
 * @splitq: is splitq or singleq
 *
 * Increments additional offload counters.
 */
void iecm_rx_extra_counters(struct iecm_queue *rxq, u32 inner_prot,
			    bool ipv4, struct iecm_rx_csum_decoded *csum_bits,
			    bool splitq)
{
	struct iecm_extra_stats *extra_stats =
					&rxq->vport->port_stats.extra_stats;
	if (ipv4) {
		if (csum_bits->ipe | csum_bits->eipe)
			extra_stats->rx_ip4_cso_err++;
		extra_stats->rx_ip4_cso++;
	}

	if (csum_bits->l4e) {
		switch (inner_prot) {
		case IECM_RX_PTYPE_INNER_PROT_TCP:
			extra_stats->rx_tcp_cso_err++;
			break;
		case IECM_RX_PTYPE_INNER_PROT_UDP:
			extra_stats->rx_udp_cso_err++;
			break;
		case IECM_RX_PTYPE_INNER_PROT_SCTP:
			extra_stats->rx_sctp_cso_err++;
			break;
		default:
			break;
		}
	}

	switch (inner_prot) {
	case IECM_RX_PTYPE_INNER_PROT_TCP:
		extra_stats->rx_tcp_cso++;
		break;
	case IECM_RX_PTYPE_INNER_PROT_UDP:
		extra_stats->rx_udp_cso++;
		break;
	case IECM_RX_PTYPE_INNER_PROT_SCTP:
		extra_stats->rx_sctp_cso++;
		break;
	default:
		break;
	}
}

#endif /* IECM_ADD_PROBES */

/**
 * iecm_rx_csum - Indicate in skb if checksum is good
 * @rxq: Rx descriptor ring packet is being transacted on
 * @skb: pointer to current skb being populated
 * @csum_bits: checksum fields extracted from the descriptor
 * @decoded: Decoded Rx packet type related fields
 *
 * skb->protocol must be set before this function is called
 */
static void iecm_rx_csum(struct iecm_queue *rxq, struct sk_buff *skb,
			 struct iecm_rx_csum_decoded *csum_bits,
			 struct iecm_rx_ptype_decoded *decoded)
{
	bool ipv4, ipv6;

	/* Start with CHECKSUM_NONE and by default csum_level = 0 */
	skb->ip_summed = CHECKSUM_NONE;

	/* check if Rx checksum is enabled */
	if (!iecm_is_feature_ena(rxq->vport, NETIF_F_RXCSUM))
		return;

	/* check if HW has decoded the packet and checksum */
	if (!(csum_bits->l3l4p))
		return;

	ipv4 = (decoded->outer_ip == IECM_RX_PTYPE_OUTER_IP) &&
	       (decoded->outer_ip_ver == IECM_RX_PTYPE_OUTER_IPV4);
	ipv6 = (decoded->outer_ip == IECM_RX_PTYPE_OUTER_IP) &&
	       (decoded->outer_ip_ver == IECM_RX_PTYPE_OUTER_IPV6);

#ifdef IECM_ADD_PROBES
	iecm_rx_extra_counters(rxq, decoded->inner_prot, ipv4, csum_bits,
			       true);

#endif /* IECM_ADD_PROBES */
	if (ipv4 && (csum_bits->ipe || csum_bits->eipe))
		goto checksum_fail;

	if (ipv6 && csum_bits->ipv6exadd)
		return;

	/* HW checksum will be invalid if vlan stripping is not enabled and
	 * packet has an outer vlan tag. raw_csum_inv will also not be set
	 * even though it's invalid.
	 */
	if (skb_vlan_tag_present(skb))
		return;

	/* check for L4 errors and handle packets that were not able to be
	 * checksummed
	 */
	if (csum_bits->l4e)
		goto checksum_fail;

	/* Only report checksum unnecessary for ICMP, TCP, UDP, or SCTP */
	switch (decoded->inner_prot) {
	case IECM_RX_PTYPE_INNER_PROT_ICMP:
	case IECM_RX_PTYPE_INNER_PROT_TCP:
	case IECM_RX_PTYPE_INNER_PROT_UDP:
	case IECM_RX_PTYPE_INNER_PROT_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	default:
		break;
	}
	return;

checksum_fail:
	rxq->vport->port_stats.rx_hw_csum_err++;
}

/**
 * iecm_rx_splitq_extract_csum_bits - Extract checksum bits from descriptor
 * @rx_desc: receive descriptor
 * @csum: structure to extract checksum fields
 *
 **/
static void
iecm_rx_splitq_extract_csum_bits(struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc,
				 struct iecm_rx_csum_decoded *csum)
{
	u8 qword0, qword1;

	qword0 = rx_desc->status_err0_qw0;
	qword1 = rx_desc->status_err0_qw1;

	csum->ipe = !!(qword1 &
		       BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_IPE_S));
	csum->eipe = !!(qword1 &
			BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_EIPE_S));
	csum->l4e = !!(qword1 &
		       BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_XSUM_L4E_S));
	csum->l3l4p = !!(qword1 &
			 BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_L3L4P_S));
	csum->ipv6exadd =
			!!(qword0 &
			   BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_IPV6EXADD_S));
	csum->rsc = !!(le16_to_cpu(rx_desc->hdrlen_flags) &
		       VIRTCHNL2_RX_FLEX_DESC_ADV_RSC_M);
	csum->raw_csum_inv = !!(le16_to_cpu(rx_desc->ptype_err_fflags0) &
				BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_FF0_S));
	csum->raw_csum = le16_to_cpu(rx_desc->misc.raw_cs);
	csum->pprs = 0;
}

/**
 * iecm_rx_rsc - Set the RSC fields in the skb
 * @rxq : Rx descriptor ring packet is being transacted on
 * @skb : pointer to current skb being populated
 * @rx_desc: Receive descriptor
 * @decoded: Decoded Rx packet type related fields
 *
 * Return 0 on success and error code on failure
 *
 * Populate the skb fields with the total number of RSC segments, RSC payload
 * length and packet type.
 */
static int iecm_rx_rsc(struct iecm_queue *rxq, struct sk_buff *skb,
		       struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc,
		       struct iecm_rx_ptype_decoded *decoded)
{
	u16 rsc_segments, rsc_payload_len;
	struct ipv6hdr *ipv6h;
	struct tcphdr *tcph;
	struct iphdr *ipv4h;
	bool ipv4, ipv6;

	if (!decoded->outer_ip)
		return -EINVAL;

	rsc_payload_len = le16_to_cpu(rx_desc->misc.rscseglen);
	if (!rsc_payload_len)
		return -EINVAL;

	ipv4 = (decoded->outer_ip == IECM_RX_PTYPE_OUTER_IP) &&
		(decoded->outer_ip_ver == IECM_RX_PTYPE_OUTER_IPV4);
	ipv6 = (decoded->outer_ip == IECM_RX_PTYPE_OUTER_IP) &&
		(decoded->outer_ip_ver == IECM_RX_PTYPE_OUTER_IPV6);

	if (!(ipv4 ^ ipv6))
		return -EINVAL;

	rsc_segments = DIV_ROUND_UP(skb->data_len, rsc_payload_len);

	NAPI_GRO_CB(skb)->count = rsc_segments;
	skb_shinfo(skb)->gso_size = rsc_payload_len;

	skb_reset_network_header(skb);

	if (ipv4) {
		ipv4h = ip_hdr(skb);
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;

		/* Reset and set transport header offset in skb */
		skb_set_transport_header(skb, sizeof(struct iphdr));
		tcph = tcp_hdr(skb);

		/* Compute the TCP pseudo header checksum*/
		tcph->check =
			~tcp_v4_check(skb->len - skb_transport_offset(skb),
				      ipv4h->saddr, ipv4h->daddr, 0);
	} else {
		ipv6h = ipv6_hdr(skb);
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
		skb_set_transport_header(skb, sizeof(struct ipv6hdr));
		tcph = tcp_hdr(skb);
		tcph->check =
			~tcp_v6_check(skb->len - skb_transport_offset(skb),
				      &ipv6h->saddr, &ipv6h->daddr, 0);
	}

	tcp_gro_complete(skb);

	u64_stats_update_begin(&rxq->stats_sync);
	rxq->q_stats.rx.rsc_pkts++;
	u64_stats_update_end(&rxq->stats_sync);

	return 0;
}

/**
 * iecm_rx_hwtstamp - check for an RX timestamp and pass up
 * the stack
 * @rx_desc: pointer to rx descritpor containing timestamp
 * @skb: skb to put timestamp in
 */
static void iecm_rx_hwtstamp(struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc,
			     struct sk_buff __maybe_unused *skb)
{
	u8 ts_lo = rx_desc->ts_low;
	u32 ts_hi = 0;
	u64 ts_ns = 0;

	ts_hi = le32_to_cpu(rx_desc->ts_high);

	ts_ns |= ts_lo | ((u64)ts_hi << 8);

	if (ts_ns) {
		memset(skb_hwtstamps(skb), 0,
		       sizeof(struct skb_shared_hwtstamps));
		skb_hwtstamps(skb)->hwtstamp = ns_to_ktime(ts_ns);
	}
}

/**
 * iecm_rx_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rxq: Rx descriptor ring packet is being transacted on
 * @skb: pointer to current skb being populated
 * @rx_desc: Receive descriptor
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, VLAN, protocol, and
 * other fields within the skb.
 */
int
iecm_rx_process_skb_fields(struct iecm_queue *rxq, struct sk_buff *skb,
			   struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc)
{
	struct iecm_rx_ptype_decoded decoded;
	struct iecm_rx_csum_decoded csum_bits;
	u16 rx_ptype;
	int err = 0;

	rx_ptype = le16_to_cpu(rx_desc->ptype_err_fflags0) &
				VIRTCHNL2_RX_FLEX_DESC_ADV_PTYPE_M;

	decoded = rxq->vport->rx_ptype_lkup[rx_ptype];
	if (!decoded.known)
		return -EINVAL;

	/* modifies the skb - consumes the enet header */
	skb->protocol = eth_type_trans(skb, rxq->vport->netdev);
	iecm_rx_splitq_extract_csum_bits(rx_desc, &csum_bits);
	iecm_rx_csum(rxq, skb, &csum_bits, &decoded);
	/* process RSS/hash */
	iecm_rx_hash(rxq, skb, rx_desc, &decoded);

	if (csum_bits.rsc)
		err = iecm_rx_rsc(rxq, skb, rx_desc, &decoded);

	iecm_rx_hwtstamp(rx_desc, skb);

	return err;
}

/**
 * iecm_rx_skb - Send a completed packet up the stack
 * @rxq: Rx ring in play
 * @skb: packet to send up
 * @vlan_tag: packet vlan tag
 *
 * This function sends the completed packet (via. skb) up the stack using
 * gro receive functions
 */
void iecm_rx_skb(struct iecm_queue *rxq, struct sk_buff *skb, u16 vlan_tag)
{
	/* Adding HW VLAN tag to skb must occur after processing csum */
	if (vlan_tag & VLAN_VID_MASK)
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tag);
#ifdef IECM_ADD_PROBES
#ifdef NETIF_F_HW_VLAN_CTAG_RX
	if (iecm_is_feature_ena(rxq->vport, NETIF_F_HW_VLAN_CTAG_RX) &&
	    vlan_tag & VLAN_VID_MASK)
#else
	if (iecm_is_feature_ena(rxq->vport, NETIF_F_HW_VLAN_RX) &&
	    vlan_tag & VLAN_VID_MASK)
#endif /* NETIF_F_HW_VLAN_CTAG_RX */
		rxq->vport->port_stats.extra_stats.rx_vlano++;
#endif /* IECM_ADD_PROBES */

	napi_gro_receive(&rxq->q_vector->napi, skb);
}

/**
 * iecm_rx_page_is_reserved - check if reuse is possible
 * @page: page struct to check
 */
static bool iecm_rx_page_is_reserved(struct page *page)
{
	return (page_to_nid(page) != numa_mem_id()) || page_is_pfmemalloc(page);
}

/**
 * iecm_rx_buf_adjust_pg - Prepare rx buffer for reuse
 * @rx_buf: Rx buffer to adjust
 * @size: Size of adjustment
 *
 * Update the offset within page so that rx buf will be ready to be reused.
 * For systems with PAGE_SIZE < 8192 this function will flip the page offset
 * so the second half of page assigned to rx buffer will be used, otherwise
 * the offset is moved by the @size bytes
 */
void
iecm_rx_buf_adjust_pg(struct iecm_rx_buf *rx_buf, unsigned int size)
{
	struct iecm_page_info *page_info =
					&rx_buf->page_info[rx_buf->page_indx];

#if (PAGE_SIZE < 8192)
	if (rx_buf->buf_size > IECM_RX_BUF_2048)
		/* flip to second page */
		rx_buf->page_indx = !rx_buf->page_indx;
	else
		/* flip page offset to other buffer */
		page_info->page_offset ^= size;
#else
	/* move offset up to the next cache line */
	page_info->page_offset += size;
#endif
}

/**
 * iecm_rx_can_reuse_page - Determine if page can be reused for another rx
 * @rx_buf: buffer containing the page
 *
 * If page is reusable, we have a green light for calling iecm_reuse_rx_page,
 * which will assign the current buffer to the buffer that next_to_alloc is
 * pointing to; otherwise, the dma mapping needs to be destroyed and
 * page freed
 */
bool iecm_rx_can_reuse_page(struct iecm_rx_buf *rx_buf)
{
	struct iecm_page_info *page_info =
					&rx_buf->page_info[rx_buf->page_indx];

#if (PAGE_SIZE >= 8192)
	unsigned int last_offset = PAGE_SIZE - rx_buf->buf_size;
#endif /* PAGE_SIZE < 8192) */
	unsigned int pagecnt_bias = page_info->pagecnt_bias;
	struct page *page = page_info->page;

	/* avoid re-using remote pages */
	if (unlikely(iecm_rx_page_is_reserved(page)))
		return false;

#if (PAGE_SIZE < 8192)
	/* if we are only owner of page we can reuse it */
	if (rx_buf->buf_size > IECM_RX_BUF_2048) {
		if (unlikely((page_count(page) - pagecnt_bias) > 0))
			return false;
	} else {
		if (unlikely((page_count(page) - pagecnt_bias) > 1))
			return false;
	}
#else
	if (rx_buf->page_offset > last_offset)
		return false;
#endif /* PAGE_SIZE < 8192) */

	/* If we have drained the page fragment pool we need to update
	 * the pagecnt_bias and page count so that we fully restock the
	 * number of references the driver holds.
	 */
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	if (unlikely(pagecnt_bias == 1)) {
		page_ref_add(page, USHRT_MAX - 1);
		page_info->pagecnt_bias = USHRT_MAX;
	}
#else
	if (likely(!pagecnt_bias)) {
		get_page(page);
		page_info->pagecnt_bias = 1;
	}
#endif

	return true;
}

/**
 * iecm_rx_add_frag - Add contents of Rx buffer to sk_buff as a frag
 * @rx_buf: buffer containing page to add
 * @skb: sk_buff to place the data into
 * @size: packet length from rx_desc
 *
 * This function will add the data contained in rx_buf->page to the skb.
 * It will just attach the page as a frag to the skb.
 * The function will then update the page offset.
 */
void iecm_rx_add_frag(struct iecm_rx_buf *rx_buf, struct sk_buff *skb,
		      unsigned int size)
{
	struct iecm_page_info *page_info =
					&rx_buf->page_info[rx_buf->page_indx];

#if (PAGE_SIZE >= 8192)
	unsigned int truesize = SKB_DATA_ALIGN(size);
#else
	unsigned int truesize = rx_buf->buf_size;
#endif

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page_info->page,
			page_info->page_offset, size, truesize);

	iecm_rx_buf_adjust_pg(rx_buf, truesize);
}

/**
 * iecm_rx_get_buf_page - Fetch Rx buffer page and synchronize data for use
 * @dev: device struct
 * @rx_buf: Rx buf to fetch page for
 * @size: size of buffer to add to skb
 *
 * This function will pull an Rx buffer page from the ring and synchronize it
 * for use by the CPU.
 */
static void
iecm_rx_get_buf_page(struct device *dev, struct iecm_rx_buf *rx_buf,
		     const unsigned int size)
{
	struct iecm_page_info *page_info =
				&rx_buf->page_info[rx_buf->page_indx];
	prefetch(page_info->page);

	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(dev, page_info->dma,
				      page_info->page_offset, size,
				      DMA_FROM_DEVICE);

	/* We have pulled a buffer for use, so decrement pagecnt_bias */
	page_info->pagecnt_bias--;
}

/**
 * iecm_rx_construct_skb - Allocate skb and populate it
 * @rxq: Rx descriptor queue
 * @rx_buf: Rx buffer to pull data from
 * @size: the length of the packet
 *
 * This function allocates an skb. It then populates it with the page
 * data from the current receive descriptor, taking care to set up the
 * skb correctly.
 */
struct sk_buff *
iecm_rx_construct_skb(struct iecm_queue *rxq, struct iecm_rx_buf *rx_buf,
		      unsigned int size)
{
	struct iecm_page_info *page_info =
					&rx_buf->page_info[rx_buf->page_indx];

	void *va = page_address(page_info->page) + page_info->page_offset;
	unsigned int headlen;
	struct sk_buff *skb;

	/* prefetch first cache line of first page */
	prefetch(va);
#if L1_CACHE_BYTES < 128
	prefetch((u8 *)va + L1_CACHE_BYTES);
#endif /* L1_CACHE_BYTES */
	/* allocate a skb to store the frags */
	skb = __napi_alloc_skb(&rxq->q_vector->napi, IECM_RX_HDR_SIZE,
			       GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!skb))
		return NULL;

	skb_record_rx_queue(skb, rxq->idx);

	/* Determine available headroom for copy */
	headlen = size;
	if (headlen > IECM_RX_HDR_SIZE)
		headlen = eth_get_headlen(skb->dev, va, IECM_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	memcpy(__skb_put(skb, headlen), va, ALIGN(headlen, sizeof(long)));

	/* if we exhaust the linear part then add what is left as a frag */
	size -= headlen;
	if (size) {
#if (PAGE_SIZE >= 8192)
		unsigned int truesize = SKB_DATA_ALIGN(size);
#else
		unsigned int truesize = rx_buf->buf_size;
#endif
		skb_add_rx_frag(skb, 0, page_info->page,
				page_info->page_offset + headlen, size,
				truesize);
		/* buffer is used by skb, update page_offset */
		iecm_rx_buf_adjust_pg(rx_buf, truesize);

	} else {
		/* buffer is unused, reset bias back to rx_buf; data was copied
		 * onto skb's linear part so there's no need for adjusting
		 * page offset and we can reuse this buffer as-is
		 */
		page_info->pagecnt_bias++;
	}

	return skb;
}

/**
 * iecm_rx_hdr_construct_skb - Allocate skb and populate it from header buffer
 * @rxq: Rx descriptor queue
 * @hdr_buf: Rx buffer to pull data from
 * @size: the length of the packet
 *
 * This function allocates an skb. It then populates it with the page data from
 * the current receive descriptor, taking care to set up the skb correctly.
 * This specifcally uses a header buffer to start building the skb.
 */
static struct sk_buff *
iecm_rx_hdr_construct_skb(struct iecm_queue *rxq, struct iecm_dma_mem *hdr_buf,
			  unsigned int size)
{
	struct sk_buff *skb;

	/* allocate a skb to store the frags */
	skb = __napi_alloc_skb(&rxq->q_vector->napi, IECM_RX_HDR_SIZE,
			       GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!skb))
		return NULL;

	skb_record_rx_queue(skb, rxq->idx);

	memcpy(__skb_put(skb, size), hdr_buf->va, size);

	return skb;
}

/**
 * iecm_rx_splitq_test_staterr - tests bits in Rx descriptor
 * status and error fields
 * @stat_err_field: field from descriptor to test bits in
 * @stat_err_bits: value to mask
 *
 */
bool
iecm_rx_splitq_test_staterr(u8 stat_err_field, const u8 stat_err_bits)
{
	return !!(stat_err_field & stat_err_bits);
}

/**
 * iecm_rx_splitq_extract_vlan_tag - Extract vlan tag from the descriptor
 * @desc: Rx flex descriptor
 * @rxq: rxq to check the vlan flags
 * @vlan_tag: vlan tag to fill in
 *
 * Return true if error bit is set in the descriptor, else return false and
 * store the vlan_tag in the variable passed in the function parameters
 */
bool iecm_rx_splitq_extract_vlan_tag(struct virtchnl2_rx_flex_desc_adv_nic_3 *desc,
				     struct iecm_queue *rxq, u16 *vlan_tag)
{
	u8 stat_err0_qw0, stat_err_bits, stat_err1;

	stat_err_bits = BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_RXE_S);
	stat_err0_qw0 = desc->status_err0_qw0;
	if (unlikely(iecm_rx_splitq_test_staterr(stat_err0_qw0, stat_err_bits)))
		return true;

	stat_err1 = desc->status_err1;

	if (stat_err0_qw0 & BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_L2TAG1P_S) &&
	    test_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG1, rxq->flags))
		*vlan_tag = le16_to_cpu(desc->l2tag1);
	if (stat_err1 & BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS1_L2TAG2P_S) &&
	    test_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG2, rxq->flags))
		*vlan_tag = le16_to_cpu(desc->l2tag2);

	return false;
}

/**
 * iecm_rx_splitq_is_non_eop - process handling of non-EOP buffers
 * @rx_desc: Rx descriptor for current buffer
 *
 * If the buffer is an EOP buffer, this function exits returning false,
 * otherwise return true indicating that this is in fact a non-EOP buffer.
 */
static bool
iecm_rx_splitq_is_non_eop(struct virtchnl2_rx_flex_desc_adv_nic_3 *rx_desc)
{
	/* if we are the last buffer then there is nothing else to do */
#define IECM_RXD_EOF BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_EOF_S)
	if (likely(iecm_rx_splitq_test_staterr(rx_desc->status_err0_qw1,
					       IECM_RXD_EOF)))
		return false;

	return true;
}

/**
 * iecm_rx_splitq_recycle_buf - Attempt to recycle or realloc buffer
 * @rxbufq: receive queue
 * @rx_buf: Rx buffer to pull data from
 *
 * This function will clean up the contents of the rx_buf. It will either
 * recycle the buffer or unmap it and free the associated resources. The buffer
 * will then be placed on a refillq where it will later be reclaimed by the
 * corresponding bufq.
 *
 * This works based on page flipping. If we assume e.g., a 4k page, it will be
 * divided into two 2k buffers. We post the first half to hardware and, after
 * using it, flip to second half of the page with iecm_adjust_pg_offset and
 * post that to hardware. The third time through we'll flip back to first half
 * of page and check if stack is still using it, if not we can reuse the buffer
 * as is, otherwise we'll drain it and get a new page.
 */
static void iecm_rx_splitq_recycle_buf(struct iecm_queue *rxbufq,
				       struct iecm_rx_buf *rx_buf)
{
	struct iecm_page_info *page_info =
					&rx_buf->page_info[rx_buf->page_indx];
	if (!iecm_rx_can_reuse_page(rx_buf)) {
		/* we are not reusing the buffer so unmap it */
#ifndef HAVE_STRUCT_DMA_ATTRS
		dma_unmap_page_attrs(rxbufq->dev, page_info->dma, PAGE_SIZE,
				     DMA_FROM_DEVICE, IECM_RX_DMA_ATTR);
#else
		dma_unmap_page(rxbufq->dev, page_info->dma, PAGE_SIZE,
			       DMA_FROM_DEVICE);
#endif /* !HAVE_STRUCT_DMA_ATTRS */
		__page_frag_cache_drain(page_info->page,
					page_info->pagecnt_bias);

		/* clear contents of buffer_info */
		page_info->page = NULL;
		rx_buf->skb = NULL;

		/* It's possible the alloc can fail here but there's not much
		 * we can do, bufq will have to try and realloc to fill the
		 * hole.
		 */
		iecm_alloc_page(rxbufq, page_info);
	}
}

/**
 * iecm_rx_bump_ntc - Bump and wrap q->next_to_clean value
 * @q: queue to bump
 */
void iecm_rx_bump_ntc(struct iecm_queue *q)
{
	u16 ntc = q->next_to_clean + 1;
	/* fetch, update, and store next to clean */
	if (ntc < q->desc_count) {
		q->next_to_clean = ntc;
	} else {
		q->next_to_clean = 0;
		change_bit(__IECM_Q_GEN_CHK, q->flags);
	}
}

#ifdef HAVE_XDP_SUPPORT
/**
 * iecm_rx_frame_truesize - Returns an actual size of Rx frame in memory
 * @buf: pointer to buffer metadata struct
 * @size: Packet length from rx_desc
 *
 * Returns an actual size of Rx frame in memory, considering page size
 * and SKB data alignment.
 */
static unsigned int iecm_rx_frame_truesize(struct iecm_rx_buf *buf,
					   unsigned int __maybe_unused size)
{
	unsigned int truesize;
#if (PAGE_SIZE >= 8192)
		truesize = SKB_DATA_ALIGN(size);
#else
		truesize = buf->buf_size;
#endif
	return truesize;
}

/**
 * iecm_prepare_xdp_tx_splitq_desc - Prepare TX descriptor for XDP in single queue mode
 * @xdpq:      Pointer to XDP TX queue
 * @dma:       Address of DMA buffer used for XDP TX.
 * @idx:       Index of the TX buffer in the queue.
 * @size:      Size of data to be transmitted.
 *
 * Returns a void pointer to iecm_tx_flex_desc structure keeping a created descriptor.
 */
void *iecm_prepare_xdp_tx_splitq_desc(struct iecm_queue *xdpq, dma_addr_t dma,
				      u16 idx, u32 size)
{
	struct iecm_tx_splitq_params tx_parms = {
		NULL, (enum iecm_tx_desc_dtype_value)0, 0, {0}, {0}
	};
	union iecm_tx_flex_desc *tx_desc;
	u16 compl_tag = xdpq->tx_buf_key;

	tx_parms.compl_tag = compl_tag;

	tx_desc = IECM_FLEX_TX_DESC(xdpq, idx);
	tx_desc->q.buf_addr = cpu_to_le64(dma);

	if (unlikely(test_bit(__IECM_Q_FLOW_SCH_EN, xdpq->flags))) {
		tx_parms.dtype = IECM_TX_DESC_DTYPE_FLEX_FLOW_SCHE;
		tx_parms.splitq_build_ctb = iecm_tx_splitq_build_flow_desc;
		tx_parms.eop_cmd = IECM_TXD_FLEX_FLOW_CMD_EOP | IECM_TXD_FLEX_FLOW_CMD_RE;
	} else {
		tx_parms.dtype = IECM_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2;
		tx_parms.splitq_build_ctb = iecm_tx_splitq_build_ctb;
		tx_parms.eop_cmd = IECM_TXD_LAST_DESC_CMD;
	}

	tx_parms.splitq_build_ctb(tx_desc, &tx_parms, tx_parms.eop_cmd | tx_parms.offload.td_cmd,
				  size);

	xdpq->tx_buf->compl_tag = compl_tag++;
	xdpq->tx_buf_key = compl_tag;

	return (void *)tx_desc;
}

/**
 * iecm_xmit_xdpq - submit single packet to XDP queue for transmission
 * @xdp: frame data to transmit
 * @xdpq: XDP queue for transmission
 */
#ifdef HAVE_XDP_FRAME_STRUCT
int iecm_xmit_xdpq(struct xdp_frame *xdp, struct iecm_queue *xdpq)
#else
int iecm_xmit_xdpq(struct xdp_buff *xdp, struct iecm_queue *xdpq)
#endif
{
	u16 ntu = xdpq->next_to_use;
	struct iecm_tx_buf *tx_buf;
	void *data, *tx_desc;
	dma_addr_t dma;
	u32 size;

	if (unlikely(!xdp))
		return IECM_XDP_CONSUMED;

	if (unlikely(!IECM_DESC_UNUSED(xdpq)))
		return IECM_XDP_CONSUMED;

#ifdef HAVE_XDP_FRAME_STRUCT
	size = xdp->len;
#else
	size = xdp->data_end - xdp->data;
#endif
	data = xdp->data;

	dma = dma_map_single(xdpq->dev, data, size, DMA_TO_DEVICE);
	if (dma_mapping_error(xdpq->dev, dma))
		return IECM_XDP_CONSUMED;

	tx_buf = &xdpq->tx_buf[ntu];
	tx_buf->bytecount = size;
	tx_buf->gso_segs = 1;
#ifdef HAVE_XDP_FRAME_STRUCT
	tx_buf->xdpf = xdp;
#else
	tx_buf->raw_buf = data;
#endif

	/* record length, and DMA address */
	dma_unmap_len_set(tx_buf, len, size);
	dma_unmap_addr_set(tx_buf, dma, dma);

#ifdef HAVE_INDIRECT_CALL_WRAPPER_HEADER
	tx_desc = INDIRECT_CALL_2(xdpq->vport->xdp_prepare_tx_desc,
				  iecm_prepare_xdp_tx_splitq_desc,
				  iecm_prepare_xdp_tx_singleq_desc,
				  xdpq, dma, ntu, size);
#else
	tx_desc = xdpq->vport->xdp_prepare_tx_desc(xdpq, dma, ntu, size);
#endif /* HAVE_INDIRECT_CALL_WRAPPER_HEADER */

	/* Make certain all of the status bits have been updated
	 * before next_to_watch is written.
	 */
	smp_wmb();

#ifdef HAVE_NETDEV_BPF_XSK_POOL
	xdpq->xdp_tx_active++;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

	ntu++;
	if (ntu == xdpq->desc_count)
		ntu = 0;
	tx_buf->next_to_watch = tx_desc;
	xdpq->next_to_use = ntu;

	return IECM_XDP_TX;
}

#ifdef HAVE_XDP_FRAME_STRUCT
/**
 * iecm_xdp_xmit - submit packets to xdp ring for transmission
 * @dev: netdev
 * @n: number of xdp frames to be transmitted
 * @frames: xdp frames to be transmitted
 * @flags: transmit flags
 *
 * Returns number of frames successfully sent. Frames that fail are
 * free'ed via XDP return API.
 * For error cases, a negative errno code is returned and no-frames
 * are transmitted (caller must handle freeing frames).
 */
int iecm_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
		  u32 flags)
#else
int iecm_xdp_xmit(struct net_device *dev, struct xdp_buff *xdp)
#endif /* HAVE_XDP_FRAME_STRUCT */
{
	struct iecm_netdev_priv *np = netdev_priv(dev);
	unsigned int queue_index = smp_processor_id();
	struct iecm_vport *vport = np->vport;
	struct iecm_queue *xdpq;
#ifdef HAVE_XDP_FRAME_STRUCT
	int i, drops = 0;
#else
	int err;
#endif /* HAVE_XDP_FRAME_STRUCT */

	if (vport->adapter->state == __IECM_DOWN)
		return -ENETDOWN;

	if (!iecm_xdp_is_prog_ena(vport) || queue_index >= vport->num_xdp_txq)
		return -ENXIO;

#ifdef HAVE_XDP_FRAME_STRUCT
	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;
#endif
	xdpq = vport->txqs[queue_index + vport->xdp_txq_offset];
#ifdef HAVE_XDP_FRAME_STRUCT
	for (i = 0; i < n; ++i) {
		struct xdp_frame *xdpf = frames[i];
		int err;

		err = iecm_xmit_xdpq(xdpf, xdpq);
		if (err != IECM_XDP_TX) {
			xdp_return_frame_rx_napi(xdpf);
			drops++;
		}
	}

	if (unlikely(flags & XDP_XMIT_FLUSH))
		iecm_xdpq_update_tail(xdpq);

	return n - drops;
#else
	err = iecm_xmit_xdpq(xdp, xdpq);
	return err == IECM_XDP_TX ? 0 : -EFAULT;
#endif /* HAVE_XDP_FRAME_STRUCT */
}

#ifndef NO_NDO_XDP_FLUSH
/**
 * iecm_xdp_flush - flush xdp ring and transmit all submitted packets
 * @dev: netdev
 */
void iecm_xdp_flush(struct net_device *dev)
{
	struct iecm_netdev_priv *np = netdev_priv(dev);
	unsigned int queue_index = smp_processor_id();
	struct iecm_vport *vport = np->vport;

	if (vport->adapter->state == __IECM_DOWN)
		return;

	if (!iecm_xdp_is_prog_ena(vport) || queue_index >= vport->num_xdp_txq)
		return;

	iecm_xdpq_update_tail(vport->txqs[queue_index + vport->xdp_txq_offset]);
}

#endif /* NO_NDO_XDP_FLUSH */
/**
 * iecm_run_xdp - Executes an XDP program on initialized xdp_buff
 * @rxq: Rx queue
 * @xdpq: XDP Tx queue
 * @xdp_prog: XDP program to run
 * @xdp: xdp_buff used as input to the XDP program
 *
 * Returns IECM_XDP_PASS for packets to be sent up the stack, IECM_XDP_CONSUMED
 * otherwise.
 */
static int iecm_run_xdp(struct iecm_queue *rxq, struct iecm_queue *xdpq,
			struct bpf_prog *xdp_prog, struct xdp_buff *xdp)
{
	u32 act = bpf_prog_run_xdp(xdp_prog, xdp);
	int err, result = IECM_XDP_PASS;

	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
#ifdef HAVE_XDP_FRAME_STRUCT
		return iecm_xmit_xdpq(xdp_convert_buff_to_frame(xdp), xdpq);
#else
		return iecm_xmit_xdpq(xdp, xdpq);
#endif
	case XDP_REDIRECT:
		err = xdp_do_redirect(rxq->vport->netdev, xdp, xdp_prog);
		result = !err ? IECM_XDP_REDIR : IECM_XDP_CONSUMED;
		break;
	default:
		bpf_warn_invalid_xdp_action(rxq->vport->netdev, xdp_prog, act);
		fallthrough;
		/* fallthrough - not supported action */
	case XDP_ABORTED:
		/* fallthrough - handle aborts by dropping frame */
	case XDP_DROP:
		return IECM_XDP_CONSUMED;
	}

	return result;
}

/**
 * iecm_rx_xdp - Initialize an xdp_buff and run XDP program
 * @rxq: current queue
 * @xdpq: XDP Tx queue
 * @rx_buf: buffer with a received packet
 * @size: size of the packet
 *
 * Returns IECM_XDP_PASS for packets to be sent up the stack, IECM_XDP_CONSUMED
 * otherwise.
 */
int iecm_rx_xdp(struct iecm_queue *rxq, struct iecm_queue *xdpq,
		struct iecm_rx_buf *rx_buf, unsigned int size)
{
	struct iecm_page_info *page_info =
					&rx_buf->page_info[rx_buf->page_indx];

	struct bpf_prog *xdp_prog;
	struct xdp_buff xdp;
	int xdp_res;

	rcu_read_lock();
	xdp_prog = READ_ONCE(rxq->xdp_prog);
	if (!xdp_prog) {
		rcu_read_unlock();
		return IECM_XDP_PASS;
	}

	xdp.data = page_address(page_info->page) + page_info->page_offset;
	xdp.data_hard_start = xdp.data - iecm_rx_offset(rxq);
	xdp.data_meta = xdp.data;
	xdp.data_end = xdp.data + size;
#ifdef HAVE_XDP_BUFF_RXQ
	xdp.rxq = &rxq->xdp_rxq;
#endif /* HAVE_XDP_BUFF_RXQ */
#ifdef HAVE_XDP_BUFF_FRAME_SZ
	xdp.frame_sz = iecm_rx_frame_truesize(rx_buf, size);
#endif /* HAVE_XDP_BUFF_FRAME_SZ */

	xdp_res = iecm_run_xdp(rxq, xdpq, xdp_prog, &xdp);
	rcu_read_unlock();

	return xdp_res;
}
#endif /* HAVE_XDP_SUPPORT */

/**
 * iecm_rx_splitq_clean - Clean completed descriptors from Rx queue
 * @rxq: Rx descriptor queue to retrieve receive buffer queue
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing. The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the system.
 *
 * Returns amount of work completed
 */
static int iecm_rx_splitq_clean(struct iecm_queue *rxq, int budget)
{
	int total_rx_bytes = 0, total_rx_pkts = 0;
#ifdef HAVE_XDP_SUPPORT
	unsigned int xdp_res, xdp_xmit = 0;
	struct iecm_queue *xdpq = NULL;
#endif /* HAVE_XDP_SUPPORT */
	struct iecm_queue *rx_bufq = NULL;
	struct sk_buff *skb = rxq->skb;
	bool failure = false;

#ifdef HAVE_XDP_SUPPORT
	if (iecm_xdp_is_prog_ena(rxq->vport))
		xdpq = iecm_get_related_xdp_queue(rxq);
#endif /* HAVE_XDP_SUPPORT */

	/* Process Rx packets bounded by budget */
	while (likely(total_rx_pkts < budget)) {
		struct virtchnl2_rx_flex_desc_adv_nic_3 *splitq_flex_rx_desc;
		struct iecm_sw_queue *refillq = NULL;
		struct iecm_dma_mem *hdr_buf = NULL;
		struct iecm_rxq_set *rxq_set = NULL;
		struct iecm_rx_buf *rx_buf = NULL;
		u16 gen_id, buf_id, vlan_tag = 0;
		union virtchnl2_rx_desc *rx_desc;
		unsigned int pkt_len = 0;
		unsigned int hdr_len = 0;
		 /* Header buffer overflow only valid for header split */
		bool hbo = false;
		int bufq_id;

#ifdef HAVE_XDP_SUPPORT
		xdp_res = IECM_XDP_PASS;

#endif /* HAVE_XDP_SUPPORT */
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

		if ((splitq_flex_rx_desc->rxdid_ucast &
		    VIRTCHNL2_RX_FLEX_DESC_ADV_RXDID_M) != VIRTCHNL2_RXDID_1_FLEX_SPLITQ) {
			iecm_rx_bump_ntc(rxq);
			rxq->vport->port_stats.rx_bad_descs++;
			continue;
		}

		pkt_len = le16_to_cpu(splitq_flex_rx_desc->pktlen_gen_bufq_id) &
			  VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_PBUF_M;

		hbo = splitq_flex_rx_desc->status_err0_qw1 &
		      BIT(VIRTCHNL2_RX_FLEX_DESC_ADV_STATUS0_HBO_S);

		if (unlikely(hbo)) {
			rxq->vport->port_stats.rx_hsplit_hbo++;
			goto bypass_hsplit;
		}

		hdr_len =
			le16_to_cpu(splitq_flex_rx_desc->hdrlen_flags) &
			VIRTCHNL2_RX_FLEX_DESC_ADV_LEN_HDR_M;

bypass_hsplit:
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

		if (pkt_len) {
			rx_buf = &rx_bufq->rx_buf.buf[buf_id];
			iecm_rx_get_buf_page(rx_bufq->dev, rx_buf, pkt_len);
		}

		if (hdr_len) {
			hdr_buf = rx_bufq->rx_buf.hdr_buf[buf_id];

			dma_sync_single_for_cpu(rxq->dev, hdr_buf->pa, hdr_buf->size,
						DMA_FROM_DEVICE);

			skb = iecm_rx_hdr_construct_skb(rxq, hdr_buf, hdr_len);
			rxq->vport->port_stats.rx_hsplit++;
		}

#ifdef HAVE_XDP_SUPPORT
		if (pkt_len)
			xdp_res = iecm_rx_xdp(rxq, xdpq, rx_buf, pkt_len);

		if (xdp_res) {
			if (xdp_res & (IECM_XDP_TX | IECM_XDP_REDIR)) {
				unsigned int truesize =
					iecm_rx_frame_truesize(rx_buf, pkt_len);

				xdp_xmit |= xdp_res;
				iecm_rx_buf_adjust_pg(rx_buf, truesize);
			} else {
				rx_buf->page_info[rx_buf->page_indx].pagecnt_bias++;
			}
			total_rx_bytes += pkt_len;
			total_rx_pkts++;
			iecm_rx_splitq_recycle_buf(rx_bufq, rx_buf);
			iecm_rx_post_buf_refill(refillq, rx_buf->buf_id);
			iecm_rx_bump_ntc(rxq);
			continue;
		}
#endif /* HAVE_XDP_SUPPORT */

		if (pkt_len) {
			if (skb)
				iecm_rx_add_frag(rx_buf, skb, pkt_len);
			else
				skb = iecm_rx_construct_skb(rxq, rx_buf,
							    pkt_len);
		}

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			/* If we fetched a buffer, but didn't use it
			 * undo pagecnt_bias decrement
			 */
			if (rx_buf)
				rx_buf->page_info[rx_buf->page_indx].pagecnt_bias++;
			break;
		}

		if (rx_buf)
			iecm_rx_splitq_recycle_buf(rx_bufq, rx_buf);
		iecm_rx_post_buf_refill(refillq, buf_id);

		iecm_rx_bump_ntc(rxq);
		/* skip if it is non EOP desc */
		if (iecm_rx_splitq_is_non_eop(splitq_flex_rx_desc))
			continue;

		/* extract vlan tag from the descriptor */
		if (unlikely(iecm_rx_splitq_extract_vlan_tag(splitq_flex_rx_desc,
							     rxq, &vlan_tag))) {
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
		if (unlikely(iecm_rx_process_skb_fields(rxq, skb,
							splitq_flex_rx_desc))) {
			dev_kfree_skb_any(skb);
			skb = NULL;
			continue;
		}

		/* send completed skb up the stack */
		iecm_rx_skb(rxq, skb, vlan_tag);
		skb = NULL;

		/* update budget accounting */
		total_rx_pkts++;
	}
#ifdef HAVE_XDP_SUPPORT
	iecm_finalize_xdp_rx(xdpq, xdp_xmit);

#endif /* HAVE_XDP_SUPPORT */
	rxq->skb = skb;
	u64_stats_update_begin(&rxq->stats_sync);
	rxq->q_stats.rx.packets += total_rx_pkts;
	rxq->q_stats.rx.bytes += total_rx_bytes;
	u64_stats_update_end(&rxq->stats_sync);

	/* guarantee a trip back through this routine if there was a failure */
	return unlikely(failure) ? budget : total_rx_pkts;
}

/**
 * iecm_rx_update_bufq_desc - Update buffer queue descriptor
 * @bufq - Pointer to the buffer queue
 * @desc - Refill queue descriptor
 * @buf_desc - Buffer queue descriptor
 *
 * Return 0 on success and negative on failure.
 */
static int iecm_rx_update_bufq_desc(struct iecm_queue *bufq, u16 *desc,
				    struct virtchnl2_splitq_rx_buf_desc *buf_desc)
{
	struct iecm_page_info *page_info;
	struct iecm_dma_mem *hdr_buf;
	struct iecm_rx_buf *buf;
	u16 buf_id;

	buf_id = ((*desc) & IECM_RX_BI_BUFID_M) >> IECM_RX_BI_BUFID_S;

	buf = &bufq->rx_buf.buf[buf_id];
	page_info = &buf->page_info[buf->page_indx];

	/* It's possible page alloc failed during rxq clean, try to
	 * recover here.
	 */
	if (unlikely(!page_info->page)) {
		if (iecm_alloc_page(bufq, page_info))
			return -ENOMEM;
	}
	dma_sync_single_range_for_device(bufq->dev, page_info->dma,
					 page_info->page_offset,
					 bufq->rx_buf_size,
					 DMA_FROM_DEVICE);
	buf_desc->pkt_addr = cpu_to_le64(page_info->dma + page_info->page_offset);
	buf_desc->qword0.buf_id = cpu_to_le16(buf_id);

	if (bufq->rx_hsplit_en) {
		hdr_buf = bufq->rx_buf.hdr_buf[buf_id];
		buf_desc->hdr_addr = cpu_to_le64(hdr_buf->pa);

		dma_sync_single_for_device(bufq->dev, hdr_buf->pa,
					   hdr_buf->size, DMA_FROM_DEVICE);
	}

	return 0;
}

/**
 * iecm_rx_clean_refillq - Clean refill queue buffers
 * @bufq: buffer queue to post buffers back to
 * @refillq: refill queue to clean
 *
 * Returns total number of descriptors cleaned
 *
 * This function takes care of the buffer refill management
 */
static void iecm_rx_clean_refillq(struct iecm_queue *bufq,
				  struct iecm_sw_queue *refillq)
{
	struct virtchnl2_splitq_rx_buf_desc *buf_desc;
	u16 refillq_ntc = refillq->next_to_clean;
	u16 bufq_nta = bufq->next_to_alloc;
	bool failure = false;
	u16 *refill_desc;
	int cleaned = 0;
	u16 gen;

	refill_desc = IECM_SPLITQ_RX_BI_DESC(refillq, refillq_ntc);
	buf_desc = IECM_SPLITQ_RX_BUF_DESC(bufq, bufq_nta);

	/* make sure we stop at ring wrap in the unlikely case ring is full */
	while (likely(cleaned < refillq->desc_count)) {
		gen = ((*refill_desc) & IECM_RX_BI_GEN_M) >> IECM_RX_BI_GEN_S;
		if (test_bit(__IECM_RFLQ_GEN_CHK, refillq->flags) != gen)
			break;

		failure = iecm_rx_update_bufq_desc(bufq, refill_desc,
						   buf_desc);
		if (failure)
			break;

		refillq_ntc++;
		refill_desc++;
		bufq_nta++;
		buf_desc++;
		cleaned++;

		if (unlikely(refillq_ntc == refillq->desc_count)) {
			change_bit(__IECM_RFLQ_GEN_CHK, refillq->flags);
			refill_desc = IECM_SPLITQ_RX_BI_DESC(refillq, 0);
			refillq_ntc = 0;
		}
		if (unlikely(bufq_nta == bufq->desc_count)) {
			buf_desc = IECM_SPLITQ_RX_BUF_DESC(bufq, 0);
			bufq_nta = 0;
		}
	}

	if (cleaned) {
		/* only update hardware tail in strides */
		if (((bufq->next_to_use <= bufq_nta ? 0 : bufq->desc_count) +
		    bufq_nta - bufq->next_to_use) >= bufq->rx_buf_stride)
			iecm_rx_buf_hw_update(bufq, bufq_nta & ~(bufq->rx_buf_stride - 1));

		/* update next to alloc since we have filled the ring */
		refillq->next_to_clean = refillq_ntc;
		bufq->next_to_alloc = bufq_nta;
	}
}

/**
 * iecm_rx_clean_refillq_all - Clean all refill queues
 * @q_vec: q vector to clean queues on
 * @budget: maximum amount of work to do
 *
 * Iterates through all refill queues assigned to the buffer queue assigned to
 * this vector.  Returns true if clean is complete within budget, false
 * otherwise.
 */
static void iecm_rx_clean_refillq_all(struct iecm_queue *bufq)
{
	struct iecm_bufq_set *bufq_set;
	struct iecm_sw_queue *refillq;
	int i = 0;

	bufq_set = container_of(bufq, struct iecm_bufq_set, bufq);
	for (i = 0; i < bufq_set->num_refillqs; i++) {
		refillq = &bufq_set->refillqs[i];
		iecm_rx_clean_refillq(bufq, refillq);
	}
}

/**
 * iecm_vport_intr_clean_queues - MSIX mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 *
 */
irqreturn_t
iecm_vport_intr_clean_queues(int __always_unused irq, void *data)
{
	struct iecm_q_vector *q_vector = (struct iecm_q_vector *)data;

	q_vector->total_events++;
	napi_schedule(&q_vector->napi);

	return IRQ_HANDLED;
}

/**
 * iecm_vport_intr_napi_del_all - Unregister napi for all q_vectors in vport
 * @vport: virtual port structure
 *
 */
static void iecm_vport_intr_napi_del_all(struct iecm_vport *vport)
{
	u16 v_idx;

	for (v_idx = 0; v_idx < vport->num_q_vectors; v_idx++) {
		struct iecm_q_vector *q_vector = &vport->q_vectors[v_idx];

		netif_napi_del(&q_vector->napi);
	}
}

/**
 * iecm_vport_intr_napi_dis_all - Disable NAPI for all q_vectors in the vport
 * @vport: main vport structure
 */
static void iecm_vport_intr_napi_dis_all(struct iecm_vport *vport)
{
	int q_idx;

	if (!vport->netdev)
		return;

	for (q_idx = 0; q_idx < vport->num_q_vectors; q_idx++) {
		struct iecm_q_vector *q_vector = &vport->q_vectors[q_idx];

		napi_disable(&q_vector->napi);
	}
}

/**
 * iecm_vport_intr_rel - Free memory allocated for interrupt vectors
 * @vport: virtual port
 *
 * Free the memory allocated for interrupt vectors  associated to a vport
 */
void iecm_vport_intr_rel(struct iecm_vport *vport)
{
	int i, j, v_idx;

	if (!vport->netdev)
		return;

	for (v_idx = 0; v_idx < vport->num_q_vectors; v_idx++) {
		struct iecm_q_vector *q_vector = &vport->q_vectors[v_idx];

		kfree(q_vector->bufq);
		q_vector->bufq = NULL;
		kfree(q_vector->tx);
		q_vector->tx = NULL;
		kfree(q_vector->rx);
		q_vector->rx = NULL;
	}

	/* Clean up the mapping of queues to vectors */
	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct iecm_rxq_group *rx_qgrp = &vport->rxq_grps[i];

		if (iecm_is_queue_model_split(vport->rxq_model)) {
			for (j = 0; j < rx_qgrp->splitq.num_rxq_sets; j++)
				rx_qgrp->splitq.rxq_sets[j]->rxq.q_vector =
									   NULL;
		} else {
			for (j = 0; j < rx_qgrp->singleq.num_rxq; j++)
				rx_qgrp->singleq.rxqs[j]->q_vector = NULL;
		}
	}

	if (iecm_is_queue_model_split(vport->txq_model)) {
		for (i = 0; i < vport->num_txq_grp; i++)
			vport->txq_grps[i].complq->q_vector = NULL;
	} else {
		for (i = 0; i < vport->num_txq_grp; i++) {
			for (j = 0; j < vport->txq_grps[i].num_txq; j++)
				vport->txq_grps[i].txqs[j]->q_vector = NULL;
		}
	}

	kfree(vport->q_vectors);
	vport->q_vectors = NULL;
}

/**
 * iecm_vport_intr_rel_irq - Free the IRQ association with the OS
 * @vport: main vport structure
 */
static void iecm_vport_intr_rel_irq(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	int vector;

	for (vector = 0; vector < vport->num_q_vectors; vector++) {
		struct iecm_q_vector *q_vector = &vport->q_vectors[vector];
		int irq_num, vidx;

		/* free only the irqs that were actually requested */
		if (!q_vector)
			continue;

		vidx = vector + vport->q_vector_base;
		irq_num = adapter->msix_entries[vidx].vector;

		/* clear the affinity_mask in the IRQ descriptor */
		irq_set_affinity_hint(irq_num, NULL);
		free_irq(irq_num, q_vector);
	}
}

/**
 * iecm_vport_intr_dis_irq_all - Disable each interrupt
 * @vport: main vport structure
 */
void iecm_vport_intr_dis_irq_all(struct iecm_vport *vport)
{
	struct iecm_q_vector *q_vector = vport->q_vectors;
	struct iecm_hw *hw = &vport->adapter->hw;
	int q_idx;

	for (q_idx = 0; q_idx < vport->num_q_vectors; q_idx++)
		wr32(hw, q_vector[q_idx].intr_reg.dyn_ctl, 0);
}

/**
 * iecm_adq_force_wb - Issue SW Interrupt so HW does a wb
 * @q_vector: vector on which to force writeback
 */
void iecm_adq_force_wb(struct iecm_q_vector *q_vector)
{
	struct iecm_intr_reg *intr_reg = &q_vector->intr_reg;
	u32 val;

	val = intr_reg->dyn_ctl_intena_m |
		intr_reg->dyn_ctl_itridx_m |	/* set no itr*/
		intr_reg->dyn_ctl_swint_trig_m |
		intr_reg->dyn_ctl_sw_itridx_ena_m;
	/* allow 00 to be written to the index */;

	if (iecm_is_vec_ch_ena(q_vector))
		clear_bit(__IECM_VEC_STATE_ONCE_IN_BP, q_vector->flags);
	wr32(&q_vector->vport->adapter->hw, intr_reg->dyn_ctl, val);
}

/**
 * iecm_vport_intr_buildreg_itr - Enable default interrupt generation settings
 * @q_vector: pointer to q_vector
 * @type: itr index
 * @itr: itr value
 */
static u32 iecm_vport_intr_buildreg_itr(struct iecm_q_vector *q_vector,
					const int type, u16 itr)
{
	u32 itr_val;

	itr &= IECM_ITR_MASK;
	/* Don't clear PBA because that can cause lost interrupts that
	 * came in while we were cleaning/polling
	 */
	itr_val = q_vector->intr_reg.dyn_ctl_intena_m |
		  (type << q_vector->intr_reg.dyn_ctl_itridx_s) |
		  (itr << (q_vector->intr_reg.dyn_ctl_intrvl_s - 1));

	return itr_val;
}

/**
 * iecm_net_dim - Update net DIM algorithm
 * @q_vector: the vector associated with the interrupt
 *
 * Create a DIM sample and notify net_dim() so that it can possibly decide
 * a new ITR value based on incoming packets, bytes, and interrupts.
 *
 * This function is a no-op if the queue is not configured to dynamic ITR.
 */
static void iecm_net_dim(struct iecm_q_vector *q_vector)
{
	if (IECM_ITR_IS_DYNAMIC(q_vector->tx_intr_mode)) {
		struct dim_sample dim_sample = {};
		u64 packets = 0, bytes = 0;
		int i;

		for (i = 0; i < q_vector->num_txq; i++) {
			packets += q_vector->tx[i]->q_stats.tx.packets;
			bytes += q_vector->tx[i]->q_stats.tx.bytes;
		}

		dim_update_sample(q_vector->total_events, packets, bytes,
				  &dim_sample);
		net_dim(&q_vector->tx_dim, dim_sample);
	}

	if (IECM_ITR_IS_DYNAMIC(q_vector->rx_intr_mode)) {
		struct dim_sample dim_sample = {};
		u64 packets = 0, bytes = 0;
		int i;

		for (i = 0; i < q_vector->num_rxq; i++) {
			packets += q_vector->rx[i]->q_stats.rx.packets;
			bytes += q_vector->rx[i]->q_stats.rx.bytes;
		}

		dim_update_sample(q_vector->total_events, packets, bytes,
				  &dim_sample);
		net_dim(&q_vector->rx_dim, dim_sample);
	}
}

/**
 * iecm_vport_intr_update_itr_ena_irq - Update itr and re-enable MSIX interrupt
 * @q_vector: q_vector for which itr is being updated and interrupt enabled
 *
 * Update the net_dim() algorithm and re-enable the interrupt associated with
 * this vector.
 */
void iecm_vport_intr_update_itr_ena_irq(struct iecm_q_vector *q_vector)
{
	struct iecm_hw *hw = &q_vector->vport->adapter->hw;
	u32 intval;

	/* if vector is channel enabled, it doesn't use ITR countdown
	 * or pseudo-lazy update for ITR
	 */
	if (iecm_is_vec_ch_ena(q_vector) && iecm_is_vec_ch_perf_ena(q_vector))
		goto do_write;

	/* net_dim() updates ITR out-of-band using a work item */
	iecm_net_dim(q_vector);

do_write:
	intval = iecm_vport_intr_buildreg_itr(q_vector,
					      VIRTCHNL2_ITR_IDX_NO_ITR, 0);

	wr32(hw, q_vector->intr_reg.dyn_ctl, intval);
}

/**
 * iecm_vport_intr_req_irq - get MSI-X vectors from the OS for the vport
 * @vport: main vport structure
 * @basename: name for the vector
 */
static int
iecm_vport_intr_req_irq(struct iecm_vport *vport, char *basename)
{
	struct iecm_adapter *adapter = vport->adapter;
	int vector, err, irq_num, vidx;

	for (vector = 0; vector < vport->num_q_vectors; vector++) {
		struct iecm_q_vector *q_vector = &vport->q_vectors[vector];

		vidx = vector + vport->q_vector_base;
		irq_num = adapter->msix_entries[vidx].vector;

		snprintf(q_vector->name, sizeof(q_vector->name) - 1,
			 "%s-%s-%d", basename, "TxRx", vidx);

		err = request_irq(irq_num, vport->irq_q_handler, 0,
				  q_vector->name, q_vector);
		if (err) {
			netdev_err(vport->netdev,
				   "Request_irq failed, error: %d\n", err);
			goto free_q_irqs;
		}
		/* assign the mask for this irq */
		irq_set_affinity_hint(irq_num, &q_vector->affinity_mask);
	}

	return 0;

free_q_irqs:
	while (vector) {
		vector--;
		vidx = vector + vport->q_vector_base;
		irq_num = adapter->msix_entries[vidx].vector,
		free_irq(irq_num, &vport->q_vectors[vector]);
	}
	return err;
}

/**
 * iecm_vport_intr_write_itr - Write ITR value to the ITR register
 * @q_vector: q_vector structure
 * @itr: Interrupt throttling rate
 * @tx: Tx or Rx ITR
 */
void iecm_vport_intr_write_itr(struct iecm_q_vector *q_vector, u16 itr, bool tx)
{
	struct iecm_hw *hw = &q_vector->vport->adapter->hw;
	struct iecm_intr_reg *intr_reg;

	if (tx && !q_vector->tx)
		return;
	else if (!tx && !q_vector->rx)
		return;

	intr_reg = &q_vector->intr_reg;
	wr32(hw, tx ? intr_reg->tx_itr : intr_reg->rx_itr,
	     ITR_REG_ALIGN(itr) >> IECM_ITR_GRAN_S);
}

/**
 * iecm_vport_intr_ena_irq_all - Enable IRQ for the given vport
 * @vport: main vport structure
 */
void iecm_vport_intr_ena_irq_all(struct iecm_vport *vport)
{
	int q_idx;

	for (q_idx = 0; q_idx < vport->num_q_vectors; q_idx++) {
		struct iecm_q_vector *q_vector = &vport->q_vectors[q_idx];

		if (q_vector->num_txq || q_vector->num_rxq) {
			/* Write the default ITR values */
			iecm_vport_intr_write_itr(q_vector,
						  q_vector->rx_itr_value,
						  false);
			iecm_vport_intr_write_itr(q_vector,
						  q_vector->tx_itr_value,
						  true);
			iecm_vport_intr_update_itr_ena_irq(q_vector);
		}
	}
}

/**
 * iecm_vport_intr_deinit - Release all vector associations for the vport
 * @vport: main vport structure
 */
void iecm_vport_intr_deinit(struct iecm_vport *vport)
{
	iecm_vport_intr_napi_dis_all(vport);
	iecm_vport_intr_napi_del_all(vport);
	iecm_vport_intr_dis_irq_all(vport);
	iecm_vport_intr_rel_irq(vport);
}

/**
 * iecm_tx_dim_work - Call back from the stack
 * @work: work queue structure
 */
static void iecm_tx_dim_work(struct work_struct *work)
{
	struct iecm_q_vector *q_vector;
	struct iecm_vport *vport;
	struct dim *dim;
	u16 itr;

	dim = container_of(work, struct dim, work);
	q_vector = container_of(dim, struct iecm_q_vector, tx_dim);
	vport = q_vector->vport;

	if (dim->profile_ix >= ARRAY_SIZE(vport->tx_itr_profile))
		dim->profile_ix = ARRAY_SIZE(vport->tx_itr_profile) - 1;

	/* look up the values in our local table */
	itr = vport->tx_itr_profile[dim->profile_ix];

	iecm_vport_intr_write_itr(q_vector, itr, true);

	dim->state = DIM_START_MEASURE;
}

/**
 * iecm_rx_dim_work - Call back from the stack
 * @work: work queue structure
 */
static void iecm_rx_dim_work(struct work_struct *work)
{
	struct iecm_q_vector *q_vector;
	struct iecm_vport *vport;
	struct dim *dim;
	u16 itr;

	dim = container_of(work, struct dim, work);
	q_vector = container_of(dim, struct iecm_q_vector, rx_dim);
	vport = q_vector->vport;

	if (dim->profile_ix >= ARRAY_SIZE(vport->rx_itr_profile))
		dim->profile_ix = ARRAY_SIZE(vport->rx_itr_profile) - 1;

	/* look up the values in our local table */
	itr = vport->rx_itr_profile[dim->profile_ix];

	iecm_vport_intr_write_itr(q_vector, itr, false);

	dim->state = DIM_START_MEASURE;
}

/**
 * iecm_vport_intr_napi_ena_all - Enable NAPI for all q_vectors in the vport
 * @vport: main vport structure
 */
static void
iecm_vport_intr_napi_ena_all(struct iecm_vport *vport)
{
	int q_idx;

	if (!vport->netdev)
		return;

	for (q_idx = 0; q_idx < vport->num_q_vectors; q_idx++) {
		struct iecm_q_vector *q_vector = &vport->q_vectors[q_idx];

		INIT_WORK(&q_vector->tx_dim.work, iecm_tx_dim_work);
		q_vector->tx_dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;

		INIT_WORK(&q_vector->rx_dim.work, iecm_rx_dim_work);
		q_vector->rx_dim.mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;

		napi_enable(&q_vector->napi);
	}
}

/**
 * iecm_tx_splitq_clean_all- Clean completetion queues
 * @q_vec: queue vector
 * @budget: Used to determine if we are in netpoll
 *
 * Returns false if clean is not complete else returns true
 */
static bool
iecm_tx_splitq_clean_all(struct iecm_q_vector *q_vec, int budget)
{
	bool clean_complete = true;
	int i, budget_per_q;

	budget_per_q = max(budget / q_vec->num_txq, 1);
	for (i = 0; i < q_vec->num_txq; i++) {
		if (!iecm_tx_clean_complq(q_vec->tx[i], budget_per_q))
			clean_complete = false;
	}
	return clean_complete;
}

/**
 * iecm_rx_splitq_clean_all- Clean completetion queues
 * @q_vec: queue vector
 * @budget: Used to determine if we are in netpoll
 * @cleaned: returns number of packets cleaned
 *
 * Returns false if clean is not complete else returns true
 */
static bool
iecm_rx_splitq_clean_all(struct iecm_q_vector *q_vec, int budget,
			 int *cleaned)
{
	bool clean_complete = true;
	int pkts_cleaned_per_q;
	int i, budget_per_q;

	budget_per_q = max(budget / q_vec->num_rxq, 1);
	for (i = 0; i < q_vec->num_rxq; i++) {
		struct iecm_queue *rxq = q_vec->rx[i];

#ifdef HAVE_NETDEV_BPF_XSK_POOL
		pkts_cleaned_per_q = rxq->xsk_pool ? iecm_rx_splitq_clean_zc(rxq, budget_per_q) :
						     iecm_rx_splitq_clean(rxq, budget_per_q);
#else
		pkts_cleaned_per_q  = iecm_rx_splitq_clean(rxq, budget_per_q);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
		/* if we clean as many as budgeted, we must not
		 * be done
		 */
		if (pkts_cleaned_per_q >= budget_per_q)
			clean_complete = false;
		*cleaned += pkts_cleaned_per_q;
	}

	for (i = 0; i < q_vec->num_bufq; i++)
		iecm_rx_clean_refillq_all(q_vec->bufq[i]);

	return clean_complete;
}

/**
 * iecm_vport_splitq_napi_poll - NAPI handler
 * @napi: struct from which you get q_vector
 * @budget: budget provided by stack
 */
static int iecm_vport_splitq_napi_poll(struct napi_struct *napi, int budget)
{
	struct iecm_q_vector *q_vector =
				container_of(napi, struct iecm_q_vector, napi);
	bool clean_complete;
	int work_done = 0;

	clean_complete = iecm_tx_splitq_clean_all(q_vector, budget);

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (budget <= 0)
		return budget;

	/* We attempt to distribute budget to each Rx queue fairly, but don't
	 * allow the budget to go below 1 because that would exit polling early.
	 */
	clean_complete |= iecm_rx_splitq_clean_all(q_vector, budget,
						   &work_done);

	/* If work not completed, return budget and polling will return */
	if (!clean_complete)
		return budget;

	/* Exit the polling mode, but don't re-enable interrupts if stack might
	 * poll us due to busy-polling
	 */
	if (likely(napi_complete_done(napi, work_done)))
		iecm_vport_intr_update_itr_ena_irq(q_vector);

	return min_t(int, work_done, budget - 1);
}

/**
 * iecm_vport_intr_map_vector_to_qs - Map vectors to queues
 * @vport: virtual port
 *
 * Mapping for vectors to queues
 */
static void iecm_vport_intr_map_vector_to_qs(struct iecm_vport *vport)
{
	int num_txq_grp = vport->num_txq_grp, bufq_vidx = 0;
#ifdef HAVE_XDP_SUPPORT
	bool is_xdp_prog_ena = iecm_xdp_is_prog_ena(vport);
#endif /* HAVE_XDP_SUPPORT */
	int i, j, qv_idx = 0, num_rxq, num_txq, q_index;
	struct iecm_rxq_group *rx_qgrp;
	struct iecm_txq_group *tx_qgrp;
	struct iecm_queue *q, *bufq;
#ifdef HAVE_XDP_SUPPORT
	int num_active_rxq;
#endif /* HAVE_XDP_SUPPORT */

#ifdef HAVE_XDP_SUPPORT
	if (is_xdp_prog_ena)
		/* XDP Tx queues are handled within Rx loop,
		 * correct num_txq_grp so that it stores number of
		 * regular Tx queue groups. This way when we later assign Tx to
		 * qvector, we go only through regular Tx queues.
		 */
		if (iecm_is_queue_model_split(vport->txq_model))
			num_txq_grp = vport->xdp_txq_offset;
#endif /* HAVE_XDP_SUPPORT */
	for (i = 0; i < vport->num_rxq_grp; i++) {
		rx_qgrp = &vport->rxq_grps[i];
		if (iecm_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

#ifdef HAVE_XDP_SUPPORT
		num_active_rxq = num_rxq - vport->num_xdp_rxq;
#endif /* HAVE_XDP_SUPPORT */

		for (j = 0; j < num_rxq; j++) {
			if (qv_idx >= vport->num_q_vectors)
				qv_idx = 0;

			if (iecm_is_queue_model_split(vport->rxq_model))
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				q = rx_qgrp->singleq.rxqs[j];
			q->q_vector = &vport->q_vectors[qv_idx];
			q_index = q->q_vector->num_rxq;
			q->q_vector->rx[q_index] = q;
			q->q_vector->num_rxq++;
#ifdef HAVE_XDP_SUPPORT
			/* Do not setup XDP Tx queues for dummy Rx queues. */
			if (j >= num_active_rxq)
				goto skip_xdp_txq_config;

			if (is_xdp_prog_ena) {
				if (iecm_is_queue_model_split(vport->txq_model)) {
					tx_qgrp = &vport->txq_grps[i + vport->xdp_txq_offset];
					q = tx_qgrp->complq;
					q->q_vector = &vport->q_vectors[qv_idx];
					q_index = q->q_vector->num_txq;
					q->q_vector->tx[q_index] = q;
					q->q_vector->num_txq++;
				} else {
					tx_qgrp = &vport->txq_grps[i];
					q = tx_qgrp->txqs[j + vport->xdp_txq_offset];
					q->q_vector = &vport->q_vectors[qv_idx];
					q_index = q->q_vector->num_txq;
					q->q_vector->tx[q_index] = q;
					q->q_vector->num_txq++;
				}
			}

skip_xdp_txq_config:
#endif /* HAVE_XDP_SUPPORT */
			qv_idx++;
		}

		if (iecm_is_queue_model_split(vport->rxq_model)) {
			for (j = 0; j < vport->num_bufqs_per_qgrp; j++) {
				bufq = &rx_qgrp->splitq.bufq_sets[j].bufq;
				bufq->q_vector = &vport->q_vectors[bufq_vidx];
				q_index = bufq->q_vector->num_bufq;
				bufq->q_vector->bufq[q_index] = bufq;
				bufq->q_vector->num_bufq++;
			}
			if (++bufq_vidx >= vport->num_q_vectors)
				bufq_vidx = 0;
		}
	}
	qv_idx = 0;
	for (i = 0; i < num_txq_grp; i++) {
		tx_qgrp = &vport->txq_grps[i];
		num_txq = tx_qgrp->num_txq;

		if (iecm_is_queue_model_split(vport->txq_model)) {
			if (qv_idx >= vport->num_q_vectors)
				qv_idx = 0;

			q = tx_qgrp->complq;
			q->q_vector = &vport->q_vectors[qv_idx];
			q_index = q->q_vector->num_txq;
			q->q_vector->tx[q_index] = q;
			q->q_vector->num_txq++;
			qv_idx++;
		} else {
#ifdef HAVE_XDP_SUPPORT
			num_txq = is_xdp_prog_ena ? tx_qgrp->num_txq - vport->xdp_txq_offset
						  : tx_qgrp->num_txq;
#endif /* HAVE_XDP_SUPPORT */
			for (j = 0; j < num_txq; j++) {
				if (qv_idx >= vport->num_q_vectors)
					qv_idx = 0;

				q = tx_qgrp->txqs[j];
				q->q_vector = &vport->q_vectors[qv_idx];
				q_index = q->q_vector->num_txq;
				q->q_vector->tx[q_index] = q;
				q->q_vector->num_txq++;

				qv_idx++;
			}
		}
	}
}

/**
 * iecm_vport_intr_init_vec_idx - Initialize the vector indexes
 * @vport: virtual port
 *
 * Initialize vector indexes with values returened over mailbox
 */
static int iecm_vport_intr_init_vec_idx(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_q_vector *q_vector;
	int i;

	if (adapter->req_vec_chunks) {
		struct virtchnl2_vector_chunks *vchunks;
		struct virtchnl2_alloc_vectors *ac;
		u16 vecids[IECM_MAX_VECIDS];
		int num_ids;

		ac = adapter->req_vec_chunks;
		vchunks = &ac->vchunks;

		num_ids = iecm_get_vec_ids(adapter, vecids, IECM_MAX_VECIDS,
					   vchunks);

		if (num_ids < adapter->num_msix_entries)
			return -EFAULT;

		for (i = 0; i < vport->num_q_vectors; i++) {
			q_vector = &vport->q_vectors[i];
			q_vector->v_idx = vecids[i + vport->q_vector_base];
		}
	} else {
		for (i = 0; i < vport->num_q_vectors; i++) {
			q_vector = &vport->q_vectors[i];
			q_vector->v_idx = i + vport->q_vector_base;
		}
	}

	return 0;
}

/**
 * iecm_vport_intr_napi_add_all- Register napi handler for all qvectors
 * @vport: virtual port structure
 */
static void iecm_vport_intr_napi_add_all(struct iecm_vport *vport)
{
	u16 v_idx;

	for (v_idx = 0; v_idx < vport->num_q_vectors; v_idx++) {
		struct iecm_q_vector *q_vector = &vport->q_vectors[v_idx];

		if (vport->netdev) {
			if (iecm_is_queue_model_split(vport->txq_model))
				netif_napi_add(vport->netdev, &q_vector->napi,
					       iecm_vport_splitq_napi_poll);
			else
				netif_napi_add(vport->netdev, &q_vector->napi,
					       iecm_vport_singleq_napi_poll);
		}

		/* only set affinity_mask if the CPU is online */
		if (cpu_online(v_idx))
			cpumask_set_cpu(v_idx, &q_vector->affinity_mask);
	}
}

/**
 * iecm_vport_intr_alloc - Allocate memory for interrupt vectors
 * @vport: virtual port
 *
 * We allocate one q_vector per queue interrupt. If allocation fails we
 * return -ENOMEM.
 */
int iecm_vport_intr_alloc(struct iecm_vport *vport)
{
	int txqs_per_vector, rxqs_per_vector, bufqs_per_vector;
	struct iecm_q_vector *q_vector;
	int v_idx, err = 0;

	vport->q_vectors = kcalloc(vport->num_q_vectors,
				   sizeof(struct iecm_q_vector), GFP_KERNEL);

	if (!vport->q_vectors)
		return -ENOMEM;

	txqs_per_vector = DIV_ROUND_UP(vport->num_txq, vport->num_q_vectors);
	rxqs_per_vector = DIV_ROUND_UP(vport->num_rxq, vport->num_q_vectors);
	bufqs_per_vector = DIV_ROUND_UP(vport->num_bufqs_per_qgrp *
					vport->num_rxq_grp,
					vport->num_q_vectors);

	for (v_idx = 0; v_idx < vport->num_q_vectors; v_idx++) {
		q_vector = &vport->q_vectors[v_idx];
		q_vector->vport = vport;

		q_vector->tx_itr_value = IECM_ITR_TX_DEF;
		q_vector->tx_intr_mode = IECM_ITR_DYNAMIC;
		q_vector->tx_itr_idx = VIRTCHNL2_ITR_IDX_1;

		q_vector->rx_itr_value = IECM_ITR_RX_DEF;
		q_vector->rx_intr_mode = IECM_ITR_DYNAMIC;
		q_vector->rx_itr_idx = VIRTCHNL2_ITR_IDX_0;

		q_vector->tx = kcalloc(txqs_per_vector,
				       sizeof(struct iecm_queue *),
				       GFP_KERNEL);
		if (!q_vector->tx) {
			err = -ENOMEM;
			goto error;
		}

		q_vector->rx = kcalloc(rxqs_per_vector,
				       sizeof(struct iecm_queue *),
				       GFP_KERNEL);
		if (!q_vector->rx) {
			err = -ENOMEM;
			goto error;
		}

		if (iecm_is_queue_model_split(vport->rxq_model)) {
			q_vector->bufq = kcalloc(bufqs_per_vector,
						 sizeof(struct iecm_queue *),
						 GFP_KERNEL);
			if (!q_vector->bufq) {
				err = -ENOMEM;
				goto error;
			}
		}
	}

	return 0;
error:
	iecm_vport_intr_rel(vport);
	return err;
}

/**
 * iecm_vport_intr_init - Setup all vectors for the given vport
 * @vport: virtual port
 *
 * Returns 0 on success or negative on failure
 */
int iecm_vport_intr_init(struct iecm_vport *vport)
{
	char int_name[IECM_INT_NAME_STR_LEN];
	int err = 0;

	err = iecm_vport_intr_init_vec_idx(vport);
	if (err)
		goto handle_err;

	iecm_vport_intr_map_vector_to_qs(vport);
	iecm_vport_intr_napi_add_all(vport);
	iecm_vport_intr_napi_ena_all(vport);

	err = vport->adapter->dev_ops.reg_ops.intr_reg_init(vport);
	if (err)
		goto unroll_vectors_alloc;

	snprintf(int_name, sizeof(int_name) - 1, "%s-%s",
		 dev_driver_string(&vport->adapter->pdev->dev),
		 vport->netdev->name);

	err = iecm_vport_intr_req_irq(vport, int_name);
	if (err)
		goto unroll_vectors_alloc;

	iecm_vport_intr_ena_irq_all(vport);
	goto handle_err;
unroll_vectors_alloc:
	iecm_vport_intr_napi_dis_all(vport);
	iecm_vport_intr_napi_del_all(vport);
handle_err:
	return err;
}

/**
 * iecm_config_rss - Prepare for RSS
 * @vport: virtual port
 *
 * Return 0 on success, negative on failure
 */
int iecm_config_rss(struct iecm_vport *vport)
{
	int err;

	err = vport->adapter->dev_ops.vc_ops.get_set_rss_key(vport, false);
	if (!err)
		err = vport->adapter->dev_ops.vc_ops.get_set_rss_lut(vport,
								     false);

	return err;
}

/**
 * iecm_fill_dflt_rss_lut - Fill the indirection table with the default values
 * @vport: virtual port structure
 */
void iecm_fill_dflt_rss_lut(struct iecm_vport *vport)
{
	u16 num_active_rxq = vport->num_rxq;
	int i;

#ifdef HAVE_XDP_SUPPORT
	/* When we use this code for legacy devices (e.g. in AVF driver), some Rx queues
	 * may not be used because we would not be able to create XDP Tx queues for them.
	 * In such a case do not add their queue IDs to the RSS LUT by setting
	 * the number of active Rx queues to XDP Tx queues count.
	 */
	if (iecm_xdp_is_prog_ena(vport))
		num_active_rxq -= vport->num_xdp_rxq;
#endif /* HAVE_XDP_SUPPORT */

	for (i = 0; i < vport->adapter->rss_data.rss_lut_size; i++)
		vport->adapter->rss_data.rss_lut[i] = i % num_active_rxq;
}

/**
 * iecm_init_rss - Prepare for RSS
 * @vport: virtual port
 *
 * Return 0 on success, negative on failure
 */
int iecm_init_rss(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	u32 lut_size;

	adapter->rss_data.rss_key = kzalloc(adapter->rss_data.rss_key_size,
					    GFP_KERNEL);
	if (!adapter->rss_data.rss_key)
		return -ENOMEM;

	lut_size = adapter->rss_data.rss_lut_size * sizeof(u32);
	adapter->rss_data.rss_lut = kzalloc(lut_size, GFP_KERNEL);
	if (!adapter->rss_data.rss_lut) {
		kfree(adapter->rss_data.rss_key);
		adapter->rss_data.rss_key = NULL;
		return -ENOMEM;
	}

	/* Initialize default rss key */
	netdev_rss_key_fill((void *)adapter->rss_data.rss_key,
			    adapter->rss_data.rss_key_size);

	/* Initialize default rss lut */
	if (adapter->rss_data.rss_lut_size % vport->num_rxq) {
		u32 dflt_qid;
		int i;

		/* Set all entries to a default RX queue if the algorithm below
		 * won't fill all entries
		 */
		if (iecm_is_queue_model_split(vport->rxq_model))
			dflt_qid =
				vport->rxq_grps[0].splitq.rxq_sets[0]->rxq.q_id;
		else
			dflt_qid =
				vport->rxq_grps[0].singleq.rxqs[0]->q_id;

		for (i = 0; i < adapter->rss_data.rss_lut_size; i++)
			adapter->rss_data.rss_lut[i] = dflt_qid;
	}

	/* Fill the default RSS lut values*/
	iecm_fill_dflt_rss_lut(vport);

	return iecm_config_rss(vport);
}

/**
 * iecm_deinit_rss - Prepare for RSS
 * @vport: virtual port
 *
 */
void iecm_deinit_rss(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;

	kfree(adapter->rss_data.rss_key);
	adapter->rss_data.rss_key = NULL;
	kfree(adapter->rss_data.rss_lut);
	adapter->rss_data.rss_lut = NULL;
}
