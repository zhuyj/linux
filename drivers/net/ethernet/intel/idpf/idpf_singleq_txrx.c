// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Intel Corporation */

#include <linux/prefetch.h>
#include "idpf.h"

/**
 * idpf_tx_singleq_csum - Enable tx checksum offloads
 * @skb: pointer to skb
 * @off: pointer to struct that holds offload parameters
 *
 * Returns 0 or error (negative) if checksum offload
 */
static
int idpf_tx_singleq_csum(struct sk_buff *skb,
			 struct idpf_tx_offload_params *off)
{
	u32 l4_len = 0, l3_len = 0, l2_len = 0;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		unsigned char *hdr;
	} l4;
	__be16 frag_off;
	unsigned char *exthdr;
	u32 offset, cmd = 0;
	u8 l4_proto = 0;
	bool is_tso;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	/* compute outer L2 header size */
	l2_len = ip.hdr - skb->data;
	offset = (l2_len / 2) << IDPF_TX_DESC_LEN_MACLEN_S;
	is_tso = (off->tx_flags & IDPF_TX_FLAGS_TSO) ? true : false;
#ifdef HAVE_ENCAP_CSUM_OFFLOAD
	if (skb->encapsulation) {
		u32 tunnel = 0;

		/* define outer network header type */
		if (off->tx_flags & IDPF_TX_FLAGS_IPV4) {
			tunnel |= is_tso ?
				  IDPF_TX_CTX_EXT_IP_IPV4 :
				  IDPF_TX_CTX_EXT_IP_IPV4_NO_CSUM;

			l4_proto = ip.v4->protocol;
		} else if (off->tx_flags & IDPF_TX_FLAGS_IPV6) {
			tunnel |= IDPF_TX_CTX_EXT_IP_IPV6;

			exthdr = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			if (l4.hdr != exthdr)
				ipv6_skip_exthdr(skb, exthdr - skb->data,
						 &l4_proto, &frag_off);
		}

		/* define outer transport */
		switch (l4_proto) {
		case IPPROTO_UDP:
			tunnel |= IDPF_TXD_CTX_UDP_TUNNELING;
			off->tx_flags |= IDPF_TX_FLAGS_TUNNEL;
			break;
#ifdef HAVE_GRE_ENCAP_OFFLOAD
		case IPPROTO_GRE:
			tunnel |= IDPF_TXD_CTX_GRE_TUNNELING;
			off->tx_flags |= IDPF_TX_FLAGS_TUNNEL;
			/* There was a long-standing issue in GRE where GSO
			 * was not setting the outer transport header unless
			 * a GRE checksum was requested. This was fixed in
			 * the 4.6 version of the kernel.  In the 4.7 kernel
			 * support for GRE over IPv6 was added to GSO.  So we
			 * can assume this workaround for all IPv4 headers
			 * without impacting later versions of the GRE.
			 */
			if (ip.v4->version == 4)
				l4.hdr = ip.hdr + (ip.v4->ihl * 4);
			break;
		case IPPROTO_IPIP:
		case IPPROTO_IPV6:
			off->tx_flags |= IDPF_TX_FLAGS_TUNNEL;
			l4.hdr = skb_inner_network_header(skb);
			break;
#endif
		default:
			if (is_tso)
				return -1;

			skb_checksum_help(skb);
			return 0;
		}

		/* compute outer L3 header size */
		tunnel |= ((l4.hdr - ip.hdr) / 4) <<
			  IDPF_TXD_CTX_QW0_TUNN_EXT_IPLEN_S;

		/* switch IP header pointer from outer to inner header */
		ip.hdr = skb_inner_network_header(skb);

		/* compute tunnel header size */
		tunnel |= ((ip.hdr - l4.hdr) / 2) <<
			  IDPF_TXD_CTX_QW0_TUNN_NATLEN_S;

		/* indicate if we need to offload outer UDP header */
#ifdef NETIF_F_GSO_PARTIAL
		if (is_tso &&
		    !(skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL) &&
		    (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM))
#else
		if (is_tso &&
		    (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM))
#endif
			tunnel |= IDPF_TXD_CTX_QW0_TUNN_L4T_CS_M;

		/* record tunnel offload values */
		off->cd_tunneling |= tunnel;

		/* switch L4 header pointer from outer to inner */
		l4.hdr = skb_inner_transport_header(skb);
		l4_proto = 0;

		/* reset type as we transition from outer to inner headers */
		off->tx_flags &= ~(IDPF_TX_FLAGS_IPV4 | IDPF_TX_FLAGS_IPV6);
		if (ip.v4->version == 4)
			off->tx_flags |= IDPF_TX_FLAGS_IPV4;
		if (ip.v6->version == 6)
			off->tx_flags |= IDPF_TX_FLAGS_IPV6;
	}
#endif /* HAVE_ENCAP_CSUM_OFFLOAD */

	/* Enable IP checksum offloads */
	if (off->tx_flags & IDPF_TX_FLAGS_IPV4) {
		l4_proto = ip.v4->protocol;
		/* the stack computes the IP header already, the only time we
		 * need the hardware to recompute it is in the case of TSO.
		 */
		if (is_tso)
			cmd |= IDPF_TX_DESC_CMD_IIPT_IPV4_CSUM;
		else
			cmd |= IDPF_TX_DESC_CMD_IIPT_IPV4;

	} else if (off->tx_flags & IDPF_TX_FLAGS_IPV6) {
		cmd |= IDPF_TX_DESC_CMD_IIPT_IPV6;
		exthdr = ip.hdr + sizeof(struct ipv6hdr);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr)
			ipv6_skip_exthdr(skb, exthdr - skb->data, &l4_proto,
					 &frag_off);
	} else {
		return -1;
	}

	/* compute inner L3 header size */
	l3_len = l4.hdr - ip.hdr;
	offset |= (l3_len / 4) << IDPF_TX_DESC_LEN_IPLEN_S;

	/* Enable L4 checksum offloads */
	switch (l4_proto) {
	case IPPROTO_TCP:
		/* enable checksum offloads */
		cmd |= IDPF_TX_DESC_CMD_L4T_EOFT_TCP;
		l4_len = l4.tcp->doff;
		offset |= l4_len << IDPF_TX_DESC_LEN_L4_LEN_S;
		break;
	case IPPROTO_UDP:
		/* enable UDP checksum offload */
		cmd |= IDPF_TX_DESC_CMD_L4T_EOFT_UDP;
		l4_len = (sizeof(struct udphdr) >> 2);
		offset |= l4_len << IDPF_TX_DESC_LEN_L4_LEN_S;
		break;
	case IPPROTO_SCTP:
		/* enable SCTP checksum offload */
		cmd |= IDPF_TX_DESC_CMD_L4T_EOFT_SCTP;
		l4_len = sizeof(struct sctphdr) >> 2;
		offset |= l4_len << IDPF_TX_DESC_LEN_L4_LEN_S;
		break;

	default:
		if (is_tso)
			return -1;
		skb_checksum_help(skb);
		return 0;
	}

	off->td_cmd |= cmd;
	off->hdr_offsets |= offset;
	return 1;
}

/**
 * idpf_tx_singleq_map - Build the Tx base descriptor
 * @tx_q: queue to send buffer on
 * @first: first buffer info buffer to use
 * @offloads: pointer to struct that holds offload parameters
 *
 * This function loops over the skb data pointed to by *first
 * and gets a physical address for each memory location and programs
 * it and the length into the transmit base mode descriptor.
 */
static void
idpf_tx_singleq_map(struct idpf_queue *tx_q, struct idpf_tx_buf *first,
		    struct idpf_tx_offload_params *offloads)
{
	u32 offsets = offloads->hdr_offsets;
	struct idpf_base_tx_desc *tx_desc;
	u64 td_cmd = offloads->td_cmd;
	unsigned int data_len, size;
	struct idpf_tx_buf *tx_buf;
	u16 i = tx_q->next_to_use;
	struct netdev_queue *nq;
	struct sk_buff *skb;
	skb_frag_t *frag;
	dma_addr_t dma;
	u64 td_tag = 0;

	skb = first->skb;

	data_len = skb->data_len;
	size = skb_headlen(skb);

	tx_desc = IDPF_BASE_TX_DESC(tx_q, i);

	dma = dma_map_single(tx_q->dev, skb->data, size, DMA_TO_DEVICE);

	tx_buf = first;

	/* write each descriptor with CRC bit */
	if (tx_q->vport->adapter->dev_ops.crc_enable)
		tx_q->vport->adapter->dev_ops.crc_enable(&td_cmd);

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		unsigned int max_data = IDPF_TX_MAX_DESC_DATA_ALIGNED;

		if (dma_mapping_error(tx_q->dev, dma))
			return idpf_tx_dma_map_error(tx_q, skb, first, i);

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buf, len, size);
		dma_unmap_addr_set(tx_buf, dma, dma);

		/* align size to end of page */
		max_data += -dma & (IDPF_TX_MAX_READ_REQ_SIZE - 1);
		tx_desc->buf_addr = cpu_to_le64(dma);

		/* account for data chunks larger than the hardware
		 * can handle
		 */
		while (unlikely(size > IDPF_TX_MAX_DESC_DATA)) {
			tx_desc->qw1 = idpf_tx_singleq_build_ctob(td_cmd,
								  offsets,
								  max_data,
								  td_tag);
			tx_desc++;
			i++;

			if (i == tx_q->desc_count) {
				tx_desc = IDPF_BASE_TX_DESC(tx_q, 0);
				i = 0;
			}

			dma += max_data;
			size -= max_data;

			max_data = IDPF_TX_MAX_DESC_DATA_ALIGNED;
			tx_desc->buf_addr = cpu_to_le64(dma);
		}

		if (likely(!data_len))
			break;
		tx_desc->qw1 = idpf_tx_singleq_build_ctob(td_cmd, offsets,
							  size, td_tag);
		tx_desc++;
		i++;

		if (i == tx_q->desc_count) {
			tx_desc = IDPF_BASE_TX_DESC(tx_q, 0);
			i = 0;
		}

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_q->dev, frag, 0, size,
				       DMA_TO_DEVICE);

		tx_buf = &tx_q->tx_buf[i];
	}

	/* record bytecount for BQL */
	nq = netdev_get_tx_queue(tx_q->vport->netdev, tx_q->idx);
	netdev_tx_sent_queue(nq, first->bytecount);

	/* record SW timestamp if HW timestamp is not available */
	skb_tx_timestamp(first->skb);

	/* write last descriptor with RS and EOP bits */
	td_cmd |= (u64)(IDPF_TX_DESC_CMD_EOP | IDPF_TX_DESC_CMD_RS);

	tx_desc->qw1 = idpf_tx_singleq_build_ctob(td_cmd, offsets, size, td_tag);

	i++;
	if (i == tx_q->desc_count)
		i = 0;

	/* set next_to_watch value indicating a packet is present */
	first->next_to_watch = tx_desc;

	idpf_tx_buf_hw_update(tx_q, i, netdev_xmit_more());
}

/**
 * idpf_tx_singleq_get_ctx_desc - grab next desc and update buffer ring
 * @txq: queue to put context descriptor on
 *
 * Since the TX buffer rings mimics the descriptor ring, update the tx buffer
 * ring entry to reflect that this index is a context descriptor
 */
static struct idpf_base_tx_ctx_desc *
idpf_tx_singleq_get_ctx_desc(struct idpf_queue *txq)
{
	struct idpf_base_tx_ctx_desc *ctx_desc;
	int i = txq->next_to_use;

	memset(&txq->tx_buf[i], 0, sizeof(struct idpf_tx_buf));
	txq->tx_buf[i].ctx_entry = true;

	/* grab the next descriptor */
	ctx_desc = IDPF_BASE_TX_CTX_DESC(txq, i);
	i++;
	txq->next_to_use = (i < txq->desc_count) ? i : 0;

	return ctx_desc;
}

/**
 * idpf_tx_singleq_frame - Sends buffer on Tx ring using base descriptors
 * @skb: send buffer
 * @tx_q: queue to send buffer on
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
static netdev_tx_t
idpf_tx_singleq_frame(struct sk_buff *skb, struct idpf_queue *tx_q)
{
	struct idpf_tx_offload_params offload = {0};
	struct idpf_tx_buf *first;
	unsigned int count;
	int csum, tso;
	__be16 protocol;

	count = idpf_tx_desc_count_required(skb);

	if (idpf_chk_linearize(skb, tx_q->tx_max_bufs, count)) {
		if (__skb_linearize(skb))
			return idpf_tx_drop_skb(tx_q, skb);

		count = idpf_size_to_txd_count(skb->len);
		u64_stats_update_begin(&tx_q->stats_sync);
		tx_q->q_stats.tx.linearize++;
		u64_stats_update_end(&tx_q->stats_sync);
	}

	if (idpf_tx_maybe_stop_common(tx_q,
				      count + IDPF_TX_DESCS_PER_CACHE_LINE +
				      IDPF_TX_DESCS_FOR_CTX)) {
		idpf_tx_buf_hw_update(tx_q, tx_q->next_to_use, false);
		return NETDEV_TX_BUSY;
	}

	protocol = vlan_get_protocol(skb);
	if (protocol == htons(ETH_P_IP))
		offload.tx_flags |= IDPF_TX_FLAGS_IPV4;
	else if (protocol == htons(ETH_P_IPV6))
		offload.tx_flags |= IDPF_TX_FLAGS_IPV6;

	tso = idpf_tso(skb, &offload);
	if (tso < 0)
		goto out_drop;

	csum = idpf_tx_singleq_csum(skb, &offload);
	if (csum < 0)
		goto out_drop;

	if (tso || offload.cd_tunneling) {
		struct idpf_base_tx_ctx_desc *ctx_desc =
			idpf_tx_singleq_get_ctx_desc(tx_q);
		u64 qw1 = (u64)IDPF_TX_DESC_DTYPE_CTX;

		if (tso) {
			qw1 |= IDPF_TX_CTX_DESC_TSO << IDPF_TXD_CTX_QW1_CMD_S;
			qw1 |= ((u64)offload.tso_len << IDPF_TXD_CTX_QW1_TSO_LEN_S) &
				IDPF_TXD_CTX_QW1_TSO_LEN_M;
			qw1 |= ((u64)offload.mss << IDPF_TXD_CTX_QW1_MSS_S) &
				IDPF_TXD_CTX_QW1_MSS_M;

			u64_stats_update_begin(&tx_q->stats_sync);
			tx_q->q_stats.tx.lso_pkts++;
			u64_stats_update_end(&tx_q->stats_sync);
		}

		ctx_desc->qw0.tunneling_params =
			cpu_to_le32(offload.cd_tunneling);

		ctx_desc->qw0.l2tag2 = cpu_to_le16(0);
		ctx_desc->qw0.rsvd1 = cpu_to_le16(0);
		ctx_desc->qw1 = cpu_to_le64(qw1);
	}

	/* record the location of the first descriptor for this packet */
	first = &tx_q->tx_buf[tx_q->next_to_use];
	first->skb = skb;

	if (tso) {
		first->gso_segs = offload.tso_segs;
		first->bytecount = skb->len + ((first->gso_segs - 1) * offload.tso_hdr_len);
	} else {
		first->bytecount = max_t(unsigned int, skb->len, ETH_ZLEN);
		first->gso_segs = 1;
	}
#ifdef IDPF_ADD_PROBES
	idpf_tx_extra_counters(tx_q, first, &offload);

#endif /* IDPF_ADD_PROBES */
	idpf_tx_singleq_map(tx_q, first, &offload);

	return NETDEV_TX_OK;

out_drop:
	return idpf_tx_drop_skb(tx_q, skb);
}

/**
 * idpf_tx_singleq_start - Selects the right Tx queue to send buffer
 * @skb: send buffer
 * @netdev: network interface device structure
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
netdev_tx_t idpf_tx_singleq_start(struct sk_buff *skb,
				  struct net_device *netdev)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);
	struct idpf_queue *tx_q;

	if (!vport || test_bit(__IDPF_HR_RESET_IN_PROG, vport->adapter->flags))
		return NETDEV_TX_BUSY;

	tx_q = vport->txqs[skb->queue_mapping];

	/* hardware can't handle really short frames, hardware padding works
	 * beyond this point
	 */
	if (skb_put_padto(skb, IDPF_TX_MIN_LEN)) {
		idpf_tx_buf_hw_update(tx_q, tx_q->next_to_use, false);
		return NETDEV_TX_OK;
	}

	return idpf_tx_singleq_frame(skb, tx_q);
}

/**
 * idpf_tx_singleq_clean - Reclaim resources from queue
 * @tx_q: Tx queue to clean
 * @napi_budget: Used to determine if we are in netpoll
 * @cleaned: returns number of packets cleaned
 *
 */
static bool idpf_tx_singleq_clean(struct idpf_queue *tx_q, int napi_budget, int *cleaned)
{
	unsigned int budget = tx_q->vport->compln_clean_budget;
	unsigned int total_bytes = 0, total_pkts = 0;
	struct idpf_base_tx_desc *tx_desc;
	s16 ntc = tx_q->next_to_clean;
	struct idpf_tx_buf *tx_buf;
	struct idpf_vport *vport;
	struct netdev_queue *nq;

	tx_desc = IDPF_BASE_TX_DESC(tx_q, ntc);
	tx_buf = &tx_q->tx_buf[ntc];
	ntc -= tx_q->desc_count;

	do {
		struct idpf_base_tx_desc *eop_desc;

		/* If this entry in the ring was used as a context descriptor,
		 * it's corresponding entry in the buffer ring will indicate as
		 * such. We can skip this descriptor since there is no buffer
		 * to clean.
		 */
		if (tx_buf->ctx_entry) {
			/* Clear this flag here to avoid stale flag values when this
			 * buffer is used for actual data in the future. There are
			 * cases where the tx_buf struct / the flags field will not
			 * be cleared before being reused.
			 */
			tx_buf->ctx_entry = false;
			goto fetch_next_txq_desc;
		}

		/* if next_to_watch is not set then no work pending */
		eop_desc = (struct idpf_base_tx_desc *)tx_buf->next_to_watch;
		if (!eop_desc)
			break;

		/* prevent any other reads prior to eop_desc */
		smp_rmb();

		/* if the descriptor isn't done, no work yet to do */
		if (!(eop_desc->qw1 &
		      cpu_to_le64(IDPF_TX_DESC_DTYPE_DESC_DONE)))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buf->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buf->bytecount;
		total_pkts += tx_buf->gso_segs;

#ifdef HAVE_XDP_SUPPORT
		if (test_bit(__IDPF_Q_XDP, tx_q->flags))
#ifdef HAVE_XDP_FRAME_STRUCT
			xdp_return_frame(tx_buf->xdpf);
#else
			page_frag_free(tx_buf->raw_buf);
#endif /* HAVE_XDP_FRAME_STRUCT */
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

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			tx_buf++;
			tx_desc++;
			ntc++;
			if (unlikely(!ntc)) {
				ntc -= tx_q->desc_count;
				tx_buf = tx_q->tx_buf;
				tx_desc = IDPF_BASE_TX_DESC(tx_q, 0);
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

		/* update budget only if we did something */
		budget--;

fetch_next_txq_desc:
		tx_buf++;
		tx_desc++;
		ntc++;
		if (unlikely(!ntc)) {
			ntc -= tx_q->desc_count;
			tx_buf = tx_q->tx_buf;
			tx_desc = IDPF_BASE_TX_DESC(tx_q, 0);
		}
	} while (likely(budget));

	ntc += tx_q->desc_count;
	tx_q->next_to_clean = ntc;

	*cleaned += total_pkts;

	u64_stats_update_begin(&tx_q->stats_sync);
	tx_q->q_stats.tx.packets += total_pkts;
	tx_q->q_stats.tx.bytes += total_bytes;
	u64_stats_update_end(&tx_q->stats_sync);
#ifdef HAVE_XDP_SUPPORT
	if (test_bit(__IDPF_Q_XDP, tx_q->flags))
		return !!budget;
#endif /* HAVE_XDP_SUPPORT */

	vport = tx_q->vport;
	nq = netdev_get_tx_queue(vport->netdev, tx_q->idx);
	netdev_tx_completed_queue(nq, total_pkts, total_bytes);

	if (unlikely(total_pkts && netif_carrier_ok(vport->netdev) &&
		     (IDPF_DESC_UNUSED(tx_q) >= IDPF_TX_WAKE_THRESH))) {
		/* Make sure any other threads stopping queue after this see
		 * new next_to_clean.
		 */
		smp_mb();
		if (__netif_subqueue_stopped(vport->netdev, tx_q->idx) &&
		    vport->state == __IDPF_VPORT_UP)
			netif_wake_subqueue(tx_q->vport->netdev, tx_q->idx);
	}

	return !!budget;
}

/**
 * idpf_tx_singleq_clean_all - Clean all Tx queues
 * @q_vec: queue vector
 * @budget: Used to determine if we are in netpoll
 * @cleaned: returns number of packets cleaned
 *
 * Returns false if clean is not complete else returns true
 */
static bool
idpf_tx_singleq_clean_all(struct idpf_q_vector *q_vec, int budget, int *cleaned)
{
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	bool is_xdp_prog_ena = idpf_xdp_is_prog_ena(q_vec->vport);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	int num_txq = q_vec->num_txq;
	bool clean_complete = true;
	struct idpf_queue *q;
	int i, budget_per_q;

	budget_per_q = num_txq ? max(budget / num_txq, 1) : 0;
	for (i = 0; i < num_txq; i++) {
		q = q_vec->tx[i];
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		if (is_xdp_prog_ena && q->xsk_pool)
			clean_complete = idpf_tx_singleq_clean_zc(q, cleaned);
		else
			clean_complete = idpf_tx_singleq_clean(q, budget_per_q, cleaned);
#else
		clean_complete = idpf_tx_singleq_clean(q, budget_per_q, cleaned);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	}

	return clean_complete;
}

/**
 * idpf_rx_singleq_test_staterr - tests bits in Rx descriptor
 * status and error fields
 * @rx_desc: pointer to receive descriptor (in le64 format)
 * @stat_err_bits: value to mask
 *
 * This function does some fast chicanery in order to return the
 * value of the mask which is really only used for boolean tests.
 * The status_error_ptype_len doesn't need to be shifted because it begins
 * at offset zero.
 */
bool
idpf_rx_singleq_test_staterr(union virtchnl2_rx_desc *rx_desc,
			     const u64 stat_err_bits)
{
	return !!(rx_desc->base_wb.qword1.status_error_ptype_len &
		  cpu_to_le64(stat_err_bits));
}

/**
 * idpf_rx_singleq_is_non_eop - process handling of non-EOP buffers
 * @rxq: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 * @skb: Current socket buffer containing buffer in progress
 */
bool idpf_rx_singleq_is_non_eop(struct idpf_queue *rxq,
				union virtchnl2_rx_desc *rx_desc,
				struct sk_buff *skb)
{
	/* if we are the last buffer then there is nothing else to do */
	if (likely(idpf_rx_singleq_test_staterr(rx_desc, IDPF_RXD_EOF_SINGLEQ)))
		return false;

	/* place skb in next buffer to be received */
	rxq->rx_buf.buf[rxq->next_to_clean].skb = skb;

	return true;
}

/**
 * idpf_rx_singleq_csum - Indicate in skb if checksum is good
 * @rxq: Rx descriptor ring packet is being transacted on
 * @skb: skb currently being received and modified
 * @csum_bits: checksum bits from descriptor
 * @ptype: the packet type decoded by hardware
 *
 * skb->protocol must be set before this function is called
 */
static void idpf_rx_singleq_csum(struct idpf_queue *rxq, struct sk_buff *skb,
				 struct idpf_rx_csum_decoded *csum_bits,
				 u16 ptype)
{
	struct idpf_rx_ptype_decoded decoded;
	bool ipv4, ipv6;

	/* Start with CHECKSUM_NONE and by default csum_level = 0 */
	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	/* check if Rx checksum is enabled */
	if (!(rxq->vport->netdev->features & NETIF_F_RXCSUM))
		return;

	/* check if HW has decoded the packet and checksum */
	if (!(csum_bits->l3l4p))
		return;

	decoded = rxq->vport->rx_ptype_lkup[ptype];
	if (!(decoded.known && decoded.outer_ip))
		return;

	ipv4 = (decoded.outer_ip == IDPF_RX_PTYPE_OUTER_IP) &&
	       (decoded.outer_ip_ver == IDPF_RX_PTYPE_OUTER_IPV4);
	ipv6 = (decoded.outer_ip == IDPF_RX_PTYPE_OUTER_IP) &&
	       (decoded.outer_ip_ver == IDPF_RX_PTYPE_OUTER_IPV6);

#ifdef IDPF_ADD_PROBES
	idpf_rx_extra_counters(rxq, decoded.inner_prot, ipv4, csum_bits, false);

#endif /* IDPF_ADD_PROBES */
	if (ipv4 && (csum_bits->ipe || csum_bits->eipe))
		goto checksum_fail;
	else if (ipv6 && (csum_bits->ipv6exadd))
		goto checksum_fail;

	/* check for L4 errors and handle packets that were not able to be
	 * checksummed due to arrival speed
	 */
	if (csum_bits->l4e)
		goto checksum_fail;

	if (csum_bits->nat && csum_bits->eudpe)
		goto checksum_fail;

	/* Handle packets that were not able to be checksummed due to arrival
	 * speed, in this case the stack can compute the csum.
	 */
	if (csum_bits->pprs)
		return;

	/* If there is an outer header present that might contain a checksum
	 * we need to bump the checksum level by 1 to reflect the fact that
	 * we are indicating we validated the inner checksum.
	 */
	if (decoded.tunnel_type >= IDPF_RX_PTYPE_TUNNEL_IP_GRENAT)
#ifdef HAVE_SKBUFF_CSUM_LEVEL
		skb->csum_level = 1;
#else
		skb->encapsulation = 1;
#endif

	/* Only report checksum unnecessary for ICMP, TCP, UDP, or SCTP */
	switch (decoded.inner_prot) {
	case IDPF_RX_PTYPE_INNER_PROT_ICMP:
	case IDPF_RX_PTYPE_INNER_PROT_TCP:
	case IDPF_RX_PTYPE_INNER_PROT_UDP:
	case IDPF_RX_PTYPE_INNER_PROT_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	default:
		break;
	}
	return;

checksum_fail:
	u64_stats_update_begin(&rxq->stats_sync);
	rxq->q_stats.rx.hw_csum_err++;
	u64_stats_update_end(&rxq->stats_sync);
}

/**
 * idpf_rx_singleq_base_csum - Indicate in skb if hw indicated a good cksum
 * @rx_q: Rx completion queue
 * @skb: skb currently being received and modified
 * @rx_desc: the receive descriptor
 * @ptype: Rx packet type
 *
 * This function only operates on the VIRTCHNL2_RXDID_1_32B_BASE_M legacy 32byte
 * descriptor writeback format.
 **/
static void
idpf_rx_singleq_base_csum(struct idpf_queue *rx_q, struct sk_buff *skb,
			  union virtchnl2_rx_desc *rx_desc, u16 ptype)
{
	struct idpf_rx_csum_decoded csum_bits;
	u32 rx_error, rx_status;
	u64 qword;

	qword = le64_to_cpu(rx_desc->base_wb.qword1.status_error_ptype_len);

	rx_status = FIELD_GET(VIRTCHNL2_RX_BASE_DESC_QW1_STATUS_M, qword);
	rx_error = FIELD_GET(VIRTCHNL2_RX_BASE_DESC_QW1_ERROR_M, qword);

	csum_bits.ipe = !!FIELD_GET(BIT(VIRTCHNL2_RX_BASE_DESC_ERROR_IPE_S),
				    rx_error);
	csum_bits.eipe = !!FIELD_GET(BIT(VIRTCHNL2_RX_BASE_DESC_ERROR_EIPE_S),
				     rx_error);
	csum_bits.l4e = !!FIELD_GET(BIT(VIRTCHNL2_RX_BASE_DESC_ERROR_L4E_S),
				    rx_error);
	csum_bits.pprs = !!FIELD_GET(BIT(VIRTCHNL2_RX_BASE_DESC_ERROR_PPRS_S),
				     rx_error);
	csum_bits.l3l4p =
		!!FIELD_GET(BIT(VIRTCHNL2_RX_BASE_DESC_STATUS_L3L4P_S),
			    rx_status);
	csum_bits.ipv6exadd =
		!!FIELD_GET(BIT(VIRTCHNL2_RX_BASE_DESC_STATUS_IPV6EXADD_S),
			    rx_status);
	csum_bits.nat = 0;
	csum_bits.eudpe = 0;

	idpf_rx_singleq_csum(rx_q, skb, &csum_bits, ptype);
}

/**
 * idpf_rx_singleq_flex_csum - Indicate in skb if hw indicated a good cksum
 * @rx_q: Rx completion queue
 * @skb: skb currently being received and modified
 * @rx_desc: the receive descriptor
 * @ptype: Rx packet type
 *
 * This function only operates on the VIRTCHNL2_RXDID_2_FLEX_SQ_NIC flexible
 * descriptor writeback format.
 **/
static void
idpf_rx_singleq_flex_csum(struct idpf_queue *rx_q, struct sk_buff *skb,
			  union virtchnl2_rx_desc *rx_desc, u16 ptype)
{
	struct idpf_rx_csum_decoded csum_bits;
	u16 rx_status0, rx_status1;

	rx_status0 = le16_to_cpu(rx_desc->flex_nic_wb.status_error0);
	rx_status1 = le16_to_cpu(rx_desc->flex_nic_wb.status_error1);

	csum_bits.ipe =
		!!FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_XSUM_IPE_S),
			    rx_status0);
	csum_bits.eipe =
		!!FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_XSUM_EIPE_S),
			    rx_status0);
	csum_bits.l4e =
		!!FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_XSUM_L4E_S),
			    rx_status0);
	csum_bits.eudpe =
		!!FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_XSUM_EUDPE_S),
			    rx_status0);
	csum_bits.l3l4p =
		!!FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_L3L4P_S),
			    rx_status0);
	csum_bits.ipv6exadd =
		!!FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_IPV6EXADD_S),
			    rx_status0);
	csum_bits.nat =
		!!FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS1_NAT_S),
			    rx_status1);
	csum_bits.pprs = 0;

	idpf_rx_singleq_csum(rx_q, skb, &csum_bits, ptype);
}

/**
 * idpf_rx_singleq_base_hash - set the hash value in the skb
 * @rx_q: Rx completion queue
 * @skb: skb currently being received and modified
 * @rx_desc: specific descriptor
 * @decoded: Decoded Rx packet type related fields
 *
 * This function only operates on the VIRTCHNL2_RXDID_1_32B_BASE_M legacy 32byte
 * descriptor writeback format.
 **/
static void
idpf_rx_singleq_base_hash(struct idpf_queue *rx_q, struct sk_buff *skb,
			  union virtchnl2_rx_desc *rx_desc,
			  struct idpf_rx_ptype_decoded *decoded)
{
#ifdef NETIF_F_RXHASH
	const __le64 rss_mask =
		cpu_to_le64((u64)VIRTCHNL2_RX_BASE_DESC_FLTSTAT_RSS_HASH <<
				VIRTCHNL2_RX_BASE_DESC_STATUS_FLTSTAT_S);
	u32 hash;

	if (!(rx_q->vport->netdev->features & NETIF_F_RXHASH))
		return;

	if ((rx_desc->base_wb.qword1.status_error_ptype_len & rss_mask) ==
								rss_mask) {
		hash = le32_to_cpu(rx_desc->base_wb.qword0.hi_dword.rss);
		skb_set_hash(skb, hash, idpf_ptype_to_htype(decoded));
	}
#endif /* NETIF_F_RXHASH */
}

/**
 * idpf_rx_singleq_flex_hash - set the hash value in the skb
 * @rx_q: Rx completion queue
 * @skb: skb currently being received and modified
 * @rx_desc: specific descriptor
 * @decoded: Decoded Rx packet type related fields
 *
 * This function only operates on the VIRTCHNL2_RXDID_2_FLEX_SQ_NIC flexible
 * descriptor writeback format.
 **/
static void
idpf_rx_singleq_flex_hash(struct idpf_queue *rx_q, struct sk_buff *skb,
			  union virtchnl2_rx_desc *rx_desc,
			  struct idpf_rx_ptype_decoded *decoded)
{
#ifdef NETIF_F_RXHASH
	if (!(rx_q->vport->netdev->features & NETIF_F_RXHASH))
		return;

	if (FIELD_GET(BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_RSS_VALID_S),
		      le16_to_cpu(rx_desc->flex_nic_wb.status_error0)))
		skb_set_hash(skb, le32_to_cpu(rx_desc->flex_nic_wb.rss_hash),
			     idpf_ptype_to_htype(decoded));
#endif /* NETIF_F_RXHASH */
}

/**
 * idpf_rx_singleq_process_skb_fields - Populate skb header fields from Rx
 * descriptor
 * @rx_q: Rx descriptor ring packet is being transacted on
 * @skb: pointer to current skb being populated
 * @rx_desc: descriptor for skb
 * @ptype: packet type
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, VLAN, protocol, and
 * other fields within the skb.
 */
void
idpf_rx_singleq_process_skb_fields(struct idpf_queue *rx_q, struct sk_buff *skb,
				   union virtchnl2_rx_desc *rx_desc,
				   u16 ptype)
{
	struct idpf_rx_ptype_decoded decoded =
					rx_q->vport->rx_ptype_lkup[ptype];

	/* modifies the skb - consumes the enet header */
	skb->protocol = eth_type_trans(skb, rx_q->vport->netdev);

	if (rx_q->rxdids == VIRTCHNL2_RXDID_1_32B_BASE_M) {
		idpf_rx_singleq_base_hash(rx_q, skb, rx_desc, &decoded);
		idpf_rx_singleq_base_csum(rx_q, skb, rx_desc, ptype);
	} else {
		idpf_rx_singleq_flex_hash(rx_q, skb, rx_desc, &decoded);
		idpf_rx_singleq_flex_csum(rx_q, skb, rx_desc, ptype);
	}
}

/**
 * idpf_rx_singleq_buf_hw_alloc_all - Replace used receive buffers
 * @rx_q: queue for which the hw buffers are allocated
 * @cleaned_count: number of buffers to replace
 *
 * Returns false if all allocations were successful, true if any fail
 */
bool idpf_rx_singleq_buf_hw_alloc_all(struct idpf_queue *rx_q,
				      u16 cleaned_count)
{
	struct virtchnl2_singleq_rx_buf_desc *singleq_rx_desc = NULL;
	struct idpf_page_info *page_info;
	u16 nta = rx_q->next_to_alloc;
	struct idpf_rx_buf *buf;

	/* do nothing if no valid netdev defined */
	if (!rx_q->vport->netdev || !cleaned_count)
		return false;

	singleq_rx_desc = IDPF_SINGLEQ_RX_BUF_DESC(rx_q, nta);
	buf = &rx_q->rx_buf.buf[nta];
	page_info = &buf->page_info[buf->page_indx];

	do {
		if (unlikely(!page_info->page)) {
			if (!idpf_init_rx_buf_hw_alloc(rx_q, buf))
				break;
		}

		/* Refresh the desc even if buffer_addrs didn't change
		 * because each write-back erases this info.
		 */
		singleq_rx_desc->pkt_addr =
			cpu_to_le64(page_info->dma + page_info->page_offset);
		singleq_rx_desc->hdr_addr = 0;
		singleq_rx_desc++;

		buf++;
		nta++;
		if (unlikely(nta == rx_q->desc_count)) {
			singleq_rx_desc = IDPF_SINGLEQ_RX_BUF_DESC(rx_q, 0);
			buf = rx_q->rx_buf.buf;
			nta = 0;
		}

		page_info = &buf->page_info[buf->page_indx];

		cleaned_count--;
	} while (cleaned_count);

	if (rx_q->next_to_alloc != nta) {
		idpf_rx_buf_hw_update(rx_q, nta);
		rx_q->next_to_alloc = nta;
	}

	return !!cleaned_count;
}

/**
 * idpf_rx_reuse_page - Put recycled buffer back onto ring
 * @rxq: Rx descriptor ring to store buffers on
 * @old_buf: donor buffer to have page reused
 */
static void idpf_rx_reuse_page(struct idpf_queue *rxq,
			       struct idpf_rx_buf *old_buf)
{
	u16 ntu = rxq->next_to_use;
	struct idpf_rx_buf *new_buf;

	new_buf = &rxq->rx_buf.buf[ntu];

	/* Transfer page from old buffer to new buffer.  Move each member
	 * individually to avoid possible store forwarding stalls and
	 * unnecessary copy of skb.
	 */
	new_buf->page_info[new_buf->page_indx].dma =
				old_buf->page_info[old_buf->page_indx].dma;
	new_buf->page_info[new_buf->page_indx].page =
				old_buf->page_info[old_buf->page_indx].page;
	new_buf->page_info[new_buf->page_indx].page_offset =
			old_buf->page_info[old_buf->page_indx].page_offset;
	new_buf->page_info[new_buf->page_indx].pagecnt_bias =
			old_buf->page_info[old_buf->page_indx].pagecnt_bias;
}

/**
 * idpf_rx_singleq_recycle_buf - Clean up used buffer and either recycle or free
 * @rxq: Rx descriptor queue to transact packets on
 * @rx_buf: Rx buffer to pull data from
 *
 * This function will clean up the contents of the rx_buf. It will either
 * recycle the buffer or unmap it and free the associated resources.
 *
 * Returns true if the buffer is reused, false if the buffer is freed.
 */
static bool idpf_rx_singleq_recycle_buf(struct idpf_queue *rxq,
					struct idpf_rx_buf *rx_buf)
{
	struct idpf_page_info *page_info =
			&rx_buf->page_info[rx_buf->page_indx];

	bool recycled = false;

	if (idpf_rx_can_reuse_page(rx_buf)) {
		/* hand second half of page back to the queue */
		idpf_rx_reuse_page(rxq, rx_buf);
		recycled = true;
	} else {
		/* we are not reusing the buffer so unmap it */
#ifndef HAVE_STRUCT_DMA_ATTRS
		dma_unmap_page_attrs(rxq->dev, page_info->dma, PAGE_SIZE,
				     DMA_FROM_DEVICE, IDPF_RX_DMA_ATTR);
#else
		dma_unmap_page(rxq->dev, page_info->dma, PAGE_SIZE,
			       DMA_FROM_DEVICE);
#endif /* !HAVE_STRUCT_DMA_ATTRS */
		__page_frag_cache_drain(page_info->page,
					page_info->pagecnt_bias);
	}

	/* clear contents of buffer_info */
	page_info->page = NULL;
	rx_buf->skb = NULL;

	return recycled;
}

/**
 * idpf_rx_singleq_put_buf - Wrapper function to clean and recycle buffers
 * @rxq: Rx descriptor queue to transact packets on
 * @rx_buf: Rx buffer to pull data from
 *
 * This function will update the next_to_use/next_to_alloc if the current
 * buffer is recycled.
 */
static void idpf_rx_singleq_put_buf(struct idpf_queue *rxq,
				    struct idpf_rx_buf *rx_buf)
{
	u16 ntu = rxq->next_to_use;
	bool recycled = false;

	recycled = idpf_rx_singleq_recycle_buf(rxq, rx_buf);

	/* update, and store next to alloc if the buffer was recycled */
	if (recycled) {
		ntu++;
		rxq->next_to_use = (ntu < rxq->desc_count) ? ntu : 0;
	}
}

/**
 * idpf_rx_singleq_bump_ntc - Bump and wrap q->next_to_clean value
 * @rxq: queue to bump
 */
void idpf_rx_singleq_bump_ntc(struct idpf_queue *rxq)
{
	u16 ntc = rxq->next_to_clean + 1;
	/* fetch, update, and store next to clean */
	if (ntc < rxq->desc_count)
		rxq->next_to_clean = ntc;
	else
		rxq->next_to_clean = 0;
}

/**
 * idpf_rx_singleq_get_buf_page - Fetch Rx buffer page and synchronize data
 * @dev: device struct
 * @rx_buf: Rx buf to fetch page for
 * @size: size of buffer to add to skb
 *
 * This function will pull an Rx buffer page from the ring and synchronize it
 * for use by the CPU.
 */
static struct sk_buff *
idpf_rx_singleq_get_buf_page(struct device *dev, struct idpf_rx_buf *rx_buf,
			     const unsigned int size)
{
	struct idpf_page_info *page_info;

	page_info = &rx_buf->page_info[rx_buf->page_indx];
	prefetch(page_info->page);

	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(dev, page_info->dma,
				      page_info->page_offset, size,
				      DMA_FROM_DEVICE);

	/* We have pulled a buffer for use, so decrement pagecnt_bias */
	page_info->pagecnt_bias--;

	return rx_buf->skb;
}

/**
 * idpf_rx_singleq_extract_base_fields - Extract fields from the Rx descriptor
 * @rx_q: Rx descriptor queue
 * @rx_desc: the descriptor to process
 * @fields: storage for extracted values
 *
 * Decode the Rx descriptor and extract relevant information including the
 * size and Rx packet type.
 *
 * This function only operates on the VIRTCHNL2_RXDID_1_32B_BASE_M legacy 32byte
 * descriptor writeback format.
 */
static inline void
idpf_rx_singleq_extract_base_fields(struct idpf_queue *rx_q,
				    union virtchnl2_rx_desc *rx_desc,
				    struct idpf_rx_extracted *fields)
{
	u64 qword;

	qword = le64_to_cpu(rx_desc->base_wb.qword1.status_error_ptype_len);

	fields->size = FIELD_GET(VIRTCHNL2_RX_BASE_DESC_QW1_LEN_PBUF_M, qword);
	fields->rx_ptype = FIELD_GET(VIRTCHNL2_RX_BASE_DESC_QW1_PTYPE_M, qword);

}

/**
 * idpf_rx_singleq_extract_flex_fields - Extract fields from the Rx descriptor
 * @rx_q: Rx descriptor queue
 * @rx_desc: the descriptor to process
 * @fields: storage for extracted values
 *
 * Decode the Rx descriptor and extract relevant information including the
 * size and Rx packet type.
 *
 * This function only operates on the VIRTCHNL2_RXDID_2_FLEX_SQ_NIC flexible
 * descriptor writeback format.
 */
static inline void
idpf_rx_singleq_extract_flex_fields(struct idpf_queue *rx_q,
				    union virtchnl2_rx_desc *rx_desc,
				    struct idpf_rx_extracted *fields)
{

	fields->size = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_PKT_LEN_M,
				 le16_to_cpu(rx_desc->flex_nic_wb.pkt_len));
	fields->rx_ptype = FIELD_GET(VIRTCHNL2_RX_FLEX_DESC_PTYPE_M,
			   le16_to_cpu(rx_desc->flex_nic_wb.ptype_flex_flags0));

}

/**
 * idpf_rx_singleq_extract_fields - Extract fields from the Rx descriptor
 * @rx_q: Rx descriptor queue
 * @rx_desc: the descriptor to process
 * @fields: storage for extracted values
 *
 */
void
idpf_rx_singleq_extract_fields(struct idpf_queue *rx_q,
			       union virtchnl2_rx_desc *rx_desc,
			       struct idpf_rx_extracted *fields)
{
	if (rx_q->rxdids == VIRTCHNL2_RXDID_1_32B_BASE_M)
		idpf_rx_singleq_extract_base_fields(rx_q, rx_desc, fields);
	else
		idpf_rx_singleq_extract_flex_fields(rx_q, rx_desc, fields);
}

/**
 * idpf_rx_singleq_clean - Reclaim resources after receive completes
 * @rx_q: rx queue to clean
 * @budget: Total limit on number of packets to process
 *
 * Returns true if there's any budget left (e.g. the clean is finished)
 */
static int idpf_rx_singleq_clean(struct idpf_queue *rx_q, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_pkts = 0;
#ifdef HAVE_XDP_SUPPORT
	unsigned int xdp_res = IDPF_XDP_PASS, xdp_xmit = 0;
	struct idpf_queue *xdpq = NULL;
#endif /* HAVE_XDP_SUPPORT */
	u16 cleaned_count = 0;
	bool failure = false;

#ifdef HAVE_XDP_SUPPORT
	if (idpf_xdp_is_prog_ena(rx_q->vport))
		xdpq = idpf_get_related_xdp_queue(rx_q);
#endif /* HAVE_XDP_SUPPORT */

	/* Process Rx packets bounded by budget */
	while (likely(total_rx_pkts < (unsigned int)budget)) {
		struct idpf_rx_extracted fields = {};
		union virtchnl2_rx_desc *rx_desc;
		struct sk_buff *skb = NULL;
		struct idpf_rx_buf *rx_buf;

		/* get the Rx desc from Rx queue based on 'next_to_clean' */
		rx_desc = IDPF_RX_DESC(rx_q, rx_q->next_to_clean);

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
#define IDPF_RXD_DD BIT(VIRTCHNL2_RX_BASE_DESC_STATUS_DD_S)
		if (!idpf_rx_singleq_test_staterr(rx_desc,
						  IDPF_RXD_DD))
			break;
		idpf_rx_singleq_extract_fields(rx_q, rx_desc, &fields);

		if (!fields.size)
			break;

		rx_buf = &rx_q->rx_buf.buf[rx_q->next_to_clean];
		skb = idpf_rx_singleq_get_buf_page(rx_q->dev, rx_buf,
						   fields.size);

#ifdef HAVE_XDP_SUPPORT
		if (xdpq)
			xdp_res = idpf_rx_xdp(rx_q, xdpq, rx_buf, fields.size);
		if (xdp_res) {
			if (xdp_res & (IDPF_XDP_TX | IDPF_XDP_REDIR)) {
				xdp_xmit |= xdp_res;
				idpf_rx_buf_adjust_pg(rx_buf, IDPF_RX_BUF_2048);
			} else {
				int page_indx = rx_buf->page_indx;

				rx_buf->page_info[page_indx].pagecnt_bias++;
			}
			total_rx_bytes += fields.size;
			total_rx_pkts++;
			cleaned_count++;
			rx_buf->page_info[rx_buf->page_indx].pagecnt_bias++;
			idpf_rx_singleq_put_buf(rx_q, rx_buf);

			idpf_rx_singleq_bump_ntc(rx_q);
			continue;
		}
#endif /* HAVE_XDP_SUPPORT */

		if (skb)
			idpf_rx_add_frag(rx_buf, skb, fields.size);
		else
			skb = idpf_rx_construct_skb(rx_q, rx_buf, fields.size);

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			rx_buf->page_info[rx_buf->page_indx].pagecnt_bias++;
			break;
		}

		idpf_rx_singleq_put_buf(rx_q, rx_buf);
		idpf_rx_singleq_bump_ntc(rx_q);

		cleaned_count++;

		/* skip if it is non EOP desc */
		if (idpf_rx_singleq_is_non_eop(rx_q, rx_desc,
					       skb))
			continue;

#define IDPF_RXD_ERR_S BIT(VIRTCHNL2_RX_BASE_DESC_QW1_ERROR_S)
		if (unlikely(idpf_rx_singleq_test_staterr(rx_desc,
							  IDPF_RXD_ERR_S))) {
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
		idpf_rx_singleq_process_skb_fields(rx_q, skb,
						   rx_desc, fields.rx_ptype);

		/* send completed skb up the stack */
		napi_gro_receive(&rx_q->q_vector->napi, skb);

		/* update budget accounting */
		total_rx_pkts++;
	}
	if (cleaned_count)
		failure = idpf_rx_singleq_buf_hw_alloc_all(rx_q, cleaned_count);

#ifdef HAVE_XDP_SUPPORT
	if (xdpq)
		idpf_finalize_xdp_rx(xdpq, xdp_xmit);
#endif /* HAVE_XDP_SUPPORT */

	u64_stats_update_begin(&rx_q->stats_sync);
	rx_q->q_stats.rx.packets += total_rx_pkts;
	rx_q->q_stats.rx.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_q->stats_sync);

	/* guarantee a trip back through this routine if there was a failure */
	return failure ? budget : (int)total_rx_pkts;
}

/**
 * idpf_rx_singleq_clean_all - Clean all Rx queues
 * @q_vec: queue vector
 * @budget: Used to determine if we are in netpoll
 * @cleaned: returns number of packets cleaned
 *
 * Returns false if clean is not complete else returns true
 */
static bool
idpf_rx_singleq_clean_all(struct idpf_q_vector *q_vec, int budget,
			  int *cleaned)
{
	int num_rxq = q_vec->num_rxq;
	bool clean_complete = true;
	int pkts_cleaned_per_q;
	int budget_per_q, i;

	/* We attempt to distribute budget to each Rx queue fairly, but don't
	 * allow the budget to go below 1 because that would exit polling early.
	 */
	budget_per_q = num_rxq ? max(budget / num_rxq, 1) : 0;
	for (i = 0; i < num_rxq; i++) {
		struct idpf_queue *rxq = q_vec->rx[i];

#ifdef HAVE_NETDEV_BPF_XSK_POOL
		pkts_cleaned_per_q = rxq->xsk_pool ? idpf_rx_singleq_clean_zc(rxq, budget_per_q) :
						     idpf_rx_singleq_clean(rxq, budget_per_q);
#else
		pkts_cleaned_per_q = idpf_rx_singleq_clean(rxq, budget_per_q);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
		/* if we clean as many as budgeted, we must not be done */
		if (pkts_cleaned_per_q >= budget_per_q)
			clean_complete = false;
		*cleaned += pkts_cleaned_per_q;
	}

	return clean_complete;
}

/**
 * idpf_vport_singleq_napi_poll - NAPI handler
 * @napi: struct from which you get q_vector
 * @budget: budget provided by stack
 */
int idpf_vport_singleq_napi_poll(struct napi_struct *napi, int budget)
{
	struct idpf_q_vector *q_vector =
				container_of(napi, struct idpf_q_vector, napi);
	bool clean_complete;
	int work_done = 0;

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (budget <= 0) {
		idpf_tx_singleq_clean_all(q_vector, budget, &work_done);
		return budget;
	}

	clean_complete = idpf_rx_singleq_clean_all(q_vector, budget,
						   &work_done);
	clean_complete &= idpf_tx_singleq_clean_all(q_vector, budget, &work_done);

	/* If work not completed, return budget and polling will return */
	if (!clean_complete)
		return budget;

	work_done = min_t(int, work_done, budget - 1);

	/* Exit the polling mode, but don't re-enable interrupts if stack might
	 * poll us due to busy-polling
	 */
	if (likely(napi_complete_done(napi, work_done)))
		idpf_vport_intr_update_itr_ena_irq(q_vector);
	return work_done;
}

#ifdef HAVE_XDP_SUPPORT
/**
 * idpf_prepare_xdp_tx_singleq_desc - Prepare TX descriptor for XDP in single queue mode
 * @xdpq: Pointer to XDP TX queue
 * @dma:  Address of DMA buffer used for XDP TX.
 * @idx:  Index of the TX buffer in the queue.
 * @size: Size of data to be transmitted.
 *
 * Returns a void pointer to idpf_base_tx_desc structure keeping a created descriptor.
 */
void *idpf_prepare_xdp_tx_singleq_desc(struct idpf_queue *xdpq, dma_addr_t dma,
				       u16 idx, u32 size)
{
	struct idpf_base_tx_desc *tx_desc;
	u64 td_cmd;

	tx_desc = IDPF_BASE_TX_DESC(xdpq, idx);
	tx_desc->buf_addr = cpu_to_le64(dma);

	td_cmd = (u64)IDPF_TXD_LAST_DESC_CMD;
	tx_desc->qw1 = idpf_tx_singleq_build_ctob(td_cmd, 0x0, size, 0);

	return (void *)tx_desc;
}
#endif /* HAVE_XDP_SUPPORT */
