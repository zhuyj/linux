// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2019 Intel Corporation */

#include <linux/prefetch.h>
#include "iecm.h"

/**
 * iecm_tx_singleq_csum - Enable tx checksum offloads
 * @first: pointer to first descriptor
 * @off: pointer to struct that holds offload parameters
 *
 * Returns 0 or error (negative) if checksum offload
 */
static
int iecm_tx_singleq_csum(struct iecm_tx_buf *first,
			 struct iecm_tx_offload_params *off)
{
	u32 l4_len = 0, l3_len = 0, l2_len = 0;
	struct sk_buff *skb = first->skb;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		unsigned char *hdr;
	} l4;
	__be16 frag_off, protocol;
	unsigned char *exthdr;
	u32 offset, cmd = 0;
	u8 l4_proto = 0;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (skb->encapsulation)
		return -1;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	/* compute outer L2 header size */
	l2_len = ip.hdr - skb->data;
	offset = (l2_len / 2) << IECM_TX_DESC_LEN_MACLEN_S;

	/* Enable IP checksum offloads */
	protocol = vlan_get_protocol(skb);
	if (protocol == htons(ETH_P_IP)) {
		l4_proto = ip.v4->protocol;
		/* the stack computes the IP header already, the only time we
		 * need the hardware to recompute it is in the case of TSO.
		 */
		if (first->tx_flags & IECM_TX_FLAGS_TSO)
			cmd |= IECM_TX_DESC_CMD_IIPT_IPV4_CSUM;
		else
			cmd |= IECM_TX_DESC_CMD_IIPT_IPV4;

	} else if (protocol == htons(ETH_P_IPV6)) {
		cmd |= IECM_TX_DESC_CMD_IIPT_IPV6;
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
	offset |= (l3_len / 4) << IECM_TX_DESC_LEN_IPLEN_S;

	/* Enable L4 checksum offloads */
	switch (l4_proto) {
	case IPPROTO_TCP:
		/* enable checksum offloads */
		cmd |= IECM_TX_DESC_CMD_L4T_EOFT_TCP;
		l4_len = l4.tcp->doff;
		offset |= l4_len << IECM_TX_DESC_LEN_L4_LEN_S;
		break;
	case IPPROTO_UDP:
		/* enable UDP checksum offload */
		cmd |= IECM_TX_DESC_CMD_L4T_EOFT_UDP;
		l4_len = (sizeof(struct udphdr) >> 2);
		offset |= l4_len << IECM_TX_DESC_LEN_L4_LEN_S;
		break;
	case IPPROTO_SCTP:
		/* enable SCTP checksum offload */
		cmd |= IECM_TX_DESC_CMD_L4T_EOFT_SCTP;
		l4_len = sizeof(struct sctphdr) >> 2;
		offset |= l4_len << IECM_TX_DESC_LEN_L4_LEN_S;
		break;

	default:
		if (first->tx_flags & IECM_TX_FLAGS_TSO)
			return -1;
		skb_checksum_help(skb);
		return 0;
	}

	off->td_cmd |= cmd;
	off->hdr_offsets |= offset;
	return 1;
}

/**
 * iecm_tx_singleq_map - Build the Tx base descriptor
 * @tx_q: queue to send buffer on
 * @first: first buffer info buffer to use
 * @offloads: pointer to struct that holds offload parameters
 *
 * This function loops over the skb data pointed to by *first
 * and gets a physical address for each memory location and programs
 * it and the length into the transmit base mode descriptor.
 */
static void
iecm_tx_singleq_map(struct iecm_queue *tx_q, struct iecm_tx_buf *first,
		    struct iecm_tx_offload_params *offloads)
{
	u32 offsets = offloads->hdr_offsets;
	struct iecm_base_tx_desc *tx_desc;
	u64 td_cmd = offloads->td_cmd;
	unsigned int data_len, size;
	struct iecm_tx_buf *tx_buf;
	u16 i = tx_q->next_to_use;
	struct netdev_queue *nq;
	struct sk_buff *skb;
	skb_frag_t *frag;
	dma_addr_t dma;
	u64 td_tag = 0;

	skb = first->skb;

	data_len = skb->data_len;
	size = skb_headlen(skb);

	tx_desc = IECM_BASE_TX_DESC(tx_q, i);

	if (first->tx_flags & IECM_TX_FLAGS_VLAN_TAG) {
		td_cmd |= (u64)IECM_TX_DESC_CMD_IL2TAG1;
		td_tag = (first->tx_flags & IECM_TX_FLAGS_VLAN_MASK) >>
			 IECM_TX_FLAGS_VLAN_SHIFT;
	}

	dma = dma_map_single(tx_q->dev, skb->data, size, DMA_TO_DEVICE);

	tx_buf = first;

	/* write each descriptor with CRC bit */
	if (tx_q->vport->adapter->dev_ops.crc_enable)
		tx_q->vport->adapter->dev_ops.crc_enable(&td_cmd);

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		unsigned int max_data = IECM_TX_MAX_DESC_DATA_ALIGNED;

		if (dma_mapping_error(tx_q->dev, dma))
			goto dma_error;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buf, len, size);
		dma_unmap_addr_set(tx_buf, dma, dma);

		/* align size to end of page */
		max_data += -dma & (IECM_TX_MAX_READ_REQ_SIZE - 1);
		tx_desc->buf_addr = cpu_to_le64(dma);

		/* account for data chunks larger than the hardware
		 * can handle
		 */
		while (unlikely(size > IECM_TX_MAX_DESC_DATA)) {
			tx_desc->qw1 = iecm_tx_singleq_build_ctob(td_cmd,
								  offsets,
								  max_data,
								  td_tag);
			tx_desc++;
			i++;

			if (i == tx_q->desc_count) {
				tx_desc = IECM_BASE_TX_DESC(tx_q, 0);
				i = 0;
			}

			dma += max_data;
			size -= max_data;

			max_data = IECM_TX_MAX_DESC_DATA_ALIGNED;
			tx_desc->buf_addr = cpu_to_le64(dma);
		}

		if (likely(!data_len))
			break;
		tx_desc->qw1 = iecm_tx_singleq_build_ctob(td_cmd, offsets,
							  size, td_tag);
		tx_desc++;
		i++;

		if (i == tx_q->desc_count) {
			tx_desc = IECM_BASE_TX_DESC(tx_q, 0);
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
	td_cmd |= (u64)(IECM_TX_DESC_CMD_EOP | IECM_TX_DESC_CMD_RS);

	tx_desc->qw1 = iecm_tx_singleq_build_ctob(td_cmd, offsets, size, td_tag);

	i++;
	if (i == tx_q->desc_count)
		i = 0;

	/* set next_to_watch value indicating a packet is present */
	first->next_to_watch = tx_desc;

	iecm_tx_buf_hw_update(tx_q, i, netdev_xmit_more());

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
 * iecm_tx_singleq_frame - Sends buffer on Tx ring using base descriptors
 * @skb: send buffer
 * @tx_q: queue to send buffer on
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
static netdev_tx_t
iecm_tx_singleq_frame(struct sk_buff *skb, struct iecm_queue *tx_q)
{
	struct iecm_tx_offload_params offload = {0};
	struct iecm_tx_buf *first;
	unsigned int count;
	int csum, tso;

	count = iecm_tx_desc_count_required(skb);

	if (iecm_chk_linearize(skb, tx_q->tx_max_bufs, count)) {
		if (__skb_linearize(skb)) {
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
		count = iecm_size_to_txd_count(skb->len);
		tx_q->vport->port_stats.tx_linearize++;
	}

	if (iecm_tx_maybe_stop_common(tx_q,
				      count + IECM_TX_DESCS_PER_CACHE_LINE +
				      IECM_TX_DESCS_FOR_CTX))
		return NETDEV_TX_BUSY;

	/* record the location of the first descriptor for this packet */
	first = &tx_q->tx_buf[tx_q->next_to_use];
	first->skb = skb;
	first->bytecount = max_t(unsigned int, skb->len, ETH_ZLEN);
	first->gso_segs = 1;
	first->tx_flags = 0;

	iecm_tx_prepare_vlan_flags(tx_q, first, skb);

	tso = iecm_tso(first, &offload);
	if (tso < 0)
		goto out_drop;

#ifdef IECM_ADD_PROBES
	iecm_tx_extra_counters(tx_q, first);

#endif /* IECM_ADD_PROBES */
	csum = iecm_tx_singleq_csum(first, &offload);
	if (csum < 0)
		goto out_drop;

	if (first->tx_flags & IECM_TX_FLAGS_TSO) {
		struct iecm_base_tx_ctx_desc *ctx_desc;
		int i = tx_q->next_to_use;
		u64 qw1 = (u64)IECM_TX_DESC_DTYPE_CTX |
			       IECM_TX_CTX_DESC_TSO << IECM_TXD_CTX_QW1_CMD_S;

		/* grab the next descriptor */
		ctx_desc = IECM_BASE_TX_CTX_DESC(tx_q, i);
		i++;
		tx_q->next_to_use = (i < tx_q->desc_count) ? i : 0;

		qw1 |= ((u64)offload.tso_len << IECM_TXD_CTX_QW1_TSO_LEN_S) &
			IECM_TXD_CTX_QW1_TSO_LEN_M;

		qw1 |= ((u64)offload.mss << IECM_TXD_CTX_QW1_MSS_S) &
			IECM_TXD_CTX_QW1_MSS_M;

		ctx_desc->qw0.rsvd0 = cpu_to_le32(0);
		ctx_desc->qw0.l2tag2 = cpu_to_le16(0);
		ctx_desc->qw0.rsvd1 = cpu_to_le16(0);
		ctx_desc->qw1 = cpu_to_le64(qw1);
	}

	iecm_tx_singleq_map(tx_q, first, &offload);

	return NETDEV_TX_OK;

out_drop:
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

/**
 * iecm_tx_singleq_start - Selects the right Tx queue to send buffer
 * @skb: send buffer
 * @netdev: network interface device structure
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 */
netdev_tx_t iecm_tx_singleq_start(struct sk_buff *skb,
				  struct net_device *netdev)
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);
	struct iecm_queue *tx_q;

	if (test_bit(__IECM_HR_RESET_IN_PROG, vport->adapter->flags))
		return NETDEV_TX_BUSY;

	tx_q = vport->txqs[skb->queue_mapping];

	/* hardware can't handle really short frames, hardware padding works
	 * beyond this point
	 */
	if (skb_put_padto(skb, IECM_TX_MIN_LEN))
		return NETDEV_TX_OK;

	return iecm_tx_singleq_frame(skb, tx_q);
}

/**
 * iecm_adq_chnl_queue_stats - Update ADQ statistics
 * @queue: Tx/Rx queue structure
 * @pkts: Number of data packets
 *
 */
static void iecm_adq_chnl_queue_stats(struct iecm_queue *queue, u64 pkts)
{
	struct iecm_ch_q_poll_stats *poll = &queue->ch_q_stats.poll;

	u64_stats_update_begin(&queue->stats_sync);
	/* separate accounting of packets (either from busy_poll or
	 * napi_poll depending upon state of vector specific
	 * flag 'in_bp', 'prev_in_bp'
	 */
	if (test_bit(__IECM_VEC_STATE_IN_BP, queue->q_vector->flags)) {
		poll->pkt_busy_poll += pkts;
	} else {
		if (test_bit(__IECM_VEC_STATE_PREV_IN_BP,
			     queue->q_vector->flags))
			poll->pkt_busy_poll += pkts;
		else
			poll->pkt_not_busy_poll += pkts;
	}
	u64_stats_update_end(&queue->stats_sync);
}

/**
 * iecm_tx_singleq_clean - Reclaim resources from queue
 * @tx_q: Tx queue to clean
 * @napi_budget: Used to determine if we are in netpoll
 *
 */
static bool iecm_tx_singleq_clean(struct iecm_queue *tx_q, int napi_budget)
{
	unsigned int budget = tx_q->vport->compln_clean_budget;
	unsigned int total_bytes = 0, total_pkts = 0;
	struct iecm_base_tx_desc *tx_desc;
	s16 ntc = tx_q->next_to_clean;
	struct iecm_tx_buf *tx_buf;
	struct netdev_queue *nq;

	tx_desc = IECM_BASE_TX_DESC(tx_q, ntc);
	tx_buf = &tx_q->tx_buf[ntc];
	ntc -= tx_q->desc_count;

	do {
		struct iecm_base_tx_desc *eop_desc =
			(struct iecm_base_tx_desc *)tx_buf->next_to_watch;

		/* if next_to_watch is not set then no work pending */
		if (!eop_desc)
			break;

		/* prevent any other reads prior to eop_desc */
		smp_rmb();

		/* if the descriptor isn't done, no work yet to do */
		if (!(eop_desc->qw1 &
		      cpu_to_le64(IECM_TX_DESC_DTYPE_DESC_DONE)))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buf->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buf->bytecount;
		total_pkts += tx_buf->gso_segs;

#ifdef HAVE_XDP_SUPPORT
		if (test_bit(__IECM_Q_XDP, tx_q->flags))
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
				tx_desc = IECM_BASE_TX_DESC(tx_q, 0);
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

		tx_buf++;
		tx_desc++;
		ntc++;
		if (unlikely(!ntc)) {
			ntc -= tx_q->desc_count;
			tx_buf = tx_q->tx_buf;
			tx_desc = IECM_BASE_TX_DESC(tx_q, 0);
		}
		/* update budget */
		budget--;
	} while (likely(budget));

	ntc += tx_q->desc_count;
	tx_q->next_to_clean = ntc;

	u64_stats_update_begin(&tx_q->stats_sync);
	tx_q->q_stats.tx.packets += total_pkts;
	tx_q->q_stats.tx.bytes += total_bytes;
	u64_stats_update_end(&tx_q->stats_sync);
	iecm_adq_chnl_queue_stats(tx_q, total_pkts);
#ifdef HAVE_XDP_SUPPORT
	if (test_bit(__IECM_Q_XDP, tx_q->flags))
		return !!budget;
#endif /* HAVE_XDP_SUPPORT */

	nq = netdev_get_tx_queue(tx_q->vport->netdev, tx_q->idx);
	netdev_tx_completed_queue(nq, total_pkts, total_bytes);

	if (unlikely(total_pkts && netif_carrier_ok(tx_q->vport->netdev) &&
		     (IECM_DESC_UNUSED(tx_q) >= IECM_TX_WAKE_THRESH))) {
		/* Make sure any other threads stopping queue after this see
		 * new next_to_clean.
		 */
		smp_mb();
		if (__netif_subqueue_stopped(tx_q->vport->netdev, tx_q->idx) &&
		    tx_q->vport->adapter->state == __IECM_UP)
			netif_wake_subqueue(tx_q->vport->netdev, tx_q->idx);
	}

	return !!budget;
}

/**
 * iecm_tx_singleq_clean_all - Clean all Tx queues
 * @q_vec: queue vector
 * @budget: Used to determine if we are in netpoll
 *
 * Returns false if clean is not complete else returns true
 */
static bool
iecm_tx_singleq_clean_all(struct iecm_q_vector *q_vec, int budget)
{
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	bool is_xdp_prog_ena = iecm_xdp_is_prog_ena(q_vec->vport);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	bool clean_complete = true;
	struct iecm_queue *q;
	int i, budget_per_q;

	budget_per_q = max(budget / q_vec->num_txq, 1);
	for (i = 0; i < q_vec->num_txq; i++) {
		q = q_vec->tx[i];
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		if (is_xdp_prog_ena && q->xsk_pool)
			clean_complete = iecm_tx_singleq_clean_zc(q);
		else
			clean_complete = iecm_tx_singleq_clean(q, budget_per_q);
#else
		clean_complete = iecm_tx_singleq_clean(q, budget_per_q);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	}

	return clean_complete;
}

/**
 * iecm_is_ctrl_pkt - check if packet is a TCP control packet or data packet
 * @skb: receive buffer
 * @rx_q: Rx queue structure
 *
 * Returns true for all unsupported protocol/configuration. Supported protocol
 * is TCP/IPv4[6].  For TCP/IPv6, this function returns true if packet contains
 * nested header.
 * Logic to determine control packet:
 * - packet is control packet if it contains flags like SYN, SYN+ACK, FIN, RST
 *
 * Returns true if packet is classified as control packet and for all unhandled
 * condition otherwise false if packet is classified as data packet
 */
static bool iecm_is_ctrl_pkt(struct sk_buff *skb, struct iecm_queue *rx_q)
{
	union {
		unsigned char *network;
		struct ipv6hdr *ipv6;
		struct iphdr *ipv4;
	} hdr;
	struct tcphdr *th;

	/* at this point, skb->data points to network header since
	 * ethernet_header was pulled inline due to eth_type_trans
	 */
	hdr.network = skb->data;

	/* only support IPv4/IPv6, all other protocol being treated like
	 * control packets
	 */
	if (skb->protocol == htons(ETH_P_IP)) {
		unsigned int hlen;

		/* access ihl as u8 to avoid unaligned access on ia64 */
		hlen = (hdr.network[0] & 0x0F) << 2;
		/* for now, assume all non TCP packets are ctrl packets, so that
		 * they don't get counted to evaluate the likelihood of being
		 * called back for polling
		 */
		if (hdr.ipv4->protocol != IPPROTO_TCP)
			return true;

		th = (struct tcphdr *)(hdr.network + hlen);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		/* for now, if next_hdr is not TCP, means it contains nested
		 * header. IPv6 packets which contains nested header:
		 * treat them like control packet, so that interrupts gets
		 * enabled normally, otherwise driver need to duplicate the
		 * code to parse nested IPv6 header.
		 */
		if (hdr.ipv6->nexthdr != IPPROTO_TCP)
			return true;

		th = (struct tcphdr *)(hdr.network + sizeof(struct ipv6hdr));
	} else {
		return true; /* if any other than IPv4[6], ctrl packet */
	}

	/* definition of control packet is, if packet is TCP/IPv4[6] and
	 * TCP flags are either SYN | FIN | RST.
	 * If neither of those flags (SYN|FIN|RST) are set, then it is
	 * data packet
	 */
	if (!th->fin && !th->rst && !th->syn)
		return false; /* data packet */
	u64_stats_update_begin(&rx_q->stats_sync);
	rx_q->ch_q_stats.rx.tcp_ctrl_pkts++;
	if (th->fin)
		rx_q->ch_q_stats.rx.tcp_fin_recv++;
	else if (th->rst)
		rx_q->ch_q_stats.rx.tcp_rst_recv++;
	else if (th->syn)
		rx_q->ch_q_stats.rx.tcp_syn_recv++;
	u64_stats_update_end(&rx_q->stats_sync);
	/* at this point based on L4 header (if it is TCP/IPv4[6]:flags,
	 * packet is detected as control packets
	 */
	return true;
}

/**
 * iecm_adq_chnl_rx_stats - Update Rx ADQ statistics
 * @rx_q: Rx queue structure
 * @pkts: Total number of packets cleaned
 *
 */
static void iecm_adq_chnl_rx_stats(struct iecm_queue *rx_q, u64 pkts)
{
	iecm_adq_chnl_queue_stats(rx_q, pkts);

	/* if vector is transitioning from BP->INT (due to busy_poll_stop()) and
	 * we find no packets, in that case: to avoid entering into INTR mode
	 * (which happens from napi_poll - enabling interrupt if
	 * unlikely_comeback_to_bp getting set), make "prev_data_pkt_recv" to be
	 * non-zero, so that interrupts won't be enabled. This is to address the
	 * issue where num_force_wb on some queues is 2 to 3 times higher than
	 * other queues and those queues also sees lot of interrupts
	 */
	if (iecm_is_vec_ch_ena(rx_q->q_vector) &&
	    iecm_is_vec_ch_perf_ena(rx_q->q_vector) &&
	    iecm_is_vec_busypoll_to_intr(rx_q->q_vector)) {
		if (!pkts)
			set_bit(__IECM_VEC_STATE_PREV_DATA_PKT_RECV,
				rx_q->q_vector->flags);
	} else if (iecm_is_vec_ch_ena(rx_q->q_vector)) {
		struct iecm_q_vector *q_vector = rx_q->q_vector;

		u64_stats_update_begin(&rx_q->stats_sync);
		if (pkts && !test_bit(__IECM_VEC_STATE_PREV_DATA_PKT_RECV,
				      q_vector->flags))
			rx_q->ch_q_stats.rx.only_ctrl_pkts++;
		if (test_bit(__IECM_VEC_STATE_IN_BP, q_vector->flags) &&
		    !test_bit(__IECM_VEC_STATE_PREV_DATA_PKT_RECV,
			      q_vector->flags))
			rx_q->ch_q_stats.rx.bp_no_data_pkt++;
		u64_stats_update_end(&rx_q->stats_sync);
	}
}

/**
 * iecm_rx_singleq_test_staterr - tests bits in Rx descriptor
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
iecm_rx_singleq_test_staterr(union virtchnl2_rx_desc *rx_desc,
			     const u64 stat_err_bits)
{
	return !!(rx_desc->base_wb.qword1.status_error_ptype_len &
		  cpu_to_le64(stat_err_bits));
}

/**
 * iecm_rx_singleq_is_non_eop - process handling of non-EOP buffers
 * @rxq: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 * @skb: Current socket buffer containing buffer in progress
 */
bool iecm_rx_singleq_is_non_eop(struct iecm_queue *rxq,
				union virtchnl2_rx_desc *rx_desc,
				struct sk_buff *skb)
{
	/* if we are the last buffer then there is nothing else to do */
#define IECM_RXD_EOF BIT(VIRTCHNL2_RX_BASE_DESC_STATUS_EOF_S)
	if (likely(iecm_rx_singleq_test_staterr(rx_desc, IECM_RXD_EOF)))
		return false;

	/* place skb in next buffer to be received */
	rxq->rx_buf.buf[rxq->next_to_clean].skb = skb;

	return true;
}

/**
 * iecm_rx_singleq_csum - Indicate in skb if checksum is good
 * @rxq: Rx descriptor ring packet is being transacted on
 * @skb: skb currently being received and modified
 * @rx_desc: the receive descriptor
 * @ptype: the packet type decoded by hardware
 *
 * skb->protocol must be set before this function is called
 */
static void iecm_rx_singleq_csum(struct iecm_queue *rxq, struct sk_buff *skb,
				 struct iecm_rx_csum_decoded *csum_bits,
				 u16 ptype)
{
	struct iecm_rx_ptype_decoded decoded;
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

	ipv4 = (decoded.outer_ip == IECM_RX_PTYPE_OUTER_IP) &&
	       (decoded.outer_ip_ver == IECM_RX_PTYPE_OUTER_IPV4);
	ipv6 = (decoded.outer_ip == IECM_RX_PTYPE_OUTER_IP) &&
	       (decoded.outer_ip_ver == IECM_RX_PTYPE_OUTER_IPV6);

#ifdef IECM_ADD_PROBES
	iecm_rx_extra_counters(rxq, decoded.inner_prot, ipv4, csum_bits, false);

#endif /* IECM_ADD_PROBES */
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
	if (decoded.tunnel_type >= IECM_RX_PTYPE_TUNNEL_IP_GRENAT)
#ifdef HAVE_SKBUFF_CSUM_LEVEL
		skb->csum_level = 1;
#else
		skb->encapsulation = 1;
#endif

	/* Only report checksum unnecessary for ICMP, TCP, UDP, or SCTP */
	switch (decoded.inner_prot) {
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
 * iecm_rx_singleq_base_csum - Indicate in skb if hw indicated a good cksum
 * @rx_q: Rx completion queue
 * @skb: skb currently being received and modified
 * @rx_desc: the receive descriptor
 * @ptype: Rx packet type
 *
 * This function only operates on the VIRTCHNL2_RXDID_1_32B_BASE_M legacy 32byte
 * descriptor writeback format.
 **/
static void
iecm_rx_singleq_base_csum(struct iecm_queue *rx_q, struct sk_buff *skb,
			  union virtchnl2_rx_desc *rx_desc, u16 ptype)
{
	struct iecm_rx_csum_decoded csum_bits;
	u32 rx_error, rx_status;
	u64 qword;

	qword = le64_to_cpu(rx_desc->base_wb.qword1.status_error_ptype_len);

	rx_status = ((qword & VIRTCHNL2_RX_BASE_DESC_QW1_STATUS_M) >>
					VIRTCHNL2_RX_BASE_DESC_QW1_STATUS_S);
	rx_error = ((qword & VIRTCHNL2_RX_BASE_DESC_QW1_ERROR_M) >>
					VIRTCHNL2_RX_BASE_DESC_QW1_ERROR_S);

	csum_bits.ipe = !!(rx_error & BIT(VIRTCHNL2_RX_BASE_DESC_ERROR_IPE_S));
	csum_bits.eipe = !!(rx_error & BIT(VIRTCHNL2_RX_BASE_DESC_ERROR_EIPE_S));
	csum_bits.l4e = !!(rx_error & BIT(VIRTCHNL2_RX_BASE_DESC_ERROR_L4E_S));
	csum_bits.pprs = !!(rx_error & BIT(VIRTCHNL2_RX_BASE_DESC_ERROR_PPRS_S));
	csum_bits.l3l4p = !!(rx_status &
			     BIT(VIRTCHNL2_RX_BASE_DESC_STATUS_L3L4P_S));
	csum_bits.ipv6exadd = !!(rx_status &
				 BIT(VIRTCHNL2_RX_BASE_DESC_STATUS_IPV6EXADD_S));
	csum_bits.nat = 0;
	csum_bits.eudpe = 0;

	iecm_rx_singleq_csum(rx_q, skb, &csum_bits, ptype);
}

/**
 * iecm_rx_singleq_flex_csum - Indicate in skb if hw indicated a good cksum
 * @rx_q: Rx completion queue
 * @skb: skb currently being received and modified
 * @rx_desc: the receive descriptor
 * @ptype: Rx packet type
 *
 * This function only operates on the VIRTCHNL2_RXDID_2_FLEX_SQ_NIC flexible
 * descriptor writeback format.
 **/
static void
iecm_rx_singleq_flex_csum(struct iecm_queue *rx_q, struct sk_buff *skb,
			  union virtchnl2_rx_desc *rx_desc, u16 ptype)
{
	struct iecm_rx_csum_decoded csum_bits;
	u16 rx_status0, rx_status1;

	rx_status0 = le16_to_cpu(rx_desc->flex_nic_wb.status_error0);
	rx_status1 = le16_to_cpu(rx_desc->flex_nic_wb.status_error1);

	csum_bits.ipe = !!(rx_status0 &
			   BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_XSUM_IPE_S));
	csum_bits.eipe = !!(rx_status0 &
			    BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_XSUM_EIPE_S));
	csum_bits.l4e = !!(rx_status0 &
			   BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_XSUM_L4E_S));
	csum_bits.eudpe = !!(rx_status0 &
			     BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_XSUM_EUDPE_S));
	csum_bits.l3l4p = !!(rx_status0 &
			     BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_L3L4P_S));
	csum_bits.ipv6exadd =
			!!(rx_status0 &
			   BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_IPV6EXADD_S));
	csum_bits.nat = !!(rx_status1 &
			   BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS1_NAT_S));
	csum_bits.pprs = 0;

	iecm_rx_singleq_csum(rx_q, skb, &csum_bits, ptype);
}

/**
 * iecm_rx_singleq_base_hash - set the hash value in the skb
 * @rx_q: Rx completion queue
 * @skb: skb currently being received and modified
 * @rx_desc: specific descriptor
 * @decoded: Decoded Rx packet type related fields
 *
 * This function only operates on the VIRTCHNL2_RXDID_1_32B_BASE_M legacy 32byte
 * descriptor writeback format.
 **/
static void
iecm_rx_singleq_base_hash(struct iecm_queue *rx_q, struct sk_buff *skb,
			  union virtchnl2_rx_desc *rx_desc,
			  struct iecm_rx_ptype_decoded *decoded)
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
		skb_set_hash(skb, hash, iecm_ptype_to_htype(decoded));
	}
#endif /* NETIF_F_RXHASH */
}

/**
 * iecm_rx_singleq_flex_hash - set the hash value in the skb
 * @rx_q: Rx completion queue
 * @skb: skb currently being received and modified
 * @rx_desc: specific descriptor
 * @decoded: Decoded Rx packet type related fields
 *
 * This function only operates on the VIRTCHNL2_RXDID_2_FLEX_SQ_NIC flexible
 * descriptor writeback format.
 **/
static void
iecm_rx_singleq_flex_hash(struct iecm_queue *rx_q, struct sk_buff *skb,
			  union virtchnl2_rx_desc *rx_desc,
			  struct iecm_rx_ptype_decoded *decoded)
{
#ifdef NETIF_F_RXHASH
	__le16 status0;

	if (!(rx_q->vport->netdev->features & NETIF_F_RXHASH))
		return;

	status0 = rx_desc->flex_nic_wb.status_error0;
	if (status0 &
		cpu_to_le16(BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_RSS_VALID_S))) {
		u32 hash = le32_to_cpu(rx_desc->flex_nic_wb.rss_hash);

		skb_set_hash(skb, hash, iecm_ptype_to_htype(decoded));
	}
#endif /* NETIF_F_RXHASH */
}

/**
 * iecm_rx_singleq_process_skb_fields - Populate skb header fields from Rx
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
iecm_rx_singleq_process_skb_fields(struct iecm_queue *rx_q, struct sk_buff *skb,
				   union virtchnl2_rx_desc *rx_desc,
				   u16 ptype)
{
	struct iecm_rx_ptype_decoded decoded =
					rx_q->vport->rx_ptype_lkup[ptype];

	/* modifies the skb - consumes the enet header */
	skb->protocol = eth_type_trans(skb, rx_q->vport->netdev);

	if (rx_q->rxdids == VIRTCHNL2_RXDID_1_32B_BASE_M) {
		iecm_rx_singleq_base_hash(rx_q, skb, rx_desc, &decoded);
		iecm_rx_singleq_base_csum(rx_q, skb, rx_desc, ptype);
	} else {
		iecm_rx_singleq_flex_hash(rx_q, skb, rx_desc, &decoded);
		iecm_rx_singleq_flex_csum(rx_q, skb, rx_desc, ptype);
	}
}

/**
 * iecm_rx_singleq_buf_hw_alloc_all - Replace used receive buffers
 * @rx_q: queue for which the hw buffers are allocated
 * @cleaned_count: number of buffers to replace
 *
 * Returns false if all allocations were successful, true if any fail
 */
bool iecm_rx_singleq_buf_hw_alloc_all(struct iecm_queue *rx_q,
				      u16 cleaned_count)
{
	struct virtchnl2_singleq_rx_buf_desc *singleq_rx_desc = NULL;
	struct iecm_page_info *page_info;
	u16 nta = rx_q->next_to_alloc;
	struct iecm_rx_buf *buf;

	/* do nothing if no valid netdev defined */
	if (!rx_q->vport->netdev || !cleaned_count)
		return false;

	singleq_rx_desc = IECM_SINGLEQ_RX_BUF_DESC(rx_q, nta);
	buf = &rx_q->rx_buf.buf[nta];
	page_info = &buf->page_info[buf->page_indx];

	do {
		if (unlikely(!page_info->page)) {
			if (!iecm_init_rx_buf_hw_alloc(rx_q, buf))
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
			singleq_rx_desc = IECM_SINGLEQ_RX_BUF_DESC(rx_q, 0);
			buf = rx_q->rx_buf.buf;
			nta = 0;
		}

		page_info = &buf->page_info[buf->page_indx];

		cleaned_count--;
	} while (cleaned_count);

	if (rx_q->next_to_alloc != nta) {
		iecm_rx_buf_hw_update(rx_q, nta);
		rx_q->next_to_alloc = nta;
	}

	return !!cleaned_count;
}

/**
 * iecm_rx_reuse_page - Put recycled buffer back onto ring
 * @rxq: Rx descriptor ring to store buffers on
 * @old_buf: donor buffer to have page reused
 */
static void iecm_rx_reuse_page(struct iecm_queue *rxq,
			       struct iecm_rx_buf *old_buf)
{
	u16 ntu = rxq->next_to_use;
	struct iecm_rx_buf *new_buf;

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
 * iecm_singleq_rx_recycle_buf - Clean up used buffer and either recycle or free
 * @rx_bufq: Rx descriptor queue to transact packets on
 * @rx_buf: Rx buffer to pull data from
 *
 * This function will clean up the contents of the rx_buf. It will either
 * recycle the buffer or unmap it and free the associated resources.
 *
 * Returns true if the buffer is reused, false if the buffer is freed.
 */
static bool iecm_singleq_rx_recycle_buf(struct iecm_queue *rxq,
					struct iecm_rx_buf *rx_buf)
{
	struct iecm_page_info *page_info =
			&rx_buf->page_info[rx_buf->page_indx];

	bool recycled = false;

	if (iecm_rx_can_reuse_page(rx_buf)) {
		/* hand second half of page back to the queue */
		iecm_rx_reuse_page(rxq, rx_buf);
		recycled = true;
	} else {
		/* we are not reusing the buffer so unmap it */
#ifndef HAVE_STRUCT_DMA_ATTRS
		dma_unmap_page_attrs(rxq->dev, page_info->dma, PAGE_SIZE,
				     DMA_FROM_DEVICE, IECM_RX_DMA_ATTR);
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
 * iecm_singleq_rx_put_buf - Wrapper function to clean and recycle buffers
 * @rx_bufq: Rx descriptor queue to transact packets on
 * @rx_buf: Rx buffer to pull data from
 *
 * This function will update the next_to_use/next_to_alloc if the current
 * buffer is recycled.
 */
static void iecm_rx_singleq_put_buf(struct iecm_queue *rx_bufq,
				    struct iecm_rx_buf *rx_buf)
{
	u16 ntu = rx_bufq->next_to_use;
	bool recycled = false;

	recycled = iecm_singleq_rx_recycle_buf(rx_bufq, rx_buf);

	/* update, and store next to alloc if the buffer was recycled */
	if (recycled) {
		ntu++;
		rx_bufq->next_to_use = (ntu < rx_bufq->desc_count) ? ntu : 0;
	}
}

/**
 * iecm_singleq_rx_bump_ntc - Bump and wrap q->next_to_clean value
 * @q: queue to bump
 */
void iecm_rx_singleq_bump_ntc(struct iecm_queue *q)
{
	u16 ntc = q->next_to_clean + 1;
	/* fetch, update, and store next to clean */
	if (ntc < q->desc_count)
		q->next_to_clean = ntc;
	else
		q->next_to_clean = 0;
}

/**
 * iecm_singleq_rx_get_buf_page - Fetch Rx buffer page and synchronize data
 * @dev: device struct
 * @rx_buf: Rx buf to fetch page for
 * @size: size of buffer to add to skb
 *
 * This function will pull an Rx buffer page from the ring and synchronize it
 * for use by the CPU.
 */
static struct sk_buff *
iecm_rx_singleq_get_buf_page(struct device *dev, struct iecm_rx_buf *rx_buf,
			     const unsigned int size)
{
	struct iecm_page_info *page_info;

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
 * iecm_rx_singleq_extract_base_fields - Extract fields from the Rx descriptor
 * @rx_q: Rx descriptor queue
 * @rx_desc: the descriptor to process
 * @fields: storage for extracted values
 *
 * Decode the Rx descriptor and extract relevant information including the
 * size, VLAN tag, and Rx packet type.
 *
 * This function only operates on the VIRTCHNL2_RXDID_1_32B_BASE_M legacy 32byte
 * descriptor writeback format.
 */
static inline void
iecm_rx_singleq_extract_base_fields(struct iecm_queue *rx_q,
				    union virtchnl2_rx_desc *rx_desc,
				    struct iecm_rx_extracted *fields)
{
	u64 qw2_status, qword;

	qword = le64_to_cpu(rx_desc->base_wb.qword1.status_error_ptype_len);
	qw2_status = le16_to_cpu(rx_desc->base_wb.qword2.ext_status);

	fields->size = (qword & VIRTCHNL2_RX_BASE_DESC_QW1_LEN_PBUF_M) >>
					VIRTCHNL2_RX_BASE_DESC_QW1_LEN_PBUF_S;
	fields->rx_ptype = (qword & VIRTCHNL2_RX_BASE_DESC_QW1_PTYPE_M) >>
					VIRTCHNL2_RX_BASE_DESC_QW1_PTYPE_S;

	if (qword & BIT(VIRTCHNL2_RX_BASE_DESC_STATUS_L2TAG1P_S) &&
	    test_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG1, rx_q->flags))
		fields->vlan_tag =
			le16_to_cpu(rx_desc->base_wb.qword0.lo_dword.l2tag1);
	if (qw2_status & BIT(VIRTCHNL2_RX_BASE_DESC_EXT_STATUS_L2TAG2P_S) &&
	    test_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG2, rx_q->flags))
		fields->vlan_tag =
			le16_to_cpu(rx_desc->base_wb.qword2.l2tag2_1);
}

/**
 * iecm_rx_singleq_extract_flex_fields - Extract fields from the Rx descriptor
 * @rx_q: Rx descriptor queue
 * @rx_desc: the descriptor to process
 * @fields: storage for extracted values
 *
 * Decode the Rx descriptor and extract relevant information including the
 * size, VLAN tag, and Rx packet type.
 *
 * This function only operates on the VIRTCHNL2_RXDID_2_FLEX_SQ_NIC flexible
 * descriptor writeback format.
 */
static inline void
iecm_rx_singleq_extract_flex_fields(struct iecm_queue *rx_q,
				    union virtchnl2_rx_desc *rx_desc,
				    struct iecm_rx_extracted *fields)
{
	__le16 status0, status1;

	fields->size = le16_to_cpu(rx_desc->flex_nic_wb.pkt_len) &
					VIRTCHNL2_RX_FLEX_DESC_PKT_LEN_M;
	fields->rx_ptype = le16_to_cpu(rx_desc->flex_nic_wb.ptype_flex_flags0) &
					VIRTCHNL2_RX_FLEX_DESC_PTYPE_M;

	status0 = rx_desc->flex_nic_wb.status_error0;
	if (status0 & cpu_to_le16(BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS0_L2TAG1P_S)) &&
	    test_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG1, rx_q->flags))
		fields->vlan_tag = le16_to_cpu(rx_desc->flex_nic_wb.l2tag1);

	status1 = rx_desc->flex_nic_wb.status_error1;
	if (status1 & cpu_to_le16(BIT(VIRTCHNL2_RX_FLEX_DESC_STATUS1_L2TAG2P_S)) &&
	    test_bit(__IECM_Q_VLAN_TAG_LOC_L2TAG2, rx_q->flags))
		fields->vlan_tag = le16_to_cpu(rx_desc->flex_nic_wb.l2tag2_2nd);
}

/**
 * iecm_rx_singleq_extract_fields - Extract fields from the Rx descriptor
 * @rx_q: Rx descriptor queue
 * @rx_desc: the descriptor to process
 * @fields: storage for extracted values
 *
 */
void
iecm_rx_singleq_extract_fields(struct iecm_queue *rx_q,
			       union virtchnl2_rx_desc *rx_desc,
			       struct iecm_rx_extracted *fields)
{
	if (rx_q->rxdids == VIRTCHNL2_RXDID_1_32B_BASE_M)
		iecm_rx_singleq_extract_base_fields(rx_q, rx_desc, fields);
	else
		iecm_rx_singleq_extract_flex_fields(rx_q, rx_desc, fields);
}

/**
 * iecm_rx_singleq_clean - Reclaim resources after receive completes
 * @rx_q: rx queue to clean
 * @budget: Total limit on number of packets to process
 *
 * Returns true if there's any budget left (e.g. the clean is finished)
 */
static int iecm_rx_singleq_clean(struct iecm_queue *rx_q, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_pkts = 0;
#ifdef HAVE_XDP_SUPPORT
	unsigned int xdp_res, xdp_xmit = 0;
	struct iecm_queue *xdpq = NULL;
#endif /* HAVE_XDP_SUPPORT */
	u16 cleaned_count = 0;
	bool failure = false;

#ifdef HAVE_XDP_SUPPORT
	if (iecm_xdp_is_prog_ena(rx_q->vport))
		xdpq = iecm_get_related_xdp_queue(rx_q);
#endif /* HAVE_XDP_SUPPORT */

	/* Process Rx packets bounded by budget */
	while (likely(total_rx_pkts < (unsigned int)budget)) {
		struct iecm_rx_extracted fields = {};
		union virtchnl2_rx_desc *rx_desc;
		struct sk_buff *skb = NULL;
		struct iecm_rx_buf *rx_buf;

		/* get the Rx desc from Rx queue based on 'next_to_clean' */
		rx_desc = IECM_RX_DESC(rx_q, rx_q->next_to_clean);

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
		if (!iecm_rx_singleq_test_staterr(rx_desc,
						  IECM_RXD_DD))
			break;
		iecm_rx_singleq_extract_fields(rx_q, rx_desc, &fields);

		if (!fields.size)
			break;

		rx_buf = &rx_q->rx_buf.buf[rx_q->next_to_clean];
		skb = iecm_rx_singleq_get_buf_page(rx_q->dev, rx_buf,
						   fields.size);

#ifdef HAVE_XDP_SUPPORT
		xdp_res = iecm_rx_xdp(rx_q, xdpq, rx_buf, fields.size);
		if (xdp_res) {
			if (xdp_res & (IECM_XDP_TX | IECM_XDP_REDIR)) {
				xdp_xmit |= xdp_res;
				iecm_rx_buf_adjust_pg(rx_buf, IECM_RX_BUF_2048);
			} else {
				int page_indx = rx_buf->page_indx;

				rx_buf->page_info[page_indx].pagecnt_bias++;
			}
			total_rx_bytes += fields.size;
			total_rx_pkts++;
			cleaned_count++;
			rx_buf->page_info[rx_buf->page_indx].pagecnt_bias++;
			iecm_rx_singleq_put_buf(rx_q, rx_buf);

			iecm_rx_singleq_bump_ntc(rx_q);
			continue;
		}
#endif /* HAVE_XDP_SUPPORT */

		if (skb)
			iecm_rx_add_frag(rx_buf, skb, fields.size);
		else
			skb = iecm_rx_construct_skb(rx_q, rx_buf, fields.size);

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			rx_buf->page_info[rx_buf->page_indx].pagecnt_bias++;
			break;
		}

		iecm_rx_singleq_put_buf(rx_q, rx_buf);
		iecm_rx_singleq_bump_ntc(rx_q);

		cleaned_count++;

		/* skip if it is non EOP desc */
		if (iecm_rx_singleq_is_non_eop(rx_q, rx_desc,
					       skb))
			continue;

#define IECM_RXD_ERR_S BIT(VIRTCHNL2_RX_BASE_DESC_QW1_ERROR_S)
		if (unlikely(iecm_rx_singleq_test_staterr(rx_desc,
							  IECM_RXD_ERR_S))) {
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
		iecm_rx_singleq_process_skb_fields(rx_q, skb,
						   rx_desc, fields.rx_ptype);

		if (iecm_is_vec_ch_ena(rx_q->q_vector) &&
		    iecm_is_vec_ch_perf_ena(rx_q->q_vector)) {
			if (!iecm_is_ctrl_pkt(skb, rx_q))
				set_bit(__IECM_VEC_STATE_PREV_DATA_PKT_RECV,
					rx_q->q_vector->flags);
		}

		/* send completed skb up the stack */
		iecm_rx_skb(rx_q, skb, fields.vlan_tag);

		/* update budget accounting */
		total_rx_pkts++;
	}
	if (cleaned_count)
		failure = iecm_rx_singleq_buf_hw_alloc_all(rx_q, cleaned_count);

#ifdef HAVE_XDP_SUPPORT
	iecm_finalize_xdp_rx(xdpq, xdp_xmit);
#endif /* HAVE_XDP_SUPPORT */

	u64_stats_update_begin(&rx_q->stats_sync);
	rx_q->q_stats.rx.packets += total_rx_pkts;
	rx_q->q_stats.rx.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_q->stats_sync);
	iecm_adq_chnl_rx_stats(rx_q, total_rx_pkts);

	/* guarantee a trip back through this routine if there was a failure */
	return failure ? budget : (int)total_rx_pkts;
}

/**
 * iecm_rx_singleq_clean_all - Clean all Rx queues
 * @q_vec: queue vector
 * @budget: Used to determine if we are in netpoll
 * @cleaned: returns number of packets cleaned
 *
 * Returns false if clean is not complete else returns true
 */
static bool
iecm_rx_singleq_clean_all(struct iecm_q_vector *q_vec, int budget,
			  int *cleaned)
{
	bool clean_complete = true;
	int pkts_cleaned_per_q;
	int budget_per_q, i;

	budget_per_q = max(budget / q_vec->num_rxq, 1);
	for (i = 0; i < q_vec->num_rxq; i++) {
		struct iecm_queue *rxq = q_vec->rx[i];
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		pkts_cleaned_per_q =  rxq->xsk_pool ? iecm_rx_singleq_clean_zc(rxq, budget_per_q) :
						      iecm_rx_singleq_clean(rxq, budget_per_q);
#else
		pkts_cleaned_per_q = iecm_rx_singleq_clean(rxq, budget_per_q);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

		/* if we clean as many as budgeted, we must not be done */
		if (pkts_cleaned_per_q >= budget_per_q)
			clean_complete = false;
		*cleaned += pkts_cleaned_per_q;
	}

	return clean_complete;
}

/**
 * iecm_adq_chnl_detect_recover - logic to revive ADQ enabled vectors
 * @vport: vport structure
 *
 * This function implements "jiffy" based logic to revive ADQ enabled
 * vectors by triggering software interrupt. It is invoked from
 * "service_task".
 **/
void iecm_adq_chnl_detect_recover(struct iecm_vport *vport)
{
	struct iecm_q_vector *q_vector = NULL;
	struct net_device *netdev;
	unsigned long end;
	unsigned int i;

	if (!vport)
		return;

	netdev = vport->netdev;
	if (!netdev)
		return;

	if (!netif_carrier_ok(netdev))
		return;

	for (i = 0; i < vport->num_q_vectors; i++) {
		struct iecm_queue *txq;
		int q;

		q_vector = &vport->q_vectors[i];
		if (!q_vector)
			continue;

		if (!iecm_is_vec_ch_ena(q_vector) ||
		    !iecm_is_vec_ch_perf_ena(q_vector))
			continue;

		for (q = 0; q < q_vector->num_txq; q++) {
			txq = q_vector->tx[q];
			if (!(txq && txq->desc_ring))
				continue;
		}

		end = q_vector->jiffy;
		if (!end)
			continue;

		/* trigger software interrupt (to revive queue processing) if
		 * vector is channel enabled and only if current jiffies is at
		 * least 1 sec (worth of jiffies, hence multiplying by HZ) more
		 * than old_jiffies
		 */
#define IECM_CH_JIFFY_DELTA_IN_SEC      (1 * HZ)
		end += IECM_CH_JIFFY_DELTA_IN_SEC;
		if (time_is_before_jiffies(end) &&
		    test_bit(__IECM_VEC_STATE_ONCE_IN_BP, q_vector->flags)) {
			iecm_inc_serv_task_sw_intr_counter(q_vector);
			iecm_adq_force_wb(q_vector);
		}
	}
}

/**
 * iecm_adq_set_wb_on_itr - trigger force write-back by setting WB_ON_ITR bit
 * @q_vector: pointer to vector
 *
 * This function is used to force write-backs by setting WB_ON_ITR bit
 * in DYN_CTLN register. WB_ON_ITR and INTENA are mutually exclusive bits.
 * Setting WB_ON_ITR bits means TX and RX descriptors are written back based
 * on ITR expiration irrespective of INTENA setting
 */
static inline void iecm_adq_set_wb_on_itr(struct iecm_q_vector *q_vector)
{
	q_vector->ch_stats.wb_on_itr_set++;
	wr32(&q_vector->vport->adapter->hw, q_vector->intr_reg.dyn_ctl,
	     q_vector->intr_reg.dyn_ctl_itridx_m |
	     q_vector->intr_reg.dyn_ctl_wb_on_itr_m);
}

/**
 * iecm_adq_refresh_bp_state - refresh state machine
 * @q_vector: q_vector structure
 *
 * Update ADQ state machine, and depending on whether this was called from
 * busy poll, enable interrupts and update ITR
 */
static void iecm_adq_refresh_bp_state(struct iecm_q_vector *q_vector)
{
	/* cache previous state of vector */
	if (test_bit(__IECM_VEC_STATE_IN_BP, q_vector->flags))
		set_bit(__IECM_VEC_STATE_PREV_IN_BP, q_vector->flags);
	else
		clear_bit(__IECM_VEC_STATE_PREV_IN_BP, q_vector->flags);

#ifdef HAVE_NAPI_STATE_IN_BUSY_POLL
	/* update current state of vector */
	if (test_bit(NAPI_STATE_IN_BUSY_POLL, &q_vector->napi.state))
		set_bit(__IECM_VEC_STATE_IN_BP, q_vector->flags);
	else
		clear_bit(__IECM_VEC_STATE_IN_BP, q_vector->flags);
#endif /* HAVE_STATE_IN_BUSY_POLL */

	if (test_bit(__IECM_VEC_STATE_IN_BP, q_vector->flags)) {
		q_vector->jiffy = jiffies;
		/* trigger force_wb by setting WB_ON_ITR only when
		 * - vector is transitioning from INTR->BUSY_POLL
		 * - once_in_bp is false, this is to prevent from doing it
		 * every time whenever vector state is changing from
		 * INTR->BUSY_POLL because that could be due to legit
		 * busy_poll stop
		 */
		if (!test_bit(__IECM_VEC_STATE_ONCE_IN_BP, q_vector->flags) &&
		    iecm_is_vec_intr_to_busypoll(q_vector))
			iecm_adq_set_wb_on_itr(q_vector);

		set_bit(__IECM_VEC_STATE_ONCE_IN_BP, q_vector->flags);
		q_vector->ch_stats.in_bp++;
		/* state transition : INTERRUPT --> BUSY_POLL */
		if (!test_bit(__IECM_VEC_STATE_PREV_IN_BP, q_vector->flags))
			q_vector->ch_stats.intr_to_bp++;
		else
			q_vector->ch_stats.bp_to_bp++;
	} else {
		q_vector->ch_stats.in_intr++;
		/* state transition : BUSY_POLL --> INTERRUPT */
		if (test_bit(__IECM_VEC_STATE_PREV_IN_BP, q_vector->flags))
			q_vector->ch_stats.bp_to_intr++;
		else
			q_vector->ch_stats.intr_to_intr++;
	}
}

/*
 * iecm_adq_handle_chnl_vector - handle channel enabled vector
 * @q_vector: ptr to q_vector
 * @unlikely_cb_bp: will comeback to busy_poll or not
 *
 * This function eithers triggers software interrupt (when unlikely_cb_bp is
 * true) or enable interrupt normally. unlikely_cb_bp gets determined based
 * on state machine and packet parsing logic.
 */
static void
iecm_adq_handle_chnl_vector(struct iecm_q_vector *q_vector, bool unlikely_cb_bp)
{
	struct iecm_vector_ch_stats *stats = &q_vector->ch_stats;

	/* caller of this function deteremines next occurrence/execution context
	 * of napi_poll (means next time whether napi_poll will be invoked from
	 * busy_poll or SOFT IRQ context). Please refer to the caller of this
	 * function to see logic for "unlikely_cb_bp" (aka, re-occurrence to
	 * busy_poll or not).
	 * If logic determines that, next occurrence of napi_poll will not be
	 * from busy_poll context, trigger software initiated interrupt on
	 * channel enabled vector to revive queue(s) processing, otherwise if
	 * in true interrupt state - just enable interrupt.
	 */
	if (unlikely_cb_bp) {
		stats->unlikely_cb_to_bp++;
		/* if once_in_bp is set and pkt inspection based optimization
		 * is off, do not trigger SW interrupt (simply bailout).
		 * No change in logic from service_task based software
		 * triggred interrupt - to revive the queue based on jiffy logic
		 */
		if (test_bit(__IECM_VEC_STATE_ONCE_IN_BP, q_vector->flags)) {
			stats->ucb_once_in_bp_true++;
			if (!iecm_is_vec_pkt_inspect_opt_ena(q_vector)) {
				stats->no_sw_intr_opt_off++;
				return;
			}
		}

		/* Since this real BP -> INT transition, reset jiffy snapshot */
		q_vector->jiffy = 0;

		/* Likewise for real BP -> INT, trigger SW interrupt, so that
		 * vector is put back in same state, trigger sw interrupt to
		 * revive the queue
		 */
		iecm_inc_napi_sw_intr_counter(q_vector);
		iecm_adq_force_wb(q_vector);
	} else if (!test_bit(__IECM_VEC_STATE_ONCE_IN_BP, q_vector->flags)) {
		stats->intr_once_bp_false++;
		iecm_vport_intr_update_itr_ena_irq(q_vector);
	}
}

/**
 * iecm_adq_enable_wb_on_itr - Enable hardware to do a wb on ITR,
 * interrupts are not enabled
 * @q_vector: the vector on which to enable writeback
 *
 **/
static void iecm_adq_enable_wb_on_itr(struct iecm_q_vector *q_vector)
{
	u32 val;

	if (!test_bit(__IECM_ADQ_TX_WB_ON_ITR, q_vector->tx[0]->flags))
		return;

	if (q_vector->wb_ena)
		return;

	val = q_vector->intr_reg.dyn_ctl_wb_on_itr_m |
		q_vector->intr_reg.dyn_ctl_itridx_m; /* set no itr */

	wr32(&q_vector->vport->adapter->hw, q_vector->intr_reg.dyn_ctl, val);
	q_vector->wb_ena = true;
}

/**
 * iecm_vport_singleq_adq_napi_poll - NAPI handler
 * @napi: struct from which you get q_vector
 * @budget: budget provided by stack
 */
static int iecm_vport_singleq_adq_napi_poll(struct napi_struct *napi, int budget)
{
	struct iecm_q_vector *q_vector =
				container_of(napi, struct iecm_q_vector, napi);
	bool cleaned_any_data_pkt = false;
	bool unlikely_cb_bp = false;
	bool ch_enabled = false;
	bool wb_on_itr_enabled;
	int work_done = 0, i;
	bool clean_complete;

	/* determine if WB_ON_ITR is enabled on not, if not - no need to
	 * apply any  performance optimization
	 */
	wb_on_itr_enabled = true;
	for (i = 0; i < q_vector->num_txq; i++) {
		if (!test_bit(__IECM_ADQ_TX_WB_ON_ITR,
			      q_vector->tx[i]->flags)) {
			wb_on_itr_enabled &= false;
			break;
		}
	}

	/* determine once if vector needs to be processed differently */
	ch_enabled = wb_on_itr_enabled &&
			iecm_is_vec_ch_ena(q_vector) &&
			iecm_is_vec_ch_perf_ena(q_vector);
	if (ch_enabled) {
		/* Refresh state machine */
		iecm_adq_refresh_bp_state(q_vector);

		/* check during previous run of napi_poll whether
		 * at least one data packets is processed or not.
		 * If yes, set the local flag 'cleaned_any_data_pkt'
		 * which is used later in this function to determine
		 * if interrupt should be enabled or deferred (this is
		 * applicable only in case when busy_poll stop is
		 * invoked, means previous state of vector is in
		 * busy_poll and current state is not
		 * (aka BUSY_POLL -> INTR))
		 */
		if (test_and_clear_bit(__IECM_VEC_STATE_PREV_DATA_PKT_RECV,
				       q_vector->flags)) {
			/* It is important to check and cache correct\
			 * information (cleaned any data packets or not)
			 * in local variable before napi_complete_done
			 * is finished. Once napi_complete_done is
			 * returned, napi_poll can get invoked again
			 * (means re-entrant) which can potentially
			 * results to incorrect decision making
			 * w.r.t. whether interrupt should be enabled or
			 * deferred)
			 */
			if (iecm_is_vec_busypoll_to_intr(q_vector)) {
				cleaned_any_data_pkt = true;
				q_vector->ch_stats.cleaned_any_data_pkt++;
			}
		}
	}

	clean_complete = iecm_tx_singleq_clean_all(q_vector, budget);

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (budget <= 0)
		return budget;

	/* state transitioning from BUSY_POLL --> INTERRUPT. This can
	 * happen due to several reason when stack calls busy_poll_stop
	 *    1. during last execution of napi_poll returned non-zero
	 * packets
	 *    2. busy_loop ended
	 *    3. need re-sched set
	 * driver keeps track of packets were cleaned during last run
	 * and if that is zero, means most likely napi_poll won't be
	 * invoked from busy_poll context; in that situation bypass
	 * processing of Rx queues and enable interrupt and let
	 * subsequent run of napi_poll from interrupt path handle
	 * cleanup of Rx queues
	 */
	if (ch_enabled && iecm_is_vec_busypoll_to_intr(q_vector))
		goto bypass;

	/* We attempt to distribute budget to each Rx queue fairly, but don't
	 * allow the budget to go below 1 because that would exit polling early.
	 */
	clean_complete |= iecm_rx_singleq_clean_all(q_vector, budget,
						    &work_done);

	/* if this vector ever was/is in BUSY_POLL, skip processing  */
	if (ch_enabled && iecm_is_vec_ever_in_busypoll(q_vector))
		goto bypass;
	/* If work not completed, return budget and polling will return */
	if (!clean_complete)
		return budget;

bypass:
	if (ch_enabled && iecm_is_vec_busypoll_to_intr(q_vector)) {
		struct iecm_vector_ch_stats *stats;

		stats = &q_vector->ch_stats;
		if (unlikely(need_resched())) {
			stats->bp_stop_need_resched++;
			if (!cleaned_any_data_pkt)
				stats->need_resched_no_data_pkt++;
		} else {
			/* Reaching here means because of 2 reason
			 * - busy_poll timeout expired
			 * - last time, cleaned data packets, hence
			 *  stack asked to stop busy_poll so that packet
			 *  can be processed by consumer
			 */
			stats->bp_stop_timeout++;
			if (!cleaned_any_data_pkt)
				stats->timeout_no_data_pkt++;
		}
	}
	/* if state transition from busy_poll to interrupt and during
	 * last run: did not cleanup TCP data packets -
	 *      then application unlikely to comeback to busy_poll
	 */
	if (ch_enabled && iecm_is_vec_busypoll_to_intr(q_vector) &&
	    !cleaned_any_data_pkt) {
		/* for now, if need_resched is true (it can be either
		 * due to voluntary/in-voluntary context switches),
		 * do not trigger SW interrupt. If need_resched is not
		 * set, safely assuming, it is due to possible timeout
		 * and unlikely that application/context will return
		 * to busy_poll, hence set 'unlikely_cb_bp' to
		 * true which will cause software triggered interrupt
		 * to revive the queue/vector
		 */
		if (unlikely(need_resched()))
			unlikely_cb_bp = false;
		else
			unlikely_cb_bp = true;
	}

	/* Work is done so exit the polling mode and re-enable the
	 * interrupt
	 */
	if (likely(napi_complete_done(napi, work_done))) {
		/* napi_ret : false (means vector is still in POLLING mode
		 *            true (means out of POLLING)
		 * NOTE: Generally if napi_ret is TRUE, enable device
		 * interrupt but there are condition/optimization,
		 * where it can be optimized. Basically, if
		 * napi_complete_done returns true but last time Rx
		 * packets were cleaned, then most likely, consumer
		 * thread will come back to do busy_polling where
		 * cleaning of Tx/Rx queue will happen normally. Hence
		 * no reason to enable the interrupt.
		 *
		 * If for some reason, consumer thread/context doesn't
		 * comeback to busy_poll:napi_poll, there is bail-out
		 * mechanism to kick start the state machine thru' SW
		 * triggered interrupt from service task.
		 */
		if (ch_enabled) {
			/* current state of NAPI is INTERRUPT */
			iecm_adq_handle_chnl_vector(q_vector,
						    unlikely_cb_bp);
		} else {
			iecm_vport_intr_update_itr_ena_irq(q_vector);
		}
	} else {
		/* if code makes it here, means busy_poll is still ON.
		 * if vector is channel enabled, setting WB_ON_ITR is
		 * handled from iecm_adq_refresh_bp_state function.
		 * otherwise set WB_ON_ITR (if supported)
		 */
		if (!ch_enabled) {
			if (wb_on_itr_enabled)
				iecm_adq_enable_wb_on_itr(q_vector);
			else
				iecm_vport_intr_update_itr_ena_irq(q_vector);
		}
	}

	return min_t(int, work_done, budget - 1);
}

/**
 * iecm_vport_singleq_napi_poll - NAPI handler
 * @napi: struct from which you get q_vector
 * @budget: budget provided by stack
 */
int iecm_vport_singleq_napi_poll(struct napi_struct *napi, int budget)
{
	struct iecm_q_vector *q_vector =
				container_of(napi, struct iecm_q_vector, napi);
	bool clean_complete;
	int work_done = 0;

	if (iecm_is_cap_ena(q_vector->vport->adapter, IECM_BASE_CAPS,
			    VIRTCHNL2_CAP_ADQ) ||
	    iecm_is_cap_ena(q_vector->vport->adapter, IECM_OTHER_CAPS,
			    VIRTCHNL2_CAP_ADQ))
		return iecm_vport_singleq_adq_napi_poll(napi, budget);

	clean_complete = iecm_tx_singleq_clean_all(q_vector, budget);

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (budget <= 0)
		return budget;

	/* We attempt to distribute budget to each Rx queue fairly, but don't
	 * allow the budget to go below 1 because that would exit polling early.
	 */
	clean_complete |= iecm_rx_singleq_clean_all(q_vector, budget,
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

#ifdef HAVE_XDP_SUPPORT
/**
 * iecm_prepare_xdp_tx_singleq_desc - Prepare TX descriptor for XDP in single queue mode
 * @xdpq: Pointer to XDP TX queue
 * @dma:  Address of DMA buffer used for XDP TX.
 * @idx:  Index of the TX buffer in the queue.
 * @size: Size of data to be transmitted.
 *
 * Returns a void pointer to iecm_base_tx_desc structure keeping a created descriptor.
 */
void *iecm_prepare_xdp_tx_singleq_desc(struct iecm_queue *xdpq, dma_addr_t dma,
				       u16 idx, u32 size)
{
	struct iecm_base_tx_desc *tx_desc;
	u64 td_cmd;

	tx_desc = IECM_BASE_TX_DESC(xdpq, idx);
	tx_desc->buf_addr = cpu_to_le64(dma);

	td_cmd = (u64)IECM_TXD_LAST_DESC_CMD;
	tx_desc->qw1 = iecm_tx_singleq_build_ctob(td_cmd, 0x0, size, 0);

	return (void *)tx_desc;
}
#endif /* HAVE_XDP_SUPPORT */
