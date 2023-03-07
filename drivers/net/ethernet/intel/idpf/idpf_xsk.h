/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2022 Intel Corporation */

#ifndef _IDPF_XSK_H_
#define _IDPF_XSK_H_
#include <net/xdp_sock_drv.h>
#include <net/xdp_sock.h>

int idpf_xsk_pool_setup(struct idpf_vport *vport, struct xsk_buff_pool *pool, u16 qid);
int idpf_rx_splitq_clean_zc(struct idpf_queue *rxq, int budget);
int idpf_rx_singleq_clean_zc(struct idpf_queue *rxq, int budget);
bool idpf_rx_splitq_buf_hw_alloc_zc_all(struct idpf_queue *rx_bufq, u16 count);
bool idpf_rx_singleq_buf_hw_alloc_zc_all(struct idpf_queue *rx_bufq, u16 count);
void idpf_rx_buf_rel_zc(struct idpf_rx_buf *buf);
struct idpf_tx_queue_stats idpf_tx_splitq_clean_zc(struct idpf_queue *xdpq, u16 compl_tag);
bool idpf_tx_singleq_clean_zc(struct idpf_queue *xdpq, int *cleaned);
bool idpf_tx_splitq_xmit_zc(struct idpf_queue *xdpq);
void idpf_xsk_cleanup_xdpq(struct idpf_queue *xdpq);
#ifdef HAVE_NDO_XSK_WAKEUP
int idpf_xsk_splitq_wakeup(struct net_device *netdev, u32 q_id, u32 __always_unused flags);
int idpf_xsk_singleq_wakeup(struct net_device *netdev, u32 q_id, u32 __always_unused flags);
#else
int idpf_xsk_splitq_async_xmit(struct net_device *netdev, u32 q_id);
int idpf_xsk_singleq_async_xmit(struct net_device *netdev, u32 q_id);
#endif /* HAVE_NDO_XSK_WAKEUP */
#endif /* !_IDPF_XSK_H_ */
