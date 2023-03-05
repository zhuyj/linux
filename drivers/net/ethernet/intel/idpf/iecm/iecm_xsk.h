/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2021 Intel Corporation */

#ifndef _IECM_XSK_H_
#define _IECM_XSK_H_
#ifdef HAVE_NETDEV_BPF_XSK_POOL
#include <net/xdp_sock_drv.h>
#include <net/xdp_sock.h>
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

struct iecm_queue;
struct iecm_vport;

#ifdef HAVE_NETDEV_BPF_XSK_POOL
int iecm_xsk_pool_setup(struct iecm_vport *vport, struct xsk_buff_pool *pool, u16 qid);
int iecm_rx_splitq_clean_zc(struct iecm_queue *rxq, int budget);
int iecm_rx_singleq_clean_zc(struct iecm_queue *rxq, int budget);
bool iecm_rx_splitq_buf_hw_alloc_zc_all(struct iecm_queue *rx_bufq, u16 count);
bool iecm_rx_singleq_buf_hw_alloc_zc_all(struct iecm_queue *rx_bufq, u16 count);
void iecm_rx_buf_rel_zc(struct iecm_rx_buf *buf);
struct iecm_tx_queue_stats iecm_tx_splitq_clean_zc(struct iecm_queue *xdpq, u16 end);
bool iecm_tx_singleq_clean_zc(struct iecm_queue *xdpq);
bool iecm_tx_splitq_xmit_zc(struct iecm_queue *xdpq);
void iecm_xsk_cleanup_xdpq(struct iecm_queue *xdpq);
#ifdef HAVE_NDO_XSK_WAKEUP
int iecm_xsk_splitq_wakeup(struct net_device *netdev, u32 q_id, u32 __always_unused flags);
int iecm_xsk_singleq_wakeup(struct net_device *netdev, u32 q_id, u32 __always_unused flags);
#else
int iecm_xsk_splitq_async_xmit(struct net_device *netdev, u32 q_id);
int iecm_xsk_singleq_async_xmit(struct net_device *netdev, u32 q_id);
#endif /* HAVE_NDO_XSK_WAKEUP */
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* !_IECM_XSK_H_ */
