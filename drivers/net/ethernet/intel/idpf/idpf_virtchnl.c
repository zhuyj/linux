// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Intel Corporation */

#include "idpf.h"

/**
 * idpf_recv_event_msg - Receive virtchnl event message
 * @vport: virtual port structure
 *
 * Receive virtchnl event message
 */
static void idpf_recv_event_msg(struct idpf_vport *vport)
{
	struct virtchnl2_event *v2e = NULL;
	bool link_status;
	u32 event;

	v2e = (struct virtchnl2_event *)vport->vc_msg;
	event = le32_to_cpu(v2e->event);

	switch (event) {
	case VIRTCHNL2_EVENT_LINK_CHANGE:
		vport->link_speed_mbps = le32_to_cpu(v2e->link_speed);
		link_status = v2e->link_status;

		if (vport->link_up != link_status) {
			vport->link_up = link_status;
			if (vport->state == __IDPF_VPORT_UP) {
				if (vport->link_up) {
					netif_tx_start_all_queues(vport->netdev);
					netif_carrier_on(vport->netdev);
				} else {
					netif_tx_stop_all_queues(vport->netdev);
					netif_carrier_off(vport->netdev);
				}
			}
		}
		break;
	default:
		dev_err(&vport->adapter->pdev->dev,
			"Unknown event %d from PF\n", event);
		break;
	}
	clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);
}

/**
 * idpf_mb_clean - Reclaim the send mailbox queue entries
 * @adapter: Driver specific private structure
 *
 * Reclaim the send mailbox queue entries to be used to send further messages
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_mb_clean(struct idpf_adapter *adapter)
{
	u16 i, num_q_msg = IDPF_DFLT_MBX_Q_LEN;
	struct idpf_ctlq_msg **q_msg;
	struct idpf_dma_mem *dma_mem;
	int err = 0;

	if (!adapter->hw.asq)
		return -EINVAL;

	q_msg = kcalloc(num_q_msg, sizeof(struct idpf_ctlq_msg *), GFP_ATOMIC);
	if (!q_msg)
		return -ENOMEM;

	err = idpf_ctlq_clean_sq(adapter->hw.asq, &num_q_msg, q_msg);
	if (err)
		goto error;

	for (i = 0; i < num_q_msg; i++) {
		if (!q_msg[i])
			continue;
		dma_mem = q_msg[i]->ctx.indirect.payload;
		if (dma_mem)
			dmam_free_coherent(&adapter->pdev->dev, dma_mem->size,
					   dma_mem->va, dma_mem->pa);
		kfree(q_msg[i]);
		kfree(dma_mem);
	}
error:
	kfree(q_msg);
	return err;
}

/**
 * idpf_send_mb_msg - Send message over mailbox
 * @adapter: Driver specific private structure
 * @op: virtchnl opcode
 * @msg_size: size of the payload
 * @msg: pointer to buffer holding the payload
 *
 * Will prepare the control queue message and initiates the send api
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_mb_msg(struct idpf_adapter *adapter, u32 op,
		     u16 msg_size, u8 *msg)
{
	struct idpf_ctlq_msg *ctlq_msg;
	struct idpf_dma_mem *dma_mem;
	int err = 0;

	/* If we are here and a reset is detected nothing much can be
	 * done. This thread should silently abort and expected to
	 * be corrected with a new run either by user or driver
	 * flows after reset
	 */
	if (idpf_is_reset_detected(adapter))
		return 0;

	err = idpf_mb_clean(adapter);
	if (err)
		return err;

	ctlq_msg = kzalloc(sizeof(*ctlq_msg), GFP_ATOMIC);
	if (!ctlq_msg)
		return -ENOMEM;

	dma_mem = kzalloc(sizeof(*dma_mem), GFP_ATOMIC);
	if (!dma_mem) {
		err = -ENOMEM;
		goto dma_mem_error;
	}

	memset(ctlq_msg, 0, sizeof(struct idpf_ctlq_msg));
	ctlq_msg->opcode = idpf_mbq_opc_send_msg_to_pf;
	ctlq_msg->func_id = 0;
	ctlq_msg->data_len = msg_size;
	ctlq_msg->cookie.mbx.chnl_opcode = op;
	ctlq_msg->cookie.mbx.chnl_retval = VIRTCHNL2_STATUS_SUCCESS;
	dma_mem->size = IDPF_DFLT_MBX_BUF_SIZE;
	dma_mem->va = dmam_alloc_coherent(&adapter->pdev->dev, dma_mem->size,
					  &dma_mem->pa, GFP_ATOMIC);
	if (!dma_mem->va) {
		err = -ENOMEM;
		goto dma_alloc_error;
	}
	memcpy(dma_mem->va, msg, msg_size);
	ctlq_msg->ctx.indirect.payload = dma_mem;

	err = idpf_ctlq_send(&adapter->hw, adapter->hw.asq, 1, ctlq_msg);
	if (err)
		goto send_error;

	return 0;
send_error:
	dmam_free_coherent(&adapter->pdev->dev, dma_mem->size, dma_mem->va,
			   dma_mem->pa);
dma_alloc_error:
	kfree(dma_mem);
dma_mem_error:
	kfree(ctlq_msg);
	return err;
}

/**
 * idpf_find_vport - Find vport pointer from control queue message
 * @adapter: driver specific private structure
 * @vport: address of vport pointer to copy the vport from adapters vport list
 * @ctlq_msg: control queue message
 *
 * This function does check for the opcodes which expect to receive payload and
 * return error value if it is not the case.
 * For virtchnl 2.0 opcodes, return 0 on success, error value on failure and
 * for other opcodes, return 0 always
 */
static int idpf_find_vport(struct idpf_adapter *adapter,
			   struct idpf_vport **vport,
			   struct idpf_ctlq_msg *ctlq_msg)
{
	bool no_op = false, vid_found = false;
	int i, err = 0, payload_size = 0;
	u16 num_max_vports;
	char *vc_msg;
	u32 v_id;

	vc_msg = kcalloc(IDPF_DFLT_MBX_BUF_SIZE, sizeof(char), GFP_KERNEL);
	if (!vc_msg)
		return -ENOMEM;

	if (ctlq_msg->data_len) {
		payload_size = ctlq_msg->ctx.indirect.payload->size;
		memcpy(vc_msg, ctlq_msg->ctx.indirect.payload->va,
		       min_t(int, payload_size, IDPF_DFLT_MBX_BUF_SIZE));
	}

	switch (ctlq_msg->cookie.mbx.chnl_opcode) {
	case VIRTCHNL2_OP_VERSION:
	case VIRTCHNL2_OP_GET_CAPS:
	case VIRTCHNL2_OP_CREATE_VPORT:
	case VIRTCHNL2_OP_SET_SRIOV_VFS:
	case VIRTCHNL2_OP_ALLOC_VECTORS:
	case VIRTCHNL2_OP_DEALLOC_VECTORS:
	case VIRTCHNL2_OP_GET_PTYPE_INFO:
		if (payload_size)
			goto free_vc_msg;
		else
			goto no_payload;
	case VIRTCHNL2_OP_RDMA:
	case VIRTCHNL2_OP_CONFIG_RDMA_IRQ_MAP:
	case VIRTCHNL2_OP_RELEASE_RDMA_IRQ_MAP:
		goto free_vc_msg;
	case VIRTCHNL2_OP_ENABLE_VPORT:
	case VIRTCHNL2_OP_DISABLE_VPORT:
	case VIRTCHNL2_OP_DESTROY_VPORT:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_vport *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_CONFIG_TX_QUEUES:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_config_tx_queues *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_CONFIG_RX_QUEUES:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_config_rx_queues *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_ENABLE_QUEUES:
	case VIRTCHNL2_OP_DISABLE_QUEUES:
	case VIRTCHNL2_OP_DEL_QUEUES:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_del_ena_dis_queues *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_ADD_QUEUES:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_add_queues *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_MAP_QUEUE_VECTOR:
	case VIRTCHNL2_OP_UNMAP_QUEUE_VECTOR:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_queue_vector_maps *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_GET_STATS:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_vport_stats *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_GET_RSS_HASH:
	case VIRTCHNL2_OP_SET_RSS_HASH:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_rss_hash *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_GET_RSS_LUT:
	case VIRTCHNL2_OP_SET_RSS_LUT:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_rss_lut *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_GET_RSS_KEY:
	case VIRTCHNL2_OP_SET_RSS_KEY:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_rss_key *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_EVENT:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_event *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_LOOPBACK:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_loopback *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_CONFIG_PROMISCUOUS_MODE:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_promisc_info *)vc_msg)->vport_id);
		break;
	case VIRTCHNL2_OP_ADD_MAC_ADDR:
	case VIRTCHNL2_OP_DEL_MAC_ADDR:
		if (!payload_size)
			goto no_payload;
		v_id = le32_to_cpu(((struct virtchnl2_mac_addr_list *)vc_msg)->vport_id);
		break;
	default:
		no_op = true;
		break;
	}

	if (no_op)
		goto free_vc_msg;

	num_max_vports = idpf_get_max_vports(adapter);
	for (i = 0; i < num_max_vports; i++) {
		if (adapter->vport_ids[i] == v_id) {
			vid_found = true;
			break;
		}
	}

	if (vid_found)
		*vport = adapter->vports[i];
	else
		err = -EINVAL;

	goto free_vc_msg;

no_payload:
	err = -EINVAL;
	dev_info(&adapter->pdev->dev, "Failed to receive payload buffer\n");
free_vc_msg:
	kfree(vc_msg);
	return err;
}

/**
 * idpf_set_msg_pending_bit - Wait for clear and set msg pending
 * @adapter: driver specific private structure
 * @vport: virtual port structure
 *
 * If clear sets msg pending bit, otherwise waits for it to clear before
 * setting it again. Returns 0 on success, negative on failure.
 */
static int idpf_set_msg_pending_bit(struct idpf_adapter *adapter,
				    struct idpf_vport *vport)
{
	unsigned int retries = 100;

	/* If msg pending bit already set, there's a message waiting to be
	 * parsed and we must wait for it to be cleared before copying a new
	 * message into the vc_msg buffer or else we'll stomp all over the
	 * previous message.
	 */
	while (retries) {
		if (vport) {
			if (!test_and_set_bit(__IDPF_VPORT_VC_MSG_PENDING,
					      vport->flags))
				break;
		} else {
			if (!test_and_set_bit(__IDPF_VC_MSG_PENDING,
					      adapter->flags))
				break;
		}
		msleep(20);
		retries--;
	}
	return retries ? 0 : -ETIMEDOUT;
}

/**
 * idpf_set_msg_pending - Wait for msg pending bit and copy msg to buf
 * @adapter: driver specific private structure
 * @vport: virtual port structure
 * @ctlq_msg: msg to copy from
 * @err_enum: err bit to set on error
 *
 * Copies payload from ctlq_msg into vc_msg buf in adapter and sets msg pending
 * bit. Returns 0 on success, negative on failure.
 */
int idpf_set_msg_pending(struct idpf_adapter *adapter,
			 struct idpf_vport *vport,
			 struct idpf_ctlq_msg *ctlq_msg,
			 enum idpf_vport_vc_state err_enum)
{
	if (ctlq_msg->cookie.mbx.chnl_retval) {
		if (vport)
			set_bit(err_enum, vport->vc_state);
		else
			set_bit(err_enum, adapter->vc_state);
		return -EINVAL;
	}

	if (idpf_set_msg_pending_bit(adapter, vport)) {
		if (vport)
			set_bit(err_enum, vport->vc_state);
		else
			set_bit(err_enum, adapter->vc_state);
		dev_info(&adapter->pdev->dev, "Timed out setting msg pending\n");
		return -ETIMEDOUT;
	}

	if (vport)
		memcpy(vport->vc_msg, ctlq_msg->ctx.indirect.payload->va,
		       min_t(int, ctlq_msg->ctx.indirect.payload->size,
			     IDPF_DFLT_MBX_BUF_SIZE));
	else
		memcpy(adapter->vc_msg, ctlq_msg->ctx.indirect.payload->va,
		       min_t(int, ctlq_msg->ctx.indirect.payload->size,
			     IDPF_DFLT_MBX_BUF_SIZE));
	return 0;
}

/**
 * idpf_recv_vchnl_op - helper function with common logic when handling the
 * reception of VIRTCHNL OPs.
 * @adapter: driver specific private structure
 * @vport: virtual port structure
 * @ctlq_msg: msg to copy from
 * @state: state bit used on timeout check
 * @err_state: err bit to set on error
 */
static void idpf_recv_vchnl_op(struct idpf_adapter *adapter,
			       struct idpf_vport *vport,
			       struct idpf_ctlq_msg *ctlq_msg,
			       enum idpf_vport_vc_state state,
			       enum idpf_vport_vc_state err_state)
{
	wait_queue_head_t *vchnl_wq;
	int err;

	if (vport)
		vchnl_wq = &vport->vchnl_wq;
	else
		vchnl_wq = &adapter->vchnl_wq;

	err = idpf_set_msg_pending(adapter, vport, ctlq_msg, err_state);
	if (wq_has_sleeper(vchnl_wq)) {
		/* sleeper is present and we got the pending bit */
		if (vport)
			set_bit(state, vport->vc_state);
		else
			set_bit(state, adapter->vc_state);

		wake_up(vchnl_wq);
	} else {
		if (!err) {
			/* We got the pending bit, but release it if we cannot
			 * find a thread waiting for the message.
			 */
			dev_warn(&adapter->pdev->dev, "opcode %d received without waiting thread\n",
				 ctlq_msg->cookie.mbx.chnl_opcode);
			if (vport)
				clear_bit(__IDPF_VPORT_VC_MSG_PENDING,
					  vport->flags);
			else
				clear_bit(__IDPF_VC_MSG_PENDING,
					  adapter->flags);
		} else {
			/* Clear the errors since there is no sleeper to pass them on */
			if (vport)
				clear_bit(err_state, vport->vc_state);
			else
				clear_bit(err_state, adapter->vc_state);
		}
	}
}

/**
 * idpf_recv_mb_msg - Receive message over mailbox
 * @adapter: Driver specific private structure
 * @op: virtchannel operation code
 * @msg: Received message holding buffer
 * @msg_size: message size
 *
 * Will receive control queue message and posts the receive buffer. Returns 0
 * on success and negative on failure.
 */
int idpf_recv_mb_msg(struct idpf_adapter *adapter, u32 op,
		     void *msg, int msg_size)
{
	struct idpf_vport *vport = NULL;
	struct idpf_ctlq_msg ctlq_msg;
	struct idpf_dma_mem *dma_mem;
	bool work_done = false;
	int num_retry = 2000;
	u16 num_q_msg;
	int err = 0;

	while (1) {
		int payload_size = 0;

		/* Try to get one message */
		num_q_msg = 1;
		dma_mem = NULL;
		err = idpf_ctlq_recv(adapter->hw.arq, &num_q_msg, &ctlq_msg);
		/* If no message then decide if we have to retry based on
		 * opcode
		 */
		if (err || !num_q_msg) {
			/* Increasing num_retry to consider the delayed
			 * responses because of large number of VF's mailbox
			 * messages. If the mailbox message is received from
			 * the other side, we come out of the sleep cycle
			 * immediately else we wait for more time.
			 */
			if (!op || !num_retry--)
				break;
			if (test_bit(__IDPF_REL_RES_IN_PROG, adapter->flags)) {
				err = -EIO;
				break;
			}
			msleep(20);
			continue;
		}

		/* If we are here a message is received. Check if we are looking
		 * for a specific message based on opcode. If it is different
		 * ignore and post buffers
		 */
		if (op && ctlq_msg.cookie.mbx.chnl_opcode != op)
			goto post_buffs;

		err = idpf_find_vport(adapter, &vport, &ctlq_msg);
		if (err)
			goto post_buffs;

		if (ctlq_msg.data_len)
			payload_size = ctlq_msg.ctx.indirect.payload->size;

		/* All conditions are met. Either a message requested is
		 * received or we received a message to be processed
		 */
		switch (ctlq_msg.cookie.mbx.chnl_opcode) {
		case VIRTCHNL2_OP_VERSION:
		case VIRTCHNL2_OP_GET_CAPS:
			if (ctlq_msg.cookie.mbx.chnl_retval) {
				dev_info(&adapter->pdev->dev, "Failure initializing, vc op: %u retval: %u\n",
					 ctlq_msg.cookie.mbx.chnl_opcode,
					 ctlq_msg.cookie.mbx.chnl_retval);
				err = -EBADMSG;
			} else if (msg) {
				memcpy(msg, ctlq_msg.ctx.indirect.payload->va,
				       min_t(int,
					     payload_size, msg_size));
			}
			work_done = true;
			break;
		case VIRTCHNL2_OP_CREATE_VPORT:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_CREATE_VPORT,
					   IDPF_VC_CREATE_VPORT_ERR);
			break;
		case VIRTCHNL2_OP_ENABLE_VPORT:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_ENA_VPORT,
					   IDPF_VC_ENA_VPORT_ERR);
			break;
		case VIRTCHNL2_OP_DISABLE_VPORT:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_DIS_VPORT,
					   IDPF_VC_DIS_VPORT_ERR);
			break;
		case VIRTCHNL2_OP_DESTROY_VPORT:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_DESTROY_VPORT,
					   IDPF_VC_DESTROY_VPORT_ERR);
			break;
		case VIRTCHNL2_OP_CONFIG_TX_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_CONFIG_TXQ,
					   IDPF_VC_CONFIG_TXQ_ERR);
			break;
		case VIRTCHNL2_OP_CONFIG_RX_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_CONFIG_RXQ,
					   IDPF_VC_CONFIG_RXQ_ERR);
			break;
		case VIRTCHNL2_OP_ENABLE_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_ENA_QUEUES,
					   IDPF_VC_ENA_QUEUES_ERR);
			break;
		case VIRTCHNL2_OP_DISABLE_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_DIS_QUEUES,
					   IDPF_VC_DIS_QUEUES_ERR);
			break;
		case VIRTCHNL2_OP_ADD_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_ADD_QUEUES,
					   IDPF_VC_ADD_QUEUES_ERR);
			break;
		case VIRTCHNL2_OP_DEL_QUEUES:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_DEL_QUEUES,
					   IDPF_VC_DEL_QUEUES_ERR);
			break;
		case VIRTCHNL2_OP_MAP_QUEUE_VECTOR:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_MAP_IRQ,
					   IDPF_VC_MAP_IRQ_ERR);
			break;
		case VIRTCHNL2_OP_UNMAP_QUEUE_VECTOR:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_UNMAP_IRQ,
					   IDPF_VC_UNMAP_IRQ_ERR);
			break;
		case VIRTCHNL2_OP_GET_STATS:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_GET_STATS,
					   IDPF_VC_GET_STATS_ERR);
			break;
		case VIRTCHNL2_OP_GET_RSS_HASH:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_GET_RSS_HASH,
					   IDPF_VC_GET_RSS_HASH_ERR);
			break;
		case VIRTCHNL2_OP_SET_RSS_HASH:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_SET_RSS_HASH,
					   IDPF_VC_SET_RSS_HASH_ERR);
			break;
		case VIRTCHNL2_OP_GET_RSS_LUT:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_GET_RSS_LUT,
					   IDPF_VC_GET_RSS_LUT_ERR);
			break;
		case VIRTCHNL2_OP_SET_RSS_LUT:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_SET_RSS_LUT,
					   IDPF_VC_SET_RSS_LUT_ERR);
			break;
		case VIRTCHNL2_OP_GET_RSS_KEY:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_GET_RSS_KEY,
					   IDPF_VC_GET_RSS_KEY_ERR);
			break;
		case VIRTCHNL2_OP_SET_RSS_KEY:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_SET_RSS_KEY,
					   IDPF_VC_SET_RSS_KEY_ERR);
			break;
		case VIRTCHNL2_OP_SET_SRIOV_VFS:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_SET_SRIOV_VFS,
					   IDPF_VC_SET_SRIOV_VFS_ERR);
			break;
		case VIRTCHNL2_OP_ALLOC_VECTORS:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_ALLOC_VECTORS,
					   IDPF_VC_ALLOC_VECTORS_ERR);
			break;
		case VIRTCHNL2_OP_DEALLOC_VECTORS:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_DEALLOC_VECTORS,
					   IDPF_VC_DEALLOC_VECTORS_ERR);
			break;
		case VIRTCHNL2_OP_GET_PTYPE_INFO:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_GET_PTYPE_INFO,
					   IDPF_VC_GET_PTYPE_INFO);
			break;
		case VIRTCHNL2_OP_LOOPBACK:
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_LOOPBACK_STATE,
					   IDPF_VC_LOOPBACK_STATE_ERR);
			break;
		case VIRTCHNL2_OP_CONFIG_PROMISCUOUS_MODE:
			/* This message can only be sent asynchronously. As
			 * such we'll have lost the context in which it was
			 * called and thus can only really report if it looks
			 * like an error occurred. Don't bother setting ERR bit
			 * or waking chnl_wq since no work queue will be waiting
			 * to read the message.
			 */
			if (ctlq_msg.cookie.mbx.chnl_retval) {
				dev_err(&adapter->pdev->dev, "Failed to set promiscuous mode: %d\n",
					ctlq_msg.cookie.mbx.chnl_retval);
			}
			break;
		case VIRTCHNL2_OP_ADD_MAC_ADDR:
			if (test_and_clear_bit(__IDPF_ADD_MAC_REQ, adapter->flags)) {
				/* Message was sent asynchronously. We don't
				 * normally print errors here, instead
				 * preferring to handle errors in the function
				 * calling wait_for_event. However, we will
				 * have lost the context in which we sent the
				 * message if asynchronous. We can't really do
				 * anything about at it this point, but we
				 * should at a minimum indicate that it looks
				 * like something went wrong. Also don't bother
				 * setting ERR bit or waking vchnl_wq since no
				 * one will be waiting to read the async
				 * message.
				 */
				if (ctlq_msg.cookie.mbx.chnl_retval) {
					dev_err(&adapter->pdev->dev, "Failed to add MAC address: %d\n",
						ctlq_msg.cookie.mbx.chnl_retval);
				}
				break;
			}
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_ADD_MAC_ADDR,
					   IDPF_VC_ADD_MAC_ADDR_ERR);
			break;
		case VIRTCHNL2_OP_DEL_MAC_ADDR:
			if (test_and_clear_bit(__IDPF_DEL_MAC_REQ, adapter->flags)) {
				/* Message was sent asynchronously. We don't
				 * normally print errors here, instead
				 * preferring to handle errors in the function
				 * calling wait_for_event. However, we will
				 * have lost the context in which we sent the
				 * message if asynchronous. We can't really do
				 * anything about at it this point, but we
				 * should at a minimum indicate that it looks
				 * like something went wrong. Also don't bother
				 * setting ERR bit or waking vchnl_wq since no
				 * one will be waiting to read the async
				 * message.
				 */
				if (ctlq_msg.cookie.mbx.chnl_retval) {
					dev_err(&adapter->pdev->dev, "Failed to delete MAC address: %d\n",
						ctlq_msg.cookie.mbx.chnl_retval);
				}
				break;
			}
			idpf_recv_vchnl_op(adapter, vport, &ctlq_msg,
					   IDPF_VC_DEL_MAC_ADDR,
					   IDPF_VC_DEL_MAC_ADDR_ERR);
			break;
		case VIRTCHNL2_OP_EVENT:
			if (idpf_set_msg_pending_bit(adapter, vport)) {
				dev_info(&adapter->pdev->dev, "Timed out setting msg pending\n");
			} else {
				memcpy(vport->vc_msg,
				       ctlq_msg.ctx.indirect.payload->va,
				       min_t(int, payload_size,
					     IDPF_DFLT_MBX_BUF_SIZE));
				idpf_recv_event_msg(vport);
			}
			break;
		case VIRTCHNL2_OP_RDMA:
			if (adapter->rdma_data.vc_send_sync_pending) {
				idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
						   IDPF_VC_IWARP_SEND_SYNC,
						   IDPF_VC_IWARP_SEND_SYNC_ERR);
			} else {
				u8 *payload = (u8 *)ctlq_msg.ctx.indirect.payload->va;

				payload_size = ctlq_msg.ctx.indirect.payload->size;

				idpf_idc_vc_receive(adapter, 0, payload,
						    payload_size);
			}
			break;
		case VIRTCHNL2_OP_CONFIG_RDMA_IRQ_MAP:
		case VIRTCHNL2_OP_RELEASE_RDMA_IRQ_MAP:
			if (ctlq_msg.cookie.mbx.chnl_retval)
				set_bit(IDPF_VC_IWARP_IRQ_MAP_UNMAP_ERR,
					adapter->vc_state);
			set_bit(IDPF_VC_IWARP_IRQ_MAP_UNMAP, adapter->vc_state);
			wake_up(&adapter->vchnl_wq);
			break;
		case VIRTCHNL2_OP_CREATE_ADI:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_CREATE_ADI,
					   IDPF_VC_CREATE_ADI_ERR);
			break;
		case VIRTCHNL2_OP_DESTROY_ADI:
			idpf_recv_vchnl_op(adapter, NULL, &ctlq_msg,
					   IDPF_VC_DESTROY_ADI,
					   IDPF_VC_DESTROY_ADI_ERR);
			break;
		default:
			dev_warn(&adapter->pdev->dev,
				 "Unhandled virtchnl response %d\n",
				 ctlq_msg.cookie.mbx.chnl_opcode);
			break;
		} /* switch v_opcode */
post_buffs:
		if (ctlq_msg.data_len)
			dma_mem = ctlq_msg.ctx.indirect.payload;
		else
			num_q_msg = 0;

		err = idpf_ctlq_post_rx_buffs(&adapter->hw, adapter->hw.arq,
					      &num_q_msg, &dma_mem);
		/* If post failed clear the only buffer we supplied */
		if (err && dma_mem)
			dmam_free_coherent(&adapter->pdev->dev, dma_mem->size,
					   dma_mem->va, dma_mem->pa);
		/* Applies only if we are looking for a specific opcode */
		if (work_done)
			break;
	}

	return err;
}

/**
 * __idpf_wait_for_event - wrapper function for wait on virtchannel response
 * @adapter: Driver private data structure
 * @vport: virtual port structure
 * @state: check on state upon timeout
 * @err_check: check if this specific error bit is set
 * @timeout: Max time to wait
 *
 * Checks if state is set upon expiry of timeout.  Returns 0 on success,
 * negative on failure.
 */
static int __idpf_wait_for_event(struct idpf_adapter *adapter,
				 struct idpf_vport *vport,
				 enum idpf_vport_vc_state state,
				 enum idpf_vport_vc_state err_check,
				 int timeout)
{
#define IDPF_MAX_WAIT 500
	int time_to_wait, num_waits, event;
	wait_queue_head_t *vchnl_wq;
	unsigned long *vc_state;

	time_to_wait = ((timeout <= IDPF_MAX_WAIT) ? timeout : IDPF_MAX_WAIT);
	num_waits = ((timeout <= IDPF_MAX_WAIT) ? 1 : timeout / IDPF_MAX_WAIT);

	if (vport) {
		vchnl_wq = &vport->vchnl_wq;
		vc_state = vport->vc_state;
	} else {
		vchnl_wq = &adapter->vchnl_wq;
		vc_state = adapter->vc_state;
	}

	while (num_waits) {
		/* If we are here and a reset is detected do not wait but
		 * return. Reset timing is out of drivers control. So
		 * while we are cleaning resources as part of reset if the
		 * underlying HW mailbox is gone, wait on mailbox messages
		 * is not meaningful
		 */
		if (idpf_is_reset_detected(adapter))
			return 0;

		event = wait_event_timeout(*vchnl_wq,
					   test_and_clear_bit(state, vc_state),
					   msecs_to_jiffies(time_to_wait));
		if (event) {
			if (test_and_clear_bit(err_check, vc_state)) {
				dev_err(&adapter->pdev->dev, "VC response error %s\n",
					idpf_vport_vc_state_str[err_check]);
				return -EINVAL;
			}
			return 0;
		}
		num_waits--;
	}

	/* Timeout occurred */
	dev_err(&adapter->pdev->dev, "VC timeout, state = %s\n",
		idpf_vport_vc_state_str[state]);
	return -ETIMEDOUT;
}

/**
 * idpf_msec_wait_for_event - wait up to msec timeout for virtchnl response
 * @adapter: Driver private data structure
 * @vport: virtual port structure
 * @state: check on state upon timeout
 * @err_check: check if this specific error bit is set
 * @timeout: Max time to wait
 *
 * Wait up to timeout msecs for virtchnl response. Returns 0 on success,
 * negative on failure.
 */
int idpf_msec_wait_for_event(struct idpf_adapter *adapter,
			     struct idpf_vport *vport,
			     enum idpf_vport_vc_state state,
			     enum idpf_vport_vc_state err_check,
			     int timeout)
{
	return __idpf_wait_for_event(adapter, vport, state, err_check, timeout);
}

/**
 * idpf_min_wait_for_event - wait for virtchannel response
 * @adapter: Driver private data structure
 * @vport: virtual port structure
 * @state: check on state upon timeout
 * @err_check: check if this specific error bit is set
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_min_wait_for_event(struct idpf_adapter *adapter,
			    struct idpf_vport *vport,
			    enum idpf_vport_vc_state state,
			    enum idpf_vport_vc_state err_check)
{
	return __idpf_wait_for_event(adapter, vport, state, err_check,
				     IDPF_WAIT_FOR_EVENT_TIMEO_MIN);
}

/**
 * idpf_wait_for_event - wait for virtchannel response
 * @adapter: Driver private data structure
 * @vport: virtual port structure
 * @state: check on state upon timeout after 500ms
 * @err_check: check if this specific error bit is set
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_wait_for_event(struct idpf_adapter *adapter,
			struct idpf_vport *vport,
			enum idpf_vport_vc_state state,
			enum idpf_vport_vc_state err_check)
{
	/* Increasing the timeout in __IDPF_INIT_SW flow to consider large
	 * number of VF's mailbox message responses. When a message is received
	 * on mailbox, this thread is wake up by the idpf_recv_mb_msg before the
	 * timeout expires. Only in the error case i.e. if no message is
	 * received on mailbox, we wait for the complete timeout which is
	 * less likely to happen.
	 */
	return __idpf_wait_for_event(adapter, vport, state, err_check,
				     IDPF_WAIT_FOR_EVENT_TIMEO);
}

/**
 * idpf_wait_for_marker_event - wait for software marker response
 * @vport: virtual port data structure
 *
 * Returns 0 success, negative on failure.
 **/
static int idpf_wait_for_marker_event(struct idpf_vport *vport)
{
	int event = 0;
	int i;

	for (i = 0; i < vport->num_txq; i++)
		set_bit(__IDPF_Q_SW_MARKER, vport->txqs[i]->flags);

	event = wait_event_timeout(vport->sw_marker_wq,
				   test_and_clear_bit(__IDPF_VPORT_SW_MARKER,
						      vport->flags),
				   msecs_to_jiffies(500));

	for (i = 0; i < vport->num_txq; i++)
		clear_bit(__IDPF_Q_POLL_MODE, vport->txqs[i]->flags);

	if (event) {
		return 0;
	}
	dev_warn(&vport->adapter->pdev->dev, "Failed to receive marker packets\n");
	return -ETIMEDOUT;
}

/**
 * idpf_send_ver_msg - send virtchnl version message
 * @adapter: Driver specific private structure
 *
 * Send virtchnl version message.  Returns 0 on success, negative on failure.
 */
int idpf_send_ver_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_version_info vvi;

	if (adapter->virt_ver_maj) {
		vvi.major = adapter->virt_ver_maj;
		vvi.minor = adapter->virt_ver_min;
	} else {
		vvi.major = IDPF_VIRTCHNL_VERSION_MAJOR;
		vvi.minor = IDPF_VIRTCHNL_VERSION_MINOR;
	}

	return idpf_send_mb_msg(adapter, VIRTCHNL2_OP_VERSION, sizeof(vvi),
				(u8 *)&vvi);
}

/**
 * idpf_recv_ver_msg - Receive virtchnl version message
 * @adapter: Driver specific private structure
 *
 * Receive virtchnl version message. Returns 0 on success, -EAGAIN if we need
 * to send version message again, otherwise negative on failure.
 */
int idpf_recv_ver_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_version_info vvi;
	int err = 0;

	err = idpf_recv_mb_msg(adapter, VIRTCHNL2_OP_VERSION, &vvi, sizeof(vvi));
	if (err)
		return err;

	if (vvi.major > IDPF_VIRTCHNL_VERSION_MAJOR) {
		dev_warn(&adapter->pdev->dev, "Virtchnl major version greater than supported\n");
		return -EINVAL;
	}
	if (vvi.major == IDPF_VIRTCHNL_VERSION_MAJOR &&
	    vvi.minor > IDPF_VIRTCHNL_VERSION_MINOR)
		dev_warn(&adapter->pdev->dev, "Virtchnl minor version not matched\n");

	/* If we have a mismatch, resend version to update receiver on what
	 * version we will use.
	 */
	if (!adapter->virt_ver_maj &&
	    vvi.major != IDPF_VIRTCHNL_VERSION_MAJOR &&
	    vvi.minor != IDPF_VIRTCHNL_VERSION_MINOR)
		err = -EAGAIN;

	adapter->virt_ver_maj = vvi.major;
	adapter->virt_ver_min = vvi.minor;

	return err;
}

/**
 * idpf_get_max_tx_hdr_size -- get the size of tx header
 * @adapter: Driver specific private structure
 */
u16 idpf_get_max_tx_hdr_size(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.max_tx_hdr_size);
}

/**
 * idpf_send_get_caps_msg - Send virtchnl get capabilities message
 * @adapter: Driver specific private structure
 *
 * Send virtchl get capabilities message. Returns 0 on success, negative on
 * failure.
 */
int idpf_send_get_caps_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_get_capabilities caps = {0};

	caps.csum_caps =
		cpu_to_le32(VIRTCHNL2_CAP_TX_CSUM_L3_IPV4	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_TCP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_UDP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_SCTP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_TCP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_UDP	|
			    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_SCTP	|
			    VIRTCHNL2_CAP_TX_CSUM_GENERIC	|
			    VIRTCHNL2_CAP_RX_CSUM_L3_IPV4	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP	|
			    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP	|
			    VIRTCHNL2_CAP_TX_CSUM_L3_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_TX_CSUM_L3_DOUBLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_L3_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_L3_DOUBLE_TUNNEL |
			    VIRTCHNL2_CAP_TX_CSUM_L4_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_TX_CSUM_L4_DOUBLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_L4_SINGLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_L4_DOUBLE_TUNNEL |
			    VIRTCHNL2_CAP_RX_CSUM_GENERIC);

	caps.seg_caps =
		cpu_to_le32(VIRTCHNL2_CAP_SEG_IPV4_TCP		|
			    VIRTCHNL2_CAP_SEG_IPV4_UDP		|
			    VIRTCHNL2_CAP_SEG_IPV4_SCTP		|
			    VIRTCHNL2_CAP_SEG_IPV6_TCP		|
			    VIRTCHNL2_CAP_SEG_IPV6_UDP		|
			    VIRTCHNL2_CAP_SEG_IPV6_SCTP		|
			    VIRTCHNL2_CAP_SEG_TX_SINGLE_TUNNEL	|
			    VIRTCHNL2_CAP_SEG_TX_DOUBLE_TUNNEL	|
			    VIRTCHNL2_CAP_SEG_GENERIC);

	caps.rss_caps =
		cpu_to_le64(VIRTCHNL2_CAP_RSS_IPV4_TCP		|
			    VIRTCHNL2_CAP_RSS_IPV4_UDP		|
			    VIRTCHNL2_CAP_RSS_IPV4_SCTP		|
			    VIRTCHNL2_CAP_RSS_IPV4_OTHER	|
			    VIRTCHNL2_CAP_RSS_IPV6_TCP		|
			    VIRTCHNL2_CAP_RSS_IPV6_UDP		|
			    VIRTCHNL2_CAP_RSS_IPV6_SCTP		|
			    VIRTCHNL2_CAP_RSS_IPV6_OTHER	|
			    VIRTCHNL2_CAP_RSS_IPV4_AH		|
			    VIRTCHNL2_CAP_RSS_IPV4_ESP		|
			    VIRTCHNL2_CAP_RSS_IPV4_AH_ESP	|
			    VIRTCHNL2_CAP_RSS_IPV6_AH		|
			    VIRTCHNL2_CAP_RSS_IPV6_ESP		|
			    VIRTCHNL2_CAP_RSS_IPV6_AH_ESP);

	caps.hsplit_caps =
		cpu_to_le32(VIRTCHNL2_CAP_RX_HSPLIT_AT_L2	|
			    VIRTCHNL2_CAP_RX_HSPLIT_AT_L3	|
			    VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V4	|
			    VIRTCHNL2_CAP_RX_HSPLIT_AT_L4V6);

	caps.rsc_caps =
		cpu_to_le32(VIRTCHNL2_CAP_RSC_IPV4_TCP		|
			    VIRTCHNL2_CAP_RSC_IPV4_SCTP		|
			    VIRTCHNL2_CAP_RSC_IPV6_TCP		|
			    VIRTCHNL2_CAP_RSC_IPV6_SCTP);

	caps.other_caps =
		cpu_to_le64(VIRTCHNL2_CAP_RDMA			|
			    VIRTCHNL2_CAP_SRIOV			|
			    VIRTCHNL2_CAP_MACFILTER		|
			    VIRTCHNL2_CAP_FLOW_DIRECTOR		|
			    VIRTCHNL2_CAP_SPLITQ_QSCHED		|
			    VIRTCHNL2_CAP_CRC			|
			    VIRTCHNL2_CAP_PROMISC		|
			    VIRTCHNL2_CAP_INLINE_IPSEC		|
			    VIRTCHNL2_CAP_EDT			|
			    VIRTCHNL2_CAP_LOOPBACK		|
			    VIRTCHNL2_CAP_RX_FLEX_DESC);

	return idpf_send_mb_msg(adapter, VIRTCHNL2_OP_GET_CAPS, sizeof(caps),
				(u8 *)&caps);
}

/**
 * idpf_recv_get_caps_msg - Receive virtchnl get capabilities message
 * @adapter: Driver specific private structure
 *
 * Receive virtchnl get capabilities message.  Returns 0 on succes, negative on
 * failure.
 */
int idpf_recv_get_caps_msg(struct idpf_adapter *adapter)
{
	return idpf_recv_mb_msg(adapter, VIRTCHNL2_OP_GET_CAPS, &adapter->caps,
				sizeof(struct virtchnl2_get_capabilities));
}

/**
 * idpf_vport_alloc_max_qs - Allocate max queues for a vport
 * @adapter: Driver specific private structure
 * @max_q: vport max queue structure
 */
int idpf_vport_alloc_max_qs(struct idpf_adapter *adapter,
			    struct idpf_vport_max_q *max_q)
{
	struct idpf_avail_queue_info *avail_queues = &adapter->avail_queues;
	struct virtchnl2_get_capabilities *caps = &adapter->caps;
	int max_rx_q, max_tx_q;
	u16 default_vports;
	int err = 0;

	default_vports = idpf_get_default_vports(adapter);
	mutex_lock(&adapter->queue_lock);
	max_rx_q = le16_to_cpu(caps->max_rx_q) / default_vports;
	max_tx_q = le16_to_cpu(caps->max_tx_q) / default_vports;
	if (adapter->num_alloc_vports < default_vports) {
		max_q->max_rxq = min_t(u16, max_rx_q, IDPF_MAX_Q);
		max_q->max_txq = min_t(u16, max_tx_q, IDPF_MAX_Q);
	} else {
		max_q->max_rxq = IDPF_MIN_Q;
		max_q->max_txq = IDPF_MIN_Q;
	}
	max_q->max_bufq = max_q->max_rxq * IDPF_MAX_BUFQS_PER_RXQ_GRP;
	max_q->max_complq = max_q->max_txq;

	if (avail_queues->avail_rxq < max_q->max_rxq ||
	    avail_queues->avail_txq < max_q->max_txq ||
	    avail_queues->avail_bufq < max_q->max_bufq ||
	    avail_queues->avail_complq < max_q->max_complq) {
		err = -EINVAL;
		goto rel_lock;
	}

	avail_queues->avail_rxq -= max_q->max_rxq;
	avail_queues->avail_txq -= max_q->max_txq;
	avail_queues->avail_bufq -= max_q->max_bufq;
	avail_queues->avail_complq -= max_q->max_complq;

rel_lock:
	mutex_unlock(&adapter->queue_lock);

	return err;
}

/**
 * idpf_vport_dealloc_max_qs - Deallocate max queues of a vport
 * @adapter: Driver specific private structure
 * @max_q: vport max queue structure
 */
void idpf_vport_dealloc_max_qs(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q)
{
	struct idpf_avail_queue_info *avail_queues;

	mutex_lock(&adapter->queue_lock);
	avail_queues = &adapter->avail_queues;

	avail_queues->avail_rxq += max_q->max_rxq;
	avail_queues->avail_txq += max_q->max_txq;
	avail_queues->avail_bufq += max_q->max_bufq;
	avail_queues->avail_complq += max_q->max_complq;

	mutex_unlock(&adapter->queue_lock);
}

/**
 * idpf_init_avail_queues - Initialize available queues on the device
 * @adapter: Driver specific private structure
 */
static void idpf_init_avail_queues(struct idpf_adapter *adapter)
{
	struct virtchnl2_get_capabilities *caps = &adapter->caps;

	adapter->avail_queues.avail_rxq = le16_to_cpu(caps->max_rx_q);
	adapter->avail_queues.avail_txq = le16_to_cpu(caps->max_tx_q);
	adapter->avail_queues.avail_bufq = le16_to_cpu(caps->max_rx_bufq);
	adapter->avail_queues.avail_complq = le16_to_cpu(caps->max_tx_complq);
}

/**
 * idpf_get_reg_intr_vecs - Get vector queue register offset
 * @vport: virtual port structure
 * @reg_vals: Register offsets to store in
 *
 * Returns number of regsiters that got populated
 */
int idpf_get_reg_intr_vecs(struct idpf_vport *vport,
			   struct idpf_vec_regs *reg_vals)
{
	struct virtchnl2_vector_chunks *chunks;
	struct virtchnl2_vector_chunk *chunk;
	struct idpf_vec_regs reg_val;
	u16 num_vchunks, num_vec;
	int num_regs = 0, i, j;

	chunks = &vport->adapter->req_vec_chunks->vchunks;
	num_vchunks = le16_to_cpu(chunks->num_vchunks);

	for (j = 0; j < num_vchunks; j++) {
		chunk = &chunks->vchunks[j];
		num_vec = le16_to_cpu(chunk->num_vectors);
		reg_val.dyn_ctl_reg = le32_to_cpu(chunk->dynctl_reg_start);
		reg_val.itrn_reg = le32_to_cpu(chunk->itrn_reg_start);
		reg_val.itrn_index_spacing = le32_to_cpu(chunk->itrn_index_spacing);
		for (i = 0; i < num_vec; i++) {
			reg_vals[num_regs].dyn_ctl_reg = reg_val.dyn_ctl_reg;
			reg_vals[num_regs].itrn_reg = reg_val.itrn_reg;
			reg_vals[num_regs].itrn_index_spacing =
						reg_val.itrn_index_spacing;

			reg_val.dyn_ctl_reg +=
				le32_to_cpu(chunk->dynctl_reg_spacing);
			reg_val.itrn_reg +=
				le32_to_cpu(chunk->itrn_reg_spacing);
			num_regs++;
		}
	}

	return num_regs;
}

/**
 * idpf_vport_get_q_reg - Get the queue registers for the vport
 * @reg_vals: register values needing to be set
 * @num_regs: amount we expect to fill
 * @q_type: queue model
 * @chunks: queue regs received over mailbox
 */
static int
idpf_vport_get_q_reg(u32 *reg_vals, int num_regs, u32 q_type,
		     struct virtchnl2_queue_reg_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_chunks);
	struct virtchnl2_queue_reg_chunk *chunk;
	int reg_filled = 0, i;
	u32 reg_val;
	u16 num_q;

	while (num_chunks--) {
		chunk = &chunks->chunks[num_chunks];
		if (le32_to_cpu(chunk->type) != q_type)
			continue;
		num_q = le32_to_cpu(chunk->num_queues);
		reg_val = le64_to_cpu(chunk->qtail_reg_start);
		for (i = 0; i < num_q; i++) {
			if (reg_filled == num_regs)
				break;
			reg_vals[reg_filled++] = reg_val;
			reg_val += le32_to_cpu(chunk->qtail_reg_spacing);
		}
	}

	return reg_filled;
}

/**
 * __idpf_queue_reg_init - initialize queue registers
 * @vport: virtual port structure
 * @reg_vals: registers we are initializing
 * @num_regs: how many registers there are in total
 * @q_type: queue model
 *
 * Return number of queues that are initialized
 */
static int
__idpf_queue_reg_init(struct idpf_vport *vport, u32 *reg_vals,
		      int num_regs, u32 q_type)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_queue *q;
	int i, j, k = 0;

	switch (q_type) {
	case VIRTCHNL2_QUEUE_TYPE_TX:
		for (i = 0; i < vport->num_txq_grp; i++) {
			struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

			for (j = 0; j < tx_qgrp->num_txq; j++) {
				if (k == num_regs)
					break;

				tx_qgrp->txqs[j]->tail =
					idpf_get_reg_addr(adapter, reg_vals[k]);
				k++;
			}
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
			int num_rxq = rx_qgrp->singleq.num_rxq;

			for (j = 0; j < num_rxq; j++) {
				if (k == num_regs)
					break;

				q = rx_qgrp->singleq.rxqs[j];
				q->tail = idpf_get_reg_addr(adapter,
							    reg_vals[k]);
				k++;
			}
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];

			for (j = 0; j < vport->num_bufqs_per_qgrp; j++) {
				if (k == num_regs)
					break;

				q = &rx_qgrp->splitq.bufq_sets[j].bufq;
				q->tail = idpf_get_reg_addr(adapter,
							    reg_vals[k]);
				k++;
			}
		}
		break;
	default:
		break;
	}

	return k;
}

/**
 * idpf_queue_reg_init - initialize queue registers
 * @vport: virtual port structure
 *
 * Return 0 on success, negative on failure
 */
int idpf_queue_reg_init(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport *vport_params;
	struct virtchnl2_queue_reg_chunks *chunks;
	struct idpf_vport_config *vport_config;
	u16 vport_idx = vport->idx;
	int num_regs, ret = 0;
	u32 *reg_vals;

	/* We may never deal with more than 256 same type of queues */
	reg_vals = (u32 *)kmalloc(sizeof(void *) * IDPF_LARGE_MAX_Q,
				  GFP_KERNEL);
	if (!reg_vals)
		return -ENOMEM;

	vport_config = vport->adapter->vport_config[vport_idx];
	if (vport_config->req_qs_chunks) {
		struct virtchnl2_add_queues *vc_aq =
		  (struct virtchnl2_add_queues *)vport_config->req_qs_chunks;
		chunks = &vc_aq->chunks;
	} else {
		vport_params = (struct virtchnl2_create_vport *)
			vport->adapter->vport_params_recvd[vport_idx];
		chunks = &vport_params->chunks;
	}

	/* Initialize Tx queue tail register address */
	num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
					VIRTCHNL2_QUEUE_TYPE_TX,
					chunks);
	if (num_regs < vport->num_txq) {
		ret = -EINVAL;
		goto free_reg_vals;
	}

	num_regs = __idpf_queue_reg_init(vport, reg_vals, num_regs,
					 VIRTCHNL2_QUEUE_TYPE_TX);
	if (num_regs < vport->num_txq) {
		ret = -EINVAL;
		goto free_reg_vals;
	}

	/* Initialize Rx/buffer queue tail register address based on Rx queue
	 * model
	 */
	if (idpf_is_queue_model_split(vport->rxq_model)) {
		num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
						VIRTCHNL2_QUEUE_TYPE_RX_BUFFER,
						chunks);
		if (num_regs < vport->num_bufq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}

		num_regs = __idpf_queue_reg_init(vport, reg_vals, num_regs,
						 VIRTCHNL2_QUEUE_TYPE_RX_BUFFER);
		if (num_regs < vport->num_bufq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}
	} else {
		num_regs = idpf_vport_get_q_reg(reg_vals, IDPF_LARGE_MAX_Q,
						VIRTCHNL2_QUEUE_TYPE_RX,
						chunks);
		if (num_regs < vport->num_rxq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}

		num_regs = __idpf_queue_reg_init(vport, reg_vals, num_regs,
						 VIRTCHNL2_QUEUE_TYPE_RX);
		if (num_regs < vport->num_rxq) {
			ret = -EINVAL;
			goto free_reg_vals;
		}
	}

free_reg_vals:
	kfree(reg_vals);
	return ret;
}

/**
 * idpf_send_create_vport_msg - Send virtchnl create vport message
 * @adapter: Driver specific private structure
 * @max_q: vport max queue info
 *
 * send virtchnl creae vport message
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_create_vport_msg(struct idpf_adapter *adapter,
			       struct idpf_vport_max_q *max_q)
{
	struct virtchnl2_create_vport *vport_msg;
	u16 idx = adapter->next_vport;
	int err, buf_size;

	buf_size = sizeof(struct virtchnl2_create_vport);
	if (!adapter->vport_params_reqd[idx]) {
		adapter->vport_params_reqd[idx] = kzalloc(buf_size,
							  GFP_KERNEL);
		if (!adapter->vport_params_reqd[idx])
			return -ENOMEM;
	}

	vport_msg = (struct virtchnl2_create_vport *)
			adapter->vport_params_reqd[idx];
	vport_msg->vport_type = cpu_to_le16(VIRTCHNL2_VPORT_TYPE_DEFAULT);
	vport_msg->vport_index = cpu_to_le16(idx);

	if (test_bit(__IDPF_REQ_TX_SPLITQ, adapter->flags))
		vport_msg->txq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SPLIT);
	else
		vport_msg->txq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SINGLE);

	if (test_bit(__IDPF_REQ_RX_SPLITQ, adapter->flags))
		vport_msg->rxq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SPLIT);
	else
		vport_msg->rxq_model = cpu_to_le16(VIRTCHNL2_QUEUE_MODEL_SINGLE);

	err = idpf_vport_calc_total_qs(adapter, idx, vport_msg, max_q);
	if (err) {
		dev_err(&adapter->pdev->dev, "Enough queues are not available");
		return err;
	}

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_CREATE_VPORT, buf_size,
			       (u8 *)vport_msg);
	if (err)
		return err;

	err = idpf_wait_for_event(adapter, NULL, IDPF_VC_CREATE_VPORT,
				  IDPF_VC_CREATE_VPORT_ERR);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to receive create vport message");
		return err;
	}

	if (!adapter->vport_params_recvd[idx]) {
		adapter->vport_params_recvd[idx] = kzalloc(IDPF_DFLT_MBX_BUF_SIZE,
							   GFP_KERNEL);
		if (!adapter->vport_params_recvd[idx]) {
			err = -ENOMEM;
			goto clear_bit;
		}
	}

	vport_msg = (struct virtchnl2_create_vport *)
			adapter->vport_params_recvd[idx];
	memcpy(vport_msg, adapter->vc_msg, IDPF_DFLT_MBX_BUF_SIZE);

clear_bit:
	clear_bit(__IDPF_VC_MSG_PENDING, adapter->flags);
	return err;
}

/**
 * idpf_check_supported_desc_ids - Verify we have required descriptor support
 * @vport: virtual port structure
 *
 * Return 0 on success, error on failure
 */
int idpf_check_supported_desc_ids(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_create_vport *vport_msg;
	u64 rx_desc_ids, tx_desc_ids;

	vport_msg = (struct virtchnl2_create_vport *)
				adapter->vport_params_recvd[vport->idx];

	rx_desc_ids = le64_to_cpu(vport_msg->rx_desc_ids);
	tx_desc_ids = le64_to_cpu(vport_msg->tx_desc_ids);

	if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT) {
		if (!(rx_desc_ids & VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M)) {
			dev_info(&adapter->pdev->dev, "RX descriptors not provided, using the default\n");
			vport_msg->rx_desc_ids = cpu_to_le64(VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M);
		}
	} else {
		if (!(rx_desc_ids & VIRTCHNL2_RXDID_2_FLEX_SQ_NIC_M))
			vport->base_rxd = true;
	}

	if (vport->txq_model != VIRTCHNL2_QUEUE_MODEL_SPLIT)
		return 0;

#define MIN_SUPPORT_TXDID (\
	VIRTCHNL2_TXDID_FLEX_FLOW_SCHED |\
	VIRTCHNL2_TXDID_FLEX_TSO_CTX |\
	VIRTCHNL2_TXDID_FLEX_DATA)
	if ((tx_desc_ids & MIN_SUPPORT_TXDID) != MIN_SUPPORT_TXDID) {
		dev_info(&adapter->pdev->dev, "Minimum TX descriptor support not provided, using the default\n");
		vport_msg->tx_desc_ids = cpu_to_le64(MIN_SUPPORT_TXDID);
	}
	return 0;
}

/**
 * idpf_send_destroy_vport_msg - Send virtchnl destroy vport message
 * @vport: virtual port data structure
 *
 * Send virtchnl destroy vport message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_destroy_vport_msg(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_vport v_id;
	int err;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_DESTROY_VPORT,
			       sizeof(v_id), (u8 *)&v_id);
	if (err)
		return err;

	err = idpf_min_wait_for_event(adapter, vport, IDPF_VC_DESTROY_VPORT,
				      IDPF_VC_DESTROY_VPORT_ERR);
	if (!err)
		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);

	return err;
}

/**
 * idpf_send_enable_vport_msg - Send virtchnl enable vport message
 * @vport: virtual port data structure
 *
 * Send enable vport virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_enable_vport_msg(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_vport v_id;
	int err;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_ENABLE_VPORT,
			       sizeof(v_id), (u8 *)&v_id);
	if (err)
		return err;

	err = idpf_wait_for_event(adapter, vport, IDPF_VC_ENA_VPORT,
				  IDPF_VC_ENA_VPORT_ERR);
	if (!err)
		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);

	return err;
}

/**
 * idpf_send_disable_vport_msg - Send virtchnl disable vport message
 * @vport: virtual port data structure
 *
 * Send disable vport virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_disable_vport_msg(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_vport v_id;
	int err;

	v_id.vport_id = cpu_to_le32(vport->vport_id);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_DISABLE_VPORT,
			       sizeof(v_id), (u8 *)&v_id);
	if (err)
		return err;

	err = idpf_min_wait_for_event(adapter, vport, IDPF_VC_DIS_VPORT,
				      IDPF_VC_DIS_VPORT_ERR);
	if (!err)
		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);

	return err;
}

/**
 * idpf_send_config_tx_queues_msg - Send virtchnl config tx queues message
 * @vport: virtual port data structure
 *
 * Send config tx queues virtchnl message. Returns 0 on success, negative on
 * failure.
 */
int idpf_send_config_tx_queues_msg(struct idpf_vport *vport)
{
	struct virtchnl2_config_tx_queues *ctq = NULL;
	int config_data_size, chunk_size, buf_size = 0;
	int totqs, num_msgs, num_chunks;
	struct virtchnl2_txq_info *qi;
	int err = 0, i, k = 0;
	bool alloc = false;

	totqs = vport->num_txq + vport->num_complq;
	qi = kcalloc(totqs, sizeof(struct virtchnl2_txq_info), GFP_KERNEL);
	if (!qi)
		return -ENOMEM;

	/* Populate the queue info buffer with all queue context info */
	for (i = 0; i < vport->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];
		int j;

		for (j = 0; j < tx_qgrp->num_txq; j++, k++) {
			qi[k].queue_id =
				cpu_to_le32(tx_qgrp->txqs[j]->q_id);
			qi[k].model =
				cpu_to_le16(vport->txq_model);
			qi[k].type =
				cpu_to_le32(tx_qgrp->txqs[j]->q_type);
			qi[k].ring_len =
				cpu_to_le16(tx_qgrp->txqs[j]->desc_count);
			qi[k].dma_ring_addr =
				cpu_to_le64(tx_qgrp->txqs[j]->dma);
			if (idpf_is_queue_model_split(vport->txq_model)) {
				struct idpf_queue *q = tx_qgrp->txqs[j];

				qi[k].tx_compl_queue_id =
					cpu_to_le16(tx_qgrp->complq->q_id);
				qi[k].relative_queue_id = cpu_to_le16(j);

				if (test_bit(__IDPF_Q_FLOW_SCH_EN, q->flags))
					qi[k].sched_mode =
					cpu_to_le16(VIRTCHNL2_TXQ_SCHED_MODE_FLOW);
				else
					qi[k].sched_mode =
					cpu_to_le16(VIRTCHNL2_TXQ_SCHED_MODE_QUEUE);
			} else {
				qi[k].sched_mode =
					cpu_to_le16(VIRTCHNL2_TXQ_SCHED_MODE_QUEUE);
			}
		}

		if (idpf_is_queue_model_split(vport->txq_model)) {
			qi[k].queue_id =
				cpu_to_le32(tx_qgrp->complq->q_id);
			qi[k].model =
				cpu_to_le16(vport->txq_model);
			qi[k].type =
				cpu_to_le32(tx_qgrp->complq->q_type);
			qi[k].ring_len =
				cpu_to_le16(tx_qgrp->complq->desc_count);
			qi[k].dma_ring_addr =
				cpu_to_le64(tx_qgrp->complq->dma);
			k++;
		}
	}

	/* Make sure accounting agrees */
	if (k != totqs) {
		err = -EINVAL;
		goto error;
	}

	/* Chunk up the queue contexts into multiple messages to avoid
	 * sending a control queue message buffer that is too large
	 */
	config_data_size = sizeof(struct virtchnl2_config_tx_queues);
	chunk_size = sizeof(struct virtchnl2_txq_info);

	num_chunks = IDPF_NUM_CHUNKS_PER_MSG(config_data_size, chunk_size) + 1;
	if (totqs < num_chunks)
		num_chunks = totqs;

	num_msgs = totqs / num_chunks;
	if (totqs % num_chunks)
		num_msgs++;

	for (i = 0, k = 0; i < num_msgs; i++) {
		if (!ctq || alloc) {
			buf_size = (chunk_size * (num_chunks - 1)) +
					config_data_size;
			kfree(ctq);
			ctq = kzalloc(buf_size, GFP_KERNEL);
			if (!ctq) {
				err = -ENOMEM;
				goto error;
			}
		} else {
			memset(ctq, 0, buf_size);
		}

		ctq->vport_id = cpu_to_le32(vport->vport_id);
		ctq->num_qinfo = cpu_to_le16(num_chunks);
		memcpy(ctq->qinfo, &qi[k], chunk_size * num_chunks);

		err = idpf_send_mb_msg(vport->adapter,
				       VIRTCHNL2_OP_CONFIG_TX_QUEUES,
				       buf_size, (u8 *)ctq);
		if (err)
			goto mbx_error;

		err = idpf_wait_for_event(vport->adapter, vport, IDPF_VC_CONFIG_TXQ,
					  IDPF_VC_CONFIG_TXQ_ERR);
		if (err)
			goto mbx_error;

		k += num_chunks;
		totqs -= num_chunks;
		if (totqs < num_chunks) {
			num_chunks = totqs;
			alloc = true;
		}

		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);
	}

mbx_error:
	kfree(ctq);
error:
	kfree(qi);
	return err;
}

/**
 * idpf_send_config_rx_queues_msg - Send virtchnl config rx queues message
 * @vport: virtual port data structure
 *
 * Send config rx queues virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_config_rx_queues_msg(struct idpf_vport *vport)
{
	struct virtchnl2_config_rx_queues *crq = NULL;
	int config_data_size, chunk_size, buf_size = 0;
	int totqs, num_msgs, num_chunks;
	struct virtchnl2_rxq_info *qi;
	int err = 0, i, k = 0;
	bool alloc = false;

	totqs = vport->num_rxq + vport->num_bufq;
	qi = kcalloc(totqs, sizeof(struct virtchnl2_rxq_info), GFP_KERNEL);
	if (!qi)
		return -ENOMEM;

	/* Populate the queue info buffer with all queue context info */
	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		int num_rxq;
		int j;

		if (!idpf_is_queue_model_split(vport->rxq_model))
			goto setup_rxqs;

		for (j = 0; j < vport->num_bufqs_per_qgrp; j++, k++) {
			struct idpf_queue *bufq =
				&rx_qgrp->splitq.bufq_sets[j].bufq;

			qi[k].queue_id = cpu_to_le32(bufq->q_id);
			qi[k].model = cpu_to_le16(vport->rxq_model);
			qi[k].type = cpu_to_le32(bufq->q_type);
			qi[k].desc_ids = cpu_to_le64(VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M);
			qi[k].ring_len = cpu_to_le16(bufq->desc_count);
			qi[k].dma_ring_addr = cpu_to_le64(bufq->dma);
			qi[k].data_buffer_size = cpu_to_le32(bufq->rx_buf_size);
			qi[k].buffer_notif_stride = bufq->rx_buf_stride;
			qi[k].rx_buffer_low_watermark =
				cpu_to_le16(bufq->rx_buffer_low_watermark);
#ifdef NETIF_F_GRO_HW
			if (idpf_is_feature_ena(vport, NETIF_F_GRO_HW))
				qi[k].qflags |= cpu_to_le16(VIRTCHNL2_RXQ_RSC);
#endif /* NETIF_F_GRO_HW */
		}

setup_rxqs:
		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++, k++) {
			struct idpf_queue *rxq;

			if (!idpf_is_queue_model_split(vport->rxq_model)) {
				rxq = rx_qgrp->singleq.rxqs[j];
				goto common_qi_fields;
			}
			rxq = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			qi[k].rx_bufq1_id =
			  cpu_to_le16(rxq->rxq_grp->splitq.bufq_sets[0].bufq.q_id);
			if (vport->num_bufqs_per_qgrp > IDPF_SINGLE_BUFQ_PER_RXQ_GRP) {
				qi[k].bufq2_ena = IDPF_BUFQ2_ENA;
				qi[k].rx_bufq2_id =
				  cpu_to_le16(rxq->rxq_grp->splitq.bufq_sets[1].bufq.q_id);
			}
			qi[k].rx_buffer_low_watermark =
				cpu_to_le16(rxq->rx_buffer_low_watermark);
#ifdef NETIF_F_GRO_HW
			if (idpf_is_feature_ena(vport, NETIF_F_GRO_HW))
				qi[k].qflags |= cpu_to_le16(VIRTCHNL2_RXQ_RSC);
#endif /* NETIF_F_GRO_HW */

common_qi_fields:
			if (rxq->rx_hsplit_en) {
				qi[k].qflags |=
					cpu_to_le16(VIRTCHNL2_RXQ_HDR_SPLIT);
				qi[k].hdr_buffer_size =
					cpu_to_le16(rxq->rx_hbuf_size);
			}
			qi[k].queue_id = cpu_to_le32(rxq->q_id);
			qi[k].model = cpu_to_le16(vport->rxq_model);
			qi[k].type = cpu_to_le32(rxq->q_type);
			qi[k].ring_len = cpu_to_le16(rxq->desc_count);
			qi[k].dma_ring_addr = cpu_to_le64(rxq->dma);
			qi[k].max_pkt_size = cpu_to_le32(rxq->rx_max_pkt_size);
			qi[k].data_buffer_size = cpu_to_le32(rxq->rx_buf_size);
			qi[k].qflags |=
				cpu_to_le16(VIRTCHNL2_RX_DESC_SIZE_32BYTE);
			qi[k].desc_ids = cpu_to_le64(rxq->rxdids);
		}
	}

	/* Make sure accounting agrees */
	if (k != totqs) {
		err = -EINVAL;
		goto error;
	}

	/* Chunk up the queue contexts into multiple messages to avoid
	 * sending a control queue message buffer that is too large
	 */
	config_data_size = sizeof(struct virtchnl2_config_rx_queues);
	chunk_size = sizeof(struct virtchnl2_rxq_info);

	num_chunks = IDPF_NUM_CHUNKS_PER_MSG(config_data_size, chunk_size) + 1;
	if (totqs < num_chunks)
		num_chunks = totqs;

	num_msgs = totqs / num_chunks;
	if (totqs % num_chunks)
		num_msgs++;

	for (i = 0, k = 0; i < num_msgs; i++) {
		if (!crq || alloc) {
			buf_size = (chunk_size * (num_chunks - 1)) +
					config_data_size;
			kfree(crq);
			crq = kzalloc(buf_size, GFP_KERNEL);
			if (!crq) {
				err = -ENOMEM;
				goto error;
			}
		} else {
			memset(crq, 0, buf_size);
		}

		crq->vport_id = cpu_to_le32(vport->vport_id);
		crq->num_qinfo = cpu_to_le16(num_chunks);
		memcpy(crq->qinfo, &qi[k], chunk_size * num_chunks);

		err = idpf_send_mb_msg(vport->adapter,
				       VIRTCHNL2_OP_CONFIG_RX_QUEUES,
				       buf_size, (u8 *)crq);
		if (err)
			goto mbx_error;

		err = idpf_wait_for_event(vport->adapter, vport, IDPF_VC_CONFIG_RXQ,
					  IDPF_VC_CONFIG_RXQ_ERR);
		if (err)
			goto mbx_error;

		k += num_chunks;
		totqs -= num_chunks;
		if (totqs < num_chunks) {
			num_chunks = totqs;
			alloc = true;
		}

		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);
	}

mbx_error:
	kfree(crq);
error:
	kfree(qi);
	return err;
}

/**
 * idpf_send_ena_dis_queues_msg - Send virtchnl enable or disable
 * queues message
 * @vport: virtual port data structure
 * @vc_op: virtchnl op code to send
 *
 * Send enable or disable queues virtchnl message. Returns 0 on success,
 * negative on failure.
 */
static int idpf_send_ena_dis_queues_msg(struct idpf_vport *vport, u32 vc_op)
{
	int num_msgs, num_chunks, config_data_size, chunk_size;
	int num_txq, num_rxq, num_q, buf_size, err = 0;
	struct virtchnl2_del_ena_dis_queues *eq = NULL;
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_queue_chunk *qc;
	bool alloc = false;
	int i, j, k = 0;

	/* validate virtchnl op */
	switch (vc_op) {
	case VIRTCHNL2_OP_ENABLE_QUEUES:
	case VIRTCHNL2_OP_DISABLE_QUEUES:
		break;
	default:
		return -EINVAL;
	}

	num_txq = vport->num_txq + vport->num_complq;
	num_rxq = vport->num_rxq + vport->num_bufq;
	num_q = num_txq + num_rxq;
	buf_size = sizeof(struct virtchnl2_queue_chunk) * (num_q);
	qc = kzalloc(buf_size, GFP_KERNEL);
	if (!qc)
		return -ENOMEM;

	for (i = 0; i < vport->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

		for (j = 0; j < tx_qgrp->num_txq; j++, k++) {
			qc[k].type = cpu_to_le32(tx_qgrp->txqs[j]->q_type);
			qc[k].start_queue_id =
					cpu_to_le32(tx_qgrp->txqs[j]->q_id);
			qc[k].num_queues = cpu_to_le32(1);
		}
	}
	if (vport->num_txq != k) {
		err = -EINVAL;
		goto error;
	}

	if (!idpf_is_queue_model_split(vport->txq_model))
		goto setup_rx;

	for (i = 0; i < vport->num_txq_grp; i++, k++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

		qc[k].type = cpu_to_le32(tx_qgrp->complq->q_type);
		qc[k].start_queue_id =
				cpu_to_le32(tx_qgrp->complq->q_id);
		qc[k].num_queues = cpu_to_le32(1);
	}
	if (vport->num_complq != (k - vport->num_txq)) {
		err = -EINVAL;
		goto error;
	}

setup_rx:
	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];

		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++, k++) {
			if (idpf_is_queue_model_split(vport->rxq_model)) {
				qc[k].start_queue_id =
				cpu_to_le32(rx_qgrp->splitq.rxq_sets[j]->rxq.q_id);
				qc[k].type =
				cpu_to_le32(rx_qgrp->splitq.rxq_sets[j]->rxq.q_type);
			} else {
				qc[k].start_queue_id =
				cpu_to_le32(rx_qgrp->singleq.rxqs[j]->q_id);
				qc[k].type =
				cpu_to_le32(rx_qgrp->singleq.rxqs[j]->q_type);
			}
			qc[k].num_queues = cpu_to_le32(1);
		}
	}
	if (vport->num_rxq != k - (vport->num_txq + vport->num_complq)) {
		err = -EINVAL;
		goto error;
	}

	if (!idpf_is_queue_model_split(vport->rxq_model))
		goto send_msg;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		struct idpf_queue *q;

		for (j = 0; j < vport->num_bufqs_per_qgrp; j++, k++) {
			q = &rx_qgrp->splitq.bufq_sets[j].bufq;
			qc[k].type = cpu_to_le32(q->q_type);
			qc[k].start_queue_id = cpu_to_le32(q->q_id);
			qc[k].num_queues = cpu_to_le32(1);
		}
	}
	if (vport->num_bufq != k - (vport->num_txq +
				       vport->num_complq +
				       vport->num_rxq)) {
		err = -EINVAL;
		goto error;
	}

send_msg:
	/* Chunk up the queue info into multiple messages */
	config_data_size = sizeof(struct virtchnl2_del_ena_dis_queues);
	chunk_size = sizeof(struct virtchnl2_queue_chunk);

	num_chunks = IDPF_NUM_CHUNKS_PER_MSG(config_data_size, chunk_size) + 1;
	if (num_q < num_chunks)
		num_chunks = num_q;

	num_msgs = num_q / num_chunks;
	if (num_q % num_chunks)
		num_msgs++;

	for (i = 0, k = 0; i < num_msgs; i++) {
		if (!eq || alloc) {
			buf_size = (chunk_size * (num_chunks - 1)) +
					config_data_size;
			kfree(eq);
			eq = kzalloc(buf_size, GFP_KERNEL);
			if (!eq) {
				err = -ENOMEM;
				goto error;
			}
		} else {
			memset(eq, 0, buf_size);
		}
		eq->vport_id = cpu_to_le32(vport->vport_id);
		eq->chunks.num_chunks = cpu_to_le16(num_chunks);
		memcpy(eq->chunks.chunks, &qc[k], chunk_size * num_chunks);

		err = idpf_send_mb_msg(adapter, vc_op, buf_size, (u8 *)eq);
		if (err)
			goto mbx_error;

		if (vc_op == VIRTCHNL2_OP_ENABLE_QUEUES)
			err = idpf_wait_for_event(adapter, vport,
						  IDPF_VC_ENA_QUEUES,
						  IDPF_VC_ENA_QUEUES_ERR);
		else
			err = idpf_min_wait_for_event(adapter, vport,
						      IDPF_VC_DIS_QUEUES,
						      IDPF_VC_DIS_QUEUES_ERR);
		if (err)
			goto mbx_error;

		k += num_chunks;
		num_q -= num_chunks;
		if (num_q < num_chunks) {
			num_chunks = num_q;
			alloc = true;
		}

		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);
	}
mbx_error:
	kfree(eq);
error:
	kfree(qc);
	return err;
}

/**
 * idpf_send_map_unmap_queue_vector_msg - Send virtchnl map or unmap queue
 * vector message
 * @vport: virtual port data structure
 * @map: true for map and false for unmap
 *
 * Send map or unmap queue vector virtchnl message.  Returns 0 on success,
 * negative on failure.
 */
int idpf_send_map_unmap_queue_vector_msg(struct idpf_vport *vport, bool map)
{
	int num_msgs, num_chunks, config_data_size, chunk_size;
	struct virtchnl2_queue_vector_maps *vqvm = NULL;
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_queue_vector *vqv;
	int buf_size, num_q, err = 0;
	bool alloc = false;
	int i, j, k = 0;

	num_q = vport->num_txq + vport->num_rxq;

	buf_size = sizeof(struct virtchnl2_queue_vector) * num_q;
	vqv = kzalloc(buf_size, GFP_KERNEL);
	if (!vqv)
		return -ENOMEM;

	for (i = 0; i < vport->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

		for (j = 0; j < tx_qgrp->num_txq; j++, k++) {
			vqv[k].queue_type = cpu_to_le32(tx_qgrp->txqs[j]->q_type);
			vqv[k].queue_id = cpu_to_le32(tx_qgrp->txqs[j]->q_id);

			if (idpf_is_queue_model_split(vport->txq_model)) {
				vqv[k].vector_id =
				cpu_to_le16(tx_qgrp->complq->q_vector->v_idx);
				vqv[k].itr_idx =
				cpu_to_le32(tx_qgrp->complq->q_vector->tx_itr_idx);
			} else {
				vqv[k].vector_id =
				cpu_to_le16(tx_qgrp->txqs[j]->q_vector->v_idx);
				vqv[k].itr_idx =
				cpu_to_le32(tx_qgrp->txqs[j]->q_vector->tx_itr_idx);
			}
		}
	}

	if (vport->num_txq != k) {
		err = -EINVAL;
		goto error;
	}

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		int num_rxq;

		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++, k++) {
			struct idpf_queue *rxq;

			if (idpf_is_queue_model_split(vport->rxq_model))
				rxq = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				rxq = rx_qgrp->singleq.rxqs[j];

			vqv[k].queue_type = cpu_to_le32(rxq->q_type);
			vqv[k].queue_id = cpu_to_le32(rxq->q_id);
			vqv[k].vector_id = cpu_to_le16(rxq->q_vector->v_idx);
			vqv[k].itr_idx = cpu_to_le32(rxq->q_vector->rx_itr_idx);
		}
	}

	if (idpf_is_queue_model_split(vport->txq_model)) {
		if (vport->num_rxq != k - vport->num_complq) {
			err = -EINVAL;
			goto error;
		}
	} else {
		if (vport->num_rxq != k - vport->num_txq) {
			err = -EINVAL;
			goto error;
		}
	}

	/* Chunk up the vector info into multiple messages */
	config_data_size = sizeof(struct virtchnl2_queue_vector_maps);
	chunk_size = sizeof(struct virtchnl2_queue_vector);

	num_chunks = IDPF_NUM_CHUNKS_PER_MSG(config_data_size, chunk_size) + 1;
	if (num_q < num_chunks)
		num_chunks = num_q;

	num_msgs = num_q / num_chunks;
	if (num_q % num_chunks)
		num_msgs++;

	for (i = 0, k = 0; i < num_msgs; i++) {
		if (!vqvm || alloc) {
			buf_size = (chunk_size * (num_chunks - 1)) +
					config_data_size;
			kfree(vqvm);
			vqvm = kzalloc(buf_size, GFP_KERNEL);
			if (!vqvm) {
				err = -ENOMEM;
				goto error;
			}
		} else {
			memset(vqvm, 0, buf_size);
		}
		vqvm->vport_id = cpu_to_le32(vport->vport_id);
		vqvm->num_qv_maps = cpu_to_le16(num_chunks);
		memcpy(vqvm->qv_maps, &vqv[k], chunk_size * num_chunks);

		if (map) {
			err = idpf_send_mb_msg(adapter,
					       VIRTCHNL2_OP_MAP_QUEUE_VECTOR,
					       buf_size, (u8 *)vqvm);
			if (!err)
				err = idpf_wait_for_event(adapter, vport,
							  IDPF_VC_MAP_IRQ,
							  IDPF_VC_MAP_IRQ_ERR);
		} else {
			err = idpf_send_mb_msg(adapter,
					       VIRTCHNL2_OP_UNMAP_QUEUE_VECTOR,
					       buf_size, (u8 *)vqvm);
			if (!err)
				err =
				idpf_min_wait_for_event(adapter, vport,
							IDPF_VC_UNMAP_IRQ,
							IDPF_VC_UNMAP_IRQ_ERR);
		}
		if (err)
			goto mbx_error;

		k += num_chunks;
		num_q -= num_chunks;
		if (num_q < num_chunks) {
			num_chunks = num_q;
			alloc = true;
		}
		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);
	}
mbx_error:
	kfree(vqvm);
error:
	kfree(vqv);
	return err;
}

/**
 * idpf_send_enable_queues_msg - send enable queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send enable queues virtchnl message.  Returns 0 on success, negative on
 * failure.
 */
int idpf_send_enable_queues_msg(struct idpf_vport *vport)
{
	return idpf_send_ena_dis_queues_msg(vport, VIRTCHNL2_OP_ENABLE_QUEUES);
}

/**
 * idpf_send_disable_queues_msg - send disable queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send disable queues virtchnl message.  Returns 0 on success, negative
 * on failure.
 */
int idpf_send_disable_queues_msg(struct idpf_vport *vport)
{
	int err, i;

	err = idpf_send_ena_dis_queues_msg(vport, VIRTCHNL2_OP_DISABLE_QUEUES);
	if (err)
		return err;

	/* switch to poll mode as interrupts will be disabled after disable
	 * queues virtchnl message is sent
	 */
	for (i = 0; i < vport->num_txq; i++)
		set_bit(__IDPF_Q_POLL_MODE, vport->txqs[i]->flags);

	/* schedule the napi to receive all the marker packets */
	for (i = 0; i < vport->num_q_vectors; i++)
		napi_schedule(&vport->q_vectors[i].napi);

	return idpf_wait_for_marker_event(vport);
}

/**
 * idpf_convert_reg_to_queue_chunks - Copy queue chunk information to the right
 * structure
 * @dchunks: Destination chunks to store data to
 * @schunks: Source chunks to copy data from
 * @num_chunks: number of chunks to copy
 */
static void
idpf_convert_reg_to_queue_chunks(struct virtchnl2_queue_chunk *dchunks,
				 struct virtchnl2_queue_reg_chunk *schunks,
				 u16 num_chunks)
{
	u16 i;

	for (i = 0; i < num_chunks; i++) {
		dchunks[i].type = schunks[i].type;
		dchunks[i].start_queue_id = schunks[i].start_queue_id;
		dchunks[i].num_queues = schunks[i].num_queues;
	}
}

/**
 * idpf_send_delete_queues_msg - send delete queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send delete queues virtchnl message. Return 0 on success, negative on
 * failure.
 */
int idpf_send_delete_queues_msg(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_create_vport *vport_params;
	struct virtchnl2_queue_reg_chunks *chunks;
	struct virtchnl2_del_ena_dis_queues *eq;
	struct idpf_vport_config *vport_config;
	u16 vport_idx = vport->idx;
	int buf_size, err;
	u16 num_chunks;

	vport_config = adapter->vport_config[vport_idx];
	if (vport_config->req_qs_chunks) {
		struct virtchnl2_add_queues *vc_aq =
			(struct virtchnl2_add_queues *)vport_config->req_qs_chunks;
		chunks = &vc_aq->chunks;
	} else {
		vport_params = (struct virtchnl2_create_vport *)
				vport->adapter->vport_params_recvd[vport_idx];
		chunks = &vport_params->chunks;
	}

	num_chunks = le16_to_cpu(chunks->num_chunks);
	buf_size = sizeof(struct virtchnl2_del_ena_dis_queues) +
			  (sizeof(struct virtchnl2_queue_chunk) *
			  (num_chunks - 1));

	eq = kzalloc(buf_size, GFP_KERNEL);
	if (!eq)
		return -ENOMEM;

	eq->vport_id = cpu_to_le32(vport->vport_id);
	eq->chunks.num_chunks = cpu_to_le16(num_chunks);

	idpf_convert_reg_to_queue_chunks(eq->chunks.chunks, chunks->chunks,
					 num_chunks);

	err = idpf_send_mb_msg(vport->adapter, VIRTCHNL2_OP_DEL_QUEUES,
			       buf_size, (u8 *)eq);
	if (err)
		goto error;

	err = idpf_min_wait_for_event(adapter, vport, IDPF_VC_DEL_QUEUES,
				      IDPF_VC_DEL_QUEUES_ERR);
	if (!err)
		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);

error:
	kfree(eq);
	return err;
}

/**
 * idpf_send_config_queues_msg - Send config queues virtchnl message
 * @vport: Virtual port private data structure
 *
 * Will send config queues virtchnl message. Returns 0 on success, negative on
 * failure.
 */
int idpf_send_config_queues_msg(struct idpf_vport *vport)
{
	int err;

	err = idpf_send_config_tx_queues_msg(vport);
	if (err)
		return err;

	return idpf_send_config_rx_queues_msg(vport);
}

/**
 * idpf_send_add_queues_msg - Send virtchnl add queues message
 * @vport: Virtual port private data structure
 * @num_tx_q: number of transmit queues
 * @num_complq: number of transmit completion queues
 * @num_rx_q: number of receive queues
 * @num_rx_bufq: number of receive buffer queues
 *
 * Returns 0 on success, negative on failure. vport _MUST_ be const here as
 * we should not change any fields within vport itself in this function.
 */
int idpf_send_add_queues_msg(const struct idpf_vport *vport, u16 num_tx_q,
			     u16 num_complq, u16 num_rx_q, u16 num_rx_bufq)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	struct virtchnl2_add_queues aq = {0};
	struct virtchnl2_add_queues *vc_msg;
	u16 vport_idx = vport->idx;
	int size, err;

	vport_config = adapter->vport_config[vport_idx];

	aq.vport_id = cpu_to_le32(vport->vport_id);
	aq.num_tx_q = cpu_to_le16(num_tx_q);
	aq.num_tx_complq = cpu_to_le16(num_complq);
	aq.num_rx_q = cpu_to_le16(num_rx_q);
	aq.num_rx_bufq = cpu_to_le16(num_rx_bufq);

	err = idpf_send_mb_msg(adapter,
			       VIRTCHNL2_OP_ADD_QUEUES,
			       sizeof(struct virtchnl2_add_queues), (u8 *)&aq);
	if (err)
		return err;

	/* We want vport to be const to prevent incidental code changes making
	 * changes to the vport config. We're making a special exception here
	 * to discard const to use the virtchnl.
	 */
	err = idpf_wait_for_event(adapter, (struct idpf_vport *)vport,
				  IDPF_VC_ADD_QUEUES, IDPF_VC_ADD_QUEUES_ERR);
	if (err)
		return err;

	kfree(vport_config->req_qs_chunks);
	vport_config->req_qs_chunks = NULL;

	vc_msg = (struct virtchnl2_add_queues *)vport->vc_msg;
	/* compare vc_msg num queues with vport num queues */
	if (le16_to_cpu(vc_msg->num_tx_q) != num_tx_q ||
	    le16_to_cpu(vc_msg->num_rx_q) != num_rx_q ||
	    le16_to_cpu(vc_msg->num_tx_complq) != num_complq ||
	    le16_to_cpu(vc_msg->num_rx_bufq) != num_rx_bufq) {
		err = -EINVAL;
		goto error;
	}

	size = sizeof(struct virtchnl2_add_queues) +
			((le16_to_cpu(vc_msg->chunks.num_chunks) - 1) *
			sizeof(struct virtchnl2_queue_reg_chunk));
	vport_config->req_qs_chunks = kzalloc(size, GFP_KERNEL);
	if (!vport_config->req_qs_chunks) {
		err = -ENOMEM;
		goto error;
	}
	memcpy(vport_config->req_qs_chunks, vc_msg, size);
error:
	clear_bit(__IDPF_VPORT_VC_MSG_PENDING,
		  ((struct idpf_vport *)vport)->flags);
	return err;
}

/**
 * idpf_send_alloc_vectors_msg - Send virtchnl alloc vectors message
 * @adapter: Driver specific private structure
 * @num_vectors: number of vectors to be allocated
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_alloc_vectors_msg(struct idpf_adapter *adapter, u16 num_vectors)
{
	struct virtchnl2_alloc_vectors *alloc_vec, *rcvd_vec;
	struct virtchnl2_alloc_vectors ac = {0};
	u16 num_vchunks;
	int size, err;

	ac.num_vectors = cpu_to_le16(num_vectors);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_ALLOC_VECTORS,
			       sizeof(ac), (u8 *)&ac);
	if (err)
		return err;

	err = idpf_wait_for_event(adapter, NULL, IDPF_VC_ALLOC_VECTORS,
				  IDPF_VC_ALLOC_VECTORS_ERR);
	if (err)
		return err;

	rcvd_vec = (struct virtchnl2_alloc_vectors *)adapter->vc_msg;
	num_vchunks = le16_to_cpu(rcvd_vec->vchunks.num_vchunks);

	size = sizeof(struct virtchnl2_alloc_vectors) +
		((num_vchunks - 1) * sizeof(struct virtchnl2_vector_chunk));

	if (size > sizeof(adapter->vc_msg)) {
		err = -EINVAL;
		goto error;
	}

	kfree(adapter->req_vec_chunks);
	adapter->req_vec_chunks = NULL;
	adapter->req_vec_chunks = kzalloc(size, GFP_KERNEL);
	if (!adapter->req_vec_chunks) {
		err = -ENOMEM;
		goto error;
	}
	memcpy(adapter->req_vec_chunks, adapter->vc_msg, size);

	alloc_vec = adapter->req_vec_chunks;
	if (le16_to_cpu(alloc_vec->num_vectors) < num_vectors) {
		kfree(adapter->req_vec_chunks);
		adapter->req_vec_chunks = NULL;
		err = -EINVAL;
	}
error:
	clear_bit(__IDPF_VC_MSG_PENDING, adapter->flags);
	return err;
}

/**
 * idpf_send_dealloc_vectors_msg - Send virtchnl de allocate vectors message
 * @adapter: Driver specific private structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_dealloc_vectors_msg(struct idpf_adapter *adapter)
{
	struct virtchnl2_vector_chunks *vcs;
	struct virtchnl2_alloc_vectors *ac;
	int buf_size, err;

	ac = adapter->req_vec_chunks;
	vcs = &ac->vchunks;

	buf_size = sizeof(struct virtchnl2_vector_chunks) +
			((le16_to_cpu(vcs->num_vchunks) - 1) *
			sizeof(struct virtchnl2_vector_chunk));

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_DEALLOC_VECTORS, buf_size,
			       (u8 *)vcs);
	if (err)
		return err;
	err = idpf_min_wait_for_event(adapter, NULL, IDPF_VC_DEALLOC_VECTORS,
				      IDPF_VC_DEALLOC_VECTORS_ERR);
	if (err)
		return err;

	kfree(adapter->req_vec_chunks);
	adapter->req_vec_chunks = NULL;
	clear_bit(__IDPF_VC_MSG_PENDING, adapter->flags);
	return err;
}

/**
 * idpf_get_max_vfs - Get max number of vfs supported
 * @adapter: Driver specific private structure
 *
 * Returns max number of VFs
 */
int idpf_get_max_vfs(struct idpf_adapter *adapter)
{
	return le16_to_cpu(adapter->caps.max_sriov_vfs);
}

/**
 * idpf_send_set_sriov_vfs_msg - Send virtchnl set sriov vfs message
 * @adapter: Driver specific private structure
 * @num_vfs: number of virtual functions to be created
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_set_sriov_vfs_msg(struct idpf_adapter *adapter, u16 num_vfs)
{
	struct virtchnl2_sriov_vfs_info svi = {0};
	int err;

	svi.num_vfs = cpu_to_le16(num_vfs);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_SET_SRIOV_VFS,
			       sizeof(svi), (u8 *)&svi);
	if (err)
		return err;

	err = idpf_wait_for_event(adapter, NULL, IDPF_VC_SET_SRIOV_VFS,
				  IDPF_VC_SET_SRIOV_VFS_ERR);
	if (!err)
		clear_bit(__IDPF_VC_MSG_PENDING, adapter->flags);

	return err;
}

/**
 * idpf_send_get_stats_msg - Send virtchnl get statistics message
 * @vport: vport to get stats for
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_stats_msg(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_vport_stats stats_msg = {0};
	struct virtchnl2_vport_stats *stats;
	int err = 0;

	/* Don't send get_stats message if the link is down */
	if (vport->state <= __IDPF_VPORT_DOWN)
		return err;

	stats_msg.vport_id = cpu_to_le32(vport->vport_id);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_GET_STATS,
			       sizeof(struct virtchnl2_vport_stats),
			       (u8 *)&stats_msg);
	if (err)
		return err;

	err = idpf_wait_for_event(adapter, vport, IDPF_VC_GET_STATS,
				  IDPF_VC_GET_STATS_ERR);
	if (err)
		return err;

	stats = (struct virtchnl2_vport_stats *)vport->vc_msg;

	vport->netstats.rx_packets = le64_to_cpu(stats->rx_unicast) +
				     le64_to_cpu(stats->rx_multicast) +
				     le64_to_cpu(stats->rx_broadcast);
	vport->netstats.rx_bytes = le64_to_cpu(stats->rx_bytes);
	vport->netstats.rx_dropped = le64_to_cpu(stats->rx_discards);
	vport->netstats.rx_over_errors = le64_to_cpu(stats->rx_overflow_drop);
	vport->netstats.rx_length_errors = le64_to_cpu(stats->rx_invalid_frame_length);

	vport->netstats.tx_packets = le64_to_cpu(stats->tx_unicast) +
				     le64_to_cpu(stats->tx_multicast) +
				     le64_to_cpu(stats->tx_broadcast);
	vport->netstats.tx_bytes = le64_to_cpu(stats->tx_bytes);
	vport->netstats.tx_errors = le64_to_cpu(stats->tx_errors);
	vport->netstats.tx_dropped = le64_to_cpu(stats->tx_discards);

	vport->port_stats.vport_stats = *stats;

	clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);

	return err;
}

/**
 * idpf_send_get_set_rss_hash_msg - Send set or get rss hash message
 * @vport: virtual port data structure
 * @get: flag to get or set rss hash
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_set_rss_hash_msg(struct idpf_vport *vport, bool get)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_rss_hash rh = {0};
	struct idpf_rss_data *rss_data;
	int err;

	rss_data = &adapter->vport_config[vport->idx]->user_config.rss_data;
	rh.vport_id = cpu_to_le32(vport->vport_id);
	rh.ptype_groups = cpu_to_le64(rss_data->rss_hash);

	if (!get)
		goto do_set;

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_GET_RSS_HASH,
			       sizeof(rh), (u8 *)&rh);
	if (err)
		return err;

	err = idpf_wait_for_event(adapter, vport, IDPF_VC_GET_RSS_HASH,
				  IDPF_VC_GET_RSS_HASH_ERR);
	if (err)
		return err;

	memcpy(&rh, vport->vc_msg, sizeof(rh));
	rss_data->rss_hash = le64_to_cpu(rh.ptype_groups);
	/* Leave the buffer clean for next message */
	memset(vport->vc_msg, 0, IDPF_DFLT_MBX_BUF_SIZE);
	clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);

	return 0;

do_set:
	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_SET_RSS_HASH,
			       sizeof(rh), (u8 *)&rh);
	if (err)
		return err;

	err = idpf_wait_for_event(adapter, vport, IDPF_VC_SET_RSS_HASH,
				  IDPF_VC_SET_RSS_HASH_ERR);
	if (!err)
		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);

	return err;
}

/**
 * idpf_send_get_set_rss_lut_msg - Send virtchnl get or set rss lut message
 * @vport: virtual port data structure
 * @get: flag to set or get rss look up table
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_set_rss_lut_msg(struct idpf_vport *vport, bool get)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_rss_lut *recv_rl;
	struct idpf_rss_data *rss_data;
	struct virtchnl2_rss_lut *rl;
	int buf_size, lut_buf_size;
	int i, err = 0;

	rss_data = &adapter->vport_config[vport->idx]->user_config.rss_data;
	buf_size = sizeof(struct virtchnl2_rss_lut) +
		       (sizeof(u32) * (rss_data->rss_lut_size - 1));
	rl = kzalloc(buf_size, GFP_KERNEL);
	if (!rl)
		return -ENOMEM;

	rl->vport_id = cpu_to_le32(vport->vport_id);
	if (!get) {
		rl->lut_entries = cpu_to_le16(rss_data->rss_lut_size);
		for (i = 0; i < rss_data->rss_lut_size; i++)
			rl->lut[i] = cpu_to_le32(rss_data->rss_lut[i]);

		err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_SET_RSS_LUT,
				       buf_size, (u8 *)rl);
		if (err)
			goto done;
	
		err = idpf_wait_for_event(adapter, vport, IDPF_VC_SET_RSS_LUT,
					  IDPF_VC_SET_RSS_LUT_ERR);
		if (!err)
			clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);

		goto done;
	}

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_GET_RSS_LUT,
			       buf_size, (u8 *)rl);
	if (err)
		goto done;

	err = idpf_wait_for_event(adapter, vport, IDPF_VC_GET_RSS_LUT,
				  IDPF_VC_GET_RSS_LUT_ERR);
	if (err)
		goto done;

	recv_rl = (struct virtchnl2_rss_lut *)vport->vc_msg;
	if (rss_data->rss_lut_size == le16_to_cpu(recv_rl->lut_entries))
		goto do_memcpy;

	rss_data->rss_lut_size = le16_to_cpu(recv_rl->lut_entries);
	kfree(rss_data->rss_lut);

	lut_buf_size = rss_data->rss_lut_size * sizeof(u32);
	rss_data->rss_lut = kzalloc(lut_buf_size, GFP_KERNEL);
	if (!rss_data->rss_lut) {
		rss_data->rss_lut_size = 0;
		/* Leave the buffer clean */
		memset(vport->vc_msg, 0, IDPF_DFLT_MBX_BUF_SIZE);
		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);
		err = -ENOMEM;
		goto done;
	}

do_memcpy:
	memcpy(rss_data->rss_lut, vport->vc_msg, rss_data->rss_lut_size);
	/* Leave the buffer clean for next message */
	memset(vport->vc_msg, 0, IDPF_DFLT_MBX_BUF_SIZE);
	clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);

done:
	kfree(rl);
	return err;
}

/**
 * idpf_send_get_set_rss_key_msg - Send virtchnl get or set rss key message
 * @vport: virtual port data structure
 * @get: flag to set or get rss look up table
 *
 * Returns 0 on success, negative on failure
 */
int idpf_send_get_set_rss_key_msg(struct idpf_vport *vport, bool get)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_rss_key *recv_rk;
	struct idpf_rss_data *rss_data;
	struct virtchnl2_rss_key *rk;
	int i, buf_size, err = 0;

	rss_data = &adapter->vport_config[vport->idx]->user_config.rss_data;
	buf_size = sizeof(struct virtchnl2_rss_key) +
		       (sizeof(u8) * (rss_data->rss_key_size - 1));
	rk = kzalloc(buf_size, GFP_KERNEL);
	if (!rk)
		return -ENOMEM;
	rk->vport_id = cpu_to_le32(vport->vport_id);

	if (get) {
		err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_GET_RSS_KEY,
				       buf_size, (u8 *)rk);
		if (err)
			goto error;

		err = idpf_wait_for_event(adapter, vport, IDPF_VC_GET_RSS_KEY,
					  IDPF_VC_GET_RSS_KEY_ERR);
		if (err)
			goto error;

		recv_rk = (struct virtchnl2_rss_key *)vport->vc_msg;
		if (rss_data->rss_key_size !=
		    le16_to_cpu(recv_rk->key_len)) {
			rss_data->rss_key_size =
				min_t(u16, NETDEV_RSS_KEY_LEN,
				      le16_to_cpu(recv_rk->key_len));
			kfree(rss_data->rss_key);
			rss_data->rss_key = kzalloc(rss_data->rss_key_size,
						    GFP_KERNEL);
			if (!rss_data->rss_key) {
				rss_data->rss_key_size = 0;
				/* Leave the buffer clean */
				memset(vport->vc_msg, 0,
				       IDPF_DFLT_MBX_BUF_SIZE);
				clear_bit(__IDPF_VPORT_VC_MSG_PENDING,
					  vport->flags);
				err = -ENOMEM;
				goto error;
			}
		}
		memcpy(rss_data->rss_key, vport->vc_msg,
		       rss_data->rss_key_size);
		/* Leave the buffer clean for next message */
		memset(vport->vc_msg, 0, IDPF_DFLT_MBX_BUF_SIZE);
		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);
	} else {
		rk->key_len = cpu_to_le16(rss_data->rss_key_size);
		for (i = 0; i < rss_data->rss_key_size; i++)
			rk->key[i] = rss_data->rss_key[i];

		err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_SET_RSS_KEY,
				       buf_size, (u8 *)rk);
		if (err)
			goto error;

		err = idpf_wait_for_event(adapter, vport, IDPF_VC_SET_RSS_KEY,
					  IDPF_VC_SET_RSS_KEY_ERR);
		if (!err)
			clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);
	}
error:
	kfree(rk);
	return err;
}

/**
 * idpf_fill_ptype_lookup - Fill L3 specific fields in ptype lookup table
 * @ptype: ptype lookup table
 * @pstate: state machine for ptype lookup table
 * @ipv4: ipv4 or ipv6
 * @frag: fragmentation allowed
 *
 */
static void idpf_fill_ptype_lookup(struct idpf_rx_ptype_decoded *ptype,
				   struct idpf_ptype_state *pstate,
				   bool ipv4, bool frag)
{
	if (!pstate->outer_ip || !pstate->outer_frag) {
		ptype->outer_ip = IDPF_RX_PTYPE_OUTER_IP;
		pstate->outer_ip = true;

		if (ipv4)
			ptype->outer_ip_ver = IDPF_RX_PTYPE_OUTER_IPV4;
		else
			ptype->outer_ip_ver = IDPF_RX_PTYPE_OUTER_IPV6;

		if (frag) {
			ptype->outer_frag = IDPF_RX_PTYPE_FRAG;
			pstate->outer_frag = true;
		}
	} else {
		ptype->tunnel_type = IDPF_RX_PTYPE_TUNNEL_IP_IP;
		pstate->tunnel_state = IDPF_PTYPE_TUNNEL_IP;

		if (ipv4)
			ptype->tunnel_end_prot =
					IDPF_RX_PTYPE_TUNNEL_END_IPV4;
		else
			ptype->tunnel_end_prot =
					IDPF_RX_PTYPE_TUNNEL_END_IPV6;

		if (frag)
			ptype->tunnel_end_frag = IDPF_RX_PTYPE_FRAG;
	}
}

/**
 * idpf_send_get_rx_ptype_msg - Send virtchnl for ptype info
 * @vport: virtual port data structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_get_rx_ptype_msg(struct idpf_vport *vport)
{
	struct idpf_rx_ptype_decoded *ptype_lkup = vport->rx_ptype_lkup;
	struct virtchnl2_get_ptype_info *get_ptype_info, *ptype_info;
	int max_ptype, ptypes_recvd = 0, len, ptype_offset;
	struct idpf_adapter *adapter = vport->adapter;
	int err = 0, i, j, k = 0;

	if (idpf_is_queue_model_split(vport->rxq_model))
		max_ptype = IDPF_RX_MAX_PTYPE;
	else
		max_ptype = IDPF_RX_MAX_BASE_PTYPE;

	memset(vport->rx_ptype_lkup, 0, sizeof(vport->rx_ptype_lkup));

	len = sizeof(struct virtchnl2_get_ptype_info);
	get_ptype_info = kzalloc(len, GFP_KERNEL);
	if (!get_ptype_info)
		return -ENOMEM;

	get_ptype_info->start_ptype_id = 0;
	get_ptype_info->num_ptypes = cpu_to_le16(max_ptype);

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_GET_PTYPE_INFO,
			       len, (u8 *)get_ptype_info);
	if (err)
		goto get_ptype_rel;

	while (ptypes_recvd < max_ptype) {
		err = idpf_wait_for_event(adapter, NULL, IDPF_VC_GET_PTYPE_INFO,
					  IDPF_VC_GET_PTYPE_INFO_ERR);
		if (err)
			goto get_ptype_rel;

		len = IDPF_DFLT_MBX_BUF_SIZE;
		ptype_info = kzalloc(len, GFP_KERNEL);
		if (!ptype_info) {
			err = -ENOMEM;
			goto clear_vc_flag;
		}

		memcpy(ptype_info, adapter->vc_msg, len);

		ptypes_recvd += le16_to_cpu(ptype_info->num_ptypes);
		if (ptypes_recvd > max_ptype) {
			err = -EINVAL;
			goto ptype_rel;
		}

		ptype_offset = sizeof(struct virtchnl2_get_ptype_info) -
						sizeof(struct virtchnl2_ptype);

		for (i = 0; i < le16_to_cpu(ptype_info->num_ptypes); i++) {
			struct idpf_ptype_state pstate = { 0 };
			struct virtchnl2_ptype *ptype;
			u16 id;

			ptype = (struct virtchnl2_ptype *)
					((u8 *)ptype_info + ptype_offset);

			ptype_offset += IDPF_GET_PTYPE_SIZE(ptype);
			if (ptype_offset > len) {
				err = -EINVAL;
				goto ptype_rel;
			}

			if (le16_to_cpu(ptype->ptype_id_10) == 0xFFFF)
				goto ptype_rel;

			if (idpf_is_queue_model_split(vport->rxq_model))
				k = le16_to_cpu(ptype->ptype_id_10);
			else
				k = ptype->ptype_id_8;

			if (ptype->proto_id_count)
				ptype_lkup[k].known = 1;

			for (j = 0; j < ptype->proto_id_count; j++) {
				id = le16_to_cpu(ptype->proto_id[j]);
				switch (id) {
				case VIRTCHNL2_PROTO_HDR_GRE:
					if (pstate.tunnel_state ==
							IDPF_PTYPE_TUNNEL_IP) {
						ptype_lkup[k].tunnel_type =
						IDPF_RX_PTYPE_TUNNEL_IP_GRENAT;
						pstate.tunnel_state |=
						IDPF_PTYPE_TUNNEL_IP_GRENAT;
					}
					break;
				case VIRTCHNL2_PROTO_HDR_MAC:
					ptype_lkup[k].outer_ip =
						IDPF_RX_PTYPE_OUTER_L2;
					if (pstate.tunnel_state ==
							IDPF_TUN_IP_GRE) {
						ptype_lkup[k].tunnel_type =
						IDPF_RX_PTYPE_TUNNEL_IP_GRENAT_MAC;
						pstate.tunnel_state |=
						IDPF_PTYPE_TUNNEL_IP_GRENAT_MAC;
					}
					break;
				case VIRTCHNL2_PROTO_HDR_IPV4:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, true,
							       false);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV6:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, false,
							       false);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV4_FRAG:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, true,
							       true);
					break;
				case VIRTCHNL2_PROTO_HDR_IPV6_FRAG:
					idpf_fill_ptype_lookup(&ptype_lkup[k],
							       &pstate, false,
							       true);
					break;
				case VIRTCHNL2_PROTO_HDR_UDP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_UDP;
					break;
				case VIRTCHNL2_PROTO_HDR_TCP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_TCP;
					break;
				case VIRTCHNL2_PROTO_HDR_SCTP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_SCTP;
					break;
				case VIRTCHNL2_PROTO_HDR_ICMP:
					ptype_lkup[k].inner_prot =
					IDPF_RX_PTYPE_INNER_PROT_ICMP;
					break;
				case VIRTCHNL2_PROTO_HDR_PAY:
					ptype_lkup[k].payload_layer =
						IDPF_RX_PTYPE_PAYLOAD_LAYER_PAY2;
					break;
				case VIRTCHNL2_PROTO_HDR_ICMPV6:
				case VIRTCHNL2_PROTO_HDR_IPV6_EH:
				case VIRTCHNL2_PROTO_HDR_PRE_MAC:
				case VIRTCHNL2_PROTO_HDR_POST_MAC:
				case VIRTCHNL2_PROTO_HDR_ETHERTYPE:
				case VIRTCHNL2_PROTO_HDR_SVLAN:
				case VIRTCHNL2_PROTO_HDR_CVLAN:
				case VIRTCHNL2_PROTO_HDR_MPLS:
				case VIRTCHNL2_PROTO_HDR_MMPLS:
				case VIRTCHNL2_PROTO_HDR_PTP:
				case VIRTCHNL2_PROTO_HDR_CTRL:
				case VIRTCHNL2_PROTO_HDR_LLDP:
				case VIRTCHNL2_PROTO_HDR_ARP:
				case VIRTCHNL2_PROTO_HDR_ECP:
				case VIRTCHNL2_PROTO_HDR_EAPOL:
				case VIRTCHNL2_PROTO_HDR_PPPOD:
				case VIRTCHNL2_PROTO_HDR_PPPOE:
				case VIRTCHNL2_PROTO_HDR_IGMP:
				case VIRTCHNL2_PROTO_HDR_AH:
				case VIRTCHNL2_PROTO_HDR_ESP:
				case VIRTCHNL2_PROTO_HDR_IKE:
				case VIRTCHNL2_PROTO_HDR_NATT_KEEP:
				case VIRTCHNL2_PROTO_HDR_L2TPV2:
				case VIRTCHNL2_PROTO_HDR_L2TPV2_CONTROL:
				case VIRTCHNL2_PROTO_HDR_L2TPV3:
				case VIRTCHNL2_PROTO_HDR_GTP:
				case VIRTCHNL2_PROTO_HDR_GTP_EH:
				case VIRTCHNL2_PROTO_HDR_GTPCV2:
				case VIRTCHNL2_PROTO_HDR_GTPC_TEID:
				case VIRTCHNL2_PROTO_HDR_GTPU:
				case VIRTCHNL2_PROTO_HDR_GTPU_UL:
				case VIRTCHNL2_PROTO_HDR_GTPU_DL:
				case VIRTCHNL2_PROTO_HDR_ECPRI:
				case VIRTCHNL2_PROTO_HDR_VRRP:
				case VIRTCHNL2_PROTO_HDR_OSPF:
				case VIRTCHNL2_PROTO_HDR_TUN:
				case VIRTCHNL2_PROTO_HDR_NVGRE:
				case VIRTCHNL2_PROTO_HDR_VXLAN:
				case VIRTCHNL2_PROTO_HDR_VXLAN_GPE:
				case VIRTCHNL2_PROTO_HDR_GENEVE:
				case VIRTCHNL2_PROTO_HDR_NSH:
				case VIRTCHNL2_PROTO_HDR_QUIC:
				case VIRTCHNL2_PROTO_HDR_PFCP:
				case VIRTCHNL2_PROTO_HDR_PFCP_NODE:
				case VIRTCHNL2_PROTO_HDR_PFCP_SESSION:
				case VIRTCHNL2_PROTO_HDR_RTP:
				case VIRTCHNL2_PROTO_HDR_NO_PROTO:
				default:
					continue;
				}
			}
		}
		clear_bit(__IDPF_VC_MSG_PENDING, adapter->flags);
		kfree(ptype_info);
	}
	kfree(get_ptype_info);
	return 0;

ptype_rel:
	kfree(ptype_info);
clear_vc_flag:
	clear_bit(__IDPF_VC_MSG_PENDING, adapter->flags);
get_ptype_rel:
	kfree(get_ptype_info);
	return err;
}

/**
 * idpf_send_ena_dis_loopback_msg - Send virtchnl enable/disable loopback message
 * @vport: virtual port data structure
 *
 * Returns 0 on success, negative on failure.
 */
int idpf_send_ena_dis_loopback_msg(struct idpf_vport *vport)
{
	struct virtchnl2_loopback loopback;
	int err = 0;

	loopback.vport_id = cpu_to_le32(vport->vport_id);
	loopback.enable = idpf_is_feature_ena(vport, NETIF_F_LOOPBACK);

	err = idpf_send_mb_msg(vport->adapter, VIRTCHNL2_OP_LOOPBACK,
			       sizeof(loopback), (u8 *)&loopback);
	if (err)
		return err;

	err = idpf_wait_for_event(vport->adapter, vport,
				  IDPF_VC_LOOPBACK_STATE,
				  IDPF_VC_LOOPBACK_STATE_ERR);
	if (!err)
		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);

	return err;
}

/**
 * idpf_send_create_adi_msg - Send virtchnl create ADI message
 * @adapter: adapter info struct
 * @vchnl_adi: pointer to create ADI struct
 *
 * Send create ADI virtchnl message and receive the result.
 * Returns 0 on success, negative on failure.
 */
int idpf_send_create_adi_msg(struct idpf_adapter *adapter,
			     struct virtchnl2_create_adi *vchnl_adi)
{
	int err = 0;

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_CREATE_ADI,
			       sizeof(*vchnl_adi), (u8 *)vchnl_adi);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to send create ADI\n");
		return err;
	}

	err = idpf_wait_for_event(adapter, NULL, IDPF_VC_CREATE_ADI,
				  IDPF_VC_CREATE_ADI_ERR);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed wait for create ADI\n");
		return err;
	}

	/* once reply is received get it from adapter->vc_msg */
	memcpy(vchnl_adi, adapter->vc_msg, IDPF_DFLT_MBX_BUF_SIZE);

	clear_bit(__IDPF_VC_MSG_PENDING, adapter->flags);

	return 0;
}

/**
 * idpf_send_destroy_adi_msg - Send virtchnl enable  message
 * @adapter: adapter info struct
 * @vchnl_adi: pointer to destroy ADI struct
 *
 * Send destroy ADI virtchnl message and receive the result.
 * Returns 0 on success, negative on failure.
 */
int idpf_send_destroy_adi_msg(struct idpf_adapter *adapter,
			      struct virtchnl2_destroy_adi *vchnl_adi)
{
	int err = 0;

	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_DESTROY_ADI,
			       sizeof(vchnl_adi), (u8 *)vchnl_adi);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to send destroy ADI\n");
		return err;
	}

	err = idpf_wait_for_event(adapter, NULL, IDPF_VC_DESTROY_ADI,
				  IDPF_VC_DESTROY_ADI_ERR);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed the wait for destroy ADI\n");
		return err;
	}

	clear_bit(__IDPF_VC_MSG_PENDING, adapter->flags);

	return 0;
}

/**
 * idpf_find_ctlq - Given a type and id, find ctlq info
 * @hw: hardware struct
 * @type: type of ctrlq to find
 * @id: ctlq id to find
 *
 * Returns pointer to found ctlq info struct, NULL otherwise.
 */
static struct idpf_ctlq_info *idpf_find_ctlq(struct idpf_hw *hw,
					     enum idpf_ctlq_type type, int id)
{
	struct idpf_ctlq_info *cq, *tmp;

	list_for_each_entry_safe(cq, tmp, &hw->cq_list_head, cq_list)
		if (cq->q_id == id && cq->cq_type == type)
			return cq;

	return NULL;
}

/**
 * idpf_init_dflt_mbx - Setup default mailbox parameters and make request
 * @adapter: adapter info struct
 *
 * Returns 0 on success, negative otherwise
 */
int idpf_init_dflt_mbx(struct idpf_adapter *adapter)
{
	struct idpf_ctlq_create_info ctlq_info[] = {
		{
			.type = IDPF_CTLQ_TYPE_MAILBOX_TX,
			.id = IDPF_DFLT_MBX_ID,
			.len = IDPF_DFLT_MBX_Q_LEN,
			.buf_size = IDPF_DFLT_MBX_BUF_SIZE
		},
		{
			.type = IDPF_CTLQ_TYPE_MAILBOX_RX,
			.id = IDPF_DFLT_MBX_ID,
			.len = IDPF_DFLT_MBX_Q_LEN,
			.buf_size = IDPF_DFLT_MBX_BUF_SIZE
		}
	};
	struct idpf_hw *hw = &adapter->hw;
	int err;

	adapter->dev_ops.reg_ops.ctlq_reg_init(ctlq_info);

#define NUM_Q 2
	err = idpf_ctlq_init(hw, NUM_Q, ctlq_info);
	if (err)
		return err;

	hw->asq = idpf_find_ctlq(hw, IDPF_CTLQ_TYPE_MAILBOX_TX,
				 IDPF_DFLT_MBX_ID);
	hw->arq = idpf_find_ctlq(hw, IDPF_CTLQ_TYPE_MAILBOX_RX,
				 IDPF_DFLT_MBX_ID);

	if (!hw->asq || !hw->arq) {
		idpf_ctlq_deinit(hw);
		return -ENOENT;
	}
	adapter->state = __IDPF_STARTUP;
	return 0;
}

/**
 * idpf_deinit_dflt_mbx - Free up ctlqs setup
 * @adapter: Driver specific private data structure
 */
void idpf_deinit_dflt_mbx(struct idpf_adapter *adapter)
{
	if (adapter->hw.arq && adapter->hw.asq) {
		idpf_mb_clean(adapter);
		idpf_ctlq_deinit(&adapter->hw);
	}
	adapter->hw.arq = NULL;
	adapter->hw.asq = NULL;
}

/**
 * idpf_vport_params_buf_alloc - Allocate memory for MailBox resources
 * @adapter: Driver specific private data structure
 *
 * Will alloc memory to hold the vport parameters received on MailBox
 */
static int idpf_vport_params_buf_alloc(struct idpf_adapter *adapter)
{
	u16 num_max_vports = idpf_get_max_vports(adapter);

	adapter->vport_params_reqd = kcalloc(num_max_vports,
					     sizeof(*adapter->vport_params_reqd),
					     GFP_KERNEL);
	if (!adapter->vport_params_reqd)
		return -ENOMEM;
	adapter->vport_params_recvd = kcalloc(num_max_vports,
					      sizeof(*adapter->vport_params_recvd),
					      GFP_KERNEL);
	if (!adapter->vport_params_recvd)
		goto err_mem;

	adapter->vport_ids = kcalloc(num_max_vports, sizeof(u32), GFP_KERNEL);
	if (!adapter->vport_ids)
		goto err_mem;

	if (adapter->vport_config)
		return 0;
	adapter->vport_config = kcalloc(num_max_vports,
					sizeof(*adapter->vport_config),
					GFP_KERNEL);
	if (!adapter->vport_config)
		goto err_mem;

	return 0;

err_mem:
	kfree(adapter->vport_params_recvd);
	adapter->vport_params_recvd = NULL;
	kfree(adapter->vport_params_reqd);
	adapter->vport_params_reqd = NULL;
	kfree(adapter->vport_ids);
	adapter->vport_ids = NULL;
	return -ENOMEM;
}

/**
 * idpf_vport_params_buf_rel - Release memory for MailBox resources
 * @adapter: Driver specific private data structure
 *
 * Will release memory to hold the vport parameters received on MailBox
 */
void idpf_vport_params_buf_rel(struct idpf_adapter *adapter)
{
	kfree(adapter->vport_params_recvd);
	adapter->vport_params_recvd = NULL;
	kfree(adapter->vport_params_reqd);
	adapter->vport_params_reqd = NULL;
	kfree(adapter->vport_ids);
	adapter->vport_ids = NULL;
}

/**
 * idpf_vc_core_init - Initialize state machine and get driver specific
 * resources
 * @adapter: Driver specific private structure
 *
 * This function will initialize the state machine and request all necessary
 * resources required by the device driver. Once the state machine is
 * initialized, allocate memory to store vport specific information and also
 * requests required interrupts.
 * 
 * Returns 0 on success, -EAGAIN function will get called again,
 * otherwise negative on failure.
 */
int idpf_vc_core_init(struct idpf_adapter *adapter)
{
	int task_delay = 30;
	u16 num_max_vports;
	int err = 0;

	while (adapter->state != __IDPF_INIT_SW) {
		switch (adapter->state) {
		case __IDPF_STARTUP:
			if (idpf_send_ver_msg(adapter))
				goto init_failed;
			adapter->state = __IDPF_VER_CHECK;
			goto restart;
		case __IDPF_VER_CHECK:
			err = idpf_recv_ver_msg(adapter);
			if (err == -EIO) {
				return err;
			} else if (err == -EAGAIN) {
				adapter->state = __IDPF_STARTUP;
				goto restart;
			} else if (err) {
				goto init_failed;
			}
			if (idpf_send_get_caps_msg(adapter))
				goto init_failed;
			adapter->state = __IDPF_GET_CAPS;
			goto restart;
		case __IDPF_GET_CAPS:
			if (idpf_recv_get_caps_msg(adapter))
				goto init_failed;
			adapter->state = __IDPF_INIT_SW;
			break;
		default:
			dev_err(&adapter->pdev->dev, "Device is in bad state: %d\n",
				adapter->state);
			goto init_failed;
		}
		break;
restart:
		/* Give enough time before proceeding further with
		 * state machine
		 */
		msleep(task_delay);
	}

	pci_sriov_set_totalvfs(adapter->pdev, idpf_get_max_vfs(adapter));
	num_max_vports = idpf_get_max_vports(adapter);
	adapter->max_vports = num_max_vports;
	adapter->vports = kcalloc(num_max_vports, sizeof(*adapter->vports),
				  GFP_KERNEL);
	if (!adapter->vports)
		return -ENOMEM;

	if (!adapter->netdevs) {
		adapter->netdevs = kcalloc(num_max_vports,
					   sizeof(struct net_device *),
					   GFP_KERNEL);
		if (!adapter->netdevs) {
			err = -ENOMEM;
			goto err_netdev_alloc;
		}
	}

	err = idpf_vport_params_buf_alloc(adapter);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to alloc vport params buffer: %d\n",
			err);
		goto err_buf_alloc;
	}

	/* Start the service task before requesting vectors. This will ensure
	 * vector information response from mailbox is handled
	 */
	queue_delayed_work(adapter->serv_wq, &adapter->serv_task,
			   msecs_to_jiffies(5 * (adapter->pdev->devfn & 0x07)));

	err = idpf_intr_req(adapter);
	if (err) {
		dev_err(&adapter->pdev->dev, "failed to enable interrupt vectors: %d\n",
			err);
		goto err_intr_req;
	}

	idpf_init_avail_queues(adapter);

	/* Skew the delay for init tasks for each function based on fn number
	 * to prevent every function from making the same call simulatenously.
	 */
	queue_delayed_work(adapter->init_wq, &adapter->init_task,
			   msecs_to_jiffies(5 * (adapter->pdev->devfn & 0x07)));

	goto no_err;

err_intr_req:
	cancel_delayed_work_sync(&adapter->serv_task);
	idpf_vport_params_buf_rel(adapter);
err_buf_alloc:
err_netdev_alloc:
	kfree(adapter->vports);
	adapter->vports = NULL;
no_err:
	return err;

init_failed:
	if (++adapter->mb_wait_count > IDPF_MB_MAX_ERR) {
		dev_err(&adapter->pdev->dev, "Failed to establish mailbox communications with hardware\n");
		return -EFAULT;
	}
	/* If it reached here, it is possible that mailbox queue initialization
	 * register writes might not have taken effect. Retry to initialize
	 * the mailbox again
	 */
	adapter->state = __IDPF_STARTUP;
	idpf_deinit_dflt_mbx(adapter);
	set_bit(__IDPF_HR_DRV_LOAD, adapter->flags);
	queue_delayed_work(adapter->vc_event_wq, &adapter->vc_event_task,
			   msecs_to_jiffies(task_delay));
	return -EAGAIN;
}

/**
 * idpf_vc_core_deinit - Device deinit routine
 * @adapter: Driver specific private structue
 *
 */
void idpf_vc_core_deinit(struct idpf_adapter *adapter)
{
	int i = 0;

	if (!adapter->vports)
		return;

	set_bit(__IDPF_REL_RES_IN_PROG, adapter->flags);

	idpf_deinit_task(adapter);
	idpf_intr_rel(adapter);
	/* Set all bits as we dont know on which vc_state the vhnl_wq is
	 * waiting on and wakeup the virtchnl workqueue even if it is waiting
	 * for the response as we are going down
	 */
	for (i = 0; i < IDPF_VC_NBITS; i++)
		set_bit(i, adapter->vc_state);
	wake_up(&adapter->vchnl_wq);

	/* Required to indicate periodic task not to schedule again */
	set_bit(__IDPF_CANCEL_SERVICE_TASK, adapter->flags);
	cancel_delayed_work_sync(&adapter->serv_task);
	clear_bit(__IDPF_CANCEL_SERVICE_TASK, adapter->flags);
	idpf_vport_params_buf_rel(adapter);
	/* Clear all the bits */
	for (i = 0; i < IDPF_VC_NBITS; i++)
		clear_bit(i, adapter->vc_state);

	kfree(adapter->vports);
	adapter->vports = NULL;
	clear_bit(__IDPF_REL_RES_IN_PROG, adapter->flags);
}

/**
 * idpf_vport_alloc_vec_indexes - Get relative vector indexes
 * @vport: virtual port data struct
 *
 * This function requests the vector information required for the vport and
 * stores the vector indexes received from the 'global vector distribution'
 * in the vport's queue vectors array.
 *
 * Return 0 on success, error on failure
 */
int idpf_vport_alloc_vec_indexes(struct idpf_vport *vport)
{
	struct idpf_vector_info vec_info;
	int num_alloc_vecs;

	vec_info.num_curr_vecs = vport->num_q_vectors;
	vec_info.num_req_vecs = max_t(u16, vport->num_txq, vport->num_rxq);
	vec_info.default_vport = vport->default_vport;
	vec_info.index = vport->idx;

	/* Additional XDP Tx queues share the q_vector with regular Tx and Rx queues
	 * to which they are assigned. Also, according to DCR-3692 XDP shall request
	 * additional Tx queues via VIRTCHNL.
	 * Therefore, to avoid exceeding over "vport->q_vector_idxs array",
	 * do not request empty q_vectors for XDP Tx queues.
	 */
	if (idpf_xdp_is_prog_ena(vport))
		vec_info.num_req_vecs = max_t(u16,
					      vport->num_txq - vport->num_xdp_txq,
					      vport->num_rxq);

	num_alloc_vecs = idpf_req_rel_vector_indexes(vport->adapter,
						     vport->q_vector_idxs,
						     &vec_info);
	if (num_alloc_vecs <= 0) {
		dev_err(&vport->adapter->pdev->dev, "Vector distribution failed: %d\n",
			num_alloc_vecs);
		return -EINVAL;
	}
	vport->num_q_vectors = num_alloc_vecs;
	return 0;
}

/**
 * idpf_vport_init - Initialize virtual port
 * @vport: virtual port to be initialized
 * @max_q: vport max queue info
 *
 * Will initialize vport with the info received through MB earlier
 */
void idpf_vport_init(struct idpf_vport *vport, struct idpf_vport_max_q *max_q)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_create_vport *vport_msg;
	struct idpf_vport_config *vport_config;
	u16 rx_itr[] = {2, 8, 32, 96, 128};
	u16 tx_itr[] = {2, 8, 64, 128, 256};
	struct idpf_rss_data *rss_data;
	u16 idx = vport->idx;

	vport_config = adapter->vport_config[idx];
	rss_data = &vport_config->user_config.rss_data;
	vport_msg = (struct virtchnl2_create_vport *)
				adapter->vport_params_recvd[idx];

	vport_config->max_q.max_txq = max_q->max_txq;
	vport_config->max_q.max_rxq = max_q->max_rxq;
	vport_config->max_q.max_complq = max_q->max_complq;
	vport_config->max_q.max_bufq = max_q->max_bufq;

	vport->txq_model = le16_to_cpu(vport_msg->txq_model);
	vport->rxq_model = le16_to_cpu(vport_msg->rxq_model);
	vport->vport_type = le16_to_cpu(vport_msg->vport_type);
	vport->vport_id = le32_to_cpu(vport_msg->vport_id);

	rss_data->rss_key_size = min_t(u16, NETDEV_RSS_KEY_LEN,
				       le16_to_cpu(vport_msg->rss_key_size));
	rss_data->rss_lut_size = le16_to_cpu(vport_msg->rss_lut_size);

	ether_addr_copy(vport->default_mac_addr, vport_msg->default_mac_addr);
	vport->max_mtu = IDPF_MAX_MTU;

	/*Initialize Tx and Rx profiles for Dynamic Interrupt Moderation */
	memcpy(vport->rx_itr_profile, rx_itr, IDPF_DIM_PROFILE_SLOTS);
	memcpy(vport->tx_itr_profile, tx_itr, IDPF_DIM_PROFILE_SLOTS);

	if (idpf_xdp_is_prog_ena(vport))
		idpf_vport_set_hsplit(vport, false);
	else
		idpf_vport_set_hsplit(vport, true);

	vport->ts_gran = IDPF_TW_TIME_STAMP_GRAN_512_DIV_S;
	vport->tw_horizon = IDPF_TW_HORIZON_512MS;

	idpf_vport_init_num_qs(vport, vport_msg);
	idpf_vport_calc_num_q_desc(vport);
	idpf_vport_calc_num_q_groups(vport);
	idpf_vport_alloc_vec_indexes(vport);
}

/**
 * idpf_get_vec_ids - Initialize vector id from Mailbox parameters
 * @adapter: adapter structure to get the mailbox vector id
 * @vecids: Array of vector ids
 * @num_vecids: number of vector ids
 * @chunks: vector ids received over mailbox
 *
 * Will initialize the mailbox vector id which is received from the
 * get capabilities and data queue vector ids with ids received as
 * mailbox parameters.
 * Returns number of ids filled
 */
int idpf_get_vec_ids(struct idpf_adapter *adapter,
		     u16 *vecids, int num_vecids,
		     struct virtchnl2_vector_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_vchunks);
	struct virtchnl2_vector_chunk *chunk;
	u16 start_vecid, num_vec;
	int num_vecid_filled = 0;
	int i, j;

	vecids[num_vecid_filled] = adapter->mb_vector.v_idx;
	num_vecid_filled++;

	for (j = 0; j < num_chunks; j++) {
		chunk = &chunks->vchunks[j];
		num_vec = le16_to_cpu(chunk->num_vectors);
		start_vecid = le16_to_cpu(chunk->start_vector_id);
		for (i = 0; i < num_vec; i++) {
			if ((num_vecid_filled + i) < num_vecids) {
				vecids[num_vecid_filled + i] = start_vecid;
				start_vecid++;
			} else {
				break;
			}
		}
		num_vecid_filled = num_vecid_filled + i;
	}

	return num_vecid_filled;
}

/**
 * idpf_vport_get_queue_ids - Initialize queue id from Mailbox parameters
 * @qids: Array of queue ids
 * @num_qids: number of queue ids
 * @q_type: queue model
 * @chunks: queue ids received over mailbox
 *
 * Will initialize all queue ids with ids received as mailbox parameters
 * Returns number of ids filled
 */
static int
idpf_vport_get_queue_ids(u32 *qids, int num_qids, u16 q_type,
			 struct virtchnl2_queue_reg_chunks *chunks)
{
	u16 num_chunks = le16_to_cpu(chunks->num_chunks);
	struct virtchnl2_queue_reg_chunk *chunk;
	u32 num_q_id_filled = 0, i;
	u32 start_q_id, num_q;

	while (num_chunks--) {
		chunk = &chunks->chunks[num_chunks];
		if (le32_to_cpu(chunk->type) != q_type)
			continue;
		num_q = le32_to_cpu(chunk->num_queues);
		start_q_id = le32_to_cpu(chunk->start_queue_id);
		for (i = 0; i < num_q; i++) {
			if ((num_q_id_filled + i) < num_qids) {
				qids[num_q_id_filled + i] = start_q_id;
				start_q_id++;
			} else {
				break;
			}
		}
		num_q_id_filled = num_q_id_filled + i;
	}

	return num_q_id_filled;
}

/**
 * __idpf_vport_queue_ids_init - Initialize queue ids from Mailbox parameters
 * @vport: virtual port for which the queues ids are initialized
 * @qids: queue ids
 * @num_qids: number of queue ids
 * @q_type: type of queue
 *
 * Will initialize all queue ids with ids received as mailbox
 * parameters. Returns number of queue ids initialized.
 */
static int
__idpf_vport_queue_ids_init(struct idpf_vport *vport, u32 *qids,
			    int num_qids, u32 q_type)
{
	struct idpf_queue *q;
	int i, j, k = 0;

	switch (q_type) {
	case VIRTCHNL2_QUEUE_TYPE_TX:
		for (i = 0; i < vport->num_txq_grp; i++) {
			struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

			for (j = 0; j < tx_qgrp->num_txq && k < num_qids; j++) {
				tx_qgrp->txqs[j]->q_id = qids[k];
				tx_qgrp->txqs[j]->q_type =
					VIRTCHNL2_QUEUE_TYPE_TX;
				k++;
			}
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
			int num_rxq;

			if (idpf_is_queue_model_split(vport->rxq_model))
				num_rxq = rx_qgrp->splitq.num_rxq_sets;
			else
				num_rxq = rx_qgrp->singleq.num_rxq;

			for (j = 0; j < num_rxq && k < num_qids; j++, k++) {
				if (idpf_is_queue_model_split(vport->rxq_model))
					q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
				else
					q = rx_qgrp->singleq.rxqs[j];
				q->q_id = qids[k];
				q->q_type = VIRTCHNL2_QUEUE_TYPE_RX;
			}
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
		for (i = 0; i < vport->num_txq_grp && k < num_qids; i++) {
			struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];

			tx_qgrp->complq->q_id = qids[k];
			tx_qgrp->complq->q_type =
				VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
			k++;
		}
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
		for (i = 0; i < vport->num_rxq_grp; i++) {
			struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];

			for (j = 0; j < vport->num_bufqs_per_qgrp && k < num_qids; j++) {
				q = &rx_qgrp->splitq.bufq_sets[j].bufq;
				q->q_id = qids[k];
				q->q_type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
				k++;
			}
		}
		break;
	default:
		break;
	}

	return k;
}

/**
 * idpf_vport_queue_ids_init - Initialize queue ids from Mailbox parameters
 * @vport: virtual port for which the queues ids are initialized
 *
 * Will initialize all queue ids with ids received as mailbox parameters.
 * Returns 0 on success, negative if all the queues are not initialized.
 */
int idpf_vport_queue_ids_init(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport *vport_params;
	struct virtchnl2_queue_reg_chunks *chunks;
	struct idpf_vport_config *vport_config;
	u16 vport_idx = vport->idx;
	/* We may never deal with more than 256 same type of queues */
#define IDPF_MAX_QIDS	256
	u32 qids[IDPF_MAX_QIDS];
	int num_ids;
	u16 q_type;

	vport_config = vport->adapter->vport_config[vport_idx];
	if (vport_config->req_qs_chunks) {
		struct virtchnl2_add_queues *vc_aq =
			(struct virtchnl2_add_queues *)vport_config->req_qs_chunks;
		chunks = &vc_aq->chunks;
	} else {
		vport_params = (struct virtchnl2_create_vport *)
				vport->adapter->vport_params_recvd[vport_idx];
		chunks = &vport_params->chunks;
	}

	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS,
					   VIRTCHNL2_QUEUE_TYPE_TX,
					   chunks);
	if (num_ids < vport->num_txq)
		return -EINVAL;
	num_ids = __idpf_vport_queue_ids_init(vport, qids, num_ids,
					      VIRTCHNL2_QUEUE_TYPE_TX);
	if (num_ids < vport->num_txq)
		return -EINVAL;
	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS,
					   VIRTCHNL2_QUEUE_TYPE_RX,
					   chunks);
	if (num_ids < vport->num_rxq)
		return -EINVAL;
	num_ids = __idpf_vport_queue_ids_init(vport, qids, num_ids,
					      VIRTCHNL2_QUEUE_TYPE_RX);
	if (num_ids < vport->num_rxq)
		return -EINVAL;

	if (!idpf_is_queue_model_split(vport->txq_model))
		goto check_rxq;
	q_type = VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS, q_type,
					   chunks);
	if (num_ids < vport->num_complq)
		return -EINVAL;
	num_ids = __idpf_vport_queue_ids_init(vport, qids,
					      num_ids,
					      q_type);
	if (num_ids < vport->num_complq)
		return -EINVAL;

check_rxq:
	if (!idpf_is_queue_model_split(vport->rxq_model))
		return 0;
	q_type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
	num_ids = idpf_vport_get_queue_ids(qids, IDPF_MAX_QIDS, q_type,
					   chunks);
	if (num_ids < vport->num_bufq)
		return -EINVAL;
	num_ids = __idpf_vport_queue_ids_init(vport, qids, num_ids,
					      q_type);
	if (num_ids < vport->num_bufq)
		return -EINVAL;

	return 0;
}

/**
 * idpf_vport_adjust_qs - Adjust to new requested queues
 * @vport: virtual port data struct
 *
 * Renegotiate queues.  Returns 0 on success, negative on failure.
 */
int idpf_vport_adjust_qs(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport vport_msg;
	int err = 0;

	vport_msg.txq_model = cpu_to_le16(vport->txq_model);
	vport_msg.rxq_model = cpu_to_le16(vport->rxq_model);
	err = idpf_vport_calc_total_qs(vport->adapter, vport->idx, &vport_msg, NULL);
	if (err)
		return err;

	idpf_vport_init_num_qs(vport, &vport_msg);
	idpf_vport_calc_num_q_groups(vport);

	return err;
}

/**
 * idpf_is_capability_ena - Default implementation of capability checking
 * @adapter: Private data struct
 * @all: all or one flag
 * @field: caps field to check for flags
 * @flag: flag to check
 *
 * Return true if all capabilities are supported, false otherwise
 */
bool idpf_is_capability_ena(struct idpf_adapter *adapter, bool all,
			    enum idpf_cap_field field, u64 flag)
{
	u8 *caps = (u8 *)&adapter->caps;
	u32 *cap_field;

	if (!caps)
		return false;

	if (field == IDPF_BASE_CAPS)
		return false;
	if (field >= IDPF_CAP_FIELD_LAST) {
		dev_err(&adapter->pdev->dev, "Bad capability field: %d\n",
			field);
		return false;
	}
	cap_field = (u32 *)(caps + field);

	if (all)
		return (*cap_field & flag) == flag;
	else
		return !!(*cap_field & flag);
}

/**
 * idpf_get_vport_id: Get vport id
 * @vport: virtual port structure
 *
 * Return vport id from the adapter persistent data
 */
u32 idpf_get_vport_id(struct idpf_vport *vport)
{
	struct virtchnl2_create_vport *vport_msg;

	vport_msg = (struct virtchnl2_create_vport *)
				vport->adapter->vport_params_recvd[vport->idx];
	return le32_to_cpu(vport_msg->vport_id);
}

/**
 * idpf_add_del_mac_filters - Add/del mac filters
 * @vport: virtual port data structure
 * @add: Add or delete flag
 * @async: Don't wait for return message
 *
 * Returns 0 on success, error on failre.
 **/
int idpf_add_del_mac_filters(struct idpf_vport *vport, bool add, bool async)
{
	struct virtchnl2_mac_addr_list *ma_list = NULL;
	struct idpf_adapter *adapter = vport->adapter;
	int num_entries, num_msgs, total_filters = 0;
	struct idpf_vport_config *vport_config;
	struct pci_dev *pdev = adapter->pdev;
	enum idpf_vport_vc_state vc, vc_err;
	struct virtchnl2_mac_addr *mac_addr;
	struct idpf_mac_filter *f, *tmp;
	int i = 0, k = 0, err = 0;
	u32 vop;

	vport_config = adapter->vport_config[vport->idx];
	spin_lock_bh(&vport->mac_filter_list_lock);

	/* Find the number of newly added filters */
	list_for_each_entry(f, &vport_config->user_config.mac_filter_list, list) {
		if (add && f->add)
			total_filters++;
		else if (!add && f->remove)
			total_filters++;
	}
	if (!total_filters) {
		spin_unlock_bh(&vport->mac_filter_list_lock);
		goto error;
	}

	/* Fill all the new filters into virtchannel message */
	mac_addr = kcalloc(total_filters, sizeof(struct virtchnl2_mac_addr),
			   GFP_ATOMIC);
	if (!mac_addr) {
		err = -ENOMEM;
		spin_unlock_bh(&vport->mac_filter_list_lock);
		goto error;
	}
	list_for_each_entry_safe(f, tmp, &vport_config->user_config.mac_filter_list,
				 list) {
		if (add && f->add) {
			ether_addr_copy(mac_addr[i].addr, f->macaddr);
			i++;
			f->add = false;
			if (i == total_filters)
				break;
		}
		if (!add && f->remove) {
			ether_addr_copy(mac_addr[i].addr, f->macaddr);
			i++;
			f->remove = false;
			if (i == total_filters)
				break;
		}
	}

	spin_unlock_bh(&vport->mac_filter_list_lock);

	/* Chunk up the filters into multiple messages to avoid
	 * sending a control queue message buffer that is too large
	 */
	if (total_filters < IDPF_NUM_FILTERS_PER_MSG)
		num_entries = total_filters;
	else
		num_entries = IDPF_NUM_FILTERS_PER_MSG;
	num_msgs = DIV_ROUND_UP(total_filters, IDPF_NUM_FILTERS_PER_MSG);

	for (i = 0, k = 0; i < num_msgs || num_entries; i++) {
		int buf_size = sizeof(struct virtchnl2_mac_addr_list) +
			(sizeof(struct virtchnl2_mac_addr) * num_entries);
		if (!ma_list || num_entries != IDPF_NUM_FILTERS_PER_MSG) {
			kfree(ma_list);
			ma_list = kzalloc(buf_size, GFP_ATOMIC);
			if (!ma_list) {
				err = -ENOMEM;
				goto list_prep_error;
			}
		} else {
			memset(ma_list, 0, buf_size);
		}

		ma_list->vport_id = cpu_to_le32(vport->vport_id);
		ma_list->num_mac_addr = cpu_to_le16(num_entries);
		memcpy(ma_list->mac_addr_list, &mac_addr[k],
		       sizeof(struct virtchnl2_mac_addr) * num_entries);

		if (add) {
			vop = VIRTCHNL2_OP_ADD_MAC_ADDR;
			vc = IDPF_VC_ADD_MAC_ADDR;
			vc_err = IDPF_VC_ADD_MAC_ADDR_ERR;
			if (async) {
				set_bit(__IDPF_ADD_MAC_REQ, vport->adapter->flags);
			} else {
				clear_bit(IDPF_VC_ADD_MAC_ADDR, adapter->vc_state);
				clear_bit(IDPF_VC_ADD_MAC_ADDR_ERR, adapter->vc_state);
			}
		} else  {
			vop = VIRTCHNL2_OP_DEL_MAC_ADDR;
			vc = IDPF_VC_DEL_MAC_ADDR;
			vc_err = IDPF_VC_DEL_MAC_ADDR_ERR;
			if (async) {
				set_bit(__IDPF_DEL_MAC_REQ, vport->adapter->flags);
			} else {
				clear_bit(IDPF_VC_DEL_MAC_ADDR, adapter->vc_state);
				clear_bit(IDPF_VC_DEL_MAC_ADDR_ERR, adapter->vc_state);
			}
		}
		err = idpf_send_mb_msg(vport->adapter, vop, buf_size,
				       (u8 *)ma_list);
		if (err)
			goto mbx_error;
		if (!async) {
			err = idpf_wait_for_event(vport->adapter, vport, vc, vc_err);
			if (err)
				goto mbx_error;
		}

		k += num_entries;
		total_filters -= num_entries;
		if (total_filters < IDPF_NUM_FILTERS_PER_MSG)
			num_entries = total_filters;
		clear_bit(__IDPF_VPORT_VC_MSG_PENDING, vport->flags);
	}
mbx_error:
	kfree(ma_list);
list_prep_error:
	kfree(mac_addr);
error:
	if (err)
		dev_err(&pdev->dev, "Failed to add or del mac filters %d", err);

	return err;
}

/**
 * idpf_set_promiscuous - set promiscuous and send message to mailbox
 * @vport: virtual port structure
 *
 * Request to enable promiscuous mode for the vport. Message is sent
 * asynchronously and won't wait for response.  Returns 0 on success, negative
 * on failure;
 */
int idpf_set_promiscuous(struct idpf_vport *vport)
{
	struct idpf_vport_user_config_data *config_data;
	struct idpf_adapter *adapter = vport->adapter;
	struct virtchnl2_promisc_info vpi;
	u16 flags = 0;
	int err = 0;

	config_data = &adapter->vport_config[vport->idx]->user_config;
	if (test_bit(__IDPF_PROMISC_UC, config_data->user_flags))
		flags |= VIRTCHNL2_UNICAST_PROMISC;
	if (test_bit(__IDPF_PROMISC_MC, config_data->user_flags))
		flags |= VIRTCHNL2_MULTICAST_PROMISC;

	vpi.vport_id = cpu_to_le32(vport->vport_id);
	vpi.flags = cpu_to_le16(flags);
	err = idpf_send_mb_msg(adapter, VIRTCHNL2_OP_CONFIG_PROMISCUOUS_MODE,
			       sizeof(struct virtchnl2_promisc_info),
			       (u8 *)&vpi);
	return err;
}

