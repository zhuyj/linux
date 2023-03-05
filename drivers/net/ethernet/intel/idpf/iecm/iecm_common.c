/*
 * Copyright (C) 2019 Intel Corporation
 *
 * For licensing information, see the file 'LICENSE' in the root folder
 */
#include "iecm_type.h"
#include "iecm_prototype.h"
#include "virtchnl.h"

/**
 * iecm_set_mac_type - Sets MAC type
 * @hw: pointer to the HW structure
 *
 * This function sets the mac type of the adapter based on the
 * vendor ID and device ID stored in the hw structure.
 */
int iecm_set_mac_type(struct iecm_hw *hw)
{
	int status = 0;

	if (hw->vendor_id == IECM_INTEL_VENDOR_ID) {
		switch (hw->device_id) {
		case IECM_DEV_ID_PF_SIMICS:
		case IECM_DEV_ID_PF:
			hw->mac.type = IECM_MAC_PF;
			break;
		case IECM_DEV_ID_VF:
			hw->mac.type = IECM_MAC_VF;
			break;
		default:
			hw->mac.type = IECM_MAC_GENERIC;
			break;
		}
	} else {
		status = -ENODEV;
	}

	return status;
}

/**
 *  iecm_init_hw - main initialization routine
 *  @hw: pointer to the hardware structure
 *  @ctlq_size: struct to pass ctlq size data
 */
int iecm_init_hw(struct iecm_hw *hw, struct iecm_ctlq_size ctlq_size)
{
	struct iecm_ctlq_create_info *q_info;
	int status = 0;
	struct iecm_ctlq_info *cq = NULL;

	/* Setup initial control queues */
	q_info = kcalloc(2, sizeof(struct iecm_ctlq_create_info), GFP_KERNEL);
	if (!q_info)
		return -ENOMEM;

	q_info[0].type             = IECM_CTLQ_TYPE_MAILBOX_TX;
	q_info[0].buf_size         = ctlq_size.asq_buf_size;
	q_info[0].len              = ctlq_size.asq_ring_size;
	q_info[0].id               = -1; /* default queue */

	if (hw->mac.type == IECM_MAC_PF) {
		q_info[0].reg.head         = PF_FW_ATQH;
		q_info[0].reg.tail         = PF_FW_ATQT;
		q_info[0].reg.len          = PF_FW_ATQLEN;
		q_info[0].reg.bah          = PF_FW_ATQBAH;
		q_info[0].reg.bal          = PF_FW_ATQBAL;
		q_info[0].reg.len_mask     = PF_FW_ATQLEN_ATQLEN_M;
		q_info[0].reg.len_ena_mask = PF_FW_ATQLEN_ATQENABLE_M;
		q_info[0].reg.head_mask    = PF_FW_ATQH_ATQH_M;
	} else {
		q_info[0].reg.head         = VF_ATQH;
		q_info[0].reg.tail         = VF_ATQT;
		q_info[0].reg.len          = VF_ATQLEN;
		q_info[0].reg.bah          = VF_ATQBAH;
		q_info[0].reg.bal          = VF_ATQBAL;
		q_info[0].reg.len_mask     = VF_ATQLEN_ATQLEN_M;
		q_info[0].reg.len_ena_mask = VF_ATQLEN_ATQENABLE_M;
		q_info[0].reg.head_mask    = VF_ATQH_ATQH_M;
	}

	q_info[1].type             = IECM_CTLQ_TYPE_MAILBOX_RX;
	q_info[1].buf_size         = ctlq_size.arq_buf_size;
	q_info[1].len              = ctlq_size.arq_ring_size;
	q_info[1].id               = -1; /* default queue */

	if (hw->mac.type == IECM_MAC_PF) {
		q_info[1].reg.head         = PF_FW_ARQH;
		q_info[1].reg.tail         = PF_FW_ARQT;
		q_info[1].reg.len          = PF_FW_ARQLEN;
		q_info[1].reg.bah          = PF_FW_ARQBAH;
		q_info[1].reg.bal          = PF_FW_ARQBAL;
		q_info[1].reg.len_mask     = PF_FW_ARQLEN_ARQLEN_M;
		q_info[1].reg.len_ena_mask = PF_FW_ARQLEN_ARQENABLE_M;
		q_info[1].reg.head_mask    = PF_FW_ARQH_ARQH_M;
	} else {
		q_info[1].reg.head         = VF_ARQH;
		q_info[1].reg.tail         = VF_ARQT;
		q_info[1].reg.len          = VF_ARQLEN;
		q_info[1].reg.bah          = VF_ARQBAH;
		q_info[1].reg.bal          = VF_ARQBAL;
		q_info[1].reg.len_mask     = VF_ARQLEN_ARQLEN_M;
		q_info[1].reg.len_ena_mask = VF_ARQLEN_ARQENABLE_M;
		q_info[1].reg.head_mask    = VF_ARQH_ARQH_M;
	}

	status = iecm_ctlq_init(hw, 2, q_info);
	if (status) {
		/* TODO return error */
		kfree(q_info);
		return status;
	}

	list_for_each_entry(cq, &hw->cq_list_head, cq_list) {
		if (cq->cq_type == IECM_CTLQ_TYPE_MAILBOX_TX)
			hw->asq = cq;
		else if (cq->cq_type == IECM_CTLQ_TYPE_MAILBOX_RX)
			hw->arq = cq;
	}

	/* TODO hardcode a mac addr for now */
	hw->mac.addr[0] = 0x00;
	hw->mac.addr[1] = 0x00;
	hw->mac.addr[2] = 0x00;
	hw->mac.addr[3] = 0x00;
	hw->mac.addr[4] = 0x03;
	hw->mac.addr[5] = 0x14;

	return 0;
}

/**
 * iecm_send_msg_to_cp
 * @hw: pointer to the hardware structure
 * @v_opcode: opcodes for VF-PF communication
 * @v_retval: return error code
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 * @cmd_details: pointer to command details
 *
 * Send message to CP. By default, this message
 * is sent asynchronously, i.e. iecm_asq_send_command() does not wait for
 * completion before returning.
 */
int iecm_send_msg_to_cp(struct iecm_hw *hw, enum virtchnl_ops v_opcode,
			int v_retval, u8 *msg, u16 msglen)
{
	struct iecm_ctlq_msg ctlq_msg = { 0 };
	struct iecm_dma_mem dma_mem = { 0 };
	int status;

	ctlq_msg.opcode = iecm_mbq_opc_send_msg_to_pf;
	ctlq_msg.func_id = 1;
	ctlq_msg.data_len = msglen;
	ctlq_msg.cookie.mbx.chnl_retval = v_retval;
	ctlq_msg.cookie.mbx.chnl_opcode = v_opcode;

	if (msglen > 0) {
		dma_mem.va = (struct iecm_dma_mem *)
			  iecm_alloc_dma_mem(hw, &dma_mem, msglen);
		if (!dma_mem.va)
			return -ENOMEM;

		memcpy(dma_mem.va, msg, msglen);
		ctlq_msg.ctx.indirect.payload = &dma_mem;
	}
	status = iecm_ctlq_send(hw, hw->asq, 1, &ctlq_msg);

	if (dma_mem.va)
		iecm_free_dma_mem(hw, &dma_mem);

	return status;
}

/**
 *  iecm_asq_done - check if FW has processed the Admin Send Queue
 *  @hw: pointer to the hw struct
 *
 *  Returns true if the firmware has processed all descriptors on the
 *  admin send queue. Returns false if there are still requests pending.
 */
bool iecm_asq_done(struct iecm_hw *hw)
{
	/* AQ designers suggest use of head for better
	 * timing reliability than DD bit
	 */
	return rd32(hw, hw->asq->reg.head) == hw->asq->next_to_use;
}

/**
 * iecm_check_asq_alive
 * @hw: pointer to the hw struct
 *
 * Returns true if Queue is enabled else false.
 */
bool iecm_check_asq_alive(struct iecm_hw *hw)
{
	if (hw->asq->reg.len)
		return !!(rd32(hw, hw->asq->reg.len) &
			  PF_FW_ATQLEN_ATQENABLE_M);

	return false;
}

/**
 *  iecm_clean_arq_element
 *  @hw: pointer to the hw struct
 *  @e: event info from the receive descriptor, includes any buffers
 *  @pending: number of events that could be left to process
 *
 *  This function cleans one Admin Receive Queue element and returns
 *  the contents through e.  It can also return how many events are
 *  left to process through 'pending'
 */
int iecm_clean_arq_element(struct iecm_hw *hw,
			   struct iecm_arq_event_info *e, u16 *pending)
{
	struct iecm_ctlq_msg msg = { 0 };
	int status;

	*pending = 1;

	status = iecm_ctlq_recv(hw->arq, pending, &msg);

	/* ctlq_msg does not align to ctlq_desc, so copy relevant data here */
	e->desc.opcode = msg.opcode;
	e->desc.cookie_high = msg.cookie.mbx.chnl_opcode;
	e->desc.cookie_low = msg.cookie.mbx.chnl_retval;
	e->desc.ret_val = msg.status;
	e->desc.datalen = msg.data_len;
	if (msg.data_len > 0) {
		e->buf_len = msg.data_len;
		memcpy(e->msg_buf, msg.ctx.indirect.payload->va, msg.data_len);
	}
	return status;
}

/**
 *  iecm_deinit_hw - shutdown routine
 *  @hw: pointer to the hardware structure
 */
int iecm_deinit_hw(struct iecm_hw *hw)
{
	hw->asq = NULL;
	hw->arq = NULL;

	return iecm_ctlq_deinit(hw);
}

/**
 * iecm_reset
 * @hw: pointer to the hardware structure
 *
 * Send a RESET message to the CPF. Does not wait for response from CPF
 * as none will be forthcoming. Immediately after calling this function,
 * the control queue should be shut down and (optionally) reinitialized.
 */
int iecm_reset(struct iecm_hw *hw)
{
	return iecm_send_msg_to_cp(hw, VIRTCHNL_OP_RESET_VF,
				      IECM_SUCCESS, NULL, 0);
}

/**
 * iecm_get_set_rss_lut
 * @hw: pointer to the hardware structure
 * @vsi_id: vsi fw index
 * @pf_lut: for PF table set true, for VSI table set false
 * @lut: pointer to the lut buffer provided by the caller
 * @lut_size: size of the lut buffer
 * @set: set true to set the table, false to get the table
 *
 * Internal function to get or set RSS look up table
 */
static int iecm_get_set_rss_lut(struct iecm_hw *hw, u16 vsi_id,
				bool pf_lut, u8 *lut, u16 lut_size,
				bool set)
{
	/* TODO fill out command */
	return 0;
}

/**
 * iecm_get_rss_lut
 * @hw: pointer to the hardware structure
 * @vsi_id: vsi fw index
 * @pf_lut: for PF table set true, for VSI table set false
 * @lut: pointer to the lut buffer provided by the caller
 * @lut_size: size of the lut buffer
 *
 * get the RSS lookup table, PF or VSI type
 */
int iecm_get_rss_lut(struct iecm_hw *hw, u16 vsi_id, bool pf_lut,
		     u8 *lut, u16 lut_size)
{
	return iecm_get_set_rss_lut(hw, vsi_id, pf_lut, lut, lut_size, false);
}

/**
 * iecm_set_rss_lut
 * @hw: pointer to the hardware structure
 * @vsi_id: vsi fw index
 * @pf_lut: for PF table set true, for VSI table set false
 * @lut: pointer to the lut buffer provided by the caller
 * @lut_size: size of the lut buffer
 *
 * set the RSS lookup table, PF or VSI type
 */
int iecm_set_rss_lut(struct iecm_hw *hw, u16 vsi_id, bool pf_lut,
		     u8 *lut, u16 lut_size)
{
	return iecm_get_set_rss_lut(hw, vsi_id, pf_lut, lut, lut_size, true);
}

/**
 * iecm_get_set_rss_key
 * @hw: pointer to the hw struct
 * @vsi_id: vsi fw index
 * @key: pointer to key info struct
 * @set: set true to set the key, false to get the key
 *
 * get the RSS key per VSI
 */
static int iecm_get_set_rss_key(struct iecm_hw *hw, u16 vsi_id,
				struct iecm_get_set_rss_key_data *key,
				bool set)
{
	/* TODO fill out command */
	return 0;
}

/**
 * iecm_get_rss_key
 * @hw: pointer to the hw struct
 * @vsi_id: vsi fw index
 * @key: pointer to key info struct
 *
 */
int iecm_get_rss_key(struct iecm_hw *hw, u16 vsi_id,
		     struct iecm_get_set_rss_key_data *key)
{
	return iecm_get_set_rss_key(hw, vsi_id, key, false);
}

/**
 * iecm_set_rss_key
 * @hw: pointer to the hw struct
 * @vsi_id: vsi fw index
 * @key: pointer to key info struct
 *
 * set the RSS key per VSI
 */
int iecm_set_rss_key(struct iecm_hw *hw, u16 vsi_id,
		     struct iecm_get_set_rss_key_data *key)
{
	return iecm_get_set_rss_key(hw, vsi_id, key, true);
}
