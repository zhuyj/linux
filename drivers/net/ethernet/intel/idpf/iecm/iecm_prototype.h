/*
 * Copyright (C) 2019 Intel Corporation
 *
 * For licensing information, see the file 'LICENSE' in the root folder
 */
#ifndef _IECM_PROTOTYPE_H_
#define _IECM_PROTOTYPE_H_

/* Include generic macros and types first */
#include "iecm_osdep.h"
#include "iecm_controlq.h"
#include "iecm_type.h"
#include "iecm_alloc.h"
#include "iecm_devids.h"
#include "iecm_controlq_api.h"
#include "iecm_lan_txrx.h"
#include "virtchnl.h"

#define APF

int iecm_init_hw(struct iecm_hw *hw, struct iecm_ctlq_size ctlq_size);
int iecm_deinit_hw(struct iecm_hw *hw);

int iecm_clean_arq_element(struct iecm_hw *hw,
			   struct iecm_arq_event_info *e,
			   u16 *events_pending);
bool iecm_asq_done(struct iecm_hw *hw);
bool iecm_check_asq_alive(struct iecm_hw *hw);

int iecm_get_rss_lut(struct iecm_hw *hw, u16 seid, bool pf_lut,
		     u8 *lut, u16 lut_size);
int iecm_set_rss_lut(struct iecm_hw *hw, u16 seid, bool pf_lut,
		     u8 *lut, u16 lut_size);
int iecm_get_rss_key(struct iecm_hw *hw, u16 seid,
		     struct iecm_get_set_rss_key_data *key);
int iecm_set_rss_key(struct iecm_hw *hw, u16 seid,
		     struct iecm_get_set_rss_key_data *key);

int iecm_set_mac_type(struct iecm_hw *hw);

int iecm_reset(struct iecm_hw *hw);
int iecm_send_msg_to_cp(struct iecm_hw *hw, enum virtchnl_ops v_opcode,
			int v_retval, u8 *msg, u16 msglen);
#endif /* _IECM_PROTOTYPE_H_ */
