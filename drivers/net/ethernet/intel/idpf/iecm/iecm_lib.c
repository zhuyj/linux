// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2019 Intel Corporation */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "iecm.h"

static const struct net_device_ops iecm_netdev_ops_splitq;
static const struct net_device_ops iecm_netdev_ops_singleq;

const char * const iecm_vport_vc_state_str[] = {
	IECM_FOREACH_VPORT_VC_STATE(IECM_GEN_STRING)
};
EXPORT_SYMBOL(iecm_vport_vc_state_str);

/**
 * iecm_get_vport_index - Get the vport index
 * @adapter: adapter structure to get the vports array
 * @vport: vport pointer for which the index to find
 */
static int iecm_get_vport_index(struct iecm_adapter *adapter,
				struct iecm_vport *vport)
{
	int i, err = -EINVAL;

	if (!adapter->vports)
		return err;

	for (i = 0; i < adapter->num_alloc_vport; i++) {
		if (adapter->vports[i] != vport)
			continue;
		return i;
	}
	return err;
}

/**
 * iecm_is_feature_ena - Determine if a particular feature is enabled
 * @vport: vport to check
 * @feature: netdev flag to check
 *
 * Returns true or false if a particular feature is enabled.
 */
bool iecm_is_feature_ena(struct iecm_vport *vport, netdev_features_t feature)
{
	struct iecm_channel_config *ch_config;
	bool ena;

	switch (feature) {
	case NETIF_F_HW_TC:
		ch_config = &vport->adapter->config_data.ch_config;
		ena = (vport->netdev->features & feature) &&
			(ch_config->num_tc > IECM_START_CHNL_TC) &&
			(ch_config->tc_running);
		break;
	default:
		ena = vport->netdev->features & feature;
		break;
	}
	return ena;
}

/**
 * iecm_is_adq_v2_ena - Determine whether ADQ V2 is enabled
 * @vport: virtual port struct
 *
 * This function returns true based on negotiated capability ADQ_V2
 * if set and ADQ enabled
 */
static bool iecm_is_adq_v2_ena(struct iecm_vport *vport)
{
	/* iecm_is_feature_ena tells if the netdev flag is set and adq is
	 * enabled
	 */
	return (iecm_is_feature_ena(vport, NETIF_F_HW_TC) &&
		iecm_is_cap_ena(vport->adapter, IECM_OTHER_CAPS,
				VIRTCHNL2_CAP_ADQ));
}

/**
 * iecm_is_vlan_cap_ena - Check if VLAN capability is enabled
 * @vport: virtual port data structure
 * @vcaps: VLAN capability bit
 * @hw_feature: bool to check if VLAN capability is supported
 *
 * Returns true if VLAN capability is set, false otherwise
 */
static bool iecm_is_vlan_cap_ena(struct iecm_vport *vport,
				 enum iecm_vlan_caps vcaps, bool hw_feature)
{
	struct iecm_adapter *adapter = vport->adapter;

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_VLAN)) {
		struct virtchnl_vlan_supported_caps *offload;
		u32 eth_offload, eth_filter;

		if (!adapter->vlan_caps)
			return false;

		eth_offload = adapter->vlan_caps->offloads.ethertype_init;
		eth_filter = adapter->vlan_caps->filtering.ethertype_init;
		switch (vcaps) {
		case IECM_CAP_VLAN_CTAG_INSERT:
			offload =
			&adapter->vlan_caps->offloads.insertion_support;
			/* The conditional statement helps to determine if the
			 * VLAN features supported by the hardware can be
			 * toggled and also determine the default VLAN features
			 * that are enabled.
			 */
			if (hw_feature) {
				if ((offload->outer & IECM_VLAN_8100) == IECM_VLAN_8100 ||
				    (offload->inner & IECM_VLAN_8100) == IECM_VLAN_8100)
					return true;
			} else {
				if ((eth_offload & VIRTCHNL_VLAN_ETHERTYPE_8100) &&
				    ((offload->outer & VIRTCHNL_VLAN_ETHERTYPE_8100) ||
				     (offload->inner & VIRTCHNL_VLAN_ETHERTYPE_8100)))
					return true;
			}
			break;
		case IECM_CAP_VLAN_STAG_INSERT:
#ifdef NETIF_F_HW_VLAN_STAG_TX
			offload =
			&adapter->vlan_caps->offloads.insertion_support;
			if (hw_feature) {
				if ((offload->outer & IECM_VLAN_88A8) ==
								IECM_VLAN_88A8)
					return true;
			} else {
				if ((eth_offload & VIRTCHNL_VLAN_ETHERTYPE_88A8) &&
				    (offload->outer & VIRTCHNL_VLAN_ETHERTYPE_88A8))
					return true;
			}
#endif /* NETIF_F_HW_VLAN_STAG_TX */
			break;
		case IECM_CAP_VLAN_CTAG_STRIP:
			offload =
			&adapter->vlan_caps->offloads.stripping_support;
			if (hw_feature) {
				if ((offload->outer & IECM_VLAN_8100) == IECM_VLAN_8100 ||
				    (offload->inner & IECM_VLAN_8100) == IECM_VLAN_8100)
					return true;
			} else {
				if ((eth_offload & VIRTCHNL_VLAN_ETHERTYPE_8100) &&
				    ((offload->outer & VIRTCHNL_VLAN_ETHERTYPE_8100) ||
				     (offload->inner & VIRTCHNL_VLAN_ETHERTYPE_8100)))
					return true;
			}
			break;
		case IECM_CAP_VLAN_STAG_STRIP:
#ifdef NETIF_F_HW_VLAN_STAG_RX
			offload =
			&adapter->vlan_caps->offloads.stripping_support;
			if (hw_feature) {
				if ((offload->outer & IECM_VLAN_88A8) ==
								IECM_VLAN_88A8)
					return true;
			} else {
				if ((eth_offload & VIRTCHNL_VLAN_ETHERTYPE_88A8) &&
				    (offload->outer & VIRTCHNL_VLAN_ETHERTYPE_88A8))
					return true;
			}
#endif /* NETIF_F_HW_VLAN_STAG_RX */
			break;
		case IECM_CAP_VLAN_CTAG_ADD_DEL:
			offload =
			&adapter->vlan_caps->filtering.filtering_support;
			if (!hw_feature) {
				if ((eth_filter & VIRTCHNL_VLAN_ETHERTYPE_8100) &&
				    ((offload->outer & VIRTCHNL_VLAN_ETHERTYPE_8100) ||
				     (offload->inner & VIRTCHNL_VLAN_ETHERTYPE_8100)))
					return true;
			}
			break;
		case IECM_CAP_VLAN_STAG_ADD_DEL:
#ifdef NETIF_F_HW_VLAN_STAG_FILTER
			offload =
			&adapter->vlan_caps->filtering.filtering_support;
			if (!hw_feature) {
				if ((eth_filter & VIRTCHNL_VLAN_ETHERTYPE_88A8) &&
				    ((offload->outer & VIRTCHNL_VLAN_ETHERTYPE_88A8) ||
				     (offload->inner & VIRTCHNL_VLAN_ETHERTYPE_88A8)))
					return true;
			}
#endif /* NETIF_F_HW_VLAN_STAG_FILTER */
			break;
		default:
			dev_err(&adapter->pdev->dev, "Invalid VLAN capability %d\n",
				vcaps);
			return false;
		}
	} else if (iecm_is_cap_ena(adapter, IECM_BASE_CAPS,
				   VIRTCHNL2_CAP_VLAN)) {
		switch (vcaps) {
		case IECM_CAP_VLAN_CTAG_INSERT:
		case IECM_CAP_VLAN_CTAG_STRIP:
			return true;
		case IECM_CAP_VLAN_CTAG_ADD_DEL:
			if (hw_feature)
				return false;
			else
				return true;
		default:
			return false;
		}
	}

	return false;
}

/**
 * iecm_netdev_to_vport - get a vport handle from a netdev
 * @netdev: network interface device structure
 */
struct iecm_vport *iecm_netdev_to_vport(struct net_device *netdev)
{
	struct iecm_netdev_priv *np = netdev_priv(netdev);

	return np->vport;
}

/**
 * iecm_netdev_to_adapter - get an adapter handle from a netdev
 * @netdev: network interface device structure
 */
struct iecm_adapter *iecm_netdev_to_adapter(struct net_device *netdev)
{
	struct iecm_netdev_priv *np = netdev_priv(netdev);

	return np->vport->adapter;
}

/**
 * iecm_mb_intr_rel_irq - Free the IRQ association with the OS
 * @adapter: adapter structure
 */
static void iecm_mb_intr_rel_irq(struct iecm_adapter *adapter)
{
	int irq_num;

	irq_num = adapter->msix_entries[0].vector;
	free_irq(irq_num, adapter);
}

/**
 * iecm_intr_rel - Release interrupt capabilities and free memory
 * @adapter: adapter to disable interrupts on
 */
static void iecm_intr_rel(struct iecm_adapter *adapter)
{
	if (!adapter->msix_entries)
		return;
	clear_bit(__IECM_MB_INTR_MODE, adapter->flags);
	clear_bit(__IECM_MB_INTR_TRIGGER, adapter->flags);
	iecm_mb_intr_rel_irq(adapter);

	pci_free_irq_vectors(adapter->pdev);
	if (adapter->dev_ops.vc_ops.dealloc_vectors) {
		int err;

		err = adapter->dev_ops.vc_ops.dealloc_vectors(adapter);
		if (err) {
			dev_err(&adapter->pdev->dev,
				"Failed to deallocate vectors: %d\n", err);
		}
	}
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
	kfree(adapter->req_vec_chunks);
	adapter->req_vec_chunks = NULL;
}

/**
 * iecm_mb_intr_clean - Interrupt handler for the mailbox
 * @irq: interrupt number
 * @data: pointer to the adapter structure
 */
static irqreturn_t iecm_mb_intr_clean(int __always_unused irq, void *data)
{
	struct iecm_adapter *adapter = (struct iecm_adapter *)data;

	set_bit(__IECM_MB_INTR_TRIGGER, adapter->flags);
	mod_delayed_work(adapter->serv_wq, &adapter->serv_task,
			 msecs_to_jiffies(0));
	return IRQ_HANDLED;
}

/**
 * iecm_mb_irq_enable - Enable MSIX interrupt for the mailbox
 * @adapter: adapter to get the hardware address for register write
 */
static void iecm_mb_irq_enable(struct iecm_adapter *adapter)
{
	struct iecm_hw *hw = &adapter->hw;
	struct iecm_intr_reg *intr = &adapter->mb_vector.intr_reg;
	u32 val;

	val = intr->dyn_ctl_intena_m | intr->dyn_ctl_itridx_m;
	wr32(hw, intr->dyn_ctl, val);
	wr32(hw, intr->icr_ena, intr->icr_ena_ctlq_m);
}

/**
 * iecm_mb_intr_req_irq - Request irq for the mailbox interrupt
 * @adapter: adapter structure to pass to the mailbox irq handler
 */
static int iecm_mb_intr_req_irq(struct iecm_adapter *adapter)
{
	struct iecm_q_vector *mb_vector = &adapter->mb_vector;
	int irq_num, mb_vidx = 0, err;

	irq_num = adapter->msix_entries[mb_vidx].vector;
	snprintf(mb_vector->name, sizeof(mb_vector->name) - 1,
		 "%s-%s-%d", dev_driver_string(&adapter->pdev->dev),
		 "Mailbox", mb_vidx);
	err = request_irq(irq_num, adapter->irq_mb_handler, 0,
			  mb_vector->name, adapter);
	if (err) {
		dev_err(&adapter->pdev->dev,
			"Request_irq for mailbox failed, error: %d\n", err);
		return err;
	}
	set_bit(__IECM_MB_INTR_MODE, adapter->flags);
	return 0;
}

/**
 * iecm_get_mb_vec_id - Get vector index for mailbox
 * @adapter: adapter structure to access the vector chunks
 *
 * The first vector id in the requested vector chunks from the CP is for
 * the mailbox
 */
static void iecm_get_mb_vec_id(struct iecm_adapter *adapter)
{
	struct virtchnl2_get_capabilities *caps;

	if (adapter->req_vec_chunks) {
		caps = (struct virtchnl2_get_capabilities *)adapter->caps;
		adapter->mb_vector.v_idx = le16_to_cpu(caps->mailbox_vector_id);
	} else {
		adapter->mb_vector.v_idx = 0;
	}
}

/**
 * iecm_mb_intr_init - Initialize the mailbox interrupt
 * @adapter: adapter structure to store the mailbox vector
 */
static int iecm_mb_intr_init(struct iecm_adapter *adapter)
{
	adapter->dev_ops.reg_ops.mb_intr_reg_init(adapter);
	adapter->irq_mb_handler = iecm_mb_intr_clean;
	return iecm_mb_intr_req_irq(adapter);
}

/**
 * iecm_intr_distribute - Distribute MSIX vectors
 * @adapter: adapter structure to get the vports
 * @pre_req: before or after msi request
 *
 * Distribute the MSIX vectors acquired from the OS to the vports based on the
 * num of vectors requested by each vport
 */
static int
iecm_intr_distribute(struct iecm_adapter *adapter, bool pre_req)
{
	struct iecm_vport *vport = adapter->vports[0];
	int err = 0;

	if (pre_req) {
		u16 vecs_avail, vecs_needed;

		vecs_avail = iecm_get_reserved_vecs(adapter);
		vecs_needed = vport->num_q_vectors + IECM_NONQ_VEC;

		if (vecs_avail < IECM_MIN_VEC) {
			return -EAGAIN;
		} else if (vecs_avail == IECM_MIN_VEC) {
			vport->num_q_vectors = IECM_MIN_Q_VEC;
		} else {
			vport->num_q_vectors = vecs_avail - IECM_NONQ_VEC;
		}
	} else {
		if (adapter->num_msix_entries != adapter->num_req_msix) {
			vport->num_q_vectors = adapter->num_msix_entries -
					       IECM_NONQ_VEC;
		}
	}

	return err;
}

/**
 * iecm_intr_req - Request interrupt capabilities
 * @adapter: adapter to enable interrupts on
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_intr_req(struct iecm_adapter *adapter)
{
	int min_vectors, max_vectors, err = 0;
	int num_q_vecs, total_num_vecs;
	u16 vecids[IECM_MAX_VECIDS];
	unsigned int vector;
	int v_actual;

	err = iecm_intr_distribute(adapter, true);
	if (err)
		return err;

	num_q_vecs = adapter->vports[0]->num_q_vectors;

	total_num_vecs = num_q_vecs + IECM_NONQ_VEC;

	if (adapter->dev_ops.vc_ops.alloc_vectors) {
		err = adapter->dev_ops.vc_ops.alloc_vectors(adapter,
							    num_q_vecs);
		if (err) {
			dev_err(&adapter->pdev->dev,
				"Failed to allocate vectors: %d\n", err);
			return -EAGAIN;
		}
	}

	min_vectors = IECM_MIN_VEC;
	max_vectors = total_num_vecs;
	v_actual = pci_alloc_irq_vectors(adapter->pdev, min_vectors,
					 max_vectors, PCI_IRQ_MSIX);
	if (v_actual < 0) {
		dev_err(&adapter->pdev->dev, "Failed to allocate MSIX vectors: %d\n",
			v_actual);
		if (adapter->dev_ops.vc_ops.dealloc_vectors)
			adapter->dev_ops.vc_ops.dealloc_vectors(adapter);
		return -EAGAIN;
	}

	adapter->msix_entries = kcalloc(v_actual, sizeof(struct msix_entry),
					GFP_KERNEL);

	if (!adapter->msix_entries) {
		pci_free_irq_vectors(adapter->pdev);
		if (adapter->dev_ops.vc_ops.dealloc_vectors)
			adapter->dev_ops.vc_ops.dealloc_vectors(adapter);
		return -ENOMEM;
	}

	iecm_get_mb_vec_id(adapter);

	if (adapter->req_vec_chunks) {
		struct virtchnl2_vector_chunks *vchunks;
		struct virtchnl2_alloc_vectors *ac;

		ac = adapter->req_vec_chunks;
		vchunks = &ac->vchunks;

		iecm_get_vec_ids(adapter, vecids, IECM_MAX_VECIDS, vchunks);
	} else {
		int i = 0;

		for (i = 0; i < v_actual; i++)
			vecids[i] = i;
	}

	for (vector = 0; vector < v_actual; vector++) {
		adapter->msix_entries[vector].entry = vecids[vector];
		adapter->msix_entries[vector].vector =
			pci_irq_vector(adapter->pdev, vector);
	}
	adapter->num_msix_entries = v_actual;
	adapter->num_req_msix = total_num_vecs;

	iecm_intr_distribute(adapter, false);

	err = iecm_mb_intr_init(adapter);
	if (err)
		goto intr_rel;
	iecm_mb_irq_enable(adapter);
	return err;

intr_rel:
	iecm_intr_rel(adapter);
	return err;
}

/**
 * iecm_find_mac_filter - Search filter list for specific mac filter
 * @vport: main vport structure
 * @macaddr: the MAC address
 *
 * Returns ptr to the filter object or NULL. Must be called while holding the
 * mac_filter_list_lock.
 **/
static struct
iecm_mac_filter *iecm_find_mac_filter(struct iecm_vport *vport,
				      const u8 *macaddr)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_mac_filter *f;

	if (!macaddr)
		return NULL;

	list_for_each_entry(f, &adapter->config_data.mac_filter_list, list) {
		if (ether_addr_equal(macaddr, f->macaddr))
			return f;
	}
	return NULL;
}

/**
 * __iecm_del_mac_filter - Delete a MAC filter from the filter list
 * @vport: main vport structure
 * @macaddr: the MAC address
 *
 * Removes filter from list
 **/
static int __iecm_del_mac_filter(struct iecm_vport *vport, const u8 *macaddr)
{
	struct iecm_mac_filter *f;

	if (!macaddr)
		return -EINVAL;

	spin_lock_bh(&vport->adapter->mac_filter_list_lock);
	f = iecm_find_mac_filter(vport, macaddr);
	if (f) {
		list_del(&f->list);
		kfree(f);
	}
	spin_unlock_bh(&vport->adapter->mac_filter_list_lock);

	return 0;
}

/**
 * iecm_del_mac_filter - Delete a MAC filter from the filter list
 * @vport: main vport structure
 * @macaddr: the MAC address
 * @async: Don't wait for return message
 *
 * Removes filter from list and if interface is up, tells hardware about the
 * removed filter.
 **/
static int iecm_del_mac_filter(struct iecm_vport *vport, const u8 *macaddr,
			       bool async)
{
	struct iecm_mac_filter *f;
	int err = 0;

	if (!macaddr)
		return -EINVAL;

	spin_lock_bh(&vport->adapter->mac_filter_list_lock);
	f = iecm_find_mac_filter(vport, macaddr);
	if (f) {
		f->remove = true;
	} else {
		spin_unlock_bh(&vport->adapter->mac_filter_list_lock);
		return -EINVAL;
	}
	spin_unlock_bh(&vport->adapter->mac_filter_list_lock);

	if (vport->adapter->state == __IECM_UP) {
		err = iecm_add_del_ether_addrs(vport, false, async);
		if (err)
			return err;
	}

	return  __iecm_del_mac_filter(vport, macaddr);
}

/**
 * __iecm_add_mac_filter - Add mac filter helper function
 * @vport: main vport struct
 * @macaddr: address to add
 *
 * Takes mac_filter_list_lock spinlock to add new filter to list.
 */
static int __iecm_add_mac_filter(struct iecm_vport *vport, const u8 *macaddr)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_mac_filter *f = NULL;
	int err = 0;

	spin_lock_bh(&adapter->mac_filter_list_lock);
	f = iecm_find_mac_filter(vport, macaddr);
	if (!f) {
		f = kzalloc(sizeof(*f), GFP_ATOMIC);
		if (!f) {
			dev_err(&adapter->pdev->dev, "Failed to allocate memory for filter: %pM",
				macaddr);
			err = -ENOMEM;
			goto error;
		}

		ether_addr_copy(f->macaddr, macaddr);

		list_add_tail(&f->list, &adapter->config_data.mac_filter_list);
		f->add = true;
	} else {
		f->remove = false;
	}
error:
	spin_unlock_bh(&adapter->mac_filter_list_lock);

	return err;
}

/**
 * iecm_add_mac_filter - Add a mac filter to the filter list
 * @vport: main vport structure
 * @macaddr: the MAC address
 * @async: Don't wait for return message
 *
 * Returns 0 on success or error on failure. If interface is up, we'll also
 * send the virtchnl message to tell hardware about the filter.
 **/
static int iecm_add_mac_filter(struct iecm_vport *vport,
			       const u8 *macaddr, bool async)
{
	int err = 0;

	if (!macaddr)
		return -EINVAL;

	err = __iecm_add_mac_filter(vport, macaddr);
	if (err)
		return err;

	if (vport->adapter->state == __IECM_UP)
		err = iecm_add_del_ether_addrs(vport, true, async);

	return err;
}

/**
 * iecm_del_all_mac_filters - Delete all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock.  Deletes all filters
 */
static void iecm_del_all_mac_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_mac_filter *f, *ftmp;

	spin_lock_bh(&adapter->mac_filter_list_lock);
	list_for_each_entry_safe(f, ftmp, &adapter->config_data.mac_filter_list, list) {
		list_del(&f->list);
		kfree(f);
	}
	spin_unlock_bh(&adapter->mac_filter_list_lock);
}

/**
 * iecm_restore_mac_filters - Re-add all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock.  Sets add field to true for filters to
 * resync filters back to HW.
 */
static void iecm_restore_mac_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_mac_filter *f;

	spin_lock_bh(&adapter->mac_filter_list_lock);
	list_for_each_entry(f, &adapter->config_data.mac_filter_list, list)
		f->add = true;
	spin_unlock_bh(&adapter->mac_filter_list_lock);

	iecm_add_del_ether_addrs(vport, true, false);
}

/**
 * iecm_remove_mac_filters - Remove all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock.  Sets remove field to true for filters to
 * remove filters in  HW.
 */
static void iecm_remove_mac_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_mac_filter *f;

	spin_lock_bh(&adapter->mac_filter_list_lock);
	list_for_each_entry(f, &adapter->config_data.mac_filter_list, list)
		f->remove = true;
	spin_unlock_bh(&adapter->mac_filter_list_lock);

	iecm_add_del_ether_addrs(vport, false, false);
}
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
/**
 * iecm_find_vlan - Search filter list for specific vlan filter
 * @vport: vport structure
 * @vlan: vlan tag
 *
 * Returns ptr to the filter object or NULL. Must be called while holding the
 * vlan_list_lock.
 */
static struct
iecm_vlan_filter *iecm_find_vlan(struct iecm_vport *vport,
				 struct iecm_vlan *vlan)
{
	struct iecm_vlan_filter *f;

	list_for_each_entry(f, &vport->adapter->config_data.vlan_filter_list,
			    list) {
		if (vlan->vid == f->vlan.vid && vlan->tpid == f->vlan.tpid)
			return f;
	}
	return NULL;
}

/**
 * iecm_add_vlan - Add a vlan filter to the list
 * @vport: vport structure
 * @vlan: VLAN tag
 *
 * Returns ptr to the filter object or NULL when no memory available.
 */
static struct
iecm_vlan_filter *iecm_add_vlan(struct iecm_vport *vport,
				struct iecm_vlan *vlan)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_vlan_filter *f = NULL;

	spin_lock_bh(&adapter->vlan_list_lock);

	f = iecm_find_vlan(vport, vlan);
	if (!f) {
		f = kzalloc(sizeof(*f), GFP_ATOMIC);
		if (!f)
			goto error;

		f->vlan.vid = vlan->vid;
		f->vlan.tpid = vlan->tpid;

		list_add_tail(&f->list, &adapter->config_data.vlan_filter_list);
		f->add = true;
	}

error:
	spin_unlock_bh(&adapter->vlan_list_lock);
	return f;
}

/**
 * iecm_del_all_vlan_filters - Delete all vlan filters
 * @vport: vport structure
 */
static void iecm_del_all_vlan_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_vlan_filter *f, *ftmp;

	spin_lock_bh(&adapter->vlan_list_lock);
	list_for_each_entry_safe(f, ftmp,
				 &adapter->config_data.vlan_filter_list, list) {
		list_del(&f->list);
		kfree(f);
	}
	spin_unlock_bh(&adapter->vlan_list_lock);
}

/**
 * iecm_get_num_vlans_added - get number of VLANs added
 * @adapter: main adapter structure
 */
static u16 iecm_get_num_vlans_added(struct iecm_adapter *adapter)
{
	return bitmap_weight(adapter->config_data.active_cvlans, VLAN_N_VID) +
		bitmap_weight(adapter->config_data.active_svlans, VLAN_N_VID);
}

/**
 * iecm_get_max_vlans_allowed - get maximum VLANs allowed
 * @adapter: main adapter structure
 *
 * This depends on the negotiated VLAN capability. For version 1, do not
 * impose a limit as that maintains current behavior and for version 2,
 * use the maximum allowed VLANs sent from the PF.
 */
static u16 iecm_get_max_vlans_allowed(struct iecm_adapter *adapter)
{
	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_VLAN))
		return adapter->vlan_caps->filtering.max_filters;
	else if (iecm_is_cap_ena(adapter, IECM_BASE_CAPS, VIRTCHNL2_CAP_VLAN))
		return VLAN_N_VID;

	return 0;
}

/**
 * iecm_is_max_vlans_added - check if maximum VLANs allowed already exist
 * @adapter: main adapter structure
 *
 * Return true on success, false on failure
 */
static bool iecm_is_max_vlans_added(struct iecm_adapter *adapter)
{
	if (iecm_get_num_vlans_added(adapter) <
	    iecm_get_max_vlans_allowed(adapter))
		return false;

	return true;
}

/**
 * iecm_vlan_rx_add_vid - Add a VLAN filter to the device
 * @netdev: network device struct
 * @proto: unused protocol data
 * @vid: VLAN tag
 *
 * Returns 0 on success
 */
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
static int iecm_vlan_rx_add_vid(struct net_device *netdev,
				__be16 proto, u16 vid)
#else
static int iecm_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
#endif /* HAVE_INT_NDO_VLAN_RX_ADD_VID */
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_vlan vlan;
	u16 vlan_proto;

#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
	vlan_proto = be16_to_cpu(proto);
#else
	vlan_proto = ETH_P_8021Q;
#endif /* HAVE_INT_NDO_VLAN_RX_ADD_VID */
	vlan = IECM_VLAN(vid, vlan_proto);

#ifdef NETIF_F_HW_VLAN_CTAG_FILTER
	if (!iecm_is_feature_ena(vport, NETIF_F_HW_VLAN_CTAG_FILTER))
#else
	if (!iecm_is_feature_ena(vport, NETIF_F_HW_VLAN_FILTER))
#endif /* NETIF_F_HW_VLAN_CTAG_FILTER */
		return -EINVAL;

	if (iecm_is_max_vlans_added(adapter)) {
		netdev_err(netdev, "Max allowed VLAN filters %u. Remove existing VLANs or disable filtering via Ethtool if supported.\n",
			   iecm_get_max_vlans_allowed(adapter));
		return -EINVAL;
	}

	iecm_add_vlan(vport, &vlan);

	if (adapter->state == __IECM_UP)
		adapter->dev_ops.vc_ops.add_del_vlans(vport, true);

	if (vlan_proto == ETH_P_8021Q)
		set_bit(vid, adapter->config_data.active_cvlans);
	else
		set_bit(vid, adapter->config_data.active_svlans);

	return 0;
}

/**
 * iecm_vlan_rx_kill_vid - Remove a VLAN filter from the device
 * @netdev: network device struct
 * @proto: unused protocol data
 * @vid: VLAN tag
 *
 * Returns 0 on success
 */
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
static int iecm_vlan_rx_kill_vid(struct net_device *netdev,
				 __be16 proto, u16 vid)
#else
static int iecm_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
#endif /* HAVE_INT_NDO_VLAN_RX_ADD_VID */
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_vlan_filter *f, *ftmp;
	struct iecm_vlan vlan;
	u16 vlan_proto;

#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
	vlan_proto = be16_to_cpu(proto);
#else
	vlan_proto = ETH_P_8021Q;
#endif /* HAVE_INT_NDO_VLAN_RX_ADD_VID */
	vlan = IECM_VLAN(vid, vlan_proto);

#ifdef NETIF_F_HW_VLAN_CTAG_FILTER
	if (!iecm_is_feature_ena(vport, NETIF_F_HW_VLAN_CTAG_FILTER))
#else
	if (!iecm_is_feature_ena(vport, NETIF_F_HW_VLAN_FILTER))
#endif /* NETIF_F_HW_VLAN_CTAG_FILTER */
		return -EINVAL;

	spin_lock_bh(&adapter->vlan_list_lock);
	f = iecm_find_vlan(vport, &vlan);
	if (f)
		f->remove = true;
	spin_unlock_bh(&adapter->vlan_list_lock);
	if (vport->adapter->state == __IECM_UP)
		adapter->dev_ops.vc_ops.add_del_vlans(vport, false);

	if (vlan_proto == ETH_P_8021Q)
		clear_bit(vid, adapter->config_data.active_cvlans);
	else
		clear_bit(vid, adapter->config_data.active_svlans);

	/* It is safe to delete entry from the list now */
	spin_lock_bh(&adapter->vlan_list_lock);
	list_for_each_entry_safe(f, ftmp,
				 &adapter->config_data.vlan_filter_list,
				 list) {
		if (f->vlan.vid == vlan.vid && f->vlan.tpid == vlan.tpid) {
			list_del(&f->list);
			kfree(f);
		}
	}
	spin_unlock_bh(&adapter->vlan_list_lock);

	return 0;
}

/**
 * iecm_restore_vlan_filters - Re-add all VLANs in list
 * @vport: main vport struct
 *
 * Takes vlan_list_lock spinlock.  Sets add field to true for vlan filters and
 * resyncs vlans back to HW.
 */
static void iecm_restore_vlan_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_vlan_filter *f;

	spin_lock_bh(&adapter->vlan_list_lock);
	list_for_each_entry(f, &adapter->config_data.vlan_filter_list, list)
		f->add = true;
	spin_unlock_bh(&adapter->vlan_list_lock);

	adapter->dev_ops.vc_ops.add_del_vlans(vport, true);
}

#endif /* HAVE_INT_NDO_VLAN_RX_ADD_VID */
/**
 * iecm_get_vlan_features - Get supported VLAN features
 * @vport: virtual port data structure
 * @hw_feature: bool to check if VLAN capability is supported by the HW
 *
 * This function will return the netdev vlan features supported by the HW if
 * hw_feature is set, else returns default vlan features enabled.
 */
#ifdef HAVE_RHEL6_NET_DEVICE_OPS_EXT
static u32
iecm_get_vlan_features(struct iecm_vport *vport, bool hw_feature)
#else
static netdev_features_t
iecm_get_vlan_features(struct iecm_vport *vport, bool hw_feature)
#endif /* HAVE_RHEL6_NET_DEVICE_OPS_EXT */
{
#ifdef HAVE_RHEL6_NET_DEVICE_OPS_EXT
	u32 features = 0;
#else
	netdev_features_t features = 0;
#endif /* HAVE_RHEL6_NET_DEVICE_OPS_EXT */

	if (iecm_is_vlan_cap_ena(vport, IECM_CAP_VLAN_CTAG_INSERT,
				 hw_feature))
		features |= IECM_F_HW_VLAN_CTAG_TX;
	if (iecm_is_vlan_cap_ena(vport, IECM_CAP_VLAN_CTAG_STRIP,
				 hw_feature))
		features |= IECM_F_HW_VLAN_CTAG_RX;
	if (iecm_is_vlan_cap_ena(vport, IECM_CAP_VLAN_CTAG_ADD_DEL,
				 hw_feature))
		features |= IECM_F_HW_VLAN_CTAG_FILTER;

#ifdef NETIF_F_HW_VLAN_STAG_TX
	if (iecm_is_vlan_cap_ena(vport, IECM_CAP_VLAN_STAG_INSERT,
				 hw_feature))
		features |= NETIF_F_HW_VLAN_STAG_TX;
#endif /* NETIF_F_HW_VLAN_STAG_TX */
#ifdef NETIF_F_HW_VLAN_STAG_RX
	if (iecm_is_vlan_cap_ena(vport, IECM_CAP_VLAN_STAG_STRIP,
				 hw_feature))
		features |= NETIF_F_HW_VLAN_STAG_RX;
#endif /* NETIF_F_HW_VLAN_STAG_RX */
#ifdef NETIF_F_HW_VLAN_STAG_FILTER
	if (iecm_is_vlan_cap_ena(vport, IECM_CAP_VLAN_STAG_ADD_DEL,
				 hw_feature))
		features |= NETIF_F_HW_VLAN_STAG_FILTER;
#endif /* NETIF_F_HW_VLAN_STAG_FILTER */

	return features;
}

/**
 * iecm_deinit_mac_addr - deinitialize mac address for vport
 * @vport: main vport structure
 */
static void iecm_deinit_mac_addr(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_mac_filter *f;

	spin_lock_bh(&adapter->mac_filter_list_lock);
	f = iecm_find_mac_filter(vport, vport->default_mac_addr);
	if (f) {
		list_del(&f->list);
		kfree(f);
	}
	spin_unlock_bh(&adapter->mac_filter_list_lock);
}

/**
 * iecm_init_mac_addr - initialize mac address for vport
 * @vport: main vport structure
 * @netdev: pointer to netdev struct associated with this vport
 */
static int iecm_init_mac_addr(struct iecm_vport *vport,
			      struct net_device *netdev)
{
	struct iecm_adapter *adapter = vport->adapter;
	int err = 0;

	if (!is_valid_ether_addr(vport->default_mac_addr)) {
		if (!iecm_is_cap_ena(vport->adapter, IECM_OTHER_CAPS,
				     VIRTCHNL2_CAP_MACFILTER)) {
			dev_err(&adapter->pdev->dev,
				"MAC address not provided and capability is not set\n");
			return -EINVAL;
		}
		eth_hw_addr_random(netdev);
		err = iecm_add_mac_filter(vport, netdev->dev_addr, false);
		if (err)
			return err;
		ether_addr_copy(vport->default_mac_addr, netdev->dev_addr);
		dev_info(&adapter->pdev->dev, "Invalid MAC address %pM, using random\n",
			 vport->default_mac_addr);
	} else {
		ether_addr_copy(netdev->dev_addr, vport->default_mac_addr);
		ether_addr_copy(netdev->perm_addr, vport->default_mac_addr);
		return iecm_add_mac_filter(vport, vport->default_mac_addr, false);
	}

	return 0;
}

/**
 * iecm_cfg_netdev - Allocate, configure and register a netdev
 * @vport: main vport structure
 *
 * Must be called with sw_mutex taken. Returns 0 on success, negative value on
 * failure.
 */
static int iecm_cfg_netdev(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
#ifdef HAVE_RHEL6_NET_DEVICE_OPS_EXT
	u32 hw_vlan_features, vlan_features;
#else
	netdev_features_t hw_vlan_features;
	netdev_features_t vlan_features;
#endif /* HAVE_RHEL6_NET_DEVICE_OPS_EXT */
	netdev_features_t dflt_features;
	netdev_features_t offloads = 0;
	struct iecm_netdev_priv *np;
	struct net_device *netdev;
	u16 max_q;
	int err;

	/* It's possible we already have a netdev allocated and registered for
	 * this vport
	 */
	if (adapter->netdevs[vport->idx]) {
		netdev = adapter->netdevs[vport->idx];
		np = netdev_priv(netdev);
		np->vport = vport;
		vport->netdev = netdev;

		return iecm_init_mac_addr(vport, netdev);
	}

	max_q = adapter->max_queue_limit;

	netdev = alloc_etherdev_mqs(sizeof(struct iecm_netdev_priv),
				    max_q, max_q);
	if (!netdev)
		return -ENOMEM;
	vport->netdev = netdev;
	np = netdev_priv(netdev);
	np->vport = vport;

	err = iecm_init_mac_addr(vport, netdev);
	if (err)
		goto err;

	/* assign netdev_ops */
	if (iecm_is_queue_model_split(vport->txq_model))
		netdev->netdev_ops = &iecm_netdev_ops_splitq;
	else
		netdev->netdev_ops = &iecm_netdev_ops_singleq;

	/* setup watchdog timeout value to be 5 second */
	netdev->watchdog_timeo = 5 * HZ;

#ifdef HAVE_NETDEVICE_MIN_MAX_MTU
	/* configure default MTU size */
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	netdev->extended->min_mtu = ETH_MIN_MTU;
	netdev->extended->max_mtu = vport->max_mtu;
#else /* HAVE_REHL7_EXTENDED_MIN_MAX_MTU */
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = vport->max_mtu;
#endif /* HAVE_RHEL7_EXTENDED_MIN_MAX_MTU */

#endif /* HAVE_NETDEVICE_MIN_MAX_MTU */
	dflt_features = NETIF_F_SG	|
			NETIF_F_HIGHDMA;

	if (iecm_is_cap_ena_all(adapter, IECM_RSS_CAPS, IECM_CAP_RSS))
		dflt_features |= NETIF_F_RXHASH;
	if (iecm_is_cap_ena_all(adapter, IECM_CSUM_CAPS, IECM_CAP_RX_CSUM_L4V4))
		dflt_features |= NETIF_F_IP_CSUM;
	if (iecm_is_cap_ena_all(adapter, IECM_CSUM_CAPS, IECM_CAP_RX_CSUM_L4V6))
		dflt_features |= NETIF_F_IPV6_CSUM;
	if (iecm_is_cap_ena(adapter, IECM_CSUM_CAPS, IECM_CAP_RX_CSUM))
		dflt_features |= NETIF_F_RXCSUM;
	if (iecm_is_cap_ena_all(adapter, IECM_CSUM_CAPS, IECM_CAP_SCTP_CSUM))
		dflt_features |= NETIF_F_SCTP_CRC;

	/* get HW VLAN features that can be toggled */
	hw_vlan_features = iecm_get_vlan_features(vport, true);

	/* get VLAN features that cannot be toggled */
	vlan_features = iecm_get_vlan_features(vport, false);
#ifdef NETIF_F_HW_TC
	/* Enable cloud filter if ADQ is supported */
	if (iecm_is_cap_ena(adapter, IECM_BASE_CAPS, VIRTCHNL2_CAP_ADQ) ||
	    iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADQ))
		dflt_features |= NETIF_F_HW_TC;
#endif /* NETIF_F_HW_TC */
	if (iecm_is_cap_ena(adapter, IECM_SEG_CAPS, VIRTCHNL2_CAP_SEG_IPV4_TCP))
		dflt_features |= NETIF_F_TSO;
	if (iecm_is_cap_ena(adapter, IECM_SEG_CAPS, VIRTCHNL2_CAP_SEG_IPV6_TCP))
		dflt_features |= NETIF_F_TSO6;
	if (iecm_is_cap_ena_all(adapter, IECM_SEG_CAPS,
				VIRTCHNL2_CAP_SEG_IPV4_UDP |
				VIRTCHNL2_CAP_SEG_IPV6_UDP))
		dflt_features |= NETIF_F_GSO_UDP_L4;
	if (iecm_is_cap_ena_all(adapter, IECM_RSC_CAPS, IECM_CAP_RSC))
		offloads |= NETIF_F_GRO_HW;
	netdev->features |= dflt_features | vlan_features;
	netdev->hw_features |= dflt_features | offloads | hw_vlan_features;
	netdev->hw_enc_features |= dflt_features | offloads;

	iecm_set_ethtool_ops(netdev);
	SET_NETDEV_DEV(netdev, &adapter->pdev->dev);

	/* carrier off on init to avoid Tx hangs */
	netif_carrier_off(netdev);

	/* make sure transmit queues start off as stopped */
	netif_tx_stop_all_queues(netdev);

	/* register last */
	err = register_netdev(netdev);
	if (err)
		goto err;

	/* The vport can be arbitrarily released so we need to also track
	 * netdevs in the adapter struct
	 */
	adapter->netdevs[vport->idx] = netdev;

	return 0;
err:
	free_netdev(vport->netdev);
	vport->netdev = NULL;

	return err;
}

/**
 * iecm_cfg_hw - Initialize HW struct
 * @adapter: adapter to setup hw struct for
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_cfg_hw(struct iecm_adapter *adapter)
{
	struct pci_dev *pdev = adapter->pdev;
	struct iecm_hw *hw = &adapter->hw;

	hw->hw_addr = pcim_iomap_table(pdev)[IECM_BAR0];
	if (!hw->hw_addr)
		return -EIO;
	hw->back = adapter;

	return 0;
}

/**
 * iecm_get_free_slot - get the next non-NULL location index in array
 * @array: array to search
 * @size: size of the array
 * @curr: last known occupied index to be used as a search hint
 *
 * void * is being used to keep the functionality generic. This lets us use this
 * function on any array of pointers.
 */
static int iecm_get_free_slot(void *array, int size, int curr)
{
	int **tmp_array = (int **)array;
	int next;

	if (curr < (size - 1) && !tmp_array[curr + 1]) {
		next = curr + 1;
	} else {
		int i = 0;

		while ((i < size) && (tmp_array[i]))
			i++;
		if (i == size)
			next = IECM_NO_FREE_SLOT;
		else
			next = i;
	}
	return next;
}

/**
 * iecm_clear_chnl_queue_attr - clears queue attributes specific to channel
 * @queue: Pointer to Tx/Rx queue
 *
 * This function clears up queue attributes such as feature flag (optimization
 * enabled or not, also resets vector feature flags associated with queue)
 **/
static void iecm_clear_chnl_queue_attr(struct iecm_queue *queue)
{
	struct iecm_q_vector *qv = queue->q_vector;

	queue->ch = NULL;

	if (!qv)
		return;

	qv->ch = NULL;

	/* revive the vector from ADQ state machine by triggering
	 * SW interrupt
	 */
	iecm_adq_force_wb(qv);
	clear_bit(__IECM_VEC_CHNL_PERF_ENA, qv->flags);
}

/**
 * iecm_clear_ch_info - clears channel specific information and flags
 * @vport: vport structure
 *
 * This function clears channel specific configurations, flags for
 * Tx, Rx queues, related vectors and triggers software interrupt
 * to revive the ADQ specific vectors, so that vector is put back in
 * interrupt state
 **/
static void iecm_clear_ch_info(struct iecm_vport *vport)
{
	int tc;

	/* To avoid running on older HW, check the ADQ_V2 and avoid setting
	 * ADQ related performance bits if not set
	 */
	if (!iecm_is_adq_v2_ena(vport))
		return;

	if (iecm_is_queue_model_split(vport->rxq_model))
		return;

	for (tc = 0; tc < VIRTCHNL_MAX_ADQ_V2_CHANNELS; tc++) {
		struct iecm_channel_ex *ch;
		int num_rxq, j;

		ch = &vport->adapter->config_data.ch_config.ch_ex_info[tc];
		if (!ch)
			continue;

		/* unlikely but make sure to have non-zero "num_rxq" for
		 * channel otherwise skip..
		 */
		num_rxq = ch->num_rxq;
		if (!num_rxq)
			continue;

		/* proceed only when there is no active filter
		 * for given channel
		 */
		if (ch->num_fltr)
			continue;

		/* Comparing with num_txq as num_txq and num_rxq are equal
		 * for single queue model
		 */
		if (vport->num_q_vectors < vport->num_txq)
			continue;

		for (j = 0; j < num_rxq; j++) {
			struct iecm_queue *txq, *rxq;

			rxq = vport->rxq_grps->singleq.rxqs[ch->base_q + j];
			txq = vport->txqs[ch->base_q + j];
			if (txq)
				iecm_clear_chnl_queue_attr(txq);
			if (rxq)
				iecm_clear_chnl_queue_attr(rxq);
		}
	}
}

/**
 * iecm_setup_chnl_queue_attr - sets queue attributes specific to channel
 * @vport: vport structure
 * @queue: Pointer to Tx/Rx queue
 * @ch: Pointer to channel
 *
 * This function sets up queue attributes such as feature flag (optimization
 * enabled or not, also sets up vector feature flags associated with queue)
 **/
static void iecm_set_chnl_queue_attr(struct iecm_vport *vport,
				     struct iecm_queue *queue,
				     struct iecm_channel_ex *ch)
{
	struct iecm_q_vector *qv = queue->q_vector;

	queue->ch = ch;

	if (!qv)
		return;

	qv->ch = ch;
	set_bit(__IECM_VEC_CHNL_PERF_ENA, qv->flags);
	if (test_bit(__IECM_VPORT_ADQ_CHNL_PKT_OPT_ENA, vport->flags))
		set_bit(__IECM_VEC_CHNL_PKT_OPT_ENA, qv->flags);
	else
		clear_bit(__IECM_VEC_CHNL_PKT_OPT_ENA, qv->flags);
}

/**
 * iecm_setup_ch_info - sets channel specific information and flags
 * @vport: vport structure
 *
 * This function sets up queues (Tx and Rx) and vector specific flags
 * as appliable for ADQ. This function is invoked as soon as filters
 * were added successfully, so that queues and vectors are setup to engage
 * for optimized packets processing using ADQ state machine based logic.
 **/
static void iecm_setup_ch_info(struct iecm_vport *vport)
{
	int tc;

	/* To avoid running on older HW, check the ADQ_V2 and avoid setting
	 * ADQ related performance bits if not set
	 */
	if (!iecm_is_adq_v2_ena(vport))
		return;

	if (iecm_is_queue_model_split(vport->rxq_model))
		return;

	for (tc = 0; tc < VIRTCHNL_MAX_ADQ_V2_CHANNELS; tc++) {
		struct iecm_channel_ex *ch;
		int num_rxq, j;

		ch = &vport->adapter->config_data.ch_config.ch_ex_info[tc];
		if (!ch)
			continue;

		/* unlikely but make sure to have non-zero "num_rxq" for
		 * channel otherwise skip
		 */
		num_rxq = ch->num_rxq;
		if (!num_rxq)
			continue;

		/* do not proceed unless there is at least one filter
		 * for given channel
		 */
		if (!ch->num_fltr)
			continue;

		/* Comparing with num_txq as num_txq and num_rxq are equal
		 * for single queue model
		 */
		if (vport->num_q_vectors < vport->num_txq)
			continue;

		for (j = 0; j < num_rxq; j++) {
			struct iecm_queue *txq, *rxq;

			rxq = vport->rxq_grps->singleq.rxqs[ch->base_q + j];
			txq = vport->txqs[ch->base_q + j];
			if (txq)
				iecm_set_chnl_queue_attr(vport,	txq, ch);
			if (rxq)
				iecm_set_chnl_queue_attr(vport,	rxq, ch);
		}
	}
}

/**
 * iecm_remove_cloud_filters - Remove all cloud filters
 * @vport: vport structure
 */
static void iecm_remove_cloud_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_cloud_filter_config *cf_config;
	struct iecm_cloud_filter *cf;

	cf_config = &adapter->config_data.cf_config;
	if (!list_empty(&cf_config->cloud_filter_list)) {
		spin_lock_bh(&adapter->cloud_filter_list_lock);
		list_for_each_entry(cf, &cf_config->cloud_filter_list, list) {
			cf->remove = true;
		}
		spin_unlock_bh(&adapter->cloud_filter_list_lock);
		iecm_send_add_del_cloud_filter_msg(vport, false);
	}
}

/**
 * iecm_del_all_cloud_filters - delete all cloud filters on the traffic classes
 * @vport: vport structure
 *
 * This function will loop through the list of cloud filters and deletes them.
 **/
static void iecm_del_all_cloud_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_cloud_filter_config *cf_config;
	struct iecm_cloud_filter *cf, *cftmp;

	cf_config = &adapter->config_data.cf_config;
	spin_lock_bh(&adapter->cloud_filter_list_lock);
	list_for_each_entry_safe(cf, cftmp,
				 &cf_config->cloud_filter_list,
				 list) {
		list_del(&cf->list);
		kfree(cf);
		cf_config->num_cloud_filters--;
	}
	spin_unlock_bh(&adapter->cloud_filter_list_lock);
}

/**
 * iecm_remove_vlan_filters - Remove all vlan filters
 * @vport: vport structure
 */
static void iecm_remove_vlan_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_user_config_data *config_data;
	struct iecm_vlan_filter *f;

	config_data = &adapter->config_data;
	if (!list_empty(&config_data->vlan_filter_list)) {
		spin_lock_bh(&adapter->vlan_list_lock);
		list_for_each_entry(f, &config_data->vlan_filter_list, list)
			f->remove = true;
		spin_unlock_bh(&adapter->vlan_list_lock);
		adapter->dev_ops.vc_ops.add_del_vlans(vport, false);
	}
}

/**
 * iecm_remove_adv_rss_cfgs - Remove all RSS configuration
 * @vport: vport structure
 */
static void iecm_remove_adv_rss_cfgs(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_adv_rss *rss;

	if (!iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADV_RSS))
		return;

	if (!list_empty(&adapter->config_data.adv_rss_list)) {
		spin_lock_bh(&adapter->adv_rss_list_lock);
		list_for_each_entry(rss, &adapter->config_data.adv_rss_list,
				    list) {
			rss->remove = true;
		}
		spin_unlock_bh(&adapter->adv_rss_list_lock);
		iecm_send_add_del_adv_rss_cfg_msg(vport, false);
	}
}

/**
 * iecm_del_all_adv_rss_cfgs - delete all RSS configuration
 * @vport: vport structure
 *
 * This function will loop through the list of RSS configuration and deletes
 * them.
 **/
static void iecm_del_all_adv_rss_cfgs(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_adv_rss *rss, *rss_tmp;

	spin_lock_bh(&adapter->adv_rss_list_lock);
	list_for_each_entry_safe(rss, rss_tmp,
				 &adapter->config_data.adv_rss_list,
				 list) {
		list_del(&rss->list);
		kfree(rss);
	}
	spin_unlock_bh(&adapter->adv_rss_list_lock);
}

/**
 * iecm_remove_fdir_filters - Remove all Flow Director filters
 * @vport: vport structure
 */
static void iecm_remove_fdir_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_fdir_fltr_config *fdir_config;
	struct iecm_fdir_fltr *fdir;

	if (!iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADV_RSS))
		return;

	fdir_config = &adapter->config_data.fdir_config;
	if (!list_empty(&fdir_config->fdir_fltr_list)) {
		spin_lock_bh(&adapter->fdir_fltr_list_lock);
		list_for_each_entry(fdir, &fdir_config->fdir_fltr_list, list) {
			fdir->remove = true;
		}
		spin_unlock_bh(&adapter->fdir_fltr_list_lock);
		iecm_send_del_fdir_filter_msg(vport);
	}
}

/**
 * iecm_del_all_fdir_filters - delete all Flow Director filters
 * @vport: vport structure
 *
 * This function will loop through the list of Flow Director filters and
 * deletes them.
 **/
static void iecm_del_all_fdir_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_fdir_fltr_config *fdir_config;
	struct iecm_fdir_fltr *fdir, *fdir_tmp;

	fdir_config = &adapter->config_data.fdir_config;

	spin_lock_bh(&adapter->fdir_fltr_list_lock);
	list_for_each_entry_safe(fdir, fdir_tmp, &fdir_config->fdir_fltr_list,
				 list) {
		list_del(&fdir->list);
		kfree(fdir);
	}
	fdir_config->num_active_filters = 0;
	spin_unlock_bh(&adapter->fdir_fltr_list_lock);
}

/**
 * iecm_remove_features - Turn off feature configs
 * @vport: virtual port structure
 */
static void iecm_remove_features(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_MACFILTER))
		iecm_remove_mac_filters(vport);

	if (iecm_is_cap_ena(adapter, IECM_BASE_CAPS, VIRTCHNL2_CAP_VLAN) ||
	    iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_VLAN))
		iecm_remove_vlan_filters(vport);

	/* Remove cloud filters if ADQ is enabled */
	if (iecm_is_feature_ena(vport, NETIF_F_HW_TC))
		iecm_remove_cloud_filters(vport);

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADV_RSS))
		iecm_remove_adv_rss_cfgs(vport);

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_FDIR))
		iecm_remove_fdir_filters(vport);
}

/**
 * iecm_vport_stop - Disable a vport
 * @vport: vport to disable
 */
static void iecm_vport_stop(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;

	mutex_lock(&vport->stop_mutex);
	if (adapter->state <= __IECM_DOWN)
		goto stop_unlock;

	netif_tx_stop_all_queues(vport->netdev);
	netif_carrier_off(vport->netdev);
	netif_tx_disable(vport->netdev);

	if (adapter->dev_ops.vc_ops.disable_vport)
		adapter->dev_ops.vc_ops.disable_vport(vport);
	adapter->dev_ops.vc_ops.disable_queues(vport);
	adapter->dev_ops.vc_ops.irq_map_unmap(vport, false);
	/* Normally we ask for queues in create_vport, but if we're changing
	 * number of requested queues we do a delete then add instead of
	 * deleting and reallocating the vport.
	 */
	if (test_and_clear_bit(__IECM_DEL_QUEUES,
			       vport->adapter->flags))
		iecm_send_delete_queues_msg(vport);

	iecm_remove_features(vport);

	adapter->link_up = false;
	iecm_vport_intr_deinit(vport);
	iecm_vport_intr_rel(vport);
	iecm_vport_queues_rel(vport);
	adapter->state = __IECM_DOWN;

stop_unlock:
	mutex_unlock(&vport->stop_mutex);
}

/**
 * iecm_stop - Disables a network interface
 * @netdev: network interface device structure
 *
 * The stop entry point is called when an interface is de-activated by the OS,
 * and the netdevice enters the DOWN state.  The hardware is still under the
 * driver's control, but the netdev interface is disabled.
 *
 * Returns success only - not allowed to fail
 */
static int iecm_stop(struct net_device *netdev)
{
	struct iecm_netdev_priv *np = netdev_priv(netdev);

	iecm_vport_stop(np->vport);

	return 0;
}

/**
 * iecm_decfg_netdev - Unregister the netdev
 * @vport: vport for which netdev to be unregistred
 */
static void iecm_decfg_netdev(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;

	if (!vport->netdev)
		return;

	unregister_netdev(vport->netdev);
	free_netdev(vport->netdev);
	vport->netdev = NULL;

	adapter->netdevs[vport->idx] = NULL;
}

/**
 * iecm_vport_rel - Delete a vport and free its resources
 * @vport: the vport being removed
 */
static void iecm_vport_rel(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;

	iecm_deinit_rss(vport);
	if (adapter->dev_ops.vc_ops.destroy_vport)
		adapter->dev_ops.vc_ops.destroy_vport(vport);
	mutex_destroy(&vport->stop_mutex);
	kfree(vport);
	vport = NULL;
}

/**
 * iecm_del_user_cfg_data - delete all user configuration data
 * @vport: virtual port private structue
 */
static void iecm_del_user_cfg_data(struct iecm_vport *vport)
{
	iecm_del_all_mac_filters(vport);
	iecm_del_all_vlan_filters(vport);
	iecm_del_all_cloud_filters(vport);
	iecm_del_all_adv_rss_cfgs(vport);
	iecm_del_all_fdir_filters(vport);
}

/**
 * iecm_vport_rel_all - Delete all vports
 * @adapter: adapter from which all vports are being removed
 */
static void iecm_vport_rel_all(struct iecm_adapter *adapter)
{
	int i;

	if (!adapter->vports)
		return;

	for (i = 0; i < adapter->num_alloc_vport; i++) {
		if (!adapter->vports[i])
			continue;
		iecm_deinit_mac_addr(adapter->vports[i]);
		iecm_vport_stop(adapter->vports[i]);
		if (!test_bit(__IECM_HR_RESET_IN_PROG, adapter->flags))
			iecm_decfg_netdev(adapter->vports[i]);
		if (test_bit(__IECM_REMOVE_IN_PROG, adapter->flags))
			iecm_del_user_cfg_data(adapter->vports[i]);
		iecm_vport_rel(adapter->vports[i]);
		adapter->vports[i] = NULL;
		adapter->next_vport = 0;
	}
	adapter->num_alloc_vport = 0;
}

/**
 * iecm_vport_set_hsplit - enable or disable header split on a given vport
 * @vport: virtual port
 * @ena: flag controlling header split, On (true) or Off (false)
 */
void iecm_vport_set_hsplit(struct iecm_vport *vport, bool ena)
{
#ifdef HAVE_XDP_SUPPORT
	if (!ena) {
		clear_bit(__IECM_PRIV_FLAGS_HDR_SPLIT,
			  vport->adapter->config_data.user_flags);
		return;
	}

#endif /* HAVE_XDP_SUPPORT */
	if (iecm_is_cap_ena_all(vport->adapter, IECM_HSPLIT_CAPS,
				IECM_CAP_HSPLIT) &&
	    iecm_is_queue_model_split(vport->rxq_model))
		set_bit(__IECM_PRIV_FLAGS_HDR_SPLIT,
			vport->adapter->config_data.user_flags);
}

/**
 * iecm_vport_alloc - Allocates the next available struct vport in the adapter
 * @adapter: board private structure
 * @vport_id: vport identifier
 *
 * returns a pointer to a vport on success, NULL on failure.
 */
static struct iecm_vport *
iecm_vport_alloc(struct iecm_adapter *adapter, int vport_id)
{
	struct iecm_vport *vport = NULL;

	if (adapter->next_vport == IECM_NO_FREE_SLOT)
		return vport;

	/* Need to protect the allocation of the vports at the adapter level */
	mutex_lock(&adapter->sw_mutex);

	vport = kzalloc(sizeof(*vport), GFP_KERNEL);
	if (!vport)
		goto unlock_adapter;

	vport->adapter = adapter;
	vport->idx = adapter->next_vport;
	vport->compln_clean_budget = IECM_TX_COMPLQ_CLEAN_BUDGET;
	adapter->num_alloc_vport++;
	adapter->dev_ops.vc_ops.vport_init(vport, vport_id);

	/* Setup default MSIX irq handler for the vport */
	vport->irq_q_handler = iecm_vport_intr_clean_queues;
	vport->q_vector_base = IECM_NONQ_VEC;

	mutex_init(&vport->stop_mutex);

	/* fill vport slot in the adapter struct */
	adapter->vports[adapter->next_vport] = vport;

	/* prepare adapter->next_vport for next use */
	adapter->next_vport = iecm_get_free_slot(adapter->vports,
						 adapter->num_alloc_vport,
						 adapter->next_vport);

unlock_adapter:
	mutex_unlock(&adapter->sw_mutex);
	return vport;
}

/**
 * iecm_statistics_task - Delayed task to get statistics over mailbox
 * @work: work_struct handle to our data
 */
static void iecm_statistics_task(struct work_struct *work)
{
	struct iecm_adapter *adapter = container_of(work,
						    struct iecm_adapter,
						    stats_task.work);
	if (test_bit(__IECM_MB_STATS_PENDING, adapter->flags) &&
	    !test_bit(__IECM_HR_RESET_IN_PROG, adapter->flags))
		adapter->dev_ops.vc_ops.get_stats_msg(adapter->vports[0]);

	if (!test_bit(__IECM_CANCEL_STATS_TASK, adapter->flags))
		queue_delayed_work(adapter->stats_wq, &adapter->stats_task,
				   msecs_to_jiffies(1000));
}

/**
 * iecm_service_task - Delayed task for handling mailbox responses
 * @work: work_struct handle to our data
 *
 */
static void iecm_service_task(struct work_struct *work)
{
	struct iecm_adapter *adapter = container_of(work,
						    struct iecm_adapter,
						    serv_task.work);

	if (test_bit(__IECM_MB_INTR_MODE, adapter->flags)) {
		if (test_and_clear_bit(__IECM_MB_INTR_TRIGGER,
				       adapter->flags)) {
			iecm_recv_mb_msg(adapter, VIRTCHNL_OP_UNKNOWN, NULL, 0);
			iecm_mb_irq_enable(adapter);
		}
	} else {
		iecm_recv_mb_msg(adapter, VIRTCHNL_OP_UNKNOWN, NULL, 0);
	}

	if (iecm_is_reset_detected(adapter) &&
	    !iecm_is_reset_in_prog(adapter)) {
		dev_info(&adapter->pdev->dev, "HW reset detected\n");
		set_bit(__IECM_HR_FUNC_RESET, adapter->flags);
		queue_delayed_work(adapter->vc_event_wq,
				   &adapter->vc_event_task,
				   msecs_to_jiffies(10));
	}

	if (adapter->state == __IECM_UP &&
	    (iecm_is_cap_ena(adapter, IECM_BASE_CAPS, VIRTCHNL2_CAP_ADQ) ||
	     iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADQ)))
		iecm_adq_chnl_detect_recover(adapter->vports[0]);

	if (!test_bit(__IECM_CANCEL_SERVICE_TASK, adapter->flags))
		queue_delayed_work(adapter->serv_wq, &adapter->serv_task,
				   msecs_to_jiffies(300));
}

/**
 * iecm_restore_vlans - Restore vlan filters/vlan stripping/insert config
 * @vport: virtual port structure
 */
static void iecm_restore_vlans(struct iecm_vport *vport)
{
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
#ifdef NETIF_F_HW_VLAN_CTAG_FILTER
	if (iecm_is_feature_ena(vport, NETIF_F_HW_VLAN_CTAG_FILTER))
#else
	if (iecm_is_feature_ena(vport, NETIF_F_HW_VLAN_FILTER))
#endif /* NETIF_F_HW_VLAN_CTAG_FILTER */
		iecm_restore_vlan_filters(vport);
#endif /* HAVE_INT_NDO_VLAN_RX_ADD_VID */
}

/*
 * iecm_restore_cloud_filters - Restore cloud filters
 * @vport - vport structure
 */
static void iecm_restore_cloud_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_cloud_filter_config *cf_config;
	struct iecm_cloud_filter *cf;

	cf_config = &adapter->config_data.cf_config;
	if (!list_empty(&cf_config->cloud_filter_list)) {
		spin_lock_bh(&adapter->cloud_filter_list_lock);
		list_for_each_entry(cf, &cf_config->cloud_filter_list, list) {
			cf->add = true;
		}
		spin_unlock_bh(&adapter->cloud_filter_list_lock);
		iecm_send_add_del_cloud_filter_msg(vport, true);
	}
}

/*
 * iecm_restore_adv_rss_cfgs - Restore all RSS configuration
 * @vport - vport structure
 */
static void iecm_restore_adv_rss_cfgs(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_adv_rss *rss;

	if (!list_empty(&adapter->config_data.adv_rss_list)) {
		spin_lock_bh(&adapter->adv_rss_list_lock);
		list_for_each_entry(rss, &adapter->config_data.adv_rss_list,
				    list) {
			rss->add = true;
		}
		spin_unlock_bh(&adapter->adv_rss_list_lock);
		iecm_send_add_del_adv_rss_cfg_msg(vport, true);
	}
}

/*
 * iecm_restore_fdir_filters - Restore all Flow Director filters
 * @vport - vport structure
 */
static void iecm_restore_fdir_filters(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_fdir_fltr_config *fdir_config;
	struct iecm_fdir_fltr *fdir;

	fdir_config = &adapter->config_data.fdir_config;
	if (!list_empty(&fdir_config->fdir_fltr_list)) {
		spin_lock_bh(&adapter->fdir_fltr_list_lock);
		list_for_each_entry(fdir, &fdir_config->fdir_fltr_list, list) {
			fdir->add = true;
		}
		spin_unlock_bh(&adapter->fdir_fltr_list_lock);
		iecm_send_add_fdir_filter_msg(vport);
	}
}

/**
 * iecm_restore_features - Restore feature configs
 * @vport: virtual port structure
 */
static void iecm_restore_features(struct iecm_vport *vport)
{
	struct iecm_adapter *adapter = vport->adapter;

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_MACFILTER))
		iecm_restore_mac_filters(vport);

	if (iecm_is_cap_ena(adapter, IECM_BASE_CAPS, VIRTCHNL2_CAP_VLAN) ||
	    iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_VLAN))
		iecm_restore_vlans(vport);

	/* Restore cloud filters if ADQ is enabled */
	if (iecm_is_feature_ena(vport, NETIF_F_HW_TC))
		iecm_restore_cloud_filters(vport);

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADV_RSS))
		iecm_restore_adv_rss_cfgs(vport);

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_FDIR))
		iecm_restore_fdir_filters(vport);

}

/**
 * iecm_set_real_num_queues - set number of queues for netdev
 * @vport: virtual port structure
 *
 * Returns 0 on success, negative on failure.
 */
static int iecm_set_real_num_queues(struct iecm_vport *vport)
{
	int err;

	/* If we're in normal up path, the stack already takes the rtnl_lock
	 * for us, however, if we're doing up as a part of a hard reset, we'll
	 * need to take the lock ourself before touching the netdev.
	 */
	if (test_bit(__IECM_HR_RESET_IN_PROG, vport->adapter->flags))
		rtnl_lock();
	err = netif_set_real_num_rx_queues(vport->netdev, vport->num_rxq);
	if (err)
		goto error;
#ifdef HAVE_XDP_SUPPORT
	if (iecm_xdp_is_prog_ena(vport))
		err = netif_set_real_num_tx_queues(vport->netdev,
						   vport->num_txq - vport->num_xdp_txq);
	else
		err = netif_set_real_num_tx_queues(vport->netdev, vport->num_txq);
#else
	err = netif_set_real_num_tx_queues(vport->netdev, vport->num_txq);
#endif /* HAVE_XDP_SUPPORT */
error:
	if (test_bit(__IECM_HR_RESET_IN_PROG, vport->adapter->flags))
		rtnl_unlock();
	return err;
}

/**
 * iecm_up_complete - Complete interface up sequence
 * @vport: virtual port strucutre
 *
 * Returns 0 on success, negative on failure.
 */
static int iecm_up_complete(struct iecm_vport *vport)
{
	int err;

	err = iecm_set_real_num_queues(vport);
	if (err)
		return err;

	if (vport->adapter->link_up && !netif_carrier_ok(vport->netdev)) {
		netif_carrier_on(vport->netdev);
		netif_tx_start_all_queues(vport->netdev);
	}

	vport->adapter->state = __IECM_UP;
	return 0;
}

/**
 * iecm_rx_init_buf_tail - Write initial buffer ring tail value
 * @vport: virtual port struct
 */
static void iecm_rx_init_buf_tail(struct iecm_vport *vport)
{
	int i, j;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct iecm_rxq_group *grp = &vport->rxq_grps[i];

		if (iecm_is_queue_model_split(vport->rxq_model)) {
			for (j = 0; j < vport->num_bufqs_per_qgrp; j++) {
				struct iecm_queue *q =
					&grp->splitq.bufq_sets[j].bufq;

				writel(q->next_to_alloc, q->tail);
			}
		} else {
			for (j = 0; j < grp->singleq.num_rxq; j++) {
				struct iecm_queue *q =
					grp->singleq.rxqs[j];

				writel(q->next_to_alloc, q->tail);
			}
		}
	}
}

/* iecm_set_vlan_offload_features - set vlan offload features
 * @netdev: netdev structure
 * @prev_features: previously set features
 * @features: current features received from user
 *
 * Returns 0 on success, error value on failure
 */
static int
iecm_set_vlan_offload_features(struct net_device *netdev,
			       netdev_features_t prev_features,
			       netdev_features_t features)
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);
	bool stripping_ena = true, insertion_ena = true;
	struct iecm_virtchnl_ops *vc_ops;
	u16 vlan_ethertype = 0;

	vc_ops = &vport->adapter->dev_ops.vc_ops;
#ifdef NETIF_F_HW_VLAN_CTAG_RX
	/* keep cases separate because one ethertype for offloads can be
	 * disabled at the same time as another is disabled, so check for an
	 * enabled ethertype first, then check for disabled. Default to
	 * ETH_P_8021Q so an ethertype is specified if disabling insertion
	 * and stripping.
	 */
	if (features & (NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_STAG_TX))
		vlan_ethertype = ETH_P_8021AD;
	else if (features & (NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX))
		vlan_ethertype = ETH_P_8021Q;
	else if (prev_features & (NETIF_F_HW_VLAN_STAG_RX |
				  NETIF_F_HW_VLAN_STAG_TX))
		vlan_ethertype = ETH_P_8021AD;
	else if (prev_features & (NETIF_F_HW_VLAN_CTAG_RX |
				  NETIF_F_HW_VLAN_CTAG_TX))
		vlan_ethertype = ETH_P_8021Q;
	else
		vlan_ethertype = ETH_P_8021Q;

	if (!(features & (NETIF_F_HW_VLAN_STAG_RX | NETIF_F_HW_VLAN_CTAG_RX)))
		stripping_ena = false;
	if (!(features & (NETIF_F_HW_VLAN_STAG_TX | NETIF_F_HW_VLAN_CTAG_TX)))
		insertion_ena = false;
#else
	if (features & (NETIF_F_HW_VLAN_RX | NETIF_F_HW_VLAN_TX))
		vlan_ethertype = ETH_P_8021Q;
	if (prev_features & (NETIF_F_HW_VLAN_RX | NETIF_F_HW_VLAN_TX))
		vlan_ethertype = ETH_P_8021Q;
	else
		vlan_ethertype = ETH_P_8021Q;

	if (!(features & NETIF_F_HW_VLAN_RX))
		stripping_ena = false;
	if (!(features & NETIF_F_HW_VLAN_TX))
		insertion_ena = false;
#endif

	vport->adapter->config_data.vlan_ethertype = vlan_ethertype;

	vc_ops->strip_vlan_msg(vport, stripping_ena);
	if (vc_ops->insert_vlan_msg)
		vc_ops->insert_vlan_msg(vport, insertion_ena);

	return 0;
}

/**
 * iecm_vport_open - Bring up a vport
 * @vport: vport to bring up
 * @alloc_res: allocate queue resources
 */
static int iecm_vport_open(struct iecm_vport *vport, bool alloc_res)
{
	struct iecm_adapter *adapter = vport->adapter;
	int err;

	if (vport->adapter->state != __IECM_DOWN)
		return -EBUSY;

	/* we do not allow interface up just yet */
	netif_carrier_off(vport->netdev);

	if (alloc_res) {
		err = iecm_vport_queues_alloc(vport);
		if (err)
			return err;
	}

	err = iecm_vport_intr_alloc(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Call to interrupt alloc returned %d\n",
			err);
		goto unroll_queues_alloc;
	}

	err = adapter->dev_ops.vc_ops.vport_queue_ids_init(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Call to queue ids init returned %d\n",
			err);
		goto unroll_intr_alloc;
	}

	err = adapter->dev_ops.vc_ops.vportq_reg_init(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Call to queue reg init returned %d\n",
			err);
		goto unroll_intr_alloc;
	}
	iecm_rx_init_buf_tail(vport);

	err = iecm_vport_intr_init(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Call to vport interrupt init returned %d\n",
			err);
		goto unroll_intr_alloc;
	}
	err = adapter->dev_ops.vc_ops.config_queues(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to config queues\n");
		goto unroll_config_queues;
	}
	err = adapter->dev_ops.vc_ops.irq_map_unmap(vport, true);
	if (err) {
		dev_err(&adapter->pdev->dev, "Call to irq_map_unmap returned %d\n",
			err);
		goto unroll_config_queues;
	}
	err = adapter->dev_ops.vc_ops.enable_queues(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to enable queues\n");
		goto unroll_enable_queues;
	}

	if (adapter->dev_ops.vc_ops.enable_vport) {
		err = adapter->dev_ops.vc_ops.enable_vport(vport);
		if (err) {
			dev_err(&adapter->pdev->dev, "Failed to enable vport\n");
			err = -EAGAIN;
			goto unroll_vport_enable;
		}
	}

	iecm_restore_features(vport);

	if (adapter->rss_data.rss_lut)
		err = iecm_config_rss(vport);
	else
		err = iecm_init_rss(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to init RSS\n");
		goto unroll_init_rss;
	}
	err = iecm_up_complete(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to complete up\n");
		goto unroll_up_comp;
	}

	return 0;

unroll_up_comp:
	iecm_deinit_rss(vport);
unroll_init_rss:
	adapter->dev_ops.vc_ops.disable_vport(vport);
unroll_vport_enable:
	adapter->dev_ops.vc_ops.disable_queues(vport);
unroll_enable_queues:
	adapter->dev_ops.vc_ops.irq_map_unmap(vport, false);
unroll_config_queues:
	iecm_vport_intr_deinit(vport);
unroll_intr_alloc:
	iecm_vport_intr_rel(vport);
unroll_queues_alloc:
	if (alloc_res)
		iecm_vport_queues_rel(vport);

	return err;
}

/**
 * iecm_init_task - Delayed initialization task
 * @work: work_struct handle to our data
 *
 * Init task finishes up pending work started in probe.  Due to the asychronous
 * nature in which the device communicates with hardware, we may have to wait
 * several milliseconds to get a response.  Instead of busy polling in probe,
 * pulling it out into a delayed work task prevents us from bogging down the
 * whole system waiting for a response from hardware.
 */
static void iecm_init_task(struct work_struct *work)
{
	struct iecm_adapter *adapter = container_of(work,
						    struct iecm_adapter,
						    init_task.work);
	struct iecm_vport *vport;
	struct pci_dev *pdev;
	int vport_id, err;
	int index;

	err = adapter->dev_ops.vc_ops.core_init(adapter, &vport_id);
	if (err)
		return;

	pdev = adapter->pdev;
	vport = iecm_vport_alloc(adapter, vport_id);
	if (!vport) {
		err = -EFAULT;
		dev_err(&pdev->dev, "failed to allocate vport: %d\n",
			err);
		return;
	}
	/* Start the service task before requesting vectors. This will ensure
	 * vector information response from mailbox is handled
	 */
	queue_delayed_work(adapter->serv_wq, &adapter->serv_task,
			   msecs_to_jiffies(5 * (pdev->devfn & 0x07)));
	err = iecm_intr_req(adapter);
	if (err) {
		dev_err(&pdev->dev, "failed to enable interrupt vectors: %d\n",
			err);
		goto intr_req_err;
	}
	err = iecm_send_vlan_v2_caps_msg(adapter);
	if (err)
		goto vlan_v2_caps_failed;

	err = adapter->dev_ops.vc_ops.get_supported_desc_ids(vport);
	if (err) {
		dev_err(&pdev->dev, "failed to get required descriptor ids\n");
		goto rxdids_failed;
	}

	if (iecm_cfg_netdev(vport))
		goto cfg_netdev_err;

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_VLAN) ||
	    iecm_is_cap_ena(adapter, IECM_BASE_CAPS, VIRTCHNL2_CAP_VLAN)) {
		err = iecm_set_vlan_offload_features(vport->netdev, 0,
						     vport->netdev->features);
		if (err)
			goto cfg_netdev_err;
	}

	err = adapter->dev_ops.vc_ops.get_ptype(vport);
	if (err)
		goto cfg_netdev_err;
	queue_delayed_work(adapter->stats_wq, &adapter->stats_task,
			   msecs_to_jiffies(10 * (pdev->devfn & 0x07)));
	/* Once state is put into DOWN, driver is ready for dev_open */
	adapter->state = __IECM_DOWN;
	if (test_and_clear_bit(__IECM_UP_REQUESTED, adapter->flags))
		iecm_vport_open(vport, true);

	/* Clear the reset flag unconditionally here in case we were in reset
	 * and the link was down
	 */
	clear_bit(__IECM_HR_RESET_IN_PROG, vport->adapter->flags);

	return;

vlan_v2_caps_failed:
rxdids_failed:
cfg_netdev_err:
	iecm_intr_rel(adapter);
intr_req_err:
	index = iecm_get_vport_index(adapter, vport);
	if (index >= 0)
		adapter->vports[index] = NULL;
	iecm_vport_rel(vport);
}

/**
 * iecm_api_init - Initialize and verify device API
 * @adapter: driver specific private structure
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_api_init(struct iecm_adapter *adapter)
{
	struct iecm_reg_ops *reg_ops = &adapter->dev_ops.reg_ops;
	struct pci_dev *pdev = adapter->pdev;

	if (!adapter->dev_ops.reg_ops_init) {
		dev_err(&pdev->dev, "Invalid device, register API init not defined\n");
		return -EINVAL;
	}
	adapter->dev_ops.reg_ops_init(adapter);
	if (!(reg_ops->ctlq_reg_init && reg_ops->intr_reg_init &&
	      reg_ops->mb_intr_reg_init && reg_ops->reset_reg_init &&
	      reg_ops->trigger_reset)) {
		dev_err(&pdev->dev, "Invalid device, missing one or more register functions\n");
		return -EINVAL;
	}

	if (adapter->dev_ops.vc_ops_init) {
		struct iecm_virtchnl_ops *vc_ops;

		adapter->dev_ops.vc_ops_init(adapter);
		vc_ops = &adapter->dev_ops.vc_ops;
		if (!(vc_ops->core_init &&
		      vc_ops->vport_init &&
		      vc_ops->vport_queue_ids_init &&
		      vc_ops->get_caps &&
		      vc_ops->config_queues &&
		      vc_ops->enable_queues &&
		      vc_ops->disable_queues &&
		      vc_ops->irq_map_unmap &&
		      vc_ops->get_set_rss_lut &&
		      vc_ops->get_set_rss_hash &&
		      vc_ops->adjust_qs &&
		      vc_ops->get_ptype &&
		      vc_ops->init_max_queues)) {
			dev_err(&pdev->dev, "Invalid device, missing one or more virtchnl functions\n");
			return -EINVAL;
		}
	} else {
		iecm_vc_ops_init(adapter);
	}

	return 0;
}

/**
 * iecm_sriov_ena - Enable or change number of VFs
 * @adapter: private data struct
 * @num_vfs: number of VFs to allocate
 */
static int iecm_sriov_ena(struct iecm_adapter *adapter, int num_vfs)
{
	struct device *dev = &adapter->pdev->dev;
	int err;

	err = iecm_send_set_sriov_vfs_msg(adapter, num_vfs);
	if (err) {
		dev_err(dev, "Failed to allocate VFs: %d\n", err);
		return err;
	}

	err = pci_enable_sriov(adapter->pdev, num_vfs);
	if (err) {
		num_vfs = 0;
		iecm_send_set_sriov_vfs_msg(adapter, num_vfs);
		dev_err(dev, "Failed to enable SR-IOV: %d\n", err);
		return err;
	}

	adapter->num_vfs = num_vfs;
	return num_vfs;
}

/**
 * iecm_sriov_configure
 * @pdev: pointer to a pci_dev structure
 * @num_vfs: number of vfs to allocate
 *
 * Enable or change the number of VFs. Called when the user updates the number
 * of VFs in sysfs.
 **/
int iecm_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct iecm_adapter *adapter = pci_get_drvdata(pdev);
	int max_vfs;

	if (!iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_SRIOV)) {
		dev_info(&pdev->dev, "SR-IOV is not supported on this device\n");
		return -EOPNOTSUPP;
	}

	/* Handle error cases first */
	max_vfs = iecm_get_max_vfs(adapter);
	if (num_vfs > max_vfs) {
		dev_warn(&pdev->dev, "Requested VFs %d exceeded max VFs %d\n",
			 num_vfs, max_vfs);
		return -EINVAL;
	}

	if (num_vfs)
		return iecm_sriov_ena(adapter, num_vfs);

	if (!pci_vfs_assigned(pdev)) {
		pci_disable_sriov(adapter->pdev);
		iecm_send_set_sriov_vfs_msg(adapter, num_vfs);
		adapter->num_vfs = num_vfs;
	} else {
		dev_warn(&pdev->dev, "Unable to free VFs because some are assigned to VMs\n");
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL(iecm_sriov_configure);

/**
 * iecm_deinit_task - Device deinit routine
 * @adapter: Driver specific private structue
 *
 * Extended remove logic which will be used for
 * hard reset as well
 */
static void iecm_deinit_task(struct iecm_adapter *adapter)
{
	int i;

	set_bit(__IECM_REL_RES_IN_PROG, adapter->flags);
	/* Wait until the init_task is done else this thread might release
	 * the resources first and the other thread might end up in a bad state
	 */
	cancel_delayed_work_sync(&adapter->init_task);
	/* Required to indicate periodic task not to schedule again */
	set_bit(__IECM_CANCEL_STATS_TASK, adapter->flags);
	cancel_delayed_work_sync(&adapter->stats_task);
	clear_bit(__IECM_CANCEL_STATS_TASK, adapter->flags);
	iecm_vport_rel_all(adapter);

	/* Set all bits as we dont know on which vc_state the vhnl_wq is
	 * waiting on and wakeup the virtchnl workqueue even if it is waiting
	 * for the response as we are going down
	 */
	for (i = 0; i < IECM_VC_NBITS; i++)
		set_bit(i, adapter->vc_state);
	wake_up(&adapter->vchnl_wq);

	/* Required to indicate periodic task not to schedule again */
	set_bit(__IECM_CANCEL_SERVICE_TASK, adapter->flags);
	cancel_delayed_work_sync(&adapter->serv_task);
	clear_bit(__IECM_CANCEL_SERVICE_TASK, adapter->flags);
	iecm_intr_rel(adapter);
	/* Clear all the bits */
	for (i = 0; i < IECM_VC_NBITS; i++)
		clear_bit(i, adapter->vc_state);
	clear_bit(__IECM_REL_RES_IN_PROG, adapter->flags);
}

/**
 * iecm_check_reset_complete - check that reset is complete
 * @hw: pointer to hw struct
 * @reset_reg: struct with reset registers
 *
 * Returns 0 if device is ready to use, or -EBUSY if it's in reset.
 **/
static int iecm_check_reset_complete(struct iecm_hw *hw,
				     struct iecm_reset_reg *reset_reg)
{
	struct iecm_adapter *adapter = (struct iecm_adapter *)hw->back;
	int i;

	for (i = 0; i < 2000; i++) {
		u32 reg_val = rd32(hw, reset_reg->rstat);

		/* 0xFFFFFFFF might be read if other side hasn't cleared the
		 * register for us yet and 0xFFFFFFFF is not a valid value for
		 * the register, so treat that as invalid.
		 */
		if (reg_val != 0xFFFFFFFF && (reg_val & reset_reg->rstat_m))
			return 0;
		usleep_range(5000, 10000);
	}

	dev_warn(&adapter->pdev->dev, "Device reset timeout!\n");
	return -EBUSY;
}

/**
 * iecm_init_hard_reset - Initiate a hardware reset
 * @adapter: Driver specific private structure
 *
 * Deallocate the vports and all the resources associated with them and
 * reallocate. Also reinitialize the mailbox. Return 0 on success,
 * negative on failure.
 */
static int iecm_init_hard_reset(struct iecm_adapter *adapter)
{
	int err = 0;

	mutex_lock(&adapter->reset_lock);

	dev_info(&adapter->pdev->dev, "Device HW Reset initiated\n");
	/* Prepare for reset */
	if (test_and_clear_bit(__IECM_HR_DRV_LOAD, adapter->flags)) {
		adapter->dev_ops.reg_ops.trigger_reset(adapter,
						       __IECM_HR_DRV_LOAD);
	} else if (test_and_clear_bit(__IECM_HR_FUNC_RESET, adapter->flags)) {
		bool is_reset = iecm_is_reset_detected(adapter);

		if (adapter->state == __IECM_UP)
			set_bit(__IECM_UP_REQUESTED, adapter->flags);
		iecm_deinit_task(adapter);
		if (!is_reset)
			adapter->dev_ops.reg_ops.trigger_reset(adapter,
							       __IECM_HR_FUNC_RESET);
		iecm_deinit_dflt_mbx(adapter);
	} else if (test_and_clear_bit(__IECM_HR_CORE_RESET, adapter->flags)) {
		if (adapter->state == __IECM_UP)
			set_bit(__IECM_UP_REQUESTED, adapter->flags);
		iecm_deinit_task(adapter);
	} else {
		dev_err(&adapter->pdev->dev, "Unhandled hard reset cause\n");
		err = -EBADRQC;
		goto handle_err;
	}

	/* Wait for reset to complete */
	err = iecm_check_reset_complete(&adapter->hw, &adapter->reset_reg);
	if (err) {
		dev_err(&adapter->pdev->dev, "The driver was unable to contact the device's firmware.  Check that the FW is running. Driver state=%u\n",
			adapter->state);
		goto handle_err;
	}

	/* Reset is complete and so start building the driver resources again */
	err = iecm_init_dflt_mbx(adapter);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to initialize default mailbox: %d\n",
			err);
	}
handle_err:
	mutex_unlock(&adapter->reset_lock);
	return err;
}

/**
 * iecm_vc_event_task - Handle virtchannel event logic
 * @work: work queue struct
 */
static void iecm_vc_event_task(struct work_struct *work)
{
	struct iecm_adapter *adapter = container_of(work,
						    struct iecm_adapter,
						    vc_event_task.work);

	if (test_bit(__IECM_HR_CORE_RESET, adapter->flags) ||
	    test_bit(__IECM_HR_FUNC_RESET, adapter->flags) ||
	    test_bit(__IECM_HR_DRV_LOAD, adapter->flags)) {
		set_bit(__IECM_HR_RESET_IN_PROG, adapter->flags);
		iecm_init_hard_reset(adapter);
	}
}

/**
 * iecm_initiate_soft_reset - Initiate a software reset
 * @vport: virtual port data struct
 * @reset_cause: reason for the soft reset
 *
 * Soft reset only reallocs vport queue resources. Returns 0 on success,
 * negative on failure.
 */
int iecm_initiate_soft_reset(struct iecm_vport *vport,
			     enum iecm_flags reset_cause)
{
	enum iecm_state current_state = vport->adapter->state;
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_vport *new_vport;
	int err = 0, i;

	/* make sure we do not end up in initiating multiple resets */
	mutex_lock(&adapter->reset_lock);

	/* If the system is low on memory, we can end up in bad state if we
	 * free all the memory for queue resources and try to allocate them
	 * again. Instead, we can pre-allocate the new resources before doing
	 * anything and bailing if the alloc fails.
	 *
	 * Make a clone of the existing vport to mimic its current configuration,
	 * then modify the new structure with any requested changes. Once the
	 * allocation of the new resources is done, stop the existing vport and
	 * copy the configuration to the main vport. If an error occurred, the
	 * existing vport will be untouched.
	 *
	 */
	new_vport = kzalloc(sizeof(*vport), GFP_KERNEL);
	if (!new_vport) {
		mutex_unlock(&adapter->reset_lock);
		return -ENOMEM;
	}
	memcpy(new_vport, vport, sizeof(*vport));

	/* Adjust resource parameters prior to reallocating resources */
	switch (reset_cause) {
	case __IECM_SR_Q_CHANGE:
		adapter->dev_ops.vc_ops.adjust_qs(new_vport);
		break;
	case __IECM_SR_Q_DESC_CHANGE:
		/* Update queue parameters before allocating resources */
		iecm_vport_calc_num_q_desc(new_vport);
		break;
	case __IECM_SR_Q_SCH_CHANGE:
	case __IECM_SR_MTU_CHANGE:
	case __IECM_SR_RSC_CHANGE:
	case __IECM_SR_HSPLIT_CHANGE:
		break;
	default:
		dev_err(&adapter->pdev->dev, "Unhandled soft reset cause\n");
		err = -EINVAL;
		goto err_default;
	}

	err = iecm_vport_queues_alloc(new_vport);
	if (err)
		goto err_default;

	if (adapter->virt_ver_maj == VIRTCHNL_VERSION_MAJOR_2) {
		if (current_state <= __IECM_DOWN) {
			adapter->dev_ops.vc_ops.delete_queues(vport);
		} else {
			set_bit(__IECM_DEL_QUEUES, adapter->flags);
			iecm_vport_stop(vport);
		}

		iecm_deinit_rss(vport);
		err = adapter->dev_ops.vc_ops.add_queues(new_vport, new_vport->num_txq,
							 new_vport->num_complq,
							 new_vport->num_rxq,
							 new_vport->num_bufq);
		if (err)
			goto err_reset;
	} else {
		iecm_vport_stop(vport);
#ifdef HAVE_XDP_SUPPORT

		/* Check if any dummy Rx queues were added/removed due to XDP
		 * and re-initialize the RSS LUT if needed.
		 */
		if (new_vport->num_xdp_rxq != vport->num_xdp_rxq)
			iecm_deinit_rss(vport);
#endif /* HAVE_XDP_SUPPORT */
	}

	memcpy(vport, new_vport, sizeof(*vport));
	/* Since iecm_vport_queues_alloc was called with new_port, the queue
	 * back pointers are currently pointing to the local new_vport. Reset
	 * the backpointers to the original vport here
	 */
	for (i = 0; i < vport->num_txq_grp; i++) {
		struct iecm_txq_group *tx_qgrp = &vport->txq_grps[i];
		int j;

		tx_qgrp->vport = vport;
		for (j = 0; j < tx_qgrp->num_txq; j++)
			tx_qgrp->txqs[j]->vport = vport;

		if (iecm_is_queue_model_split(vport->txq_model))
			tx_qgrp->complq->vport = vport;
	}

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct iecm_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		struct iecm_queue *q;
		int j, num_rxq;

		rx_qgrp->vport = vport;
		for (j = 0; j < vport->num_bufqs_per_qgrp; j++)
			rx_qgrp->splitq.bufq_sets[j].bufq.vport = vport;

		if (iecm_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++) {
			if (iecm_is_queue_model_split(vport->rxq_model))
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				q = rx_qgrp->singleq.rxqs[j];
			q->vport = vport;
		}
	}

	/* Post resource allocation reset */
	if (reset_cause == __IECM_SR_Q_CHANGE) {
		iecm_intr_rel(adapter);
		iecm_intr_req(adapter);
	}

	kfree(new_vport);

	if (current_state == __IECM_UP)
		err = iecm_vport_open(vport, false);
	mutex_unlock(&adapter->reset_lock);
	return err;
err_reset:
	iecm_vport_queues_rel(vport);
err_default:
	kfree(new_vport);
	mutex_unlock(&adapter->reset_lock);
	return err;
}

/**
 * iecm_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @ent: entry in iecm_pci_tbl
 * @adapter: driver specific private structure
 *
 * Returns 0 on success, negative on failure
 */
int iecm_probe(struct pci_dev *pdev,
	       const struct pci_device_id __always_unused *ent,
	       struct iecm_adapter *adapter)
{
	int err;

	if (!adapter->drv_name) {
		dev_err(&pdev->dev, "Invalid configuration, no drv_name given\n");
		err = -EINVAL;
		return err;
	}
	if (!adapter->drv_ver) {
		dev_err(&pdev->dev, "Invalid configuration, no drv_ver given\n");
		err = -EINVAL;
		return err;
	}

	adapter->pdev = pdev;
	err = iecm_api_init(adapter);
	if (err) {
		dev_err(&pdev->dev, "Device API is incorrectly configured\n");
		return err;
	}

	err = pcim_enable_device(pdev);
	if (err)
		return err;

	err = pcim_iomap_regions(pdev, BIT(IECM_BAR0), pci_name(pdev));
	if (err) {
		dev_err(&pdev->dev, "BAR0 I/O map error %d\n", err);
		return err;
	}

	/* set up for high or low dma */
	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err)
		err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (err) {
		dev_err(&pdev->dev, "DMA configuration failed: 0x%x\n", err);
		return err;
	}

	pci_enable_pcie_error_reporting(pdev);
	pci_set_master(pdev);
	pci_set_drvdata(pdev, adapter);

	adapter->init_wq =
		alloc_workqueue("%s", WQ_MEM_RECLAIM, 0, KBUILD_MODNAME);
	if (!adapter->init_wq) {
		dev_err(&pdev->dev, "Failed to allocate workqueue\n");
		err = -ENOMEM;
		goto err_wq_alloc;
	}

	adapter->serv_wq =
		alloc_workqueue("%s", WQ_MEM_RECLAIM, 0, KBUILD_MODNAME);
	if (!adapter->serv_wq) {
		dev_err(&pdev->dev, "Failed to allocate workqueue\n");
		err = -ENOMEM;
		goto err_mbx_wq_alloc;
	}

	adapter->stats_wq =
		alloc_workqueue("%s", WQ_MEM_RECLAIM, 0, KBUILD_MODNAME);
	if (!adapter->stats_wq) {
		dev_err(&pdev->dev, "Failed to allocate workqueue\n");
		err = -ENOMEM;
		goto err_stats_wq_alloc;
	}
	adapter->vc_event_wq =
		alloc_workqueue("%s", WQ_MEM_RECLAIM, 0, KBUILD_MODNAME);
	if (!adapter->vc_event_wq) {
		dev_err(&pdev->dev, "Failed to allocate workqueue\n");
		err = -ENOMEM;
		goto err_vc_event_wq_alloc;
	}

	/* setup msglvl */
	adapter->msg_enable = netif_msg_init(adapter->debug_msk,
					     IECM_AVAIL_NETIF_M);

	adapter->vports = kcalloc(IECM_MAX_NUM_VPORTS,
				  sizeof(*adapter->vports), GFP_KERNEL);
	if (!adapter->vports) {
		err = -ENOMEM;
		goto err_vport_alloc;
	}

	adapter->netdevs = kcalloc(IECM_MAX_NUM_VPORTS,
				   sizeof(struct net_device *), GFP_KERNEL);
	if (!adapter->netdevs) {
		err = -ENOMEM;
		goto err_netdev_alloc;
	}

	err = iecm_vport_params_buf_alloc(adapter);
	if (err) {
		dev_err(&pdev->dev, "Failed to alloc vport params buffer: %d\n",
			err);
		goto err_mb_res;
	}

	err = iecm_cfg_hw(adapter);
	if (err) {
		dev_err(&pdev->dev, "Failed to configure HW structure for adapter: %d\n",
			err);
		goto err_cfg_hw;
	}

	mutex_init(&adapter->sw_mutex);
	mutex_init(&adapter->reset_lock);
	init_waitqueue_head(&adapter->vchnl_wq);
	init_waitqueue_head(&adapter->sw_marker_wq);

	spin_lock_init(&adapter->cloud_filter_list_lock);
	spin_lock_init(&adapter->mac_filter_list_lock);
	spin_lock_init(&adapter->vlan_list_lock);
	spin_lock_init(&adapter->adv_rss_list_lock);
	spin_lock_init(&adapter->fdir_fltr_list_lock);
	INIT_LIST_HEAD(&adapter->config_data.cf_config.cloud_filter_list);
	INIT_LIST_HEAD(&adapter->config_data.cf_config.block_cb_list);
	INIT_LIST_HEAD(&adapter->config_data.mac_filter_list);
	INIT_LIST_HEAD(&adapter->config_data.vlan_filter_list);
	INIT_LIST_HEAD(&adapter->config_data.adv_rss_list);
	INIT_LIST_HEAD(&adapter->config_data.fdir_config.fdir_fltr_list);

	INIT_DELAYED_WORK(&adapter->stats_task, iecm_statistics_task);
	INIT_DELAYED_WORK(&adapter->serv_task, iecm_service_task);
	INIT_DELAYED_WORK(&adapter->init_task, iecm_init_task);
	INIT_DELAYED_WORK(&adapter->vc_event_task, iecm_vc_event_task);

	adapter->dev_ops.reg_ops.reset_reg_init(&adapter->reset_reg);
	set_bit(__IECM_HR_DRV_LOAD, adapter->flags);
	queue_delayed_work(adapter->vc_event_wq, &adapter->vc_event_task,
			   msecs_to_jiffies(10 * (pdev->devfn & 0x07)));

	return 0;
err_cfg_hw:
	iecm_vport_params_buf_rel(adapter);
err_mb_res:
	kfree(adapter->netdevs);
err_netdev_alloc:
	kfree(adapter->vports);
err_vport_alloc:
	destroy_workqueue(adapter->vc_event_wq);
err_vc_event_wq_alloc:
	destroy_workqueue(adapter->stats_wq);
err_stats_wq_alloc:
	destroy_workqueue(adapter->serv_wq);
err_mbx_wq_alloc:
	destroy_workqueue(adapter->init_wq);
err_wq_alloc:
	pci_disable_pcie_error_reporting(pdev);
	return err;
}
EXPORT_SYMBOL(iecm_probe);

/**
 * iecm_remove - Device removal routine
 * @pdev: PCI device information struct
 */
void iecm_remove(struct pci_dev *pdev)
{
	struct iecm_adapter *adapter = pci_get_drvdata(pdev);

	if (!adapter)
		return;

	dev_info(&pdev->dev, "Removing device\n");
	set_bit(__IECM_REMOVE_IN_PROG, adapter->flags);

	/* Wait until vc_event_task is done to consider if any hard reset is
	 * in progress else we may go ahead and release the resources but the
	 * thread doing the hard reset might continue the init path and
	 * end up in bad state.
	 */
	cancel_delayed_work_sync(&adapter->vc_event_task);
	if (adapter->num_vfs)
		iecm_sriov_configure(pdev, 0);
	iecm_deinit_task(adapter);
	/* Be a good citizen and leave the device clean on exit */
	adapter->dev_ops.reg_ops.trigger_reset(adapter, __IECM_HR_FUNC_RESET);
	iecm_deinit_dflt_mbx(adapter);
	msleep(20);
	destroy_workqueue(adapter->serv_wq);
	destroy_workqueue(adapter->vc_event_wq);
	destroy_workqueue(adapter->stats_wq);
	destroy_workqueue(adapter->init_wq);
	kfree(adapter->vports);
	kfree(adapter->netdevs);
	kfree(adapter->vlan_caps);
	iecm_vport_params_buf_rel(adapter);
	mutex_destroy(&adapter->sw_mutex);
	mutex_destroy(&adapter->reset_lock);
	pci_disable_pcie_error_reporting(pdev);
	pcim_iounmap_regions(pdev, BIT(IECM_BAR0));
	pci_disable_device(pdev);
}
EXPORT_SYMBOL(iecm_remove);

/**
 * iecm_addr_sync - Callback for dev_(mc|uc)_sync to add address
 * @netdev: the netdevice
 * @addr: address to add
 *
 * Called by __dev_(mc|uc)_sync when an address needs to be added. We call
 * __dev_(uc|mc)_sync from .set_rx_mode. Kernel takes addr_list_lock spinlock
 * meaning we cannot sleep in this context. Due to this, we have to add the
 * filter and send the virtchnl message asynchronously without waiting for the
 * response from the other side. We won't know whether or not the operation
 * actually succeeded until we get the message back.  Returns 0 on success,
 * negative on failure.
 */
static int iecm_addr_sync(struct net_device *netdev, const u8 *addr)
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);

	return iecm_add_mac_filter(vport, addr, true);
}

/**
 * iecm_addr_unsync - Callback for dev_(mc|uc)_sync to remove address
 * @netdev: the netdevice
 * @addr: address to add
 *
 * Called by __dev_(mc|uc)_sync when an address needs to be added. We call
 * __dev_(uc|mc)_sync from .set_rx_mode. Kernel takes addr_list_lock spinlock
 * meaning we cannot sleep in this context. Due to this we have to delete the
 * filter and send the virtchnl message asychronously without waiting for the
 * return from the other side.  We won't know whether or not the operation
 * actually succeeded until we get the message back. Returns 0 on success,
 * negative on failure.
 */
static int iecm_addr_unsync(struct net_device *netdev, const u8 *addr)
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);

	/* Under some circumstances, we might receive a request to delete
	 * our own device address from our uc list. Because we store the
	 * device address in the VSI's MAC/VLAN filter list, we need to ignore
	 * such requests and not delete our device address from this list.
	 */
	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	iecm_del_mac_filter(vport, addr, true);

	return 0;
}

/**
 * iecm_set_rx_mode - NDO callback to set the netdev filters
 * @netdev: network interface device structure
 *
 * Stack takes addr_list_lock spinlock before calling our .set_rx_mode.  We
 * cannot sleep in this context.
 */
static void iecm_set_rx_mode(struct net_device *netdev)
{
	struct iecm_adapter *adapter = iecm_netdev_to_adapter(netdev);
	int err;

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_MACFILTER)) {
		__dev_uc_sync(netdev, iecm_addr_sync, iecm_addr_unsync);
		__dev_mc_sync(netdev, iecm_addr_sync, iecm_addr_unsync);
	}

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_PROMISC)) {
		bool changed = false;

		/* IFF_PROMISC enables both unicast and multicast promiscuous,
		 * while IFF_ALLMULTI only enables multicast such that:
		 *
		 * promisc  + allmulti		= unicast | multicast
		 * promisc  + !allmulti		= unicast | multicast
		 * !promisc + allmulti		= multicast
		 */
		if ((netdev->flags & IFF_PROMISC) &&
		    !test_and_set_bit(__IECM_PROMISC_UC,
				      adapter->config_data.user_flags)) {
			changed = true;
			dev_info(&adapter->pdev->dev, "Entering promiscuous mode\n");
			if (!test_and_set_bit(__IECM_PROMISC_MC,
					      adapter->flags))
				dev_info(&adapter->pdev->dev, "Entering multicast promiscuous mode\n");
		}
		if (!(netdev->flags & IFF_PROMISC) &&
		    test_and_clear_bit(__IECM_PROMISC_UC,
				       adapter->config_data.user_flags)) {
			changed = true;
			dev_info(&adapter->pdev->dev, "Leaving promiscuous mode\n");
		}
		if (netdev->flags & IFF_ALLMULTI &&
		    !test_and_set_bit(__IECM_PROMISC_MC,
				      adapter->config_data.user_flags)) {
			changed = true;
			dev_info(&adapter->pdev->dev, "Entering multicast promiscuous mode\n");
		}
		if (!(netdev->flags & (IFF_ALLMULTI | IFF_PROMISC)) &&
		    test_and_clear_bit(__IECM_PROMISC_MC,
				       adapter->config_data.user_flags)) {
			changed = true;
			dev_info(&adapter->pdev->dev, "Leaving multicast promiscuous mode\n");
		}

		if (changed) {
			err = iecm_set_promiscuous(adapter);
			if (err) {
				dev_info(&adapter->pdev->dev, "Failed to set promiscuous mode: %d\n",
					 err);
			}
		}
	}
}

/**
 * iecm_set_features - set the netdev feature flags
 * @netdev: ptr to the netdev being adjusted
 * @features: the feature set that the stack is suggesting
 */
static int iecm_set_features(struct net_device *netdev,
			     netdev_features_t features)
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);
	struct iecm_adapter *adapter = vport->adapter;
	int err = 0;

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_VLAN) ||
	    iecm_is_cap_ena(adapter, IECM_BASE_CAPS, VIRTCHNL2_CAP_VLAN)) {
		err = iecm_set_vlan_offload_features(netdev, netdev->features,
						     features);
		if (err)
			return err;
	}

#ifdef NETIF_F_GRO_HW
	if ((netdev->features ^ features) & NETIF_F_GRO_HW) {
		netdev->features ^= NETIF_F_GRO_HW;
		err = iecm_initiate_soft_reset(vport, __IECM_SR_RSC_CHANGE);
	}
#endif /* NETIF_F_GRO_HW */

	return err;
}

/**
 * iecm_fix_netdev_vlan_features - fix netdev VLAN features if required
 * @vport: virtual port data structure
 * @requested_features: netdev features requested by stack
 *
 * CTAG and STAG are mutually exclusive. If user tries to turn on both CTAG and
 * STAG at the same time, this call back will turn off the STAG flag based on
 * the requested features from the stack.
 */
static netdev_features_t
iecm_fix_netdev_vlan_features(struct iecm_vport *vport,
			      netdev_features_t requested_features)
{
	struct iecm_adapter *adapter = vport->adapter;
	netdev_features_t allowed_features;

	allowed_features = iecm_get_vlan_features(vport, true) |
				iecm_get_vlan_features(vport, false);

	if (!iecm_is_netdev_vlan_feature_allowed(requested_features,
						 allowed_features,
						 IECM_F_HW_VLAN_CTAG_TX))
		requested_features &= ~IECM_F_HW_VLAN_CTAG_TX;

	if (!iecm_is_netdev_vlan_feature_allowed(requested_features,
						 allowed_features,
						 IECM_F_HW_VLAN_CTAG_RX))
		requested_features &= ~IECM_F_HW_VLAN_CTAG_RX;

	if (!iecm_is_netdev_vlan_feature_allowed(requested_features,
						 allowed_features,
						 IECM_F_HW_VLAN_CTAG_FILTER))
		requested_features &= ~IECM_F_HW_VLAN_CTAG_FILTER;

#ifdef NETIF_F_HW_VLAN_STAG_TX
	if (!iecm_is_netdev_vlan_feature_allowed(requested_features,
						 allowed_features,
						 NETIF_F_HW_VLAN_STAG_TX))
		requested_features &= ~NETIF_F_HW_VLAN_STAG_TX;
#endif /* NETIF_F_HW_VLAN_STAG_TX */

#ifdef NETIF_F_HW_VLAN_STAG_RX
	if (!iecm_is_netdev_vlan_feature_allowed(requested_features,
						 allowed_features,
						 NETIF_F_HW_VLAN_STAG_RX))
		requested_features &= ~NETIF_F_HW_VLAN_STAG_RX;
#endif /* NETIF_F_HW_VLAN_STAG_RX */

#ifdef NETIF_F_HW_VLAN_STAG_FILTER
	if (!iecm_is_netdev_vlan_feature_allowed(requested_features,
						 allowed_features,
						 NETIF_F_HW_VLAN_STAG_FILTER))
		requested_features &= ~NETIF_F_HW_VLAN_STAG_FILTER;
#endif /* NETIF_F_HW_VLAN_STAG_RX */

#if defined(NETIF_F_HW_VLAN_STAG_RX) && defined(NETIF_F_HW_VLAN_STAG_TX)
	if ((requested_features &
	     (IECM_F_HW_VLAN_CTAG_TX | IECM_F_HW_VLAN_CTAG_RX)) &&
	    (requested_features &
	     (NETIF_F_HW_VLAN_STAG_TX | NETIF_F_HW_VLAN_STAG_RX)) &&
	    adapter->vlan_caps->offloads.ethertype_match ==
	     VIRTCHNL_ETHERTYPE_STRIPPING_MATCHES_INSERTION) {
		netdev_warn(vport->netdev, "cannot support CTAG and STAG VLAN stripping and/or insertion simultaneously since CTAG and STAG offloads are mutually exclusive, clearing STAG offload settings\n");
		requested_features &= ~(NETIF_F_HW_VLAN_STAG_RX |
					NETIF_F_HW_VLAN_STAG_TX);
	}
#endif /* NETIF_F_HW_VLAN_STAG_RX && NETIF_F_HW_VLAN_STAG_TX */

	return requested_features;
}

/**
 * iecm_fix_features - fix up the netdev feature bits
 * @netdev: our net device
 * @features: desired feature bits
 *
 * Returns fixed-up features bits
 */
static netdev_features_t iecm_fix_features(struct net_device *netdev,
					   netdev_features_t features)
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);

	return iecm_fix_netdev_vlan_features(vport, features);
}

/**
 * iecm_open - Called when a network interface becomes active
 * @netdev: network interface device structure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the netdev watchdog is enabled,
 * and the stack is notified that the interface is ready.
 *
 * Returns 0 on success, negative value on failure
 */
static int iecm_open(struct net_device *netdev)
{
	struct iecm_netdev_priv *np = netdev_priv(netdev);

	return iecm_vport_open(np->vport, true);
}

/**
 * iecm_change_mtu - NDO callback to change the MTU
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 */
static int iecm_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct iecm_vport *vport =  iecm_netdev_to_vport(netdev);

#ifdef HAVE_NETDEVICE_MIN_MAX_MTU
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	if (new_mtu < netdev->extended->min_mtu) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   netdev->extended->min_mtu);
		return -EINVAL;
	} else if (new_mtu > netdev->extended->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   netdev->extended->max_mtu);
		return -EINVAL;
	}
#else /* HAVE_RHEL7_EXTENDED_MIN_MAX_MTU */
	if (new_mtu < netdev->min_mtu) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   netdev->min_mtu);
		return -EINVAL;
	} else if (new_mtu > netdev->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   netdev->max_mtu);
		return -EINVAL;
	}
#endif /* HAVE_RHEL7_EXTENDED_MIN_MAX_MTU */
#else /* HAVE_NETDEVICE_MIN_MAX_MTU */
	if (new_mtu < ETH_MIN_MTU) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   ETH_MIN_MTU);
		return -EINVAL;
	} else if (new_mtu > vport->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   vport->max_mtu);
		return -EINVAL;
	}
#endif /* HAVE_NETDEVICE_MIN_MAX_MTU */
	netdev->mtu = new_mtu;

	return iecm_initiate_soft_reset(vport, __IECM_SR_MTU_CHANGE);
}

#ifdef HAVE_NDO_FEATURES_CHECK
/**
 * iecm_features_check - Validate encapsulated packet conforms to limits
 * @skb: skb buffer
 * @netdev: This port's netdev
 * @features: Offload features that the stack believes apply
 */
static netdev_features_t
iecm_features_check(struct sk_buff *skb,
		    struct net_device *netdev,
		    netdev_features_t features)
{
	struct iecm_adapter *adapter = iecm_netdev_to_adapter(netdev);
	size_t len;

	/* No point in doing any of this if neither checksum nor GSO are
	 * being requested for this frame.  We can rule out both by just
	 * checking for CHECKSUM_PARTIAL
	 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return features;

	/* We cannot support GSO if the MSS is going to be less than
	 * 88 bytes. If it is then we need to drop support for GSO.
	 */
	if (skb_is_gso(skb) &&
	    (skb_shinfo(skb)->gso_size < IECM_TX_TSO_MIN_MSS))
		features &= ~NETIF_F_GSO_MASK;

	/* MACLEN can support at most 63 words */
	len = skb_network_header(skb) - skb->data;
	if (len & ~(63 * 2))
		goto out_err;

	/* IPLEN and EIPLEN can support at most 127 dwords */
	len = skb_transport_header(skb) - skb_network_header(skb);
	if (len & ~(iecm_get_max_tx_hdr_size(adapter)))
		goto out_err;

	if (skb->encapsulation) {
		/* L4TUNLEN can support 127 words */
		len = skb_inner_network_header(skb) - skb_transport_header(skb);
		if (len & ~(127 * 2))
			goto out_err;

		/* IPLEN can support at most 127 dwords */
		len = skb_inner_transport_header(skb) -
		      skb_inner_network_header(skb);
		if (len & ~(iecm_get_max_tx_hdr_size(adapter)))
			goto out_err;
	}

	/* No need to validate L4LEN as TCP is the only protocol with a
	 * a flexible value and we support all possible values supported
	 * by TCP, which is at most 15 dwords
	 */

	return features;
out_err:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

#endif /* HAVE_NDO_FEATURES_CHECK */
#ifdef HAVE_ETF_SUPPORT
/**
 * iecm_change_tx_sch_mode - reset queue context with appropriate
 * tx scheduling mode
 * @vport: virtual port data structure
 * @txq: queue to reset
 * @flow_sched: true if flow scheduling requested, false otherwise
 */
static int iecm_change_tx_sch_mode(struct iecm_vport *vport,
				   struct iecm_queue *txq,
				   bool flow_sched)
{
	if (flow_sched && !test_bit(__IECM_Q_FLOW_SCH_EN, txq->flags))
		return iecm_initiate_soft_reset(vport,
						__IECM_SR_Q_SCH_CHANGE);
	else if (!flow_sched && test_bit(__IECM_Q_FLOW_SCH_EN, txq->flags))
		return iecm_initiate_soft_reset(vport,
						__IECM_SR_Q_SCH_CHANGE);

	return 0;
}

static int iecm_offload_txtime(struct iecm_vport *vport,
			       struct tc_etf_qopt_offload *qopt)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_queue *tx_q;
	int err = 0;

	if (!iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_EDT))
		return -EOPNOTSUPP;

	if (qopt->queue < 0 || qopt->queue > vport->num_txq)
		return -EINVAL;

	/* Set config data to enable in future when queues are allocated */
	if (qopt->enable)
		set_bit(qopt->queue, adapter->config_data.etf_qenable);
	else
		clear_bit(qopt->queue, adapter->config_data.etf_qenable);

	tx_q = vport->txqs[qopt->queue];

	/* MEV-1 does not support queue based scheduling in the split queue
	 * mode.  It will only be enabled in MEV-2 and beyond based on the CP
	 * advertising the VIRTCHNL2_CAP_SPLITQ_QSCHED capability flag
	 */
	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS,
			    VIRTCHNL2_CAP_SPLITQ_QSCHED)) {
		err = iecm_change_tx_sch_mode(vport, tx_q, qopt->enable);
	} else {
		/* Set bit in queue itself if queues are already allocated */
		if (qopt->enable)
			set_bit(__IECM_Q_ETF_EN, tx_q->flags);
		else
			clear_bit(__IECM_Q_ETF_EN, tx_q->flags);
	}

	return err;
}
#endif /* HAVE_ETF_SUPPORT */

#ifdef HAVE_SETUP_TC
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
#ifdef __TC_MQPRIO_MODE_MAX
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
/**
 * iecm_is_vlan_tc_filter_allowed - allowed to add tc-filter using VLAN
 * @vport: vport structure
 * @vlan: VLAN to verify
 *
 * Using specified "vlan" ID, there must be active VLAN filter in VF's
 * MAC-VLAN filter list.
 */
static bool
iecm_is_vlan_tc_filter_allowed(struct iecm_vport *vport,
			       struct iecm_vlan *vlan)
{
	struct iecm_vlan_filter *f;
	bool allowed;

	spin_lock_bh(&vport->adapter->vlan_list_lock);
	f = iecm_find_vlan(vport, vlan);
	allowed = (f && !f->add && !f->remove);
	spin_unlock_bh(&vport->adapter->vlan_list_lock);
	return allowed;
}
#endif /* HAVE_INT_NDO_VLAN_RX_ADD_VID */

/**
 * iecm_is_mac_tc_filter_allowed - allowed to add tc-filter using MAC addr
 * @vport: vport structure
 * @macaddr: MAC address
 *
 * Using specified MAC address, there must be active MAC filter in
 * MAC filter list.
 */
static bool
iecm_is_mac_tc_filter_allowed(struct iecm_vport *vport, const u8 *macaddr)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_mac_filter *f;
	bool allowed;

	spin_lock_bh(&adapter->mac_filter_list_lock);
	f = iecm_find_mac_filter(vport, macaddr);
	allowed = (f && !f->add && !f->remove);
	spin_unlock_bh(&adapter->mac_filter_list_lock);
	return allowed;
}

#ifdef HAVE_TC_FLOWER_ENC
/**
 * iecm_parse_keyid - Parse keyid
 * @rule: Flow rule structure
 * @field_flags: Cloud filter flags
 */
static void  iecm_parse_keyid(struct flow_rule *rule, u8 *field_flags)
{
	struct flow_match_enc_keyid match;

	flow_rule_match_enc_keyid(rule, &match);

	if (match.mask->keyid != 0)
		*field_flags |= IECM_CLOUD_FIELD_TEN_ID;
}
#endif /* HAVE_TC_FLOWER_ENC */

/**
 * iecm_parse_flow_type - Parse flow type based on L2 and L3 protocols
 * @vport: vport structure
 * @rule: rule from user
 * @cf: Structure for the virtchnl filter
 * @filter: Structure for the cloud filter
 *
 * Return 0 on success, negative on failure
 */
static int
iecm_parse_flow_type(struct iecm_vport *vport,
		     struct flow_rule *rule, struct virtchnl_filter *cf,
		     struct iecm_cloud_filter *filter)
{
	struct iecm_adapter *adapter = vport->adapter;
	enum virtchnl_flow_type flow_type;
	struct flow_match_basic match;
	u16 n_proto_mask = 0;
	u16 n_proto_key = 0;
	u16 n_proto = 0;
	u8 ip_proto = 0;

	flow_rule_match_basic(rule, &match);

	n_proto_key = ntohs(match.key->n_proto);
	n_proto_mask = ntohs(match.mask->n_proto);

	if (n_proto_key == ETH_P_ALL) {
		n_proto_key = 0;
		n_proto_mask = 0;
	}
	n_proto = n_proto_key & n_proto_mask;
	if (n_proto != ETH_P_IP && n_proto != ETH_P_IPV6)
		return -EINVAL;

	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADQ)) {
		if (match.key->ip_proto != IPPROTO_TCP &&
		    match.key->ip_proto != IPPROTO_UDP) {
			dev_err(&adapter->pdev->dev,
				"Only TCP or UDP transport is supported\n");
			return -EINVAL;
		}
	} else if (match.key->ip_proto != IPPROTO_TCP) {
		dev_err(&adapter->pdev->dev,
			"Only TCP transport is supported\n");
		return -EINVAL;
	}
	ip_proto = match.key->ip_proto;

	/* determine VIRTCHNL flow_type based on L3 and L4 protocol */
	if (n_proto == ETH_P_IP)
		flow_type = (ip_proto == IPPROTO_TCP) ?
			     VIRTCHNL_TCP_V4_FLOW :
			     VIRTCHNL_UDP_V4_FLOW;
	else
		flow_type = (ip_proto == IPPROTO_TCP) ?
			     VIRTCHNL_TCP_V6_FLOW :
			     VIRTCHNL_UDP_V6_FLOW;
	cf->flow_type = flow_type;
	filter->f.flow_type = flow_type;

	return 0;
}

/**
 * iecm_parse_ether_header - Parse ethernet header fields
 * @vport: vport structure
 * @field_flags: Cloud filter flags
 * @d_spec: Virtchnl structure for L4 specs
 * @m_spec: Virtchnl structure for L4 specs
 * @rule: Flow rule structure
 *
 * Return 0 on success, negative on failure
 */
static int
iecm_parse_ether_header(struct iecm_vport *vport, u8 *field_flags,
			struct virtchnl_l4_spec *d_spec,
			struct virtchnl_l4_spec *m_spec,
			struct flow_rule *rule)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct flow_match_eth_addrs match;
	bool adv_adq_ena;

	adv_adq_ena = iecm_is_cap_ena(adapter, IECM_OTHER_CAPS,
				      VIRTCHNL2_CAP_ADQ);

	flow_rule_match_eth_addrs(rule, &match);

	/* use is_broadcast and is_zero to check for all 0xf or 0 */
	if (!is_zero_ether_addr(match.mask->dst)) {
		if (adv_adq_ena || is_broadcast_ether_addr(match.mask->dst)) {
			*field_flags |= IECM_CLOUD_FIELD_OMAC;
		} else {
			dev_err(&adapter->pdev->dev, "Bad ether dest mask %pM\n",
				match.mask->dst);
			return -EINVAL;
		}
	}

	if (!is_zero_ether_addr(match.mask->src)) {
		if (adv_adq_ena || is_broadcast_ether_addr(match.mask->src)) {
			*field_flags |= IECM_CLOUD_FIELD_IMAC;
		} else {
			dev_err(&adapter->pdev->dev, "Bad ether src mask %pM\n",
				match.mask->src);
			return -EINVAL;
		}
	}

	if (!is_zero_ether_addr(match.key->dst)) {
		if (!iecm_is_mac_tc_filter_allowed(adapter->vports[0],
						   match.key->dst)) {
			dev_err(&adapter->pdev->dev,
				"Dest MAC %pM doesn't belong to this device\n",
				match.key->dst);
			return -EINVAL;
		}

		if (is_valid_ether_addr(match.key->dst) ||
		    is_multicast_ether_addr(match.key->dst)) {
			/* set the mask if a valid dst_mac address */
			if (adv_adq_ena)
				ether_addr_copy(m_spec->dst_mac,
						match.mask->dst);
			else
				eth_broadcast_addr(m_spec->dst_mac);
			ether_addr_copy(d_spec->dst_mac,
					match.key->dst);
		}
	}

	if (!is_zero_ether_addr(match.key->src))
		if (is_valid_ether_addr(match.key->src) ||
		    is_multicast_ether_addr(match.key->src)) {
			/* set the mask if a valid src_mac address */
			if (adv_adq_ena) {
				ether_addr_copy(m_spec->src_mac,
						match.mask->src);
			} else {
				eth_broadcast_addr(m_spec->src_mac);
			}
			ether_addr_copy(d_spec->src_mac,
					match.key->src);
		}
	return 0;
}

/**
 * iecm_parse_vlan_header - Parse vlan header fields
 * @vport: vport structure
 * @field_flags: Cloud filter flags
 * @d_spec: Virtchnl structure for L4 specs
 * @m_spec: Virtchnl structure for L4 specs
 * @rule: Flow rule structure
 *
 * Return 0 on success, negative on failure
 */
static int
iecm_parse_vlan_header(struct iecm_vport *vport, u8 *field_flags,
		       struct virtchnl_l4_spec *d_spec,
		       struct virtchnl_l4_spec *m_spec,
		       struct flow_rule *rule)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct flow_match_vlan match;

	flow_rule_match_vlan(rule, &match);
	if (match.mask->vlan_id) {
		u16 vid = match.key->vlan_id & VLAN_VID_MASK;
		struct iecm_vlan vlan;

		vlan = IECM_VLAN(vid, ETH_P_8021Q);

		if (match.mask->vlan_id != VLAN_VID_MASK) {
			dev_err(&adapter->pdev->dev, "Bad vlan mask %u\n",
				match.mask->vlan_id);
			return -EINVAL;
		}
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
		if (!iecm_is_vlan_tc_filter_allowed(vport, &vlan)) {
			dev_err(&adapter->pdev->dev,
				"VLAN %u doesn't belong to this VF\n",
				vid);
			return -EINVAL;
		}
#endif /* HAVE_INT_NDO_VLAN_RX_ADD_VID */
		*field_flags |= IECM_CLOUD_FIELD_IVLAN;
		m_spec->vlan_id = cpu_to_be16(match.mask->vlan_id);
		d_spec->vlan_id = cpu_to_be16(match.key->vlan_id);
	}
	return 0;
}

/**
 * iecm_parse_ipv4_header - Parse ipv4 header fields
 * @vport: vport structure
 * @field_flags: Cloud filter flags
 * @d_spec: Virtchnl structure for L4 specs
 * @m_spec: Virtchnl structure for L4 specs
 * @rule: Flow rule structure
 *
 * Return 0 on success, negative on failure
 */
static int
iecm_parse_ipv4_header(struct iecm_vport *vport, u8 *field_flags,
		       struct virtchnl_l4_spec *d_spec,
		       struct virtchnl_l4_spec *m_spec,
		       struct flow_rule *rule)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct flow_match_ipv4_addrs match;
	bool adv_adq_ena;

	adv_adq_ena = iecm_is_cap_ena(adapter, IECM_OTHER_CAPS,
				      VIRTCHNL2_CAP_ADQ);

	flow_rule_match_ipv4_addrs(rule, &match);

	if (*field_flags & IECM_CLOUD_FIELD_TEN_ID) {
		dev_info(&adapter->pdev->dev,
			 "Tenant id not allowed for ip filter\n");
		return -EINVAL;
	}

	if (match.mask->dst) {
		if (adv_adq_ena || match.mask->dst == cpu_to_be32(0xffffffff)) {
			*field_flags |= IECM_CLOUD_FIELD_IIP;
		} else {
			dev_err(&adapter->pdev->dev, "Bad ip dst mask 0x%08x\n",
				be32_to_cpu(match.mask->dst));
			return -EINVAL;
		}
	}

	if (match.mask->src) {
		if (adv_adq_ena || match.mask->src == cpu_to_be32(0xffffffff)) {
			*field_flags |= IECM_CLOUD_FIELD_IIP;
		} else {
			dev_err(&adapter->pdev->dev, "Bad ip src mask 0x%08x\n",
				be32_to_cpu(match.mask->dst));
			return -EINVAL;
		}
	}

	if (match.key->dst) {
		if (adv_adq_ena)
			m_spec->dst_ip[0] = match.mask->dst;
		else
			m_spec->dst_ip[0] = cpu_to_be32(0xffffffff);
		d_spec->dst_ip[0] = match.key->dst;
	}

	if (match.key->src) {
		if (adv_adq_ena)
			m_spec->src_ip[0] = match.mask->src;
		else
			m_spec->src_ip[0] = cpu_to_be32(0xffffffff);
		d_spec->src_ip[0] = match.key->src;
	}
	return 0;
}

/**
 * iecm_parse_ipv6_header - Parse ipv6 header fields
 * @vport: vport structure
 * @field_flags: Cloud filter flags
 * @d_spec: Virtchnl structure for L4 specs
 * @m_spec: Virtchnl structure for L4 specs
 * @rule: Flow rule structure
 *
 * Return 0 on success, negative on failure
 */
static int
iecm_parse_ipv6_header(struct iecm_vport *vport, u8 *field_flags,
		       struct virtchnl_l4_spec *d_spec,
		       struct virtchnl_l4_spec *m_spec,
		       struct flow_rule *rule)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct flow_match_ipv6_addrs match;
	int i;

	flow_rule_match_ipv6_addrs(rule, &match);

	/* validate mask, make sure it is not IPV6_ADDR_ANY */
	if (ipv6_addr_any(&match.mask->dst)) {
		dev_err(&adapter->pdev->dev, "Bad ipv6 dst mask 0x%02x\n",
			IPV6_ADDR_ANY);
		return -EINVAL;
	}

	/* src and dest IPv6 address should not be LOOPBACK
	 * (0:0:0:0:0:0:0:1) which can be represented as ::1
	 */
	if (ipv6_addr_loopback(&match.key->dst) ||
	    ipv6_addr_loopback(&match.key->src)) {
		dev_err(&adapter->pdev->dev,
			"ipv6 addr should not be loopback\n");
		return -EINVAL;
	}

	if (!ipv6_addr_any(&match.mask->dst) ||
	    !ipv6_addr_any(&match.mask->src))
		*field_flags |= IECM_CLOUD_FIELD_IIP;

	/* copy dest IPv6 mask and address */
	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADQ)) {
		memcpy(&m_spec->dst_ip, &match.mask->dst.s6_addr32,
		       sizeof(m_spec->dst_ip));
	} else {
		for (i = 0; i < 4; i++)
			m_spec->dst_ip[i] = cpu_to_be32(0xffffffff);
	}
	memcpy(&d_spec->dst_ip, &match.key->dst.s6_addr32,
	       sizeof(d_spec->dst_ip));

	/* copy source IPv6 mask and address */
	if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADQ)) {
		memcpy(&m_spec->src_ip, &match.mask->src.s6_addr32,
		       sizeof(m_spec->src_ip));
	} else {
		for (i = 0; i < 4; i++)
			m_spec->src_ip[i] = cpu_to_be32(0xffffffff);
	}
	memcpy(&d_spec->src_ip, &match.key->src.s6_addr32,
	       sizeof(d_spec->src_ip));

	return 0;
}

/**
 * iecm_parse_l4_header - Parse l4 header fields
 * @vport: vport structure
 * @d_spec: Virtchnl structure for L4 specs
 * @m_spec: Virtchnl structure for L4 specs
 * @rule: Flow rule structure
 *
 * Return 0 on success, negative on failure
 */
static int
iecm_parse_l4_header(struct iecm_vport *vport,
		     struct virtchnl_l4_spec *d_spec,
		     struct virtchnl_l4_spec *m_spec,
		     struct flow_rule *rule)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct flow_match_ports match;

	flow_rule_match_ports(rule, &match);

	if (match.key->dst) {
		if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS,
				    VIRTCHNL2_CAP_ADQ) ||
		    match.mask->dst == cpu_to_be16(0xffff)) {
			m_spec->dst_port = match.mask->dst;
			d_spec->dst_port = match.key->dst;
		} else {
			dev_err(&adapter->pdev->dev, "Bad dst port mask %u\n",
				be16_to_cpu(match.mask->dst));
			return -EINVAL;
		}
	}

	if (match.key->src) {
		if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS,
				    VIRTCHNL2_CAP_ADQ) ||
		    match.mask->src == cpu_to_be16(0xffff)) {
			m_spec->src_port = match.mask->src;
			d_spec->src_port = match.key->src;
		} else {
			dev_err(&adapter->pdev->dev, "Bad src port mask %u\n",
				be16_to_cpu(match.mask->src));
			return -EINVAL;
		}
	}
	return 0;
}

/**
 * iecm_parse_cls_flower - Parse tc flower filters provided by kernel
 * @vport: vport structure
 * @f: pointer to struct flow_cls_offload
 * @filter: pointer to cloud filter structure
 */
static int iecm_parse_cls_flower(struct iecm_vport *vport,
				 struct flow_cls_offload *f,
				 struct iecm_cloud_filter *filter)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct iecm_adapter *adapter = vport->adapter;
	struct virtchnl_l4_spec *d_spec, *m_spec;
	struct virtchnl_filter *cf = &filter->f;
	struct flow_dissector *dissector;
	u8 field_flags = 0;
	u16 addr_type = 0;
	int err = 0;

	dissector = rule->match.dissector;
	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
#ifdef HAVE_TC_FLOWER_ENC
	      BIT(FLOW_DISSECTOR_KEY_ENC_KEYID) |
#endif /* HAVE_TC_FLOWER_ENC */
	      BIT(FLOW_DISSECTOR_KEY_PORTS))) {
		dev_err(&adapter->pdev->dev, "Unsupported key used: 0x%x\n",
			dissector->used_keys);
		return -EOPNOTSUPP;
	}
#ifdef HAVE_TC_FLOWER_ENC
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ENC_KEYID))
		iecm_parse_keyid(rule, &field_flags);
#endif /* HAVE_TC_FLOWER_ENC */

	/* even though following code refers as "tcp_sec", it is not
	 * just for TCP but a generic struct representing
	 * L2, L3 + L4 fields if specified
	 */
	m_spec = &cf->mask.tcp_spec;
	d_spec = &cf->data.tcp_spec;

	/* determine flow type, TCP/UDP_V4[6]_FLOW based on
	 * L2 proto (aka ETH proto) and L3 proto (aka IP_PROTO)
	 */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		err = iecm_parse_flow_type(vport, rule, cf, filter);
		if (err)
			return err;
	}

	/* process Ethernet header fields */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		err = iecm_parse_ether_header(vport, &field_flags,
					      d_spec, m_spec, rule);
		if (err)
			return err;
	}

	/* process VLAN header for single VLAN (type could be S/C-tag) */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		err = iecm_parse_vlan_header(vport, &field_flags,
					     d_spec, m_spec, rule);
		if (err)
			return err;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);
		addr_type = match.key->addr_type;
	}

	/* process IPv4 header */
	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		err = iecm_parse_ipv4_header(vport, &field_flags,
					     d_spec, m_spec, rule);
		if (err)
			return err;
	}

	/* process IPv6 header */
	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		err = iecm_parse_ipv6_header(vport, &field_flags,
					     d_spec, m_spec, rule);
		if (err)
			return err;
	}

	/* process L4 header, supported L4 protocols are TCP and UDP */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		err = iecm_parse_l4_header(vport, d_spec, m_spec, rule);
		if (err)
			return err;
	}
	cf->field_flags = field_flags;

	return 0;
}

/**
 * iecm_handle_tclass - Forward to a traffic class on the device
 * @vport: vport structure
 * @tc: traffic class index on the device
 * @filter: pointer to cloud filter structure
 *
 * Return 0 on success, negative on failure
 */
static int iecm_handle_tclass(struct iecm_vport *vport, int tc,
			      struct iecm_cloud_filter *filter)
{
	struct iecm_adapter *adapter = vport->adapter;

	if (tc == 0)
		return 0;
	if ((!iecm_is_adq_v2_ena(vport)) &&
	    !filter->f.data.tcp_spec.dst_port) {
		dev_err(&adapter->pdev->dev,
			"Specify destination port to redirect to traffic class other than TC0\n");
		return -EINVAL;
	}
	/* redirect to a traffic class on the same device */
	filter->f.action = VIRTCHNL_ACTION_TC_REDIRECT;
	filter->f.action_meta = tc;
	return 0;
}

/* iecm_find_cf - Find the cloud filter in the list
 * @vport: vport structure
 * @cookie: filter specific cookie
 *
 * Returns pointer to the filter object or NULL. Must be called while holding
 * cloud_filter_list_lock.
 */
static struct iecm_cloud_filter *iecm_find_cf(struct iecm_vport *vport,
					      unsigned long *cookie)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_cloud_filter *filter = NULL;

	if (!cookie)
		return NULL;

	list_for_each_entry(filter,
			    &adapter->config_data.cf_config.cloud_filter_list,
			    list) {
		if (!memcmp(cookie, &filter->cookie, sizeof(filter->cookie)))
			return filter;
	}
	return NULL;
}

/**
 * iecm_configure_clsflower - Add tc flower filters
 * @vport: vport structure
 * @cls_flower: Pointer to struct flow_cls_offload
 *
 * Return 0 on success, negative on failure
 */
static int iecm_configure_clsflower(struct iecm_vport *vport,
				    struct flow_cls_offload *cls_flower)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_user_config_data *config_data;
	struct iecm_cloud_filter *filter = NULL;
	int err = -EINVAL;
	int tc;

	config_data = &adapter->config_data;
	tc = tc_classid_to_hwtc(vport->netdev, cls_flower->classid);
	if (tc < 0) {
		dev_err(&adapter->pdev->dev, "Invalid traffic class\n");
		return -EINVAL;
	}

#define IECM_MAX_CLOUD_ADQ_FILTERS	128

	if (config_data->cf_config.num_cloud_filters >=
						IECM_MAX_CLOUD_ADQ_FILTERS) {
		dev_err(&adapter->pdev->dev,
			"Unable to add filter (action is forward to TC), reached max allowed filters (%u)\n",
			IECM_MAX_CLOUD_ADQ_FILTERS);
		return -ENOSPC;
	}

	/* bail out here if filter already exists */
	spin_lock_bh(&adapter->cloud_filter_list_lock);
	filter = iecm_find_cf(vport, &cls_flower->cookie);
	if (filter) {
		filter->remove = false;
		dev_err(&adapter->pdev->dev, "Failed to add TC Flower filter, it already exists\n");
		spin_unlock_bh(&adapter->cloud_filter_list_lock);
		return -EEXIST;
	}
	spin_unlock_bh(&adapter->cloud_filter_list_lock);

	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter)
		return -ENOMEM;

	filter->cookie = cls_flower->cookie;

	/* set the mask to all zeroes to begin with */
	memset(&filter->f.mask.tcp_spec, 0, sizeof(struct virtchnl_l4_spec));

	/* start out with flow type and eth type IPv4 to begin with */
	filter->f.flow_type = VIRTCHNL_TCP_V4_FLOW;
	err = iecm_parse_cls_flower(vport, cls_flower, filter);
	if (err)
		goto error;

	err = iecm_handle_tclass(vport, tc, filter);
	if (err)
		goto error;

	/* store "channel" as back ptr to filter and it is applicable
	 * only if filter is for ADQ TC, where "hw_tc <n>"
	 */
	if (tc >= IECM_START_CHNL_TC &&
	    tc < ARRAY_SIZE(config_data->ch_config.ch_ex_info))
		filter->ch = &config_data->ch_config.ch_ex_info[tc];
	else
		filter->ch = NULL;

	/* add filter to the list */
	spin_lock_bh(&adapter->cloud_filter_list_lock);
	list_add_tail(&filter->list, &config_data->cf_config.cloud_filter_list);
	filter->add = true;
	spin_unlock_bh(&adapter->cloud_filter_list_lock);
	if (vport->adapter->state == __IECM_UP)
		err = iecm_send_add_del_cloud_filter_msg(vport, true);
	spin_lock_bh(&adapter->cloud_filter_list_lock);
	/* We have to find it again in case another thread has already
	 * deleted and kfreed it.
	 */
	filter = iecm_find_cf(vport, &cls_flower->cookie);
	if (filter && err) {
		list_del(&filter->list);
		spin_unlock_bh(&adapter->cloud_filter_list_lock);
		goto error;
	}
	else if (filter && filter->ch)
		filter->ch->num_fltr++;
	spin_unlock_bh(&adapter->cloud_filter_list_lock);

	config_data->cf_config.num_cloud_filters++;
	iecm_setup_ch_info(vport);
error:
	if (err)
		kfree(filter);
	return err;
}

/**
 * iecm_delete_clsflower - Remove tc flower filters
 * @vport: vport structure
 * @cls_flower: Pointer to struct flow_cls_offload
 *
 * Return 0 on success, negative on failure
 */
static int iecm_delete_clsflower(struct iecm_vport *vport,
				 struct flow_cls_offload *cls_flower)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_cloud_filter *filter = NULL;
	int err = 0;

	spin_lock_bh(&adapter->cloud_filter_list_lock);
	filter = iecm_find_cf(vport, &cls_flower->cookie);
	if (filter) {
		filter->remove = true;
		adapter->config_data.cf_config.num_cloud_filters--;
		if (filter->ch)
			filter->ch->num_fltr--;
		iecm_clear_ch_info(vport);
	} else if (adapter->config_data.cf_config.num_cloud_filters) {
		/* "num_cloud_filters" can become zero if egress qdisc is
		 * detached as per design, driver deletes related filters
		 * when qdisc is detached to avoid stale filters, hence
		 * num_cloud_filters can become zero. But since netdev
		 * layer doesn't know that filters are deleted by driver
		 * implictly when egress qdisc is deleted, it sees filters
		 * being present and "in_hw". User can request delete
		 * of specific filter of detach ingress qdisc - in either of
		 * those operation, filter(s) won't be found in driver cache,
		 * hence instead of returning, let this function return SUCCESS
		 * Returning of err as -EINVAL is only applicable when
		 * unable to find filter and num_cloud_filters is non-zero
		 */
		err = -EINVAL;
	}
	spin_unlock_bh(&adapter->cloud_filter_list_lock);

	if (filter) {
		if (vport->adapter->state == __IECM_UP)
			err = iecm_send_add_del_cloud_filter_msg(vport, false);
		spin_lock_bh(&adapter->cloud_filter_list_lock);
		/* It can happen that asynchronously the filter was already
		 * deleted from the list. Make sure it's still there and marked
		 * for remove under spinlock before actually trying to delete
		 * from list.
		 */
		filter = iecm_find_cf(vport, &cls_flower->cookie);
		if (filter) {
			list_del(&filter->list);
			kfree(filter);
		}
		spin_unlock_bh(&adapter->cloud_filter_list_lock);
	}
	return err;
}

/**
 * iecm_setup_tc_cls_flower - flower classifier offloads
 * @vport: vport structure
 * @cls_flower: pointer to struct flow_cls_offload
 *
 * Return 0 on success, negative on failure
 */
static int iecm_setup_tc_cls_flower(struct iecm_vport *vport,
				    struct flow_cls_offload *cls_flower)
{
	if (cls_flower->common.chain_index)
		return -EOPNOTSUPP;

	switch (cls_flower->command) {
	case FLOW_CLS_REPLACE:
		return iecm_configure_clsflower(vport, cls_flower);
	case FLOW_CLS_DESTROY:
		return iecm_delete_clsflower(vport, cls_flower);
	case FLOW_CLS_STATS:
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}
}

/**
 * iecm_setup_tc_block_cb - block callback for tc
 * @type: type of offload
 * @type_data: offload data
 * @cb_priv: Private adapter structure
 *
 * This function is the block callback for traffic classes
 * Return 0 on success, negative on failure
 **/
static int iecm_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
				  void *cb_priv)
{
	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return iecm_setup_tc_cls_flower((struct iecm_vport *)cb_priv,
						(struct flow_cls_offload *)
						 type_data);
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * iecm_validate_tx_bandwidth - validate the max Tx bandwidth
 * @vport: vport structure
 * @max_tx_rate: max Tx bandwidth for a tc
 **/
static int iecm_validate_tx_bandwidth(struct iecm_vport *vport,
				      u64 max_tx_rate)
{
	struct iecm_adapter *adapter = vport->adapter;
	int speed = 0, ret = 0;

	if (adapter->link_speed_mbps) {
		if (adapter->link_speed_mbps < U32_MAX) {
			speed = adapter->link_speed_mbps;
			goto validate_bw;
		} else {
			dev_err(&adapter->pdev->dev, "Unknown link speed\n");
			return -EINVAL;
		}
	}

	switch (adapter->link_speed) {
	case VIRTCHNL_LINK_SPEED_40GB:
		speed = SPEED_40000;
		break;
	case VIRTCHNL_LINK_SPEED_25GB:
		speed = SPEED_25000;
		break;
	case VIRTCHNL_LINK_SPEED_20GB:
		speed = SPEED_20000;
		break;
	case VIRTCHNL_LINK_SPEED_10GB:
		speed = SPEED_10000;
		break;
	case VIRTCHNL_LINK_SPEED_5GB:
		speed = SPEED_5000;
		break;
	case VIRTCHNL_LINK_SPEED_2_5GB:
		speed = SPEED_2500;
		break;
	case VIRTCHNL_LINK_SPEED_1GB:
		speed = SPEED_1000;
		break;
	case VIRTCHNL_LINK_SPEED_100MB:
		speed = SPEED_100;
		break;
	default:
		break;
	}

validate_bw:
	if (max_tx_rate > speed) {
		dev_err(&adapter->pdev->dev, "Invalid tx rate specified\n");
		ret = -EINVAL;
	}

	return ret;
}

/**
 * iecm_validate_channel_config - validate queue mapping info
 * @vport: vport structure
 * @mqprio_qopt: queue parameters
 * @max_tc_allowed: MAX TC allowed, it could be 4 or 16 depends.
 *
 * This function validates if the configuration provided by the user to
 * configure queue channels is valid or not.
 *
 * Returns 0 on a valid config and negative on invalid config.
 **/
static int iecm_validate_ch_config(struct iecm_vport *vport,
				   struct tc_mqprio_qopt_offload *mqprio_qopt,
				   u8 max_tc_allowed)
{
	struct iecm_adapter *adapter = vport->adapter;
	u32 tc, qcount, non_power_2_qcount = 0;
	u64 total_max_rate = 0;
	int i, num_qs = 0;
	u64 tx_rate = 0;

	if (mqprio_qopt->qopt.num_tc > max_tc_allowed ||
	    mqprio_qopt->qopt.num_tc < 1)
		return -EINVAL;

	/* For ADQ there are few rules on queue allocation for each TC
	 *     1. Number of queues for TC0 should always be a power of 2
	 *     2. Number of queues for rest of TCs can be non-power of 2
	 *     3. If the previous TC has non-power of 2 queues, then all the
	 *        following TCs should be either
	 *        a. same number of queues as that of the previous non-power
	 *           of 2 or
	 *        b. less than previous non-power of 2 and power of 2
	 *        ex: 1@0 2@1 3@3 4@6 - Invalid
	 *            1@0 2@1 3@3 3@6 - Valid
	 *            1@0 2@1 3@3 2@6 - Valid
	 *            1@0 2@1 3@3 1@6 - Valid
	 */
	for (tc = 0; tc < mqprio_qopt->qopt.num_tc; tc++) {
		qcount = mqprio_qopt->qopt.count[tc];

		/* case 1. check for first TC to be always power of 2 in ADQ */
		if (!tc && !is_power_of_2(qcount)) {
			dev_err(&adapter->pdev->dev,
				"TC0:qcount[%d] must be a power of 2\n",
				qcount);
			return -EINVAL;
		}
		/* case 2 & 3, check for non-power of 2 number of queues */
		if (tc && non_power_2_qcount) {
			if (qcount > non_power_2_qcount) {
				dev_err(&adapter->pdev->dev,
					"TC%d has %d qcount cannot be > non_power_of_2 qcount [%d]\n",
					tc, qcount, non_power_2_qcount);
				return -EINVAL;
			} else if (qcount < non_power_2_qcount) {
				/* it must be power of 2, otherwise fail */
				if (!is_power_of_2(qcount)) {
					dev_err(&adapter->pdev->dev,
						"TC%d has %d qcount must be a power of 2 < non_power_of_2 qcount [%d]\n",
						tc, qcount, non_power_2_qcount);
					return -EINVAL;
				}
			}
		} else if (tc && !is_power_of_2(qcount)) {
			/* this is the first TC to have a non-power of 2 queue
			 * count and the code is going to enter this section
			 * only once. The qcount for this TC will serve as
			 * our reference/guide to allocate number of queues
			 * for all the further TCs as per section a. and b. in
			 * case 3 mentioned above.
			 */
			non_power_2_qcount = qcount;
			dev_dbg(&adapter->pdev->dev,
				"TC%d:count[%d] non power of 2\n", tc,
				qcount);
			}
	}

	for (i = 0; i <= mqprio_qopt->qopt.num_tc - 1; i++) {
		if (!mqprio_qopt->qopt.count[i] ||
		    mqprio_qopt->qopt.offset[i] != num_qs)
			return -EINVAL;
		if (mqprio_qopt->min_rate[i]) {
			dev_err(&adapter->pdev->dev,
				"Invalid min tx rate (greater than 0) specified\n");
			return -EINVAL;
		}
		/*convert to Mbps */
		tx_rate = div_u64(mqprio_qopt->max_rate[i], IECM_MBPS_DIVISOR);
		total_max_rate += tx_rate;
		num_qs += mqprio_qopt->qopt.count[i];
	}
	/* Comparing with num_txq as num_txq and num_rxq are equal for single
	 * queue model
	 */
	if (num_qs > vport->num_txq) {
		dev_err(&adapter->pdev->dev,
			"Cannot support requested number of queues\n");
		return -EINVAL;
	}
	/* no point in validating TX bandwidth rate limit if the user hasn't
	 * specified any rate limit for any TCs, so validate only if it's set.
	 */
	if (total_max_rate)
		return iecm_validate_tx_bandwidth(vport, total_max_rate);
	else
		return 0;
}

/**
 * __iecm_setup_tc - configure multiple traffic classes
 * @vport: vport structure
 * @type_data: tc offload data
 *
 * This function processes the config information provided by the
 * user to configure traffic classes/queue channels and packages the
 * information to request the PF to setup traffic classes.
 *
 * Returns 0 on success.
 **/
static int __iecm_setup_tc(struct iecm_vport *vport, void *type_data)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct tc_mqprio_qopt_offload *mqprio_qopt;
	struct net_device *netdev = vport->netdev;
	struct iecm_channel_config *ch_config;
	u8 num_tc = 0, total_qs = 0;
	int ret = 0, netdev_tc = 0;
	u8 max_tc_allowed;
	u64 max_tx_rate;
	u16 mode;
	int i;

	mqprio_qopt = (struct tc_mqprio_qopt_offload *)type_data;
	ch_config = &adapter->config_data.ch_config;
	num_tc = mqprio_qopt->qopt.num_tc;
	mode = mqprio_qopt->mode;

	/* delete queue_channel */
	if (!mqprio_qopt->qopt.hw) {
		if (ch_config->tc_running) {
			/* reset the tc configuration */
			netdev_reset_tc(netdev);
			ch_config->num_tc = 0;
			netif_tx_stop_all_queues(netdev);
			netif_tx_disable(netdev);
			ret = iecm_send_disable_channels_msg(vport);
			iecm_del_all_cloud_filters(vport);
			netif_tx_start_all_queues(netdev);
			if (!test_bit(__IECM_REL_RES_IN_PROG, adapter->flags) &&
			    !ret) {
				ch_config->tc_running = false;
				set_bit(__IECM_HR_FUNC_RESET, adapter->flags);
				queue_delayed_work(adapter->vc_event_wq,
						   &adapter->vc_event_task,
						   msecs_to_jiffies(10));
			}
			return ret;
		} else {
			return -EINVAL;
		}
	}

	if (mode == TC_MQPRIO_MODE_CHANNEL) {
		if (!iecm_is_cap_ena(adapter, IECM_BASE_CAPS,
				     VIRTCHNL2_CAP_ADQ) &&
		    !iecm_is_cap_ena(adapter, IECM_OTHER_CAPS,
					     VIRTCHNL2_CAP_ADQ)) {
			dev_info(&adapter->pdev->dev, "ADQ not supported\n");
			return -EOPNOTSUPP;
		}

		if (ch_config->tc_running) {
			dev_info(&adapter->pdev->dev, "TC configuration already exists\n");
			return -EINVAL;
		}

		/* If negotiated capability between VF and PF indicated that
		 * ADQ_V2 is enabled, means it's OK to allow max_tc
		 * to be 16. This is needed to handle the case where iAVF
		 * is newer but PF is older or different generation
		 */
		if (iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADQ))
			max_tc_allowed = VIRTCHNL_MAX_ADQ_V2_CHANNELS;
		else
			max_tc_allowed = VIRTCHNL_MAX_ADQ_CHANNELS;

		ret = iecm_validate_ch_config(vport, mqprio_qopt,
					      max_tc_allowed);
		if (ret)
			return ret;
		/* Return if same TC config is requested */
		if (ch_config->num_tc == num_tc)
			return 0;
		ch_config->num_tc = num_tc;

		for (i = 0; i < max_tc_allowed; i++) {
			if (i < num_tc) {
				ch_config->ch_info[i].count =
					mqprio_qopt->qopt.count[i];
				ch_config->ch_info[i].offset =
					mqprio_qopt->qopt.offset[i];
				total_qs += mqprio_qopt->qopt.count[i];
				max_tx_rate = mqprio_qopt->max_rate[i];
				/* convert to Mbps */
				max_tx_rate = div_u64(max_tx_rate,
						      IECM_MBPS_DIVISOR);
				ch_config->ch_info[i].max_tx_rate =
								max_tx_rate;
				ch_config->ch_ex_info[i].num_rxq =
						mqprio_qopt->qopt.count[i];
				ch_config->ch_ex_info[i].base_q =
						mqprio_qopt->qopt.offset[i];
			} else {
				ch_config->ch_info[i].count = 1;
				ch_config->ch_info[i].offset = 0;
			}
		}

		/* Store queue info based on TC so that, VF gets configured
		 * with correct number of queues when VF completes ADQ config
		 * flow
		 */
		ch_config->total_qs = total_qs;

		netif_tx_stop_all_queues(netdev);
		netif_tx_disable(netdev);
		ret = iecm_send_enable_channels_msg(vport);
		if (ret)
			return ret;
		netdev_reset_tc(netdev);
		/* Report the tc mapping up the stack */
		netdev_set_num_tc(netdev, num_tc);
		for (i = 0; i < max_tc_allowed; i++) {
			u16 qcount = mqprio_qopt->qopt.count[i];
			u16 qoffset = mqprio_qopt->qopt.offset[i];

			if (i < num_tc)
				netdev_set_tc_queue(netdev, netdev_tc++, qcount,
						    qoffset);
		}
		/* Start all queues */
		netif_tx_start_all_queues(netdev);
		ch_config->tc_running = true;
		set_bit(__IECM_HR_FUNC_RESET, adapter->flags);
		queue_delayed_work(adapter->vc_event_wq,
				   &adapter->vc_event_task,
				   msecs_to_jiffies(10));
	}
	return ret;
}
#endif /* HAVE_SETUP_TC */
#endif /* HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV */
#endif /* __TC_MQPRIO_MODE_MAX */

/**
 * iecm_setup_tc - ndo callback to setup up TC schedulers
 * @netdev: pointer to net_device struct
 * @type: TC type
 * @type_data: TC type specific data
 */
static int iecm_setup_tc(struct net_device *netdev, enum tc_setup_type type,
			 void *type_data)
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_cloud_filter_config *cf_config;
	int err = 0;

	cf_config = &adapter->config_data.cf_config;
	switch (type) {
#ifdef HAVE_ETF_SUPPORT
	case TC_SETUP_QDISC_ETF:
		if (iecm_is_queue_model_split(vport->txq_model))
			err =
			iecm_offload_txtime(vport,
					    (struct tc_etf_qopt_offload *)
					     type_data);
		break;
#endif /* HAVE_ETF_SUPPORT */
#ifdef HAVE_SETUP_TC
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
#ifdef __TC_MQPRIO_MODE_MAX
	case TC_SETUP_BLOCK:
		if (iecm_is_cap_ena(adapter, IECM_BASE_CAPS,
				    VIRTCHNL2_CAP_ADQ) ||
		    iecm_is_cap_ena(adapter, IECM_OTHER_CAPS,
				    VIRTCHNL2_CAP_ADQ)) {
			err =
			flow_block_cb_setup_simple((struct flow_block_offload *)
						    type_data,
						   &cf_config->block_cb_list,
						   iecm_setup_tc_block_cb,
						   vport, vport, true);
		}
		break;
	case TC_SETUP_QDISC_MQPRIO:
		if (iecm_is_cap_ena(adapter, IECM_BASE_CAPS,
				    VIRTCHNL2_CAP_ADQ) ||
		    iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADQ))
			__iecm_setup_tc(vport, type_data);
		break;
#endif /* __TC_MQPRIO_MODE_MAX */
#endif /* HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV */
#endif /* HAVE_SETUP_TC */
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

/**
 * iecm_fill_adv_rss_ip4_hdr - fill the IPv4 RSS protocol header
 * @hdr: the virtchnl message protocol header data structure
 * @hash_flds: the RSS configuration protocol hash fields
 */
static void
iecm_fill_adv_rss_ip4_hdr(struct virtchnl_proto_hdr *hdr, u64 hash_flds)
{
	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, IPV4);

	if (hash_flds & IECM_ADV_RSS_HASH_FLD_IPV4_SA)
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV4, SRC);

	if (hash_flds & IECM_ADV_RSS_HASH_FLD_IPV4_DA)
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV4, DST);
}

/**
 * iecm_fill_adv_rss_ip6_hdr - fill the IPv6 RSS protocol header
 * @hdr: the virtchnl message protocol header data structure
 * @hash_flds: the RSS configuration protocol hash fields
 */
static void
iecm_fill_adv_rss_ip6_hdr(struct virtchnl_proto_hdr *hdr, u64 hash_flds)
{
	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, IPV6);

	if (hash_flds & IECM_ADV_RSS_HASH_FLD_IPV6_SA)
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV6, SRC);

	if (hash_flds & IECM_ADV_RSS_HASH_FLD_IPV6_DA)
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV6, DST);
}

/**
 * iecm_fill_adv_rss_tcp_hdr - fill the TCP RSS protocol header
 * @hdr: the virtchnl message protocol header data structure
 * @hash_flds: the RSS configuration protocol hash fields
 */
static void
iecm_fill_adv_rss_tcp_hdr(struct virtchnl_proto_hdr *hdr, u64 hash_flds)
{
	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, TCP);

	if (hash_flds & IECM_ADV_RSS_HASH_FLD_TCP_SRC_PORT)
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, TCP, SRC_PORT);

	if (hash_flds & IECM_ADV_RSS_HASH_FLD_TCP_DST_PORT)
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, TCP, DST_PORT);
}

/**
 * iecm_fill_adv_rss_udp_hdr - fill the UDP RSS protocol header
 * @hdr: the virtchnl message protocol header data structure
 * @hash_flds: the RSS configuration protocol hash fields
 */
static void
iecm_fill_adv_rss_udp_hdr(struct virtchnl_proto_hdr *hdr, u64 hash_flds)
{
	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, UDP);

	if (hash_flds & IECM_ADV_RSS_HASH_FLD_UDP_SRC_PORT)
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, UDP, SRC_PORT);

	if (hash_flds & IECM_ADV_RSS_HASH_FLD_UDP_DST_PORT)
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, UDP, DST_PORT);
}

/**
 * iecm_fill_adv_rss_sctp_hdr - fill the SCTP RSS protocol header
 * @hdr: the virtchnl message protocol header data structure
 * @hash_flds: the RSS configuration protocol hash fields
 */
static void
iecm_fill_adv_rss_sctp_hdr(struct virtchnl_proto_hdr *hdr, u64 hash_flds)
{
	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, SCTP);

	if (hash_flds & IECM_ADV_RSS_HASH_FLD_SCTP_SRC_PORT)
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, SCTP, SRC_PORT);

	if (hash_flds & IECM_ADV_RSS_HASH_FLD_SCTP_DST_PORT)
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, SCTP, DST_PORT);
}

/**
 * iecm_fill_adv_rss_cfg_msg - fill the RSS configuration into virtchnl message
 * @rss_cfg: the virtchnl message to be filled with RSS configuration setting
 * @packet_hdrs: the RSS configuration protocol header types
 * @hash_flds: the RSS configuration protocol hash fields
 *
 * Returns 0 if the RSS configuration virtchnl message is filled successfully
 */
static int
iecm_fill_adv_rss_cfg_msg(struct virtchnl_rss_cfg *rss_cfg,
			  u32 packet_hdrs, u64 hash_flds)
{
	struct virtchnl_proto_hdrs *proto_hdrs = &rss_cfg->proto_hdrs;
	struct virtchnl_proto_hdr *hdr;

	rss_cfg->rss_algorithm = VIRTCHNL_RSS_ALG_TOEPLITZ_ASYMMETRIC;

	proto_hdrs->tunnel_level = 0;	/* always outer layer */

	hdr = &proto_hdrs->proto_hdr[proto_hdrs->count++];
	switch (packet_hdrs & IECM_ADV_RSS_FLOW_SEG_HDR_L3) {
	case IECM_ADV_RSS_FLOW_SEG_HDR_IPV4:
		iecm_fill_adv_rss_ip4_hdr(hdr, hash_flds);
		break;
	case IECM_ADV_RSS_FLOW_SEG_HDR_IPV6:
		iecm_fill_adv_rss_ip6_hdr(hdr, hash_flds);
		break;
	default:
		return -EINVAL;
	}

	hdr = &proto_hdrs->proto_hdr[proto_hdrs->count++];
	switch (packet_hdrs & IECM_ADV_RSS_FLOW_SEG_HDR_L4) {
	case IECM_ADV_RSS_FLOW_SEG_HDR_TCP:
		iecm_fill_adv_rss_tcp_hdr(hdr, hash_flds);
		break;
	case IECM_ADV_RSS_FLOW_SEG_HDR_UDP:
		iecm_fill_adv_rss_udp_hdr(hdr, hash_flds);
		break;
	case IECM_ADV_RSS_FLOW_SEG_HDR_SCTP:
		iecm_fill_adv_rss_sctp_hdr(hdr, hash_flds);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/**
 * iecm_find_adv_rss_cfg_by_hdrs - find RSS configuration with header type
 * @vport: vport structure
 * @packet_hdrs: protocol header type to find.
 *
 * Returns pointer to advance RSS configuration if found or null
 */
static struct iecm_adv_rss *
iecm_find_adv_rss_cfg_by_hdrs(struct iecm_vport *vport, u32 packet_hdrs)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_adv_rss *rss;

	list_for_each_entry(rss, &adapter->config_data.adv_rss_list, list)
		if (rss->packet_hdrs == packet_hdrs)
			return rss;

	return NULL;
}

/**
 * iecm_dump_adv_rss_cfg_info
 * @vport: vport structure
 * @packet_hdrs: The protocol headers for RSS configuration
 * @hash_flds: The protocol hash fields for RSS configuration
 * @prefix: the prefix string description to dump the RSS
 * @postfix: the postfix string description to dump the RSS
 *
 * Dump the advance RSS configuration
 **/
static void
iecm_dump_adv_rss_cfg_info(struct iecm_vport *vport,
			   u32 packet_hdrs, u64 hash_flds,
			   const char *prefix, const char *postfix)
{
	static char hash_opt[300];
	const char *proto;

	if (packet_hdrs & IECM_ADV_RSS_FLOW_SEG_HDR_TCP)
		proto = "TCP";
	else if (packet_hdrs & IECM_ADV_RSS_FLOW_SEG_HDR_UDP)
		proto = "UDP";
	else if (packet_hdrs & IECM_ADV_RSS_FLOW_SEG_HDR_SCTP)
		proto = "SCTP";
	else
		return;

	memset(hash_opt, 0, sizeof(hash_opt));

	strcat(hash_opt, proto);
	if (packet_hdrs & IECM_ADV_RSS_FLOW_SEG_HDR_IPV4)
		strcat(hash_opt, "v4 ");
	else
		strcat(hash_opt, "v6 ");

	if (hash_flds & (IECM_ADV_RSS_HASH_FLD_IPV4_SA |
			 IECM_ADV_RSS_HASH_FLD_IPV6_SA))
		strcat(hash_opt, "[IP SA] ");
	if (hash_flds & (IECM_ADV_RSS_HASH_FLD_IPV4_DA |
			 IECM_ADV_RSS_HASH_FLD_IPV6_DA))
		strcat(hash_opt, "[IP DA] ");
	if (hash_flds & (IECM_ADV_RSS_HASH_FLD_TCP_SRC_PORT |
			 IECM_ADV_RSS_HASH_FLD_UDP_SRC_PORT |
			 IECM_ADV_RSS_HASH_FLD_SCTP_SRC_PORT))
		strcat(hash_opt, "[src port] ");
	if (hash_flds & (IECM_ADV_RSS_HASH_FLD_TCP_DST_PORT |
			 IECM_ADV_RSS_HASH_FLD_UDP_DST_PORT |
			 IECM_ADV_RSS_HASH_FLD_SCTP_DST_PORT))
		strcat(hash_opt, "[dst port] ");

	if (!prefix)
		prefix = "";

	if (!postfix)
		postfix = "";

	dev_info(&vport->adapter->pdev->dev, "%s %s %s\n",
		 prefix, hash_opt, postfix);
}

/**
 * iecm_adv_rss_parse_hdrs - parses headers from RSS hash input
 * @cmd: ethtool rxnfc command
 *
 * This function parses the rxnfc command and returns intended
 * header types for RSS configuration
 */
static u32 iecm_adv_rss_parse_hdrs(struct ethtool_rxnfc *cmd)
{
	u32 hdrs = IECM_ADV_RSS_FLOW_SEG_HDR_NONE;

	switch (cmd->flow_type) {
	case TCP_V4_FLOW:
		hdrs |= IECM_ADV_RSS_FLOW_SEG_HDR_TCP |
			IECM_ADV_RSS_FLOW_SEG_HDR_IPV4;
		break;
	case UDP_V4_FLOW:
		hdrs |= IECM_ADV_RSS_FLOW_SEG_HDR_UDP |
			IECM_ADV_RSS_FLOW_SEG_HDR_IPV4;
		break;
	case SCTP_V4_FLOW:
		hdrs |= IECM_ADV_RSS_FLOW_SEG_HDR_SCTP |
			IECM_ADV_RSS_FLOW_SEG_HDR_IPV4;
		break;
	case TCP_V6_FLOW:
		hdrs |= IECM_ADV_RSS_FLOW_SEG_HDR_TCP |
			IECM_ADV_RSS_FLOW_SEG_HDR_IPV6;
		break;
	case UDP_V6_FLOW:
		hdrs |= IECM_ADV_RSS_FLOW_SEG_HDR_UDP |
			IECM_ADV_RSS_FLOW_SEG_HDR_IPV6;
		break;
	case SCTP_V6_FLOW:
		hdrs |= IECM_ADV_RSS_FLOW_SEG_HDR_SCTP |
			IECM_ADV_RSS_FLOW_SEG_HDR_IPV6;
		break;
	default:
		break;
	}

	return hdrs;
}

/**
 * iecm_adv_rss_parse_hash_flds - parses hash fields from RSS hash input
 * @cmd: ethtool rxnfc command
 *
 * This function parses the rxnfc command and returns intended hash fields for
 * RSS configuration
 */
static u64 iecm_adv_rss_parse_hash_flds(struct ethtool_rxnfc *cmd)
{
	u64 hfld = IECM_ADV_RSS_HASH_INVALID;

	if (cmd->data & RXH_IP_SRC || cmd->data & RXH_IP_DST) {
		switch (cmd->flow_type) {
		case TCP_V4_FLOW:
		case UDP_V4_FLOW:
		case SCTP_V4_FLOW:
			if (cmd->data & RXH_IP_SRC)
				hfld |= IECM_ADV_RSS_HASH_FLD_IPV4_SA;
			if (cmd->data & RXH_IP_DST)
				hfld |= IECM_ADV_RSS_HASH_FLD_IPV4_DA;
			break;
		case TCP_V6_FLOW:
		case UDP_V6_FLOW:
		case SCTP_V6_FLOW:
			if (cmd->data & RXH_IP_SRC)
				hfld |= IECM_ADV_RSS_HASH_FLD_IPV6_SA;
			if (cmd->data & RXH_IP_DST)
				hfld |= IECM_ADV_RSS_HASH_FLD_IPV6_DA;
			break;
		default:
			break;
		}
	}

	if (cmd->data & RXH_L4_B_0_1 || cmd->data & RXH_L4_B_2_3) {
		switch (cmd->flow_type) {
		case TCP_V4_FLOW:
		case TCP_V6_FLOW:
			if (cmd->data & RXH_L4_B_0_1)
				hfld |= IECM_ADV_RSS_HASH_FLD_TCP_SRC_PORT;
			if (cmd->data & RXH_L4_B_2_3)
				hfld |= IECM_ADV_RSS_HASH_FLD_TCP_DST_PORT;
			break;
		case UDP_V4_FLOW:
		case UDP_V6_FLOW:
			if (cmd->data & RXH_L4_B_0_1)
				hfld |= IECM_ADV_RSS_HASH_FLD_UDP_SRC_PORT;
			if (cmd->data & RXH_L4_B_2_3)
				hfld |= IECM_ADV_RSS_HASH_FLD_UDP_DST_PORT;
			break;
		case SCTP_V4_FLOW:
		case SCTP_V6_FLOW:
			if (cmd->data & RXH_L4_B_0_1)
				hfld |= IECM_ADV_RSS_HASH_FLD_SCTP_SRC_PORT;
			if (cmd->data & RXH_L4_B_2_3)
				hfld |= IECM_ADV_RSS_HASH_FLD_SCTP_DST_PORT;
			break;
		default:
			break;
		}
	}

	return hfld;
}

/**
 * iecm_set_adv_rss_hash_opt - Enable/Disable flow types for RSS hash
 * @vport: vport structure
 * @cmd: ethtool rxnfc command
 *
 * Returns Success if the flow input set is supported.
 */
int
iecm_set_adv_rss_hash_opt(struct iecm_vport *vport, struct ethtool_rxnfc *cmd)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_adv_rss *rss, *rss_new;
	u64 hash_flds;
	int err = 0;
	u32 hdrs;

	if (adapter->state != __IECM_UP)
		return -EIO;

	if (!iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADV_RSS))
		return -EOPNOTSUPP;

	hdrs = iecm_adv_rss_parse_hdrs(cmd);
	if (hdrs == IECM_ADV_RSS_FLOW_SEG_HDR_NONE)
		return -EINVAL;

	hash_flds = iecm_adv_rss_parse_hash_flds(cmd);
	if (hash_flds == IECM_ADV_RSS_HASH_INVALID)
		return -EINVAL;

	rss_new = kzalloc(sizeof(*rss_new), GFP_KERNEL);
	if (!rss_new)
		return -ENOMEM;

	/* Since this can fail, do it now to avoid dirtying the list, we'll
	 * copy it from rss_new if it turns out we're updating an existing
	 * filter instead of adding a new one.
	 */
	if (iecm_fill_adv_rss_cfg_msg(&rss_new->cfg_msg, hdrs, hash_flds)) {
		kfree(rss_new);
		return -EINVAL;
	}

	iecm_dump_adv_rss_cfg_info(vport, hdrs, hash_flds,
				   "Input set change for", "is pending");

	spin_lock_bh(&adapter->adv_rss_list_lock);
	rss = iecm_find_adv_rss_cfg_by_hdrs(vport, hdrs);
	if (rss) {
		if (rss->hash_flds != hash_flds) {
			rss->remove = false;
			memcpy(&rss->cfg_msg, &rss_new->cfg_msg,
			       sizeof(rss_new->cfg_msg));
			kfree(rss_new);
		} else {
			kfree(rss_new);
			spin_unlock_bh(&adapter->adv_rss_list_lock);
			return -EEXIST;
		}
	} else {
		rss = rss_new;
		rss->packet_hdrs = hdrs;
		list_add_tail(&rss->list, &adapter->config_data.adv_rss_list);
	}
	rss->add = true;
	rss->hash_flds = hash_flds;

	if (vport->adapter->state == __IECM_UP)
		return err;

	spin_unlock_bh(&adapter->adv_rss_list_lock);
	err = iecm_send_add_del_adv_rss_cfg_msg(vport, true);
	if (err) {
		spin_lock_bh(&adapter->adv_rss_list_lock);
		/* We have to find it again to make sure another thread hasn't
		 * already deleted and kfreed it.
		 */
		rss = iecm_find_adv_rss_cfg_by_hdrs(vport, hdrs);
		if (rss) {
			list_del(&rss->list);
			kfree(rss);
		}
		spin_unlock_bh(&adapter->adv_rss_list_lock);
	}

	if (!err)
		iecm_dump_adv_rss_cfg_info(vport, hdrs, hash_flds,
					   "Input set change for",
					   "successful");
	else
		iecm_dump_adv_rss_cfg_info(vport, hdrs, hash_flds,
					   "Failed to change the input set for",
					   NULL);

	return err;
}

/**
 * iecm_get_adv_rss_hash_opt - Retrieve hash fields for a given flow-type
 * @vport: vport structure
 * @cmd: ethtool rxnfc command
 *
 * Returns Success if the flow input set is supported.
 */
int
iecm_get_adv_rss_hash_opt(struct iecm_vport *vport, struct ethtool_rxnfc *cmd)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_adv_rss *rss;
	u64 hash_flds;
	u32 hdrs;

	if (adapter->state != __IECM_UP)
		return -EIO;

	if (!iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_ADV_RSS))
		return -EOPNOTSUPP;

	cmd->data = 0;

	hdrs = iecm_adv_rss_parse_hdrs(cmd);
	if (hdrs == IECM_ADV_RSS_FLOW_SEG_HDR_NONE)
		return -EINVAL;

	spin_lock_bh(&adapter->adv_rss_list_lock);
	rss = iecm_find_adv_rss_cfg_by_hdrs(vport, hdrs);
	if (rss)
		hash_flds = rss->hash_flds;
	else
		hash_flds = IECM_ADV_RSS_HASH_INVALID;
	spin_unlock_bh(&adapter->adv_rss_list_lock);

	if (hash_flds == IECM_ADV_RSS_HASH_INVALID)
		return -EINVAL;

	if (hash_flds & (IECM_ADV_RSS_HASH_FLD_IPV4_SA |
			 IECM_ADV_RSS_HASH_FLD_IPV6_SA))
		cmd->data |= (u64)RXH_IP_SRC;

	if (hash_flds & (IECM_ADV_RSS_HASH_FLD_IPV4_DA |
			 IECM_ADV_RSS_HASH_FLD_IPV6_DA))
		cmd->data |= (u64)RXH_IP_DST;

	if (hash_flds & (IECM_ADV_RSS_HASH_FLD_TCP_SRC_PORT |
			 IECM_ADV_RSS_HASH_FLD_UDP_SRC_PORT |
			 IECM_ADV_RSS_HASH_FLD_SCTP_SRC_PORT))
		cmd->data |= (u64)RXH_L4_B_0_1;

	if (hash_flds & (IECM_ADV_RSS_HASH_FLD_TCP_DST_PORT |
			 IECM_ADV_RSS_HASH_FLD_UDP_DST_PORT |
			 IECM_ADV_RSS_HASH_FLD_SCTP_DST_PORT))
		cmd->data |= (u64)RXH_L4_B_2_3;

	return 0;
}

/**
 * iecm_pkt_udp_no_pay_len - the length of UDP packet without payload
 * @fltr: Flow Director filter data structure
 */
static u16 iecm_pkt_udp_no_pay_len(struct iecm_fdir_fltr *fltr)
{
	return sizeof(struct ethhdr) +
		(fltr->ip_ver == 4 ? sizeof(struct iphdr)
				   : sizeof(struct ipv6hdr)) +
		sizeof(struct udphdr);
}

/**
 * iecm_fill_fdir_gtpu_hdr - fill the GTP-U protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the GTP-U protocol header is set successfully
 */
static int
iecm_fill_fdir_gtpu_hdr(struct iecm_fdir_fltr *fltr,
			struct virtchnl_proto_hdrs *proto_hdrs)
{
	struct virtchnl_proto_hdr *uhdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count - 1];
	struct virtchnl_proto_hdr *ghdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count++];
	struct virtchnl_proto_hdr *ehdr = NULL;
	u16 adj_offs, hdr_offs;
	int i;

	VIRTCHNL_SET_PROTO_HDR_TYPE(ghdr, GTPU_IP);

	adj_offs = iecm_pkt_udp_no_pay_len(fltr);

	for (i = 0; i < fltr->flex_cnt; i++) {
#define IECM_GTPU_HDR_TEID_OFFS0	4
#define IECM_GTPU_HDR_TEID_OFFS1	6
#define IECM_GTPU_HDR_N_PDU_AND_NEXT_EXTHDR_OFFS	10
#define IECM_GTPU_HDR_NEXT_EXTHDR_TYPE_MASK		0x00FF /* skip N_PDU */
/* PDU Session Container Extension Header (PSC) */
#define IECM_GTPU_PSC_EXTHDR_TYPE			0x85
#define IECM_GTPU_HDR_PSC_PDU_TYPE_AND_QFI_OFFS		13
#define IECM_GTPU_HDR_PSC_PDU_QFI_MASK			0x3F /* skip Type */
#define IECM_GTPU_EH_QFI_IDX				1

		if (fltr->flex_words[i].offset < adj_offs)
			return -EINVAL;

		hdr_offs = fltr->flex_words[i].offset - adj_offs;

		switch (hdr_offs) {
		case IECM_GTPU_HDR_TEID_OFFS0:
		case IECM_GTPU_HDR_TEID_OFFS1: {
			__be16 *pay_word = (__be16 *)ghdr->buffer;

			pay_word[hdr_offs >> 1] =
					htons(fltr->flex_words[i].word);
			VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(ghdr, GTPU_IP, TEID);
			}
			break;
		case IECM_GTPU_HDR_N_PDU_AND_NEXT_EXTHDR_OFFS:
			if ((fltr->flex_words[i].word &
			     IECM_GTPU_HDR_NEXT_EXTHDR_TYPE_MASK) !=
						IECM_GTPU_PSC_EXTHDR_TYPE)
				return -EOPNOTSUPP;
			if (!ehdr)
				ehdr =
				   &proto_hdrs->proto_hdr[proto_hdrs->count++];
			VIRTCHNL_SET_PROTO_HDR_TYPE(ehdr, GTPU_EH);
			break;
		case IECM_GTPU_HDR_PSC_PDU_TYPE_AND_QFI_OFFS:
			if (!ehdr)
				return -EINVAL;
			ehdr->buffer[IECM_GTPU_EH_QFI_IDX] =
					fltr->flex_words[i].word &
						IECM_GTPU_HDR_PSC_PDU_QFI_MASK;
			VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(ehdr, GTPU_EH, QFI);
			break;
		default:
			return -EINVAL;
		}
	}

	/* The PF ignores the UDP header fields */
	uhdr->field_selector = 0;

	return 0;
}

/**
 * iecm_fill_fdir_pfcp_hdr - fill the PFCP protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the PFCP protocol header is set successfully
 */
static int
iecm_fill_fdir_pfcp_hdr(struct iecm_fdir_fltr *fltr,
			struct virtchnl_proto_hdrs *proto_hdrs)
{
	struct virtchnl_proto_hdr *uhdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count - 1];
	struct virtchnl_proto_hdr *hdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count++];
	u16 adj_offs, hdr_offs;
	int i;

	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, PFCP);

	adj_offs = iecm_pkt_udp_no_pay_len(fltr);

	for (i = 0; i < fltr->flex_cnt; i++) {
#define IECM_PFCP_HDR_SFIELD_AND_MSG_TYPE_OFFS	0
		if (fltr->flex_words[i].offset < adj_offs)
			return -EINVAL;

		hdr_offs = fltr->flex_words[i].offset - adj_offs;

		switch (hdr_offs) {
		case IECM_PFCP_HDR_SFIELD_AND_MSG_TYPE_OFFS:
			hdr->buffer[0] = (fltr->flex_words[i].word >> 8) & 0xff;
			VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, PFCP, S_FIELD);
			break;
		default:
			return -EINVAL;
		}
	}

	/* The PF ignores the UDP header fields */
	uhdr->field_selector = 0;

	return 0;
}

/**
 * iecm_fill_fdir_nat_t_esp_hdr - fill the NAT-T-ESP protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the NAT-T-ESP protocol header is set successfully
 */
static int
iecm_fill_fdir_nat_t_esp_hdr(struct iecm_fdir_fltr *fltr,
			     struct virtchnl_proto_hdrs *proto_hdrs)
{
	struct virtchnl_proto_hdr *uhdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count - 1];
	struct virtchnl_proto_hdr *hdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count++];
	u16 adj_offs, hdr_offs;
	u32 spi = 0;
	int i;

	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, ESP);

	adj_offs = iecm_pkt_udp_no_pay_len(fltr);

	for (i = 0; i < fltr->flex_cnt; i++) {
#define IECM_NAT_T_ESP_SPI_OFFS0	0
#define IECM_NAT_T_ESP_SPI_OFFS1	2
		if (fltr->flex_words[i].offset < adj_offs)
			return -EINVAL;

		hdr_offs = fltr->flex_words[i].offset - adj_offs;

		switch (hdr_offs) {
		case IECM_NAT_T_ESP_SPI_OFFS0:
			spi |= fltr->flex_words[i].word << 16;
			break;
		case IECM_NAT_T_ESP_SPI_OFFS1:
			spi |= fltr->flex_words[i].word;
			break;
		default:
			return -EINVAL;
		}
	}

	/* Not support IKE Header Format with SPI 0 */
	if (!spi)
		return -EOPNOTSUPP;

	*(__be32 *)hdr->buffer = htonl(spi);
	VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, ESP, SPI);

	/* The PF ignores the UDP header fields */
	uhdr->field_selector = 0;

	return 0;
}

/**
 * iecm_fill_fdir_udp_flex_pay_hdr - fill the UDP payload header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the UDP payload defined protocol header is set successfully
 */
static int
iecm_fill_fdir_udp_flex_pay_hdr(struct iecm_fdir_fltr *fltr,
				struct virtchnl_proto_hdrs *proto_hdrs)
{
#define IECM_GTPU_PORT		2152
#define IECM_NAT_T_ESP_PORT	4500
#define IECM_PFCP_PORT		8805
	int err;

	switch (ntohs(fltr->ip_data.dst_port)) {
	case IECM_GTPU_PORT:
		err = iecm_fill_fdir_gtpu_hdr(fltr, proto_hdrs);
		break;
	case IECM_NAT_T_ESP_PORT:
		err = iecm_fill_fdir_nat_t_esp_hdr(fltr, proto_hdrs);
		break;
	case IECM_PFCP_PORT:
		err = iecm_fill_fdir_pfcp_hdr(fltr, proto_hdrs);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

/**
 * iecm_fill_fdir_ip4_hdr - fill the IPv4 protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the IPv4 protocol header is set successfully
 */
static int
iecm_fill_fdir_ip4_hdr(struct iecm_fdir_fltr *fltr,
		       struct virtchnl_proto_hdrs *proto_hdrs)
{
	struct virtchnl_proto_hdr *hdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count++];
	struct iphdr *iph = (struct iphdr *)hdr->buffer;

	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, IPV4);

	if (fltr->ip_mask.tos == U8_MAX) {
		iph->tos = fltr->ip_data.tos;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV4, DSCP);
	}

	if (fltr->ip_mask.proto == U8_MAX) {
		iph->protocol = fltr->ip_data.proto;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV4, PROT);
	}

	if (fltr->ip_mask.v4_addrs.src_ip == htonl(U32_MAX)) {
		iph->saddr = fltr->ip_data.v4_addrs.src_ip;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV4, SRC);
	}

	if (fltr->ip_mask.v4_addrs.dst_ip == htonl(U32_MAX)) {
		iph->daddr = fltr->ip_data.v4_addrs.dst_ip;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV4, DST);
	}

	fltr->ip_ver = 4;

	return 0;
}

/**
 * iecm_fill_fdir_ip6_hdr - fill the IPv6 protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the IPv6 protocol header is set successfully
 */
static int
iecm_fill_fdir_ip6_hdr(struct iecm_fdir_fltr *fltr,
		       struct virtchnl_proto_hdrs *proto_hdrs)
{
	static const struct in6_addr ipv6_addr_full_mask = {
		.in6_u = {
			.u6_addr8 = {
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			}
		}
	};
	struct virtchnl_proto_hdr *hdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count++];
	struct ipv6hdr *iph = (struct ipv6hdr *)hdr->buffer;

	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, IPV6);

	if (fltr->ip_mask.tclass == U8_MAX) {
		iph->priority = (fltr->ip_data.tclass >> 4) & 0xF;
		iph->flow_lbl[0] = (fltr->ip_data.tclass << 4) & 0xF0;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV6, TC);
	}

	if (fltr->ip_mask.proto == U8_MAX) {
		iph->nexthdr = fltr->ip_data.proto;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV6, PROT);
	}

	if (!memcmp(&fltr->ip_mask.v6_addrs.src_ip, &ipv6_addr_full_mask,
		    sizeof(struct in6_addr))) {
		memcpy(&iph->saddr, &fltr->ip_data.v6_addrs.src_ip,
		       sizeof(struct in6_addr));
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV6, SRC);
	}

	if (!memcmp(&fltr->ip_mask.v6_addrs.dst_ip, &ipv6_addr_full_mask,
		    sizeof(struct in6_addr))) {
		memcpy(&iph->daddr, &fltr->ip_data.v6_addrs.dst_ip,
		       sizeof(struct in6_addr));
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, IPV6, DST);
	}

	fltr->ip_ver = 6;

	return 0;
}

/**
 * iecm_fill_fdir_tcp_hdr - fill the TCP protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the TCP protocol header is set successfully
 */
static int
iecm_fill_fdir_tcp_hdr(struct iecm_fdir_fltr *fltr,
		       struct virtchnl_proto_hdrs *proto_hdrs)
{
	struct virtchnl_proto_hdr *hdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count++];
	struct tcphdr *tcph = (struct tcphdr *)hdr->buffer;

	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, TCP);

	if (fltr->ip_mask.src_port == htons(U16_MAX)) {
		tcph->source = fltr->ip_data.src_port;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, TCP, SRC_PORT);
	}

	if (fltr->ip_mask.dst_port == htons(U16_MAX)) {
		tcph->dest = fltr->ip_data.dst_port;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, TCP, DST_PORT);
	}

	return 0;
}

/**
 * iecm_fill_fdir_udp_hdr - fill the UDP protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the UDP protocol header is set successfully
 */
static int
iecm_fill_fdir_udp_hdr(struct iecm_fdir_fltr *fltr,
		       struct virtchnl_proto_hdrs *proto_hdrs)
{
	struct virtchnl_proto_hdr *hdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count++];
	struct udphdr *udph = (struct udphdr *)hdr->buffer;

	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, UDP);

	if (fltr->ip_mask.src_port == htons(U16_MAX)) {
		udph->source = fltr->ip_data.src_port;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, UDP, SRC_PORT);
	}

	if (fltr->ip_mask.dst_port == htons(U16_MAX)) {
		udph->dest = fltr->ip_data.dst_port;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, UDP, DST_PORT);
	}

	if (!fltr->flex_cnt)
		return 0;

	return iecm_fill_fdir_udp_flex_pay_hdr(fltr, proto_hdrs);
}

/**
 * iecm_fill_fdir_sctp_hdr - fill the SCTP protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the SCTP protocol header is set successfully
 */
static int
iecm_fill_fdir_sctp_hdr(struct iecm_fdir_fltr *fltr,
			struct virtchnl_proto_hdrs *proto_hdrs)
{
	struct virtchnl_proto_hdr *hdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count++];
	struct sctphdr *sctph = (struct sctphdr *)hdr->buffer;

	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, SCTP);

	if (fltr->ip_mask.src_port == htons(U16_MAX)) {
		sctph->source = fltr->ip_data.src_port;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, SCTP, SRC_PORT);
	}

	if (fltr->ip_mask.dst_port == htons(U16_MAX)) {
		sctph->dest = fltr->ip_data.dst_port;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, SCTP, DST_PORT);
	}

	return 0;
}

/**
 * iecm_fill_fdir_ah_hdr - fill the AH protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the AH protocol header is set successfully
 */
static int
iecm_fill_fdir_ah_hdr(struct iecm_fdir_fltr *fltr,
		      struct virtchnl_proto_hdrs *proto_hdrs)
{
	struct virtchnl_proto_hdr *hdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count++];
	struct ip_auth_hdr *ah = (struct ip_auth_hdr *)hdr->buffer;

	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, AH);

	if (fltr->ip_mask.spi == htonl(U32_MAX)) {
		ah->spi = fltr->ip_data.spi;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, AH, SPI);
	}

	return 0;
}

/**
 * iecm_fill_fdir_esp_hdr - fill the ESP protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the ESP protocol header is set successfully
 */
static int
iecm_fill_fdir_esp_hdr(struct iecm_fdir_fltr *fltr,
		       struct virtchnl_proto_hdrs *proto_hdrs)
{
	struct virtchnl_proto_hdr *hdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count++];
	struct ip_esp_hdr *esph = (struct ip_esp_hdr *)hdr->buffer;

	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, ESP);

	if (fltr->ip_mask.spi == htonl(U32_MAX)) {
		esph->spi = fltr->ip_data.spi;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, ESP, SPI);
	}

	return 0;
}

/**
 * iecm_fill_fdir_l4_hdr - fill the L4 protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the L4 protocol header is set successfully
 */
static int
iecm_fill_fdir_l4_hdr(struct iecm_fdir_fltr *fltr,
		      struct virtchnl_proto_hdrs *proto_hdrs)
{
	struct virtchnl_proto_hdr *hdr;
	__be32 *l4_4_data;

	if (!fltr->ip_mask.proto) /* IPv4/IPv6 header only */
		return 0;

	hdr = &proto_hdrs->proto_hdr[proto_hdrs->count++];
	l4_4_data = (__be32 *)hdr->buffer;

	/* L2TPv3 over IP with 'Session ID' */
	if (fltr->ip_data.proto == 115 &&
	    fltr->ip_mask.l4_header == htonl(U32_MAX)) {
		VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, L2TPV3);
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, L2TPV3, SESS_ID);

		*l4_4_data = fltr->ip_data.l4_header;
	} else {
		return -EOPNOTSUPP;
	}

	return 0;
}

/**
 * iecm_fill_fdir_eth_hdr - fill the Ethernet protocol header
 * @fltr: Flow Director filter data structure
 * @proto_hdrs: Flow Director protocol headers data structure
 *
 * Returns 0 if the Ethernet protocol header is set successfully
 */
static int
iecm_fill_fdir_eth_hdr(struct iecm_fdir_fltr *fltr,
		       struct virtchnl_proto_hdrs *proto_hdrs)
{
	struct virtchnl_proto_hdr *hdr =
				&proto_hdrs->proto_hdr[proto_hdrs->count++];
	struct ethhdr *ehdr = (struct ethhdr *)hdr->buffer;

	VIRTCHNL_SET_PROTO_HDR_TYPE(hdr, ETH);

	if (fltr->eth_mask.etype == htons(U16_MAX)) {
		if (fltr->eth_data.etype == htons(ETH_P_IP) ||
		    fltr->eth_data.etype == htons(ETH_P_IPV6))
			return -EOPNOTSUPP;

		ehdr->h_proto = fltr->eth_data.etype;
		VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT(hdr, ETH, ETHERTYPE);
	}

	return 0;
}

/**
 * iecm_fill_fdir_add_msg - fill the Flow Director filter into virtchnl message
 * @vport: vport structure
 * @fltr: Flow Director filter data structure
 *
 * Returns 0 if the add Flow Director virtchnl message is filled successfully
 */
static int
iecm_fill_fdir_add_msg(struct iecm_vport *vport, struct iecm_fdir_fltr *fltr)
{
	struct virtchnl_fdir_add *vc_msg = &fltr->vc_add_msg;
	struct virtchnl_proto_hdrs *proto_hdrs;
	int err;

	proto_hdrs = &vc_msg->rule_cfg.proto_hdrs;

	err = iecm_fill_fdir_eth_hdr(fltr, proto_hdrs); /* L2 always exists */
	if (err)
		return err;

	switch (fltr->flow_type) {
	case IECM_FDIR_FLOW_IPV4_TCP:
		err = iecm_fill_fdir_ip4_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_tcp_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_IPV4_UDP:
		err = iecm_fill_fdir_ip4_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_udp_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_IPV4_SCTP:
		err = iecm_fill_fdir_ip4_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_sctp_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_IPV4_AH:
		err = iecm_fill_fdir_ip4_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_ah_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_IPV4_ESP:
		err = iecm_fill_fdir_ip4_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_esp_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_IPV4_OTHER:
		err = iecm_fill_fdir_ip4_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_l4_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_IPV6_TCP:
		err = iecm_fill_fdir_ip6_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_tcp_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_IPV6_UDP:
		err = iecm_fill_fdir_ip6_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_udp_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_IPV6_SCTP:
		err = iecm_fill_fdir_ip6_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_sctp_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_IPV6_AH:
		err = iecm_fill_fdir_ip6_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_ah_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_IPV6_ESP:
		err = iecm_fill_fdir_ip6_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_esp_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_IPV6_OTHER:
		err = iecm_fill_fdir_ip6_hdr(fltr, proto_hdrs) |
		      iecm_fill_fdir_l4_hdr(fltr, proto_hdrs);
		break;
	case IECM_FDIR_FLOW_NON_IP_L2:
		break;
	default:
		err = -EINVAL;
		break;
	}

	if (err)
		return err;

	vc_msg->vsi_id = vport->vport_id;
	vc_msg->rule_cfg.action_set.count = 1;
	vc_msg->rule_cfg.action_set.actions[0].type = fltr->action;
	vc_msg->rule_cfg.action_set.actions[0].act_conf.queue.index =
								fltr->q_index;

	return 0;
}

/**
 * iecm_fdir_flow_proto_name - get the flow protocol name
 * @flow_type: Flow Director filter flow type
 **/
static const char *
iecm_fdir_flow_proto_name(enum iecm_fdir_flow_type flow_type)
{
	switch (flow_type) {
	case IECM_FDIR_FLOW_IPV4_TCP:
	case IECM_FDIR_FLOW_IPV6_TCP:
		return "TCP";
	case IECM_FDIR_FLOW_IPV4_UDP:
	case IECM_FDIR_FLOW_IPV6_UDP:
		return "UDP";
	case IECM_FDIR_FLOW_IPV4_SCTP:
	case IECM_FDIR_FLOW_IPV6_SCTP:
		return "SCTP";
	case IECM_FDIR_FLOW_IPV4_AH:
	case IECM_FDIR_FLOW_IPV6_AH:
		return "AH";
	case IECM_FDIR_FLOW_IPV4_ESP:
	case IECM_FDIR_FLOW_IPV6_ESP:
		return "ESP";
	case IECM_FDIR_FLOW_IPV4_OTHER:
	case IECM_FDIR_FLOW_IPV6_OTHER:
		return "Other";
	case IECM_FDIR_FLOW_NON_IP_L2:
		return "Ethernet";
	default:
		return NULL;
	}
}

/**
 * iecm_dump_fdir_fltr
 * @vport: vport structure
 * @fltr: Flow Director filter to print
 *
 * Print the Flow Director filter
 **/
static void
iecm_dump_fdir_fltr(struct iecm_vport *vport, struct iecm_fdir_fltr *fltr)
{
	const char *proto = iecm_fdir_flow_proto_name(fltr->flow_type);
	struct device *dev = &vport->adapter->pdev->dev;

	if (!proto)
		return;

	switch (fltr->flow_type) {
	case IECM_FDIR_FLOW_IPV4_TCP:
	case IECM_FDIR_FLOW_IPV4_UDP:
	case IECM_FDIR_FLOW_IPV4_SCTP:
		dev_info(dev, "Rule ID: %u dst_ip: %pI4 src_ip %pI4 %s: dst_port %hu src_port %hu\n",
			 fltr->loc,
			 &fltr->ip_data.v4_addrs.dst_ip,
			 &fltr->ip_data.v4_addrs.src_ip,
			 proto,
			 ntohs(fltr->ip_data.dst_port),
			 ntohs(fltr->ip_data.src_port));
		break;
	case IECM_FDIR_FLOW_IPV4_AH:
	case IECM_FDIR_FLOW_IPV4_ESP:
		dev_info(dev, "Rule ID: %u dst_ip: %pI4 src_ip %pI4 %s: SPI %u\n",
			 fltr->loc,
			 &fltr->ip_data.v4_addrs.dst_ip,
			 &fltr->ip_data.v4_addrs.src_ip,
			 proto,
			 ntohl(fltr->ip_data.spi));
		break;
	case IECM_FDIR_FLOW_IPV4_OTHER:
		dev_info(dev, "Rule ID: %u dst_ip: %pI4 src_ip %pI4 proto: %u L4_bytes: 0x%x\n",
			 fltr->loc,
			 &fltr->ip_data.v4_addrs.dst_ip,
			 &fltr->ip_data.v4_addrs.src_ip,
			 fltr->ip_data.proto,
			 ntohl(fltr->ip_data.l4_header));
		break;
	case IECM_FDIR_FLOW_IPV6_TCP:
	case IECM_FDIR_FLOW_IPV6_UDP:
	case IECM_FDIR_FLOW_IPV6_SCTP:
		dev_info(dev, "Rule ID: %u dst_ip: %pI6 src_ip %pI6 %s: dst_port %hu src_port %hu\n",
			 fltr->loc,
			 &fltr->ip_data.v6_addrs.dst_ip,
			 &fltr->ip_data.v6_addrs.src_ip,
			 proto,
			 ntohs(fltr->ip_data.dst_port),
			 ntohs(fltr->ip_data.src_port));
		break;
	case IECM_FDIR_FLOW_IPV6_AH:
	case IECM_FDIR_FLOW_IPV6_ESP:
		dev_info(dev, "Rule ID: %u dst_ip: %pI6 src_ip %pI6 %s: SPI %u\n",
			 fltr->loc,
			 &fltr->ip_data.v6_addrs.dst_ip,
			 &fltr->ip_data.v6_addrs.src_ip,
			 proto,
			 ntohl(fltr->ip_data.spi));
		break;
	case IECM_FDIR_FLOW_IPV6_OTHER:
		dev_info(dev, "Rule ID: %u dst_ip: %pI6 src_ip %pI6 proto: %u L4_bytes: 0x%x\n",
			 fltr->loc,
			 &fltr->ip_data.v6_addrs.dst_ip,
			 &fltr->ip_data.v6_addrs.src_ip,
			 fltr->ip_data.proto,
			 ntohl(fltr->ip_data.l4_header));
		break;
	case IECM_FDIR_FLOW_NON_IP_L2:
		dev_info(dev, "Rule ID: %u eth_type: 0x%x\n",
			 fltr->loc,
			 ntohs(fltr->eth_data.etype));
		break;
	default:
		break;
	}
}

/**
 * iecm_fdir_is_dup_fltr - test if filter is already in list
 * @adapter: board private structure
 * @fltr: Flow Director filter data structure
 *
 * Returns true if the filter is found in the list
 */
static bool
iecm_fdir_is_dup_fltr(struct iecm_adapter *adapter,
		      struct iecm_fdir_fltr *fltr)
{
	struct iecm_fdir_fltr_config *fdir_config;
	struct iecm_fdir_fltr *tmp;

	fdir_config = &adapter->config_data.fdir_config;
	list_for_each_entry(tmp, &fdir_config->fdir_fltr_list, list) {
		if (tmp->flow_type != fltr->flow_type)
			continue;

		if (!memcmp(&tmp->eth_data, &fltr->eth_data,
			    sizeof(fltr->eth_data)) &&
		    !memcmp(&tmp->ip_data, &fltr->ip_data,
			    sizeof(fltr->ip_data)) &&
		    !memcmp(&tmp->ext_data, &fltr->ext_data,
			    sizeof(fltr->ext_data)))
			return true;
	}

	return false;
}

/**
 * iecm_find_fdir_fltr_by_loc - find filter with location
 * @adapter: board private structure
 * @loc: location to find.
 *
 * Returns pointer to Flow Director filter if found or null
 */
static struct iecm_fdir_fltr *
iecm_find_fdir_fltr_by_loc(struct iecm_adapter *adapter, u32 loc)
{
	struct iecm_fdir_fltr_config *fdir_config;
	struct iecm_fdir_fltr *rule;

	fdir_config = &adapter->config_data.fdir_config;
	list_for_each_entry(rule, &fdir_config->fdir_fltr_list, list)
		if (rule->loc == loc)
			return rule;

	return NULL;
}

/**
 * iecm_fdir_list_add_fltr - add a new node to the flow director filter list
 * @adapter: board private structure
 * @fltr: filter node to add to structure
 */
static void
iecm_fdir_list_add_fltr(struct iecm_adapter *adapter,
			struct iecm_fdir_fltr *fltr)
{
	struct iecm_fdir_fltr *rule, *parent = NULL;
	struct iecm_fdir_fltr_config *fdir_config;

	fdir_config = &adapter->config_data.fdir_config;

	spin_lock_bh(&adapter->fdir_fltr_list_lock);
	list_for_each_entry(rule, &fdir_config->fdir_fltr_list, list) {
		if (rule->loc >= fltr->loc)
			break;
		parent = rule;
	}

	if (parent)
		list_add(&fltr->list, &parent->list);
	else
		list_add(&fltr->list, &fdir_config->fdir_fltr_list);
	fltr->add = true;
	spin_unlock_bh(&adapter->fdir_fltr_list_lock);
}

/**
 * iecm_fltr_to_ethtool_flow - convert filter type values to ethtool
 * flow type values
 * @flow: filter type to be converted
 *
 * Returns the corresponding ethtool flow type.
 */
static int iecm_fltr_to_ethtool_flow(enum iecm_fdir_flow_type flow)
{
	switch (flow) {
	case IECM_FDIR_FLOW_IPV4_TCP:
		return TCP_V4_FLOW;
	case IECM_FDIR_FLOW_IPV4_UDP:
		return UDP_V4_FLOW;
	case IECM_FDIR_FLOW_IPV4_SCTP:
		return SCTP_V4_FLOW;
	case IECM_FDIR_FLOW_IPV4_AH:
		return AH_V4_FLOW;
	case IECM_FDIR_FLOW_IPV4_ESP:
		return ESP_V4_FLOW;
	case IECM_FDIR_FLOW_IPV4_OTHER:
		return IPV4_USER_FLOW;
	case IECM_FDIR_FLOW_IPV6_TCP:
		return TCP_V6_FLOW;
	case IECM_FDIR_FLOW_IPV6_UDP:
		return UDP_V6_FLOW;
	case IECM_FDIR_FLOW_IPV6_SCTP:
		return SCTP_V6_FLOW;
	case IECM_FDIR_FLOW_IPV6_AH:
		return AH_V6_FLOW;
	case IECM_FDIR_FLOW_IPV6_ESP:
		return ESP_V6_FLOW;
	case IECM_FDIR_FLOW_IPV6_OTHER:
		return IPV6_USER_FLOW;
	case IECM_FDIR_FLOW_NON_IP_L2:
		return ETHER_FLOW;
	default:
		/* 0 is undefined ethtool flow */
		return 0;
	}
}

/**
 * iecm_ethtool_flow_to_fltr - convert ethtool flow type to filter enum
 * @eth: Ethtool flow type to be converted
 *
 * Returns flow enum
 */
static enum iecm_fdir_flow_type iecm_ethtool_flow_to_fltr(int eth)
{
	switch (eth) {
	case TCP_V4_FLOW:
		return IECM_FDIR_FLOW_IPV4_TCP;
	case UDP_V4_FLOW:
		return IECM_FDIR_FLOW_IPV4_UDP;
	case SCTP_V4_FLOW:
		return IECM_FDIR_FLOW_IPV4_SCTP;
	case AH_V4_FLOW:
		return IECM_FDIR_FLOW_IPV4_AH;
	case ESP_V4_FLOW:
		return IECM_FDIR_FLOW_IPV4_ESP;
	case IPV4_USER_FLOW:
		return IECM_FDIR_FLOW_IPV4_OTHER;
	case TCP_V6_FLOW:
		return IECM_FDIR_FLOW_IPV6_TCP;
	case UDP_V6_FLOW:
		return IECM_FDIR_FLOW_IPV6_UDP;
	case SCTP_V6_FLOW:
		return IECM_FDIR_FLOW_IPV6_SCTP;
	case AH_V6_FLOW:
		return IECM_FDIR_FLOW_IPV6_AH;
	case ESP_V6_FLOW:
		return IECM_FDIR_FLOW_IPV6_ESP;
	case IPV6_USER_FLOW:
		return IECM_FDIR_FLOW_IPV6_OTHER;
	case ETHER_FLOW:
		return IECM_FDIR_FLOW_NON_IP_L2;
	default:
		return IECM_FDIR_FLOW_NONE;
	}
}

/**
 * iecm_is_mask_valid - check mask field set
 * @mask: full mask to check
 * @field: field for which mask should be valid
 *
 * If the mask is fully set return true. If it is not valid for field return
 * false.
 */
static bool iecm_is_mask_valid(u64 mask, u64 field)
{
	return (mask & field) == field;
}

/**
 * iecm_parse_rx_flow_user_data - deconstruct user-defined data
 * @fsp: pointer to ethtool Rx flow specification
 * @fltr: pointer to Flow Director filter for userdef data storage
 *
 * Returns 0 on success, negative error value on failure
 */
static int
iecm_parse_rx_flow_user_data(struct ethtool_rx_flow_spec *fsp,
			     struct iecm_fdir_fltr *fltr)
{
	struct iecm_flex_word *flex;
	int i, cnt = 0;

	if (!(fsp->flow_type & FLOW_EXT))
		return 0;

	for (i = 0; i < IECM_FLEX_WORD_NUM; i++) {
#define IECM_USERDEF_FLEX_WORD_M	GENMASK(15, 0)
#define IECM_USERDEF_FLEX_OFFS_S	16
#define IECM_USERDEF_FLEX_OFFS_M	GENMASK(31, IECM_USERDEF_FLEX_OFFS_S)
#define IECM_USERDEF_FLEX_FLTR_M	GENMASK(31, 0)
		u32 value = be32_to_cpu(fsp->h_ext.data[i]);
		u32 mask = be32_to_cpu(fsp->m_ext.data[i]);

		if (!value || !mask)
			continue;

		if (!iecm_is_mask_valid(mask, IECM_USERDEF_FLEX_FLTR_M))
			return -EINVAL;

		/* 504 is the maximum value for offsets, and offset is measured
		 * from the start of the MAC address.
		 */
#define IECM_USERDEF_FLEX_MAX_OFFS_VAL 504
		flex = &fltr->flex_words[cnt++];
		flex->word = value & IECM_USERDEF_FLEX_WORD_M;
		flex->offset = (value & IECM_USERDEF_FLEX_OFFS_M) >>
			     IECM_USERDEF_FLEX_OFFS_S;
		if (flex->offset > IECM_USERDEF_FLEX_MAX_OFFS_VAL)
			return -EINVAL;
	}

	fltr->flex_cnt = cnt;

	return 0;
}

/**
 * iecm_fill_rx_flow_ext_data - fill the additional data
 * @fsp: pointer to ethtool Rx flow specification
 * @fltr: pointer to Flow Director filter to get additional data
 */
static void
iecm_fill_rx_flow_ext_data(struct ethtool_rx_flow_spec *fsp,
			   struct iecm_fdir_fltr *fltr)
{
	if (!fltr->ext_mask.usr_def[0] && !fltr->ext_mask.usr_def[1])
		return;

	fsp->flow_type |= FLOW_EXT;

	memcpy(fsp->h_ext.data, fltr->ext_data.usr_def,
	       sizeof(fsp->h_ext.data));
	memcpy(fsp->m_ext.data, fltr->ext_mask.usr_def,
	       sizeof(fsp->m_ext.data));
}

/**
 * iecm_get_fdir_fltr_entry - fill ethtool structure with Flow Director
 * filter data
 * @vport: vport structure
 * @cmd: ethtool command data structure to receive the filter data
 *
 * Returns 0 as expected for success by ethtool
 */
int
iecm_get_fdir_fltr_entry(struct iecm_vport *vport, struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp =
					(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_fdir_fltr *rule;
	int ret = 0;

	if (adapter->state != __IECM_UP)
		return -EIO;

	if (!iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_FDIR))
		return -EOPNOTSUPP;

	spin_lock_bh(&adapter->fdir_fltr_list_lock);

	rule = iecm_find_fdir_fltr_by_loc(adapter, fsp->location);
	if (!rule) {
		ret = -EINVAL;
		goto release_lock;
	}

	fsp->flow_type = iecm_fltr_to_ethtool_flow(rule->flow_type);

	memset(&fsp->m_u, 0, sizeof(fsp->m_u));
	memset(&fsp->m_ext, 0, sizeof(fsp->m_ext));

	switch (fsp->flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
		fsp->h_u.tcp_ip4_spec.ip4src = rule->ip_data.v4_addrs.src_ip;
		fsp->h_u.tcp_ip4_spec.ip4dst = rule->ip_data.v4_addrs.dst_ip;
		fsp->h_u.tcp_ip4_spec.psrc = rule->ip_data.src_port;
		fsp->h_u.tcp_ip4_spec.pdst = rule->ip_data.dst_port;
		fsp->h_u.tcp_ip4_spec.tos = rule->ip_data.tos;
		fsp->m_u.tcp_ip4_spec.ip4src = rule->ip_mask.v4_addrs.src_ip;
		fsp->m_u.tcp_ip4_spec.ip4dst = rule->ip_mask.v4_addrs.dst_ip;
		fsp->m_u.tcp_ip4_spec.psrc = rule->ip_mask.src_port;
		fsp->m_u.tcp_ip4_spec.pdst = rule->ip_mask.dst_port;
		fsp->m_u.tcp_ip4_spec.tos = rule->ip_mask.tos;
		break;
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
		fsp->h_u.ah_ip4_spec.ip4src = rule->ip_data.v4_addrs.src_ip;
		fsp->h_u.ah_ip4_spec.ip4dst = rule->ip_data.v4_addrs.dst_ip;
		fsp->h_u.ah_ip4_spec.spi = rule->ip_data.spi;
		fsp->h_u.ah_ip4_spec.tos = rule->ip_data.tos;
		fsp->m_u.ah_ip4_spec.ip4src = rule->ip_mask.v4_addrs.src_ip;
		fsp->m_u.ah_ip4_spec.ip4dst = rule->ip_mask.v4_addrs.dst_ip;
		fsp->m_u.ah_ip4_spec.spi = rule->ip_mask.spi;
		fsp->m_u.ah_ip4_spec.tos = rule->ip_mask.tos;
		break;
	case IPV4_USER_FLOW:
		fsp->h_u.usr_ip4_spec.ip4src = rule->ip_data.v4_addrs.src_ip;
		fsp->h_u.usr_ip4_spec.ip4dst = rule->ip_data.v4_addrs.dst_ip;
		fsp->h_u.usr_ip4_spec.l4_4_bytes = rule->ip_data.l4_header;
		fsp->h_u.usr_ip4_spec.tos = rule->ip_data.tos;
		fsp->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
		fsp->h_u.usr_ip4_spec.proto = rule->ip_data.proto;
		fsp->m_u.usr_ip4_spec.ip4src = rule->ip_mask.v4_addrs.src_ip;
		fsp->m_u.usr_ip4_spec.ip4dst = rule->ip_mask.v4_addrs.dst_ip;
		fsp->m_u.usr_ip4_spec.l4_4_bytes = rule->ip_mask.l4_header;
		fsp->m_u.usr_ip4_spec.tos = rule->ip_mask.tos;
		fsp->m_u.usr_ip4_spec.ip_ver = 0xFF;
		fsp->m_u.usr_ip4_spec.proto = rule->ip_mask.proto;
		break;
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
		memcpy(fsp->h_u.usr_ip6_spec.ip6src,
		       &rule->ip_data.v6_addrs.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->h_u.usr_ip6_spec.ip6dst,
		       &rule->ip_data.v6_addrs.dst_ip, sizeof(struct in6_addr));
		fsp->h_u.tcp_ip6_spec.psrc = rule->ip_data.src_port;
		fsp->h_u.tcp_ip6_spec.pdst = rule->ip_data.dst_port;
		fsp->h_u.tcp_ip6_spec.tclass = rule->ip_data.tclass;
		memcpy(fsp->m_u.usr_ip6_spec.ip6src,
		       &rule->ip_mask.v6_addrs.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->m_u.usr_ip6_spec.ip6dst,
		       &rule->ip_mask.v6_addrs.dst_ip, sizeof(struct in6_addr));
		fsp->m_u.tcp_ip6_spec.psrc = rule->ip_mask.src_port;
		fsp->m_u.tcp_ip6_spec.pdst = rule->ip_mask.dst_port;
		fsp->m_u.tcp_ip6_spec.tclass = rule->ip_mask.tclass;
		break;
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
		memcpy(fsp->h_u.ah_ip6_spec.ip6src,
		       &rule->ip_data.v6_addrs.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->h_u.ah_ip6_spec.ip6dst,
		       &rule->ip_data.v6_addrs.dst_ip, sizeof(struct in6_addr));
		fsp->h_u.ah_ip6_spec.spi = rule->ip_data.spi;
		fsp->h_u.ah_ip6_spec.tclass = rule->ip_data.tclass;
		memcpy(fsp->m_u.ah_ip6_spec.ip6src,
		       &rule->ip_mask.v6_addrs.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->m_u.ah_ip6_spec.ip6dst,
		       &rule->ip_mask.v6_addrs.dst_ip, sizeof(struct in6_addr));
		fsp->m_u.ah_ip6_spec.spi = rule->ip_mask.spi;
		fsp->m_u.ah_ip6_spec.tclass = rule->ip_mask.tclass;
		break;
	case IPV6_USER_FLOW:
		memcpy(fsp->h_u.usr_ip6_spec.ip6src,
		       &rule->ip_data.v6_addrs.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->h_u.usr_ip6_spec.ip6dst,
		       &rule->ip_data.v6_addrs.dst_ip, sizeof(struct in6_addr));
		fsp->h_u.usr_ip6_spec.l4_4_bytes = rule->ip_data.l4_header;
		fsp->h_u.usr_ip6_spec.tclass = rule->ip_data.tclass;
		fsp->h_u.usr_ip6_spec.l4_proto = rule->ip_data.proto;
		memcpy(fsp->m_u.usr_ip6_spec.ip6src,
		       &rule->ip_mask.v6_addrs.src_ip, sizeof(struct in6_addr));
		memcpy(fsp->m_u.usr_ip6_spec.ip6dst,
		       &rule->ip_mask.v6_addrs.dst_ip, sizeof(struct in6_addr));
		fsp->m_u.usr_ip6_spec.l4_4_bytes = rule->ip_mask.l4_header;
		fsp->m_u.usr_ip6_spec.tclass = rule->ip_mask.tclass;
		fsp->m_u.usr_ip6_spec.l4_proto = rule->ip_mask.proto;
		break;
	case ETHER_FLOW:
		fsp->h_u.ether_spec.h_proto = rule->eth_data.etype;
		fsp->m_u.ether_spec.h_proto = rule->eth_mask.etype;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	iecm_fill_rx_flow_ext_data(fsp, rule);

	if (rule->action == VIRTCHNL_ACTION_DROP)
		fsp->ring_cookie = RX_CLS_FLOW_DISC;
	else
		fsp->ring_cookie = rule->q_index;

release_lock:
	spin_unlock_bh(&adapter->fdir_fltr_list_lock);
	return ret;
}

/**
 * iecm_get_fdir_fltr_ids - fill buffer with filter IDs of active filters
 * @vport: vport structure
 * @cmd: ethtool command data structure
 * @rule_locs: ethtool array passed in from OS to receive filter IDs
 *
 * Returns 0 as expected for success by ethtool
 */
int
iecm_get_fdir_fltr_ids(struct iecm_vport *vport, struct ethtool_rxnfc *cmd,
		       u32 *rule_locs)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct iecm_fdir_fltr_config *fdir_config;
	struct iecm_fdir_fltr *fltr;
	unsigned int cnt = 0;
	int ret = 0;

	if (adapter->state != __IECM_UP)
		return -EIO;

	if (!iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_FDIR))
		return -EOPNOTSUPP;

	cmd->data = IECM_MAX_FDIR_FILTERS;

	fdir_config = &adapter->config_data.fdir_config;

	spin_lock_bh(&adapter->fdir_fltr_list_lock);

	list_for_each_entry(fltr, &fdir_config->fdir_fltr_list, list) {
		if (cnt == cmd->rule_cnt) {
			ret = -EMSGSIZE;
			goto release_lock;
		}
		rule_locs[cnt] = fltr->loc;
		cnt++;
	}

release_lock:
	spin_unlock_bh(&adapter->fdir_fltr_list_lock);
	if (!ret)
		cmd->rule_cnt = cnt;

	return ret;
}

/**
 * iecm_add_fdir_fltr_info - Set the input set for Flow Director filter
 * @vport: vport structure
 * @fsp: pointer to ethtool Rx flow specification
 * @fltr: filter structure
 */
static int
iecm_add_fdir_fltr_info(struct iecm_vport *vport,
			struct ethtool_rx_flow_spec *fsp,
			struct iecm_fdir_fltr *fltr)
{
	struct iecm_adapter *adapter = vport->adapter;
	u32 flow_type, q_index = 0;
	enum virtchnl_action act;
	int err;

	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		act = VIRTCHNL_ACTION_DROP;
	} else {
		q_index = fsp->ring_cookie;
		if (q_index >= vport->num_rxq)
			return -EINVAL;

		act = VIRTCHNL_ACTION_QUEUE;
	}

	fltr->action = act;
	fltr->loc = fsp->location;
	fltr->q_index = q_index;

	if (fsp->flow_type & FLOW_EXT) {
		memcpy(fltr->ext_data.usr_def, fsp->h_ext.data,
		       sizeof(fltr->ext_data.usr_def));
		memcpy(fltr->ext_mask.usr_def, fsp->m_ext.data,
		       sizeof(fltr->ext_mask.usr_def));
	}

	flow_type = fsp->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS);
	fltr->flow_type = iecm_ethtool_flow_to_fltr(flow_type);

	switch (flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
		fltr->ip_data.v4_addrs.src_ip = fsp->h_u.tcp_ip4_spec.ip4src;
		fltr->ip_data.v4_addrs.dst_ip = fsp->h_u.tcp_ip4_spec.ip4dst;
		fltr->ip_data.src_port = fsp->h_u.tcp_ip4_spec.psrc;
		fltr->ip_data.dst_port = fsp->h_u.tcp_ip4_spec.pdst;
		fltr->ip_data.tos = fsp->h_u.tcp_ip4_spec.tos;
		fltr->ip_mask.v4_addrs.src_ip = fsp->m_u.tcp_ip4_spec.ip4src;
		fltr->ip_mask.v4_addrs.dst_ip = fsp->m_u.tcp_ip4_spec.ip4dst;
		fltr->ip_mask.src_port = fsp->m_u.tcp_ip4_spec.psrc;
		fltr->ip_mask.dst_port = fsp->m_u.tcp_ip4_spec.pdst;
		fltr->ip_mask.tos = fsp->m_u.tcp_ip4_spec.tos;
		break;
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
		fltr->ip_data.v4_addrs.src_ip = fsp->h_u.ah_ip4_spec.ip4src;
		fltr->ip_data.v4_addrs.dst_ip = fsp->h_u.ah_ip4_spec.ip4dst;
		fltr->ip_data.spi = fsp->h_u.ah_ip4_spec.spi;
		fltr->ip_data.tos = fsp->h_u.ah_ip4_spec.tos;
		fltr->ip_mask.v4_addrs.src_ip = fsp->m_u.ah_ip4_spec.ip4src;
		fltr->ip_mask.v4_addrs.dst_ip = fsp->m_u.ah_ip4_spec.ip4dst;
		fltr->ip_mask.spi = fsp->m_u.ah_ip4_spec.spi;
		fltr->ip_mask.tos = fsp->m_u.ah_ip4_spec.tos;
		break;
	case IPV4_USER_FLOW:
		fltr->ip_data.v4_addrs.src_ip = fsp->h_u.usr_ip4_spec.ip4src;
		fltr->ip_data.v4_addrs.dst_ip = fsp->h_u.usr_ip4_spec.ip4dst;
		fltr->ip_data.l4_header = fsp->h_u.usr_ip4_spec.l4_4_bytes;
		fltr->ip_data.tos = fsp->h_u.usr_ip4_spec.tos;
		fltr->ip_data.proto = fsp->h_u.usr_ip4_spec.proto;
		fltr->ip_mask.v4_addrs.src_ip = fsp->m_u.usr_ip4_spec.ip4src;
		fltr->ip_mask.v4_addrs.dst_ip = fsp->m_u.usr_ip4_spec.ip4dst;
		fltr->ip_mask.l4_header = fsp->m_u.usr_ip4_spec.l4_4_bytes;
		fltr->ip_mask.tos = fsp->m_u.usr_ip4_spec.tos;
		fltr->ip_mask.proto = fsp->m_u.usr_ip4_spec.proto;
		break;
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
		memcpy(&fltr->ip_data.v6_addrs.src_ip,
		       fsp->h_u.usr_ip6_spec.ip6src, sizeof(struct in6_addr));
		memcpy(&fltr->ip_data.v6_addrs.dst_ip,
		       fsp->h_u.usr_ip6_spec.ip6dst, sizeof(struct in6_addr));
		fltr->ip_data.src_port = fsp->h_u.tcp_ip6_spec.psrc;
		fltr->ip_data.dst_port = fsp->h_u.tcp_ip6_spec.pdst;
		fltr->ip_data.tclass = fsp->h_u.tcp_ip6_spec.tclass;
		memcpy(&fltr->ip_mask.v6_addrs.src_ip,
		       fsp->m_u.usr_ip6_spec.ip6src, sizeof(struct in6_addr));
		memcpy(&fltr->ip_mask.v6_addrs.dst_ip,
		       fsp->m_u.usr_ip6_spec.ip6dst, sizeof(struct in6_addr));
		fltr->ip_mask.src_port = fsp->m_u.tcp_ip6_spec.psrc;
		fltr->ip_mask.dst_port = fsp->m_u.tcp_ip6_spec.pdst;
		fltr->ip_mask.tclass = fsp->m_u.tcp_ip6_spec.tclass;
		break;
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
		memcpy(&fltr->ip_data.v6_addrs.src_ip,
		       fsp->h_u.ah_ip6_spec.ip6src, sizeof(struct in6_addr));
		memcpy(&fltr->ip_data.v6_addrs.dst_ip,
		       fsp->h_u.ah_ip6_spec.ip6dst, sizeof(struct in6_addr));
		fltr->ip_data.spi = fsp->h_u.ah_ip6_spec.spi;
		fltr->ip_data.tclass = fsp->h_u.ah_ip6_spec.tclass;
		memcpy(&fltr->ip_mask.v6_addrs.src_ip,
		       fsp->m_u.ah_ip6_spec.ip6src, sizeof(struct in6_addr));
		memcpy(&fltr->ip_mask.v6_addrs.dst_ip,
		       fsp->m_u.ah_ip6_spec.ip6dst, sizeof(struct in6_addr));
		fltr->ip_mask.spi = fsp->m_u.ah_ip6_spec.spi;
		fltr->ip_mask.tclass = fsp->m_u.ah_ip6_spec.tclass;
		break;
	case IPV6_USER_FLOW:
		memcpy(&fltr->ip_data.v6_addrs.src_ip,
		       fsp->h_u.usr_ip6_spec.ip6src, sizeof(struct in6_addr));
		memcpy(&fltr->ip_data.v6_addrs.dst_ip,
		       fsp->h_u.usr_ip6_spec.ip6dst, sizeof(struct in6_addr));
		fltr->ip_data.l4_header = fsp->h_u.usr_ip6_spec.l4_4_bytes;
		fltr->ip_data.tclass = fsp->h_u.usr_ip6_spec.tclass;
		fltr->ip_data.proto = fsp->h_u.usr_ip6_spec.l4_proto;
		memcpy(&fltr->ip_mask.v6_addrs.src_ip,
		       fsp->m_u.usr_ip6_spec.ip6src, sizeof(struct in6_addr));
		memcpy(&fltr->ip_mask.v6_addrs.dst_ip,
		       fsp->m_u.usr_ip6_spec.ip6dst, sizeof(struct in6_addr));
		fltr->ip_mask.l4_header = fsp->m_u.usr_ip6_spec.l4_4_bytes;
		fltr->ip_mask.tclass = fsp->m_u.usr_ip6_spec.tclass;
		fltr->ip_mask.proto = fsp->m_u.usr_ip6_spec.l4_proto;
		break;
	case ETHER_FLOW:
		fltr->eth_data.etype = fsp->h_u.ether_spec.h_proto;
		fltr->eth_mask.etype = fsp->m_u.ether_spec.h_proto;
		break;
	default:
		/* not doing un-parsed flow types */
		return -EINVAL;
	}

	if (iecm_fdir_is_dup_fltr(adapter, fltr))
		return -EEXIST;

	err = iecm_parse_rx_flow_user_data(fsp, fltr);
	if (err)
		return err;

	return iecm_fill_fdir_add_msg(vport, fltr);
}

/**
 * iecm_add_fdir_fltr - add Flow Director filter
 * @vport: vport structure
 * @cmd: command to add Flow Director filter
 *
 * Returns 0 on success and negative values for failure
 */
int iecm_add_fdir_fltr(struct iecm_vport *vport, struct ethtool_rxnfc *cmd)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct ethtool_rx_flow_spec *fsp = &cmd->fs;
	struct iecm_fdir_fltr_config *fdir_config;
	struct iecm_fdir_fltr *fltr;
	int err;

	if (adapter->state != __IECM_UP)
		return -EIO;

	if (!iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_FDIR))
		return -EOPNOTSUPP;

	if (fsp->flow_type & FLOW_MAC_EXT)
		return -EINVAL;

	fdir_config = &adapter->config_data.fdir_config;
	if (fdir_config->num_active_filters >= IECM_MAX_FDIR_FILTERS) {
		dev_err(&adapter->pdev->dev,
			"Unable to add Flow Director filter because vport reached the limit of max allowed filters (%u)\n",
			IECM_MAX_FDIR_FILTERS);
		return -ENOSPC;
	}

	spin_lock_bh(&adapter->fdir_fltr_list_lock);
	fltr = iecm_find_fdir_fltr_by_loc(adapter, fsp->location);
	if (fltr) {
		fltr->remove = false;
		dev_err(&adapter->pdev->dev, "Failed to add Flow Director filter, it already exists\n");
		spin_unlock_bh(&adapter->fdir_fltr_list_lock);
		return -EEXIST;
	}
	spin_unlock_bh(&adapter->fdir_fltr_list_lock);

	fltr = kzalloc(sizeof(*fltr), GFP_KERNEL);
	if (!fltr)
		return -ENOMEM;

	err = iecm_add_fdir_fltr_info(vport, fsp, fltr);
	if (err)
		goto error;

	iecm_fdir_list_add_fltr(adapter, fltr);
	err = iecm_send_add_fdir_filter_msg(vport);
	if (!err) {
		fdir_config->num_active_filters++;
	} else {
		spin_lock_bh(&adapter->fdir_fltr_list_lock);
		list_del(&fltr->list);
		spin_unlock_bh(&adapter->fdir_fltr_list_lock);
	}

error:
	if (!err) {
		dev_info(&adapter->pdev->dev, "Flow Director filter with location %u is added\n",
			 fsp->location);
	} else {
		dev_info(&adapter->pdev->dev, "Failed to add Flow Director filter\n");
		iecm_dump_fdir_fltr(vport, fltr);
		kfree(fltr);
	}

	return err;
}

/**
 * iecm_del_fdir_fltr - delete Flow Director filter
 * @vport: vport structure
 * @cmd: command to delete Flow Director filter
 *
 * Returns 0 on success and negative values for failure
 */
int iecm_del_fdir_fltr(struct iecm_vport *vport, struct ethtool_rxnfc *cmd)
{
	struct iecm_adapter *adapter = vport->adapter;
	struct ethtool_rx_flow_spec *fsp = &cmd->fs;
	struct iecm_fdir_fltr_config *fdir_config;
	struct iecm_fdir_fltr *fltr = NULL;
	int err = 0;

	if (adapter->state != __IECM_UP)
		return -EIO;

	if (!iecm_is_cap_ena(adapter, IECM_OTHER_CAPS, VIRTCHNL2_CAP_FDIR))
		return -EOPNOTSUPP;

	fdir_config = &adapter->config_data.fdir_config;
	spin_lock_bh(&adapter->fdir_fltr_list_lock);
	fltr = iecm_find_fdir_fltr_by_loc(adapter, fsp->location);
	if (fltr) {
		fltr->remove = true;
		fdir_config->num_active_filters--;
	}
	spin_unlock_bh(&adapter->fdir_fltr_list_lock);
	if (vport->adapter->state == __IECM_UP) {
		err = iecm_send_del_fdir_filter_msg(vport);
		if (err)
			dev_err(&adapter->pdev->dev, "Failed to del Flow Director filter\n");
	}
	/* If the above fails, still delete the filter from the list because
	 * either HW thinks it doesn't exist or we have a bad filter somehow
	 * and it doesn't do us any good to continue hanging on to it.
	 */
	spin_lock_bh(&adapter->fdir_fltr_list_lock);
	fltr = iecm_find_fdir_fltr_by_loc(adapter, fsp->location);
	/* It can happen that asynchronously the filter has already been
	 * removed from the list, make sure it's still there under spinlock
	 * before deleting it.
	 */
	if (fltr) {
		list_del(&fltr->list);
		kfree(fltr);
	}
	spin_unlock_bh(&adapter->fdir_fltr_list_lock);

	return err;
}

#ifdef HAVE_XDP_SUPPORT
/**
 * iecm_vport_set_xdp_tx_desc_handler - Set a handler function for XDP Tx descriptor
 * @vport: vport to setup XDP Tx descriptor handler for
 */
static void iecm_vport_set_xdp_tx_desc_handler(struct iecm_vport *vport)
{
	if (vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE)
		vport->xdp_prepare_tx_desc = iecm_prepare_xdp_tx_singleq_desc;
	else
		vport->xdp_prepare_tx_desc = iecm_prepare_xdp_tx_splitq_desc;
}

/**
 * iecm_xdp_setup_prog - Add or remove XDP eBPF program
 * @vport: vport to setup XDP for
 * @prog: XDP program
 * @extack: netlink extended ack
 */
static int
iecm_xdp_setup_prog(struct iecm_vport *vport, struct bpf_prog *prog,
		    struct netlink_ext_ack *extack)
{
	struct bpf_prog **current_prog = &vport->adapter->config_data.xdp_prog;
	int frame_size = vport->netdev->mtu + IECM_PACKET_HDR_PAD;
	struct bpf_prog *old_prog;

	if (frame_size > IECM_RX_BUF_2048) {
		NL_SET_ERR_MSG_MOD(extack, "MTU too large for loading XDP");
		return -EOPNOTSUPP;
	}

	if (!iecm_xdp_is_prog_ena(vport) && !prog) {
		return 0;
	} else if (!iecm_xdp_is_prog_ena(vport) && prog) {
		netdev_warn(vport->netdev, "Setting up XDP disables header split\n");
		iecm_vport_set_hsplit(vport, false);
		iecm_vport_set_xdp_tx_desc_handler(vport);
	}

	old_prog = xchg(current_prog, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	return iecm_initiate_soft_reset(vport, __IECM_SR_Q_CHANGE);
}

/**
 * iecm_xdp - implements XDP handler
 * @dev: netdevice
 * @xdp: XDP command
 */
#ifdef HAVE_NDO_BPF
static int iecm_xdp(struct net_device *dev, struct netdev_bpf *xdp)
#else
static int iecm_xdp(struct net_device *dev, struct netdev_xdp *xdp)
#endif /* HAVE_NDO_BPF */
{
	struct iecm_vport *vport = iecm_netdev_to_vport(dev);
#ifdef HAVE_XDP_QUERY_PROG
	struct bpf_prog *current_prog;
#endif /* HAVE_XDP_QUERY_PROG */

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return iecm_xdp_setup_prog(vport, xdp->prog, xdp->extack);
#ifdef HAVE_XDP_QUERY_PROG
	case XDP_QUERY_PROG:
		current_prog = vport->adapter->config_data.xdp_prog;
		xdp->prog_id = current_prog ? current_prog->aux->id : 0;

#ifndef NO_NETDEV_BPF_PROG_ATTACHED
		xdp->prog_attached = iecm_xdp_is_prog_ena(vport);
#endif /* !NO_NETDEV_BPF_PROG_ATTACHED */
		return 0;
#endif /* HAVE_XDP_QUERY_PROG */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	case XDP_SETUP_XSK_POOL:
		return iecm_xsk_pool_setup(vport, xdp->xsk.pool, xdp->xsk.queue_id);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	default:
		return -EINVAL;
	}
}
#endif /* HAVE_XDP_SUPPORT */

/**
 * iecm_set_mac - NDO callback to set port mac address
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int iecm_set_mac(struct net_device *netdev, void *p)
{
	struct iecm_vport *vport = iecm_netdev_to_vport(netdev);
	struct sockaddr *addr = p;
	int err = 0;

	if (!iecm_is_cap_ena(vport->adapter, IECM_OTHER_CAPS,
			     VIRTCHNL2_CAP_MACFILTER)) {
		dev_info(&vport->adapter->pdev->dev, "Setting MAC address is not supported\n");
		return -EOPNOTSUPP;
	}

	if (!is_valid_ether_addr(addr->sa_data)) {
		dev_info(&vport->adapter->pdev->dev, "Invalid MAC address: %pM\n",
			 addr->sa_data);
		return -EADDRNOTAVAIL;
	}

	if (ether_addr_equal(netdev->dev_addr, addr->sa_data))
		return 0;

	/* Add new filter */
	err = iecm_add_mac_filter(vport, addr->sa_data, false);
	if (err) {
		__iecm_del_mac_filter(vport, addr->sa_data);
		return err;
	}

	/* Delete the current filter */
	if (is_valid_ether_addr(vport->default_mac_addr))
		iecm_del_mac_filter(vport, vport->default_mac_addr, false);

	ether_addr_copy(vport->default_mac_addr, addr->sa_data);
	ether_addr_copy(netdev->dev_addr, addr->sa_data);

	return err;
}

void *iecm_alloc_dma_mem(struct iecm_hw *hw, struct iecm_dma_mem *mem, u64 size)
{
	struct iecm_adapter *adapter = (struct iecm_adapter *)hw->back;
	size_t sz = ALIGN(size, 4096);

	mem->va = dma_alloc_coherent(&adapter->pdev->dev, sz,
				     &mem->pa, GFP_KERNEL | __GFP_ZERO);
	mem->size = size;

	return mem->va;
}

void iecm_free_dma_mem(struct iecm_hw *hw, struct iecm_dma_mem *mem)
{
	struct iecm_adapter *adapter = (struct iecm_adapter *)hw->back;

	dma_free_coherent(&adapter->pdev->dev, mem->size,
			  mem->va, mem->pa);
	mem->size = 0;
	mem->va = NULL;
	mem->pa = 0;
}

static const struct net_device_ops iecm_netdev_ops_splitq = {
	.ndo_open = iecm_open,
	.ndo_stop = iecm_stop,
	.ndo_start_xmit = iecm_tx_splitq_start,
#ifdef HAVE_NDO_FEATURES_CHECK
	.ndo_features_check = iecm_features_check,
#endif /* HAVE_NDO_FEATURES_CHECK */
	.ndo_set_rx_mode = iecm_set_rx_mode,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = iecm_set_mac,
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	.extended.ndo_change_mtu = iecm_change_mtu,
#else
	.ndo_change_mtu = iecm_change_mtu,
#endif
	.ndo_get_stats64 = iecm_get_stats64,
	.ndo_fix_features = iecm_fix_features,
	.ndo_set_features = iecm_set_features,
	.ndo_tx_timeout = iecm_tx_timeout,
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
	.ndo_vlan_rx_add_vid = iecm_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = iecm_vlan_rx_kill_vid,
#endif /* HAVE_INT_NDO_VLAN_RX_ADD_VID */
#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC
	.extended.ndo_setup_tc_rh = iecm_setup_tc,
#else
	.ndo_setup_tc = iecm_setup_tc,
#endif /* HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC */
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NDO_BPF
	.ndo_bpf = iecm_xdp,
#else
	.ndo_xdp = iecm_xdp,
#endif /* HAVE_NDO_BPF */
	.ndo_xdp_xmit = iecm_xdp_xmit,
#ifndef NO_NDO_XDP_FLUSH
	.ndo_xdp_flush = iecm_xdp_flush,
#endif /* !NO_NDO_XDP_FLUSH */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
#ifdef HAVE_NDO_XSK_WAKEUP
	.ndo_xsk_wakeup = iecm_xsk_splitq_wakeup,
#else
	.ndo_xsk_async_xmit = iecm_xsk_splitq_async_xmit,
#endif /* HAVE_NDO_XSK_WAKEUP */
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#endif /* HAVE_XDP_SUPPORT */
};

static const struct net_device_ops iecm_netdev_ops_singleq = {
	.ndo_open = iecm_open,
	.ndo_stop = iecm_stop,
	.ndo_start_xmit = iecm_tx_singleq_start,
#ifdef HAVE_NDO_FEATURES_CHECK
	.ndo_features_check = iecm_features_check,
#endif /* HAVE_NDO_FEATURES_CHECK */
	.ndo_set_rx_mode = iecm_set_rx_mode,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = iecm_set_mac,
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	.extended.ndo_change_mtu = iecm_change_mtu,
#else
	.ndo_change_mtu = iecm_change_mtu,
#endif
	.ndo_get_stats64 = iecm_get_stats64,
	.ndo_fix_features = iecm_fix_features,
	.ndo_set_features = iecm_set_features,
	.ndo_tx_timeout = iecm_tx_timeout,
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
	.ndo_vlan_rx_add_vid = iecm_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = iecm_vlan_rx_kill_vid,
#endif /* HAVE_INT_NDO_VLAN_RX_ADD_VID */
#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC
	.extended.ndo_setup_tc_rh = iecm_setup_tc,
#else
	.ndo_setup_tc           = iecm_setup_tc,
#endif /* HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC */
#ifdef HAVE_XDP_SUPPORT
	.ndo_xdp_xmit = iecm_xdp_xmit,
#ifndef NO_NDO_XDP_FLUSH
	.ndo_xdp_flush = iecm_xdp_flush,
#endif /* !NO_NDO_XDP_FLUSH */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
#ifdef HAVE_NDO_XSK_WAKEUP
	.ndo_xsk_wakeup = iecm_xsk_singleq_wakeup,
#else
	.ndo_xsk_async_xmit = iecm_xsk_singleq_async_xmit,
#endif /* HAVE_NDO_XSK_WAKEUP */
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
#ifdef HAVE_NDO_BPF
	.ndo_bpf = iecm_xdp,
#else
	.ndo_xdp = iecm_xdp,
#endif /* HAVE_NDO_BPF */
#endif /* HAVE_XDP_SUPPORT */
};
