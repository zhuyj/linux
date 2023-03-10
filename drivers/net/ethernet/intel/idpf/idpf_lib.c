// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Intel Corporation */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "idpf.h"

static const struct net_device_ops idpf_netdev_ops_splitq;
static const struct net_device_ops idpf_netdev_ops_singleq;

const char * const idpf_vport_vc_state_str[] = {
	IDPF_FOREACH_VPORT_VC_STATE(IDPF_GEN_STRING)
};

/**
 * idpf_is_feature_ena - Determine if a particular feature is enabled
 * @vport: vport to check
 * @feature: netdev flag to check
 *
 * Returns true or false if a particular feature is enabled.
 */
bool idpf_is_feature_ena(struct idpf_vport *vport, netdev_features_t feature)
{
	return vport->netdev->features & feature;
}

/**
 * idpf_netdev_to_vport - get a vport handle from a netdev
 * @netdev: network interface device structure
 *
 * It's possible for the vport to be NULL. Caller must check for a valid
 * pointer.
 */
struct idpf_vport *idpf_netdev_to_vport(struct net_device *netdev)
{
	struct idpf_netdev_priv *np = netdev_priv(netdev);

	return np->vport;
}

/**
 * idpf_init_vector_stack - Fill the MSIX vector stack with vector index
 * @adapter: private data struct
 *
 * Return 0 on success, error on failure
 */
int idpf_init_vector_stack(struct idpf_adapter *adapter)
{
	struct idpf_vector_lifo *stack;
	int i, err = 0;
	u16 min_vec;

	mutex_lock(&adapter->vector_lock);
	min_vec = adapter->num_msix_entries - adapter->num_avail_msix;
	stack = &adapter->vector_stack;
	stack->size = adapter->num_msix_entries;
	/* set the base and top to point at start of the 'free pool' to
	 * distribute the unused vectors on-demand basis
	 */
	stack->base = min_vec;
	stack->top = min_vec;

	stack->vec_idx = kcalloc(stack->size, sizeof(u16), GFP_KERNEL);
	if (!stack->vec_idx) {
		err = -ENOMEM;
		goto rel_lock;
	}

	for (i = 0; i < stack->size; i++)
		stack->vec_idx[i] = i;

rel_lock:
	mutex_unlock(&adapter->vector_lock);

	return err;
}

/**
 * idpf_deinit_vector_stack - zero out the MSIX vector stack
 * @adapter: private data struct
 */
void idpf_deinit_vector_stack(struct idpf_adapter *adapter)
{
	struct idpf_vector_lifo *stack;

	mutex_lock(&adapter->vector_lock);
	stack = &adapter->vector_stack;
	kfree(stack->vec_idx);
	stack->vec_idx = NULL;
	mutex_unlock(&adapter->vector_lock);
}

/**
 * idpf_mb_intr_rel_irq - Free the IRQ association with the OS
 * @adapter: adapter structure
 */
static void idpf_mb_intr_rel_irq(struct idpf_adapter *adapter)
{
	int irq_num;

	irq_num = adapter->msix_entries[0].vector;
	free_irq(irq_num, adapter);
}

/**
 * idpf_intr_rel - Release interrupt capabilities and free memory
 * @adapter: adapter to disable interrupts on
 */
void idpf_intr_rel(struct idpf_adapter *adapter)
{
	int err;

	if (!adapter->msix_entries)
		return;
	clear_bit(__IDPF_MB_INTR_MODE, adapter->flags);
	clear_bit(__IDPF_MB_INTR_TRIGGER, adapter->flags);
	idpf_mb_intr_rel_irq(adapter);

	pci_free_irq_vectors(adapter->pdev);

	err = idpf_send_dealloc_vectors_msg(adapter);
	if (err)
		dev_err(&adapter->pdev->dev,
			"Failed to deallocate vectors: %d\n", err);
	idpf_deinit_vector_stack(adapter);
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
}

/**
 * idpf_mb_intr_clean - Interrupt handler for the mailbox
 * @irq: interrupt number
 * @data: pointer to the adapter structure
 */
static irqreturn_t idpf_mb_intr_clean(int __always_unused irq, void *data)
{
	struct idpf_adapter *adapter = (struct idpf_adapter *)data;

	set_bit(__IDPF_MB_INTR_TRIGGER, adapter->flags);
	mod_delayed_work(adapter->serv_wq, &adapter->serv_task,
			 msecs_to_jiffies(0));
	return IRQ_HANDLED;
}

/**
 * idpf_mb_irq_enable - Enable MSIX interrupt for the mailbox
 * @adapter: adapter to get the hardware address for register write
 */
static void idpf_mb_irq_enable(struct idpf_adapter *adapter)
{
	struct idpf_intr_reg *intr = &adapter->mb_vector.intr_reg;
	u32 val;

	val = intr->dyn_ctl_intena_m | intr->dyn_ctl_itridx_m;
	writel(val, intr->dyn_ctl);
	writel(intr->icr_ena_ctlq_m, intr->icr_ena);
}

/**
 * idpf_mb_intr_req_irq - Request irq for the mailbox interrupt
 * @adapter: adapter structure to pass to the mailbox irq handler
 */
static int idpf_mb_intr_req_irq(struct idpf_adapter *adapter)
{
	struct idpf_q_vector *mb_vector = &adapter->mb_vector;
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
	set_bit(__IDPF_MB_INTR_MODE, adapter->flags);
	return 0;
}

/**
 * idpf_get_mb_vec_id - Get vector index for mailbox
 * @adapter: adapter structure to access the vector chunks
 *
 * The first vector id in the requested vector chunks from the CP is for
 * the mailbox
 */
static void idpf_get_mb_vec_id(struct idpf_adapter *adapter)
{
	if (adapter->req_vec_chunks)
		adapter->mb_vector.v_idx =
			le16_to_cpu(adapter->caps.mailbox_vector_id);
	else
		adapter->mb_vector.v_idx = 0;
}

/**
 * idpf_mb_intr_init - Initialize the mailbox interrupt
 * @adapter: adapter structure to store the mailbox vector
 */
static int idpf_mb_intr_init(struct idpf_adapter *adapter)
{
	adapter->dev_ops.reg_ops.mb_intr_reg_init(adapter);
	adapter->irq_mb_handler = idpf_mb_intr_clean;
	return idpf_mb_intr_req_irq(adapter);
}

/**
 * idpf_vector_lifo_push - push MSIX vector index onto stack
 * @adapter: private data struct
 * @vec_idx: vector index to store
 */
static int idpf_vector_lifo_push(struct idpf_adapter *adapter, u16 vec_idx)
{
	struct idpf_vector_lifo *stack = &adapter->vector_stack;

	lockdep_assert_held(&adapter->vector_lock);

	if (stack->top == stack->base) {
		dev_err(&adapter->pdev->dev, "Exceeded the vector stack limit: %d\n",
			stack->top);
		return -EINVAL;
	}

	stack->vec_idx[--stack->top] = vec_idx;
	return 0;
}

/**
 * idpf_vector_lifo_pop - pop MSIX vector index from stack
 * @adapter: private data struct
 */
static int idpf_vector_lifo_pop(struct idpf_adapter *adapter)
{
	struct idpf_vector_lifo *stack = &adapter->vector_stack;

	lockdep_assert_held(&adapter->vector_lock);

	if (stack->top == stack->size) {
		dev_err(&adapter->pdev->dev, "No interrupt vectors are available to distribute!\n");
		return -EINVAL;
	}

	return stack->vec_idx[stack->top++];
}

/**
 * idpf_vector_stash - Store the vector indexes onto the stack
 * @adapter: private data struct
 * @q_vector_idxs: vector index array
 * @vec_info: info related to the number of vectors
 *
 * This function is a no-op if there are no vectors indexes to be stashed
 */
static void idpf_vector_stash(struct idpf_adapter *adapter, u16 *q_vector_idxs,
			      struct idpf_vector_info *vec_info)
{
	int i, base = 0;
	u16 vec_idx;

	lockdep_assert_held(&adapter->vector_lock);

	if (!vec_info->num_curr_vecs)
		return;

	/* For default vports, no need to stash vector allocated from the
	 * default pool onto the stack
	 */
	if (vec_info->default_vport)
		base = IDPF_MIN_Q_VEC;

	for (i = vec_info->num_curr_vecs - 1; i >= base ; i--) {
		vec_idx = q_vector_idxs[i];
		idpf_vector_lifo_push(adapter, vec_idx);
		adapter->num_avail_msix++;
	}
}

/**
 * idpf_req_rel_vector_indexes - Request or release MSIX vector indexes
 * @adapter: driver specific private structure
 * @q_vector_idxs: vector index array
 * @vec_info: info related to the number of vectors
 *
 * This is the core function to distribute the MSIX vectors acquired from the
 * OS. It expectes the caller to pass the number of vectors required and
 * also previously allocated. First, it stashes previously allocated vector
 * indexes on to the stack and then figures out if it can allocate requested
 * vectors. It can wait on acquiring the mutex lock. If the caller passes 0 as
 * requested vectors, then this function just stashes the already allocated
 * vectors and returns 0.
 *
 * Returns actual number of vectors allocated on success, error value on failure
 * If 0 is returned, implies the stack has no vectors to allocate which is also
 * a failure case for the caller
 */
int idpf_req_rel_vector_indexes(struct idpf_adapter *adapter, u16 *q_vector_idxs,
				struct idpf_vector_info *vec_info)
{
	u16 avail_q_vecs, num_req_vecs, num_alloc_vecs = 0;
	struct idpf_vector_lifo *stack;
	int i, j, vecid, max_vecs = 0;

	mutex_lock(&adapter->vector_lock);
	stack = &adapter->vector_stack;
	num_req_vecs = vec_info->num_req_vecs;

	/* Stash interrupt vector indexes onto the stack if required */
	idpf_vector_stash(adapter, q_vector_idxs, vec_info);

	if (!num_req_vecs)
		goto rel_lock;

	if (vec_info->default_vport) {
		/* As IDPF_MIN_Q_VEC per default vport is put aside in the
		 * default pool of the stack, use them for default vports
		 */
		j = (vec_info->index * IDPF_MIN_Q_VEC)  + IDPF_MBX_Q_VEC;
		for (i = 0; i < IDPF_MIN_Q_VEC; i++) {
			q_vector_idxs[num_alloc_vecs++] = stack->vec_idx[j++];
			num_req_vecs--;
		}
	}

	/* Find if stack has enough vector to allocate */
	avail_q_vecs = adapter->num_avail_msix;
	if (avail_q_vecs >= num_req_vecs)
		max_vecs = num_req_vecs;
	else if (avail_q_vecs)
		max_vecs = avail_q_vecs;

	for (j = 0; j < max_vecs; j++) {
		vecid = idpf_vector_lifo_pop(adapter);
		q_vector_idxs[num_alloc_vecs++] = vecid;
	}
	adapter->num_avail_msix -= max_vecs;

	if (vec_info->default_vport && !vec_info->index &&
	    idpf_is_rdma_cap_ena(adapter))
		adapter->rdma_data.num_vecs = IDPF_MAX_RDMA_VEC;

rel_lock:
	mutex_unlock(&adapter->vector_lock);
	return num_alloc_vecs;
}

/**
 * idpf_intr_req - Request interrupt capabilities
 * @adapter: adapter to enable interrupts on
 *
 * Returns 0 on success, negative on failure
 */
int idpf_intr_req(struct idpf_adapter *adapter)
{
	u16 default_vports = idpf_get_default_vports(adapter);
	int num_q_vecs, total_vecs, num_vec_ids;
	int min_vectors, v_actual, err = 0;
	unsigned int vector;
	u16 *vecids;

	total_vecs = idpf_get_reserved_vecs(adapter);
	num_q_vecs = total_vecs - IDPF_MBX_Q_VEC;

	err = idpf_send_alloc_vectors_msg(adapter, num_q_vecs);
	if (err) {
		dev_err(&adapter->pdev->dev,
			"Failed to allocate vectors: %d\n", err);
		return -EAGAIN;
	}

	min_vectors = IDPF_MBX_Q_VEC + (IDPF_MIN_Q_VEC * default_vports);
	min_vectors += IDPF_MAX_RDMA_VEC;
	v_actual = pci_alloc_irq_vectors(adapter->pdev, min_vectors,
					 total_vecs, PCI_IRQ_MSIX);
	if (v_actual < min_vectors) {
		dev_err(&adapter->pdev->dev, "Failed to allocate MSIX vectors: %d\n",
			v_actual);
		err = -EAGAIN;
		goto send_dealloc_vecs;
	}

	adapter->msix_entries = kcalloc(v_actual, sizeof(struct msix_entry),
					GFP_KERNEL);

	if (!adapter->msix_entries) {
		err = -ENOMEM;
		goto free_irq;
	}

	idpf_get_mb_vec_id(adapter);

	vecids = kcalloc(total_vecs, sizeof(u16), GFP_KERNEL);
	if (!vecids) {
		err = -ENOMEM;
		goto free_msix;
	}

	if (adapter->req_vec_chunks) {
		struct virtchnl2_vector_chunks *vchunks;
		struct virtchnl2_alloc_vectors *ac;

		ac = adapter->req_vec_chunks;
		vchunks = &ac->vchunks;

		num_vec_ids = idpf_get_vec_ids(adapter, vecids, total_vecs,
					       vchunks);
		if (num_vec_ids < v_actual) {
			err = -EINVAL;
			goto free_vecids;
		}
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

	adapter->num_req_msix = total_vecs;
	adapter->num_msix_entries = v_actual;
	/* 'num_avail_msix' is used to distribute excess vectors to the vports
	 * after considering the minimum vectors required per each default
	 * vport
	 */
	adapter->num_avail_msix = v_actual - min_vectors;

	/* Fill MSIX vector lifo stack with vector indexes */
	err = idpf_init_vector_stack(adapter);
	if (err)
		goto free_vecids;

	err = idpf_mb_intr_init(adapter);
	if (err)
		goto deinit_vec_stack;
	idpf_mb_irq_enable(adapter);
	kfree(vecids);
	return err;

deinit_vec_stack:
	idpf_deinit_vector_stack(adapter);
free_vecids:
	kfree(vecids);
free_msix:
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
free_irq:
	pci_free_irq_vectors(adapter->pdev);
send_dealloc_vecs:
	idpf_send_dealloc_vectors_msg(adapter);

	return err;
}

/**
 * idpf_find_mac_filter - Search filter list for specific mac filter
 * @vport: main vport structure
 * @macaddr: the MAC address
 *
 * Returns ptr to the filter object or NULL. Must be called while holding the
 * mac_filter_list_lock.
 **/
static struct
idpf_mac_filter *idpf_find_mac_filter(struct idpf_vport *vport,
				      const u8 *macaddr)
{
	struct idpf_vport_user_config_data *config_data;
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_mac_filter *f;

	if (!macaddr)
		return NULL;

	config_data = &adapter->vport_config[vport->idx]->user_config;
	list_for_each_entry(f, &config_data->mac_filter_list, list) {
		if (ether_addr_equal(macaddr, f->macaddr))
			return f;
	}
	return NULL;
}

/**
 * __idpf_del_mac_filter - Delete a MAC filter from the filter list
 * @vport: main vport structure
 * @macaddr: the MAC address
 *
 * Removes filter from list
 **/
static int __idpf_del_mac_filter(struct idpf_vport *vport, const u8 *macaddr)
{
	struct idpf_mac_filter *f;

	if (!macaddr)
		return -EINVAL;

	spin_lock_bh(&vport->mac_filter_list_lock);
	f = idpf_find_mac_filter(vport, macaddr);
	if (f) {
		list_del(&f->list);
		kfree(f);
	}
	spin_unlock_bh(&vport->mac_filter_list_lock);

	return 0;
}

/**
 * idpf_del_mac_filter - Delete a MAC filter from the filter list
 * @vport: main vport structure
 * @macaddr: the MAC address
 * @async: Don't wait for return message
 *
 * Removes filter from list and if interface is up, tells hardware about the
 * removed filter.
 **/
static int idpf_del_mac_filter(struct idpf_vport *vport, const u8 *macaddr,
			       bool async)
{
	struct idpf_mac_filter *f;
	int err = 0;

	if (!macaddr)
		return -EINVAL;

	spin_lock_bh(&vport->mac_filter_list_lock);
	f = idpf_find_mac_filter(vport, macaddr);
	if (f) {
		f->remove = true;
	} else {
		spin_unlock_bh(&vport->mac_filter_list_lock);
		return -EINVAL;
	}
	spin_unlock_bh(&vport->mac_filter_list_lock);

	if (vport->state == __IDPF_VPORT_UP) {
		err = idpf_add_del_mac_filters(vport, false, async);
		if (err)
			return err;
	}

	return  __idpf_del_mac_filter(vport, macaddr);
}

/**
 * __idpf_add_mac_filter - Add mac filter helper function
 * @vport: main vport struct
 * @macaddr: address to add
 *
 * Takes mac_filter_list_lock spinlock to add new filter to list.
 */
static int __idpf_add_mac_filter(struct idpf_vport *vport, const u8 *macaddr)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f = NULL;
	int err = 0;

	vport_config = adapter->vport_config[vport->idx];
	spin_lock_bh(&vport->mac_filter_list_lock);
	f = idpf_find_mac_filter(vport, macaddr);
	if (f) {
		f->remove = false;
		goto unlock;
	}

	f = kzalloc(sizeof(*f), GFP_ATOMIC);
	if (!f) {
		err = -ENOMEM;
		goto unlock;
	}

	ether_addr_copy(f->macaddr, macaddr);
	list_add_tail(&f->list, &vport_config->user_config.mac_filter_list);
	f->add = true;

unlock:
	spin_unlock_bh(&vport->mac_filter_list_lock);
	return err;
}

/**
 * idpf_add_mac_filter - Add a mac filter to the filter list
 * @vport: main vport structure
 * @macaddr: the MAC address
 * @async: Don't wait for return message
 *
 * Returns 0 on success or error on failure. If interface is up, we'll also
 * send the virtchnl message to tell hardware about the filter.
 **/
static int idpf_add_mac_filter(struct idpf_vport *vport,
			       const u8 *macaddr, bool async)
{
	int err = 0;

	if (!macaddr)
		return -EINVAL;

	err = __idpf_add_mac_filter(vport, macaddr);
	if (err)
		return err;

	if (vport->state == __IDPF_VPORT_UP)
		err = idpf_add_del_mac_filters(vport, true, async);

	return err;
}

/**
 * idpf_del_all_mac_filters - Delete all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock.  Deletes all filters
 */
static void idpf_del_all_mac_filters(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f, *ftmp;

	vport_config = adapter->vport_config[vport->idx];
	spin_lock_bh(&vport->mac_filter_list_lock);
	list_for_each_entry_safe(f, ftmp, &vport_config->user_config.mac_filter_list,
				 list) {
		list_del(&f->list);
		kfree(f);
	}
	spin_unlock_bh(&vport->mac_filter_list_lock);
}

/**
 * idpf_restore_mac_filters - Re-add all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock.  Sets add field to true for filters to
 * resync filters back to HW.
 */
static void idpf_restore_mac_filters(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f;

	vport_config = adapter->vport_config[vport->idx];
	spin_lock_bh(&vport->mac_filter_list_lock);
	list_for_each_entry(f, &vport_config->user_config.mac_filter_list, list)
		f->add = true;
	spin_unlock_bh(&vport->mac_filter_list_lock);

	idpf_add_del_mac_filters(vport, true, false);
}

/**
 * idpf_remove_mac_filters - Remove all MAC filters in list
 * @vport: main vport struct
 *
 * Takes mac_filter_list_lock spinlock.  Sets remove field to true for filters to
 * remove filters in  HW.
 */
static void idpf_remove_mac_filters(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	struct idpf_mac_filter *f;

	vport_config = adapter->vport_config[vport->idx];
	spin_lock_bh(&vport->mac_filter_list_lock);
	list_for_each_entry(f, &vport_config->user_config.mac_filter_list, list)
		f->remove = true;
	spin_unlock_bh(&vport->mac_filter_list_lock);

	idpf_add_del_mac_filters(vport, false, false);
}

/**
 * idpf_deinit_mac_addr - deinitialize mac address for vport
 * @vport: main vport structure
 */
static void idpf_deinit_mac_addr(struct idpf_vport *vport)
{
	struct idpf_mac_filter *f;

	spin_lock_bh(&vport->mac_filter_list_lock);
	f = idpf_find_mac_filter(vport, vport->default_mac_addr);
	if (f) {
		list_del(&f->list);
		kfree(f);
	}
	spin_unlock_bh(&vport->mac_filter_list_lock);
}

/**
 * idpf_init_mac_addr - initialize mac address for vport
 * @vport: main vport structure
 * @netdev: pointer to netdev struct associated with this vport
 */
static int idpf_init_mac_addr(struct idpf_vport *vport,
			      struct net_device *netdev)
{
	struct idpf_adapter *adapter = vport->adapter;
	int err = 0;

	if (is_valid_ether_addr(vport->default_mac_addr)) {
		eth_hw_addr_set(netdev, vport->default_mac_addr);
		ether_addr_copy(netdev->perm_addr, vport->default_mac_addr);
		return idpf_add_mac_filter(vport, vport->default_mac_addr, false);
	}

	if (!idpf_is_cap_ena(vport->adapter, IDPF_OTHER_CAPS,
			     VIRTCHNL2_CAP_MACFILTER)) {
		dev_err(&adapter->pdev->dev,
			"MAC address not provided and capability is not set\n");
		return -EINVAL;
	}
	eth_hw_addr_random(netdev);
	err = idpf_add_mac_filter(vport, netdev->dev_addr, false);
	if (err)
		return err;
	ether_addr_copy(vport->default_mac_addr, netdev->dev_addr);
	dev_info(&adapter->pdev->dev, "Invalid MAC address %pM, using random\n",
		 vport->default_mac_addr);

	return 0;
}

/**
 * idpf_cfg_netdev - Allocate, configure and register a netdev
 * @vport: main vport structure
 *
 * Returns 0 on success, negative value on failure.
 */
static int idpf_cfg_netdev(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	netdev_features_t dflt_features;
	netdev_features_t offloads = 0;
	struct idpf_netdev_priv *np;
	struct net_device *netdev;
	u16 idx = vport->idx;
	int err;

	lockdep_assert_held(&adapter->sw_mutex);
	vport_config = adapter->vport_config[idx];

	/* It's possible we already have a netdev allocated and registered for
	 * this vport
	 */
	if (test_bit(__IDPF_VPORT_REG_NETDEV, vport_config->flags)) {
		netdev = adapter->netdevs[idx];
		np = netdev_priv(netdev);
		np->vport = vport;
		vport->netdev = netdev;

		return idpf_init_mac_addr(vport, netdev);
	}

	netdev = alloc_etherdev_mqs(sizeof(struct idpf_netdev_priv),
				    vport_config->max_q.max_txq,
				    vport_config->max_q.max_rxq);
	if (!netdev)
		return -ENOMEM;
	vport->netdev = netdev;
	np = netdev_priv(netdev);
	np->vport = vport;

	err = idpf_init_mac_addr(vport, netdev);
	if (err)
		goto err;

	/* assign netdev_ops */
	if (idpf_is_queue_model_split(vport->txq_model))
		netdev->netdev_ops = &idpf_netdev_ops_splitq;
	else
		netdev->netdev_ops = &idpf_netdev_ops_singleq;

	/* setup watchdog timeout value to be 5 second */
	netdev->watchdog_timeo = 5 * HZ;

	/* configure default MTU size */
	netdev->min_mtu = ETH_MIN_MTU;
	netdev->max_mtu = vport->max_mtu;

	dflt_features = NETIF_F_SG	|
			NETIF_F_HIGHDMA;

	if (idpf_is_cap_ena_all(adapter, IDPF_RSS_CAPS, IDPF_CAP_RSS))
		dflt_features |= NETIF_F_RXHASH;
	if (idpf_is_cap_ena_all(adapter, IDPF_CSUM_CAPS, IDPF_CAP_RX_CSUM_L4V4))
		dflt_features |= NETIF_F_IP_CSUM;
	if (idpf_is_cap_ena_all(adapter, IDPF_CSUM_CAPS, IDPF_CAP_RX_CSUM_L4V6))
		dflt_features |= NETIF_F_IPV6_CSUM;
	if (idpf_is_cap_ena(adapter, IDPF_CSUM_CAPS, IDPF_CAP_RX_CSUM))
		dflt_features |= NETIF_F_RXCSUM;
	if (idpf_is_cap_ena_all(adapter, IDPF_CSUM_CAPS, IDPF_CAP_SCTP_CSUM))
		dflt_features |= NETIF_F_SCTP_CRC;

	if (idpf_is_cap_ena(adapter, IDPF_SEG_CAPS, VIRTCHNL2_CAP_SEG_IPV4_TCP))
		dflt_features |= NETIF_F_TSO;
	if (idpf_is_cap_ena(adapter, IDPF_SEG_CAPS, VIRTCHNL2_CAP_SEG_IPV6_TCP))
		dflt_features |= NETIF_F_TSO6;
	if (idpf_is_cap_ena_all(adapter, IDPF_SEG_CAPS,
				VIRTCHNL2_CAP_SEG_IPV4_UDP |
				VIRTCHNL2_CAP_SEG_IPV6_UDP))
		dflt_features |= NETIF_F_GSO_UDP_L4;
	if (idpf_is_cap_ena_all(adapter, IDPF_RSC_CAPS, IDPF_CAP_RSC))
		offloads |= NETIF_F_GRO_HW;
#ifdef HAVE_ENCAP_CSUM_OFFLOAD
	/* advertise to stack only if offloads for encapsulated packets is
	 * supported
	 */
	if (idpf_is_cap_ena_all(vport->adapter, IDPF_SEG_CAPS,
				IDPF_CAP_TUNNEL)) {
		offloads |= NETIF_F_GSO_UDP_TUNNEL	|
#ifdef HAVE_GRE_ENCAP_OFFLOAD
			    NETIF_F_GSO_GRE		|
#ifdef NETIF_F_GSO_PARTIAL
			    NETIF_F_GSO_GRE_CSUM	|
			    NETIF_F_GSO_PARTIAL		|
#endif
			    NETIF_F_GSO_UDP_TUNNEL_CSUM	|
#ifdef NETIF_F_GSO_IPXIP4
			    NETIF_F_GSO_IPXIP4		|
#ifdef NETIF_F_GSO_IPXIP6
			    NETIF_F_GSO_IPXIP6		|
#endif
#else /* NETIF_F_GSO_IPXIP4 */
#ifdef NETIF_F_GSO_IPIP
			    NETIF_F_GSO_IPIP		|
#endif
#ifdef NETIF_F_GSO_SIT
			    NETIF_F_GSO_SIT		|
#endif
#endif /* NETIF_F_GSO_IPXIP4 */
#endif /* NETIF_F_GRE_ENCAP_OFFLOAD */
			    0;

		if (!idpf_is_cap_ena_all(vport->adapter, IDPF_CSUM_CAPS,
					 IDPF_CAP_TUNNEL_TX_CSUM))
#ifndef NETIF_F_GSO_PARTIAL
			offloads ^= NETIF_F_GSO_UDP_TUNNEL_CSUM;
#else
			netdev->gso_partial_features |=
				NETIF_F_GSO_UDP_TUNNEL_CSUM;

		netdev->gso_partial_features |= NETIF_F_GSO_GRE_CSUM;
		offloads |= NETIF_F_TSO_MANGLEID;
#endif /* !NETIF_F_GSO_PARTIAL */
	}
#endif /* HAVE_ENCAP_CSUM_OFFLOAD */
	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_LOOPBACK))
		offloads |= NETIF_F_LOOPBACK;
	netdev->features |= dflt_features;
	netdev->hw_features |= dflt_features | offloads;
	netdev->hw_enc_features |= dflt_features | offloads;
	idpf_set_ethtool_ops(netdev);
	SET_NETDEV_DEV(netdev, &adapter->pdev->dev);

	/* carrier off on init to avoid Tx hangs */
	netif_carrier_off(netdev);

	/* make sure transmit queues start off as stopped */
	netif_tx_stop_all_queues(netdev);

	/* The vport can be arbitrarily released so we need to also track
	 * netdevs in the adapter struct
	 */
	adapter->netdevs[idx] = netdev;

	return 0;
err:
	free_netdev(vport->netdev);
	vport->netdev = NULL;

	return err;
}

/**
 * idpf_cfg_hw - Initialize HW struct
 * @adapter: adapter to setup hw struct for
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_cfg_hw(struct idpf_adapter *adapter)
{
	u64 region2_start = adapter->dev_ops.bar0_region2_start;
	struct pci_dev *pdev = adapter->pdev;
	struct idpf_hw *hw = &adapter->hw;
	resource_size_t res_start;
	long len;

	res_start = pci_resource_start(pdev, 0);
	len = adapter->dev_ops.bar0_region1_size;
	hw->hw_addr = ioremap(res_start, len);
	if (!hw->hw_addr) {
		dev_info(&pdev->dev, "ioremap(0x%04llx) region1 failed:\n",
			 res_start);
		return -EIO;
	}
	hw->hw_addr_len = len;

	len = pci_resource_len(pdev, 0) - region2_start;
	if (len <= 0)
		goto store_adapter;

	hw->hw_addr_region2 = ioremap(res_start + region2_start, len);
	if (!hw->hw_addr_region2) {
		dev_info(&pdev->dev, "ioremap(0x%04llx) region2 failed:\n",
			 res_start + region2_start);
		return -EIO;
	}
	hw->hw_addr_region2_len = len;

store_adapter:
	hw->back = adapter;

	return 0;
}

/**
 * idpf_get_free_slot - get the next non-NULL location index in array
 * @adapter: adapter in which to look for a free vport slot
 */
static int idpf_get_free_slot(struct idpf_adapter *adapter)
{
	unsigned int i;

	for (i = 0; i < adapter->max_vports; ++i)
		if (!adapter->vports[i])
			break;
	return (i == adapter->max_vports) ? IDPF_NO_FREE_SLOT : i;
}

/**
 * idpf_remove_features - Turn off feature configs
 * @vport: virtual port structure
 */
static void idpf_remove_features(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;

	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_MACFILTER))
		idpf_remove_mac_filters(vport);

}

/**
 * idpf_vport_stop - Disable a vport
 * @vport: vport to disable
 */
static void idpf_vport_stop(struct idpf_vport *vport)
{
	mutex_lock(&vport->stop_mutex);
	if (vport->state <= __IDPF_VPORT_DOWN)
		goto stop_unlock;

	netif_tx_stop_all_queues(vport->netdev);
	netif_carrier_off(vport->netdev);
	netif_tx_disable(vport->netdev);

	idpf_send_disable_vport_msg(vport);
	idpf_send_disable_queues_msg(vport);
	idpf_send_map_unmap_queue_vector_msg(vport, false);
	/* Normally we ask for queues in create_vport, but if we're changing
	 * number of requested queues we do a delete then add instead of
	 * deleting and reallocating the vport.
	 */
	if (test_and_clear_bit(__IDPF_VPORT_DEL_QUEUES, vport->flags))
		idpf_send_delete_queues_msg(vport);

	idpf_remove_features(vport);

	vport->link_up = false;
	idpf_vport_intr_deinit(vport);
	idpf_vport_intr_rel(vport);
	idpf_vport_queues_rel(vport);
	vport->state = __IDPF_VPORT_DOWN;

stop_unlock:
	mutex_unlock(&vport->stop_mutex);
}

/**
 * idpf_stop - Disables a network interface
 * @netdev: network interface device structure
 *
 * The stop entry point is called when an interface is de-activated by the OS,
 * and the netdevice enters the DOWN state.  The hardware is still under the
 * driver's control, but the netdev interface is disabled.
 *
 * Returns success only - not allowed to fail
 */
static int idpf_stop(struct net_device *netdev)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);

	if (!vport)
		return 0;

	idpf_vport_stop(vport);

	return 0;
}

/**
 * idpf_decfg_netdev - Unregister the netdev
 * @vport: vport for which netdev to be unregistred
 */
static void idpf_decfg_netdev(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;

	if (!vport->netdev)
		return;

	unregister_netdev(vport->netdev);
	free_netdev(vport->netdev);
	vport->netdev = NULL;

	adapter->netdevs[vport->idx] = NULL;
}

/**
 * idpf_vport_rel - Delete a vport and free its resources
 * @vport: the vport being removed
 */
static void idpf_vport_rel(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	struct idpf_vector_info vec_info;
	struct idpf_rss_data *rss_data;
	struct idpf_vport_max_q max_q;
	u16 idx = vport->idx;
	int i;

	vport_config = adapter->vport_config[vport->idx];
	if (!idx)
		idpf_idc_deinit(adapter);

	idpf_deinit_rss(vport);
	rss_data = &vport_config->user_config.rss_data;
	kfree(rss_data->rss_key);
	rss_data->rss_key = NULL;

	idpf_send_destroy_vport_msg(vport);

	/* Set all bits as we dont know on which vc_state the vport vhnl_wq
	 * is waiting on and wakeup the virtchnl workqueue even if it is
	 * waiting for the response as we are going down
	 */
	for (i = 0; i < IDPF_VC_NBITS; i++)
		set_bit(i, vport->vc_state);
	wake_up(&vport->vchnl_wq);
	mutex_destroy(&vport->stop_mutex);
	mutex_destroy(&vport->soft_reset_lock);
	/* Clear all the bits */
	for (i = 0; i < IDPF_VC_NBITS; i++)
		clear_bit(i, vport->vc_state);

#ifdef HAVE_NETDEV_BPF_XSK_POOL
	if (vport->af_xdp_zc_qps) {
		bitmap_free(vport->af_xdp_zc_qps);
		vport->af_xdp_zc_qps = NULL;
	}

#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	/* Release all max queues allocated to the adapter's pool */
	max_q.max_rxq = vport_config->max_q.max_rxq;
	max_q.max_txq = vport_config->max_q.max_txq;
	max_q.max_bufq = vport_config->max_q.max_bufq;
	max_q.max_complq = vport_config->max_q.max_complq;
	idpf_vport_dealloc_max_qs(adapter, &max_q);

	/* Release all the allocated vectors on the stack */
	vec_info.num_req_vecs = 0;
	vec_info.num_curr_vecs = vport->num_q_vectors;
	vec_info.default_vport = vport->default_vport;

	idpf_req_rel_vector_indexes(adapter, vport->q_vector_idxs, &vec_info);

	kfree(vport->q_vector_idxs);
	vport->q_vector_idxs = NULL;

	kfree(adapter->vport_params_recvd[idx]);
	adapter->vport_params_recvd[idx] = NULL;
	kfree(adapter->vport_params_reqd[idx]);
	adapter->vport_params_reqd[idx] = NULL;
	if (adapter->vport_config[idx]) {
		kfree(adapter->vport_config[idx]->req_qs_chunks);
		adapter->vport_config[idx]->req_qs_chunks = NULL;
	}
	kfree(vport);
	adapter->num_alloc_vports--;
}

/**
 * idpf_del_user_cfg_data - delete all user configuration data
 * @vport: virtual port private structue
 */
static void idpf_del_user_cfg_data(struct idpf_vport *vport)
{
	idpf_del_all_mac_filters(vport);
}

/**
 * idpf_vport_dealloc - cleanup and release a given vport
 * @vport: pointer to idpf vport structure
 *
 * returns nothing
 */
void idpf_vport_dealloc(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_netdev_priv *np;
	unsigned int i;

	i = vport->idx;
	idpf_deinit_mac_addr(vport);
	idpf_vport_stop(vport);
	if (!test_bit(__IDPF_HR_RESET_IN_PROG, adapter->flags))
		idpf_decfg_netdev(vport);
	if (test_bit(__IDPF_REMOVE_IN_PROG, adapter->flags))
		idpf_del_user_cfg_data(vport);
	if (adapter->netdevs[i]) {
		np = netdev_priv(adapter->netdevs[i]);
		if (np)
			np->vport = NULL;
	}
	idpf_vport_rel(vport);
	adapter->vports[i] = NULL;
	adapter->next_vport = idpf_get_free_slot(adapter);
}

/**
 * idpf_vport_set_hsplit - enable or disable header split on a given vport
 * @vport: virtual port
 * @ena: flag controlling header split, On (true) or Off (false)
 */
void idpf_vport_set_hsplit(struct idpf_vport *vport, bool ena)
{
	struct idpf_vport_user_config_data *config_data;

	config_data = &vport->adapter->vport_config[vport->idx]->user_config;
	if (!ena) {
		clear_bit(__IDPF_PRIV_FLAGS_HDR_SPLIT, config_data->user_flags);
		return;
	}

	if (idpf_is_cap_ena_all(vport->adapter, IDPF_HSPLIT_CAPS,
				IDPF_CAP_HSPLIT) &&
	    idpf_is_queue_model_split(vport->rxq_model))
		set_bit(__IDPF_PRIV_FLAGS_HDR_SPLIT, config_data->user_flags);
}

/**
 * idpf_vport_alloc - Allocates the next available struct vport in the adapter
 * @adapter: board private structure
 * @max_q: vport max queue info
 *
 * returns a pointer to a vport on success, NULL on failure.
 */
static struct idpf_vport *idpf_vport_alloc(struct idpf_adapter *adapter,
					   struct idpf_vport_max_q *max_q)
{
	struct idpf_vport *vport = NULL;
	struct idpf_rss_data *rss_data;
	u16 size, num_max_q;

	if (adapter->next_vport == IDPF_NO_FREE_SLOT)
		return vport;

	vport = kzalloc(sizeof(*vport), GFP_KERNEL);
	if (!vport)
		return vport;

	if (!adapter->vport_config[adapter->next_vport]) {
		size = sizeof(struct idpf_vport_config);
		adapter->vport_config[adapter->next_vport] =
			kzalloc(size, GFP_KERNEL);
		if (!adapter->vport_config[adapter->next_vport])
			goto free_vport;
	}

	vport->adapter = adapter;
	vport->idx = adapter->next_vport;
	vport->compln_clean_budget = IDPF_TX_COMPLQ_CLEAN_BUDGET;
	vport->default_vport = adapter->num_alloc_vports <
			       idpf_get_default_vports(adapter);

	num_max_q = max_t(u16, max_q->max_txq, max_q->max_rxq);
	vport->q_vector_idxs = kcalloc(num_max_q, sizeof(u16), GFP_KERNEL);
	if (!vport->q_vector_idxs)
		goto free_vport;

	idpf_vport_init(vport, max_q);
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	vport->xsk_changing = false;
	vport->af_xdp_zc_qps = bitmap_zalloc(max_t(int, vport->num_txq, vport->num_rxq),
					     GFP_KERNEL);
	if (!vport->af_xdp_zc_qps)
		goto free_qvec_idxs;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

	/* This alloc is done separate from the LUT because it's not strictly
	 * dependent on how many queues we have. If we change number of queues
	 * and soft reset we'll need a new LUT but the key can remain the same
	 * for as long as the vport exists.
	 */
	rss_data = &adapter->vport_config[vport->idx]->user_config.rss_data;
	rss_data->rss_key = kzalloc(rss_data->rss_key_size, GFP_KERNEL);
	if (!rss_data->rss_key)
#ifdef HAVE_NETDEV_BPF_XSK_POOL
		goto free_af_xdp_zc_qps;
#else
		goto free_qvec_idxs;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	/* Initialize default rss key */
	netdev_rss_key_fill((void *)rss_data->rss_key, rss_data->rss_key_size);

	mutex_init(&vport->stop_mutex);

	/* fill vport slot in the adapter struct */
	adapter->vports[adapter->next_vport] = vport;
	adapter->vport_ids[adapter->next_vport] = idpf_get_vport_id(vport);

	adapter->num_alloc_vports++;
	/* prepare adapter->next_vport for next use */
	adapter->next_vport = idpf_get_free_slot(adapter);

	return vport;

#ifdef HAVE_NETDEV_BPF_XSK_POOL
free_af_xdp_zc_qps:
	kfree(vport->af_xdp_zc_qps);
	vport->af_xdp_zc_qps = NULL;
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
free_qvec_idxs:
	kfree(vport->q_vector_idxs);
	vport->q_vector_idxs = NULL;
free_vport:
	kfree(vport);
	return NULL;
}

/**
 * idpf_statistics_task - Delayed task to get statistics over mailbox
 * @work: work_struct handle to our data
 */
static void idpf_statistics_task(struct work_struct *work)
{
	struct idpf_adapter *adapter = container_of(work,
						    struct idpf_adapter,
						    stats_task.work);
	int i;

	for (i = 0; i < adapter->max_vports; i++) {
		struct idpf_vport *vport = adapter->vports[i];

		if (vport && !test_bit(__IDPF_HR_RESET_IN_PROG, adapter->flags))
			idpf_send_get_stats_msg(vport);
	}

	if (!test_bit(__IDPF_CANCEL_STATS_TASK, adapter->flags))
		queue_delayed_work(adapter->stats_wq, &adapter->stats_task,
				   msecs_to_jiffies(10000));
}

/**
 * idpf_service_task - Delayed task for handling mailbox responses
 * @work: work_struct handle to our data
 *
 */
static void idpf_service_task(struct work_struct *work)
{
	struct idpf_adapter *adapter = container_of(work,
						    struct idpf_adapter,
						    serv_task.work);

	if (test_bit(__IDPF_MB_INTR_MODE, adapter->flags)) {
		if (test_and_clear_bit(__IDPF_MB_INTR_TRIGGER,
				       adapter->flags)) {
			idpf_recv_mb_msg(adapter, VIRTCHNL2_OP_UNKNOWN, NULL, 0);
			idpf_mb_irq_enable(adapter);
		}
	} else {
		idpf_recv_mb_msg(adapter, VIRTCHNL2_OP_UNKNOWN, NULL, 0);
	}

	if (idpf_is_reset_detected(adapter) &&
	    !idpf_is_reset_in_prog(adapter) &&
	    !test_bit(__IDPF_REMOVE_IN_PROG, adapter->flags)) {
		dev_info(&adapter->pdev->dev, "HW reset detected\n");
		set_bit(__IDPF_HR_FUNC_RESET, adapter->flags);
		queue_delayed_work(adapter->vc_event_wq,
				   &adapter->vc_event_task,
				   msecs_to_jiffies(10));
	}

	if (!test_bit(__IDPF_CANCEL_SERVICE_TASK, adapter->flags))
		queue_delayed_work(adapter->serv_wq, &adapter->serv_task,
				   msecs_to_jiffies(300));
}

/**
 * idpf_restore_features - Restore feature configs
 * @vport: virtual port structure
 */
static void idpf_restore_features(struct idpf_vport *vport)
{
	struct idpf_adapter *adapter = vport->adapter;

	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_MACFILTER))
		idpf_restore_mac_filters(vport);

}

/**
 * idpf_set_real_num_queues - set number of queues for netdev
 * @vport: virtual port structure
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_set_real_num_queues(struct idpf_vport *vport)
{
	int err;

	/* If we're in normal up path, the stack already takes the rtnl_lock
	 * for us, however, if we're doing up as a part of a hard reset, we'll
	 * need to take the lock ourself before touching the netdev.
	 */
	if (test_bit(__IDPF_HR_RESET_IN_PROG, vport->adapter->flags))
		rtnl_lock();
	err = netif_set_real_num_rx_queues(vport->netdev, vport->num_rxq);
	if (err)
		goto error;
	if (idpf_xdp_is_prog_ena(vport))
		err = netif_set_real_num_tx_queues(vport->netdev,
						   vport->num_txq - vport->num_xdp_txq);
	else
		err = netif_set_real_num_tx_queues(vport->netdev, vport->num_txq);
error:
	if (test_bit(__IDPF_HR_RESET_IN_PROG, vport->adapter->flags))
		rtnl_unlock();
	return err;
}

/**
 * idpf_up_complete - Complete interface up sequence
 * @vport: virtual port strucutre
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_up_complete(struct idpf_vport *vport)
{
	int err;

	err = idpf_set_real_num_queues(vport);
	if (err)
		return err;

	if (vport->link_up && !netif_carrier_ok(vport->netdev)) {
		netif_carrier_on(vport->netdev);
		netif_tx_start_all_queues(vport->netdev);
	}

	vport->state = __IDPF_VPORT_UP;
	return 0;
}

/**
 * idpf_rx_init_buf_tail - Write initial buffer ring tail value
 * @vport: virtual port struct
 */
static void idpf_rx_init_buf_tail(struct idpf_vport *vport)
{
	int i, j;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *grp = &vport->rxq_grps[i];

		if (idpf_is_queue_model_split(vport->rxq_model)) {
			for (j = 0; j < vport->num_bufqs_per_qgrp; j++) {
				struct idpf_queue *q =
					&grp->splitq.bufq_sets[j].bufq;

				writel(q->next_to_alloc, q->tail);
			}
		} else {
			for (j = 0; j < grp->singleq.num_rxq; j++) {
				struct idpf_queue *q =
					grp->singleq.rxqs[j];

				writel(q->next_to_alloc, q->tail);
			}
		}
	}
}

/**
 * idpf_vport_xdp_init - Prepare and configure XDP structures
 * @vport: vport where XDP should be initialized
 *
 * returns 0 on success or error code in case of any failure
 */
static int idpf_vport_xdp_init(struct idpf_vport *vport)
{
	struct idpf_vport_user_config_data *config_data;
	struct idpf_adapter *adapter;
	u16 idx = vport->idx;
	int i, err = 0;

	adapter = vport->adapter;
	config_data = &adapter->vport_config[idx]->user_config;

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		struct idpf_queue *q;
		int j, num_rxq;

		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++) {
#ifdef HAVE_NETDEV_BPF_XSK_POOL
			struct idpf_queue *rxbufq;
			int alloc_desc_count, k;

#endif /* HAVE_NETDEV_BPF_XSK_POOL */
			if (idpf_is_queue_model_split(vport->rxq_model))
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				q = rx_qgrp->singleq.rxqs[j];

			WRITE_ONCE(q->xdp_prog, config_data->xdp_prog);
			err = idpf_xdp_rxq_init(q);
			if (err)
				goto exit_xdp_init;

#ifdef HAVE_NETDEV_BPF_XSK_POOL
			if (!q->xsk_pool)
				continue;

			if (idpf_is_queue_model_split(vport->rxq_model)) {
				for (k = 0; k < vport->num_bufqs_per_qgrp; k++) {
					rxbufq = &rx_qgrp->splitq.bufq_sets[k].bufq;
					rxbufq->xsk_pool = q->xsk_pool;
					alloc_desc_count = rxbufq->desc_count - 1;
					err = idpf_rx_splitq_buf_hw_alloc_zc_all(rxbufq,
										 alloc_desc_count);
					if (err) {
						dev_info(rxbufq->dev,
							 "Failed to allocate some buffers on UMEM enabled qp id %d, rxbufq %d\n",
							 q->idx, k);
					}
				}
			} else {
				err = idpf_rx_singleq_buf_hw_alloc_zc_all(q,
									  q->desc_count - 1);
				if (err)
					dev_info(q->dev,
						 "Failed to allocate some buffers on UMEM enabled qp id %d\n",
						 q->idx);
			}
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
		}
	}

exit_xdp_init:
	return err;
}

/**
 * idpf_vport_open - Bring up a vport
 * @vport: vport to bring up
 * @alloc_res: allocate queue resources
 */
static int idpf_vport_open(struct idpf_vport *vport, bool alloc_res)
{
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_vport_config *vport_config;
	int err;

	vport_config = adapter->vport_config[vport->idx];
	if (vport->state != __IDPF_VPORT_DOWN)
		return -EBUSY;

	/* we do not allow interface up just yet */
	netif_carrier_off(vport->netdev);

	if (alloc_res) {
		err = idpf_vport_queues_alloc(vport);
		if (err)
			return err;
	}

	idpf_vport_xdp_init(vport);

	err = idpf_vport_intr_alloc(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Call to interrupt alloc returned %d\n",
			err);
		goto unroll_queues_alloc;
	}

	err = idpf_vport_queue_ids_init(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Call to queue ids init returned %d\n",
			err);
		goto unroll_intr_alloc;
	}

	err = idpf_queue_reg_init(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Call to queue reg init returned %d\n",
			err);
		goto unroll_intr_alloc;
	}
	idpf_rx_init_buf_tail(vport);

	err = idpf_vport_intr_init(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Call to vport interrupt init returned %d\n",
			err);
		goto unroll_intr_alloc;
	}
	err = idpf_send_config_queues_msg(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to config queues\n");
		goto unroll_config_queues;
	}
	err = idpf_send_map_unmap_queue_vector_msg(vport, true);
	if (err) {
		dev_err(&adapter->pdev->dev, "Call to irq_map_unmap returned %d\n",
			err);
		goto unroll_config_queues;
	}
	err = idpf_send_enable_queues_msg(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to enable queues\n");
		goto unroll_enable_queues;
	}

	err = idpf_send_enable_vport_msg(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to enable vport\n");
		err = -EAGAIN;
		goto unroll_vport_enable;
	}

	idpf_restore_features(vport);

	if (vport_config->user_config.rss_data.rss_lut)
		err = idpf_config_rss(vport);
	else
		err = idpf_init_rss(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to init RSS\n");
		goto unroll_init_rss;
	}
	err = idpf_up_complete(vport);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to complete up\n");
		goto unroll_up_comp;
	}

	return 0;

unroll_up_comp:
	idpf_deinit_rss(vport);
unroll_init_rss:
	idpf_send_disable_vport_msg(vport);
unroll_vport_enable:
	idpf_send_disable_queues_msg(vport);
unroll_enable_queues:
	idpf_send_map_unmap_queue_vector_msg(vport, false);
unroll_config_queues:
	idpf_vport_intr_deinit(vport);
unroll_intr_alloc:
	idpf_vport_intr_rel(vport);
unroll_queues_alloc:
	if (alloc_res)
		idpf_vport_queues_rel(vport);

	return err;
}

/**
 * idpf_init_task - Delayed initialization task
 * @work: work_struct handle to our data
 *
 * Init task finishes up pending work started in probe. Due to the asynchronous
 * nature in which the device communicates with hardware, we may have to wait
 * several milliseconds to get a response.  Instead of busy polling in probe,
 * pulling it out into a delayed work task prevents us from bogging down the
 * whole system waiting for a response from hardware.
 */
void idpf_init_task(struct work_struct *work)
{
	struct idpf_adapter *adapter = container_of(work,
						    struct idpf_adapter,
						    init_task.work);
	struct idpf_vport_config *vport_config;
	struct idpf_vport_max_q max_q;
	u16 num_default_vports = 0;
	struct idpf_vport *vport;
	struct pci_dev *pdev;
	bool dynamic_vport;
	int index, err;

	/* Need to protect the allocation of the vports at the adapter level */
	mutex_lock(&adapter->sw_mutex);
	num_default_vports = idpf_get_default_vports(adapter);
	if (adapter->num_alloc_vports < num_default_vports)
		dynamic_vport = false;
	else
		dynamic_vport = true;
	err = idpf_vport_alloc_max_qs(adapter, &max_q);
	if (err) {
		mutex_unlock(&adapter->sw_mutex);
		goto unwind_vports;
	}

	err = idpf_send_create_vport_msg(adapter, &max_q);
	if (err) {
		idpf_vport_dealloc_max_qs(adapter, &max_q);
		mutex_unlock(&adapter->sw_mutex);
		goto unwind_vports;
	}

	pdev = adapter->pdev;
	vport = idpf_vport_alloc(adapter, &max_q);
	if (!vport) {
		err = -EFAULT;
		dev_err(&pdev->dev, "failed to allocate vport: %d\n",
			err);
		idpf_vport_dealloc_max_qs(adapter, &max_q);
		mutex_unlock(&adapter->sw_mutex);
		goto unwind_vports;
	}
	mutex_unlock(&adapter->sw_mutex);

	index = vport->idx;

	vport_config = adapter->vport_config[index];
	init_waitqueue_head(&vport->sw_marker_wq);
	init_waitqueue_head(&vport->vchnl_wq);
	mutex_init(&vport->soft_reset_lock);

	spin_lock_init(&vport->mac_filter_list_lock);
	INIT_LIST_HEAD(&vport_config->user_config.mac_filter_list);

	err = idpf_check_supported_desc_ids(vport);
	if (err) {
		dev_err(&pdev->dev, "failed to get required descriptor ids\n");
		goto cfg_netdev_err;
	}

	if (idpf_cfg_netdev(vport))
		goto cfg_netdev_err;

	err = idpf_send_get_rx_ptype_msg(vport);
	if (err)
		goto handle_err;

	if (!vport->idx) {
		err = idpf_idc_init(adapter);
		if (err)
			goto handle_err;
	}

	/* Once state is put into DOWN, driver is ready for dev_open */
	vport->state = __IDPF_VPORT_DOWN;
	if (test_and_clear_bit(__IDPF_VPORT_UP_REQUESTED, vport_config->flags))
		idpf_vport_open(vport, true);

	mutex_lock(&adapter->sw_mutex);

	/* Spawn and return 'idpf_init_task' work queue until all the
	 * default vports are created
	 */
	if (adapter->num_alloc_vports < num_default_vports) {
		queue_delayed_work(adapter->init_wq, &adapter->init_task,
				   msecs_to_jiffies(5 * (adapter->pdev->devfn & 0x07)));
		mutex_unlock(&adapter->sw_mutex);

		return;
	}
	mutex_unlock(&adapter->sw_mutex);

	for (index = 0; index < adapter->max_vports; index++) {
		if (adapter->netdevs[index] &&
		    !test_bit(__IDPF_VPORT_REG_NETDEV,
			      adapter->vport_config[index]->flags)) {
			register_netdev(adapter->netdevs[index]);
			set_bit(__IDPF_VPORT_REG_NETDEV,
				adapter->vport_config[index]->flags);
		}
	}

	/* As all the required vports are created, clear the reset flag
	 * unconditionally here in case we were in reset and the link was down.
	 */
	clear_bit(__IDPF_HR_RESET_IN_PROG, vport->adapter->flags);
	 /* Start the statistics task now */
	queue_delayed_work(adapter->stats_wq, &adapter->stats_task,
			   msecs_to_jiffies(10 * (pdev->devfn & 0x07)));

	return;

handle_err:
	idpf_decfg_netdev(vport);
cfg_netdev_err:
	idpf_vport_rel(vport);
	adapter->vports[index] = NULL;
unwind_vports:
	/*
	 * We need not release everything on failure to create dynamic vport
	 */
	if (!dynamic_vport) {
		for (index = 0; index < adapter->max_vports; index++) {
			if (adapter->vports[index])
				idpf_vport_dealloc(adapter->vports[index]);
		}
	}
}

/**
 * idpf_sriov_ena - Enable or change number of VFs
 * @adapter: private data struct
 * @num_vfs: number of VFs to allocate
 */
static int idpf_sriov_ena(struct idpf_adapter *adapter, int num_vfs)
{
	struct device *dev = &adapter->pdev->dev;
	int err;

	err = idpf_send_set_sriov_vfs_msg(adapter, num_vfs);
	if (err) {
		dev_err(dev, "Failed to allocate VFs: %d\n", err);
		return err;
	}

	err = pci_enable_sriov(adapter->pdev, num_vfs);
	if (err) {
		num_vfs = 0;
		idpf_send_set_sriov_vfs_msg(adapter, num_vfs);
		dev_err(dev, "Failed to enable SR-IOV: %d\n", err);
		return err;
	}

	adapter->num_vfs = num_vfs;
	return num_vfs;
}

/**
 * idpf_sriov_configure
 * @pdev: pointer to a pci_dev structure
 * @num_vfs: number of vfs to allocate
 *
 * Enable or change the number of VFs. Called when the user updates the number
 * of VFs in sysfs.
 **/
int idpf_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_SRIOV)) {
		dev_info(&pdev->dev, "SR-IOV is not supported on this device\n");
		return -EOPNOTSUPP;
	}

	if (num_vfs)
		return idpf_sriov_ena(adapter, num_vfs);

	if (!pci_vfs_assigned(pdev)) {
		pci_disable_sriov(adapter->pdev);
		idpf_send_set_sriov_vfs_msg(adapter, 0);
		adapter->num_vfs = 0;
	} else {
		dev_warn(&pdev->dev, "Unable to free VFs because some are assigned to VMs\n");
		return -EINVAL;
	}

	return 0;
}

/**
 * idpf_deinit_task - Device deinit routine
 * @adapter: Driver specific private structue
 *
 * Extended remove logic which will be used for
 * hard reset as well
 */
void idpf_deinit_task(struct idpf_adapter *adapter)
{
	unsigned int i;

	/* Wait until the init_task is done else this thread might release
	 * the resources first and the other thread might end up in a bad state
	 */
	cancel_delayed_work_sync(&adapter->init_task);
	/* Required to indicate periodic task not to schedule again */
	set_bit(__IDPF_CANCEL_STATS_TASK, adapter->flags);
	cancel_delayed_work_sync(&adapter->stats_task);
	clear_bit(__IDPF_CANCEL_STATS_TASK, adapter->flags);
	for (i = 0; i < adapter->max_vports; i++) {
		if (adapter->vports[i])
			idpf_vport_dealloc(adapter->vports[i]);
	}
}

/**
 * idpf_check_reset_complete - check that reset is complete
 * @hw: pointer to hw struct
 * @reset_reg: struct with reset registers
 *
 * Returns 0 if device is ready to use, or -EBUSY if it's in reset.
 **/
static int idpf_check_reset_complete(struct idpf_hw *hw,
				     struct idpf_reset_reg *reset_reg)
{
	struct idpf_adapter *adapter = (struct idpf_adapter *)hw->back;
	int i;

	for (i = 0; i < 2000; i++) {
		u32 reg_val = readl(reset_reg->rstat);

		/* 0xFFFFFFFF might be read if other side hasn't cleared the
		 * register for us yet and 0xFFFFFFFF is not a valid value for
		 * the register, so treat that as invalid.
		 */
		if (reg_val != 0xFFFFFFFF && (reg_val & reset_reg->rstat_m))
			return 0;
		usleep_range(5000, 10000);
	}

	dev_warn(&adapter->pdev->dev, "Device reset timeout!\n");
	/* Clear the reset flag unconditionally here since the reset
	 * technically isn't in progress anymore from the driver's perspective
	 */
	clear_bit(__IDPF_HR_RESET_IN_PROG, adapter->flags);

	return -EBUSY;
}

/**
 * idpf_set_vport_state - Set the vport state to be after the reset
 * @adapter: Driver specific private structure
 */
static void idpf_set_vport_state(struct idpf_adapter *adapter)
{
	u16 i;

	for (i = 0; i < adapter->max_vports; i++) {
		if (adapter->vports[i] &&
		    adapter->vports[i]->state == __IDPF_VPORT_UP)
			set_bit(__IDPF_VPORT_UP_REQUESTED,
				adapter->vport_config[i]->flags);
	}
}

/**
 * idpf_init_hard_reset - Initiate a hardware reset
 * @adapter: Driver specific private structure
 *
 * Deallocate the vports and all the resources associated with them and
 * reallocate. Also reinitialize the mailbox. Return 0 on success,
 * negative on failure.
 */
static int idpf_init_hard_reset(struct idpf_adapter *adapter)
{
	int err = 0;

	mutex_lock(&adapter->reset_lock);

	dev_info(&adapter->pdev->dev, "Device HW Reset initiated\n");
	/* Prepare for reset */
	if (test_and_clear_bit(__IDPF_HR_DRV_LOAD, adapter->flags)) {
		adapter->dev_ops.reg_ops.trigger_reset(adapter,
						       __IDPF_HR_DRV_LOAD);
	} else if (test_and_clear_bit(__IDPF_HR_FUNC_RESET, adapter->flags)) {
		bool is_reset = idpf_is_reset_detected(adapter);

		idpf_set_vport_state(adapter);
		idpf_vc_core_deinit(adapter);
		if (!is_reset)
			adapter->dev_ops.reg_ops.trigger_reset(adapter,
							       __IDPF_HR_FUNC_RESET);
		idpf_deinit_dflt_mbx(adapter);
	} else if (test_and_clear_bit(__IDPF_HR_CORE_RESET, adapter->flags)) {
		idpf_set_vport_state(adapter);
		idpf_vc_core_deinit(adapter);
	} else {
		dev_err(&adapter->pdev->dev, "Unhandled hard reset cause\n");
		err = -EBADRQC;
		goto handle_err;
	}

	/* Wait for reset to complete */
	err = idpf_check_reset_complete(&adapter->hw, &adapter->reset_reg);
	if (err) {
		dev_err(&adapter->pdev->dev, "The driver was unable to contact the device's firmware.  Check that the FW is running. Driver state=%u\n",
			adapter->state);
		goto handle_err;
	}

	/* Reset is complete and so start building the driver resources again */
	err = idpf_init_dflt_mbx(adapter);
	if (err) {
		dev_err(&adapter->pdev->dev, "Failed to initialize default mailbox: %d\n",
			err);
	}

	/* Initialize the state machine, also allocate memory and request
	 * resources
	 */
	err = idpf_vc_core_init(adapter);
	if (err)
		goto init_err;

	mutex_unlock(&adapter->reset_lock);
	return 0;

init_err:
	idpf_deinit_dflt_mbx(adapter);
handle_err:
	mutex_unlock(&adapter->reset_lock);
	return err;
}

/**
 * idpf_vc_event_task - Handle virtchannel event logic
 * @work: work queue struct
 */
static void idpf_vc_event_task(struct work_struct *work)
{
	struct idpf_adapter *adapter = container_of(work,
						    struct idpf_adapter,
						    vc_event_task.work);

	if (test_bit(__IDPF_REMOVE_IN_PROG, adapter->flags))
		return;

	if (test_bit(__IDPF_HR_CORE_RESET, adapter->flags) ||
	    test_bit(__IDPF_HR_FUNC_RESET, adapter->flags) ||
	    test_bit(__IDPF_HR_DRV_LOAD, adapter->flags)) {
		set_bit(__IDPF_HR_RESET_IN_PROG, adapter->flags);
		idpf_init_hard_reset(adapter);
	}
}

#ifdef HAVE_NETDEV_BPF_XSK_POOL
/**
 * idpf_vport_copy_xdp_data - Deep copy XDP specific data from one vport to another
 * @dst_vport: destination vport to copy XDP data
 * @src_vport: source vport from which XDP data will be copied
 *
 * Returns zero on success or an error code in case of any failure.
 */
static int idpf_vport_copy_xdp_data(struct idpf_vport *dst_vport, struct idpf_vport *src_vport)
{
	int old_size, new_size, copy_size;

	old_size = max_t(int, src_vport->num_txq, src_vport->num_rxq);
	new_size = max_t(int, dst_vport->num_txq, dst_vport->num_rxq);
	copy_size = min_t(int, old_size, new_size);

	dst_vport->af_xdp_zc_qps = bitmap_zalloc(new_size, GFP_KERNEL);
	if (!dst_vport->af_xdp_zc_qps)
		return -ENOMEM;

	bitmap_copy(dst_vport->af_xdp_zc_qps, src_vport->af_xdp_zc_qps, copy_size);

	return 0;
}

#endif /* HAVE_NETDEV_BPF_XSK_POOL */
/**
 * idpf_initiate_soft_reset - Initiate a software reset
 * @vport: virtual port data struct
 * @reset_cause: reason for the soft reset
 *
 * Soft reset only reallocs vport queue resources. Returns 0 on success,
 * negative on failure.
 */
int idpf_initiate_soft_reset(struct idpf_vport *vport,
			     enum idpf_vport_flags reset_cause)
{
	struct idpf_adapter *adapter = vport->adapter;
	enum idpf_vport_state current_state;
	struct idpf_vport *new_vport;
	int err = 0, i;

	current_state = vport->state;

	/* make sure we do not end up in initiating multiple resets */
	mutex_lock(&vport->soft_reset_lock);

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
		mutex_unlock(&vport->soft_reset_lock);
		return -ENOMEM;
	}
	/* This purposely avoids copying the end of the struct because it
	 * contains wait_queues and mutexes and other stuff we don't want to
	 * mess with. Nothing below should use those variables from new_vport
	 * and should instead always refer to them in vport if they need to.
	 */
	memcpy(new_vport, vport, offsetof(struct idpf_vport, state));

#ifdef HAVE_NETDEV_BPF_XSK_POOL
	/* Perform a deep copy of some XDP data */
	idpf_vport_copy_xdp_data(new_vport, vport);

#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	/* Adjust resource parameters prior to reallocating resources */
	switch (reset_cause) {
	case __IDPF_SR_Q_CHANGE:
		err =  idpf_vport_adjust_qs(new_vport);
		if (err)
			goto free_vport;
		break;
	case __IDPF_SR_Q_DESC_CHANGE:
		/* Update queue parameters before allocating resources */
		idpf_vport_calc_num_q_desc(new_vport);
		break;
	case __IDPF_SR_Q_SCH_CHANGE:
	case __IDPF_SR_MTU_CHANGE:
	case __IDPF_SR_RSC_CHANGE:
	case __IDPF_SR_HSPLIT_CHANGE:
		break;
	default:
		dev_err(&adapter->pdev->dev, "Unhandled soft reset cause\n");
		err = -EINVAL;
		goto free_vport;
	}

	err = idpf_vport_queues_alloc(new_vport);
	if (err)
		goto free_vport;
	if (!new_vport->idx)
		idpf_idc_event(adapter, reset_cause, true);

	if (current_state <= __IDPF_VPORT_DOWN) {
		idpf_send_delete_queues_msg(vport);
	} else {
		set_bit(__IDPF_VPORT_DEL_QUEUES, vport->flags);
		idpf_vport_stop(vport);
	}

	idpf_deinit_rss(vport);
	/* We're passing in vport here because we need it's wait_queue
	 * to send a message and it should be getting all the vport
	 * config data out of the adapter but we need to be careful not
	 * to add code to add_queues to change the vport config within
	 * vport itself as it will be wiped with a memcpy later.
	 */
	err = idpf_send_add_queues_msg(vport, new_vport->num_txq,
				       new_vport->num_complq,
				       new_vport->num_rxq,
				       new_vport->num_bufq);
	if (err)
		goto err_reset;
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	bitmap_free(vport->af_xdp_zc_qps);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

	/* Same comment as above regarding avoiding copying the wait_queues and
	 * mutexes applies here. We do not want to mess with those if possible.
	 */
	memcpy(vport, new_vport, offsetof(struct idpf_vport, state));
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	idpf_vport_copy_xdp_data(vport, new_vport);
	bitmap_free(new_vport->af_xdp_zc_qps);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */

	/* Since idpf_vport_queues_alloc was called with new_port, the queue
	 * back pointers are currently pointing to the local new_vport. Reset
	 * the backpointers to the original vport here
	 */
	for (i = 0; i < vport->num_txq_grp; i++) {
		struct idpf_txq_group *tx_qgrp = &vport->txq_grps[i];
		int j;

		tx_qgrp->vport = vport;
		for (j = 0; j < tx_qgrp->num_txq; j++)
			tx_qgrp->txqs[j]->vport = vport;

		if (idpf_is_queue_model_split(vport->txq_model))
			tx_qgrp->complq->vport = vport;
	}

	for (i = 0; i < vport->num_rxq_grp; i++) {
		struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		struct idpf_queue *q;
		int j, num_rxq;

		rx_qgrp->vport = vport;
		for (j = 0; j < vport->num_bufqs_per_qgrp; j++)
			rx_qgrp->splitq.bufq_sets[j].bufq.vport = vport;

		if (idpf_is_queue_model_split(vport->rxq_model))
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (j = 0; j < num_rxq; j++) {
			if (idpf_is_queue_model_split(vport->rxq_model))
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				q = rx_qgrp->singleq.rxqs[j];
			q->vport = vport;
		}
	}

	kfree(new_vport);

	if (reset_cause == __IDPF_SR_Q_CHANGE)
		idpf_vport_alloc_vec_indexes(vport);

	if (current_state == __IDPF_VPORT_UP)
		err = idpf_vport_open(vport, false);
	if (!vport->idx)
		idpf_idc_event(adapter, reset_cause, false);
	mutex_unlock(&vport->soft_reset_lock);
	return err;
err_reset:
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	bitmap_free(new_vport->af_xdp_zc_qps);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	idpf_vport_queues_rel(new_vport);
free_vport:
	kfree(new_vport);
	mutex_unlock(&vport->soft_reset_lock);
	return err;
}

/**
 * idpf_probe_common - Device initialization routine
 * @pdev: PCI device information struct
 * @adapter: driver specific private structure
 *
 * Returns 0 on success, negative on failure
 */
int idpf_probe_common(struct pci_dev *pdev, struct idpf_adapter *adapter)
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
	err = pci_enable_device(pdev);
	if (err)
		return err;

	err = pci_request_mem_regions(pdev, pci_name(pdev));
	if (err) {
		dev_err(&pdev->dev,
			"pci_request_selected_regions failed %d\n", err);
		pci_disable_device(pdev);
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
	adapter->msg_enable = netif_msg_init(-1, IDPF_AVAIL_NETIF_M);

	err = idpf_cfg_hw(adapter);
	if (err) {
		dev_err(&pdev->dev, "Failed to configure HW structure for adapter: %d\n",
			err);
		goto err_cfg_hw;
	}

	pr_info("file: %s +%d, caller:%ps\n", __FILE__, __LINE__, __builtin_return_address(0));
#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
	if (adapter->dev_ops.vdcm_init) {
		pr_info("file: %s +%d, %ps caller:%ps\n", __FILE__, __LINE__, adapter->dev_ops.vdcm_init, __builtin_return_address(0));
		err = adapter->dev_ops.vdcm_init(adapter->pdev);
		if (err)
			dev_err(&pdev->dev, "Failed to initialize SIOV\n");
	}
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */
	mutex_init(&adapter->sw_mutex);
	mutex_init(&adapter->reset_lock);
	mutex_init(&adapter->vector_lock);
	mutex_init(&adapter->queue_lock);
	init_waitqueue_head(&adapter->vchnl_wq);

	INIT_DELAYED_WORK(&adapter->stats_task, idpf_statistics_task);
	INIT_DELAYED_WORK(&adapter->serv_task, idpf_service_task);
	INIT_DELAYED_WORK(&adapter->init_task, idpf_init_task);
	INIT_DELAYED_WORK(&adapter->vc_event_task, idpf_vc_event_task);

	adapter->dev_ops.reg_ops.reset_reg_init(adapter);
	set_bit(__IDPF_HR_DRV_LOAD, adapter->flags);
	queue_delayed_work(adapter->vc_event_wq, &adapter->vc_event_task,
			   msecs_to_jiffies(10 * (pdev->devfn & 0x07)));

#ifdef DEVLINK_ENABLED
	idpf_devlink_init(adapter, &pdev->dev);
#endif /* DEVLINK_ENABLED */
	return 0;

err_cfg_hw:
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

/**
 * idpf_remove_common - Device removal routine
 * @pdev: PCI device information struct
 */
void idpf_remove_common(struct pci_dev *pdev)
{
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);
	int i = 0;

	if (!adapter)
		return;

	dev_info(&pdev->dev, "Removing device\n");
	set_bit(__IDPF_REMOVE_IN_PROG, adapter->flags);

	/* Wait until vc_event_task is done to consider if any hard reset is
	 * in progress else we may go ahead and release the resources but the
	 * thread doing the hard reset might continue the init path and
	 * end up in bad state.
	 */
	cancel_delayed_work_sync(&adapter->vc_event_task);
	if (adapter->num_vfs)
		idpf_sriov_configure(pdev, 0);
#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
	if (adapter->dev_ops.vdcm_deinit)
		adapter->dev_ops.vdcm_deinit(pdev);
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */
#ifdef DEVLINK_ENABLED
	idpf_devlink_deinit(adapter);
#endif /* DEVLINK_ENABLED */
	idpf_vc_core_deinit(adapter);
	/* Be a good citizen and leave the device clean on exit */
	adapter->dev_ops.reg_ops.trigger_reset(adapter, __IDPF_HR_FUNC_RESET);
	idpf_deinit_dflt_mbx(adapter);

	/* There are some cases where it's possible to still have netdevs
	 * registered with the stack at this point, e.g. if the driver detected
	 * a HW reset and rmmod is called before it fully recovers. Unregister
	 * any stale netdevs here.
	 */
	for (i = 0; i < adapter->max_vports; i++) {
		if (!adapter->netdevs[i])
			continue;
		if (adapter->netdevs[i]->reg_state != NETREG_UNINITIALIZED)
			unregister_netdev(adapter->netdevs[i]);
		free_netdev(adapter->netdevs[i]);
		adapter->netdevs[i] = NULL;
	}

	msleep(20);
	destroy_workqueue(adapter->serv_wq);
	destroy_workqueue(adapter->vc_event_wq);
	destroy_workqueue(adapter->stats_wq);
	destroy_workqueue(adapter->init_wq);
	for (i = 0; i < adapter->max_vports; i++) {
		kfree(adapter->vport_config[i]);
		adapter->vport_config[i] = NULL;
	}
	kfree(adapter->vport_config);
	adapter->vport_config = NULL;
	kfree(adapter->netdevs);
	adapter->netdevs = NULL;
	mutex_destroy(&adapter->sw_mutex);
	mutex_destroy(&adapter->reset_lock);
	mutex_destroy(&adapter->vector_lock);
	mutex_destroy(&adapter->queue_lock);
	pci_disable_pcie_error_reporting(pdev);
	iounmap(adapter->hw.hw_addr);
	if (adapter->hw.hw_addr_region2)
		iounmap(adapter->hw.hw_addr_region2);
	pci_release_mem_regions(pdev);
	pci_disable_device(pdev);
}

/**
 * idpf_addr_sync - Callback for dev_(mc|uc)_sync to add address
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
static int idpf_addr_sync(struct net_device *netdev, const u8 *addr)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);

	if (!vport)
		return -EINVAL;

	return idpf_add_mac_filter(vport, addr, true);
}

/**
 * idpf_addr_unsync - Callback for dev_(mc|uc)_sync to remove address
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
static int idpf_addr_unsync(struct net_device *netdev, const u8 *addr)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);

	if (!vport)
		return -EINVAL;

	/* Under some circumstances, we might receive a request to delete
	 * our own device address from our uc list. Because we store the
	 * device address in the VSI's MAC filter list, we need to ignore
	 * such requests and not delete our device address from this list.
	 */
	if (ether_addr_equal(addr, netdev->dev_addr))
		return 0;

	idpf_del_mac_filter(vport, addr, true);

	return 0;
}

/**
 * idpf_set_rx_mode - NDO callback to set the netdev filters
 * @netdev: network interface device structure
 *
 * Stack takes addr_list_lock spinlock before calling our .set_rx_mode.  We
 * cannot sleep in this context.
 */
static void idpf_set_rx_mode(struct net_device *netdev)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);
	struct idpf_vport_user_config_data *config_data;
	struct idpf_adapter *adapter;
	bool changed = false;
	int err;

	if (!vport)
		return;

	adapter = vport->adapter;

	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_MACFILTER)) {
		__dev_uc_sync(netdev, idpf_addr_sync, idpf_addr_unsync);
		__dev_mc_sync(netdev, idpf_addr_sync, idpf_addr_unsync);
	}

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_PROMISC))
		return;

	config_data = &adapter->vport_config[vport->idx]->user_config;
	/* IFF_PROMISC enables both unicast and multicast promiscuous,
	 * while IFF_ALLMULTI only enables multicast such that:
	 *
	 * promisc  + allmulti		= unicast | multicast
	 * promisc  + !allmulti		= unicast | multicast
	 * !promisc + allmulti		= multicast
	 */
	if ((netdev->flags & IFF_PROMISC) &&
	    !test_and_set_bit(__IDPF_PROMISC_UC,
			      config_data->user_flags)) {
		changed = true;
		dev_info(&adapter->pdev->dev, "Entering promiscuous mode\n");
		if (!test_and_set_bit(__IDPF_PROMISC_MC,
				      adapter->flags))
			dev_info(&adapter->pdev->dev, "Entering multicast promiscuous mode\n");
	}
	if (!(netdev->flags & IFF_PROMISC) &&
	    test_and_clear_bit(__IDPF_PROMISC_UC,
			       config_data->user_flags)) {
		changed = true;
		dev_info(&adapter->pdev->dev, "Leaving promiscuous mode\n");
	}
	if (netdev->flags & IFF_ALLMULTI &&
	    !test_and_set_bit(__IDPF_PROMISC_MC,
			      config_data->user_flags)) {
		changed = true;
		dev_info(&adapter->pdev->dev, "Entering multicast promiscuous mode\n");
	}
	if (!(netdev->flags & (IFF_ALLMULTI | IFF_PROMISC)) &&
	    test_and_clear_bit(__IDPF_PROMISC_MC,
			       config_data->user_flags)) {
		changed = true;
		dev_info(&adapter->pdev->dev, "Leaving multicast promiscuous mode\n");
	}

	if (changed) {
		err = idpf_set_promiscuous(vport);
		if (err) {
			dev_info(&adapter->pdev->dev, "Failed to set promiscuous mode: %d\n",
				 err);
		}
	}
}

/**
 * idpf_vport_manage_rss_lut - disable/enable RSS
 * @adapter: adapter structure
 * @vport: the vport being changed
 * @ena: boolean value indicating if this is an enable or disable request
 *
 * In the event of disable request for RSS, this function will zero out RSS
 * LUT, while in the event of enable request for RSS, it will reconfigure RSS
 * LUT with the default LUT configuration.
 */
static int idpf_vport_manage_rss_lut(struct idpf_adapter *adapter,
				     struct idpf_vport *vport, bool ena)
{
	struct idpf_rss_data *rss_data =
		&adapter->vport_config[vport->idx]->user_config.rss_data;
	int lut_size = rss_data->rss_lut_size * sizeof(u32);

	if (ena) {
		/* This will contain the default or user configured LUT */
		memcpy(rss_data->rss_lut, rss_data->cached_lut, lut_size);
	} else {
		/* Save a copy of the current LUT to be restored later if
		 * requested. Use a previously allocated buffer if available
		 */
		memcpy(rss_data->cached_lut, rss_data->rss_lut, lut_size);

		/* Zero out the current LUT to disable */
		memset(rss_data->rss_lut, 0, lut_size);
	}

	return idpf_config_rss(vport);
}

/**
 * idpf_set_features - set the netdev feature flags
 * @netdev: ptr to the netdev being adjusted
 * @features: the feature set that the stack is suggesting
 */
static int idpf_set_features(struct net_device *netdev,
			     netdev_features_t features)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);
	struct idpf_adapter *adapter;
	int err = 0;

	if (!vport)
		return -EINVAL;

	adapter = vport->adapter;

	if (idpf_is_reset_in_prog(adapter)) {
		dev_err(&adapter->pdev->dev, "Device is resetting, changing advanced netdev features temporarily unavailable.\n");
		return -EBUSY;
	}

	if (features & NETIF_F_RXHASH && !(netdev->features & NETIF_F_RXHASH)) {
		err = idpf_vport_manage_rss_lut(adapter, vport, true);
		if (err)
			goto set_feature_err;
	} else if (!(features & NETIF_F_RXHASH) &&
		   netdev->features & NETIF_F_RXHASH) {
		err = idpf_vport_manage_rss_lut(adapter, vport, false);
		if (err)
			goto set_feature_err;
	}

#ifdef NETIF_F_GRO_HW
	if ((netdev->features ^ features) & NETIF_F_GRO_HW) {
		netdev->features ^= NETIF_F_GRO_HW;
		err = idpf_initiate_soft_reset(vport, __IDPF_SR_RSC_CHANGE);
		if (err)
			goto set_feature_err;
	}

#endif /* NETIF_F_GRO_HW */
	if ((netdev->features ^ features) & NETIF_F_LOOPBACK) {
		netdev->features ^= NETIF_F_LOOPBACK;
		err = idpf_send_ena_dis_loopback_msg(vport);
	}

set_feature_err:
	return err;
}

/**
 * idpf_fix_features - fix up the netdev feature bits
 * @netdev: our net device
 * @features: desired feature bits
 *
 * Returns fixed-up features bits
 */
static netdev_features_t idpf_fix_features(struct net_device *netdev,
					   netdev_features_t features)
{
	return features;
}

/**
 * idpf_open - Called when a network interface becomes active
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
static int idpf_open(struct net_device *netdev)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);

	if (!vport)
		return -EINVAL;

	return idpf_vport_open(vport, true);
}

/**
 * idpf_change_mtu - NDO callback to change the MTU
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct idpf_vport *vport =  idpf_netdev_to_vport(netdev);

	if (!vport)
		return -EINVAL;

	if (new_mtu < netdev->min_mtu) {
		netdev_err(netdev, "new MTU invalid. min_mtu is %d\n",
			   netdev->min_mtu);
		return -EINVAL;
	} else if (new_mtu > netdev->max_mtu) {
		netdev_err(netdev, "new MTU invalid. max_mtu is %d\n",
			   netdev->max_mtu);
		return -EINVAL;
	}

	if (idpf_xdp_is_prog_ena(vport) && new_mtu > IDPF_XDP_MAX_MTU) {
		netdev_err(netdev, "New MTU value is not valid. The maximum MTU value is %d.\n",
			   IDPF_XDP_MAX_MTU);
		return -EINVAL;
	}
	netdev->mtu = new_mtu;

	return idpf_initiate_soft_reset(vport, __IDPF_SR_MTU_CHANGE);
}

/**
 * idpf_features_check - Validate packet conforms to limits
 * @skb: skb buffer
 * @netdev: This port's netdev
 * @features: Offload features that the stack believes apply
 */
static netdev_features_t
idpf_features_check(struct sk_buff *skb,
		    struct net_device *netdev,
		    netdev_features_t features)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);
	struct idpf_adapter *adapter = vport->adapter;
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
	    (skb_shinfo(skb)->gso_size < IDPF_TX_TSO_MIN_MSS))
		features &= ~NETIF_F_GSO_MASK;

	/* Ensure MACLEN is <= 126 bytes (63 words) and not an odd size */
	len = skb_network_header(skb) - skb->data;
	if (len & ~(126))
		goto out_err;

	len = skb_transport_header(skb) - skb_network_header(skb);
	if (unlikely(len > idpf_get_max_tx_hdr_size(adapter)))
		goto out_err;

	if (!skb->encapsulation)
		return features;

	/* L4TUNLEN can support 127 words */
	len = skb_inner_network_header(skb) - skb_transport_header(skb);
	if (len & ~(127 * 2))
		goto out_err;

	/* IPLEN can support at most 127 dwords */
	len = skb_inner_transport_header(skb) -
	      skb_inner_network_header(skb);
	if (unlikely(len > idpf_get_max_tx_hdr_size(adapter)))
		goto out_err;

	/* No need to validate L4LEN as TCP is the only protocol with a
	 * a flexible value and we support all possible values supported
	 * by TCP, which is at most 15 dwords
	 */

	return features;

out_err:
	return features & ~(NETIF_F_CSUM_MASK | NETIF_F_GSO_MASK);
}

/**
 * idpf_change_tx_sch_mode - reset queue context with appropriate
 * tx scheduling mode
 * @vport: virtual port data structure
 * @txq: queue to reset
 * @flow_sched: true if flow scheduling requested, false otherwise
 */
static int idpf_change_tx_sch_mode(struct idpf_vport *vport,
				   struct idpf_queue *txq,
				   bool flow_sched)
{
	if (flow_sched && !test_bit(__IDPF_Q_FLOW_SCH_EN, txq->flags))
		return idpf_initiate_soft_reset(vport,
						__IDPF_SR_Q_SCH_CHANGE);
	else if (!flow_sched && test_bit(__IDPF_Q_FLOW_SCH_EN, txq->flags))
		return idpf_initiate_soft_reset(vport,
						__IDPF_SR_Q_SCH_CHANGE);

	return 0;
}

static int idpf_offload_txtime(struct idpf_vport *vport,
			       struct tc_etf_qopt_offload *qopt)
{
	struct idpf_vport_user_config_data *config_data;
	struct idpf_adapter *adapter = vport->adapter;
	struct idpf_queue *tx_q;

	if (!idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS, VIRTCHNL2_CAP_EDT))
		return -EOPNOTSUPP;

	if (qopt->queue < 0 || qopt->queue > vport->num_txq)
		return -EINVAL;

	config_data = &adapter->vport_config[vport->idx]->user_config;
	/* Set config data to enable in future when queues are allocated */
	if (qopt->enable)
		set_bit(qopt->queue, config_data->etf_qenable);
	else
		clear_bit(qopt->queue, config_data->etf_qenable);

	tx_q = vport->txqs[qopt->queue];

	/* MEV-1 does not support queue based scheduling in the split queue
	 * mode.  It will only be enabled in MEV-2 and beyond based on the CP
	 * advertising the VIRTCHNL2_CAP_SPLITQ_QSCHED capability flag
	 */
	if (idpf_is_cap_ena(adapter, IDPF_OTHER_CAPS,
			    VIRTCHNL2_CAP_SPLITQ_QSCHED))
		return idpf_change_tx_sch_mode(vport, tx_q, qopt->enable);

	/* Set bit in queue itself if queues are already allocated */
	if (qopt->enable)
		set_bit(__IDPF_Q_ETF_EN, tx_q->flags);
	else
		clear_bit(__IDPF_Q_ETF_EN, tx_q->flags);

	return 0;
}

/**
 * idpf_setup_tc - ndo callback to setup up TC schedulers
 * @netdev: pointer to net_device struct
 * @type: TC type
 * @type_data: TC type specific data
 */
static int idpf_setup_tc(struct net_device *netdev, enum tc_setup_type type,
			 void *type_data)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);

	if (!vport)
		return -EINVAL;

	switch (type) {
	case TC_SETUP_QDISC_ETF:
		if (!idpf_is_queue_model_split(vport->txq_model))
			return -EOPNOTSUPP;
		return idpf_offload_txtime(vport,
				       (struct tc_etf_qopt_offload *)type_data);
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * idpf_vport_set_xdp_tx_desc_handler - Set a handler function for XDP Tx descriptor
 * @vport: vport to setup XDP Tx descriptor handler for
 */
static void idpf_vport_set_xdp_tx_desc_handler(struct idpf_vport *vport)
{
	if (vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE)
		vport->xdp_prepare_tx_desc = idpf_prepare_xdp_tx_singleq_desc;
	else
		vport->xdp_prepare_tx_desc = idpf_prepare_xdp_tx_splitq_desc;
}

/**
 * idpf_xdp_setup_prog - Add or remove XDP eBPF program
 * @vport: vport to setup XDP for
 * @prog: XDP program
 * @extack: netlink extended ack
 */
static int
idpf_xdp_setup_prog(struct idpf_vport *vport, struct bpf_prog *prog,
		    struct netlink_ext_ack *extack)
{
	int frame_size = vport->netdev->mtu;
	struct bpf_prog **current_prog;
	struct bpf_prog *old_prog;
	u16 idx = vport->idx;

	current_prog = &vport->adapter->vport_config[idx]->user_config.xdp_prog;
	if (frame_size > IDPF_XDP_MAX_MTU ||
	    frame_size > vport->bufq_size[0]) {
		NL_SET_ERR_MSG_MOD(extack, "MTU too large for loading XDP");
		return -EOPNOTSUPP;
	}

	if (!idpf_xdp_is_prog_ena(vport) && !prog) {
		return 0;
	} else if (!idpf_xdp_is_prog_ena(vport) && prog) {
		netdev_warn(vport->netdev, "Setting up XDP disables header split\n");
		idpf_vport_set_hsplit(vport, false);
		idpf_vport_set_xdp_tx_desc_handler(vport);
	}

	old_prog = xchg(current_prog, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	return idpf_initiate_soft_reset(vport, __IDPF_SR_Q_CHANGE);
}

/**
 * idpf_xdp - implements XDP handler
 * @dev: netdevice
 * @xdp: XDP command
 */
#ifdef HAVE_NDO_BPF
static int idpf_xdp(struct net_device *dev, struct netdev_bpf *xdp)
#else
static int idpf_xdp(struct net_device *dev, struct netdev_xdp *xdp)
#endif /* HAVE_NDO_BPF */
{
	struct idpf_vport *vport = idpf_netdev_to_vport(dev);
#ifdef HAVE_XDP_QUERY_PROG
	struct bpf_prog *current_prog;
	u16 idx;
#endif /* HAVE_XDP_QUERY_PROG */

	if (!vport)
		return -EINVAL;

#ifdef HAVE_XDP_QUERY_PROG
	idx = vport->idx;

#endif /* HAVE_XDP_QUERY_PROG */
	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return idpf_xdp_setup_prog(vport, xdp->prog, xdp->extack);
#ifdef HAVE_XDP_QUERY_PROG
	case XDP_QUERY_PROG:
		current_prog = vport->adapter->vport_config[idx]->user_config.xdp_prog;
		xdp->prog_id = current_prog ? current_prog->aux->id : 0;

		return 0;
#endif /* HAVE_XDP_QUERY_PROG */
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	case XDP_SETUP_XSK_POOL:
		return idpf_xsk_pool_setup(vport, xdp->xsk.pool, xdp->xsk.queue_id);
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
	default:
		return -EINVAL;
	}
}

/**
 * idpf_set_mac - NDO callback to set port mac address
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int idpf_set_mac(struct net_device *netdev, void *p)
{
	struct idpf_vport *vport = idpf_netdev_to_vport(netdev);
	struct sockaddr *addr = p;
	int err = 0;

	if (!vport)
		return -EINVAL;

	if (!idpf_is_cap_ena(vport->adapter, IDPF_OTHER_CAPS,
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
	err = idpf_add_mac_filter(vport, addr->sa_data, false);
	if (err) {
		__idpf_del_mac_filter(vport, addr->sa_data);
		return err;
	}

	/* Delete the current filter */
	if (is_valid_ether_addr(vport->default_mac_addr))
		idpf_del_mac_filter(vport, vport->default_mac_addr, false);

	ether_addr_copy(vport->default_mac_addr, addr->sa_data);
	eth_hw_addr_set(netdev, addr->sa_data);

	return err;
}

void *idpf_alloc_dma_mem(struct idpf_hw *hw, struct idpf_dma_mem *mem, u64 size)
{
	struct idpf_adapter *adapter = (struct idpf_adapter *)hw->back;
	size_t sz = ALIGN(size, 4096);

	mem->va = dma_alloc_coherent(&adapter->pdev->dev, sz,
				     &mem->pa, GFP_KERNEL | __GFP_ZERO);
	mem->size = sz;

	return mem->va;
}

void idpf_free_dma_mem(struct idpf_hw *hw, struct idpf_dma_mem *mem)
{
	struct idpf_adapter *adapter = (struct idpf_adapter *)hw->back;

	dma_free_coherent(&adapter->pdev->dev, mem->size,
			  mem->va, mem->pa);
	mem->size = 0;
	mem->va = NULL;
	mem->pa = 0;
}

static const struct net_device_ops idpf_netdev_ops_splitq = {
	.ndo_open = idpf_open,
	.ndo_stop = idpf_stop,
	.ndo_start_xmit = idpf_tx_splitq_start,
	.ndo_features_check = idpf_features_check,
	.ndo_set_rx_mode = idpf_set_rx_mode,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = idpf_set_mac,
	.ndo_change_mtu = idpf_change_mtu,
	.ndo_get_stats64 = idpf_get_stats64,
	.ndo_fix_features = idpf_fix_features,
	.ndo_set_features = idpf_set_features,
	.ndo_tx_timeout = idpf_tx_timeout,
	.ndo_setup_tc = idpf_setup_tc,
#ifdef HAVE_NDO_BPF
	.ndo_bpf = idpf_xdp,
#else
	.ndo_xdp = idpf_xdp,
#endif /* HAVE_NDO_BPF */
	.ndo_xdp_xmit = idpf_xdp_xmit,
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	.ndo_xsk_wakeup = idpf_xsk_splitq_wakeup,
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
};

static const struct net_device_ops idpf_netdev_ops_singleq = {
	.ndo_open = idpf_open,
	.ndo_stop = idpf_stop,
	.ndo_start_xmit = idpf_tx_singleq_start,
	.ndo_features_check = idpf_features_check,
	.ndo_set_rx_mode = idpf_set_rx_mode,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_mac_address = idpf_set_mac,
	.ndo_change_mtu = idpf_change_mtu,
	.ndo_get_stats64 = idpf_get_stats64,
	.ndo_fix_features = idpf_fix_features,
	.ndo_set_features = idpf_set_features,
	.ndo_tx_timeout = idpf_tx_timeout,
	.ndo_setup_tc = idpf_setup_tc,
#ifdef HAVE_NDO_BPF
	.ndo_bpf = idpf_xdp,
#else
	.ndo_xdp = idpf_xdp,
#endif /* HAVE_NDO_BPF */
	.ndo_xdp_xmit = idpf_xdp_xmit,
#ifdef HAVE_NETDEV_BPF_XSK_POOL
	.ndo_xsk_wakeup = idpf_xsk_singleq_wakeup,
#endif /* HAVE_NETDEV_BPF_XSK_POOL */
};
