// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, Intel Corporation. */

#include "idpf.h"

/**
 * idpf_sf_by_sfnum - Search for a given subfn number in the subfn list
 * stored inside the adapter structure.
 * @adapter: pointer to idpf adapter structure
 * @sfnum: sub function number to be searched
 *
 * Returns pointer to subfn structure entry or NULL if not found.
 */
static struct idpf_sf *idpf_sf_by_sfnum(struct idpf_adapter *adapter, u32 sfnum)
{
	struct idpf_sf *sf;

	list_for_each_entry(sf, &adapter->sf_list, list) {
		if (sf->sfnum == sfnum)
			return sf;
	}
	return NULL;
}

/**
 * idpf_devlink_create_sf_port - Create and register a devlink_port for this SF.
 * @sf: the subfunction to create a devlink port for
 * Return: 0 on success or an error code on failure.
 */
static int idpf_devlink_create_sf_port(struct idpf_sf *sf)
{
	struct devlink_port_attrs attrs = {};
	struct devlink_port *devlink_port;
	struct idpf_adapter *adapter;
	struct devlink *devlink;
	struct device *dev;
	int err;

	adapter = sf->adapter;
	dev = idpf_adapter_to_dev(adapter);
	devlink_port = &sf->devl_port;
	attrs.flavour = DEVLINK_PORT_FLAVOUR_PCI_SF;
	attrs.pci_sf.pf = 0;
	attrs.pci_sf.sf = sf->sfnum;
	devlink_port_attrs_set(devlink_port, &attrs);
	devlink = priv_to_devlink(adapter);
	err = devlink_port_register(devlink, devlink_port, sf->sf_id);
	if (err) {
		dev_err(dev, "Failed to create devlink port: sfnum %d, err %d",
			sf->sfnum, err);
		return err;
	}
	dev_dbg(dev, "%s: sfnum %d sf_id %d successful\n",
		__func__, sf->sfnum, sf->sf_id);
	return 0;
}

/**
 * idpf_dl_port_new - Add a new port function of a specified flavor
 * @devlink: Devlink instance pointer
 * @new_attr: attributes of the new port
 * @extack: extack for reporting error messages
 * @new_port_index: pointer to index of the new port. Value filled by func.
 *
 * Fills the 4th parameter with the index for the new sub function.
 * Returns 0 on success, negative value otherwise.
 */
static int idpf_dl_port_new(struct devlink *devlink,
			    const struct devlink_port_new_attrs *new_attr,
			    struct netlink_ext_ack *extack,
			    unsigned int *new_port_index)
{
	struct idpf_adapter *adapter =
		devlink_priv(devlink);
	struct device *dev = idpf_adapter_to_dev(adapter);
	struct idpf_sf *sf;
	int err;

	dev_dbg(dev, "%s: flavour:%d index:%d pfnum:%d\n", __func__,
		new_attr->flavour, new_attr->port_index, new_attr->pfnum);
	if (!new_attr->sfnum_valid) {
		NL_SET_ERR_MSG_MOD(extack, "sfnum autogeneration is not supported");
		return -EINVAL;
	}
	if (idpf_sf_by_sfnum(adapter, new_attr->sfnum)) {
		NL_SET_ERR_MSG_MOD(extack, "sfnum already exists");
		return -EEXIST;
	}
	if (adapter->sf_cnt >= IDPF_MAX_DYNAMIC_VPORT) {
		NL_SET_ERR_MSG_MOD(extack, "Cannot create more vports");
		return -EINVAL;
	}

	sf = kzalloc(sizeof(*sf), GFP_KERNEL);
	if (!sf)
		return -ENOMEM;
	sf->vport = NULL;
	sf->adapter = adapter;
	sf->state = DEVLINK_PORT_FN_STATE_INACTIVE;
	sf->sf_id = ++adapter->sf_id;
	sf->sfnum = new_attr->sfnum;
	eth_random_addr(sf->hw_addr);
	err = idpf_devlink_create_sf_port(sf);
	if (err)
		goto unroll_sf_alloc;
	list_add(&sf->list, &adapter->sf_list);
	*new_port_index = sf->sf_id;
	adapter->sf_cnt++;
	return 0;

unroll_sf_alloc:
	kfree(sf);
	return err;
}

/**
 * idpf_destroy_sf - Free the vport and the associated subfunc structure.
 * the corresponding devlink port is also unregistered.
 * @sf: pointer to subfunction structure
 */
static void idpf_destroy_sf(struct idpf_sf *sf)
{
	struct idpf_adapter *adapter;
	struct device *dev;

	adapter = sf->adapter;
	dev = idpf_adapter_to_dev(adapter);
	dev_dbg(dev, "%s: sfnum %d vport %p\n", __func__, sf->sfnum, sf->vport);
	if (sf->vport)
		idpf_vport_dealloc(sf->vport);
	devlink_port_unregister(&sf->devl_port);
	list_del(&sf->list);
	kfree(sf);
	adapter->sf_cnt--;
}

/**
 * idpf_dl_port_del - delete a port function that is referenced via port_index
 * @devlink: Devlink instance pointer
 * @port_index: index of the subfunction to be deleted
 * @extack: extack for reporting error messages
 *
 * Return: 0 on success, negative value otherwise.
 */
static int idpf_dl_port_del(struct devlink *devlink, unsigned int port_index,
			    struct netlink_ext_ack *extack)
{
	struct idpf_adapter *adapter =
		devlink_priv(devlink);
	struct device *dev = idpf_adapter_to_dev(adapter);
	struct idpf_sf *sf = NULL, *sf_tmp;

	dev_dbg(dev, "%s: index:%d\n", __func__, port_index);
	list_for_each_entry(sf_tmp, &adapter->sf_list, list) {
		if (sf_tmp->sf_id == port_index) {
			sf = sf_tmp;
			break;
		}
	}
	if (!sf) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to find a SF port with a given index");
		return -EINVAL;
	}
	idpf_destroy_sf(sf);
	return 0;
}

/**
 * idpf_dl_port_fn_state_set - Set the admin state of a port function
 * This function uses the idpf_init_task task to spawn a new vport and
 * create a netdev and associated infrastructure.
 * @port: The devlink port
 * @state: Admin state
 * @extack: extack for reporting error messages
 *
 * Return: 0 on success, negative value otherwise.
 */
#ifdef HAVE_DEVLINK_SET_STATE_3_PARAM
static int idpf_dl_port_fn_state_set(struct devlink_port *port,
				     enum devlink_port_fn_state state,
				     struct netlink_ext_ack *extack)
#else
static int idpf_dl_port_fn_state_set(struct devlink *unused,
				     struct devlink_port *port,
				     enum devlink_port_fn_state state,
				     struct netlink_ext_ack *extack)
#endif
{
	struct idpf_sf *sf = container_of(port, struct idpf_sf, devl_port);
	struct idpf_adapter *adapter = sf->adapter;
	struct device *dev;
	u16 next_vport;

	dev = idpf_adapter_to_dev(adapter);
	dev_dbg(dev, "%s: sfnum %d input_state %d curr_state %d\n",
		__func__, sf->sfnum, state, sf->state);
	if (port->attrs.flavour != DEVLINK_PORT_FLAVOUR_PCI_SF) {
		NL_SET_ERR_MSG_MOD(extack, "Port is not a SF");
		return -EOPNOTSUPP;
	}
	if (state == sf->state)
		return 0;
	next_vport = adapter->next_vport;
	if (next_vport == IDPF_NO_FREE_SLOT) {
		NL_SET_ERR_MSG_MOD(extack, "No more free vport slot");
		return -ENOMEM;
	}
	INIT_WORK(&adapter->init_task.work, idpf_init_task);
	schedule_work(&adapter->init_task.work);
	flush_work(&adapter->init_task.work);
	if (!adapter->vports[next_vport]) {
		NL_SET_ERR_MSG_MOD(extack, "vport allocation failed");
		return -ENOMEM;
	}
	sf->vport = adapter->vports[next_vport];
	devlink_port_type_eth_set(&sf->devl_port, adapter->netdevs[next_vport]);
	sf->state = DEVLINK_PORT_FN_STATE_ACTIVE;
	return 0;
}

/**
 * idpf_destroy_sf_list - For a given input adapter, free all the associated
 * subfunctions.
 * @adapter: pointer to idpf adapter structure
 */
static void idpf_destroy_sf_list(struct idpf_adapter *adapter)
{
	struct idpf_sf *sf, *temp_sf;

	list_for_each_entry_safe(sf, temp_sf, &adapter->sf_list, list) {
		idpf_destroy_sf(sf);
	}
}

const struct devlink_ops idpf_devlink_ops = {
	.port_new = idpf_dl_port_new,
	.port_del = idpf_dl_port_del,
	.port_fn_state_set = idpf_dl_port_fn_state_set,
};

/**
 * idpf_devlink_deinit - Unregister and deallocate all devlink related
 * content and data structures for a given idpf adapter.
 * @adapter: pointer to idpf adapter structure
 */
void idpf_devlink_deinit(struct idpf_adapter *adapter)
{
	idpf_destroy_sf_list(adapter);
	devlink_unregister(priv_to_devlink(adapter));
}

/**
 * idpf_devlink_init - Register driver resource flags, parameters and
 * the devlink port corresponding to the idpf adapter.
 * @adapter: pointer to idpf adapter structure to be associated with devlink
 * @dev: pointer to device structure for backward compatibiity. Older kernels
 * expected an additional parameter in register API
 */
void idpf_devlink_init(struct idpf_adapter *adapter, struct device *dev)
{
#ifdef HAVE_DEVLINK_REGISTER_SETS_DEV
	devlink_register(priv_to_devlink(adapter), dev);
#else
	devlink_register(priv_to_devlink(adapter));
#endif
	INIT_LIST_HEAD(&adapter->sf_list);
	adapter->sf_id = 0;
}
