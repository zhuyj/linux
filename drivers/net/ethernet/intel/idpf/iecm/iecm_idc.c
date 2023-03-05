// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2019 Intel Corporation */

#include "iecm.h"

static DEFINE_IDA(iecm_idc_ida);

/**
 * iecm_idc_init - Called to initialize IDC
 * @adapter driver private data structure
 */
int iecm_idc_init(struct iecm_adapter *adapter)
{
	int err;

	if (!iecm_is_rdma_cap_ena(adapter) ||
	    !adapter->dev_ops.idc_ops.idc_init)
		return 0;

	err = adapter->dev_ops.idc_ops.idc_init(adapter);
	if (err)
		dev_err(&adapter->pdev->dev, "failed to initialize idc: %d\n",
			err);

	return err;
}

/**
 * iecm_idc_deinit - Called to de-initialize IDC
 * @adapter driver private data structure
 */
void iecm_idc_deinit(struct iecm_adapter *adapter)
{
	if (iecm_is_rdma_cap_ena(adapter) &&
	    adapter->dev_ops.idc_ops.idc_deinit)
		adapter->dev_ops.idc_ops.idc_deinit(adapter);
}

/**
 * iecm_get_auxiliary_drv - retrieve iidc_auxiliary_drv structure
 * @cdev_info: pointer to iidc_core_dev_info struct
 *
 * This function has to be called with a device_lock on the
 * cdev_info->adev.dev to avoid race conditions.
 */
static struct iidc_auxiliary_drv *
iecm_get_auxiliary_drv(struct iidc_core_dev_info *cdev_info)
{
	struct auxiliary_device *adev;

	if (!cdev_info)
		return NULL;

	adev = cdev_info->adev;
	if (!adev || !adev->dev.driver)
		return NULL;

	return container_of(adev->dev.driver, struct iidc_auxiliary_drv,
			    adrv.driver);
}

/**
 * iecm_idc_event - Function to handle IDC event
 * @adapter: driver private data structure
 * @reason: event reason
 * @pre_event: before triggering the event
 */
void iecm_idc_event(struct iecm_adapter *adapter, enum iecm_flags reason,
		    bool pre_event)
{
	struct iidc_core_dev_info *cdev_info;
	struct iidc_auxiliary_drv *iadrv;
	enum iidc_event_type event_type;
	struct iidc_event *event;

	switch (reason) {
	case __IECM_SR_MTU_CHANGE:
		if (pre_event)
			event_type = IIDC_EVENT_BEFORE_MTU_CHANGE;
		else
			event_type = IIDC_EVENT_AFTER_MTU_CHANGE;
		break;
	default:
		/* We do not care about other events */
		return;
	};

	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return;
	set_bit(event_type, event->type);

	cdev_info = adapter->rdma_data.cdev_info;

	device_lock(&cdev_info->adev->dev);
	iadrv = iecm_get_auxiliary_drv(cdev_info);
	if (iadrv && iadrv->event_handler)
		iadrv->event_handler(cdev_info, event);
	device_unlock(&cdev_info->adev->dev);
	kfree(event);
}

/**
 * iecm_idc_vc_receive - Used to pass the received msg over IDC
 * @adapter: driver specific private data
 * @f_id: function source id
 * @msg: payload received on mailbox
 * @msg_size: size of the payload
 *
 * This function is used by the Auxiliary Device to pass the receive mailbox
 * message an Auxiliary Driver cell
 */
int iecm_idc_vc_receive(struct iecm_adapter *adapter, u32 f_id, u8 *msg,
			u16 msg_size)
{
	struct iecm_rdma_data *rdma_data = &adapter->rdma_data;
	struct iidc_core_dev_info *cdev_info;
	struct iidc_auxiliary_drv *iadrv;
	int err = 0;

	if (!rdma_data->cdev_info || !rdma_data->cdev_info->adev)
		return -ENODEV;

	cdev_info = rdma_data->cdev_info;

	device_lock(&cdev_info->adev->dev);
	iadrv = iecm_get_auxiliary_drv(cdev_info);
	if (iadrv && iadrv->vc_receive)
		err = iadrv->vc_receive(cdev_info, f_id, msg, msg_size);
	device_unlock(&cdev_info->adev->dev);
	if (err)
		pr_err("Failed to pass receive idc msg, err %d\n", err);

	return err;
}

/**
 * iecm_idc_request_reset - Called by an Auxiliary Driver
 * @cdev_info: IIDC device specific pointer
 * @reset_type: function, core or other
 *
 * This callback function is accessed by an Auxiliary Driver to request a reset
 * on the Auxiliary Device
 */
static int
iecm_idc_request_reset(struct iidc_core_dev_info *cdev_info,
		       enum iidc_reset_type __always_unused reset_type)
{
	struct iecm_adapter *adapter = pci_get_drvdata(cdev_info->pdev);

	if (!iecm_is_reset_in_prog(adapter)) {
		set_bit(__IECM_HR_FUNC_RESET, adapter->flags);
		queue_delayed_work(adapter->vc_event_wq,
				   &adapter->vc_event_task,
				   msecs_to_jiffies(10));
	}

	return 0;
}

/**
 * iecm_idc_vc_send - Called by an Auxiliary Driver
 * @cdev_info: IIDC device specific pointer
 * @vf_id: always unused
 * @msg: payload to be sent
 * @msg_size: size of the payload
 *
 * This callback function is accessed by an Auxiliary Driver to request a send
 * on the mailbox queue
 */
static int
iecm_idc_vc_send(struct iidc_core_dev_info *cdev_info,
		 u32 __always_unused vf_id, u8 *msg, u16 msg_size)
{
	struct iecm_adapter *adapter;
	int err;

	if (cdev_info->cdev_info_id != IIDC_RDMA_ID)
		return -EINVAL;

	if (msg_size > IECM_DFLT_MBX_BUF_SIZE)
		return -EINVAL;

	adapter = pci_get_drvdata(cdev_info->pdev);

	err = iecm_send_mb_msg(adapter, VIRTCHNL_OP_IWARP, msg_size, msg);
	if (err)
		pr_err("Failed to pass send IDC msg, err %d\n", err);

	return err;
}

/**
 * iecm_idc_vc_send_sync - synchronous version of vc_send
 * @cdev_info: core device info pointer
 * @send_msg: message to send
 * @msg_size: size of message to send
 * @recv_msg: message to populate on reception of response
 * @recv_len: length of message copied into recv_msg or 0 on error
 */
static int
iecm_idc_vc_send_sync(struct iidc_core_dev_info *cdev_info, u8 *send_msg,
		      u16 msg_size, u8 *recv_msg, u16 *recv_len)
{
	struct iecm_adapter *adapter = pci_get_drvdata(cdev_info->pdev);
	u16 size = min_t(u16, *recv_len, IECM_DFLT_MBX_BUF_SIZE);
	int err;

	if (!recv_msg || !recv_len || msg_size > IECM_DFLT_MBX_BUF_SIZE)
		return -EINVAL;

	adapter->rdma_data.vc_send_sync_pending = true;

	err = iecm_idc_vc_send(cdev_info, 0, send_msg, msg_size);
	if (!err) {
		err = iecm_wait_for_event(adapter, IECM_VC_IWARP_SEND_SYNC,
					  IECM_VC_IWARP_SEND_SYNC_ERR);
		if (err)
			return err;
		memcpy(recv_msg, adapter->vc_msg, size);
		*recv_len = size;
		clear_bit(__IECM_VC_MSG_PENDING, adapter->flags);
	}

	adapter->rdma_data.vc_send_sync_pending = false;
	return err;
}

/**
 * iecm_idc_vc_qv_map_unmap - Called by an Auxiliary Driver
 * @cdev_info: IIDC device specific pointer
 * @qvl_info: payload to be sent on mailbox
 * @map: map or unmap
 *
 * This callback function is called by an Auxiliary Driver to request a map or
 * unmap of queues to vectors on mailbox queue
 */
static int
iecm_idc_vc_qv_map_unmap(struct iidc_core_dev_info *cdev_info,
			 struct iidc_qvlist_info *qvl_info, bool map)
{
	struct iecm_adapter *adapter = pci_get_drvdata(cdev_info->pdev);
	enum virtchnl_ops vop;
	int size = 0, err = 0;

	size = sizeof(struct iidc_qvlist_info) +
		(sizeof(struct iidc_qv_info) * (qvl_info->num_vectors - 1));

	if (map)
		vop = VIRTCHNL_OP_CONFIG_IWARP_IRQ_MAP;
	else
		vop = VIRTCHNL_OP_RELEASE_IWARP_IRQ_MAP;

	err = iecm_send_mb_msg(adapter, vop, size, (u8 *)qvl_info);
	if (!err)
		err = iecm_wait_for_event(adapter, IECM_VC_IWARP_IRQ_MAP_UNMAP,
					  IECM_VC_IWARP_IRQ_MAP_UNMAP_ERR);
	if (err)
		pr_err("Failed on IDC qv map unmap msg, err %d\n", err);

	return err;
}

/* Implemented by the Auxiliary Device and called by the Auxiliary Driver */
static const struct iidc_core_ops idc_ops = {
	.request_reset                  = iecm_idc_request_reset,
	.vc_send                        = iecm_idc_vc_send,
	.vc_send_sync			= iecm_idc_vc_send_sync,
	.vc_queue_vec_map_unmap         = iecm_idc_vc_qv_map_unmap,
};

/**
 * iecm_adev_release - function to be mapped to aux dev's release op
 * @dev: pointer to device to free
 */
static void iecm_adev_release(struct device *dev)
{
	struct iidc_auxiliary_dev *iadev;

	iadev = container_of(dev, struct iidc_auxiliary_dev, adev.dev);
	kfree(iadev);
	iadev = NULL;
}

/* iecm_plug_aux_dev - allocate and register an Auxiliary device
 * @rdma_data: pointer to rdma data struct
 */
static int iecm_plug_aux_dev(struct iecm_rdma_data *rdma_data)
{
	struct iidc_core_dev_info *cdev_info;
	struct iidc_auxiliary_dev *iadev;
	struct auxiliary_device *adev;
	int err;

	cdev_info = rdma_data->cdev_info;
	if (!cdev_info)
		return -ENODEV;

	rdma_data->aux_idx = ida_alloc(&iecm_idc_ida, GFP_KERNEL);
	if (rdma_data->aux_idx < 0) {
		pr_err("failed to allocate unique device ID for Auxiliary driver\n");
		return -ENOMEM;
	}

	iadev = kzalloc(sizeof(*iadev), GFP_KERNEL);
	if (!iadev) {
		err = -ENOMEM;
		goto err_iadev_alloc;
	}

	adev = &iadev->adev;
	cdev_info->adev = adev;
	iadev->cdev_info = cdev_info;

	if (cdev_info->rdma_protocol == IIDC_RDMA_PROTOCOL_IWARP)
		adev->name = IIDC_RDMA_IWARP_NAME;
	else
		adev->name = IIDC_RDMA_ROCE_NAME;

	adev->id = rdma_data->aux_idx;
	adev->dev.release = iecm_adev_release;
	adev->dev.parent = &cdev_info->pdev->dev;

	err = auxiliary_device_init(adev);
	if (err)
		goto err_aux_dev_init;

	err = auxiliary_device_add(adev);
	if (err)
		goto err_aux_dev_add;

	return 0;

err_aux_dev_add:
	cdev_info->adev = NULL;
	auxiliary_device_uninit(adev);
err_aux_dev_init:
	kfree((void *)adev->name);
	kfree(iadev);
err_iadev_alloc:
	ida_free(&iecm_idc_ida, rdma_data->aux_idx);

	return err;
}

/* iecm_unplug_aux_dev - unregister and free an Auxiliary device
 * @rdma_data: pointer to rdma data struct
 */
static void iecm_unplug_aux_dev(struct iecm_rdma_data *rdma_data)
{
	struct auxiliary_device *adev;

	if (!rdma_data->cdev_info)
		return;

	adev = rdma_data->cdev_info->adev;
	auxiliary_device_delete(adev);
	auxiliary_device_uninit(adev);
	adev = NULL;

	ida_free(&iecm_idc_ida, rdma_data->aux_idx);
}

/**
 * iecm_idc_init_msix_data - initialize MSIX data for the cdev_info structure
 * @adapter driver private data structure
 */
static void
iecm_idc_init_msix_data(struct iecm_adapter *adapter)
{
	struct iidc_core_dev_info *cdev_info;
	struct iecm_rdma_data *rdma_data;
	int idc_vector_start;

	if (!adapter->msix_entries)
		return;

	rdma_data = &adapter->rdma_data;
	cdev_info = rdma_data->cdev_info;

	idc_vector_start = IECM_NONQ_VEC + adapter->vports[0]->num_q_vectors;
	cdev_info->msix_entries = &adapter->msix_entries[idc_vector_start];
	cdev_info->msix_count = rdma_data->num_vecs;
}

/**
 * iecm_idc_init_qos_info - initialialize default QoS information
 * @qos_info: QoS information structure to populate
 */
static void
iecm_idc_init_qos_info(struct iidc_qos_params *qos_info)
{
	int i;

	qos_info->num_apps = 0;
	qos_info->num_tc = 1;

	for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++)
		qos_info->up2tc[i] = 0;

	qos_info->tc_info[0].rel_bw = 100;
	for (i = 1; i < IEEE_8021QAZ_MAX_TCS; i++)
		qos_info->tc_info[i].rel_bw = 0;
}

/**
 * iecm_idc_init_aux_device - initialize Auxiliary Device(s)
 * @adapter driver private data structure
 * @ftype - function type
 */
int
iecm_idc_init_aux_device(struct iecm_adapter *adapter,
			 enum iidc_function_type ftype)
{
	struct iidc_core_dev_info *cdev_info;
	struct iecm_rdma_data *rdma_data;
	int err;

	rdma_data = &adapter->rdma_data;

	/* structure layout needed for container_of's looks like:
	 * iidc_auxiliary_dev (container_of super-struct for adev)
	 * |--> auxiliary_device
	 * |--> *iidc_core_dev_info (pointer from cdev_info struct)
	 *
	 * The iidc_auxiliary_device has a lifespan as long as it
	 * is on the bus.  Once removed it will be freed and a new
	 * one allocated if needed to re-add.
	 */
	rdma_data->cdev_info = kzalloc(sizeof(struct iidc_core_dev_info),
				       GFP_KERNEL);
	if (!rdma_data->cdev_info) {
		err = -ENOMEM;
		goto err_cdev_info_alloc;
	}

	cdev_info = rdma_data->cdev_info;
	cdev_info->hw_addr = (u8 __iomem *)adapter->hw.hw_addr;
	cdev_info->ver.major = IIDC_MAJOR_VER;
	cdev_info->ver.minor = IIDC_MINOR_VER;
	cdev_info->ftype = ftype;
	cdev_info->vport_id = adapter->vports[0]->vport_id;
	cdev_info->netdev = adapter->vports[0]->netdev;
	cdev_info->pdev = adapter->pdev;
	cdev_info->ops = &idc_ops;
	cdev_info->rdma_protocol = IIDC_RDMA_PROTOCOL_IWARP;
	cdev_info->cdev_info_id = IIDC_RDMA_ID;

	iecm_idc_init_qos_info(&cdev_info->qos_info);
	iecm_idc_init_msix_data(adapter);

	err = iecm_plug_aux_dev(rdma_data);
	if (err)
		goto err_plug_aux_dev;

	return 0;

err_plug_aux_dev:
	kfree(rdma_data->cdev_info);
	rdma_data->cdev_info = NULL;
err_cdev_info_alloc:
	memset(rdma_data, 0, sizeof(*rdma_data));

	return err;
}
EXPORT_SYMBOL(iecm_idc_init_aux_device);

/**
 * iecm_idc_deinit_aux_device - de-initialize Auxiliary Device(s)
 * @adapter driver private data structure
 */
void iecm_idc_deinit_aux_device(struct iecm_adapter *adapter)
{
	struct iecm_rdma_data *rdma_data = &adapter->rdma_data;

	iecm_unplug_aux_dev(rdma_data);
	kfree(rdma_data->cdev_info);
	memset(rdma_data, 0, sizeof(*rdma_data));
}
EXPORT_SYMBOL(iecm_idc_deinit_aux_device);
