// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Intel Corporation */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "idpf.h"
#include "idpf_devids.h"

MODULE_VERSION(IDPF_DRV_VER);
#define DRV_SUMMARY	"Infrastructure Data Path Function Linux Driver"
static const char idpf_driver_string[] = DRV_SUMMARY;
static const char idpf_copyright[] = "Copyright (c) 2022, Intel Corporation.";

MODULE_DESCRIPTION(DRV_SUMMARY);
MODULE_LICENSE("GPL");

/**
 * idpf_remove - Device removal routine
 * @pdev: PCI device information struct
 */
static void idpf_remove(struct pci_dev *pdev)
{
	struct idpf_adapter *adapter = pci_get_drvdata(pdev);

	if (!adapter)
		return;

	idpf_remove_common(pdev);
	pci_set_drvdata(pdev, NULL);
#ifdef DEVLINK_ENABLED
	devlink_free(priv_to_devlink(adapter));
#else
	kfree(adapter);
#endif /* DEVLINK_ENABLED */
}

/**
 * idpf_shutdown - PCI callback for shutting down device
 * @pdev: PCI device information struct
 */
static void idpf_shutdown(struct pci_dev *pdev)
{
	idpf_remove(pdev);

	if (system_state == SYSTEM_POWER_OFF)
		pci_set_power_state(pdev, PCI_D3hot);
}

/**
 * idpf_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @ent: entry in idpf_pci_tbl
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct idpf_adapter *adapter;

#ifdef DEVLINK_ENABLED
	struct device *dev = &pdev->dev;
	struct devlink *devlink;

	devlink = devlink_alloc(&idpf_devlink_ops, sizeof(struct idpf_adapter),
				dev);
	if (!devlink)
		return -ENOMEM;
	adapter = devlink_priv(devlink);
#else
	adapter = kzalloc(sizeof(*adapter), GFP_KERNEL);
#endif /* DEVLINK_ENABLED */
	if (!adapter)
		return -ENOMEM;
	adapter->drv_name = IDPF_DRV_NAME;
	adapter->drv_ver = IDPF_DRV_VER;
	set_bit(__IDPF_REQ_TX_SPLITQ, adapter->flags);
	set_bit(__IDPF_REQ_RX_SPLITQ, adapter->flags);
	if (ent->device == IDPF_DEV_ID_PF)
		return idpf_pf_probe(pdev, adapter);
	if (ent->device == IAVF_DEV_ID_VF)
		return idpf_vf_probe(pdev, adapter);
	if (ent->device == IAVF_DEV_ID_VF_SIOV)
		return idpf_vf_probe(pdev, adapter);

	if (ent->device == IAVF_DEV_ID_ADAPTIVE_VF)
		return idpf_vf_probe(pdev, adapter);

	dev_err(&pdev->dev, "Unexpected dev ID 0x%x in idpf probe\n",
		ent->device);
	return -EINVAL;
}

/* idpf_pci_tbl - PCI Dev iapf ID Table
 *
 * Wildcard entries (PCI_ANY_ID) should come last
 * Last entry must be all 0s
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static const struct pci_device_id idpf_pci_tbl[] = {
	{ PCI_VDEVICE(INTEL, IDPF_DEV_ID_PF), 0 },
	{ PCI_VDEVICE(INTEL, IAVF_DEV_ID_VF), 0 },
	{ PCI_VDEVICE(INTEL, IAVF_DEV_ID_VF_SIOV), 0 },

	{ PCI_VDEVICE(INTEL, IAVF_DEV_ID_ADAPTIVE_VF), 0 },

	/* required last entry */
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, idpf_pci_tbl);

static struct pci_driver idpf_driver = {
	.name = KBUILD_MODNAME,
	.id_table = idpf_pci_tbl,
	.probe = idpf_probe,
	.sriov_configure = idpf_sriov_configure,
	.remove = idpf_remove,
	.shutdown = idpf_shutdown,
};

/**
 * idpf_module_init - Driver registration routine
 *
 * idpf_module_init is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 */
static int __init idpf_module_init(void)
{
	int status;

	pr_info("%s - version %s\n", idpf_driver_string, IDPF_DRV_VER);
	pr_info("%s\n", idpf_copyright);

	status = pci_register_driver(&idpf_driver);
	if (status)
		pr_err("failed to register pci driver, err %d\n", status);

	return status;
}
module_init(idpf_module_init);

/**
 * idpf_module_exit - Driver exit cleanup routine
 *
 * idpf_module_exit is called just before the driver is removed
 * from memory.
 */
static void __exit idpf_module_exit(void)
{
	pci_unregister_driver(&idpf_driver);
	pr_info("module unloaded\n");
}
module_exit(idpf_module_exit);
