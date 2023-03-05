// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2019 Intel Corporation */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "idpf_dev.h"
#include "idpf_devids.h"

#define DRV_VERSION	"0.4.530"
MODULE_VERSION(DRV_VERSION);
static const char idpf_drv_ver[] = DRV_VERSION;
static const char idpf_drv_name[] = "idpf";
#define DRV_SUMMARY	"Intel(R) Data Plane Function Linux Driver"
static const char idpf_driver_string[] = DRV_SUMMARY;
static const char idpf_copyright[] = "Copyright (c) 2020, Intel Corporation.";

MODULE_DESCRIPTION(DRV_SUMMARY);
MODULE_LICENSE("GPL");

static int debug = -1;
module_param(debug, int, 0644);
#ifndef CONFIG_DYNAMIC_DEBUG
MODULE_PARM_DESC(debug, "netif level (0=none,...,16=all), hw debug_mask (0x8XXXXXXX)");
#else
MODULE_PARM_DESC(debug, "netif level (0=none,...,16=all)");
#endif /* !CONFIG_DYNAMIC_DEBUG */

/**
 * idpf_reg_ops_init - Initialize register API function pointers
 * @adapter: Driver specific private structure
 */
static void idpf_reg_ops_init(struct iecm_adapter *adapter)
{
	adapter->dev_ops.reg_ops.ctlq_reg_init = idpf_ctlq_reg_init;
	adapter->dev_ops.reg_ops.intr_reg_init = idpf_intr_reg_init;
	adapter->dev_ops.reg_ops.mb_intr_reg_init = idpf_mb_intr_reg_init;
	adapter->dev_ops.reg_ops.reset_reg_init = idpf_reset_reg_init;
	adapter->dev_ops.reg_ops.trigger_reset = idpf_trigger_reset;
	adapter->dev_ops.reg_ops.read_master_time = idpf_read_master_time_ns;
}

/**
 * idpf_probe - Device initialization routine
 * @pdev: PCI device information struct
 * @ent: entry in idpf_pci_tbl
 *
 * Returns 0 on success, negative on failure
 */
static int idpf_probe(struct pci_dev *pdev,
		      const struct pci_device_id __always_unused *ent)
{
	struct iecm_adapter *adapter = NULL;
	int err;

	adapter = kzalloc(sizeof(*adapter), GFP_KERNEL);
	if (!adapter)
		return -ENOMEM;

	adapter->drv_name = idpf_drv_name;
	adapter->drv_ver = idpf_drv_ver;
	adapter->dev_ops.reg_ops_init = idpf_reg_ops_init;
	adapter->debug_msk = debug;
	set_bit(__IECM_REQ_TX_SPLITQ, adapter->flags);
	set_bit(__IECM_REQ_RX_SPLITQ, adapter->flags);

	err = iecm_probe(pdev, ent, adapter);
	if (err)
		kfree(adapter);

	return err;
}

/**
 * idpf_remove - Device removal routine
 * @pdev: PCI device information struct
 */
static void idpf_remove(struct pci_dev *pdev)
{
	struct iecm_adapter *adapter = pci_get_drvdata(pdev);

	if (!adapter)
		return;

	iecm_remove(pdev);
	pci_set_drvdata(pdev, NULL);
	kfree(adapter);
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

/* idpf_pci_tbl - PCI Dev iapf ID Table
 *
 * Wildcard entries (PCI_ANY_ID) should come last
 * Last entry must be all 0s
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static const struct pci_device_id idpf_pci_tbl[] = {
	{ PCI_VDEVICE(INTEL, IDPF_DEV_ID_PF_SIMICS), 0 },
	{ PCI_VDEVICE(INTEL, IDPF_DEV_ID_PF), 0 },
	/* required last entry */
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, idpf_pci_tbl);

static struct pci_driver idpf_driver = {
	.name = KBUILD_MODNAME,
	.id_table = idpf_pci_tbl,
	.probe = idpf_probe,
	.sriov_configure = iecm_sriov_configure,
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

	pr_info("%s - version %s\n", idpf_driver_string, idpf_drv_ver);
	pr_info("%s\n", idpf_copyright);

	status = pci_register_driver(&idpf_driver);
	if (status) {
		pr_err("failed to register pci driver, err %d\n", status);
	}

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
