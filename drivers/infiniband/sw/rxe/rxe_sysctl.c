/*
 *Copyright (c) 2020 Mellanox Technologies Ltd. All rights reserved.
 *Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 *
 *This software is available to you under a choice of one of two
 *licenses.  You may choose to be licensed under the terms of the GNU
 *General Public License (GPL) Version 2, available from the file
 *COPYING in the main directory of this source tree, or the
 *OpenIB.org BSD license below:
 *
 *    Redistribution and use in source and binary forms, with or
 *    without modification, are permitted provided that the following
 *    conditions are met:
 *
 *     - Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer.
 *
 *     - Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *
 *THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 *BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 *ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 *CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <net/net_namespace.h>
#include "rxe_sysctl.h"

static struct ctl_table_header *rxe_sysctl_reg_table;
unsigned int rxe_sysctl_network_layer = 3;
static int two = 2;
static int three = 3;

static struct ctl_table rxe_sysctl_layer_table[] = {
	{
		.procname	= "rxe_network_layer",
		.data		= &rxe_sysctl_network_layer,
		.maxlen         = sizeof(int),
		.mode           = 0444,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &two,
		.extra2         = &three,
	},
	{ }
};

void rxe_sysctl_exit(void)
{
	unregister_net_sysctl_table(rxe_sysctl_reg_table);
}

int rxe_sysctl_init(void)
{
	rxe_sysctl_reg_table =
		register_net_sysctl(&init_net, "net/rxe",
				rxe_sysctl_layer_table);
	if (!rxe_sysctl_reg_table)
		return -ENOMEM;

#if IS_ENABLED(CONFIG_RDMA_RXE_L2)
	rxe_sysctl_network_layer = 2;
#else
	rxe_sysctl_network_layer = 3;
#endif

	return 0;
}
