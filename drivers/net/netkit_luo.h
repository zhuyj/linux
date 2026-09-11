/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */

#ifndef NETKIT_LUO_H
#define NETKIT_LUO_H

/* For netkit_luo */
struct netkit_luo_info {
	char netkit_name[16];
	char net_mode[IFNAMSIZ];
	int index;
};

#if IS_ENABLED(CONFIG_LIVEUPDATE_NETKIT)
int netkit_luo_init(void);
void netkit_luo_exit(void);
#else /* LIVEUPDATE_NETKIT */
static int netkit_luo_init(void)
{
	return 0;
}
static void netkit_luo_exit(void)
{
}
#endif /* LIVEUPDATE_NETKIT */

#endif /* NETKIT_LUO_H */
