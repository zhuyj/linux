/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */

#ifndef RXE_LUO_H
#define RXE_LUO_H

/* For rxe_luo */
struct rxe_luo_info {
	char rxe_name[64];
	char ndev_name[IFNAMSIZ];
	char ns_name[256]; /* netns name or ID */
	unsigned long index;
};

#if IS_ENABLED(CONFIG_LIVEUPDATE_RXE)
int rxe_luo_init(void);
void rxe_luo_exit(void);
#else /* LIVEUPDATE_RXE */
static int rxe_luo_init(void)
{
	return 0;
}
static void rxe_luo_exit(void)
{
}
#endif /* LIVEUPDATE_RXE */

#endif /* RXE_LUO_H */
