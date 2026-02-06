/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2026, Google LLC.
 * Zhu Yanjun <yanjun.zhu@linux.dev>
 */

#ifndef __RXE_LIVEUPDATE_H
#define __RXE_LIVEUPDATE_H

#ifdef CONFIG_LIVEUPDATE
int __init rxe_liveupdate_init(void);
void rxe_liveupdate_cleanup(void);
#else
static inline int rxe_liveupdate_init(void)
{
	return 0;
}

static inline void rxe_liveupdate_cleanup(void)
{
}
#endif /* CONFIG_LIVEUPDATE */
#endif /* __RXE_LIVEUPDATE_H */
