/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */

/*
 * Copyright (c) 2026, Zhu Yanjun <yanjun.zhu@linux.dev>
 */

#ifndef DMABUF_LIVEUPDATE_H
#define DMABUF_LIVEUPDATE_H

#ifdef CONFIG_DMABUF_LIVEUPDATE
int __init dmabuf_liveupdate_init(void);
void dmabuf_liveupdate_cleanup(void);
#else
static inline int dmabuf_liveupdate_init(void)
{
        return 0;
}

static inline void dmabuf_liveupdate_cleanup(void)
{
}
#endif /* CONFIG_DMABUF_LIVEUPDATE */
#endif /* DMABUF_LIVEUPDATE_H */
