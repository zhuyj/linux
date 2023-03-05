/*
 * Copyright (C) 2019 Intel Corporation
 *
 * For licensing information, see the file 'LICENSE' in the root folder
 */
#ifndef _IECM_ALLOC_H_
#define _IECM_ALLOC_H_

/* Memory types */
enum iecm_memset_type {
	IECM_NONDMA_MEM = 0,
	IECM_DMA_MEM
};

/* Memcpy types */
enum iecm_memcpy_type {
	IECM_NONDMA_TO_NONDMA = 0,
	IECM_NONDMA_TO_DMA,
	IECM_DMA_TO_DMA,
	IECM_DMA_TO_NONDMA
};

#endif /* _IECM_ALLOC_H_ */
