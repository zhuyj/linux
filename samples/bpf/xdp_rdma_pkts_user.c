// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <errno.h>
#include <assert.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <libgen.h>
#include <linux/if_link.h>

#include "perf-sys.h"

#include <linux/ip.h>
#include <linux/udp.h>
#include <ctype.h>

typedef unsigned char __u8;

typedef short unsigned int __u16;

typedef unsigned int __u32;

typedef long long unsigned int __u64;

typedef __u8 u8;

typedef __u16 u16;

typedef __u32 u32;

typedef __u64 u64;

static int if_idx;
static char *if_name;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static __u32 prog_id;
static struct perf_buffer *pb = NULL;

static int do_attach(int idx, int fd, const char *name)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	int err;

	err = bpf_xdp_attach(idx, fd, xdp_flags|XDP_FLAGS_RDMA, NULL);
	if (err < 0) {
		printf("ERROR: failed to attach program to %s\n", name);
		return err;
	}

	err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
	if (err) {
		printf("can't get prog info - %s\n", strerror(errno));
		return err;
	}
	prog_id = info.id;

	return err;
}

static int do_detach(int idx, const char *name)
{
	__u32 curr_prog_id = 0;
	int err = 0;

	err = bpf_xdp_query_id(idx, xdp_flags, &curr_prog_id);
	if (err) {
		printf("bpf_get_link_xdp_id failed\n");
		return err;
	}
	if (prog_id == curr_prog_id) {
		err = bpf_xdp_detach(idx, xdp_flags|XDP_FLAGS_RDMA, NULL);
		if (err < 0)
			printf("ERROR: failed to detach prog from %s\n", name);
	} else if (!curr_prog_id) {
		printf("couldn't find a prog id on a %s\n", name);
	} else {
		printf("program on interface changed, not removing\n");
	}

	return err;
}

#define SAMPLE_SIZE	4096ul
#include <arpa/inet.h>
struct rxe_bth {
	__u8		opcode;
	__u8		flags;
	__be16		pkey;
	__be32		qpn;
	__be32		apsn;
};

struct rxe_immdt {
	__be32		imm;
};

struct rxe_reth {
	__be64		va;
	__be32		rkey;
	__be32		len;
};

struct rxe_aeth {
	__be32		smsn;
};

/******************************************************************************
 * Atomic Ack Extended Transport Header
 ******************************************************************************/
struct rxe_atmack {
	__be64		orig;
};

/******************************************************************************
 * Invalidate Extended Transport Header
 ******************************************************************************/
struct rxe_ieth {
	__be32		rkey;
};

/******************************************************************************
 * Datagram Extended Transport Header
 ******************************************************************************/
struct rxe_deth {
	__be32	qkey;
	__be32	sqp;
};

#define IB_OPCODE(transport, op) \
	IB_OPCODE_ ## transport ## _ ## op = \
		IB_OPCODE_ ## transport + IB_OPCODE_ ## op

enum {
	/* transport types -- just used to define real constants */
	IB_OPCODE_RC                                = 0x00,
	IB_OPCODE_UC                                = 0x20,
	IB_OPCODE_RD                                = 0x40,
	IB_OPCODE_UD                                = 0x60,
	/* per IBTA 1.3 vol 1 Table 38, A10.3.2 */
	IB_OPCODE_CNP                               = 0x80,
	/* Manufacturer specific */
	IB_OPCODE_MSP                               = 0xe0,

	/* operations -- just used to define real constants */
	IB_OPCODE_SEND_FIRST                        = 0x00,
	IB_OPCODE_SEND_MIDDLE                       = 0x01,
	IB_OPCODE_SEND_LAST                         = 0x02,
	IB_OPCODE_SEND_LAST_WITH_IMMEDIATE          = 0x03,
	IB_OPCODE_SEND_ONLY                         = 0x04,
	IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE          = 0x05,
	IB_OPCODE_RDMA_WRITE_FIRST                  = 0x06,
	IB_OPCODE_RDMA_WRITE_MIDDLE                 = 0x07,
	IB_OPCODE_RDMA_WRITE_LAST                   = 0x08,
	IB_OPCODE_RDMA_WRITE_LAST_WITH_IMMEDIATE    = 0x09,
	IB_OPCODE_RDMA_WRITE_ONLY                   = 0x0a,
	IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE    = 0x0b,
	IB_OPCODE_RDMA_READ_REQUEST                 = 0x0c,
	IB_OPCODE_RDMA_READ_RESPONSE_FIRST          = 0x0d,
	IB_OPCODE_RDMA_READ_RESPONSE_MIDDLE         = 0x0e,
	IB_OPCODE_RDMA_READ_RESPONSE_LAST           = 0x0f,
	IB_OPCODE_RDMA_READ_RESPONSE_ONLY           = 0x10,
	IB_OPCODE_ACKNOWLEDGE                       = 0x11,
	IB_OPCODE_ATOMIC_ACKNOWLEDGE                = 0x12,
	IB_OPCODE_COMPARE_SWAP                      = 0x13,
	IB_OPCODE_FETCH_ADD                         = 0x14,
	/* opcode 0x15 is reserved */
	IB_OPCODE_SEND_LAST_WITH_INVALIDATE         = 0x16,
	IB_OPCODE_SEND_ONLY_WITH_INVALIDATE         = 0x17,

	/* real constants follow -- see comment about above IB_OPCODE()
	   macro for more details */

	/* RC */
	IB_OPCODE(RC, SEND_FIRST),
	IB_OPCODE(RC, SEND_MIDDLE),
	IB_OPCODE(RC, SEND_LAST),
	IB_OPCODE(RC, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RC, SEND_ONLY),
	IB_OPCODE(RC, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_WRITE_FIRST),
	IB_OPCODE(RC, RDMA_WRITE_MIDDLE),
	IB_OPCODE(RC, RDMA_WRITE_LAST),
	IB_OPCODE(RC, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_WRITE_ONLY),
	IB_OPCODE(RC, RDMA_WRITE_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_READ_REQUEST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_FIRST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_MIDDLE),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_LAST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_ONLY),
	IB_OPCODE(RC, ACKNOWLEDGE),
	IB_OPCODE(RC, ATOMIC_ACKNOWLEDGE),
	IB_OPCODE(RC, COMPARE_SWAP),
	IB_OPCODE(RC, FETCH_ADD),
	IB_OPCODE(RC, SEND_LAST_WITH_INVALIDATE),
	IB_OPCODE(RC, SEND_ONLY_WITH_INVALIDATE),

	/* UC */
	IB_OPCODE(UC, SEND_FIRST),
	IB_OPCODE(UC, SEND_MIDDLE),
	IB_OPCODE(UC, SEND_LAST),
	IB_OPCODE(UC, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(UC, SEND_ONLY),
	IB_OPCODE(UC, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(UC, RDMA_WRITE_FIRST),
	IB_OPCODE(UC, RDMA_WRITE_MIDDLE),
	IB_OPCODE(UC, RDMA_WRITE_LAST),
	IB_OPCODE(UC, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(UC, RDMA_WRITE_ONLY),
	IB_OPCODE(UC, RDMA_WRITE_ONLY_WITH_IMMEDIATE),

	/* RD */
	IB_OPCODE(RD, SEND_FIRST),
	IB_OPCODE(RD, SEND_MIDDLE),
	IB_OPCODE(RD, SEND_LAST),
	IB_OPCODE(RD, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RD, SEND_ONLY),
	IB_OPCODE(RD, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_WRITE_FIRST),
	IB_OPCODE(RD, RDMA_WRITE_MIDDLE),
	IB_OPCODE(RD, RDMA_WRITE_LAST),
	IB_OPCODE(RD, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_WRITE_ONLY),
	IB_OPCODE(RD, RDMA_WRITE_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_READ_REQUEST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_FIRST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_MIDDLE),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_LAST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_ONLY),
	IB_OPCODE(RD, ACKNOWLEDGE),
	IB_OPCODE(RD, ATOMIC_ACKNOWLEDGE),
	IB_OPCODE(RD, COMPARE_SWAP),
	IB_OPCODE(RD, FETCH_ADD),

	/* UD */
	IB_OPCODE(UD, SEND_ONLY),
	IB_OPCODE(UD, SEND_ONLY_WITH_IMMEDIATE)
};

enum rxe_hdr_type {
	RXE_LRH,
	RXE_GRH,
	RXE_BTH,
	RXE_RETH,
	RXE_AETH,
	RXE_ATMETH,
	RXE_ATMACK,
	RXE_IETH,
	RXE_RDETH,
	RXE_DETH,
	RXE_IMMDT,
	RXE_PAYLOAD,
	NUM_HDR_TYPES
};

#define RXE_NUM_OPCODE		256

struct rxe_opcode_info {
	char			*name;
	int			length;
	int			offset[NUM_HDR_TYPES];
};

/******************************************************************************
 * Atomic Extended Transport Header
 ******************************************************************************/
struct rxe_atmeth {
	__be64			va;
	__be32			rkey;
	__be64			swap_add;
	__be64			comp;
} __packed;

/******************************************************************************
 * Reliable Datagram Extended Transport Header
 ******************************************************************************/
struct rxe_rdeth {
	__be32			een;
};

enum rxe_hdr_length {
	RXE_BTH_BYTES		= sizeof(struct rxe_bth),
	RXE_DETH_BYTES		= sizeof(struct rxe_deth),
	RXE_IMMDT_BYTES		= sizeof(struct rxe_immdt),
	RXE_RETH_BYTES		= sizeof(struct rxe_reth),
	RXE_AETH_BYTES		= sizeof(struct rxe_aeth),
	RXE_ATMACK_BYTES	= sizeof(struct rxe_atmack),
	RXE_ATMETH_BYTES	= sizeof(struct rxe_atmeth),
	RXE_IETH_BYTES		= sizeof(struct rxe_ieth),
	RXE_RDETH_BYTES		= sizeof(struct rxe_rdeth),
};

struct rxe_opcode_info rxe_opcode[RXE_NUM_OPCODE] = {
	[IB_OPCODE_RC_SEND_FIRST]			= {
		.name	= "IB_OPCODE_RC_SEND_FIRST",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_MIDDLE]		= {
		.name	= "IB_OPCODE_RC_SEND_MIDDLE",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_LAST]			= {
		.name	= "IB_OPCODE_RC_SEND_LAST",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_ONLY]			= {
		.name	= "IB_OPCODE_RC_SEND_ONLY",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_FIRST]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_FIRST",
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_MIDDLE]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_MIDDLE",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_LAST]			= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_LAST",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_ONLY]			= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_ONLY",
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES +
					  RXE_RETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RETH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_REQUEST]			= {
		.name	= "IB_OPCODE_RC_RDMA_READ_REQUEST",
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST",
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_AETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST",
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_AETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY",
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_AETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RC_ACKNOWLEDGE",
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_AETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE",
		.length = RXE_BTH_BYTES + RXE_ATMACK_BYTES + RXE_AETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_AETH]	= RXE_BTH_BYTES,
			[RXE_ATMACK]	= RXE_BTH_BYTES +
					  RXE_AETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_ATMACK_BYTES +
					  RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_COMPARE_SWAP]			= {
		.name	= "IB_OPCODE_RC_COMPARE_SWAP",
		.length = RXE_BTH_BYTES + RXE_ATMETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_ATMETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_ATMETH_BYTES,
		}
	},
	[IB_OPCODE_RC_FETCH_ADD]			= {
		.name	= "IB_OPCODE_RC_FETCH_ADD",
		.length = RXE_BTH_BYTES + RXE_ATMETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_ATMETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_ATMETH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE]		= {
		.name	= "IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE",
		.length = RXE_BTH_BYTES + RXE_IETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_IETH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE]		= {
		.name	= "IB_OPCODE_RC_SEND_ONLY_INV",
		.length = RXE_BTH_BYTES + RXE_IETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_IETH_BYTES,
		}
	},

	/* UC */
	[IB_OPCODE_UC_SEND_FIRST]			= {
		.name	= "IB_OPCODE_UC_SEND_FIRST",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_MIDDLE]		= {
		.name	= "IB_OPCODE_UC_SEND_MIDDLE",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_LAST]			= {
		.name	= "IB_OPCODE_UC_SEND_LAST",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_ONLY]			= {
		.name	= "IB_OPCODE_UC_SEND_ONLY",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_FIRST]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_FIRST",
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_MIDDLE]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_MIDDLE",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_LAST]			= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_LAST",
		.length = RXE_BTH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_IMMDT]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_ONLY]			= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_ONLY",
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_RETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RETH]	= RXE_BTH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES +
					  RXE_RETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RETH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},

	/* RD */
	[IB_OPCODE_RD_SEND_FIRST]			= {
		.name	= "IB_OPCODE_RD_SEND_FIRST",
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_MIDDLE]		= {
		.name	= "IB_OPCODE_RD_SEND_MIDDLE",
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_LAST]			= {
		.name	= "IB_OPCODE_RD_SEND_LAST",
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES +
			  RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_ONLY]			= {
		.name	= "IB_OPCODE_RD_SEND_ONLY",
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES +
			  RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_FIRST]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_FIRST",
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES +
			  RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_RETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES +
					  RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_MIDDLE]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_MIDDLE",
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_LAST]			= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_LAST",
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES +
			  RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_ONLY]			= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_ONLY",
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES +
			  RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_RETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES +
					  RXE_RETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_RETH_BYTES +
			  RXE_DETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_RETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES +
					  RXE_RETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES +
					  RXE_RETH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_REQUEST]			= {
		.name	= "IB_OPCODE_RD_RDMA_READ_REQUEST",
		.length = RXE_BTH_BYTES + RXE_RETH_BYTES + RXE_DETH_BYTES +
			  RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_RETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RETH_BYTES +
					  RXE_DETH_BYTES +
					  RXE_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_FIRST]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_FIRST",
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_AETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE",
		.length = RXE_BTH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_LAST]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_LAST",
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_AETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_ONLY]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_ONLY",
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_AETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RD_ACKNOWLEDGE",
		.length = RXE_BTH_BYTES + RXE_AETH_BYTES + RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_AETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE",
		.length = RXE_BTH_BYTES + RXE_ATMACK_BYTES + RXE_AETH_BYTES +
			  RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_AETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_ATMACK]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_COMPARE_SWAP]			= {
		.name	= "RD_COMPARE_SWAP",
		.length = RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES +
			  RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_ATMETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_ATMETH_BYTES +
					  RXE_DETH_BYTES +
					  RXE_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_FETCH_ADD]			= {
		.name	= "IB_OPCODE_RD_FETCH_ADD",
		.length = RXE_BTH_BYTES + RXE_ATMETH_BYTES + RXE_DETH_BYTES +
			  RXE_RDETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_RDETH]	= RXE_BTH_BYTES,
			[RXE_DETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES,
			[RXE_ATMETH]	= RXE_BTH_BYTES +
					  RXE_RDETH_BYTES +
					  RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_ATMETH_BYTES +
					  RXE_DETH_BYTES +
					  RXE_RDETH_BYTES,
		}
	},

	/* UD */
	[IB_OPCODE_UD_SEND_ONLY]			= {
		.name	= "IB_OPCODE_UD_SEND_ONLY",
		.length = RXE_BTH_BYTES + RXE_DETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_DETH]	= RXE_BTH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_DETH_BYTES,
		}
	},
	[IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE",
		.length = RXE_BTH_BYTES + RXE_IMMDT_BYTES + RXE_DETH_BYTES,
		.offset = {
			[RXE_BTH]	= 0,
			[RXE_DETH]	= RXE_BTH_BYTES,
			[RXE_IMMDT]	= RXE_BTH_BYTES +
					  RXE_DETH_BYTES,
			[RXE_PAYLOAD]	= RXE_BTH_BYTES +
					  RXE_DETH_BYTES +
					  RXE_IMMDT_BYTES,
		}
	},

};

static inline u8 __bth_opcode(void *arg)
{
	struct rxe_bth *bth = arg;

	return bth->opcode;
}

static inline u8 bth_opcode(struct rxe_bth *bth)
{
	return __bth_opcode(bth);
}

static inline u8 bth_flags(struct rxe_bth *bth)
{
	return bth->flags;;
}

static inline u16 __bth_pkey(void *arg)
{
	struct rxe_bth *bth = arg;

	return ntohs(bth->pkey);
}

static inline u16 bth_pkey(struct rxe_bth *bth)
{
	return __bth_pkey(bth);
}

#define BTH_QPN_MASK		(0x00ffffff)
#define BTH_PSN_MASK		((1 << 24) - 1)

static inline u32 __bth_qpn(void *arg)
{
	struct rxe_bth *bth = arg;

	return BTH_QPN_MASK & ntohl(bth->qpn);
}

static inline u32 bth_qpn(struct rxe_bth *bth)
{
	return __bth_qpn(bth);
}

static inline u32 __bth_psn(void *arg)
{
	struct rxe_bth *bth = arg;

	return BTH_PSN_MASK & ntohl(bth->apsn);
}

static inline u32 bth_psn(struct rxe_bth *bth)
{
	return __bth_psn(bth);
}

static inline void print_bth(struct rxe_bth *bth)
{
	printf("struct rxe_bth {\n");
	printf("\t__u8            opcode; 0x%x\n", bth_opcode(bth));
	printf("\t__u8            flags;  0x%x\n", bth_flags(bth));
	printf("\t__be16          pkey;   0x%x\n", bth_pkey(bth));
	printf("\t__be32          qpn;    0x%x\n", bth_qpn(bth));
	printf("\t__be32          apsn;   0x%x\n", bth_psn(bth));
	printf("};\n");
}

static inline void print_reth(struct rxe_reth *reth)
{
	printf("struct rxe_reth {\n");
	printf("\t__be64		va;\n");
	printf("\t__be32		rkey;\n");
	printf("\t__be32		len;\n");
	printf("};\n");
}

#define AETH_MSN_MASK		(0x00ffffff)

static inline u32 aeth_msn(struct rxe_aeth *aeth)
{
	return AETH_MSN_MASK & ntohl(aeth->smsn);
}

static inline void print_aeth(struct rxe_aeth *aeth)
{
	printf("struct rxe_aeth {\n");
	printf("\t___be32		smsn; 0x%x\n", aeth_msn(aeth));
	printf("};\n");
}

static inline u64 atmeth_va(struct rxe_atmeth *atmeth)
{
	return ntohl(atmeth->va);
}

static inline u32 atmeth_rkey(struct rxe_atmeth *atmeth)
{
	return ntohl(atmeth->rkey);
}

static inline u64 atmeth_swap_add(struct rxe_atmeth *atmeth)
{
	return ntohl(atmeth->swap_add);
}

static inline u64 atmeth_comp(struct rxe_atmeth *atmeth)
{
	return ntohl(atmeth->comp);
}

static inline void print_atmeth(struct rxe_atmeth *atmeth)
{
	printf("struct rxe_atmeth {\n");
	printf("\t__be64		va;       0x%llx\n", atmeth_va(atmeth));
	printf("\t__be32		rkey;     0x%x\n", atmeth_rkey(atmeth));
	printf("\t__be64		swap_add; 0x%llx\n", atmeth_swap_add(atmeth));
	printf("\t__be64		comp;     0x%llx\n", atmeth_comp(atmeth));
	printf("} __packed;\n");
}

static inline u64 atmack_orig(struct rxe_atmack *atmack)
{
	return ntohl(atmack->orig);
}

static inline void print_atmack(struct rxe_atmack *atmack)
{
	printf("struct rxe_atmack {\n");
	printf("\t__be64		orig; 0x%llx\n", atmack_orig(atmack));
	printf("};\n");
}

static inline u32 ieth_rkey(struct rxe_ieth *ieth)
{
	return ntohl(ieth->rkey);
}

static inline void print_ieth(struct rxe_ieth *ieth)
{
	printf("struct rxe_ieth {\n");
	printf("\t__be32		rkey; 0x%x\n", ieth_rkey(ieth));
	printf("};\n");
}

#define RDETH_EEN_MASK		(0x00ffffff)

static inline u32 rdeth_een(struct rxe_rdeth *rdeth)
{
	return RDETH_EEN_MASK & ntohl(rdeth->een);
}

static inline void print_rdeth(struct rxe_rdeth *rdeth)
{
	printf("struct rxe_rdeth {\n");
	printf("\t__be32		een; 0x%x\n", rdeth_een(rdeth));
	printf("};\n");
}

#define DETH_SQP_MASK		(0x00ffffff)

static inline u32 deth_qkey(struct rxe_deth *deth)
{
	return ntohl(deth->qkey);
}

static inline u32 deth_sqp(struct rxe_deth *deth)
{
	return DETH_SQP_MASK & ntohl(deth->sqp);
}

static inline void print_deth(struct rxe_deth *deth)
{
	printf("struct rxe_deth {\n");
	printf("\t__be32	qkey; 0x%x\n", deth_qkey(deth));
	printf("\t__be32	sqp;  0x%x\n", deth_sqp(deth));
	printf("};\n");
}

static inline __be32 immdt_imm(struct rxe_immdt *immdt)
{
	return immdt->imm;
}

static inline void print_immdt(struct rxe_immdt *immdt)
{
	printf("struct rxe_immdt {\n");
	printf("\t__be32		imm; 0x%x\n", immdt_imm(immdt));
	printf("};\n");
}

static inline void print_ipaddr(struct iphdr *iph)
{
	unsigned char *ip_addr = (unsigned char *)&iph->saddr;

	printf("struct iphdr {\n");
	printf("\t__be32	saddr; %d.%d.%d.%d\n", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
	ip_addr = (unsigned char *)&iph->daddr;
	printf("\t__be32	daddr; %d.%d.%d.%d\n", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
	printf("};\n");
}

static inline void print_udphdr(struct udphdr *udp_hdr)
{
	printf("struct udphdr {\n");
	printf("\t__be16	source; %d\n", ntohs(udp_hdr->source));
	printf("\t__be16	dest;   %d\n", ntohs(udp_hdr->dest));
	printf("\t__be16	len;    %d\n", ntohs(udp_hdr->len));
	printf("\t__sum16	check;  %d\n", ntohs(udp_hdr->check));
	printf("};\n");
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
	struct {
		__u16 cookie;
		__u16 pkt_len;
		__u8  pkt_data[SAMPLE_SIZE];
	} __packed *e = data;

	struct iphdr *iph = (struct iphdr *)e->pkt_data;
	struct udphdr *udp_hdr;
	struct rxe_bth *bth;

	if (e->cookie != 0xdead) {
		printf("BUG cookie %x sized %d\n", e->cookie, size);
		return;
	}

	printf("Pkt len: %-5d bytes. IP hdr: \n", e->pkt_len);
	if (iph->protocol != 0x11) {
		printf("\n");
		return;
	}
	print_ipaddr(iph);
	udp_hdr = (struct udphdr *)(e->pkt_data + sizeof(struct iphdr));
	printf("udp hdr: \n");
	print_udphdr(udp_hdr);
	bth = (struct rxe_bth *)(e->pkt_data + sizeof(struct iphdr) + sizeof(struct udphdr));
	printf("%s\n", rxe_opcode[bth->opcode].name);
	print_bth(bth);

	for (int i=RXE_BTH+1; i<NUM_HDR_TYPES; i++) {
		int offset = rxe_opcode[bth->opcode].offset[i];
		if (offset) {
			char *cur_p = (char *)bth + offset;
			switch(i) {
				case	RXE_RETH:
					printf("RXE_RETH\n");
					struct rxe_reth *reth = (struct rxe_reth *)cur_p;
					print_reth(reth);
					break;

				case	RXE_AETH:
					printf("RXE_AETH\n");
					struct rxe_aeth *aeth = (struct rxe_aeth*)cur_p;
					print_aeth(aeth);
					break;

				case	RXE_ATMETH:
					printf("RXE_ATMETH\n");
					struct rxe_atmeth *atmeth = (struct rxe_atmeth *)cur_p;
					print_atmeth(atmeth);
					break;

				case	RXE_ATMACK:
					printf("RXE_ATMACK\n");
					struct rxe_atmack *atmack = (struct rxe_atmack *)cur_p;
					print_atmack(atmack);
					break;

				case	RXE_IETH:
					printf("RXE_IETH\n");
					struct rxe_ieth *ieth = (struct rxe_ieth *)cur_p;
					print_ieth(ieth);
					break;

				case	RXE_RDETH:
					printf("RXE_RDETH\n");
					struct rxe_rdeth *rdeth = (struct rxe_rdeth *)cur_p;
					print_rdeth(rdeth);
					break;

				case	RXE_DETH:
					printf("RXE_DETH\n");
					struct rxe_deth *deth = (struct rxe_deth *)cur_p;
					print_deth(deth);
					break;

				case	RXE_IMMDT:
					printf("RXE_IMMDT\n");
					struct rxe_immdt *immdt = (struct rxe_immdt *)cur_p;
					print_immdt(immdt);
					break;

				case	RXE_PAYLOAD:
					printf("RXE_PAYLOAD\n");
					int len = ntohs(udp_hdr->len) - rxe_opcode[bth->opcode].length;
					for (int j=0; j<len; j++) {
						if (isprint(cur_p[j])) {
							printf("%c", cur_p[j]);
						} else {
							printf("%02x", cur_p[j]);
						}
					}
					printf("\n");
					break;
				default:
					break;
			}
		}
	}

	printf("\n");
}

static void sig_handler(int signo)
{
	do_detach(if_idx, if_name);
	perf_buffer__free(pb);
	exit(0);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"%s: %s [OPTS] <ifname|ifindex>\n\n"
		"OPTS:\n"
		"    -F    force loading prog\n",
		__func__, prog);
}

int main(int argc, char **argv)
{
	const char *optstr = "FS";
	int prog_fd, map_fd, opt;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	char filename[256];
	int ret, err;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (!(xdp_flags & XDP_FLAGS_SKB_MODE))
		xdp_flags |= XDP_FLAGS_DRV_MODE;

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj))
		return 1;

	prog = bpf_object__next_program(obj, NULL);
	bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

	err = bpf_object__load(obj);
	if (err)
		return 1;

	prog_fd = bpf_program__fd(prog);

	map = bpf_object__next_map(obj, NULL);
	if (!map) {
		printf("finding a map in obj file failed\n");
		return 1;
	}
	map_fd = bpf_map__fd(map);

	if_idx = if_nametoindex(argv[optind]);
	if (!if_idx)
		if_idx = strtoul(argv[optind], NULL, 0);

	if (!if_idx) {
		fprintf(stderr, "Invalid ifname\n");
		return 1;
	}
	if_name = argv[optind];
	err = do_attach(if_idx, prog_fd, if_name);
	if (err)
		return err;

	if (signal(SIGINT, sig_handler) ||
	    signal(SIGHUP, sig_handler) ||
	    signal(SIGTERM, sig_handler)) {
		perror("signal");
		return 1;
	}

	pb = perf_buffer__new(map_fd, 8, print_bpf_output, NULL, NULL, NULL);
	err = libbpf_get_error(pb);
	if (err) {
		perror("perf_buffer setup failed");
		return 1;
	}

	while ((ret = perf_buffer__poll(pb, 1000)) >= 0) {
	}

	kill(0, SIGINT);
	return ret;
}
