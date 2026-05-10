#include <sys/resource.h>
#include <net/if.h>
#include "rxe_pkg_kernel.skel.h"

#include <linux/ip.h>
#include <linux/udp.h>
#include <ctype.h>

#include <net/ethernet.h>
#include <arpa/inet.h>

typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

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

static void print_bpf_output(void *data, __u32 size)
{
	struct iphdr *iph = (struct iphdr *)data;
	struct udphdr *udp_hdr;
	struct rxe_bth *bth;

	print_ipaddr(iph);
	udp_hdr = (struct udphdr *)(data + sizeof(struct iphdr));
	printf("udp hdr: \n");
	print_udphdr(udp_hdr);
	bth = (struct rxe_bth *)(data + sizeof(struct iphdr) + sizeof(struct udphdr));
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

static int handle_event(void *ctx, void *data, long unsigned int data_sz) {
	print_bpf_output(data+sizeof(struct ethhdr),
			 data_sz-sizeof(struct ethhdr));
	return 0;
}

int main() {
	struct rxe_pkg_kernel_dump *skel;
	int err;
	struct ring_buffer *ringbuf = NULL;
	struct rlimit rlim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		perror("setrlimit failed");
		return 1;
	}

	skel = rxe_pkg_kernel_dump__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	int ifindex = if_nametoindex("nk1");
	if (ifindex == 0) {
		perror("if_nametoindex nk1 failed");
		return 1;
	}

	skel->links.handle_netkit_ingress = bpf_program__attach_netkit(
		skel->progs.handle_netkit_ingress, ifindex, NULL);

	if (!skel->links.handle_netkit_ingress) {
		fprintf(stderr, "Failed to attach to netkit nk1\n");
		goto cleanup;
	}

	err = rxe_pkg_kernel_dump__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb),
				   handle_event, NULL, NULL);

	while (1) {
		err = ring_buffer__poll(ringbuf, 100 /* timeout */);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "poll error\n");
			break;
		}
	}

cleanup:
	ring_buffer__free(ringbuf);
	rxe_pkg_kernel_dump__destroy(skel);
	return 0;
}
