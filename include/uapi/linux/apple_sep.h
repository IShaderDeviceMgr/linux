/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note OR MIT */
/*
 * Apple SEP transport: userspace interface of drivers/soc/apple/sep.
 *
 * The kernel only moves messages. The single privileged client (sepd) owns
 * storage and policy: it answers the SEP's xART storage requests, drives the
 * key store and, later, Touch ID.
 *
 * /dev/apple-sep may be open once at a time and needs CAP_SYS_ADMIN. All
 * operations are ioctls; APPLE_SEP_IOC_NEXT_EVENT blocks (interruptibly).
 */

#ifndef _UAPI_LINUX_APPLE_SEP_H
#define _UAPI_LINUX_APPLE_SEP_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define APPLE_SEP_ABI_VERSION		3

/* Endpoints with out-of-line buffers that APPLE_SEP_IOC_EP_ENABLE accepts. */
#define APPLE_SEP_EP_SBIO		0x08
#define APPLE_SEP_EP_SCRD		0x0a
#define APPLE_SEP_EP_SKS		0x12
#define APPLE_SEP_EP_XARM		0x13

/* apple_sep_info.phase */
#define APPLE_SEP_PHASE_TZ0_SENT	0
#define APPLE_SEP_PHASE_SHMEM_SENT	1
#define APPLE_SEP_PHASE_RUNNING		2

struct apple_sep_info {
	__u32 abi_version;
	__u32 phase;
	__u8  advertised[32];		/* bitmap: endpoint advertised by the SEP */
	__u8  enabled[32];		/* bitmap: out-of-line buffers registered */
	__u8  names[256][4];		/* discovery name per endpoint, 0 if none */
};

struct apple_sep_ep_enable {
	__u8  ep;
	__u8  reserved[3];
	__u32 in_size;			/* out: host -> SEP buffer size */
	__u32 out_size;			/* out: SEP -> host buffer size */
};

/* apple_sep_event.type */
#define APPLE_SEP_EVENT_XART		1	/* an xART storage request */
#define APPLE_SEP_EVENT_ENDPOINT	2	/* an endpoint was advertised */

/* Maximum xART payload in either direction. */
#define APPLE_SEP_XART_MAX		0x8000

/*
 * The SEP did not visibly overwrite the consumed-buffer pattern within the
 * kernel's wait, so the payload may be stale. The request is delivered anyway;
 * the client decides (for a write, refusing is the safe answer).
 */
#define APPLE_SEP_XART_F_UNWRITTEN	0x01

struct apple_sep_event {
	/* in */
	__u64 payload_ptr;		/* user buffer for the request payload */
	__u32 payload_cap;		/* must be >= APPLE_SEP_XART_MAX */
	__u32 timeout_ms;		/* 0 = wait forever */
	/* out */
	__u32 type;
	__u32 payload_len;		/* bytes written to payload_ptr */
	union {
		struct {
			__u8  tag;
			__u8  op;
			__u16 len;	/* length field of the request word */
			__u8  args[3];
			__u8  flags;	/* APPLE_SEP_XART_F_* */
		} xart;
		struct {
			__u8  ep;
			__u8  reserved[3];
			__u8  name[4];
		} endpoint;
		__u8 raw[8];
	};
};

/* apple_sep_xart_reply.status */
#define APPLE_SEP_XART_OK		0x00
#define APPLE_SEP_XART_UNAVAILABLE	0x02
#define APPLE_SEP_XART_FAILED		0x16

struct apple_sep_xart_reply {
	__u64 payload_ptr;		/* bytes for the SEP's inbound buffer */
	__u32 payload_len;		/* <= APPLE_SEP_XART_MAX */
	__u8  tag;
	__u8  status;
	__u16 len;			/* length field of the reply word */
	__u8  args[3];
	__u8  reserved[5];
};

/*
 * One key-store (SKS, EP 0x12) request. The client builds the complete request
 * image (length-prefixed IPC header + body); the kernel picks the sequence
 * number, sends it, and returns the response image. Requires
 * APPLE_SEP_IOC_EP_ENABLE(APPLE_SEP_EP_SKS) first.
 *
 * A request that times out or is interrupted may still be running in the
 * SEP; the key store then refuses further calls (-EIO) until the late reply
 * arrives.
 */
struct apple_sep_sks_call {
	/* in */
	__u64 req_ptr;
	__u64 resp_ptr;
	__u32 req_len;			/* 0x54..=in_size */
	__u32 resp_cap;			/* >= out_size is always enough */
	__u32 timeout_ms;		/* 0 = 6000 */
	__u8  selector;
	__u8  reserved[3];
	/* out */
	__s32 status;			/* reply status byte, sign-extended */
	__u32 resp_len;			/* response image bytes copied */
};

/*
 * Per-SEP-boot scratch for the client. The kernel never interprets it; it
 * lives exactly as long as the SEP session, so a restarted client can tell
 * what it already did (for example, that the key store is initialised).
 */
#define APPLE_SEP_SCRATCH_SIZE		256

struct apple_sep_scratch {
	__u8 data[APPLE_SEP_SCRATCH_SIZE];
};

/*
 * One biometric-endpoint (SBIO, EP 0x08) operation: the request payload is
 * sent in chunks and the response reassembled by the kernel. Requires
 * APPLE_SEP_IOC_EP_ENABLE(APPLE_SEP_EP_SBIO) first. One at a time.
 */
#define APPLE_SEP_SBIO_MAX		0x4b000

/* apple_sep_sbio_call.result */
#define APPLE_SEP_SBIO_ANSWERED		0	/* status is the SEP's */
#define APPLE_SEP_SBIO_NO_STATUS	1	/* error marker without a status */
#define APPLE_SEP_SBIO_UNWRITTEN	2	/* chunk header never reached memory */

struct apple_sep_sbio_call {
	/* in */
	__u64 req_ptr;
	__u64 resp_ptr;
	__u32 req_len;			/* <= APPLE_SEP_SBIO_MAX */
	__u32 resp_cap;
	__u32 timeout_ms;		/* per wait; 0 = 5000 */
	__u16 opcode;
	__u16 reserved;
	/* out */
	__u32 result;			/* APPLE_SEP_SBIO_* */
	__u32 status;			/* with ANSWERED: 0 ok, 1, 0x16, 0x8002, 0x101... */
	__u32 resp_len;
	__u32 reserved2;
};

/*
 * The Touch ID sensor (the DT node the SEP node's apple,biometric-sensor
 * points at). Only handshake-sized reads are allowed from userspace
 * (APPLE_SEP_MESA_RX_MAX); fingerprint captures never leave the kernel.
 */
#define APPLE_SEP_MESA_POWER_OFF	0
#define APPLE_SEP_MESA_POWER_ON		1
#define APPLE_SEP_MESA_POWER_CYCLE	2

#define APPLE_SEP_MESA_XFER_DUPLEX	0	/* tx_len == rx_len, one transfer */
#define APPLE_SEP_MESA_XFER_TX		1	/* transmit only */
#define APPLE_SEP_MESA_XFER_TX_RX	2	/* tx, then rx, one CS assertion */

#define APPLE_SEP_MESA_TX_MAX		0x20000
#define APPLE_SEP_MESA_RX_MAX		0x4f

struct apple_sep_mesa_power {
	__u32 op;
};

struct apple_sep_mesa_xfer {
	__u64 tx_ptr;
	__u64 rx_ptr;
	__u32 tx_len;
	__u32 rx_len;
	__u32 mode;
	__u32 reserved;
};

#define APPLE_SEP_IOC_MAGIC		0xA9

#define APPLE_SEP_IOC_INFO		_IOR(APPLE_SEP_IOC_MAGIC, 0x00, struct apple_sep_info)
#define APPLE_SEP_IOC_EP_ENABLE		_IOWR(APPLE_SEP_IOC_MAGIC, 0x01, struct apple_sep_ep_enable)
#define APPLE_SEP_IOC_NEXT_EVENT	_IOWR(APPLE_SEP_IOC_MAGIC, 0x02, struct apple_sep_event)
#define APPLE_SEP_IOC_XART_REPLY	_IOW(APPLE_SEP_IOC_MAGIC, 0x03, struct apple_sep_xart_reply)
#define APPLE_SEP_IOC_SKS_CALL		_IOWR(APPLE_SEP_IOC_MAGIC, 0x04, struct apple_sep_sks_call)
#define APPLE_SEP_IOC_SCRATCH_GET	_IOR(APPLE_SEP_IOC_MAGIC, 0x05, struct apple_sep_scratch)
#define APPLE_SEP_IOC_SCRATCH_SET	_IOW(APPLE_SEP_IOC_MAGIC, 0x06, struct apple_sep_scratch)
#define APPLE_SEP_IOC_SBIO_CALL		_IOWR(APPLE_SEP_IOC_MAGIC, 0x07, struct apple_sep_sbio_call)
#define APPLE_SEP_IOC_MESA_POWER	_IOW(APPLE_SEP_IOC_MAGIC, 0x08, struct apple_sep_mesa_power)
#define APPLE_SEP_IOC_MESA_XFER		_IOW(APPLE_SEP_IOC_MAGIC, 0x09, struct apple_sep_mesa_xfer)

#endif /* _UAPI_LINUX_APPLE_SEP_H */
