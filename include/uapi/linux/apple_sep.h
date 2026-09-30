/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note OR MIT */
/*
 * Apple SEP transport: userspace interface of drivers/soc/apple/sep.
 *
 * The kernel only moves messages. The single privileged client (sepd) owns
 * storage and policy: it answers the SEP's xART storage requests and, in later
 * revisions, drives the key store and Touch ID.
 *
 * /dev/apple-sep may be open once at a time and needs CAP_SYS_ADMIN. All
 * operations are ioctls; APPLE_SEP_IOC_NEXT_EVENT blocks (interruptibly).
 */

#ifndef _UAPI_LINUX_APPLE_SEP_H
#define _UAPI_LINUX_APPLE_SEP_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define APPLE_SEP_ABI_VERSION		1

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

#define APPLE_SEP_IOC_MAGIC		0xA9

#define APPLE_SEP_IOC_INFO		_IOR(APPLE_SEP_IOC_MAGIC, 0x00, struct apple_sep_info)
#define APPLE_SEP_IOC_EP_ENABLE		_IOWR(APPLE_SEP_IOC_MAGIC, 0x01, struct apple_sep_ep_enable)
#define APPLE_SEP_IOC_NEXT_EVENT	_IOWR(APPLE_SEP_IOC_MAGIC, 0x02, struct apple_sep_event)
#define APPLE_SEP_IOC_XART_REPLY	_IOW(APPLE_SEP_IOC_MAGIC, 0x03, struct apple_sep_xart_reply)

#endif /* _UAPI_LINUX_APPLE_SEP_H */
