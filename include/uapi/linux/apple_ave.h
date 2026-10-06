/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note OR MIT */
/*
 * Apple AVE2 video encoder: userspace interface of drivers/soc/apple/ave.
 *
 * Userspace (a VA-API driver) builds the firmware's parameter blocks; the
 * kernel owns every device address and buffer size in them. Each open file
 * is one encoding session.
 *
 * Bring-up interface: /dev/apple-ave needs CAP_SYS_ADMIN, because the kernel
 * does not yet validate every field of the parameter blocks that changes how
 * much memory the firmware touches. Only H.264 is accepted for now.
 *
 * Flow: SESSION_CREATE (the kernel allocates the firmware buffers and opens
 * a firmware client), then INIT with the codec's init block. Closing the
 * file tears the session down.
 */

#ifndef _UAPI_LINUX_APPLE_AVE_H
#define _UAPI_LINUX_APPLE_AVE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define APPLE_AVE_ABI_VERSION		1

/* apple_ave_session_create.codec */
#define APPLE_AVE_CODEC_H264		0
#define APPLE_AVE_CODEC_HEVC		1

/* Size of the H.264 init block (firmware command AVC_INIT). */
#define APPLE_AVE_H264_INIT_SIZE	0x10e10

struct apple_ave_session_create {
	/* in */
	__u32 codec;		/* APPLE_AVE_CODEC_* */
	__u32 width;		/* 64..4096, even */
	__u32 height;		/* 64..4096, even */
	__u32 flags;		/* must be 0 */
	/* out */
	__u32 abi_version;
	__u32 client;		/* firmware client id */
	__u32 init_size;	/* exact size APPLE_AVE_IOC_INIT expects */
	__u32 coded_num;	/* bitstream buffers the kernel allocated */
	__u32 coded_size;	/* bytes each */
	__u32 reserved[7];	/* must be 0 */
};

struct apple_ave_init {
	__u64 block_ptr;	/* user address of the init block */
	__u32 block_size;	/* must equal init_size */
	__u32 fw_status;	/* out: firmware status, 0xee0000 = success */
};

#define APPLE_AVE_IOC_MAGIC		0xae

#define APPLE_AVE_IOC_SESSION_CREATE \
	_IOWR(APPLE_AVE_IOC_MAGIC, 0x00, struct apple_ave_session_create)
#define APPLE_AVE_IOC_INIT \
	_IOWR(APPLE_AVE_IOC_MAGIC, 0x01, struct apple_ave_init)

#endif /* _UAPI_LINUX_APPLE_AVE_H */
