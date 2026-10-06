// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Rust mirror of `include/uapi/linux/apple_ave.h`. Keep the two in step; the
//! size assertions below catch layout drift.

use kernel::ioctl::_IOWR;
use kernel::transmute::{AsBytes, FromBytes};

pub(crate) const ABI_VERSION: u32 = 1;

pub(crate) const CODEC_H264: u32 = 0;

pub(crate) const H264_INIT_SIZE: usize = 0x10e10;

#[repr(C)]
pub(crate) struct SessionCreate {
    pub(crate) codec: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) flags: u32,
    pub(crate) abi_version: u32,
    pub(crate) client: u32,
    pub(crate) init_size: u32,
    pub(crate) coded_num: u32,
    pub(crate) coded_size: u32,
    pub(crate) reserved: [u32; 7],
}

#[repr(C)]
pub(crate) struct Init {
    pub(crate) block_ptr: u64,
    pub(crate) block_size: u32,
    pub(crate) fw_status: u32,
}

kernel::static_assert!(core::mem::size_of::<SessionCreate>() == 64);
kernel::static_assert!(core::mem::size_of::<Init>() == 16);

// SAFETY: plain integers with no padding (sizes asserted above), so every
// bit pattern is valid and the byte image is faithful.
unsafe impl FromBytes for SessionCreate {}
// SAFETY: see above.
unsafe impl AsBytes for SessionCreate {}
// SAFETY: see above.
unsafe impl FromBytes for Init {}
// SAFETY: see above.
unsafe impl AsBytes for Init {}

const MAGIC: u32 = 0xae;

pub(crate) const IOC_SESSION_CREATE: u32 = _IOWR::<SessionCreate>(MAGIC, 0x00);
pub(crate) const IOC_INIT: u32 = _IOWR::<Init>(MAGIC, 0x01);
