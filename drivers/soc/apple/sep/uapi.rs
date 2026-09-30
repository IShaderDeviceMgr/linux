// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Rust mirror of `include/uapi/linux/apple_sep.h`. Keep the two in step; the
//! size assertions below catch layout drift.

use kernel::ioctl::{_IOR, _IOW, _IOWR};
use kernel::transmute::{AsBytes, FromBytes};

pub(crate) const ABI_VERSION: u32 = 2;
pub(crate) const XART_MAX: usize = 0x8000;

pub(crate) const EVENT_XART: u32 = 1;
pub(crate) const EVENT_ENDPOINT: u32 = 2;

pub(crate) const XART_FAILED: u8 = 0x16;

#[repr(C)]
pub(crate) struct Info {
    pub(crate) abi_version: u32,
    pub(crate) phase: u32,
    pub(crate) advertised: [u8; 32],
    pub(crate) enabled: [u8; 32],
    pub(crate) names: [[u8; 4]; 256],
}

#[repr(C)]
pub(crate) struct EpEnable {
    pub(crate) ep: u8,
    pub(crate) reserved: [u8; 3],
    pub(crate) in_size: u32,
    pub(crate) out_size: u32,
}

#[repr(C)]
pub(crate) struct Event {
    pub(crate) payload_ptr: u64,
    pub(crate) payload_cap: u32,
    pub(crate) timeout_ms: u32,
    pub(crate) ty: u32,
    pub(crate) payload_len: u32,
    /// `xart`: tag, op, len (LE u16), args[3], reserved.
    /// `endpoint`: ep, reserved[3], name[4].
    pub(crate) body: [u8; 8],
}

#[repr(C)]
pub(crate) struct XartReply {
    pub(crate) payload_ptr: u64,
    pub(crate) payload_len: u32,
    pub(crate) tag: u8,
    pub(crate) status: u8,
    pub(crate) len: u16,
    pub(crate) args: [u8; 3],
    pub(crate) reserved: [u8; 5],
}

#[repr(C)]
pub(crate) struct SksCall {
    pub(crate) req_ptr: u64,
    pub(crate) resp_ptr: u64,
    pub(crate) req_len: u32,
    pub(crate) resp_cap: u32,
    pub(crate) timeout_ms: u32,
    pub(crate) selector: u8,
    pub(crate) reserved: [u8; 3],
    pub(crate) status: i32,
    pub(crate) resp_len: u32,
}

pub(crate) const SCRATCH_SIZE: usize = 256;

#[repr(C)]
pub(crate) struct Scratch {
    pub(crate) data: [u8; SCRATCH_SIZE],
}

kernel::static_assert!(core::mem::size_of::<SksCall>() == 40);
kernel::static_assert!(core::mem::size_of::<Scratch>() == 256);
kernel::static_assert!(core::mem::size_of::<Info>() == 1096);
kernel::static_assert!(core::mem::size_of::<EpEnable>() == 12);
kernel::static_assert!(core::mem::size_of::<Event>() == 32);
kernel::static_assert!(core::mem::size_of::<XartReply>() == 24);

// SAFETY: plain integers and byte arrays with no padding (sizes asserted
// above), so every bit pattern is valid and the byte image is faithful.
unsafe impl FromBytes for EpEnable {}
// SAFETY: see above.
unsafe impl AsBytes for EpEnable {}
// SAFETY: see above.
unsafe impl AsBytes for Info {}
// SAFETY: see above.
unsafe impl FromBytes for Event {}
// SAFETY: see above.
unsafe impl AsBytes for Event {}
// SAFETY: see above.
unsafe impl FromBytes for XartReply {}
// SAFETY: see above.
unsafe impl FromBytes for SksCall {}
// SAFETY: see above.
unsafe impl AsBytes for SksCall {}
// SAFETY: see above.
unsafe impl FromBytes for Scratch {}
// SAFETY: see above.
unsafe impl AsBytes for Scratch {}

const MAGIC: u32 = 0xa9;

pub(crate) const IOC_INFO: u32 = _IOR::<Info>(MAGIC, 0x00);
pub(crate) const IOC_EP_ENABLE: u32 = _IOWR::<EpEnable>(MAGIC, 0x01);
pub(crate) const IOC_NEXT_EVENT: u32 = _IOWR::<Event>(MAGIC, 0x02);
pub(crate) const IOC_XART_REPLY: u32 = _IOW::<XartReply>(MAGIC, 0x03);
pub(crate) const IOC_SKS_CALL: u32 = _IOWR::<SksCall>(MAGIC, 0x04);
pub(crate) const IOC_SCRATCH_GET: u32 = _IOR::<Scratch>(MAGIC, 0x05);
pub(crate) const IOC_SCRATCH_SET: u32 = _IOW::<Scratch>(MAGIC, 0x06);
