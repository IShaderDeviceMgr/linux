// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! SEP mailbox message layout.
//!
//! Every message is one 64-bit word (`msg1` is always zero). Byte 0 is the
//! endpoint; the layout of the rest depends on the endpoint. The generic
//! layout below is used by the control, discovery, shared-memory and boot
//! endpoints.

use kernel::soc::apple::mailbox::Message;

pub(crate) const EP_CONTROL: u8 = 0x00;
pub(crate) const EP_SBIO: u8 = 0x08;
pub(crate) const EP_SCRD: u8 = 0x0a;
pub(crate) const EP_SKS: u8 = 0x12;
pub(crate) const EP_XARM: u8 = 0x13;
pub(crate) const EP_PNON: u8 = 0x15;
pub(crate) const EP_DISCOVER: u8 = 0xfd;
pub(crate) const EP_SHMEM: u8 = 0xfe;
pub(crate) const EP_BOOT: u8 = 0xff;

const TAG_SHIFT: u32 = 8;
const TYPE_SHIFT: u32 = 16;
const PARAM_SHIFT: u32 = 24;
const DATA_SHIFT: u32 = 32;

/// IOVAs and sizes are passed in 4 KiB units, whatever the CPU page size.
pub(crate) const IOVA_SHIFT: u32 = 12;

pub(crate) const BOOT_TZ0: u8 = 0x05;
pub(crate) const BOOT_IMG4: u8 = 0x06;
pub(crate) const SHMEM_SET: u8 = 0x18;
pub(crate) const BOOT_TZ0_ACK1: u8 = 0x69;
pub(crate) const BOOT_TZ0_ACK2: u8 = 0xd2;
pub(crate) const BOOT_IMG4_ACK: u8 = 0x6a;

/// Discovery message types: both advertise the endpoint in `param`.
pub(crate) const DISCOVER_DESCRIPTOR: u8 = 0x00;
pub(crate) const DISCOVER_CONFIG: u8 = 0x01;

/// Control replies carry this type and echo the request's tag.
pub(crate) const CONTROL_REPLY: u8 = 0x01;

#[derive(Clone, Copy)]
pub(crate) struct Fields {
    pub(crate) ep: u8,
    pub(crate) tag: u8,
    pub(crate) ty: u8,
    pub(crate) param: u8,
    pub(crate) data: u32,
}

pub(crate) const fn decode(msg: &Message) -> Fields {
    let w = msg.msg0;
    Fields {
        ep: w as u8,
        tag: (w >> TAG_SHIFT) as u8,
        ty: (w >> TYPE_SHIFT) as u8,
        param: (w >> PARAM_SHIFT) as u8,
        data: (w >> DATA_SHIFT) as u32,
    }
}

pub(crate) const fn encode(ep: u8, tag: u8, ty: u8, param: u8, data: u32) -> Message {
    Message {
        msg0: (ep as u64)
            | ((tag as u64) << TAG_SHIFT)
            | ((ty as u64) << TYPE_SHIFT)
            | ((param as u64) << PARAM_SHIFT)
            | ((data as u64) << DATA_SHIFT),
        msg1: 0,
    }
}

/// An IOVA as the 32-bit page number the SEP expects, or `None` if it does
/// not fit or is not 4 KiB aligned.
pub(crate) fn iova_field(iova: u64) -> Option<u32> {
    if iova & ((1 << IOVA_SHIFT) - 1) != 0 {
        return None;
    }
    u32::try_from(iova >> IOVA_SHIFT).ok()
}

/// The four printable characters of a discovery name, or '?' for the rest.
pub(crate) fn fourcc(data: u32) -> [u8; 4] {
    let mut name = data.to_be_bytes();
    for c in name.iter_mut() {
        if !c.is_ascii_graphic() {
            *c = b'?';
        }
    }
    name
}

// The TZ0 word the upstream stub sent, as a regression check on the layout.
kernel::static_assert!(encode(EP_BOOT, 0, BOOT_TZ0, 0, 0).msg0 == 0x0005_00ff);
kernel::static_assert!(
    decode(&encode(EP_CONTROL, 0x12, 0x34, 0x56, 0x789a_bcde)).data == 0x789a_bcde
);
