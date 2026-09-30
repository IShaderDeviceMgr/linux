// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! XARM (EP 0x13): the SEP's xART storage requests.
//!
//! Word layout, request and reply alike (bytes of `msg0`):
//! `[ep, tag, op|status, len_lo, len_hi, a0, a1, a2]`. The request payload is
//! in the XARM outbound buffer, the reply payload in the inbound one. The
//! kernel only transports these; sepd answers them.

use crate::proto;
use kernel::soc::apple::mailbox::Message;

/// "Is protected data available?", the first request after boot. It carries
/// no payload, so it can be queued before the buffers are registered.
pub(crate) const OP_QUERY_PROTECTED: u8 = 0x0e;

/// Notifications 0x1d..=0x1f are fire-and-forget: they take no reply.
pub(crate) fn is_notification(op: u8) -> bool {
    (0x1d..=0x1f).contains(&op)
}

#[derive(Clone, Copy)]
pub(crate) struct Req {
    pub(crate) tag: u8,
    pub(crate) op: u8,
    pub(crate) len: u16,
    pub(crate) args: [u8; 3],
}

pub(crate) fn decode(msg: &Message) -> Req {
    let b = msg.msg0.to_le_bytes();
    Req {
        tag: b[1],
        op: b[2],
        len: u16::from_le_bytes([b[3], b[4]]),
        args: [b[5], b[6], b[7]],
    }
}

pub(crate) fn encode_reply(tag: u8, status: u8, len: u16, args: [u8; 3]) -> Message {
    let l = len.to_le_bytes();
    Message {
        msg0: u64::from_le_bytes([
            proto::EP_XARM,
            tag,
            status,
            l[0],
            l[1],
            args[0],
            args[1],
            args[2],
        ]),
        msg1: 0,
    }
}
