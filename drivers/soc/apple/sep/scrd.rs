// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Credential endpoint (SCRD, EP 0x0a) framing (SEP.md §3.3).
//!
//! Request word: `[ep, request, len (LE u16), 0, 0, 0, 0]`, with the payload
//! (`"DRCS" | cmd | …`, built by sepd) at the start of the inbound buffer.
//! Reply word: `[ep, request, response size (LE u16), status (LE i32)]`,
//! with the response at the start of the outbound buffer. There is no
//! sequence number: one request is outstanding at a time, and a reply is
//! matched by its request byte.

use crate::proto;
use kernel::soc::apple::mailbox::Message;

pub(crate) fn encode(request: u8, len: u16) -> Message {
    let l = len.to_le_bytes();
    Message {
        msg0: u64::from_le_bytes([proto::EP_SCRD, request, l[0], l[1], 0, 0, 0, 0]),
        msg1: 0,
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Reply {
    pub(crate) request: u8,
    pub(crate) size: u16,
    pub(crate) status: i32,
}

pub(crate) fn decode(msg: &Message) -> Reply {
    let b = msg.msg0.to_le_bytes();
    Reply {
        request: b[1],
        size: u16::from_le_bytes([b[2], b[3]]),
        status: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    }
}

/// The one outstanding request, if any, and its reply once it arrives.
pub(crate) struct ScrdState {
    waiting: Option<u8>,
    reply: Option<Reply>,
    /// A request was abandoned (timeout or signal) and its reply has not
    /// come; the buffers may still be in use, so no new request is sent.
    wedged: bool,
}

pub(crate) enum Delivery {
    Matched,
    LateCleared,
    Unmatched,
}

impl ScrdState {
    pub(crate) const fn new() -> Self {
        ScrdState {
            waiting: None,
            reply: None,
            wedged: false,
        }
    }

    pub(crate) fn wedged(&self) -> bool {
        self.wedged
    }

    pub(crate) fn begin(&mut self, request: u8) {
        self.waiting = Some(request);
        self.reply = None;
    }

    pub(crate) fn take_reply(&mut self) -> Option<Reply> {
        let r = self.reply.take();
        if r.is_some() {
            self.waiting = None;
        }
        r
    }

    /// Gives up on the outstanding request. With `sent`, the SEP has it and
    /// may still answer, so the endpoint stays closed until it does.
    pub(crate) fn abandon(&mut self, sent: bool) {
        self.reply = None;
        self.wedged = sent;
        if !sent {
            self.waiting = None;
        }
    }

    pub(crate) fn deliver(&mut self, r: Reply) -> Delivery {
        if self.waiting != Some(r.request) {
            return Delivery::Unmatched;
        }
        if self.wedged {
            self.wedged = false;
            self.waiting = None;
            return Delivery::LateCleared;
        }
        self.reply = Some(r);
        Delivery::Matched
    }
}
