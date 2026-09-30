// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Key-store (SKS, EP 0x12) transport.
//!
//! Word layout (bytes of `msg0`):
//! request `[ep, selector, seq, 0, 0, 0, len_lo, len_hi]`,
//! reply   `[ep, selector | 0x80, seq, status (i8), -, -, size_lo, size_hi]`.
//! The request image (built by sepd) goes in the SKS inbound buffer; the
//! response image comes back in the outbound buffer. A reply is matched to
//! its request by (selector, seq).
//!
//! A request that gets no reply may still be running in the SEP, which may
//! still be reading or writing the buffers. The key store is then *wedged*:
//! every later call is refused until the late reply arrives.

use crate::proto;
use kernel::prelude::*;
use kernel::soc::apple::mailbox::Message;

const REPLY_BIT: u8 = 0x80;
const SEQ_BASE: u8 = 0x60;
/// Abandoned requests remembered for matching a late reply.
const MAX_ABANDONED: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Id {
    pub(crate) selector: u8,
    pub(crate) seq: u8,
}

#[derive(Clone, Copy)]
pub(crate) struct Reply {
    pub(crate) id: Id,
    pub(crate) status: i8,
    pub(crate) size: u16,
}

pub(crate) fn decode(msg: &Message) -> Reply {
    let b = msg.msg0.to_le_bytes();
    Reply {
        id: Id {
            selector: b[1] & !REPLY_BIT,
            seq: b[2],
        },
        status: b[3] as i8,
        size: u16::from_le_bytes([b[6], b[7]]),
    }
}

pub(crate) fn encode(id: Id, len: u16) -> Message {
    let l = len.to_le_bytes();
    Message {
        msg0: u64::from_le_bytes([proto::EP_SKS, id.selector, id.seq, 0, 0, 0, l[0], l[1]]),
        msg1: 0,
    }
}

pub(crate) enum Delivery {
    /// The reply the caller is waiting for.
    Matched,
    /// A late reply to an abandoned request; the key store is usable again.
    LateCleared,
    Unmatched,
}

pub(crate) struct SksState {
    counter: u8,
    waiting: Option<Id>,
    reply: Option<Reply>,
    abandoned: KVec<Id>,
    wedged: bool,
}

impl SksState {
    pub(crate) fn new() -> Self {
        SksState {
            counter: 0,
            waiting: None,
            reply: None,
            abandoned: KVec::new(),
            wedged: false,
        }
    }

    pub(crate) fn wedged(&self) -> bool {
        self.wedged
    }

    /// Starts a request: allocates its sequence number.
    pub(crate) fn begin(&mut self, selector: u8) -> Result<Id> {
        if self.wedged {
            return Err(EIO);
        }
        if self.waiting.is_some() {
            return Err(EBUSY);
        }
        let seq = seq_for(self.counter);
        self.counter = self.counter.wrapping_add(1);
        let id = Id { selector, seq };
        self.waiting = Some(id);
        self.reply = None;
        Ok(id)
    }

    pub(crate) fn take_reply(&mut self) -> Option<Reply> {
        let r = self.reply.take()?;
        self.waiting = None;
        Some(r)
    }

    /// Gives up on the current request. If it was sent, the SEP may still be
    /// using the buffers, so the key store is wedged until it answers.
    pub(crate) fn abandon(&mut self, sent: bool) {
        let Some(id) = self.waiting.take() else {
            return;
        };
        self.reply = None;
        if sent {
            self.wedged = true;
            if self.abandoned.len() >= MAX_ABANDONED {
                let _ = self.abandoned.remove(0);
            }
            let _ = self.abandoned.push(id, GFP_KERNEL);
        }
    }

    pub(crate) fn deliver(&mut self, reply: Reply) -> Delivery {
        if self.waiting == Some(reply.id) && self.reply.is_none() {
            self.reply = Some(reply);
            return Delivery::Matched;
        }
        if let Some(i) = self.abandoned.iter().position(|a| *a == reply.id) {
            let _ = self.abandoned.remove(i);
            if self.abandoned.is_empty() {
                self.wedged = false;
            }
            return Delivery::LateCleared;
        }
        Delivery::Unmatched
    }
}

/// The reference driver's sequence space: `0x60 | (n & !0x60)`, which
/// repeats every 32 requests.
const fn seq_for(counter: u8) -> u8 {
    SEQ_BASE | (counter & !SEQ_BASE)
}

kernel::static_assert!(seq_for(0) != seq_for(1));
kernel::static_assert!(seq_for(0) == seq_for(32));
