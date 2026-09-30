// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Control endpoint (EP 0x00) request/reply correlation.
//!
//! Requests carry a tag the SEP echoes in its reply. Tags come from a small
//! pool; a tag whose request timed out is retired until its late reply shows
//! up, so a late reply can never be taken as the answer to a later request.

use crate::proto;
use kernel::prelude::*;

pub(crate) const OP_NOP: u8 = 0x00;
pub(crate) const OP_SECMODE: u8 = 0x14;
pub(crate) const OP_GET_ENTROPY: u8 = 0x36;
// Type 0x18 wedges the control endpoint (reference driver); it has no constant
// here on purpose.

/// Reserved tag for GET_ENTROPY, outside the pool (reference driver).
pub(crate) const TAG_ENTROPY: u8 = 0xe7;

const TAG_FIRST: u8 = 0x01;
const TAG_LAST: u8 = 0x7e;
const POOL: usize = (TAG_LAST - TAG_FIRST + 1) as usize;
const MAX_INFLIGHT: usize = 8;

#[derive(Clone, Copy)]
struct Slot {
    tag: u8,
    reply: Option<u32>,
}

pub(crate) struct ControlState {
    slots: [Option<Slot>; MAX_INFLIGHT],
    next: u8,
    /// Bit `tag` set: that tag timed out and its reply has not arrived yet.
    retired: [u64; 4],
    unmatched: u32,
}

impl ControlState {
    pub(crate) fn new() -> Self {
        ControlState {
            slots: [None; MAX_INFLIGHT],
            next: TAG_FIRST,
            retired: [0; 4],
            unmatched: 0,
        }
    }

    fn is_retired(&self, tag: u8) -> bool {
        self.retired[usize::from(tag >> 6)] & (1u64 << (tag & 63)) != 0
    }

    fn set_retired(&mut self, tag: u8, on: bool) {
        let word = &mut self.retired[usize::from(tag >> 6)];
        if on {
            *word |= 1u64 << (tag & 63);
        } else {
            *word &= !(1u64 << (tag & 63));
        }
    }

    fn busy(&self, tag: u8) -> bool {
        self.is_retired(tag) || self.slots.iter().flatten().any(|s| s.tag == tag)
    }

    /// Reserves a slot for a fixed tag outside the pool (GET_ENTROPY uses
    /// [`TAG_ENTROPY`], as the reference driver does).
    pub(crate) fn alloc_fixed(&mut self, tag: u8) -> Result<usize> {
        if self.busy(tag) {
            return Err(EBUSY);
        }
        let idx = self.slots.iter().position(|s| s.is_none()).ok_or(EBUSY)?;
        self.slots[idx] = Some(Slot { tag, reply: None });
        Ok(idx)
    }

    /// Reserves a slot and a tag.
    pub(crate) fn alloc(&mut self) -> Result<(usize, u8)> {
        let idx = self.slots.iter().position(|s| s.is_none()).ok_or(EBUSY)?;
        for _ in 0..POOL {
            let tag = self.next;
            self.next = if tag >= TAG_LAST { TAG_FIRST } else { tag + 1 };
            if !self.busy(tag) {
                self.slots[idx] = Some(Slot { tag, reply: None });
                return Ok((idx, tag));
            }
        }
        Err(EBUSY)
    }

    /// Takes the reply for `idx` and frees the slot, if the reply has arrived.
    pub(crate) fn take(&mut self, idx: usize) -> Option<u32> {
        let reply = self.slots[idx]?.reply?;
        self.slots[idx] = None;
        Some(reply)
    }

    /// Gives up on `idx` (timeout, signal or send failure). If `sent`, the
    /// tag stays retired until its reply arrives.
    pub(crate) fn abandon(&mut self, idx: usize, sent: bool) {
        if let Some(slot) = self.slots[idx].take() {
            if sent {
                self.set_retired(slot.tag, true);
            }
        }
    }

    /// Files a reply. Returns true if a waiter should be woken.
    pub(crate) fn deliver(&mut self, tag: u8, data: u32) -> bool {
        if let Some(slot) = self
            .slots
            .iter_mut()
            .flatten()
            .find(|s| s.tag == tag && s.reply.is_none())
        {
            slot.reply = Some(data);
            return true;
        }
        if self.is_retired(tag) {
            self.set_retired(tag, false);
        } else {
            self.unmatched = self.unmatched.saturating_add(1);
        }
        false
    }

    pub(crate) fn unmatched(&self) -> u32 {
        self.unmatched
    }
}

pub(crate) fn encode(
    tag: u8,
    op: u8,
    param: u8,
    data: u32,
) -> kernel::soc::apple::mailbox::Message {
    proto::encode(proto::EP_CONTROL, tag, op, param, data)
}

kernel::static_assert!(TAG_LAST < TAG_ENTROPY);
