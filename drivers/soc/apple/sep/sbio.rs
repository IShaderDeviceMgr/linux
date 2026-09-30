// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Biometric endpoint (SBIO, EP 0x08) chunked transport.
//!
//! Word layout (bytes of `msg0`): `[ep, marker, opcode_lo, opcode_hi, 0, 0,
//! seq_lo, seq_hi]`. Markers: 0xFC first chunk, 0xFD next chunk, 0xFE "send
//! your next chunk" (a grant when we send; a continuation request when we
//! receive), 0xFF error. Markers below 0xFC are notifications.
//!
//! Each chunk in the OOL buffer starts with seven LE u32: version (1), total,
//! offset, flags, err, opcode, chunk length; the chunk follows. The host sends
//! FC, then for each later chunk waits for an FE grant and sends FD. The SEP
//! answers the same way, and the host requests each further chunk with FE.
//! The final `err` is the operation status (SEP.md §3.4).

use crate::proto;
use kernel::prelude::*;
use kernel::soc::apple::mailbox::Message;

pub(crate) const MARKER_FIRST: u8 = 0xfc;
pub(crate) const MARKER_NEXT: u8 = 0xfd;
pub(crate) const MARKER_REQUEST: u8 = 0xfe;
pub(crate) const MARKER_ERROR: u8 = 0xff;

pub(crate) const HEADER_LEN: usize = 28;
const VERSION: u32 = 1;
/// Largest transaction the reference accepted in either direction.
pub(crate) const MAX_TRANSACTION: usize = 0x4b000;

#[derive(Clone, Copy)]
pub(crate) struct Packet {
    pub(crate) version: u32,
    pub(crate) total: u32,
    pub(crate) offset: u32,
    pub(crate) flags: u32,
    pub(crate) err: u32,
    pub(crate) opcode: u32,
    pub(crate) chunk: u32,
}

impl Packet {
    pub(crate) fn decode(b: &[u8]) -> Option<Packet> {
        let w = |i: usize| -> Option<u32> {
            Some(u32::from_le_bytes(
                b.get(i * 4..i * 4 + 4)?.try_into().ok()?,
            ))
        };
        Some(Packet {
            version: w(0)?,
            total: w(1)?,
            offset: w(2)?,
            flags: w(3)?,
            err: w(4)?,
            opcode: w(5)?,
            chunk: w(6)?,
        })
    }

    pub(crate) fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        for (i, v) in [
            self.version,
            self.total,
            self.offset,
            self.flags,
            self.err,
            self.opcode,
            self.chunk,
        ]
        .iter()
        .enumerate()
        {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    pub(crate) fn data(opcode: u16, total: usize, offset: usize, chunk: usize) -> Packet {
        Packet {
            version: VERSION,
            total: total as u32,
            offset: offset as u32,
            flags: 0,
            err: 0,
            opcode: u32::from(opcode),
            chunk: chunk as u32,
        }
    }
}

pub(crate) const fn encode(opcode: u16, marker: u8, seq: u16) -> Message {
    Message {
        msg0: (proto::EP_SBIO as u64)
            | ((marker as u64) << 8)
            | ((opcode as u64) << 16)
            | ((seq as u64) << 48),
        msg1: 0,
    }
}

pub(crate) fn marker_of(msg: &Message) -> u8 {
    (msg.msg0 >> 8) as u8
}

// The reference driver's INIT_SBIO_COMMUNICATION word.
kernel::static_assert!(encode(0x73, MARKER_FIRST, 0).msg0 == 0x0000_0073_fc08);

/// How a transaction ended.
#[derive(Clone, Copy)]
pub(crate) enum Status {
    /// The operation status the SEP reported (0 = success).
    Answered(u32),
    /// An FF error marker whose header carried no status.
    Unreported,
    /// A chunk notification arrived but its header was never written.
    Unwritten,
}

/// What the receive path must do after a chunk.
pub(crate) enum Progress {
    /// Request chunk `received` of `total` with an FE carrying `seq`.
    NeedMore {
        opcode: u16,
        received: u32,
        total: u32,
        seq: u16,
    },
    Complete,
    Ignored,
}

struct Active {
    opcode: u16,
    total: u32,
    payload: KVVec<u8>,
    seq: u16,
}

pub(crate) struct SbioState {
    active: Option<Active>,
    done: Option<(Status, KVVec<u8>)>,
    sending: bool,
    grants: u32,
}

impl SbioState {
    pub(crate) fn new() -> Self {
        SbioState {
            active: None,
            done: None,
            sending: false,
            grants: 0,
        }
    }

    pub(crate) fn begin(&mut self, opcode: u16) {
        self.done = None;
        self.grants = 0;
        self.sending = true;
        self.active = Some(Active {
            opcode,
            total: 0,
            payload: KVVec::new(),
            seq: 0,
        });
    }

    pub(crate) fn sent_all(&mut self) {
        self.sending = false;
        self.grants = 0;
    }

    pub(crate) fn take_grant(&mut self) -> bool {
        if self.grants > 0 {
            self.grants -= 1;
            return true;
        }
        false
    }

    pub(crate) fn has_done(&self) -> bool {
        self.done.is_some()
    }

    pub(crate) fn take_done(&mut self) -> Option<(Status, KVVec<u8>)> {
        self.done.take()
    }

    pub(crate) fn abort(&mut self) {
        self.active = None;
        self.done = None;
        self.sending = false;
        self.grants = 0;
    }

    fn finish(&mut self, status: Status, payload: KVVec<u8>) {
        self.active = None;
        self.done = Some((status, payload));
    }

    /// An FE while we are sending: permission for the next chunk.
    pub(crate) fn grant(&mut self) -> bool {
        if self.sending {
            self.grants = self.grants.saturating_add(1);
            return true;
        }
        false
    }

    pub(crate) fn fail(&mut self, status: Status) {
        if self.active.is_some() {
            self.finish(status, KVVec::new());
        }
    }

    /// An FF error marker.
    pub(crate) fn error(&mut self, err: Option<u32>) -> bool {
        if self.active.is_none() {
            return false;
        }
        let status = match err {
            Some(e) if e != 0 => Status::Answered(e),
            _ => Status::Unreported,
        };
        self.finish(status, KVVec::new());
        true
    }

    /// An FC/FD data chunk from the SEP.
    pub(crate) fn chunk(&mut self, marker: u8, p: &Packet, data: &[u8]) -> Progress {
        let Some(active) = self.active.as_mut() else {
            return Progress::Ignored;
        };
        // The SEP echoes the opcode; anything else is stray.
        if p.opcode != u32::from(active.opcode) {
            return Progress::Ignored;
        }
        let bad = p.version != VERSION
            || p.chunk as usize != data.len()
            || p.total as usize > MAX_TRANSACTION
            || match marker {
                MARKER_FIRST => !active.payload.is_empty() || p.offset != 0,
                MARKER_NEXT => p.offset as usize != active.payload.len() || p.total != active.total,
                _ => true,
            };
        if bad {
            self.finish(Status::Unreported, KVVec::new());
            return Progress::Complete;
        }
        if marker == MARKER_FIRST {
            active.total = p.total;
        }
        if p.err != 0 {
            let got = core::mem::take(&mut active.payload);
            self.finish(Status::Answered(p.err), got);
            return Progress::Complete;
        }
        if active.payload.extend_from_slice(data, GFP_KERNEL).is_err() {
            self.finish(Status::Unreported, KVVec::new());
            return Progress::Complete;
        }
        let received = active.payload.len() as u32;
        if received >= active.total {
            let got = core::mem::take(&mut active.payload);
            self.finish(Status::Answered(0), got);
            return Progress::Complete;
        }
        active.seq = active.seq.wrapping_add(1);
        Progress::NeedMore {
            opcode: active.opcode,
            received,
            total: active.total,
            seq: active.seq,
        }
    }
}
