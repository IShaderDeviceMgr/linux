// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! BootPolicy endpoint (`pnon`, EP 0x15) framing and allow-list (SEP.md §10).
//!
//! macOS's BootPolicy kext passes libbootpolicy's commands through unchanged:
//! request word `[ep, 1, len (LE u16), 0, 0, 0, 0]` with the command at the
//! start of the inbound buffer, reply word `[ep, 1, size (LE u16), status
//! (LE i32)]` with the response at the start of the outbound buffer. That is
//! the SCRD layout, so the SCRD request state is reused.
//!
//! A command is a 0x20-byte header, `"hcPB"`, the command number (LE u32) and
//! 0x18 zero bytes, followed by command-specific input. The response starts
//! with `"hrPB"`, a status (LE u32) and breadcrumbs.
//!
//! Only commands that change no state may be sent: the read-only commands
//! below, each of which takes the bare header as its whole input. The driver
//! builds that header itself, so userspace chooses a command number and
//! nothing else. Allowing a command that signs or commits a LocalPolicy is a
//! code change behind its own gate, never a parameter.

use crate::proto;
use kernel::soc::apple::mailbox::Message;

/// The kext's only request code ("perform command").
const REQUEST_COMMAND: u8 = 1;
pub(crate) const HEADER_LEN: usize = 0x20;
const MAGIC: [u8; 4] = *b"hcPB";

/// Read-only commands B1 may send (libbootpolicy 13.5).
const ALLOWED: [u32; 5] = [
    0x0b, // get_proposed_local_policy_nonce_digest
    0x0e, // get_blessed_local_policy_nonce_digest
    0x36, // get_booted_local_policy
    0x3e, // get_current_os_type
    0x3f, // get_current_os_type_restrictions_override_status
];

pub(crate) fn allowed(command: u32) -> bool {
    ALLOWED.contains(&command)
}

/// The whole request for an allowed command: the bare header.
pub(crate) fn request(command: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(&MAGIC);
    h[4..8].copy_from_slice(&command.to_le_bytes());
    h
}

pub(crate) fn encode(len: u16) -> Message {
    let l = len.to_le_bytes();
    Message {
        msg0: u64::from_le_bytes([proto::EP_PNON, REQUEST_COMMAND, l[0], l[1], 0, 0, 0, 0]),
        msg1: 0,
    }
}

/// The request byte a reply must echo.
pub(crate) const fn request_byte() -> u8 {
    REQUEST_COMMAND
}
