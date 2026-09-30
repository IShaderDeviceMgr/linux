// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Fingerprint capture: the one part of the Mesa protocol kept in the kernel.
//!
//! sepd starts a capture with APPLE_SEP_IOC_BIO_CAPTURE. The driver tells the
//! sensor to capture, waits until its status reports data ready, reads the
//! image and checks its CRC. The image is then held here until
//! APPLE_SEP_IOC_BIO_RELAY sends it to the SEP (SBIO 0x65) or discards it.
//! Either way it is wiped; it never reaches userspace.
//!
//! Sensor side (reference `sensor.rs`): command `80 40 00 07 00 00 00`
//! starts a capture. The 16-byte status (read as in the handshake) has the
//! state at byte 7 (17 armed, 19 reading, 7 data ready, 9 needs a patch) and,
//! when data is ready, the byte count at 12..16. The image is read with
//! `80 13 00 0b 00 00 00 ‖ u32 len` and ends in a CRC-16/ARC of the rest.

use crate::sensor;
use kernel::prelude::*;

pub(crate) const MAX_CAPTURE: usize = 0x10000;
/// SBIO opcode that hands a capture to the SEP.
pub(crate) const OP_RELAY_CAPTURE: u16 = 0x65;
const CRC_LEN: usize = 2;

const CMD_LEN: usize = 7;
pub(crate) const CMD_START_CAPTURE: [u8; CMD_LEN] = [0x80, 0x40, 0x00, 0x07, 0, 0, 0];
const CMD_GET_STATUS: [u8; CMD_LEN] = [0x80, 0x10, 0x00, 0x07, 0, 0, 0];
const CMD_READ: [u8; CMD_LEN] = [0x80, 0x13, 0x00, 0x0b, 0, 0, 0];
const STATUS_XFER_LEN: usize = 23;
const STATUS_AT: usize = 7;

pub(crate) const STATE_DATA_READY: u8 = 7;
pub(crate) const STATE_NEEDS_PATCH: u8 = 9;

/// A captured image. Zeroed when dropped.
pub(crate) struct Capture(KVec<u8>);

impl Capture {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            // SAFETY: a valid, uniquely borrowed byte.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }
}

pub(crate) struct Status {
    pub(crate) state: u8,
    /// Bytes available, meaningful in `STATE_DATA_READY`.
    pub(crate) count: u32,
}

pub(crate) fn command(m: &sensor::Mesa, cmd: &[u8; CMD_LEN]) -> Result {
    let mut rx = [0u8; CMD_LEN];
    m.xfer(sensor::XFER_DUPLEX, cmd, Some(&mut rx))
}

pub(crate) fn status(m: &sensor::Mesa) -> Result<Status> {
    let mut tx = [0xffu8; STATUS_XFER_LEN];
    tx[..CMD_LEN].copy_from_slice(&CMD_GET_STATUS);
    let mut rx = [0u8; STATUS_XFER_LEN];
    m.xfer(sensor::XFER_DUPLEX, &tx, Some(&mut rx))?;
    let st = &rx[STATUS_AT..];
    Ok(Status {
        state: st[7],
        count: u32::from_le_bytes([st[12], st[13], st[14], st[15]]),
    })
}

/// CRC-16/ARC (poly 0xA001 reflected, init 0), as the sensor uses.
pub(crate) const fn crc16_arc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    let mut i = 0;
    while i < data.len() {
        crc ^= data[i] as u16;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa001
            } else {
                crc >> 1
            };
            bit += 1;
        }
        i += 1;
    }
    crc
}
kernel::static_assert!(crc16_arc(b"123456789") == 0xbb3d);

pub(crate) enum ReadError {
    Length,
    Crc,
    Bus(Error),
}

/// Reads `len` bytes of image and checks the trailing CRC.
pub(crate) fn read(m: &sensor::Mesa, len: u32) -> core::result::Result<Capture, ReadError> {
    let n = len as usize;
    if n <= CRC_LEN || n > MAX_CAPTURE {
        return Err(ReadError::Length);
    }
    let mut cmd = [0u8; CMD_LEN + 4];
    cmd[..CMD_LEN].copy_from_slice(&CMD_READ);
    cmd[CMD_LEN..].copy_from_slice(&len.to_le_bytes());
    // kmalloc, not vmalloc: the SPI core may map it for DMA.
    let mut cap =
        Capture(KVec::from_elem(0xffu8, n, GFP_KERNEL).map_err(|_| ReadError::Bus(ENOMEM))?);
    m.xfer(sensor::XFER_TX_RX, &cmd, Some(&mut cap.0[..]))
        .map_err(ReadError::Bus)?;
    let split = n - CRC_LEN;
    let want = u16::from_le_bytes([cap.0[split], cap.0[split + 1]]);
    if crc16_arc(&cap.0[..split]) != want {
        return Err(ReadError::Crc);
    }
    Ok(cap)
}
