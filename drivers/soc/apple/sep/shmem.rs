// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! The shared-memory table handed to the SEP with `SET_SHMEM`.
//!
//! Offset 0 holds a directory of 16-byte entries `{fourcc, u32 size,
//! u64 offset}`; `size` is the space reserved, not the payload length. Each
//! payload is a `u32` length followed by its bytes, at a 16 KiB-aligned
//! offset from 0x4000. The layout is the one the upstream stub used:
//!
//! * `CNIP`: the panic region, 0x8000 bytes, payload `[0]`;
//! * `OPLA`: the local-policy manifest m1n1 copied into the SEP node;
//! * `IPIS`: the iBoot manifest, likewise;
//! * `llun`: terminator.

use kernel::{device, dma, platform, prelude::*};

pub(crate) type ShMem = dma::Coherent<[u8]>;

/// Capacity of the table on the cold-boot SoCs (T8103, T6000).
pub(crate) const SIZE: usize = 0x3_0000;

const ENTRY_SIZE: usize = 16;
const PAYLOAD_BASE: usize = 0x4000;
const ALIGN: usize = 0x4000;
const PANIC_SIZE: usize = 0x8000;

const fn align_up(v: usize) -> usize {
    (v + ALIGN - 1) & !(ALIGN - 1)
}

struct Item<'a> {
    fourcc: &'a [u8; 4],
    offset: usize,
    size: usize,
    payload: &'a [u8],
}

fn manifest(dev: &device::Device, name: &CStr) -> Result<KVec<u8>> {
    let fwnode = dev.fwnode().ok_or(ENODEV)?;
    let len = fwnode.property_count_elem::<u8>(name).inspect_err(|e| {
        dev_err!(
            dev,
            "no '{}' in the SEP node; is m1n1 new enough and is the 'sep' alias present? ({:?})\n",
            name,
            e
        );
    })?;
    if len == 0 {
        return Err(ENODATA);
    }
    fwnode
        .property_read_array_vec::<u8>(name, len)?
        .required_by(dev)
}

/// Reads both manifests and builds the table. Everything is validated before
/// the buffer exists, so a malformed table can never reach the SEP: the
/// registration is one-shot, and a bad table spends it.
pub(crate) fn build(pdev: &platform::Device<device::Core>) -> Result<ShMem> {
    let dev: &device::Device = pdev.as_ref();
    let lpol = manifest(dev, c"local-policy-manifest")?;
    let ibot = manifest(dev, c"iboot-manifest")?;

    // Payloads carry a u32 length prefix; the panic region's payload is one
    // zero byte.
    let panic = [0u8; 1];
    let lpol_at = PAYLOAD_BASE + PANIC_SIZE;
    let lpol_size = align_up(lpol.len() + 4);
    let ibot_at = lpol_at + lpol_size;
    let ibot_size = align_up(ibot.len() + 4);
    let items = [
        Item {
            fourcc: b"CNIP",
            offset: PAYLOAD_BASE,
            size: PANIC_SIZE,
            payload: &panic,
        },
        Item {
            fourcc: b"OPLA",
            offset: lpol_at,
            size: lpol_size,
            payload: &lpol,
        },
        Item {
            fourcc: b"IPIS",
            offset: ibot_at,
            size: ibot_size,
            payload: &ibot,
        },
    ];

    let end = ibot_at.checked_add(ibot_size).ok_or(EINVAL)?;
    if end > SIZE || (items.len() + 1) * ENTRY_SIZE > PAYLOAD_BASE {
        dev_err!(
            dev,
            "SEP manifests need 0x{:x} bytes; the table holds 0x{:x}\n",
            end,
            SIZE
        );
        return Err(ENOSPC);
    }

    let buf = dma::Coherent::<u8>::zeroed_slice(pdev.as_ref(), SIZE, GFP_KERNEL)?;

    // SAFETY: the SEP has not been told this buffer exists and nothing else
    // holds a reference to it, so this is the only access.
    let mem = unsafe { buf.as_mut() };
    for (i, item) in items.iter().enumerate() {
        let p = item.offset;
        mem[p..p + 4].copy_from_slice(&(item.payload.len() as u32).to_le_bytes());
        mem[p + 4..p + 4 + item.payload.len()].copy_from_slice(item.payload);

        let e = i * ENTRY_SIZE;
        mem[e..e + 4].copy_from_slice(item.fourcc);
        mem[e + 4..e + 8].copy_from_slice(&(item.size as u32).to_le_bytes());
        mem[e + 8..e + 16].copy_from_slice(&(item.offset as u64).to_le_bytes());
    }
    let e = items.len() * ENTRY_SIZE;
    mem[e..e + 4].copy_from_slice(b"llun");

    dev_info!(
        dev,
        "shared memory: local policy {} bytes, iBoot manifest {} bytes, 0x{:x} of 0x{:x} used\n",
        lpol.len(),
        ibot.len(),
        end,
        SIZE
    );
    Ok(buf)
}
