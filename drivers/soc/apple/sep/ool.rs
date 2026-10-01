// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Out-of-line (OOL) buffers: one pair per service endpoint.
//!
//! "Inbound" and "outbound" are named from the SEP's side: the host writes the
//! inbound buffer and the SEP reads it; the SEP writes the outbound buffer and
//! the host reads it. The buffers are allocated at probe (allocation needs the
//! bound device) and registered with the SEP on request. Once registered they
//! are never freed: the SEP keeps their IOVAs for the rest of the boot.

use crate::proto;
use kernel::{device, dma, prelude::*};

/// Written into an outbound range once it has been consumed, so a stale
/// payload can be told from one the SEP has just written.
pub(crate) const POISON_OUT: u8 = 0x5a;
const POISON_IN: u8 = 0xa5;

/// Sizes as the reference driver registered them (bytes).
pub(crate) struct Geometry {
    pub(crate) ep: u8,
    pub(crate) alloc: usize,
    pub(crate) in_size: usize,
    pub(crate) out_size: usize,
}

pub(crate) const ENDPOINTS: [Geometry; 5] = [
    Geometry {
        ep: proto::EP_SBIO,
        alloc: 0x4000,
        in_size: 0x4000,
        out_size: 0x4000,
    },
    Geometry {
        ep: proto::EP_SCRD,
        alloc: 0x4000,
        in_size: 0x4000,
        out_size: 0x4000,
    },
    Geometry {
        ep: proto::EP_SKS,
        alloc: 0x8000,
        in_size: 0x8000,
        out_size: 0x4000,
    },
    Geometry {
        ep: proto::EP_XARM,
        alloc: 0x8000,
        in_size: 0x8000,
        out_size: 0x8000,
    },
    // BootPolicy (SEP.md §10.1c). macOS's kext requires at least 0xc150 bytes
    // inbound and 0x7f24 outbound; both rounded up to 16 KiB pages.
    Geometry {
        ep: proto::EP_PNON,
        alloc: 0x10000,
        in_size: 0x10000,
        out_size: 0x8000,
    },
];

/// Index of the SBIO pair in [`ENDPOINTS`].
pub(crate) const SBIO: usize = 0;
kernel::static_assert!(ENDPOINTS[SBIO].ep == proto::EP_SBIO);
/// Index of the SCRD pair in [`ENDPOINTS`].
pub(crate) const SCRD: usize = 1;
kernel::static_assert!(ENDPOINTS[SCRD].ep == proto::EP_SCRD);
/// Index of the SKS pair in [`ENDPOINTS`].
pub(crate) const SKS: usize = 2;
kernel::static_assert!(ENDPOINTS[SKS].ep == proto::EP_SKS);
/// Index of the XARM pair in [`ENDPOINTS`].
pub(crate) const XARM: usize = 3;
kernel::static_assert!(ENDPOINTS[XARM].ep == proto::EP_XARM);
/// Index of the BootPolicy (`pnon`) pair in [`ENDPOINTS`].
pub(crate) const PNON: usize = 4;
kernel::static_assert!(ENDPOINTS[PNON].ep == proto::EP_PNON);

pub(crate) fn index_of(ep: u8) -> Option<usize> {
    ENDPOINTS.iter().position(|g| g.ep == ep)
}

pub(crate) struct Ool {
    pub(crate) geometry: &'static Geometry,
    inbound: dma::Coherent<[u8]>,
    outbound: dma::Coherent<[u8]>,
    pub(crate) registered: bool,
}

impl Ool {
    pub(crate) fn new(
        dev: &device::Device<device::Bound>,
        geometry: &'static Geometry,
    ) -> Result<Ool> {
        let inbound = dma::Coherent::<u8>::zeroed_slice(dev, geometry.alloc, GFP_KERNEL)?;
        let outbound = dma::Coherent::<u8>::zeroed_slice(dev, geometry.alloc, GFP_KERNEL)?;
        // SAFETY: the SEP does not know these buffers yet; nothing else
        // accesses them.
        unsafe {
            inbound.as_mut().fill(POISON_IN);
            outbound.as_mut().fill(POISON_OUT);
        }
        Ok(Ool {
            geometry,
            inbound,
            outbound,
            registered: false,
        })
    }

    pub(crate) fn in_iova(&self) -> u64 {
        self.inbound.dma_handle()
    }

    pub(crate) fn out_iova(&self) -> u64 {
        self.outbound.dma_handle()
    }

    /// Whether the SEP has written anything over the poison in
    /// `[off, off + len)`.
    pub(crate) fn out_written(&self, off: usize, len: usize) -> bool {
        let end = off.saturating_add(len).min(self.geometry.out_size);
        let off = off.min(end);
        // SAFETY: the SEP writes this buffer before notifying us and waits for
        // our reply; reading a byte it may still be writing is harmless here,
        // as it only delays the check.
        let out = unsafe { &self.outbound.as_ref()[off..end] };
        out.iter().any(|&b| b != POISON_OUT)
    }

    /// Copies `[off, off + len)` of the outbound buffer and re-poisons that
    /// range.
    pub(crate) fn take_out(&self, off: usize, len: usize) -> Result<KVec<u8>> {
        let end = off.checked_add(len).ok_or(EINVAL)?;
        if end > self.geometry.out_size {
            return Err(EMSGSIZE);
        }
        let mut v = KVec::new();
        // SAFETY: the SEP finished writing before notifying us and does not
        // touch the buffer again until we reply; we are the only host accessor
        // (the caller holds this pair's lock).
        unsafe {
            v.extend_from_slice(&self.outbound.as_ref()[off..end], GFP_KERNEL)?;
            self.outbound.as_mut()[off..end].fill(POISON_OUT);
        }
        Ok(v)
    }

    /// Copies `[0, len)` of the outbound buffer, leaving it as it is.
    pub(crate) fn read_out(&self, len: usize) -> Result<KVec<u8>> {
        if len > self.geometry.out_size {
            return Err(EMSGSIZE);
        }
        let mut v = KVec::new();
        // SAFETY: called after the SEP's reply, when it no longer touches the
        // buffer; the caller holds this pair's lock.
        v.extend_from_slice(unsafe { &self.outbound.as_ref()[..len] }, GFP_KERNEL)?;
        Ok(v)
    }

    /// Zeroes both buffers, so no request or response bytes (which may be
    /// key material) linger between calls.
    pub(crate) fn clear(&self) {
        // SAFETY: called only when no request is outstanding on this
        // endpoint, so the SEP is not accessing either buffer; the caller
        // holds this pair's lock.
        unsafe {
            self.inbound.as_mut()[..self.geometry.alloc].fill(0);
            self.outbound.as_mut()[..self.geometry.alloc].fill(0);
        }
    }

    /// Writes `data` at the start of the inbound buffer.
    pub(crate) fn put_in(&self, data: &[u8]) -> Result {
        if data.len() > self.geometry.in_size {
            return Err(EMSGSIZE);
        }
        // SAFETY: the SEP reads the inbound buffer only after our reply
        // message, which is sent after this returns; the caller holds this
        // pair's lock, so there is no other host writer.
        unsafe { self.inbound.as_mut()[..data.len()].copy_from_slice(data) };
        Ok(())
    }
}
