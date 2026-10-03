// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Apple AVE2 video encoder: coprocessor bring-up (skeleton)
//!
//! The encoder is an ASC coprocessor running an RTKit firmware that iBoot
//! preloads (ADT `ave0`: `pre-loaded`, `segment-ranges`). m1n1 reserves the
//! two firmware segments as `memory-region`s with `iommu-addresses`, so the
//! DART domain already maps `__TEXT` at IOVA 0 and `__DATA` right after it,
//! where the firmware is linked, and copies the ADT `segment-ranges` to
//! `apple,segment-ranges`.
//!
//! This driver boots the firmware and runs the start-up handshake: the
//! firmware's first mailbox message (IPC channel count, channel buffer size,
//! channel descriptor size, firmware heap size), then the IPC memory, heap
//! and channel-memory exchange, ending with the IOP "ready" flag. Nothing is
//! encoded yet. The sequence follows macOS 13.5 AppleAVE2 for T6000
//! ("Castor") `AVE_HwC::StartUpIOP`, see j314s-notes AVE2.md §4.
//!
//! The firmware writes to its `__DATA` segment, and a restart needs a pristine
//! copy, which only exists before the first start. The driver therefore
//! snapshots `__DATA` before starting and, on unbind, halts the CPU and
//! restores it. If that cannot be done safely, it refuses to start the
//! firmware again until reboot.

use kernel::{
    bindings,
    device::{
        self,
        Core, //
    },
    devres::Devres,
    dma::Coherent,
    dma_read, dma_write,
    io::{
        mem::{
            IoMem,
            Mem,
            MemFlag, //
        },
        poll::read_poll_timeout,
        Io, //
    },
    module_platform_driver, of, platform,
    prelude::*,
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            Relaxed, //
        },
    },
    time::Delta,
};

/// ADT reg 1: IOP block. The ASC sits at +0x400000.
const COPROC_SIZE: usize = 0x800000;
/// ADT reg 2: "SVE ctrl" mailbox.
const MBOX_SIZE: usize = 0x8000;

/// Boot address: `(addr & MASK) | MAGIC` (`AVE_IOP_Config_Castor`). iBoot
/// programs it with `__TEXT`'s `remap` address (= its physical address)
/// and bit 0 set, e.g. 0x0102010000918001; macOS leaves it alone on Castor.
/// The kext's own formula uses the DART address (0) and does not boot here.
const BOOT_ADDR: usize = 0x50000;
const BOOT_ADDR_MASK: u64 = 0x3ff_ffff_f800;
const BOOT_ADDR_MAGIC: u64 = 0x0102_0000_0000_0000;
/// Set by iBoot; meaning unknown.
const BOOT_ADDR_BIT0: u64 = 1;

const ASC: usize = 0x400000;
const ASC_CPU_CONTROL: usize = ASC + 0x44;
const ASC_CPU_STATUS: usize = ASC + 0x48;
const ASC_UNK_400: usize = ASC + 0x400;
const ASC_UNK_808: usize = ASC + 0x808;
const CPU_RUN: u32 = 1 << 4;
const CPU_STATUS_BUSY: u32 = 0x3;

/// Mailbox register offsets (`AVE_SVECtrl_GetReg`, chip types 4..=15).
const MBOX_DOORBELL: usize = 0x0c;
const MBOX_STATUS: usize = 0x10;
const MBOX_WORD0: usize = 0x18;
const MBOX_NUM_WORDS: usize = 8;
const MBOX_STATUS_PENDING: u32 = 1;

/// `AVE_SVECtrl::SetIOPFlag` value.
const IOP_FLAG_MAGIC: u32 = 0x0804_2006;
/// `_E_AVE_DevID` for T6000 (`gs_saAVE_DevID_Conversion`).
const DEV_ID_T6000: u32 = 14;
/// `_E_AVE_DevType` for T6000.
const DEV_TYPE_T6000: u32 = 11;
/// Max IPC channels (`AVE_IPC_Ch_Max`).
const IPC_CH_MAX: u32 = 8;

/// The IPC surface (`AVE_IPC::Init`), shared with the firmware. Host-side
/// structures (channel memory, exchange memory) are carved out of it; the
/// firmware has its own address for it (`Kernel2FwAddr`).
const IPC_SIZE: usize = 0x70_0000;
/// `AVE_ChkPool` default alignment.
const IPC_ALIGN: usize = 0x40;
/// `sizeof(union ffwIOPChannelDescriptor64)`.
const CH_DESC_SIZE: u32 = 0x100;
/// Channel descriptor fields, filled in by the firmware (`AVE_IPC::CreateChannel`).
const CH_DESC_NAME_LEN: usize = 0x40;
/// Selects this side's ring role: 0 -> 1, 1 -> 0, else 2
/// (`AppleAVEIOProcessorChannel::Create`).
const CH_DESC_ROLE: usize = 0x40;
const CH_DESC_TYPE: usize = 0x44;
/// Number of ring entries.
const CH_DESC_COUNT: usize = 0x48;
/// Firmware address of the ring.
const CH_DESC_ENTRY: usize = 0x4c;
/// `IOProcessorChannel` ring entry: u64 buffer address | owner bit 0, u64,
/// u64, padding.
const CH_ENTRY_SIZE: usize = 0x40;
/// Exchange ("handshake") memory, `AVE_IPC::Alloc(0x50)`, chip type >= 6.
const XCHG_SIZE: usize = 0x50;
const XCHG_CH_MEM: usize = 0x08;
const XCHG_HEAP_ADDR: usize = 0x1c;
const XCHG_HEAP_SIZE: usize = 0x24;
const XCHG_DEV_TYPE: usize = 0x28;
/// `ms_iFwClientSize` limit checked by StartUpIOP.
const FW_CLIENT_MAX: u32 = 1 << 20;
/// Scratch word the host sets to `IOP_FLAG_MAGIC` last; the firmware clears it.
const IOP_FLAG_READY: usize = 3;

const SEG_ENTRY_SIZE: usize = 32;
const SZ_16K: u64 = 0x4000;

/// Set while the firmware may be running or its `__DATA` may be dirty.
static STARTED: Atomic<bool> = Atomic::new(false);

/// One ADT `segment-ranges` entry (`struct adt_segment_ranges` in m1n1).
#[derive(Clone, Copy)]
struct Segment {
    phys: u64,
    iova: u64,
    /// Apparently the IOP CPU's own address for the segment.
    remap: u64,
    size: u64,
}

fn le_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

fn join(lo: u32, hi: u32) -> u64 {
    u64::from(lo) | u64::from(hi) << 32
}

fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

/// Reads `apple,segment-ranges` and checks it is `__TEXT` at IOVA 0 followed
/// by `__DATA`, which is what the firmware is linked for.
fn read_segments(dev: &device::Device) -> Result<(Segment, Segment)> {
    let prop = c"apple,segment-ranges";
    let node = dev.fwnode().ok_or(ENODEV)?;
    let len = node.property_count_elem::<u8>(prop).inspect_err(|_| {
        dev_err!(dev, "no {:?}: m1n1 adds it when iBoot preloaded the firmware\n", prop);
    })?;
    if len != 2 * SEG_ENTRY_SIZE {
        dev_err!(dev, "expected 2 firmware segments, {:?} is {} bytes\n", prop, len);
        return Err(EINVAL);
    }
    let raw = node.property_read_array_vec::<u8>(prop, len)?.required_by(dev)?;

    let seg = |i: usize| {
        let e = &raw[i * SEG_ENTRY_SIZE..(i + 1) * SEG_ENTRY_SIZE];
        Segment {
            phys: le_u64(&e[0..]),
            iova: le_u64(&e[8..]),
            remap: le_u64(&e[16..]),
            size: u64::from(le_u32(&e[24..])),
        }
    };
    let (text, data) = (seg(0), seg(1));
    if text.iova != 0 || data.iova != text.size || text.size == 0 || data.size == 0 {
        dev_err!(
            dev,
            "unexpected segment layout: text {:#x}@{:#x} data {:#x}@{:#x}\n",
            text.size,
            text.iova,
            data.size,
            data.iova
        );
        return Err(EINVAL);
    }
    Ok((text, data))
}

/// Finds the `memory-region` entry that m1n1 reserved for `seg`.
fn find_region(dev: &device::Device, of: &of::Node, seg: &Segment) -> Result<kernel::io::resource::Resource> {
    let want = seg.size.next_multiple_of(SZ_16K);
    for i in 0..2 {
        let res = of.reserved_mem_region_to_resource(i)?;
        if res.start() == seg.phys && res.size() == want {
            return Ok(res);
        }
    }
    dev_err!(dev, "no memory-region for segment at {:#x} ({:#x} bytes)\n", seg.phys, want);
    Err(EINVAL)
}

/// Checks that the device's DART domain maps `seg` where the firmware expects it.
fn check_mapping(dev: &device::Device, seg: &Segment) -> Result {
    // SAFETY: `dev` is a valid, bound device.
    let domain = unsafe { bindings::iommu_get_domain_for_dev(dev.as_raw()) };
    if domain.is_null() {
        dev_err!(dev, "no IOMMU domain: are ave_dart0/1 enabled?\n");
        return Err(ENODEV);
    }
    for off in [0, seg.size - 1] {
        // SAFETY: `domain` was returned by the IOMMU core for this bound device.
        let phys = unsafe { bindings::iommu_iova_to_phys(domain, seg.iova + off) };
        if phys != seg.phys + off {
            dev_err!(
                dev,
                "IOVA {:#x} maps to {:#x}, expected {:#x}\n",
                seg.iova + off,
                phys,
                seg.phys + off
            );
            return Err(EINVAL);
        }
    }
    Ok(())
}

/// A coherent buffer shared with the firmware, accessed by byte offset.
struct Shared(Coherent<[u32]>);

impl Shared {
    fn new(dev: &device::Device<device::Bound>, size: usize) -> Result<Self> {
        Ok(Shared(Coherent::<u32>::zeroed_slice(dev, size / 4, GFP_KERNEL)?))
    }

    fn iova(&self) -> u64 {
        self.0.dma_handle()
    }

    fn size(&self) -> usize {
        self.0.size()
    }

    fn r32(&self, off: usize) -> Result<u32> {
        Ok(dma_read!(self.0, [off / 4]?))
    }

    fn w32(&self, off: usize, v: u32) -> Result {
        dma_write!(self.0, [off / 4]?, v);
        Ok(())
    }

    fn r64(&self, off: usize) -> Result<u64> {
        Ok(join(self.r32(off)?, self.r32(off + 4)?))
    }

    fn w64(&self, off: usize, v: u64) -> Result {
        self.w32(off, v as u32)?;
        self.w32(off + 4, (v >> 32) as u32)
    }
}

/// `AVE_SVECtrl::SendIOPMsg`: four words, then the doorbell. `writel`
/// orders the earlier writes to shared memory before the doorbell.
fn mbox_send(mbox: &IoMem<MBOX_SIZE>, w: [u32; 4]) -> Result {
    for (i, v) in w.iter().enumerate() {
        mbox.try_write32(*v, MBOX_WORD0 + 4 * i)?;
    }
    mbox.write32(1, MBOX_DOORBELL);
    Ok(())
}

/// `AVE_SVECtrl::RecvIOPMsg`: waits for a message, acks it and reads the words.
fn mbox_recv(
    dev: &device::Device,
    coproc: &IoMem<COPROC_SIZE>,
    mbox: &IoMem<MBOX_SIZE>,
    what: &str,
) -> Result<[u32; MBOX_NUM_WORDS]> {
    read_poll_timeout(
        || Ok(mbox.read32(MBOX_STATUS)),
        |s: &u32| s & MBOX_STATUS_PENDING != 0,
        Delta::from_millis(1),
        Delta::from_millis(2000),
    )
    .inspect_err(|_| {
        dev_err!(
            dev,
            "no message from the firmware ({}): cpu_control {:#x} cpu_status {:#x}\n",
            what,
            coproc.read32(ASC_CPU_CONTROL),
            coproc.read32(ASC_CPU_STATUS)
        );
    })?;
    mbox.write32(MBOX_STATUS_PENDING, MBOX_STATUS);
    let mut w = [0u32; MBOX_NUM_WORDS];
    for (i, v) in w.iter_mut().enumerate() {
        *v = mbox.try_read32(MBOX_WORD0 + 4 * i)?;
    }
    dev_dbg!(dev, "<- {}: {:x?}\n", what, w);
    Ok(w)
}

/// The rest of `AVE_HwC::StartUpIOP` after the firmware's first message, for
/// chip types >= 6. Buffers are stored in `ipc_slot`/`heap_slot` before the
/// firmware learns about them, so they outlive the CPU on every error path.
fn handshake(
    dev: &device::Device<device::Bound>,
    coproc: &IoMem<COPROC_SIZE>,
    mbox: &IoMem<MBOX_SIZE>,
    ipc_slot: &mut Option<Shared>,
    heap_slot: &mut Option<Shared>,
    first: [u32; MBOX_NUM_WORDS],
) -> Result {
    let (nch, buf_size, desc_size, heap_size) =
        (first[0], first[1] as usize, first[2], first[3] as usize);
    let xchg_off = buf_size.next_multiple_of(IPC_ALIGN);
    if desc_size != CH_DESC_SIZE
        || (nch * CH_DESC_SIZE) as usize > buf_size
        || xchg_off + XCHG_SIZE > IPC_SIZE
    {
        dev_err!(dev, "unsupported channel layout: {} x {:#x} in {:#x}\n", nch, desc_size, buf_size);
        return Err(EIO);
    }

    // IPC memory: tell the firmware where it is, learn its address for it.
    let ipc = ipc_slot.insert(Shared::new(dev, IPC_SIZE)?);
    let iova = ipc.iova();
    mbox_send(mbox, [iova as u32, (iova >> 32) as u32, ipc.size() as u32, 0])?;
    let r = mbox_recv(dev, coproc, mbox, "IPC memory address")?;
    let fw_base = join(r[0], r[1]);
    dev_info!(dev, "IPC memory: iova {:#x} size {:#x} -> firmware address {:#x}\n", iova, ipc.size(), fw_base);
    if fw_base == 0 {
        return Err(EIO);
    }
    let k2f = |off: usize| fw_base + off as u64;

    // Firmware heap (AVE_HwC::CreateFwHeap), addressed by IOVA.
    let (heap_iova, heap_len) = if heap_size != 0 {
        let heap = heap_slot.insert(Shared::new(dev, heap_size.next_multiple_of(SZ_16K as usize))?);
        (heap.iova(), heap.size())
    } else {
        (0, 0)
    };

    // Channel memory at the start of the IPC surface (zeroed), then the
    // exchange memory describing it and the heap.
    ipc.w64(xchg_off + XCHG_CH_MEM, k2f(0))?;
    ipc.w64(xchg_off + XCHG_HEAP_ADDR, heap_iova)?;
    ipc.w32(xchg_off + XCHG_HEAP_SIZE, heap_len as u32)?;
    ipc.w32(xchg_off + XCHG_DEV_TYPE, DEV_TYPE_T6000)?;
    let x = k2f(xchg_off);
    mbox_send(mbox, [x as u32, (x >> 32) as u32, 0, 0])?;
    let r = mbox_recv(dev, coproc, mbox, "IPC channel info")?;
    let ch_fw = join(r[0], r[1]);
    dev_info!(
        dev,
        "channel memory {:#x} (sent {:#x}), heap {:#x}+{:#x}, firmware client buffer {:#x}\n",
        ch_fw,
        k2f(0),
        heap_iova,
        heap_len,
        r[2]
    );
    if ch_fw != k2f(0) || r[2] > FW_CLIENT_MAX {
        dev_err!(dev, "unexpected channel info reply {:x?}\n", r);
        return Err(EIO);
    }

    // The firmware has filled in the channel descriptors.
    for i in 0..nch as usize {
        let d = i * CH_DESC_SIZE as usize;
        let mut name = [0u8; CH_DESC_NAME_LEN];
        for (j, c) in name.chunks_mut(4).enumerate() {
            c.copy_from_slice(&ipc.r32(d + 4 * j)?.to_le_bytes());
        }
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        let name = core::str::from_utf8(&name[..len]).unwrap_or("?");
        let entry = ipc.r64(d + CH_DESC_ENTRY)?;
        let count = ipc.r32(d + CH_DESC_COUNT)? as usize;
        let role = match ipc.r32(d + CH_DESC_ROLE)? {
            0 => 1u64,
            1 => 0,
            _ => 2,
        };
        let off = entry.wrapping_sub(fw_base);
        dev_info!(
            dev,
            "channel {}: {:?} type {:#x} role {} entries {} at {:#x} (IPC +{:#x})\n",
            i,
            name,
            ipc.r32(d + CH_DESC_TYPE)?,
            role,
            count,
            entry,
            off
        );
        let ring = usize::try_from(off).map_err(|_| EIO)?;
        if count == 0 || ring.checked_add(count * CH_ENTRY_SIZE).is_none_or(|end| end > buf_size) {
            dev_err!(dev, "channel {} ring outside the channel memory\n", i);
            return Err(EIO);
        }
        // IOProcessorChannelCreate: the side whose role has bit 0 set owns
        // the ring initially and marks every entry with its role, i.e. empty
        // for the other side. Zeroed entries would read as messages with a
        // NULL buffer to the firmware.
        if role & 1 != 0 {
            for e in 0..count {
                let at = ring + e * CH_ENTRY_SIZE;
                ipc.w64(at, role)?;
                ipc.w64(at + 8, 0)?;
                ipc.w64(at + 0x10, 0)?;
            }
        }
    }

    // SetIOPFlag(3); the firmware clears it once it is ready.
    mbox.try_write32(IOP_FLAG_MAGIC, MBOX_WORD0 + 4 * IOP_FLAG_READY)?;
    read_poll_timeout(
        || mbox.try_read32(MBOX_WORD0 + 4 * IOP_FLAG_READY),
        |v: &u32| *v == 0,
        Delta::from_micros(100),
        Delta::from_millis(2000),
    )
    .inspect_err(|_| {
        dev_err!(
            dev,
            "firmware did not clear the ready flag: {:#x}\n",
            mbox.read32(MBOX_WORD0 + 4 * IOP_FLAG_READY)
        );
    })?;
    dev_info!(dev, "IPC up: {} channels\n", nch);
    Ok(())
}

/// Logs runs of printable text of at least 12 bytes in `buf`, skipping runs
/// identical to `orig` when given. For post-mortem debugging only.
fn dump_text(dev: &device::Device, what: &str, buf: &[u8], orig: Option<&[u8]>) {
    const MIN_TEXT: usize = 12;
    const MAX_LINES: usize = 80;
    let printable = |c: u8| (0x20..0x7f).contains(&c) || c == b'\n' || c == b'\t';
    let mut lines = 0;
    let mut i = 0;
    while i < buf.len() && lines < MAX_LINES {
        if !printable(buf[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < buf.len() && printable(buf[i]) {
            i += 1;
        }
        if i - start < MIN_TEXT || orig.is_some_and(|o| o[start..i] == buf[start..i]) {
            continue;
        }
        for line in buf[start..i].split(|&c| c == b'\n').filter(|l| !l.is_empty()) {
            let line = &line[..line.len().min(160)];
            dev_info!(dev, "{} +{:#x}: {}\n", what, start, core::str::from_utf8(line).unwrap_or("?"));
            lines += 1;
            if lines >= MAX_LINES {
                dev_info!(dev, "{}: more text not shown\n", what);
                break;
            }
        }
    }
}

/// RTKit crash state in `__DATA` of AppleAVE2FW-6070.11.1 (macOS 13.5),
/// from `_RTK_abort`, `__rtk_arch_exception` and the crashlog recorder.
/// Firmware virtual addresses; `__DATA` is linked at 0xd0000.
mod fw6070 {
    pub(super) const DATA_VA: u64 = 0xd0000;
    pub(super) const VERSION_VA: u64 = 0x1edc26;
    pub(super) const VERSION: &[u8] = b"gIRTKit: RTKit-2062.141.1.release - Client: HEAD_c86a10b71_AppleAVE2FW-6070.11.1";
    /// `sub_9e2e4(reason)`: 3 = unhandled exception, 4 = `_RTK_abort`.
    pub(super) const HALT_REASON: u64 = 0x1f6998;
    pub(super) const CRASH_COUNT: u64 = 0xd28f0;
    pub(super) const CRASH_TYPE: u64 = 0xd2948;
    pub(super) const CRASH_FRAME: u64 = 0xd2950;
    pub(super) const CRASH_MSG: u64 = 0xd2960;
    pub(super) const EXC_COUNT: u64 = 0x1f69b8;
    pub(super) const EXC_TYPE: u64 = 0x1f69e8;
    pub(super) const EXC_FRAME: u64 = 0x1f69f0;
    /// Offsets in an exception frame.
    pub(super) const FRAME_LR: u64 = 0xf0;
    pub(super) const FRAME_PC: u64 = 0x100;
    pub(super) const FRAME_FAR: u64 = 0x328;
    pub(super) const FRAME_ESR: u64 = 0x338;
}

/// Decodes the firmware's crash record from a `__DATA` copy, if this is the
/// firmware build the addresses were taken from.
fn dump_crash(dev: &device::Device, data: &[u8]) {
    use fw6070::*;
    let at = |va: u64, n: usize| -> Option<&[u8]> {
        let off = usize::try_from(va.checked_sub(DATA_VA)?).ok()?;
        data.get(off..off.checked_add(n)?)
    };
    let u64_at = |va: u64| at(va, 8).map(le_u64);
    let u32_at = |va: u64| at(va, 4).map(le_u32);
    if at(VERSION_VA, VERSION.len()) != Some(VERSION) {
        dev_info!(dev, "unknown firmware build; crash state not decoded\n");
        return;
    }
    dev_info!(
        dev,
        "fw crash state: halt {:x?} crashes {:x?} type {:x?} frame {:x?} msg {:x?}; exceptions {:x?} type {:x?} frame {:x?}\n",
        u64_at(HALT_REASON),
        u32_at(CRASH_COUNT),
        u32_at(CRASH_TYPE),
        u64_at(CRASH_FRAME),
        u64_at(CRASH_MSG),
        u32_at(EXC_COUNT),
        u32_at(EXC_TYPE),
        u64_at(EXC_FRAME)
    );
    for frame in [u64_at(CRASH_FRAME), u64_at(EXC_FRAME)].into_iter().flatten() {
        if frame == 0 {
            continue;
        }
        match (
            u64_at(frame + FRAME_PC),
            u64_at(frame + FRAME_LR),
            u64_at(frame + FRAME_FAR),
            u64_at(frame + FRAME_ESR),
        ) {
            (Some(pc), Some(lr), Some(far), Some(esr)) => dev_info!(
                dev,
                "fw frame {:#x}: pc {:#x} lr {:#x} far {:#x} esr {:#x}\n",
                frame,
                pc,
                lr,
                far,
                esr
            ),
            _ => dev_info!(dev, "fw frame {:#x} is outside __DATA\n", frame),
        }
    }
}

/// Maps `__DATA` and copies it while the firmware has not run yet.
fn snapshot_data(res: kernel::io::resource::Resource, len: usize) -> Result<(Mem, KVVec<u8>)> {
    // SAFETY: The mapping is only used for CPU copies of the firmware's own
    // segment; it does not initiate DMA.
    let data_seg = unsafe { Mem::try_new(res, MemFlag::WC.into()) }?;
    if data_seg.size() < len {
        return Err(EINVAL);
    }
    let mut pristine = KVVec::with_capacity(len, GFP_KERNEL)?;
    // SAFETY: `data_seg` maps at least `len` bytes, checked above.
    let src = unsafe { core::slice::from_raw_parts(data_seg.ptr(), len) };
    pristine.extend_from_slice(src, GFP_KERNEL)?;
    Ok((data_seg, pristine))
}

struct AveDriver {
    dev: ARef<device::Device>,
    coproc: Pin<KBox<Devres<IoMem<COPROC_SIZE>>>>,
    mbox: Pin<KBox<Devres<IoMem<MBOX_SIZE>>>>,
    text: Segment,
    /// CPU mapping of the firmware's `__DATA` segment.
    data_seg: Mem,
    /// `__DATA` as iBoot left it, before the firmware first ran.
    pristine: KVVec<u8>,
    /// IPC surface and firmware heap, once handed to the firmware.
    ipc: Option<Shared>,
    heap: Option<Shared>,
}

// SAFETY: `Mem` is a plain mapping of reserved memory that is only touched
// from probe and drop, which the driver core serialises.
unsafe impl Send for AveDriver {}
// SAFETY: See above; no method takes `&self` concurrently.
unsafe impl Sync for AveDriver {}

impl AveDriver {
    fn boot(&mut self, pdev: &platform::Device<Core>) -> Result {
        let dev = &self.dev;
        let coproc = self.coproc.access(pdev.as_ref())?;
        let mbox = self.mbox.access(pdev.as_ref())?;

        let ctl = coproc.read32(ASC_CPU_CONTROL);
        let status = coproc.read32(ASC_CPU_STATUS);
        let boot = coproc.read64(BOOT_ADDR);
        dev_info!(
            dev,
            "before start: cpu_control {:#x} cpu_status {:#x} boot_addr {:#x} mbox_status {:#x}\n",
            ctl,
            status,
            boot,
            mbox.read32(MBOX_STATUS)
        );
        if ctl & CPU_RUN != 0 {
            dev_err!(dev, "the AVE CPU is already running\n");
            return Err(EBUSY);
        }

        // Keep iBoot's boot address. Recompute it from the ADT only to check
        // it, or to put it back after something (an earlier version of this
        // driver) overwrote it.
        let want = (self.text.remap & BOOT_ADDR_MASK) | BOOT_ADDR_MAGIC | BOOT_ADDR_BIT0;
        if self.text.remap & !BOOT_ADDR_MASK != 0 {
            dev_err!(dev, "__TEXT remap {:#x} does not fit the boot address\n", self.text.remap);
            return Err(EINVAL);
        }
        if boot != want {
            coproc.write64(want, BOOT_ADDR);
            dev_info!(
                dev,
                "boot_addr {:#x} -> {:#x} (reads back {:#x})\n",
                boot,
                want,
                coproc.read64(BOOT_ADDR)
            );
        }

        // AVE_HwC::StartUpIOP: SetIOPFlag(0), SVE ID, device ID.
        mbox.write32(IOP_FLAG_MAGIC, MBOX_WORD0);
        mbox.write32(0, MBOX_WORD0 + 4);
        mbox.write32(DEV_ID_T6000, MBOX_WORD0 + 8);

        // AVE_IOP_Start_Castor.
        coproc.write32(1, ASC_UNK_808);
        coproc.write32(0, ASC_CPU_CONTROL);
        coproc.write32(0x10000, ASC_UNK_400);
        coproc.write32(CPU_RUN, ASC_CPU_CONTROL);

        let w = mbox_recv(dev, coproc, mbox, "boot message")?;
        dev_info!(
            dev,
            "firmware up: {} IPC channels, buf {:#x}, desc {:#x}, heap {:#x}\n",
            w[0],
            w[1],
            w[2],
            w[3]
        );
        if w[0] == 0 || w[0] > IPC_CH_MAX || w[1] == 0 {
            dev_err!(dev, "unexpected boot message\n");
            return Err(EIO);
        }

        let r = handshake(pdev.as_ref(), coproc, mbox, &mut self.ipc, &mut self.heap, w);
        if r.is_err() {
            dev_err!(
                dev,
                "handshake failed: cpu_control {:#x} cpu_status {:#x}\n",
                coproc.read32(ASC_CPU_CONTROL),
                coproc.read32(ASC_CPU_STATUS)
            );
            self.dump_firmware_text();
        }
        r
    }

    /// Post-mortem: logs text the firmware left in its `__DATA` (only what
    /// changed since boot, e.g. console or assert output) and in the IPC
    /// memory. Best effort; allocation failures just skip a region.
    fn dump_firmware_text(&self) {
        let len = self.pristine.len();
        let mut data = KVVec::new();
        // SAFETY: `data_seg` maps at least `len` bytes (checked at probe);
        // reading it while the firmware runs only races on the values read.
        let src = unsafe { core::slice::from_raw_parts(self.data_seg.ptr(), len) };
        if data.extend_from_slice(src, GFP_KERNEL).is_ok() {
            dump_text(&self.dev, "__DATA", &data, Some(&self.pristine));
            dump_crash(&self.dev, &data);
        }
        if let Some(ipc) = &self.ipc {
            let mut buf = KVVec::new();
            let ok = (0..ipc.size())
                .step_by(4)
                .try_for_each(|off| -> Result {
                    buf.extend_from_slice(&ipc.r32(off)?.to_le_bytes(), GFP_KERNEL)?;
                    Ok(())
                })
                .is_ok();
            if ok {
                dump_text(&self.dev, "IPC", &buf, None);
            }
        }
    }

    /// Halts the CPU and puts `__DATA` back. Returns false if the firmware
    /// state cannot be trusted afterwards.
    fn stop(&self) -> bool {
        let Some(coproc) = self.coproc.try_access() else {
            dev_err!(self.dev, "stop: registers gone, firmware left as is\n");
            return false;
        };
        coproc.write32(0, ASC_CPU_CONTROL);
        let idle = read_poll_timeout(
            || Ok(coproc.read32(ASC_CPU_STATUS)),
            |s: &u32| s & CPU_STATUS_BUSY == 0,
            Delta::from_millis(1),
            Delta::from_millis(200),
        );
        if let Err(e) = idle {
            dev_err!(
                self.dev,
                "stop: CPU did not go idle (status {:#x}): {:?}\n",
                coproc.read32(ASC_CPU_STATUS),
                e
            );
            return false;
        }
        // SAFETY: `data_seg` maps `pristine.len()` bytes of reserved memory
        // that nothing else uses while the CPU is halted.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.pristine.as_ptr(),
                self.data_seg.ptr(),
                self.pristine.len(),
            )
        };
        true
    }
}

impl Drop for AveDriver {
    fn drop(&mut self) {
        if self.stop() {
            dev_info!(self.dev, "stopped; __DATA restored\n");
            STARTED.store(false, Relaxed);
        } else {
            // The firmware may still write to these; never free them.
            if let Some(m) = self.ipc.take() {
                core::mem::forget(m);
            }
            if let Some(m) = self.heap.take() {
                core::mem::forget(m);
            }
            dev_err!(self.dev, "firmware state unknown; not starting again until reboot\n");
        }
    }
}

kernel::of_device_table!(
    OF_TABLE,
    MODULE_OF_TABLE,
    (),
    [(of::DeviceId::new(c"apple,t6000-ave"), ())]
);

impl platform::Driver for AveDriver {
    type IdInfo = ();

    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);

    fn probe(pdev: &platform::Device<Core>, _info: Option<&()>) -> impl PinInit<Self, Error> {
        let dev: ARef<device::Device> = pdev.as_ref().into();
        let of = dev.of_node().ok_or(ENODEV)?;

        let (text, data) = read_segments(&dev)?;
        find_region(&dev, &of, &text)?;
        let data_res = find_region(&dev, &of, &data)?;
        check_mapping(&dev, &text)?;
        check_mapping(&dev, &data)?;

        let coproc_req = pdev.io_request_by_name(c"coproc").ok_or(EINVAL)?;
        let coproc = KBox::pin_init(coproc_req.iomap_sized::<COPROC_SIZE>(), GFP_KERNEL)?;
        let mbox_req = pdev.io_request_by_name(c"mbox").ok_or(EINVAL)?;
        let mbox = KBox::pin_init(mbox_req.iomap_sized::<MBOX_SIZE>(), GFP_KERNEL)?;

        if STARTED.xchg(true, Relaxed) {
            dev_err!(dev, "firmware already started this boot and not restored; reboot to retry\n");
            return Err(EBUSY);
        }
        // Nothing has run yet, so a failure here leaves __DATA untouched.
        let (data_seg, pristine) = snapshot_data(data_res, data.size as usize).inspect_err(|_| {
            STARTED.store(false, Relaxed);
        })?;
        dev_info!(
            dev,
            "firmware: text {:#x}+{:#x}, data {:#x}+{:#x}\n",
            text.phys,
            text.size,
            data.phys,
            data.size
        );

        let mut this = AveDriver {
            dev,
            coproc,
            mbox,
            text,
            data_seg,
            pristine,
            ipc: None,
            heap: None,
        };
        // On failure `this` is dropped, which halts the CPU and restores
        // __DATA (or leaves STARTED set if it cannot).
        this.boot(pdev)?;
        Ok(this)
    }
}

module_platform_driver! {
    type: AveDriver,
    name: "apple_ave",
    description: "Apple AVE2 video encoder",
    license: "Dual MIT/GPL",
}
