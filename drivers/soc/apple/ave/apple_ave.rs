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

mod bufsize;

use kernel::{
    bindings,
    device::{
        self,
        Bound,
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
    irq::{
        self,
        IrqReturn,
        ThreadedHandler,
        ThreadedIrqReturn,
        ThreadedRegistration, //
    },
    module_platform_driver, new_mutex, of, platform,
    prelude::*,
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            Relaxed, //
        },
        Arc,
        Mutex,
    },
    time::{
        msecs_to_jiffies,
        Delta, //
    },
    workqueue::{
        self,
        impl_has_delayed_work,
        new_delayed_work,
        DelayedWork,
        WorkItem, //
    },
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
/// Start of the host-managed allocation pool in the IPC memory, after the
/// channel and exchange memory.
const IPC_POOL_START: usize = 0x10000;
/// `AVE_HwC::ProcessIntr_Log` copies at most this much of a log message.
const LOG_MAX: usize = 0x200;
/// Fallback channel service period; the interrupt does the real work.
const POLL_MS: u32 = 1000;
/// Command buffer (`AVE_HwC::m_iCmdIPCBuf`, `Alloc(0xe0)`): two 0x70 slots.
const CMD_BUF_SIZE: usize = 0xe0;
/// Firmware command ids (`CFlowControllerBase::CmdProcessor`) and sizes.
const CMD_CONFIG: u32 = 1;
const CMD_CONFIG_SIZE: usize = 0x70;
/// `NotificationToHost` code for a completed Config, and "no error".
const NOTIFY_CONFIG_DONE: u32 = 0xe01;
const FW_ERROR_NONE: u32 = 0xee0000;
/// Notification message size (0x40, or 0x48 for two codes).
const NOTIFY_MAX: usize = 0x48;

/// ADT interrupt index the macOS driver uses (`filterInterruptEventSource`
/// index 0): the SVE mailbox status, one bit per channel.
const MBOX_IRQ_INDEX: u32 = 0;

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

/// `dma_rmb()`/`dma_wmb()`: order accesses to memory shared with the
/// (non-coherent) coprocessor.
fn dma_rmb() {
    // SAFETY: A barrier instruction; no memory or register side effects.
    unsafe { core::arch::asm!("dmb oshld", options(nostack, preserves_flags)) };
}

fn dma_wmb() {
    // SAFETY: As above.
    unsafe { core::arch::asm!("dmb oshst", options(nostack, preserves_flags)) };
}

/// First-fit allocator over the IPC memory past the channel and exchange
/// memory, standing in for macOS's `AVE_ChkPool` (0x40 alignment).
struct Pool {
    end: usize,
    /// (offset, size), sorted by offset.
    used: KVec<(usize, usize)>,
}

impl Pool {
    fn alloc(&mut self, size: usize) -> Option<usize> {
        let size = size.checked_next_multiple_of(IPC_ALIGN).filter(|&s| s != 0)?;
        let mut cur = IPC_POOL_START;
        for &(off, len) in self.used.iter() {
            if off - cur >= size {
                break;
            }
            cur = off + len;
        }
        if cur.checked_add(size)? > self.end {
            return None;
        }
        self.used.push((cur, size), GFP_KERNEL).ok()?;
        self.used.sort_unstable_by_key(|&(off, _)| off);
        Some(cur)
    }

    fn free(&mut self, off: usize) -> Option<usize> {
        let i = self.used.iter().position(|&(o, _)| o == off)?;
        self.used.remove(i).ok().map(|(_, len)| len)
    }
}

/// One host-side channel ring endpoint.
struct Ring {
    /// Offset of the ring in the IPC memory.
    off: usize,
    count: usize,
    /// Mailbox status/doorbell bit (descriptor +0x44).
    bit: u32,
    /// Next entry to look at.
    idx: usize,
}

impl Ring {
    fn entry(&self) -> usize {
        self.off + self.idx * CH_ENTRY_SIZE
    }

    fn advance(&mut self) {
        self.idx = (self.idx + 1) % self.count;
    }
}

/// Channels the host services, set up by the handshake.
struct Chans {
    fw_base: u64,
    /// SHAREDMALLOC: firmware requests, host replies in place (host role 0).
    malloc: Option<Ring>,
    /// TERMINAL: firmware log lines, unidirectional (host role 2).
    terminal: Option<Ring>,
    /// IO: host commands (host role 1). `idx` is the next slot to send in.
    io: Option<Ring>,
    /// Next IO slot the firmware will hand back, and commands outstanding.
    io_ret: usize,
    io_outstanding: usize,
    /// IO_T2H: firmware notifications, acked in place (host role 0).
    io_t2h: Option<Ring>,
    /// IPC offset of the command buffer.
    cmd_buf: usize,
    pool: Pool,
}

/// The IPC memory and the host side of its channels, shared with the
/// channel service work.
#[pin_data]
struct Ipc {
    dev: ARef<device::Device>,
    mem: Shared,
    mbox: Arc<Devres<IoMem<MBOX_SIZE>>>,
    /// Interrupts taken, for diagnostics.
    irqs: Atomic<u32>,
    /// Notifications received and the last code/error, for command waits.
    notifies: Atomic<u32>,
    last_code: Atomic<u32>,
    last_error: Atomic<u32>,
    #[pin]
    chans: Mutex<Chans>,
    /// Set on teardown; the work stops re-arming once it sees it.
    stopping: Atomic<bool>,
    /// The work is queued or running and will run again.
    armed: Atomic<bool>,
    #[pin]
    poll: DelayedWork<Ipc>,
}

impl_has_delayed_work! {
    impl HasDelayedWork<Self> for Ipc { self.poll }
}

impl WorkItem for Ipc {
    type Pointer = Arc<Ipc>;

    fn run(this: Arc<Ipc>) {
        if this.stopping.load(Relaxed) {
            this.armed.store(false, Relaxed);
            return;
        }
        match this.service() {
            Ok(0) => {}
            Ok(n) => dev_info!(
                this.dev,
                "fallback poll serviced {} entries ({} interrupts so far)\n",
                n,
                this.irqs.load(Relaxed)
            ),
            Err(e) => dev_err!(this.dev, "channel service failed: {:?}\n", e),
        }
        let _ = workqueue::system().enqueue_delayed(this, msecs_to_jiffies(POLL_MS));
    }
}

impl Ipc {
    fn new(
        bdev: &device::Device<device::Bound>,
        mbox: Arc<Devres<IoMem<MBOX_SIZE>>>,
    ) -> Result<Arc<Ipc>> {
        let mem = Shared::new(bdev, IPC_SIZE)?;
        let dev: &device::Device = bdev;
        Arc::pin_init(
            try_pin_init!(Ipc {
                dev: dev.into(),
                mem,
                mbox,
                irqs: Atomic::new(0),
                notifies: Atomic::new(0),
                last_code: Atomic::new(0),
                last_error: Atomic::new(0),
                chans <- new_mutex!(Chans {
                    fw_base: 0,
                    malloc: None,
                    terminal: None,
                    io: None,
                    io_ret: 0,
                    io_outstanding: 0,
                    io_t2h: None,
                    cmd_buf: 0,
                    pool: Pool { end: IPC_SIZE, used: KVec::new() },
                }),
                stopping: Atomic::new(false),
                armed: Atomic::new(false),
                poll <- new_delayed_work!("Ipc::poll"),
            }),
            GFP_KERNEL,
        )
    }

    fn start(this: &Arc<Ipc>) {
        this.armed.store(true, Relaxed);
        if workqueue::system().enqueue_delayed(this.clone(), 0).is_err() {
            this.armed.store(false, Relaxed);
        }
    }

    /// Stops the service work and waits until it has finished running.
    fn stop(&self) {
        self.stopping.store(true, Relaxed);
        // SAFETY: `poll` lives as long as `self`; `work` is the first member
        // of `struct delayed_work`.
        let dwork = unsafe { DelayedWork::raw_as_work(&self.poll) }.cast::<bindings::delayed_work>();
        for _ in 0..10 {
            // SAFETY: `dwork` was initialised by `new_delayed_work!`.
            unsafe { bindings::flush_delayed_work(dwork) };
            if !self.armed.load(Relaxed) {
                break;
            }
        }
        // The run that cleared `armed` may still be returning.
        // SAFETY: As above.
        unsafe { bindings::flush_delayed_work(dwork) };
    }

    /// Services the host's channels; returns the number of entries handled.
    fn service(&self) -> Result<usize> {
        let mut guard = self.chans.lock();
        let c = &mut *guard;
        let fw_base = c.fw_base;
        let mut n = 0;
        if let Some(r) = c.malloc.as_mut() {
            n += self.serve_malloc(fw_base, r, &mut c.pool)?;
        }
        if let Some(r) = c.terminal.as_mut() {
            n += self.drain_terminal(fw_base, r)?;
        }
        if let Some(r) = c.io.as_ref() {
            n += self.reap_commands(r, &mut c.io_ret, &mut c.io_outstanding)?;
        }
        if let Some(r) = c.io_t2h.as_mut() {
            n += self.serve_notifications(fw_base, r)?;
        }
        Ok(n)
    }

    /// `AVE_SVECtrl::SetIPCIntr`: tell the firmware a channel has news.
    fn doorbell(&self, bit: u32) {
        if let Some(mbox) = self.mbox.try_access() {
            mbox.write32(1 << bit, MBOX_DOORBELL);
        }
    }

    /// `AVE_HwC::ProcessIntr_IPCMem`: buffer 0 = allocate `size`, otherwise
    /// free the buffer. The reply goes back in the same entry.
    fn serve_malloc(&self, fw_base: u64, r: &mut Ring, pool: &mut Pool) -> Result<usize> {
        let mem = &self.mem;
        let mut n = 0;
        for _ in 0..r.count {
            let at = r.entry();
            let w0 = mem.r64(at)?;
            if w0 & 1 != 0 {
                break;
            }
            dma_rmb();
            let buf = w0 & !3;
            let size = mem.r64(at + 8)? as usize;
            let (reply, len) = if buf == 0 {
                match pool.alloc(size) {
                    Some(off) => {
                        for o in (off..off + size).step_by(4) {
                            mem.w32(o, 0)?;
                        }
                        dev_dbg!(self.dev, "fw alloc {:#x} -> IPC +{:#x}\n", size, off);
                        (fw_base + off as u64, size)
                    }
                    None => {
                        dev_err!(self.dev, "fw alloc of {:#x} bytes failed\n", size);
                        (0, 0)
                    }
                }
            } else {
                let off = usize::try_from(buf.wrapping_sub(fw_base)).unwrap_or(usize::MAX);
                match pool.free(off) {
                    Some(len) => dev_dbg!(self.dev, "fw free IPC +{:#x} ({:#x})\n", off, len),
                    None => dev_err!(self.dev, "fw freed unknown buffer {:#x}\n", buf),
                }
                (buf, 0)
            };
            mem.w64(at + 8, len as u64)?;
            mem.w64(at + 0x10, 0)?;
            dma_wmb();
            mem.w64(at, reply | 1)?;
            r.advance();
            n += 1;
        }
        // AVE_IPC::Send rings the channel's doorbell after each reply.
        if n != 0 {
            self.doorbell(r.bit);
        }
        Ok(n)
    }

    /// `AVE_HwC::ProcessIntr_Log`: print each line, hand the entry back.
    fn drain_terminal(&self, fw_base: u64, r: &mut Ring) -> Result<usize> {
        let mem = &self.mem;
        let mut n = 0;
        for _ in 0..r.count {
            let at = r.entry();
            let w0 = mem.r64(at)?;
            if w0 & 1 != 0 {
                break;
            }
            dma_rmb();
            let off = usize::try_from((w0 & !3).wrapping_sub(fw_base)).unwrap_or(usize::MAX);
            let len = (mem.r64(at + 8)? as usize).min(LOG_MAX);
            if off.checked_add(len).is_some_and(|end| end <= IPC_SIZE) {
                let mut text = [0u8; LOG_MAX + 4];
                for o in (0..len).step_by(4) {
                    let a = (off + o) & !3;
                    let word = mem.r32(a)?.to_le_bytes();
                    for (k, b) in word.iter().enumerate() {
                        let pos = a + k;
                        if pos >= off && pos < off + len {
                            text[pos - off] = *b;
                        }
                    }
                }
                let end = text[..len].iter().position(|&c| c == 0).unwrap_or(len);
                for line in text[..end].split(|&c| c == b'\n' || c == b'\r').filter(|l| !l.is_empty()) {
                    dev_info!(self.dev, "fw: {}\n", core::str::from_utf8(line).unwrap_or("<non-UTF-8>"));
                }
            } else {
                dev_warn!(self.dev, "log message outside the IPC memory: {:#x}\n", w0);
            }
            // Unidirectional receive: give the entry back (host role 2 ^ 1).
            mem.w64(at, 3)?;
            r.advance();
            n += 1;
        }
        Ok(n)
    }

    /// `AVE_HwC::ProcessIntr_CmdAck`: the firmware hands command entries
    /// back once it has taken the command (owner bit back to host role 1).
    fn reap_commands(&self, r: &Ring, ret: &mut usize, outstanding: &mut usize) -> Result<usize> {
        let mut n = 0;
        while *outstanding != 0 {
            let at = r.off + *ret * CH_ENTRY_SIZE;
            let w0 = self.mem.r64(at)?;
            if w0 & 1 == 0 {
                break;
            }
            dev_dbg!(self.dev, "fw took command at {:#x}\n", w0 & !3);
            *ret = (*ret + 1) % r.count;
            *outstanding -= 1;
            n += 1;
        }
        Ok(n)
    }

    /// `ProcessIntr_IPCCh` case 2: log the notification and echo the entry
    /// back (the firmware's `PostCmdSynchronous` waits for that).
    fn serve_notifications(&self, fw_base: u64, r: &mut Ring) -> Result<usize> {
        let mem = &self.mem;
        let mut n = 0;
        for _ in 0..r.count {
            let at = r.entry();
            let w0 = mem.r64(at)?;
            if w0 & 1 != 0 {
                break;
            }
            dma_rmb();
            let buf = w0 & !3;
            let size = mem.r64(at + 8)?;
            let off = usize::try_from(buf.wrapping_sub(fw_base)).unwrap_or(usize::MAX);
            if off.checked_add(NOTIFY_MAX).is_some_and(|end| end <= IPC_SIZE) && off % 4 == 0 {
                let code = mem.r32(off)? & 0xffff;
                let client = mem.r32(off + 0x10)?;
                let tag = mem.r32(off + 0x1c)?;
                let error = mem.r32(off + 0x38)?;
                dev_info!(
                    self.dev,
                    "fw notify {:#x}: client {} tag {:#x} error {:#x} (size {:#x})\n",
                    code,
                    client,
                    tag,
                    error,
                    size
                );
                self.last_code.store(code, Relaxed);
                self.last_error.store(error, Relaxed);
            } else {
                dev_warn!(self.dev, "notification outside the IPC memory: {:#x}\n", w0);
            }
            self.notifies.fetch_add(1, Relaxed);
            mem.w64(at + 0x10, 0)?;
            dma_wmb();
            mem.w64(at, buf | 1)?;
            r.advance();
            n += 1;
        }
        if n != 0 {
            self.doorbell(r.bit);
        }
        Ok(n)
    }

    /// `AVE_IPC::Send(IO, ...)`: queue the command at IPC offset `cmd` and
    /// ring the IO doorbell.
    fn send_command(&self, c: &mut Chans, cmd: usize, len: usize) -> Result {
        let fw = c.fw_base + cmd as u64;
        let r = c.io.as_mut().ok_or(ENODEV)?;
        if c.io_outstanding >= r.count {
            return Err(EBUSY);
        }
        let at = r.entry();
        if self.mem.r64(at)? & 1 == 0 {
            // Still owned by the firmware.
            return Err(EBUSY);
        }
        self.mem.w64(at + 8, len as u64)?;
        self.mem.w64(at + 0x10, 0)?;
        dma_wmb();
        // Host role 1: hand the entry to the firmware (owner bit 0).
        self.mem.w64(at, fw)?;
        let bit = r.bit;
        r.advance();
        c.io_outstanding += 1;
        self.doorbell(bit);
        Ok(())
    }

    /// `AVE_HwC::SendFwCmd_Config` with `MakeFwCmd_Config`'s Castor values
    /// (`AVE_Cfg_Default`), then wait for `NotificationToHost(0xe01)`.
    fn config(&self) -> Result {
        let before = self.notifies.load(Relaxed);
        {
            let mut guard = self.chans.lock();
            let c = &mut *guard;
            let b = c.cmd_buf;
            let mem = &self.mem;
            for o in (0..CMD_CONFIG_SIZE).step_by(4) {
                mem.w32(b + o, 0)?;
            }
            mem.w32(b, CMD_CONFIG)?;
            // +0x10..+0x1f: client 0, ..., tag 0xffffffff.
            mem.w32(b + 0x1c, 0xffff_ffff)?;
            // +0x28: timeout, iTimeOutCntFactor (1) * 3000.
            mem.w64(b + 0x28, 3000)?;
            // +0x40 cfg type == 3 (0), +0x41 1, +0x42 cfg+0x75 (1).
            mem.w32(b + 0x40, 0x0001_0100)?;
            // +0x48 PMGR DART address: not mapped on chip types > 5.
            // +0x50/+0x54 doorbell cadence, +0x58/+0x59 DSIDs, +0x60/+0x68
            // surface: 0.
            self.send_command(c, b, CMD_CONFIG_SIZE)?;
        }
        dev_info!(self.dev, "sent Config\n");
        for _ in 0..3000 {
            if self.notifies.load(Relaxed) != before {
                let (code, error) = (self.last_code.load(Relaxed), self.last_error.load(Relaxed));
                if code == NOTIFY_CONFIG_DONE && error == FW_ERROR_NONE {
                    dev_info!(self.dev, "Config done\n");
                    return Ok(());
                }
                dev_err!(self.dev, "Config: notification {:#x} error {:#x}\n", code, error);
                return Err(EIO);
            }
            kernel::time::delay::fsleep(Delta::from_millis(1));
        }
        dev_err!(self.dev, "Config: no notification within 3 s\n");
        Err(ETIMEDOUT)
    }
}

/// The mailbox interrupt (`AVE_HwC::FilterISR`/`ProcessIntr`): ack the
/// status bits in hard IRQ context, service the channels in the thread.
#[pin_data]
struct AveIrq {
    ipc: Arc<Ipc>,
}

impl ThreadedHandler for AveIrq {
    fn handle(&self, dev: &device::Device<Bound>) -> ThreadedIrqReturn {
        let Ok(mbox) = self.ipc.mbox.access(dev) else {
            return ThreadedIrqReturn::None;
        };
        let status = mbox.read32(MBOX_STATUS);
        if status == 0 {
            return ThreadedIrqReturn::None;
        }
        // AVE_SVECtrl::ClearIntr: write-one-to-clear.
        mbox.write32(status, MBOX_STATUS);
        if mbox.read32(MBOX_STATUS) & status == status {
            // Not cleared: claim nothing, so a stuck level interrupt gets
            // disabled by the spurious-IRQ detector instead of livelocking.
            // The fallback poll keeps the channels going.
            return ThreadedIrqReturn::None;
        }
        ThreadedIrqReturn::WakeThread
    }

    fn handle_threaded(&self, _dev: &device::Device<Bound>) -> IrqReturn {
        let ipc = &self.ipc;
        if ipc.irqs.fetch_add(1, Relaxed) == 0 {
            dev_info!(ipc.dev, "first mailbox interrupt\n");
        }
        if !ipc.stopping.load(Relaxed) {
            if let Err(e) = ipc.service() {
                dev_err!(ipc.dev, "channel service failed: {:?}\n", e);
            }
        }
        IrqReturn::Handled
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
/// chip types >= 6. The IPC memory and the heap are owned by the driver
/// before the firmware learns about them, so they outlive the CPU on every
/// error path.
fn handshake(
    dev: &device::Device<device::Bound>,
    coproc: &IoMem<COPROC_SIZE>,
    mbox: &IoMem<MBOX_SIZE>,
    shared: &Ipc,
    heap_slot: &mut Option<Shared>,
    first: [u32; MBOX_NUM_WORDS],
) -> Result {
    let (nch, buf_size, desc_size, heap_size) =
        (first[0], first[1] as usize, first[2], first[3] as usize);
    let xchg_off = buf_size.next_multiple_of(IPC_ALIGN);
    if desc_size != CH_DESC_SIZE
        || (nch * CH_DESC_SIZE) as usize > buf_size
        || xchg_off + XCHG_SIZE > IPC_POOL_START
    {
        dev_err!(dev, "unsupported channel layout: {} x {:#x} in {:#x}\n", nch, desc_size, buf_size);
        return Err(EIO);
    }

    // IPC memory: tell the firmware where it is, learn its address for it.
    let ipc = &shared.mem;
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
    let (mut malloc, mut terminal, mut io, mut io_t2h) = (None, None, None, None);
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
        let bit = ipc.r32(d + CH_DESC_TYPE)?;
        let host_ring = || Ring { off: ring, count, bit, idx: 0 };
        match (name, role) {
            ("SHAREDMALLOC", 0) => malloc = Some(host_ring()),
            ("TERMINAL", 2) => terminal = Some(host_ring()),
            ("IO", 1) => io = Some(host_ring()),
            ("IO_T2H", 0) => io_t2h = Some(host_ring()),
            _ => {}
        }
    }
    if malloc.is_none() || terminal.is_none() || io.is_none() || io_t2h.is_none() {
        dev_err!(dev, "SHAREDMALLOC, TERMINAL, IO or IO_T2H channel missing or unexpected\n");
        return Err(EIO);
    }
    {
        let mut c = shared.chans.lock();
        c.fw_base = fw_base;
        c.malloc = malloc;
        c.terminal = terminal;
        c.io = io;
        c.io_t2h = io_t2h;
        c.cmd_buf = c.pool.alloc(CMD_BUF_SIZE).ok_or(ENOMEM)?;
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

/// Smoke test of the `bufsize` port: the firmware buffer set the kext would
/// size for an 8-bit 4:2:0 H.264 session at usage Default, no B-frames.
fn log_buffer_set(dev: &device::Device, w: u32, h: u32) {
    use bufsize::*;
    let dev_type = DEV_TYPE_T6000;
    let refs = ref_num_default(30, 0, 0);
    let coded_num = coded_data_num(dev_type, 0, 0, 0, 1, false, false);
    let coded = coded_data_size(&CodedDataArgs {
        codec: CODEC_AVC,
        w,
        h,
        chroma: CHROMA_420,
        depth: 8,
        explicit: 0,
        percent: 0,
    });
    let recon = recon_size_avc(w, h, CHROMA_420);
    dev_info!(
        dev,
        "bufsize {}x{} AVC: refs {} | coded {} x {:#x} | header {} x {:#x} | params {:#x} | recon {:#x}+{:#x} | colocated {} x {:#x}\n",
        w,
        h,
        refs,
        coded_num,
        coded,
        coded_num,
        CODED_HEADER_SIZE,
        param_set_size(CODEC_AVC, 1),
        recon.luma,
        recon.chroma,
        colocated_num(refs, 0, -1, false),
        colocated_size(CODEC_AVC, w, h)
    );
    dev_info!(
        dev,
        "bufsize {}x{} AVC: lowres {} x {:#x} | lowres results {} x {} x {:#x} | nbr info/pixel/data {:#x}/{:#x}/{:#x} | entropy {:#x} | fw client {:#x}\n",
        w,
        h,
        lowres_ref_num(refs, 0, -1, false, false),
        lowres_ref_size(dev_type, CODEC_AVC, w, h, CHROMA_420),
        lowres_result_set_num(false),
        lowres_result_num(dev_type),
        lowres_result_size(dev_type, CODEC_AVC, w, h),
        src_nbr_info_size(CODEC_AVC, w, h),
        src_nbr_pixel_size(CODEC_AVC, w, h),
        src_nbr_data_size(CODEC_AVC, w),
        entropy_size(CODEC_AVC, w, h, CHROMA_420, 8, false),
        fw_client_size(0xb0000)
    );
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
    mbox: Arc<Devres<IoMem<MBOX_SIZE>>>,
    text: Segment,
    /// CPU mapping of the firmware's `__DATA` segment.
    data_seg: Mem,
    /// `__DATA` as iBoot left it, before the firmware first ran.
    pristine: KVVec<u8>,
    /// Mailbox interrupt, registered once the handshake is done.
    irq: Option<Pin<KBox<ThreadedRegistration<AveIrq>>>>,
    /// IPC memory and its channel service, and the firmware heap.
    ipc: Option<Arc<Ipc>>,
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

        let ipc = self.ipc.insert(Ipc::new(pdev.as_ref(), self.mbox.clone())?).clone();
        let r = handshake(pdev.as_ref(), coproc, mbox, &ipc, &mut self.heap, w);
        if r.is_ok() {
            // The handshake polled the status register itself; from here on
            // the interrupt acks it. The firmware's first SHAREDMALLOC
            // request is already waiting, so it fires right away.
            let irq_ipc = ipc.clone();
            let reg = KBox::pin_init(
                pdev.request_threaded_irq_by_index(
                    irq::Flags::TRIGGER_NONE,
                    MBOX_IRQ_INDEX,
                    c"apple-ave",
                    try_pin_init!(AveIrq { ipc: irq_ipc }),
                ),
                GFP_KERNEL,
            )
            .inspect_err(|e| dev_err!(dev, "mailbox interrupt: {:?}\n", e))?;
            self.irq = Some(reg);
            Ipc::start(&ipc);
            // First command. Not fatal: leave the firmware up for inspection.
            if let Err(e) = ipc.config() {
                dev_err!(dev, "Config failed: {:?}\n", e);
            }
            log_buffer_set(dev, 1920, 1080);
        } else {
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
        if let Some(ipc) = self.ipc.as_ref().map(|i| &i.mem) {
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
        // No channel service once the CPU is halted: free the interrupt
        // (waits for a running handler), then stop the fallback work.
        drop(self.irq.take());
        if let Some(ipc) = &self.ipc {
            ipc.stop();
        }
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
        let mbox = Arc::pin_init(mbox_req.iomap_sized::<MBOX_SIZE>(), GFP_KERNEL)?;

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
            irq: None,
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
