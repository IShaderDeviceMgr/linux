// SPDX-License-Identifier: GPL-2.0-only OR MIT
#![recursion_limit = "2048"]

//! Apple SEP (Secure Enclave Processor) transport driver.
//!
//! On T8103 and T6000 the SEP is not running when Linux starts. m1n1 reserves
//! the SEPOS image as the `sepfw` region and copies the boot manifests into
//! this node; the driver builds the shared-memory table, runs the boot
//! handshake on the boot endpoint and then records the endpoints the SEP
//! advertises.
//!
//! The handshake is one-shot per system boot: once the SEP has taken a
//! shared-memory table it cannot be given another, and the memory it was
//! handed must never be freed. The driver therefore pins its module as soon
//! as it starts the handshake, refuses to attach a second time, and leaks its
//! state if it is ever unbound.
//!
//! This is only the transport. Services that need storage or policy (xART,
//! the key store, Touch ID) are served from userspace; see SEP.md.
//!
//! Copyright (C) The Asahi Linux Contributors

mod control;
mod proto;
mod rxring;
mod shmem;

use kernel::{
    bindings,
    device,
    module_platform_driver,
    new_condvar,
    new_mutex,
    of,
    platform,
    prelude::*,
    soc::apple::mailbox::{
        MailCallback,
        Mailbox,
        Message, //
    },
    sync::{
        aref::ARef,
        atomic::{
            Atomic,
            Relaxed, //
        },
        Arc,
        CondVar,
        CondVarTimeoutResult,
        Mutex, //
    },
    time,
    types::ForeignOwnable,
    workqueue::{
        self,
        impl_has_delayed_work,
        impl_has_work,
        new_delayed_work,
        new_work,
        DelayedWork,
        Work,
        WorkItem, //
    }, //
};

/// Set once the boot handshake has started; never cleared (see module docs).
static ATTACHED: Atomic<bool> = Atomic::new(false);

const RX_WORK: u64 = 0;
const SETTLE_WORK: u64 = 1;

/// Quiet period that ends a burst of discovery messages.
const SETTLE_MS: time::Msecs = 500;
/// How long to wait for the first endpoint after the IMG4 acknowledgement.
/// J316s starts discovery about 370 ms after it (reference driver).
const FIRST_ENDPOINT_MS: u32 = 6000;
const CONTROL_TIMEOUT_MS: time::Msecs = 2000;
const ENTROPY_PROBE_WORDS: usize = 4;
/// Per-endpoint cap on logged messages from services nobody serves yet.
const UNSERVED_LOG_MAX: u32 = 8;

const PHASE_TZ0_SENT: u32 = 0;
const PHASE_SHMEM_SENT: u32 = 1;
const PHASE_RUNNING: u32 = 2;

struct FwRegion {
    addr: u64,
    size: usize,
}

struct Endpoints {
    names: [Option<[u8; 4]>; 256],
    count: usize,
    /// Messages received per endpoint that has no handler in this driver.
    unserved: [u32; 256],
}

impl Endpoints {
    fn new() -> Self {
        Endpoints {
            names: [None; 256],
            count: 0,
            unserved: [0; 256],
        }
    }
}

fn service_name(ep: u8) -> &'static str {
    match ep {
        proto::EP_CONTROL => "control",
        proto::EP_SBIO => "biometric (SBIO)",
        proto::EP_SCRD => "credential (SCRD)",
        proto::EP_SKS => "key store (SKS)",
        proto::EP_XARM => "xART storage (XARM)",
        _ => "",
    }
}

#[pin_data]
struct SepData {
    dev: ARef<device::Device>,
    #[pin]
    mbox: Mutex<Option<Mailbox<SepData>>>,
    shmem: shmem::ShMem,
    fw: FwRegion,
    fw_mapped: Atomic<bool>,
    phase: Atomic<u32>,
    shutting_down: Atomic<bool>,

    rx: rxring::RxRing,
    #[pin]
    rx_work: Work<SepData, RX_WORK>,

    /// Discovery messages seen; the settle work waits for this to go quiet.
    discovered: Atomic<u32>,
    settle_mark: Atomic<u32>,
    settle_idle_ms: Atomic<u32>,
    surveyed: Atomic<bool>,
    #[pin]
    settle_work: DelayedWork<SepData, SETTLE_WORK>,

    #[pin]
    endpoints: Mutex<Endpoints>,

    #[pin]
    control: Mutex<control::ControlState>,
    #[pin]
    control_wq: CondVar,
}

impl_has_work! {
    impl HasWork<Self, RX_WORK> for SepData { self.rx_work }
}

impl_has_delayed_work! {
    impl HasDelayedWork<Self, SETTLE_WORK> for SepData { self.settle_work }
}

// SAFETY: every mutable field is behind a `Mutex`, an atomic or the SPSC ring
// (whose own safety comment covers it). The DMA buffer is written only in
// `shmem::build`, before the SEP is told about it, and read only by the SEP.
// The mailbox handle is only used under its mutex.
unsafe impl Send for SepData {}
// SAFETY: see above.
unsafe impl Sync for SepData {}

impl SepData {
    fn new(pdev: &platform::Device<device::Core>, fw: FwRegion) -> Result<Arc<SepData>> {
        let dev: &device::Device = pdev.as_ref();
        Arc::pin_init(
            try_pin_init!(SepData {
                shmem: shmem::build(pdev)?,
                dev: ARef::<device::Device>::from(dev),
                mbox <- new_mutex!(None),
                fw,
                fw_mapped: Atomic::new(false),
                phase: Atomic::new(PHASE_TZ0_SENT),
                shutting_down: Atomic::new(false),
                rx: rxring::RxRing::new(),
                rx_work <- new_work!("SepData::rx_work"),
                discovered: Atomic::new(0),
                settle_mark: Atomic::new(0),
                settle_idle_ms: Atomic::new(0),
                surveyed: Atomic::new(false),
                settle_work <- new_delayed_work!("SepData::settle_work"),
                endpoints <- new_mutex!(Endpoints::new()),
                control <- new_mutex!(control::ControlState::new()),
                control_wq <- new_condvar!("SepData::control_wq"),
            }),
            GFP_KERNEL,
        )
    }

    fn send(&self, msg: Message) -> Result<()> {
        let guard = self.mbox.lock();
        let mbox: &Option<Mailbox<SepData>> = &guard;
        mbox.as_ref().ok_or(ENODEV)?.send(msg, false)
    }

    // --- boot handshake ---------------------------------------------------

    fn start(&self) -> Result<()> {
        dev_info!(self.dev, "boot: sending TZ0\n");
        self.send(proto::encode(proto::EP_BOOT, 0, proto::BOOT_TZ0, 0, 0))
    }

    /// Second TZ0 acknowledgement: hand over the firmware and the table.
    fn send_firmware_and_shmem(&self) -> Result<()> {
        if self.fw_mapped.xchg(true, Relaxed) {
            dev_warn!(self.dev, "boot: repeated TZ0 acknowledgement ignored\n");
            return Ok(());
        }

        // SAFETY: `self.dev` is a live device and the region is the reserved
        // `sepfw` memory m1n1 described for it. The mapping is never undone:
        // the SEP keeps using this IOVA for the rest of the boot.
        let fw_iova = unsafe {
            let iova = bindings::dma_map_resource(
                self.dev.as_raw(),
                self.fw.addr,
                self.fw.size,
                bindings::dma_data_direction_DMA_TO_DEVICE,
                0,
            );
            if bindings::dma_mapping_error(self.dev.as_raw(), iova) != 0 {
                dev_err!(self.dev, "boot: could not map the SEP firmware\n");
                return Err(ENOMEM);
            }
            iova
        };
        let shm_iova = self.shmem.dma_handle();
        let (Some(fw_field), Some(shm_field)) =
            (proto::iova_field(fw_iova), proto::iova_field(shm_iova))
        else {
            dev_err!(
                self.dev,
                "boot: IOVAs out of range for the SEP (firmware {:#x}, table {:#x})\n",
                fw_iova,
                shm_iova
            );
            return Err(ERANGE);
        };

        self.send(proto::encode(
            proto::EP_BOOT,
            0,
            proto::BOOT_IMG4,
            0,
            fw_field,
        ))?;
        self.phase.store(PHASE_SHMEM_SENT, Relaxed);
        self.send(proto::encode(
            proto::EP_SHMEM,
            0,
            proto::SHMEM_SET,
            0,
            shm_field,
        ))?;
        dev_info!(
            self.dev,
            "boot: firmware at IOVA {:#x} ({} bytes), table at IOVA {:#x}\n",
            fw_iova,
            self.fw.size,
            shm_iova
        );
        Ok(())
    }

    fn on_boot(this: &Arc<SepData>, f: proto::Fields) {
        match f.ty {
            proto::BOOT_TZ0_ACK1 => dev_info!(this.dev, "boot: TZ0 acknowledged (1/2)\n"),
            proto::BOOT_TZ0_ACK2 => {
                dev_info!(this.dev, "boot: TZ0 acknowledged (2/2)\n");
                if let Err(e) = this.send_firmware_and_shmem() {
                    dev_err!(this.dev, "boot: firmware/table handoff failed: {:?}\n", e);
                }
            }
            proto::BOOT_IMG4_ACK => {
                dev_info!(this.dev, "boot: IMG4 acknowledged; SEPOS is running\n");
                this.phase.store(PHASE_RUNNING, Relaxed);
                Self::arm_settle(this);
            }
            ty => dev_warn!(this.dev, "boot: unknown message type {:#04x}\n", ty),
        }
    }

    // --- receive path -----------------------------------------------------

    fn drain(this: &Arc<SepData>) {
        let dropped = this.rx.take_dropped();
        if dropped > 0 {
            dev_err!(this.dev, "rx: ring full, {} message(s) dropped\n", dropped);
        }
        while let Some(msg) = this.rx.pop() {
            Self::dispatch(this, msg);
        }
    }

    fn dispatch(this: &Arc<SepData>, msg: Message) {
        let f = proto::decode(&msg);
        match f.ep {
            proto::EP_BOOT => Self::on_boot(this, f),
            proto::EP_DISCOVER => Self::on_discover(this, f, msg),
            proto::EP_CONTROL => this.on_control(f),
            proto::EP_SHMEM => {}
            ep => this.on_unserved(ep, msg),
        }
    }

    fn on_discover(this: &Arc<SepData>, f: proto::Fields, msg: Message) {
        match f.ty {
            proto::DISCOVER_DESCRIPTOR | proto::DISCOVER_CONFIG => {
                let name = proto::fourcc(f.data);
                let count = {
                    let mut eps = this.endpoints.lock();
                    let slot = &mut eps.names[usize::from(f.param)];
                    let new = slot.is_none();
                    if f.ty == proto::DISCOVER_DESCRIPTOR {
                        *slot = Some(name);
                    } else if new {
                        *slot = Some(*b"????");
                    }
                    if new {
                        eps.count += 1;
                    }
                    eps.count
                };
                dev_info!(
                    this.dev,
                    "discover: endpoint {:#04x} type {} data {:#010x} '{}' {} ({} known)\n",
                    f.param,
                    f.ty,
                    f.data,
                    core::str::from_utf8(&name).unwrap_or("????"),
                    service_name(f.param),
                    count
                );
            }
            ty => dev_info!(
                this.dev,
                "discover: type {} (msg0 {:#018x})\n",
                ty,
                msg.msg0
            ),
        }
        this.discovered.fetch_add(1, Relaxed);
        Self::arm_settle(this);
    }

    fn on_control(&self, f: proto::Fields) {
        if f.ty != proto::CONTROL_REPLY {
            // SEP-initiated; seen on J314s: types 0x0d and 0x29 right after
            // discovery, 0x10 later, all with tag 0. Meaning unknown (SEP.md
            // O11), so log every field.
            dev_info!(
                self.dev,
                "control: unsolicited type {:#04x} tag {:#04x} param {:#04x} data {:#010x}\n",
                f.ty,
                f.tag,
                f.param,
                f.data
            );
            return;
        }
        if self.control.lock().deliver(f.tag, f.data) {
            self.control_wq.notify_all();
        }
    }

    /// Messages for services this driver does not serve yet. XARM requests
    /// are deliberately left unanswered: until the userspace xART server
    /// exists there is nothing correct to reply with (see SEP.md §3.1).
    fn on_unserved(&self, ep: u8, msg: Message) {
        let n = {
            let mut eps = self.endpoints.lock();
            let n = &mut eps.unserved[usize::from(ep)];
            *n = n.saturating_add(1);
            *n
        };
        if n > UNSERVED_LOG_MAX {
            return;
        }
        if ep == proto::EP_XARM {
            let b = msg.msg0.to_le_bytes();
            dev_info!(
                self.dev,
                "xarm: request tag {:#04x} op {:#04x} len {} args {:02x} {:02x} {:02x} held (no xART server)\n",
                b[1],
                b[2],
                u16::from_le_bytes([b[3], b[4]]),
                b[5],
                b[6],
                b[7]
            );
        } else {
            dev_info!(
                self.dev,
                "rx: endpoint {:#04x} {} unserved (msg0 {:#018x})\n",
                ep,
                service_name(ep),
                msg.msg0
            );
        }
    }

    // --- control endpoint -------------------------------------------------

    fn control_call(&self, op: u8, param: u8, data: u32, fixed_tag: Option<u8>) -> Result<u32> {
        let (idx, tag) = {
            let mut c = self.control.lock();
            match fixed_tag {
                Some(tag) => (c.alloc_fixed(tag)?, tag),
                None => c.alloc()?,
            }
        };
        if let Err(e) = self.send(control::encode(tag, op, param, data)) {
            self.control.lock().abandon(idx, false);
            return Err(e);
        }

        let mut remaining = time::msecs_to_jiffies(CONTROL_TIMEOUT_MS);
        let mut guard = self.control.lock();
        loop {
            if let Some(reply) = guard.take(idx) {
                return Ok(reply);
            }
            if self.shutting_down.load(Relaxed) {
                guard.abandon(idx, true);
                return Err(ENODEV);
            }
            match self
                .control_wq
                .wait_interruptible_timeout(&mut guard, remaining)
            {
                CondVarTimeoutResult::Woken { jiffies } => remaining = jiffies,
                CondVarTimeoutResult::Timeout => {
                    if let Some(reply) = guard.take(idx) {
                        return Ok(reply);
                    }
                    guard.abandon(idx, true);
                    return Err(ETIMEDOUT);
                }
                CondVarTimeoutResult::Signal { .. } => {
                    guard.abandon(idx, true);
                    return Err(EINTR);
                }
            }
        }
    }

    // --- settle: runs once discovery has gone quiet -------------------------

    fn arm_settle(this: &Arc<SepData>) {
        if this.shutting_down.load(Relaxed) || this.surveyed.load(Relaxed) {
            return;
        }
        // Already pending is fine: the tick re-arms while traffic continues.
        // system_long: the survey blocks on control replies for seconds.
        let _ = workqueue::system_long().enqueue_delayed::<Arc<SepData>, SETTLE_WORK>(
            this.clone(),
            time::msecs_to_jiffies(SETTLE_MS),
        );
    }

    fn settle(this: &Arc<SepData>) {
        if this.shutting_down.load(Relaxed) || this.surveyed.load(Relaxed) {
            return;
        }
        let seen = this.discovered.load(Relaxed);
        if seen != this.settle_mark.load(Relaxed) {
            this.settle_mark.store(seen, Relaxed);
            this.settle_idle_ms.store(0, Relaxed);
            Self::arm_settle(this);
            return;
        }
        if seen == 0 {
            let idle = this.settle_idle_ms.load(Relaxed).saturating_add(SETTLE_MS);
            this.settle_idle_ms.store(idle, Relaxed);
            if idle < FIRST_ENDPOINT_MS {
                Self::arm_settle(this);
                return;
            }
            dev_err!(
                this.dev,
                "attach: no endpoint advertised {} ms after IMG4\n",
                idle
            );
        }
        if this.surveyed.xchg(true, Relaxed) {
            return;
        }
        this.survey();
    }

    /// Read-only health survey after the first discovery burst: lists the
    /// endpoints and exercises the control endpoint. Nothing here changes SEP
    /// state. GET_ENTROPY is probed but its output is not used for anything:
    /// on 13.5 firmware it has been seen to return zeros (SEP.md O4).
    fn survey(&self) {
        {
            let eps = self.endpoints.lock();
            dev_info!(self.dev, "attach: {} endpoint(s) advertised\n", eps.count);
            for (id, name) in eps.names.iter().enumerate() {
                if let Some(name) = name {
                    dev_info!(
                        self.dev,
                        "  {:#04x} '{}' {}\n",
                        id,
                        core::str::from_utf8(name).unwrap_or("????"),
                        service_name(id as u8)
                    );
                }
            }
        }

        match self.control_call(control::OP_NOP, 0, 0, None) {
            Ok(_) => dev_info!(self.dev, "control: NOP answered\n"),
            Err(e) => dev_err!(self.dev, "control: NOP failed: {:?}\n", e),
        }
        match self.control_call(control::OP_SECMODE, 0, 0, None) {
            Ok(v) => dev_info!(self.dev, "control: security mode {:#x}\n", v),
            Err(e) => dev_warn!(self.dev, "control: security mode query failed: {:?}\n", e),
        }

        let mut answered = 0;
        let mut any_bits = 0u32;
        for _ in 0..ENTROPY_PROBE_WORDS {
            match self.control_call(control::OP_GET_ENTROPY, 0, 0, Some(control::TAG_ENTROPY)) {
                Ok(v) => {
                    answered += 1;
                    any_bits |= v;
                }
                Err(e) => {
                    dev_warn!(self.dev, "control: GET_ENTROPY failed: {:?}\n", e);
                    break;
                }
            }
        }
        let verdict = if answered == 0 {
            "no data"
        } else if any_bits == 0 {
            "ALL ZERO"
        } else {
            "non-zero"
        };
        dev_info!(
            self.dev,
            "control: GET_ENTROPY answered {}/{} word(s), {}; not registered as an RNG\n",
            answered,
            ENTROPY_PROBE_WORDS,
            verdict
        );

        let unmatched = self.control.lock().unmatched();
        if unmatched > 0 {
            dev_warn!(
                self.dev,
                "control: {} reply(ies) matched no request\n",
                unmatched
            );
        }
    }

    // --- teardown -----------------------------------------------------------

    fn detach(this: &Arc<SepData>) {
        this.shutting_down.store(true, Relaxed);
        this.control_wq.notify_all();
        // Stops the callbacks and drops the mailbox's reference to us.
        *this.mbox.lock() = None;
        // The SEP was given the table and the firmware IOVA for the rest of
        // this boot. Freeing either would let it DMA into reused memory, so
        // the state is leaked on purpose.
        core::mem::forget(this.clone());
        dev_warn!(
            this.dev,
            "detached; the SEP keeps its memory until reboot and cannot be re-attached\n"
        );
    }
}

impl MailCallback for SepData {
    type Data = Arc<SepData>;

    /// Hard-IRQ context, under the mailbox's receive spinlock: no sleeping,
    /// no allocation, no printing.
    fn recv_message(data: <Self::Data as ForeignOwnable>::Borrowed<'_>, msg: Message) {
        if data.shutting_down.load(Relaxed) {
            return;
        }
        data.rx.push(msg);
        let this: Arc<SepData> = data.into();
        // Already queued is fine: the pending drain picks this message up.
        let _ = workqueue::system().enqueue::<Arc<SepData>, RX_WORK>(this);
    }
}

impl WorkItem<RX_WORK> for SepData {
    type Pointer = Arc<SepData>;

    fn run(this: Arc<SepData>) {
        if !this.shutting_down.load(Relaxed) {
            SepData::drain(&this);
        }
    }
}

impl WorkItem<SETTLE_WORK> for SepData {
    type Pointer = Arc<SepData>;

    fn run(this: Arc<SepData>) {
        SepData::settle(&this);
    }
}

struct SepDriver(Arc<SepData>);

kernel::of_device_table!(
    OF_TABLE,
    MODULE_OF_TABLE,
    (),
    [(of::DeviceId::new(c"apple,sep"), ())]
);

impl platform::Driver for SepDriver {
    type IdInfo = ();

    const OF_ID_TABLE: Option<of::IdTable<()>> = Some(&OF_TABLE);

    fn probe(
        pdev: &platform::Device<device::Core>,
        _info: Option<&()>,
    ) -> impl PinInit<Self, Error> {
        let dev: &device::Device = pdev.as_ref();
        if ATTACHED.load(Relaxed) {
            dev_err!(
                dev,
                "the SEP was already booted on this system boot; it cannot be attached again until reboot\n"
            );
            return Err(EBUSY);
        }

        let of = dev.of_node().ok_or(ENODEV)?;
        let res = of
            .reserved_mem_region_to_resource_byname(c"sepfw")
            .inspect_err(|e| {
                dev_err!(
                    dev,
                    "no 'sepfw' region: m1n1 adds it only when the DT has a 'sep' alias ({:?})\n",
                    e
                );
            })?;
        let data = SepData::new(
            pdev,
            FwRegion {
                addr: res.start(),
                size: res.size().try_into()?,
            },
        )?;
        // May return -EPROBE_DEFER; nothing has been sent to the SEP yet.
        *data.mbox.lock() = Some(Mailbox::new_byname(dev, c"mbox", data.clone())?);

        // Point of no return: from TZ0 on, the SEP may take our memory.
        if ATTACHED.xchg(true, Relaxed) {
            return Err(EBUSY);
        }
        // SAFETY: `THIS_MODULE` is this module (or null when built in, which
        // `__module_get` accepts). The reference is never dropped, so the
        // module cannot be unloaded while the SEP holds our memory.
        unsafe { bindings::__module_get(THIS_MODULE.as_ptr()) };

        if let Err(e) = data.start() {
            dev_err!(dev, "boot: could not send TZ0: {:?}\n", e);
            SepData::detach(&data);
            return Err(e);
        }
        Ok(Self(data))
    }
}

impl Drop for SepDriver {
    fn drop(&mut self) {
        SepData::detach(&self.0);
    }
}

module_platform_driver! {
    type: SepDriver,
    name: "apple_sep",
    description: "Apple SEP transport driver",
    license: "Dual MIT/GPL",
}
