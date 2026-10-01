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
//! the key store, Touch ID) are served from userspace through
//! `/dev/apple-sep` (`include/uapi/linux/apple_sep.h`); see SEP.md.
//!
//! Copyright (C) The Asahi Linux Contributors

mod bootpolicy;
mod capture;
mod chardev;
mod control;
mod events;
mod ool;
mod proto;
mod rxring;
mod sbio;
mod scrd;
mod sensor;
mod shmem;
mod sks;
mod uapi;
mod xarm;

use kernel::{
    bindings,
    device,
    miscdevice::{
        MiscDeviceOptions,
        MiscDeviceRegistration, //
    },
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
    uaccess::{
        UserPtr,
        UserSlice, //
    },
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
/// SBIO: per-wait default and cap, as for the key store.
const SBIO_DEFAULT_TIMEOUT_MS: u32 = 5000;
const SBIO_MAX_TIMEOUT_MS: u32 = 60_000;
/// Upper bound on waiting for the SEP's DMA write of an SBIO chunk.
const SBIO_WRITE_WAIT_MS: u32 = 200;
/// Smallest SKS request image: u32 header size + the 0x50-byte IPC header.
const SKS_MIN_IMAGE: usize = 0x54;
/// The 13.5 key store's per-request wait (`sep_deliver_msg_gated`).
const SKS_DEFAULT_TIMEOUT_MS: u32 = 6000;
const SKS_MAX_TIMEOUT_MS: u32 = 60_000;
/// SCRD: per-request default and cap (the reference used 2 s).
const SCRD_DEFAULT_TIMEOUT_MS: u32 = 2000;
const SCRD_MAX_TIMEOUT_MS: u32 = 60_000;
/// Smallest SCRD payload: "DRCS", command, two bytes, version.
const SCRD_MIN_REQUEST: usize = 8;
/// BootPolicy: per-request default and cap (the kext waits up to 15 s).
const BOOTPOLICY_DEFAULT_TIMEOUT_MS: u32 = 5000;
const BOOTPOLICY_MAX_TIMEOUT_MS: u32 = 15_000;
/// Capture: overall wait default and cap (reference: 60 s).
const CAPTURE_DEFAULT_TIMEOUT_MS: u32 = 60_000;
const CAPTURE_MAX_TIMEOUT_MS: u32 = 120_000;
/// Status re-read interval with a data-ready interrupt (a backstop) and
/// without one (polling), as in the reference.
const CAPTURE_IRQ_WAIT_MS: u32 = 250;
/// How far a read already under way may run past the caller's timeout: a
/// timeout cuts only the wait for a finger, never a finger being read
/// (idling the sensor then would throw the read away).
const CAPTURE_READ_GRACE_MS: u32 = 3000;
const CAPTURE_POLL_MS: i64 = 2;
/// Upper bound on waiting for the SEP's DMA write of an XARM payload.
const XARM_WRITE_WAIT_MS: u32 = 200;
/// `APPLE_SEP_XART_F_UNWRITTEN`.
const XART_F_UNWRITTEN: u8 = 0x01;
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
        proto::EP_PNON => "boot policy (pnon)",
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

    /// Out-of-line buffer pairs, in `ool::ENDPOINTS` order.
    #[pin]
    ool: Mutex<KVec<ool::Ool>>,
    /// Serialises OOL registration (it blocks on control replies).
    #[pin]
    enable_lock: Mutex<()>,

    #[pin]
    events: Mutex<events::Events>,
    #[pin]
    events_wq: CondVar,
    client_open: Atomic<bool>,
    /// Opaque per-SEP-boot client state (APPLE_SEP_IOC_SCRATCH_*).
    #[pin]
    scratch: Mutex<[u8; uapi::SCRATCH_SIZE]>,

    /// One key-store request at a time.
    #[pin]
    sks_serial: Mutex<()>,
    #[pin]
    sks: Mutex<sks::SksState>,
    #[pin]
    sks_wq: CondVar,

    /// One biometric transaction at a time.
    #[pin]
    sbio_serial: Mutex<()>,
    #[pin]
    sbio: Mutex<sbio::SbioState>,
    #[pin]
    sbio_wq: CondVar,
    /// The Touch ID sensor, resolved on first use.
    #[pin]
    mesa: Mutex<Option<Arc<sensor::Mesa>>>,
    /// A capture waiting for BIO_RELAY; wiped when dropped.
    #[pin]
    held: Mutex<Option<capture::Capture>>,

    /// One credential request at a time.
    #[pin]
    scrd_serial: Mutex<()>,
    #[pin]
    scrd: Mutex<scrd::ScrdState>,
    #[pin]
    scrd_wq: CondVar,

    /// One BootPolicy request at a time (same framing as SCRD).
    #[pin]
    bp_serial: Mutex<()>,
    #[pin]
    bp: Mutex<scrd::ScrdState>,
    #[pin]
    bp_wq: CondVar,

    #[pin]
    miscdev: Mutex<Option<Pin<KBox<MiscDeviceRegistration<chardev::Client>>>>>,
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
                ool <- new_mutex!(Self::alloc_ool(pdev)?),
                enable_lock <- new_mutex!(()),
                events <- new_mutex!(events::Events::new()),
                events_wq <- new_condvar!("SepData::events_wq"),
                client_open: Atomic::new(false),
                scratch <- new_mutex!([0; uapi::SCRATCH_SIZE]),
                sks_serial <- new_mutex!(()),
                sks <- new_mutex!(sks::SksState::new()),
                sks_wq <- new_condvar!("SepData::sks_wq"),
                sbio_serial <- new_mutex!(()),
                sbio <- new_mutex!(sbio::SbioState::new()),
                sbio_wq <- new_condvar!("SepData::sbio_wq"),
                mesa <- new_mutex!(None),
                held <- new_mutex!(None),
                scrd_serial <- new_mutex!(()),
                scrd <- new_mutex!(scrd::ScrdState::new()),
                scrd_wq <- new_condvar!("SepData::scrd_wq"),
                bp_serial <- new_mutex!(()),
                bp <- new_mutex!(scrd::ScrdState::new()),
                bp_wq <- new_condvar!("SepData::bp_wq"),
                miscdev <- new_mutex!(None),
            }),
            GFP_KERNEL,
        )
    }

    fn alloc_ool(pdev: &platform::Device<device::Core>) -> Result<KVec<ool::Ool>> {
        let mut v = KVec::with_capacity(ool::ENDPOINTS.len(), GFP_KERNEL)?;
        for g in ool::ENDPOINTS.iter() {
            v.push(ool::Ool::new(pdev.as_ref(), g)?, GFP_KERNEL)?;
        }
        Ok(v)
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
            proto::EP_XARM => this.on_xarm(msg),
            proto::EP_SKS => this.on_sks(msg),
            proto::EP_SBIO => this.on_sbio(msg),
            proto::EP_SCRD => this.on_scrd(msg),
            proto::EP_PNON => this.on_bootpolicy(msg),
            proto::EP_SHMEM => {}
            ep => this.on_unserved(ep, msg),
        }
    }

    fn on_discover(this: &Arc<SepData>, f: proto::Fields, msg: Message) {
        match f.ty {
            proto::DISCOVER_DESCRIPTOR | proto::DISCOVER_CONFIG => {
                let name = proto::fourcc(f.data);
                let (count, named) = {
                    let mut eps = this.endpoints.lock();
                    let slot = &mut eps.names[usize::from(f.param)];
                    let new = slot.is_none();
                    let mut named = false;
                    if f.ty == proto::DISCOVER_DESCRIPTOR {
                        named = *slot != Some(name);
                        *slot = Some(name);
                    } else if new {
                        *slot = Some(*b"????");
                    }
                    if new {
                        eps.count += 1;
                    }
                    (eps.count, named)
                };
                if named {
                    this.queue_event(events::Event::Endpoint { ep: f.param, name });
                }
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

    /// Messages for services nobody serves yet: logged, never answered.
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
        dev_info!(
            self.dev,
            "rx: endpoint {:#04x} {} unserved (msg0 {:#018x})\n",
            ep,
            service_name(ep),
            msg.msg0
        );
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

    // --- xART requests and the userspace client -----------------------------

    fn queue_event(&self, ev: events::Event) {
        let (rejected, dropped) = {
            let mut q = self.events.lock();
            let r = q.push(ev);
            (r.err(), q.take_dropped())
        };
        if dropped > 0 {
            dev_warn!(
                self.dev,
                "events: queue full, {} endpoint event(s) dropped\n",
                dropped
            );
        }
        match rejected {
            None => self.events_wq.notify_all(),
            Some(events::Event::Xart { req, .. }) => {
                dev_err!(
                    self.dev,
                    "xarm: queue full, op {:#04x} tag {:#04x} failed\n",
                    req.op,
                    req.tag
                );
                self.fail_xarm(req.tag);
            }
            Some(events::Event::Endpoint { .. }) => {}
        }
    }

    fn fail_xarm(&self, tag: u8) {
        let _ = self.send(xarm::encode_reply(tag, uapi::XART_FAILED, 0, [0; 3]));
    }

    /// An xART request from the SEP. Everything is handed to sepd; the kernel
    /// only moves the payload out of the DMA buffer.
    fn on_xarm(&self, msg: Message) {
        let req = xarm::decode(&msg);
        if xarm::is_notification(req.op) {
            dev_dbg!(self.dev, "xarm: notification op {:#04x}\n", req.op);
            return;
        }

        if !self.ool.lock()[ool::XARM].registered {
            // Before sepd has registered the buffers only the payload-less
            // query can be held for it; anything else is failed, as the
            // reference driver does.
            if req.op == xarm::OP_QUERY_PROTECTED {
                dev_info!(
                    self.dev,
                    "xarm: protected-data query held until sepd enables xART\n"
                );
                self.queue_event(events::Event::Xart {
                    req,
                    payload: KVec::new(),
                    flags: 0,
                });
            } else {
                dev_warn!(
                    self.dev,
                    "xarm: op {:#04x} arrived before the buffers were registered; failed\n",
                    req.op
                );
                self.fail_xarm(req.tag);
            }
            return;
        }

        let len = usize::from(req.len);
        let mut flags = 0;
        let payload = if len == 0 {
            KVec::new()
        } else {
            // The notification can overtake the SEP's DMA write; wait until
            // the consumed-buffer pattern is overwritten, but deliver anyway
            // (flagged) if it is not.
            let mut written = false;
            for _ in 0..XARM_WRITE_WAIT_MS {
                if self.ool.lock()[ool::XARM].out_written(0, len) {
                    written = true;
                    break;
                }
                time::delay::fsleep(time::Delta::from_millis(1));
            }
            if !written {
                flags |= XART_F_UNWRITTEN;
            }
            match self.ool.lock()[ool::XARM].take_out(0, len) {
                Ok(p) => p,
                Err(e) => {
                    dev_err!(
                        self.dev,
                        "xarm: op {:#04x} len {} unreadable ({:?}); failed\n",
                        req.op,
                        len,
                        e
                    );
                    self.fail_xarm(req.tag);
                    return;
                }
            }
        };
        self.queue_event(events::Event::Xart {
            req,
            payload,
            flags,
        });
    }

    fn client_open(&self) -> Result {
        if self.shutting_down.load(Relaxed) {
            return Err(ENODEV);
        }
        if self.client_open.xchg(true, Relaxed) {
            return Err(EBUSY);
        }
        Ok(())
    }

    fn client_release(&self) {
        // A capture nobody will relay is wiped now.
        drop(self.held.lock().take());
        let requeued = self.events.lock().requeue_inflight();
        self.client_open.store(false, Relaxed);
        if requeued > 0 {
            dev_warn!(
                self.dev,
                "client closed with {} unanswered xART request(s); requeued\n",
                requeued
            );
            self.events_wq.notify_all();
        }
    }

    fn info(&self) -> Result<KBox<uapi::Info>> {
        let mut info = KBox::new(
            uapi::Info {
                abi_version: uapi::ABI_VERSION,
                phase: self.phase.load(Relaxed),
                advertised: [0; 32],
                enabled: [0; 32],
                names: [[0; 4]; 256],
            },
            GFP_KERNEL,
        )?;
        {
            let eps = self.endpoints.lock();
            for (i, name) in eps.names.iter().enumerate() {
                if let Some(name) = name {
                    info.advertised[i / 8] |= 1 << (i % 8);
                    info.names[i] = *name;
                }
            }
        }
        for o in self.ool.lock().iter() {
            if o.registered {
                let e = usize::from(o.geometry.ep);
                info.enabled[e / 8] |= 1 << (e % 8);
            }
        }
        Ok(info)
    }

    /// Registers an endpoint's OOL buffers with the SEP. Idempotent.
    fn ep_enable(&self, ep: u8) -> Result<(usize, usize)> {
        let idx = ool::index_of(ep).ok_or(EINVAL)?;
        if self.endpoints.lock().names[usize::from(ep)].is_none() {
            return Err(ENODEV);
        }
        let _serial = self.enable_lock.lock();
        let (g, in_iova, out_iova, done) = {
            let ool = self.ool.lock();
            let o = &ool[idx];
            (o.geometry, o.in_iova(), o.out_iova(), o.registered)
        };
        if done {
            return Ok((g.in_size, g.out_size));
        }
        let (Some(in_field), Some(out_field)) =
            (proto::iova_field(in_iova), proto::iova_field(out_iova))
        else {
            return Err(ERANGE);
        };
        // The order the reference driver used: inbound size and address,
        // then outbound. From the first of these on, the SEP may use the
        // buffers, so they are never freed (see the crate docs).
        for (op, data) in [
            (control::OP_OOL_IN_SIZE, g.in_size as u32),
            (control::OP_OOL_IN_ADDR, in_field),
            (control::OP_OOL_OUT_SIZE, g.out_size as u32),
            (control::OP_OOL_OUT_ADDR, out_field),
        ] {
            self.control_call(op, ep, data, None).inspect_err(|e| {
                dev_err!(
                    self.dev,
                    "ool: endpoint {:#04x} registration step {:#04x} failed: {:?}\n",
                    ep,
                    op,
                    e
                );
            })?;
        }
        self.ool.lock()[idx].registered = true;
        dev_info!(
            self.dev,
            "ool: endpoint {:#04x} {} buffers registered (in 0x{:x} @ {:#x}, out 0x{:x} @ {:#x})\n",
            ep,
            service_name(ep),
            g.in_size,
            in_iova,
            g.out_size,
            out_iova
        );
        Ok((g.in_size, g.out_size))
    }

    fn next_event(&self, ev: &mut uapi::Event) -> Result {
        if (ev.payload_cap as usize) < uapi::XART_MAX {
            return Err(EINVAL);
        }
        let mut remaining = if ev.timeout_ms == 0 {
            time::Jiffies::MAX
        } else {
            time::msecs_to_jiffies(ev.timeout_ms)
        };
        let popped = {
            let mut q = self.events.lock();
            loop {
                if self.shutting_down.load(Relaxed) {
                    return Err(ENODEV);
                }
                if let Some(e) = q.pop() {
                    break e;
                }
                if remaining == 0 {
                    return Err(ETIMEDOUT);
                }
                match self.events_wq.wait_interruptible_timeout(&mut q, remaining) {
                    CondVarTimeoutResult::Woken { jiffies } => remaining = jiffies,
                    CondVarTimeoutResult::Timeout => remaining = 0,
                    CondVarTimeoutResult::Signal { .. } => return Err(ERESTARTSYS),
                }
            }
        };

        ev.body = [0; 8];
        ev.payload_len = 0;
        match popped {
            events::Event::Endpoint { ep, name } => {
                ev.ty = uapi::EVENT_ENDPOINT;
                ev.body[0] = ep;
                ev.body[4..8].copy_from_slice(&name);
            }
            events::Event::Xart {
                req,
                payload,
                flags,
            } => {
                if !payload.is_empty() {
                    let dst = UserPtr::from_addr(ev.payload_ptr as usize);
                    if let Err(e) = UserSlice::new(dst, payload.len())
                        .writer()
                        .write_slice(&payload)
                    {
                        self.events.lock().push_front(events::Event::Xart {
                            req,
                            payload,
                            flags,
                        });
                        return Err(e);
                    }
                }
                ev.ty = uapi::EVENT_XART;
                ev.payload_len = payload.len() as u32;
                let l = req.len.to_le_bytes();
                ev.body = [
                    req.tag,
                    req.op,
                    l[0],
                    l[1],
                    req.args[0],
                    req.args[1],
                    req.args[2],
                    flags,
                ];
                let mut q = self.events.lock();
                if let Err(back) = q.track(events::Event::Xart {
                    req,
                    payload,
                    flags,
                }) {
                    q.push_front(back);
                    return Err(ENOMEM);
                }
            }
        }
        Ok(())
    }

    fn xart_reply(&self, r: &uapi::XartReply) -> Result {
        let len = r.payload_len as usize;
        if len > uapi::XART_MAX {
            return Err(EMSGSIZE);
        }
        let mut buf = KVec::new();
        if len > 0 {
            UserSlice::new(UserPtr::from_addr(r.payload_ptr as usize), len)
                .read_all(&mut buf, GFP_KERNEL)?;
        }
        // Held across the send so a tag can only be answered once.
        let mut q = self.events.lock();
        if !q.is_inflight(r.tag) {
            return Err(ENOENT);
        }
        {
            let ool = self.ool.lock();
            let o = &ool[ool::XARM];
            if !o.registered {
                return Err(EINVAL);
            }
            if len > 0 {
                o.put_in(&buf)?;
            }
        }
        self.send(xarm::encode_reply(r.tag, r.status, r.len, r.args))?;
        q.complete(r.tag);
        Ok(())
    }

    // --- key store -----------------------------------------------------------

    fn on_sks(&self, msg: Message) {
        let reply = sks::decode(&msg);
        match self.sks.lock().deliver(reply) {
            sks::Delivery::Matched => self.sks_wq.notify_all(),
            sks::Delivery::LateCleared => {
                // The SEP is done with the buffers now; scrub them.
                self.ool.lock()[ool::SKS].clear();
                dev_warn!(
                    self.dev,
                    "sks: late reply to selector {:#04x} seq {:#04x} (status {})\n",
                    reply.id.selector,
                    reply.id.seq,
                    reply.status
                );
            }
            sks::Delivery::Unmatched => dev_warn!(
                self.dev,
                "sks: unmatched message selector {:#04x} seq {:#04x} status {} size {}\n",
                reply.id.selector,
                reply.id.seq,
                reply.status,
                reply.size
            ),
        }
    }

    /// One key-store request/response exchange (APPLE_SEP_IOC_SKS_CALL).
    fn sks_call(&self, c: &mut uapi::SksCall) -> Result {
        if c.reserved != [0; 3] {
            return Err(EINVAL);
        }
        let g = &ool::ENDPOINTS[ool::SKS];
        let len = c.req_len as usize;
        if !(SKS_MIN_IMAGE..=g.in_size).contains(&len) {
            return Err(EINVAL);
        }
        let wire_len = u16::try_from(len).map_err(|_| EINVAL)?;
        let mut image = KVec::new();
        UserSlice::new(UserPtr::from_addr(c.req_ptr as usize), len)
            .read_all(&mut image, GFP_KERNEL)?;
        let timeout_ms = match c.timeout_ms {
            0 => SKS_DEFAULT_TIMEOUT_MS,
            t => t.min(SKS_MAX_TIMEOUT_MS),
        };

        let _serial = self.sks_serial.lock();
        if self.sks.lock().wedged() {
            return Err(EIO);
        }
        {
            let ool = self.ool.lock();
            let o = &ool[ool::SKS];
            if !o.registered {
                return Err(EINVAL);
            }
            o.clear();
            o.put_in(&image)?;
        }
        let id = self.sks.lock().begin(c.selector)?;
        if let Err(e) = self.send(sks::encode(id, wire_len)) {
            self.sks.lock().abandon(false);
            self.ool.lock()[ool::SKS].clear();
            return Err(e);
        }

        let mut remaining = time::msecs_to_jiffies(timeout_ms);
        let reply = {
            let mut st = self.sks.lock();
            loop {
                if let Some(r) = st.take_reply() {
                    break r;
                }
                let abandon = if self.shutting_down.load(Relaxed) {
                    Some(ENODEV)
                } else if remaining == 0 {
                    Some(ETIMEDOUT)
                } else {
                    match self.sks_wq.wait_interruptible_timeout(&mut st, remaining) {
                        CondVarTimeoutResult::Woken { jiffies } => {
                            remaining = jiffies;
                            None
                        }
                        CondVarTimeoutResult::Timeout => {
                            remaining = 0;
                            None
                        }
                        // The request is already with the SEP; it cannot
                        // be restarted, so this is not ERESTARTSYS.
                        CondVarTimeoutResult::Signal { .. } => Some(EINTR),
                    }
                };
                if let Some(e) = abandon {
                    st.abandon(true);
                    drop(st);
                    dev_err!(
                        self.dev,
                        "sks: selector {:#04x} seq {:#04x} abandoned ({:?}); key store wedged until it answers\n",
                        id.selector,
                        id.seq,
                        e
                    );
                    return Err(e);
                }
            }
        };

        let size = usize::from(reply.size);
        let response = {
            let ool = self.ool.lock();
            let o = &ool[ool::SKS];
            let r = o.read_out(size);
            o.clear();
            r
        };
        let response = response.inspect_err(|_| {
            dev_err!(
                self.dev,
                "sks: selector {:#04x} response of {} bytes exceeds the buffer\n",
                id.selector,
                size
            );
        })?;
        if response.len() > c.resp_cap as usize {
            return Err(EMSGSIZE);
        }
        if !response.is_empty() {
            UserSlice::new(UserPtr::from_addr(c.resp_ptr as usize), response.len())
                .writer()
                .write_slice(&response)?;
        }
        c.status = i32::from(reply.status);
        c.resp_len = response.len() as u32;
        Ok(())
    }

    fn scratch_get(&self) -> [u8; uapi::SCRATCH_SIZE] {
        *self.scratch.lock()
    }

    fn scratch_set(&self, data: &[u8; uapi::SCRATCH_SIZE]) {
        *self.scratch.lock() = *data;
    }

    // --- biometric endpoint (SBIO) -----------------------------------------

    /// Polls until the SEP's write over the poison in `[off, off + len)` is
    /// visible, for at most `SBIO_WRITE_WAIT_MS`.
    fn sbio_await_written(&self, off: usize, len: usize) -> bool {
        for _ in 0..SBIO_WRITE_WAIT_MS {
            if self.ool.lock()[ool::SBIO].out_written(off, len) {
                return true;
            }
            time::delay::fsleep(time::Delta::from_millis(1));
        }
        false
    }

    fn on_sbio(&self, msg: Message) {
        let marker = sbio::marker_of(&msg);
        if marker < sbio::MARKER_FIRST {
            dev_dbg!(self.dev, "sbio: notification {:#018x}\n", msg.msg0);
            return;
        }
        if marker == sbio::MARKER_REQUEST {
            // A grant carries no buffer contents; do not read it.
            if self.sbio.lock().grant() {
                self.sbio_wq.notify_all();
            }
            return;
        }
        if marker == sbio::MARKER_ERROR {
            let err = self.ool.lock()[ool::SBIO]
                .take_out(0, sbio::HEADER_LEN)
                .ok()
                .and_then(|h| sbio::Packet::decode(&h))
                .map(|p| p.err);
            if self.sbio.lock().error(err) {
                self.sbio_wq.notify_all();
            }
            return;
        }

        // FC / FD: a data chunk. Its header must be fresh (reference
        // behaviour); the payload is delivered even if it looks stale.
        if !self.sbio_await_written(0, sbio::HEADER_LEN) {
            self.sbio.lock().fail(sbio::Status::Unwritten);
            self.sbio_wq.notify_all();
            return;
        }
        let packet = self.ool.lock()[ool::SBIO]
            .take_out(0, sbio::HEADER_LEN)
            .ok()
            .and_then(|h| sbio::Packet::decode(&h));
        let chunk = packet.map_or(0, |p| p.chunk as usize);
        let fits = sbio::HEADER_LEN + chunk <= ool::ENDPOINTS[ool::SBIO].out_size;
        let (Some(packet), true) = (packet, fits) else {
            self.sbio.lock().fail(sbio::Status::Unreported);
            self.sbio_wq.notify_all();
            return;
        };
        if chunk > 0 && !self.sbio_await_written(sbio::HEADER_LEN, chunk) {
            dev_warn!(self.dev, "sbio: chunk payload may be stale\n");
        }
        let Ok(data) = self.ool.lock()[ool::SBIO].take_out(sbio::HEADER_LEN, chunk) else {
            self.sbio.lock().fail(sbio::Status::Unreported);
            self.sbio_wq.notify_all();
            return;
        };

        let progress = self.sbio.lock().chunk(marker, &packet, &data);
        match progress {
            sbio::Progress::Complete => self.sbio_wq.notify_all(),
            sbio::Progress::Ignored => {
                dev_dbg!(
                    self.dev,
                    "sbio: stray chunk for opcode {:#x}\n",
                    packet.opcode
                )
            }
            sbio::Progress::NeedMore {
                opcode,
                received,
                total,
                seq,
            } => {
                let hdr = sbio::Packet::data(opcode, total as usize, received as usize, 0).encode();
                let sent = self.ool.lock()[ool::SBIO]
                    .put_in(&hdr)
                    .and_then(|()| self.send(sbio::encode(opcode, sbio::MARKER_REQUEST, seq)));
                if sent.is_err() {
                    self.sbio.lock().fail(sbio::Status::Unreported);
                    self.sbio_wq.notify_all();
                }
            }
        }
    }

    fn sbio_wait(
        &self,
        timeout_ms: u32,
        mut ready: impl FnMut(&mut sbio::SbioState) -> bool,
    ) -> Result {
        let mut remaining = time::msecs_to_jiffies(timeout_ms);
        let mut st = self.sbio.lock();
        loop {
            if ready(&mut st) {
                return Ok(());
            }
            if self.shutting_down.load(Relaxed) {
                return Err(ENODEV);
            }
            if remaining == 0 {
                return Err(ETIMEDOUT);
            }
            match self.sbio_wq.wait_interruptible_timeout(&mut st, remaining) {
                CondVarTimeoutResult::Woken { jiffies } => remaining = jiffies,
                CondVarTimeoutResult::Timeout => remaining = 0,
                CondVarTimeoutResult::Signal { .. } => return Err(EINTR),
            }
        }
    }

    /// One SBIO operation (APPLE_SEP_IOC_SBIO_CALL).
    fn sbio_call(&self, c: &mut uapi::SbioCall) -> Result {
        if c.reserved != 0 || c.reserved2 != 0 {
            return Err(EINVAL);
        }
        let total = c.req_len as usize;
        if total > uapi::SBIO_MAX {
            return Err(EMSGSIZE);
        }
        let mut req = KVVec::new();
        if total > 0 {
            UserSlice::new(UserPtr::from_addr(c.req_ptr as usize), total)
                .read_all(&mut req, GFP_KERNEL)?;
        }
        let timeout_ms = match c.timeout_ms {
            0 => SBIO_DEFAULT_TIMEOUT_MS,
            t => t.min(SBIO_MAX_TIMEOUT_MS),
        };
        let (status, resp) = self.sbio_run(c.opcode, &req, timeout_ms)?;
        (c.result, c.status) = Self::sbio_result(status);
        if resp.len() > c.resp_cap as usize {
            return Err(EMSGSIZE);
        }
        if !resp.is_empty() {
            UserSlice::new(UserPtr::from_addr(c.resp_ptr as usize), resp.len())
                .writer()
                .write_slice(&resp)?;
        }
        c.resp_len = resp.len() as u32;
        Ok(())
    }

    /// One complete SBIO transaction, serialised with all others.
    fn sbio_run(
        &self,
        opcode: u16,
        req: &[u8],
        timeout_ms: u32,
    ) -> Result<(sbio::Status, KVVec<u8>)> {
        let _serial = self.sbio_serial.lock();
        if !self.ool.lock()[ool::SBIO].registered {
            return Err(EINVAL);
        }
        self.sbio.lock().begin(opcode);
        self.sbio_exchange(opcode, req, timeout_ms)
            .inspect_err(|e| {
                self.sbio.lock().abort();
                dev_err!(self.dev, "sbio: opcode {:#x} failed: {:?}\n", opcode, e);
            })
    }

    fn sbio_result(status: sbio::Status) -> (u32, u32) {
        match status {
            sbio::Status::Answered(s) => (uapi::SBIO_ANSWERED, s),
            sbio::Status::Unreported => (uapi::SBIO_NO_STATUS, 0),
            sbio::Status::Unwritten => (uapi::SBIO_UNWRITTEN, 0),
        }
    }

    /// Sends `req` in chunks and waits for the reassembled answer.
    fn sbio_exchange(
        &self,
        opcode: u16,
        req: &[u8],
        timeout_ms: u32,
    ) -> Result<(sbio::Status, KVVec<u8>)> {
        let cap = ool::ENDPOINTS[ool::SBIO].in_size - sbio::HEADER_LEN;
        let total = req.len();
        let mut off = 0;
        let mut seq: u16 = 0;
        loop {
            let n = (total - off).min(cap);
            let mut chunk = KVec::with_capacity(sbio::HEADER_LEN + n, GFP_KERNEL)?;
            chunk.extend_from_slice(
                &sbio::Packet::data(opcode, total, off, n).encode(),
                GFP_KERNEL,
            )?;
            chunk.extend_from_slice(&req[off..off + n], GFP_KERNEL)?;
            self.ool.lock()[ool::SBIO].put_in(&chunk)?;
            let marker = if off == 0 {
                sbio::MARKER_FIRST
            } else {
                sbio::MARKER_NEXT
            };
            self.send(sbio::encode(opcode, marker, seq))?;
            off += n;
            seq = seq.wrapping_add(1);
            if off >= total {
                break;
            }
            // The SEP grants each further chunk with an FE; it may also end
            // the transaction early with an error.
            let mut early = false;
            self.sbio_wait(timeout_ms, |st| {
                early = st.has_done();
                early || st.take_grant()
            })?;
            if early {
                break;
            }
        }
        self.sbio.lock().sent_all();

        let mut done = None;
        self.sbio_wait(timeout_ms, |st| {
            done = st.take_done();
            done.is_some()
        })?;
        done.ok_or(EIO)
    }

    // --- Touch ID sensor -------------------------------------------------------

    fn mesa(&self) -> Result<Arc<sensor::Mesa>> {
        let mut slot = self.mesa.lock();
        if let Some(m) = slot.as_ref() {
            return Ok(m.clone());
        }
        let m = Arc::new(sensor::Mesa::get(&self.dev)?, GFP_KERNEL)?;
        *slot = Some(m.clone());
        Ok(m)
    }

    fn mesa_power(&self, p: &uapi::MesaPower) -> Result {
        if p.op > sensor::POWER_CYCLE {
            return Err(EINVAL);
        }
        self.mesa()?.power(p.op)
    }

    /// A raw sensor transfer for the handshake. Reads are capped at
    /// `MESA_RX_MAX` so captures cannot reach userspace this way.
    fn mesa_xfer(&self, x: &uapi::MesaXfer) -> Result {
        let (tx_len, rx_len) = (x.tx_len as usize, x.rx_len as usize);
        let rx_ok = match x.mode {
            sensor::XFER_DUPLEX => rx_len == tx_len,
            sensor::XFER_TX => rx_len == 0,
            sensor::XFER_TX_RX => rx_len > 0,
            _ => false,
        };
        if x.reserved != 0
            || !rx_ok
            || !(1..=uapi::MESA_TX_MAX).contains(&tx_len)
            || rx_len > uapi::MESA_RX_MAX
        {
            return Err(EINVAL);
        }
        let mesa = self.mesa()?;
        let mut tx = KVec::new();
        UserSlice::new(UserPtr::from_addr(x.tx_ptr as usize), tx_len)
            .read_all(&mut tx, GFP_KERNEL)?;
        let mut rx = KVec::from_elem(0u8, rx_len, GFP_KERNEL)?;
        mesa.xfer(x.mode, &tx, (rx_len > 0).then_some(&mut rx[..]))?;
        if rx_len > 0 {
            UserSlice::new(UserPtr::from_addr(x.rx_ptr as usize), rx_len)
                .writer()
                .write_slice(&rx)?;
        }
        Ok(())
    }

    /// APPLE_SEP_IOC_BIO_CAPTURE: capture, wait for data, read and check it,
    /// and hold it for BIO_RELAY.
    fn bio_capture(&self, c: &mut uapi::BioCapture) -> Result {
        if c.reserved != 0 {
            return Err(EINVAL);
        }
        let timeout_ms = match c.timeout_ms {
            0 => CAPTURE_DEFAULT_TIMEOUT_MS,
            t => t.min(CAPTURE_MAX_TIMEOUT_MS),
        };
        let mesa = self.mesa()?;
        // A capture still held is stale now.
        drop(self.held.lock().take());

        let irq_before = mesa.ready_count();
        mesa.ready_arm();
        capture::command(&mesa, &capture::CMD_START_CAPTURE)?;
        let start = time::Instant::<time::Monotonic>::now();
        let mut states = 0u32;
        let (result, count) = loop {
            let st = capture::status(&mesa)?;
            if st.state < 32 {
                states |= 1 << st.state;
            }
            if st.state == capture::STATE_NEEDS_PATCH {
                break (uapi::CAPTURE_NEEDS_PATCH, 0);
            }
            if st.state == capture::STATE_DATA_READY {
                break if st.count == 0 {
                    (uapi::CAPTURE_NO_FINGER, 0)
                } else {
                    (uapi::CAPTURE_READY, st.count)
                };
            }
            let limit = if st.state == capture::STATE_READING {
                timeout_ms + CAPTURE_READ_GRACE_MS
            } else {
                timeout_ms
            };
            if start.elapsed().as_millis() >= i64::from(limit) {
                break (uapi::CAPTURE_TIMEOUT, 0);
            }
            // On an early return the sensor stays armed; sepd idles it.
            match mesa.ready_wait(CAPTURE_IRQ_WAIT_MS) {
                Ok(_) => mesa.ready_arm(),
                Err(e) if e == ENODEV => {
                    time::delay::fsleep(time::Delta::from_millis(CAPTURE_POLL_MS));
                    if kernel::current!().signal_pending() {
                        return Err(EINTR);
                    }
                }
                Err(_) => return Err(EINTR),
            }
        };
        c.irqs = match (irq_before, mesa.ready_count()) {
            (Some(a), Some(b)) => b.wrapping_sub(a),
            _ => uapi::CAPTURE_NO_IRQ,
        };
        c.states = states;
        c.capture_len = 0;
        c.result = result;
        if result != uapi::CAPTURE_READY {
            return Ok(());
        }
        match capture::read(&mesa, count) {
            Ok(cap) => {
                c.capture_len = cap.bytes().len() as u32;
                *self.held.lock() = Some(cap);
            }
            Err(capture::ReadError::Length) => c.result = uapi::CAPTURE_BAD_LENGTH,
            Err(capture::ReadError::Crc) => c.result = uapi::CAPTURE_BAD_CRC,
            Err(capture::ReadError::Bus(e)) => return Err(e),
        }
        Ok(())
    }

    /// APPLE_SEP_IOC_BIO_RELAY: the held capture to the SEP (SBIO 0x65), or
    /// discarded. Wiped either way.
    fn bio_relay(&self, r: &mut uapi::BioRelay) -> Result {
        if r.reserved != 0 || r.flags & !uapi::BIO_RELAY_DISCARD != 0 {
            return Err(EINVAL);
        }
        let cap = self.held.lock().take().ok_or(ENOENT)?;
        if r.flags & uapi::BIO_RELAY_DISCARD != 0 {
            return Ok(());
        }
        let timeout_ms = match r.timeout_ms {
            0 => SBIO_DEFAULT_TIMEOUT_MS,
            t => t.min(SBIO_MAX_TIMEOUT_MS),
        };
        let (status, resp) = self.sbio_run(capture::OP_RELAY_CAPTURE, cap.bytes(), timeout_ms)?;
        drop(cap);
        (r.result, r.status) = Self::sbio_result(status);
        r.resp_len = resp.len() as u32;
        Ok(())
    }

    // --- credential endpoint (SCRD) -------------------------------------------

    fn on_scrd(&self, msg: Message) {
        let reply = scrd::decode(&msg);
        match self.scrd.lock().deliver(reply) {
            scrd::Delivery::Matched => self.scrd_wq.notify_all(),
            scrd::Delivery::LateCleared => {
                self.ool.lock()[ool::SCRD].clear();
                dev_warn!(
                    self.dev,
                    "scrd: late reply to request {} (status {})\n",
                    reply.request,
                    reply.status
                );
            }
            scrd::Delivery::Unmatched => dev_warn!(
                self.dev,
                "scrd: unmatched message (msg0 {:#018x})\n",
                msg.msg0
            ),
        }
    }

    /// APPLE_SEP_IOC_SCRD_CALL.
    fn scrd_call(&self, c: &mut uapi::ScrdCall) -> Result {
        if c.reserved != [0; 3] {
            return Err(EINVAL);
        }
        let g = &ool::ENDPOINTS[ool::SCRD];
        let len = c.req_len as usize;
        if !(SCRD_MIN_REQUEST..=g.in_size).contains(&len) {
            return Err(EINVAL);
        }
        let mut req = KVec::new();
        UserSlice::new(UserPtr::from_addr(c.req_ptr as usize), len)
            .read_all(&mut req, GFP_KERNEL)?;
        let timeout_ms = match c.timeout_ms {
            0 => SCRD_DEFAULT_TIMEOUT_MS,
            t => t.min(SCRD_MAX_TIMEOUT_MS),
        };

        let _serial = self.scrd_serial.lock();
        if self.scrd.lock().wedged() {
            return Err(EIO);
        }
        {
            let ool = self.ool.lock();
            let o = &ool[ool::SCRD];
            if !o.registered {
                return Err(EINVAL);
            }
            o.clear();
            o.put_in(&req)?;
        }
        self.scrd.lock().begin(c.request);
        if let Err(e) = self.send(scrd::encode(c.request, len as u16)) {
            self.scrd.lock().abandon(false);
            self.ool.lock()[ool::SCRD].clear();
            return Err(e);
        }

        let mut remaining = time::msecs_to_jiffies(timeout_ms);
        let reply = {
            let mut st = self.scrd.lock();
            loop {
                if let Some(r) = st.take_reply() {
                    break r;
                }
                let abandon = if self.shutting_down.load(Relaxed) {
                    Some(ENODEV)
                } else if remaining == 0 {
                    Some(ETIMEDOUT)
                } else {
                    match self.scrd_wq.wait_interruptible_timeout(&mut st, remaining) {
                        CondVarTimeoutResult::Woken { jiffies } => {
                            remaining = jiffies;
                            None
                        }
                        CondVarTimeoutResult::Timeout => {
                            remaining = 0;
                            None
                        }
                        // Already with the SEP: not restartable.
                        CondVarTimeoutResult::Signal { .. } => Some(EINTR),
                    }
                };
                if let Some(e) = abandon {
                    st.abandon(true);
                    drop(st);
                    dev_err!(
                        self.dev,
                        "scrd: request {} abandoned ({:?}); endpoint closed until it answers\n",
                        c.request,
                        e
                    );
                    return Err(e);
                }
            }
        };

        let response = {
            let ool = self.ool.lock();
            let o = &ool[ool::SCRD];
            let r = o.read_out(usize::from(reply.size));
            o.clear();
            r
        }?;
        if response.len() > c.resp_cap as usize {
            return Err(EMSGSIZE);
        }
        if !response.is_empty() {
            UserSlice::new(UserPtr::from_addr(c.resp_ptr as usize), response.len())
                .writer()
                .write_slice(&response)?;
        }
        c.status = reply.status;
        c.resp_len = response.len() as u32;
        Ok(())
    }

    fn on_bootpolicy(&self, msg: Message) {
        let reply = scrd::decode(&msg);
        match self.bp.lock().deliver(reply) {
            scrd::Delivery::Matched => self.bp_wq.notify_all(),
            scrd::Delivery::LateCleared => {
                self.ool.lock()[ool::PNON].clear();
                dev_warn!(
                    self.dev,
                    "bootpolicy: late reply (status {:#x})\n",
                    reply.status
                );
            }
            scrd::Delivery::Unmatched => dev_warn!(
                self.dev,
                "bootpolicy: unmatched message (msg0 {:#018x})\n",
                msg.msg0
            ),
        }
    }

    /// APPLE_SEP_IOC_BOOTPOLICY_CALL: one allow-listed read-only command.
    fn bootpolicy_call(&self, c: &mut uapi::BootPolicyCall) -> Result {
        if c.reserved != 0 {
            return Err(EINVAL);
        }
        if !bootpolicy::allowed(c.command) {
            dev_warn!(
                self.dev,
                "bootpolicy: command {:#x} is not allowed\n",
                c.command
            );
            return Err(EPERM);
        }
        let req = bootpolicy::request(c.command);
        let timeout_ms = match c.timeout_ms {
            0 => BOOTPOLICY_DEFAULT_TIMEOUT_MS,
            t => t.min(BOOTPOLICY_MAX_TIMEOUT_MS),
        };

        let _serial = self.bp_serial.lock();
        if self.bp.lock().wedged() {
            return Err(EIO);
        }
        {
            let ool = self.ool.lock();
            let o = &ool[ool::PNON];
            if !o.registered {
                return Err(EINVAL);
            }
            o.clear();
            o.put_in(&req)?;
        }
        self.bp.lock().begin(bootpolicy::request_byte());
        if let Err(e) = self.send(bootpolicy::encode(bootpolicy::HEADER_LEN as u16)) {
            self.bp.lock().abandon(false);
            self.ool.lock()[ool::PNON].clear();
            return Err(e);
        }

        let mut remaining = time::msecs_to_jiffies(timeout_ms);
        let reply = {
            let mut st = self.bp.lock();
            loop {
                if let Some(r) = st.take_reply() {
                    break r;
                }
                let abandon = if self.shutting_down.load(Relaxed) {
                    Some(ENODEV)
                } else if remaining == 0 {
                    Some(ETIMEDOUT)
                } else {
                    match self.bp_wq.wait_interruptible_timeout(&mut st, remaining) {
                        CondVarTimeoutResult::Woken { jiffies } => {
                            remaining = jiffies;
                            None
                        }
                        CondVarTimeoutResult::Timeout => {
                            remaining = 0;
                            None
                        }
                        // Already with the SEP: not restartable.
                        CondVarTimeoutResult::Signal { .. } => Some(EINTR),
                    }
                };
                if let Some(e) = abandon {
                    st.abandon(true);
                    drop(st);
                    dev_err!(
                        self.dev,
                        "bootpolicy: command {:#x} abandoned ({:?}); endpoint closed until it answers\n",
                        c.command,
                        e
                    );
                    return Err(e);
                }
            }
        };

        let response = {
            let ool = self.ool.lock();
            let o = &ool[ool::PNON];
            let r = o.read_out(usize::from(reply.size));
            o.clear();
            r
        }?;
        if response.len() > c.resp_cap as usize {
            return Err(EMSGSIZE);
        }
        if !response.is_empty() {
            UserSlice::new(UserPtr::from_addr(c.resp_ptr as usize), response.len())
                .writer()
                .write_slice(&response)?;
        }
        c.status = reply.status;
        c.resp_len = response.len() as u32;
        Ok(())
    }

    // --- teardown -----------------------------------------------------------

    fn detach(this: &Arc<SepData>) {
        this.shutting_down.store(true, Relaxed);
        this.control_wq.notify_all();
        this.events_wq.notify_all();
        this.sks_wq.notify_all();
        this.sbio_wq.notify_all();
        this.scrd_wq.notify_all();
        this.bp_wq.notify_all();
        // Deregisters /dev/apple-sep. An open client keeps its own reference
        // and gets -ENODEV from then on.
        drop(this.miscdev.lock().take());
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

        chardev::publish(&data);
        match KBox::pin_init(
            MiscDeviceRegistration::register(MiscDeviceOptions { name: c"apple-sep" }),
            GFP_KERNEL,
        ) {
            Ok(reg) => *data.miscdev.lock() = Some(reg),
            Err(e) => dev_err!(dev, "could not register /dev/apple-sep: {:?}\n", e),
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
