// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Apple AOP ambient light sensor driver
//!
//! Copyright (C) The Asahi Linux Contributors

use kernel::{
    bindings, c_str,
    device::{self, Core},
    error::to_result,
    ffi::{c_int, c_ulong, c_void},
    firmware::Firmware,
    iio::common::aop_sensors::{AopSensorData, IIORegistration, MessageProcessor},
    module_platform_driver, of, platform,
    prelude::*,
    soc::apple::aop::{EPICService, FakehidListener, AOP},
    sync::{aref::ARef, Arc},
    types::ForeignOwnable,
};

const EPIC_SUBTYPE_GET_AOP_PROPERTY: u16 = 0xa;
const EPIC_SUBTYPE_SET_ALS_PROPERTY: u16 = 0x4;
const LUX_OFFSET_CT720: usize = 0x1d;
const LUX_OFFSET_VD6286: usize = 0x28;

/// ALS property: report interval in microseconds; 0 turns the sensor off
/// (macOS AppleALSColorSensor: "requested ReportInterval=0 turn OFF sensor").
const ALS_PROP_REPORT_INTERVAL: u32 = 0;
const ALS_PROP_CALIBRATION: u32 = 0xb;
/// Report interval while the system is awake.
const REPORT_INTERVAL_US: u32 = 200000;

fn get_lux_offset(aop: &dyn AOP, dev: &platform::Device, svc: &EPICService) -> Result<usize> {
    let name = get_aop_property(aop, svc, 0xf, 16)?.1;
    match name.as_slice() {
        b"Redbird\0" => Ok(LUX_OFFSET_VD6286),
        b"FireFish2\0" => Ok(LUX_OFFSET_CT720),
        _ => {
            dev_warn!(
                dev.as_ref(),
                "Unknown sensor type {:?}",
                core::str::from_utf8(&name)
            );
            Err(EIO)
        }
    }
}

fn enable_als(aop: &dyn AOP, dev: &platform::Device, svc: &EPICService) -> Result<()> {
    let fw = Firmware::request(c_str!("apple/aop-als-cal.bin"), dev.as_ref())?;
    set_als_property(aop, svc, ALS_PROP_CALIBRATION, fw.data())?;
    set_report_interval(aop, svc, REPORT_INTERVAL_US)?;

    Ok(())
}

fn set_report_interval(aop: &dyn AOP, svc: &EPICService, us: u32) -> Result<u32> {
    set_als_property(aop, svc, ALS_PROP_REPORT_INTERVAL, &us.to_le_bytes())
}

/// Turns the sensor off across system sleep.
///
/// The AOP keeps running in s2idle, and each report it sends wakes the CPUs:
/// at the awake interval that is several wakeups a second for the whole
/// sleep (SLEEP.md §1.2). macOS stops the sensor before sleeping as well.
///
/// A PM notifier runs in process context before tasks are frozen and after
/// they are thawed, while the AOP is fully up, so the blocking EPIC call is
/// safe here.
#[repr(C)]
struct PmHook {
    /// Must stay the first field: `pm_notify` casts back from it.
    nb: bindings::notifier_block,
    registered: bool,
    aop: Arc<dyn AOP>,
    svc: EPICService,
    dev: ARef<device::Device>,
}

// SAFETY: the only raw pointer is the notifier chain's `next` link, which
// the PM core reads and writes under the chain's lock; the rest is `Send`.
unsafe impl Send for PmHook {}

impl PmHook {
    fn register(
        aop: Arc<dyn AOP>,
        svc: EPICService,
        dev: ARef<device::Device>,
    ) -> Result<Pin<KBox<PmHook>>> {
        let mut hook = KBox::pin(
            PmHook {
                nb: bindings::notifier_block {
                    notifier_call: Some(pm_notify),
                    ..Default::default()
                },
                registered: false,
                aop,
                svc,
                dev,
            },
            GFP_KERNEL,
        )?;
        // SAFETY: nothing is moved out of the pinned box.
        let this = unsafe { Pin::get_unchecked_mut(hook.as_mut()) };
        // SAFETY: `nb` is pinned and stays registered only until `drop`,
        // which runs before the box is freed.
        to_result(unsafe { bindings::register_pm_notifier(&mut this.nb) })?;
        this.registered = true;
        Ok(hook)
    }
}

impl Drop for PmHook {
    fn drop(&mut self) {
        if self.registered {
            // SAFETY: registered in `register`; this waits for a running
            // callback to finish.
            unsafe { bindings::unregister_pm_notifier(&mut self.nb) };
        }
    }
}

unsafe extern "C" fn pm_notify(
    nb: *mut bindings::notifier_block,
    action: c_ulong,
    _: *mut c_void,
) -> c_int {
    // SAFETY: `nb` is the first field of a registered, pinned `PmHook`
    // (`repr(C)`), which outlives its registration.
    let hook = unsafe { &*nb.cast::<PmHook>() };
    let us = match action as u32 {
        bindings::PM_SUSPEND_PREPARE | bindings::PM_HIBERNATION_PREPARE => 0,
        bindings::PM_POST_SUSPEND | bindings::PM_POST_HIBERNATION => REPORT_INTERVAL_US,
        _ => return bindings::NOTIFY_DONE as c_int,
    };
    // Never veto the transition: a failure here only costs wakeups (going
    // to sleep) or light readings (after waking).
    match set_report_interval(hook.aop.as_ref(), &hook.svc, us) {
        Ok(0) => {}
        Ok(rc) => dev_warn!(
            hook.dev,
            "Report interval {} us: AOP returned {:#x}",
            us,
            rc
        ),
        Err(e) => dev_warn!(hook.dev, "Report interval {} us failed: {:?}", us, e),
    }
    bindings::NOTIFY_OK as c_int
}

fn get_aop_property(
    aop: &dyn AOP,
    svc: &EPICService,
    tag: u32,
    data_len: usize,
) -> Result<(u32, KVec<u8>)> {
    let mut buf = KVec::new();
    buf.resize(8, 0, GFP_KERNEL)?;
    buf[4..8].copy_from_slice(&tag.to_le_bytes());
    aop.epic_call_ret(svc, EPIC_SUBTYPE_GET_AOP_PROPERTY, &buf, data_len)
}

fn set_als_property(aop: &dyn AOP, svc: &EPICService, tag: u32, data: &[u8]) -> Result<u32> {
    let mut buf = KVec::new();
    buf.resize(data.len() + 8, 0, GFP_KERNEL)?;
    buf[8..].copy_from_slice(data);
    buf[4..8].copy_from_slice(&tag.to_le_bytes());
    aop.epic_call(svc, EPIC_SUBTYPE_SET_ALS_PROPERTY, &buf)
}

fn f32_to_u32(f: u32) -> u32 {
    if f & 0x80000000 != 0 {
        return 0;
    }
    let exp = ((f & 0x7f800000) >> 23) as i32 - 127;
    if exp < 0 {
        return 0;
    }
    if exp == 128 && f & 0x7fffff != 0 {
        return 0;
    }
    let mant = f & 0x7fffff | 0x800000;
    if exp <= 23 {
        return mant >> (23 - exp);
    }
    if exp >= 32 {
        return u32::MAX;
    }
    mant << (exp - 23)
}

/// The fakehid listener registered with the AOP, removed again on drop.
///
/// The AOP calls the listener through a vtable in this module, so it must be
/// gone before the module can be unloaded.
struct ListenerGuard {
    aop: Arc<dyn AOP>,
    svc: EPICService,
}

impl ListenerGuard {
    fn new(
        aop: Arc<dyn AOP>,
        svc: EPICService,
        listener: Arc<dyn FakehidListener>,
    ) -> Result<Self> {
        aop.add_fakehid_listener(svc, listener)?;
        Ok(ListenerGuard { aop, svc })
    }
}

impl Drop for ListenerGuard {
    fn drop(&mut self) {
        self.aop.remove_fakehid_listener(&self.svc);
    }
}

struct MsgProc(usize);

impl MessageProcessor for MsgProc {
    fn process(&self, message: &[u8]) -> u32 {
        let offset = self.0;
        let raw = u32::from_le_bytes(message[offset..offset + 4].try_into().unwrap());
        f32_to_u32(raw)
    }
}

struct IIOAopAlsDriver {
    // Dropped in declaration order: stop the sleep hook and the AOP's calls
    // into this module before the IIO device goes away.
    _pm: Pin<KBox<PmHook>>,
    _listener: ListenerGuard,
    _iio: IIORegistration<MsgProc>,
}

kernel::of_device_table!(
    OF_TABLE,
    MODULE_OF_TABLE,
    (),
    [(of::DeviceId::new(c_str!("apple,aop-als")), ())]
);

impl platform::Driver for IIOAopAlsDriver {
    type IdInfo = ();

    const OF_ID_TABLE: Option<of::IdTable<Self::IdInfo>> = Some(&OF_TABLE);

    fn probe(pdev: &platform::Device<Core>, _info: Option<&()>) -> impl PinInit<Self, Error> {
        let dev = pdev.as_ref();
        let parent = dev.parent().unwrap();
        // SAFETY: our parent is AOP, and AopDriver is repr(transparent) for Arc<dyn Aop>
        let adata_ptr = unsafe { Pin::<KBox<Arc<dyn AOP>>>::borrow(parent.get_drvdata()) };
        let adata = (&*adata_ptr).clone();
        // SAFETY: AOP sets the platform data correctly
        let service = unsafe { *((*dev.as_raw()).platform_data as *const EPICService) };
        let ty = bindings::BINDINGS_IIO_LIGHT;
        let offset = get_lux_offset(adata.as_ref(), pdev, &service)?;
        let data = AopSensorData::new(dev.into(), ty, MsgProc(offset))?;
        let listener = ListenerGuard::new(adata.clone(), service, data.clone())?;
        enable_als(adata.as_ref(), pdev, &service)?;
        let pm = PmHook::register(adata, service, dev.into())?;
        let info_mask = 1 << bindings::BINDINGS_IIO_CHAN_INFO_PROCESSED;
        Ok(IIOAopAlsDriver {
            _pm: pm,
            _listener: listener,
            _iio: IIORegistration::<MsgProc>::new(
                data,
                c"aop-sensors-als",
                ty,
                info_mask,
                &THIS_MODULE,
            )?,
        })
    }
}

module_platform_driver! {
    type: IIOAopAlsDriver,
    name: "iio_aop_als",
    description: "AOP ambient light sensor driver",
    license: "Dual MIT/GPL",
    alias: ["platform:iio_aop_als"],
    firmware: ["apple/aop-als-cal.bin"],
}
