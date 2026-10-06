// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Apple AOP sensors common code
//!
//! Copyright (C) The Asahi Linux Contributors

use core::marker::{PhantomData, PhantomPinned};
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use kernel::{
    bindings,
    device,
    error::to_result,
    ffi::{c_int, c_ulong, c_void},
    prelude::*,
    soc::apple::aop::{EPICService, FakehidListener, AOP},
    sync::{
        aref::ARef,
        Arc, //
    },
    types::ForeignOwnable,
    ThisModule, //
};

/// TODO: add documentation
pub trait MessageProcessor {
    /// TODO: add documentation
    fn process(&self, message: &[u8]) -> u32;
}

/// TODO: add documentation
pub struct AopSensorData<T: MessageProcessor> {
    dev: ARef<device::Device>,
    ty: u32,
    value: AtomicU32,
    msg_proc: T,
}

impl<T: MessageProcessor> AopSensorData<T> {
    /// TODO: add documentation
    pub fn new(dev: ARef<device::Device>, ty: u32, msg_proc: T) -> Result<Arc<AopSensorData<T>>> {
        Ok(Arc::new(
            AopSensorData {
                dev,
                ty,
                value: AtomicU32::new(0),
                msg_proc,
            },
            GFP_KERNEL,
        )?)
    }
}

impl<T: MessageProcessor> FakehidListener for AopSensorData<T> {
    fn process_fakehid_report(&self, data: &[u8]) -> Result<()> {
        self.value
            .store(self.msg_proc.process(data), Ordering::Relaxed);
        Ok(())
    }
}

unsafe extern "C" fn aop_read_raw<T: MessageProcessor + 'static>(
    dev: *mut bindings::iio_dev,
    chan: *const bindings::iio_chan_spec,
    val: *mut i32,
    _: *mut i32,
    mask: isize,
) -> i32 {
    let data = unsafe { Arc::<AopSensorData<T>>::borrow((*dev).priv_.cast()) };
    let ty = unsafe { (*chan).type_ };
    if mask != bindings::BINDINGS_IIO_CHAN_INFO_PROCESSED as isize
        && mask != bindings::BINDINGS_IIO_CHAN_INFO_RAW as isize
    {
        return EINVAL.to_errno();
    }
    if data.ty != ty {
        return EINVAL.to_errno();
    }
    let value = data.value.load(Ordering::Relaxed);
    unsafe {
        *val = value as i32;
    }
    bindings::IIO_VAL_INT as i32
}

struct IIOSpec {
    spec: [bindings::iio_chan_spec; 1],
    vtable: bindings::iio_info,
    _p: PhantomPinned,
}

/// TODO: add documentation
pub struct IIORegistration<T: MessageProcessor + 'static> {
    dev: *mut bindings::iio_dev,
    spec: Pin<KBox<IIOSpec>>,
    registered: bool,
    _p: PhantomData<AopSensorData<T>>,
}

impl<T: MessageProcessor + 'static> IIORegistration<T> {
    /// TODO: add documentation
    pub fn new(
        data: Arc<AopSensorData<T>>,
        name: &'static CStr,
        ty: u32,
        info_mask: usize,
        module: &ThisModule,
    ) -> Result<Self> {
        let spec = KBox::pin(
            IIOSpec {
                spec: [bindings::iio_chan_spec {
                    type_: ty,
                    __bindgen_anon_1: bindings::iio_chan_spec__bindgen_ty_1 {
                        scan_type: bindings::iio_scan_type {
                            sign: b'u' as _,
                            realbits: 32,
                            storagebits: 32,
                            ..Default::default()
                        },
                    },
                    info_mask_separate: info_mask,
                    ..Default::default()
                }],
                vtable: bindings::iio_info {
                    read_raw: Some(aop_read_raw::<T>),
                    ..Default::default()
                },
                _p: PhantomPinned,
            },
            GFP_KERNEL,
        )?;
        let mut this = IIORegistration {
            dev: ptr::null_mut(),
            spec,
            registered: false,
            _p: PhantomData,
        };
        this.dev = unsafe { bindings::iio_device_alloc(data.dev.as_raw(), 0) };
        unsafe {
            (*this.dev).priv_ = data.clone().into_foreign().cast();
            (*this.dev).name = name.as_ptr() as _;
            // spec is now pinned
            (*this.dev).channels = this.spec.spec.as_ptr();
            (*this.dev).num_channels = this.spec.spec.len() as i32;
            (*this.dev).info = &this.spec.vtable;
        }
        let ret = unsafe { bindings::__iio_device_register(this.dev, module.as_ptr()) };
        if ret < 0 {
            dev_err!(data.dev, "Unable to register iio sensor");
            return Err(Error::from_errno(ret));
        }
        this.registered = true;
        Ok(this)
    }
}

impl<T: MessageProcessor + 'static> Drop for IIORegistration<T> {
    fn drop(&mut self) {
        if self.dev != ptr::null_mut() {
            unsafe {
                if self.registered {
                    bindings::iio_device_unregister(self.dev);
                }
                Arc::<AopSensorData<T>>::from_foreign((*self.dev).priv_.cast());
                bindings::iio_device_free(self.dev);
            }
        }
    }
}

unsafe impl<T: MessageProcessor> Send for IIORegistration<T> {}
unsafe impl<T: MessageProcessor> Sync for IIORegistration<T> {}

/// EPIC subtype of the SPU "set property" command (macOS
/// `AppleSPUInterface::_spuSetPropertyGated`, command 4).
const EPIC_SUBTYPE_SET_PROPERTY: u16 = 0x4;

/// SPU property 0: report interval in microseconds; 0 turns the sensor off.
const SPU_PROP_REPORT_INTERVAL: u32 = 0;

/// Sets SPU property `tag` of a sensor service to `data`; returns the AOP's
/// status code.
pub fn set_spu_property(aop: &dyn AOP, svc: &EPICService, tag: u32, data: &[u8]) -> Result<u32> {
    let mut buf = KVec::new();
    buf.resize(data.len() + 8, 0, GFP_KERNEL)?;
    buf[8..].copy_from_slice(data);
    buf[4..8].copy_from_slice(&tag.to_le_bytes());
    aop.epic_call(svc, EPIC_SUBTYPE_SET_PROPERTY, &buf)
}

/// Sets a sensor's report interval; 0 turns it off.
pub fn set_report_interval(aop: &dyn AOP, svc: &EPICService, us: u32) -> Result<u32> {
    set_spu_property(aop, svc, SPU_PROP_REPORT_INTERVAL, &us.to_le_bytes())
}

/// Turns a sensor off across system sleep and back on at `awake_us` after.
///
/// The AOP keeps running in s2idle, and each report it sends wakes the CPUs
/// (SLEEP.md §1.2, §3.1). macOS does the same in
/// `AppleSPUHIDDriver::setPowerStateGated`: report interval 0 when powering
/// down, the saved interval when powering up.
///
/// A PM notifier runs in process context before tasks are frozen and after
/// they are thawed, while the AOP is fully up, so the blocking EPIC call is
/// safe here.
#[repr(C)]
pub struct SleepHook {
    /// Must stay the first field: `sleep_notify` casts back from it.
    nb: bindings::notifier_block,
    registered: bool,
    aop: Arc<dyn AOP>,
    svc: EPICService,
    dev: ARef<device::Device>,
    awake_us: u32,
}

// SAFETY: the only raw pointer is the notifier chain's `next` link, which
// the PM core reads and writes under the chain's lock; the rest is `Send`.
unsafe impl Send for SleepHook {}

impl SleepHook {
    /// Registers the hook; it stays registered until dropped.
    pub fn register(
        aop: Arc<dyn AOP>,
        svc: EPICService,
        dev: ARef<device::Device>,
        awake_us: u32,
    ) -> Result<Pin<KBox<SleepHook>>> {
        let mut hook = KBox::pin(
            SleepHook {
                nb: bindings::notifier_block {
                    notifier_call: Some(sleep_notify),
                    ..Default::default()
                },
                registered: false,
                aop,
                svc,
                dev,
                awake_us,
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

impl Drop for SleepHook {
    fn drop(&mut self) {
        if self.registered {
            // SAFETY: registered in `register`; this waits for a running
            // callback to finish.
            unsafe { bindings::unregister_pm_notifier(&mut self.nb) };
        }
    }
}

unsafe extern "C" fn sleep_notify(
    nb: *mut bindings::notifier_block,
    action: c_ulong,
    _: *mut c_void,
) -> c_int {
    // SAFETY: `nb` is the first field of a registered, pinned `SleepHook`
    // (`repr(C)`), which outlives its registration.
    let hook = unsafe { &*nb.cast::<SleepHook>() };
    let us = match action as u32 {
        bindings::PM_SUSPEND_PREPARE | bindings::PM_HIBERNATION_PREPARE => 0,
        bindings::PM_POST_SUSPEND | bindings::PM_POST_HIBERNATION => hook.awake_us,
        _ => return bindings::NOTIFY_DONE as c_int,
    };
    // Never veto the transition: a failure here only costs wakeups (going
    // to sleep) or sensor readings (after waking).
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
