// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Apple AOP ambient light sensor driver
//!
//! Copyright (C) The Asahi Linux Contributors

use kernel::{
    bindings, c_str,
    device::Core,
    firmware::Firmware,
    iio::common::aop_sensors::{
        set_report_interval, set_spu_property, AopSensorData, IIORegistration, MessageProcessor,
        SleepHook,
    },
    module_platform_driver, of, platform,
    prelude::*,
    soc::apple::aop::{EPICService, FakehidListener, AOP},
    sync::Arc,
    types::ForeignOwnable,
};

const EPIC_SUBTYPE_GET_AOP_PROPERTY: u16 = 0xa;
const LUX_OFFSET_CT720: usize = 0x1d;
const LUX_OFFSET_VD6286: usize = 0x28;

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
    set_spu_property(aop, svc, ALS_PROP_CALIBRATION, fw.data())?;
    set_report_interval(aop, svc, REPORT_INTERVAL_US)?;

    Ok(())
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
    _pm: Pin<KBox<SleepHook>>,
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
        let pm = SleepHook::register(adata, service, dev.into(), REPORT_INTERVAL_US)?;
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
