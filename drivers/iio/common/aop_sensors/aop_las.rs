// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Apple AOP lid angle sensor driver
//!
//! Copyright (C) The Asahi Linux Contributors

use kernel::{
    bindings, c_str,
    device::Core,
    iio::common::aop_sensors::{AopSensorData, IIORegistration, MessageProcessor},
    module_platform_driver, of, platform,
    prelude::*,
    soc::apple::aop::{EPICService, FakehidListener, AOP},
    sync::Arc,
    types::ForeignOwnable,
};

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

struct MsgProc;

impl MessageProcessor for MsgProc {
    fn process(&self, message: &[u8]) -> u32 {
        message[1] as u32
    }
}

struct IIOAopLasDriver {
    // Dropped in declaration order: the AOP must stop calling into this
    // module before the IIO device goes away.
    _listener: ListenerGuard,
    _iio: IIORegistration<MsgProc>,
}

kernel::of_device_table!(
    OF_TABLE,
    MODULE_OF_TABLE,
    (),
    [(of::DeviceId::new(c_str!("apple,aop-las")), ())]
);

impl platform::Driver for IIOAopLasDriver {
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

        let ty = bindings::BINDINGS_IIO_ANGL;
        let data = AopSensorData::new(dev.into(), ty, MsgProc)?;
        let listener = ListenerGuard::new(adata, service, data.clone())?;
        let info_mask = 1 << bindings::BINDINGS_IIO_CHAN_INFO_RAW;
        Ok(IIOAopLasDriver {
            _listener: listener,
            _iio: IIORegistration::<MsgProc>::new(
                data,
                c"aop-sensors-las",
                ty,
                info_mask,
                &THIS_MODULE,
            )?,
        })
    }
}

module_platform_driver! {
    type: IIOAopLasDriver,
    name: "iio_aop_las",
    description: "AOP lid angle sensor driver",
    license: "Dual MIT/GPL",
    alias: ["platform:iio_aop_las"],
}
