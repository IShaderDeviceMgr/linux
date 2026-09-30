// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! `/dev/apple-sep`: the single privileged userspace client (sepd).

use crate::{uapi, SepData};
use core::sync::atomic::{AtomicPtr, Ordering};
use kernel::{
    bindings,
    fs::File,
    miscdevice::{MiscDevice, MiscDeviceRegistration},
    prelude::*,
    sync::{Arc, ArcBorrow},
    uaccess::{UserPtr, UserSlice},
};

/// The attached SEP. Set once per boot and never cleared: it owns one
/// reference, taken with `Arc::into_raw`, that is deliberately never
/// released, because the SEP state lives until reboot (see the crate docs).
static SEP: AtomicPtr<SepData> = AtomicPtr::new(core::ptr::null_mut());

pub(crate) fn publish(sep: &Arc<SepData>) {
    let raw = Arc::into_raw(sep.clone()).cast_mut();
    if SEP
        .compare_exchange(
            core::ptr::null_mut(),
            raw,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        // SAFETY: `raw` came from `Arc::into_raw` just above and was not
        // published, so this reclaims that reference exactly once.
        drop(unsafe { Arc::from_raw(raw) });
    }
}

fn current() -> Result<Arc<SepData>> {
    let raw = SEP.load(Ordering::Acquire);
    if raw.is_null() {
        return Err(ENODEV);
    }
    // SAFETY: `raw` came from `Arc::into_raw` in `publish`, and that
    // reference is never released, so the object is alive.
    let borrow = unsafe { ArcBorrow::<SepData>::from_raw(raw) };
    Ok(borrow.into())
}

pub(crate) struct Client {
    sep: Arc<SepData>,
}

#[vtable]
impl MiscDevice for Client {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &File, _misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        // SAFETY: `capable` only reads the current task's credentials.
        if !unsafe { bindings::capable(bindings::CAP_SYS_ADMIN as i32) } {
            return Err(EPERM);
        }
        let sep = current()?;
        sep.client_open()?;
        match KBox::pin(Client { sep: sep.clone() }, GFP_KERNEL) {
            Ok(client) => Ok(client),
            Err(e) => {
                sep.client_release();
                Err(e.into())
            }
        }
    }

    fn release(device: Pin<KBox<Self>>, _file: &File) {
        device.sep.client_release();
    }

    fn ioctl(me: Pin<&Client>, _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        let sep = &me.sep;
        let user = UserPtr::from_addr(arg);
        match cmd {
            uapi::IOC_INFO => {
                let info = sep.info()?;
                UserSlice::new(user, core::mem::size_of::<uapi::Info>())
                    .writer()
                    .write(&*info)?;
            }
            uapi::IOC_EP_ENABLE => {
                let (mut r, mut w) =
                    UserSlice::new(user, core::mem::size_of::<uapi::EpEnable>()).reader_writer();
                let mut req: uapi::EpEnable = r.read()?;
                if req.reserved != [0; 3] {
                    return Err(EINVAL);
                }
                let (in_size, out_size) = sep.ep_enable(req.ep)?;
                req.in_size = in_size as u32;
                req.out_size = out_size as u32;
                w.write(&req)?;
            }
            uapi::IOC_NEXT_EVENT => {
                let (mut r, mut w) =
                    UserSlice::new(user, core::mem::size_of::<uapi::Event>()).reader_writer();
                let mut ev: uapi::Event = r.read()?;
                sep.next_event(&mut ev)?;
                w.write(&ev)?;
            }
            uapi::IOC_XART_REPLY => {
                let reply: uapi::XartReply =
                    UserSlice::new(user, core::mem::size_of::<uapi::XartReply>())
                        .reader()
                        .read()?;
                if reply.reserved != [0; 5] {
                    return Err(EINVAL);
                }
                sep.xart_reply(&reply)?;
            }
            uapi::IOC_SKS_CALL => {
                let (mut r, mut w) =
                    UserSlice::new(user, core::mem::size_of::<uapi::SksCall>()).reader_writer();
                let mut call: uapi::SksCall = r.read()?;
                sep.sks_call(&mut call)?;
                w.write(&call)?;
            }
            uapi::IOC_SCRATCH_GET => {
                let s = uapi::Scratch {
                    data: sep.scratch_get(),
                };
                UserSlice::new(user, core::mem::size_of::<uapi::Scratch>())
                    .writer()
                    .write(&s)?;
            }
            uapi::IOC_SCRATCH_SET => {
                let s: uapi::Scratch = UserSlice::new(user, core::mem::size_of::<uapi::Scratch>())
                    .reader()
                    .read()?;
                sep.scratch_set(&s.data);
            }
            uapi::IOC_SBIO_CALL => {
                let (mut r, mut w) =
                    UserSlice::new(user, core::mem::size_of::<uapi::SbioCall>()).reader_writer();
                let mut call: uapi::SbioCall = r.read()?;
                sep.sbio_call(&mut call)?;
                w.write(&call)?;
            }
            uapi::IOC_MESA_POWER => {
                let p: uapi::MesaPower =
                    UserSlice::new(user, core::mem::size_of::<uapi::MesaPower>())
                        .reader()
                        .read()?;
                sep.mesa_power(&p)?;
            }
            uapi::IOC_MESA_XFER => {
                let x: uapi::MesaXfer =
                    UserSlice::new(user, core::mem::size_of::<uapi::MesaXfer>())
                        .reader()
                        .read()?;
                sep.mesa_xfer(&x)?;
            }
            uapi::IOC_SCRD_CALL => {
                let (mut r, mut w) =
                    UserSlice::new(user, core::mem::size_of::<uapi::ScrdCall>()).reader_writer();
                let mut call: uapi::ScrdCall = r.read()?;
                sep.scrd_call(&mut call)?;
                w.write(&call)?;
            }
            uapi::IOC_BIO_CAPTURE => {
                let (mut r, mut w) =
                    UserSlice::new(user, core::mem::size_of::<uapi::BioCapture>()).reader_writer();
                let mut c: uapi::BioCapture = r.read()?;
                sep.bio_capture(&mut c)?;
                w.write(&c)?;
            }
            uapi::IOC_BIO_RELAY => {
                let (mut r, mut w) =
                    UserSlice::new(user, core::mem::size_of::<uapi::BioRelay>()).reader_writer();
                let mut c: uapi::BioRelay = r.read()?;
                sep.bio_relay(&mut c)?;
                w.write(&c)?;
            }
            _ => return Err(ENOTTY),
        }
        Ok(0)
    }
}
