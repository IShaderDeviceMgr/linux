// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! The Touch ID sensor, reached through `apple-mesa.ko` (`apple-mesa.h`).
//!
//! The SEP node names the sensor with `apple,biometric-sensor = <&mesa>`.
//! This side resolves that handle and forwards power and transfer requests;
//! the Mesa handshake protocol lives in sepd. The one piece of the protocol
//! kept here is the fingerprint capture (`capture`), so that raw images never
//! leave the kernel.

use kernel::{bindings, device, error::from_err_ptr, prelude::*};

extern "C" {
    // `struct device_node *`, passed opaquely (the Rust binding of the struct
    // is not FFI-safe, and apple-mesa only hands it to the driver core).
    fn apple_mesa_get(np: *mut c_void) -> *mut c_void;
    fn apple_mesa_power(m: *mut c_void, op: c_int) -> c_int;
    fn apple_mesa_xfer(
        m: *mut c_void,
        mode: c_int,
        tx: *const c_void,
        tx_len: usize,
        rx: *mut c_void,
        rx_len: usize,
    ) -> c_int;
    fn apple_mesa_ready_arm(m: *mut c_void);
    fn apple_mesa_ready_wait(m: *mut c_void, timeout_ms: c_uint) -> c_int;
    fn apple_mesa_ready_count(m: *mut c_void) -> c_int;
}

/// `APPLE_MESA_XFER_*`, equal to the UAPI's `APPLE_SEP_MESA_XFER_*`.
pub(crate) const XFER_DUPLEX: u32 = 0;
pub(crate) const XFER_TX: u32 = 1;
pub(crate) const XFER_TX_RX: u32 = 2;
/// `APPLE_MESA_POWER_*`, equal to the UAPI's `APPLE_SEP_MESA_POWER_*`.
pub(crate) const POWER_CYCLE: u32 = 2;

/// A bound sensor.
///
/// # Invariants
/// The pointer came from `apple_mesa_get`, whose device reference is never
/// dropped, and apple-mesa suppresses unbind, so it stays valid.
pub(crate) struct Mesa(*mut c_void);

// SAFETY: apple-mesa serialises every call with its own mutex.
unsafe impl Send for Mesa {}
// SAFETY: see above.
unsafe impl Sync for Mesa {}

impl Mesa {
    /// The sensor the SEP node points at; `EPROBE_DEFER` until it is bound.
    pub(crate) fn get(dev: &device::Device) -> Result<Mesa> {
        // SAFETY: `dev` is live; its `of_node` is NULL or a node it holds.
        let np = unsafe { (*dev.as_raw()).of_node };
        if np.is_null() {
            return Err(ENODEV);
        }
        // SAFETY: an all-zero `of_phandle_args` is a valid out-parameter.
        let mut args: bindings::of_phandle_args = unsafe { core::mem::zeroed() };
        // SAFETY: `np` is live, the name is NUL-terminated, and `args` is a
        // valid out-parameter. This is `of_parse_phandle(np, name, 0)`.
        let rc = unsafe {
            bindings::__of_parse_phandle_with_args(
                np,
                c"apple,biometric-sensor".as_char_ptr(),
                core::ptr::null(),
                0,
                0,
                &mut args,
            )
        };
        if rc != 0 {
            return Err(ENODEV);
        }
        // SAFETY: `args.np` holds a reference taken by the parse above.
        let m = unsafe { apple_mesa_get(args.np.cast()) };
        // SAFETY: drops the parse's node reference; `apple_mesa_get` took its
        // own on the device.
        unsafe { bindings::of_node_put(args.np) };
        Ok(Mesa(from_err_ptr(m)?))
    }

    pub(crate) fn power(&self, op: u32) -> Result {
        // SAFETY: valid handle per the type invariant.
        kernel::error::to_result(unsafe { apple_mesa_power(self.0, op as c_int) })
    }

    /// Forgets data-ready edges seen so far.
    pub(crate) fn ready_arm(&self) {
        // SAFETY: valid handle per the type invariant.
        unsafe { apple_mesa_ready_arm(self.0) }
    }

    /// `Ok(true)` after a data-ready edge, `Ok(false)` on timeout, `ENODEV`
    /// without an interrupt, `ERESTARTSYS` on a signal.
    pub(crate) fn ready_wait(&self, timeout_ms: u32) -> Result<bool> {
        // SAFETY: valid handle per the type invariant.
        let rc = unsafe { apple_mesa_ready_wait(self.0, timeout_ms as c_uint) };
        kernel::error::to_result(rc).map(|()| rc > 0)
    }

    /// Data-ready edges since probe, if there is an interrupt.
    pub(crate) fn ready_count(&self) -> Option<u32> {
        // SAFETY: valid handle per the type invariant.
        let rc = unsafe { apple_mesa_ready_count(self.0) };
        (rc >= 0).then_some(rc as u32)
    }

    pub(crate) fn xfer(&self, mode: u32, tx: &[u8], rx: Option<&mut [u8]>) -> Result {
        let (rx_ptr, rx_len) = match rx {
            Some(r) => (r.as_mut_ptr().cast::<c_void>(), r.len()),
            None => (core::ptr::null_mut(), 0),
        };
        // SAFETY: valid handle; `tx` and `rx` are live kmalloc'd slices for
        // the duration of the call.
        let rc = unsafe {
            apple_mesa_xfer(
                self.0,
                mode as c_int,
                tx.as_ptr().cast(),
                tx.len(),
                rx_ptr,
                rx_len,
            )
        };
        kernel::error::to_result(rc)
    }
}
