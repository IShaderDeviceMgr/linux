// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Encoding sessions and `/dev/apple-ave`.
//!
//! One open file is one firmware client. `SESSION_CREATE` allocates the
//! firmware buffers that `AVE_Client_CalcSurfaceInfo` would (sizes from
//! [`bufsize`]) and sends START (kext "Open"). `INIT` takes userspace's init
//! block, overwrites the header and every device address and size in it with
//! the kernel's own (j314s-notes AVE2.md §7.1, §7.4), checks the geometry
//! against the session and sends AVC_INIT (kext "Start"). Closing the file
//! sends UNINIT and STOP.
//!
//! Only the configuration macOS uses by default is supported: H.264, one
//! SVE, usage Default, firmware rate control, no user DPB, MCTF, transcode,
//! multi-pass or entropy buffers. In that configuration the kext allocates
//! no reconstructed-frame buffers up front, so INIT does not either.
//!
//! Lifetime: the [`Encoder`] owns every session's buffers, not the files, so
//! that unbinding can halt the firmware and then free them while the device
//! is still bound ([`Encoder::revoke`]).

use super::{
    bufsize::{self, CodedDataArgs, CHROMA_420, CODEC_AVC, DEV_TYPE_T6000},
    uapi, Ipc, Shared, FW_ERROR_NONE, SZ_16K,
};
use kernel::{
    bindings, device,
    fs::File,
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    new_mutex,
    prelude::*,
    sync::{aref::ARef, Arc, Mutex},
    uaccess::{UserPtr, UserSlice},
};

/// Firmware commands (`eCAveCmdID`) with their sizes, the completion they
/// are answered with, and the kext command (`_E_AVE_Cmd`) the kext puts in
/// the header at +0x1c.
const CMD_START: u16 = 2;
const CMD_START_SIZE: usize = 0x40;
const NOTIFY_START_DONE: u32 = 0xe02;
const TAG_OPEN: u32 = 3;

const CMD_AVC_INIT: u16 = 4;
const NOTIFY_INIT_DONE: u32 = 0xe04;
const TAG_START: u32 = 6;

const CMD_UNINIT: u16 = 6;
const CMD_UNINIT_SIZE: usize = 0x40;
const NOTIFY_UNINIT_DONE: u32 = 0xe05;
const TAG_STOP: u32 = 7;

const CMD_STOP: u16 = 12;
const CMD_STOP_SIZE: usize = 0x48;
const NOTIFY_STOP_DONE: u32 = 0xe0a;
const TAG_CLOSE: u32 = 4;

/// Command header (`AVE_CHM_MakeFwCmd_*`).
const HDR_ID: usize = 0x00;
const HDR_SEQ: usize = 0x08;
const HDR_CLIENT: usize = 0x10;
const HDR_CLIENT_TYPE: usize = 0x14;
const HDR_CODEC: usize = 0x18;
const HDR_TAG: usize = 0x1c;
const HDR_PRIORITY: usize = 0x20;
const HDR_TIMEOUT: usize = 0x28;
const HDR_SIZE: usize = 0x40;

/// IOServiceOpen type AppleVideoEncoder uses (`AppleAVEVA_DriverCreate`).
const CLIENT_TYPE_ENCODE: u32 = 1;
const PRIORITY: u32 = 200;
/// The kext's `_S_AVE_TimeOut`; Config uses the same.
const CMD_TIMEOUT: u64 = 3000;

/// AVC_INIT (`AVE_CHM_MakeFwCmd_Start_AVC`).
const INIT_FW_CLIENT: usize = 0x40;
const INIT_FW_CLIENT_SIZE: usize = 0x48;
const INIT_VP: usize = 0x60;
const INIT_SVE_MAP: usize = 0x10de8;
const INIT_SVE_MAP_SIZE: usize = 0x24;
const INIT_CHM: usize = 0x10e0c;

/// `AVE_VIDEO_PARAMS` fields (VideoParams-relative).
const VP_WIDTH: usize = 0x0;
const VP_HEIGHT: usize = 0x4;
/// Every address/size field `AVE_CHM_SetFwBuf` writes, as ranges; the
/// kernel clears them all before filling in its own buffers.
const VP_ADDR_RANGES: [(usize, usize); 3] = [(0x28, 0x650), (0xf650, 0xfc78), (0xfe70, 0xfe90)];
const VP_LOWRES_RESULTS: usize = 0x358;
const VP_LOWRES_RESULTS_SET: usize = 0x40;
const VP_CODED: usize = 0x458;
const VP_CODED_SIZE: usize = 0x4f8;
const VP_CODED_HDR: usize = 0x560;
const VP_CODED_HDR_SIZE: usize = 0x600;
const VP_COLOCATED: usize = 0xf650;
const VP_SRC_NBR_INFO: usize = 0xf770;
const VP_SRC_NBR_PIXELS: usize = 0xf790;
const VP_SRC_NBR_DATA: usize = 0xf7b0;
const VP_PARAM_SETS: usize = 0xfad0;
const VP_PARAM_SETS_SIZE: usize = 0xfad8;

/// Array bounds in VideoParams.
const CODED_MAX: u32 = 20;
const SLOTS_MAX: u32 = 17;
const LOWRES_RESULTS_MAX: u32 = 8;
const SRC_NBR_MAX: u32 = 4;

const DIM_MIN: u32 = 64;
const DIM_MAX: u32 = 4096;
const SESSIONS_MAX: usize = 4;

/// One firmware buffer, mapped in the AVE DART.
struct Buf {
    mem: Shared,
    /// Size given to the firmware (the allocation is rounded up to 16K).
    size: u32,
}

impl Buf {
    fn new(dev: &device::Device<device::Bound>, size: u32) -> Result<Self> {
        if size == 0 {
            return Err(EINVAL);
        }
        let alloc = (size as usize).checked_next_multiple_of(SZ_16K as usize).ok_or(EINVAL)?;
        Ok(Buf { mem: Shared::new(dev, alloc)?, size })
    }

    fn iova(&self) -> u64 {
        self.mem.iova()
    }
}

fn bufs(dev: &device::Device<device::Bound>, n: u32, size: u32) -> Result<KVec<Buf>> {
    let mut v = KVec::with_capacity(n as usize, GFP_KERNEL)?;
    for _ in 0..n {
        v.push(Buf::new(dev, size)?, GFP_KERNEL)?;
    }
    Ok(v)
}

/// Buffer counts and sizes for a session (`AVE_Client_CalcSurfaceInfo`
/// with the defaults listed in the module docs).
struct Plan {
    param_sets: u32,
    coded_num: u32,
    coded: u32,
    coded_hdr: u32,
    colocated_num: u32,
    colocated: u32,
    lowres_result_sets: u32,
    lowres_result_num: u32,
    lowres_result: u32,
    src_nbr_info_num: u32,
    src_nbr_info: u32,
    src_nbr_pixel_num: u32,
    src_nbr_pixel: u32,
    src_nbr_data_num: u32,
    src_nbr_data: u32,
    fw_client: u32,
}

impl Plan {
    fn new(w: u32, h: u32, fw_client_reported: u32) -> Result<Self> {
        let dev = DEV_TYPE_T6000;
        let codec = CODEC_AVC;
        // Usage Default, no B-frames, IDR period 30: one reference
        // (`AVE_Client_CalcRefNum_Ext`); no user DPB, not forced.
        let refs = bufsize::ref_num_default(30, 0, 0);
        let p = Plan {
            param_sets: bufsize::param_set_size(codec, 1),
            coded_num: bufsize::coded_data_num(dev, 0, 0, 0, 1, false, false),
            coded: bufsize::coded_data_size(&CodedDataArgs {
                codec,
                w,
                h,
                chroma: CHROMA_420,
                depth: 8,
                explicit: 0,
                percent: 0,
            }),
            coded_hdr: bufsize::CODED_HEADER_SIZE,
            colocated_num: bufsize::colocated_num(refs, 0, -1, false),
            colocated: bufsize::colocated_size(codec, w, h),
            lowres_result_sets: bufsize::lowres_result_set_num(false),
            lowres_result_num: bufsize::lowres_result_num(dev),
            lowres_result: bufsize::lowres_result_size(dev, codec, w, h),
            src_nbr_info_num: bufsize::src_nbr_num(dev),
            src_nbr_info: bufsize::src_nbr_info_size(codec, w, h),
            src_nbr_pixel_num: bufsize::src_nbr_num(dev),
            src_nbr_pixel: bufsize::src_nbr_pixel_size(codec, w, h),
            src_nbr_data_num: bufsize::src_nbr_data_num(dev),
            src_nbr_data: bufsize::src_nbr_data_size(codec, w),
            fw_client: bufsize::fw_client_size(fw_client_reported),
        };
        // The VideoParams arrays bound what the firmware can be given.
        if p.coded_num == 0
            || p.coded_num > CODED_MAX
            || p.colocated_num > SLOTS_MAX
            || p.lowres_result_sets > 2
            || p.lowres_result_num > LOWRES_RESULTS_MAX
            || p.src_nbr_info_num > SRC_NBR_MAX
            || p.src_nbr_pixel_num > SRC_NBR_MAX
            || p.src_nbr_data_num > SRC_NBR_MAX
        {
            return Err(EINVAL);
        }
        Ok(p)
    }
}

/// The firmware buffers of one session.
struct Bufs {
    param_sets: Buf,
    coded: KVec<Buf>,
    coded_hdr: KVec<Buf>,
    colocated: KVec<Buf>,
    /// `[set][k]`, flattened.
    lowres_results: KVec<Buf>,
    lowres_result_num: u32,
    src_nbr_info: KVec<Buf>,
    src_nbr_pixels: KVec<Buf>,
    src_nbr_data: KVec<Buf>,
    /// Per-CHM work surface (INIT +0x40, `ms_iFwClientSize`).
    fw_client: Buf,
}

impl Bufs {
    fn new(dev: &device::Device<device::Bound>, p: &Plan) -> Result<Self> {
        Ok(Bufs {
            param_sets: Buf::new(dev, p.param_sets)?,
            coded: bufs(dev, p.coded_num, p.coded)?,
            coded_hdr: bufs(dev, p.coded_num, p.coded_hdr)?,
            colocated: bufs(dev, p.colocated_num, p.colocated)?,
            lowres_results: bufs(dev, p.lowres_result_sets * p.lowres_result_num, p.lowres_result)?,
            lowres_result_num: p.lowres_result_num,
            src_nbr_info: bufs(dev, p.src_nbr_info_num, p.src_nbr_info)?,
            src_nbr_pixels: bufs(dev, p.src_nbr_pixel_num, p.src_nbr_pixel)?,
            src_nbr_data: bufs(dev, p.src_nbr_data_num, p.src_nbr_data)?,
            fw_client: Buf::new(dev, p.fw_client)?,
        })
    }

    fn total(&self) -> usize {
        let one = |b: &Buf| b.mem.size();
        let many = |v: &KVec<Buf>| v.iter().map(one).sum::<usize>();
        one(&self.param_sets)
            + many(&self.coded)
            + many(&self.coded_hdr)
            + many(&self.colocated)
            + many(&self.lowres_results)
            + many(&self.src_nbr_info)
            + many(&self.src_nbr_pixels)
            + many(&self.src_nbr_data)
            + one(&self.fw_client)
    }

    /// `AVE_CHM_SetFwBuf`: writes the buffer addresses and sizes into the
    /// VideoParams at `vp` in `block`, after clearing every such field.
    fn fill_video_params(&self, block: &mut [u8], vp: usize) -> Result {
        for (start, end) in VP_ADDR_RANGES {
            block.get_mut(vp + start..vp + end).ok_or(EINVAL)?.fill(0);
        }
        put64(block, vp + VP_PARAM_SETS, self.param_sets.iova())?;
        put32(block, vp + VP_PARAM_SETS_SIZE, self.param_sets.size)?;
        for (i, b) in self.coded.iter().enumerate() {
            put64(block, vp + VP_CODED + 8 * i, b.iova())?;
            put32(block, vp + VP_CODED_SIZE + 4 * i, b.size)?;
        }
        for (i, b) in self.coded_hdr.iter().enumerate() {
            put64(block, vp + VP_CODED_HDR + 8 * i, b.iova())?;
            put32(block, vp + VP_CODED_HDR_SIZE + 4 * i, b.size)?;
        }
        // Layer 0 of `p_apsColocated[layer][17]`.
        for (j, b) in self.colocated.iter().enumerate() {
            put64(block, vp + VP_COLOCATED + 8 * j, b.iova())?;
        }
        let per_set = self.lowres_result_num as usize;
        for (i, b) in self.lowres_results.iter().enumerate() {
            let at = VP_LOWRES_RESULTS + (i / per_set) * VP_LOWRES_RESULTS_SET + 8 * (i % per_set);
            put64(block, vp + at, b.iova())?;
        }
        for (field, v) in [
            (VP_SRC_NBR_INFO, &self.src_nbr_info),
            (VP_SRC_NBR_PIXELS, &self.src_nbr_pixels),
            (VP_SRC_NBR_DATA, &self.src_nbr_data),
        ] {
            for (i, b) in v.iter().enumerate() {
                put64(block, vp + field + 8 * i, b.iova())?;
            }
        }
        Ok(())
    }
}

fn put32(b: &mut [u8], off: usize, v: u32) -> Result {
    b.get_mut(off..off + 4).ok_or(EINVAL)?.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn put64(b: &mut [u8], off: usize, v: u64) -> Result {
    b.get_mut(off..off + 8).ok_or(EINVAL)?.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn get32(b: &[u8], off: usize) -> Result<u32> {
    let w = b.get(off..off + 4).ok_or(EINVAL)?;
    Ok(u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// START done.
    Opened,
    /// AVC_INIT done.
    Inited,
}

struct Session {
    client: u32,
    codec: u32,
    width: u32,
    height: u32,
    stage: Stage,
    /// The firmware has been given the buffer addresses (INIT was sent), so
    /// they may only be freed once it has let go of the client.
    fw_has_bufs: bool,
    seq: u64,
    bufs: Bufs,
}

impl Session {
    /// The common command header (`AVE_CHM_MakeFwCmd_*`).
    fn header(&mut self, b: &mut [u8], id: u16, tag: u32) -> Result {
        self.seq += 1;
        b.get_mut(..HDR_SIZE).ok_or(EINVAL)?.fill(0);
        b[HDR_ID..HDR_ID + 2].copy_from_slice(&id.to_le_bytes());
        put64(b, HDR_SEQ, self.seq)?;
        put32(b, HDR_CLIENT, self.client)?;
        put32(b, HDR_CLIENT_TYPE, CLIENT_TYPE_ENCODE)?;
        put32(b, HDR_CODEC, self.codec)?;
        put32(b, HDR_TAG, tag)?;
        put32(b, HDR_PRIORITY, PRIORITY)?;
        put64(b, HDR_TIMEOUT, CMD_TIMEOUT)
    }
}

struct State {
    /// Taken by [`Encoder::revoke`] before the driver unbinds; nothing is
    /// allocated or sent afterwards, and open files no longer keep the IPC
    /// memory alive.
    ipc: Option<Arc<Ipc>>,
    next_client: u32,
    sessions: KVec<Session>,
}

/// Sessions taken from a revoked [`Encoder`].
pub(crate) struct Revoked(KVec<Session>);

impl Revoked {
    /// Frees the buffers: only once the firmware can no longer touch them.
    pub(crate) fn free(self) {
        drop(self.0);
    }

    /// Leaks the buffers, for when the firmware could not be halted.
    pub(crate) fn leak(self) {
        core::mem::forget(self.0);
    }
}

/// The encoder as seen by sessions: the firmware's IPC and the sessions'
/// buffers.
#[pin_data]
pub(crate) struct Encoder {
    dev: ARef<device::Device>,
    #[pin]
    state: Mutex<State>,
}

impl Encoder {
    pub(crate) fn new(dev: ARef<device::Device>, ipc: Arc<Ipc>) -> Result<Arc<Self>> {
        Arc::pin_init(
            try_pin_init!(Encoder {
                dev,
                state <- new_mutex!(State {
                    ipc: Some(ipc),
                    // The kext numbers user clients from 1.
                    next_client: 1,
                    sessions: KVec::new(),
                }),
            }),
            GFP_KERNEL,
        )
    }

    /// Stops accepting work and hands over every session, so the driver can
    /// free their buffers once the firmware is halted (or leak them if it
    /// cannot be).
    pub(crate) fn revoke(&self) -> Revoked {
        let mut st = self.state.lock();
        st.ipc = None;
        Revoked(core::mem::take(&mut st.sessions))
    }

    fn create(&self, req: &mut uapi::SessionCreate) -> Result<u32> {
        if req.codec != uapi::CODEC_H264 {
            return Err(EINVAL);
        }
        if req.flags != 0 || req.reserved != [0; 7] {
            return Err(EINVAL);
        }
        let (w, h) = (req.width, req.height);
        if !(DIM_MIN..=DIM_MAX).contains(&w) || !(DIM_MIN..=DIM_MAX).contains(&h) || w % 2 != 0 || h % 2 != 0
        {
            return Err(EINVAL);
        }
        let mut st = self.state.lock();
        let ipc = st.ipc.clone().ok_or(ENODEV)?;
        if st.sessions.len() >= SESSIONS_MAX {
            return Err(EBUSY);
        }
        let fw_client = ipc.chans.lock().fw_client_size;
        let plan = Plan::new(w, h, fw_client)?;
        // SAFETY: `ipc` is still set, and `revoke` takes it under this lock
        // before the driver unbinds, so the device is bound while we hold it.
        let bdev = unsafe { self.dev.as_bound() };
        let bufs = Bufs::new(bdev, &plan)?;
        let client = st.next_client;
        st.next_client = st.next_client.checked_add(1).unwrap_or(1);
        let mut s = Session {
            client,
            codec: CODEC_AVC,
            width: w,
            height: h,
            stage: Stage::Opened,
            fw_has_bufs: false,
            seq: 0,
            bufs,
        };

        let mut cmd = [0u8; CMD_START_SIZE];
        s.header(&mut cmd, CMD_START, TAG_OPEN)?;
        let status = ipc.run_command(&cmd, NOTIFY_START_DONE, client)?;
        if status != FW_ERROR_NONE {
            dev_err!(self.dev, "START (client {}): firmware status {:#x}\n", client, status);
            return Err(EIO);
        }
        dev_info!(
            self.dev,
            "session {}: {}x{} H.264, {} KiB of firmware buffers, {} x {:#x} bitstream\n",
            client,
            w,
            h,
            s.bufs.total() / 1024,
            plan.coded_num,
            plan.coded
        );
        st.sessions.push(s, GFP_KERNEL)?;

        req.abi_version = uapi::ABI_VERSION;
        req.client = client;
        req.init_size = uapi::H264_INIT_SIZE as u32;
        req.coded_num = plan.coded_num;
        req.coded_size = plan.coded;
        Ok(client)
    }

    /// AVC_INIT with userspace's `block`; returns the firmware status.
    fn init(&self, client: u32, block: &mut [u8]) -> Result<u32> {
        if block.len() != uapi::H264_INIT_SIZE {
            return Err(EINVAL);
        }
        let mut guard = self.state.lock();
        let st = &mut *guard;
        let ipc = st.ipc.as_ref().ok_or(ENODEV)?;
        let s = st.sessions.iter_mut().find(|s| s.client == client).ok_or(ENOENT)?;
        if s.stage != Stage::Opened {
            return Err(EBUSY);
        }
        // The buffers are sized for the session's geometry; refuse a block
        // that describes another.
        let (w, h) = (get32(block, INIT_VP + VP_WIDTH)?, get32(block, INIT_VP + VP_HEIGHT)?);
        if (w, h) != (s.width, s.height) {
            dev_err!(self.dev, "INIT (client {}): {}x{} block for a {}x{} session\n", client, w, h, s.width, s.height);
            return Err(EINVAL);
        }

        s.header(block, CMD_AVC_INIT, TAG_START)?;
        put64(block, INIT_FW_CLIENT, s.bufs.fw_client.iova())?;
        put32(block, INIT_FW_CLIENT_SIZE, s.bufs.fw_client.size)?;
        // +0x50/+0x58 (firmware client memory) only exist with several SVEs.
        s.bufs.fill_video_params(block, INIT_VP)?;
        // `_S_AVE_SVEMap`: one SVE, number 0; CHM index 0.
        let map = block.get_mut(INIT_SVE_MAP..INIT_SVE_MAP + INIT_SVE_MAP_SIZE).ok_or(EINVAL)?;
        map.fill(0);
        map[..4].copy_from_slice(&1u32.to_le_bytes());
        put32(block, INIT_CHM, 0)?;

        s.fw_has_bufs = true;
        let status = ipc.run_command(block, NOTIFY_INIT_DONE, client)?;
        if status == FW_ERROR_NONE {
            s.stage = Stage::Inited;
            dev_info!(self.dev, "session {}: INIT done\n", client);
        } else {
            dev_err!(self.dev, "INIT (client {}): firmware status {:#x}\n", client, status);
        }
        Ok(status)
    }

    /// Ends the session: UNINIT if it was initialised, then STOP. Its
    /// buffers are freed only if the firmware confirmed both.
    fn destroy(&self, client: u32) {
        let mut st = self.state.lock();
        let Some(i) = st.sessions.iter().position(|s| s.client == client) else {
            // Already handed to `revoke`.
            return;
        };
        let Ok(mut s) = st.sessions.remove(i) else {
            return;
        };
        let Some(ipc) = st.ipc.clone() else {
            // Unreachable: `revoke` takes the sessions with the IPC.
            core::mem::forget(s);
            return;
        };
        let mut clean = true;
        let mut run = |s: &mut Session, id: u16, size: usize, tag: u32, done: u32, what: &str| {
            let mut cmd = [0u8; CMD_STOP_SIZE];
            let r = s
                .header(&mut cmd[..size], id, tag)
                .and_then(|()| ipc.run_command(&cmd[..size], done, s.client));
            match r {
                Ok(FW_ERROR_NONE) => {}
                Ok(status) => {
                    dev_err!(self.dev, "{} (client {}): firmware status {:#x}\n", what, s.client, status);
                    clean = false;
                }
                Err(e) => {
                    dev_err!(self.dev, "{} (client {}): {:?}\n", what, s.client, e);
                    clean = false;
                }
            }
        };
        if s.stage == Stage::Inited {
            run(&mut s, CMD_UNINIT, CMD_UNINIT_SIZE, TAG_STOP, NOTIFY_UNINIT_DONE, "UNINIT");
        }
        // STOP +0x40: a kext option byte (client +0xe0c95), 0.
        run(&mut s, CMD_STOP, CMD_STOP_SIZE, TAG_CLOSE, NOTIFY_STOP_DONE, "STOP");
        if clean || !s.fw_has_bufs {
            dev_info!(self.dev, "session {} closed\n", s.client);
            drop(s);
        } else {
            dev_warn!(self.dev, "session {}: firmware may still use its buffers; leaking them\n", s.client);
            core::mem::forget(s);
        }
    }
}

/// `/dev/apple-ave` and the encoder its files reach.
#[pin_data]
pub(crate) struct AveMisc {
    /// Initialised before `reg`, so `open` can rely on it.
    enc: Arc<Encoder>,
    #[pin]
    reg: MiscDeviceRegistration<Client>,
}

impl AveMisc {
    pub(crate) fn new(enc: Arc<Encoder>) -> impl PinInit<Self, Error> {
        try_pin_init!(AveMisc {
            enc,
            reg <- MiscDeviceRegistration::register(MiscDeviceOptions { name: c"apple-ave" }),
        })
    }
}

/// An open `/dev/apple-ave`: at most one session.
#[pin_data]
pub(crate) struct Client {
    enc: Arc<Encoder>,
    /// Firmware client id of this file's session, 0 before SESSION_CREATE.
    #[pin]
    session: Mutex<u32>,
}

#[vtable]
impl MiscDevice for Client {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &File, misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        // Bring-up: the parameter blocks are not fully validated yet.
        // SAFETY: `capable` only reads the current task's credentials.
        if !unsafe { bindings::capable(bindings::CAP_SYS_ADMIN as i32) } {
            return Err(EPERM);
        }
        // SAFETY: The only `MiscDeviceRegistration<Client>` is `AveMisc::reg`,
        // and it is registered only while its `AveMisc` is alive and pinned.
        let me = unsafe { &*kernel::container_of!(core::ptr::from_ref(misc), AveMisc, reg) };
        KBox::try_pin_init(
            try_pin_init!(Client {
                enc: me.enc.clone(),
                session <- new_mutex!(0),
            }),
            GFP_KERNEL,
        )
    }

    fn release(device: Pin<KBox<Self>>, _file: &File) {
        let client = *device.session.lock();
        if client != 0 {
            device.enc.destroy(client);
        }
    }

    fn ioctl(me: Pin<&Client>, _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        let user = UserPtr::from_addr(arg);
        match cmd {
            uapi::IOC_SESSION_CREATE => {
                let (mut r, mut w) =
                    UserSlice::new(user, core::mem::size_of::<uapi::SessionCreate>()).reader_writer();
                let mut req: uapi::SessionCreate = r.read()?;
                let mut session = me.session.lock();
                if *session != 0 {
                    return Err(EBUSY);
                }
                let client = me.enc.create(&mut req)?;
                *session = client;
                w.write(&req)?;
            }
            uapi::IOC_INIT => {
                let (mut r, mut w) = UserSlice::new(user, core::mem::size_of::<uapi::Init>()).reader_writer();
                let mut req: uapi::Init = r.read()?;
                let len = req.block_size as usize;
                if len != uapi::H264_INIT_SIZE {
                    return Err(EINVAL);
                }
                let mut block = KVVec::new();
                UserSlice::new(UserPtr::from_addr(req.block_ptr as usize), len).read_all(&mut block, GFP_KERNEL)?;
                let session = me.session.lock();
                if *session == 0 {
                    return Err(ENOENT);
                }
                let status = me.enc.init(*session, &mut block)?;
                req.fw_status = status;
                w.write(&req)?;
                if status != FW_ERROR_NONE {
                    return Err(EIO);
                }
            }
            _ => return Err(ENOTTY),
        }
        Ok(0)
    }
}
