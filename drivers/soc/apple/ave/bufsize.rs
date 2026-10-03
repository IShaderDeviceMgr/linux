// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! Firmware buffer counts and sizes for an encoding session.
//!
//! Transcribed from the macOS 13.5 AppleAVE2 kext helpers that
//! `AVE_Client_CalcSurfaceInfo` calls (`AVE_CalcBufNumOf*`,
//! `AVE_CalcBufSizeOf*`, `AVE_CalcFrameSize*`), keeping their names and
//! integer behaviour (u32 wrap-around included). The few places that use
//! floating point there are done with integer arithmetic rounding up, so a
//! buffer is never smaller than the kext would make it. See j314s-notes
//! AVE2.md §7.3.
//!
//! Only the buffers in `AVE_VIDEO_PARAMS` that an H.264/HEVC encode can use
//! are covered (no MCTF, transcode, CRC QP-mod or MB statistics).

#![allow(dead_code)]

/// `_E_AVE_CodecType`.
pub(crate) const CODEC_AVC: u32 = 0;
pub(crate) const CODEC_HEVC: u32 = 1;

/// `_E_AVE_DevType` of T6000 (Castor).
pub(crate) const DEV_TYPE_T6000: u32 = 11;

/// `CHROMA_FORMAT` (= chroma_format_idc).
pub(crate) const CHROMA_420: u32 = 1;

fn round_up(v: u32, a: u32) -> u32 {
    v.wrapping_add(a - 1) & !(a - 1)
}

/// `AVE_CalcFrameSize`: bytes of a w x h frame at `depth` bits.
pub(crate) fn frame_size(w: u32, h: u32, depth: u32, chroma: u32) -> u32 {
    if chroma > 3 {
        return 0;
    }
    let luma = h.wrapping_mul(w).wrapping_mul((depth + 7) >> 3);
    let c = match chroma {
        1 => luma >> 2,
        2 => luma >> 1,
        3 => luma,
        _ => 0,
    };
    luma.wrapping_add(c << 1)
}

/// `AVE_CalcBufSizeOfParameterSet`.
pub(crate) fn param_set_size(codec: u32, layers: u32) -> u32 {
    match codec {
        CODEC_AVC => 0x200,
        CODEC_HEVC => layers << 10,
        _ => 0,
    }
}

/// `AVE_CalcBufNumOfMBInputCtrl`.
pub(crate) fn mb_input_ctrl_num(codec: u32, enable: bool) -> u32 {
    match codec {
        CODEC_HEVC => {
            if enable {
                1
            } else {
                2
            }
        }
        CODEC_AVC => u32::from(enable),
        _ => 0,
    }
}

/// `AVE_CalcBufSizeOfMBInputCtrl`.
pub(crate) fn mb_input_ctrl_size(codec: u32, w: u32, h: u32) -> u32 {
    let v = match codec {
        CODEC_AVC => round_up(w, 16).wrapping_mul((h + 15) >> 4),
        CODEC_HEVC => round_up(w, 32).wrapping_mul((h + 31) >> 5),
        _ => 0,
    };
    round_up(v, 0x1000)
}

/// `AVE_CalcBufNumOfCodedData` (also used for coded headers, and slice
/// headers on HEVC).
pub(crate) fn coded_data_num(
    dev: u32,
    user_num: u32,
    b_frames: u32,
    ref_ctl: u32,
    layers: u32,
    multi_flag: bool,
    extra: bool,
) -> u32 {
    let n = if (dev & !1) == 0xc || dev.wrapping_sub(0x11) < 2 || ref_ctl == 0 || extra {
        b_frames + if extra { 3 } else { 0 } + 7
    } else if multi_flag {
        5
    } else {
        (if b_frames == 0 { 1 } else { b_frames }) + 2
    };
    let n = n.wrapping_mul(layers);
    let cap = (if extra { 0x14 } else { 0xe }) / 3u32.wrapping_sub(layers).max(1);
    let n = n.min(cap);
    if user_num == 0 {
        n
    } else {
        user_num.min(0x14)
    }
}

/// Inputs of `AVE_CalcBufSizeOfCodedData` that matter for an 8-bit 4:2:0
/// session without the transcode or lossless options.
pub(crate) struct CodedDataArgs {
    pub(crate) codec: u32,
    pub(crate) w: u32,
    pub(crate) h: u32,
    pub(crate) chroma: u32,
    pub(crate) depth: u32,
    /// Explicit size from the session (`arg6`), 0 = compute.
    pub(crate) explicit: u32,
    /// Size percentage (`arg8`), 0 = 100 %.
    pub(crate) percent: u32,
}

/// `AVE_CalcBufSizeOfCodedData`, for the case `arg7` (lossless) = 0,
/// `arg9` = 0, `arg10` = 0 and `arg11` < 2 (no QP-dependent scaling). The
/// other branches are not ported yet.
pub(crate) fn coded_data_size(a: &CodedDataArgs) -> u32 {
    let align = if a.codec == CODEC_AVC { 16 } else { 32 };
    let w = round_up(a.w, align);
    let mut base = frame_size(w, a.h, 8, 1);
    if a.depth > 8 {
        base = (base.wrapping_mul(5) >> 2) & 0x1fff_ffff;
    }
    // 4:4:4 x1.3/1.6 and 4:2:2 x1.5/1.2 (kext uses doubles); round up.
    let small = a.h.wrapping_mul(a.w) <= 0xe1000;
    base = match a.chroma {
        3 => {
            if small {
                base.div_ceil(5).wrapping_mul(8)
            } else {
                base.div_ceil(10).wrapping_mul(13)
            }
        }
        2 => {
            if small {
                base.div_ceil(2).wrapping_mul(3)
            } else {
                base.div_ceil(5).wrapping_mul(6)
            }
        }
        _ => base,
    };
    let mut size = if a.percent == 0 { base } else { (base / 100).wrapping_mul(a.percent) };
    let min = frame_size((align + 0x27f) & !(align - 1), 0x1e0, 8, 1);
    if size <= min {
        size = min;
    }
    size = size.min(base << 1);
    if a.explicit != 0 {
        size = a.explicit;
    }
    round_up(size, 0x1000)
}

/// `AVE_CalcBufSizeOfCodedHeader`.
pub(crate) const CODED_HEADER_SIZE: u32 = 0x23000;
/// `AVE_CalcBufSizeOfSliceHeader`.
pub(crate) const SLICE_HEADER_SIZE: u32 = 0x40000;

/// `AVE_CalcBufNumOfSliceHeader`: HEVC only.
pub(crate) fn slice_header_num(codec: u32, coded_num: u32) -> u32 {
    if codec == CODEC_HEVC {
        coded_num
    } else {
        0
    }
}

/// `AVE_CalcBufSetNumOfRecon`.
pub(crate) fn recon_set_num(usage: u32, rvra: bool) -> u32 {
    if usage == 1 && rvra {
        2
    } else {
        1
    }
}

/// `AVE_CalcBufLayerNumOfRecon`.
pub(crate) fn recon_layer_num(layers: u32) -> u32 {
    layers.min(2)
}

/// `AVE_CalcBufNumOfRecon`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn recon_num(
    refs: u32,
    usage: u32,
    user_dpb: i32,
    force: bool,
    rc_driver: u32,
    mb_input: u32,
    idr_period: u32,
    codec: u32,
    w: u32,
    h: u32,
) -> u32 {
    let n = if !((user_dpb >= 0 && usage == 1) || force) {
        0
    } else if (mb_input | rc_driver) == 0 && idr_period == 1 && codec == CODEC_HEVC {
        if w <= 0x1000 && h <= 0x1000 {
            refs + 1
        } else {
            0
        }
    } else {
        refs + 1
    };
    n.min(0x11)
}

/// Plane sizes of one reconstructed frame (`AVE_CalcBufSizeOfRecon`).
#[derive(Default, Clone, Copy)]
pub(crate) struct ReconSize {
    pub(crate) luma: u32,
    pub(crate) chroma: u32,
    pub(crate) luma_meta: u32,
    pub(crate) chroma_meta: u32,
}

impl ReconSize {
    pub(crate) fn total(&self) -> u32 {
        self.luma
            .wrapping_add(self.chroma)
            .wrapping_add(self.luma_meta)
            .wrapping_add(self.chroma_meta)
    }
}

/// `AVE_CalcBufSizeOfRecon`, AVC uncompressed-reference case (`arg8` =
/// false), which is what Castor uses for H.264.
pub(crate) fn recon_size_avc(w: u32, h: u32, chroma: u32) -> ReconSize {
    let mbw = (w + 15) >> 4;
    let mbh = (h + 15) >> 4;
    let per_mb: u32 = match chroma {
        0 => 0,
        1 => 0x80,
        2 => 0x100,
        _ => 0x200,
    };
    ReconSize {
        luma: round_up((mbw.wrapping_mul(mbh)) << 8, 0x200),
        chroma: per_mb.wrapping_mul(mbw).wrapping_mul(mbh),
        ..Default::default()
    }
}

/// `AVE_CalcBufSetNumOfColocated`.
pub(crate) fn colocated_set_num(dev: u32, sve: u32) -> u32 {
    if dev > 0x12 || (1u32 << dev) & 0x63000 == 0 {
        1
    } else {
        sve.min(4)
    }
}

/// `AVE_CalcBufNumOfColocated`.
pub(crate) fn colocated_num(refs: u32, usage: u32, user_dpb: i32, force: bool) -> u32 {
    if !((user_dpb >= 0 && usage == 1) || force) {
        2
    } else {
        refs + 1
    }
}

/// `AVE_CalcBufSizeOfColocated`.
pub(crate) fn colocated_size(codec: u32, w: u32, h: u32) -> u32 {
    match codec {
        CODEC_HEVC => (((w << 1) + 0x3e) & !0x3f)
            .wrapping_mul((((h + 0x1f) >> 5) + 1) & 0x3ff_fffe),
        CODEC_AVC => (((w << 3) + 0x78) & !0x7f).wrapping_mul((h + 15) >> 4),
        _ => 0,
    }
}

/// `AVE_CalcBufTypeNumOfLowResRef`.
pub(crate) fn lowres_ref_type_num(mctf: bool) -> u32 {
    if mctf {
        2
    } else {
        1
    }
}

/// `AVE_CalcBufNumOfLowResRef`.
pub(crate) fn lowres_ref_num(refs: u32, usage: u32, user_dpb: i32, force: bool, mctf: bool) -> u32 {
    let n = if (user_dpb >= 0 && usage == 1) || force { refs + 1 } else { 0 };
    if mctf {
        n.max(5)
    } else {
        n
    }
}

/// `AVE_CalcBufSizeOfLowResRef` (client type != 2, i.e. not LRME-only).
pub(crate) fn lowres_ref_size(dev: u32, codec: u32, w: u32, h: u32, chroma: u32) -> u32 {
    let w4 = w << 2;
    let shift = if dev >= 0x13 && chroma != 0 { 1 } else { 0 };
    match codec {
        CODEC_HEVC => {
            round_up(((((w4 + 0x7c) & !0x7f) + 0xc0) & !0xff).wrapping_mul((h + 0x3f) >> 6), 0x200)
                << shift
        }
        CODEC_AVC => round_up(((w4 + 0xfc) & !0xff).wrapping_mul((h + 0x3f) >> 4), 0x200) << shift,
        _ => 0,
    }
}

/// `AVE_CalcBufSetNumOfLowResResult`.
pub(crate) fn lowres_result_set_num(multi_sve: bool) -> u32 {
    if multi_sve {
        1
    } else {
        2
    }
}

/// `AVE_CalcBufNumOfLowResResult`.
pub(crate) fn lowres_result_num(dev: u32) -> u32 {
    if dev > 0xa {
        4
    } else {
        8
    }
}

/// `AVE_CalcBufSizeOfLowResResult` (client type != 2).
pub(crate) fn lowres_result_size(dev: u32, codec: u32, w: u32, h: u32) -> u32 {
    if codec != CODEC_AVC && codec != CODEC_HEVC {
        return 0;
    }
    if dev >= 0x19 {
        return ((0x3f + ((w + 0x1f) >> 5).wrapping_mul(0xa0)) & !0x3f).wrapping_mul((h + 0x3f) >> 6);
    }
    if dev < 0xb {
        return if codec == CODEC_HEVC {
            ((0x3f + ((w + 0x1f) >> 5).wrapping_mul(0x60)) & !0x3f)
                .wrapping_mul((((h + 0x1f) >> 5) + 1) >> 1)
        } else {
            ((0x3f + ((w + 0xf) >> 4).wrapping_mul(0x18)) & !0x3f)
                .wrapping_mul((((h + 0xf) >> 4) + 3) >> 2)
        };
    }
    0x400 + (((w << 2) + 0x7c) & !0x7f).wrapping_mul((h + 0x3f) >> 6)
}

/// `AVE_CalcBufSetNumOfLowResRCResult` / `NumOf…`: only with low-res RC on
/// device types > 0xb, so none on Castor.
pub(crate) fn lowres_rc_result_num(dev: u32, enable: bool) -> (u32, u32) {
    if dev > 0xb && enable {
        (2, 8)
    } else {
        (0, 0)
    }
}

/// `AVE_CalcBufNumOfSrcNeighborInfo` / `…Pixel`.
pub(crate) fn src_nbr_num(dev: u32) -> u32 {
    if dev.wrapping_sub(0x11) < 2 {
        4
    } else {
        1
    }
}

/// `AVE_CalcBufNumOfSrcNeighborData` (table for device types 0xc..0x12).
pub(crate) fn src_nbr_data_num(dev: u32) -> u32 {
    const T: [u32; 7] = [4, 4, 1, 1, 1, 4, 4];
    match dev.checked_sub(0xc) {
        Some(i) if i <= 6 => T[i as usize],
        _ => 1,
    }
}

/// `AVE_CalcBufNumOfSrcNeighborFwData`: none on Castor.
pub(crate) fn src_nbr_fw_data_num(dev: u32) -> u32 {
    if (dev & !1) == 0xc {
        1
    } else if dev.wrapping_sub(0x11) < 2 {
        4
    } else {
        0
    }
}

/// `AVE_CalcBufSizeOfSrcNeighborInfo`.
pub(crate) fn src_nbr_info_size(codec: u32, w: u32, h: u32) -> u32 {
    let v = match codec {
        CODEC_HEVC => ((w + 0x1f) >> 5)
            .wrapping_mul(((((h + 0x1f) >> 5) + 1) >> 1).wrapping_sub(1))
            .wrapping_mul(0xc0),
        CODEC_AVC => ((w << 4) + 0xf0) & !0xff,
        _ => return 0,
    };
    (v as i32).max(0x4000) as u32
}

/// `AVE_CalcBufSizeOfSrcNeighborPixel`.
pub(crate) fn src_nbr_pixel_size(codec: u32, w: u32, h: u32) -> u32 {
    let v = match codec {
        CODEC_HEVC => ((w + 0x1f) >> 5)
            .wrapping_mul(((((h + 0x1f) >> 5) + 1) >> 1).wrapping_sub(1))
            .wrapping_mul(0x300),
        CODEC_AVC => ((w << 6) + 0x3c0) & !0x3ff,
        _ => return 0,
    };
    (v as i32).max(0x4000) as u32
}

/// `AVE_CalcBufSizeOfSrcNeighborData`.
pub(crate) fn src_nbr_data_size(codec: u32, w: u32) -> u32 {
    let v = match codec {
        CODEC_HEVC => ((w + 0x1f) >> 3) & 0x1fff_fffc,
        CODEC_AVC => ((w + 0xf) >> 4).wrapping_mul(0x38),
        _ => return 0,
    };
    (v as i32).max(0x4000) as u32
}

/// `AVE_CalcBufSizeOfSrcNeighborFwData`.
pub(crate) fn src_nbr_fw_data_size(codec: u32, w: u32) -> u32 {
    let v = match codec {
        CODEC_HEVC => (w << 1) + 0xbe,
        CODEC_AVC => (w << 2) + 0xbc,
        _ => return 0,
    };
    let v = ((v & !0x3f).wrapping_sub(1)) & !0x7f;
    (v as i32).max(0x4000) as u32
}

/// `AVE_CalcBufSetNumOfEntropyCoding`.
pub(crate) fn entropy_set_num(sve: i32, flag: bool) -> u32 {
    if sve > 1 {
        4
    } else if flag {
        2
    } else {
        1
    }
}

/// `AVE_CalcBufNumOfEntropyCoding`: per set, only when enabled.
pub(crate) fn entropy_num(codec: u32, sve: u32, enable: bool) -> u32 {
    if !enable {
        return 0;
    }
    match codec {
        CODEC_HEVC => sve << 1,
        CODEC_AVC => sve << 2,
        _ => 0,
    }
}

/// `AVE_CalcBufSizeOfEntropyCoding`.
pub(crate) fn entropy_size(codec: u32, w: u32, h: u32, chroma: u32, depth: u32, rows: bool) -> u32 {
    match codec {
        CODEC_HEVC => {
            const T: [u32; 3] = [0x900, 0xc00, 0x1200];
            let per = match chroma.wrapping_sub(1) {
                i @ 0..=2 => T[i as usize],
                _ => 0x600,
            };
            let rows = if rows { (((h + 0x1f) >> 5) + 1) >> 1 } else { 4 };
            let mult = if depth != 8 { 2 } else { 1 };
            mult * ((w + 0x1f) >> 5) * rows * per
        }
        CODEC_AVC => {
            let per = if rows { (((h + 0xf) >> 4) + 3) >> 2 } else { 8 };
            (((w << 6) + 0x3c0) & !0x3ff).wrapping_mul(per)
        }
        _ => 0,
    }
}

/// `AVE_CalcBufSizeOfFwClient`: the firmware's client buffer size from the
/// boot handshake (0xb0000 on Castor), 1 MiB if unknown.
pub(crate) fn fw_client_size(reported: u32) -> u32 {
    if reported == 0 {
        0x10_0000
    } else {
        reported
    }
}

/// `AVE_CalcBufNumOfFwClientMem` / `AVE_CalcBufSizeOfFwClientMem`.
pub(crate) fn fw_client_mem(sve: u32) -> (u32, u32) {
    (u32::from(sve > 1), sve << 16)
}

/// `AVE_DRC::calcRefNum`.
pub(crate) fn drc_ref_num(user_dpb_set: bool, user_dpb: u32, max_dpb: u32, ltr: bool) -> u32 {
    let n = if user_dpb_set {
        match user_dpb {
            0..=1 => 0,
            2..=9 => user_dpb - 2,
            _ => 8,
        }
    } else if max_dpb > 8 {
        8
    } else {
        max_dpb.wrapping_sub(1)
    };
    if n > 1 && ltr {
        n + 1
    } else {
        1
    }
}

/// `AVE_Client_CalcRefNum_Ext` for usage Default (not iChat), without the
/// extra-reference options: B-frames or VideoParams +0x20 (Data +0x7d0)
/// need 2 references,
/// otherwise 1; all-intra (IDR period 1) needs none.
pub(crate) fn ref_num_default(idr_period: u32, b_frames: u32, vp_7d0: u32) -> u32 {
    if idr_period == 1 {
        0
    } else if b_frames != 0 || vp_7d0 != 0 {
        2
    } else {
        1
    }
}
