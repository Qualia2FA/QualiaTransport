// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

//! End-to-end loop: payload → QR code → pixels → payload.
//!
//! These tests walk **the path a user really walks**: render the code into an image, then read
//! it back out of that image. Testing only "the encoder reports no error" is not enough — that
//! does not prove the rendered code can be scanned, and a code that cannot be scanned is, to
//! the user, the same as one that was never generated.
//!
//! Image decoding is an optional feature, so this whole file is not compiled when it is off.

#![cfg(feature = "scan-image")]

use qualia_transport::Error;
use qualia_transport::envelope;
use qualia_transport::image::GrayImage;
use qualia_transport::qr::{self, EcLevel, QrProfile};

/// Deterministic pseudo-random payload.
///
/// `rand` is deliberately not used: it is a denied dependency of this project (`deny.toml`),
/// and a test needs **reproducibility** rather than statistical randomness — a failing case
/// must be replayable as it was.
fn pseudo_random(len: usize) -> Vec<u8> {
    let mut state: u32 = 0x9e37_79b9;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 24) as u8);
    }
    out
}

/// Encode → render → scan → compare.
fn round_trip(profile: &QrProfile, len: usize) {
    let payload = pseudo_random(len);
    let symbol = profile
        .encode_payload(&payload)
        .unwrap_or_else(|error| panic!("{len} 字节应当装得下：{error}"));
    assert!(
        symbol.version() <= profile.max_version(),
        "编出了 {} 版，超过声明的上限 {}",
        symbol.version(),
        profile.max_version()
    );
    let image = symbol.render(4, 4).expect("渲染参数合法");
    let decoded = qr::scan::decode_payload(&image).unwrap_or_else(|error| {
        panic!(
            "从图里读不回来（{} 版、纠错 {}、{len} 字节）：{error}",
            symbol.version(),
            symbol.ec_level().letter()
        )
    });
    assert_eq!(decoded, payload, "读回来的载荷与编进去的不一致");
}

/// Four error-correction levels × versions from the smallest to the largest: **each** one must
/// render and read back.
///
/// The lengths are 1, half the capacity and the capacity, covering exactly the three typical
/// shapes: shortest, mid-size, exactly full.
#[test]
fn every_profile_round_trips_through_pixels() {
    let profiles = [
        (EcLevel::Low, 1),
        (EcLevel::Low, 5),
        (EcLevel::Medium, 10),
        (EcLevel::Quartile, 15),
        (EcLevel::High, 20),
        (EcLevel::Low, 40),
    ];
    for (ec, max_version) in profiles {
        let profile = QrProfile::new(ec, max_version).expect("版本合法");
        let capacity = profile.payload_capacity();
        for len in [1, capacity / 2, capacity] {
            round_trip(&profile, len);
        }
    }
}

/// What a user imports is usually not a "clean" code: screenshots have wide margins, photos are
/// taken at an angle and against a background.
///
/// The easiest shape to reproduce is covered here: a code pasted onto a larger white canvas. It
/// verifies that the decoder **locates** the code instead of assuming it fills the whole image.
#[test]
fn a_code_inside_a_larger_canvas_is_still_found() {
    let profile = QrProfile::new(EcLevel::Medium, 10).expect("版本合法");
    let payload = pseudo_random(40);
    let symbol = profile.encode_payload(&payload).expect("装得下");
    let code = symbol.render(4, 4).expect("渲染参数合法");

    let offset = 60_u32;
    let width = code.width() + 2 * offset;
    let height = code.height() + 2 * offset;
    let mut canvas = vec![u8::MAX; (width as usize) * (height as usize)];
    for y in 0..code.height() {
        for x in 0..code.width() {
            let source = code.pixel(x, y).expect("坐标在界内");
            let index = ((y + offset) as usize) * (width as usize) + (x + offset) as usize;
            canvas[index] = source;
        }
    }
    let canvas = GrayImage::from_luma8(width, height, canvas).expect("尺寸自洽");
    let decoded = qr::scan::decode_payload(&canvas).expect("大画布里的码也应当找得到");
    assert_eq!(decoded, payload);
}

/// Someone else's QR code must be reported as "not our code".
///
/// This test uses **another encoder** (calling `qrcodegen` directly) and **another renderer**
/// (the few lines written by hand below). The reason matches the wire-format tests: our own
/// encoder plus our own renderer only verify self-consistency and stay blind to a shared
/// misunderstanding of what a QR code is.
#[test]
fn someone_elses_qr_is_reported_as_foreign() {
    let url = "https://example.com/not-ours";
    let code = qrcodegen::QrCode::encode_text(url, qrcodegen::QrCodeEcc::Medium)
        .expect("短文本一定装得下");
    let image = render_foreign(&code, 6, 4);

    let text = qr::scan::decode_text(&image).expect("这张码本身是好的");
    assert_eq!(text, url, "读出来的应当是原文");

    let result = qr::scan::decode_payload(&image);
    let is_foreign = matches!(result, Err(Error::NotOurQrText));
    assert!(
        is_foreign,
        "别人的码应当报「不是本应用的码」，实际 {result:?}"
    );
}

/// An image without a code must report [`Error::NoQrFound`], not some decoder-internal error.
#[test]
fn a_blank_image_reports_not_found() {
    let blank = GrayImage::from_luma8(200, 200, vec![u8::MAX; 200 * 200]).expect("尺寸自洽");
    let result = qr::scan::decode_payload(&blank);
    let is_missing = matches!(result, Err(Error::NoQrFound));
    assert!(
        is_missing,
        "空白图应当报「没有找到二维码」，实际 {result:?}"
    );
    assert!(qr::scan::decode_text(&blank).is_err());
}

/// Images too small to geometrically hold a code must be rejected outright, and must not panic.
///
/// A version 1 QR code is 21×21 modules and a module is at least one pixel, so an image smaller
/// than 21×21 cannot contain a code. This also pins the "the client side passed a tiny image"
/// path: it must be an error, not a crash.
#[test]
fn images_too_small_to_hold_a_qr_are_rejected() {
    for side in [1_u32, 2, 20] {
        let image =
            GrayImage::from_luma8(side, side, vec![0; (side * side) as usize]).expect("尺寸自洽");
        let payload = qr::scan::decode_payload(&image);
        let text = qr::scan::decode_text(&image);
        let payload_is_missing = matches!(payload, Err(Error::NoQrFound));
        let text_is_missing = matches!(text, Err(Error::NoQrFound));
        assert!(
            payload_is_missing,
            "{side}×{side} 的图不该有码：{payload:?}"
        );
        assert!(text_is_missing, "{side}×{side} 的图不该有码：{text:?}");
    }
}

/// Envelope text must fall **entirely** inside the QR alphanumeric mode.
///
/// That is the constraint behind using Base32 rather than Base64 (see `src/base32.rs`). As soon
/// as a lowercase letter or an underscore enters the envelope, the whole code falls back to byte
/// mode and every payload byte costs 2 extra bits — nothing looks wrong in the UI, the code
/// merely gets bigger and harder to scan.
#[test]
fn envelope_text_stays_inside_the_alphanumeric_charset() {
    const ALPHANUMERIC: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    for len in [0_usize, 1, 7, 64, 512] {
        let text = envelope::encode(&pseudo_random(len));
        assert!(
            text.chars()
                .all(|character| ALPHANUMERIC.contains(character)),
            "{len} 字节载荷的信封里出现了字母数字模式之外的字符：{text}"
        );
    }
}

/// Envelope expansion must be bounded: Base32 is 8/5, plus a frame header of fewer than 20
/// characters.
#[test]
fn envelope_overhead_stays_bounded() {
    for len in [16_usize, 256, 1024] {
        let text = envelope::encode(&pseudo_random(len));
        let limit = len * 8 / 5 + 20;
        assert!(
            text.len() <= limit,
            "{len} 字节的信封长 {} 个字符，超过上限 {limit}",
            text.len()
        );
    }
}

/// One byte over the capacity must fail, and the reported `needed`/`limit` are both in **payload
/// bytes**.
#[test]
fn one_byte_over_capacity_is_reported_in_payload_units() {
    let profile = QrProfile::new(EcLevel::Medium, 8).expect("版本合法");
    let capacity = profile.payload_capacity();
    let result = profile.encode_payload(&vec![0_u8; capacity + 1]);
    match result {
        Err(Error::PayloadTooLarge { needed, limit }) => {
            assert_eq!(needed, capacity + 1);
            assert_eq!(limit, capacity);
        }
        other => panic!("应当报「装不下」，实际 {other:?}"),
    }
}

/// Multiple frames: split → render each → scan each → reassemble.
///
/// This is the pixel version of the real path where one device displays and another scans the
/// codes one by one. Three things must hold at the same time: every code **renders** (the
/// capacity is reduced by the longest frame header for a reason), every code **reads back**,
/// and the reassembled bytes equal the original payload.
///
/// The scanning order is deliberately reversed: frames may arrive out of order, which is what
/// the reassembler exists for.
#[test]
fn a_multi_frame_payload_round_trips_through_pixels() {
    let profile = QrProfile::new(EcLevel::Low, 10).expect("版本合法");
    let single = profile.payload_capacity();
    let payload = pseudo_random(single + 1);
    let symbols = profile
        .encode_payload_frames(&payload, 4)
        .expect("两张码装得下这份载荷");
    assert!(
        symbols.len() >= 2,
        "{} 字节超过单帧容量 {single}，应当被拆开，实际 {} 张",
        payload.len(),
        symbols.len()
    );
    for (index, symbol) in symbols.iter().enumerate() {
        assert!(
            symbol.version() <= profile.max_version(),
            "第 {} 张编出了 {} 版，超过声明的上限 {}",
            index + 1,
            symbol.version(),
            profile.max_version()
        );
    }

    let mut reassembler = qualia_transport::frame::Reassembler::from_first_frame();
    let mut done = None;
    for symbol in symbols.iter().rev() {
        let image = symbol.render(4, 4).expect("渲染参数合法");
        let frame = qr::scan::decode_frame(&image)
            .unwrap_or_else(|error| panic!("{} 版的码读不回来：{error}", symbol.version()));
        done = reassembler.accept(frame).expect("每一张都该被收下");
    }
    assert_eq!(done.expect("两张都扫到了就该拼齐"), payload);
}

/// A multi-frame code fed to the **single-frame entry** must report "this entry takes single
/// frames only", not "this is not our code".
///
/// The two scan entries share the step that picks a code of this application out of the whole
/// image and differ only in what they do with it afterwards. Their behaviour is pinned on the
/// error type: the wrong kind points the UI guidance in the wrong direction ("wrong code" vs
/// "this code is only one of several").
#[test]
fn the_two_scan_entries_differ_only_in_how_they_treat_multi_frame_codes() {
    let profile = QrProfile::new(EcLevel::Low, 10).expect("版本合法");
    let payload = pseudo_random(profile.payload_capacity() + 1);
    let symbols = profile.encode_payload_frames(&payload, 4).expect("拆得开");
    assert!(symbols.len() >= 2);

    let first = symbols[0].render(4, 4).expect("渲染参数合法");

    let frame = qr::scan::decode_frame(&first).expect("多帧入口必须解得开");
    assert_eq!(frame.index, 1);
    assert_eq!(frame.total, symbols.len() as u32);
    assert_eq!(
        frame.payload.len(),
        profile.frame_payload_capacity().min(payload.len()),
        "第 1 张（非末帧）应当恰好是满载的那一段"
    );
    assert_eq!(frame.payload[..], payload[..frame.payload.len()]);

    match qr::scan::decode_payload(&first) {
        Err(Error::MultiFrameUnsupported { count }) => {
            assert_eq!(count, symbols.len() as u32);
        }
        other => panic!("单帧入口应当报「只收单帧」，实际 {other:?}"),
    }

    let single_payload = pseudo_random(8);
    let single = profile.encode_payload(&single_payload).expect("装得下");
    let image = single.render(4, 4).expect("渲染参数合法");
    assert_eq!(
        qr::scan::decode_payload(&image).expect("单帧入口"),
        single_payload
    );
    let frame = qr::scan::decode_frame(&image).expect("多帧入口也收单帧");
    assert_eq!(frame.index, 1);
    assert_eq!(frame.total, 1);
    assert_eq!(frame.payload, single_payload);
}

/// The **independent renderer** used by the tests: it draws modules straight into a grayscale
/// image.
///
/// It is a separate implementation from `Symbol::render`, so "the code read back matches the one
/// written out" cannot hold merely because the rendering code shares one misunderstanding.
fn render_foreign(code: &qrcodegen::QrCode, scale: u32, quiet: u32) -> GrayImage {
    let modules = u32::try_from(code.size()).expect("边长不会是负数");
    let side = (modules + 2 * quiet) * scale;
    let mut pixels = vec![u8::MAX; (side * side) as usize];
    for y in 0..modules {
        for x in 0..modules {
            if !code.get_module(
                i32::try_from(x).expect("边长很小"),
                i32::try_from(y).expect("边长很小"),
            ) {
                continue;
            }
            for dy in 0..scale {
                for dx in 0..scale {
                    let px = (quiet + x) * scale + dx;
                    let py = (quiet + y) * scale + dy;
                    pixels[(py * side + px) as usize] = 0;
                }
            }
        }
    }
    GrayImage::from_luma8(side, side, pixels).expect("尺寸自洽")
}

/// **Regression**: decoding this image makes the decoder panic internally, and the image is
/// attacker-controlled input.
///
/// # What the input is
///
/// A 54-byte, 43×43 **periodic noise** image, built byte for byte the same way as in the fuzz
/// target `qr_scan`. Such an image makes the perspective transform inside the decoder
/// (`rqrr` 0.11.0) compute extreme values or NaN and hit its own
/// `assert!(x <= i32::MAX as f64)` in `geometry.rs`, which panics the thread. On the client side
/// that reads as "the user imports a picture someone sent and the whole application dies".
///
/// # What this test pins
///
/// "The process does not die because of one image" and "the decoder panic is reported
/// faithfully" as [`Error::QrDecoderPanicked`] — not folded into "no code found" or "not our
/// code". It does **not** require this image to decode: the image carries no code.
///
/// The convergence cannot be observed from the fuzz target, because `libfuzzer-sys`'s panic
/// hook aborts before unwinding and on Windows libFuzzer's exception handler treats Rust's SEH
/// throw as a crash: putting the sample into the fuzz corpus would make `qr_scan` report a crash
/// on every run, while this test passes on every platform.
///
/// These assertions are tied to that `assert!` inside `rqrr`: if a later version stops
/// panicking, they are relaxed to "an error is returned", together with the `catch_unwind`
/// layer in this crate.
#[test]
fn a_pathological_image_does_not_take_the_process_down() {
    const FUZZ_INPUT: [u8; 54] = [
        0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0xd8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x36, 0xff,
        0x01, 0x06, 0xff, 0x2b, 0xeb, 0x00, 0x00, 0x00, 0xbb, 0x14, 0xa4, 0x78, 0x00, 0x00, 0x66,
        0x33, 0x3b, 0x14, 0x00, 0x00, 0x3b, 0x14, 0x00, 0x00,
    ];
    let width = 1 + u32::from(FUZZ_INPUT[0]) % 48;
    let height = 1 + u32::from(FUZZ_INPUT[1]) % 48;
    let needed = (width as usize) * (height as usize);
    let pixels: Vec<u8> = FUZZ_INPUT[2..]
        .iter()
        .copied()
        .cycle()
        .take(needed)
        .collect();
    let image = GrayImage::from_luma8(width, height, pixels).expect("尺寸自洽");

    for result in [
        qr::scan::decode_text(&image).err(),
        qr::scan::decode_payload(&image).err(),
        qr::scan::decode_frame(&image).err(),
    ] {
        assert!(
            matches!(result, Some(Error::QrDecoderPanicked)),
            "解码器崩过必须被如实报出来，而不是混进「没找到码」或「不是我们的码」：{result:?}"
        );
    }
}
