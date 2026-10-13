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
        .unwrap_or_else(|error| panic!("{len} bytes must fit: {error}"));
    assert!(
        symbol.version() <= profile.max_version(),
        "encoded version {}, above the declared limit {}",
        symbol.version(),
        profile.max_version()
    );
    let image = symbol.render(4, 4).expect("the render geometry is legal");
    let decoded = qr::scan::decode_payload(&image).unwrap_or_else(|error| {
        panic!(
            "cannot read it back from the image (version {}, ec {}, {len} bytes): {error}",
            symbol.version(),
            symbol.ec_level().letter()
        )
    });
    assert_eq!(
        decoded, payload,
        "the payload read back differs from the one encoded"
    );
}

/// A blurred code reads back.
///
/// Softness bleeds light into the dark modules, and a threshold in the middle of the range then
/// cuts them thinner than they were drawn, until the finder patterns no longer measure
/// 1:1:3:1:1 and no grid is found — for a picture in which every module is present. The reader
/// darkens the picture among its later attempts, which is what puts the thickness back.
#[test]
fn a_blurred_code_is_still_read() {
    let profile = QrProfile::new(EcLevel::Medium, 10).expect("the profile is legal");
    let payload = pseudo_random(20);
    let symbol = profile.encode_payload(&payload).expect("20 bytes must fit");
    let image = symbol.render(8, 4).expect("the render geometry is legal");

    for radius in 1..=3usize {
        let blurred = blur(&image, radius);
        assert_eq!(
            qr::scan::decode_payload(&blurred)
                .unwrap_or_else(|error| panic!("a code blurred by {radius} must read: {error}")),
            payload
        );
    }
}

/// Every pixel replaced by the average of its `(2 * radius + 1)²` neighbourhood.
fn blur(image: &GrayImage, radius: usize) -> GrayImage {
    let width = image.width() as usize;
    let height = image.height() as usize;
    let source = image.pixels();
    let mut pixels = vec![0u8; source.len()];
    for y in 0..height {
        for x in 0..width {
            let mut total = 0u32;
            let mut count = 0u32;
            for dy in -(radius as i64)..=(radius as i64) {
                let ny = (y as i64 + dy).clamp(0, height as i64 - 1) as usize;
                for dx in -(radius as i64)..=(radius as i64) {
                    let nx = (x as i64 + dx).clamp(0, width as i64 - 1) as usize;
                    total += u32::from(source[ny * width + nx]);
                    count += 1;
                }
            }
            pixels[y * width + x] = (total / count) as u8;
        }
    }
    GrayImage::from_luma8(image.width(), image.height(), pixels).expect("the size is consistent")
}

/// A code photographed off a screen reads back with the screen's own pixel grid on top of it.
///
/// A photograph of a screen carries an interference pattern that says nothing about the code,
/// and whether the decoder's own resampling lands on the modules or between them depends on the
/// resolution the picture happens to have. The pattern here is deliberately coarse enough to
/// matter at the picture's own size and to average away when four pixels become one.
#[test]
fn a_code_under_screen_interference_is_still_read() {
    let profile = QrProfile::new(EcLevel::Medium, 10).expect("the profile is legal");
    let payload = pseudo_random(20);
    let symbol = profile.encode_payload(&payload).expect("20 bytes must fit");
    let image = symbol.render(8, 4).expect("the render geometry is legal");

    let width = image.width() as usize;
    let noisy = GrayImage::from_luma8(
        image.width(),
        image.height(),
        image
            .pixels()
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let shift = if (index % width + index / width).is_multiple_of(2) {
                    40
                } else {
                    -40
                };
                ((*value as i16) + shift).clamp(0, 255) as u8
            })
            .collect(),
    )
    .expect("the size is consistent");

    assert_eq!(
        qr::scan::decode_payload(&noisy).expect("a code under interference"),
        payload
    );
}

/// A code drawn light on dark reads back too.
///
/// Both ways round carry the same data, and a design tool or a dark theme is free to pick
/// either; the decoder is asked about the inverted image when the code as handed over holds
/// nothing it will accept.
#[test]
fn an_inverted_code_is_still_read() {
    let profile = QrProfile::new(EcLevel::Medium, 10).expect("the profile is legal");
    let payload = pseudo_random(20);
    let symbol = profile.encode_payload(&payload).expect("20 bytes must fit");
    let image = symbol.render(4, 4).expect("the render geometry is legal");

    let flipped = GrayImage::from_luma8(
        image.width(),
        image.height(),
        image.pixels().iter().map(|value| !value).collect(),
    )
    .expect("the size is consistent");

    assert_eq!(
        qr::scan::decode_payload(&flipped).expect("a code read the other way round"),
        payload
    );
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
        let profile = QrProfile::new(ec, max_version).expect("the version is legal");
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
    let profile = QrProfile::new(EcLevel::Medium, 10).expect("the version is legal");
    let payload = pseudo_random(40);
    let symbol = profile.encode_payload(&payload).expect("must fit");
    let code = symbol.render(4, 4).expect("the render geometry is legal");

    let offset = 60_u32;
    let width = code.width() + 2 * offset;
    let height = code.height() + 2 * offset;
    let mut canvas = vec![u8::MAX; (width as usize) * (height as usize)];
    for y in 0..code.height() {
        for x in 0..code.width() {
            let source = code.pixel(x, y).expect("the coordinates are in bounds");
            let index = ((y + offset) as usize) * (width as usize) + (x + offset) as usize;
            canvas[index] = source;
        }
    }
    let canvas = GrayImage::from_luma8(width, height, canvas).expect("the size is consistent");
    let decoded =
        qr::scan::decode_payload(&canvas).expect("a code on a larger canvas must also be found");
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
        .expect("a short text always fits");
    let image = render_foreign(&code, 6, 4);

    let text = qr::scan::decode_text(&image).expect("this code itself is fine");
    assert_eq!(text, url, "the text read back must be the original");

    let result = qr::scan::decode_payload(&image);
    let is_foreign = matches!(result, Err(Error::NotOurQrText));
    assert!(
        is_foreign,
        "someone else's code must report a foreign code, got {result:?}"
    );
}

/// An image without a code must report [`Error::NoQrFound`], not some decoder-internal error.
#[test]
fn a_blank_image_reports_not_found() {
    let blank =
        GrayImage::from_luma8(200, 200, vec![u8::MAX; 200 * 200]).expect("the size is consistent");
    let result = qr::scan::decode_payload(&blank);
    let is_missing = matches!(result, Err(Error::NoQrFound));
    assert!(
        is_missing,
        "a blank image must report no QR code found, got {result:?}"
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
        let image = GrayImage::from_luma8(side, side, vec![0; (side * side) as usize])
            .expect("the size is consistent");
        let payload = qr::scan::decode_payload(&image);
        let text = qr::scan::decode_text(&image);
        let payload_is_missing = matches!(payload, Err(Error::NoQrFound));
        let text_is_missing = matches!(text, Err(Error::NoQrFound));
        assert!(
            payload_is_missing,
            "a {side}×{side} image cannot hold a code: {payload:?}"
        );
        assert!(
            text_is_missing,
            "a {side}×{side} image cannot hold a code: {text:?}"
        );
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
            "the envelope of a {len}-byte payload leaves the alphanumeric mode: {text}"
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
            "the envelope of {len} bytes is {} characters long, above the limit {limit}",
            text.len()
        );
    }
}

/// One byte over the capacity must fail, and the reported `needed`/`limit` are both in **payload
/// bytes**.
#[test]
fn one_byte_over_capacity_is_reported_in_payload_units() {
    let profile = QrProfile::new(EcLevel::Medium, 8).expect("the version is legal");
    let capacity = profile.payload_capacity();
    let result = profile.encode_payload(&vec![0_u8; capacity + 1]);
    match result {
        Err(Error::PayloadTooLarge { needed, limit }) => {
            assert_eq!(needed, capacity + 1);
            assert_eq!(limit, capacity);
        }
        other => panic!("expected PayloadTooLarge, got {other:?}"),
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
    let profile = QrProfile::new(EcLevel::Low, 10).expect("the version is legal");
    let single = profile.payload_capacity();
    let payload = pseudo_random(single + 1);
    let symbols = profile
        .encode_payload_frames(&payload, 4)
        .expect("two codes can hold this payload");
    assert!(
        symbols.len() >= 2,
        "{} bytes exceed the single-frame capacity {single} and must be split, got {} frames",
        payload.len(),
        symbols.len()
    );
    for (index, symbol) in symbols.iter().enumerate() {
        assert!(
            symbol.version() <= profile.max_version(),
            "frame {} encoded version {}, above the declared limit {}",
            index + 1,
            symbol.version(),
            profile.max_version()
        );
    }

    let mut reassembler = qualia_transport::frame::Reassembler::from_first_frame();
    let mut done = None;
    for symbol in symbols.iter().rev() {
        let image = symbol.render(4, 4).expect("the render geometry is legal");
        let frame = qr::scan::decode_frame(&image).unwrap_or_else(|error| {
            panic!(
                "the code of version {} cannot be read back: {error}",
                symbol.version()
            )
        });
        done = reassembler
            .accept(frame)
            .expect("every frame must be accepted");
    }
    assert_eq!(
        done.expect("both frames scanned means it must reassemble"),
        payload
    );
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
    let profile = QrProfile::new(EcLevel::Low, 10).expect("the version is legal");
    let payload = pseudo_random(profile.payload_capacity() + 1);
    let symbols = profile
        .encode_payload_frames(&payload, 4)
        .expect("must split");
    assert!(symbols.len() >= 2);

    let first = symbols[0]
        .render(4, 4)
        .expect("the render geometry is legal");

    let frame = qr::scan::decode_frame(&first).expect("the multi-frame entry point must decode");
    assert_eq!(frame.index, 1);
    assert_eq!(frame.total, symbols.len() as u32);
    assert_eq!(
        frame.payload.len(),
        profile.frame_payload_capacity().min(payload.len()),
        "frame 1 (non-final) must be exactly the full chunk"
    );
    assert_eq!(frame.payload[..], payload[..frame.payload.len()]);

    match qr::scan::decode_payload(&first) {
        Err(Error::MultiFrameUnsupported { count }) => {
            assert_eq!(count, symbols.len() as u32);
        }
        other => panic!("expected MultiFrameUnsupported, got {other:?}"),
    }

    let single_payload = pseudo_random(8);
    let single = profile.encode_payload(&single_payload).expect("must fit");
    let image = single.render(4, 4).expect("the render geometry is legal");
    assert_eq!(
        qr::scan::decode_payload(&image).expect("the single-frame entry point"),
        single_payload
    );
    let frame = qr::scan::decode_frame(&image)
        .expect("the multi-frame entry point accepts single frames too");
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
    let modules = u32::try_from(code.size()).expect("the side length cannot be negative");
    let side = (modules + 2 * quiet) * scale;
    let mut pixels = vec![u8::MAX; (side * side) as usize];
    for y in 0..modules {
        for x in 0..modules {
            if !code.get_module(
                i32::try_from(x).expect("the side length is small"),
                i32::try_from(y).expect("the side length is small"),
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
    GrayImage::from_luma8(side, side, pixels).expect("the size is consistent")
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
    let image = GrayImage::from_luma8(width, height, pixels).expect("the size is consistent");

    for result in [
        qr::scan::decode_text(&image).err(),
        qr::scan::decode_payload(&image).err(),
        qr::scan::decode_frame(&image).err(),
    ] {
        assert!(
            matches!(result, Some(Error::QrDecoderPanicked)),
            "a decoder panic must be reported as such, not folded into 'no code found': {result:?}"
        );
    }
}
