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

//! Fuzz target: decoding QR codes from **images**.
//!
//! # Input surface
//!
//! "Import from an image" means a user hands the application a picture **someone else gave
//! them**: a screenshot, an image saved from a chat app, a file dragged off a web page. Image
//! decoding is a classic source of memory-safety problems (out of bounds, integer overflow,
//! huge allocations), so this target feeds arbitrary pixels in and watches three things:
//!
//! 1. **Never panics** — including 1×1 sizes, extreme aspect ratios and noise.
//!
//!    Periodic noise can drive the perspective transform inside the decoder (`rqrr`) to extreme
//!    values and into its own `assert!`, which panics the thread; a few dozen input bytes
//!    (43×43 cyclic pixels) are enough to trigger it. Every decoder call in this crate is
//!    therefore wrapped in `catch_unwind` and a panic surfaces as
//!    [`Error::QrDecoderPanicked`] (see that variant); the regression test is
//!    `tests/roundtrip.rs`'s `a_pathological_image_does_not_take_the_process_down`. This target
//!    watches for **new** panics.
//!
//!    Two fuzz-environment boundaries can make a local run look as if the convergence did not
//!    work: `libfuzzer-sys`'s panic hook aborts before unwinding (see [`loosen_panic_hook`]), and
//!    on Windows libFuzzer's exception handler treats Rust's SEH throw as a crash. **A crash
//!    reported by this target on Windows does not mean the convergence is broken** — that is
//!    confirmed by `cargo test` and by the Linux fuzz job. A converged panic is deliberately
//!    **not** a crash here: rethrowing it would keep an upstream defect visible but would also
//!    leave this gate red for as long as the defect survives. Visibility comes from elsewhere:
//!    the application logs [`Error::QrDecoderPanicked`], and the panic message itself still
//!    reaches stderr through the default hook.
//! 2. **One image must not swallow the memory** — the size is decided by the input but
//!    **bounded** (see `MAX_SIDE`); otherwise one fuzz iteration becomes one huge allocation and
//!    the target becomes unusable.
//! 3. **Anything that decodes must encode back** — the decoded payload rendered as a QR code
//!    again must read back as the same bytes. This runs only when random pixels really do decode,
//!    which is extremely rare, so its extra cost is negligible.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia_transport::image::GrayImage;
use qualia_transport::qr::{self, EcLevel, QrProfile};

/// Upper bound on the image side length (pixels).
///
/// It is deliberately small: QR detection works pixel by pixel, so a large image turns a single
/// execution from microseconds into milliseconds and drops the coverage rate by orders of
/// magnitude. The out-of-bounds and overflow cases that matter sit on small sizes (1×1, 21×21,
/// non-square), not on large images.
const MAX_SIDE: u32 = 48;

/// Makes the library's `catch_unwind` actually take effect.
///
/// `libfuzzer-sys` registers a panic hook that `abort`s **before** unwinding, so that libFuzzer
/// gets a full call stack for crash de-duplication. The consequence is that a panic the library
/// has already converged still looks like a crash here, because the hook never gives
/// `catch_unwind` the chance to unwind — and `qr_scan` covers a path known to panic inside
/// `rqrr`. This function installs a hook that prints the panic and returns instead.
///
/// # Known boundary
///
/// Replacing the hook is **not** enough on **Windows**: a Rust panic there is thrown as an SEH
/// exception, and libFuzzer installs a process-level exception handler that treats the throw as a
/// crash. So on Windows a converged panic still shows up as a crash when running `qr_scan`, while
/// the fuzz job runs on Linux, where a panic raises no signal and the convergence applies.
/// Confirming the convergence locally is `cargo test` (the regression test in
/// `tests/roundtrip.rs`), not this target.
///
/// # What is lost
///
/// A panic that is not converged still counts as a crash: libfuzzer-sys's outer `catch_unwind`
/// cannot catch it and `abort`s, and libFuzzer records the input all the same. What is lost is
/// the call stack from before the unwind; the input sample remains, and one replay produces a
/// stack. The `eprintln!` below at least keeps the panic message.
fn loosen_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| eprintln!("panicked: {info}")));
    });
}

fuzz_target!(|data: &[u8]| {
    loosen_panic_hook();
    if data.len() < 3 {
        return;
    }
    let width = 1 + u32::from(data[0]) % MAX_SIDE;
    let height = 1 + u32::from(data[1]) % MAX_SIDE;
    let needed = (width as usize) * (height as usize);
    let pixels: Vec<u8> = data[2..].iter().copied().cycle().take(needed).collect();
    let Ok(image) = GrayImage::from_luma8(width, height, pixels) else {
        panic!("构造出的图像尺寸与像素数不符");
    };

    let _ = qr::scan::decode_text(&image);

    let Ok(payload) = qr::scan::decode_payload(&image) else {
        return;
    };

    let profile = QrProfile::new(EcLevel::Low, 40).expect("版本合法");
    let Ok(symbol) = profile.encode_payload(&payload) else {
        return;
    };
    let rendered = symbol.render(4, 4).expect("渲染参数合法");
    let again = qr::scan::decode_payload(&rendered).expect("自己画的码必须读得回来");
    assert_eq!(again, payload, "解码再编码的往返不一致");
});
