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

//! Reading QR codes out of images (`scan-image` feature).
//!
//! This is the scanning path of the side that has no camera: a desktop imports a
//! picture instead (a screenshot of the phone screen, a photo, a file from a
//! chat). Mobile platforms scan with the platform camera and receive text
//! directly, which is why this module is an optional feature.
//!
//! Input is pixels, not files: image **format** decoding belongs to the platform
//! (see [`crate::image`]), and this module only accepts grayscale pixels.
//!
//! # Decoder panics are contained
//!
//! An imported image may come from anyone. The decoder (`rqrr` 0.11.0) asserts
//! inside its perspective transform, and a degenerate image — periodic noise
//! reaches it with a few dozen bytes — makes that transform produce an extreme
//! value or NaN, which panics the thread.
//!
//! The contract of this crate is that no input may cause a panic, so every call
//! into the decoder goes through `caught` (a private function of this module):
//! the panic becomes [`Error::QrDecoderPanicked`] and the caller sees "this image
//! cannot be read" instead of losing the process.
//!
//! Two consequences are worth stating: the containment relies on panic unwinding
//! (a `panic = "abort"` build loses it), and each call pays for one
//! `catch_unwind` (microseconds against a millisecond of image decoding).

use crate::envelope;
use crate::error::{Error, Result};
use crate::frame::{self, Frame};
use crate::image::GrayImage;
use rqrr::PreparedImage;

/// Smallest image side that can be recognised, in pixels.
///
/// The smallest QR code (version 1) is 21×21 modules and a module needs at least
/// one pixel, so an image smaller than 21×21 **cannot** contain a code. Rejecting
/// it early skips a detection that is bound to fail and avoids the decoder's
/// boundary paths on tiny images.
const MIN_IMAGE_SIDE: u32 = 21;

/// Reads one piece of text out of an image (the first code that decodes).
///
/// An image may contain several QR codes; this returns the **first** one that
/// yields text, in the order the decoder located them. To find the one belonging
/// to this application, use [`decode_payload`].
///
/// # Errors
///
/// - [`Error::NoQrFound`]: no code in the image, or none large enough to read.
/// - [`Error::QrNotText`]: the decoded bytes are not valid UTF-8.
/// - [`Error::QrDecode`]: a code was found but failed checksum or error correction.
pub fn decode_text(image: &GrayImage) -> Result<String> {
    let mut found: Option<String> = None;
    let report = scan_either_way(image, |raw| {
        if let Ok(text) = core::str::from_utf8(raw) {
            found = Some(text.to_owned());
            true
        } else {
            false
        }
    });
    found.ok_or_else(|| report.into_error())
}

/// Reads a **payload of this application** out of an image (single frame only).
///
/// Unlike [`decode_text`] it skips foreign QR codes: when an image holds both a
/// code of this application and, say, an advertisement, the former wins instead
/// of the call reporting a foreign code.
///
/// Multi-frame codes need [`decode_frame`]: this entry point takes one text and
/// returns one complete payload, and it reports [`Error::MultiFrameUnsupported`]
/// when the code is part of a set (that is a wrong entry point, not a bad code).
///
/// # Errors
///
/// When no code of this application is present, the most informative error is
/// returned: a code that is ours but damaged reports its specific error (for
/// example [`Error::MalformedBase32`]), otherwise [`Error::NotOurQrText`] for a
/// foreign code or [`Error::NoQrFound`].
pub fn decode_payload(image: &GrayImage) -> Result<Vec<u8>> {
    decode_with(image, envelope::decode)
}

/// Reads **one frame of this application** out of an image, that is one code of a
/// multi-frame set.
///
/// Single frames (`1/1`) take this path too, so callers maintain one code path
/// (see [`crate::frame::decode_frame`]).
///
/// # Errors
///
/// The same as [`decode_payload`], except that [`Error::MultiFrameUnsupported`]
/// is never returned.
pub fn decode_frame(image: &GrayImage) -> Result<Frame> {
    decode_with(image, frame::decode_frame)
}

/// Picks one code **of this application** out of the image and hands its text to
/// `parse`.
///
/// The two scanning entry points differ only in `parse`, and the picking rules —
/// skip foreign codes, pick the most informative error — have to be identical,
/// otherwise an image that decodes through one entry point reports a different
/// error through the other. The function is private, which is why the two entry
/// points above refer to it in code font.
fn decode_with<T, F>(image: &GrayImage, mut parse: F) -> Result<T>
where
    F: FnMut(&str) -> Result<T>,
{
    let mut found: Option<T> = None;
    let mut specific: Option<Error> = None;
    let report = scan_either_way(image, |raw| {
        let Ok(text) = core::str::from_utf8(raw) else {
            return false;
        };
        match parse(text) {
            Ok(value) => {
                found = Some(value);
                true
            }
            Err(error) => {
                if !matches!(error, Error::NotOurQrText) {
                    specific = Some(error);
                }
                false
            }
        }
    });
    match found {
        Some(value) => Ok(value),
        None => Err(specific.unwrap_or_else(|| report.into_error())),
    }
}

/// What happened during one scan, used to pick the most informative error.
#[derive(Default)]
struct ScanReport {
    /// A grid was found but did not decode (the first such error).
    grid_error: Option<Error>,
    /// Bytes were decoded, but they are not text.
    saw_binary: bool,
    /// Text was decoded.
    saw_text: bool,
    /// The callback took something, so the scan stopped early and found what it wanted.
    accepted: bool,
    /// The decoder itself panicked and `caught` stopped it.
    ///
    /// This is a real anomaly rather than "no code found": folding it into
    /// [`Error::NoQrFound`] would hide it from logs entirely. See
    /// [`Error::QrDecoderPanicked`].
    decoder_panicked: bool,
}

impl ScanReport {
    /// Picks one error, most informative first.
    ///
    /// The order follows what the caller can tell the user: **text was decoded**
    /// means the image does contain a code, just not ours ("you scanned the wrong
    /// code"); **the decoder panicked** means the image could not even be scanned
    /// to the end, which is worth more than "no code found"; **bytes that are not
    /// text** mean that code was not meant for text; a grid error means the code is
    /// there but unreadable; nothing at all means the image holds no code.
    fn into_error(self) -> Error {
        if self.saw_text {
            Error::NotOurQrText
        } else if self.decoder_panicked {
            Error::QrDecoderPanicked
        } else if self.saw_binary {
            Error::QrNotText
        } else if let Some(error) = self.grid_error {
            error
        } else {
            Error::NoQrFound
        }
    }
}

/// Wraps one decoder call that may panic.
///
/// `rqrr` 0.11.0 asserts inside its perspective transform, and a degenerate image
/// (periodic noise is the easiest to reproduce) makes the transform produce an
/// extreme value or NaN. A few dozen input bytes are enough, and the input is
/// **attacker controlled**, because "import an image" means the user may hand the
/// application a picture somebody else sent them.
///
/// Since the assertion is in the dependency, each call into it is contained here:
/// `None` means "the decoder panicked" and the caller records
/// [`Error::QrDecoderPanicked`]. The containment is per call rather than per scan,
/// so a callback of the caller's own is never inside it and a panic in this crate
/// is not swallowed by accident.
fn caught<T>(f: impl FnOnce() -> T) -> Option<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).ok()
}

/// Scans `image`, and scans it inverted when the first pass accepted nothing.
///
/// A code drawn light on dark holds exactly the same data as one drawn the usual way round;
/// only the convention differs, and the tool that drew it — or the theme it was drawn for —
/// is free to pick either. The decoder accepts the usual one only, so reading the other means
/// asking it about the inverted image.
///
/// The second pass runs only after a first pass that accepted nothing, so an image with a
/// readable code on it pays one detection, and the retry costs nothing on the ordinary path.
/// When neither way round is accepted, the first pass's report is returned: it describes the
/// image the caller actually handed over, which is what its error message should be about.
fn scan_either_way<F>(image: &GrayImage, mut on_raw: F) -> ScanReport
where
    F: FnMut(&[u8]) -> bool,
{
    let report = scan(image, &mut on_raw);
    if report.accepted {
        return report;
    }
    let Some(flipped) = inverted(image) else {
        return report;
    };
    let flipped_report = scan(&flipped, &mut on_raw);
    if flipped_report.accepted {
        flipped_report
    } else {
        report
    }
}

/// The same image with light and dark exchanged.
///
/// Returns `None` when the copy cannot be built (the size limits of [`GrayImage`]), which
/// leaves the caller with the report it already has rather than an error of its own.
fn inverted(image: &GrayImage) -> Option<GrayImage> {
    let pixels = image.pixels().iter().map(|value| !value).collect();
    GrayImage::from_luma8(image.width(), image.height(), pixels).ok()
}

/// Tries to decode every grid, handing each **successfully decoded byte stream**
/// to the callback.
///
/// The callback returning `true` means "this is what I wanted" and stops the scan.
/// A callback is used instead of returning `Vec<Vec<u8>>` because decoded grids
/// borrow the decoder's own buffers and callers usually want only the first usable
/// one; the price is that error reporting is collected separately (see
/// [`ScanReport`]).
fn scan<F>(image: &GrayImage, mut on_raw: F) -> ScanReport
where
    F: FnMut(&[u8]) -> bool,
{
    let mut report = ScanReport::default();
    if image.width() < MIN_IMAGE_SIDE || image.height() < MIN_IMAGE_SIDE {
        return report;
    }
    // Preparation can panic as well: `prepare_from_greyscale` has an `expect`.
    let Some(mut prepared) = caught(|| {
        PreparedImage::prepare_from_greyscale(
            image.width() as usize,
            image.height() as usize,
            |x, y| image.at(x, y),
        )
    }) else {
        report.decoder_panicked = true;
        return report;
    };
    // Locating the grids is where the assertion inside `Perspective::map` fires.
    let Some(grids) = caught(|| prepared.detect_grids()) else {
        report.decoder_panicked = true;
        return report;
    };

    for grid in grids {
        // Decoding one grid does not affect the others, so a panic here is
        // recorded and the loop continues.
        let decoded = caught(|| {
            let mut raw = Vec::new();
            grid.decode_to(&mut raw).map(|metadata| (raw, metadata))
        });
        match decoded {
            Some(Ok((raw, _metadata))) => {
                if core::str::from_utf8(&raw).is_ok() {
                    report.saw_text = true;
                } else {
                    report.saw_binary = true;
                }
                if on_raw(&raw) {
                    report.accepted = true;
                    return report;
                }
            }
            Some(Err(error)) => {
                if report.grid_error.is_none() {
                    report.grid_error = Some(Error::QrDecode(error));
                }
            }
            None => report.decoder_panicked = true,
        }
    }
    report
}
