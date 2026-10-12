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

//! Grayscale images: the form in which pixels are passed between rendering and scanning.
//!
//! # The boundary is drawn at pixels, not at image files
//!
//! On the "import a QR code from an image" path the user supplies a PNG/JPEG file. Turning it
//! into pixels is **something the platform already does**: the JVM has `ImageIO`, Android has
//! `BitmapFactory`, iOS has `UIImage`. Decoding it here would require an image format crate, a
//! decoder maintained for every platform, and would import the historical vulnerabilities of
//! those decoders (image decoders are a frequent source of CVEs).
//!
//! This crate therefore accepts pixels only: **the format belongs to the platform, the QR code
//! belongs to this crate**.

use crate::error::{Error, Result};

/// An 8-bit grayscale image: row-major, `0` is black, `255` is white.
///
/// The dimensions and the pixel count must agree — the only invariant of this type, and the
/// only thing the sole constructor guarantees. The QR localization algorithm indexes and
/// interpolates into the image, so an image claiming 1000×1000 with 10 pixels would make it
/// run out of bounds in other layers.
pub struct GrayImage {
    /// Width, in pixels.
    width: u32,
    /// Height, in pixels.
    height: u32,
    /// Row-major grayscale values, always `width * height` long.
    pixels: Vec<u8>,
}

impl GrayImage {
    /// Pixel limit for a single image: 64 Mi pixels (about 64 MB of grayscale data).
    ///
    /// This is not a cryptographic boundary but a **work boundary**: QR detection does not
    /// need the original resolution, and the platform side should scale the long edge down to
    /// one or two thousand pixels before handing the image over. The limit exists so that a
    /// forgotten downscale shows up as an explicit error instead of an allocation of several
    /// hundred megabytes.
    pub const MAX_PIXELS: usize = 64 * 1024 * 1024;

    /// Constructs from grayscale pixels.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadImageGeometry`] if the width or the height is 0, if the pixel count
    /// does not match `width * height`, or if it exceeds [`GrayImage::MAX_PIXELS`].
    pub fn from_luma8(width: u32, height: u32, pixels: Vec<u8>) -> Result<Self> {
        let expected = image_size(width, height, pixels.len())?;
        if expected != pixels.len() {
            return Err(Error::BadImageGeometry {
                width,
                height,
                pixels: pixels.len(),
            });
        }
        Ok(Self {
            width,
            height,
            pixels,
        })
    }

    /// Constructs from RGBA pixels (alpha is dropped).
    ///
    /// Luma uses the Rec.601 fixed-point approximation `(77·R + 150·G + 29·B) / 256` — the
    /// three weights sum to exactly 256, so the result is an exact 8-bit luma and needs no
    /// clamping.
    ///
    /// **Alpha is dropped rather than composited**: compositing a transparent background onto
    /// black or white would require assuming a background colour, while the QR localization
    /// algorithm does its own adaptive thresholding — it knows the foreground better than we
    /// do.
    pub fn from_rgba8(width: u32, height: u32, pixels: &[u8]) -> Result<Self> {
        let expected = image_size(width, height, pixels.len())?;
        let Some(expected_bytes) = expected.checked_mul(4) else {
            return Err(Error::BadImageGeometry {
                width,
                height,
                pixels: pixels.len(),
            });
        };
        if expected_bytes != pixels.len() {
            return Err(Error::BadImageGeometry {
                width,
                height,
                pixels: pixels.len(),
            });
        }
        let luma = pixels
            .as_chunks::<4>()
            .0
            .iter()
            .map(|pixel| {
                ((77 * u32::from(pixel[0]) + 150 * u32::from(pixel[1]) + 29 * u32::from(pixel[2]))
                    >> 8) as u8
            })
            .collect();
        Ok(Self {
            width,
            height,
            pixels: luma,
        })
    }

    /// Width, in pixels.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Height, in pixels.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// The row-major grayscale values.
    #[must_use]
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// Returns one pixel; out of bounds yields `None`.
    #[must_use]
    pub fn pixel(&self, x: u32, y: u32) -> Option<u8> {
        if x >= self.width || y >= self.height {
            return None;
        }
        self.at(x as usize, y as usize).into()
    }

    /// Unchecked internal read: out of bounds yields white.
    ///
    /// All callers guarantee that the coordinates are in bounds (rendering by the construction
    /// process, scanning by the decoder's `width()` / `height()`). Returning white instead of
    /// panicking makes a hypothetical out-of-bounds read show up as an image nothing can be
    /// scanned from, rather than a crash — no input to this crate may cause a panic.
    pub(crate) fn at(&self, x: usize, y: usize) -> u8 {
        let index = y * (self.width as usize) + x;
        self.pixels.get(index).copied().unwrap_or(u8::MAX)
    }
}

/// Validates the dimensions and computes how many pixels there should be.
fn image_size(width: u32, height: u32, actual: usize) -> Result<usize> {
    let bad = || Error::BadImageGeometry {
        width,
        height,
        pixels: actual,
    };
    if width == 0 || height == 0 {
        return Err(bad());
    }
    let Some(expected) = (width as usize).checked_mul(height as usize) else {
        return Err(bad());
    };
    if expected > GrayImage::MAX_PIXELS {
        return Err(bad());
    }
    Ok(expected)
}

impl core::fmt::Debug for GrayImage {
    /// Prints the dimensions only.
    ///
    /// A 4000×3000 image has 12 million pixels, and `derive(Debug)` would pour all of them
    /// into the log — useless (who reads a grayscale array) and a memory amplification point
    /// for the log.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "GrayImage {{ {}×{}, {} bytes }}",
            self.width,
            self.height,
            self.pixels.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luma_round_trips() {
        let image = GrayImage::from_luma8(2, 2, vec![0, 1, 2, 3]).expect("the size is consistent");
        assert_eq!(image.width(), 2);
        assert_eq!(image.height(), 2);
        assert_eq!(image.pixel(0, 0), Some(0));
        assert_eq!(image.pixel(1, 1), Some(3));
        assert_eq!(image.pixel(2, 0), None, "out of bounds must return None");
        assert_eq!(image.pixel(0, 2), None);
    }

    #[test]
    fn mismatched_size_is_rejected() {
        assert!(GrayImage::from_luma8(2, 2, vec![0, 1, 2]).is_err());
        assert!(GrayImage::from_luma8(0, 2, vec![]).is_err());
        assert!(GrayImage::from_luma8(2, 0, vec![]).is_err());
        assert!(GrayImage::from_luma8(u32::MAX, u32::MAX, vec![0]).is_err());
    }

    #[test]
    fn rgba_converts_to_luma() {
        let pixels = vec![
            0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 255, 0, 255, 0, 255,
        ];
        let image = GrayImage::from_rgba8(4, 1, &pixels).expect("the size is consistent");
        assert_eq!(image.pixel(0, 0), Some(0));
        assert_eq!(image.pixel(1, 0), Some(255));
        assert_eq!(image.pixel(2, 0), Some(76), "0.299 × 255 ≈ 76");
        assert_eq!(image.pixel(3, 0), Some(149), "0.587 × 255 ≈ 149");
    }

    #[test]
    fn rgba_size_must_match() {
        assert!(GrayImage::from_rgba8(1, 1, &[0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(GrayImage::from_rgba8(1, 1, &[0, 0, 0, 0]).is_ok());
    }

    #[test]
    fn debug_does_not_dump_pixels() {
        let image = GrayImage::from_luma8(2, 2, vec![7; 4]).expect("the size is consistent");
        let debug = format!("{image:?}");
        assert!(debug.contains("2×2"), "must print the dimensions: {debug}");
        assert!(!debug.contains('7'), "must not print pixels: {debug}");
    }
}
