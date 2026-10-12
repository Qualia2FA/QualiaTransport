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

//! QR codes: capacity model, encoding, and rendering.
//!
//! # Capacity is derived from the encoder
//!
//! ISO/IEC 18004 Table 7 gives the byte-mode capacity of every version and error
//! correction level (2953 bytes for version 40 at level L). This module does not carry
//! that table: it derives the capacity by binary-searching the encoder itself, asking
//! whether an `n`-byte payload fits into some version not above `max_version`. The
//! number therefore agrees with the encoder by construction. The cost is a few dozen
//! encoder runs (microseconds) when a [`QrProfile`] is built.
//!
//! # "Does not fit" is an answer needed in advance
//!
//! A QR channel has no retry: a payload that does not fit cannot be sent. Hence
//! [`QrProfile::payload_capacity`] reports the exact limit of the channel before
//! anything is displayed, and [`QrProfile::encode_payload`] fails with
//! [`Error::PayloadTooLarge`], whose `needed` and `limit` fields are both in payload
//! bytes: the caller can tell the user how much is missing and suggest the LAN channel.
//!
//! # Multi-frame (animated) QR codes
//!
//! A payload above the limit of one code can be split into several codes displayed in
//! sequence and scanned one by one; splitting and reassembly live in [`crate::frame`].
//! This path needs no network infrastructure.
//!
//! Three capacities are all in payload bytes but cover different scopes:
//!
//! | Method | Meaning |
//! |--------|---------|
//! | [`QrProfile::payload_capacity`] | what **one** code holds (single frame, shortest frame header) |
//! | [`QrProfile::frame_payload_capacity`] | what **each** code holds when split (longest frame header) |
//! | [`QrProfile::exchange_capacity`] | what one exchange (up to N codes) holds in total |
//!
//! The first two differ (both can be 0 on small versions) and must not be mixed up:
//! the frame header sits at the start of the envelope and grows with the number of
//! digits of the frame count — 2 extra characters from ten frames on, 4 from a hundred
//! on — while `payload_capacity` is exactly the length at which one more character no
//! longer fits. Splitting at that capacity produces frames that cannot be rendered once
//! a payload needs ten or more codes. [`QrProfile::encode_payload_frames`] is the
//! complete entry point and picks the correct capacity itself.
//!
//! # Rendering
//!
//! [`Symbol::render`] turns a symbol into a grayscale image: dark modules are 0, light
//! modules and the quiet zone are 255. The quiet zone must be at least 4 modules wide
//! (ISO/IEC 18004), and a request whose pixel count would exceed
//! [`GrayImage::MAX_PIXELS`] is rejected with [`Error::BadRenderGeometry`] instead of
//! allocating.

use crate::envelope;
use crate::error::{Error, Result};
use crate::image::GrayImage;
use qrcodegen::{QrCode, QrCodeEcc, QrSegment, Version};

#[cfg(feature = "scan-image")]
pub mod scan;

/// Minimum quiet zone width, in modules.
///
/// ISO/IEC 18004 requires 4 modules of blank space on each side of a symbol. With less
/// than that a scanner may fail to locate the finder patterns, so a smaller quiet zone
/// is rejected rather than silently rendered into an unscannable image.
const MIN_QUIET_ZONE: u16 = 4;

/// Lower bound of the version range (21×21 modules).
const MIN_VERSION: u8 = 1;

/// Upper bound of the version range (177×177 modules).
const MAX_VERSION: u8 = 40;

/// Hard upper bound of the capacity search, in bytes.
///
/// The byte-mode limit of version 40 at level L is 2953 bytes, and the Base32 expansion
/// of the envelope keeps the encoded text far below 8192 characters. The bound makes the
/// search terminate: even a wrong [`MAX_VERSION`] yields the conservative answer "at
/// least 8192 bytes fit" rather than a runaway search.
const CAPACITY_SEARCH_LIMIT: usize = 8192;

/// Error correction level (L/M/Q/H in ISO/IEC 18004).
///
/// A higher level recovers more damage and holds less payload. The choice belongs to the
/// platform: a code on a screen suffers no ink damage but may be photographed at an
/// angle, blurred, or with glare, while a printed code needs margin for wear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcLevel {
    /// Recovers roughly 7% of the codewords.
    Low,
    /// Recovers roughly 15% of the codewords.
    Medium,
    /// Recovers roughly 25% of the codewords.
    Quartile,
    /// Recovers roughly 30% of the codewords.
    High,
}

impl EcLevel {
    /// Single-letter notation of the specification.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::Low => 'L',
            Self::Medium => 'M',
            Self::Quartile => 'Q',
            Self::High => 'H',
        }
    }

    /// Parses the single-letter notation (case-insensitive).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownEcLevel`] for any letter other than `L`, `M`, `Q`, or `H`.
    pub fn from_letter(letter: char) -> Result<Self> {
        match letter.to_ascii_uppercase() {
            'L' => Ok(Self::Low),
            'M' => Ok(Self::Medium),
            'Q' => Ok(Self::Quartile),
            'H' => Ok(Self::High),
            other => Err(Error::UnknownEcLevel { letter: other }),
        }
    }

    /// Converts to the encoder's type.
    const fn as_qrcodegen(self) -> QrCodeEcc {
        match self {
            Self::Low => QrCodeEcc::Low,
            Self::Medium => QrCodeEcc::Medium,
            Self::Quartile => QrCodeEcc::Quartile,
            Self::High => QrCodeEcc::High,
        }
    }
}

/// Capability of one QR channel: error correction level plus the highest version it is
/// willing to display.
///
/// The maximum version is a property of the platform, not of the data set: a desktop
/// window fits 177×177 modules comfortably, a watch does not, and the platform also
/// decides what happens when a payload does not fit (for example, suggesting the LAN
/// channel).
///
/// # Construction cost
///
/// [`QrProfile::new`] computes the payload limits of the channel on the spot, by
/// binary-searching the encoder (a few dozen encoder runs). Build it once and reuse it
/// instead of rebuilding it for every display. Both the single-frame and the multi-frame
/// capacity are computed, one search each; both depend only on the error correction
/// level and the maximum version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrProfile {
    /// Error correction level.
    ec: EcLevel,
    /// Highest version this channel will display (1–40).
    max_version: u8,
    /// Maximum payload bytes this channel holds (computed at construction).
    payload_capacity: usize,
    /// Maximum payload bytes **each** code holds when split (computed at construction).
    frame_capacity: usize,
}

impl QrProfile {
    /// Builds the capability description of one channel.
    ///
    /// # Errors
    ///
    /// Returns [`Error::VersionOutOfRange`] when `max_version` is outside 1–40.
    pub fn new(ec: EcLevel, max_version: u8) -> Result<Self> {
        if !(MIN_VERSION..=MAX_VERSION).contains(&max_version) {
            return Err(Error::VersionOutOfRange {
                version: max_version,
            });
        }
        Ok(Self {
            ec,
            max_version,
            payload_capacity: capacity_for(ec, max_version, |len| envelope::encode(&vec![0; len])),
            frame_capacity: capacity_for(ec, max_version, |len| {
                envelope::encode_frame(&vec![0; len], envelope::MAX_FRAMES, envelope::MAX_FRAMES)
            }),
        })
    }

    /// Error correction level.
    #[must_use]
    pub const fn ec_level(&self) -> EcLevel {
        self.ec
    }

    /// Highest version this channel will display.
    #[must_use]
    pub const fn max_version(&self) -> u8 {
        self.max_version
    }

    /// Maximum **payload** bytes this channel holds.
    ///
    /// This is the final answer of the whole envelope + Base32 + QR chain, and it is the
    /// number the core library's `TransportCapabilities::check_fits` compares against.
    ///
    /// It describes **one** code (a single frame). When a payload is split across several
    /// codes each one holds less; see [`QrProfile::frame_payload_capacity`].
    #[must_use]
    pub const fn payload_capacity(&self) -> usize {
        self.payload_capacity
    }

    /// Maximum payload bytes **each** code holds when a payload is split.
    ///
    /// It is smaller than [`QrProfile::payload_capacity`]: the frame header sits at the
    /// start of the envelope (`Q2FA1:<frame index>/<frame count>:`), and its length is
    /// `8 + digits(frame index) + digits(frame count)`:
    ///
    /// | Frame count | Longest frame header | Longer than a single frame (`1/1`) |
    /// |-------------|----------------------|------------------------------------|
    /// | 1–9         | `9/9`                | 0 characters |
    /// | 10–99       | `99/99`              | 2 characters |
    /// | 100–255     | `255/255`            | 4 characters |
    ///
    /// `payload_capacity` is exactly the length at which one more character would require
    /// a higher version, so a full frame cut to that length overflows the version once the
    /// frame count reaches two digits.
    ///
    /// # The 4 characters are deducted for the worst case
    ///
    /// The deduction is a constant independent of the frame count: it assumes the longest
    /// header, the one for [`envelope::MAX_FRAMES`] frames, so "the payload can be split"
    /// and "every frame can be encoded" hold by construction. The cost is two or three
    /// bytes per code.
    #[must_use]
    pub const fn frame_payload_capacity(&self) -> usize {
        self.frame_capacity
    }

    /// Payload bytes one exchange holds in total when it may use at most `max_frames`
    /// codes.
    ///
    /// # Declaration use
    ///
    /// The platform declares this number as the core library's
    /// `TransportCapabilities::max_message_len`. That field speaks of one message, and one
    /// message may span several codes here, so declaration and rendering must use the same
    /// number; otherwise the core library approves a share this side cannot render.
    ///
    /// # Clamping, all of it decided by the format and by arithmetic
    ///
    /// - `max_frames` above [`envelope::MAX_FRAMES`] is clamped to that bound: the format
    ///   cannot express frame 256, so asking for more codes adds no capacity.
    /// - The result is never below [`QrProfile::payload_capacity`], since a single code is
    ///   one way of using "at most N codes" for N ≥ 1.
    /// - `max_frames == 0` yields 0: using no code at all holds nothing. The caller is
    ///   meant to turn that into a readable error (`limit: 0`) rather than a usable number.
    /// - The multiplication of the per-frame capacity saturates at `usize::MAX` on
    ///   overflow instead of panicking; the `MAX_FRAMES` clamp above already makes that
    ///   branch unreachable.
    #[must_use]
    pub const fn exchange_capacity(&self, max_frames: u32) -> usize {
        if max_frames == 0 {
            return 0;
        }
        let frames = if max_frames > envelope::MAX_FRAMES {
            envelope::MAX_FRAMES
        } else {
            max_frames
        };
        let split = match self.frame_capacity.checked_mul(frames as usize) {
            Some(total) => total,
            None => usize::MAX,
        };
        if split > self.payload_capacity {
            split
        } else {
            self.payload_capacity
        }
    }

    /// Encodes a payload into one QR symbol.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PayloadTooLarge`] when the payload does not fit, carrying the
    /// required payload bytes and the limit of this channel.
    pub fn encode_payload(&self, payload: &[u8]) -> Result<Symbol> {
        let text = crate::envelope::encode(payload);
        encode_within(&text, self.ec, self.max_version).ok_or(Error::PayloadTooLarge {
            needed: payload.len(),
            limit: self.payload_capacity,
        })
    }

    /// Encodes a payload into **one or more** QR symbols (animated QR).
    ///
    /// A payload that fits one code yields one symbol, bit-for-bit identical to
    /// [`QrProfile::encode_payload`]; a larger payload is split at
    /// [`QrProfile::frame_payload_capacity`] and returned in frame order. The caller
    /// displays the returned symbols in sequence and the user scans them one by one (the
    /// scanning order does not matter, the reassembler accepts any order).
    ///
    /// # Interface
    ///
    /// The caller passes only the maximum number of codes it is willing to let the user
    /// scan. The split point and the per-code capacity both come from this function, so
    /// the two numbers that must agree cannot drift apart.
    ///
    /// # Errors
    ///
    /// - [`Error::PayloadTooLarge`]: the payload exceeds
    ///   [`QrProfile::exchange_capacity`]`(max_frames)`. `needed`/`limit` are both in
    ///   **payload bytes**, so the caller can say how much is missing and suggest the LAN
    ///   channel.
    ///
    /// A `max_frames` value above the format's 255-frame bound does not reach
    /// [`Error::TooManyFrames`]: that bound is already folded into
    /// [`QrProfile::exchange_capacity`] (a larger request only pins `limit` there), so this
    /// entry point cannot produce it. [`Error::TooManyFrames`] belongs to callers of
    /// [`crate::frame::encode_frames`] directly. An inconsistency in the split point (a bug
    /// in this module rather than a property of the caller's input) is likewise reported as
    /// [`Error::PayloadTooLarge`] instead of a panic.
    pub fn encode_payload_frames(&self, payload: &[u8], max_frames: u32) -> Result<Vec<Symbol>> {
        let limit = self.exchange_capacity(max_frames);
        if payload.len() > limit {
            return Err(Error::PayloadTooLarge {
                needed: payload.len(),
                limit,
            });
        }
        if payload.len() <= self.payload_capacity {
            return Ok(vec![self.encode_payload(payload)?]);
        }

        let texts = crate::frame::encode_frames(payload, self.frame_capacity)?;
        texts
            .iter()
            .map(|text| {
                encode_within(text, self.ec, self.max_version).ok_or(Error::PayloadTooLarge {
                    needed: payload.len(),
                    limit: self.frame_capacity,
                })
            })
            .collect()
    }
}

/// One generated QR code: the module matrix, without colour or scaling.
///
/// It deliberately does not use the derived `Debug`: the matrix holds tens of thousands of
/// booleans, dumping it into a log is useless and a large amplification, and the
/// hand-written `Debug` prints only the version, the level, the mask, and the side length.
pub struct Symbol {
    /// Version (1–40).
    version: u8,
    /// Error correction level.
    ec: EcLevel,
    /// Mask chosen by the encoder (0–7).
    mask: u8,
    /// Modules per side (`4 * version + 17`).
    size: u16,
    /// Row-major module matrix: `true` is dark.
    modules: Vec<bool>,
}

impl Symbol {
    /// Version (1–40).
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Error correction level.
    #[must_use]
    pub const fn ec_level(&self) -> EcLevel {
        self.ec
    }

    /// Mask chosen by the encoder (0–7).
    ///
    /// The mask breaks up large same-colour areas so a scanner can locate the symbol; the
    /// specification defines 8 of them and the encoder picks one by penalty score. It is
    /// exposed for diagnostics only (two encodes of the same payload must agree on the
    /// mask); renderers do not need it.
    #[must_use]
    pub const fn mask(&self) -> u8 {
        self.mask
    }

    /// Modules per side, including the function patterns and excluding the quiet zone.
    #[must_use]
    pub const fn size(&self) -> u16 {
        self.size
    }

    /// Row-major module matrix: `true` is dark, always `size * size` long.
    ///
    /// This is the main entry point for renderers: walk this slice with the scale and
    /// colours of the platform instead of calling [`Symbol::module`] once per pixel.
    #[must_use]
    pub fn modules(&self) -> &[bool] {
        &self.modules
    }

    /// Returns one module, or `None` when a coordinate is out of bounds.
    #[must_use]
    pub fn module(&self, x: u16, y: u16) -> Option<bool> {
        if x >= self.size || y >= self.size {
            return None;
        }
        self.modules
            .get(usize::from(y) * usize::from(self.size) + usize::from(x))
            .copied()
    }

    /// Renders the symbol into a grayscale image: dark modules are 0, light modules and
    /// the quiet zone are 255.
    ///
    /// # Arguments
    ///
    /// - `scale`: pixels per module, at least 1.
    /// - `quiet_zone`: quiet zone width in modules on each side, at least 4 as required by
    ///   ISO/IEC 18004. Below that the symbol cannot be scanned, so the request is refused.
    ///
    /// # Purpose
    ///
    /// Platforms draw the module matrix themselves (with theme colours, rounded corners,
    /// animations); this method serves the other two cases: tests (the encode → render →
    /// scan loop has to run for real) and image export (a pixel buffer is needed when the
    /// user sends or saves the code).
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadRenderGeometry`] for invalid geometry or when the result would
    /// exceed [`GrayImage::MAX_PIXELS`] pixels.
    pub fn render(&self, scale: u16, quiet_zone: u16) -> Result<GrayImage> {
        if scale == 0 || quiet_zone < MIN_QUIET_ZONE {
            return Err(Error::BadRenderGeometry { scale, quiet_zone });
        }
        let side_modules = u32::from(self.size) + 2 * u32::from(quiet_zone);
        let side_pixels = side_modules
            .checked_mul(u32::from(scale))
            .ok_or(Error::BadRenderGeometry { scale, quiet_zone })?;
        let count = (side_pixels as usize)
            .checked_mul(side_pixels as usize)
            .ok_or(Error::BadRenderGeometry { scale, quiet_zone })?;
        if count > GrayImage::MAX_PIXELS {
            return Err(Error::BadRenderGeometry { scale, quiet_zone });
        }

        let mut pixels = vec![u8::MAX; count];
        let scale_px = u32::from(scale);
        let quiet_px = u32::from(quiet_zone) * scale_px;
        for y in 0..self.size {
            for x in 0..self.size {
                if self.module(x, y) != Some(true) {
                    continue;
                }
                let left = quiet_px + u32::from(x) * scale_px;
                let top = quiet_px + u32::from(y) * scale_px;
                for dy in 0..scale_px {
                    let row = (top + dy) as usize * side_pixels as usize;
                    for dx in 0..scale_px {
                        if let Some(pixel) = pixels.get_mut(row + (left + dx) as usize) {
                            *pixel = 0;
                        }
                    }
                }
            }
        }
        GrayImage::from_luma8(side_pixels, side_pixels, pixels)
    }
}

impl core::fmt::Debug for Symbol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Symbol {{ version {}, ec {}, mask {}, {}×{} }}",
            self.version,
            self.ec.letter(),
            self.mask,
            self.size,
            self.size
        )
    }
}

/// Encodes a text into some version not above `max_version`; returns `None` when it does
/// not fit.
///
/// Makes no decision beyond version selection: the error correction level is used as
/// passed (never raised silently, since the level is a capability the platform declares),
/// and the mask is chosen by the encoder through its penalty score. Segments come from
/// `QrSegment::make_segments`, which splits numeric, alphanumeric, and byte runs by
/// charset and accepts arbitrary text, so no input panics here.
fn encode_within(text: &str, ec: EcLevel, max_version: u8) -> Option<Symbol> {
    let segments = QrSegment::make_segments(text);
    let code = QrCode::encode_segments_advanced(
        &segments,
        ec.as_qrcodegen(),
        Version::MIN,
        Version::new(max_version),
        None,
        false,
    )
    .ok()?;
    Some(Symbol::from_code(&code, ec))
}

impl Symbol {
    /// Extracts the module matrix from the encoder's result.
    fn from_code(code: &QrCode, ec: EcLevel) -> Self {
        let version = code.version().value();
        let size = 4 * u16::from(version) + 17;
        let mut modules = Vec::with_capacity(usize::from(size) * usize::from(size));
        for y in 0..i32::from(size) {
            for x in 0..i32::from(size) {
                modules.push(code.get_module(x, y));
            }
        }
        Self {
            version,
            ec,
            mask: code.mask().value(),
            size,
            modules,
        }
    }
}

/// Computes the maximum payload bytes this channel holds.
///
/// Doubling finds the first length that does not fit, then a binary search narrows the
/// range down between the last length that fits and the first that does not.
///
/// # A fixed envelope header is the premise of the search
///
/// `make_text` turns an `n`-byte payload into the text to be encoded, and its length
/// depends only on `n`, never on the content (the envelope header is fixed and Base32
/// expands by 8/5). Only then is "this length fits" a well-defined proposition. The
/// single-frame and multi-frame cases differ only in that argument: the multi-frame one
/// passes the longest frame header, the one for [`envelope::MAX_FRAMES`] (see
/// [`QrProfile::frame_payload_capacity`]).
///
/// # Probing with zero bytes is exact
///
/// The Base32 output length depends only on the input length (`ceil(8n/5)` characters),
/// and the Base32 alphabet lies entirely inside the QR alphanumeric mode, so the required
/// version depends only on the text length, never on its content. "Do `n` bytes fit" is
/// therefore one and the same answer for every `n`-byte payload, and probing with zero
/// bytes neither underestimates nor overestimates. `capacity_is_content_independent` pins
/// this property.
///
/// Returns 0 when not even an empty payload fits, which can only come from an
/// out-of-range version, and [`QrProfile::new`] rejects that beforehand. If doubling
/// reaches [`CAPACITY_SEARCH_LIMIT`] without hitting a failure, that limit is returned: a
/// conservative answer rather than a wrong one. Invariant of the search: `low` fits,
/// `high` does not, and the binary search ends with the two adjacent.
fn capacity_for<F>(ec: EcLevel, max_version: u8, make_text: F) -> usize
where
    F: Fn(usize) -> String,
{
    let fits = |len: usize| encode_within(&make_text(len), ec, max_version).is_some();
    if !fits(0) {
        return 0;
    }
    let mut low = 0;
    let mut high = 1;
    while high <= CAPACITY_SEARCH_LIMIT && fits(high) {
        low = high;
        high *= 2;
    }
    if high > CAPACITY_SEARCH_LIMIT {
        return CAPACITY_SEARCH_LIMIT;
    }
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if fits(middle) {
            low = middle;
        } else {
            high = middle;
        }
    }
    low
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The declared maximum version really bounds the size of the symbol.
    #[test]
    fn version_limit_is_respected() {
        for max_version in [1_u8, 2, 5, 10, 20, 40] {
            let profile =
                QrProfile::new(EcLevel::Medium, max_version).expect("the version is legal");
            let capacity = profile.payload_capacity();
            let symbol = profile
                .encode_payload(&vec![0; capacity])
                .expect("a payload within the limit must encode");
            assert!(
                symbol.version() <= max_version,
                "encoded version {}, above the declared limit {max_version}",
                symbol.version()
            );
            assert_eq!(
                symbol.size(),
                4 * u16::from(symbol.version()) + 17,
                "the side length does not match the version"
            );
            assert_eq!(
                symbol.modules().len(),
                usize::from(symbol.size()) * usize::from(symbol.size()),
                "the module count does not match the side length"
            );
        }
    }

    /// Exceeding the capacity reports `needed`/`limit` in **payload bytes** and produces
    /// no symbol.
    #[test]
    fn exceeding_capacity_reports_payload_bytes() {
        let profile = QrProfile::new(EcLevel::Medium, 10).expect("the version is legal");
        let capacity = profile.payload_capacity();
        let result = profile.encode_payload(&vec![0; capacity + 1]);
        match result {
            Err(Error::PayloadTooLarge { needed, limit }) => {
                assert_eq!(
                    needed,
                    capacity + 1,
                    "needed must be the payload byte count"
                );
                assert_eq!(
                    limit, capacity,
                    "limit must be the capacity of this channel"
                );
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    /// Every frame produced by splitting at the multi-frame capacity can be encoded.
    ///
    /// Both directions are pinned: each frame encodes at
    /// [`QrProfile::frame_payload_capacity`], and splitting the same payload at the
    /// single-frame capacity really does yield a frame that cannot be encoded.
    #[test]
    fn frames_split_at_the_multi_frame_capacity_always_render() {
        for (ec, max_version) in [
            (EcLevel::Low, 1),
            (EcLevel::Medium, 1),
            (EcLevel::Low, 5),
            (EcLevel::Medium, 10),
            (EcLevel::High, 20),
            (EcLevel::Low, 40),
        ] {
            let profile = QrProfile::new(ec, max_version).expect("the version is legal");
            let single = profile.payload_capacity();
            let per_frame = profile.frame_payload_capacity();
            assert!(
                per_frame <= single,
                "the multi-frame capacity must not exceed the single-frame one: {per_frame} > {single} (version {}, ec {})",
                max_version,
                ec.letter()
            );
            if single == 0 {
                continue;
            }

            let payload = vec![0x5A; single * 10];
            let symbols = profile
                .encode_payload_frames(&payload, 20)
                .unwrap_or_else(|error| panic!("version {} must split: {error}", max_version));
            assert!(
                symbols.len() >= 10,
                "{} bytes at version {} with a {single}-byte capacity must need ten frames or more, got {}",
                payload.len(),
                max_version,
                symbols.len()
            );
            for (index, symbol) in symbols.iter().enumerate() {
                assert!(
                    symbol.version() <= max_version,
                    "frame {} encoded version {}, above the declared limit {max_version}",
                    index + 1,
                    symbol.version()
                );
            }

            let texts = crate::frame::encode_frames(&payload, single).expect("must split");
            assert!(
                texts
                    .iter()
                    .any(|text| encode_within(text, ec, max_version).is_none()),
                "every frame split at the single-frame capacity of {single} encoded — the multi-frame capacity deducted characters for nothing"
            );

            let many = vec![0x3C; single * 100];
            let symbols = profile
                .encode_payload_frames(&many, envelope::MAX_FRAMES)
                .unwrap_or_else(|error| panic!("one hundred codes must split: {error}"));
            assert!(
                symbols.len() >= 100,
                "{} bytes must need one hundred frames or more, got {}",
                many.len(),
                symbols.len()
            );
            for symbol in &symbols {
                assert!(
                    symbol.version() <= max_version,
                    "the segment with three-digit frame numbers encoded version {}, above the limit {max_version}",
                    symbol.version()
                );
            }
        }
    }

    /// A payload that fits one code yields a bit-identical symbol from the single-frame
    /// and the multi-frame entry point.
    #[test]
    fn one_frame_payloads_take_the_single_frame_path() {
        let profile = QrProfile::new(EcLevel::Medium, 12).expect("the version is legal");
        let payload = vec![7_u8; profile.payload_capacity()];
        let single = profile
            .encode_payload(&payload)
            .expect("must fit in a single frame");
        let frames = profile
            .encode_payload_frames(&payload, 8)
            .expect("must also fit through the multi-frame entry point");
        assert_eq!(frames.len(), 1, "what fits must not be split");
        assert_eq!(frames[0].modules(), single.modules());
        assert_eq!(frames[0].version(), single.version());
    }

    /// The arithmetic of [`QrProfile::exchange_capacity`]: 0 codes hold nothing, the bound
    /// is clamped by the format, the result never decreases and is never below the
    /// single-frame capacity.
    #[test]
    fn exchange_capacity_is_the_declared_limit() {
        let profile = QrProfile::new(EcLevel::Low, 10).expect("the version is legal");
        let single = profile.payload_capacity();
        let per_frame = profile.frame_payload_capacity();

        assert_eq!(
            profile.exchange_capacity(0),
            0,
            "no codes allowed means it does not fit"
        );
        let mut previous = 0;
        for frames in 0..=envelope::MAX_FRAMES {
            let capacity = profile.exchange_capacity(frames);
            assert!(
                capacity >= previous,
                "more frames must not shrink the capacity"
            );
            if frames > 0 {
                assert!(
                    capacity >= single,
                    "one code is also a use of 'at most {frames} codes'"
                );
            }
            assert!(
                capacity >= per_frame * frames as usize,
                "{frames} codes of {per_frame} bytes each must all count towards the total"
            );
            previous = capacity;
        }
        assert_eq!(
            profile.exchange_capacity(envelope::MAX_FRAMES),
            profile.exchange_capacity(u32::MAX),
            "a frame count above the format limit must not buy more capacity"
        );
    }

    /// Exceeding the limit of one exchange reports both numbers in **payload bytes**.
    #[test]
    fn exceeding_the_exchange_capacity_reports_payload_bytes() {
        let profile = QrProfile::new(EcLevel::Low, 10).expect("the version is legal");
        let limit = profile.exchange_capacity(5);
        let payload = vec![0_u8; limit + 1];
        match profile.encode_payload_frames(&payload, 5) {
            Err(Error::PayloadTooLarge {
                needed,
                limit: reported,
            }) => {
                assert_eq!(needed, payload.len());
                assert_eq!(reported, limit);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    /// Capacity does not depend on the payload content: a limit probed with zero bytes
    /// holds for any content.
    #[test]
    fn capacity_is_content_independent() {
        let profile = QrProfile::new(EcLevel::Quartile, 12).expect("the version is legal");
        let capacity = profile.payload_capacity();
        let mut pseudo_random = Vec::with_capacity(capacity);
        let mut state: u32 = 0x1234_5678;
        for _ in 0..capacity {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            pseudo_random.push((state >> 24) as u8);
        }
        for payload in [vec![0_u8; capacity], vec![0xff_u8; capacity], pseudo_random] {
            assert!(
                profile.encode_payload(&payload).is_ok(),
                "a payload of the limit length must encode (the content must not affect the capacity)"
            );
        }
    }

    /// Capacity is non-increasing in the error correction level and non-decreasing in the
    /// version.
    #[test]
    fn capacity_is_monotone_in_level_and_version() {
        let levels = [
            EcLevel::Low,
            EcLevel::Medium,
            EcLevel::Quartile,
            EcLevel::High,
        ];
        for max_version in [1_u8, 5, 15, 40] {
            let capacities: Vec<usize> = levels
                .iter()
                .map(|&ec| {
                    QrProfile::new(ec, max_version)
                        .expect("the version is legal")
                        .payload_capacity()
                })
                .collect();
            for pair in capacities.windows(2) {
                assert!(
                    pair[0] >= pair[1],
                    "a higher error correction level must not increase the capacity: {capacities:?} (version {max_version})"
                );
            }
        }
        for ec in levels {
            let capacities: Vec<usize> = [1_u8, 5, 15, 40]
                .iter()
                .map(|&version| {
                    QrProfile::new(ec, version)
                        .expect("the version is legal")
                        .payload_capacity()
                })
                .collect();
            for pair in capacities.windows(2) {
                assert!(
                    pair[0] <= pair[1],
                    "a higher version must not shrink the capacity: {capacities:?} (ec {})",
                    ec.letter()
                );
            }
        }
    }

    /// The payload capacity of version 1 at level L stays in a sane range: below the
    /// 17-byte byte-mode capacity of the bare symbol, but not absurdly small.
    #[test]
    fn smallest_channel_capacity_is_in_a_sane_range() {
        let profile = QrProfile::new(EcLevel::Low, 1).expect("the version is legal");
        let capacity = profile.payload_capacity();
        assert!(
            (8..=15).contains(&capacity),
            "version 1 at level L must carry 8-15 payload bytes, got {capacity}"
        );
    }

    /// Encoding the same payload twice yields the same symbol: version, mask, and modules.
    #[test]
    fn encoding_is_deterministic() {
        let profile = QrProfile::new(EcLevel::Medium, 20).expect("the version is legal");
        let payload = b"deterministic";
        let first = profile.encode_payload(payload).expect("must encode");
        let second = profile.encode_payload(payload).expect("must encode");
        assert_eq!(first.version(), second.version());
        assert_eq!(first.mask(), second.mask());
        assert_eq!(first.modules(), second.modules());
    }

    #[test]
    fn version_out_of_range_is_rejected() {
        assert!(QrProfile::new(EcLevel::Low, 0).is_err());
        assert!(QrProfile::new(EcLevel::Low, 41).is_err());
        assert!(QrProfile::new(EcLevel::Low, 1).is_ok());
        assert!(QrProfile::new(EcLevel::Low, 40).is_ok());
    }

    #[test]
    fn ec_level_letters_round_trip() {
        for ec in [
            EcLevel::Low,
            EcLevel::Medium,
            EcLevel::Quartile,
            EcLevel::High,
        ] {
            assert_eq!(
                EcLevel::from_letter(ec.letter()).expect("the letter it returned"),
                ec
            );
            assert_eq!(
                EcLevel::from_letter(ec.letter().to_ascii_lowercase())
                    .expect("lower case is accepted too"),
                ec
            );
        }
        assert!(EcLevel::from_letter('X').is_err());
    }

    /// Rendering: image size, quiet zone, and dark modules at the right positions.
    #[test]
    fn render_lays_out_modules_and_quiet_zone() {
        let profile = QrProfile::new(EcLevel::Low, 1).expect("the version is legal");
        let symbol = profile.encode_payload(b"hi").expect("must encode");
        let scale = 3;
        let quiet = 4;
        let image = symbol.render(scale, quiet).expect("the geometry is legal");
        let side = (u32::from(symbol.size()) + 2 * u32::from(quiet)) * u32::from(scale);
        assert_eq!(image.width(), side);
        assert_eq!(image.height(), side);
        assert_eq!(
            image.pixel(0, 0),
            Some(255),
            "the top-left corner must be the quiet zone"
        );
        assert_eq!(
            image.pixel(side - 1, side - 1),
            Some(255),
            "the bottom-right corner must be the quiet zone"
        );
        let origin = u32::from(quiet) * u32::from(scale);
        assert_eq!(
            symbol.module(0, 0),
            Some(true),
            "the corner of a finder pattern must be dark"
        );
        for dy in 0..u32::from(scale) {
            for dx in 0..u32::from(scale) {
                assert_eq!(
                    image.pixel(origin + dx, origin + dy),
                    Some(0),
                    "module ({dx},{dy}) was not rendered dark"
                );
            }
        }
    }

    #[test]
    fn render_rejects_useless_geometry() {
        let profile = QrProfile::new(EcLevel::Low, 1).expect("the version is legal");
        let symbol = profile.encode_payload(b"hi").expect("must encode");
        assert!(symbol.render(0, 4).is_err(), "a scale of 0 is meaningless");
        assert!(
            symbol.render(1, 3).is_err(),
            "a quiet zone below 4 cannot be scanned"
        );
        assert!(symbol.render(1, 4).is_ok());
        assert!(symbol.render(u16::MAX, 4).is_err());
    }

    #[test]
    fn module_out_of_bounds_is_none() {
        let profile = QrProfile::new(EcLevel::Low, 1).expect("the version is legal");
        let symbol = profile.encode_payload(b"hi").expect("must encode");
        assert!(symbol.module(symbol.size(), 0).is_none());
        assert!(symbol.module(0, symbol.size()).is_none());
        assert!(symbol.module(0, 0).is_some());
    }

    #[test]
    fn debug_prints_metadata_not_modules() {
        let profile = QrProfile::new(EcLevel::High, 5).expect("the version is legal");
        let symbol = profile.encode_payload(b"debug").expect("must encode");
        let debug = format!("{symbol:?}");
        assert!(
            debug.contains("ec H"),
            "must carry the error correction level: {debug}"
        );
        assert!(debug.contains('×'), "must carry the side length: {debug}");
        assert!(debug.len() < 80, "the Debug output is too long: {debug}");
    }
}
