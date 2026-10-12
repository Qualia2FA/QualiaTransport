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

//! **Dynamic QR codes**: a payload that does not fit into one code is split across
//! several codes, which the scanning side collects and reassembles one by one.
//!
//! # What it is for
//!
//! The capacity of a QR code is a hard limit (the number computed by
//! [`crate::qr::QrProfile`]), while one synchronization payload can be larger.
//! This module implements **splitting the payload into several codes shown in
//! sequence** — the last path that depends on no network infrastructure and the
//! only one left when there is no Wi-Fi and multicast is disabled.
//!
//! # The wire format does not change
//!
//! Frame index and frame count are part of the envelope
//! (`Q2FA1:<index>/<total>:<BASE32>`), so this module introduces no new wire
//! format: it is simply the first producer of texts such as `1/3`, `2/3`, `3/3`.
//!
//! ```text
//! Q2FA1:1/2:<Base32 of the first part>
//! Q2FA1:2/2:<Base32 of the second part>
//! ```
//!
//! # One step remains between this module and a QR code, and it lives in [`crate::qr`]
//!
//! [`encode_frames`] returns **text**, and text still has to go through the
//! encoder to become a code. Between the two steps sits a quantity only the QR
//! code knows: how many **payload bytes** one code can hold (the envelope and
//! Base32 inflate the data, and a multi-frame header is longer than a
//! single-frame one). The complete "split + render" entry point is therefore
//! [`crate::qr::QrProfile::encode_payload_frames`], which uses
//! [`crate::qr::QrProfile::frame_payload_capacity`] as its capacity. Do **not**
//! split with the single-frame [`crate::qr::QrProfile::payload_capacity`]: the
//! resulting codes do not fit (see the note on `frame_payload_capacity`).
//!
//! # How reassembly knows that the codes belong to one payload
//!
//! A single structural fact of the encoding decides it: **every code except the
//! last is full**. Frames are cut at the capacity, hence
//!
//! - frames 1 to N-1 have a length **exactly equal** to the capacity;
//! - frame N has a length in `1..=capacity`. The only exception is a payload that
//!   is empty and fits in one frame (`Q2FA1:1/1:`): there is no cut to make, so
//!   zero bytes are the whole content.
//!
//! That exception is not a loophole in the check but a precise statement of the
//! rule: for `N >= 2` an empty frame can only come from an encoder that cut one
//! frame too many, and such a code reassembles to a payload that silently gained
//! zero bytes; for `N = 1` an empty frame is exactly "the payload is empty". The
//! splitting side emits such an empty frame only for an empty payload
//! (`chunks()` never yields an empty chunk), so both sides agree on which frame
//! sets are legal: **everything that can be encoded can be reassembled**.
//!
//! Crossed scans ("the user scanned frame 1/3 of payload A and then frame 2/3 of
//! payload B") are therefore caught on the spot: the two payloads have different
//! capacities (or, at equal capacity, different cut points), so the second frame
//! is not a full one. The cost is that the reassembling side has to know the
//! capacity — a number the scanning side usually cannot obtain, because it belongs
//! to the displaying screen. Scanning therefore uses
//! [`Reassembler::from_first_frame`], which **observes** the full-frame length on
//! the first frame it receives and assumes nothing.
//!
//! # What the shape check cannot detect
//!
//! The envelope carries no checksum and no field saying which payload a frame
//! belongs to, so two payloads with the same total length and the same cut points
//! are indistinguishable at this layer and can be swapped frame by frame. The rule
//! above is not authentication in the cryptographic sense but a **cheap shape
//! check** against user-level confusion, not against an attacker: authentication
//! belongs to the payload layer's AEAD, which rejects a mixed-up result.

use crate::base32;
use crate::envelope;
use crate::error::{Error, Result};

/// Splits one payload into the texts of its frames.
///
/// Every returned string is a complete envelope text, ready for
/// [`encode_payload_frames`](crate::qr::QrProfile::encode_payload_frames), and any
/// other encoder accepts it too (the text is already in the envelope format).
///
/// # `capacity` must be the **multi-frame** capacity
///
/// It has to satisfy "the envelope text of every frame fits into the code on the
/// other side". The single-frame capacity
/// ([`crate::qr::QrProfile::payload_capacity`]) **cannot** be used here: from two
/// digits of frame count upwards the header grows by 2 to 4 characters
/// (`255/255:` is 4 characters longer than `1/1:`), and the single-frame capacity
/// sits exactly where one more character no longer fits. The right number is
/// [`crate::qr::QrProfile::frame_payload_capacity`].
///
/// # Empty payloads and zero capacity
///
/// An empty payload is **one** code: zero codes cannot be scanned, and one empty
/// code behaves exactly like the single-frame path (`Q2FA1:1/1:`). It needs no
/// capacity check, since it occupies no payload bytes.
///
/// # Errors
///
/// - [`Error::TooManyFrames`]: the required number of frames exceeds
///   [`envelope::MAX_FRAMES`]. Both fields count frames.
/// - [`Error::PayloadTooLarge`]: `capacity` is 0 while the payload is not empty —
///   a channel whose code holds no byte at all is not a channel. `needed` and
///   `limit` are **payload bytes**, and `limit` reports 0, which reads the same
///   way as "the capacity is small".
pub fn encode_frames(payload: &[u8], capacity: usize) -> Result<Vec<String>> {
    if payload.is_empty() {
        return Ok(vec![envelope::encode_frame(payload, 1, 1)]);
    }
    if capacity == 0 {
        return Err(Error::PayloadTooLarge {
            needed: payload.len(),
            limit: 0,
        });
    }

    let chunks = payload.len().div_ceil(capacity);
    if chunks > envelope::MAX_FRAMES as usize {
        return Err(Error::TooManyFrames {
            needed: chunks as u32,
            limit: envelope::MAX_FRAMES,
        });
    }

    let total = chunks as u32;
    Ok(payload
        .chunks(capacity)
        .enumerate()
        .map(|(offset, chunk)| envelope::encode_frame(chunk, offset as u32 + 1, total))
        .collect())
}

/// One frame read from the text of a single code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Which code this is, 1-based: the range is `1..=total`, with
    /// `total <= 255` ([`envelope::MAX_FRAMES`]).
    pub index: u32,
    /// How many codes there are in total.
    pub total: u32,
    /// The bytes carried by this code.
    pub payload: Vec<u8>,
}

/// Collects frames one by one and reassembles the original payload.
///
/// # It is stateful because scanning is stateful
///
/// The user points a phone at a screen: the first code may be blurred and need a
/// rescan, the order may be reversed, and the same code may be scanned twice. The
/// reassembler therefore accepts frames in **any order** and **repeatedly**, and
/// reports which frames are still missing — exactly what the user interface has to
/// display.
///
/// # The length of a full frame is **observed** on the first frame
///
/// The rule is "every frame except the last is exactly full". That length must
/// **not** be assumed equal to the capacity given by the caller: the displaying
/// side may have split with a value more conservative than the one it reports, in
/// which case every frame is shorter than the capacity and the reassembler would
/// reject **correct** codes. Therefore:
///
/// - when the capacity is known, it is an **upper bound** (no frame may exceed
///   it);
/// - "how long a full frame is" is decided by the first frame received, and every
///   later non-final frame must have that same length.
///
/// This rule is independent of the difference between [`Reassembler::new`] and
/// [`Reassembler::from_first_frame`]: both constructors run the same checks and
/// differ only in their initial state.
///
/// # Which constructor the scanning side should use
///
/// **Use [`Reassembler::from_first_frame`].** The capacity belongs to the
/// displaying side's screen
/// ([`crate::qr::QrProfile::frame_payload_capacity`]) and is unavailable to the
/// scanner; passing this device's own display capacity as the upper bound would
/// reject **legal** frames sent by a larger screen — a phone scanning a desktop's
/// codes has exactly that shape. Use [`Reassembler::new`] only when the other
/// side's cut points are genuinely known (self-tests within one process, or a peer
/// that told you its capacity out of band).
///
/// # A capacity of 0 means "not known yet"
///
/// [`Reassembler::new`] treats 0 as "capacity unknown" and performs no upper bound
/// check, deriving all lengths from observation, rather than declaring every frame
/// bad: 0 is not a very small capacity but the absence of the number, and turning
/// the caller's omission into "every code is broken" would make a working flow
/// unusable while pointing the error at the QR code.
#[derive(Clone)]
pub struct Reassembler {
    /// The capacity declared by the displaying side, as a payload byte limit.
    /// [`usize::MAX`] when unknown.
    capacity: usize,
    /// The length of a full frame, fixed by the first frame received.
    unit: Option<usize>,
    /// The frame contents received so far, ordered by frame index. A missing
    /// position is `None`.
    ///
    /// A `Vec` rather than a `HashMap`: frame indices are dense and there are at
    /// most [`envelope::MAX_FRAMES`] (255) of them. A 255-entry `Vec` is smaller
    /// than a hash map and its **iteration order is deterministic**, which keeps
    /// the "still missing" output stable and the user interface from flickering.
    /// The storage is allocated at full length up front because the maximum is
    /// known, while growing on demand would move it repeatedly in the worst case.
    frames: Vec<Option<Vec<u8>>>,
    /// The total reported by the first frame.
    total: Option<u32>,
    /// The number of frames received so far.
    received: usize,
}

impl Reassembler {
    /// Creates a reassembler; `capacity` is how many **payload bytes** per code
    /// the displaying side declares.
    ///
    /// It is an **upper bound**, not an equality (see "The length of a full frame
    /// is observed on the first frame" in the type documentation). The scanning
    /// side cannot obtain the displaying side's number and should therefore use
    /// [`Reassembler::from_first_frame`]; passing a capacity that is **too small**
    /// rejects the peer's legal frames.
    ///
    /// Passing 0 means "not known yet": no upper bound check, with the full-frame
    /// length derived from observation. When that is the actual situation,
    /// [`Reassembler::from_first_frame`] says it more directly.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: if capacity == 0 { usize::MAX } else { capacity },
            frames: vec![None; envelope::MAX_FRAMES as usize],
            unit: None,
            total: None,
            received: 0,
        }
    }

    /// Creates a reassembler with an **unknown capacity**: the length of a full
    /// frame is decided by the first frame received.
    ///
    /// For the case where the scan callback only receives a string (platform
    /// cameras work that way). Equivalent to [`Reassembler::new`]`(0)`; the
    /// separate constructor puts the intent in the name instead of in a `0`.
    #[must_use]
    pub fn from_first_frame() -> Self {
        Self::new(0)
    }

    /// The capacity declared by the displaying side ([`usize::MAX`] when unknown).
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// The length of a full frame; `None` until the first frame arrives.
    #[must_use]
    pub const fn unit_len(&self) -> Option<usize> {
        self.unit
    }

    /// How many frames are expected in total; `None` until the first frame
    /// arrives.
    #[must_use]
    pub const fn expected_frames(&self) -> Option<u32> {
        self.total
    }

    /// How many frames have been received.
    #[must_use]
    pub const fn received(&self) -> usize {
        self.received
    }

    /// Which frames are still missing (frame indices, ascending); empty until the
    /// first frame arrives.
    ///
    /// The values returned are **frame indices**, not offsets, because they are
    /// shown to the user directly ("frames 2 and 3 still missing").
    #[must_use]
    pub fn missing(&self) -> Vec<u32> {
        let Some(total) = self.total else {
            return Vec::new();
        };
        (1..=total)
            .filter(|index| {
                self.frames
                    .get(*index as usize - 1)
                    .is_none_or(Option::is_none)
            })
            .collect()
    }

    /// Accepts the text of one code.
    ///
    /// Returns `Ok(None)` when the frame was accepted but others are still
    /// missing, and `Ok(Some(payload))` when the set is complete.
    ///
    /// The Base32 body is decoded before any state is written, so a decoding
    /// failure leaves the reassembler untouched.
    ///
    /// # Scanning the same frame twice is not an error
    ///
    /// It yields `Ok(None)` and leaves the counters unchanged. The user interface
    /// is not necessarily closed right after the last frame, and scanning it again
    /// is normal; reporting an error would show "this code is broken" for a code
    /// that is fine.
    ///
    /// # Errors
    ///
    /// - [`Error::NotOurQrText`]: not a code of this application.
    /// - [`Error::MalformedFrameHeader`]: the frame header is malformed.
    /// - [`Error::MalformedBase32`]: the Base32 payload is malformed.
    /// - [`Error::FrameMismatch`]: this frame does not belong to the same payload
    ///   as the previous ones (a different frame count, an out-of-range index, or
    ///   a wrong length shape). **A failing push leaves the reassembler
    ///   unchanged**, so the user can keep scanning the right frame instead of
    ///   starting over.
    pub fn push(&mut self, text: &str) -> Result<Option<Vec<u8>>> {
        let (index, total, body) = envelope::decode_parts(text)?;
        let payload = base32::decode(body)?;
        self.accept_parts(index, total, payload)
    }

    /// Accepts one frame whose parts are already decoded.
    ///
    /// # Errors
    ///
    /// The same as [`Reassembler::push`] except for the three parsing errors.
    pub fn accept(&mut self, frame: Frame) -> Result<Option<Vec<u8>>> {
        self.accept_parts(frame.index, frame.total, frame.payload)
    }

    /// Accepts one already-parsed frame: validates the header, checks that it
    /// belongs to the same payload as the frames received so far, records it, and
    /// assembles the payload once every frame has arrived.
    ///
    /// The header must satisfy `1 <= index <= total <= ` [`envelope::MAX_FRAMES`];
    /// the check repeats the one in [`envelope`] because this layer cannot assume
    /// that a caller came through `push` (`accept` is public).
    ///
    /// Returns `Ok(None)` while frames are still missing, `Ok(Some(payload))` on
    /// the frame that completes the set, and [`Error::FrameMismatch`] **without
    /// changing the state** when the frame is inconsistent.
    fn accept_parts(
        &mut self,
        index: u32,
        total: u32,
        payload: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        if total == 0 || total > envelope::MAX_FRAMES || index == 0 || index > total {
            return Err(Error::FrameMismatch);
        }

        let sample = if index != total {
            Some(payload.len())
        } else {
            None
        };
        self.check_consistent(index, total, payload.len(), sample)?;

        let Some(slot) = self.frames.get_mut(index as usize - 1) else {
            return Err(Error::FrameMismatch);
        };
        if slot.is_some() {
            return Ok(None);
        }

        self.total = Some(total);
        if sample.is_some() {
            self.unit = sample;
        }
        *slot = Some(payload);
        self.received += 1;

        if self.received == total as usize {
            return Ok(Some(self.assemble()?));
        }
        Ok(None)
    }

    /// Checks whether this frame belongs to the same payload as the frames already
    /// received.
    ///
    /// # The rule
    ///
    /// The encoder cuts at a fixed length, so the **only legal shape** is: the
    /// first N-1 frames have an equal length (called unit) and frame N has a length
    /// in `1..=unit`. Every check below follows from that single rule, rather than
    /// adding a second set of rules:
    ///
    /// - **Non-final frame**: its length must not exceed the capacity upper bound;
    ///   if a full-frame sample is already known, it must equal that sample.
    /// - **Final frame**: its length must not exceed the capacity upper bound, nor
    ///   the known full-frame length if there is one.
    /// - **Empty frame**: legal only when it is the only frame (`total == 1`),
    ///   where zero bytes are the whole content and the splitting side encodes an
    ///   empty payload the same way. An empty frame inside a multi-frame set can
    ///   only come from an encoder that cut one frame too many, and accepting it
    ///   would let a silently altered payload through.
    ///
    /// `sample` is the length this frame offers if it is a non-final one. Passing
    /// it as a parameter instead of reading the unit here keeps the reasoning
    /// unambiguous while no unit is known: frames may arrive out of order, and a
    /// final frame that arrives first must not constrain a non-final frame that
    /// arrives later.
    ///
    /// # It stops user-level confusion, not an attacker
    ///
    /// When two payloads are scanned in an interleaved way, the units mismatch
    /// immediately (the two payloads have different cut points) and the error is
    /// reported on the spot. Without this step the mismatched bytes would only be
    /// rejected by the **payload layer's AEAD**, reported as "decryption failed" —
    /// a diagnosis pointing at the wrong key.
    fn check_consistent(
        &self,
        index: u32,
        total: u32,
        len: usize,
        sample: Option<usize>,
    ) -> Result<()> {
        if len == 0 && total > 1 {
            return Err(Error::FrameMismatch);
        }
        if len > self.capacity {
            return Err(Error::FrameMismatch);
        }
        if let Some(known) = self.total
            && known != total
        {
            return Err(Error::FrameMismatch);
        }

        let fullness = match (self.unit, sample) {
            (Some(known), Some(offer)) => {
                if known != offer {
                    return Err(Error::FrameMismatch);
                }
                Some(known)
            }
            (Some(known), None) => Some(known),
            (None, Some(offer)) => Some(offer),
            (None, None) => None,
        };

        match (index == total, fullness) {
            (false, Some(unit)) if len != unit => Err(Error::FrameMismatch),
            (true, Some(unit)) if len > unit => Err(Error::FrameMismatch),
            _ => Ok(()),
        }
    }

    /// Concatenates the received frames in order.
    ///
    /// Only called once every frame has arrived; a missing slot is still reported
    /// as [`Error::FrameMismatch`] instead of being unwrapped.
    fn assemble(&self) -> Result<Vec<u8>> {
        let total = self.total.ok_or(Error::FrameMismatch)? as usize;
        let mut out = Vec::new();
        for slot in self.frames.iter().take(total) {
            let Some(chunk) = slot else {
                return Err(Error::FrameMismatch);
            };
            out.extend_from_slice(chunk);
        }
        Ok(out)
    }
}

impl core::fmt::Debug for Reassembler {
    /// Prints only how many frames were received and which are still missing.
    ///
    /// **Never prints frame contents**: they come from attacker-controlled QR
    /// texts, have unbounded length, and may contain private data. This matches
    /// [`crate::envelope`] — the concern is log amplification, not secret leakage.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reassembler")
            .field("expected", &self.total)
            .field("received", &self.received)
            .field("missing", &self.missing())
            .finish()
    }
}

/// Reads one frame from the text of a single code.
///
/// It differs from [`envelope::decode`] in exactly one point: **multiple frames
/// are not rejected** but decoded into frame index and frame count. A single frame
/// (`1/1`) goes through the same path, so callers have only one path to maintain.
///
/// # Errors
///
/// The same as [`envelope::decode`], minus [`Error::MultiFrameUnsupported`].
pub fn decode_frame(text: &str) -> Result<Frame> {
    let (index, count, body) = envelope::decode_parts(text)?;
    Ok(Frame {
        index,
        total: count,
        payload: base32::decode(body)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The frame texts are pinned byte for byte.
    ///
    /// The expected Base32 comes from the RFC 4648 §10 vectors: `foo` → `MZXW6`,
    /// `bar` → `MJQXE`, `foobar` → `MZXW6YTBOI`. Hand-written expectations are used
    /// instead of decoding against encoding: that would only prove the two sides
    /// agree and stay blind to both of them changing together, while a frame header
    /// cannot be changed once emitted.
    #[test]
    fn the_frame_texts_are_pinned() {
        let frames = encode_frames(b"foobar", 3).expect("拆得开");
        assert_eq!(frames, vec!["Q2FA1:1/2:MZXW6", "Q2FA1:2/2:MJQXE"]);

        let frames = encode_frames(b"foobar", 2).expect("拆得开");
        assert_eq!(frames.len(), 3, "6 字节按 2 字节切是 3 帧，不是 4 帧");
        assert!(
            frames[0].starts_with("Q2FA1:1/3:") && frames[2].starts_with("Q2FA1:3/3:"),
            "帧头必须逐字节对：{frames:?}"
        );

        assert_eq!(encode_frames(b"", 3).expect("空载荷"), vec!["Q2FA1:1/1:"]);
    }

    /// A single frame takes the same path and its text is unchanged: the
    /// single-frame form is `1/1` and the multi-frame implementation must not
    /// alter it.
    #[test]
    fn a_single_frame_still_looks_the_same() {
        assert_eq!(
            encode_frames(b"foo", 100).expect("一帧够"),
            vec![envelope::encode(b"foo")]
        );
        let frame = decode_frame("Q2FA1:1/1:MZXW6").expect("解得开");
        assert_eq!(frame.index, 1);
        assert_eq!(frame.total, 1);
        assert_eq!(frame.payload, b"foo");
    }

    /// **Frames reassemble in any order.**
    ///
    /// Both a reversed order and a rotation starting in the middle yield the
    /// original payload.
    #[test]
    fn frames_reassemble_in_any_order() {
        let payload: Vec<u8> = (0..=255_u8).cycle().take(1000).collect();
        let frames = encode_frames(&payload, 64).expect("拆得开");
        assert!(frames.len() > 4, "这份载荷应当拆成好几帧");

        let mut reassembler = Reassembler::new(64);
        let mut result = None;
        for text in frames.iter().rev() {
            result = reassembler.push(text).expect("每一张都该被收下");
        }
        assert_eq!(result.expect("应当拼齐"), payload);

        let mut reassembler = Reassembler::new(64);
        let mut result = None;
        for offset in 0..frames.len() {
            let text = &frames[(offset + 3) % frames.len()];
            result = reassembler.push(text).expect("每一张都该被收下");
        }
        assert_eq!(result.expect("应当拼齐"), payload);
    }

    /// Scanning the same frame twice is neither an error nor a change of the
    /// counters.
    #[test]
    fn scanning_the_same_frame_twice_is_not_an_error() {
        let frames = encode_frames(b"hello world", 4).expect("拆得开");
        let mut reassembler = Reassembler::new(4);

        assert_eq!(reassembler.push(&frames[0]).expect("第一张"), None);
        assert_eq!(reassembler.received(), 1);
        assert_eq!(reassembler.expected_frames(), Some(3));

        for _ in 0..3 {
            assert_eq!(reassembler.push(&frames[0]).expect("重复不算错"), None);
        }
        assert_eq!(reassembler.received(), 1, "重复不该把计数推上去");
        assert_eq!(reassembler.missing(), vec![2, 3]);
    }

    /// The "still missing" list is accurate and **ascending**, since it is shown to
    /// the user; an unstable order would make it jump.
    #[test]
    fn the_missing_list_is_accurate_and_sorted() {
        let frames = encode_frames(&[0_u8; 100], 10).expect("拆得开");
        assert_eq!(frames.len(), 10);

        let mut reassembler = Reassembler::new(10);
        assert_eq!(reassembler.expected_frames(), None, "还没扫之前不知道总数");
        assert!(reassembler.missing().is_empty());

        reassembler.push(&frames[0]).expect("第一张");
        assert_eq!(reassembler.missing(), (2..=10).collect::<Vec<u32>>());

        reassembler.push(&frames[4]).expect("第五张");
        reassembler.push(&frames[9]).expect("第十张");
        assert_eq!(
            reassembler.missing(),
            vec![2, 3, 4, 6, 7, 8, 9],
            "缺的那几张必须按帧号升序（3 是「第三张」，不是下标 3）"
        );
    }

    /// **The "the first N-1 frames have equal length" rule really does reject
    /// frames.**
    ///
    /// Both directions are exercised: a non-final frame that is too short and one
    /// that is too long, the shapes produced when a user interleaves two payloads
    /// with different cut points. A rejected frame leaves the reassembler
    /// unchanged, so scanning can continue with the right frame.
    #[test]
    fn the_fullness_rule_rejects_mismatched_frames() {
        let a = encode_frames(&[0xAA_u8; 30], 8).expect("拆得开");

        let mut short = Reassembler::new(8);
        short.push(&a[0]).expect("A 的第一张");
        short.push(&a[1]).expect("A 的第二张");
        let result = short.accept(Frame {
            index: 3,
            total: 4,
            payload: vec![0xAA; 6],
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "非末帧必须满载，6 字节的第 3 帧应当被抓住，实际 {result:?}"
        );
        assert_eq!(short.received(), 2);
        short.push(&a[2]).expect("接着扫 A 是对的");
        assert!(short.push(&a[3]).expect("最后一张").is_some());

        let mut long = Reassembler::new(8);
        long.push(&a[0]).expect("A 的第一张");
        let result = long.accept(Frame {
            index: 2,
            total: 4,
            payload: vec![0xAA; 9],
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "超过容量的帧应当被抓住，实际 {result:?}"
        );
    }

    /// **Two payloads of the same shape are indistinguishable at this layer.**
    ///
    /// The format has no field for "which payload I belong to" (see "What the
    /// shape check cannot detect" in the module documentation), so swapping frames
    /// between two payloads of equal total length and equal cut points produces a
    /// mixed payload that this layer cannot notice; the payload layer's AEAD
    /// rejects it. Pinning the boundary here keeps it from being mistaken for
    /// coverage: reassembly is a cheap shape check against user confusion, not
    /// cryptographic authentication.
    #[test]
    fn two_identically_shaped_payloads_are_indistinguishable_here() {
        let a = encode_frames(&[0xAA_u8; 24], 8).expect("拆得开");
        let b = encode_frames(&[0xBB_u8; 24], 8).expect("拆得开");
        assert_eq!(a.len(), b.len(), "两份形状相同，都是三帧 8 字节");

        let mut reassembler = Reassembler::new(8);
        reassembler.push(&a[0]).expect("A 的第一张");
        reassembler
            .push(&b[1])
            .expect("B 的第二张——长度一样，这里看不出来");
        let done = reassembler
            .push(&a[2])
            .expect("A 的第三张")
            .expect("三帧齐了");

        assert_eq!(done.len(), 24);
        assert_ne!(done, vec![0xAA_u8; 24]);
        assert_ne!(done, vec![0xBB_u8; 24]);
        assert_eq!(done[..8], [0xAA_u8; 8]);
        assert_eq!(done[8..16], [0xBB_u8; 8]);
        assert_eq!(done[16..], [0xAA_u8; 8]);
    }

    /// Frames carrying a different frame count are rejected.
    #[test]
    fn a_different_frame_count_is_caught() {
        let a = encode_frames(&[0xAA_u8; 30], 8).expect("拆得开");
        let b = encode_frames(&[0xBB_u8; 10], 8).expect("拆得开");

        let mut reassembler = Reassembler::new(8);
        reassembler.push(&a[0]).expect("A 的第一张");
        let result = reassembler.push(&b[0]);
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "张数不同必须被抓住，实际 {result:?}"
        );
    }

    /// Inconsistent frame index and frame count (0, or an index beyond the total)
    /// are always rejected, leaving the state untouched.
    #[test]
    fn impossible_frame_numbers_are_rejected() {
        let mut reassembler = Reassembler::new(8);
        for (index, total) in [(0_u32, 1_u32), (1, 0), (3, 2), (2, 1), (300, 1)] {
            let frame = Frame {
                index,
                total,
                payload: vec![0; 8],
            };
            let result = reassembler.accept(frame);
            assert!(
                matches!(result, Err(Error::FrameMismatch)),
                "{index}/{total} 应当被拒绝，实际 {result:?}"
            );
        }
        assert_eq!(reassembler.received(), 0);
    }

    /// **An empty frame is rejected inside a multi-frame set and accepted as the
    /// whole payload.**
    ///
    /// An empty final frame in a multi-frame set means the encoder cut one frame
    /// too many, and such a code reassembles to a payload with extra zero bytes — a
    /// silently altered payload. A single frame (`1/1`) has no such ambiguity: it
    /// is "the payload is empty", exactly the way the splitting side encodes an
    /// empty payload, so both sides must agree or this module would emit a code its
    /// own peer rejects.
    #[test]
    fn an_empty_frame_is_only_legal_when_it_is_the_whole_payload() {
        let mut reassembler = Reassembler::new(8);
        reassembler
            .accept(Frame {
                index: 1,
                total: 2,
                payload: vec![1; 4],
            })
            .expect("第一张");
        let result = reassembler.accept(Frame {
            index: 2,
            total: 2,
            payload: Vec::new(),
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "多帧里的空末帧必须被拒绝，实际 {result:?}"
        );

        let mut reassembler = Reassembler::new(8);
        let result = reassembler.accept(Frame {
            index: 1,
            total: 2,
            payload: Vec::new(),
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "多帧里的空首帧必须被拒绝，实际 {result:?}"
        );

        let mut reassembler = Reassembler::new(8);
        let done = reassembler
            .accept(Frame {
                index: 1,
                total: 1,
                payload: Vec::new(),
            })
            .expect("空载荷是合法的单帧");
        assert_eq!(done.expect("一张就齐了"), Vec::<u8>::new());
        assert!(reassembler.missing().is_empty());

        let frames = encode_frames(b"", 8).expect("空载荷是一张码");
        let mut reassembler = Reassembler::new(8);
        let done = reassembler.push(&frames[0]).expect("自己编的必须收得下");
        assert_eq!(done.expect("一张就齐了"), Vec::<u8>::new());
    }

    /// With an unknown capacity the full-frame length comes from the **first**
    /// frame: the second (final) frame may be shorter than the unit but not longer.
    #[test]
    fn an_unknown_capacity_derives_the_unit_from_the_first_frame() {
        let mut reassembler = Reassembler::from_first_frame();
        assert_eq!(reassembler.capacity(), usize::MAX, "未知容量不做上界检查");
        assert_eq!(reassembler.unit_len(), None);

        reassembler
            .accept(Frame {
                index: 1,
                total: 2,
                payload: vec![1; 5],
            })
            .expect("第一帧给出了 unit");
        assert_eq!(reassembler.unit_len(), Some(5), "unit 应当来自第一帧");

        let too_long = Reassembler::from_first_frame();
        let mut too_long = {
            let mut it = too_long;
            it.accept(Frame {
                index: 1,
                total: 2,
                payload: vec![1; 5],
            })
            .expect("第一帧");
            it
        };
        let result = too_long.accept(Frame {
            index: 2,
            total: 2,
            payload: vec![2; 9],
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "末帧长于 unit 必须被拒绝，实际 {result:?}"
        );

        let done = reassembler
            .accept(Frame {
                index: 2,
                total: 2,
                payload: vec![2; 3],
            })
            .expect("末帧短于 unit 是合法的");
        assert_eq!(done.expect("拼齐"), [vec![1_u8; 5], vec![2_u8; 3]].concat());
    }

    /// **Non-final frames must all have the same length**, whether or not the
    /// capacity is known. This is the rule that identifies "these codes are one
    /// payload": two payloads have different cut points, so an interleaved scan
    /// mismatches on the unit. A failing frame leaves the state unchanged.
    #[test]
    fn non_final_frames_must_all_be_the_same_length() {
        let mut reassembler = Reassembler::from_first_frame();
        reassembler
            .accept(Frame {
                index: 1,
                total: 3,
                payload: vec![1; 8],
            })
            .expect("第一帧 8 字节");
        let result = reassembler.accept(Frame {
            index: 2,
            total: 3,
            payload: vec![2; 7],
        });
        assert!(
            matches!(result, Err(Error::FrameMismatch)),
            "第二帧只有 7 字节，必须被拒绝，实际 {result:?}"
        );
        assert_eq!(reassembler.received(), 1, "出错时状态不变");
    }

    /// Exceeding the frame limit reports how many frames are needed and what the
    /// limit is; 255 frames, the maximum, still encode, and frame indices are
    /// decimal without zero padding.
    #[test]
    fn too_many_frames_reports_the_frame_counts() {
        let result = encode_frames(&vec![0_u8; 256], 1);
        match result {
            Err(Error::TooManyFrames { needed, limit }) => {
                assert_eq!(needed, 256);
                assert_eq!(limit, envelope::MAX_FRAMES);
            }
            other => panic!("应当报帧数超过上限，实际 {other:?}"),
        }

        let frames = encode_frames(&vec![0_u8; 255], 1).expect("刚好在上限之内");
        assert_eq!(frames.len(), 255);
        assert_eq!(frames[254], "Q2FA1:255/255:AA");
        assert_eq!(frames[0], "Q2FA1:1/255:AA");
    }

    /// A split request with a capacity of 0 is rejected and reports **payload
    /// bytes**; an empty payload still encodes to one code, since it occupies no
    /// bytes and is therefore not "does not fit".
    #[test]
    fn encoding_into_a_zero_capacity_is_rejected() {
        let result = encode_frames(b"x", 0);
        match result {
            Err(Error::PayloadTooLarge { needed, limit }) => {
                assert_eq!(needed, 1);
                assert_eq!(limit, 0);
            }
            other => panic!("应当报「装不下」，实际 {other:?}"),
        }
        assert_eq!(encode_frames(b"", 0).expect("空载荷"), vec!["Q2FA1:1/1:"]);
    }

    /// Text that is not a code of this application is reported as
    /// [`Error::NotOurQrText`], not as a malformed header.
    #[test]
    fn foreign_text_is_reported_as_foreign() {
        for text in ["hello", "Q2FA2:1/1:MZXW6", "https://example.com"] {
            let result = decode_frame(text);
            assert!(
                matches!(result, Err(Error::NotOurQrText)),
                "{text} 应当报「不是我们的码」，实际 {result:?}"
            );
        }
    }

    /// The debug output prints counters only and **never frame contents**: neither
    /// the Base32 text nor the decoded bytes may appear.
    #[test]
    fn debug_does_not_dump_frames() {
        let mut reassembler = Reassembler::new(8);
        reassembler
            .push("Q2FA1:1/2:MZXW6YTBOI")
            .expect("第一张收下");
        let text = format!("{reassembler:?}");
        assert!(text.contains("expected: Some(2)"), "实际 {text}");
        assert!(text.contains("received: 1"), "实际 {text}");
        assert!(!text.contains("MZXW6"), "帧文本泄露进了 Debug：{text}");
        assert!(!text.contains("foo"), "帧内容泄露进了 Debug：{text}");
    }

    /// A payload split and reassembled is **byte-for-byte identical** for every
    /// capacity, from 1 (the most frames) up to capacities larger than the payload.
    ///
    /// The payload is 200 bytes so that a capacity of 1 yields 200 frames, within
    /// [`envelope::MAX_FRAMES`] (255); 300 bytes would be rejected at capacity 1,
    /// which is not the property under test here.
    #[test]
    fn every_capacity_round_trips() {
        let payload: Vec<u8> = (0..=255_u8).cycle().take(200).collect();
        for capacity in [1_usize, 2, 3, 7, 64, 199, 200, 201, 1000] {
            let frames = encode_frames(&payload, capacity).expect("拆得开");
            let mut reassembler = Reassembler::new(capacity);
            let mut result = None;
            for text in &frames {
                result = reassembler.push(text).expect("每一张都该被收下");
            }
            assert_eq!(
                result.expect("应当拼齐"),
                payload.as_slice(),
                "容量 {capacity} 下往返不一致"
            );
        }
    }
}
