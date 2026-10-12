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

//! Property tests: properties that must hold for **arbitrary** input.
//!
//! Division of labour with `tests/roundtrip.rs`: the cases there are picked typical shapes
//! (shortest, mid-size, exactly full), while this file tries to falsify "holds for every
//! input". Both are needed: picked cases cannot prove generality, and random cases never
//! reach the boundaries.

use proptest::prelude::*;
#[cfg(feature = "scan-image")]
use qualia_transport::Error;
use qualia_transport::envelope;
use qualia_transport::frame::{self, Reassembler};
#[cfg(feature = "scan-image")]
use qualia_transport::qr::{EcLevel, QrProfile};

/// Arbitrary byte strings (bounded length).
///
/// The upper bound is 512: the envelope itself works independently of length, while the QR
/// properties that really depend on length have their own test with a much smaller bound
/// (see `qr_round_trips`).
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..512)
}

/// Arbitrary text, deliberately heavy on non-ASCII and non-printable characters.
fn arb_text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..64).prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    /// The envelope must round-trip arbitrary byte strings exactly.
    #[test]
    fn envelope_round_trips(payload in arb_bytes()) {
        let text = envelope::encode(&payload);
        let decoded = envelope::decode(&text).expect("a self-encoded text must decode");
        prop_assert_eq!(decoded, payload);
    }

    /// **Arbitrary** text must not make decoding panic: it comes straight from a scanner and
    /// is attacker-controlled input.
    ///
    /// Also pins the weaker property: whatever decodes must be the **canonical** form
    /// (encode it back and decode again, same result). Otherwise one payload would have
    /// several legal texts, while replay accounting and de-duplication compare texts for
    /// equality.
    #[test]
    fn envelope_decode_never_panics(text in arb_text()) {
        if let Ok(payload) = envelope::decode(&text) {
            let canonical = envelope::encode(&payload);
            let again = envelope::decode(&canonical).expect("the canonical spelling must decode");
            prop_assert_eq!(again, payload);
        }
    }

    /// Text placed behind a valid frame header must not panic either.
    ///
    /// This is closer to the real attack surface than the previous case: a scanned code
    /// **always** carries a valid prefix (the prefix is what we check, so an attacker supplies
    /// it), and the deep parsing path must survive arbitrary content on its own.
    #[test]
    fn envelope_decode_never_panics_behind_a_valid_prefix(inner in arb_text()) {
        let text = format!("Q2FA1:1/1:{inner}");
        let _ = envelope::decode(&text);
    }

    /// Encode/decode loop: any small payload rendered as a QR code and read back must match
    /// byte for byte.
    ///
    /// The length bound is deliberately small (32 bytes): this case runs real pixel rendering
    /// and QR detection, so every case costs milliseconds, and raising the bound would only
    /// slow the test down without finding more. Large payloads are covered by the fixed-size
    /// cases in `tests/roundtrip.rs`.
    #[cfg(feature = "scan-image")]
    #[test]
    fn qr_round_trips(payload in prop::collection::vec(any::<u8>(), 0..32)) {
        let profile = QrProfile::new(EcLevel::Low, 5).expect("the version is legal");
        match profile.encode_payload(&payload) {
            Ok(symbol) => {
                let image = symbol.render(4, 4).expect("the render geometry is legal");
                let decoded = qualia_transport::qr::scan::decode_payload(&image)
                    .expect("a rendered code must read back");
                prop_assert_eq!(decoded, payload);
            }
            Err(Error::PayloadTooLarge { .. }) => {}
            Err(other) => prop_assert!(false, "impossible failure: {}", other),
        }
    }

    /// **Any payload, any capacity**: split into frames → feed them one by one to the
    /// reassembler → get the bytes back unchanged.
    ///
    /// The order is deliberately reversed and the first frame is fed twice: a user scanning
    /// guarantees neither an order nor that the same frame is not scanned twice. Neither may
    /// change the result.
    ///
    /// Payload length includes 0: the empty payload is one `Q2FA1:1/1:` and must reassemble as
    /// such (whatever the framing side can produce, the reassembling side accepts — both sides
    /// pin this property together).
    #[test]
    fn frames_round_trip_through_the_reassembler(
        payload in arb_bytes(),
        capacity in 1_usize..64,
    ) {
        prop_assume!(payload.len().div_ceil(capacity) <= envelope::MAX_FRAMES as usize);

        let frames = frame::encode_frames(&payload, capacity).expect("the frame count is within the limit");
        let expected_frames = payload.len().div_ceil(capacity).max(1);
        prop_assert_eq!(frames.len(), expected_frames);

        let mut reassembler = Reassembler::from_first_frame();
        let mut done = None;
        for text in frames.iter().rev() {
            done = reassembler.push(text).expect("a frame it split itself must be accepted");
        }
        prop_assert_eq!(reassembler.received(), expected_frames);
        if expected_frames > 1 {
            prop_assert!(
                reassembler.unit_len().is_some(),
                "a full frame length must be observed"
            );
        }
        let repeated = reassembler.push(&frames[0]).expect("a repeated scan is not an error");
        prop_assert!(repeated.is_none(), "scanning again after completion must not hand out another");
        prop_assert_eq!(reassembler.received(), expected_frames, "a repeat must not change the count");
        prop_assert_eq!(done.expect("must reassemble"), payload.as_slice());

        let mut reassembler = Reassembler::new(capacity);
        let mut done = None;
        for text in &frames {
            done = reassembler.push(text).expect("such a frame must be accepted");
        }
        prop_assert_eq!(done.expect("must reassemble"), payload);
    }

    /// Every frame text produced by the splitter stays **inside** the QR alphanumeric mode.
    ///
    /// This matters more with several frames than with one: the frame header grows with the
    /// frame numbers (`1/100`, `255/255`), and as soon as one character is outside those 45,
    /// the whole code falls back to byte mode — nothing looks wrong in the UI, the code merely
    /// gets bigger and harder to scan, and the capacity table no longer holds.
    #[test]
    fn frame_texts_stay_inside_the_alphanumeric_charset(
        payload in prop::collection::vec(any::<u8>(), 0..200),
        capacity in 1_usize..8,
    ) {
        const ALPHANUMERIC: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
        prop_assume!(payload.len().div_ceil(capacity) <= envelope::MAX_FRAMES as usize);

        let frames = frame::encode_frames(&payload, capacity).expect("the frame count is within the limit");
        prop_assert!(
            frames.iter().all(|text| text
                .chars()
                .all(|character| ALPHANUMERIC.contains(character))),
            "the frame text contains a character outside the alphanumeric mode"
        );
    }

    /// **Arbitrary text** must neither panic the reassembler nor make it hand out a payload out
    /// of nowhere.
    ///
    /// It is the entry point for attacker-controlled input (scanned text comes straight in),
    /// and `Reassembler` is **stateful**: this case feeds a single text, while the state machine
    /// is covered by `fuzz/fuzz_targets/frame_reassemble.rs`, whose input is cut into chunks and
    /// fed one by one to the same reassembler.
    #[test]
    fn reassembler_never_panics_on_arbitrary_text(text in arb_text()) {
        let mut reassembler = Reassembler::from_first_frame();
        if let Ok(Some(bytes)) = reassembler.push(&text) {
            let frame = frame::decode_frame(&text).expect("a text that just decoded must decode");
            prop_assert_eq!(frame.total, 1);
            prop_assert_eq!(bytes, frame.payload);
        }
        prop_assert!(reassembler.received() <= 1);
    }
}
