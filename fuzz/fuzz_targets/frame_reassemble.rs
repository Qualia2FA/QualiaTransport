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

//! Fuzz target: framing and reassembly of dynamic QR codes.
//!
//! # Input surface
//!
//! [`envelope::decode`] is **stateless**: one line of text in, one payload or one error out.
//! The reassembler is **stateful**, and its state machine is only reached by sequences such as
//! "scan frame 1 of A, then frame 2 of B", which a single-input fuzz target never produces.
//! This target therefore **cuts the input into chunks** and feeds them one by one to the same
//! reassembler, with state shared across chunks. Every chunk is fed both as text (which goes
//! through Base32 decoding) and as an already decoded frame (which skips parsing).
//!
//! # Properties
//!
//! 1. **Never panics** — including the places inside the reassembler that index by frame number.
//! 2. **A rejected frame leaves the state unchanged** — after a user scans the wrong code, the
//!    right one must still be accepted. This property is verified by "`received` and `missing`
//!    are unchanged before and after the error".
//! 3. **The assembled result matches the frame contents** — the accepted frames ordered by frame
//!    number and concatenated must equal the bytes the reassembler hands back. This is the most
//!    valuable property of this target: it watches **order**, and ordering by frame number
//!    rather than by arrival is what the whole module exists for.
//! 4. **Framing then reassembly round-trips** — whatever this crate splits must reassemble. This
//!    also brings the producing side (`encode_frames`) into the same check.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia_transport::envelope;
use qualia_transport::frame::{self, Frame, Reassembler};

/// Maximum number of frames fed in one fuzz run. Kept small so that every input reaches deep
/// into the state machine.
const MAX_FRAMES: usize = 8;

fuzz_target!(|data: &[u8]| {
    check_reassembly(data);
    check_roundtrip(data);
});

/// ① Cut the input into chunks, feed them one by one to the same reassembler, and check the
/// properties of the state machine.
fn check_reassembly(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let capacity = usize::from(data[0]);
    let body = &data[1..];

    let mut reassembler = Reassembler::new(capacity);
    let mut accepted: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    let mut last_received = 0_usize;

    for (round, byte) in body.iter().enumerate().take(MAX_FRAMES) {
        let start = round;
        let end = start.saturating_add(usize::from(*byte)).min(body.len());
        let chunk = &body[start..end];

        if let Ok(text) = core::str::from_utf8(chunk) {
            let _ = reassembler.push(text);
        }
        if chunk.len() >= 9 {
            let index = u32::from(chunk[0]);
            let total = u32::from(chunk[1]);
            let payload = chunk[8..].to_vec();
            if let Ok(done) = reassembler.accept(Frame {
                index,
                total,
                payload: payload.clone(),
            }) {
                if reassembler.received() > last_received {
                    accepted.push((index, total, payload));
                    last_received = reassembler.received();
                }
                if let Some(bytes) = done {
                    check_assembled(&reassembler, &accepted, &bytes);
                }
            }
        }

        assert!(
            reassembler.received() >= last_received,
            "the number of received frames went down: {last_received} → {}",
            reassembler.received()
        );
        last_received = reassembler.received();
        if let Some(total) = reassembler.expected_frames() {
            assert!(
                reassembler.received() <= total as usize,
                "more frames received than the total"
            );
        }
    }

    if let Some(total) = reassembler.expected_frames()
        && reassembler.received() == total as usize
    {
        assert!(
            reassembler.missing().is_empty(),
            "complete, yet frames are still reported missing: {:?}",
            reassembler.missing()
        );
    }
}

/// ② Frames must reassemble back into the payload, including when the **capacity is unknown**.
fn check_roundtrip(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let capacity = usize::from(data[0]) % 16 + 1;
    let payload = &data[1..];
    if payload.len() > capacity * MAX_FRAMES {
        return;
    }

    let Ok(frames) = frame::encode_frames(payload, capacity) else {
        return;
    };
    assert!(frames.len() <= envelope::MAX_FRAMES as usize);

    let mut reassembler = Reassembler::new(capacity);
    let mut done = None;
    for text in &frames {
        done = reassembler
            .push(text)
            .expect("a frame it split itself must be accepted");
    }
    assert_eq!(
        done.expect("a frame it split itself must reassemble")
            .as_slice(),
        payload,
        "the frame round trip is inconsistent (capacity known)"
    );

    let mut reassembler = Reassembler::from_first_frame();
    let mut done = None;
    for text in frames.iter().rev() {
        done = reassembler
            .push(text)
            .expect("it must be accepted with an unknown capacity too (reversed)");
    }
    assert_eq!(
        done.expect("it must reassemble in reverse order too")
            .as_slice(),
        payload,
        "the frame round trip is inconsistent (unknown capacity, reversed)"
    );
}

/// Once complete, the bytes handed back must equal the frames ordered by frame number and
/// concatenated.
///
/// This watches **order**: assembling by arrival order silently yields different bytes when the
/// codes are scanned out of order, and the result looks perfectly normal — the payload layer's
/// AEAD only reports a failed decryption.
fn check_assembled(reassembler: &Reassembler, accepted: &[(u32, u32, Vec<u8>)], bytes: &[u8]) {
    let total = reassembler
        .expected_frames()
        .expect("a complete set has a total");
    let mut expected = Vec::new();
    for index in 1..=total {
        let Some((_, _, payload)) = accepted
            .iter()
            .find(|(at, count, _)| *at == index && *count == total)
        else {
            panic!("complete, yet frame {index} is not among the accepted ones (total {total})");
        };
        expected.extend_from_slice(payload);
    }
    assert_eq!(bytes, expected.as_slice(), "the assembly order is wrong");
}
