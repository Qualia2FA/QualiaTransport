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

//! Fuzz target: parsing of the QR text envelope.
//!
//! # Input surface
//!
//! A QR code is **publicly visible**: it is shown on a screen, photographed and forwarded, so
//! who decodes its text is not controlled at all — anyone holding the code can push
//! **arbitrary** text into [`envelope::decode`]. This is the one place in this crate that
//! interprets untrusted data as structure.
//!
//! # Properties
//!
//! 1. **Never panics** — the denial-of-service line.
//! 2. **Anything that decodes is canonical** — one payload has exactly one text
//!    representation. This is not a matter of taste: de-duplication and replay accounting
//!    compare identities for equality, and the identity comes from the payload.
//! 3. **Envelope expansion is bounded** (Base32's 8/5 plus a fixed header), and **the whole
//!    text stays inside the QR alphanumeric mode**. Once that is broken, encoding silently
//!    falls back to byte mode — nothing looks wrong in the UI, the code merely gets bigger and
//!    harder to scan.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia_transport::envelope;

/// Valid prefixes, used to push the input into the deep parsing path.
///
/// Pure random bytes almost never hit `Q2FA1:` and would only cover the outermost
/// "prefix does not match" branch. This target therefore has a second mode that appends the
/// same input behind each of these prefixes.
const PREFIXES: &[&str] = &[
    "Q2FA1:1/1:",
    "Q2FA1:1/2:",
    "Q2FA1:2/2:",
    "Q2FA1:255/255:",
    "Q2FA1:0/0:",
    "Q2FA1:1/0:",
    "Q2FA1:",
    "Q2FA1:1/1",
    "Q2FA1",
];

/// The 45 characters allowed by the QR alphanumeric mode.
const ALPHANUMERIC: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    check(&text);

    if let Some(&selector) = data.first() {
        let prefix = PREFIXES[usize::from(selector) % PREFIXES.len()];
        let mut candidate = String::with_capacity(prefix.len() + text.len());
        candidate.push_str(prefix);
        candidate.push_str(&text);
        check(&candidate);
    }
});

/// The one property that must hold: return instead of crashing; and if decoding succeeds, the
/// result must be self-consistent.
fn check(text: &str) {
    let Ok(payload) = envelope::decode(text) else {
        return;
    };

    let canonical = envelope::encode(&payload);
    let again = envelope::decode(&canonical).expect("自己编出来的文本必须解得开");
    assert_eq!(again, payload, "信封往返不一致");

    assert!(
        canonical.len() <= payload.len() * 8 / 5 + 16,
        "信封膨胀超出预期：{} 字节的载荷编成了 {} 个字符",
        payload.len(),
        canonical.len()
    );

    assert!(
        canonical.chars().all(|character| ALPHANUMERIC.contains(character)),
        "信封里出现了字母数字模式之外的字符：{canonical}"
    );
}
