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

//! Base32 per RFC 4648 §6 (upper-case alphabet).
//!
//! The QR **alphanumeric mode** accepts 45 characters only: `0`–`9`, `A`–`Z`, space and
//! `$ % * + - . / :`. Base64's lower-case letters are not among them, so it can only use byte
//! mode, at 10.67 bits per payload byte; the upper-case letters and digits of Base32 **all**
//! fall inside alphanumeric mode, at 8.8 bits per payload byte. The alphabet contains no
//! `0`/`1`/`8`/`9`, so there is no `0`/`O` or `1`/`I` ambiguity when the text is copied, and
//! decoding is case-insensitive: the text still decodes after a clipboard, a chat application
//! or OCR has been through it.

use crate::error::{Error, Result};

/// The RFC 4648 §6 alphabet: `A`–`Z` followed by `2`–`7`.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes bytes into Base32 text: upper case, **without padding**.
///
/// No `=` is written because padding carries no information (the length follows from the text
/// length itself) while a QR code is charged per character: every 5 bytes would add 1–6
/// characters of padding for nothing.
///
/// The accumulator only keeps the low bits that have not been consumed yet, so its width
/// **never exceeds 12 bits** (at most 4 leftover bits + 8 new bits) and the shift cannot
/// overflow `u32`; clearing the consumed high bits every iteration is what keeps that
/// invariant.
pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(
                ALPHABET[((accumulator >> bits) & 0x1f) as usize],
            ));
        }
        accumulator &= (1_u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(
            ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize],
        ));
    }
    out
}

/// Decodes Base32 text back into bytes.
///
/// Deliberately tolerant in three ways, matching the core library's `base32`:
///
/// 1. **Case-insensitive** — the text may have been through a clipboard, a chat application or
///    OCR.
/// 2. **Trailing padding tolerated** — some scanners append `=`.
/// 3. **Leading and trailing whitespace tolerated** — some scanners append a newline.
///
/// Deliberately strict in two ways:
///
/// 1. **An impossible length is rejected.** The length of Base32 text can only have the
///    remainders 0/2/4/5/7; texts with remainder 1/3/6 cannot be produced by any byte string.
/// 2. **Non-zero trailing bits are rejected.** Otherwise the same bytes would have several
///    valid texts, and "are these two codes the same one" would become a question without an
///    answer — deduplication and replay accounting both rely on text equality.
///
/// After the loop `bits` is at most 7; 5 or more leftover bits mean the length itself is
/// illegal (remainder 1/3/6), and non-zero leftover low bits mean this is not the canonical
/// spelling. Neither is "another legal spelling"; both return [`Error::MalformedBase32`].
pub(crate) fn decode(text: &str) -> Result<Vec<u8>> {
    let body = text.trim().trim_end_matches('=');
    let mut out = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in body.bytes() {
        let value = symbol_value(byte).ok_or(Error::MalformedBase32)?;
        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xff) as u8);
        }
        accumulator &= (1_u32 << bits) - 1;
    }
    if bits >= 5 || accumulator != 0 {
        return Err(Error::MalformedBase32);
    }
    Ok(out)
}

/// Maps one character to its 5-bit value; returns `None` if it is not in the alphabet.
fn symbol_value(byte: u8) -> Option<u8> {
    match byte.to_ascii_uppercase() {
        upper @ b'A'..=b'Z' => Some(upper - b'A'),
        digit @ b'2'..=b'7' => Some(digit - b'2' + 26),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Base32 test vectors of RFC 4648 §10 (in their unpadded form).
    ///
    /// The vectors come from the specification text rather than from encoding a self-made
    /// value and decoding it again: the latter is completely blind to a wholesale
    /// implementation error — mapping `2`–`7` wrongly on both sides still round-trips green.
    #[test]
    fn rfc4648_vectors() {
        let vectors: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ];
        for (data, expected) in vectors {
            assert_eq!(
                encode(data),
                *expected,
                "encoding does not match RFC 4648 §10: {data:?}"
            );
            assert_eq!(
                decode(expected).expect("a specification vector must decode"),
                *data,
                "decoding does not match RFC 4648 §10: {expected}"
            );
        }
    }

    /// Both the padded spelling and the all-lower-case spelling must decode.
    #[test]
    fn padded_and_lowercase_forms_decode() {
        assert_eq!(
            decode("MZXW6YTBOI======").expect("padding is legal"),
            b"foobar",
            "the padded canonical spelling must decode"
        );
        assert_eq!(
            decode("mzxw6ytboi").expect("lower case is legal"),
            b"foobar",
            "decoding is case-insensitive"
        );
        assert_eq!(decode("  MZXW6  ").expect("whitespace is legal"), b"foo");
    }

    /// Text whose length remainder is 1/3/6 cannot be produced by any byte string and must be
    /// rejected.
    #[test]
    fn rejects_impossible_lengths() {
        for text in ["A", "AAA", "AAAAAA"] {
            assert!(
                decode(text).is_err(),
                "text of impossible length was accepted: {text:?}"
            );
        }
    }

    /// Non-zero trailing bits must be rejected. `MY` and `MZ` both decode to `f`, but only the
    /// former is the canonical spelling.
    #[test]
    fn rejects_non_canonical_tail_bits() {
        assert_eq!(decode("MY").expect("canonical spelling"), b"f");
        assert!(
            decode("MZ").is_err(),
            "flipping one tail bit yields another text, and it must be rejected — otherwise \
             the same bytes have several legal spellings and deduplication and replay \
             accounting lose their basis"
        );
    }

    /// Characters outside the alphabet are rejected, in particular `0`/`1`/`8`/`9` must not be
    /// treated as valid values.
    #[test]
    fn rejects_characters_outside_the_alphabet() {
        for text in ["M0", "M1", "M8", "M9", "M!", "M ", "M-", "M_", "Mé"] {
            assert!(
                decode(text).is_err(),
                "illegal character was accepted: {text:?}"
            );
        }
    }

    /// Empty text decodes to an empty byte string. That is not "illegal input" but "a
    /// zero-length payload" — whether to accept it is for the upper layer to decide (this
    /// crate does not decide it on its behalf).
    #[test]
    fn empty_text_decodes_to_empty_bytes() {
        assert_eq!(decode("").expect("empty payload"), b"");
        assert_eq!(encode(&[]), "");
    }
}
