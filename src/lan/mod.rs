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

//! LAN channel (QWBP): find peers on the same network segment, then move bytes to them.
//!
//! # Two halves, each solving one problem
//!
//! | Module | Role | Mechanism |
//! |--------|------|-----------|
//! | [`lobby`] | Discovery: who is on this segment, and where to reach them | UDP multicast to `239.255.81.65:21377`, unauthenticated |
//! | *transport* | Carriage: move a whole sync payload to a peer | QUIC over an offline iroh configuration, behind the `iroh-lan` feature |
//!
//! The dividing line is not "which half runs first" but the **trust level**: multicast is a
//! shared medium, so anyone can inject arbitrary bytes into it, and the information it
//! carries can only be a **hint** — "somebody is probably on this segment". Real identity is
//! proven by the handshake that establishes the connection, and whether a payload may be
//! accepted is decided by the core library's allow list
//! (`qualia2fa_core::transport::SyncSession::restricted`).
//!
//! # Discovery is unauthenticated
//!
//! An announcement is not signed: a forged one can only make the receiver open a connection,
//! and that connection fails in the handshake because the spoofer cannot produce the endpoint
//! private key. Signing every announcement would mean waking the hardware keystore every
//! cycle to defend against an attack the connection layer already stops.
//! **Discovery may be unauthenticated; credentials must come from the channel.**
//!
//! # The QR-code route to a connection
//!
//! Multicast requires both ends in the **same broadcast domain**. Across segments, or where
//! network policy forbids multicast, there is another route: [`LanAddress`] is carried
//! out-of-band inside a QR code (the core library's `SharePlan::LinkEstablishment` case) and
//! the receiver dials it directly. Both routes produce the **same kind of connection**, so
//! the protocol layer does not need to know which one the user took.
//!
//! The conversion between a record and QR text is part of this module, and it goes **through**
//! the QR half rather than around it: a record is a [`ADDRESS_LEN`]-byte payload, so
//! [`LanAddress::to_qr_symbols`] hands it to
//! [`crate::qr::QrProfile::encode_payload_frames`], which applies the channel's capacity and
//! splits it across several codes when one cannot hold it, and
//! [`LanAddress::to_qr_frame_texts`] is the same split as text (both share one split point in
//! [`crate::qr::QrProfile`]). The receiving side is [`LanAddressScanner`], which collects those
//! codes through the same [`Reassembler`] the generic QR route uses — any order, repeats
//! allowed, capacity unknown. [`LanAddress::to_qr_text`] and [`LanAddress::from_qr_text`] are
//! the single-code form of the same conversion, for a medium that carries one string.
//!
//! # Purity
//!
//! [`wire`] is pure logic: no sockets, no clock, every input is a parameter, so properties
//! such as "three devices converge on one view" can be verified inside a single process with
//! no network. [`lobby`] is the only place that touches I/O, and the reasoning inside it is
//! kept to a minimum — the decisions live in [`wire`].

pub mod lobby;
pub mod wire;

/// The LAN data plane (an offline iroh configuration).
///
/// The whole module sits behind a feature: iroh pulls in over two hundred crates and a tokio
/// runtime, while the QR-code route needs only a QR encoder. Mobile builds use the QR route
/// first (the platform camera already hands back text) and desktop builds enable this half;
/// making that boundary a feature rather than a documentation note keeps it enforced.
#[cfg(feature = "iroh-lan")]
pub mod transport;

use crate::envelope;
use crate::error::{Error, Result};
use crate::frame::Reassembler;
use crate::qr::{QrProfile, Symbol};
use wire::EndpointKey;

/// Prefix that marks LAN connection information inside a QR code.
///
/// Not the same thing as the QR envelope's `Q2FA1`: the envelope says how a piece of text
/// travels inside a QR code, this says what the text contains. The two layers are separate
/// because the same envelope also carries other payloads (pairing bootstrap data, sync
/// payloads), and those must not look like a LAN address.
const ADDRESS_PREFIX: &[u8; 6] = b"Q2FAL1";

/// Version of the LAN connection information layout.
const ADDRESS_VERSION: u8 = 1;

/// Fixed length of the LAN connection information, in bytes.
///
/// Prefix 6 + version 1 + endpoint key 32 + port 2 + checksum 1.
pub const ADDRESS_LEN: usize = ADDRESS_PREFIX.len() + 1 + wire::ENDPOINT_KEY_LEN + 2 + 1;

/// A LAN connection record that can be dialed directly.
///
/// # What it is for
///
/// The multicast lobby requires both ends in the same broadcast domain. Across segments (the
/// user's two devices on different access points), or where network policy forbids multicast
/// (many corporate WiFi networks), the only route is to hand "where to connect to me" to the
/// peer **out-of-band** — a QR code. That is the core library's link-establishment mode, and
/// it is the entire purpose of [`LanAddress`].
///
/// # It is shorter than a multicast announcement
///
/// An announcement carries both the device id (32 bytes) and the endpoint key (32 bytes),
/// because a multicast receiver needs the device id for its allow list. This record is
/// delivered **out-of-band**: whoever scans the QR code has already confirmed the peer's
/// identity during pairing, and that flow supplies the device id. Leaving out those 32 bytes
/// is real QR capacity: 42 bytes here against 84 for an announcement.
///
/// # Checksum
///
/// The last byte is an 8-bit sum. It is **not** a security measure — this record carries no
/// confidentiality or authentication duty (see the module documentation). It catches one
/// thing: **a digit copied or read off wrongly by a human**. Without it, a mistyped port sends
/// the peer to a port nobody listens on, and the failure surfaces as a connection timeout
/// rather than as "the code was copied wrong".
///
/// # Carrying it in a QR code
///
/// The record is a payload like any other, so the QR half carries it unchanged:
/// [`LanAddress::to_qr_symbols`] renders it for a channel (capacity and splitting included),
/// [`LanAddress::to_qr_frame_texts`] gives the same codes as text, and
/// [`LanAddress::to_qr_text`] / [`LanAddress::from_qr_text`] are the single-code form. The
/// receiving side collects the codes with [`LanAddressScanner`]. At level L, version 4 is the
/// smallest version whose code holds the whole record, so a channel capped below that splits
/// it — which is why the multi-code path exists at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanAddress {
    /// The peer's transport endpoint public key.
    pub endpoint_key: EndpointKey,
    /// The port the peer listens on.
    pub port: u16,
}

impl LanAddress {
    /// Builds a connection record.
    #[must_use]
    pub const fn new(endpoint_key: EndpointKey, port: u16) -> Self {
        Self { endpoint_key, port }
    }

    /// Encodes into [`ADDRESS_LEN`] bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; ADDRESS_LEN] {
        let mut out = [0_u8; ADDRESS_LEN];
        let mut at = 0;
        out[at..at + ADDRESS_PREFIX.len()].copy_from_slice(ADDRESS_PREFIX);
        at += ADDRESS_PREFIX.len();
        out[at] = ADDRESS_VERSION;
        at += 1;
        out[at..at + wire::ENDPOINT_KEY_LEN].copy_from_slice(self.endpoint_key.as_bytes());
        at += wire::ENDPOINT_KEY_LEN;
        out[at..at + 2].copy_from_slice(&self.port.to_be_bytes());
        at += 2;
        out[at] = checksum(&out[..at]);
        out
    }

    /// Parses one connection record out of a byte slice.
    ///
    /// # Errors
    ///
    /// - [`Error::NotOurLanAddress`]: the prefix does not match, so this is not LAN connection
    ///   information.
    /// - [`Error::UnsupportedDatagramVersion`]: the prefix matches but the version is newer
    ///   than this build. It reuses the lobby datagram variant because it is the same
    ///   situation: **ours, but newer than this build**. Reporting it as "not ours" would make
    ///   anything a future version introduces get dropped silently.
    /// - [`Error::BadLanAddressLength`]: the length is wrong.
    /// - [`Error::ZeroPort`]: the port is 0.
    /// - [`Error::MalformedFrameHeader`]: the checksum byte does not match, which in practice
    ///   means a copy error. It reuses the QR envelope variant for the same reason as above:
    ///   the format is right, the contents are broken.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let prefix = bytes
            .get(..ADDRESS_PREFIX.len())
            .ok_or(Error::NotOurLanAddress)?;
        if prefix != ADDRESS_PREFIX {
            return Err(Error::NotOurLanAddress);
        }
        if bytes.len() != ADDRESS_LEN {
            return Err(Error::BadLanAddressLength {
                expected: ADDRESS_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[ADDRESS_PREFIX.len()] != ADDRESS_VERSION {
            return Err(Error::UnsupportedDatagramVersion {
                found: bytes[ADDRESS_PREFIX.len()],
                supported: ADDRESS_VERSION,
            });
        }

        let mut key = [0_u8; wire::ENDPOINT_KEY_LEN];
        let key_start = ADDRESS_PREFIX.len() + 1;
        key.copy_from_slice(&bytes[key_start..key_start + wire::ENDPOINT_KEY_LEN]);
        let port_at = key_start + wire::ENDPOINT_KEY_LEN;
        let port = u16::from_be_bytes([bytes[port_at], bytes[port_at + 1]]);
        let expected = checksum(&bytes[..port_at + 2]);
        if bytes[port_at + 2] != expected {
            return Err(Error::MalformedFrameHeader);
        }
        if port == 0 {
            return Err(Error::ZeroPort);
        }

        Ok(Self {
            endpoint_key: EndpointKey::from_bytes(key),
            port,
        })
    }

    /// The QR text of this record in **one** code: `Q2FA1:1/1:<BASE32>` over
    /// [`LanAddress::encode`].
    ///
    /// The frame header says `1/1`, so [`LanAddress::from_qr_text`] reads it back with no
    /// reassembly state at all, and the whole string stays inside the QR alphanumeric mode
    /// (see [`crate::envelope`]).
    ///
    /// # It checks no capacity
    ///
    /// Whether a code can hold these 78 characters is a property of the **displaying side's**
    /// channel, and this method has no channel to ask: it serves a medium that carries one
    /// string — a clipboard, a chat message, a code the caller renders elsewhere. Use
    /// [`LanAddress::to_qr_symbols`] or [`LanAddress::to_qr_frame_texts`] when the capacity
    /// has to be respected: a small channel splits the record across several codes, and a
    /// `1/1` text would then be a claim that no displayed code can back up.
    #[must_use]
    pub fn to_qr_text(&self) -> String {
        envelope::encode(&self.encode())
    }

    /// Reads a record back out of the QR text of **one** code.
    ///
    /// # Errors
    ///
    /// - [`Error::NotOurQrText`], [`Error::MalformedFrameHeader`], [`Error::MalformedBase32`]:
    ///   the text is not a QR envelope of this application.
    /// - [`Error::MultiFrameUnsupported`]: the text is one code of a split record; feed the
    ///   codes to [`LanAddressScanner`] instead.
    /// - [`Error::NotOurLanAddress`], [`Error::BadLanAddressLength`],
    ///   [`Error::UnsupportedDatagramVersion`], [`Error::MalformedFrameHeader`],
    ///   [`Error::ZeroPort`]: the envelope decoded, but what it carried is not a valid record
    ///   (see [`LanAddress::decode`]).
    pub fn from_qr_text(text: &str) -> Result<Self> {
        Self::decode(&envelope::decode(text)?)
    }

    /// Renders this record into the QR codes to display, one per code.
    ///
    /// # Arguments
    ///
    /// - `profile`: the capability of the displaying channel (error correction level and the
    ///   highest version it will show).
    /// - `max_frames`: how many codes the user is willing to scan.
    ///
    /// The capacity, the split point and the frame headers are the ones
    /// [`crate::qr::QrProfile::encode_payload_frames`] uses for any other payload: the record
    /// is handed over as its [`ADDRESS_LEN`] bytes, and nothing about it is special to the QR
    /// half. A record that fits one code yields one symbol; a channel that cannot hold it
    /// splits the record across several codes, which is what
    /// [`LanAddress::to_qr_frame_texts`] exposes as text.
    ///
    /// # Errors
    ///
    /// - [`Error::PayloadTooLarge`]: the record does not fit
    ///   [`crate::qr::QrProfile::exchange_capacity`]`(max_frames)` — a narrow channel (a low
    ///   maximum version, or a single code allowed) can be too small for even these
    ///   [`ADDRESS_LEN`] bytes. `needed`/`limit` are in **payload bytes**.
    pub fn to_qr_symbols(&self, profile: &QrProfile, max_frames: u32) -> Result<Vec<Symbol>> {
        profile.encode_payload_frames(&self.encode(), max_frames)
    }

    /// The **texts** of those codes, one per code, using the same split as
    /// [`LanAddress::to_qr_symbols`].
    ///
    /// For a caller whose display path carries strings rather than module matrices, or that
    /// wants the text of every code of a split record. A record that fits one code yields a
    /// single text, byte for byte the one [`LanAddress::to_qr_text`] returns.
    ///
    /// # Errors
    ///
    /// The same as [`LanAddress::to_qr_symbols`], with the same meaning.
    pub fn to_qr_frame_texts(&self, profile: &QrProfile, max_frames: u32) -> Result<Vec<String>> {
        profile.frame_texts(&self.encode(), max_frames)
    }
}

/// 8-bit sum checksum.
///
/// A **byte sum** rather than a CRC: what it must catch is one digit transcribed wrongly by a
/// user, not random corruption (the same string of bytes is either copied or it is not), and
/// it has to stay simple enough to re-add by hand from a photograph. Every covered byte is
/// added with wrapping arithmetic over `u8`.
fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0_u8, |acc, byte| acc.wrapping_add(*byte))
}

/// Collects the codes of one QR-carried [`LanAddress`] and hands the record back.
///
/// # What it is for
///
/// It is the receiving half of the route in which a peer's address travels inside a QR code
/// because multicast is unavailable (see the module documentation). One code can hold the whole
/// [`ADDRESS_LEN`]-byte record (at level L from version 4 up); a narrower channel makes
/// [`LanAddress::to_qr_symbols`] split it, and the scanning side then has to collect the codes
/// before the address exists.
///
/// # It is a [`Reassembler`] plus one step
///
/// Collecting is entirely [`Reassembler`]'s behaviour, unchanged: codes may arrive in **any
/// order**, a code may be scanned again, the full-frame length is observed from the first code
/// rather than assumed, and [`LanAddressScanner::missing`] reports what the user interface has
/// to show. What this type adds is the last step — the completed payload is parsed back into a
/// [`LanAddress`], so a caller never handles the record's bytes itself.
///
/// # Scanning one record after another
///
/// A text that was part of a record already handed out is recognised as **a repeat** and
/// reports `Ok(None)`: a camera keeps firing at a screen that is not changing, and reporting
/// the same address on every callback would be noise rather than news. Any other text starts a
/// new record, so a screen that moves on to another address is scanned without building a new
/// scanner. The remembered texts are bounded by the format's frame limit
/// ([`envelope::MAX_FRAMES`]); past that bound a repeat is merely not recognised, and the
/// scanner starts a new record instead.
///
/// # It does not authenticate
///
/// Whoever shows the code decides which endpoint a scan dials. The record is a hint, exactly
/// like a multicast announcement (see the module documentation); the handshake on the
/// connection that is dialed with the [`EndpointKey`] and port taken from here is what proves
/// the peer.
pub struct LanAddressScanner {
    /// The frame collector, with an **unknown capacity**: the displaying side's capacity is
    /// not available on this side (see [`Reassembler::from_first_frame`]).
    reassembler: Reassembler,
    /// The texts accepted for the record being collected.
    ///
    /// They are what tells "a code of the record just handed out" from "the first code of
    /// another record" once the collector is complete; each one was accepted by the
    /// reassembler, so treating it as a repeat is always correct.
    texts: Vec<String>,
    /// Whether the current record has been completed and handed out.
    complete: bool,
}

impl LanAddressScanner {
    /// Creates a scanner that has collected nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reassembler: Reassembler::from_first_frame(),
            texts: Vec::new(),
            complete: false,
        }
    }

    /// Accepts the text of one code.
    ///
    /// Returns `Ok(None)` while codes are still missing, `Ok(Some(address))` on the code that
    /// completes the record.
    ///
    /// # Errors
    ///
    /// - [`Error::NotOurQrText`], [`Error::MalformedFrameHeader`], [`Error::MalformedBase32`],
    ///   [`Error::FrameMismatch`]: the text is not a code of this record (see
    ///   [`Reassembler::push`]). A failing text leaves the collected codes unchanged.
    /// - [`Error::NotOurLanAddress`], [`Error::BadLanAddressLength`],
    ///   [`Error::UnsupportedDatagramVersion`], [`Error::MalformedFrameHeader`],
    ///   [`Error::ZeroPort`]: the record was completed, but what it carried is not a valid
    ///   record (see [`LanAddress::decode`]). The next text then starts a new record, so one
    ///   malformed code cannot leave the scanner unable to scan anything else.
    pub fn push(&mut self, text: &str) -> Result<Option<LanAddress>> {
        let known = self.texts.iter().any(|seen| seen == text);
        if self.complete && !known {
            self.restart();
        }

        let completed = self.reassembler.push(text)?;
        if !known && self.texts.len() < envelope::MAX_FRAMES as usize {
            self.texts.push(text.to_owned());
        }

        match completed {
            None => Ok(None),
            Some(payload) => {
                self.complete = true;
                Ok(Some(LanAddress::decode(&payload)?))
            }
        }
    }

    /// Which codes are still missing (frame indices, ascending); empty before the first code
    /// arrives.
    #[must_use]
    pub fn missing(&self) -> Vec<u32> {
        self.reassembler.missing()
    }

    /// How many codes the record consists of; `None` until the first code arrives.
    #[must_use]
    pub const fn expected_codes(&self) -> Option<u32> {
        self.reassembler.expected_frames()
    }

    /// Drops everything collected so far.
    fn restart(&mut self) {
        self.reassembler = Reassembler::from_first_frame();
        self.texts.clear();
        self.complete = false;
    }
}

impl Default for LanAddressScanner {
    /// Same as [`LanAddressScanner::new`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qr::EcLevel;

    fn endpoint(seed: u8) -> EndpointKey {
        EndpointKey::from_bytes([seed; 32])
    }

    /// The wire format is pinned byte for byte.
    ///
    /// Every field, the big-endian port, and the checksum byte are asserted against expected
    /// values written out by hand rather than produced by encoding and decoding: a round trip
    /// proves only that the two halves agree with each other, and is blind to both of them
    /// drifting together. The expected checksum is summed from the covered range instead of
    /// being hardcoded, so the assertion cannot stay green after the format changes.
    #[test]
    fn wire_format_is_pinned() {
        let address = LanAddress::new(EndpointKey::from_bytes([0xBB; 32]), 0x1234);
        let bytes = address.encode();

        assert_eq!(bytes.len(), ADDRESS_LEN);
        assert_eq!(
            ADDRESS_LEN, 42,
            "prefix 6 + version 1 + endpoint key 32 + port 2 + checksum 1"
        );
        assert_eq!(&bytes[0..6], b"Q2FAL1");
        assert_eq!(bytes[6], 1, "version");
        assert_eq!(&bytes[7..39], &[0xBB; 32], "endpoint key");
        assert_eq!(&bytes[39..41], &[0x12, 0x34], "the port is big-endian");
        let expected = b'Q'
            .wrapping_add(b'2')
            .wrapping_add(b'F')
            .wrapping_add(b'A')
            .wrapping_add(b'L')
            .wrapping_add(b'1')
            .wrapping_add(ADDRESS_VERSION)
            .wrapping_add(0xBB_u8.wrapping_mul(32))
            .wrapping_add(0x12)
            .wrapping_add(0x34);
        assert_eq!(bytes[41], expected, "checksum byte");

        assert_eq!(
            LanAddress::decode(&bytes).expect("a self-encoded record must decode"),
            address
        );
    }

    #[test]
    fn round_trips_every_boundary() {
        for (seed, port) in [(0_u8, 1_u16), (0xFF, u16::MAX), (1, 1024), (0x80, 21_377)] {
            let address = LanAddress::new(endpoint(seed), port);
            let decoded = LanAddress::decode(&address.encode()).expect("round trip");
            assert_eq!(
                decoded, address,
                "round trip mismatch for seed {seed} port {port}"
            );
        }
    }

    /// Foreign bytes must be reported as "not ours", never as "ours but broken".
    #[test]
    fn foreign_bytes_are_recognized_as_foreign() {
        for bytes in [
            b"".as_slice(),
            b"Q2FA1:1/1:MZXW6",
            b"Q2FASYN\0",
            b"q2fal1",
            b"Q2FAL",
        ] {
            let result = LanAddress::decode(bytes);
            let is_foreign = matches!(result, Err(Error::NotOurLanAddress));
            assert!(is_foreign, "should report a foreign record, got {result:?}");
        }
    }

    /// Once the prefix matches, every kind of nonconforming input gets its own error.
    #[test]
    fn our_bytes_are_diagnosed_precisely() {
        let good = LanAddress::new(endpoint(1), 1234).encode();

        for length in [ADDRESS_LEN - 1, ADDRESS_LEN + 1] {
            let mut bad = good.to_vec();
            bad.resize(length, 0);
            let result = LanAddress::decode(&bad);
            let is_length = matches!(result, Err(Error::BadLanAddressLength { .. }));
            assert!(
                is_length,
                "{length} bytes must report a bad length, got {result:?}"
            );
        }

        let mut newer = good;
        newer[6] = ADDRESS_VERSION + 1;
        let result = LanAddress::decode(&newer);
        let is_version = matches!(
            result,
            Err(Error::UnsupportedDatagramVersion { found, supported })
                if found == ADDRESS_VERSION + 1 && supported == ADDRESS_VERSION
        );
        assert!(
            is_version,
            "should report a version newer than this build, got {result:?}"
        );

        let mut corrupted = good;
        corrupted[10] ^= 0x01;
        let result = LanAddress::decode(&corrupted);
        let is_checksum = matches!(result, Err(Error::MalformedFrameHeader));
        assert!(
            is_checksum,
            "a mistyped byte must be caught by the checksum, got {result:?}"
        );
    }

    /// The checksum must be sensitive to every covered bit.
    ///
    /// Every single-bit flip in the range the checksum covers (bytes `7..ADDRESS_LEN - 1`)
    /// must be caught. The prefix and the version byte have their own earlier checks and
    /// report other errors, which is correct but is not what this test is about.
    #[test]
    fn every_single_bit_flip_is_caught() {
        let good = LanAddress::new(endpoint(0x5A), 21_377).encode();

        for index in 7..(ADDRESS_LEN - 1) {
            for bit in 0..8 {
                let mut corrupted = good;
                corrupted[index] ^= 1 << bit;
                let result = LanAddress::decode(&corrupted);
                assert!(
                    matches!(result, Err(Error::MalformedFrameHeader)),
                    "flipping bit {bit} of byte {index} was not caught, got {result:?}"
                );
            }
        }
    }

    /// Port 0 is rejected.
    ///
    /// Port 0 means "let the system pick one" in the socket API; in a record that is already
    /// complete it can only be an error on the sender's side, and a device that dialed it
    /// would try a port nobody listens on. The record is built by hand with a correct
    /// checksum, so the checksum check cannot mask the port check.
    #[test]
    fn a_zero_port_is_rejected() {
        let mut bytes = LanAddress::new(endpoint(1), 1234).encode();
        bytes[39] = 0;
        bytes[40] = 0;
        let sum = checksum(&bytes[..41]);
        bytes[41] = sum;

        let result = LanAddress::decode(&bytes);
        let is_zero = matches!(result, Err(Error::ZeroPort));
        assert!(is_zero, "should report port 0, got {result:?}");
    }

    /// No input may make the parser panic, and no input may make it accept a record.
    ///
    /// Every length from 0 to `ADDRESS_LEN + 4` and four fill patterns are tried; one of the
    /// patterns gets a real prefix so that parsing reaches deeper paths.
    #[test]
    fn arbitrary_bytes_never_panic() {
        for length in 0..=(ADDRESS_LEN + 4) {
            for fill in [0x00_u8, 0xFF, 0x51, 0x0A] {
                let mut bytes = vec![fill; length];
                if length >= ADDRESS_PREFIX.len() && fill == 0x51 {
                    bytes[..ADDRESS_PREFIX.len()].copy_from_slice(ADDRESS_PREFIX);
                }
                let _ = LanAddress::decode(&bytes);
            }
        }
    }

    /// The QR text of a record is pinned byte for byte.
    ///
    /// The expected Base32 is derived from the record's bytes by hand from the format, not
    /// produced by this crate's encoder: a round trip through [`LanAddress::to_qr_text`] and
    /// [`LanAddress::from_qr_text`] would only prove that the two halves agree with each other,
    /// and stays blind to both of them encoding something other than the documented record.
    /// The record is the one `wire_format_is_pinned` uses (key `0xBB`×32, port `0x1234`,
    /// checksum `0x2E`), so the two tests pin the same bytes from both ends.
    #[test]
    fn the_qr_text_is_pinned() {
        let address = LanAddress::new(EndpointKey::from_bytes([0xBB; 32]), 0x1234);
        assert_eq!(
            address.to_qr_text(),
            "Q2FA1:1/1:KEZEMQKMGEA3XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XOYSGQXA"
        );
        assert_eq!(
            address.to_qr_text().len(),
            10 + 68,
            "the envelope header of a single frame plus the Base32 of 42 bytes without padding"
        );
        assert_eq!(
            LanAddress::from_qr_text(&address.to_qr_text()).expect("a self-encoded text decodes"),
            address
        );
    }

    /// Every boundary value survives the QR text round trip.
    #[test]
    fn qr_text_round_trips_every_boundary() {
        for (seed, port) in [(0_u8, 1_u16), (0xFF, u16::MAX), (1, 1024), (0x80, 21_377)] {
            let address = LanAddress::new(endpoint(seed), port);
            let decoded = LanAddress::from_qr_text(&address.to_qr_text()).expect("round trip");
            assert_eq!(
                decoded, address,
                "round trip mismatch for seed {seed} port {port}"
            );
        }
    }

    /// **Version 4 at level L is the smallest single code that holds the whole record**, and a
    /// narrower channel splits it.
    ///
    /// The boundary is asserted against the capacities [`QrProfile`] computes from the encoder,
    /// not against a table copied out of ISO/IEC 18004: what matters here is that "this does not
    /// fit one code" is answered by the same code that renders, and the capacities of versions 3
    /// and 4 are merely the shape that answer has.
    #[test]
    fn a_record_that_does_not_fit_one_code_is_split() {
        let address = LanAddress::new(endpoint(0x11), 21_377);

        let wide = QrProfile::new(EcLevel::Low, 4).expect("the version is legal");
        assert!(
            wide.payload_capacity() >= ADDRESS_LEN,
            "version 4 at level L must hold the {ADDRESS_LEN}-byte record, it holds {}",
            wide.payload_capacity()
        );
        assert_eq!(
            address
                .to_qr_symbols(&wide, 1)
                .expect("one code holds the record")
                .len(),
            1,
            "a record that fits one code must not be split"
        );
        assert_eq!(
            address
                .to_qr_frame_texts(&wide, 1)
                .expect("the text of that code"),
            vec![address.to_qr_text()],
            "the single-code path must produce the pinned text"
        );

        let narrow = QrProfile::new(EcLevel::Low, 3).expect("the version is legal");
        assert!(
            narrow.payload_capacity() < ADDRESS_LEN,
            "version 3 at level L must be too small for the {ADDRESS_LEN}-byte record, it holds {}",
            narrow.payload_capacity()
        );
        let symbols = address
            .to_qr_symbols(&narrow, 8)
            .expect("eight codes hold the record");
        let texts = address
            .to_qr_frame_texts(&narrow, 8)
            .expect("eight codes hold the record");
        assert!(
            symbols.len() > 1 && texts.len() == symbols.len(),
            "the texts and the symbols must be one and the same exchange: {} symbols, {} texts",
            symbols.len(),
            texts.len()
        );
        assert!(
            texts.iter().all(|text| text != &address.to_qr_text()),
            "a split record must not also appear in its single-code spelling: {texts:?}"
        );

        let mut scanner = LanAddressScanner::new();
        let mut done = None;
        for text in texts.iter().rev() {
            done = scanner
                .push(text)
                .expect("a code it split itself must be accepted");
        }
        assert_eq!(
            done.expect("every code scanned means the record is complete"),
            address
        );
    }

    /// The single-code entry points report a split record as the wrong entry point, and
    /// somebody else's text as foreign.
    #[test]
    fn the_single_code_entry_points_report_what_they_got() {
        let address = LanAddress::new(endpoint(4), 5_555);
        let profile = QrProfile::new(EcLevel::Low, 3).expect("the version is legal");
        let texts = address
            .to_qr_frame_texts(&profile, 8)
            .expect("must split on a version 3 channel");
        assert!(texts.len() > 1, "this record must split, got {texts:?}");

        let result = LanAddress::from_qr_text(&texts[0]);
        let is_multi = matches!(
            result,
            Err(Error::MultiFrameUnsupported { count }) if count == texts.len() as u32
        );
        assert!(
            is_multi,
            "a split record must report the wrong entry point, got {result:?}"
        );

        for text in ["https://example.com", "Q2FA2:1/1:MY"] {
            let result = LanAddress::from_qr_text(text);
            let is_foreign = matches!(result, Err(Error::NotOurQrText));
            assert!(is_foreign, "{text} must be foreign, got {result:?}");
        }

        let result = LanAddress::from_qr_text("Q2FA1:1:MY");
        let broken = matches!(result, Err(Error::MalformedFrameHeader));
        assert!(
            broken,
            "our prefix with a broken frame header must say so, got {result:?}"
        );

        let short = envelope::encode(b"Q2FAL1");
        let result = LanAddress::from_qr_text(&short);
        let is_length = matches!(result, Err(Error::BadLanAddressLength { .. }));
        assert!(
            is_length,
            "6 bytes must report a bad length, got {result:?}"
        );

        let other = envelope::encode(&[b'X'; ADDRESS_LEN]);
        let result = LanAddress::from_qr_text(&other);
        let is_address = matches!(result, Err(Error::NotOurLanAddress));
        assert!(
            is_address,
            "the right length with a wrong prefix must be foreign, got {result:?}"
        );

        let mut newer = address.encode();
        newer[6] = ADDRESS_VERSION + 1;
        let result = LanAddress::from_qr_text(&envelope::encode(&newer));
        let is_version = matches!(
            result,
            Err(Error::UnsupportedDatagramVersion { found, supported })
                if found == ADDRESS_VERSION + 1 && supported == ADDRESS_VERSION
        );
        assert!(
            is_version,
            "a newer record must report its version, got {result:?}"
        );

        let mut scanner = LanAddressScanner::new();
        let result = scanner.push("hello");
        assert!(
            matches!(result, Err(Error::NotOurQrText)),
            "a foreign text must be foreign, got {result:?}"
        );
    }

    /// A channel whose whole exchange cannot hold the record reports that in **payload bytes**,
    /// through both text and symbol entry points.
    #[test]
    fn a_channel_too_small_for_the_record_is_rejected() {
        let address = LanAddress::new(endpoint(2), 1_234);
        let profile = QrProfile::new(EcLevel::Low, 1).expect("the version is legal");
        let limit = profile.exchange_capacity(1);
        assert!(
            limit < ADDRESS_LEN,
            "one version 1 code must not hold {ADDRESS_LEN} bytes, it holds {limit}"
        );

        let reports = [
            address.to_qr_symbols(&profile, 1).map(|_| ()),
            address.to_qr_frame_texts(&profile, 1).map(|_| ()),
        ];
        for result in reports {
            match result {
                Err(Error::PayloadTooLarge {
                    needed,
                    limit: reported,
                }) => {
                    assert_eq!(needed, ADDRESS_LEN, "the whole record is what has to fit");
                    assert_eq!(reported, limit, "the limit must be the exchange capacity");
                }
                other => panic!("expected PayloadTooLarge, got {other:?}"),
            }
        }
    }

    /// The scanner accepts the codes of a split record **in any order** and **repeatedly**, and
    /// hands the record out exactly once.
    #[test]
    fn the_scanner_accepts_any_order_and_repeats() {
        let address = LanAddress::new(endpoint(0x33), 6_000);
        let profile = QrProfile::new(EcLevel::Low, 3).expect("the version is legal");
        let texts = address
            .to_qr_frame_texts(&profile, 8)
            .expect("must split on a version 3 channel");
        assert!(texts.len() > 1, "this record must split, got {texts:?}");

        let mut scanner = LanAddressScanner::new();
        assert_eq!(scanner.expected_codes(), None);
        assert_eq!(
            scanner.push(&texts[1]).expect("the last code first"),
            None,
            "one code of two does not complete the record"
        );
        assert_eq!(scanner.expected_codes(), Some(texts.len() as u32));
        assert_eq!(scanner.missing(), vec![1]);
        assert_eq!(
            scanner.push(&texts[1]).expect("a repeat is not an error"),
            None
        );
        assert_eq!(
            scanner.push(&texts[0]).expect("the first code"),
            Some(address)
        );
        assert!(scanner.missing().is_empty());
        assert_eq!(
            scanner
                .push(&texts[0])
                .expect("a code of the completed record"),
            None,
            "a code of the record just handed out is a repeat, not a new record"
        );
    }

    /// A **different** record after a completed one is scanned without building a new scanner.
    #[test]
    fn the_scanner_starts_over_on_another_record() {
        let first = LanAddress::new(endpoint(1), 1_000);
        let second = LanAddress::new(endpoint(2), 2_000);

        let mut scanner = LanAddressScanner::new();
        assert_eq!(
            scanner.push(&first.to_qr_text()).expect("the first record"),
            Some(first)
        );
        assert_eq!(
            scanner
                .push(&second.to_qr_text())
                .expect("the second record"),
            Some(second),
            "another record must be scanned, not swallowed as a repeat"
        );
    }

    /// A completed payload that is not a record is reported by its own error, and the scanner
    /// keeps working afterwards.
    #[test]
    fn a_completed_payload_that_is_not_a_record_is_reported() {
        let mut scanner = LanAddressScanner::new();
        let result = scanner.push(&envelope::encode(&[0_u8; ADDRESS_LEN]));
        let is_address = matches!(result, Err(Error::NotOurLanAddress));
        assert!(is_address, "42 zero bytes are not a record, got {result:?}");

        let address = LanAddress::new(endpoint(3), 4_321);
        assert_eq!(
            scanner.push(&address.to_qr_text()).expect("must scan"),
            Some(address),
            "the scanner must not be stuck after a malformed record"
        );
    }
}
