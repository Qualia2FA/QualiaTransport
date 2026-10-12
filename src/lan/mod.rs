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

use crate::error::{Error, Result};
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
