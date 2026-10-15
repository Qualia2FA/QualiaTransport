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

//! **Transport channels** for Qualia2FA.
//!
//! This crate does one thing: it hands a byte string out and takes a byte string back. The
//! protocol itself — whose payload arrives first, how conflicts are reported, how replays
//! are blocked — lives in `qualia2fa-core`, and this crate knows nothing about it. The
//! interface between the two is the core library's `Transport` trait, and the **dependency
//! direction is "this crate ← core library"**: any project that needs to "put bytes into a
//! QR code" or "find a peer on the LAN" can use this crate as is, without accepting
//! Qualia2FA's vault format or account model.
//!
//! # What is here
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`qr`] | QR capacity model, encoding, rendering and (optional) image decoding |
//! | [`envelope`] | Binary payload ↔ text a QR code can carry |
//! | [`frame`] | Animated QR: a payload that does not fit is split into several codes, which the scanning side reassembles |
//! | [`image`] | The pixel form passed between rendering and scanning |
//! | [`lan`] | LAN: multicast lobby (discovery), connection info and (optional) QUIC data plane |
//!
//! # Payloads are carried as text
//!
//! QR byte mode can carry arbitrary bytes, but then **only this crate could read the code
//! back**: platform cameras (Android ML Kit, iOS AVFoundation) return strings, a clipboard
//! holds text, and a human copying a code reads text. Payloads therefore go into a text
//! envelope and are encoded in the QR **alphanumeric mode** — about 10% of the capacity, in
//! exchange for every scanner returning the same string. See the module documentation of
//! [`envelope`].
//!
//! The frame index and the frame count are part of that envelope from the start
//! (`Q2FA1:2/3:`), so carrying a payload in several codes needs no additional wire format.
//! Splitting and reassembly live in [`frame`], and the layer that turns a split payload into
//! images lives in [`qr::QrProfile::encode_payload_frames`].
//!
//! # QR code and LAN
//!
//! The two channels do **not** replace each other:
//!
//! - The QR code has very little bandwidth, is one-shot and requires both ends to be
//!   present, but it needs no network infrastructure and no permissions (Android 17's
//!   `ACCESS_LOCAL_NETWORK` and the iOS multicast entitlement do not apply to it).
//! - The LAN has ample bandwidth and can be reused, but it requires both ends in the same
//!   broadcast domain, and multicast is disabled on many corporate WiFi networks.
//!
//! The combination is: **which route carries discovery is decided on the spot, the payload
//! itself takes whichever route has enough bandwidth**. The core library's `SharePlan` makes
//! that decision; this crate provides both routes.
//!
//! The two halves meet where the LAN route needs the QR channel: when multicast is
//! unavailable, a connection record travels out of band in a QR code. That conversion lives in
//! [`lan`] — [`lan::LanAddress::to_qr_symbols`] renders a record into codes through the same
//! capacity and framing path as any other payload, [`lan::LanAddressScanner`] collects them
//! again — so a caller does not assemble it from [`qr`] and [`frame`] on its own.
//!
//! # Not implemented
//!
//! The per-platform LAN permission flows (Android 17's `ACCESS_LOCAL_NETWORK`, iOS
//! `NSLocalNetworkUsageDescription` and the multicast entitlement) belong to the platform
//! integration layer and are out of scope here. The LAN path's "no internet" property
//! currently goes as far as "no relay is built, no DNS/pkarr registration, HTTPS probing
//! disabled"; **packet-capture verification has not been done**, so nothing beyond that may
//! be claimed publicly (see the `iroh-lan` section of the `README`).
//!
//! # Purity
//!
//! [`qr`], [`envelope`], [`frame`], [`image`] and [`lan::wire`] are pure logic: no file
//! system, no network, no clock, no environment variables; every input is a parameter. Hence
//! `#![forbid(unsafe_code)]` holds, and no input may cause a panic — the only permitted way
//! to fail is returning an [`Error`].
//!
//! The same contract covers panics inside **dependencies**, at the cost of one convergence
//! point: every call into the image decoder (`rqrr`) from `qr::scan` is wrapped in
//! `catch_unwind`, which turns an upstream assertion failure into
//! [`Error::QrDecoderPanicked`]. That is **containment, not a fix** (the fix belongs
//! upstream), and it relies on unwinding: on a platform side built with `panic = "abort"`,
//! this layer stops working.
//!
//! [`lan::lobby`] is the **only** module that touches I/O (a UDP socket and one background
//! thread), and the decisions inside it are kept to a minimum: all the reasoning lives in
//! [`lan::wire`], so properties such as "three devices converge on one view" can be verified
//! in a single process, without a network.
//!
//! # Supported toolchains
//!
//! The default build supports **Rust 1.89** (the manifest's `rust-version`). Enabling the
//! default-off `iroh-lan` feature raises that floor to **1.91**, the `rust-version` iroh 1.3.0
//! declares; Cargo has one `rust-version` per package and no per-feature equivalent, so that
//! field states the default build's floor and the feature's floor is documented in the
//! manifest and in the `lan::transport` module (which exists only with that feature).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

pub mod envelope;
pub mod error;
pub mod frame;
pub mod image;
pub mod lan;
pub mod qr;

/// Base32 per RFC 4648 §6.
///
/// Deliberately not a dependency from crates.io: the codec layer of this crate thus stays
/// **zero-dependency**, and this implementation matches the semantics of the core library's
/// `base32` (case-insensitive, padding tolerated, non-canonical trailing bits rejected), so
/// that one RFC does not grow two behaviours across two repositories.
mod base32;

pub use error::{Error, Result};
