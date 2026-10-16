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

//! Error types of this crate.
//!
//! # Error messages carry metadata only
//!
//! Sizes, version numbers, frame indices and error correction levels may appear in an error
//! message; **payload contents and the raw scanned text may not**. Errors end up in logs, and
//! logs get reported, screenshotted and pasted into issues — the payloads this crate handles
//! are mostly ciphertext, but during pairing a QR payload carries an ephemeral public key and
//! nonces, which have no business appearing in a log.

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors of this crate.
///
/// Marked `#[non_exhaustive]`: adding a variant is not a breaking change, and callers must
/// keep a catch-all arm — the only compensation for the compiler staying silent when a new
/// failure mode appears.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The payload does not fit this channel.
    ///
    /// `needed` and `limit` are **both counted in payload bytes** (not in envelope text
    /// characters), because the caller holds the payload as a number of bytes and this "how
    /// much is missing" number is meant to be shown to the user directly.
    #[error("payload does not fit: {needed} bytes needed, this channel carries {limit} bytes")]
    PayloadTooLarge {
        /// Number of bytes that actually have to fit.
        needed: usize,
        /// Maximum number of bytes this channel can carry.
        limit: usize,
    },

    /// The text does not fit a symbol within the requested version.
    ///
    /// This belongs to [`crate::qr::encode_text`], which encodes a caller's text as it
    /// stands rather than wrapping it in this crate's envelope: there is no payload and no
    /// channel capacity to compare against, so the two numbers are the text's own byte
    /// length and the version ceiling that was asked for.
    #[error("the text does not fit a version {max_version} symbol: {bytes} bytes")]
    TextTooLong {
        /// Byte length of the text that has to fit.
        bytes: usize,
        /// Highest version the caller was willing to use.
        max_version: u8,
    },

    /// The number of frames produced (or required) exceeds the format limit.
    ///
    /// The two numbers have **different units** from [`Error::PayloadTooLarge`]: that one is
    /// "N bytes needed, M bytes allowed", this one is "N frames needed, M frames allowed", and
    /// the caller passes either on to the user as it is.
    ///
    /// The frame limit is fixed by the **format** (the number of decimal digits of
    /// `Q2FA1:<index>/<count>`, see `envelope::MAX_FRAMES`), not by the encoder or the screen.
    #[error("this payload needs {needed} frames, and the limit is {limit} frames")]
    TooManyFrames {
        /// Number of frames needed (or about to be produced).
        needed: u32,
        /// Maximum number of frames the format allows.
        limit: u32,
    },

    /// The text is not a QR code of this application.
    ///
    /// Separate from "it is our code, but broken", because the two mean completely different
    /// things to the user: the former usually means the user scanned the wrong code
    /// (somebody else's QR code), the latter means rescan or switch channel.
    #[error("this is not a Qualia2FA QR code")]
    NotOurQrText,

    /// The frame header is invalid (wrong shape, leading zeros, index beyond the count).
    #[error("the frame header of the QR text is malformed")]
    MalformedFrameHeader,

    /// The code is a valid multi-frame code, and this entry point **accepts single frames
    /// only**.
    ///
    /// # Multi-frame itself is implemented; this variant means the wrong entry point
    ///
    /// It does not mean "not done yet", it means "you took the wrong door":
    /// [`crate::envelope::decode`] is the convenience entry point for "one text → one byte
    /// string", and only [`crate::frame::Reassembler`] accepts multiple frames. **Report it as
    /// it is** rather than pretending the input is corrupt — that is how the caller learns to
    /// switch to the reassembler instead of assuming the user took a blurry photo of the
    /// code.
    #[error("this code has {count} frames, and this entry point accepts single frames only")]
    MultiFrameUnsupported {
        /// Frame count the text claims.
        count: u32,
    },

    /// The Base32 payload is invalid (illegal character, illegal length, or non-canonical
    /// trailing bits).
    #[error("the Base32 payload in the QR text is malformed")]
    MalformedBase32,

    /// The error correction level is not `L`/`M`/`Q`/`H`.
    #[error("error correction level {letter:?} is not L/M/Q/H")]
    UnknownEcLevel {
        /// The character that was actually received.
        letter: char,
    },

    /// The QR version is not within 1–40.
    #[error("QR version {version} is not within 1-40")]
    VersionOutOfRange {
        /// The version number that was actually received.
        version: u8,
    },

    /// The rendering parameters are invalid.
    #[error("invalid render geometry: scale {scale}, quiet zone {quiet_zone} modules")]
    BadRenderGeometry {
        /// How many pixels each module is enlarged to.
        scale: u16,
        /// Width of the quiet zone left around the code, in modules.
        quiet_zone: u16,
    },

    /// The image dimensions do not match the pixel count, or the dimensions exceed the limit.
    #[error("invalid image geometry: {width}×{height}, {pixels} pixels")]
    BadImageGeometry {
        /// Claimed width, in pixels.
        width: u32,
        /// Claimed height, in pixels.
        height: u32,
        /// Number of pixels actually supplied.
        pixels: usize,
    },

    /// The image contains no readable QR code.
    ///
    /// Separate from `Error::QrDecode`: this one means "not even localization succeeded",
    /// rather than "one was found but could not be read". The former usually means the image
    /// contains no code at all (or it is too small or too blurry).
    #[error("no QR code was found in the image")]
    NoQrFound,

    /// The image decoder **panicked** on this image, and this crate caught it.
    ///
    /// `rqrr` 0.11.0 has `assert!(x <= i32::MAX as f64)` inside `Perspective::map`, and
    /// degenerate images such as **periodic noise** make its perspective transform produce
    /// huge values or NaN, which trips the assertion and panics the thread. All it takes to
    /// trigger is an image of a few dozen bytes, and the input on this path is
    /// **attacker-controlled**: an imported image may come from anyone.
    ///
    /// This crate's contract is "no input may cause a panic", so every call into the decoder
    /// is wrapped in `catch_unwind`. That is **containment, not a fix**: the fix belongs
    /// upstream, and this error variant is what keeps such an input from taking the whole
    /// process (on a platform side, the whole application) down with it.
    ///
    /// # What the caller should do with it
    ///
    /// Same user-visible handling as "no code in the image": try another image, or scan with
    /// the camera. The difference is that this one **belongs in the log** — it is a pending
    /// upstream defect, not the user scanning the wrong thing.
    #[error("the image decoder could not handle this image")]
    QrDecoderPanicked,

    /// The scanned QR code is not text (and therefore cannot be a code of this application).
    #[error("the scanned QR code is not text")]
    QrNotText,

    /// Image decoding failed.
    ///
    /// Present only with the `scan-image` feature, which is its only source.
    #[cfg(feature = "scan-image")]
    #[error("QR image decoding failed: {0}")]
    QrDecode(#[from] rqrr::DeQRError),

    /// The text is not LAN connection info of this application.
    ///
    /// Separate from [`Error::NotOurQrText`]: that one says "what was scanned is not a QR
    /// envelope", this one says "the envelope decoded, but it carried something else".
    /// Merging the two would make "somebody else's sync code was scanned" indistinguishable
    /// from "a pairing code was scanned", and the two are handled completely differently.
    #[error("this is not Qualia2FA LAN connection info")]
    NotOurLanAddress,

    /// The LAN connection info has the wrong length.
    ///
    /// This structure is **fixed-size**, so a wrong length is bad input and needs no further
    /// guessing.
    #[error("wrong LAN connection info length: expected {expected} bytes, got {actual} bytes")]
    BadLanAddressLength {
        /// Number of bytes of the fixed-size structure.
        expected: usize,
        /// Number of bytes actually received.
        actual: usize,
    },

    /// The port in the LAN connection info is 0.
    ///
    /// Port 0 means "let the system pick one", so it **must not** appear in connection info
    /// that has already been established: a peer receiving it could only connect to a
    /// non-existent port.
    #[error("the port in the LAN connection info is 0")]
    ZeroPort,

    /// The received UDP datagram is not a lobby datagram of this protocol.
    ///
    /// The LAN multicast group is **shared**: other programs on the same subnet may be using
    /// it, and anyone may pour arbitrary bytes into it. A wrong magic number means "not our
    /// datagram" and is simply dropped, not reported as a parse failure.
    #[error("this is not a Qualia2FA lobby datagram")]
    NotOurDatagram,

    /// The kind of the lobby datagram is not recognized.
    ///
    /// Separate from [`Error::NotOurDatagram`]: the magic number matched, so this is
    /// genuinely our datagram, only **newer than this build**. Folding it into "not our
    /// datagram" would make old clients silently drop a new client's announcements as noise
    /// when a datagram kind is added, and that is a hard class of failure to diagnose.
    #[error("unrecognized lobby datagram kind: {kind}")]
    UnknownDatagramKind {
        /// The kind byte that was actually received.
        kind: u8,
    },

    /// The format version of the lobby datagram is newer than this build supports.
    ///
    /// A separate variant for the same reason as [`Error::UnknownDatagramKind`]: it must be
    /// distinguishable from "not our datagram".
    #[error("lobby datagram version {found} is newer than the supported {supported}")]
    UnsupportedDatagramVersion {
        /// Version the datagram claims.
        found: u8,
        /// Version this build supports.
        supported: u8,
    },

    /// The lobby datagram has the wrong length.
    #[error("wrong lobby datagram length: expected {expected} bytes, got {actual} bytes")]
    BadDatagramLength {
        /// Number of bytes a datagram of this kind should have.
        expected: usize,
        /// Number of bytes actually received.
        actual: usize,
    },

    /// No peer was found on the LAN.
    ///
    /// This is not an error state but "nothing yet" — the caller decides from it whether to
    /// keep waiting. Reporting it separately from "the channel is broken" keeps the UI from
    /// showing "no other device on this subnet for now" as a fault.
    #[error("no peer has been found on the LAN yet")]
    NoLanPeersFound,

    /// A LAN socket operation failed.
    ///
    /// Separate from the other variants: this one is an **environment** problem (no network
    /// interface, port already in use, multicast blocked by a firewall), not an input
    /// problem. Merging them would show "network unavailable" as "corrupt datagram".
    #[error("LAN socket operation failed: {operation}")]
    LanSocket {
        /// Which operation failed (`bind` / `join_multicast` / `send_to` / `recv_from` …).
        operation: &'static str,
    },

    /// The LAN transport received a message addressed somewhere else.
    ///
    /// The only reason this variant exists is a **contract**: `Recipient::One` must not
    /// degrade into a broadcast. When a directed message finds no connection to that peer on
    /// this machine, the correct handling is an error, and **not** falling back to sending it
    /// to everyone — that would put a payload meant for B into C's hands while the user sees
    /// nothing unusual.
    #[error("this directed message has no usable connection")]
    NoConnectionToPeer,

    /// This frame is **not part of the same payload** as the frames received so far.
    ///
    /// A user who scans frame 1 of payload A and then frame 2 of payload B would reassemble
    /// wrong bytes, and the failure would only surface at the **AEAD of the payload layer**,
    /// reported as "decryption failed" — a signal pointing diagnostics at the wrong key, while
    /// all the user needs is to rescan one code.
    ///
    /// The reassembly layer therefore does a **cheap shape check** (see the documentation of
    /// the `frame` module) and reports this mix-up early. The "do not distinguish failure
    /// reasons" discipline of [`Error::VaultDecryptionFailed`] governs **ciphertext** and has
    /// nothing to do with the cleartext frame header here: the frame header is printed on the
    /// QR code and is public.
    ///
    /// [`Error::VaultDecryptionFailed`]: https://docs.rs/qualia2fa-core
    #[error("this frame is not part of the same payload as the frames received so far")]
    FrameMismatch,

    /// A LAN transport layer (iroh/QUIC) operation failed.
    ///
    /// Separate from [`Error::LanSocket`]: that one is the lobby's UDP traffic, this one is
    /// the QUIC data plane. Merging them would show "multicast blocked by a firewall" and
    /// "QUIC connection timed out" as one fault, although the two are handled completely
    /// differently.
    #[error("LAN transport failed: {operation}")]
    LanTransport {
        /// Which operation failed (`bind` / `connect` / `write` …).
        operation: &'static str,
    },

    /// The transport entry point has no message at the moment.
    ///
    /// # It is not an error
    ///
    /// "There is nothing in the channel right now" and "the channel is broken" must stay
    /// separate: for the former the caller should keep waiting (or do something else), for
    /// the latter it should report to the user. The core library models the distinction as a
    /// variant of its [`Error`], and since this crate cannot reference core types it defines
    /// it once more **here** — the semantics correspond word for word to `SyncNoSessionFound`
    /// on that side, and the adapter layer that joins them forwards it with a single `match`
    /// that contains no decisions.
    ///
    /// An interface that merges the two cases into one `Option` is the shortest path to a
    /// caller writing `let _ = receive(...)`, and that one line silently disables replay
    /// protection.
    #[error("the transport channel has no message at the moment")]
    TransportEmpty,
}
