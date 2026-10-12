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
    #[error("载荷装不下：需要 {needed} 字节，这条通道最多 {limit} 字节")]
    PayloadTooLarge {
        /// Number of bytes that actually have to fit.
        needed: usize,
        /// Maximum number of bytes this channel can carry.
        limit: usize,
    },

    /// The number of frames produced (or required) exceeds the format limit.
    ///
    /// The two numbers have **different units** from [`Error::PayloadTooLarge`]: that one is
    /// "N bytes needed, M bytes allowed", this one is "N frames needed, M frames allowed", and
    /// the caller passes either on to the user as it is.
    ///
    /// The frame limit is fixed by the **format** (the number of decimal digits of
    /// `Q2FA1:<index>/<count>`, see `envelope::MAX_FRAMES`), not by the encoder or the screen.
    #[error("这份载荷需要 {needed} 张码，而上限是 {limit} 张")]
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
    #[error("这不是 Qualia2FA 的二维码")]
    NotOurQrText,

    /// The frame header is invalid (wrong shape, leading zeros, index beyond the count).
    #[error("二维码文本的帧头不合法")]
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
    #[error("这张码有 {count} 帧，这条入口只收单帧")]
    MultiFrameUnsupported {
        /// Frame count the text claims.
        count: u32,
    },

    /// The Base32 payload is invalid (illegal character, illegal length, or non-canonical
    /// trailing bits).
    #[error("二维码文本里的 Base32 载荷不合法")]
    MalformedBase32,

    /// The error correction level is not `L`/`M`/`Q`/`H`.
    #[error("纠错级别 {letter:?} 不是 L/M/Q/H")]
    UnknownEcLevel {
        /// The character that was actually received.
        letter: char,
    },

    /// The QR version is not within 1–40.
    #[error("二维码版本 {version} 不在 1–40 之内")]
    VersionOutOfRange {
        /// The version number that was actually received.
        version: u8,
    },

    /// The rendering parameters are invalid.
    #[error("渲染参数不合法：缩放 {scale} 倍、静区 {quiet_zone} 模块")]
    BadRenderGeometry {
        /// How many pixels each module is enlarged to.
        scale: u16,
        /// Width of the quiet zone left around the code, in modules.
        quiet_zone: u16,
    },

    /// The image dimensions do not match the pixel count, or the dimensions exceed the limit.
    #[error("图像尺寸不合法：{width}×{height}，像素 {pixels} 个")]
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
    /// Separate from [`Error::QrDecode`]: this one means "not even localization succeeded",
    /// rather than "one was found but could not be read". The former usually means the image
    /// contains no code at all (or it is too small or too blurry).
    #[error("图像里没有找到二维码")]
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
    #[error("图像解码器无法处理这张图")]
    QrDecoderPanicked,

    /// The scanned QR code is not text (and therefore cannot be a code of this application).
    #[error("扫到的二维码不是文本")]
    QrNotText,

    /// Image decoding failed.
    ///
    /// Present only with the `scan-image` feature, which is its only source.
    #[cfg(feature = "scan-image")]
    #[error("二维码图像解码失败：{0}")]
    QrDecode(#[from] rqrr::DeQRError),

    /// The text is not LAN connection info of this application.
    ///
    /// Separate from [`Error::NotOurQrText`]: that one says "what was scanned is not a QR
    /// envelope", this one says "the envelope decoded, but it carried something else".
    /// Merging the two would make "somebody else's sync code was scanned" indistinguishable
    /// from "a pairing code was scanned", and the two are handled completely differently.
    #[error("这不是 Qualia2FA 的局域网连接信息")]
    NotOurLanAddress,

    /// The LAN connection info has the wrong length.
    ///
    /// This structure is **fixed-size**, so a wrong length is bad input and needs no further
    /// guessing.
    #[error("局域网连接信息长度不对：期望 {expected} 字节，实际 {actual} 字节")]
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
    #[error("局域网连接信息里的端口为 0")]
    ZeroPort,

    /// The received UDP datagram is not a lobby datagram of this protocol.
    ///
    /// The LAN multicast group is **shared**: other programs on the same subnet may be using
    /// it, and anyone may pour arbitrary bytes into it. A wrong magic number means "not our
    /// datagram" and is simply dropped, not reported as a parse failure.
    #[error("这不是 Qualia2FA 的大厅报文")]
    NotOurDatagram,

    /// The kind of the lobby datagram is not recognized.
    ///
    /// Separate from [`Error::NotOurDatagram`]: the magic number matched, so this is
    /// genuinely our datagram, only **newer than this build**. Folding it into "not our
    /// datagram" would make old clients silently drop a new client's announcements as noise
    /// when a datagram kind is added, and that is a hard class of failure to diagnose.
    #[error("不认识的大厅报文种类：{kind}")]
    UnknownDatagramKind {
        /// The kind byte that was actually received.
        kind: u8,
    },

    /// The format version of the lobby datagram is newer than this build supports.
    ///
    /// A separate variant for the same reason as [`Error::UnknownDatagramKind`]: it must be
    /// distinguishable from "not our datagram".
    #[error("大厅报文版本 {found} 比本机支持的 {supported} 新")]
    UnsupportedDatagramVersion {
        /// Version the datagram claims.
        found: u8,
        /// Version this build supports.
        supported: u8,
    },

    /// The lobby datagram has the wrong length.
    #[error("大厅报文长度不对：期望 {expected} 字节，实际 {actual} 字节")]
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
    #[error("局域网上还没有发现任何对端")]
    NoLanPeersFound,

    /// A LAN socket operation failed.
    ///
    /// Separate from the other variants: this one is an **environment** problem (no network
    /// interface, port already in use, multicast blocked by a firewall), not an input
    /// problem. Merging them would show "network unavailable" as "corrupt datagram".
    #[error("局域网 socket 操作失败：{operation}")]
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
    #[error("这条定向消息没有可用的连接")]
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
    #[error("这一帧与之前收到的不是同一份载荷")]
    FrameMismatch,

    /// A LAN transport layer (iroh/QUIC) operation failed.
    ///
    /// Separate from [`Error::LanSocket`]: that one is the lobby's UDP traffic, this one is
    /// the QUIC data plane. Merging them would show "multicast blocked by a firewall" and
    /// "QUIC connection timed out" as one fault, although the two are handled completely
    /// differently.
    #[error("局域网传输失败：{operation}")]
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
    #[error("传输通道里暂时没有消息")]
    TransportEmpty,
}
