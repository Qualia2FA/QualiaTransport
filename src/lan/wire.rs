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

//! The **wire format** of the LAN lobby: who is on this segment, and at which address to
//! reach them.
//!
//! # Format (version 1)
//!
//! Every datagram is a fixed **84 bytes**, all fields big-endian:
//!
//! ```text
//! magic 8 | version 1 | kind 1 | sequence 8 | device id 32 | endpoint key 32 | port 2
//! ```
//!
//! | Field | Contents | Notes |
//! |-------|----------|-------|
//! | magic | `Q2FALAN\0` | the multicast group is shared, so "is this our datagram at all" has to come first |
//! | version | `1` | a field of its own, so "newer than this build" is reported separately from "not ours" |
//! | kind | [`Kind`] | see below |
//! | sequence | each device's own counter | suppresses reordering and duplicate delivery on the multicast path |
//! | device id | [`DeviceId`] (32 bytes) | the identity the user sees, and the one the allow list uses |
//! | endpoint key | [`EndpointKey`] (32 bytes) | the identity the transport connects with, **proven by the handshake** |
//! | port | `u16` | which port to connect to |
//!
//! The fixed length leaves the parser exactly one shape — "reject if the length is wrong" —
//! with no variable-length parsing anywhere, and variable-length parsing is what input can
//! steer. Adding a field therefore requires a new version number.
//!
//! The device id and the endpoint key are **two distinct identities**:
//!
//! - [`DeviceId`] is the SHA-256 of the device identity public key (P-256, the one in the
//!   platform hardware keystore). It is the identity **the user sees**, and the value in the
//!   sync allow list.
//! - [`EndpointKey`] is the transport's (QUIC) long-term key; establishing a connection
//!   **proves by handshake** that its holder really owns it.
//!
//! A multicast announcement is **unauthenticated**: anyone can claim to be any device. It can
//! therefore only answer "who is probably on this segment and where do I reach them", and
//! **cannot** answer "is that really that device". The handshake (endpoint key) and the sync
//! layer's allow list (device id) answer the latter. Carrying both fields is what makes "what
//! the announcement claims" and "what the connection proves" **cross-checkable**: a connection
//! whose two identities disagree must be dropped, and that is an explicit check rather than an
//! understanding.
//!
//! Announcements are unsigned: the announce interval is 30 seconds, and signing every one of
//! them would wake the hardware keystore twice a minute. A forged announcement makes the
//! receiver open a connection, and that connection fails in the handshake because the spoofer
//! cannot produce the endpoint private key. **Discovery may be unauthenticated; credentials
//! must come from the channel.**

use qualia_dik::{DEVICE_ID_LEN, DeviceId};

use crate::error::{Error, Result};

/// Magic number of a lobby datagram.
///
/// 8 bytes with a trailing NUL, the same convention as the core library's vault files and sync
/// payloads, so it is recognizable at a glance in a hex editor.
pub const MAGIC: &[u8; 8] = b"Q2FALAN\0";

/// Wire format version.
pub const VERSION: u8 = 1;

/// Length of an endpoint public key (the QUIC long-term key is an Ed25519 public key).
pub const ENDPOINT_KEY_LEN: usize = 32;

/// Length of the sequence number.
pub const SEQUENCE_LEN: usize = 8;

/// Total length of a datagram.
///
/// Written as the sum of the field lengths, **deliberately not as a literal**, so that it
/// cannot drift away from the fields it is made of.
pub const DATAGRAM_LEN: usize =
    MAGIC.len() + 1 + 1 + SEQUENCE_LEN + DEVICE_ID_LEN + ENDPOINT_KEY_LEN + 2;

/// The transport endpoint public key.
///
/// It is the QUIC long-term identity, **not** the device identity (that one is [`DeviceId`]);
/// see the module docs. Unlike [`DeviceId`] it changes when the endpoint key is rotated.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointKey([u8; ENDPOINT_KEY_LEN]);

impl EndpointKey {
    /// Constructs from 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ENDPOINT_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ENDPOINT_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for EndpointKey {
    /// Prints the first 8 bytes only.
    ///
    /// The same treatment as [`DeviceId`]: the full public key holds no secret, and a short
    /// prefix is enough to tell whether two devices matched.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EndpointKey({})", hex8(&self.0))
    }
}

/// Formats the first 8 bytes of a byte slice as hexadecimal.
fn hex8(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The kind of a datagram.
///
/// [`Kind::Bye`] is a courtesy, not a security mechanism: anybody can send one on
/// behalf of anybody, exactly as anybody can send [`Kind::Hello`]. A received `Bye`
/// marks the peer as gone (see [`PeerStatus`]) without removing it from the view;
/// [`LanView::forget`] removes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// I am here, you can connect to me.
    Hello,
    /// I am leaving, stop waiting for me.
    Bye,
}

impl Kind {
    /// The byte value on the wire.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Hello => 0x01,
            Self::Bye => 0x02,
        }
    }

    /// Rebuilds a kind from its wire byte.
    #[must_use]
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::Bye),
            _ => None,
        }
    }
}

/// One announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announcement {
    /// Whether this is "I am here" or "I am leaving".
    pub kind: Kind,
    /// The sender's own sequence number, incremented per announcement.
    ///
    /// It starts at 0 and belongs to one device: counters of different devices are
    /// unrelated, so comparing them across devices means nothing.
    pub sequence: u64,
    /// The sender's device id.
    pub device: DeviceId,
    /// The sender's transport endpoint public key.
    pub endpoint_key: EndpointKey,
    /// The port the sender listens on.
    pub port: u16,
}

impl Announcement {
    /// Encodes into [`DATAGRAM_LEN`] bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; DATAGRAM_LEN] {
        let mut out = [0_u8; DATAGRAM_LEN];
        let mut at = 0;
        out[at..at + MAGIC.len()].copy_from_slice(MAGIC);
        at += MAGIC.len();
        out[at] = VERSION;
        at += 1;
        out[at] = self.kind.as_byte();
        at += 1;
        out[at..at + SEQUENCE_LEN].copy_from_slice(&self.sequence.to_be_bytes());
        at += SEQUENCE_LEN;
        out[at..at + DEVICE_ID_LEN].copy_from_slice(self.device.as_bytes());
        at += DEVICE_ID_LEN;
        out[at..at + ENDPOINT_KEY_LEN].copy_from_slice(&self.endpoint_key.0);
        at += ENDPOINT_KEY_LEN;
        out[at..at + 2].copy_from_slice(&self.port.to_be_bytes());
        out
    }

    /// Decodes one announcement from bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::NotOurDatagram`]: wrong magic number. The multicast group is shared,
    ///   so foreign programs and injected bytes are normal traffic; this is a **drop**,
    ///   not a failure.
    /// - [`Error::UnsupportedDatagramVersion`]: ours, but newer than this build.
    /// - [`Error::UnknownDatagramKind`]: ours, but an unknown kind.
    /// - [`Error::BadDatagramLength`]: length is not [`DATAGRAM_LEN`].
    ///
    /// The magic number is checked before the length, so a foreign datagram reports
    /// "not ours" instead of "wrong length", which would look like a fault.
    pub fn decode(datagram: &[u8]) -> Result<Self> {
        let header = datagram.get(..MAGIC.len()).ok_or(Error::NotOurDatagram)?;
        if header != MAGIC {
            return Err(Error::NotOurDatagram);
        }

        if datagram.len() != DATAGRAM_LEN {
            return Err(Error::BadDatagramLength {
                expected: DATAGRAM_LEN,
                actual: datagram.len(),
            });
        }

        let version = datagram[MAGIC.len()];
        if version != VERSION {
            return Err(Error::UnsupportedDatagramVersion {
                found: version,
                supported: VERSION,
            });
        }

        let kind_byte = datagram[MAGIC.len() + 1];
        let kind =
            Kind::from_byte(kind_byte).ok_or(Error::UnknownDatagramKind { kind: kind_byte })?;

        let mut at = MAGIC.len() + 2;
        let sequence = read_u64(&datagram[at..at + SEQUENCE_LEN]);
        at += SEQUENCE_LEN;
        let mut device = [0_u8; DEVICE_ID_LEN];
        device.copy_from_slice(&datagram[at..at + DEVICE_ID_LEN]);
        at += DEVICE_ID_LEN;
        let mut endpoint_key = [0_u8; ENDPOINT_KEY_LEN];
        endpoint_key.copy_from_slice(&datagram[at..at + ENDPOINT_KEY_LEN]);
        at += ENDPOINT_KEY_LEN;
        let port = u16::from_be_bytes([datagram[at], datagram[at + 1]]);

        Ok(Self {
            kind,
            sequence,
            device: DeviceId::from_bytes(device),
            endpoint_key: EndpointKey::from_bytes(endpoint_key),
            port,
        })
    }
}

/// Reads an 8-byte big-endian integer.
fn read_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(bytes);
    u64::from_be_bytes(buf)
}

/// The state of a peer in the lobby.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    /// The peer is here.
    Here,
    /// The peer announced that it is leaving.
    ///
    /// Not the same as "forget it": the peer may only have restarted, and its first
    /// announcement afterwards puts it back to [`PeerStatus::Here`]. The status is kept
    /// separately so that the UI can tell "switched off" from "lost the network"
    /// without waiting for the lease.
    Left,
}

/// One peer remembered by the lobby.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    /// Device id.
    pub device: DeviceId,
    /// Transport endpoint public key.
    pub endpoint_key: EndpointKey,
    /// Port.
    pub port: u16,
    /// The status heard last.
    pub status: PeerStatus,
    /// When this peer was last heard from, in caller-supplied milliseconds.
    pub last_seen_ms: u64,
    /// The sequence number heard last.
    pub sequence: u64,
}

/// Whether an announcement counts as news.
///
/// # The sequence number is the only criterion
///
/// The comparison is `<=` rather than `<`: the same sequence number arriving twice is
/// normal on the multicast path (several interfaces, several paths,
/// `IP_MULTICAST_LOOP`), and the copy must not start another connection attempt.
///
/// A lower sequence number means the sender restarted, and is deliberately **not**
/// news: treating it as news would reopen the replay window. A restarted device
/// becomes visible again once its counter passes the watermark, which in practice
/// costs the user one restart.
fn is_newer(previous: Peer, sequence: u64) -> bool {
    sequence > previous.sequence
}

/// Every peer currently visible in the lobby.
///
/// Pure logic, no socket: the type answers only "given these announcements, who is on
/// the segment". The byte level lives in [`crate::lan::lobby`], so this reasoning can
/// be driven to convergence in one process (see the `three_devices_converge` test).
#[derive(Debug, Clone, Default)]
pub struct LanView {
    /// Peers indexed by device id.
    peers: Vec<Peer>,
}

impl LanView {
    /// Maximum number of peers remembered.
    ///
    /// A security bound rather than a performance knob: a device id is public, so any
    /// machine on the segment can invent unlimited "new devices" at 84 bytes per
    /// announcement, and without a bound a script that keeps announcing grows the
    /// receiver's memory without limit.
    ///
    /// 1024 is far above the device count of a real segment (a home or small office has
    /// single digits). Reaching it evicts the least recently heard peers rather than
    /// refusing the new announcement.
    pub const MAX_PEERS: usize = 1024;

    /// An empty view.
    #[must_use]
    pub const fn new() -> Self {
        Self { peers: Vec::new() }
    }

    /// Takes one announcement and reports whether it changed anything.
    ///
    /// `now_ms` comes from the caller, because the crate reads no clock.
    ///
    /// `false` means the sequence number is not newer than the known one (reordering or
    /// duplicate delivery), or the same [`Kind::Bye`] arrived twice. It does **not** mean
    /// the datagram was malformed: that is reported by [`Announcement::decode`].
    pub fn observe(&mut self, announcement: Announcement, now_ms: u64) -> bool {
        let device = announcement.device;

        if let Some(previous) = self.peers.iter_mut().find(|peer| peer.device == device) {
            if !is_newer(*previous, announcement.sequence) {
                return false;
            }
            previous.endpoint_key = announcement.endpoint_key;
            previous.port = announcement.port;
            previous.status = match announcement.kind {
                Kind::Hello => PeerStatus::Here,
                Kind::Bye => PeerStatus::Left,
            };
            previous.last_seen_ms = now_ms;
            previous.sequence = announcement.sequence;
            return true;
        }

        if self.peers.len() >= Self::MAX_PEERS {
            self.evict_least_recent();
        }

        self.peers.push(Peer {
            device,
            endpoint_key: announcement.endpoint_key,
            port: announcement.port,
            status: match announcement.kind {
                Kind::Hello => PeerStatus::Here,
                Kind::Bye => PeerStatus::Left,
            },
            last_seen_ms: now_ms,
            sequence: announcement.sequence,
        });
        true
    }

    /// Drops the least recently heard peer.
    ///
    /// The criterion is "heard from longest ago", ties broken by the smallest device id,
    /// and it has to be deterministic: an eviction policy that follows the internal
    /// storage order would let two views drop different peers for the same input, and
    /// every view converging on one list is what the lobby guarantees.
    fn evict_least_recent(&mut self) {
        let Some(victim) = self
            .peers
            .iter()
            .enumerate()
            .min_by_key(|(_, peer)| (peer.last_seen_ms, peer.device))
            .map(|(index, _)| index)
        else {
            return;
        };
        self.peers.swap_remove(victim);
    }

    /// Every peer currently considered here, sorted by device id.
    ///
    /// The sort gives the caller a stable order, so the UI does not reshuffle because of
    /// internal storage changes.
    #[must_use]
    pub fn here(&self) -> Vec<Peer> {
        let mut peers: Vec<Peer> = self
            .peers
            .iter()
            .copied()
            .filter(|peer| peer.status == PeerStatus::Here)
            .collect();
        peers.sort_by_key(|peer| peer.device);
        peers
    }

    /// Every peer, including the ones that left, sorted by device id.
    #[must_use]
    pub fn all(&self) -> Vec<Peer> {
        let mut peers = self.peers.clone();
        peers.sort_by_key(|peer| peer.device);
        peers
    }

    /// Looks up one peer.
    #[must_use]
    pub fn get(&self, device: &DeviceId) -> Option<Peer> {
        self.peers
            .iter()
            .find(|peer| peer.device == *device)
            .copied()
    }

    /// How many milliseconds without news a peer stops counting as here.
    ///
    /// 3 minutes against an announce interval of
    /// [`crate::lan::lobby::ANNOUNCE_INTERVAL_MS`] (30 seconds) tolerates four lost
    /// announcements, which covers a short suspend or an ARP storm, while a device that
    /// was switched off does not stay listed as available for long.
    pub const STALE_AFTER_MS: u64 = 180_000;

    /// Marks peers whose lease ran out as no longer here.
    ///
    /// Expiry **marks** instead of removing, so the sequence watermark survives and a
    /// recorded old announcement stays rejected by the comparison in
    /// [`LanView::observe`]. Callers that need the memory back use [`LanView::forget`].
    ///
    /// The sequence number of an expired peer is raised to `max(known) + 1`, so the state
    /// change can be replayed through an ordinary [`LanView::observe`] call on another
    /// view; otherwise that view would see an equal sequence number and drop the change as
    /// old news. The replay window does not grow, because real old announcements carry
    /// numbers far below the new watermark.
    ///
    /// Returns the devices that were marked, so the caller can clean up their connections.
    pub fn expire(&mut self, now_ms: u64) -> Vec<DeviceId> {
        let mut expired = Vec::new();
        for peer in &mut self.peers {
            if peer.status == PeerStatus::Here
                && now_ms.saturating_sub(peer.last_seen_ms) > Self::STALE_AFTER_MS
            {
                peer.status = PeerStatus::Left;
                peer.sequence = peer.sequence.saturating_add(1);
                expired.push(peer.device);
            }
        }
        expired
    }

    /// Forgets a peer completely, including its sequence watermark.
    ///
    /// This reopens the replay window for that peer, so it belongs to an explicit user
    /// action ("remove this device") rather than to lease cleanup, which is
    /// [`LanView::expire`].
    pub fn forget(&mut self, device: &DeviceId) -> bool {
        let before = self.peers.len();
        self.peers.retain(|peer| peer.device != *device);
        self.peers.len() != before
    }

    /// How many peers are remembered, including the ones that left.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the view is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A device whose id and endpoint key both derive from `seed`, so a test can tell
    /// one device from another at a glance.
    fn device(seed: u8) -> (DeviceId, EndpointKey) {
        (
            DeviceId::from_bytes([seed; 32]),
            EndpointKey::from_bytes([seed.wrapping_add(0x80); 32]),
        )
    }

    /// Builds an endpoint public key.
    fn endpoint_key(seed: u8) -> EndpointKey {
        EndpointKey::from_bytes([seed; 32])
    }

    fn hello(seed: u8, sequence: u64) -> Announcement {
        let (device, endpoint_key) = device(seed);
        Announcement {
            kind: Kind::Hello,
            sequence,
            device,
            endpoint_key,
            port: 41_000 + u16::from(seed),
        }
    }

    /// **The wire format is pinned byte by byte.**
    ///
    /// The expected bytes are written out by hand instead of comparing
    /// [`Announcement::encode`] against [`Announcement::decode`], which would only prove
    /// that the two agree with each other. Every byte of the datagram appears here once.
    #[test]
    fn wire_format_is_pinned() {
        let announcement = Announcement {
            kind: Kind::Hello,
            sequence: 0x0102_0304_0506_0708,
            device: DeviceId::from_bytes([0xAA; 32]),
            endpoint_key: EndpointKey::from_bytes([0xBB; 32]),
            port: 0xCCDD,
        };
        let bytes = announcement.encode();

        assert_eq!(bytes.len(), DATAGRAM_LEN);
        assert_eq!(&bytes[0..8], b"Q2FALAN\0");
        assert_eq!(bytes[8], 1, "version");
        assert_eq!(bytes[9], 0x01, "Hello");
        assert_eq!(
            &bytes[10..18],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "the sequence is big-endian"
        );
        assert_eq!(&bytes[18..50], &[0xAA; 32], "device id");
        assert_eq!(&bytes[50..82], &[0xBB; 32], "endpoint key");
        assert_eq!(&bytes[82..84], &[0xCC, 0xDD], "the port is big-endian");

        assert_eq!(
            Announcement::decode(&bytes).expect("a self-encoded datagram must decode"),
            announcement
        );
    }

    #[test]
    fn every_kind_round_trips() {
        for kind in [Kind::Hello, Kind::Bye] {
            let mut announcement = hello(7, 42);
            announcement.kind = kind;
            let decoded = Announcement::decode(&announcement.encode()).expect("round trip");
            assert_eq!(
                decoded, announcement,
                "round trip mismatch for kind {kind:?}"
            );
        }
    }

    /// Boundary port and sequence values must round-trip unchanged.
    #[test]
    fn boundary_values_round_trip() {
        for (sequence, port) in [(0_u64, 1_u16), (u64::MAX, u16::MAX), (1, 0)] {
            let mut announcement = hello(1, sequence);
            announcement.port = port;
            let decoded = Announcement::decode(&announcement.encode()).expect("round trip");
            assert_eq!(decoded.sequence, sequence);
            assert_eq!(decoded.port, port);
        }
    }

    /// A foreign datagram reports "not ours" rather than "ours but broken".
    #[test]
    fn foreign_datagrams_are_recognized_as_foreign() {
        for datagram in [
            b"".as_slice(),
            b"hello",
            b"GET / HTTP/1.1\r\n",
            b"Q2FALAN",       // the magic differs by one byte, and the length is short
            b"q2falan\0",     // case-sensitive
            b"Q2FASYN\0\x01", // the magic of the core library's sync payload
        ] {
            let result = Announcement::decode(datagram);
            let is_foreign = matches!(result, Err(Error::NotOurDatagram));
            assert!(
                is_foreign,
                "should report a foreign datagram, got {result:?}"
            );
        }
    }

    /// Once the magic number matches, every other violation is reported **separately**:
    /// length, version and kind each have their own error. The version is checked before
    /// the kind, so the kind case restores the version first.
    #[test]
    fn our_datagrams_are_diagnosed_precisely() {
        let good = hello(3, 9).encode();

        for length in [DATAGRAM_LEN - 1, DATAGRAM_LEN + 1] {
            let mut bad = good.to_vec();
            bad.resize(length, 0);
            let result = Announcement::decode(&bad);
            let is_length = matches!(result, Err(Error::BadDatagramLength { .. }));
            assert!(
                is_length,
                "{length} bytes must report a bad length, got {result:?}"
            );
        }

        let mut newer = good;
        newer[8] = VERSION + 1;
        let result = Announcement::decode(&newer);
        let is_version = matches!(
            result,
            Err(Error::UnsupportedDatagramVersion { found, supported })
                if found == VERSION + 1 && supported == VERSION
        );
        assert!(
            is_version,
            "should report a version newer than this build, got {result:?}"
        );

        let mut unknown = good;
        unknown[8] = VERSION;
        unknown[9] = 0x7F;
        let result = Announcement::decode(&unknown);
        let is_kind = matches!(result, Err(Error::UnknownDatagramKind { kind: 0x7F }));
        assert!(is_kind, "should report an unknown kind, got {result:?}");
    }

    /// Multicast noise must not make the parser panic or accept.
    ///
    /// The loop is a cheap stand-in for the `lan_datagram` fuzz target: any length with
    /// any content must neither panic nor be accepted. Half of the inputs carry a real
    /// magic number so that parsing reaches the length and kind checks.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let good = hello(1, 1).encode();
        for length in 0..=(DATAGRAM_LEN + 4) {
            for fill in [0x00_u8, 0xFF, 0x51, 0x0A] {
                let mut bytes = vec![fill; length];
                if length >= 8 && fill == 0x51 {
                    bytes[..8].copy_from_slice(MAGIC);
                } else if length >= 8 {
                    bytes[..8].copy_from_slice(&good[..8]);
                }
                let _ = Announcement::decode(&bytes);
            }
        }
    }

    /// The view computes "who is here" correctly: an announcement whose sequence number
    /// did not increase changes nothing, a larger one refreshes the entry.
    #[test]
    fn the_view_reports_who_is_here() {
        let mut view = LanView::new();
        assert!(view.is_empty());
        assert!(
            view.observe(hello(1, 0), 1_000),
            "the first announcement must be accepted"
        );
        assert_eq!(view.len(), 1);

        assert!(view.observe(hello(2, 0), 1_000));
        assert_eq!(view.here().len(), 2);

        assert!(
            !view.observe(hello(1, 0), 2_000),
            "a repeat with the same sequence must not count as news"
        );
        assert_eq!(
            view.get(&device(1).0)
                .expect("must be in the view")
                .last_seen_ms,
            1_000,
            "an ignored announcement must not refresh the timestamp"
        );

        assert!(view.observe(hello(1, 1), 2_000));
        assert_eq!(
            view.get(&device(1).0)
                .expect("must be in the view")
                .last_seen_ms,
            2_000
        );
    }

    /// After `Bye`, a `Hello` brings the peer back (the restart case).
    ///
    /// A restarted device starts at sequence 0, which is below the watermark and
    /// therefore **not** news; once its counter passes the watermark it is visible again.
    #[test]
    fn a_peer_can_come_back_after_saying_goodbye() {
        let mut view = LanView::new();
        let (id, _) = device(5);

        view.observe(hello(5, 0), 1_000);
        assert_eq!(view.here().len(), 1);

        let mut bye = hello(5, 1);
        bye.kind = Kind::Bye;
        assert!(view.observe(bye, 2_000));
        assert!(
            view.here().is_empty(),
            "a device that said goodbye must not still count as here"
        );
        assert_eq!(
            view.len(),
            1,
            "but it stays in the view — the sequence watermark must be kept"
        );
        assert_eq!(
            view.get(&id).expect("must be in the view").status,
            PeerStatus::Left
        );

        assert!(
            !view.observe(hello(5, 0), 3_000),
            "a lower sequence is not news"
        );
        assert!(view.here().is_empty());

        assert!(view.observe(hello(5, 2), 4_000));
        assert_eq!(view.here().len(), 1);
        assert_eq!(
            view.get(&id).expect("must be in the view").status,
            PeerStatus::Here
        );
    }

    /// Lease: a peer that stays quiet stops counting as here but is **not** deleted, and
    /// a later expiry round does not report it again.
    #[test]
    fn a_silent_peer_expires_but_is_remembered() {
        let mut view = LanView::new();
        view.observe(hello(1, 0), 1_000);
        view.observe(hello(2, 0), 1_000);

        assert!(
            view.expire(1_000 + LanView::STALE_AFTER_MS).is_empty(),
            "exactly at the deadline is not yet expired"
        );
        let expired = view.expire(1_000 + LanView::STALE_AFTER_MS + 1);
        assert_eq!(expired.len(), 2);
        assert!(view.here().is_empty());
        assert_eq!(
            view.len(),
            2,
            "the watermark must be kept, otherwise old announcements can be replayed"
        );

        assert!(
            view.expire(999_999).is_empty(),
            "a peer must be reported expired only once"
        );
    }

    /// **Expiry has to be replayable.**
    ///
    /// The lobby keeps two views: the background thread owns the one doing the real
    /// reasoning, and `Lobby` holds the one the caller reads. They synchronise only
    /// through the event queue, so expiry has to be expressible as an ordinary
    /// [`LanView::observe`] call.
    ///
    /// The second `observe` below also pins the raised sequence number of
    /// [`LanView::expire`]: without it the sequence comparison would drop the notice as
    /// old news.
    #[test]
    fn an_expiry_can_be_replayed_into_another_view() {
        let (id, _) = device(1);
        let mut first = LanView::new();
        first.observe(hello(1, 0), 0);

        let later = LanView::STALE_AFTER_MS + 1;
        assert_eq!(first.expire(later), vec![id]);
        let expired = first.get(&id).expect("must still be in the view");

        let mut second = LanView::new();
        second.observe(hello(1, 0), 0);
        assert_eq!(second.here().len(), 1);

        let replay = Announcement {
            kind: Kind::Bye,
            sequence: expired.sequence,
            device: expired.device,
            endpoint_key: expired.endpoint_key,
            port: expired.port,
        };
        assert!(
            second.observe(replay, later),
            "an expiry notice must be treated as news"
        );
        assert!(second.here().is_empty());
        assert_eq!(
            second.get(&id).expect("must still be in the view").status,
            PeerStatus::Left
        );
    }

    /// "Leaving" and "expired" describe the same state, so the view treats them the same
    #[test]
    fn saying_goodbye_and_expiring_leave_the_same_state() {
        let (id, _) = device(2);

        let mut said = LanView::new();
        said.observe(hello(2, 0), 0);
        let mut bye = hello(2, 1);
        bye.kind = Kind::Bye;
        said.observe(bye, 500);

        let mut expired = LanView::new();
        expired.observe(hello(2, 0), 0);
        expired.expire(LanView::STALE_AFTER_MS + 1);

        let said = said.get(&id).expect("must be in the view");
        let expired = expired.get(&id).expect("must be in the view");
        assert_eq!(said.status, expired.status);
        assert_eq!(said.endpoint_key, expired.endpoint_key);
        assert_eq!(said.port, expired.port);
        assert_eq!(said.device, expired.device);
    }

    /// **Three devices converge on one view.**
    ///
    /// Each device feeds its announcements to the other two, as multicast would, and the
    /// three views must end up with the same list: all three devices of the session. No
    /// network is involved, so the reasoning is verified inside one process.
    ///
    /// The list **includes the device itself**. The view is the participant list of this
    /// sync session, not a list of remote devices: the initiator has to decide whether
    /// everyone is present, and only a list holding everyone answers that.
    #[test]
    fn three_devices_converge() {
        let mut views = [LanView::new(), LanView::new(), LanView::new()];
        let hellos = [hello(1, 0), hello(2, 0), hello(3, 0)];

        for (sender, announcement) in hellos.iter().enumerate() {
            for (receiver, view) in views.iter_mut().enumerate() {
                if sender == receiver {
                    continue;
                }
                view.observe(*announcement, 10_000);
            }
        }

        for (seed, view) in (1..=3).zip(views.iter_mut()) {
            view.observe(hello(seed, 0), 10_000);
        }

        let expected: Vec<DeviceId> = (1..=3).map(|seed| device(seed).0).collect();
        for (index, view) in views.iter().enumerate() {
            let here: Vec<DeviceId> = view.here().into_iter().map(|peer| peer.device).collect();
            assert_eq!(
                here, expected,
                "the view of device {index} did not converge"
            );
        }
    }

    /// The list includes the device itself, and its own entry cannot collide with another
    /// device's announcement.
    ///
    /// The key of [`LanView`] is the **device id**, not a "peer versus self" flag; a view
    /// that filtered itself out would fail the convergence test above.
    #[test]
    fn the_view_includes_its_own_device() {
        let mut view = LanView::new();
        let (me, _) = device(9);
        assert!(view.observe(hello(9, 0), 1_000));
        assert_eq!(view.here().len(), 1);
        assert_eq!(view.here()[0].device, me);
    }

    /// **The view has to be bounded.**
    ///
    /// A device id is public information, so any machine on the segment can invent
    /// unlimited "new devices" at 84 bytes each. The test fills [`LanView::MAX_PEERS`] for
    /// real instead of checking the arithmetic.
    #[test]
    fn the_view_is_bounded_under_a_flood_of_new_devices() {
        let mut view = LanView::new();
        let flood = LanView::MAX_PEERS + 500;

        for index in 0..flood {
            let mut seed = [0_u8; 32];
            seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let announcement = Announcement {
                kind: Kind::Hello,
                sequence: 0,
                device: DeviceId::from_bytes(seed),
                endpoint_key: endpoint_key(0),
                port: 1,
            };
            view.observe(announcement, index as u64);
        }

        assert_eq!(
            view.len(),
            LanView::MAX_PEERS,
            "the view must stop at MAX_PEERS peers instead of growing with the input"
        );
    }

    /// Eviction is **deterministic** and drops the least recently heard peers.
    ///
    /// "Every view converges on one list" is what the lobby guarantees, and an eviction
    /// that followed the internal storage order would drop different peers in two views
    /// that received the same announcements.
    #[test]
    fn eviction_drops_the_least_recently_seen() {
        let mut view = LanView::new();

        for index in 0..LanView::MAX_PEERS {
            view.observe(announcement_for(device_at(index)), index as u64);
        }
        assert!(view.get(&device_at(0)).is_some());

        let newcomer = DeviceId::from_bytes([0xFF; 32]);
        view.observe(
            Announcement {
                kind: Kind::Hello,
                sequence: 0,
                device: newcomer,
                endpoint_key: endpoint_key(1),
                port: 1,
            },
            LanView::MAX_PEERS as u64 + 1,
        );

        assert_eq!(view.len(), LanView::MAX_PEERS);
        assert!(
            view.get(&newcomer).is_some(),
            "the newcomer must be in the list"
        );
        assert!(
            view.get(&device_at(0)).is_none(),
            "the least active one must be evicted"
        );
        assert!(
            view.get(&device_at(1)).is_some(),
            "the next oldest is still there"
        );
    }

    /// After eviction the **same peer can come back**, because its sequence watermark went
    /// with it.
    ///
    /// This is the other side of [`LanView::forget`]: an evicted peer is indistinguishable
    /// from an explicitly forgotten one, and both reopen that peer's replay window. It is
    /// why eviction only happens when the view is full.
    #[test]
    fn an_evicted_peer_restarts_from_a_clean_watermark() {
        let mut view = LanView::new();
        for index in 0..LanView::MAX_PEERS {
            view.observe(announcement_for(device_at(index)), index as u64);
        }
        let victim = device_at(0);

        assert!(
            !view.observe(announcement_for(victim), 0),
            "a lower sequence is blocked while the watermark is there"
        );

        view.observe(
            Announcement {
                kind: Kind::Hello,
                sequence: 0,
                device: DeviceId::from_bytes([0xEE; 32]),
                endpoint_key: endpoint_key(2),
                port: 1,
            },
            LanView::MAX_PEERS as u64 + 1,
        );
        assert!(
            view.get(&victim).is_none(),
            "the victim must have been evicted"
        );
        assert!(
            view.observe(announcement_for(victim), 0),
            "the watermark is gone, so the old sequence gets in again"
        );
    }

    /// Builds an announcement from one device, with sequence number 0.
    fn announcement_for(device: DeviceId) -> Announcement {
        Announcement {
            kind: Kind::Hello,
            sequence: 0,
            device,
            endpoint_key: endpoint_key(0),
            port: 1,
        }
    }

    /// Builds the device with index `index`, used to fill the view.
    fn device_at(index: usize) -> DeviceId {
        let mut seed = [0_u8; 32];
        seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
        DeviceId::from_bytes(seed)
    }

    /// Forgetting a peer clears its watermark, so an old announcement is accepted again.
    ///
    /// This is the documented cost of `forget`, and the reason lease cleanup uses
    /// `expire` instead.
    #[test]
    fn forgetting_a_peer_reopens_the_replay_window() {
        let mut view = LanView::new();
        let (id, _) = device(4);
        view.observe(hello(4, 100), 1_000);
        assert!(
            !view.observe(hello(4, 0), 2_000),
            "a lower sequence is blocked"
        );

        assert!(view.forget(&id));
        assert!(view.is_empty());
        assert!(
            view.observe(hello(4, 0), 3_000),
            "the watermark is gone, so the old announcement gets in again"
        );
    }

    /// The debug output prints only the first 8 bytes, so that a log line does not carry
    /// two 32-byte hexadecimal strings.
    #[test]
    fn debug_output_is_short() {
        let key = EndpointKey::from_bytes([0x80; 32]);
        assert_eq!(format!("{key:?}"), "EndpointKey(8080808080808080)");
        let text = format!("{:?}", EndpointKey::from_bytes([1; 32]));
        assert_eq!(text.len(), "EndpointKey(".len() + 16 + 1);
    }
}
