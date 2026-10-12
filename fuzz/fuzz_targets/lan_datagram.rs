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

//! Fuzz target: parsing of the LAN lobby datagrams and of connection information.
//!
//! # Input surface
//!
//! A QR code has to be photographed before it can deliver data, while the multicast group is a
//! **shared medium**: any machine on the same subnet can push arbitrary bytes to
//! `239.255.81.65:21377` with no precondition at all. The lobby's background thread feeds those
//! bytes one by one into [`Announcement::decode`] — that is, this is the only parsing path in
//! this crate driven directly by strangers over the network.
//!
//! The second path is [`LanAddress::decode`], which parses the text inside a QR code, and QR
//! codes are public.
//!
//! # Properties
//!
//! 1. **Never panics** — the main purpose of this target. Every slice by offset in a fixed-size
//!    parser is a candidate: a length check written after its slice turns one 20-byte datagram
//!    into a crash.
//! 2. **Anything parsed encodes back unchanged** — the wire format has exactly one
//!    representation. This is not a matter of taste: "is this announcement the one from before"
//!    is decided purely by field equality, and two byte representations of one announcement
//!    would leave gaps in sequence de-duplication.
//! 3. **Duplicates and reordering do not change the result** — feeding the same set of
//!    announcements again leaves the view unchanged. Multicast guarantees neither order nor the
//!    absence of duplicates, so this property is required on a real network.
//! 4. **The view stays bounded under pressure** — a datagram carries a 32-byte device identity,
//!    so every datagram can be a "new device". The view must keep only a fixed number of peers,
//!    otherwise any machine on the subnet can exhaust our memory by announcing forever.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia_transport::lan::{LanAddress, wire};

/// Datagram length: equal to [`wire::DATAGRAM_LEN`].
const DATAGRAM_LEN: usize = wire::DATAGRAM_LEN;

fuzz_target!(|data: &[u8]| {
    check_announcement(data);

    check_address(data);

    check_view(data);
});

/// ① Parse the whole input as a single announcement and check the round trip.
fn check_announcement(data: &[u8]) {
    let Ok(announcement) = wire::Announcement::decode(data) else {
        return;
    };

    let encoded = announcement.encode();
    assert_eq!(
        encoded.len(),
        DATAGRAM_LEN,
        "编码出来的长度必须是那个加出来的常量"
    );
    let again = wire::Announcement::decode(&encoded).expect("自己编出来的必须解得开");
    assert_eq!(again, announcement, "公告往返不一致");
    assert_eq!(again.encode(), encoded, "往返之后字节必须完全相同");
}

/// ② Parse the whole input as a single connection address and check the round trip.
fn check_address(data: &[u8]) {
    let Ok(address) = LanAddress::decode(data) else {
        return;
    };

    let encoded = address.encode();
    let again = LanAddress::decode(&encoded).expect("自己编出来的必须解得开");
    assert_eq!(again, address, "连接信息往返不一致");
    assert_eq!(again.encode(), encoded, "往返之后字节必须完全相同");
    assert_ne!(address.port, 0, "端口 0 不该被解出来");
}

/// ③ Cut the input into several announcements and feed them in order to one view, then check the
/// merge properties.
///
/// This is the main mode of this target: a single datagram only covers the parser, while the
/// **merging of the view** needs a series of datagrams. The split points are decided by the
/// input, so the fuzzer can freely build the "duplicate, out of order, uneven length" sequences
/// that really occur on multicast: a fixed-size split models several datagrams back to back, a
/// variable-size split models a corrupted length field.
///
/// The view is fed with `now_ms = 0`, so no peer ever expires; a peer's sequence watermark must
/// still equal the highest sequence seen, because `observe` updates on a new sequence only,
/// which is the whole implementation of sequence de-duplication.
fn check_view(data: &[u8]) {
    let mut view = wire::LanView::new();

    let mut chunks: Vec<&[u8]> = data.chunks(DATAGRAM_LEN).collect();
    for (index, byte) in data.iter().enumerate() {
        let end = index.saturating_add(usize::from(*byte)).min(data.len());
        chunks.push(&data[index..end]);
    }

    let mut parsed = Vec::new();
    for chunk in &chunks {
        if let Ok(announcement) = wire::Announcement::decode(chunk) {
            view.observe(announcement, 0);
            parsed.push(announcement);
        }
    }

    for announcement in &parsed {
        let peer = view.get(&announcement.device).expect("刚喂进去的必须在视图里");
        let highest = parsed
            .iter()
            .filter(|other| other.device == announcement.device)
            .map(|other| other.sequence)
            .max()
            .expect("至少有一条");
        assert_eq!(
            peer.sequence, highest,
            "视图里的序号水位必须是见过的最大序号"
        );
    }

    let before = view.all();
    for announcement in &parsed {
        view.observe(*announcement, 0);
    }
    assert_eq!(view.all(), before, "重复喂同一批公告不得改变视图");

    assert!(
        view.len() <= wire::LanView::MAX_PEERS,
        "视图记住了 {} 个对端，超过上限 {}",
        view.len(),
        wire::LanView::MAX_PEERS
    );
    let distinct: std::collections::BTreeSet<_> =
        parsed.iter().map(|announcement| announcement.device).collect();
    assert!(
        view.len() <= distinct.len(),
        "视图里的对端数不该超过输入里出现过的不同设备数"
    );
}
