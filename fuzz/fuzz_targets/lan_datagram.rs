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

//! fuzz 目标：局域网大厅的报文与连接信息解析。
//!
//! # 为什么这条输入面比二维码那条更宽
//!
//! 二维码要有人**拍到**它才能把数据送进来，而组播组是**共享介质**：同一个网段上
//! 任何一台机器都能往 `239.255.81.65:21377` 灌任意字节，不需要任何前提。大厅的后台
//! 线程会把这些字节一条条喂给 [`Announcement::decode`]——也就是说，这是本 crate 里
//! **唯一一条由陌生人在网络上直接驱动的解析路径**。
//!
//! 第二条路径是 [`LanAddress::decode`]：它解的是二维码里那段文本，而二维码是公开的。
//!
//! # 要保证的性质
//!
//! 1. **绝不 panic**——这是本目标的主要目的。定长解析里每一处按偏移切片都是候选：
//!    长度检查与切片之间的顺序一旦写错，就是一个可以被一条 20 字节的报文触发的崩溃。
//! 2. **解析出来的一定能原样编回去**——线格式必须只有一种表示。这条性质不是审美：
//!    「这条公告是不是刚才那条」完全靠字段相等判断，而两种字节表示同一个公告会让
//!    序号去重出现空隙。
//! 3. **重复与乱序不改变结果**——同一个公告集合多喂一遍，视图不变。组播不保证顺序，
//!    也不保证不重复，因此这是真实网络上必需的性质。
//! 4. **压力下视图有界**——报文里带的是 32 字节的设备标识，因此每条报文都可能是一个
//!    「新设备」。视图必须只保留固定数量的对端，否则同网段的一台机器只要不停发公告
//!    就能把我们的内存吃光。

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia_transport::lan::{LanAddress, wire};

/// 报文长度：与 [`wire::DATAGRAM_LEN`] 一致。
const DATAGRAM_LEN: usize = wire::DATAGRAM_LEN;

fuzz_target!(|data: &[u8]| {
    // ① 整段当一条公告。
    check_announcement(data);

    // ② 整段当一条连接信息。
    check_address(data);

    // ③ 按输入里的字节切分成多条公告，顺序喂给同一个视图。
    //
    //    这是本目标的主要模式：单条报文只能覆盖解析器，而**视图的归并**要一串报文
    //    才能走到。切分点由输入决定，因此 fuzzer 可以自由构造「重复、乱序、长度不齐」
    //    这些组播上真实会出现的序列。
    check_view(data);
});

/// 解析一条公告，并核对往返一致。
fn check_announcement(data: &[u8]) {
    let Ok(announcement) = wire::Announcement::decode(data) else {
        return;
    };

    // 规范表示：再编一遍必须解回同一个结构，且字节完全相同。
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

/// 解析一条连接信息，并核对往返一致。
fn check_address(data: &[u8]) {
    let Ok(address) = LanAddress::decode(data) else {
        return;
    };

    let encoded = address.encode();
    let again = LanAddress::decode(&encoded).expect("自己编出来的必须解得开");
    assert_eq!(again, address, "连接信息往返不一致");
    assert_eq!(again.encode(), encoded, "往返之后字节必须完全相同");
    // 端口 0 是被明确拒绝的状态，因此解出来的东西不可能带着它。
    assert_ne!(address.port, 0, "端口 0 不该被解出来");
}

/// 把输入切成若干条公告，喂给同一个视图，核对归并的性质。
fn check_view(data: &[u8]) {
    let mut view = wire::LanView::new();

    // 两种切法都要跑：「报文边界不对」是一个真实存在的输入形状。
    // 定长切模拟「一串报文连在一起」，变长切模拟「长度字段被改了」。
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

    // 性质 A：视图里每个对端的序号水位，必须等于它那些公告里最大的那个。
    //
    // 这里**不**用「`now_ms` 恒为 0 因此不会过期」来省掉这一条：`observe` 的语义
    // 就是「新序号才更新」，而它是序号去重的全部实现。
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

    // 性质 B：把同一批公告再喂一遍，视图**逐字段不变**（幂等）。
    let before = view.all();
    for announcement in &parsed {
        view.observe(*announcement, 0);
    }
    assert_eq!(view.all(), before, "重复喂同一批公告不得改变视图");

    // 性质 C：视图有界，且不可能超过「输入里出现过的不同设备数」。
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
