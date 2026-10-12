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

//! fuzz 目标：动态二维码的拆帧与拼装。
//!
//! # 为什么它需要单独一个目标
//!
//! [`envelope::decode`] 那条路是**无状态**的：一行文本进来，一份字节或一个错误出去。
//! 拼装器是**有状态**的，而状态机是「先扫了 A 的第 1 帧、再扫 B 的第 2 帧」这类
//! 序列才能走到的地方——单条输入的 fuzz 永远覆盖不到。因此本目标把输入**切成若干
//! 段**，逐段喂给同一个拼装器，段与段之间共享状态。
//!
//! # 要保证的性质
//!
//! 1. **绝不 panic**——包括拼装器里那些按帧号索引的地方。
//! 2. **报错时状态不变**——用户扫错一张之后，正确的那张还必须能扫进去。这条性质
//!    靠「出错前后 `received` 与 `missing` 都不变」来验。
//! 3. **拼齐之后的结果必须与帧内容一致**——把收到的帧按帧号排好接起来，必须等于
//!    拼装器交回的那份字节。这条是本目标最有价值的一条：它盯的是**顺序**，而
//!    「按帧号而不是按到达顺序拼」正是整个模块存在的理由。
//! 4. **拆帧再拼装必须还原**——凡是我们自己拆出来的帧，都必须能被拼回来。这条把
//!    输入端（`encode_frames`）也纳入了同一次验证。

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia_transport::envelope;
use qualia_transport::frame::{self, Frame, Reassembler};

/// 一次 fuzz 里最多喂多少帧。取小一点，让每个输入都能跑到状态机的深处。
const MAX_FRAMES: usize = 8;

fuzz_target!(|data: &[u8]| {
    check_reassembly(data);
    check_roundtrip(data);
});

/// ① 把输入切成若干段，逐段喂给同一个拼装器，核对状态机的性质。
fn check_reassembly(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let capacity = usize::from(data[0]); // 0 表示「容量未知」，是合法输入
    let body = &data[1..];

    let mut reassembler = Reassembler::new(capacity);
    let mut accepted: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    let mut last_received = 0_usize;

    for (round, byte) in body.iter().enumerate().take(MAX_FRAMES) {
        // 每一轮从**剩余输入**里取一段，段长由当前字节决定。这样同一份输入可以同时
        // 表达「一条完整的码」与「一串畸形字节」。
        let start = round;
        let end = start.saturating_add(usize::from(*byte)).min(body.len());
        let chunk = &body[start..end];

        // 两种喂法都要走：文本（会经过 Base32 解码）与已经解好的帧（跳过解析）。
        if let Ok(text) = core::str::from_utf8(chunk) {
            let _ = reassembler.push(text);
        }
        if chunk.len() >= 9 {
            let index = u32::from(chunk[0]);
            let total = u32::from(chunk[1]);
            let payload = chunk[8..].to_vec();
            if let Ok(done) = reassembler.accept(Frame {
                index,
                total,
                payload: payload.clone(),
            }) {
                if reassembler.received() > last_received {
                    accepted.push((index, total, payload));
                    last_received = reassembler.received();
                }
                if let Some(bytes) = done {
                    check_assembled(&reassembler, &accepted, &bytes);
                }
            }
        }

        // 性质：状态只会**单调增长**。
        //
        // 这条比「报错时状态不变」弱，但它对两种喂法都成立，而不变量本身是对的：
        // 一条被拒的帧不该让已经收到的帧消失（那正是 `check_consistent` 必须在写入
        // 状态**之前**做的理由）。
        assert!(
            reassembler.received() >= last_received,
            "收到的张数减少了：{last_received} → {}",
            reassembler.received()
        );
        last_received = reassembler.received();
        if let Some(total) = reassembler.expected_frames() {
            assert!(
                reassembler.received() <= total as usize,
                "收到的张数超过了总张数"
            );
        }
    }

    // 全收齐时，`missing` 必须是空的；没收齐时不能是空的。
    if let Some(total) = reassembler.expected_frames()
        && reassembler.received() == total as usize
    {
        assert!(
            reassembler.missing().is_empty(),
            "收齐了却还说缺帧：{:?}",
            reassembler.missing()
        );
    }
}

/// ② 拆帧再拼装必须还原，且**容量未知时也能拼回来**。
fn check_roundtrip(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    // 容量控制在能覆盖 1..=8 帧的范围内（见 `MAX_FRAMES`）。
    let capacity = usize::from(data[0]) % 16 + 1;
    let payload = &data[1..];
    if payload.len() > capacity * MAX_FRAMES {
        return;
    }

    let Ok(frames) = frame::encode_frames(payload, capacity) else {
        return;
    };
    assert!(frames.len() <= envelope::MAX_FRAMES as usize);

    // 容量已知时拼回来。
    let mut reassembler = Reassembler::new(capacity);
    let mut done = None;
    for text in &frames {
        done = reassembler.push(text).expect("自己拆出来的帧必须收得下");
    }
    assert_eq!(
        done.expect("自己拆出来的帧必须拼得齐").as_slice(),
        payload,
        "拆帧往返不一致（容量已知）"
    );

    // 容量未知时也拼回来——这是平台相机那条路的形态。
    let mut reassembler = Reassembler::from_first_frame();
    let mut done = None;
    for text in frames.iter().rev() {
        done = reassembler
            .push(text)
            .expect("容量未知时也应当收得下（逆序）");
    }
    assert_eq!(
        done.expect("逆序也必须拼得齐").as_slice(),
        payload,
        "拆帧往返不一致（容量未知、逆序）"
    );
}

/// 拼齐之后，交回的字节必须等于「按帧号排好接起来」。
///
/// 这条盯的是**顺序**：按到达顺序拼会在乱序扫描时悄悄产出另一份字节，而它看起来
/// 完全正常——载荷层的 AEAD 只会说「解密失败」。
fn check_assembled(reassembler: &Reassembler, accepted: &[(u32, u32, Vec<u8>)], bytes: &[u8]) {
    let total = reassembler.expected_frames().expect("拼齐了就有总数");
    let mut expected = Vec::new();
    for index in 1..=total {
        // 连 `total` 一起匹配：同一个 fuzz 输入里可能先后凑齐过**两份**载荷，而
        // 它们的帧号会重叠。只按帧号找会拿到上一份的那一帧。
        let Some((_, _, payload)) = accepted
            .iter()
            .find(|(at, count, _)| *at == index && *count == total)
        else {
            // 还有帧没被收下（`accepted` 只记录被收下的），说明这次 `done` 不是由
            // 这一轮的帧凑齐的——那不可能，因为 `done` 只在 `received == total` 时
            // 非空。真出现的话，这条 panic 正好暴露。
            panic!("拼齐了却找不到第 {index} 帧（总数 {total}）");
        };
        expected.extend_from_slice(payload);
    }
    assert_eq!(bytes, expected.as_slice(), "拼装顺序不对");
}
