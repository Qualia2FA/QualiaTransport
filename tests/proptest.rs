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

//! 属性测试：对**任意**输入成立的性质。
//!
//! 与 `tests/roundtrip.rs` 的分工：那里的用例是挑出来的典型形状（最短、中间、刚好
//! 装满），这里试图证伪「对任意输入都成立」。两者都要有——挑出来的用例证明不了普遍
//! 性，而随机用例永远覆盖不到边界。

use proptest::prelude::*;
use qualia_transport::envelope;
use qualia_transport::frame::{self, Reassembler};
// 只被二维码闭环那条性质用到；关掉图像解码时它不该留在文件里当未使用导入
// （CI 的 `-D warnings` 会把「未使用导入」变成错误，而这正是我们想要的严格程度）。
#[cfg(feature = "scan-image")]
use qualia_transport::Error;
#[cfg(feature = "scan-image")]
use qualia_transport::qr::{EcLevel, QrProfile};

/// 任意字节串（有界长度）。
///
/// 上界取 512：信封本身与长度无关地工作，而真正受长度影响的二维码有单独的属性测试，
/// 那里用的是小得多的界（见 `qr_round_trip`）。
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..512)
}

/// 任意文本，刻意包含大量非 ASCII 与不可打印字符。
fn arb_text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..64).prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    /// 信封必须对任意字节串精确往返。
    #[test]
    fn envelope_round_trips(payload in arb_bytes()) {
        let text = envelope::encode(&payload);
        let decoded = envelope::decode(&text).expect("自己编出来的必须解得开");
        prop_assert_eq!(decoded, payload);
    }

    /// **任意**文本都不得让解码 panic——它直接来自扫码器，属于攻击者可控输入。
    ///
    /// 同时钉住弱一点的那条性质：一旦解开，就必须是**规范写法**（再编回去再解一次，
    /// 结果不变）。否则同一份载荷会有多个合法文本，而重放记账与去重都靠文本相等。
    #[test]
    fn envelope_decode_never_panics(text in arb_text()) {
        if let Ok(payload) = envelope::decode(&text) {
            let canonical = envelope::encode(&payload);
            let again = envelope::decode(&canonical).expect("规范写法必须解得开");
            prop_assert_eq!(again, payload);
        }
    }

    /// 把任意文本塞进合法帧头之后，同样不得 panic。
    ///
    /// 这一条比上一条更接近真实攻击面：扫到的码**总是**有一个合法前缀（前缀是我们
    /// 自己检查的，攻击者当然会带上它），因此深层解析路径必须自己扛住任意内容。
    #[test]
    fn envelope_decode_never_panics_behind_a_valid_prefix(inner in arb_text()) {
        let text = format!("Q2FA1:1/1:{inner}");
        let _ = envelope::decode(&text);
    }

    /// 编解码闭环：任意小载荷经二维码画出来、再读回来，必须一字不差。
    ///
    /// 长度上界刻意压得很小（32 字节）：这一条要跑真实的像素渲染与二维码定位，每次
    /// 用例都要几毫秒，把上界放大只会拖慢测试而不会多发现什么——大载荷由
    /// `tests/roundtrip.rs` 里的定长用例覆盖。
    #[cfg(feature = "scan-image")]
    #[test]
    fn qr_round_trips(payload in prop::collection::vec(any::<u8>(), 0..32)) {
        let profile = QrProfile::new(EcLevel::Low, 5).expect("版本合法");
        match profile.encode_payload(&payload) {
            Ok(symbol) => {
                let image = symbol.render(4, 4).expect("渲染参数合法");
                let decoded = qualia_transport::qr::scan::decode_payload(&image)
                    .expect("画出来的码必须读得回来");
                prop_assert_eq!(decoded, payload);
            }
            // 装不下是允许的（这条通道很小），但**只允许**这一种失败。
            Err(Error::PayloadTooLarge { .. }) => {}
            Err(other) => prop_assert!(false, "不该出现的失败：{}", other),
        }
    }

    /// **任意载荷、任意容量**：拆帧 → 逐张喂给拼装器 → 逐字节还原。
    ///
    /// 顺序刻意用倒序，并重复喂第一张：用户扫的时候既不保证顺序，也可能同一张扫到
    /// 两次。这两件事都不该改变结果。
    ///
    /// 载荷长度包含 0：空载荷是一张 `Q2FA1:1/1:`，它必须能原样拼回来（拆帧侧编得出
    /// 来的，拼装侧就一定收得下——这条性质由两侧共同钉住）。
    #[test]
    fn frames_round_trip_through_the_reassembler(
        payload in arb_bytes(),
        capacity in 1_usize..64,
    ) {
        // 帧数上限是格式的一部分：超过它的输入不属于这条性质（那条路径由
        // `frame` 模块自己的定长用例覆盖）。
        prop_assume!(payload.len().div_ceil(capacity) <= envelope::MAX_FRAMES as usize);

        let frames = frame::encode_frames(&payload, capacity).expect("帧数在上限之内");
        let expected_frames = payload.len().div_ceil(capacity).max(1);
        prop_assert_eq!(frames.len(), expected_frames);

        // 倒序 + 重复第一张。
        let mut reassembler = Reassembler::from_first_frame();
        let mut done = None;
        for text in frames.iter().rev() {
            done = reassembler.push(text).expect("自己拆出来的帧必须收得下");
        }
        prop_assert_eq!(reassembler.received(), expected_frames);
        if expected_frames > 1 {
            // 多帧时「满载帧多长」必须已经被观察到；单帧时没有满载帧可言（`1/1` 的
            // 那一张就是全部），因此那一条不适用。
            prop_assert!(reassembler.unit_len().is_some(), "多帧时应当观察到满载长度");
        }
        let repeated = reassembler.push(&frames[0]).expect("重复扫不算错");
        prop_assert!(repeated.is_none(), "齐了之后再扫不该又交出一份");
        prop_assert_eq!(reassembler.received(), expected_frames, "重复不该改变计数");
        prop_assert_eq!(done.expect("应当拼齐"), payload.as_slice());

        // 容量已知时同样要还原（`new` 多一条上界检查，其余规则一致）。
        let mut reassembler = Reassembler::new(capacity);
        let mut done = None;
        for text in &frames {
            done = reassembler.push(text).expect("按容量拆的帧必须收得下");
        }
        prop_assert_eq!(done.expect("应当拼齐"), payload);
    }

    /// 拆出来的每一帧文本都**只**落在二维码的字母数字模式里。
    ///
    /// 这条性质在多帧上比单帧更要紧：帧头会随帧号变长（`1/100`、`255/255`），而一旦
    /// 某个字符不在那 45 个字符里，整张码就会退回字节模式——界面上看不出异常，只是
    /// 码变大了、更难扫了，而容量表也不再成立。
    #[test]
    fn frame_texts_stay_inside_the_alphanumeric_charset(
        payload in prop::collection::vec(any::<u8>(), 0..200),
        capacity in 1_usize..8,
    ) {
        const ALPHANUMERIC: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
        prop_assume!(payload.len().div_ceil(capacity) <= envelope::MAX_FRAMES as usize);

        let frames = frame::encode_frames(&payload, capacity).expect("帧数在上限之内");
        // 载荷给到 200 字节、容量给到 1，帧号与帧数必然出现过三位数。
        prop_assert!(
            frames.iter().all(|text| text
                .chars()
                .all(|character| ALPHANUMERIC.contains(character))),
            "帧文本里出现了字母数字模式之外的字符"
        );
    }

    /// **任意文本**都不得让拼装器 panic，也不得让它凭空交出一份载荷。
    ///
    /// 它是攻击者可控输入的入口（扫到的文本直接进来），而 `Reassembler` 是**有状态**
    /// 的：这一条只喂一条文本，状态机那条路由 `fuzz/fuzz_targets/frame_reassemble.rs`
    /// 覆盖（那里的输入被切成若干段，逐段喂同一个拼装器）。
    #[test]
    fn reassembler_never_panics_on_arbitrary_text(text in arb_text()) {
        let mut reassembler = Reassembler::from_first_frame();
        if let Ok(Some(bytes)) = reassembler.push(&text) {
            // 一条文本就凑齐，只可能是「单帧」——那它解出的就是这一帧的内容。
            let frame = frame::decode_frame(&text).expect("刚解开过的文本必须解得开");
            prop_assert_eq!(frame.total, 1);
            prop_assert_eq!(bytes, frame.payload);
        }
        // 无论输入是什么，拼装器都不该声称收到过不存在的东西。
        prop_assert!(reassembler.received() <= 1);
    }
}
