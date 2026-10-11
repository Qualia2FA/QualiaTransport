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
}
