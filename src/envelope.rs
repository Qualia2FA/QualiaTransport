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

//! 二维码承载的**文本信封**：把一串字节变成一串能放进二维码的文本，再变回来。
//!
//! # 格式（版本 1）
//!
//! ```text
//! Q2FA1:<帧号>/<帧数>:<BASE32>
//! ```
//!
//! 单帧时是 `Q2FA1:1/1:MZXW6`（这一串本身是 RFC 4648 的示例向量，不是任何真实载荷）。
//!
//! # 每一段的理由
//!
//! - **`Q2FA1:` 前缀**。扫码器读回来的可能是任何东西：别人家的二维码、一个网址、
//!   一张名片。前缀让「这不是本应用的码」一眼可判，而不是先解一遍 Base32、再报一个
//!   「载荷坏了」——后者会把用户引向完全错误的方向（以为要重扫，其实是扫错了）。
//! - **整串只落在二维码的字母数字模式里**。`Q`、`2`、`F`、`A`、`1`、`:`、`/` 与
//!   Base32 的大写字母和数字都在那 45 个字符的表内，因此整张码只用一种模式编码。
//!   这是**选 Base32 而不是 Base64 的真正原因**：Base32 的字母表完全落在二维码的
//!   字母数字模式里（那 45 个字符），而 Base64 的小写字母不在其中。详见 `base32`
//!   模块的文档——那是私有模块，因此这里只能写成代码字体，做不了文档链接。
//! - **帧号/帧数写在 Base32 之前**。将来做「动态二维码」（一张码装不下时连续显示多
//!   张）时，扫描方**不需要解开任何一帧的载荷**就能知道还差哪几帧。字段现在就有，
//!   是为了让那个格式升级不必再破一次线格式——**单帧的写法就是 `1/1`**。
//! - **不做校验和**。载荷本身在协议层由 AEAD 认证，信封再加一层校验和只会造成
//!   「校验过了所以它是真的」这种误读。信封只负责**表示**，不负责**认证**：
//!   它防的是抄错字符，不是伪造。
//!
//! # 为什么不让二维码直接携带字节
//!
//! 二维码的字节模式确实能原样携带任意字节，代价是**只有本 crate 自己解得出**：
//! 平台相机（ML Kit、AVFoundation）交回的是字符串，剪贴板里只能放文本，人眼抄下来
//! 的更只能是文本。走文本信封要多花约 10% 的容量，换来的是「任何扫码器读出来的都是
//! 同一串文本」——而二维码这条路的用户正是拿着各种扫码器的人。

use crate::base32;
use crate::error::{Error, Result};

/// 信封前缀。**大小写敏感**：它是我们自己生成的，只有机器经手。
const PREFIX: &str = "Q2FA1";

/// 帧数上限。
///
/// 255 是个务实的选择：一帧至少要能装下信封头（约 10 个字符），而二维码在最小的
/// 版本 1 上也有 17 个字符的字母数字容量；255 帧已经远超任何可用的动态二维码序列
/// （用户要连续扫 255 次本身就是不可接受的产品行为）。
pub const MAX_FRAMES: u32 = 255;

/// 把载荷编成二维码可承载的文本（单帧）。
///
/// 空载荷会编成 `Q2FA1:1/1:`——格式上合法，但**没有意义**：没有任何协议消息是空的。
/// 是否接受它由上层判断，信封不替它决定（见 [`decode`] 的说明）。
#[must_use]
pub fn encode(payload: &[u8]) -> String {
    let encoded = base32::encode(payload);
    let mut text = String::with_capacity(PREFIX.len() + 8 + encoded.len());
    text.push_str(PREFIX);
    text.push_str(":1/1:");
    text.push_str(&encoded);
    text
}

/// 把二维码承载的文本解回载荷。
///
/// # 宽容与严格
///
/// 宽容：首尾空白。有的扫码器会在文本末尾多给一个换行，而那不是用户能控制的事。
///
/// 严格：**前导零**（`01/1` 不是规范写法）、**帧号越界**（`2/1`）、以及 Base32 的
/// 一切非规范写法。理由与 Base32 那一层相同：同一份载荷必须只有一种文本表示，否则
/// 「这两张码是不是同一张」就没有答案，而重放记账正是靠文本/载荷标识相等来判断的。
///
/// # 错误
///
/// - [`Error::NotOurQrText`]：前缀不对（扫到了别家的码）。
/// - [`Error::MalformedFrameHeader`]：前缀对，但帧头不合法。
/// - [`Error::MultiFrameUnsupported`]：这张码是多帧的，而当前只实现单帧。
/// - [`Error::MalformedBase32`]：Base32 载荷不合法。
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    let rest = text.strip_prefix(PREFIX).ok_or(Error::NotOurQrText)?;
    let rest = rest.strip_prefix(':').ok_or(Error::NotOurQrText)?;
    let (header, body) = rest.split_once(':').ok_or(Error::MalformedFrameHeader)?;
    let (index, count) = header.split_once('/').ok_or(Error::MalformedFrameHeader)?;
    let index = parse_decimal(index).ok_or(Error::MalformedFrameHeader)?;
    let count = parse_decimal(count).ok_or(Error::MalformedFrameHeader)?;

    if count == 1 {
        if index != 1 {
            return Err(Error::MalformedFrameHeader);
        }
    } else if (2..=MAX_FRAMES).contains(&count) && (1..=count).contains(&index) {
        // 结构与范围都对，只是这一版还没实现拼装。**如实报告**，不要假装是坏输入：
        // 将来实现多帧时，正是这个错误告诉我们「这段文本确实是我们写的」。
        return Err(Error::MultiFrameUnsupported { count });
    } else {
        return Err(Error::MalformedFrameHeader);
    }

    base32::decode(body)
}

/// 解析一个十进制字段：非空、无前导零、全为数字、不超过 9 位。
///
/// 9 位的上限是**为了不依赖溢出来拒绝输入**：`u32` 的十进制最长 10 位，而本格式里的
/// 两个字段都远小于这个数，截到 9 位既留足余量，又让「超长数字」在解析前就被拒绝。
fn parse_decimal(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 9 || text.starts_with('0') {
        return None;
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 格式必须逐字节钉住。
    ///
    /// 这里刻意**手写**期望的文本，而不是调用 [`encode`] 与 [`decode`] 互相对照：
    /// 后者只能证明「编码与解码自洽」，对「两边一起改错」完全盲——而线格式一旦发出去
    /// 就改不动了。
    #[test]
    fn wire_format_is_pinned() {
        assert_eq!(encode(b"foo"), "Q2FA1:1/1:MZXW6");
        assert_eq!(encode(b"foobar"), "Q2FA1:1/1:MZXW6YTBOI");
        assert_eq!(encode(b"f"), "Q2FA1:1/1:MY");
        assert_eq!(encode(b""), "Q2FA1:1/1:");
        assert_eq!(decode("Q2FA1:1/1:MZXW6").expect("规范写法"), b"foo");
    }

    #[test]
    fn round_trips_arbitrary_bytes() {
        for len in [0_usize, 1, 5, 6, 31, 64, 255, 1024] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let text = encode(&payload);
            assert_eq!(decode(&text).expect("自己编的必须解得开"), payload);
        }
    }

    /// 别的二维码必须被报成「不是我们的码」，而不是「载荷坏了」。
    #[test]
    fn other_peoples_codes_are_recognized_as_foreign() {
        for text in [
            "",
            "https://example.com",
            "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP",
            "Q2FA",
            "Q2FA1",
            // 前缀大小写敏感：它是机器生成的，只有机器经手。
            "q2fa1:1/1:MZXW6",
            "X2FA1:1/1:MZXW6",
        ] {
            let result = decode(text);
            let is_foreign = matches!(result, Err(Error::NotOurQrText));
            assert!(is_foreign, "应当报「不是本应用的码」，实际 {result:?}");
        }
    }

    #[test]
    fn malformed_frame_headers_are_rejected() {
        for text in [
            "Q2FA1:1/1",              // 缺载荷分隔符
            "Q2FA1:1:MZXW6",          // 缺帧数
            "Q2FA1:/1:MZXW6",         // 帧号为空
            "Q2FA1:1/:MZXW6",         // 帧数为空
            "Q2FA1:01/1:MY",          // 前导零
            "Q2FA1:1/01:MY",          // 前导零
            "Q2FA1:0/1:MY",           // 帧号从 1 开始
            "Q2FA1:1/0:MY",           // 帧数至少是 1
            "Q2FA1:2/1:MY",           // 帧号大于帧数
            "Q2FA1:3/2:MY",           // 帧号越界
            "Q2FA1:1/256:MY",         // 超出帧数上限
            "Q2FA1:1/99999999999:MY", // 字段过长
            "Q2FA1:1/1x:MY",
            "Q2FA1: 1/1:MY",
        ] {
            let result = decode(text);
            let is_malformed = matches!(result, Err(Error::MalformedFrameHeader));
            assert!(is_malformed, "应当报帧头不合法，实际 {result:?}");
        }
    }

    /// 多帧是**计划中的格式**，不是坏输入：它必须与「帧头不合法」分开报。
    #[test]
    fn multi_frame_is_reported_as_unsupported_not_malformed() {
        let result = decode("Q2FA1:1/2:MZXW6");
        let expected = matches!(result, Err(Error::MultiFrameUnsupported { count: 2 }));
        assert!(expected, "2 帧应当报「尚未支持」，实际 {result:?}");

        // 边界：255 帧是格式允许的最大值，仍然报「尚未支持」。
        let result = decode("Q2FA1:255/255:MY");
        let expected = matches!(result, Err(Error::MultiFrameUnsupported { count: 255 }));
        assert!(expected, "255 帧应当是合法帧头，实际 {result:?}");
    }

    #[test]
    fn bad_base32_is_reported_as_such() {
        for text in [
            "Q2FA1:1/1:M0",    // 0 不在字母表里
            "Q2FA1:1/1:M",     // 长度不可能
            "Q2FA1:1/1:MZ",    // 非零尾比特
            "Q2FA1:1/1:MZ:W6", // 载荷里混进了分隔符
        ] {
            let result = decode(text);
            let is_base32 = matches!(result, Err(Error::MalformedBase32));
            assert!(is_base32, "应当报 Base32 不合法，实际 {result:?}");
        }
    }

    /// 扫码器多给的换行不该让用户看到「这不是本应用的码」。
    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(decode("  Q2FA1:1/1:MZXW6\n").expect("空白宽容"), b"foo");
        assert_eq!(decode("\tQ2FA1:1/1:MY ").expect("空白宽容"), b"f");
    }
}
