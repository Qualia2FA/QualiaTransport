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

//! RFC 4648 §6 的 Base32（大写字母表）。
//!
//! # 为什么自己写而不依赖现成的 crate
//!
//! 本 crate 的编解码层刻意保持**零依赖**：二维码信封是本项目自定义的线格式，它的
//! 每一个字节都该能在一屏之内读完（见 [`crate::envelope`]）。引一个通用 Base32
//! crate 只会把「同一份 RFC 有两种细微不同的解释」这个风险搬进来。
//!
//! # 为什么是 Base32 而不是 Base64
//!
//! 二维码的**字母数字模式**只接受 45 个字符：`0`–`9`、`A`–`Z`、空格与
//! `$ % * + - . / :`。Base64 的小写字母不在其中，于是它只能走字节模式，每个载荷
//! 字节要花 10.67 位；而 Base32 的大写字母与数字**全部落在**字母数字模式里，每个载荷
//! 字节只花 8.8 位。两者相差约 10%，而 Base32 还额外赢在两处：
//!
//! - **抄写不会错**：字母表不含 `0`/`1`/`8`/`9`，因此没有 `0`/`O`、`1`/`I` 的歧义。
//! - **大小写无关**：文本经过剪贴板、聊天软件或 OCR 之后仍然解得开。

use crate::error::{Error, Result};

/// RFC 4648 §6 的字母表：`A`–`Z` 后接 `2`–`7`。
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 把字节编成 Base32 文本：大写、**不带填充**。
///
/// 不写 `=` 是因为填充不携带任何信息（长度由文本长度本身决定），而二维码是按字符
/// 计费的：每 5 个字节就白白多出 1–6 个字符的填充。
pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    // 累积器只保留未消费的低位，因此它的宽度**永远不超过 12 位**（最多 4 位残留 + 8 位
    // 新字节）。若不清掉已消费的高位，移位会在第 5 个字节上溢出 u32——debug 构建直接
    // panic，而那正是「任何输入都不得导致 panic」要挡住的东西。
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(
                ALPHABET[((accumulator >> bits) & 0x1f) as usize],
            ));
        }
        accumulator &= (1_u32 << bits) - 1;
    }
    if bits > 0 {
        // 末尾不足 5 位时**左移补零**（补在低位），这样解出来的尾比特必然是 0。
        out.push(char::from(
            ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize],
        ));
    }
    out
}

/// 把 Base32 文本解回字节。
///
/// 刻意宽容的三处，与核心库的 `base32` 保持一致：
///
/// 1. **大小写不敏感**——文本可能经过剪贴板、聊天软件、OCR。
/// 2. **容忍尾部填充**——有的扫码器会补上 `=`。
/// 3. **容忍首尾空白**——有的扫码器会在末尾多给一个换行。
///
/// 刻意严格的两处：
///
/// 1. **非法长度必须拒绝**。Base32 的长度余数只能是 0/2/4/5/7；余数 1/3/6 的文本
///    不可能由任何字节串编出来。
/// 2. **非零尾比特必须拒绝**。否则同一份字节会有多个合法文本，而「这两张码是不是
///    同一张」就变成一个没有答案的问题——去重、重放记账全都要靠文本相等来判断。
pub(crate) fn decode(text: &str) -> Result<Vec<u8>> {
    let body = text.trim().trim_end_matches('=');
    let mut out = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in body.bytes() {
        let value = symbol_value(byte).ok_or(Error::MalformedBase32)?;
        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xff) as u8);
        }
        accumulator &= (1_u32 << bits) - 1;
    }
    // 走到这里 `bits` 至多 7。留下 5 位以上说明长度本身非法（余数 1/3/6），
    // 而留下非零的低位说明这不是规范写法——两者都不是「合法的另一种写法」。
    if bits >= 5 || accumulator != 0 {
        return Err(Error::MalformedBase32);
    }
    Ok(out)
}

/// 把单个字符映射成 5 位的值；不在字母表里就返回 `None`。
fn symbol_value(byte: u8) -> Option<u8> {
    match byte.to_ascii_uppercase() {
        upper @ b'A'..=b'Z' => Some(upper - b'A'),
        digit @ b'2'..=b'7' => Some(digit - b'2' + 26),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10 的 Base32 测试向量（去掉填充后的形式）。
    ///
    /// 用规范正文的向量而不是「自己编出来再自己解开」：后者对「整条实现错掉」完全盲
    /// ——两边同时把 `2`–`7` 映射错，往返测试照样是绿的。
    #[test]
    fn rfc4648_vectors() {
        let vectors: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ];
        for (data, expected) in vectors {
            assert_eq!(
                encode(data),
                *expected,
                "编码与 RFC 4648 §10 不符：{data:?}"
            );
            assert_eq!(
                decode(expected).expect("规范向量必须解得开"),
                *data,
                "解码与 RFC 4648 §10 不符：{expected}"
            );
        }
    }

    /// 带填充的写法与全小写的写法都必须能解开。
    #[test]
    fn padded_and_lowercase_forms_decode() {
        assert_eq!(
            decode("MZXW6YTBOI======").expect("填充合法"),
            b"foobar",
            "带填充的规范写法应当解得开"
        );
        assert_eq!(
            decode("mzxw6ytboi").expect("小写合法"),
            b"foobar",
            "大小写不敏感"
        );
        assert_eq!(decode("  MZXW6  ").expect("空白合法"), b"foo");
    }

    /// 长度余数为 1/3/6 的文本不可能由任何字节串编出来，必须拒绝。
    #[test]
    fn rejects_impossible_lengths() {
        for text in ["A", "AAA", "AAAAAA"] {
            assert!(decode(text).is_err(), "长度非法的文本被接受了：{text:?}");
        }
    }

    /// 非零尾比特必须拒绝。`MY` 与 `MZ` 都解出 `f`，但只有前者是规范写法。
    #[test]
    fn rejects_non_canonical_tail_bits() {
        assert_eq!(decode("MY").expect("规范写法"), b"f");
        assert!(
            decode("MZ").is_err(),
            "把尾比特改一位就得到另一个文本，它必须被拒绝——否则同一份字节有多个\
             合法写法，去重与重放记账就失去依据"
        );
    }

    /// 字母表之外的字符一律拒绝，尤其不能把 `0`/`1`/`8`/`9` 当成合法值。
    #[test]
    fn rejects_characters_outside_the_alphabet() {
        for text in ["M0", "M1", "M8", "M9", "M!", "M ", "M-", "M_", "Mé"] {
            assert!(decode(text).is_err(), "非法字符被接受了：{text:?}");
        }
    }

    /// 空文本解出空字节串。这不是「非法输入」，而是「零长度的载荷」——是否接受它
    /// 由上层判断（本 crate 不替它决定）。
    #[test]
    fn empty_text_decodes_to_empty_bytes() {
        assert_eq!(decode("").expect("空载荷"), b"");
        assert_eq!(encode(&[]), "");
    }
}
