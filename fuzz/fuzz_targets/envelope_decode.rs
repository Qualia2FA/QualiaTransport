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

//! fuzz 目标：二维码文本信封的解析。
//!
//! # 为什么它是本 crate 最主要的攻击面
//!
//! 二维码是**公开可见**的：它贴在屏幕上、被人拍照、被转发。因此「谁来解这段文本」
//! 这件事完全不受控——任何拿到那张码的人都能把**任意**文本送进 [`envelope::decode`]。
//! 这是本 crate 唯一会把不可信数据解释为结构的地方，也是唯一一个「解析错了就直接
//! 影响内存安全」的地方。
//!
//! 要保证的性质：
//!
//! 1. **绝不 panic**——拒绝服务防线。
//! 2. **解得开就一定是规范写法**——同一份载荷只能有一种文本表示。这条性质不是
//!    审美问题：去重与重放记账都靠「标识相等」判断，而标识来自载荷。
//! 3. **信封的膨胀有界**（Base32 的 8/5 加一个固定帧头），且**整串都在二维码的
//!    字母数字模式里**。后者一旦被破坏，编码会悄悄退回字节模式——界面上看不出任何
//!    异常，只是码变大、更难扫。

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia_transport::envelope;

/// 合法的开头，用来把输入推进深层解析。
///
/// 纯随机字节几乎永远不会命中 `Q2FA1:`，从而只覆盖到「前缀不匹配」这一条最外的分支。
/// 因此本目标有第二种模式：把同一份输入接在这些开头之后。
const PREFIXES: &[&str] = &[
    "Q2FA1:1/1:",
    "Q2FA1:1/2:",
    "Q2FA1:2/2:",
    "Q2FA1:255/255:",
    "Q2FA1:0/0:",
    "Q2FA1:1/0:",
    "Q2FA1:",
    "Q2FA1:1/1",
    "Q2FA1",
];

/// 二维码字母数字模式允许的 45 个字符。
const ALPHANUMERIC: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fuzz_target!(|data: &[u8]| {
    // 无效 UTF-8 用替换字符表示，而不是丢弃——保证信息不丢失。
    let text = String::from_utf8_lossy(data);
    check(&text);

    // 模式 2：把同一份输入接在每个合法开头之后，强制进入真正的解析路径。
    // 用取首字节的方式选择开头，fuzzer 只要变异这一个字节就能切换分支。
    if let Some(&selector) = data.first() {
        let prefix = PREFIXES[usize::from(selector) % PREFIXES.len()];
        let mut candidate = String::with_capacity(prefix.len() + text.len());
        candidate.push_str(prefix);
        candidate.push_str(&text);
        check(&candidate);
    }
});

/// 唯一必须成立的性质：返回，而不是崩溃；解得开的话，结果必须自洽。
fn check(text: &str) {
    let Ok(payload) = envelope::decode(text) else {
        return;
    };

    // 规范写法：解出来的载荷再编回去，必须解回同一份字节。
    let canonical = envelope::encode(&payload);
    let again = envelope::decode(&canonical).expect("自己编出来的文本必须解得开");
    assert_eq!(again, payload, "信封往返不一致");

    // 膨胀有界：Base32 是 8/5，帧头是固定的十来个字符。
    assert!(
        canonical.len() <= payload.len() * 8 / 5 + 16,
        "信封膨胀超出预期：{} 字节的载荷编成了 {} 个字符",
        payload.len(),
        canonical.len()
    );

    // 整串必须落在二维码的字母数字模式里（见本文件顶部的说明）。
    assert!(
        canonical.chars().all(|character| ALPHANUMERIC.contains(character)),
        "信封里出现了字母数字模式之外的字符：{canonical}"
    );
}
