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

//! fuzz 目标：从**图像**里解码二维码。
//!
//! # 这条路径为什么是不可信输入
//!
//! 「从图片导入」意味着用户会把一张**别人给的**图片交给应用：截图、聊天软件里存下来
//! 的图、从网页上拖下来的文件。图像解码是内存安全问题的传统高发区（越界、整数溢出、
//! 巨量分配），因此本目标把任意像素喂进去，盯住三件事：
//!
//! 1. **绝不 panic**——包括尺寸为 1×1、极端长宽比、以及噪声。
//! 2. **不因为一张图就吞掉内存**——尺寸由输入决定但**有界**（见 `MAX_SIDE`），
//!    否则 fuzz 的一轮就会变成一次大分配，目标本身变得不可用。
//! 3. **解得开就要能再编回去**——解码出的载荷经二维码再画一遍，必须读回同样的字节。
//!    这一条只在「随机像素真的解出了码」时才会执行，而那种情况极其罕见，因此它带来
//!    的额外代价可以忽略。

#![no_main]

use libfuzzer_sys::fuzz_target;
use qualia_transport::image::GrayImage;
use qualia_transport::qr::{self, EcLevel, QrProfile};

/// 图像边长的上界（像素）。
///
/// 定得很小是**刻意的**：二维码定位是逐像素的，图一大，单次执行就从微秒变成毫秒，
/// 覆盖速度掉几个数量级。真正需要担心的越界与溢出都发生在小尺寸的边界上（1×1、
/// 21×21、非方形），而不是大图上。
const MAX_SIDE: u32 = 48;

fuzz_target!(|data: &[u8]| {
    // 至少要有 2 个字节定尺寸、1 个字节当像素。
    if data.len() < 3 {
        return;
    }
    let width = 1 + u32::from(data[0]) % MAX_SIDE;
    let height = 1 + u32::from(data[1]) % MAX_SIDE;
    let needed = (width as usize) * (height as usize);
    // 像素不足时**循环复用**已有字节，而不是拒绝：这样任意长度的输入都能构造出一张
    // 完整尺寸的图，fuzzer 也不必先学会「把输入撑到 2304 字节」。
    let pixels: Vec<u8> = data[2..].iter().copied().cycle().take(needed).collect();
    let Ok(image) = GrayImage::from_luma8(width, height, pixels) else {
        // 尺寸由上面两个取模算出来，必然自洽；真走到这里说明构造逻辑坏了。
        panic!("构造出的图像尺寸与像素数不符");
    };

    // 唯一必须成立的性质：返回，而不是崩溃。
    let _ = qr::scan::decode_text(&image);

    let Ok(payload) = qr::scan::decode_payload(&image) else {
        return;
    };

    // 罕见路径：把读出来的载荷重新画成码、再读一遍。
    let profile = QrProfile::new(EcLevel::Low, 40).expect("版本合法");
    let Ok(symbol) = profile.encode_payload(&payload) else {
        // 装不下是正常的（画这张码的人可能用了别的参数），不是缺陷。
        return;
    };
    let rendered = symbol.render(4, 4).expect("渲染参数合法");
    let again = qr::scan::decode_payload(&rendered).expect("自己画的码必须读得回来");
    assert_eq!(again, payload, "解码再编码的往返不一致");
});
