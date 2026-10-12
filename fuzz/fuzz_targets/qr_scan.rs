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
//!
//!    这一条**曾经真的不成立**：周期性噪声会让解码器（`rqrr`）内部的透视变换算出
//!    极大值，撞上它自己的 `assert!`。触发它只需要几十字节的输入（43×43 的循环像素），
//!    而这个目标在 2.7 万次执行内就找到了第一张这样的图。
//!
//!    本 crate 随后把每一次解码器调用包进了 `catch_unwind`，panic 变成
//!    [`Error::QrDecoderPanicked`]（见该变体的说明），回归测试是
//!    `tests/roundtrip.rs` 的 `a_pathological_image_does_not_take_the_process_down`。
//!    因此这个目标现在盯的是**新的**那种 panic。
//!
//!    ⚠️ 两处与 fuzz 环境有关的边界，都会让人误判「修了也没用」：`libfuzzer-sys` 的
//!    panic hook 在展开前就 abort（见 [`loosen_panic_hook`]），而 Windows 上 libFuzzer
//!    的异常处理器会把 Rust 的 SEH 抛出当成崩溃。**本机（Windows）看到这个目标报崩溃，
//!    不等于收敛没生效**——那件事由 `cargo test` 与 CI 的 Linux fuzz job 负责确认。
//!
//!    还有一处刻意的取舍：**收敛过的 panic 在这个目标里不算崩溃**。把它重新抛出来能
//!    让上游缺陷继续可见，代价是这一关会**长期红着**（上游一天不修就红一天），而长期
//!    红的关卡只会被无视。可见性改由别处提供：应用侧会把
//!    [`Error::QrDecoderPanicked`] 写进日志，而那个 panic 自己的那句话仍会由默认 hook
//!    打到 stderr 上。
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

/// 让库里的 `catch_unwind` 真正起作用。
///
/// # 为什么非做不可
///
/// `libfuzzer-sys` 注册了一个 panic hook，它在**展开之前**直接 `abort`——那是为了让
/// libFuzzer 拿到完整的调用栈给崩溃去重（上游源码里写着这个理由）。代价是：**库里
/// 已经收敛掉的 panic 在这里看起来仍然是一次崩溃**，因为 hook 根本不给 `catch_unwind`
/// 展开的机会。而 `qr_scan` 恰恰要覆盖一条已知会让上游 panic 的路径（`rqrr` 的断言）。
///
/// # 已知的边界
///
/// 在 **Windows** 上换掉这个 hook 也**不够**：Rust 的 panic 在那里以 SEH 异常的形式
/// 抛出，而 libFuzzer 自己有一个进程级的异常处理器，它会把这次抛出当成崩溃。
/// 也就是说：本机（Windows）跑 `qr_scan` 时，「已经收敛的 panic」仍会表现为一次崩溃，
/// 而 CI 的 fuzz job 在 Linux 上——那里 panic 不发信号，收敛照常生效。想在本机确认
/// 「收敛有效」，看的是 `cargo test`（`tests/roundtrip.rs` 里那条回归测试），不是这个
/// 目标。
///
/// # 换掉之后损失了什么
///
/// 没被收敛的 panic 仍然是一次崩溃：libfuzzer-sys 外层的 `catch_unwind` 接不住时自己
/// `abort`，libFuzzer 照样记录输入。丢掉的是**那一份展开前的调用栈**，而输入样本仍在，
/// 复现一次就有栈了。这里保留一行 `eprintln!`，至少 panic 的那句话不会消失。
fn loosen_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| eprintln!("panicked: {info}")));
    });
}

fuzz_target!(|data: &[u8]| {
    loosen_panic_hook();
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
    //
    // `Err(Error::QrDecoderPanicked)` 在这里是**允许**的（见模块文档的取舍：收敛过的
    // panic 不算崩溃，否则这一关会因为一个上游缺陷长期红着）。
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
