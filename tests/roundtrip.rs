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

//! 端到端闭环：载荷 → 二维码 → 像素 → 载荷。
//!
//! 这些测试走的是**用户真正走的那条路**：把码画成图，再从图里读回来。只测
//! 「编码器不报错」是不够的——那证明不了画出来的东西扫得出来，而扫不出来的码对用户
//! 来说与没生成过没有区别。
//!
//! 图像解码是可选 feature，因此整个文件在关闭它时不参与编译。

#![cfg(feature = "scan-image")]

use qualia_transport::Error;
use qualia_transport::envelope;
use qualia_transport::image::GrayImage;
use qualia_transport::qr::{self, EcLevel, QrProfile};

/// 确定性伪随机载荷。
///
/// 刻意不用 `rand`：它是本项目禁用的依赖（`deny.toml`），而且测试需要的是**可复现**，
/// 不是统计随机性——失败的用例必须能原样重放。
fn pseudo_random(len: usize) -> Vec<u8> {
    let mut state: u32 = 0x9e37_79b9;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 24) as u8);
    }
    out
}

/// 编码 → 渲染 → 扫描 → 比对。
fn round_trip(profile: &QrProfile, len: usize) {
    let payload = pseudo_random(len);
    let symbol = profile
        .encode_payload(&payload)
        .unwrap_or_else(|error| panic!("{len} 字节应当装得下：{error}"));
    assert!(
        symbol.version() <= profile.max_version(),
        "编出了 {} 版，超过声明的上限 {}",
        symbol.version(),
        profile.max_version()
    );
    let image = symbol.render(4, 4).expect("渲染参数合法");
    let decoded = qr::scan::decode_payload(&image).unwrap_or_else(|error| {
        panic!(
            "从图里读不回来（{} 版、纠错 {}、{len} 字节）：{error}",
            symbol.version(),
            symbol.ec_level().letter()
        )
    });
    assert_eq!(decoded, payload, "读回来的载荷与编进去的不一致");
}

/// 四种纠错级别 × 从最小到最大的版本：**每一个**都要能画出来又读回来。
///
/// 长度取「1、上限的一半、上限」，正好覆盖三种典型形状：最短、中间、刚好装满。
#[test]
fn every_profile_round_trips_through_pixels() {
    let profiles = [
        (EcLevel::Low, 1),
        (EcLevel::Low, 5),
        (EcLevel::Medium, 10),
        (EcLevel::Quartile, 15),
        (EcLevel::High, 20),
        (EcLevel::Low, 40),
    ];
    for (ec, max_version) in profiles {
        let profile = QrProfile::new(ec, max_version).expect("版本合法");
        let capacity = profile.payload_capacity();
        for len in [1, capacity / 2, capacity] {
            round_trip(&profile, len);
        }
    }
}

/// 用户导入的往往不是一张「干净」的码：截图里有大片留白、拍摄时有倾斜与背景。
///
/// 这里覆盖最容易复现的那一种——把码贴在一张更大的白底画布上。它验证的是解码器
/// 走的是**定位**而不是「假设码铺满整张图」。
#[test]
fn a_code_inside_a_larger_canvas_is_still_found() {
    let profile = QrProfile::new(EcLevel::Medium, 10).expect("版本合法");
    let payload = pseudo_random(40);
    let symbol = profile.encode_payload(&payload).expect("装得下");
    let code = symbol.render(4, 4).expect("渲染参数合法");

    let offset = 60_u32;
    let width = code.width() + 2 * offset;
    let height = code.height() + 2 * offset;
    let mut canvas = vec![u8::MAX; (width as usize) * (height as usize)];
    for y in 0..code.height() {
        for x in 0..code.width() {
            let source = code.pixel(x, y).expect("坐标在界内");
            let index = ((y + offset) as usize) * (width as usize) + (x + offset) as usize;
            canvas[index] = source;
        }
    }
    let canvas = GrayImage::from_luma8(width, height, canvas).expect("尺寸自洽");
    let decoded = qr::scan::decode_payload(&canvas).expect("大画布里的码也应当找得到");
    assert_eq!(decoded, payload);
}

/// 别人的二维码必须被报成「不是我们的码」。
///
/// 这条测试用的是**另一个编码器**（直接调 `qrcodegen`）与**另一份渲染代码**（本测试
/// 里手写的那几行）。理由与线格式测试相同：只用自己的编码器加自己的渲染器，验证的是
/// 自洽性；对「我们对二维码的理解整体偏了」完全盲。
#[test]
fn someone_elses_qr_is_reported_as_foreign() {
    let url = "https://example.com/not-ours";
    let code = qrcodegen::QrCode::encode_text(url, qrcodegen::QrCodeEcc::Medium)
        .expect("短文本一定装得下");
    let image = render_foreign(&code, 6, 4);

    let text = qr::scan::decode_text(&image).expect("这张码本身是好的");
    assert_eq!(text, url, "读出来的应当是原文");

    let result = qr::scan::decode_payload(&image);
    let is_foreign = matches!(result, Err(Error::NotOurQrText));
    assert!(
        is_foreign,
        "别人的码应当报「不是本应用的码」，实际 {result:?}"
    );
}

/// 图里没有码时必须报 [`Error::NoQrFound`]，而不是某个解码器的内部错误。
#[test]
fn a_blank_image_reports_not_found() {
    let blank = GrayImage::from_luma8(200, 200, vec![u8::MAX; 200 * 200]).expect("尺寸自洽");
    let result = qr::scan::decode_payload(&blank);
    let is_missing = matches!(result, Err(Error::NoQrFound));
    assert!(
        is_missing,
        "空白图应当报「没有找到二维码」，实际 {result:?}"
    );
    assert!(qr::scan::decode_text(&blank).is_err());
}

/// 小到几何上不可能含码的图必须被直接拒绝，且不得 panic。
///
/// 版本 1 的二维码是 21×21 个模块，一个模块至少一个像素——小于 21×21 的图里不可能
/// 有码。这条测试同时盯住「端侧传了小图」这条路径：它必须是错误，不是崩溃。
#[test]
fn images_too_small_to_hold_a_qr_are_rejected() {
    for side in [1_u32, 2, 20] {
        let image =
            GrayImage::from_luma8(side, side, vec![0; (side * side) as usize]).expect("尺寸自洽");
        let payload = qr::scan::decode_payload(&image);
        let text = qr::scan::decode_text(&image);
        let payload_is_missing = matches!(payload, Err(Error::NoQrFound));
        let text_is_missing = matches!(text, Err(Error::NoQrFound));
        assert!(
            payload_is_missing,
            "{side}×{side} 的图不该有码：{payload:?}"
        );
        assert!(text_is_missing, "{side}×{side} 的图不该有码：{text:?}");
    }
}

/// 信封文本必须**整串**落在二维码的字母数字模式里。
///
/// 这是「用 Base32 而不是 Base64」的**全部理由**（见 `src/base32.rs`）。一旦有人往
/// 信封里加一个小写字母或下划线，整张码就会退回字节模式，每个载荷字节多花 2 位——
/// 界面上看不出任何异常，只是码变大了、更难扫了。
#[test]
fn envelope_text_stays_inside_the_alphanumeric_charset() {
    const ALPHANUMERIC: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    for len in [0_usize, 1, 7, 64, 512] {
        let text = envelope::encode(&pseudo_random(len));
        assert!(
            text.chars()
                .all(|character| ALPHANUMERIC.contains(character)),
            "{len} 字节载荷的信封里出现了字母数字模式之外的字符：{text}"
        );
    }
}

/// 信封的膨胀必须是有界的：Base32 是 8/5，加上不到 20 个字符的帧头。
#[test]
fn envelope_overhead_stays_bounded() {
    for len in [16_usize, 256, 1024] {
        let text = envelope::encode(&pseudo_random(len));
        let limit = len * 8 / 5 + 20;
        assert!(
            text.len() <= limit,
            "{len} 字节的信封长 {} 个字符，超过上限 {limit}",
            text.len()
        );
    }
}

/// 超出上限一个字节就必须报错，且报出的 `needed`/`limit` 都以**载荷字节**为单位。
#[test]
fn one_byte_over_capacity_is_reported_in_payload_units() {
    let profile = QrProfile::new(EcLevel::Medium, 8).expect("版本合法");
    let capacity = profile.payload_capacity();
    let result = profile.encode_payload(&vec![0_u8; capacity + 1]);
    match result {
        Err(Error::PayloadTooLarge { needed, limit }) => {
            assert_eq!(needed, capacity + 1);
            assert_eq!(limit, capacity);
        }
        other => panic!("应当报「装不下」，实际 {other:?}"),
    }
}

/// 多帧：拆帧 → 逐张渲染 → 逐张扫描 → 拼装。
///
/// 这是「桌面端展示、另一端逐张扫」那条真实路径的像素版本。三件事必须同时成立：
/// 每一张都**画得出来**（容量按最长帧头扣掉那几个字符不是白扣的）、每一张都**读得
/// 回来**、拼出来的字节与原始载荷一致。
///
/// 扫描顺序刻意用倒序：帧可以乱序到达，而那正是拼装器存在的理由。
#[test]
fn a_multi_frame_payload_round_trips_through_pixels() {
    let profile = QrProfile::new(EcLevel::Low, 10).expect("版本合法");
    let single = profile.payload_capacity();
    // 单帧容量多一个字节：一张装不下，两张装得下。
    let payload = pseudo_random(single + 1);
    let symbols = profile
        .encode_payload_frames(&payload, 4)
        .expect("两张码装得下这份载荷");
    assert!(
        symbols.len() >= 2,
        "{} 字节超过单帧容量 {single}，应当被拆开，实际 {} 张",
        payload.len(),
        symbols.len()
    );
    for (index, symbol) in symbols.iter().enumerate() {
        assert!(
            symbol.version() <= profile.max_version(),
            "第 {} 张编出了 {} 版，超过声明的上限 {}",
            index + 1,
            symbol.version(),
            profile.max_version()
        );
    }

    let mut reassembler = qualia_transport::frame::Reassembler::from_first_frame();
    let mut done = None;
    for symbol in symbols.iter().rev() {
        let image = symbol.render(4, 4).expect("渲染参数合法");
        let frame = qr::scan::decode_frame(&image)
            .unwrap_or_else(|error| panic!("{} 版的码读不回来：{error}", symbol.version()));
        done = reassembler.accept(frame).expect("每一张都该被收下");
    }
    assert_eq!(done.expect("两张都扫到了就该拼齐"), payload);
}

/// 多帧的码走**单帧入口**时必须报「这条入口只收单帧」，而不是「这不是我们的码」。
///
/// 两条扫描入口共用「在整张图里挑出属于本应用的码」那一步，差别只在挑出来之后怎么
/// 处置。把它们的行为钉在错误类型上：报错了种类，界面上给出的引导就会指向错的方向
/// （「扫错了码」vs「这张码只是其中一张」）。
#[test]
fn the_two_scan_entries_differ_only_in_how_they_treat_multi_frame_codes() {
    let profile = QrProfile::new(EcLevel::Low, 10).expect("版本合法");
    let payload = pseudo_random(profile.payload_capacity() + 1);
    let symbols = profile.encode_payload_frames(&payload, 4).expect("拆得开");
    assert!(symbols.len() >= 2);

    let first = symbols[0].render(4, 4).expect("渲染参数合法");

    // 多帧入口：解得开，而且是「第 1 张，共 N 张」。
    let frame = qr::scan::decode_frame(&first).expect("多帧入口必须解得开");
    assert_eq!(frame.index, 1);
    assert_eq!(frame.total, symbols.len() as u32);
    assert_eq!(
        frame.payload.len(),
        profile.frame_payload_capacity().min(payload.len()),
        "第 1 张（非末帧）应当恰好是满载的那一段"
    );
    assert_eq!(frame.payload[..], payload[..frame.payload.len()]);

    // 单帧入口：如实报「这条路只收单帧」，而不是把它当成坏码或别人的码。
    match qr::scan::decode_payload(&first) {
        Err(Error::MultiFrameUnsupported { count }) => {
            assert_eq!(count, symbols.len() as u32);
        }
        other => panic!("单帧入口应当报「只收单帧」，实际 {other:?}"),
    }

    // 单帧的码在两个入口下都解得开，且结果一致。
    let single_payload = pseudo_random(8);
    let single = profile.encode_payload(&single_payload).expect("装得下");
    let image = single.render(4, 4).expect("渲染参数合法");
    assert_eq!(
        qr::scan::decode_payload(&image).expect("单帧入口"),
        single_payload
    );
    let frame = qr::scan::decode_frame(&image).expect("多帧入口也收单帧");
    assert_eq!(frame.index, 1);
    assert_eq!(frame.total, 1);
    assert_eq!(frame.payload, single_payload);
}

/// 测试里用的**独立渲染器**：直接把模块画进灰度图。
///
/// 它与 `Symbol::render` 是两份互不相干的实现，因此「读回来的码与写出去的一致」这条
/// 结论不会因为渲染代码里的一处共同误解而虚假成立。
fn render_foreign(code: &qrcodegen::QrCode, scale: u32, quiet: u32) -> GrayImage {
    let modules = u32::try_from(code.size()).expect("边长不会是负数");
    let side = (modules + 2 * quiet) * scale;
    let mut pixels = vec![u8::MAX; (side * side) as usize];
    for y in 0..modules {
        for x in 0..modules {
            if !code.get_module(
                i32::try_from(x).expect("边长很小"),
                i32::try_from(y).expect("边长很小"),
            ) {
                continue;
            }
            for dy in 0..scale {
                for dx in 0..scale {
                    let px = (quiet + x) * scale + dx;
                    let py = (quiet + y) * scale + dy;
                    pixels[(py * side + px) as usize] = 0;
                }
            }
        }
    }
    GrayImage::from_luma8(side, side, pixels).expect("尺寸自洽")
}
