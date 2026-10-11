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

//! 本 crate 的错误类型。
//!
//! # 错误信息里只允许出现元数据
//!
//! 尺寸、版本号、帧号、纠错级别可以进错误信息；**载荷内容与扫到的原始文本不可以**。
//! 错误会被写进日志，而日志会被上报、被截图、被贴进 issue——本 crate 处理的虽然多
//! 半是密文，但配对阶段的二维码载荷里就有临时公钥与随机数，它们出现在日志里没有
//! 任何好处。

/// 本 crate 的结果类型。
pub type Result<T> = core::result::Result<T, Error>;

/// 本 crate 的错误。
///
/// 标了 `#[non_exhaustive]`：新增变体不算破坏性变更，而调用方必须留一个兜底分支
/// ——那正是「新增失败模式时编译器的沉默」这一风险的唯一补偿。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// 载荷装不下这条通道。
    ///
    /// `needed` 与 `limit` **都以载荷字节为单位**（不是信封文本的字符数），因为调用方
    /// 拿到的载荷就是若干字节，而「差多少」这个数字要能直接显示给用户。
    #[error("载荷装不下：需要 {needed} 字节，这条通道最多 {limit} 字节")]
    PayloadTooLarge {
        /// 实际需要装下的字节数。
        needed: usize,
        /// 这条通道能装下的最大字节数。
        limit: usize,
    },

    /// 这段文本不是本应用的二维码。
    ///
    /// 与「是本应用的码但坏了」分开，是因为两者对用户的意义完全不同：前者多半是
    /// 用户扫错了码（扫到了别人的二维码），后者才是要重扫或换通道。
    #[error("这不是 Qualia2FA 的二维码")]
    NotOurQrText,

    /// 帧头不合法（格式不对、有前导零、帧号超出帧数）。
    #[error("二维码文本的帧头不合法")]
    MalformedFrameHeader,

    /// 这张码是多帧的（动态二维码），而当前只实现了单帧。
    ///
    /// 单独一个变体是刻意的：多帧是**计划中的格式**，不是坏输入。把它混进
    /// [`Error::MalformedFrameHeader`] 会让将来实现多帧时无从判断「这段文本到底
    /// 是不是我们写的」。
    #[error("这张码有 {count} 帧，当前只支持单帧")]
    MultiFrameUnsupported {
        /// 文本自称的帧数。
        count: u32,
    },

    /// Base32 载荷不合法（非法字符、非法长度，或非规范的尾比特）。
    #[error("二维码文本里的 Base32 载荷不合法")]
    MalformedBase32,

    /// 纠错级别不是 `L`/`M`/`Q`/`H`。
    #[error("纠错级别 {letter:?} 不是 L/M/Q/H")]
    UnknownEcLevel {
        /// 实际拿到的那个字符。
        letter: char,
    },

    /// 二维码版本号不在 1–40 之内。
    #[error("二维码版本 {version} 不在 1–40 之内")]
    VersionOutOfRange {
        /// 实际拿到的版本号。
        version: u8,
    },

    /// 渲染参数不合法。
    #[error("渲染参数不合法：缩放 {scale} 倍、静区 {quiet_zone} 模块")]
    BadRenderGeometry {
        /// 每个模块放大成多少个像素。
        scale: u16,
        /// 四周留出的静区宽度（模块数）。
        quiet_zone: u16,
    },

    /// 图像尺寸与像素数不匹配，或尺寸超出上限。
    #[error("图像尺寸不合法：{width}×{height}，像素 {pixels} 个")]
    BadImageGeometry {
        /// 声称的宽度（像素）。
        width: u32,
        /// 声称的高度（像素）。
        height: u32,
        /// 实际给出的像素个数。
        pixels: usize,
    },

    /// 图像里没有可读的二维码。
    ///
    /// 与 [`Error::QrDecode`] 分开：这一条的含义是「连定位都没成功」，而不是
    /// 「找到了但读不出来」。前者多半是图片里根本没有码（或太小、太糊）。
    #[error("图像里没有找到二维码")]
    NoQrFound,

    /// 扫到的二维码不是文本（因此不可能是本应用的码）。
    #[error("扫到的二维码不是文本")]
    QrNotText,

    /// 图像解码失败。
    ///
    /// 只在开启 `scan-image` feature 时存在——那是这条错误唯一的来源。
    #[cfg(feature = "scan-image")]
    #[error("二维码图像解码失败：{0}")]
    QrDecode(#[from] rqrr::DeQRError),
}
