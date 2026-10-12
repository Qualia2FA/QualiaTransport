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

//! 二维码：容量模型、编码与渲染。
//!
//! # 容量是**算出来的**，不是抄表
//!
//! 「版本 40 的 L 级能装 2953 字节」这个数字在规范里是一张 40×4 的表（ISO/IEC 18004
//! 表 7）。把它抄进来是最容易做、也最容易做错的一件事：**抄错不会编译报错**，而且
//! 一旦编码器换了实现，抄来的表与真实行为就开始各自漂移，症状是「界面说装得下、
//! 编码时却报错」。
//!
//! 因此本模块的容量是**对编码器本身做二分搜索**得到的：问「`n` 字节的载荷能不能装进
//! 不超过 `max_version` 的某一版」。它与编码器**按构造一致**，不可能漂移。
//! 代价是构造 [`QrProfile`] 时要跑几十次编码（微秒级），换来的是那个数字永远是真的。
//!
//! # 「装不下」是一个必须提前知道的答案
//!
//! 二维码与字节流通道的根本区别是：**装不下就是装不下**，没有重试余地。用户已经举着
//! 手机在扫了，这时才发现装不下是最坏的时机。因此 [`QrProfile::payload_capacity`]
//! 在**展示之前**就给出这条通道的精确上限，而 [`QrProfile::encode_payload`] 超限时
//! 报出的 [`Error::PayloadTooLarge`] 带着 `needed` 与 `limit` 两个数字——调用方据此
//! 才能告诉用户「差多少」，并顺势引导改用局域网通道。
//!
//! # 一张装不下时：多帧（动态二维码）
//!
//! 一份载荷超过一张码的上限时还有第三条路：**拆成若干张码连续显示**，用户逐张扫
//! （拆与拼在 [`crate::frame`]）。它不依赖任何网络设施，因此是「没有 WiFi、组播又被
//! 禁」时唯一还走得通的那条。
//!
//! 于是有三个数字，单位都是**载荷字节**，但覆盖的范围不同：
//!
//! | 方法 | 含义 |
//! |------|------|
//! | [`QrProfile::payload_capacity`] | **一张**码能装多少（单帧，帧头最短） |
//! | [`QrProfile::frame_payload_capacity`] | 拆帧时**每一张**能装多少（按最长的帧头算） |
//! | [`QrProfile::exchange_capacity`] | 一次交换（最多 N 张码）合起来能装多少 |
//!
//! 前两个不相等（小版本上可能同时为 0），而且**不能混用**：帧头写在信封开头，而它
//! 的长度随**帧数**的位数增长——帧数到两位数就多 2 个字符，到三位数多 4 个，而
//! `payload_capacity` 恰好是「再多一个字符就装不下」的那个位置。拿它去切帧，一份
//! 需要十张以上码的载荷就会切出**渲染不出来**的帧。完整入口是
//! [`QrProfile::encode_payload_frames`]，它自己取正确的容量，调用方无从弄错。

use crate::envelope;
use crate::error::{Error, Result};
use crate::image::GrayImage;
use qrcodegen::{QrCode, QrCodeEcc, QrSegment, Version};

#[cfg(feature = "scan-image")]
pub mod scan;

/// 静区的最小宽度（模块数）。
///
/// ISO/IEC 18004 要求二维码四周各留 4 个模块的空白。少了它，扫码器可能找不到定位
/// 图案——这不是审美问题，是**能不能扫出来**的问题，所以宁可拒绝也不默默画一张
/// 扫不出来的图。
const MIN_QUIET_ZONE: u16 = 4;

/// 版本号的下界（21×21 模块）。
const MIN_VERSION: u8 = 1;

/// 版本号的上界（177×177 模块）。
const MAX_VERSION: u8 = 40;

/// 容量搜索的硬上界（字节）。
///
/// 40 版 L 级的字节模式上限是 2953 字节，加上信封的 Base32 膨胀后仍然远小于 8192。
/// 这个上界存在的意义是让搜索**必然终止**，而不是从规范里搬一个数字：即便有人把
/// [`MAX_VERSION`] 改错，搜索也只会得出「至少能装 8192」这个保守结论，不会失控。
const CAPACITY_SEARCH_LIMIT: usize = 8192;

/// 纠错级别（ISO/IEC 18004 的 L/M/Q/H）。
///
/// 级别越高，可恢复的污损越多，能装的载荷越少。**这个选择属于平台**：屏幕上的码没有
/// 油墨污损，但可能被拍得歪、糊、有反光；印在纸上的码则要留出磨损余量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcLevel {
    /// 约可恢复 7% 的码字。
    Low,
    /// 约可恢复 15% 的码字。
    Medium,
    /// 约可恢复 25% 的码字。
    Quartile,
    /// 约可恢复 30% 的码字。
    High,
}

impl EcLevel {
    /// 规范里的单字母记法。
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::Low => 'L',
            Self::Medium => 'M',
            Self::Quartile => 'Q',
            Self::High => 'H',
        }
    }

    /// 从单字母记法解析（大小写不敏感）。
    ///
    /// # 错误
    ///
    /// 不是 `L`/`M`/`Q`/`H` 时返回 [`Error::UnknownEcLevel`]。
    pub fn from_letter(letter: char) -> Result<Self> {
        match letter.to_ascii_uppercase() {
            'L' => Ok(Self::Low),
            'M' => Ok(Self::Medium),
            'Q' => Ok(Self::Quartile),
            'H' => Ok(Self::High),
            other => Err(Error::UnknownEcLevel { letter: other }),
        }
    }

    /// 转成编码器的类型。
    const fn as_qrcodegen(self) -> QrCodeEcc {
        match self {
            Self::Low => QrCodeEcc::Low,
            Self::Medium => QrCodeEcc::Medium,
            Self::Quartile => QrCodeEcc::Quartile,
            Self::High => QrCodeEcc::High,
        }
    }
}

/// 一条二维码通道的能力：纠错级别 + 愿意展示的最大版本。
///
/// **最大版本是平台属性，不是数据集属性。** 桌面窗口能舒舒服服铺下 177×177 个模块，
/// 手表不能；同一个数据集在前者上绰绰有余、在后者上装不下，而「装不下」之后的处置
/// （引导改用局域网）也由平台决定。远期的智能手表只需要改这一个数字。
///
/// # 构造代价
///
/// [`QrProfile::new`] 会**实时算出**这条通道的载荷上限（对编码器做二分搜索，几十次
/// 编码）。它应当被构造一次并复用，而不是每次展示时重建。多帧的容量一并算出来——
/// 两个数字各一次搜索，而它们都只依赖「纠错级别 + 最大版本」这两个参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrProfile {
    /// 纠错级别。
    ec: EcLevel,
    /// 愿意展示的最大版本（1–40）。
    max_version: u8,
    /// 这条通道能装下的最大载荷字节数（构造时算好）。
    payload_capacity: usize,
    /// 拆帧时**每一张**码能装下的最大载荷字节数（构造时算好）。
    frame_capacity: usize,
}

impl QrProfile {
    /// 建立一条通道的能力描述。
    ///
    /// # 错误
    ///
    /// `max_version` 不在 1–40 之内时返回 [`Error::VersionOutOfRange`]。
    pub fn new(ec: EcLevel, max_version: u8) -> Result<Self> {
        if !(MIN_VERSION..=MAX_VERSION).contains(&max_version) {
            return Err(Error::VersionOutOfRange {
                version: max_version,
            });
        }
        Ok(Self {
            ec,
            max_version,
            payload_capacity: capacity_for(ec, max_version, |len| envelope::encode(&vec![0; len])),
            frame_capacity: capacity_for(ec, max_version, |len| {
                envelope::encode_frame(&vec![0; len], envelope::MAX_FRAMES, envelope::MAX_FRAMES)
            }),
        })
    }

    /// 纠错级别。
    #[must_use]
    pub const fn ec_level(&self) -> EcLevel {
        self.ec
    }

    /// 愿意展示的最大版本。
    #[must_use]
    pub const fn max_version(&self) -> u8 {
        self.max_version
    }

    /// 这条通道能装下的最大**载荷**字节数。
    ///
    /// 这是「信封 + Base32 + 二维码」整条链路的最终答案，正是核心库的
    /// `TransportCapabilities::check_fits` 要比较的那个数。
    ///
    /// 它说的是**一张码**（单帧）。拆成多张时每一张的上限更小，见
    /// [`QrProfile::frame_payload_capacity`]。
    #[must_use]
    pub const fn payload_capacity(&self) -> usize {
        self.payload_capacity
    }

    /// 拆帧时**每一张**码能装下的最大载荷字节数。
    ///
    /// # 它为什么小于 [`QrProfile::payload_capacity`]
    ///
    /// 帧头写在信封开头（`Q2FA1:<帧号>/<帧数>:`），长度是 `8 + 帧号位数 + 帧数位数`：
    ///
    /// | 帧数 | 最长的帧头 | 比单帧（`1/1`）长 |
    /// |------|-----------|-------------------|
    /// | 1–9   | `9/9`     | 0 个字符 |
    /// | 10–99 | `99/99`   | 2 个字符 |
    /// | 100–255 | `255/255` | 4 个字符 |
    ///
    /// 而 `payload_capacity` 是**再多一个字符就换版本**的那个位置，所以帧数一旦上两位数，
    /// 按它切出来的满载帧就会顶出这个版本。
    ///
    /// # 这 4 个字符是按**最坏情况**扣的，这是刻意的
    ///
    /// 严格说容量是帧数的函数（3 张码时帧头与单帧一样长，能多装两三个字节），而帧数
    /// 又由容量算出——那是一个循环。循环里任何一处近似都会变成「界面说要 3 张、第 2 张
    /// 却渲染不出来」，而按最长帧头扣是一个**与帧数无关**的常数：切得开与画得出按构造
    /// 一致。代价是每张码少装两三个字节，也就是一万字节的载荷上多半张码的量级。
    #[must_use]
    pub const fn frame_payload_capacity(&self) -> usize {
        self.frame_capacity
    }

    /// 一次交换最多用 `max_frames` 张码时，合起来能装下的载荷字节数。
    ///
    /// # 它给谁用
    ///
    /// 平台侧要拿它去声明核心库的 `TransportCapabilities::max_message_len`——那个字段
    /// 说的是「一条消息」，而一条消息在这里可能横跨几张码。**声明与渲染必须用同一个
    /// 数字**，否则核心库会批准一份这份载荷渲染不出来的分享。
    ///
    /// # 两处夹取，都是格式与算术决定的
    ///
    /// - `max_frames` 超过 [`envelope::MAX_FRAMES`] 时按那个上限算：格式写不下第 256
    ///   帧，再多要几张也不会多出容量。
    /// - 结果不小于 [`QrProfile::payload_capacity`]：一张码也是「最多 N 张」的一种用法
    ///   （N ≥ 1 时），而去掉那一项会让极小的版本出现「允许两张码反而装得更少」。
    #[must_use]
    pub const fn exchange_capacity(&self, max_frames: u32) -> usize {
        if max_frames == 0 {
            // 「一张都不许用」就是装不下任何东西。它不是一个静默的默认值：调用方
            // 要为此拿到一条可读的错误（`limit: 0`），而不是一个能用的数字。
            return 0;
        }
        let frames = if max_frames > envelope::MAX_FRAMES {
            envelope::MAX_FRAMES
        } else {
            max_frames
        };
        let split = match self.frame_capacity.checked_mul(frames as usize) {
            Some(total) => total,
            // 溢出只可能出现在调用方给了一个荒唐的帧数上，而那条路上面已经被
            // `MAX_FRAMES`（255）截断了。留着它是为了不让「不可能」变成一个 panic。
            None => usize::MAX,
        };
        if split > self.payload_capacity {
            split
        } else {
            self.payload_capacity
        }
    }

    /// 把载荷编成一张二维码符号。
    ///
    /// # 错误
    ///
    /// 装不下时返回 [`Error::PayloadTooLarge`]，带上实际需要的字节数与这条通道的上限。
    pub fn encode_payload(&self, payload: &[u8]) -> Result<Symbol> {
        let text = crate::envelope::encode(payload);
        encode_within(&text, self.ec, self.max_version).ok_or(Error::PayloadTooLarge {
            needed: payload.len(),
            limit: self.payload_capacity,
        })
    }

    /// 把载荷编成**一张或多张**二维码符号（动态二维码）。
    ///
    /// 一张装得下时返回一张，与 [`QrProfile::encode_payload`] 的结果**逐位相同**；
    /// 装不下时按 [`QrProfile::frame_payload_capacity`] 切开，返回按帧号排列的若干张。
    /// 调用方把返回的每一张依次显示，用户逐张扫（顺序无所谓，拼装器收任意顺序）。
    ///
    /// # 为什么容量不由调用方传
    ///
    /// 切帧有两个数字必须一致（切点、每张码的容量），而它们一旦由调用方各传一次，
    /// 「界面说要 3 张、第 2 张却渲染不出来」就只是一次笔误的距离。这里把两者收进
    /// 同一个函数：调用方只说「我最多愿意让用户扫几张」。
    ///
    /// # 错误
    ///
    /// - [`Error::PayloadTooLarge`]：载荷超过
    ///   [`QrProfile::exchange_capacity`]`(max_frames)`。`needed`/`limit` 都是**载荷
    ///   字节**，调用方据此可以说清「差多少」，并引导改用局域网。
    ///
    /// `max_frames` 要得再多也不会撞上格式的 255 帧上限：那条上限已经折进
    /// [`QrProfile::exchange_capacity`] 里了（超过它的要求只会让 `limit` 停在那儿），
    /// 因此从这个入口走不到 [`Error::TooManyFrames`]——那一条属于直接调
    /// [`crate::frame::encode_frames`] 的调用方。
    pub fn encode_payload_frames(&self, payload: &[u8], max_frames: u32) -> Result<Vec<Symbol>> {
        let limit = self.exchange_capacity(max_frames);
        if payload.len() > limit {
            return Err(Error::PayloadTooLarge {
                needed: payload.len(),
                limit,
            });
        }
        // 一张装得下就只出一张码：多帧是**装不下时**的出路，不是默认路径。这条分支
        // 同时保证了「同一份载荷在单帧与多帧入口下编出同一张码」。
        if payload.len() <= self.payload_capacity {
            return Ok(vec![self.encode_payload(payload)?]);
        }

        // 帧数上限已经由 `limit` 保证（见文档），因此这里那个 `TooManyFrames` 走不到；
        // 用 `?` 而不是 `expect` 是因为「走不到」这句话不该变成一个 panic。
        let texts = crate::frame::encode_frames(payload, self.frame_capacity)?;
        texts
            .iter()
            .map(|text| {
                encode_within(text, self.ec, self.max_version).ok_or(Error::PayloadTooLarge {
                    // 走到这里说明切点算错了——那是本模块的 bug，不是调用方的输入问题。
                    // 仍然返回错误而不是 panic：本 crate 的契约是「任何输入都不得导致
                    // panic」，而一个内部错误不该成为唯一的例外。
                    needed: payload.len(),
                    limit: self.frame_capacity,
                })
            })
            .collect()
    }
}

/// 一张生成好的二维码：模块矩阵，不含颜色与缩放。
///
/// 它刻意**不带 `Debug` 的默认实现**：矩阵动辄三万多个布尔值，倒进日志既没用又是
/// 一个放大点，而手写的 `Debug` 只打印版本、级别、掩码与边长。
pub struct Symbol {
    /// 版本号（1–40）。
    version: u8,
    /// 纠错级别。
    ec: EcLevel,
    /// 编码器选中的掩码（0–7）。
    mask: u8,
    /// 每边的模块数（`4 * version + 17`）。
    size: u16,
    /// 行优先的模块矩阵：`true` 是深色。
    modules: Vec<bool>,
}

impl Symbol {
    /// 版本号（1–40）。
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// 纠错级别。
    #[must_use]
    pub const fn ec_level(&self) -> EcLevel {
        self.ec
    }

    /// 编码器选中的掩码（0–7）。
    ///
    /// 掩码的作用是打散大块同色区域，让扫码器更容易定位；规范给了 8 种，编码器按罚分
    /// 自动挑一种。它被露出来只是为了诊断（同一份载荷的两次编码必须得到同一个掩码），
    /// 渲染方不需要关心它。
    #[must_use]
    pub const fn mask(&self) -> u8 {
        self.mask
    }

    /// 每边的模块数（含功能图案，不含静区）。
    #[must_use]
    pub const fn size(&self) -> u16 {
        self.size
    }

    /// 行优先的模块矩阵：`true` 是深色，长度恒为 `size * size`。
    ///
    /// 这是给渲染方的主入口：端侧按自己的缩放与颜色遍历这一片布尔值即可，不需要一个
    /// 像素一个像素地调 [`Symbol::module`]。
    #[must_use]
    pub fn modules(&self) -> &[bool] {
        &self.modules
    }

    /// 取一个模块；越界返回 `None`。
    #[must_use]
    pub fn module(&self, x: u16, y: u16) -> Option<bool> {
        if x >= self.size || y >= self.size {
            return None;
        }
        self.modules
            .get(usize::from(y) * usize::from(self.size) + usize::from(x))
            .copied()
    }

    /// 渲染成灰度图：深色模块是 0，浅色模块与静区是 255。
    ///
    /// # 参数
    ///
    /// - `scale`：每个模块放大成多少个像素。必须 ≥ 1。
    /// - `quiet_zone`：四周留出的静区宽度（模块数）。必须 ≥ 4（ISO/IEC 18004 的
    ///   要求），小了就不是审美问题而是**扫不出来**。
    ///
    /// # 它给谁用
    ///
    /// 端侧自己会把模块矩阵画到界面上（那里有主题色、圆角、动画），本方法服务的是
    /// 另外两件事：**测试**（编码 → 渲染 → 扫描这条闭环必须真的跑一遍）与**导出图片**
    /// （用户要把码发出去或存下来时，总得有一份像素）。
    ///
    /// # 错误
    ///
    /// 参数不合法或结果超过 [`GrayImage::MAX_PIXELS`] 时返回
    /// [`Error::BadRenderGeometry`]。
    pub fn render(&self, scale: u16, quiet_zone: u16) -> Result<GrayImage> {
        if scale == 0 || quiet_zone < MIN_QUIET_ZONE {
            return Err(Error::BadRenderGeometry { scale, quiet_zone });
        }
        let side_modules = u32::from(self.size) + 2 * u32::from(quiet_zone);
        let side_pixels = side_modules
            .checked_mul(u32::from(scale))
            .ok_or(Error::BadRenderGeometry { scale, quiet_zone })?;
        let count = (side_pixels as usize)
            .checked_mul(side_pixels as usize)
            .ok_or(Error::BadRenderGeometry { scale, quiet_zone })?;
        if count > GrayImage::MAX_PIXELS {
            return Err(Error::BadRenderGeometry { scale, quiet_zone });
        }

        let mut pixels = vec![u8::MAX; count];
        let scale_px = u32::from(scale);
        let quiet_px = u32::from(quiet_zone) * scale_px;
        for y in 0..self.size {
            for x in 0..self.size {
                if self.module(x, y) != Some(true) {
                    continue;
                }
                let left = quiet_px + u32::from(x) * scale_px;
                let top = quiet_px + u32::from(y) * scale_px;
                for dy in 0..scale_px {
                    let row = (top + dy) as usize * side_pixels as usize;
                    for dx in 0..scale_px {
                        if let Some(pixel) = pixels.get_mut(row + (left + dx) as usize) {
                            *pixel = 0;
                        }
                    }
                }
            }
        }
        GrayImage::from_luma8(side_pixels, side_pixels, pixels)
    }
}

impl core::fmt::Debug for Symbol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Symbol {{ 版本 {}, 纠错 {}, 掩码 {}, {}×{} }}",
            self.version,
            self.ec.letter(),
            self.mask,
            self.size,
            self.size
        )
    }
}

/// 把一段文本编进不超过 `max_version` 的某一版；装不下返回 `None`。
///
/// **不做版本选择以外的任何决策**：纠错级别照传进来的用（不自动提升——级别是平台
/// 声明的能力，悄悄改掉会让「界面说这条通道是 M 级」变成假话），掩码交给编码器按
/// 罚分自动挑（规范给了 8 种，我们没有任何理由在这里插手）。
fn encode_within(text: &str, ec: EcLevel, max_version: u8) -> Option<Symbol> {
    // `make_segments` 自己会按字符集分段（数字/字母数字/字节），因此对任意文本都不会
    // panic——而手工调 `make_alphanumeric` 会在遇到表外字符时 expect 失败。
    let segments = QrSegment::make_segments(text);
    let code = QrCode::encode_segments_advanced(
        &segments,
        ec.as_qrcodegen(),
        Version::MIN,
        Version::new(max_version),
        None,
        false,
    )
    .ok()?;
    Some(Symbol::from_code(&code, ec))
}

impl Symbol {
    /// 从编码器的结果取出模块矩阵。
    fn from_code(code: &QrCode, ec: EcLevel) -> Self {
        let version = code.version().value();
        let size = 4 * u16::from(version) + 17;
        let mut modules = Vec::with_capacity(usize::from(size) * usize::from(size));
        for y in 0..i32::from(size) {
            for x in 0..i32::from(size) {
                modules.push(code.get_module(x, y));
            }
        }
        Self {
            version,
            ec,
            mask: code.mask().value(),
            size,
            modules,
        }
    }
}

/// 算出这条通道能装下的最大载荷字节数。
///
/// 先用倍增找到第一个装不下的长度，再在「最后装得下」与「第一个装不下」之间二分。
///
/// # 「信封头固定」是这条搜索的前提
///
/// `make_text` 把「`len` 字节的载荷」编成待编码的文本，而它的**长度只由 `len` 决定、
/// 与内容无关**（信封头是定长的，Base32 是 8/5 膨胀）。这两条合起来才让搜索有意义：
/// 否则「这个长度装得下」就不是一个良定义的命题。
///
/// 单帧与多帧的差别全部落在这个函数的参数上：多帧那一次传进来的帧头按
/// [`envelope::MAX_FRAMES`] 取**最长**的一种（见
/// [`QrProfile::frame_payload_capacity`] 的说明）。
///
/// # 为什么用全零字节探测是**精确**的
///
/// Base32 的输出长度只取决于输入长度（`ceil(8n/5)` 个字符），而 Base32 的字母表完全
/// 落在二维码的字母数字模式里，因此**所需版本只取决于文本长度，与文本内容无关**。
/// 换句话说「`n` 个字节装不装得下」对同一个 `n` 是一致答案，用零字节探测不会低估也
/// 不会高估任何别的 `n` 字节载荷。这条性质由 `capacity_is_content_independent` 钉住。
fn capacity_for<F>(ec: EcLevel, max_version: u8, make_text: F) -> usize
where
    F: Fn(usize) -> String,
{
    let fits = |len: usize| encode_within(&make_text(len), ec, max_version).is_some();
    if !fits(0) {
        // 连空载荷都装不下：只可能是版本号非法，而它在 `QrProfile::new` 里已经被挡住。
        return 0;
    }
    let mut low = 0;
    let mut high = 1;
    while high <= CAPACITY_SEARCH_LIMIT && fits(high) {
        low = high;
        high *= 2;
    }
    if high > CAPACITY_SEARCH_LIMIT {
        // 探到了硬上界还没失败：这不可能发生（40 版 L 级也只有 2953 字节），
        // 但如果有人把上界改小了，这里给出的是一个**保守**答案而不是一个错答案。
        return CAPACITY_SEARCH_LIMIT;
    }
    // 不变式：`low` 装得下、`high` 装不下。二分到两者相邻。
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if fits(middle) {
            low = middle;
        } else {
            high = middle;
        }
    }
    low
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 版本必须真的限制住码的尺寸：说 5 版就必须是 5 版以内。
    #[test]
    fn version_limit_is_respected() {
        for max_version in [1_u8, 2, 5, 10, 20, 40] {
            let profile = QrProfile::new(EcLevel::Medium, max_version).expect("版本合法");
            let capacity = profile.payload_capacity();
            let symbol = profile
                .encode_payload(&vec![0; capacity])
                .expect("上限之内必须编得出来");
            assert!(
                symbol.version() <= max_version,
                "编出了 {} 版，超过了声明的上限 {max_version}",
                symbol.version()
            );
            assert_eq!(
                symbol.size(),
                4 * u16::from(symbol.version()) + 17,
                "边长与版本不符"
            );
            assert_eq!(
                symbol.modules().len(),
                usize::from(symbol.size()) * usize::from(symbol.size()),
                "模块数与边长不符"
            );
        }
    }

    /// 超限必须报出**载荷字节**为单位的 needed/limit，而且报错时不得产出一张码。
    #[test]
    fn exceeding_capacity_reports_payload_bytes() {
        let profile = QrProfile::new(EcLevel::Medium, 10).expect("版本合法");
        let capacity = profile.payload_capacity();
        let result = profile.encode_payload(&vec![0; capacity + 1]);
        match result {
            Err(Error::PayloadTooLarge { needed, limit }) => {
                assert_eq!(needed, capacity + 1, "needed 应当是载荷字节数");
                assert_eq!(limit, capacity, "limit 应当是这条通道的上限");
            }
            other => panic!("应当报「装不下」，实际 {other:?}"),
        }
    }

    /// **拆出来的每一张都必须真的画得出来。**
    ///
    /// 这是 [`QrProfile::frame_payload_capacity`] 存在的全部理由。按单帧容量切帧时，
    /// 帧头在帧数上两位数之后会长出 2 个字符，而单帧容量恰好是「再多一个字符就装不下」
    /// 的位置——于是那些帧一张也编不出来，症状是「界面说要 10 张，第 10 张渲染失败」。
    ///
    /// 两个方向一起钉：多帧容量下每一张都编得出来，而单帧容量下确实有帧编不出来
    /// （否则这个扣除就是白扣的，后人会把它当成多余的保守值删掉）。
    #[test]
    fn frames_split_at_the_multi_frame_capacity_always_render() {
        for (ec, max_version) in [
            (EcLevel::Low, 1),
            (EcLevel::Medium, 1),
            (EcLevel::Low, 5),
            (EcLevel::Medium, 10),
            (EcLevel::High, 20),
            (EcLevel::Low, 40),
        ] {
            let profile = QrProfile::new(ec, max_version).expect("版本合法");
            let single = profile.payload_capacity();
            let per_frame = profile.frame_payload_capacity();
            assert!(
                per_frame <= single,
                "多帧容量不该大于单帧容量：{per_frame} > {single}（{} 版、纠错 {}）",
                max_version,
                ec.letter()
            );
            if single == 0 {
                // 极小的版本（例如 1 版 H 级）连信封头都装不下，没有可切的载荷。
                continue;
            }

            // 十张码：帧号到两位数，正是单帧容量不够用的那一段。
            let payload = vec![0x5A; single * 10];
            let symbols = profile
                .encode_payload_frames(&payload, 20)
                .unwrap_or_else(|error| panic!("{} 版应当拆得开：{error}", max_version));
            assert!(
                symbols.len() >= 10,
                "{} 字节在 {} 版的 {single} 字节容量下应当要十张以上，实际 {}",
                payload.len(),
                max_version,
                symbols.len()
            );
            for (index, symbol) in symbols.iter().enumerate() {
                assert!(
                    symbol.version() <= max_version,
                    "第 {} 张编出了 {} 版，超过声明的上限 {max_version}",
                    index + 1,
                    symbol.version()
                );
            }

            // 反证：同样的载荷按**单帧**容量切，末帧（帧号与帧数都是两位数，帧头 12 个
            // 字符）必然顶出版本上限。
            let texts = crate::frame::encode_frames(&payload, single).expect("切得开");
            assert!(
                texts
                    .iter()
                    .any(|text| encode_within(text, ec, max_version).is_none()),
                "按单帧容量 {single} 切的帧竟然每一张都编得出来——那说明多帧容量白扣了字符"
            );

            // 三位数帧号（`150/150`，最长的帧头）那一段也要走一遍。这里只编符号、
            // 不渲染像素：像素级的多帧闭环在 `tests/roundtrip.rs` 里。
            let many = vec![0x3C; single * 100];
            let symbols = profile
                .encode_payload_frames(&many, envelope::MAX_FRAMES)
                .unwrap_or_else(|error| panic!("一百张码应当拆得开：{error}"));
            assert!(
                symbols.len() >= 100,
                "{} 字节应当要一百张以上，实际 {}",
                many.len(),
                symbols.len()
            );
            for symbol in &symbols {
                assert!(
                    symbol.version() <= max_version,
                    "三位数帧号的那一段编出了 {} 版，超过上限 {max_version}",
                    symbol.version()
                );
            }
        }
    }

    /// 一张装得下时，多帧入口与单帧入口编出**逐位相同**的码。
    ///
    /// 两条入口编出两张不同的码，就意味着同一份载荷有两种二维码表示，而「这两张码是
    /// 不是同一张」在界面上是一件用户看得见的事。
    #[test]
    fn one_frame_payloads_take_the_single_frame_path() {
        let profile = QrProfile::new(EcLevel::Medium, 12).expect("版本合法");
        let payload = vec![7_u8; profile.payload_capacity()];
        let single = profile.encode_payload(&payload).expect("单帧装得下");
        let frames = profile
            .encode_payload_frames(&payload, 8)
            .expect("多帧入口也装得下");
        assert_eq!(frames.len(), 1, "装得下就不该拆");
        assert_eq!(frames[0].modules(), single.modules());
        assert_eq!(frames[0].version(), single.version());
    }

    /// [`QrProfile::exchange_capacity`] 的算术：0 张是装不下、上限按格式夹取、单调不减、
    /// 且永远不小于单帧容量。
    #[test]
    fn exchange_capacity_is_the_declared_limit() {
        let profile = QrProfile::new(EcLevel::Low, 10).expect("版本合法");
        let single = profile.payload_capacity();
        let per_frame = profile.frame_payload_capacity();

        assert_eq!(profile.exchange_capacity(0), 0, "一张都不许用＝装不下");
        let mut previous = 0;
        for frames in 0..=envelope::MAX_FRAMES {
            let capacity = profile.exchange_capacity(frames);
            assert!(capacity >= previous, "帧数变多不该让容量变小");
            if frames > 0 {
                assert!(
                    capacity >= single,
                    "一张码也是「最多 {frames} 张」的一种用法"
                );
            }
            assert!(
                capacity >= per_frame * frames as usize,
                "{frames} 张码各装 {per_frame} 字节，合起来必须都算得进去"
            );
            previous = capacity;
        }
        // 三位数帧号写不进格式：要得再多也停在第 255 帧那个数字上。
        assert_eq!(
            profile.exchange_capacity(envelope::MAX_FRAMES),
            profile.exchange_capacity(u32::MAX),
            "超过格式上限的帧数不该换来更多容量"
        );
    }

    /// 超过一次交换的上限时，报出的两个数字都是**载荷字节**。
    #[test]
    fn exceeding_the_exchange_capacity_reports_payload_bytes() {
        let profile = QrProfile::new(EcLevel::Low, 10).expect("版本合法");
        let limit = profile.exchange_capacity(5);
        let payload = vec![0_u8; limit + 1];
        match profile.encode_payload_frames(&payload, 5) {
            Err(Error::PayloadTooLarge {
                needed,
                limit: reported,
            }) => {
                assert_eq!(needed, payload.len());
                assert_eq!(reported, limit);
            }
            other => panic!("应当报「装不下」，实际 {other:?}"),
        }
    }

    /// 容量与载荷内容无关：全零探测出来的上限对任意内容都成立。
    #[test]
    fn capacity_is_content_independent() {
        let profile = QrProfile::new(EcLevel::Quartile, 12).expect("版本合法");
        let capacity = profile.payload_capacity();
        // 三种极端内容：全零、全 0xFF、伪随机。
        let mut pseudo_random = Vec::with_capacity(capacity);
        let mut state: u32 = 0x1234_5678;
        for _ in 0..capacity {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            pseudo_random.push((state >> 24) as u8);
        }
        for payload in [vec![0_u8; capacity], vec![0xff_u8; capacity], pseudo_random] {
            assert!(
                profile.encode_payload(&payload).is_ok(),
                "上限长度的载荷必须编得出来（内容不该影响容量）"
            );
        }
    }

    /// 纠错级别越高，装得越少；版本越高，装得越多。**两条单调性**。
    ///
    /// 它们不是显然的：容量表是人抄的，抄错一行的症状正是单调性被破坏。这里虽然容量
    /// 是算出来的，但这条测试同时钉住了底层的编码器没有给出离谱的结果。
    #[test]
    fn capacity_is_monotone_in_level_and_version() {
        let levels = [
            EcLevel::Low,
            EcLevel::Medium,
            EcLevel::Quartile,
            EcLevel::High,
        ];
        for max_version in [1_u8, 5, 15, 40] {
            let capacities: Vec<usize> = levels
                .iter()
                .map(|&ec| {
                    QrProfile::new(ec, max_version)
                        .expect("版本合法")
                        .payload_capacity()
                })
                .collect();
            for pair in capacities.windows(2) {
                assert!(
                    pair[0] >= pair[1],
                    "纠错级别升高后容量不该变大：{capacities:?}（版本 {max_version}）"
                );
            }
        }
        for ec in levels {
            let capacities: Vec<usize> = [1_u8, 5, 15, 40]
                .iter()
                .map(|&version| {
                    QrProfile::new(ec, version)
                        .expect("版本合法")
                        .payload_capacity()
                })
                .collect();
            for pair in capacities.windows(2) {
                assert!(
                    pair[0] <= pair[1],
                    "版本升高后容量不该变小：{capacities:?}（纠错 {}）",
                    ec.letter()
                );
            }
        }
    }

    /// 版本 1 的 L 级在字节模式下的容量是 17 字节，走信封（Base32 + 头）后应当明显
    /// 更小，但也不该小到荒谬。这里钉一个**量级**，防止有人在信封里塞进几十字节的
    /// 元数据却没人发现。
    #[test]
    fn smallest_channel_capacity_is_in_a_sane_range() {
        let profile = QrProfile::new(EcLevel::Low, 1).expect("版本合法");
        let capacity = profile.payload_capacity();
        assert!(
            (8..=15).contains(&capacity),
            "版本 1 的 L 级应当能装 8–15 字节的载荷，实际 {capacity}"
        );
    }

    /// 同一份载荷两次编码必须得到同一个符号。
    ///
    /// 规范允许编码器任选掩码（按罚分挑），但**同一个实现必须给出同一个答案**：否则
    /// 「这两张码是不是同一张」在字节层面无从判断，测试也无从写起。
    #[test]
    fn encoding_is_deterministic() {
        let profile = QrProfile::new(EcLevel::Medium, 20).expect("版本合法");
        let payload = b"deterministic";
        let first = profile.encode_payload(payload).expect("编得出来");
        let second = profile.encode_payload(payload).expect("编得出来");
        assert_eq!(first.version(), second.version());
        assert_eq!(first.mask(), second.mask());
        assert_eq!(first.modules(), second.modules());
    }

    #[test]
    fn version_out_of_range_is_rejected() {
        assert!(QrProfile::new(EcLevel::Low, 0).is_err());
        assert!(QrProfile::new(EcLevel::Low, 41).is_err());
        assert!(QrProfile::new(EcLevel::Low, 1).is_ok());
        assert!(QrProfile::new(EcLevel::Low, 40).is_ok());
    }

    #[test]
    fn ec_level_letters_round_trip() {
        for ec in [
            EcLevel::Low,
            EcLevel::Medium,
            EcLevel::Quartile,
            EcLevel::High,
        ] {
            assert_eq!(EcLevel::from_letter(ec.letter()).expect("自己给的字母"), ec);
            assert_eq!(
                EcLevel::from_letter(ec.letter().to_ascii_lowercase()).expect("小写也认"),
                ec
            );
        }
        assert!(EcLevel::from_letter('X').is_err());
    }

    /// 渲染：尺寸、静区、以及深色模块落在正确的位置上。
    #[test]
    fn render_lays_out_modules_and_quiet_zone() {
        let profile = QrProfile::new(EcLevel::Low, 1).expect("版本合法");
        let symbol = profile.encode_payload(b"hi").expect("编得出来");
        let scale = 3;
        let quiet = 4;
        let image = symbol.render(scale, quiet).expect("参数合法");
        let side = (u32::from(symbol.size()) + 2 * u32::from(quiet)) * u32::from(scale);
        assert_eq!(image.width(), side);
        assert_eq!(image.height(), side);
        // 静区必须是白的。
        assert_eq!(image.pixel(0, 0), Some(255), "左上角应当是静区");
        assert_eq!(
            image.pixel(side - 1, side - 1),
            Some(255),
            "右下角应当是静区"
        );
        // 第一个模块（定位图案的一部分）必须是黑的，且整块 scale×scale 都是黑的。
        let origin = u32::from(quiet) * u32::from(scale);
        assert_eq!(symbol.module(0, 0), Some(true), "定位图案的角必须是深色");
        for dy in 0..u32::from(scale) {
            for dx in 0..u32::from(scale) {
                assert_eq!(
                    image.pixel(origin + dx, origin + dy),
                    Some(0),
                    "模块 ({dx},{dy}) 没有被渲染成深色"
                );
            }
        }
    }

    #[test]
    fn render_rejects_useless_geometry() {
        let profile = QrProfile::new(EcLevel::Low, 1).expect("版本合法");
        let symbol = profile.encode_payload(b"hi").expect("编得出来");
        assert!(symbol.render(0, 4).is_err(), "缩放为 0 无意义");
        assert!(symbol.render(1, 3).is_err(), "静区小于 4 会扫不出来");
        assert!(symbol.render(1, 4).is_ok());
        // 放大到超过像素上限必须报错，而不是申请几百 MB。
        assert!(symbol.render(u16::MAX, 4).is_err());
    }

    #[test]
    fn module_out_of_bounds_is_none() {
        let profile = QrProfile::new(EcLevel::Low, 1).expect("版本合法");
        let symbol = profile.encode_payload(b"hi").expect("编得出来");
        assert!(symbol.module(symbol.size(), 0).is_none());
        assert!(symbol.module(0, symbol.size()).is_none());
        assert!(symbol.module(0, 0).is_some());
    }

    #[test]
    fn debug_prints_metadata_not_modules() {
        let profile = QrProfile::new(EcLevel::High, 5).expect("版本合法");
        let symbol = profile.encode_payload(b"debug").expect("编得出来");
        let debug = format!("{symbol:?}");
        assert!(debug.contains("纠错 H"), "应当带上纠错级别：{debug}");
        assert!(debug.contains('×'), "应当带上边长：{debug}");
        // 模块矩阵有三万多个布尔值，绝不能整份倒出来。
        assert!(debug.len() < 80, "Debug 输出过长：{debug}");
    }
}
