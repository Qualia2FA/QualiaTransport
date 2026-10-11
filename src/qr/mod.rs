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
/// 编码）。它应当被构造一次并复用，而不是每次展示时重建。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrProfile {
    /// 纠错级别。
    ec: EcLevel,
    /// 愿意展示的最大版本（1–40）。
    max_version: u8,
    /// 这条通道能装下的最大载荷字节数（构造时算好）。
    payload_capacity: usize,
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
            payload_capacity: payload_capacity(ec, max_version),
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
    #[must_use]
    pub const fn payload_capacity(&self) -> usize {
        self.payload_capacity
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
/// # 为什么用全零字节探测是**精确**的
///
/// Base32 的输出长度只取决于输入长度（`ceil(8n/5)` 个字符），而 Base32 的字母表完全
/// 落在二维码的字母数字模式里，因此**所需版本只取决于文本长度，与文本内容无关**。
/// 换句话说「`n` 个字节装不装得下」对同一个 `n` 是一致答案，用零字节探测不会低估也
/// 不会高估任何别的 `n` 字节载荷。这条性质由 `capacity_is_content_independent` 钉住。
fn payload_capacity(ec: EcLevel, max_version: u8) -> usize {
    let fits = |len: usize| {
        encode_within(&crate::envelope::encode(&vec![0; len]), ec, max_version).is_some()
    };
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
