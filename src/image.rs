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

//! 灰度图像：渲染与扫描之间传递像素的形式。
//!
//! # 边界画在「像素」上，不画在「图片文件」上
//!
//! 「从图片导入二维码」这条路径上，用户给的是一个 PNG/JPEG 文件。把它解成像素是
//! **平台已经会做的事**：JVM 有 `ImageIO`，Android 有 `BitmapFactory`，iOS 有
//! `UIImage`。若本 crate 自己解，就要引入一个图像格式 crate、为每个平台维护一份
//! 解码器，并把那些解码器历史上的漏洞一并收进来（图像解码器是 CVE 的常客）。
//!
//! 因此本 crate 只认像素：**格式归平台，二维码归本 crate**。

use crate::error::{Error, Result};

/// 8 位灰度图：行优先、`0` 是黑、`255` 是白。
///
/// 尺寸与像素数必须自洽——这是本类型唯一的不变式，也是唯一能构造它的入口替你保证的
/// 事。二维码的定位算法会在图上做索引与插值，一个「声称 1000×1000 却有 10 个像素」
/// 的图像会让它在别的层里越界。
pub struct GrayImage {
    /// 宽度（像素）。
    width: u32,
    /// 高度（像素）。
    height: u32,
    /// 行优先的灰度值，长度恒为 `width * height`。
    pixels: Vec<u8>,
}

impl GrayImage {
    /// 单张图像的像素数上限：64 Mi 像素（约 64 MB 灰度数据）。
    ///
    /// 这不是密码学边界，而是**工作量边界**：二维码识别不需要原始分辨率，端侧应当先
    /// 把长边缩到一两千像素再送进来。上限存在的意义是让「端侧忘了缩」这件事表现为
    /// 一个明确的错误，而不是一次几百 MB 的分配。
    pub const MAX_PIXELS: usize = 64 * 1024 * 1024;

    /// 从灰度像素构造。
    ///
    /// # 错误
    ///
    /// 宽或高为 0、像素个数与 `width * height` 不符、或超过
    /// [`GrayImage::MAX_PIXELS`] 时返回 [`Error::BadImageGeometry`]。
    pub fn from_luma8(width: u32, height: u32, pixels: Vec<u8>) -> Result<Self> {
        let expected = image_size(width, height, pixels.len())?;
        if expected != pixels.len() {
            return Err(Error::BadImageGeometry {
                width,
                height,
                pixels: pixels.len(),
            });
        }
        Ok(Self {
            width,
            height,
            pixels,
        })
    }

    /// 从 RGBA 像素构造（丢掉 alpha）。
    ///
    /// 亮度用 Rec.601 的定点近似 `(77·R + 150·G + 29·B) / 256`——三个权重之和恰好是
    /// 256，因此结果是精确的 8 位亮度，不需要再做夹取。
    ///
    /// **alpha 被丢掉而不是参与合成**：把透明背景合成成黑色或白色都需要一个背景色
    /// 假设，而二维码的定位算法自己会做自适应阈值——它比我们更清楚前景是什么。
    pub fn from_rgba8(width: u32, height: u32, pixels: &[u8]) -> Result<Self> {
        let expected = image_size(width, height, pixels.len())?;
        let Some(expected_bytes) = expected.checked_mul(4) else {
            return Err(Error::BadImageGeometry {
                width,
                height,
                pixels: pixels.len(),
            });
        };
        if expected_bytes != pixels.len() {
            return Err(Error::BadImageGeometry {
                width,
                height,
                pixels: pixels.len(),
            });
        }
        let luma = pixels
            .as_chunks::<4>()
            .0
            .iter()
            .map(|pixel| {
                ((77 * u32::from(pixel[0]) + 150 * u32::from(pixel[1]) + 29 * u32::from(pixel[2]))
                    >> 8) as u8
            })
            .collect();
        Ok(Self {
            width,
            height,
            pixels: luma,
        })
    }

    /// 宽度（像素）。
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// 高度（像素）。
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// 行优先的灰度值。
    #[must_use]
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// 取一个像素；越界返回 `None`。
    #[must_use]
    pub fn pixel(&self, x: u32, y: u32) -> Option<u8> {
        if x >= self.width || y >= self.height {
            return None;
        }
        self.at(x as usize, y as usize).into()
    }

    /// 内部的无检查取值：越界返回白色。
    ///
    /// 调用方都保证坐标在界内（渲染时由构造过程保证，扫描时由解码器的 `width()` /
    /// `height()` 保证）。返回白色而不是 panic，是为了让「万一越界」表现为一张扫不出
    /// 东西的图，而不是一次崩溃——本 crate 的任何输入都不得导致 panic。
    pub(crate) fn at(&self, x: usize, y: usize) -> u8 {
        let index = y * (self.width as usize) + x;
        self.pixels.get(index).copied().unwrap_or(u8::MAX)
    }
}

/// 校验尺寸并算出应有多少像素。
fn image_size(width: u32, height: u32, actual: usize) -> Result<usize> {
    let bad = || Error::BadImageGeometry {
        width,
        height,
        pixels: actual,
    };
    if width == 0 || height == 0 {
        return Err(bad());
    }
    let Some(expected) = (width as usize).checked_mul(height as usize) else {
        return Err(bad());
    };
    if expected > GrayImage::MAX_PIXELS {
        return Err(bad());
    }
    Ok(expected)
}

impl core::fmt::Debug for GrayImage {
    /// 只打印尺寸。
    ///
    /// 一张 4000×3000 的图的像素数是 1200 万，`derive(Debug)` 会把它整份倒进日志
    /// ——那既没用（谁看得懂灰度数组），又把日志变成一个内存放大点。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "GrayImage {{ {}×{}, {} 字节 }}",
            self.width,
            self.height,
            self.pixels.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luma_round_trips() {
        let image = GrayImage::from_luma8(2, 2, vec![0, 1, 2, 3]).expect("尺寸自洽");
        assert_eq!(image.width(), 2);
        assert_eq!(image.height(), 2);
        assert_eq!(image.pixel(0, 0), Some(0));
        assert_eq!(image.pixel(1, 1), Some(3));
        assert_eq!(image.pixel(2, 0), None, "越界必须返回 None");
        assert_eq!(image.pixel(0, 2), None);
    }

    #[test]
    fn mismatched_size_is_rejected() {
        assert!(GrayImage::from_luma8(2, 2, vec![0, 1, 2]).is_err());
        assert!(GrayImage::from_luma8(0, 2, vec![]).is_err());
        assert!(GrayImage::from_luma8(2, 0, vec![]).is_err());
        // 宽×高必须用 checked 乘法：u32 的乘积在这里能溢出。
        assert!(GrayImage::from_luma8(u32::MAX, u32::MAX, vec![0]).is_err());
    }

    #[test]
    fn rgba_converts_to_luma() {
        // 纯黑、纯白、纯红、纯绿。
        let pixels = vec![
            0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 255, 0, 255, 0, 255,
        ];
        let image = GrayImage::from_rgba8(4, 1, &pixels).expect("尺寸自洽");
        assert_eq!(image.pixel(0, 0), Some(0));
        assert_eq!(image.pixel(1, 0), Some(255));
        assert_eq!(image.pixel(2, 0), Some(76), "0.299 × 255 ≈ 76");
        assert_eq!(image.pixel(3, 0), Some(149), "0.587 × 255 ≈ 149");
    }

    #[test]
    fn rgba_size_must_match() {
        assert!(GrayImage::from_rgba8(1, 1, &[0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(GrayImage::from_rgba8(1, 1, &[0, 0, 0, 0]).is_ok());
    }

    #[test]
    fn debug_does_not_dump_pixels() {
        let image = GrayImage::from_luma8(2, 2, vec![7; 4]).expect("尺寸自洽");
        let debug = format!("{image:?}");
        assert!(debug.contains("2×2"), "应当打印尺寸：{debug}");
        assert!(!debug.contains('7'), "不应当打印像素：{debug}");
    }
}
