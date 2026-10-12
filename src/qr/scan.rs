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

//! 从图像里读二维码（`scan-image` feature）。
//!
//! # 它服务的是「没有摄像头的那一端」
//!
//! 桌面端没有摄像头，于是「选一张图片导入」是它唯一的扫码路径——用户会把手机上的码
//! 截图、拍照，或者从聊天软件里存下来。移动端走平台相机（拿到的已经是文本），
//! 因此不需要本模块；这正是它被做成可选 feature 的原因。
//!
//! # 输入是像素，不是文件
//!
//! 图像**格式**的解码归平台（见 [`crate::image`] 的说明），本模块只认灰度像素。

use crate::envelope;
use crate::error::{Error, Result};
use crate::frame::{self, Frame};
use crate::image::GrayImage;
use rqrr::PreparedImage;

/// 能被识别的图像的最小边长（像素）。
///
/// 最小的二维码（版本 1）是 21×21 个模块，而一个模块至少要占一个像素——因此小于
/// 21×21 的图**几何上不可能**含有任何二维码。这不是「大概率没有」，是确定的。
/// 先挡住它，既省掉一次注定失败的检测，也避开了解码器在极小图上的边界路径。
const MIN_IMAGE_SIDE: u32 = 21;

/// 从图像里读出一段文本（第一张读得出来的码）。
///
/// 同一张图里可能有多个二维码；本函数返回**第一个**能解出文本的，顺序由解码器的
/// 定位结果决定。要「找出属于本应用的那一张」，用 [`decode_payload`]。
///
/// # 错误
///
/// - [`Error::NoQrFound`]：图里没有码，或码小到读不出来。
/// - [`Error::QrNotText`]：读出来的字节不是合法 UTF-8（这张码不是给文本用的）。
/// - [`Error::QrDecode`]：找到了码但校验/纠错失败。
pub fn decode_text(image: &GrayImage) -> Result<String> {
    let mut found: Option<String> = None;
    let report = scan(image, |raw| {
        if let Ok(text) = core::str::from_utf8(raw) {
            found = Some(text.to_owned());
            true
        } else {
            false
        }
    });
    found.ok_or_else(|| report.into_error())
}

/// 从图像里读出**本应用的**载荷（**只接受单帧**）。
///
/// 与 [`decode_text`] 的区别是它会跳过别人的二维码：同一张图里既有本应用的码、又有
/// 一个广告二维码时，前者胜出，而不是报「这不是 Qualia2FA 的二维码」。
///
/// 多帧的码请用 [`decode_frame`]：这一条是「一段文本 → 一份完整载荷」的便捷入口，
/// 它遇到多帧会报 [`Error::MultiFrameUnsupported`]（那不是一个错误，而是「走错入口」）。
///
/// # 错误
///
/// 图像里没有任何本应用的码时，报出**最有信息量**的那一个：若某张码确实是我们的、
/// 只是内容坏了，报它的具体错误（例如 [`Error::MalformedBase32`]）；否则报
/// [`Error::NotOurQrText`]（扫到了别人的码）或 [`Error::NoQrFound`]。
pub fn decode_payload(image: &GrayImage) -> Result<Vec<u8>> {
    decode_with(image, envelope::decode)
}

/// 从图像里读出**本应用的一帧**——多帧时是其中一张。
///
/// # 它为什么与 [`decode_payload`] 分开
///
/// 单帧与多帧是两条不同的路：前者「一张码就是全部」，后者「这一张只是一部分，还要
/// 拿 [`crate::frame::Reassembler`] 攒」。两条路的第一件事完全相同（在整张图里挑出
/// **属于本应用**的那张码），差别只在挑出来之后怎么处置——因此它们共用
/// `decode_with`（本模块的私有函数），错误挑选的规则也完全一致。
///
/// 单帧（`1/1`）也走这条路：调用方因此只有一条路径要维护（见
/// [`crate::frame::decode_frame`]）。
///
/// # 错误
///
/// 与 [`decode_payload`] 相同，只是不再返回 [`Error::MultiFrameUnsupported`]。
pub fn decode_frame(image: &GrayImage) -> Result<Frame> {
    decode_with(image, frame::decode_frame)
}

/// 在整张图里挑出一张**属于本应用**的码，交给 `parse` 处置。
///
/// 两条扫描入口只有 `parse` 不同，而「挑」的规则——跳过别人的码、错误按信息量挑一个
/// ——必须完全一致：不一致的症状是「单帧能扫出来的图，多帧入口报了一个别的错」。
/// 它是本模块的私有函数，因此上面那两处只能写成代码字体。
fn decode_with<T, F>(image: &GrayImage, mut parse: F) -> Result<T>
where
    F: FnMut(&str) -> Result<T>,
{
    let mut found: Option<T> = None;
    let mut specific: Option<Error> = None;
    let report = scan(image, |raw| {
        let Ok(text) = core::str::from_utf8(raw) else {
            return false;
        };
        match parse(text) {
            Ok(value) => {
                found = Some(value);
                true
            }
            Err(error) => {
                // 「不是我们的码」在扫描场景里是**预期内**的结果（同一张图里可以有
                // 任何东西），而「是我们的码但坏了」才是要报告给用户的那一个。
                if !matches!(error, Error::NotOurQrText) {
                    specific = Some(error);
                }
                false
            }
        }
    });
    match found {
        Some(value) => Ok(value),
        None => Err(specific.unwrap_or_else(|| report.into_error())),
    }
}

/// 一次扫描里发生了什么，用来挑出最有信息量的错误。
#[derive(Default)]
struct ScanReport {
    /// 找到了格子但解不出来（第一个这样的错误）。
    grid_error: Option<Error>,
    /// 解出了字节但不是文本。
    saw_binary: bool,
    /// 解出了文本。
    saw_text: bool,
}

impl ScanReport {
    /// 按信息量从高到低挑一个错误。
    ///
    /// 顺序不是随手排的：**读出了文本**说明图里确实有码，只是不是我们的（对用户来说
    /// 意味着「你扫错码了」）；**读出了字节但不是文本**说明那张码不是给文本用的；
    /// 只有格子上报的错误才说明「码在那儿但读不出来」；三者都没有才是「图里没有码」。
    fn into_error(self) -> Error {
        if self.saw_text {
            Error::NotOurQrText
        } else if self.saw_binary {
            Error::QrNotText
        } else if let Some(error) = self.grid_error {
            error
        } else {
            Error::NoQrFound
        }
    }
}

/// 逐个格子尝试解码，把每个**成功解出的字节流**交给回调。
///
/// 回调返回 `true` 表示「拿到了想要的东西」，扫描立即停止。
///
/// # 为什么用回调而不是返回 `Vec<Vec<u8>>`
///
/// 解码器返回的格子借用着它自己的缓冲区，因此「先把所有格子解出来再挑」需要把所有
/// 中间结果都留在内存里；而调用方真正要的往往只是第一个能用的。回调让「边扫边停」
/// 成为可能，代价是错误报告要单独收集（见 [`ScanReport`]）。
fn scan<F>(image: &GrayImage, mut on_raw: F) -> ScanReport
where
    F: FnMut(&[u8]) -> bool,
{
    let mut report = ScanReport::default();
    if image.width() < MIN_IMAGE_SIDE || image.height() < MIN_IMAGE_SIDE {
        return report;
    }
    let mut prepared = PreparedImage::prepare_from_greyscale(
        image.width() as usize,
        image.height() as usize,
        |x, y| image.at(x, y),
    );
    for grid in prepared.detect_grids() {
        let mut raw = Vec::new();
        match grid.decode_to(&mut raw) {
            Ok(_metadata) => {
                if core::str::from_utf8(&raw).is_ok() {
                    report.saw_text = true;
                } else {
                    report.saw_binary = true;
                }
                if on_raw(&raw) {
                    return report;
                }
            }
            Err(error) => {
                if report.grid_error.is_none() {
                    report.grid_error = Some(Error::QrDecode(error));
                }
            }
        }
    }
    report
}
