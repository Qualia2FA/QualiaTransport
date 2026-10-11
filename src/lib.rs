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

//! Qualia2FA 的**传输通道**。
//!
//! 本 crate 只做一件事：把一段字节送出去、再把一段字节收回来。协议本身——谁的载荷
//! 先到、冲突怎么报、重放怎么挡——住在 `qualia2fa-core` 里，本 crate 对它一无所知。
//! 两者之间的接口是核心库的 `Transport` trait，而**依赖方向是「本 crate ← 核心库」**：
//! 任何需要「把字节放进二维码」或「在局域网里找到对端」的项目都能直接用本 crate，
//! 不需要接受 Qualia2FA 的保险库格式或账号模型。
//!
//! # 现在有什么
//!
//! | 模块 | 内容 |
//! |------|------|
//! | [`qr`] | 二维码的容量模型、编码、渲染与（可选）图像解码 |
//! | [`envelope`] | 二进制载荷 ↔ 二维码可承载文本 |
//! | [`image`] | 渲染与扫描之间传递像素的形式 |
//!
//! # 为什么二维码要先变成文本
//!
//! 二维码的「字节模式」确实能原样携带任意字节，但那样一来**只有本 crate 自己解得出
//! 来**：平台相机（Android ML Kit、iOS AVFoundation）交回的是字符串，剪贴板里也只能
//! 放文本，人眼抄下来的更只能是文本。于是本 crate 统一把载荷放进一层文本信封，再用
//! 二维码的**字母数字模式**编码——代价只有约 10% 的容量，换来的是「任何扫码器读出来
//! 的都是同一串文本」。详见 [`envelope`] 的模块文档。
//!
//! # 还没有什么
//!
//! **局域网通道（QWBP）尚未实现**：UDP 组播发现、iroh 离线传输、以及各平台的局域网
//! 权限流程都还在计划里。本 crate 的模块划分已经为它留好位置——它与二维码的区别只是
//! 「字节怎么过去」，上层的合并与裁决逻辑完全共用。
//!
//! # 纯度约定
//!
//! 本 crate 是纯逻辑的：不碰文件系统、网络、时钟与环境变量，全部输入都是参数。
//! 因此 `#![forbid(unsafe_code)]` 成立，且任何输入都不得导致 panic——唯一允许的
//! 失败方式是返回 [`Error`]。

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

pub mod envelope;
pub mod error;
pub mod image;
pub mod qr;

/// RFC 4648 §6 的 Base32。
///
/// 刻意不依赖现成的 crate：本 crate 的编解码层因此保持**零依赖**，且这份实现的语义
/// 与核心库的 `base32` 显式对齐（大小写不敏感、容忍填充、拒绝非规范尾比特），
/// 免得同一份 RFC 在两个仓库里长出两种行为。
mod base32;

pub use error::{Error, Result};
